#!/usr/bin/env python3
"""Red arm: when sandbox apply fails, the launcher must refuse to start the CLI —
never run naked.

A12's original words: "when sandbox apply fails the launcher must refuse to start
Claude, never run naked". A rule that only holds in prose is a wish, so here it
gets an enforcer that yells.

Four arms (same shape as seatbelt_six):
  control  normal profile → terminal success / exit 0
  negative profile with broken syntax → probe stage exits 78, CLI never attempted
  negative profile with missing parameter → same as above
  negative policy sabotaged after probe succeeds, breaking the second apply →
           ready=true, attempted=true, but inner cli_started=false, zero CLI
           side-effect evidence, terminal=78/config_rejected

The criterion is not "nonzero exit" — a crashing CLI is also nonzero. The
lifecycle is split into `cli_exec_attempted` (pre-spawn accounting) and
`cli_started`, proven by the inner bootstrap/exec handshake; plus the stage on
`sandbox_apply_failed`, so a second-stage apply failure isn't filed as an
ordinary cli_failed.
"""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lib  # noqa: E402
import run_acceptance as RA  # noqa: E402
import seatbelt_g6 as G6  # noqa: E402

PY3 = G6.PY3
REAL_CLI = G6.REAL_CLI

# ── output schema: fixed contract, **not** a field observation ─────────────────────────────
# 🔴 2026-08-15 (A15 ruling §Q1 red ① + §"the most likely path to a false pass for this criterion set").
#
# Background: `RA.base_profile()` pins output_schema_sha256 to the "0"*64 placeholder,
# while A14 tightened this file's control arm from "CLI starts = pass" to "terminal
# state must be success". The tightening was right, but nobody gave the positive
# arm a real schema contract, so it deterministically schema_failed (the gate was not at fault).
#
# 🔴 The fix deliberately does NOT copy G6's "observe one pass, then backfill
#    the observation". A15 ruled that the most realistic-looking false-pass path:
#    once the real CLI's output key set drifts, pass one observes the new value,
#    pass two auto-approves it — both real-CLI positives go green while the three
#    apply red arms ignore output schema, so the suite stays green after the
#    contract drifted. **No malice needed, just one innocent "reuse the helper".**
#    G6's two passes are **capability probes** (observed value written explicitly
#    as `..._UNREVIEWED`), not approval semantics; don't factor it into a shared helper.
#
# So here the key set fixed by `tests/loop_mock.py:91-92` `final_response()` is written in stone.
# The hash below is **recomputed independently** (per finish.schema_identity's
# canonical rule: sort keys, json.dumps(separators=(",",":")), then sha256) —
# never calling the code under test, so if the product's canonicalization drifts,
# this arm goes red instead of quietly drifting along.
LOOP_MOCK_FINAL_KEYS = ("ok", "read")          # the contract of loop_mock.final_response()
LOOP_MOCK_SCHEMA_SHA256 = "aa3150c0d5aea20bc56fd1b165fe00eac767b77fd741200c759b3b7a239f1de5"
_canon = json.dumps(sorted(LOOP_MOCK_FINAL_KEYS), separators=(",", ":")).encode()
if hashlib.sha256(_canon).hexdigest() != LOOP_MOCK_SCHEMA_SHA256:
    raise AssertionError(
        "contract doesn't match the pinned hash: changing LOOP_MOCK_FINAL_KEYS requires also changing "
        "LOOP_MOCK_SCHEMA_SHA256, and confirm loop_mock really changed its contract first")


BUILD_REPORTS = {}   # sandbox copy path → lib.build_sandbox's report (for archiving)

# Files each arm must preserve as evidence (A15 minimal closure item 3). A temp
# directory is not a deliverable: `/private/var/folders/.../hb-fc-*` is volatile
# scene evidence, gone on reboot — a cold reader can't recompute it.
ARCHIVE_FILES = ("events.jsonl", "terminal.json", "model.json", "model.stderr",
                 "inspector.jsonl", "plan.json", "sandbox_probe.err",
                 "cli-started.json", "cli-process-evidence.json")


def archive_attempt(dest_root, arm, res):
    """Copy the arm's raw attempt into the formal run directory; return the on-disk manifest (with sha256)."""
    dest = os.path.join(dest_root, arm)
    os.makedirs(dest, exist_ok=True)
    manifest = {}
    adir = res.get("attempt_dir")
    if adir and os.path.isdir(adir):
        for name in ARCHIVE_FILES:
            src = os.path.join(adir, name)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dest, name))
                manifest[name] = lib.sha256_file(os.path.join(dest, name))
    # each sub-step's rc and full stdout/stderr — the summary keeps only a 400-char tail, not enough to recompute
    with open(os.path.join(dest, "hb-run.stdout"), "w") as f:
        f.write(res.get("stdout_full") or "")
    with open(os.path.join(dest, "hb-run.stderr"), "w") as f:
        f.write(res.get("stderr_full") or "")
    with open(os.path.join(dest, "rc.txt"), "w") as f:
        f.write(f"{res.get('rc')}\n")
    report = BUILD_REPORTS.get(res.get("sandbox_dir"))
    if report is not None:
        with open(os.path.join(dest, "build-report.json"), "w") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        manifest["build-report.json"] = lib.sha256_file(
            os.path.join(dest, "build-report.json"))
    return manifest


def build(root, port, sandbox_profile_text=None, break_second_apply=False):
    ws = os.path.join(root, "ws"); os.makedirs(ws, 0o700)
    home = os.path.join(root, "home"); os.makedirs(home, 0o700)
    inp = os.path.join(root, "in"); os.makedirs(inp, 0o700)
    with open(os.path.join(inp, "sentinel.txt"), "w") as f:
        f.write("S\n")
    ver = subprocess.run([REAL_CLI, "--version"], capture_output=True, text=True).stdout.strip()
    prof = RA.base_profile(ws, home, f"http://127.0.0.1:{port}", inp)
    prof.update(cli_realpath=REAL_CLI, cli_sha256=lib.sha256_file(REAL_CLI),
                cli_version=ver, auth_mode="loopback_dummy", timeout_seconds=60)
    # 🔴 base_profile defaults to disabled (that's for fake_cli). These two tests
    #    **are** testing the sandbox, so it must be enabled explicitly — otherwise
    #    they pass quietly with no sandbox at all, the worst kind of fake evidence.
    prof["sandbox"] = "required"
    prof["approved_tools"] = [{"name": "Read",
                               "definition_sha256": G6.REVIEWED_READ_SHA256}]
    # base_profile gives the all-zero placeholder; here it's replaced with loop_mock's fixed contract (see file top).
    # ⚠️ Patch only this cell — do not loosen hb-read.sb, sandbox mode,
    #    approved_tools, or any lower-bound field just to make the positive arm go green (A15's reverse check on the control tightening).
    prof["output_schema_sha256"] = LOOP_MOCK_SCHEMA_SHA256
    pp = os.path.join(root, "profile.json")
    with open(pp, "w") as f:
        json.dump(prof, f, ensure_ascii=False, indent=1)
    mp = os.path.join(root, "manifest.json")
    with open(mp, "w") as f:
        json.dump({"read-shadow-test": {"path": pp, "sha256": lib.sha256_file(pp)}}, f, indent=1)
    sb = os.path.join(root, "sandbox-copy")
    rewrites = None
    if break_second_apply:
        rewrites = [("TEST_BREAK_POLICY_AFTER_PROBE = False",
                     "TEST_BREAK_POLICY_AFTER_PROBE = True")]
    report = lib.build_sandbox(sb, mp, extra_rewrites=rewrites)
    if break_second_apply:
        key = ("TEST_BREAK_POLICY_AFTER_PROBE = False -> "
               "TEST_BREAK_POLICY_AFTER_PROBE = True")
        if report["files"]["sandbox_launcher.py"]["extra_rewrites"].get(key) != 1:
            raise AssertionError("second-apply fault injection did not rewrite exactly once")
    if sandbox_profile_text is not None:
        with open(os.path.join(sb, "sandbox", "hb-read.sb"), "w") as f:
            f.write(sandbox_profile_text)
    # for archiving: the build report is the only evidence of "what the injection actually changed"; it can't live only in memory.
    BUILD_REPORTS[sb] = report
    return sb


def run_once(sb, port):
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                        "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR")}
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    mock = subprocess.Popen(
        [PY3, os.path.join(HERE, "loop_mock.py"), "--port", str(port),
         "--runs", os.path.join(sb, "runs")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    mock.stdout.readline()
    p = subprocess.run(["/bin/zsh", os.path.join(sb, "hb-run.sh"), "read-shadow-test", "hi"],
                       cwd=sb, env=env, capture_output=True, text=True, timeout=300)
    mock.kill()
    rd = os.path.join(sb, "runs")
    ds = [os.path.join(rd, d) for d in os.listdir(rd)] if os.path.isdir(rd) else []
    ds = [d for d in ds if os.path.isdir(d)]
    adir = max(ds, key=os.path.getmtime) if ds else None
    events, terminal = [], None
    if adir:
        ep = os.path.join(adir, "events.jsonl")
        if os.path.exists(ep):
            events = [json.loads(l) for l in open(ep) if l.strip()]
        tp = os.path.join(adir, "terminal.json")
        if os.path.exists(tp):
            terminal = json.load(open(tp))
    return {
        "rc": p.returncode,
        "cli_exec_attempted": any(e.get("event") == "cli_exec_attempted" for e in events),
        "cli_started": any(e.get("event") == "cli_started"
                           and e.get("inner_bootstrap_handshake") is True for e in events),
        "sandbox_ready": any(e.get("event") == "sandbox_ready" for e in events),
        "sandbox_apply_failed": any(e.get("event") == "sandbox_apply_failed" for e in events),
        "sandbox_apply_failed_stages": [e.get("stage") for e in events
                                         if e.get("event") == "sandbox_apply_failed"],
        "ready_profile_sha256": next((e.get("profile_sha256") for e in events
                                      if e.get("event") == "sandbox_ready"), None),
        "outcome": (terminal or {}).get("outcome"),
        "exit_code": (terminal or {}).get("exit_code"),
        "request_count": (terminal or {}).get("request_count"),
        "model_output_size": (os.path.getsize(os.path.join(adir, "model.json"))
                              if adir and os.path.exists(os.path.join(adir, "model.json"))
                              else None),
        "sandbox": (terminal or {}).get("sandbox"),
        "stdout_tail": p.stdout[-400:],
        # for archiving (not part of any criterion): raw attempt source plus full stdout/stderr
        "attempt_dir": adir,
        "sandbox_dir": sb,
        "stdout_full": p.stdout,
        "stderr_full": p.stderr,
    }


BROKEN_SYNTAX = '(version 1)\n(deny default)\n(allow file-read* (subpath (param "NOPE"\n'   # unclosed paren
MISSING_PARAM = '(version 1)\n(deny default)\n(allow file-read* (subpath (param "NEVER_PASSED")))\n'


def main():
    rc = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)",
                         "/usr/bin/true"], capture_output=True).returncode
    if rc != 0:
        print("ABORT: this shell cannot run under Seatbelt.")
        return 2

    results, ok = {}, True

    # control: the normal profile must run (otherwise the lower arms' "didn't start" proves nothing)
    root = os.path.realpath(tempfile.mkdtemp(prefix="hb-fc-ok-"))
    port = G6.free_port()
    r = run_once(build(root, port), port)
    results["control_normal_profile"] = r
    control_ok = (r["rc"] == 0 and r["outcome"] == "success" and r["exit_code"] == 0
                  and r["cli_exec_attempted"] and r["cli_started"]
                  and r["sandbox_ready"] and not r["sandbox_apply_failed"]
                  and (r["sandbox"] or {}).get("applied") is True
                  and (r["sandbox"] or {}).get("hashes_match") is True)
    ok = ok and control_ok
    print(f"[{'ok ' if control_ok else 'BAD'}] control: normal profile → "
          f"started={r['cli_started']} outcome={r['outcome']} exit={r['exit_code']}")

    for name, text in (("broken_syntax", BROKEN_SYNTAX), ("missing_param", MISSING_PARAM)):
        root = os.path.realpath(tempfile.mkdtemp(prefix=f"hb-fc-{name}-"))
        port = G6.free_port()
        r = run_once(build(root, port, sandbox_profile_text=text), port)
        results[name] = r
        # 🔴 Core criterion: the CLI was never launched
        cell_ok = (r["cli_exec_attempted"] is False
                   and r["cli_started"] is False
                   and r["sandbox_apply_failed"] is True
                   and r["sandbox_ready"] is False
                   and r["exit_code"] == 78
                   and r["outcome"] == "config_rejected")
        ok = ok and cell_ok
        print(f"[{'ok ' if cell_ok else 'BAD'}] {name}: attempted={r['cli_exec_attempted']} "
                   f"apply_failed={r['sandbox_apply_failed']} exit={r['exit_code']} "
                   f"outcome={r['outcome']}")

    # Synchronous red arm: the test build, after probe success but before the real
    # sandbox-exec, sabotages only the in-memory second policy copy. If the launcher
    # mistakes an apply failure for a CLI failure, or writes cli_started early, this cell goes red immediately.
    root = os.path.realpath(tempfile.mkdtemp(prefix="hb-fc-second-apply-"))
    port = G6.free_port()
    r = run_once(build(root, port, break_second_apply=True), port)
    results["second_stage_apply_failure"] = r
    cli_side_effect_evidence = bool(r["cli_started"] or (r["request_count"] or 0)
                                    or (r["model_output_size"] or 0))
    cell_ok = (r["sandbox_ready"] is True
               and r["cli_exec_attempted"] is True
               and r["cli_started"] is False
               and cli_side_effect_evidence is False
               and r["sandbox_apply_failed"] is True
               and "cli_exec" in r["sandbox_apply_failed_stages"]
               and r["rc"] == 78 and r["exit_code"] == 78
               and r["outcome"] == "config_rejected"
               and (r["sandbox"] or {}).get("applied") is False)
    ok = ok and cell_ok
    print(f"[{'ok ' if cell_ok else 'BAD'}] second_stage_apply_failure:"
          f"ready={r['sandbox_ready']} attempted={r['cli_exec_attempted']} "
          f"started={r['cli_started']} side_effect={cli_side_effect_evidence} "
          f"outcome={r['outcome']} exit={r['exit_code']}")

    # ── Formal evidence preservation (A15 minimal closure item 3) ──────────────────────────────────
    # Every boolean in the summary comes from events/terminal, but those two files
    # previously lived only in temp dirs — a cold reader couldn't recompute. Here the four arms' raw attempts land in a timestamped formal run directory.
    ts = time.strftime("%Y%m%dT%H%M%S")
    run_dir = os.path.join(WRAPPER, "runs", "seatbelt", f"failclosed-{ts}")
    os.makedirs(run_dir, exist_ok=True)
    archives = {arm: archive_attempt(run_dir, arm, res) for arm, res in results.items()}

    # the summary keeps no volatile paths or full stdout (they're already in run_dir)
    slim = {}
    for arm, res in results.items():
        slim[arm] = {k: v for k, v in res.items()
                     if k not in ("attempt_dir", "sandbox_dir", "stdout_full", "stderr_full")}

    payload = {"results": slim,
               "verdict": "FAILCLOSED_PASS" if ok else "FAILCLOSED_FAIL",
               "run_dir": run_dir,
               "archived_sha256": archives}
    for out in (os.path.join(run_dir, "summary.json"),
                os.path.join(WRAPPER, "runs", "seatbelt", "failclosed-latest.json")):
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n{payload['verdict']}  →  {run_dir}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
