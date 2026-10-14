#!/usr/bin/env python3
"""Cell 6 — the real Claude Code launches inside Seatbelt, completes the sentinel
Read, streams back, exits normally.

This is the one explicit "don't know" A12 left behind:
    "Not whether Seatbelt syntax can express it, but whether Claude Code can fully
     start, read the sentinel, stream back and exit inside a 'zero persistent
     writes' profile."
Codex can't answer this cell — it runs inside an outer Seatbelt itself, so it
can't nest a second one.

## Why a test topology instead of the production profile

The production profile pins the CLI 2.1.226 sha256, but this machine has
self-upgraded to 2.1.232, so `hb-run.sh read-shadow-loopback` hits
`REJECT CLI sha256 drift` at preflight. **That gate is correct; don't bypass
it.** Re-capturing the golden definition and re-signing is the owner's action
(the signature binds their name and the bytes), not something this script
should do for them.

So keep two things separate:
  · "the definition didn't change" — a governance question, owned by the
    signature gate, waiting on re-signing.
  · "can the CLI do its job inside this sandbox" — a capability question, which
    is this cell, and a test topology proves it just as well.
The test topology is **isomorphic** to production: the same hb-read.sb
(byte-for-byte copy, see lib.SOURCE_DIRS), the same hb-run/preflight/inspector/
finish sources; only the manifest points at this round's temp profile.

## Cost

Upstream is `tests/loop_mock.py`, listening on 127.0.0.1 — no network, zero API
calls. Afterwards it asserts terminal's upstream_origin really is loopback.
"""

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

# Three environment-dependent values. Defaults are the standard install locations on the author's machine; override with env vars on another machine.
PY3 = os.environ.get("HB_PY3", "/Library/Developer/CommandLineTools/usr/bin/python3")
REAL_CLI = os.environ.get(
    "HB_REAL_CLI",
    "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe")
# Read definition canonical hash, signed after field-by-field review on 2026-08-09.
# This only **references** it; the script grants no approval itself. Canonical copy:
# tests/baselines/read-definition-loopback_dummy.json's reviewed_definition_sha256.
# 🔴 **No default value, on purpose.** This is "the approval value somebody signed
# after reviewing a specific CLI version's specific tool definition field by field" — it is bound to the bytes;
# on a different CLI version or a different reviewer, it must not be inherited.
# Shipping a default would do a review on the reader's behalf that they never did.
# Capture it yourself: `python3 tests/capture_tool_baseline.py`, review field by field, then fill in the hash:
#     export HB_REVIEWED_READ_SHA256=<the value you yourself reviewed>
REVIEWED_READ_SHA256 = os.environ.get("HB_REVIEWED_READ_SHA256", "")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    if not REVIEWED_READ_SHA256:
        print("ABORT: HB_REVIEWED_READ_SHA256 is not set.")
        print("       this cell must use a tool-definition hash **you reviewed yourself** as the upper bound, not someone else's.")
        print("       first run tests/capture_tool_baseline.py to capture one, review it field by field, then export.")
        return 2
    if not os.path.exists(REAL_CLI):
        print(f"ABORT: real CLI not found at {REAL_CLI} (override with HB_REAL_CLI)")
        return 2
    # Prove this shell can really apply seatbelt (same one as seatbelt_six)
    rc = subprocess.run([  "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)",
                           "/usr/bin/true"], capture_output=True).returncode
    if rc != 0:
        print("ABORT: this shell cannot run under Seatbelt (an outer sandbox already exists). G6 must run in a normal local shell.")
        return 2

    # realpath: on macOS tempfile gives /var/folders/…, while /var is a symlink to /private/var.
    # Preflight requires declared paths to match realpath verbatim (correct — that gate exists to stop
    # workspaces being pointed elsewhere via symlinks), so the fixture resolves first instead of loosening the gate.
    root = os.path.realpath(tempfile.mkdtemp(prefix="hb-g6-"))
    port = free_port()
    ws = os.path.join(root, "ws"); os.makedirs(ws, 0o700)
    home = os.path.join(root, "home"); os.makedirs(home, 0o700)
    inp = os.path.join(root, "in"); os.makedirs(inp, 0o700)
    with open(os.path.join(inp, "sentinel.txt"), "w") as f:
        f.write("S\n")

    ver = subprocess.run([REAL_CLI, "--version"], capture_output=True, text=True).stdout.strip()
    prof = RA.base_profile(ws, home, f"http://127.0.0.1:{port}", inp)
    prof.update(cli_realpath=REAL_CLI, cli_sha256=lib.sha256_file(REAL_CLI),
                cli_version=ver, auth_mode="loopback_dummy", timeout_seconds=90)
    # 🔴 base_profile defaults to disabled (that's for fake_cli).
    #    These two tests **are** testing the sandbox, so it must be enabled explicitly — otherwise
    #    they pass quietly with no sandbox at all, the worst kind of fake evidence.
    prof["sandbox"] = "required"
    # `base_profile`'s approved_tools carries the Read definition hash that **fake_cli** would send;
    # the real CLI's doesn't match → upper-bound gate blocks (that's how round one of G6 went policy_blocked,
    # and the gate was right). Here it's replaced with the value signed on 2026-08-09.
    # 🔴 Note this **references an already-signed approval**, not one this script invents:
    #    measured: CLI 2.1.226 → 2.1.232 changed the Read definition canonical hash not one bit,
    #    still 76184d62… (that's what this round's inspector.jsonl observed).
    #    Only cli_sha256 changed (the binary itself), so that's the cell the production profile needs updated.
    prof["approved_tools"] = [{"name": "Read", "definition_sha256": REVIEWED_READ_SHA256}]
    pp = os.path.join(root, "profile.json")
    with open(pp, "w") as f:
        json.dump(prof, f, ensure_ascii=False, indent=1)
    mp = os.path.join(root, "manifest.json")
    with open(mp, "w") as f:
        json.dump({"read-shadow-test": {"path": pp, "sha256": lib.sha256_file(pp)}}, f, indent=1)

    sb = os.path.join(root, "sandbox-copy")
    build_report = lib.build_sandbox(sb, mp)
    # Byte-for-byte confirm the copy's hb-read.sb is the production one — the copy must run the rules under test.
    prod_sb = lib.sha256_file(os.path.join(WRAPPER, "sandbox", "hb-read.sb"))
    copy_sb = lib.sha256_file(os.path.join(sb, "sandbox", "hb-read.sb"))
    if prod_sb != copy_sb:
        print(f"ABORT: the sandbox profile in the copy differs from production\n  prod={prod_sb}\n  copy={copy_sb}")
        return 2

    # `base_profile`'s output_schema_sha256 is the **all-zero placeholder** (use cases fill it in for fake_cli).
    # The real CLI's output key set never matches all-zero → schema_failed.
    # So G6 runs two passes: pass one only observes the real CLI's output schema; pass two does the grading.
    # 🔴 This observed value is **UNREVIEWED**, lives only inside this disposable test fixture,
    #    and is never written back to the production profile — treating a field observation as approval is TOFU,
    #    ruled so once by external review on 2026-08-08 (`read-shadow-real` was pulled from the manifest for it).
    #    Production's cell is aa3150c0… (captured at 2.1.226); whether to re-capture and re-sign on CLI upgrades is the owner's call.
    mock = subprocess.Popen(
        [PY3, os.path.join(HERE, "loop_mock.py"), "--port", str(port),
         "--runs", os.path.join(sb, "runs")],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ready = mock.stdout.readline()
    if not ready.startswith("READY"):
        print(f"ABORT: loop_mock failed to start: {ready!r}")
        mock.kill()
        return 2

    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                        "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR")}
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"

    def one_pass():
        return subprocess.run(["/bin/zsh", os.path.join(sb, "hb-run.sh"), "read-shadow-test",
                               "read the sentinel"],
                              cwd=sb, env=env, capture_output=True, text=True, timeout=300)

    def newest_attempt():
        rd = os.path.join(sb, "runs")
        ds = [os.path.join(rd, d) for d in os.listdir(rd)] if os.path.isdir(rd) else []
        ds = [d for d in ds if os.path.exists(os.path.join(d, "terminal.json"))]
        return max(ds, key=os.path.getmtime) if ds else None

    t0 = time.time()
    # Pass one: observe the real CLI's output schema
    run = one_pass()
    observed_schema = None
    probe_dir = newest_attempt()
    if probe_dir and os.path.exists(os.path.join(probe_dir, "model.json")):
        sys.path.insert(0, WRAPPER)
        import finish  # noqa: PLC0415
        try:
            doc = json.load(open(os.path.join(probe_dir, "model.json")))
            # 🔴 What gets verified is not the CLI's output document itself, but the JSON **after
            #    the challenge line in the model reply body** (finish.py:138-148).
            #    The first version hashed the whole model.json and got a plausible-looking
            #    hash of entirely the wrong object — of course it still schema_failed when filled back in.
            #    This copies finish's extraction verbatim so there isn't a second truth.
            result = str(doc.get("result", ""))
            lines_after_first = [l for l in result.splitlines()[1:] if l.strip()]
            payload = None
            if lines_after_first:
                try:
                    payload = json.loads("\n".join(lines_after_first))
                except Exception:
                    payload = None
            observed_schema = finish.schema_identity(payload)
        except Exception:
            observed_schema = None

    if observed_schema:
        prof["output_schema_sha256"] = observed_schema
        with open(pp, "w") as f:
            json.dump(prof, f, ensure_ascii=False, indent=1)
        # The profile changed, so the manifest's sha256 must be recomputed or preflight calls it profile drift
        with open(mp, "w") as f:
            json.dump({"read-shadow-test": {"path": pp, "sha256": lib.sha256_file(pp)}}, f, indent=1)
        shutil.copy2(mp, os.path.join(sb, "profiles", "manifest.json"))
        # Pass two: the grading pass
        run = one_pass()
    elapsed = round(time.time() - t0, 1)
    mock.kill()

    # ── Grading: only the on-disk terminal counts, not what hb-run printed ─────────────
    adirs = sorted((os.path.join(sb, "runs", d) for d in os.listdir(os.path.join(sb, "runs"))),
                   key=os.path.getmtime) if os.path.isdir(os.path.join(sb, "runs")) else []
    terminal = None
    for d in reversed(adirs):
        tp = os.path.join(d, "terminal.json")
        if os.path.exists(tp):
            terminal = json.load(open(tp))
            terminal["_dir"] = d
            break

    checks = {}
    if terminal is None:
        checks["terminal_exists"] = False
    else:
        adir = terminal["_dir"]
        insp = [json.loads(l) for l in open(os.path.join(adir, "inspector.jsonl"))
                if l.strip()] if os.path.exists(os.path.join(adir, "inspector.jsonl")) else []
        events = [json.loads(l) for l in open(os.path.join(adir, "events.jsonl"))
                  if l.strip()]
        checks = {
            "terminal_exists": True,
            # ① The sandbox really applied: ready/exec/start actual-byte hashes must close against the production hashes
            "sandbox_applied": terminal.get("sandbox", {}).get("applied") is True,
            "sandbox_apply_failed": terminal.get("sandbox", {}).get("apply_failed") is False,
            "sandbox_hashes_match": terminal.get("sandbox", {}).get("hashes_match") is True,
            "sandbox_hash_recorded":
                bool(terminal.get("sandbox", {}).get("profile_sha256")),
            "sandbox_hash_matches_production":
                terminal.get("sandbox", {}).get("profile_sha256") == prod_sb,
            # ② intent and inner bootstrap/exec fact are recorded separately; both must exist
            "cli_exec_attempted": any(e.get("event") == "cli_exec_attempted" for e in events),
            "cli_started": any(e.get("event") == "cli_started"
                               and e.get("inner_bootstrap_handshake") is True for e in events),
            "outcome_success": terminal.get("outcome") == "success",
            "exit_zero": terminal.get("exit_code") == 0,
            # ③ The sentinel was really read — this cell is the line loop_mock's selfcert red arm guards
            "requests_made": terminal.get("request_count", 0) > 0,
            "tool_use_seen": any(r.get("decision") == "forward" for r in
                                 terminal.get("requests", [])),
            # ④ Zero API: upstream must be loopback
            "upstream_is_loopback":
                terminal.get("upstream_origin", "").startswith("http://127.0.0.1:"),
        }
        checks["_inspector_records"] = len(insp)

    hard = {k: v for k, v in checks.items() if not k.startswith("_")}
    ok = all(hard.values())

    out = {
        "cell": "G6",
        "desc": "real Claude Code starts inside Seatbelt, completes the sentinel Read, streams back, exits normally",
        "cli_version": ver,
        "elapsed_seconds": elapsed,
        "sandbox_profile_sha256": prod_sb,
        "observed_output_schema_sha256_UNREVIEWED": observed_schema,
        "topology": "test (read-shadow-test + loop_mock)",
        "why_not_production_profile":
            "the production profile pins CLI 2.1.226, this machine is already on 2.1.232, and preflight correctly REJECTs."
            "re-capturing and re-signing is the owner's action, outside this script's scope.",
        "checks": checks,
        "hb_run_stdout_tail": run.stdout[-1500:],
        "hb_run_stderr_tail": run.stderr[-1500:],
        "terminal_outcome": (terminal or {}).get("outcome"),
        "terminal_dir": (terminal or {}).get("_dir"),
        "verdict": "G6_PASS" if ok else "G6_FAIL",
    }

    dest = os.path.join(WRAPPER, "runs", "seatbelt",
                        f"g6-{time.strftime('%Y%m%dT%H%M%S')}")
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "g6.json"), "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    if terminal:
        shutil.copytree(terminal["_dir"], os.path.join(dest, "attempt"), dirs_exist_ok=True)

    for k, v in checks.items():
        if not k.startswith("_"):
            print(f"  [{'ok ' if v else 'BAD'}] {k}")
    print(f"\n{out['verdict']}  ({elapsed}s, CLI {ver})")
    print(f"artifact: {dest}/g6.json")
    if not ok:
        print("\n--- hb-run stderr tail ---")
        print(run.stderr[-1200:])
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
