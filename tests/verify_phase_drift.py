#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent grader for the two dummy-Keychains phase-drift cases.

★2026-08-09. A6b wrote down these two definitions; A8 ruled "**not done**: they are
still only static definitions". A definition is not an executor — a case nobody runs
and a case that doesn't exist look the same in acceptance artifacts.

What it judges is the same thing in two places: under `loopback_dummy`, "no
Library/Keychains in the dedicated HOME" **isn't settled by one check before the run**;
all three phases must hold.

  · `before_ready` arm: the trusted fake inspector creates an absolute symlink between
    process start and the READY print → `pre_cli` must reject, and must **not spawn the
    CLI**, with upstream delta 0.
  · `after_spawn` arm: the trusted fake CLI first completes a protocol byte-identical
    with the positive case and creates the symlink **before exiting** → `post_cli` must
    re-judge the otherwise-successful attempt as `config_rejected`.

🔴 Grading discipline:
  ① **Read no self-reported verdict fields.** Phase outcomes are recomputed from
     `SNAPSHOT_OK` / `SNAPSHOT_TAMPERED` in `verify.log` / the event streams; whoever
     says it passed is ignored.
  ② Changes must have **independent attribution** evidence: the pid in the mutation
     evidence must equal the pid in that process's own process evidence, and
     writer_sha256 must equal the fixture file's real hash. Otherwise "who changed it"
     is a guess.
  ③ The failure path must **not clean up the scene**: after the run the symlink must
     still be there and match the mutation record.

    verify_phase_drift.py <attempt_dir> --arm before_ready|after_spawn ...
"""
import argparse
import hashlib
import json
import os
import sys

FAILS = []
NOTES = []


def need(ok, msg, detail=""):
    if not ok:
        FAILS.append(f"{msg}" + (f" —— {detail}" if detail else ""))
    else:
        NOTES.append(f"✔ {msg}" + (f"({detail})" if detail else ""))


def sha_file(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def load(path, what):
    if not os.path.exists(path):
        FAILS.append(f"missing {what}: {os.path.basename(path)}")
        return None
    try:
        return json.load(open(path))
    except Exception as e:                                   # noqa: BLE001
        FAILS.append(f"{what} unreadable: {type(e).__name__}")
        return None


def read_events(adir):
    """Events are scattered across two files: `events.jsonl` is written by the shell,
    `inspector.jsonl` by the inspector itself (`inspector_ready` lives in the latter).
    **Read both** — reading only one makes "the event never happened" look identical
    to "I looked in the wrong place"."""
    rows = []
    for name in ("events.jsonl", "inspector.jsonl"):
        p = os.path.join(adir, name)
        if not os.path.exists(p):
            continue
        for line in open(p):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:                            # noqa: BLE001
                    pass
    return rows


def phase_results(adir):
    """Recompute each phase's verdict. **Read no self-reported summary fields.**

    ⚠️ The three phases' verdicts are not in the same file: the `post_cli` hb-run was
    redirected into `verify.log`, while the `pre_inspector`/`pre_cli` runs went straight
    onto hb-run's own stdout (persisted by the harness verbatim as `hb-run.out`). The
    first version read only verify.log, so the first two phases were always None —
    that was **the grader looking in the wrong place**, masquerading as "those two
    phases never ran".
    """
    text = ""
    for name in ("verify.log", "hb-run.out"):
        p = os.path.join(adir, name)
        if os.path.exists(p):
            text += open(p, errors="replace").read() + "\n"
    out = {}
    for line in text.splitlines():
        line = line.strip()
        for token, verdict in (("SNAPSHOT_OK", "pass"), ("SNAPSHOT_TAMPERED", "reject")):
            if line.startswith(token):
                for part in line.split():
                    if part.startswith("phase="):
                        out.setdefault(part[6:], []).append(verdict)
    return out, text


def protocol_projection(adir):
    """Project only comparable fields from the protocol artifacts; never read the fixture's completed_* self-reports."""
    rows = read_events(adir)
    reqs = [r for r in rows if r.get("event") == "request"]
    scans = [r for r in rows if r.get("event") == "response_scan_terminal"]
    uses = [r for r in rows if r.get("event") == "tool_use_seen"]
    results = [r for r in rows if r.get("event") == "tool_result_seen"]
    terminal = load(os.path.join(adir, "terminal.json"), "terminal.json") or {}
    model = load(os.path.join(adir, "model.json"), "model.json") or {}
    result_text = model.get("result") if isinstance(model.get("result"), str) else ""
    result_lines = result_text.splitlines()
    normalized_model = dict(model)
    if result_lines:
        normalized_model["result"] = "<CHALLENGE>\n" + "\n".join(result_lines[1:])
    projection = {
        "requests": [{k: r.get(k) for k in (
            "tool_names", "tool_definition_hashes", "decision", "upstream_status",
            "upstream_error", "response_complete", "request_stream")}
                     for r in reqs],
        "scans": [{k: r.get(k) for k in (
            "required", "format", "outcome", "reason_code", "message_stop_seen",
            "tool_use_count", "unknown_event_count")}
                  for r in scans],
        "uses": [{"name": r.get("name"), "path_match": r.get("path_match")}
                 for r in uses],
        "results": [{"is_error": r.get("is_error"),
                     "contains_challenge": r.get("contains_challenge")}
                    for r in results],
        "required_actions": terminal.get("required_actions"),
        "cli": {k: terminal.get(k) for k in (
            "cli_exit", "cli_timed_out", "cli_is_error", "cli_stop_reason",
            "permission_denials_count", "challenge_first_line", "output_schema_ok")},
        "model": normalized_model,
    }
    facts = {
        "requests": reqs, "scans": scans, "uses": uses, "results": results,
        "terminal": terminal, "events": rows, "projection": projection,
    }
    return facts


def require_positive_protocol(label, adir, wrapper_rc, mock_delta, want_outcome):
    facts = protocol_projection(adir)
    terminal = facts["terminal"]
    attempted = [e for e in facts["events"] if e.get("event") == "attempted"]
    finished = [e for e in facts["events"] if e.get("event") == "finished"]
    need(wrapper_rc == (0 if want_outcome == "success" else 78),
         f"{label}: wrapper rc matches expectation", str(wrapper_rc))
    need(mock_delta == 3, f"{label}: mock_request_delta==3 (really completed the three-request chain)",
         str(mock_delta))
    need(len(facts["requests"]) == 3
         and all(r.get("decision") == "forward" and r.get("upstream_status") == 200
                 and r.get("response_complete") is True for r in facts["requests"]),
         f"{label}: all three requests forward/200/complete")
    need(len(facts["scans"]) == 3
         and all(r.get("outcome") == "ok" for r in facts["scans"]),
         f"{label}: all three response scans independently closed as ok")
    use_ids = [r.get("tool_use_id") for r in facts["uses"]]
    result_ids = [r.get("tool_use_id") for r in facts["results"]]
    need(len(use_ids) == 1 and result_ids == use_ids
         and facts["uses"][0].get("path_match") is True
         and facts["results"][0].get("is_error") is False
         and facts["results"][0].get("contains_challenge") is True,
         f"{label}: single tool_use/result id pair with path/challenge holding")
    actions = terminal.get("required_actions") or []
    need(len(actions) == 1 and actions[0].get("causal_evidence") is True,
         f"{label}: required action causal evidence is true")
    need(terminal.get("challenge_first_line") is True
         and terminal.get("output_schema_ok") is True,
         f"{label}: challenge first line and output schema both pass")
    need(terminal.get("outcome") == want_outcome,
         f"{label}: terminal.outcome=={want_outcome}", str(terminal.get("outcome")))
    need(len(attempted) == 1 and len(finished) == 1,
         f"{label}: attempted/finished counts are both 1",
         f"{len(attempted)}/{len(finished)}")
    return facts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("attempt_dir")
    ap.add_argument("--arm", choices=["before_ready", "after_spawn"], required=True)
    ap.add_argument("--home", required=True)
    ap.add_argument("--fixture-root", required=True)
    ap.add_argument("--fake-cli", required=True)
    ap.add_argument("--fake-inspector", required=True)
    ap.add_argument("--wrapper-rc", type=int, required=True)
    ap.add_argument("--mock-delta", type=int, required=True)
    ap.add_argument("--initial-absent", required=True)
    ap.add_argument("--control-attempt-dir")
    ap.add_argument("--control-wrapper-rc", type=int)
    ap.add_argument("--control-mock-delta", type=int)
    a = ap.parse_args()

    adir = a.attempt_dir
    target = os.path.join(a.home, "Library", "Keychains")

    need(a.initial_absent == "1", "initial Library/Keychains is absent (dummy-branch precondition)")

    phases, vlog = phase_results(adir)
    events = read_events(adir)
    terminal = load(os.path.join(adir, "terminal.json"), "terminal.json") or {}

    # ── The change really happened, and **that process** did it ──
    if a.arm == "before_ready":
        mut = load(os.path.join(adir, "auth-mutation-by-inspector.json"), "inspector mutation evidence")
        proc = load(os.path.join(adir, "inspector-process-evidence.json"), "inspector process evidence")
        actor, writer = "fake_inspector", a.fake_inspector
        need(bool(mut) and mut.get("completed_before_ready") is True,
             "change completed before READY (barrier is structural, not a timing race)")
        need(bool(mut) and mut.get("completed_after_inspector_entry") is True,
             "change completed after the inspector process entered")
    else:
        mut = load(os.path.join(adir, "auth-mutation-by-cli.json"), "cli mutation evidence")
        proc = load(os.path.join(adir, "cli-process-evidence.json"), "cli process evidence")
        actor, writer = "fake_cli", a.fake_cli
        need(bool(mut) and mut.get("completed_before_cli_exit") is True,
             "change completed before CLI exit")
        started = load(os.path.join(adir, "cli-started.json"), "cli-started.json")
        need(bool(started), "cli_marker_count==1 (CLI was really spawned)")

    if mut and proc:
        need(mut.get("actor") == actor, f"mutation actor is {actor}")
        need(mut.get("pid") == proc.get("pid"),
             "mutation pid matches that process's self-reported process evidence",
             f"{mut.get('pid')} vs {proc.get('pid')}")
        need(mut.get("writer_sha256") == sha_file(writer),
             "mutation writer_sha256 equals the fixture file's real hash (not its own claim)")
        need((mut.get("after") or {}).get("readlink_is_absolute") is True,
             "what was created is an **absolute** symlink")
        link = (mut.get("after") or {}).get("readlink") or ""
        need(os.path.abspath(link).startswith(os.path.abspath(a.fixture_root) + os.sep),
             "symlink points inside the marked fixture root", link)

    # ── Did the gate bite? ──
    need(phases.get("pre_inspector") == ["pass"],
         "pre_inspector recheck passed (start was clean)", str(phases.get("pre_inspector")))
    hit = "pre_cli" if a.arm == "before_ready" else "post_cli"
    need(phases.get(hit) == ["reject"],
         f"{hit} recheck **rejected** (drift caught)", str(phases.get(hit)))
    if a.arm == "after_spawn":
        need(phases.get("pre_cli") == ["pass"],
             "pre_cli still passes (drift happened after it, must not bite early)", str(phases.get("pre_cli")))

        need(bool(a.control_attempt_dir), "after_spawn carries a no-drift control attempt")
        if a.control_attempt_dir:
            control = require_positive_protocol(
                "no-drift control", a.control_attempt_dir, a.control_wrapper_rc,
                a.control_mock_delta, "success")
            mutant = require_positive_protocol(
                "trailing-drift arm", adir, a.wrapper_rc, a.mock_delta, "config_rejected")
            need(control["projection"] == mutant["projection"],
                 "non-mutation protocol fields of both arms match field by field")
            c_phases, _ = phase_results(a.control_attempt_dir)
            need(c_phases.get("pre_inspector") == ["pass"]
                 and c_phases.get("pre_cli") == ["pass"]
                 and c_phases.get("post_cli") == ["pass"],
                 "no-drift control passes all three phases", str(c_phases))
            need(not os.path.lexists(os.path.join(
                control["terminal"].get("home_realpath", ""), "Library", "Keychains")),
                "Keychains still absent after the no-drift control")
            # Independent timing evidence: the mutation file was created only **after
            # the full protocol log closed**. inspector.jsonl is an independent
            # observation written by the inspector process, not the mutation actor's
            # own completed_after_* booleans — that's the value of this assertion.
            #
            # 🔴 2026-08-15 (A15 ruling, REPORT-A15.md §Q1 red ②): model.json's mtime
            #    **cannot** be used as the anchor for "CLI output has landed" anymore;
            #    that half is deleted. The reason is structural, not a race: the fake
            #    CLI prints+flushes before exiting, and the bytes only reach
            #    sandbox_launcher's pipe; the launcher uses `proc.communicate()` in
            #    `run_child()` to get the complete stdout only **after** the child
            #    exits, and writes it out at `sandbox_launcher.py:288-291`, while the
            #    redirect target of hb-run.sh:209-224 is model.json. So model.json's
            #    final mtime is **necessarily** later than "the mutation before exit" —
            #    this condition can never hold.
            #    Measured over two rounds: mutation predates model.json by 3,487,743ns
            #    / 3,379,035ns, while lagging inspector.jsonl by 341,624ns / 331,458ns.
            #    ⚠️ This assertion itself dates to 08-09; A14 didn't change it — it was
            #       A14 turning the launcher into buffer-then-write that invalidated
            #       its premise. Don't add model.json back.
            #    ⚠️ If the stronger property "mutation only after stdout was
            #       independently observed" is ever wanted, no CLI-written file may
            #       substitute: the parent observer must write a receipt with a content
            #       hash after reading the complete stdout, then release the mutation
            #       with an independent ack. That's an enhancement, not a necessary
            #       condition of this arm's semantics.
            mut_path = os.path.join(adir, "auth-mutation-by-cli.json")
            insp_path = os.path.join(adir, "inspector.jsonl")
            if all(os.path.exists(p) for p in (mut_path, insp_path)):
                mut_mtime = os.stat(mut_path).st_mtime_ns
                need(mut_mtime >= os.stat(insp_path).st_mtime_ns,
                     "mutation is later than the full three-request/three-scan protocol log closure")

    need(a.wrapper_rc == 78, "wrapper exit code 78", str(a.wrapper_rc))
    need(terminal.get("outcome") == "config_rejected",
         "terminal.outcome==config_rejected", str(terminal.get("outcome")))
    finished = [e for e in events if e.get("event") == "finished"]
    attempted = [e for e in events if e.get("event") == "attempted"]
    need(len(attempted) == 1, "attempted_count==1", str(len(attempted)))
    need(len(finished) == 1, "finished_count==1", str(len(finished)))

    if a.arm == "before_ready":
        ready = [e for e in events if e.get("event") == "inspector_ready"]
        need(len(ready) == 1, "exactly one inspector_ready", str(len(ready)))
        need(not os.path.exists(os.path.join(adir, "cli-started.json")),
             "🔴 cli_marker_count==0 -- no CLI spawned **after** catching the drift")
        need(a.mock_delta == 0, "mock_request_delta==0", str(a.mock_delta))

    # ── The failure path must not clean up the scene ──
    need(os.path.islink(target), "symlink still there after the run (failure path did not alter the scene)")
    if os.path.islink(target) and mut:
        need(os.readlink(target) == (mut.get("after") or {}).get("readlink"),
             "post-run readlink matches the mutation record byte for byte")

    for n in NOTES:
        print(n)
    for f in FAILS:
        print("✘", f)
    if FAILS:
        print(f"\nPHASE_DRIFT_{a.arm.upper()} BROKEN={len(FAILS)}")
        print("phase verdict source text: " + " | ".join(
            l.strip() for l in vlog.splitlines() if "SNAPSHOT" in l)[:400])
        return 1
    print(f"\nPHASE_DRIFT_{a.arm.upper()} OK ({len(NOTES)} items)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
