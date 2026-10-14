#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attempt wrap-up: after freezing the inspector, **recompute** terminal.json from events.

spec:310 — terminal is a summary recomputed from events, not anyone's self-reported conclusion.
This is the same move verify_acceptance.py makes on the acceptance script:
**what the party under test says about itself doesn't count; recompute it from the traces it left.**

Lower-bound judgement (spec:85-110): per attempt, guard "what had to be done was really done, and the result holds".
The upper bound is guarded by the inspector before forwarding; here we only re-check its traces. The lower bound has to be judged here,
because it is a property of the **whole run**, not keyed to request number, so it never needs to know which request was the model's turn.

outcome priority (spec:326):
    config_rejected > inspector_failed/policy_blocked > timeout/cli_failed
    > obligation_failed/schema_failed/postcondition_failed > success
🔴 As long as the inspector has a blocked, it must **not** be overridden by a non-zero CLI exit into a plain cli_failed —
   "it failed on its own too" does not make "the out-of-scope attempt" stop counting.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time

PRIORITY = ["config_rejected", "inspector_failed", "policy_blocked", "timeout",
            "cli_failed", "obligation_failed", "schema_failed",
            "postcondition_failed", "success"]

def real_home():
    """The real user home directory. Uses getpwuid rather than $HOME — these processes are started with `env -i`,
    so there is no HOME in the environment at all; and this value must match "who is running", not be rewritable by the environment."""
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser("~")


# ── This deployment's state invariants (the only deployment-specific list in this repo) ──────────────
# After a run, these files must be byte-for-byte unchanged — one of the wrapper's postconditions.
# Replace them with your own; paths are relative to the **real user home directory**.
# 🔴 Empty = check no state = this whole postcondition is switched off, **and it raises no error**.
STATE_INVARIANT_NAMES = [
    ".claude-heartbeat-log.jsonl",
    ".claude-heartbeat-armed.json",
    ".claude-heartbeat-armed-events.jsonl",
    ".claude-nudge-state.json",
    ".claude-heartbeat-items.json",
]

STATE_TARGETS = [os.path.join(real_home(), n) for n in STATE_INVARIANT_NAMES]


def sha_file(path):
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return "NOT_REGULAR"
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "ABSENT"


def snapshot_state():
    """Record only hash and size; never copy any private content (spec:328)."""
    out = {}
    for p in STATE_TARGETS:
        h = sha_file(p)
        try:
            out[p] = {"sha256": h, "size": os.stat(p).st_size}
        except OSError:
            out[p] = {"sha256": h}
    out["heartbeat_room_snapshot"] = {
        "status": "unmeasured",
        "reason": "spec:337 — no trusted room id, so no guessing; this cell is not judged before phase 1"}
    return out


def read_jsonl(path):
    rows = []
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    rows.append({"_unparseable": True})
    return rows


def schema_identity(doc):
    """Identity of the output schema: the canonical hash of the set of key names.

    Pin only the shape, not the values — the values differ every run (the challenge is random),
    and pinning the values would require the model to parrot a constant, which tests nothing.
    """
    if not isinstance(doc, dict):
        return None
    canon = json.dumps(sorted(doc.keys()), separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def judge_lower_bound(plan, insp_rows, cli_doc):
    """Lower bound for the whole run. Returns (ok, obligations, notes)."""
    challenge = plan["challenge"]
    notes = {}

    tool_uses = [r for r in insp_rows if r.get("event") == "tool_use_seen"]
    tool_results = [r for r in insp_rows if r.get("event") == "tool_result_seen"]

    obligations = []
    for act in plan["required_actions"]:
        if act["tool"] != "Read":
            obligations.append({"id": act["id"], "observed": 0, "success": 0,
                                "causal_evidence": False,
                                "why": f"unsupported tool {act['tool']!r}"})
            continue
        # Observed: the name is right, **and what it read is this run's sentinel path**
        matched = [u for u in tool_uses
                   if u.get("name") == "Read" and u.get("path_match") is True]
        ok_ids = set()
        for u in matched:
            uid = u.get("tool_use_id")
            # Causal evidence: the result for the same tool_use_id, not an error, and **its content carries this run's challenge**
            for r in tool_results:
                if r.get("tool_use_id") != uid:
                    continue
                if r.get("is_error"):
                    continue
                if not r.get("contains_challenge"):
                    continue
                ok_ids.add(uid)
        obligations.append({
            "id": act["id"],
            "observed": len(matched),
            "success": len(ok_ids),
            "min_success": act["min_success"],
            # 🔴 Causal evidence = tool_use and tool_result are tied together by **the same id**.
            # "There was one successful Read" is not enough: that could be the result of a different call.
            "causal_evidence": len(ok_ids) >= act["min_success"],
        })

    # The challenge must be on the first line of the final output (spec:373) — prevents "paste a fixed value at the end"
    result = str((cli_doc or {}).get("result", ""))
    first_line = result.splitlines()[0].strip() if result.strip() else ""
    notes["challenge_first_line"] = (first_line == challenge)
    notes["challenge_present_anywhere"] = challenge in result

    # Final JSON shape
    payload = None
    lines = [l for l in result.splitlines()[1:] if l.strip()]
    if lines:
        try:
            payload = json.loads("\n".join(lines))
        except Exception:
            payload = None
    got_schema = schema_identity(payload)
    notes["output_schema_sha256_actual"] = got_schema
    notes["output_schema_ok"] = (got_schema == plan["output_schema_sha256"])

    denials = (cli_doc or {}).get("permission_denials") or []
    notes["permission_denials_count"] = len(denials)

    ok = (all(o["causal_evidence"] for o in obligations)
          and notes["challenge_first_line"]
          and notes["output_schema_ok"]
          and len(denials) == 0)
    return ok, obligations, notes


def main():
    if len(sys.argv) != 6:
        print("usage: finish.py <attempt_dir> <cli_exit> <timed_out:0|1> "
              "<inspector_exit> <cli_stdout_path>", file=sys.stderr)
        return 64
    adir, cli_exit, timed_out, insp_exit, cli_out = sys.argv[1:6]
    cli_exit = int(cli_exit); timed_out = timed_out == "1"

    plan = json.load(open(os.path.join(adir, "plan.json")))
    events = read_jsonl(os.path.join(adir, "events.jsonl"))
    insp_rows = read_jsonl(os.path.join(adir, "inspector.jsonl"))

    if any(e.get("event") == "finished" for e in events):
        print("finish: a finished event already exists; not writing it again", file=sys.stderr)
        return 0

    reqs = [r for r in insp_rows if r.get("event") == "request"]
    blocked = [r for r in reqs if r.get("decision") == "block"]
    # 🔴 2026-08-08, a gap exposed by lb-postcondition-false: previously only upstream_error
    # (exception / redirect / incomplete response) counted as bad, **non-2xx status codes did not**. So "every model call returns 500,
    # while the CLI still prints a nice-looking result" would be judged a success — the same shape again as "never trust self-reports".
    upstream_bad = [r for r in reqs
                    if r.get("upstream_error")
                    or (r.get("decision") == "forward"
                        and isinstance(r.get("upstream_status"), int)
                        and not (200 <= r["upstream_status"] < 300))]
    incomplete = [r for r in reqs if r.get("decision") == "forward"
                  and not r.get("response_complete")]

    cli_doc = None
    if os.path.exists(cli_out):
        try:
            cli_doc = json.load(open(cli_out))
        except Exception:
            cli_doc = None

    ready = [r for r in insp_rows if r.get("event") == "inspector_ready"]
    inspector_failed = (not ready) or (insp_exit not in ("0", "-15", "143", "None"))

    # ── Closure result of the response scan (★2026-08-08 external review A7) ────────────────────
    # This section separates two things that previously looked the same:
    #   · "Scanned completely, and there really is no tool use in the response" → obligation_failed (the model didn't do it)
    #   · "The observer did not understand this response"                    → inspector_failed (we are not entitled to judge)
    # The real subscription call on 2026-08-08 was the latter misreported as the former: the model had in fact read the sentinel;
    # the scanner couldn't understand the streaming response. Failing closed was right, but **the cause was misattributed**.
    scan_terms = [r for r in insp_rows if r.get("event") == "response_scan_terminal"]
    forwarded_2xx = [r for r in reqs
                     if r.get("decision") == "forward"
                     and isinstance(r.get("upstream_status"), int)
                     and 200 <= r["upstream_status"] < 300]
    scan_by_req = {}
    for r in scan_terms:
        scan_by_req.setdefault(r.get("request_id"), []).append(r)
    scan_problems = []
    for r in forwarded_2xx:
        rows = scan_by_req.get(r.get("request_id")) or []
        if len(rows) != 1:
            scan_problems.append({"request_id": r.get("request_id"),
                                  "problem": f"terminal row count {len(rows)}, exactly 1 required"})
        elif rows[0].get("outcome") != "ok":
            scan_problems.append({"request_id": r.get("request_id"),
                                  "problem": "scan_failed",
                                  "reason_code": rows[0].get("reason_code")})
    scan_ok = not scan_problems
    total_tool_use = sum(int(r.get("tool_use_count") or 0)
                         for rows in scan_by_req.values() for r in rows)

    # ── The three closing phases of the snapshot/bridge re-check (external review A4 §2) ──────────────
    # "How many cells there should be" is not a constant; it depends on how far this run got. The lifecycle basis is
    # the pre-spawn cli_exec_attempted: it holds the line against "tried to start but not in the ledger";
    # cli_started is proven separately by the inner bootstrap/exec handshake, and intent must not pass for fact.
    ALL_PHASES = ["pre_inspector", "pre_cli", "post_cli"]
    verified_phases = [e.get("phase") for e in events
                       if e.get("event") == "snapshot_verified"]
    tampered_phases = [e.get("phase") for e in events
                       if e.get("event") == "snapshot_tampered"]
    cli_exec_attempted = any(e.get("event") == "cli_exec_attempted" for e in events)
    cli_started = any(e.get("event") == "cli_started"
                      and e.get("inner_bootstrap_handshake") is True for e in events)
    required_phases = ALL_PHASES if cli_exec_attempted else ["pre_inspector"]
    missing_phases = [p for p in required_phases if p not in verified_phases]

    sandbox_mode = plan.get("sandbox_mode")
    sandbox_expected_sha = plan.get("hashes", {}).get("sandbox_profile")
    ready_events = [e for e in events if e.get("event") == "sandbox_ready"]
    exec_events = [e for e in events if e.get("event") == "cli_exec_attempted"]
    started_events = [e for e in events if e.get("event") == "cli_started"
                      and e.get("inner_bootstrap_handshake") is True]
    ready_sha = ready_events[-1].get("profile_sha256") if len(ready_events) == 1 else None
    exec_sha = exec_events[-1].get("profile_sha256") if len(exec_events) == 1 else None
    started_sha = started_events[-1].get("profile_sha256") if len(started_events) == 1 else None
    sandbox_hashes_match = (
        sandbox_mode == "required"
        and len(ready_events) == len(exec_events) == len(started_events) == 1
        and ready_sha == exec_sha == started_sha == sandbox_expected_sha
    )
    sandbox_applied = sandbox_hashes_match and cli_started

    lb_ok, obligations, notes = judge_lower_bound(plan, insp_rows, cli_doc)

    # ── outcome: take the first that holds, in priority order ──
    candidates = []
    # The snapshot was modified after preflight — highest priority, equivalent to the config being rejected:
    # what the CLI consumed this run is no longer the verified copy, so every later judgement has lost its premise.
    if tampered_phases:
        candidates.append("config_rejected")
    # A missing re-check cell — a different shape from "checked and fine". Bridge drift ranks with snapshot drift,
    # both are config_rejected, **ahead of any CLI result**: however good the CLI run looks,
    # its premise (what it read is the verified copy) can no longer be proven by anyone.
    if missing_phases:
        candidates.append("config_rejected")
    # A Seatbelt apply/identity failure is **not** a CLI failure. A required attempt counts as applied only when the ready,
    # exec-attempt and inner-start events each appear exactly once and the actual policy hash equals
    # the plan hash; a missing handshake, duplicate/missing events, or a hash mismatch all fail closed.
    sandbox_failed = any(e.get("event") == "sandbox_apply_failed" for e in events)
    if sandbox_failed or (sandbox_mode == "required"
                          and cli_exec_attempted and not sandbox_applied):
        candidates.append("config_rejected")
    if inspector_failed:
        candidates.append("inspector_failed")
    # 🔴 Scan not closed = the observer didn't understand = we have no evidence with which to judge the lower bound.
    # It must rank ahead of obligation_failed — otherwise an observer that can't understand
    # would record every run as "the model didn't do it", exactly the misdiagnosis of 08-08.
    if scan_problems:
        candidates.append("inspector_failed")
    if blocked:
        candidates.append("policy_blocked")     # 🔴 before cli_failed
    if timed_out:
        candidates.append("timeout")
    if cli_exit != 0 or cli_doc is None:
        candidates.append("cli_failed")
    if upstream_bad or incomplete:
        candidates.append("postcondition_failed")
    if not lb_ok:
        if not notes["output_schema_ok"]:
            candidates.append("schema_failed")
        else:
            candidates.append("obligation_failed")
    if not candidates:
        candidates.append("success")
    outcome = sorted(candidates, key=PRIORITY.index)[0]

    state_after = snapshot_state()
    state_before = plan.get("state_before") or {}
    changed = [k for k, v in state_before.items()
               if k != "heartbeat_room_snapshot"
               and state_after.get(k, {}).get("sha256") != v.get("sha256")]
    if changed:
        outcome = sorted(candidates + ["postcondition_failed"], key=PRIORITY.index)[0]

    exit_map = {"success": 0, "config_rejected": 78, "inspector_failed": 80,
                "policy_blocked": 81, "timeout": 82, "cli_failed": 83,
                "obligation_failed": 84, "schema_failed": 85,
                "postcondition_failed": 86}

    terminal = {
        "schema_version": 1,
        "attempt_id": plan["attempt_id"],
        "profile_id": plan["profile_id"],
        "started_at": (events[0].get("ts") if events else None),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "outcome": outcome,
        "outcome_candidates": candidates,
        "exit_code": exit_map[outcome],
        "error_type": None if outcome == "success" else outcome,
        "detail": "",
        "trust_boundary": "same-uid processes are inside the TCB; "
                          "this does not resist a hostile same-uid injector",
        "hashes": plan["hashes"],
        # `profile_sha256` is the hash of the actual policy bytes matching the CLI-start handshake,
        # not an expected value copied from the plan. All four cells planned/ready/exec/start are published;
        # `applied` is true only when they close and are equal.
        "sandbox": {
            "mode": sandbox_mode,
            "disabled_event": any(e.get("event") == "sandbox_disabled" for e in events),
            "profile_path": plan.get("sandbox_profile_path"),
            "planned_profile_sha256": sandbox_expected_sha,
            "ready_profile_sha256": ready_sha,
            "exec_profile_sha256": exec_sha,
            "profile_sha256": started_sha,
            "hashes_match": sandbox_hashes_match,
            "ready": len(ready_events) == 1 and ready_sha == sandbox_expected_sha,
            "applied": sandbox_applied,
            "apply_failed": any(e.get("event") == "sandbox_apply_failed" for e in events),
        },
        "inspector_log_sha256": sha_file(os.path.join(adir, "inspector.jsonl")),
        "events_sha256_at_finish": sha_file(os.path.join(adir, "events.jsonl")),
        "workspace_realpath": plan["workspace"],
        "home_realpath": plan["home"],
        "model": plan["model"],
        "timeout_seconds": plan["timeout_seconds"],
        "upstream_origin": plan["upstream_origin"],
        "capability_path_len": len(plan["capability_path"]),
        "inspector_exit": insp_exit,
        "request_count": len(reqs),
        "blocked_count": len(blocked),
        "requests": [{"request_id": r.get("request_id"),
                      "tool_names": r.get("tool_names"),
                      "tool_definition_hashes": r.get("tool_definition_hashes"),
                      "decision": r.get("decision"),
                      "upstream_status": r.get("upstream_status"),
                      "upstream_error": r.get("upstream_error"),
                      "response_complete": r.get("response_complete")} for r in reqs],
        "required_actions": obligations,
        "cli_exit": cli_exit,
        "cli_timed_out": timed_out,
        "cli_is_error": (cli_doc or {}).get("is_error"),
        "cli_stop_reason": (cli_doc or {}).get("stop_reason"),
        "permission_denials_count": notes["permission_denials_count"],
        "challenge_first_line": notes["challenge_first_line"],
        "output_schema_ok": notes["output_schema_ok"],
        "postconditions": {
            "no_blocked_requests": not blocked,
            "no_upstream_error": not upstream_bad,
            "all_upstream_2xx": not [r for r in reqs
                                     if r.get("decision") == "forward"
                                     and isinstance(r.get("upstream_status"), int)
                                     and not (200 <= r["upstream_status"] < 300)],
            "all_responses_complete": not incomplete,
            "state_unchanged": not changed,
            "snapshot_phases_complete": not missing_phases,
            "no_snapshot_tampering": not tampered_phases,
            "response_scan_closed": scan_ok,
        },
        "state_invariants": {"before": state_before, "after": state_after,
                             "changed": changed},
        "ambient_overrides_cleared": plan.get("ambient_overrides_cleared", []),
        # ★2026-08-08: which kind of credential each run used must be distinguishable from the artefacts.
        # `auth_mode` is a declaration; `dummy_auth_blocked` is **what actually happened** —
        # the latter is recorded by the inspector before forwarding, not self-reported by anyone.
        "auth_mode": plan.get("auth_mode"),
        "auth_blocked_count": len([r for r in reqs if r.get("auth_block_reason")]),
        "response_scan": {
            "required_count": len(forwarded_2xx),
            "terminal_count": len(scan_terms),
            "all_ok": scan_ok,
            "problems": scan_problems,
            "tool_use_count": total_tool_use,
            "formats": sorted({r.get("format") for r in scan_terms if r.get("format")}),
        },
        "snapshot_phases": {
            "cli_exec_attempted": cli_exec_attempted,
            "cli_started": cli_started,
            "required": required_phases,
            "verified": verified_phases,
            "missing": missing_phases,
            "tampered": tampered_phases,
        },
        # The bridge baseline is copied into terminal verbatim, so an independent oracle can re-check the topology without asking us.
        # ⚠️ None of this contains keychain content — only dev/inode/uid/mode and the literal readlink values.
        "keychain_bridge": plan.get("keychain_bridge"),
    }

    with open(os.path.join(adir, "terminal.json"), "w") as f:
        json.dump(terminal, f, ensure_ascii=False, indent=1)
    with open(os.path.join(adir, "events.jsonl"), "a") as f:
        f.write(json.dumps({"event": "finished", "attempt_id": plan["attempt_id"],
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                            "outcome": outcome, "exit_code": exit_map[outcome]},
                           ensure_ascii=False) + "\n")
    print(f"OUTCOME {outcome} exit={exit_map[outcome]} "
          f"requests={len(reqs)} blocked={len(blocked)}")
    return exit_map[outcome]


if __name__ == "__main__":
    sys.exit(main())
