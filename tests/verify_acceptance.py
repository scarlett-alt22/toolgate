#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Re-compute acceptance from case artifacts independently; the runner's status/detail
are only for reconciliation.

The case list comes from tests/cases.json; for each case, re-walk/hash the artifact
tree, parse events/terminal/inspector logs, verify the attempted/finished cardinalities
and the terminal schema/internal hashes, then compute actual pass/fail from expected
plus artifacts. A runner self-reporting `status=pass` plays no part in the verdict.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
VALID_RUNNER_STATUS = {"pass", "fail", "unimplemented"}
COMMON_TERMINAL = {
    "schema_version", "attempt_id", "profile_id", "started_at", "finished_at",
    "outcome", "exit_code", "error_type", "detail", "trust_boundary",
    "request_count", "blocked_count",
}
FULL_TERMINAL = COMMON_TERMINAL | {
    "hashes", "workspace_realpath", "home_realpath", "model", "timeout_seconds",
    "upstream_origin", "inspector_exit", "requests", "required_actions",
    "cli_exit", "cli_timed_out", "cli_is_error", "permission_denials_count",
    "output_schema_ok", "postconditions", "state_invariants", "inspector_log_sha256",
    "events_sha256_at_finish", "response_scan", "snapshot_phases",
}
EXIT_MAP = {"success": 0, "config_rejected": 78, "inspector_failed": 80,
            "policy_blocked": 81, "timeout": 82, "cli_failed": 83,
            "obligation_failed": 84, "schema_failed": 85,
            "postcondition_failed": 86}


def sha_file(path):
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return "NOT_REGULAR"
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "ABSENT"


def artifact_index(root):
    """Independently implemented from the runner; no lib import, no symlink following, no FIFO opening."""
    out = {}
    if not os.path.isdir(root):
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            try:
                st = os.lstat(path)
            except OSError as e:
                out[rel] = {"type": "unreadable", "error": type(e).__name__}
                continue
            if stat.S_ISDIR(st.st_mode):
                continue
            if stat.S_ISLNK(st.st_mode):
                out[rel] = {"type": "symlink", "target": os.readlink(path)}
            elif stat.S_ISREG(st.st_mode):
                out[rel] = {"type": "regular", "size": st.st_size,
                            "sha256": sha_file(path)}
            elif stat.S_ISFIFO(st.st_mode):
                out[rel] = {"type": "fifo"}
            else:
                out[rel] = {"type": "other", "mode_type": stat.S_IFMT(st.st_mode)}
    return dict(sorted(out.items()))


def load_json(path, problems, label):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        return doc
    except Exception as e:                                      # noqa: BLE001
        problems.append(f"{label} unreadable: {type(e).__name__}")
        return None


def load_jsonl(path, problems, label):
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
            if line.strip():
                rows.append(json.loads(line))
    except Exception as e:                                      # noqa: BLE001
        problems.append(f"{label} line {lineno} unreadable: {type(e).__name__}")
    return rows


def find_attempts(root, problems):
    found = []
    for dirpath, dirnames, _files in os.walk(root, followlinks=False):
        if os.path.basename(dirpath) != "runs":
            continue
        for name in sorted(dirnames):
            adir = os.path.join(dirpath, name)
            if os.path.isfile(os.path.join(adir, "events.jsonl")):
                found.append(read_attempt(adir, problems))
        dirnames[:] = []
    return found


def hash_events_before_finished(path, rows):
    """finish.py hashes first, then appends finished; reproduce the file bytes as they were."""
    if not rows or rows[-1].get("event") != "finished":
        return None
    raw_lines = open(path, "rb").readlines()
    return hashlib.sha256(b"".join(raw_lines[:-1])).hexdigest()


def read_attempt(adir, problems):
    ev_path = os.path.join(adir, "events.jsonl")
    events = load_jsonl(ev_path, problems, os.path.relpath(ev_path, adir))
    insp_path = os.path.join(adir, "inspector.jsonl")
    inspector = load_jsonl(insp_path, problems, os.path.relpath(insp_path, adir))
    terminal_path = os.path.join(adir, "terminal.json")
    terminal = (load_json(terminal_path, problems, os.path.relpath(terminal_path, adir))
                if os.path.exists(terminal_path) else None)
    plan_path = os.path.join(adir, "plan.json")
    plan = (load_json(plan_path, problems, os.path.relpath(plan_path, adir))
            if os.path.exists(plan_path) else None)
    return {"dir": adir, "name": os.path.basename(adir), "events": events,
            "inspector": inspector, "terminal": terminal, "plan": plan,
            "attempted": [e for e in events if e.get("event") == "attempted"],
            "finished": [e for e in events if e.get("event") == "finished"],
            "abandoned": [e for e in events if e.get("event") == "abandoned"]}


def validate_plan_hashes(a, problems, cid, drift_expected=False):
    plan, terminal = a["plan"], a["terminal"]
    if not isinstance(plan, dict) or not isinstance(terminal, dict):
        return
    hashes = terminal.get("hashes")
    if hashes != plan.get("hashes") or not isinstance(hashes, dict):
        problems.append(f"{cid}: terminal.hashes mismatch with plan / missing")
        return
    paths = {"settings": plan.get("settings_path"), "mcp": plan.get("mcp_path"),
             "policy": plan.get("policy_path"), "sentinel": plan.get("sentinel_path"),
             "cli": plan.get("cli_realpath")}
    if plan.get("sandbox_mode") == "required":
        paths["sandbox_profile"] = plan.get("sandbox_profile_path")
    # ★2026-08-09 the spec set by external review A11. The first version was my bool
    # flag (pass if any drift at all); it constructed counter-examples proving that was
    # **fail-open**: CLI-only drift passed, drift-everywhere-else passed,
    # missing/non-regular objects counted as successful injection, and an early return
    # skipped the wrapper-source check.
    # 🔴 Now: **the actual drift set must be strictly equal to the declared set**, and
    # the target must still be a regular file. This is the third time I swapped the
    # criterion myself and the third time it got blocked — recorded here, not elsewhere.
    def _drift_state(key, pth):
        """Return 'match' / 'drift' / 'unusable'. ABSENT, symlinks, FIFOs don't count as successful injection."""
        if not isinstance(pth, str):
            return "unusable"
        try:
            st = os.lstat(pth)
        except OSError:
            return "unusable"
        if not stat.S_ISREG(st.st_mode):
            return "unusable"
        return "match" if sha_file(pth) == hashes.get(key) else "drift"

    states = {k: _drift_state(k, pth) for k, pth in paths.items()}
    if drift_expected:
        declared = set(drift_expected)
        unknown = declared - set(paths)
        if unknown:
            problems.append(f"{cid}: declared nonexistent drift targets {sorted(unknown)}")
        actual = {k for k, st_ in states.items() if st_ == "drift"}
        if actual != declared:
            problems.append(f"{cid}: drift set mismatch - declared {sorted(declared)},"
                            f"actual {sorted(actual)} (one more or one fewer both fail)")
        bad = [k for k in declared if states.get(k) == "unusable"]
        if bad:
            problems.append(f"{cid}: drift targets {bad} missing or not a regular file"
                            f" - that does not count as a successful injection")
        others = [k for k in paths if k not in declared and states[k] != "match"]
        if others:
            problems.append(f"{cid}: non-target objects {others} also changed; counterfactual not narrow")
    else:
        for key, st_ in states.items():
            if st_ != "match":
                problems.append(f"{cid}: {key} artifact hash mismatch with terminal/plan")
    # 🔴 The wrapper-source check **runs unconditionally** — no branch may skip it with
    # an early return.
    sandbox = os.path.dirname(os.path.dirname(a["dir"]))
    for name, want in (hashes.get("wrapper_sources") or {}).items():
        if sha_file(os.path.join(sandbox, name)) != want:
            problems.append(f"{cid}: wrapper source {name} hash mismatch")


def validate_terminal(a, problems, cid, drift_expected=False):
    t = a["terminal"]
    if t is None:
        if a["finished"]:
            problems.append(f"{cid}: finished present but terminal.json missing")
        return
    if not isinstance(t, dict):
        problems.append(f"{cid}: terminal root is not an object")
        return
    missing = sorted(COMMON_TERMINAL - set(t))
    if missing:
        problems.append(f"{cid}: terminal common schema missing {missing}")
    full = isinstance(a["plan"], dict) and any(
        e.get("event") == "cli_exec_attempted" for e in a["events"])
    if full:
        missing_full = sorted(FULL_TERMINAL - set(t))
        if missing_full:
            problems.append(f"{cid}: terminal full schema missing {missing_full}")
    if t.get("schema_version") != 1 or t.get("attempt_id") != a["name"]:
        problems.append(f"{cid}: terminal schema_version/attempt_id do not hold")
    if len(a["attempted"]) != 1:
        problems.append(f"{cid}: attempted_count={len(a['attempted'])}, required 1")
    if len(a["finished"]) != 1:
        problems.append(f"{cid}: terminal exists but finished_count={len(a['finished'])}, required 1")
    elif (a["finished"][0].get("outcome") != t.get("outcome")
          or a["finished"][0].get("exit_code") != t.get("exit_code")):
        problems.append(f"{cid}: finished and terminal outcome/exit_code inconsistent")
    if t.get("outcome") in EXIT_MAP and t.get("exit_code") != EXIT_MAP[t["outcome"]]:
        problems.append(f"{cid}: terminal exit_code inconsistent with outcome mapping table")
    reqs = [r for r in a["inspector"] if r.get("event") == "request"]
    if t.get("request_count") != len(reqs):
        problems.append(f"{cid}: request_count self-reported {t.get('request_count')}, log recount {len(reqs)}")
    blocked = sum(r.get("decision") == "block" for r in reqs)
    if t.get("blocked_count") != blocked:
        problems.append(f"{cid}: blocked_count self-reported {t.get('blocked_count')}, log recount {blocked}")
    if "inspector_log_sha256" in t:
        got = sha_file(os.path.join(a["dir"], "inspector.jsonl"))
        if t.get("inspector_log_sha256") != got:
            problems.append(f"{cid}: inspector_log_sha256 mismatch with existing artifact")
    if "events_sha256_at_finish" in t:
        got = hash_events_before_finished(os.path.join(a["dir"], "events.jsonl"), a["events"])
        if t.get("events_sha256_at_finish") != got:
            problems.append(f"{cid}: events_sha256_at_finish independent recomputation mismatch")
    validate_plan_hashes(a, problems, cid, drift_expected)


def obs_delta(obs, role, field="requests"):
    try:
        return obs["mock_after"][role][field] - obs["mock_before"][role][field]
    except Exception:                                          # noqa: BLE001
        return None


def only_attempt(attempts):
    return attempts[0] if len(attempts) == 1 else None


def basic_closed(a):
    return bool(a and len(a["attempted"]) == 1 and len(a["finished"]) == 1
                and isinstance(a["terminal"], dict))


def eval_preflight(cid, expected, attempts, obs, root, expected_error_type=None):
    if cid == "pf-ambient-override":
        a = only_attempt(attempts)
        if not a:
            return False
        oracle = subprocess.run(
            ["/usr/bin/python3", os.path.join(TESTS, "verify_ambient.py"), a["dir"]],
            text=True, capture_output=True, timeout=30)
        return oracle.returncode == 0 and obs_delta(obs, "primary") == 0
    if expected == "pass":
        a = only_attempt(attempts)
        return bool(a and len(a["attempted"]) == 1 and not a["finished"]
                    and a["terminal"] is None and obs_delta(obs, "primary") == 0)
    a = only_attempt(attempts)
    return bool(basic_closed(a) and a["terminal"].get("outcome") == "config_rejected"
                and a["terminal"].get("exit_code") == 78
                and (expected_error_type is None
                     or a["terminal"].get("error_type") == expected_error_type)
                and obs_delta(obs, "primary") == 0 and obs_delta(obs, "secondary") == 0)


def eval_upper(cid, expected, attempts, obs):
    if expected in {"forward", "block403"}:
        a = only_attempt(attempts)
        if not a or a["terminal"] is not None or len(a["attempted"]) != 1:
            return False
        reqs = [r for r in a["inspector"] if r.get("event") == "request"]
        if len(reqs) != 1:
            return False
        r = reqs[0]
        if expected == "forward":
            return (r.get("decision") == "forward" and bool(r.get("forward_started_at"))
                    and obs_delta(obs, "primary") == 1)
        return (r.get("decision") == "block" and bool(r.get("block_reason"))
                and r.get("forward_started_at") is None and obs_delta(obs, "primary") == 0)
    a = only_attempt(attempts)
    if not basic_closed(a) or a["terminal"].get("outcome") == "success":
        return False
    if cid == "ub-redirect-302":
        return (obs_delta(obs, "secondary") == 0
                and any(r.get("upstream_error") == "redirect_not_followed"
                        for r in a["inspector"] if r.get("event") == "request"))
    if cid == "ub-inspector-dies":
        return a["terminal"].get("outcome") == "inspector_failed"
    if cid == "ub-log-truncated":
        return a["terminal"].get("outcome") == "inspector_failed"
    if cid == "ub-response-incomplete":
        return any(r.get("response_complete") is False
                   for r in a["inspector"] if r.get("event") == "request")
    return True


def eval_lower(expected, attempts):
    a = only_attempt(attempts)
    if not basic_closed(a):
        return False
    outcome = a["terminal"].get("outcome")
    if expected == "not_success":
        return outcome != "success"
    return outcome == expected


def eval_terminal(cid, attempts):
    if cid == "tm-concurrency-20":
        ids = [a["terminal"].get("attempt_id") for a in attempts if isinstance(a["terminal"], dict)]
        return (len(attempts) == 20 and len(set(ids)) == 20
                and all(basic_closed(a) for a in attempts))
    if cid == "tm-abandoned-recovery":
        return (len(attempts) == 2
                and sum(len(a["abandoned"]) == 1 and not a["finished"] for a in attempts) == 1
                and sum(basic_closed(a) for a in attempts) == 1)
    a = only_attempt(attempts)
    if not basic_closed(a):
        return False
    t = a["terminal"]
    if cid == "tm-blocked-wins":
        return t.get("outcome") == "policy_blocked" and t.get("blocked_count", 0) >= 1
    if cid == "tm-finished-configfail":
        return t.get("outcome") == "config_rejected" and t.get("request_count") == 0
    if cid == "tm-log-hash-stable":
        return t.get("inspector_log_sha256") == sha_file(os.path.join(a["dir"], "inspector.jsonl"))
    if cid == "tm-fields-complete":
        return not (FULL_TERMINAL - set(t)) and t.get("outcome") == "success"
    if cid == "tm-state-invariants":
        inv = t.get("state_invariants") or {}
        room = (inv.get("after") or {}).get("heartbeat_room_snapshot") or {}
        return inv.get("changed") == [] and room.get("status") == "unmeasured"
    return True


def phase_projection(a):
    reqs = [r for r in a["inspector"] if r.get("event") == "request"]
    scans = [r for r in a["inspector"] if r.get("event") == "response_scan_terminal"]
    uses = [r for r in a["inspector"] if r.get("event") == "tool_use_seen"]
    results = [r for r in a["inspector"] if r.get("event") == "tool_result_seen"]
    t = a["terminal"] or {}
    return {
        "requests": [{k: r.get(k) for k in ("tool_names", "tool_definition_hashes", "decision",
                     "upstream_status", "upstream_error", "response_complete", "request_stream")}
                     for r in reqs],
        "scans": [{k: r.get(k) for k in ("format", "outcome", "reason_code",
                    "message_stop_seen", "tool_use_count", "unknown_event_count")} for r in scans],
        "uses": [{"name": r.get("name"), "path_match": r.get("path_match")} for r in uses],
        "results": [{"is_error": r.get("is_error"),
                     "contains_challenge": r.get("contains_challenge")} for r in results],
        "required_actions": t.get("required_actions"),
        "cli": {k: t.get(k) for k in ("cli_exit", "cli_timed_out", "cli_is_error",
                "cli_stop_reason", "permission_denials_count", "challenge_first_line",
                "output_schema_ok")},
    }


def protocol_ok(a, outcome):
    if not basic_closed(a) or a["terminal"].get("outcome") != outcome:
        return False
    reqs = [r for r in a["inspector"] if r.get("event") == "request"]
    scans = [r for r in a["inspector"] if r.get("event") == "response_scan_terminal"]
    uses = [r for r in a["inspector"] if r.get("event") == "tool_use_seen"]
    results = [r for r in a["inspector"] if r.get("event") == "tool_result_seen"]
    actions = a["terminal"].get("required_actions") or []
    return (len(reqs) == 3 and all(r.get("decision") == "forward"
            and r.get("upstream_status") == 200 and r.get("response_complete") is True for r in reqs)
            and len(scans) == 3 and all(r.get("outcome") == "ok" for r in scans)
            and len(uses) == len(results) == 1
            and uses[0].get("tool_use_id") == results[0].get("tool_use_id")
            and uses[0].get("path_match") is True
            and results[0].get("contains_challenge") is True
            and results[0].get("is_error") is False
            and len(actions) == 1 and actions[0].get("causal_evidence") is True
            and a["terminal"].get("challenge_first_line") is True
            and a["terminal"].get("output_schema_ok") is True)


def eval_phase(cid, attempts, obs, root):
    controls = [a for a in attempts if os.sep + "positive-control" + os.sep in a["dir"]]
    mutants = [a for a in attempts if a not in controls]
    mutant = only_attempt(mutants)
    if cid.endswith("before-cli-spawn"):
        if not basic_closed(mutant) or obs_delta(obs, "primary") != 0:
            return False
        phases = [(e.get("event"), e.get("phase")) for e in mutant["events"]]
        target = os.path.join(mutant["terminal"].get("home_realpath", ""),
                              "Library", "Keychains")
        return (mutant["terminal"].get("outcome") == "config_rejected"
                and ("snapshot_verified", "pre_inspector") in phases
                and ("snapshot_tampered", "pre_cli") in phases
                and not os.path.exists(os.path.join(mutant["dir"], "cli-started.json"))
                and os.path.islink(target))
    control = only_attempt(controls)
    if not protocol_ok(control, "success") or not protocol_ok(mutant, "config_rejected"):
        return False
    if obs_delta(obs, "primary") != 6 or phase_projection(control) != phase_projection(mutant):
        return False
    phases_c = {(e.get("event"), e.get("phase")) for e in control["events"]}
    phases_m = {(e.get("event"), e.get("phase")) for e in mutant["events"]}
    mut_path = os.path.join(mutant["dir"], "auth-mutation-by-cli.json")
    started_path = os.path.join(mutant["dir"], "cli-started.json")
    proc_path = os.path.join(mutant["dir"], "cli-process-evidence.json")
    insp_path = os.path.join(mutant["dir"], "inspector.jsonl")
    target = os.path.join(mutant["terminal"].get("home_realpath", ""), "Library", "Keychains")
    # 🔴 2026-08-15 (A15 ruling §Q1 red ②): model.json's mtime has been removed from
    #    the criteria. The launcher buffers stdout and only writes it out after the CLI
    #    exits, so model.json is necessarily newer than "the mutation before exit" —
    #    that condition is structurally impossible. The canonical explanation lives at
    #    the same place in verify_phase_drift.py; don't change only one side (these two
    #    oracles judge the same thing — changing only the runner's copy would leave the
    #    independent verifier still failing it).
    # 🔴 Same-round follow-up (A15 minimal closure item 2): the independent grader
    #    previously had only mtime + symlink left, which handed "was it that process"
    #    entirely to the runner. Now it re-computes pid and writer hash itself, and the
    #    writer hash is compared against **the fixture file's real bytes**, not the
    #    string the artifact self-reports.
    if not all(os.path.exists(p) for p in (mut_path, started_path, proc_path, insp_path)):
        return False
    try:
        with open(mut_path, encoding="utf-8") as f:
            mut = json.load(f)
        with open(started_path, encoding="utf-8") as f:
            started = json.load(f)
        with open(proc_path, encoding="utf-8") as f:
            proc = json.load(f)
    except (OSError, ValueError):
        return False
    fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fixtures", "fake_cli.py")
    mt = os.stat(mut_path).st_mtime_ns
    return ({("snapshot_verified", p) for p in ("pre_inspector", "pre_cli", "post_cli")} <= phases_c
            and ("snapshot_tampered", "post_cli") in phases_m
            and os.path.islink(target)
            and mut.get("actor") == "fake_cli"
            and mut.get("pid") == proc.get("pid") == started.get("pid")
            and mut.get("writer_sha256") == started.get("writer_sha256") == sha_file(fixture)
            and (mut.get("after") or {}).get("readlink_is_absolute") is True
            and mt >= os.stat(insp_path).st_mtime_ns)


def evaluate(cid, group, case, attempts, obs, root):
    expected = case["expected"]
    if group == "preflight":
        return eval_preflight(cid, expected, attempts, obs, root,
                              case.get("expected_error_type"))
    if group == "upper_bound":
        return eval_upper(cid, expected, attempts, obs)
    if group == "lower_bound":
        return eval_lower(expected, attempts)
    if group == "terminal":
        return eval_terminal(cid, attempts)
    if group == "auth_phase_drift":
        return eval_phase(cid, attempts, obs, root)
    return False


def main():
    if len(sys.argv) != 2:
        print("usage: verify_acceptance.py <summary.json>", file=sys.stderr)
        return 2
    path = os.path.realpath(sys.argv[1])
    if not os.path.isfile(path):
        print(f"❌ not found: {path} - no artifacts, no verdict", file=sys.stderr)
        return 2
    problems = []
    summary = load_json(path, problems, "summary.json")
    if not isinstance(summary, dict):
        print("❌ summary root is not an object")
        return 1
    cases_path = os.path.join(TESTS, "cases.json")
    cases = load_json(cases_path, problems, "cases.json") or {}
    cases_sha = sha_file(cases_path)
    if summary.get("cases_file_sha256") != cases_sha:
        problems.append("cases.json hash mismatch with summary record")

    definitions = {}
    for group in cases.get("groups") or []:
        for case in group.get("cases") or []:
            definitions[case["id"]] = (group["id"], case)
    rows = summary.get("results") if isinstance(summary.get("results"), list) else []
    by_id = {}
    for r in rows:
        cid = r.get("case_id") if isinstance(r, dict) else None
        if cid in by_id:
            problems.append(f"duplicate reported case {cid}")
        by_id[cid] = r
    missing = sorted(set(definitions) - set(by_id))
    extra = sorted(set(by_id) - set(definitions))
    if missing:
        problems.append(f"roster missing {len(missing)} cases: {missing[:8]}")
    if extra:
        problems.append(f"roster has {len(extra)} extra cases: {extra[:8]}")

    summary_dir = os.path.dirname(path)
    computed = {}
    total_artifacts = 0
    real_origin_deltas = 0
    for cid, (group, case) in definitions.items():
        r = by_id.get(cid)
        if not isinstance(r, dict):
            computed[cid] = "fail"
            continue
        if r.get("group") != group or r.get("expected") != case.get("expected"):
            problems.append(f"{cid}: group/expected inconsistent with cases.json")
        if r.get("status") not in VALID_RUNNER_STATUS:
            problems.append(f"{cid}: runner status invalid {r.get('status')!r}")
        relroot = r.get("artifact_root")
        root = os.path.realpath(os.path.join(summary_dir, relroot or ""))
        if (not isinstance(relroot, str)
                or not root.startswith(summary_dir + os.sep) or not os.path.isdir(root)):
            problems.append(f"{cid}: artifact_root missing/out-of-bounds/nonexistent")
            computed[cid] = "fail"
            continue
        actual_index = artifact_index(root)
        declared_index = r.get("artifact_index")
        if declared_index != actual_index:
            problems.append(f"{cid}: artifact index/hash inconsistent with existing case tree")
        total_artifacts += len(actual_index)
        obs = load_json(os.path.join(root, "harness-observation.json"), problems,
                        f"{cid}/harness-observation.json") or {}
        if obs.get("case_id") != cid:
            problems.append(f"{cid}: harness observation identity mismatch")
        for role in ("primary", "secondary"):
            delta = obs_delta(obs, role, "real_origin_attempts")
            if delta is None:
                problems.append(f"{cid}: missing {role} real_origin counter")
            else:
                real_origin_deltas += delta
        attempts = find_attempts(root, problems)
        for a in attempts:
            # Pass **the set itself**, not a bool — A11's spec is "strict equality";
            # converting to bool downgrades it back to my fail-open first version.
            validate_terminal(a, problems, cid,
                              case.get("artifacts_expected_to_drift"))
            if a["terminal"] is None and not a["abandoned"] and len(a["attempted"]) != 1:
                problems.append(f"{cid}: open attempt attempted_count is not 1")
        ok = (declared_index == actual_index
              and evaluate(cid, group, case, attempts, obs, root))
        computed[cid] = "pass" if ok else "fail"
        if r.get("status") != computed[cid]:
            problems.append(f"{cid}: runner self-reported {r.get('status')}, artifact independently judged {computed[cid]}")

    recount = {"pass": sum(v == "pass" for v in computed.values()),
               "fail": sum(v == "fail" for v in computed.values())}
    compact_recount = {k: v for k, v in recount.items() if v}
    if summary.get("total_cases") != len(rows):
        problems.append(f"summary total_cases={summary.get('total_cases')}, actual results={len(rows)}")
    if summary.get("counts") != compact_recount:
        problems.append(f"summary counts={summary.get('counts')}, artifact recount={compact_recount}")
    if summary.get("all_pass") is not (recount["fail"] == 0):
        problems.append(f"summary all_pass={summary.get('all_pass')}, artifact recount={recount['fail'] == 0}")
    if summary.get("anthropic_requests") != real_origin_deltas:
        problems.append(f"summary ANTHROPIC_REQUESTS={summary.get('anthropic_requests')},"
                        f"case artifact recount={real_origin_deltas}")
    if real_origin_deltas != 0:
        problems.append(f"🔴 case observations recount real-origin delta={real_origin_deltas}")
    state_before, state_after = summary.get("state_before") or {}, summary.get("state_after") or {}
    state_changed = [k for k, v in state_before.items() if k != "heartbeat_room_snapshot"
                     and (state_after.get(k) or {}).get("sha256") != v.get("sha256")]
    if state_changed or summary.get("state_changed") != state_changed:
        problems.append(f"🔴 state hash recount changes={state_changed}, self-reported={summary.get('state_changed')}")
    room = (state_after.get("heartbeat_room_snapshot") or {}).get("status")
    if room != "unmeasured":
        problems.append(f"Room status should be unmeasured, got {room!r}")

    print(f"Roster: expected {len(definitions)} cases, got {len(rows)}, missing {len(missing)}, extra {len(extra)}")
    print(f"Artifact independent grading: {recount}; recounted/verified {total_artifacts} artifacts")
    print(f"REAL_ORIGIN_DELTA={real_origin_deltas}; six legacy state changes: {state_changed or 'none'}; Room={room}")
    if problems:
        for p in problems:
            print("❌", p)
        print(f"\nVERIFY_FAILED ({len(problems)} items)")
        return 1
    if recount["fail"]:
        print("\nVERIFY_OK_BUT_NOT_ALL_PASS")
        return 1
    print("\nVERIFY_ALL_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
