#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recompute finish.py's five-cells-by-three-arms verdict offline from in-repo fixtures.

Runs only this repo's finish.py; no mock, no hb-run, no network or API.

    /usr/bin/python3 tests/finish_arms.py
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile


TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
FINISH = os.path.join(WRAPPER, "finish.py")
FIXTURES = os.path.join(TESTS, "fixtures", "finish")
BASE = os.path.join(FIXTURES, "base")
CASES = os.path.join(FIXTURES, "cases.json")


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def file_hashes(root):
    out = {}
    for here, _dirs, names in os.walk(root):
        for name in names:
            path = os.path.join(here, name)
            rel = os.path.relpath(path, root)
            out[rel] = sha256(path)
    return out


def select(rows, selector):
    return [row for row in rows
            if all(row.get(key) == value for key, value in selector.items())]


def apply_mutation(attempt_dir, mutation):
    """Materialize one semantic variable, and reject any fuzzy match or old-value drift."""
    op = mutation["op"]
    if op == "none":
        return "none (as-is)"

    path = os.path.join(attempt_dir, "inspector.jsonl")
    rows = load_jsonl(path)

    if op == "set_fields":
        matched = select(rows, mutation["selector"])
        if len(matched) != 1:
            raise AssertionError(f"selector must match exactly 1 row, got {len(matched)}")
        row = matched[0]
        details = []
        for field, transition in mutation["changes"].items():
            old = transition["from"]
            new = transition["to"]
            if row.get(field) != old:
                raise AssertionError(
                    f"{field} old-value drift: expected {old!r}, actual {row.get(field)!r}")
            row[field] = new
            details.append(f"{field}:{old!r}→{new!r}")
        write_jsonl(path, rows)
        return ", ".join(details)

    if op == "remove_events":
        removed = []
        for event, expected_count in mutation["events"].items():
            actual = sum(row.get("event") == event for row in rows)
            if actual != expected_count:
                raise AssertionError(
                    f"{event} count drift: expected {expected_count}, actual {actual}")
            removed.append(f"{event}×{actual}")
        targets = set(mutation["events"])
        rows = [row for row in rows if row.get("event") not in targets]
        write_jsonl(path, rows)
        return "removed " + "+".join(removed)

    raise AssertionError(f"unknown mutation op: {op!r}")


def assert_fixture_shape(attempt_dir, case, before_hashes):
    """Prove each arm only touches the inspector variables its manifest declares."""
    after_hashes = file_hashes(attempt_dir)
    changed_files = sorted(
        rel for rel in set(before_hashes) | set(after_hashes)
        if before_hashes.get(rel) != after_hashes.get(rel))
    expected_files = [] if case["mutation"]["op"] == "none" else ["inspector.jsonl"]
    if changed_files != expected_files:
        raise AssertionError(
            f"input isolation failed: actual changes {changed_files}, allowed {expected_files}")

    rows = load_jsonl(os.path.join(attempt_dir, "inspector.jsonl"))
    terms = [row for row in rows if row.get("event") == "response_scan_terminal"]
    uses = [row for row in rows if row.get("event") == "tool_use_seen"]
    results = [row for row in rows if row.get("event") == "tool_result_seen"]

    if case["id"] == "baseline":
        ids = [row.get("tool_use_id") for row in uses]
        if not (len(ids) == len(set(ids)) == 1 and
                len(results) == 1 and results[0].get("tool_use_id") == ids[0]):
            raise AssertionError("baseline arm: tool id is not a unique one-to-one causal chain")
    elif case["id"] == "truncated_stream":
        if not (uses and results and any(
                row.get("outcome") == "failed" and
                row.get("reason_code") == "truncated_stream" and
                row.get("tool_use_count") == 1 for row in terms)):
            raise AssertionError("truncated arm did not keep both tool use and truncated terminal")
    elif case["id"] == "causal_evidence_absent":
        if uses or results or not terms or not all(row.get("outcome") == "ok" for row in terms):
            raise AssertionError("absent-evidence arm must only have closed scans, no leftover use/result causal events")
    elif case["id"] == "upstream_non_2xx":
        requests = [row for row in rows if row.get("event") == "request"]
        bad = [row for row in requests if row.get("upstream_status") == 500]
        if len(bad) != 1 or not uses or not results or not all(
                row.get("outcome") == "ok" for row in terms):
            raise AssertionError("non-2xx arm must keep full success evidence apart from the one status")


def assert_terminal_evidence(case, terminal):
    """Reject "same outcome by coincidence": each cell must fire on exactly the evidence it declares."""
    expected = case["expected_outcome"]
    candidates = terminal.get("outcome_candidates")
    if candidates != [expected]:
        raise AssertionError(
            f"outcome is not single-cause: expected sole candidate {expected!r}, actual {candidates!r}")

    actions = terminal.get("required_actions") or []
    causal = bool(actions) and all(action.get("causal_evidence") for action in actions)
    post = terminal.get("postconditions") or {}
    scan = terminal.get("response_scan") or {}

    if case["id"] == "baseline":
        if not (causal and post.get("response_scan_closed") is True
                and post.get("all_upstream_2xx") is True):
            raise AssertionError("baseline arm: causal, scan, and 2xx premises did not all hold")
        return "causal=true, scan_closed=true, all_2xx=true"

    if case["id"] == "scan_outcome_failed":
        problems = scan.get("problems") or []
        if not (causal and post.get("response_scan_closed") is False
                and len(problems) == 1
                and problems[0].get("problem") == "scan_failed"
                and problems[0].get("reason_code") is None):
            raise AssertionError("outcome=failed arm was not uniquely attributed to an unclosed scan")
        return "causal=true, scan_closed=false, reason=None"

    if case["id"] == "truncated_stream":
        problems = scan.get("problems") or []
        if not (causal and scan.get("tool_use_count") == 1
                and post.get("response_scan_closed") is False
                and len(problems) == 1
                and problems[0].get("reason_code") == "truncated_stream"):
            raise AssertionError("truncated arm did not keep tool use with unique truncated_stream attribution")
        return "causal=true, tool_use=1, reason=truncated_stream"

    if case["id"] == "causal_evidence_absent":
        if not (not causal and post.get("response_scan_closed") is True
                and terminal.get("challenge_first_line") is True
                and terminal.get("output_schema_ok") is True):
            raise AssertionError("absent-evidence arm was not isolated as a pure lower-bound obligation failure")
        return "causal=false, scan_closed=true, self-report still looks good"

    if case["id"] == "upstream_non_2xx":
        if not (causal and post.get("response_scan_closed") is True
                and post.get("all_upstream_2xx") is False):
            raise AssertionError("non-2xx arm was not isolated as a pure postcondition failure")
        return "causal=true, scan_closed=true, all_2xx=false"

    raise AssertionError(f"no terminal evidence oracle: {case['id']!r}")


def run_case(case, base_hashes):
    with tempfile.TemporaryDirectory(prefix="finish-arm-") as tmp:
        attempt_dir = os.path.join(tmp, case["id"])
        shutil.copytree(BASE, attempt_dir)
        change = apply_mutation(attempt_dir, case["mutation"])
        assert_fixture_shape(attempt_dir, case, base_hashes)

        proc = subprocess.run(
            [sys.executable, FINISH, attempt_dir, "0", "0", "143",
             os.path.join(attempt_dir, "model.json")],
            capture_output=True, text=True, timeout=20)

        terminal_path = os.path.join(attempt_dir, "terminal.json")
        if not os.path.exists(terminal_path):
            return False, (f"variable={case['variable']}; changed={change}; "
                           f"terminal missing; rc={proc.returncode}; stderr={proc.stderr.strip()}")
        with open(terminal_path, encoding="utf-8") as f:
            terminal = json.load(f)

        actual = terminal.get("outcome")
        terminal_exit = terminal.get("exit_code")
        expected = case["expected_outcome"]
        expected_exit = case["expected_exit"]
        proof = assert_terminal_evidence(case, terminal)
        finished = [row for row in load_jsonl(os.path.join(attempt_dir, "events.jsonl"))
                    if row.get("event") == "finished"]
        ok = (actual == expected
              and proc.returncode == expected_exit
              and terminal_exit == expected_exit
              and len(finished) == 1
              and finished[0].get("outcome") == expected)
        detail = (f"variable={case['variable']}; changed={change}; "
                  f"expected={expected}/{expected_exit} "
                  f"actual={actual}/{proc.returncode}; proof={proof}")
        if proc.stderr.strip():
            detail += f"; stderr={proc.stderr.strip()}"
        return ok, detail


def main():
    try:
        with open(CASES, encoding="utf-8") as f:
            cases = json.load(f)
        if len(cases) != 5:
            raise AssertionError(f"expected exactly five arms, got {len(cases)}")
        variables = [case["variable"] for case in cases]
        if len(variables) != len(set(variables)):
            raise AssertionError(f"each arm must declare one independent variable: {variables}")
        base_hashes = file_hashes(BASE)
        if sorted(base_hashes) != ["events.jsonl", "inspector.jsonl", "model.json", "plan.json"]:
            raise AssertionError(f"base file set drift: {sorted(base_hashes)}")
    except Exception as exc:
        print(f"✘ fixture load failed  {exc}")
        print()
        print("FINISH_ARMS 0/5 BROKEN=5")
        return 1

    results = []
    for index, case in enumerate(cases, 1):
        try:
            ok, detail = run_case(case, base_hashes)
        except Exception as exc:
            ok, detail = False, f"variable={case.get('variable')}; fixture_error={exc}"
        results.append(ok)
        print(f"{'✔' if ok else '✘'} {index}/5 {case['label']}  {detail}")

    passed = sum(results)
    print()
    print(f"FINISH_ARMS {passed}/{len(results)}"
          f"{' ALL_OK' if passed == len(results) else ' BROKEN=' + str(len(results) - passed)}")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
