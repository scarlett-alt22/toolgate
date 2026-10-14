#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture a **real** agent's multi-request trace as a regression fixture. Spec: REPORT-A19
§7.1/§7.2.

    python3 tools/capture_real_trace.py --client claude --runs 3 \
        --prompt "reply with the single word: ok" --out tests/fixtures/real-claude-code/<id>

Why it's needed: hand-made fixtures cannot produce the behavior that actually matters here.
The first time this was pointed at a real agent, it revealed that **the tool surface is
exposed per request** — no mock would ever show that.

🔴 Three boundaries (all from A19; dropping any one disqualifies the fixture):
  ① **Privacy is done before anything lands on disk**: prompt/messages bodies, headers,
     Authorization, and tool input/result never enter the capture's field of view. If that
     can't be done, the capture must be judged unqualified — not cleaned up after the fact.
  ② **The allow/block outcomes from capture time are provenance only**, never a regression
     oracle — recording an old implementation's decisions and re-comparing them is golden
     echo.
  ③ **`expected.json` must be reviewed by a human**. This script only generates the skeleton
     with `reviewed_by: null`; until someone fills it in, the regression test must judge
     "NOT_QUALIFIED", not pass.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)


def sha_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def client_version(client):
    try:
        out = subprocess.run([client, "--version"], capture_output=True, text=True,
                             timeout=60)
        return (out.stdout or out.stderr).strip()
    except Exception:                                            # noqa: BLE001
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--client", default="claude")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--prompt", default="reply with the single word: ok")
    ap.add_argument("--out", required=True)
    ap.add_argument("--fixture-id", default=None)
    a = ap.parse_args()

    client_path = shutil.which(a.client)
    if not client_path:
        raise SystemExit("client executable not found: {}".format(a.client))
    ver = client_version(client_path)
    if not ver:
        # §7.1(4): no client version means unqualified — no filling the gap by guessing
        raise SystemExit("could not get the client version — per A19 §7.1 this capture is unqualified")

    from toolgate import config as cfg_mod
    from toolgate import runner as run_mod

    home = tempfile.mkdtemp(prefix="toolgate-capture-")
    cfg = dict(cfg_mod.DEFAULT_CONFIG)
    cfg.update(cfg_mod.PRESETS["anthropic"])
    cfg_mod.save_config(home, cfg)
    capture_path = os.path.join(home, "capture.jsonl")

    # have the inspector started by the runner write the admission projection to capture_path
    orig_build = run_mod.build_policy

    def build_with_capture(d, c, mode, run_dir):
        pol = orig_build(d, c, mode, run_dir)
        pol["capture_path"] = capture_path
        return pol

    run_mod.build_policy = build_with_capture

    run_ids, exits = [], []
    for _ in range(a.runs):
        rc, _log, run_dir = run_mod.run(home, cfg, "observe",
                                        [client_path, "-p", a.prompt])
        run_ids.append(os.path.basename(run_dir))
        exits.append(rc)
        time.sleep(1)

    rows = []
    if os.path.exists(capture_path):
        with open(capture_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
    # consecutive ordinals: one global and one per-run, both required (§7.2)
    per_run = {}
    for i, r in enumerate(rows):
        r["ordinal"] = i
        per_run[r["run_id"]] = per_run.get(r["run_id"], -1) + 1
        r["ordinal_in_run"] = per_run[r["run_id"]]

    out = os.path.abspath(a.out)
    os.makedirs(out, exist_ok=True)
    fid = a.fixture_id or os.path.basename(out)

    meta = {
        "schema_version": 1,
        "fixture_id": fid,
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "provenance": "real_claude_code",
        "client": {"product": a.client, "version_stdout": ver,
                   "executable_sha256": sha_file(os.path.realpath(client_path))},
        "capture_harness": {
            "path": "tools/capture_real_trace.py",
            "sha256": sha_file(os.path.join(REPO, "tools", "capture_real_trace.py")),
        },
        "host": {"os": platform.system(), "arch": platform.machine()},
        "profile": {
            "wire_format": {"value": cfg["wire_format"], "source": "config"},
            "endpoint": {"value": cfg["messages_path"], "source": "config"},
            "client_version": {"value": ver, "source": "client --version"},
            "invocation_mode": {"value": "print", "source": "argv (-p)"},
            # unobservable → write unknown — never guess from tool names (A19 §5.1)
            "permission_mode": {"value": "unknown", "source": "not observable on the wire"},
            "project_config": {"value": "unknown", "source": "not observable on the wire"},
        },
        "launch": {
            "argv_shape": [a.client, "-p", "<redacted>"],
            "project_config_sha256": "unknown",
            "feature_config_sha256": "unknown",
        },
        "capture": {
            "run_count": len(run_ids),
            "accepted_request_count": len(rows),
            "client_exit_codes": exits,
            "completed": all(r.get("complete") for r in rows) and bool(rows),
        },
        "privacy": {"omitted_fields": ["headers", "authorization", "x-api-key",
                                       "messages", "prompt", "tool_input", "tool_result",
                                       "response_body"]},
    }
    with open(os.path.join(out, "metadata.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1, sort_keys=True)
    with open(os.path.join(out, "requests.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")

    # expected.json gets only the skeleton. 🔴 reviewed_by must be filled in by a human —
    # the capture program copying its own output as the "expectation" is exactly what A19
    # calls golden echo.
    expected_path = os.path.join(out, "expected.json")
    if not os.path.exists(expected_path):
        with open(expected_path, "w", encoding="utf-8") as f:
            json.dump({
                "schema_version": 1,
                "reviewed_by": None,
                "reviewed_at": None,
                "review_note": "Until a human has reviewed the tool definitions in "
                               "requests.jsonl line by line, this fixture is unqualified; "
                               "the regression test must judge NOT_QUALIFIED on that basis.",
                "reviewed_pairs": [],
                "expected_request_pair_sets": [],
                "expected_union": [],
            }, f, ensure_ascii=False, indent=1, sort_keys=True)

    print("fixture: {}".format(out))
    print("  runs={} requests={} completed={}".format(
        meta["capture"]["run_count"], meta["capture"]["accepted_request_count"],
        meta["capture"]["completed"]))
    sets = {json.dumps(sorted((t or {}).get("name", "?") for t in
                              (r["admission_body"]["tools"] or [])))
            for r in rows}
    print("  distinct tool-name sets: {}".format(len(sets)))
    print("  🔴 expected.json needs a human review before filling in reviewed_by, otherwise the regression judges NOT_QUALIFIED")
    shutil.rmtree(home, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
