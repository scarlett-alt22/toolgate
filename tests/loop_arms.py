#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Closed-loop positive/negative arms — the **re-runnable** version.

★ Why it exists, as of 2026-08-09 — two reasons, both from external review A8:
  ① The 08-08 closed loop was **hand-run**: only the artifacts survived, not the
     procedure. A8 therefore said the `FINISH_THREE_ARMS 5/5` input fixtures
     weren't committed with the package — "the current package can't
     independently recompute those five cells".
     **Evidence that can't be re-run is closer to no evidence than you'd think.**
  ② That round's `success` was retracted: the loop mock returned the same
     `toolu_loop_1` every time, so one tool_result could match two tool_uses.
     The mock is fixed (unique ids, `tools=[]` returns no client tool use);
     here both arms are re-run.

🔴 Zero API cost: uses the `read-shadow-loopback` profile = `auth_mode=loopback_dummy`,
   upstream is the loop_mock on local 127.0.0.1:53127. The real CLI, the fake
   upstream, and the real keychain are never touched.

    /usr/bin/python3 tests/loop_arms.py [--keep]
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
PROFILE_ID = "read-shadow-loopback"
RUNS = os.path.join(WRAPPER, "runs")
EVIDENCE = os.path.join(WRAPPER, "evidence-loop")

TASK = ("Read the sentinel file in your input directory and reply with the challenge "
        "string on the first line, then the required JSON object.")

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))
    return bool(ok)


def mock_port():
    """The port is fixed by the profile (upstream_origin); never guessed."""
    prof = json.load(open(os.path.join(WRAPPER, "profiles", PROFILE_ID + ".json")))
    return int(prof["upstream_origin"].rsplit(":", 1)[1])


def port_free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def newest_attempt(before):
    cands = [d for d in os.listdir(RUNS)
             if os.path.isdir(os.path.join(RUNS, d)) and d not in before]
    if not cands:
        return None
    return os.path.join(RUNS, max(cands, key=lambda d: os.path.getmtime(os.path.join(RUNS, d))))


def run_arm(mode, port):
    """Start mock → run one full hb-run round → collect artifacts. Returns (attempt_dir, cli_rc, stats)."""
    before = set(os.listdir(RUNS)) if os.path.isdir(RUNS) else set()
    mock = subprocess.Popen(
        ["/usr/bin/python3", os.path.join(TESTS, "loop_mock.py"),
         "--port", str(port), "--runs", RUNS, "--mode", mode],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True)
    try:
        deadline = time.time() + 15
        ready = False
        while time.time() < deadline:
            line = mock.stdout.readline()
            if line.startswith("READY"):
                ready = True
                break
            if mock.poll() is not None:
                break
        if not ready:
            raise RuntimeError(f"loop_mock({mode}) failed to start")

        proc = subprocess.run([os.path.join(WRAPPER, "hb-run.sh"), PROFILE_ID, TASK],
                              capture_output=True, text=True, timeout=300)
        adir = newest_attempt(before)
        try:
            stats = json.load(urllib.request.urlopen(
                f"http://127.0.0.1:{port}/__mock/stats", timeout=5))
        except Exception:
            stats = {}
        return adir, proc.returncode, stats, proc.stdout + proc.stderr
    finally:
        mock.terminate()
        try:
            mock.wait(timeout=5)
        except Exception:
            mock.kill()


def load(adir, name):
    p = os.path.join(adir, name)
    if not os.path.exists(p):
        return None
    if name.endswith(".jsonl"):
        out = []
        for line in open(p):
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
    return json.load(open(p))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep attempt directories")
    args = ap.parse_args()

    port = mock_port()
    if not port_free(port):
        print(f"port {port} is occupied — refusing to run the closed loop without knowing who the upstream is", file=sys.stderr)
        return 2

    os.makedirs(EVIDENCE, exist_ok=True)
    summary = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "arms": {}}

    # ── Positive arm ───────────────────────────────────────────────────────────
    adir, rc, stats, _log = run_arm("normal", port)
    check("positive arm: produced an attempt directory", adir is not None, str(adir))
    if adir:
        term = load(adir, "terminal.json") or {}
        insp = load(adir, "inspector.jsonl") or []
        uses = [e for e in insp if e.get("event") == "tool_use_seen"]
        results = [e for e in insp if e.get("event") == "tool_result_seen"]
        terms = [e for e in insp if e.get("event") == "response_scan_terminal"]
        ids = [u.get("tool_use_id") for u in uses]
        summary["arms"]["normal"] = {
            "attempt_dir": os.path.basename(adir), "hb_run_rc": rc,
            "outcome": term.get("outcome"), "tool_use_ids": ids,
            "tool_result_ids": [r.get("tool_use_id") for r in results],
            "scan_terminals": [{k: t.get(k) for k in ("outcome", "reason_code", "format",
                                                      "tool_use_count")} for t in terms],
            "mock_stats": stats,
        }
        check("positive arm: terminal is success", term.get("outcome") == "success",
              f"outcome={term.get('outcome')}")
        # 🔴 This is the direct fix for what 08-08 retracted: ids must be pairwise distinct.
        check("positive arm: each tool_use_id unique (no longer the same toolu_loop_1)",
              len(ids) == len(set(ids)) and len(ids) >= 1, f"ids={ids}")
        check("positive arm: every tool_result maps to exactly one tool_use",
              all(r.get("tool_use_id") in set(ids) for r in results) and len(results) >= 1
              and len({r.get("tool_use_id") for r in results}) == len(results),
              f"results={[r.get('tool_use_id') for r in results]}")
        check("positive arm: every required response has a closed scan event and outcome=ok",
              terms and all(t.get("outcome") == "ok" for t in terms),
              f"{len(terms)} closed events")
        check("positive arm: mock never answered tools=[] with a client tool use",
              stats.get("no_tools_text_sent", 0) >= 0
              and stats.get("tool_use_sent", 0) == len(ids),
              f"tool_use_sent={stats.get('tool_use_sent')} received {len(ids)}")
        if not args.keep:
            shutil.copytree(adir, os.path.join(EVIDENCE, "normal"), dirs_exist_ok=True)

    # ── Negative arm (anti-self-certification) ────────────────────────────────────────────────────
    adir2, rc2, stats2, _log2 = run_arm("selfcert", port)
    check("negative arm: produced an attempt directory", adir2 is not None, str(adir2))
    if adir2:
        term2 = load(adir2, "terminal.json") or {}
        insp2 = load(adir2, "inspector.jsonl") or []
        uses2 = [e for e in insp2 if e.get("event") == "tool_use_seen"]
        terms2 = [e for e in insp2 if e.get("event") == "response_scan_terminal"]
        summary["arms"]["selfcert"] = {
            "attempt_dir": os.path.basename(adir2), "hb_run_rc": rc2,
            "outcome": term2.get("outcome"), "tool_use_count": len(uses2),
            "scan_terminals": [{k: t.get(k) for k in ("outcome", "reason_code")}
                               for t in terms2],
            "mock_stats": stats2,
        }
        check("negative arm: mock copied the challenge into text yet must **not** get success",
              term2.get("outcome") == "obligation_failed",
              f"outcome={term2.get('outcome')}")
        check("negative arm: zero tool_use at all", len(uses2) == 0, f"n={len(uses2)}")
        # The key distinction: the negative arm must fail because "the model didn't do it", not because "we misread it".
        check("negative arm: all scans ok — the failure is attributed to the lower bound, not the observer",
              terms2 and all(t.get("outcome") == "ok" for t in terms2),
              json.dumps([t.get("reason_code") for t in terms2]))
        if not args.keep:
            shutil.copytree(adir2, os.path.join(EVIDENCE, "selfcert"), dirs_exist_ok=True)

    # 🔴 Cross-arm: the two arms each run in their own process, so ids are naturally distinct — this **cannot**
    #    count as attempt-level uniqueness evidence; that evidence lives in sse_redgreen ⑨.
    json.dump(summary, open(os.path.join(EVIDENCE, "summary.json"), "w"),
              ensure_ascii=False, indent=2)

    width = max(len(n) for n, _, _ in RESULTS) if RESULTS else 10
    bad = 0
    for name, ok, detail in RESULTS:
        if not ok:
            bad += 1
        print(f"{'✔' if ok else '✘'} {name.ljust(width)}  {detail}")
    print()
    print(f"LOOP_ARMS {len(RESULTS) - bad}/{len(RESULTS)}"
          f"{'  ALL_OK' if bad == 0 else '  BROKEN=' + str(bad)}")
    print(f"evidence: {EVIDENCE}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
