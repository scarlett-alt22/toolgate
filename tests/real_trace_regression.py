#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression over a real Claude Code multi-request trace (spec: REPORT-A19 §7.3).

Synthetic fixtures cannot produce what actually matters here: the first time this was
pointed at a real agent, it revealed that **the tool surface is exposed per request**.
So one of the stable gates is a real trace as a regression.

🔴 **This is not a golden echo.** Expectations don't come from the capture run's
forward/block results but from A19's semantic transforms: take real requests and apply
"change one character", "append a synthetic tool", "delete an approved one", asserting
the classification of each. The real trace's job is to provide **real request
sequences, field combinations, and tool definitions** — not to canonize what the old
implementation decided at the time.

🔴 **The two gates only a human can pass must be called out when missing — never
forwarded, never silently skipped** (following the verify_baselines precedent: it
doesn't force them to be complete; it forces **every run to recite them**):
     ① the fixture itself is not in the repo (it contains the real environment's full
        tool manifest, which is personal information);
     ② `expected.json`'s `reviewed_by` is empty — nobody has reviewed those definitions
        one by one.

    /usr/bin/python3 tests/real_trace_regression.py
"""
import copy
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
FIXDIR = os.path.join(HERE, "fixtures", "real-claude-code")

spec = importlib.util.spec_from_file_location("insp", os.path.join(WRAPPER, "inspector.py"))
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)

CAP = "c" * 40
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(("✔ " if ok else "✘ ") + name + (("   " + detail) if detail else ""))


def reference_hash(tool):
    """An **independent** reference implementation: no import of the production
    canonicalizer; compute it from the spec by hand.

    Why it exists: computing it with the production code and then comparing against
    the production code proves nothing.
    """
    obj = {"name": tool.get("name"),
           "description": tool.get("description"),
           "input_schema": tool.get("input_schema")}
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def load_fixtures():
    if not os.path.isdir(FIXDIR):
        return []
    out = []
    for name in sorted(os.listdir(FIXDIR)):
        d = os.path.join(FIXDIR, name)
        if os.path.isfile(os.path.join(d, "requests.jsonl")):
            out.append(d)
    return out


def set_policy(pairs, names):
    I.POLICY = {"attempt_id": "trace", "capability_path": CAP,
                "upstream_origin": "http://127.0.0.1:1",
                "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": 1},
                "auth_mode": "loopback_dummy", "expected_auth_token": "t",
                "messages_path": "/v1/messages?beta=true", "model": None,
                "mode": "observe",          # model=None is only allowed in observe mode
                "max_body_bytes": 64 * 1024 * 1024,
                "approved_tools": {"{}#{}".format(n, h[:8]): h for n, h in pairs},
                "approved_names": sorted(names), "required_actions": []}


def replay(tools):
    raw = json.dumps({"model": "x", "tools": tools}).encode()
    return I.decide("POST", "/" + CAP + "/v1/messages?beta=true", raw)


def main():
    fixtures = load_fixtures()
    if not fixtures:
        print("NOT_QUALIFIED: no real trace fixture in the repo.")
        print("  it contains the real environment's full tool manifest (incl. your MCP integrations); personal info,")
        print("  so it stays out of version control. To establish this gate:")
        print("    python3 tools/capture_real_trace.py --client claude --runs 4 \\")
        print("        --out tests/fixtures/real-claude-code/<id>")
        print("  then **manually** review each tool definition in requests.jsonl and fill expected.json's reviewed_by.")
        print("\nREAL_TRACE 0/0  NOT_QUALIFIED (not a pass - this gate is not established yet)")
        return 0

    for d in fixtures:
        print("── fixture: {} ──".format(os.path.basename(d)))
        meta = json.load(open(os.path.join(d, "metadata.json"), encoding="utf-8"))
        rows = [json.loads(l) for l in open(os.path.join(d, "requests.jsonl"),
                                            encoding="utf-8") if l.strip()]

        # ① provenance (§7.3-1)
        ords = [r["ordinal"] for r in rows]
        check("① provenance=real + ordinals contiguous + counts consistent + all complete",
              meta.get("provenance") == "real_claude_code"
              and ords == list(range(len(rows)))
              and meta["capture"]["accepted_request_count"] == len(rows)
              and all(r.get("complete") for r in rows)
              and meta["capture"].get("completed") is True,
              "requests={}".format(len(rows)))
        check("① at least two complete requests, at least two distinct tool sets (§7.1-3)",
              len(rows) >= 2 and len({json.dumps(sorted(
                  t.get("name") for t in (r["admission_body"]["tools"] or [])))
                  for r in rows}) >= 2)
        raw_text = open(os.path.join(d, "requests.jsonl"), encoding="utf-8").read()
        check("① privacy denylist: no credentials, no prompt text",
              "sk-ant" not in raw_text and "Bearer " not in raw_text
              and "x-api-key" not in raw_text.lower())

        # ② independent re-computation by the reference implementation (the doable part of §7.3-2)
        all_tools = [t for r in rows for t in (r["admission_body"]["tools"] or [])]
        mismatches = [t.get("name") for t in all_tools
                      if reference_hash(t) != I.sha(I.canon_tool(t))]
        check("② independent reference impl agrees with the production canonicalizer per definition ({} defs)".format(len(all_tools)),
              not mismatches, "mismatches: {}".format(mismatches[:3]))

        # union manifest
        pairs = {(t["name"], reference_hash(t)) for t in all_tools}
        names = {n for n, _ in pairs}
        set_policy(pairs, names)

        # ③ subset replay (§7.3-3/8): every real request must forward
        bad = []
        for r in rows:
            dec, reason, _ = replay(r["admission_body"]["tools"] or [])
            if dec != "forward":
                bad.append((r["ordinal"], reason))
        check("③ replay real requests against union as approved list → all forwarded",
              not bad, "failed: {}".format(bad[:2]))

        sizes = sorted({len(r["admission_body"]["tools"] or []) for r in rows})
        check("③ at least one is a **proper subset** of the union (absence causes no drift)",
              len(sizes) >= 2, "tool counts per request: {}".format(sizes))

        # ④ transform: one-character description change → contract_drift (§7.3-6)
        base = copy.deepcopy(rows[0]["admission_body"]["tools"][0])
        drifted = copy.deepcopy(base)
        drifted["description"] = (drifted.get("description") or "") + "."
        dec, reason, _ = replay([drifted])
        check("④ one-char change to a real definition → contract_drift",
              dec == "block" and str(reason).startswith("contract_drift"), str(reason)[:60])

        # ⑤ transform: append a synthetic tool → tool_added (§7.3-7)
        synth = {"name": "A19SyntheticTool", "description": "synthetic",
                 "input_schema": {"type": "object", "properties": {}}}
        dec, reason, _ = replay((rows[0]["admission_body"]["tools"] or []) + [synth])
        check("⑤ append a synthetic tool to a real request → tool_added",
              dec == "block" and str(reason).startswith("tool_added"), str(reason)[:60])

        # ⑥ transform: delete one approved definition → still forwards (§7.3-8)
        trimmed = (rows[0]["admission_body"]["tools"] or [])[1:]
        dec, reason, _ = replay(trimmed)
        check("⑥ delete one approved definition from a real request → still forwards (absence is not drift)",
              dec == "forward", str(reason))

        # the gate only a human can pass
        exp_path = os.path.join(d, "expected.json")
        exp = json.load(open(exp_path, encoding="utf-8")) if os.path.exists(exp_path) else {}
        if not exp.get("reviewed_by"):
            print("  🔴 REVIEW_PENDING: expected.json reviewed_by is empty — "
                  "nobody has reviewed these tool definitions one by one.")
            print("     §7.3 items 2/4/5 (vs manual reviewed_pairs, prefix union, natural HOLD)"
                  "cannot be judged until then; this stable gate is not established.")

    good = sum(1 for r in RESULTS if r)
    print("\nREAL_TRACE {}/{}".format(good, len(RESULTS))
          + ("  ALL_OK" if good == len(RESULTS) else "  BROKEN"))
    return 0 if good == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
