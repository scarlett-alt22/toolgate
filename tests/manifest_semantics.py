#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Set semantics of the approved manifest (spec from external ruling A18 §Q4).

    tools in request ⊆ approved manifest   → forward
    approved name + new hash               → block (contract_drift)
    never-approved name or definition      → block (tool_added)
    approved tool absent this round        → **not drift**, just undisclosed this round
    one name may carry several approved definitions → all forward

This group exists because of real traffic: `claude -p` run twice with the same command
advertised `Agent` on one run and `Bash` on the other. Treating "this round's tool set"
as an identity that must be equal round over round would flag always-legitimate traffic
as drift — and that bug is **invisible** in tests that only ever send one tool.

🔴 "Absence is not drift" is the easiest thing to write as a vacuously true assertion.
This test is constructed **approve two, send one**: any implementation that demands
"the request set must equal the approved set" goes red here.

    /usr/bin/python3 tests/manifest_semantics.py
"""
import copy
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
spec = importlib.util.spec_from_file_location("insp", os.path.join(WRAPPER, "inspector.py"))
I = importlib.util.module_from_spec(spec)
spec.loader.exec_module(I)

CAP = "c" * 40
MODEL = "test-model"
MPATH = "/v1/messages?beta=true"
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(("✔ " if ok else "✘ ") + name + (("   " + detail) if detail else ""))


def tool(name, desc):
    return {"name": name, "description": desc,
            "input_schema": {"type": "object", "properties": {}}}


READ_V1 = tool("Read", "Read a file.")
READ_V2 = tool("Read", "Read a file. You may also use the shell.")
BASH = tool("Bash", "Run a command.")
AGENT = tool("Agent", "Spawn a sub-agent.")


def h(t):
    return I.sha(I.canon_tool(t))


def set_policy(approved_tools, approved_names):
    I.POLICY = {"attempt_id": "mf", "capability_path": CAP,
                "upstream_origin": "http://127.0.0.1:1",
                "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": 1},
                "auth_mode": "loopback_dummy", "expected_auth_token": "t",
                "messages_path": MPATH, "model": MODEL,
                "max_body_bytes": 2 * 1024 * 1024,
                # The keys are just identifiers; the gate only looks at the values set, so one
                # name can have several approved definitions.
                "approved_tools": {"{}#{}".format(t["name"], h(t)[:8]): h(t)
                                   for t in approved_tools},
                "approved_names": approved_names,
                "required_actions": []}


def call(tools):
    raw = json.dumps({"model": MODEL, "tools": tools}).encode()
    return I.decide("POST", "/" + CAP + MPATH, raw)


def main():
    # ── ① Forward subsets (empty set included) ─────────────────────────
    set_policy([READ_V1, BASH, AGENT], ["Read", "Bash", "Agent"])
    for label, tools in (("empty tool set", []),
                         ("send one", [READ_V1]),
                         ("send two", [READ_V1, BASH]),
                         ("send all", [READ_V1, BASH, AGENT])):
        d, reason, _ = call(tools)
        check("① subset forwards: {}".format(label), d == "forward", str(reason))

    # ── ② 🔴 Absence is not drift ──────────────────────────────────────
    # Three approved, one disclosed this round. Any implementation that treats
    # "this round's set" as required to equal the approved set goes red here.
    d, reason, _ = call([AGENT])
    check("② 🔴 three approved, one disclosed this round → forward (absence is not drift)",
          d == "forward", str(reason))

    # ── ③ One name may carry several approved definitions ──────────────
    set_policy([READ_V1, READ_V2], ["Read"])
    for label, t in (("variant one", READ_V1), ("variant two", READ_V2)):
        d, reason, _ = call([t])
        check("③ several approved definitions under one name: {} forwards".format(label), d == "forward", str(reason))

    # ── ④ Approved name + unapproved hash → contract_drift ─────────────
    set_policy([READ_V1], ["Read"])
    d, reason, _ = call([READ_V2])
    check("④ same name, definition changed → contract_drift",
          d == "block" and str(reason).startswith("contract_drift"), str(reason))

    # ── ⑤ Never-approved name → tool_added ─────────────────────────────
    d, reason, _ = call([BASH])
    check("⑤ never-approved tool → tool_added (reported separately from drift)",
          d == "block" and str(reason).startswith("tool_added"), str(reason))

    # 🔴 Converse: without approved_names, added must not be misreported as drift.
    set_policy([READ_V1], [])
    d, reason, _ = call([BASH])
    check("⑤ converse: when it is unknown whether the name was ever approved, report tool_added, not drift",
          d == "block" and str(reason).startswith("tool_added"), str(reason))

    # ── ⑤b Duplicate name within one request: block even if both are approved, with an
    #      independent shape reason ──
    # A19 §S1: "one name may carry several approved definitions" means **appearing
    # in separate requests**. A duplicate name within one round is ambiguity, not legal
    # polymorphism; and the error must not misreport it as contract_drift.
    set_policy([READ_V1, READ_V2], ["Read"])
    d, reason, _ = call([READ_V1, READ_V2])
    check("⑤b two same-named definitions in one request (both approved) → block, and report duplicate_tool_name, not drift",
          d == "block" and str(reason).startswith("duplicate_tool_name"), str(reason))

    # ── ⑥ Positive control: with an empty approved set nothing forwards ──
    #    (the criterion is not "always forward")
    set_policy([], [])
    d, reason, _ = call([READ_V1])
    check("positive control: empty approved set → block (otherwise the forwards above prove nothing)",
          d == "block", str(reason))

    good = sum(1 for r in RESULTS if r)
    print("\nMANIFEST_SEMANTICS {}/{}".format(good, len(RESULTS))
          + ("  ALL_OK" if good == len(RESULTS) else "  BROKEN"))
    return 0 if good == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
