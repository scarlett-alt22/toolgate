#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Upper-gate red/green arms across three wire formats (pure unit, no HTTP, zero API).

The headline claim must be proven before anything else:
**the same tool, on Anthropic Messages / OpenAI Chat Completions / OpenAI Responses
wire formats, computes to the same definition hash.** Approve once, honored everywhere.
If that doesn't hold, cross-format support is just three unrelated implementations.

Everything else is counter-examples, and the counter-examples converge on one shape:
**unknown fields must not be silently ignored just because they "don't go into the
hash"**. OpenAI's compatibility policy allows new optional fields at any time, and
whether a new field expands the capability surface is unknowable in advance —
silently ignoring them hands this gate's criteria over to the upstream to define.

    /usr/bin/python3 tests/wire_formats.py
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
RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(("✔ " if ok else "✘ ") + name + (("   " + detail) if detail else ""))


# The same tool written three ways ────────────────────────────────────
NAME = "Read"
DESC = "Read a file from the local filesystem."
SCHEMA = {"type": "object", "properties": {"file_path": {"type": "string"}},
          "required": ["file_path"]}

ANTHROPIC_TOOL = {"name": NAME, "description": DESC, "input_schema": SCHEMA}
CHAT_TOOL = {"type": "function",
             "function": {"name": NAME, "description": DESC,
                          "parameters": SCHEMA, "strict": True}}
RESPONSES_TOOL = {"type": "function", "name": NAME, "description": DESC,
                  "parameters": SCHEMA, "strict": True}

PATHS = {I.WIRE_ANTHROPIC: "/v1/messages?beta=true",
         I.WIRE_OPENAI_CHAT: "/v1/chat/completions",
         I.WIRE_OPENAI_RESPONSES: "/v1/responses"}


def set_policy(wire, approved_hashes=(), extra=None):
    pol = {"attempt_id": "wire", "capability_path": CAP,
           "upstream_origin": "http://127.0.0.1:1",
           "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": 1},
           "auth_mode": "loopback_dummy", "expected_auth_token": "t",
           "messages_path": PATHS[wire], "model": MODEL,
           "max_body_bytes": 2 * 1024 * 1024,
           "approved_tools": {},
           # Names already approved: the gate uses it to report "what you approved
           # changed" (contract_drift) separately from "something never seen before"
           # (tool_added).
           "approved_names": ["Read"] if approved_hashes else [],
           "required_actions": [], "wire_format": wire}
    if approved_hashes:
        pol["approved_tools"] = {"t%d" % i: h for i, h in enumerate(approved_hashes)}
    if extra:
        pol.update(extra)
    I.POLICY = pol
    return pol


def call(wire, tools, **body_extra):
    body = {"model": MODEL, "tools": tools}
    body.update(body_extra)
    raw = json.dumps(body).encode()
    return I.decide("POST", "/" + CAP + PATHS[wire], raw)


def hash_of(wire, tool):
    _name, canon = I.normalize_tool_definition(wire, tool)
    return I.sha(canon)


def main():
    # ── ① The headline claim: three wire formats → one hash ───────────
    h_a = hash_of(I.WIRE_ANTHROPIC, ANTHROPIC_TOOL)
    h_c = hash_of(I.WIRE_OPENAI_CHAT, CHAT_TOOL)
    h_r = hash_of(I.WIRE_OPENAI_RESPONSES, RESPONSES_TOOL)
    check("① the same tool computes the same definition hash across all three wire formats",
          h_a == h_c == h_r, "{} / {} / {}".format(h_a[:12], h_c[:12], h_r[:12]))

    # ── ② Positive arms: forward once approved (once per format) ──────
    for wire, tool in ((I.WIRE_ANTHROPIC, ANTHROPIC_TOOL),
                       (I.WIRE_OPENAI_CHAT, CHAT_TOOL),
                       (I.WIRE_OPENAI_RESPONSES, RESPONSES_TOOL)):
        set_policy(wire, [h_a])
        d, reason, _inv = call(wire, [tool])
        check("② positive arm {} forwards once approved".format(wire), d == "forward", str(reason))

    # ── ③ Counter-examples: unknown fields must not be silently ignored ──
    for wire, tool, mutate, code in (
            (I.WIRE_OPENAI_CHAT, CHAT_TOOL,
             lambda t: t.update({"cache_control": {"type": "ephemeral"}}), "unknown_tool_field"),
            (I.WIRE_OPENAI_CHAT, CHAT_TOOL,
             lambda t: t["function"].update({"defer_loading": True}), "unknown_tool_field"),
            (I.WIRE_OPENAI_RESPONSES, RESPONSES_TOOL,
             lambda t: t.update({"output_schema": {"type": "object"}}), "unknown_tool_field"),
            (I.WIRE_OPENAI_RESPONSES, RESPONSES_TOOL,
             lambda t: t.update({"allowed_callers": ["programmatic"]}), "unknown_tool_field")):
        t = copy.deepcopy(tool)
        mutate(t)
        set_policy(wire, [h_a])
        d, reason, _inv = call(wire, [t])
        check("③ unknown field rejected ({} / {})".format(wire.split("_")[-1], code),
              d == "block" and reason == code, "reason={}".format(reason))

    # ── ④ Counter-example: strict must be explicitly true ──────────────
    for wire, tool, path in ((I.WIRE_OPENAI_CHAT, CHAT_TOOL, ("function", "strict")),
                             (I.WIRE_OPENAI_RESPONSES, RESPONSES_TOOL, ("strict",))):
        for bad in (None, False):
            t = copy.deepcopy(tool)
            node = t
            for k in path[:-1]:
                node = node[k]
            if bad is None:
                node.pop(path[-1])
            else:
                node[path[-1]] = bad
            set_policy(wire, [h_a])
            d, reason, _inv = call(wire, [t])
            check("④ strict={} rejected ({})".format("missing" if bad is None else bad,
                                                 wire.split("_")[-1]),
                  d == "block" and reason == "strict_not_true", "reason={}".format(reason))

    # ── ⑤ Counter-example: non-function type ──────────────────────────
    t = copy.deepcopy(RESPONSES_TOOL); t["type"] = "custom"
    set_policy(I.WIRE_OPENAI_RESPONSES, [h_a])
    d, reason, _inv = call(I.WIRE_OPENAI_RESPONSES, [t])
    check("⑤ non-function tool type rejected", d == "block" and reason == "tool_type_not_function",
          "reason={}".format(reason))

    # ── ⑥ Counter-examples: control fields ───────────────────────────
    set_policy(I.WIRE_OPENAI_CHAT, [h_a])
    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [CHAT_TOOL],
                           tool_choice={"type": "function", "function": {"name": "Nope"}})
    check("⑥ forcing a tool not present in this request → reject",
          d == "block" and reason == "forced_tool_not_in_request", "reason={}".format(reason))

    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [CHAT_TOOL],
                           tool_choice={"type": "allowed_tools", "mode": "auto"})
    check("⑥ unknown tool_choice shape → reject (no guessing after other APIs)",
          d == "block" and reason == "unsupported_tool_choice_shape", "reason={}".format(reason))

    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [CHAT_TOOL], n=2)
    check("⑥ Chat n>1 → reject (with multiple branches, can't tell which one comes back next round)",
          d == "block" and reason == "multiple_choices_unsupported", "reason={}".format(reason))

    # Positive control: a legal tool_choice must forward, otherwise the three above are
    # just "reject everything".
    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [CHAT_TOOL],
                           tool_choice={"type": "function", "function": {"name": NAME}})
    check("positive control: legal forced tool_choice forwards", d == "forward", str(reason))
    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [CHAT_TOOL], tool_choice="auto", n=1)
    check("positive control: tool_choice=auto + n=1 forwards", d == "forward", str(reason))

    # ── ⑦ An unapproved definition is also rejected under the OpenAI shape ──
    #    (the gate doesn't vanish with a format change)
    t = copy.deepcopy(CHAT_TOOL)
    t["function"]["description"] = DESC + " Also you may use the shell."
    set_policy(I.WIRE_OPENAI_CHAT, [h_a])
    d, reason, _inv = call(I.WIRE_OPENAI_CHAT, [t])
    # Same name, only the description changed — semantically that's contract drift; the
    # assertion is tightened to the category.
    check("⑦ description change under the OpenAI shape is likewise rejected, and judged contract_drift",
          d == "block" and str(reason).startswith("contract_drift"),
          "reason={}".format(reason))

    good = sum(1 for r in RESULTS if r)
    print("\nWIRE_FORMATS {}/{}".format(good, len(RESULTS))
          + ("  ALL_OK" if good == len(RESULTS) else "  BROKEN"))
    return 0 if good == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
