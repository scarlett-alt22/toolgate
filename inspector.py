#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capability upper-bound gate, applied before forwarding. v2 — 2026-08-08, rewritten per inspector-review2 §D.

It is the only place in this system that can see "which tools were actually advertised this round":
the top level of the CLI's `--output-format json` has no tools field, and neither do the debug logs (measured 08-07).

🔴 **The block must happen before forwarding.** The first version on 08-07 graded after the fact and was caught by Codex's review:
in one turn Bash really was advertised extra, and the model could use it at that very moment — grading afterwards cannot undo side effects.

v2 changes five things relative to v1, each answering a P0 Codex raised:
  ① **malformed no longer fails open**. v1 treated a body parse failure as "no tools" and forwarded it;
     now any parse failure is blocked. **"Can't read it" does not mean "safe".**
  ② **Judge by full-definition hash, not just by name**. v1 looked only at the tool name, so
     "same-name Read with a swapped schema" and "duplicate Read" both got through.
  ③ **Approved values are read only from the hash-locked policy snapshot written by the wrapper**, never from the ambient env.
     v1 read HB_INSPECTOR_ALLOWED_TOOLS, which let an environment variable decide how wide the gate was.
  ④ **capability path**: a random ≥128-bit prefix; requests to the wrong path are never recognised —
     which also separates "some other process happened to connect to this port" from this run's requests.
  ⑤ **Every 3xx is recorded as an upstream error and not followed**; a blocked request never has forward_started_at.

🔴 Logging discipline (spec:306): **never log headers, API keys, prompt/messages bodies,
raw tool input, or raw tool results.** Things that need evidence, like paths, are kept only as sha256.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

MAX_BODY_BYTES_DEFAULT = 2 * 1024 * 1024

POLICY = None
LOG_LOCK = threading.Lock()
LOG_PATH = None


def sha(b):
    if isinstance(b, str):
        b = b.encode()
    return hashlib.sha256(b).hexdigest()


def log(kind, **fields):
    rec = {"event": kind, "ts": time.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(time.time()*1000)%1000:03d}",
           "attempt_id": POLICY["attempt_id"], **fields}
    with LOG_LOCK:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            f.flush()
            os.fsync(f.fileno())


def canon_tool(obj):
    """Canonical bytes of a tool definition. The full definition, not just the name."""
    # spec:78 mandates UTF-8 + ensure_ascii=false. The default True gives a definition containing non-ASCII
    # a different hash; even if the capturer and the runtime make the same mistake, it cannot be called the spec value.
    return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


class _AmbiguousJSON(ValueError):
    """This body has more than one valid reading. **Don't pick one; reject.**"""


def _reject_duplicate_keys(pairs):
    seen = set()
    for k, _v in pairs:
        if k in seen:
            raise _AmbiguousJSON(f"duplicate key {k!r}")
        seen.add(k)
    return dict(pairs)


def _reject_json_constant(name):
    # NaN / Infinity / -Infinity are not in the JSON spec, yet Python accepts them by default.
    raise _AmbiguousJSON(f"non-standard literal {name}")


def _strict_json_loads(text):
    """The single strict JSON entry point: rejects duplicate keys and the non-standard constants Python accepts by default."""
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                      parse_constant=_reject_json_constant)


# ── Upper-bound decision: runs before forwarding, returns (decision, reason, inventory) ──────────────

# ── Wire-format adapter layer (M3, 2026-08-15, spec from external survey REPORT-A17) ─────────────
# Projects each vendor's wire tool onto **the same semantic triple**, then runs the same canonical hash.
# So the same tool gets the same definition hash on all three wire formats — approve once, recognised everywhere.
#
# 🔴 Two hard constraints, both ruled by A17; dropping either one turns this gate into decoration:
#   ① **Accept only a closed subset**. Unknown/new tool-definition fields **must not be ignored just because "they don't go into the hash"**;
#      they must be rejected before forwarding. OpenAI's compatibility policy allows new optional fields at any time, and whether a new field
#      widens the capability surface is unpredictable — silently ignoring it hands the gate's criteria to the upstream to define.
#   ② **Do not claim equivalence with the existing lower bound**. Chat's role:"tool" and Responses'
#      function_call_output **have no** standard counterpart of Anthropic's `tool_result.is_error`;
#      the standard wire alone can only prove "the result for the same call id was brought back", not "it was not an execution error".
#      So in this version the OpenAI response side is recorded as **unmeasured** — not ok, and never allowed into success.
WIRE_ANTHROPIC = "anthropic_messages"
WIRE_OPENAI_CHAT = "openai_chat_completions"
WIRE_OPENAI_RESPONSES = "openai_responses"
VALID_WIRE_FORMATS = (WIRE_ANTHROPIC, WIRE_OPENAI_CHAT, WIRE_OPENAI_RESPONSES)

# Keys each wire format may carry beyond the semantic triple. **Any other key is rejected.**
_OPENAI_CHAT_TOOL_KEYS = {"type", "function"}
_OPENAI_CHAT_FUNCTION_KEYS = {"name", "description", "parameters", "strict"}
_OPENAI_RESPONSES_TOOL_KEYS = {"type", "name", "description", "parameters", "strict"}


class GateShapeError(ValueError):
    """Non-conforming shape. `code` is a stable reason code that contains no raw content."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def canonical_semantic_tool(name, description, input_schema):
    """Canonical bytes of the semantic triple. Shares the same rules as the Anthropic path.

    🔴 **No semantic rewriting of JSON Schema**: required/enum arrays are not sorted, defaults are not filled in,
       equivalent schemas are not merged. What gets approved is "the canonical representation of the definition I looked at",
       not a schema-equivalence decider that has not been proven correct. Only object keys are sorted.
    """
    return json.dumps({"name": name, "description": description,
                       "input_schema": input_schema},
                      sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def _require(cond, code):
    if not cond:
        raise GateShapeError(code)


def normalize_tool_definition(wire_format, t):
    """provider wire tool → (name, canonical_bytes). Raises GateShapeError if it doesn't conform."""
    _require(isinstance(t, dict), "tool_elem_not_object")

    if wire_format == WIRE_ANTHROPIC:
        # 🔴 The Anthropic branch **stays as it was**: hash the whole tool object.
        #    Switching it to the projection would make every existing approved value and baseline drift — that is a separate change, not one to slip in.
        #    When an Anthropic tool happens to have exactly these three keys, both paths produce the same bytes.
        name = t.get("name")
        _require(isinstance(name, str) and name.strip(), "tool_name_invalid")
        return name, canon_tool(t)

    if wire_format == WIRE_OPENAI_CHAT:
        _require(set(t) <= _OPENAI_CHAT_TOOL_KEYS, "unknown_tool_field")
        _require(t.get("type") == "function", "tool_type_not_function")
        fn = t.get("function")
        _require(isinstance(fn, dict), "function_wrapper_invalid")
        _require(set(fn) <= _OPENAI_CHAT_FUNCTION_KEYS, "unknown_tool_field")
        # strict must be **explicitly true**: by default Chat is not in strict mode, so the schema no longer
        # reliably constrains the arguments the model actually generates — and then approving a schema means nothing.
        _require(fn.get("strict") is True, "strict_not_true")
        name, desc, params = fn.get("name"), fn.get("description"), fn.get("parameters")
    elif wire_format == WIRE_OPENAI_RESPONSES:
        _require(set(t) <= _OPENAI_RESPONSES_TOOL_KEYS, "unknown_tool_field")
        _require(t.get("type") == "function", "tool_type_not_function")
        _require(t.get("strict") is True, "strict_not_true")
        name, desc, params = t.get("name"), t.get("description"), t.get("parameters")
    else:
        raise GateShapeError("unknown_wire_format")

    _require(isinstance(name, str) and name.strip(), "tool_name_invalid")
    _require(isinstance(desc, str), "tool_description_invalid")
    _require(isinstance(params, dict), "tool_parameters_invalid")
    return name, canonical_semantic_tool(name, desc, params)


def validate_request_controls(wire_format, doc, names):
    """Control fields outside the definition that nonetheless change "which tools are actually usable".

    They **do not go into the hash** (changing tool_choice should not turn the same tool into a different one),
    but they **must be validated separately** — otherwise a malformed or unknown-shaped control field could bypass this gate's premise.
    """
    if wire_format == WIRE_ANTHROPIC:
        return
    pc = doc.get("parallel_tool_calls")
    _require(pc is None or isinstance(pc, bool), "parallel_tool_calls_not_bool")
    if wire_format == WIRE_OPENAI_CHAT and "n" in doc:
        # Multiple choices = multiple distinct call branches, and "which one the next request brings back"
        # cannot be determined from the standard wire. This version accepts a single branch only.
        _require(doc.get("n") == 1, "multiple_choices_unsupported")
    tc = doc.get("tool_choice")
    if tc is None or tc in ("none", "auto", "required"):
        return
    _require(isinstance(tc, dict), "unsupported_tool_choice_shape")
    if wire_format == WIRE_OPENAI_CHAT:
        _require(set(tc) == {"type", "function"} and tc.get("type") == "function",
                 "unsupported_tool_choice_shape")
        fn = tc.get("function")
        _require(isinstance(fn, dict) and set(fn) == {"name"},
                 "unsupported_tool_choice_shape")
        forced = fn.get("name")
    else:
        _require(set(tc) == {"type", "name"} and tc.get("type") == "function",
                 "unsupported_tool_choice_shape")
        forced = tc.get("name")
    # The forced choice must appear exactly once in this request, and its definition must already have passed the gate.
    _require(isinstance(forced, str) and names.count(forced) == 1,
             "forced_tool_not_in_request")


def extract_tool_definitions(wire_format, doc):
    """Extract every tool this request advertises; returns [(name, canonical_bytes)].

    🔴 A missing tools field **does not mean** no tools: it means this request doesn't look like what we approved.
    """
    _require("tools" in doc, "tools_field_missing")
    tools = doc["tools"]
    _require(isinstance(tools, list), "tools_not_array")
    return [normalize_tool_definition(wire_format, t) for t in tools]


# ── Run modes (productised 2026-08-15) ────────────────────────────────────────
# 🔴 The default is **enforce**. A policy with no mode must be the blocking tier —
#    "the config left it out" and "I chose to only observe" look identical in the file; the default must sit on the safe side.
#    An invalid value does not fall back to the default; startup rejects it outright (see main()).
MODE_ENFORCE = "enforce"
MODE_OBSERVE = "observe"
VALID_MODES = (MODE_ENFORCE, MODE_OBSERVE)


def record_surface(inv):
    """observe mode: append **newly seen** tool definitions to the tool-surface archive, de-duplicated by hash.

    Why it exists: record only the hash and all the user gets is "it changed"; record the definition and you can say
    "`Read`'s description gained this sentence" — **same data, one is a refusal, the other is intelligence**,
    and intelligence is the entire product value of observe mode.

    🔴 Three boundaries:
      ① Written in both modes (changed 2026-08-15; originally observe only). enforce must also be able to say what it blocked.
      ② It writes an **archive file**, not the event log. Logs get copied and pasted into issues;
         this file contains the raw descriptions of your own tools — treat it like config.
      ③ **A write failure never affects the request path.** This is an observer; a broken observer should not stop traffic.
         A failure records one `surface_write_failed` line and does not raise.
    """
    path = POLICY.get("surface_path")
    if not path:
        return
    try:
        known = set()
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        known.add(json.loads(line).get("definition_sha256"))
        fresh = []
        names = inv.get("tool_names") or []
        for idx, (t, h) in enumerate(zip(inv.get("tool_objects") or [],
                                         inv.get("tool_definition_hashes") or [])):
            if h and h not in known:
                known.add(h)
                fresh.append({"first_seen_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                              # which run first saw it — used to judge whether the tool surface has converged
                              "run": POLICY.get("attempt_id"),
                              "definition_sha256": h,
                              # the normalised name: Chat hides name inside function;
                              # taking the outer object would give null
                              "name": names[idx] if idx < len(names) else None,
                              "definition": t})
        if fresh:
            with open(path, "a", encoding="utf-8") as f:
                for row in fresh:
                    f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
    except Exception as e:                                       # noqa: BLE001
        log("surface_write_failed", error=type(e).__name__)


def record_capture(method, path, doc, inv, complete):
    """Write one admission projection per A19 §7.2, for the real-trace regression fixture.

    🔴 Privacy is done **before writing to disk**, not cleaned afterwards: only the fields admission needs are taken here;
       `messages`/prompt bodies, headers, Authorization, tool input/result **never enter**
       this function's view. Fields that can't be obtained are written explicitly as absent, never faked with empty values.
    🔴 `capture_outcome` is provenance only and **must not be used as a regression oracle** — recording the old implementation's
       decision and re-comparing it is golden echo, not regression testing.
    """
    path_cap = POLICY.get("capture_path")
    if not path_cap:
        return
    try:
        def field(key):
            return {"present": key in doc, "value": doc.get(key)}
        row = {
            "run_id": POLICY.get("attempt_id"),
            "received_offset_ms": int((time.time() - _CAPTURE_T0) * 1000),
            "method": method,
            "path_with_query": path.replace(POLICY.get("capability_path", ""), "<cap>"),
            "wire_format": POLICY.get("wire_format", WIRE_ANTHROPIC),
            "top_level_keys": sorted(doc.keys()) if isinstance(doc, dict) else None,
            "admission_body": {
                "model": field("model"),
                "stream": field("stream"),
                # The heart of the fixture: **the complete array of real wire tool objects**, not hashes/names
                "tools": doc.get("tools") if isinstance(doc, dict) else None,
                "tool_choice": field("tool_choice"),
                "parallel_tool_calls": field("parallel_tool_calls"),
                "n": field("n"),
            },
            # Without an independent marker it is unknown — no guessing from tool names like Agent/Bash
            "request_role": {"value": "unknown", "source": "no_independent_marker"},
            "complete": bool(complete),
            "capture_outcome_provenance_only": {
                "tool_names": inv.get("tool_names"),
                "tool_definition_hashes": inv.get("tool_definition_hashes"),
            },
        }
        with open(path_cap, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:                                       # noqa: BLE001
        log("capture_write_failed", error=type(e).__name__)


_CAPTURE_T0 = time.time()


def decide(method, path, raw):
    """Per-request upper bound of spec:72-84. Failing any one is a block, and it **never fails open**."""
    inv = {"tools_present": False, "tools_type": None, "tool_names": [],
           "tool_definition_hashes": [], "model": None, "body_bytes": len(raw),
           "stream": None,
           # 🔴 Tool objects **stay only in inv, for observe mode's tool-surface archive**,
           #    and never enter the event log — `base` picks keys by allowlist, so raw definitions can't get in.
           #    Logs get copied everywhere and pasted into issues; the tool-surface archive is config; the two must not mix.
           "tool_objects": []}

    # ── Routing failures: **rejected in every mode**. ─────────────────────────────────
    # Observe mode means "don't decide for you", not "forward everything" — when these three fail
    # we don't even know where to forward the request; letting it through would not be lenience, it would be guessing.
    if method != "POST":
        inv["block_class"] = "routing"
        return "block", f"method is not POST: {method}", inv

    split = urlsplit(path)
    want_prefix = "/" + POLICY["capability_path"]
    if not split.path.startswith(want_prefix):
        # Don't print the actual prefix, so the log itself doesn't become a place that leaks the capability
        inv["block_class"] = "routing"
        return "block", "capability path prefix mismatch", inv
    rest = path[len(want_prefix):]
    if rest != POLICY["messages_path"]:
        inv["block_class"] = "routing"
        return "block", f"path/query is not the approved messages_path: {rest!r}", inv

    # After the three routing checks, every later failure is a **policy decision** — in observe mode they are downgraded to records.
    inv["block_class"] = "policy"

    if len(raw) > POLICY.get("max_body_bytes", MAX_BODY_BYTES_DEFAULT):
        return "block", f"body exceeds the limit ({len(raw)} bytes)", inv

    # ① Block every malformed body. Can't read it ≠ safe.
    # 🔴 ★2026-08-09 external review A9: this used to be a **plain `json.loads`**, so
    #    `{"tools":[{"name":"Bash"}],"tools":[]}` was forwarded — Python takes the last value
    #    (an empty array; the gate sees "no tools"), while if the upstream parser takes the first, at that moment the model
    #    gets Bash. **This is not a parsing blemish; it is a capability-gate bypass caused by parser differential**,
    #    striking at the very reason this whole system exists. `spec.md:76` already required rejecting duplicate keys and
    #    NaN/Infinity; the implementation hadn't caught up.
    #    Criterion: **from the same raw bytes, the upstream and I must derive the same capability set**;
    #    if that can't be guaranteed, don't forward — an ambiguous body has no "correct reading" to choose.
    try:
        doc = _strict_json_loads(raw.decode("utf-8"))
    except _AmbiguousJSON as e:
        return "block", f"body JSON is ambiguous; refusing to pick between two readings: {e}", inv
    except Exception as e:
        return "block", f"body is not valid JSON ({type(e).__name__}) — malformed is always blocked, never fails open", inv
    if not isinstance(doc, dict):
        inv["tools_type"] = type(doc).__name__
        return "block", f"body root is not an object, it is {type(doc).__name__}", inv

    # Kept for capture. ⚠️ The event log's `base` picks keys **by allowlist**, so this can't get into it.
    inv["_doc"] = doc
    inv["model"] = doc.get("model") if isinstance(doc.get("model"), str) else None
    # 🔴 `model: null` = "not declared yet". In observe mode this cell is skipped and the observed value is recorded —
    #    a monitor that doesn't yet know which model you use should not invent a policy decision about it
    #    (otherwise the first run is flooded with "model mismatch" and the real tool-surface signal is drowned).
    #    ⚠️ In enforce mode `model: null` is already rejected at startup: **no declaration, no right to enforce**.
    if POLICY["model"] is not None and inv["model"] != POLICY["model"]:
        return "block", f"model is not the approved one: {inv['model']!r}", inv

    # ★2026-08-08 A7 §3: `stream` decides which scanner this response should get,
    # so it must be decidable. Anything non-bool is rejected **before forwarding** —
    # a request I can't decide how to observe should not be let through.
    if "stream" in doc and not isinstance(doc["stream"], bool):
        return "block", f"stream is not a bool: {type(doc['stream']).__name__}", inv
    inv["stream"] = bool(doc.get("stream", False))

    if "tools" not in doc:
        # Missing tools field: must not be treated as "no tools". A missing field and an empty array are two different things;
        # the former means this request doesn't look like what we approved.
        return "block", "body is missing the tools field (missing field ≠ empty tool set)", inv

    inv["tools_present"] = True
    tools = doc["tools"]
    inv["tools_type"] = type(tools).__name__
    if not isinstance(tools, list):
        return "block", f"tools is not an array, it is {type(tools).__name__}", inv

    # ② Upper bound: **every full-definition hash that appears must belong to the approved list**.
    #
    # 🔴 Set semantics (set by A18, 2026-08-15) — read these four together:
    #      tools in the request ⊆ approved list     → forward
    #      approved name + new hash                 → block (contract_drift)
    #      a name or definition never approved      → block (tool_added)
    #      an approved tool absent this round       → **not drift**, just not disclosed this round
    #    The last is the easiest to get wrong: the tool surface is **disclosed gradually across requests** (measured: the same `claude -p` command
    #    run twice advertised only Agent, then only Bash). Treating "this round's tool set" as an identity that must be equal round after round
    #    flags legitimate traffic as drift.
    #
    # 🔴 One name can have **several** approved hashes — the same tool legitimately has different definitions in different contexts.
    #    So the keys of approved_tools are only identifiers; the decision looks only at the set of values.
    #
    # 🔴 2026-08-15 (A16 step 2) folded the original four name branches (name must be a non-empty string /
    #    no duplicate names / name must be in the approved table / then compare the hash looked up by name) into these two.
    #    The equivalence comes from canonicalisation: **the name itself is a field of the canonical object**,
    #    so none of "missing name, empty name, non-string, swapped for Bash, same name with a changed schema" can
    #    produce the approved full hash; two byte-identical definitions hit "duplicate hash".
    #
    # 🔴🔴 This must **never** degrade into "hash-check only the names we recognise; continue on unknown names".
    #    That is the false-pass path A16 named as the most convincing one: it looks like "handing the name layer to
    #    Claude's native deny", but it actually moves the approval domain from hash back to name — an extra Bash/Write
    #    is forwarded without any lookup, while ub-same-name-diff-schema is still blocked (the case still passes),
    #    so the hole is invisible if you look only at that case. The criterion is "every hash is in the set",
    #    not "only approved names get a hash check".
    #
    # Semantics unchanged: **any subset** of the approved set is allowed (`tools=[]` and a single approved tool
    # both forward); an exact full set per round is not required.
    # In the production policy approved_tools is {name: definition_sha256}; some fixtures pass
    # an empty container (`[]`). Both shapes are accepted, but only to the extent that "an approved hash set can be derived" —
    # if it can't, it is an **empty set**, and an empty set means every tool is blocked (fail closed), not forwarded.
    # ⚠️ The original implementation used `name in approved` for membership, which lists happen to support too, so this shape difference
    #    went unnoticed; switching to a hash set would crash the inspector on the spot (the connection simply drops),
    #    so it is written out explicitly here rather than relying on coincidence.
    _approved = POLICY["approved_tools"]
    approved_hashes = set(_approved.values()) if isinstance(_approved, dict) else set(_approved)
    wire = POLICY.get("wire_format", WIRE_ANTHROPIC)
    seen_hashes, seen_names, names = [], [], []
    for t in tools:
        # 🔴 Normalise one by one. The adapter layer **only projects the wire shape onto the semantic triple or raises**;
        #    it doesn't decide forward/block — only then are "extracting the list" and "approving the hash" cleanly separated,
        #    and there's no hole like "some shape of tool never reached the hash check at all".
        try:
            name, canon = normalize_tool_definition(wire, t)
        except GateShapeError as e:
            inv["tool_names"].append(t.get("name") if isinstance(t, dict) else None)
            inv["tool_definition_hashes"].append(None)
            return "block", e.code, inv
        h = sha(canon)
        # name is recorded as evidence only; it plays no part in the decision
        inv["tool_names"].append(name)
        inv["tool_definition_hashes"].append(h)
        # 🔴 What is stored is the **normalised semantic object**, not the raw wire object. Two reasons:
        #   ① Chat Completions wraps name/description/parameters inside `function`;
        #      recording the outer object would record name as null — and the diff couldn't recognise the tool;
        #   ② with the canonical form recorded, the same tool moving from Anthropic to OpenAI is not
        #      shown as "changed". Approve once, recognised everywhere, rests on this layer.
        inv["tool_objects"].append(json.loads(canon.decode("utf-8")))
        names.append(name)
        if h in seen_hashes:
            return "block", f"duplicate_full_definition ({h[:12]})", inv
        seen_hashes.append(h)
        # 🔴 **Duplicate-name** definitions within one request — blocked even if both are approved.
        #    "One name can have several approved definitions" means they appear **in different requests**,
        #    not that one round advertises two at once. Duplicate names within one round are ambiguous to the upstream, and ambiguity is exactly
        #    the class of problem this gate exists for (from the same bytes, the upstream and I must derive the same capability set).
        #    ⚠️ Use an **independent shape reason**; it must not be misreported as contract_drift (A19 §S1) —
        #       that error says "something you approved changed", whereas nothing changed here; only the shape is wrong.
        if name in seen_names:
            return "block", f"duplicate_tool_name ({name})", inv
        seen_names.append(name)
        if h not in approved_hashes:
            # 🔴 2026-08-15 (A18) split one reason into two. To the user they are **entirely different**
            #    things, and merging them into one message leaves people not knowing what to do:
            #      · contract_drift — a name you approved now has a different definition. **This is the reason the gate exists.**
            #      · tool_added     — a tool that was never approved has appeared. Most likely this agent
            #                          only advertises it in other situations (the tool surface is disclosed gradually across requests),
            #                          or something really was added. Either way a human should look.
            #    ⚠️ Both block; what is split is the **wording**, not the strictness.
            #    The raw definition is not echoed: the log itself must not become a place that leaks tool definitions.
            if name in (POLICY.get("approved_names") or []):
                return "block", f"contract_drift ({name}: {h[:12]})", inv
            return "block", f"tool_added ({name}: {h[:12]})", inv

    # Control fields outside the definition (tool_choice / parallel_tool_calls / n). They don't go into the hash,
    # but they change "which tools are actually usable", so they must be validated separately; unknown shapes are rejected.
    try:
        validate_request_controls(wire, doc, names)
    except GateShapeError as e:
        return "block", e.code, inv

    return "forward", None, inv


# ── Response parsing: keep structural evidence only, never content ────────────────────────────────────
def scan_request(request_id, raw):
    """Scan tool_result in the **request**.

    🔴 Found during end-to-end testing on 2026-08-08: in the Messages API, tool_use comes back in the **response**,
    while tool_result is carried by the client in the **next request**. Scanning only responses would never see
    tool_result — the lower bound's "causal evidence tied by one id" would be missing half,
    so "it read" and "it read successfully" couldn't be told apart.
    """
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception:
        return
    if not isinstance(doc, dict):
        return
    challenge = POLICY.get("challenge") or ""
    for m in doc.get("messages") or []:
        if not isinstance(m, dict):
            continue
        for b in m.get("content") if isinstance(m.get("content"), list) else []:
            if not isinstance(b, dict) or b.get("type") != "tool_result":
                continue
            c = b.get("content")
            text = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
            log("tool_result_seen", request_id=request_id,
                tool_use_id=b.get("tool_use_id"), is_error=bool(b.get("is_error")),
                contains_challenge=bool(challenge) and challenge in text,
                content_sha256=sha(text))


def _emit_tool_use(request_id, tool_use_id, name, file_path):
    """Record one piece of tool_use structural evidence. Only id / name / path sha256 / whether it hit the sentinel."""
    sentinel_path = POLICY.get("sentinel_path") or ""
    log("tool_use_seen", request_id=request_id,
        tool_use_id=tool_use_id, name=name,
        input_path_sha256=sha(file_path) if isinstance(file_path, str) else None,
        path_match=(file_path == sentinel_path) if isinstance(file_path, str) else False)


# ── Response scanning (★2026-08-08 complete rewrite after external review A7) ────────────────────────
# The old version was `scan_response(request_id, whole_body)`: read the whole body → `json.loads` →
# `return` on failure. The first real traffic exposed two problems:
#   ① The real API's responses are streamed; `json.loads` can't parse them → not one `tool_use_seen` recorded
#      → half the lower bound's causal evidence missing → judged obligation_failed. **That was a false negative of the observer.**
#   ② That `except: return` was **silent**: "couldn't parse" and "there was genuinely no tool_use in the response"
#      looked identical in the artefacts — the very disease we spent a whole day taking apart, the scanner had it too.
# Now: incremental, bounded, and every required response leaves exactly one closed `response_scan_terminal`.
# ⚠️ External review explicitly required relay and scan to change together: swapping the scanner alone isn't enough;
#    "read the whole body, then pass it back" itself had to go.

# ── Hard memory bounds ──────────────────────────────────────────────────────────
# 🔴 2026-08-09: the comment here in the previous version said "four hard memory bounds"; external review A8 showed **only
#    two actually held** — no concurrency limit (`ThreadingHTTPServer` opens as many threads as it likes),
#    empty partial_json let the `parts` list grow without bound while the counter stayed at 0, and `len(part)` counted
#    Unicode characters, not UTF-8 bytes. **Claimed strength > actual strength, and the claim was in the most visible place.**
#    After each line below is written "what it actually bounds", and **what remains unbounded**.
MAX_SSE_EVENT_BYTES = 1 * 1024 * 1024      # a single SSE event; doubles as the cap on the unparsed buffer
MAX_TOOL_INPUT_BYTES = 1 * 1024 * 1024     # accumulated **bytes** of a single tool input (not characters)
MAX_OPEN_BLOCKS = 32                       # content blocks open at once (including text, not only tools)
MAX_JSON_SHADOW_BYTES = 8 * 1024 * 1024    # a single non-streaming shadow buffer
MAX_TRACKED_TOOL_USE_IDS = 100_000         # attempt-level id registry; fails closed when full
MAX_CONCURRENT_RELAYS = 8                  # 🔴 global number of concurrent relays; the limits above are multiplied by this
MAX_DISCARD_BYTES = 1 * 1024 * 1024        # drain cap for responses not forwarded (3xx / invalid framing)
RELAY_CHUNK = 64 * 1024
# ⚠️ **Still unbounded**: the total length of a single response (we scan while forwarding, so we shouldn't be accumulating it anyway),
#    and the total number of requests within an attempt (governed by hb-run/finish's attempt upper bound, not here).

# Number of relays in flight at once. BoundedSemaphore: more releases than acquires blows up on the spot
# instead of quietly enlarging the limit — if this gate itself breaks, it has to be visible.
RELAY_SEM = threading.BoundedSemaphore(MAX_CONCURRENT_RELAYS)


class _ScanFailure(Exception):
    """Scan failure. Carries only a closed reason_code — **no exception message, no content**."""
    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code


class _ClientGone(Exception):
    """The downstream (CLI) disconnected first. **This is not an upstream failure** and must not be recorded as upstream_error."""


# ── Attempt-level tool_use id registry ────────────────────────────────────────
# 🔴 Why it spans requests: the `success` retracted on 08-08 died on exactly this — the loop mock returned
#    the same `toolu_loop_1` every time, so **one tool_result matched two tool_uses at once**,
#    and the "causal pairing" was manufactured by the fixture. De-duplication within a response can't stop that; it has to be attempt-level.
_TOOL_ID_LOCK = threading.Lock()
_SEEN_TOOL_USE_IDS = set()


def register_tool_use_id(tool_use_id):
    """Returns ok/duplicate/exhausted; three states can't be squashed into a bool and the cause guessed afterwards."""
    with _TOOL_ID_LOCK:
        if tool_use_id in _SEEN_TOOL_USE_IDS:
            return "duplicate"
        if len(_SEEN_TOOL_USE_IDS) >= MAX_TRACKED_TOOL_USE_IDS:
            return "exhausted"
        _SEEN_TOOL_USE_IDS.add(tool_use_id)
        return "ok"


def require_unique_tool_use_id(tool_use_id, response_seen_ids):
    """Register one id; a true duplicate and capacity exhaustion each use their own closed reason code."""
    if tool_use_id in response_seen_ids:
        raise _ScanFailure("duplicate_tool_use_id")
    outcome = register_tool_use_id(tool_use_id)
    if outcome == "duplicate":
        raise _ScanFailure("duplicate_tool_use_id")
    if outcome == "exhausted":
        raise _ScanFailure("tool_use_id_registry_exhausted")
    response_seen_ids.add(tool_use_id)


def reset_tool_use_ids():
    """**For red/green fixtures only.** In production one attempt is one process, and this is never called."""
    with _TOOL_ID_LOCK:
        _SEEN_TOOL_USE_IDS.clear()


# Per WHATWG, SSE line terminators are CRLF / CR / LF (the old version recognised only the first two,
# so a stream separated by bare CR was misreported as truncated). Event boundary = an empty line.
_SSE_LINE_RE = re.compile(r"\r\n|\r|\n")
# The bare `\r` / `\n` branches must explicitly exclude the case where they are part of a CRLF; otherwise the regex would
# backtrack and split one CRLF into `\r` + `\n`, mistaking **every line** for an empty-line boundary.
_SSE_BOUNDARY_RE = re.compile(
    rb"(?:\r\n|\r(?!\n)|(?<!\r)\n)(?:\r\n|\r(?!\n)|(?<!\r)\n)")


class SseResponseScanner:
    """Incremental SSE state machine. Its conclusions must be the same for any network chunk boundaries.

    A tool input gets its id/name from `content_block_start`, then accumulates over several
    `input_json_delta.partial_json` until `content_block_stop`, when the complete input can be parsed
    — so `tool_use_seen` is **recorded once, at block_stop**, not at start.
    """
    # ★2026-08-09 external review A8 §1: the previous version **validated parsing only, not sequence**.
    # It returned `scan ok` for every one of the following, and each would make the "causal evidence" false:
    #   duplicate tool_use_id / opening the same index twice (silently overwriting the previous block) /
    #   orphan delta and orphan stop / tool_use without an id / no message_start /
    #   duplicate message_stop / `event:` name not matching the JSON `type`.
    # 🔴 The criterion is not "it parses", it's **whether this stream can support the claim I want to prove with it**.
    format = "sse"

    def __init__(self, request_id):
        self.request_id = request_id
        self.buf = b""
        self.open_blocks = {}          # index -> {"tool": {...} | None}
        self.tool_use_count = 0
        self.unknown_event_count = 0
        self.message_start_seen = False
        self.message_stop_seen = False
        self.bytes_seen = 0
        self.stream_error = None
        self.seen_ids = set()          # tool_use ids within this response (there's a separate attempt-level registry)

    def feed(self, chunk):
        self.bytes_seen += len(chunk)
        self.buf += chunk
        self._drain(final=False)

    def _drain(self, final):
        while True:
            bound = self._next_boundary(final)
            if bound is None:
                if len(self.buf) > MAX_SSE_EVENT_BYTES:
                    raise _ScanFailure("event_too_large")
                return
            block, self.buf = self.buf[:bound[0]], self.buf[bound[1]:]
            if len(block) > MAX_SSE_EVENT_BYTES:
                raise _ScanFailure("event_too_large")
            self._handle_event(block)

    def _next_boundary(self, final=False):
        # A trailing lone `\r` may be the first half of `\r\n` — don't look at it; wait for the next chunk.
        # (Otherwise `x\r` + `\r\n` would be read as two terminators across the chunk boundary.)
        limit = len(self.buf)
        if not final and self.buf.endswith(b"\r"):
            limit -= 1
        if limit <= 0:
            return None
        m = _SSE_BOUNDARY_RE.search(self.buf, 0, limit)
        return (m.start(), m.end()) if m else None

    def _handle_event(self, block):
        try:
            text = block.decode("utf-8")
        except UnicodeDecodeError:
            raise _ScanFailure("invalid_utf8")
        data_lines = []
        event_name = None
        event_seen = False
        for line in _SSE_LINE_RE.split(text):
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
            elif line.startswith("event:"):
                event_seen = True
                event_name = line[6:].strip()        # per the SSE spec, the last event: wins
        if not data_lines:
            return                                   # only event:/id:/comment lines
        payload = "\n".join(data_lines)
        if payload.strip() == "[DONE]":
            return
        try:
            doc = _strict_json_loads(payload)
        except Exception:
            raise _ScanFailure("invalid_sse_json")
        if not isinstance(doc, dict):
            raise _ScanFailure("invalid_sse_json")
        # An Anthropic wire event carries its type name twice; both must be present, both non-empty strings,
        # and byte-for-byte equal. Only types that are **equal but unknown** go to the forward-compatibility counter.
        kind = doc.get("type")
        if (not event_seen or not isinstance(event_name, str) or not event_name
                or not isinstance(kind, str) or not kind or event_name != kind):
            raise _ScanFailure("event_type_mismatch")
        self._dispatch(doc)

    def _dispatch(self, doc):
        kind = doc.get("type")

        # No event should follow message_stop (a duplicate message_stop lands here too).
        if self.message_stop_seen:
            raise _ScanFailure("invalid_sse_sequence")

        if kind == "message_start":
            if self.message_start_seen:
                raise _ScanFailure("invalid_sse_sequence")
            self.message_start_seen = True
            return

        # The protocol allows ping / error anywhere, including before message_start.
        if kind == "ping":
            return
        if kind == "error":
            # 🔴 An in-stream error is the API's stream error, **not** a parse failure.
            # Record only the safe error type, not the message; the postcondition does the failing.
            err = doc.get("error")
            self.stream_error = err.get("type") if isinstance(err, dict) else "unknown"
            return

        if kind in ("content_block_start", "content_block_delta",
                    "content_block_stop", "message_delta", "message_stop"):
            if not self.message_start_seen:
                raise _ScanFailure("invalid_sse_sequence")
        else:
            # The protocol explicitly allows new event types — unknown doesn't mean bad; just count it.
            # ⚠️ An unknown event must **never** be escalated to a sequence failure (named by A8).
            self.unknown_event_count += 1
            return

        if kind == "message_delta":
            return
        if kind == "message_stop":
            self.message_stop_seen = True
            return

        idx = doc.get("index")
        if not isinstance(idx, int) or isinstance(idx, bool):
            raise _ScanFailure("invalid_sse_sequence")

        if kind == "content_block_start":
            if idx in self.open_blocks:
                raise _ScanFailure("invalid_sse_sequence")     # opening twice = silent overwrite
            if len(self.open_blocks) >= MAX_OPEN_BLOCKS:
                raise _ScanFailure("event_too_large")
            cb = doc.get("content_block")
            if not isinstance(cb, dict):
                raise _ScanFailure("invalid_sse_sequence")
            if cb.get("type") != "tool_use":
                self.open_blocks[idx] = {"tool": None}
                return
            tid, name = cb.get("id"), cb.get("name")
            if not (isinstance(tid, str) and tid.strip()):
                raise _ScanFailure("invalid_sse_sequence")
            if not (isinstance(name, str) and name.strip()):
                raise _ScanFailure("invalid_sse_sequence")
            require_unique_tool_use_id(tid, self.seen_ids)
            self.open_blocks[idx] = {"tool": {"id": tid, "name": name,
                                              "buf": bytearray()}}
            return

        if kind == "content_block_delta":
            blk = self.open_blocks.get(idx)
            if blk is None:
                raise _ScanFailure("invalid_sse_sequence")     # orphan delta
            d = doc.get("delta")
            if not isinstance(d, dict):
                raise _ScanFailure("invalid_sse_sequence")
            if d.get("type") != "input_json_delta":
                return
            if blk["tool"] is None:
                raise _ScanFailure("invalid_sse_sequence")     # tool input received by a non-tool block
            part = d.get("partial_json")
            if not isinstance(part, str):
                raise _ScanFailure("tool_input_invalid")
            # 🔴 What accumulates is **UTF-8 bytes**. The old version counted `len(part)` (characters)
            #    and appended to a list — endless empty deltas could blow up the list while the counter stayed at 0.
            enc = part.encode("utf-8")
            if len(blk["tool"]["buf"]) + len(enc) > MAX_TOOL_INPUT_BYTES:
                raise _ScanFailure("event_too_large")
            blk["tool"]["buf"] += enc
            return

        # content_block_stop
        if idx not in self.open_blocks:
            raise _ScanFailure("invalid_sse_sequence")         # orphan stop
        blk = self.open_blocks.pop(idx)
        t = blk["tool"]
        if t is None:
            return
        raw = bytes(t["buf"])
        if raw.strip():
            try:
                inp = _strict_json_loads(raw.decode("utf-8"))
            except Exception:
                raise _ScanFailure("tool_input_invalid")
            if not isinstance(inp, dict):
                raise _ScanFailure("tool_input_invalid")
        else:
            inp = {}                                           # tool with no arguments; valid
        _emit_tool_use(self.request_id, t["id"], t["name"], inp.get("file_path"))
        self.tool_use_count += 1

    def finish(self):
        self._drain(final=True)        # the last event may end with a lone CR
        if self.buf.strip():
            raise _ScanFailure("truncated_stream")
        if self.open_blocks:
            raise _ScanFailure("truncated_stream")
        if not self.message_start_seen:
            raise _ScanFailure("truncated_stream")
        if not self.message_stop_seen:
            raise _ScanFailure("truncated_stream")
        return {"stream_error": self.stream_error}


class JsonResponseScanner:
    """Non-streaming: keep a **bounded** shadow buffer while forwarding, and scan it as whole JSON after EOF.

    ⚠️ A true token-level incremental JSON parser is deferred. Only two things have to hold here:
    the relay no longer "accumulates the whole response before sending", and memory doesn't grow without bound with the response.
    """
    format = "json"

    def __init__(self, request_id):
        self.request_id = request_id
        self.buf = b""
        self.bytes_seen = 0
        self.overflow = False
        self.tool_use_count = 0
        self.unknown_event_count = 0
        self.message_stop_seen = True     # non-streaming has no such concept; always true
        self.stream_error = None
        self.seen_ids = set()

    def feed(self, chunk):
        self.bytes_seen += len(chunk)
        if self.overflow:
            return
        if len(self.buf) + len(chunk) > MAX_JSON_SHADOW_BYTES:
            self.overflow = True
            self.buf = b""
            return
        self.buf += chunk

    def finish(self):
        # ★2026-08-09 A8 §3: the previous version **validated that it parsed, not its shape**.
        # So `{"type":"message"}` was read as "a valid response that just has no tools" —
        # the very same look-alike we spent a whole day taking apart: **"no tools" and "I didn't understand" must not look the same.**
        if self.overflow:
            raise _ScanFailure("json_scan_limit_exceeded")
        try:
            doc = _strict_json_loads(self.buf.decode("utf-8"))
        except UnicodeDecodeError:
            raise _ScanFailure("invalid_utf8")
        except Exception:
            raise _ScanFailure("invalid_json")
        if not isinstance(doc, dict):
            raise _ScanFailure("invalid_json_shape")
        blocks = doc.get("content")
        if not isinstance(blocks, list):
            raise _ScanFailure("invalid_json_shape")       # missing content / not an array
        for b in blocks:
            if not isinstance(b, dict):
                raise _ScanFailure("invalid_json_shape")
            if b.get("type") != "tool_use":
                continue
            tid, name, inp = b.get("id"), b.get("name"), b.get("input")
            if not (isinstance(tid, str) and tid.strip()):
                raise _ScanFailure("invalid_json_shape")
            if not (isinstance(name, str) and name.strip()):
                raise _ScanFailure("invalid_json_shape")
            if not isinstance(inp, dict):
                raise _ScanFailure("invalid_json_shape")   # a scalar input is no longer silently treated as {}
            require_unique_tool_use_id(tid, self.seen_ids)
            _emit_tool_use(self.request_id, tid, name, inp.get("file_path"))
            self.tool_use_count += 1
        return {"stream_error": None}


def pick_scanner(request_id, want_stream, media_type):
    """The scan obligation is decided by the **request context**, not by "try to parse whatever response shows up".

    External review A7 §3: `stream:true` requires `text/event-stream`; missing/false requires JSON.
    A content-type mismatch is a visible failure, not something silently let through.
    """
    base = (media_type or "").split(";")[0].strip().lower()
    if want_stream:
        if base != "text/event-stream":
            raise _ScanFailure("content_type_mismatch")
        return SseResponseScanner(request_id)
    # ★2026-08-09 A8 §3: an empty string (= the upstream gave no Content-Type at all) used to be accepted as JSON,
    # contradicting A7's "a JSON media type is required". **A response that declares no type is not mine to assume anything about.**
    if base not in ("application/json", "application/vnd.api+json"):
        raise _ScanFailure("content_type_mismatch")
    return JsonResponseScanner(request_id)


def check_auth_headers(headers):
    """Validate the credentials on the request before forwarding. Returns None (forward) or a rejection reason.

    🔴 Applies only under `loopback_dummy`. In real mode the wrapper **does not know** what the real credentials look like,
    and should not — that is between the keychain and the CLI; guessing here would only guess wrong.

    ⚠️ What is returned is a **stable code**, not prose. Two reasons:
      ① The rejection reason goes into the log, and the log must contain neither header values **nor header names** —
         acceptance has a `no_auth_in_log` assertion that scans for `authorization`/`x-api-key`/`bearer `;
         writing prose would turn our own log into a counterexample to that assertion (the first version stepped on exactly that);
      ② a code is machine-decidable, so the oracle doesn't have to match prose.
    """
    if POLICY.get("auth_mode") != "loopback_dummy":
        return None, {}
    # 🔴 A missing expected token is already rejected in main() before the server starts (and preflight constructs that field),
    #    so this branch is unreachable at request time — removed on 2026-08-15 per A16 step 1.
    #    ⚠️ The startup rejection **must not** be removed along with it; that one is the guard that actually holds.
    expected = POLICY["expected_auth_token"]

    # Only `get_all` can count "two were sent"; `get` just gives you the first.
    got = headers.get_all("authorization") or []
    meta = {"observed_identity_count": len(got)}

    # 🔴 The priority is fixed by external review (A6b ②): alternate identity > count > value.
    # The order isn't arbitrary — a request carrying both an alternate identity and a wrong value
    # should be reported as "it carries a different identity", the more fundamental problem.
    if headers.get("x-api-key") is not None:
        return "alternate_identity_present", meta
    if len(got) != 1:
        return "dummy_identity_count_invalid", meta
    value = got[0].strip()
    if value == expected:
        meta["identity_form"] = "literal"
    elif value == f"Bearer {expected}":
        meta["identity_form"] = "prefixed"
    else:
        return "dummy_identity_mismatch", meta
    return None, meta


_CANON_DECIMAL_RE = re.compile(r"\A(?:0|[1-9][0-9]*)\Z")


def validate_framing(resp):
    """The upstream response's framing must be **trustworthy**; returns (declared_len|None, error_code|None).

    ★2026-08-09 A8 §2: the previous version passed any non-empty `Content-Length` straight through to the downstream,
    and only then did `int(declared)`. So `Content-Length: +5` / `007` / `5, 6` /
    framing that also carried `Transfer-Encoding` — invalid or conflicting framing — was **passed down as-is**
    for the downstream to crash into — which is exactly the shape of the request-smuggling class of problems.
    🔴 Criterion: **before forwarding I must be able to say how long this response is, or say explicitly "it is chunked".**
    If I can't say either, it doesn't get forwarded.
    """
    raw_te = resp.headers.get_all("Transfer-Encoding") or []
    raw_values = resp.headers.get_all("Content-Length") or []
    # Several comma-separated values on one header line count as several values (RFC 9110 §8.6)
    values = [v.strip() for item in raw_values for v in str(item).split(",")]
    te_values = [v.strip().lower() for item in raw_te for v in str(item).split(",")]

    # An empty value is also a bad value; don't filter it out and misread `Content-Length:` as "no CL".
    if raw_te and raw_values:
        return None, "conflicting_framing"
    if raw_values:
        # "Two identical values" is still not a **single** CL; different parsers may merge by different rules; reject the ambiguity.
        if len(raw_values) != 1 or len(values) != 1:
            return None, "invalid_content_length"
        v = values[0]
        if not _CANON_DECIMAL_RE.match(v):
            # Non-canonical decimal: `+5`, `007`, empty, `0x5`, negatives are all stopped here
            return None, "invalid_content_length"
        return int(v), None
    if raw_te:
        # http.client de-chunks only for the last, supported chunked encoding. We accept something narrower:
        # exactly one header, exactly one token, token=chunked, and the underlying layer really recognises it as chunked.
        if (len(raw_te) != 1 or te_values != ["chunked"]
                or getattr(resp, "chunked", False) is not True):
            return None, "invalid_transfer_encoding"
        return None, None
    # close-delimited has no approvable framing identity on this Messages relay.
    return None, "missing_response_framing"


def bounded_drain(resp, cap=MAX_DISCARD_BYTES):
    """Responses that aren't forwarded still get read off, but **bounded**. The old version did an unbounded `resp.read()` here."""
    got = 0
    while got < cap:
        chunk = resp.read1(RELAY_CHUNK)
        if not chunk:
            break
        got += len(chunk)
    return got


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hb-inspector/2"

    def log_message(self, *a):
        pass

    def _to_client(self, data):
        """Write downstream. **A downstream disconnect is not an upstream failure** — a separate exception keeps the attribution apart."""
        try:
            self.wfile.write(data)
        except OSError as e:
            raise _ClientGone() from e

    def _flush_client(self):
        try:
            self.wfile.flush()
        except OSError as e:
            raise _ClientGone() from e

    def do_POST(self):
        self._handle("POST")

    def do_GET(self):
        self._handle("GET")

    def do_PUT(self):
        self._handle("PUT")

    def do_DELETE(self):
        self._handle("DELETE")

    def _handle(self, method):
        request_id = str(uuid.uuid4())
        n = int(self.headers.get("Content-Length") or 0)
        cap = POLICY.get("max_body_bytes", MAX_BODY_BYTES_DEFAULT)
        raw = self.rfile.read(min(n, cap + 1)) if n else b""
        received_at = time.strftime("%Y-%m-%dT%H:%M:%S")

        decision, reason, inv = decide(method, self.path, raw)

        # ── observe mode: policy decisions downgraded to records; routing failures still blocked ────────────────────
        # 🔴 observe mode **provides no enforcement at all**. Its use: from day one you can see
        #    "what tools my agent actually advertises, and when that changes", without first understanding
        #    the threat model, capturing a baseline or signing a hash. Blocking is a later opt-in.
        # 🔴 `would_block_reason` must be recorded: otherwise observe mode's output is just "everything forwarded",
        #    which is the same as not having installed it. **This record is the entire product value of the mode.**
        mode = POLICY.get("mode", MODE_ENFORCE)
        # 🔴 Changed 2026-08-15: **recorded in both modes**. The original design recorded only in observe, for log hygiene;
        #    real traffic overturned that — when enforce blocks a request, all the user gets is
        #    a hash, **with no way to know what was blocked**, except switching back to observe and running again.
        #    A gate that can't say what it blocked gets switched off in real use.
        #    De-duplication is still by hash, so approved definitions aren't written twice.
        record_surface(inv)
        if inv.get("_doc") is not None:
            record_capture(method, self.path, inv["_doc"], inv, complete=True)
        would_block_reason = None
        if (decision == "block" and mode == MODE_OBSERVE
                and inv.get("block_class") == "policy"):
            would_block_reason = reason
            decision, reason = "forward", None

        base = {
            "request_id": request_id, "received_at": received_at, "method": method,
            "path": urlsplit(self.path).path.replace(POLICY["capability_path"], "<cap>"),
            "model": inv["model"], "body_bytes": inv["body_bytes"],
            "tools_present": inv["tools_present"], "tools_type": inv["tools_type"],
            "tool_names": inv["tool_names"],
            "tool_definition_hashes": inv["tool_definition_hashes"],
            "decision": decision, "block_reason": reason,
            "upstream_origin": POLICY["upstream_origin"],
            # One of the three things external review A7 required keeping: the request-side stream boolean.
            # Without it, afterwards you can't tell "the response should be SSE" from "it was supposed to be JSON".
            "request_stream": inv.get("stream"),
            # Productised 2026-08-15: the mode, and "would it have been blocked under enforce".
            # The entire evidence of observe mode lives in these two fields.
            "mode": mode,
            "would_block": would_block_reason is not None,
            "would_block_reason": would_block_reason,
        }

        if decision == "block":
            # 🔴 A blocked request never has forward_started_at — independently verified by the mock counter
            log("request", **base, forward_started_at=None,
                upstream_status=None, response_complete=False, upstream_error=None)
            payload = json.dumps({"error": {"type": "policy_blocked", "message": reason}}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # ── Before forwarding: the credential gate (★2026-08-08 external review A5 §2) ────────────────────
        # Only this step proves that **what the CLI actually sent** is the public fake credential, not merely that the plan claims dummy.
        # "The plan says dummy" and "the process really used dummy" are two different things,
        # the same shape as terminal self-report vs. recomputing from events.
        auth_bad, auth_meta = check_auth_headers(self.headers)
        if auth_bad:
            # 🔴 `decision` must be recorded as block. The `base["decision"]` above is the body gate's judgement
            # (it judged forward), but this request **really was blocked** — leaving "forward" in the log
            # would make "blocked" and "let through" look identical in the artefacts, the very thing we keep taking apart.
            blocked_base = dict(base, decision="block", block_reason=auth_bad)
            log("request", **blocked_base, forward_started_at=None,
                upstream_status=None, response_complete=False, upstream_error=None,
                auth_mode=POLICY.get("auth_mode"), dummy_auth_match=False, **auth_meta)
            payload = json.dumps({"error": {"type": "policy_blocked",
                                            "message": auth_bad}}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        scan_request(request_id, raw)

        # ── Forward ──
        forward_started_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        # 🔴 The connect target is read only from upstream_connect pinned in the policy; **the origin string is no longer parsed**.
        # The old code did `urlsplit(POLICY["upstream_origin"]).hostname` here,
        # while preflight judged loopback with `startswith("127.0.0.1")` —
        # `http://127.0.0.1@192.0.2.1:9` made the two sides look at two different hosts.
        up = POLICY["upstream_connect"]
        conn_cls = (http.client.HTTPSConnection if up["scheme"] == "https"
                    else http.client.HTTPConnection)
        status = None
        upstream_error = None
        client_disconnected = False
        complete = False
        headers_sent = False
        scanner = None
        scan_outcome, scan_reason = None, None
        media_type = None
        conn = None

        try:
            conn = conn_cls(up["host"], up["port"], timeout=60)
            fwd_headers = {"Content-Type": "application/json",
                           "Content-Length": str(len(raw)),
                           "anthropic-version": self.headers.get("anthropic-version", "2023-06-01")}
            # Auth headers are passed through as-is but **never logged**; only the required few are picked here, no wholesale copy.
            for h in ("x-api-key", "authorization", "anthropic-beta"):
                v = self.headers.get(h)
                if v:
                    fwd_headers[h] = v
            conn.request("POST", POLICY["messages_path"], body=raw, headers=fwd_headers)
            resp = conn.getresponse()
            status = resp.status
            media_type = resp.getheader("Content-Type")

            declared, framing_error = validate_framing(resp)

            if 300 <= status < 400:
                # ⑤ Every 3xx is treated as an upstream error and not followed
                upstream_error = "redirect_not_followed"
                if framing_error is None:
                    bounded_drain(resp)
            elif framing_error:
                # framing unclear → not one byte goes downstream, not even headers.
                # 🔴 **No drain either**: untrustworthy framing means "where reading ends" is untrustworthy.
                #    The `Content-Length: -1` red case of 2026-08-09 exercised this path —
                #    `http.client` accepts -1 via `int()`, so `read1` never sees an end,
                #    and the whole request hangs until timeout. **Reading by a length I've just judged false is self-contradictory.**
                #    The connection is dropped by `conn.close()` in finally; the remaining bytes are none of our business.
                upstream_error = framing_error
            else:
                # The scan obligation is decided by request context (A7 §3): only what should be a Messages 2xx response
                # is required to scan cleanly. 403/502/control-plane responses don't produce false parse failures.
                scan_required = (200 <= status < 300)
                if scan_required:
                    try:
                        scanner = pick_scanner(request_id, inv.get("stream") is True, media_type)
                    except _ScanFailure as sf:
                        scan_outcome, scan_reason = "failed", sf.reason_code

                # ── Scan while forwarding; flush every chunk ────────────────────────────
                # 🔴 No more `body = resp.read()` accumulating the whole body before passing it back: that both makes first-byte latency equal
                # the full response time and makes memory grow without bound with the response.
                self.send_response(status)
                if media_type:
                    self.send_header("Content-Type", media_type)   # keep the upstream's; no longer force json
                if declared is not None:
                    self.send_header("Content-Length", str(declared))
                    chunked = False
                else:
                    self.send_header("Transfer-Encoding", "chunked")  # one or the other, never both
                    chunked = True
                self.end_headers()
                headers_sent = True

                seen = 0
                while True:
                    chunk = resp.read1(RELAY_CHUNK)
                    if not chunk:
                        break
                    seen += len(chunk)
                    # payload bytes unchanged byte for byte; only the transfer chunking may differ
                    if chunked:
                        self._to_client(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                    else:
                        self._to_client(chunk)
                    self._flush_client()
                    if scanner is not None and scan_outcome is None:
                        try:
                            scanner.feed(chunk)
                        except _ScanFailure as sf:
                            scan_outcome, scan_reason = "failed", sf.reason_code
                        except Exception:
                            # a scanner exception must not crash the forwarding thread — but this run must not be a success
                            scan_outcome, scan_reason = "failed", "scan_internal_error"
                if chunked:
                    self._to_client(b"0\r\n\r\n")
                    self._flush_client()

                complete = (declared is None) or (seen == declared)
                if not complete:
                    upstream_error = "incomplete_response"
                if scanner is not None and scan_outcome is None:
                    try:
                        extra = scanner.finish()
                        scan_outcome, scan_reason = "ok", None
                        if extra.get("stream_error"):
                            upstream_error = upstream_error or "stream_error"
                    except _ScanFailure as sf:
                        scan_outcome, scan_reason = "failed", sf.reason_code
                    except Exception:
                        scan_outcome, scan_reason = "failed", "scan_internal_error"
        except _ClientGone:
            # ★2026-08-09 A8 §2: the downstream disconnected first. The old version recorded it as
            # `upstream_error="BrokenPipeError"` — **attributing it to the wrong party**,
            # and "the upstream blew up" and "the CLI walked away" are two things to look at separately.
            client_disconnected = True
            self.close_connection = True
            if scanner is not None and scan_outcome is None:
                scan_outcome, scan_reason = "failed", "client_disconnected"
        except Exception as e:
            upstream_error = upstream_error or type(e).__name__
            if scanner is not None and scan_outcome is None:
                scan_outcome, scan_reason = "failed", "truncated_stream"
        finally:
            # 🔴 The old version had `conn.close()` at the end of the normal path inside try: any exception
            # skipped it, and the upstream connection was **never explicitly closed**. Putting it in finally is what actually closes it.
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        log("request", **base, forward_started_at=forward_started_at,
            upstream_status=status, response_complete=complete, upstream_error=upstream_error,
            client_disconnected=client_disconnected,
            auth_mode=POLICY.get("auth_mode"),
            dummy_auth_match=(POLICY.get("auth_mode") == "loopback_dummy" or None),
            **auth_meta)

        # 🔴 Exactly one closing event per required response. It is the dividing line between "scanned and fine" and
        # "didn't understand" — finish.py relies on it to separate obligation_failed from
        # inspector_failed. A missing event is itself a failure.
        if 200 <= (status or 0) < 300:
            log("response_scan_terminal", request_id=request_id, required=True,
                format=(scanner.format if scanner is not None else None),
                outcome=(scan_outcome or "failed"),
                reason_code=scan_reason,
                bytes_seen=(scanner.bytes_seen if scanner is not None else 0),
                message_stop_seen=(scanner.message_stop_seen if scanner is not None else False),
                tool_use_count=(scanner.tool_use_count if scanner is not None else 0),
                unknown_event_count=(scanner.unknown_event_count if scanner is not None else 0))

        if headers_sent:
            # once headers are committed a 502 can't be faked any more: cut the connection and let response_complete speak
            if upstream_error or client_disconnected:
                self.close_connection = True
            return

        if client_disconnected:
            return          # the downstream has already gone; nobody is left to receive this 502

        if upstream_error or status is None:
            payload = json.dumps({"error": {"type": "upstream_error",
                                            "message": upstream_error or "no status"}}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Acquire a global slot **before** creating a worker, parsing headers or reading the body.

    `ThreadingHTTPServer.process_request()` is what creates the thread; a gate placed in the handler is therefore
    always one layer too late. When full, the accept thread answers with a fixed 503 and closes, without reading the request at all.
    """
    daemon_threads = True

    @staticmethod
    def _capacity_response():
        body = b'{"error":{"type":"policy_blocked","message":"relay_capacity_exceeded"}}'
        return (b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                b"Connection: close\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body)

    def process_request(self, request, client_address):
        if not RELAY_SEM.acquire(blocking=False):
            request_id = str(uuid.uuid4())
            # This is also a request rejected by the inspector; record it in the general request ledger so that finish doesn't
            # miss a capacity rejection as cli_failed/success. Headers aren't parsed yet, so unknown fields are explicitly None.
            log("request", request_id=request_id,
                received_at=time.strftime("%Y-%m-%dT%H:%M:%S"), method=None, path=None,
                model=None, body_bytes=0, tools_present=None, tools_type=None,
                tool_names=[], tool_definition_hashes=[], decision="block",
                block_reason="relay_capacity_exceeded", upstream_origin=POLICY.get("upstream_origin"),
                request_stream=None, forward_started_at=None, upstream_status=None,
                response_complete=False, upstream_error=None, body_bytes_read=0,
                worker_created=False)
            log("capacity_rejected", request_id=request_id,
                reason_code="relay_capacity_exceeded", body_bytes_read=0,
                worker_created=False)
            try:
                request.sendall(self._capacity_response())
            except OSError:
                pass
            self.shutdown_request(request)
            return
        log("relay_slot_acquired", body_bytes_read=0, worker_created=False)
        try:
            super().process_request(request, client_address)
        except Exception:
            RELAY_SEM.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            RELAY_SEM.release()


def main():
    global POLICY, LOG_PATH
    # ★2026-08-08 P0: the port used to be read from ambient `HB_INSPECTOR_PORT`, and hb-run.sh started the inspector
    # with exactly that unscrubbed environment — one environment variable could change production behaviour.
    # The first fix added a `--test-port N` escape hatch; external review cut it the same day ((b)): **no caller needs it**
    # (hb-run never passes it, nor does acceptance), and an argument only an attacker would use is pure exposure.
    # Production now always binds ("127.0.0.1", 0) and lets the kernel choose; the port is read back from the READY line.
    # Tests that need a specific port rely on the trusted fake inspector's own argument, which never enters the production binary.
    if len(sys.argv) != 3:
        print("usage: inspector.py <policy.json> <events.jsonl>", file=sys.stderr)
        return 64
    policy_path, LOG_PATH = sys.argv[1], sys.argv[2]

    with open(policy_path, "rb") as f:
        raw = f.read()
    POLICY = json.loads(raw)
    for k in ("attempt_id", "capability_path", "upstream_origin", "messages_path",
              "model", "approved_tools", "auth_mode", "upstream_connect"):
        if k not in POLICY:
            print(f"inspector: policy is missing field {k}", file=sys.stderr)
            return 64
    if len(POLICY["capability_path"]) < 32:
        print("inspector: capability_path is too short (needs ≥128 random bits)", file=sys.stderr)
        return 64

    # ── Startup re-validation (★2026-08-08 external review A5 §1) ────────────────────────────
    # preflight checking once isn't enough: **this process** is the one that actually connects,
    # so it must confirm for itself. If it fails, it **doesn't print READY** — hb-run won't start the model without READY,
    # so "not validated" and "validated" are distinguishable by external behaviour, not by this code's good conduct.
    up = POLICY["upstream_connect"]
    origin = POLICY["upstream_origin"]
    if not isinstance(up, dict) or set(up) != {"scheme", "host", "port"}:
        print("inspector: upstream_connect has the wrong shape", file=sys.stderr)
        return 64
    # 🔴 An invalid mode **does not fall back to the default** — "a typo" and "I want observe mode" must be distinguishable.
    #    Only absence (no key) means enforce; a wrong value is a config error, rejected on the spot.
    if POLICY.get("model") is None and POLICY.get("mode", MODE_ENFORCE) != MODE_OBSERVE:
        print("inspector: model must not be null in enforce mode — no declaration, no right to enforce",
              file=sys.stderr)
        return 64
    if POLICY.get("wire_format", WIRE_ANTHROPIC) not in VALID_WIRE_FORMATS:
        print(f"inspector: invalid wire_format {POLICY.get('wire_format')!r}"
              f" (allowed: {VALID_WIRE_FORMATS})", file=sys.stderr)
        return 64
    if POLICY.get("mode", MODE_ENFORCE) not in VALID_MODES:
        print(f"inspector: invalid mode {POLICY.get('mode')!r} (allowed: {VALID_MODES})",
              file=sys.stderr)
        return 64
    # `passthrough` is the public name of `real_keychain_bridge`: the client's own credentials are forwarded as-is to
    # the https upstream, and this gate **neither checks nor logs** them. The old name is kept because the existing 104 cases use it;
    # a rename shouldn't quietly change the criteria (that's a separate thing). The semantics are identical, and so are the constraints:
    # it must be https and must not carry expected_auth_token.
    if POLICY["auth_mode"] not in ("loopback_dummy", "real_keychain_bridge", "passthrough"):
        print(f"inspector: invalid auth_mode {POLICY['auth_mode']!r}", file=sys.stderr)
        return 64
    if POLICY["auth_mode"] == "loopback_dummy":
        # Byte-for-byte reconstruction — the same criterion as preflight's gate, computed independently by each.
        # Both compute it rather than "trusting preflight did", because the policy is a file,
        # and a file can be changed between two processes.
        if up != {"scheme": "http", "host": "127.0.0.1", "port": up.get("port")}:
            print(f"inspector: loopback_dummy connect target must be http/127.0.0.1, "
                  f"got {up!r}", file=sys.stderr)
            return 64
        if not isinstance(up["port"], int) or not 1 <= up["port"] <= 65535:
            print(f"inspector: invalid connect port {up.get('port')!r}", file=sys.stderr)
            return 64
        if origin != f"http://127.0.0.1:{up['port']}":
            print(f"inspector: upstream_origin does not match the pinned connect target: "
                  f"{origin!r}", file=sys.stderr)
            return 64
        if not POLICY.get("expected_auth_token"):
            print("inspector: loopback_dummy must carry expected_auth_token", file=sys.stderr)
            return 64
    else:
        if up["scheme"] != "https" or POLICY.get("expected_auth_token") is not None:
            print("inspector: real-mode connect/credential declaration is wrong", file=sys.stderr)
            return 64

    srv = BoundedThreadingHTTPServer(("127.0.0.1", 0), Handler)
    actual = srv.server_address[1]
    log("inspector_ready", port=actual, policy_sha256=sha(raw), pid=os.getpid())
    print(f"READY 127.0.0.1:{actual} policy_sha256={sha(raw)}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
