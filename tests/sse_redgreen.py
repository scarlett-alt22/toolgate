#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red/green matrix for the SSE / JSON response scanner (the batch external
review A7 called for).

⚠️ **Not part of the 92 gates**: run_acceptance only reads cases.json.
This is the red/green evidence from the day the forwarding path was replaced
(2026-08-08); run it manually:
       /usr/bin/python3 tests/sse_redgreen.py

It hits the scanner classes directly, without HTTP, so it cannot cover the relay
layer cells (latency mock proving relay-while-forwarding, upstream/downstream
mid-stream disconnects, out-of-scope responses) — those need an HTTP-level
fixture, not yet written — see the self-reported boundary at the end.

The core cell is the **old-vs-new comparison**: on the same official-shaped SSE,
the old implementation records 0 `tool_use_seen`, the new one records exactly 1.
"""
import importlib.util
import json
import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
sys.path.insert(0, WRAPPER)
import inspector as I  # noqa: E402

CHAL = "CHAL-redgreen-fixed"
SENTINEL = "/tmp/hb-redgreen/input/sentinel.txt"
I.POLICY = {"sentinel_path": SENTINEL, "challenge": CHAL, "capability_path": "c" * 32,
            "model": "m", "approved_tools": [], "messages_path": "/v1/messages?beta=true",
            "upstream_origin": "http://127.0.0.1:1", "attempt_id": "x",
            "auth_mode": "loopback_dummy", "expected_auth_token": "t",
            "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": 1}}

CAPTURED = []
I.log = lambda kind, **f: CAPTURED.append({"event": kind, **f})


def sse(*events):
    out = b""
    for e in events:
        out += b"event: " + e["type"].encode() + b"\ndata: " + json.dumps(e).encode() + b"\n\n"
    return out


def tool_use_stream(path=SENTINEL, parts=None, stop=True, name="Read",
                    tool_id="toolu_01", noise=False):
    """Official shape: message_start → block_start(tool_use) → several input_json_delta
    segments → content_block_stop → message_stop. tool input is only complete at stop."""
    body = json.dumps({"file_path": path})
    parts = parts or [body[:5], body[5:12], body[12:]]
    evs = [{"type": "message_start", "message": {"id": "msg_1"}}]
    if noise:
        evs += [{"type": "ping"}, {"type": "some_future_event_v9", "whatever": 1}]
    evs.append({"type": "content_block_start", "index": 0,
                "content_block": {"type": "tool_use", "id": tool_id, "name": name}})
    for p in parts:
        evs.append({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": p}})
    evs.append({"type": "content_block_stop", "index": 0})
    if stop:
        evs.append({"type": "message_stop"})
    return sse(*evs)


def run_scanner(scanner, blob, chunk=None, keep_ids=False):
    """Feed to the scanner; returns (outcome, reason_code, tool_use_seen list).

    ★2026-08-09: the `tool_use_id` uniqueness registry is **attempt-level** (across
    requests), so every cell's fixture must clear it first, or from the second cell on
    all streams reusing the same id will legitimately report `duplicate_tool_use_id`.
    ⚠️ `keep_ids=True` deliberately does NOT clear — reserved for the cell that tests
    cross-response duplication; the clearing action itself must be switchable off for
    it to be testable.
    """
    if not keep_ids:
        I.reset_tool_use_ids()
    CAPTURED.clear()
    step = chunk or len(blob) or 1
    try:
        for i in range(0, len(blob), step):
            scanner.feed(blob[i:i + step])
        scanner.finish()
        outcome, reason = "ok", None
    except I._ScanFailure as sf:
        outcome, reason = "failed", sf.reason_code
    return outcome, reason, [c for c in CAPTURED if c["event"] == "tool_use_seen"]


RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))


# ── ① Old vs new: this cell is the reason the whole thing exists ──────────────────────────────────
blob = tool_use_stream()
# 🔴 This cell is the most important red arm in the whole repo: it proves the
# **new scanner catches what the old scanner missed**. The old implementation is
# kept as a frozen fixture in tests/fixtures/inspector-prestream.py (the version
# before the 2026-08-08 streaming change). **Don't delete it just because it "looks
# like an old file"** — deleting this cell leaves only "the new implementation runs",
# and that proves nothing.
import shutil                                                     # noqa: E402
import tempfile                                                   # noqa: E402
_tmp = tempfile.mkdtemp(prefix="old-inspector-")
_old_path = os.path.join(_tmp, "old_inspector.py")
shutil.copy(os.path.join(WRAPPER, "tests", "fixtures", "inspector-prestream.py"), _old_path)
spec = importlib.util.spec_from_file_location("old_inspector", _old_path)
old = importlib.util.module_from_spec(spec)
OLD_CAP = []
try:
    spec.loader.exec_module(old)
except SystemExit:
    pass
old.POLICY = I.POLICY
old.log = lambda kind, **f: OLD_CAP.append({"event": kind, **f})
old.scan_response("req1", blob)
old_n = len([c for c in OLD_CAP if c["event"] == "tool_use_seen"])
shutil.rmtree(_tmp, ignore_errors=True)

outcome, reason, uses = run_scanner(I.SseResponseScanner("req1"), blob)
check("① old implementation records 0 entries on official-shape SSE", old_n == 0, f"old tool_use_seen={old_n}")
check("① new implementation records exactly 1 entry", outcome == "ok" and len(uses) == 1,
      f"outcome={outcome} reason={reason} n={len(uses)}")
if uses:
    u = uses[0]
    check("① id/name/path_match all match",
          u["tool_use_id"] == "toolu_01" and u["name"] == "Read" and u["path_match"] is True,
          json.dumps({k: u[k] for k in ("tool_use_id", "name", "path_match")}, ensure_ascii=False))
    check("① log contains no raw path text", SENTINEL not in json.dumps(uses, ensure_ascii=False),
          "only input_path_sha256 retained")

# ── ② Chunk at arbitrary byte boundaries, same verdict ───────────────────────────────────────
bad_sizes = []
for size in range(1, len(blob) + 1):
    o, r, u = run_scanner(I.SseResponseScanner("r"), blob, chunk=size)
    if not (o == "ok" and len(u) == 1 and u[0]["path_match"] is True):
        bad_sizes.append(size)
check(f"② chunking at every byte boundary (1..{len(blob)}) gives the same verdict", not bad_sizes,
      f"{len(blob)} chunkings total" + (f", failed at {bad_sizes[:5]}" if bad_sizes else ", all consistent"))

# ── ③ Valid SSE, text only, no tool use ─────────────────────────────────────────────
text_only = sse({"type": "message_start", "message": {"id": "m"}},
                {"type": "content_block_start", "index": 0,
                 "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0,
                 "delta": {"type": "text_delta", "text": "hello"}},
                {"type": "content_block_stop", "index": 0},
                {"type": "message_stop"})
o, r, u = run_scanner(I.SseResponseScanner("r"), text_only)
check("③ text only: scan ok and tool_use=0 (not an observer failure)",
      o == "ok" and len(u) == 0, f"outcome={o} reason={r} n={len(u)}")

# ── ④ Bad streams land on the correct terminal reason ────────────────────────────────────
o, r, _ = run_scanner(I.SseResponseScanner("r"), b"event: x\ndata: {not json}\n\n")
check("④ malformed JSON event → invalid_sse_json", r == "invalid_sse_json", f"{o}/{r}")

o, r, _ = run_scanner(
    I.SseResponseScanner("r"),
    b'event: ping\ndata: {"type":"ping","type":"message_stop"}\n\n')
check("④ duplicate keys in SSE JSON → invalid_sse_json", r == "invalid_sse_json", f"{o}/{r}")

o, r, _ = run_scanner(I.SseResponseScanner("r"), tool_use_stream(stop=False))
check("④ truncated (no message_stop) → truncated_stream", r == "truncated_stream", f"{o}/{r}")

o, r, _ = run_scanner(I.SseResponseScanner("r"),
                      tool_use_stream(parts=["x" * (I.MAX_TOOL_INPUT_BYTES + 10)]))
check("④ tool input over the limit → event_too_large", r == "event_too_large", f"{o}/{r}")

bad_input = tool_use_stream(parts=['{"file_path": '])   # assembled, not valid JSON
o, r, _ = run_scanner(I.SseResponseScanner("r"), bad_input)
check("④ tool input does not assemble into JSON → tool_input_invalid", r == "tool_input_invalid", f"{o}/{r}")

dup_input = tool_use_stream(parts=['{"file_path":"x","file_path":"' + SENTINEL + '"}'])
o, r, _ = run_scanner(I.SseResponseScanner("r"), dup_input)
check("④ duplicate keys in tool input → tool_input_invalid", r == "tool_input_invalid", f"{o}/{r}")

err_stream = sse({"type": "message_start", "message": {"id": "m"}},
                 {"type": "error", "error": {"type": "overloaded_error", "message": "SECRET"}},
                 {"type": "message_stop"})
sc = I.SseResponseScanner("r")
o, r, _ = run_scanner(sc, err_stream)
check("④ in-stream error is not a parse failure; only the safe type is recorded",
      o == "ok" and sc.stream_error == "overloaded_error", f"{o}/{r}/{sc.stream_error}")

o, r, _ = run_scanner(I.SseResponseScanner("r"), b"data: \xff\xfe\n\n")
check("④ invalid UTF-8 → invalid_utf8", r == "invalid_utf8", f"{o}/{r}")

# ── ⑤ ping and valid unknown events don't false-positive ────────────────────────────────
# ⚠️ This fixture was changed on 2026-08-09: the old version was `sse(message_start,
#    ping, unknown) + tool_use_stream()`, but `tool_use_stream()` brings its own
#    message_start — **two message_starts in one stream**, which must go red once
#    sequence validation lands. The fixture was never protocol-valid; the old
#    scanner just couldn't tell. Now the noise goes into the same valid stream.
noisy = tool_use_stream(noise=True)
sc = I.SseResponseScanner("r")
o, r, u = run_scanner(sc, noisy)
check("⑤ ping + unknown events: no false-positive failure, unknown count visible",
      o == "ok" and len(u) == 1 and sc.unknown_event_count == 1,
      f"outcome={o} reason={r} unknown={sc.unknown_event_count}")

# ── ⑥ Non-streaming JSON regression: old behavior doesn't regress ─────────────────────────────
plain = json.dumps({"id": "msg", "content": [
    {"type": "tool_use", "id": "toolu_json", "name": "Read", "input": {"file_path": SENTINEL}}]}).encode()
o, r, u = run_scanner(I.JsonResponseScanner("r"), plain)
check("⑥ non-streaming JSON still records 1 entry with path_match correct",
      o == "ok" and len(u) == 1 and u[0]["path_match"] is True, f"{o}/{r}/n={len(u)}")

o, r, _ = run_scanner(I.JsonResponseScanner("r"), b"{not json")
check("⑥ non-streaming bad JSON is now a **visible failure**, no more silent return", o == "failed", f"{o}/{r}")

o, r, _ = run_scanner(
    I.JsonResponseScanner("r"),
    b'{"content":[],"content":[{"type":"text","text":"x"}]}')
check("⑥ duplicate keys in non-streaming JSON → invalid_json", r == "invalid_json", f"{o}/{r}")

# ── ⑦ content-type picks the scanner; mismatch is a visible failure ───────────────────────────
def picked(stream, ct):
    try:
        return I.pick_scanner("r", stream, ct).format
    except I._ScanFailure as sf:
        return "FAIL:" + sf.reason_code
check("⑦ stream=true + text/event-stream → sse", picked(True, "text/event-stream; charset=utf-8") == "sse")
check("⑦ stream=true but JSON returned → content_type_mismatch",
      picked(True, "application/json") == "FAIL:content_type_mismatch")
check("⑦ stream=false + JSON → json", picked(False, "application/json") == "json")
check("⑦ stream=false but SSE returned → content_type_mismatch",
      picked(False, "text/event-stream") == "FAIL:content_type_mismatch")

# ── ⑧ Sequence validation: the eight bad shapes A8 §1 called for ───────────────────────────────
# 🔴 This whole section is new. The previous scanner returned `scan ok` for every
#    item below, yet each one would turn "causal evidence chained on one id" fake.
def seq(*events):
    return sse(*events)


MS = {"type": "message_start", "message": {"id": "m"}}
CBS_TOOL = {"type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": "toolu_a", "name": "Read"}}


def reason_of(blob, scanner=None):
    o, r, _ = run_scanner(scanner or I.SseResponseScanner("r"), blob)
    return r


check("⑧ duplicate tool_use_id within one response → duplicate_tool_use_id",
      reason_of(seq(MS, CBS_TOOL, {"type": "content_block_stop", "index": 0},
                    {"type": "content_block_start", "index": 1,
                     "content_block": {"type": "tool_use", "id": "toolu_a", "name": "Read"}},
                    {"type": "content_block_stop", "index": 1},
                    {"type": "message_stop"})) == "duplicate_tool_use_id")

check("⑧ reopening the same index (silent overwrite) → invalid_sse_sequence",
      reason_of(seq(MS, CBS_TOOL,
                    {"type": "content_block_start", "index": 0,
                     "content_block": {"type": "tool_use", "id": "toolu_b", "name": "Read"}},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

check("⑧ orphan delta (index never started) → invalid_sse_sequence",
      reason_of(seq(MS, {"type": "content_block_delta", "index": 7,
                         "delta": {"type": "input_json_delta", "partial_json": "{}"}},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

check("⑧ orphan stop → invalid_sse_sequence",
      reason_of(seq(MS, {"type": "content_block_stop", "index": 7},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

check("⑧ tool_use missing id → invalid_sse_sequence",
      reason_of(seq(MS, {"type": "content_block_start", "index": 0,
                         "content_block": {"type": "tool_use", "name": "Read"}},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

check("⑧ content sent with no message_start → invalid_sse_sequence",
      reason_of(seq(CBS_TOOL, {"type": "content_block_stop", "index": 0},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

check("⑧ duplicate message_stop → invalid_sse_sequence",
      reason_of(seq(MS, {"type": "message_stop"},
                    {"type": "message_stop"})) == "invalid_sse_sequence")

# `event:` vs JSON `type` mismatch: `sse()` writes the event name from type, so this one is hand-written.
mismatch = (b"event: message_start\ndata: " + json.dumps(MS).encode() + b"\n\n"
            b"event: content_block_start\ndata: "
            + json.dumps({"type": "message_stop"}).encode() + b"\n\n")
check("⑧ event: name does not match JSON type → event_type_mismatch",
      reason_of(mismatch) == "event_type_mismatch")

missing_type = (b"event: future_event\ndata: {\"payload\":1}\n\n")
nonstring_type = (b"event: future_event\ndata: {\"type\":7}\n\n")
empty_type = (b"event: \ndata: {\"type\":\"\"}\n\n")
missing_event = (b"data: {\"type\":\"future_event\"}\n\n")
unknown_equal = (b"event: future_event\ndata: {\"type\":\"future_event\"}\n\n")
for label, blob2 in (("JSON type missing", missing_type),
                     ("JSON type not a string", nonstring_type),
                     ("empty string on both ends", empty_type),
                     ("event: missing", missing_event)):
    check(f"⑧ {label} → event_type_mismatch",
          reason_of(blob2) == "event_type_mismatch")
sc_unknown = I.SseResponseScanner("unknown")
try:
    sc_unknown.feed(unknown_equal)
    unknown_ok = sc_unknown.unknown_event_count == 1
except I._ScanFailure:
    unknown_ok = False
check("⑧ unknown type equal on both ends is only counted, then ignored", unknown_ok)

# ── ⑨ Attempt-level uniqueness: this cell is where the withdrawn success died ──────────────────────
# The 08-08 loop mock returned the same `toolu_loop_1` every time; two **different
# responses** each recorded once, so one tool_result matched two uses. In-response
# dedup can't stop that.
I.reset_tool_use_ids()

# Registry exhaustion and true duplicates must use different codes, or field
# attribution would read "memory bound hit" as "upstream reused an id". Shrink
# the cap to 1 temporarily, occupy one slot, then send a second unique id.
old_registry_cap = I.MAX_TRACKED_TOOL_USE_IDS
try:
    I.MAX_TRACKED_TOOL_USE_IDS = 1
    I.reset_tool_use_ids()
    o_cap1, r_cap1, _ = run_scanner(
        I.SseResponseScanner("cap1"), tool_use_stream(tool_id="toolu_cap_1"), keep_ids=True)
    o_cap2, r_cap2, _ = run_scanner(
        I.SseResponseScanner("cap2"), tool_use_stream(tool_id="toolu_cap_2"), keep_ids=True)
    check("⑨ tool_use id registry full → tool_use_id_registry_exhausted (not masquerading as duplicate)",
          o_cap1 == "ok" and r_cap2 == "tool_use_id_registry_exhausted",
          f"first={o_cap1}/{r_cap1} second={o_cap2}/{r_cap2}")
finally:
    I.MAX_TRACKED_TOOL_USE_IDS = old_registry_cap
    I.reset_tool_use_ids()
o1, r1, u1 = run_scanner(I.SseResponseScanner("req1"), tool_use_stream(tool_id="toolu_dup"),
                         keep_ids=True)
o2, r2, u2 = run_scanner(I.SseResponseScanner("req2"), tool_use_stream(tool_id="toolu_dup"),
                         keep_ids=True)
check("⑨ duplicate tool_use_id across responses: first ok, second duplicate_tool_use_id",
      o1 == "ok" and len(u1) == 1 and r2 == "duplicate_tool_use_id",
      f"resp1={o1}/{r1} resp2={o2}/{r2}")
o3, r3, u3 = run_scanner(I.SseResponseScanner("req3"), tool_use_stream(tool_id="toolu_uniq"),
                         keep_ids=True)
check("⑨ a different unique id in the same attempt still passes (not a blanket rejection)",
      o3 == "ok" and len(u3) == 1, f"{o3}/{r3}")
I.reset_tool_use_ids()

# ── ⑩ Line terminators: WHATWG allows CRLF / CR / LF ───────────────────────────────────────
# The old version only recognized `\n\n` and `\r\n\r\n`; CR-only streams were
lf = tool_use_stream()
for label, blob2 in (("CRLF", lf.replace(b"\n", b"\r\n")),
                     ("pure CR", lf.replace(b"\n", b"\r"))):
    o, r, u = run_scanner(I.SseResponseScanner("r"), blob2)
    check(f"⑩ {label} separators: same verdict as LF (ok, 1 tool_use)",
          o == "ok" and len(u) == 1, f"{o}/{r}/n={len(u)}")
# misreported as truncated_stream. When a chunk boundary lands mid-CRLF, \r must
# not count as a terminator on its own.
crlf = lf.replace(b"\n", b"\r\n")
bad = [s for s in range(1, len(crlf) + 1)
       if run_scanner(I.SseResponseScanner("r"), crlf, chunk=s)[0] != "ok"]
check("⑩ every byte-boundary chunking of the CRLF stream agrees", not bad,
      f"{len(crlf)} chunkings total" + (f", failed at {bad[:5]}" if bad else ", all consistent"))

# ── ⑫ Memory hard bounds: empty deltas no longer bloat the list; bytes counted, not chars ────────
# A8 split out the "four memory hard bounds" from the old comment; in practice only two held.
many_empty = tool_use_stream(parts=[""] * 5000 + ['{"file_path": "%s"}' % SENTINEL])
o, r, u = run_scanner(I.SseResponseScanner("r"), many_empty)
check("⑫ 5000 empty partial_jsons cause no failure and no accumulation (bounded bytearray)",
      o == "ok" and len(u) == 1, f"{o}/{r}")
# Multi-byte: the bound counts **UTF-8 bytes**, not characters. To actually
# measure the difference, "char count" and "byte count" must fall on opposite
# sides of the bound — but a single event can't hold that much (events have their
# own 1 MiB cap, and json.dumps escapes each CH into 6 bytes of \uXXXX),
# so it must **accumulate across multiple delta events**. That is also the shape
# of a real stream.
# ⚠️ The first version of this cell used a single event, so it hit the event cap
#    first — it reported event_too_large, looked "green", but never touched the
#    tool-input bound at all. **The case didn't test what it claimed to test.**
CH = "密"                                   # 1 char = 3 UTF-8 bytes
under = [CH * 100_000] * 3                  # 300,000 chars / 900,000 bytes < 1 MiB
over = [CH * 100_000] * 4                   # 400,000 chars / 1,200,000 bytes > 1 MiB
assert len("".join(under)) < I.MAX_TOOL_INPUT_BYTES        # old char-based counting: both within the bound
assert len("".join(over)) < I.MAX_TOOL_INPUT_BYTES
o, r, _ = run_scanner(I.SseResponseScanner("r"), tool_use_stream(parts=under))
check("⑫ 900 KB multibyte tool input within the bound (no false kill; fails at JSON parse)",
      r == "tool_input_invalid", f"{o}/{r}")
o, r, _ = run_scanner(I.SseResponseScanner("r"), tool_use_stream(parts=over))
check("⑫ 1.2 MB multibyte tool input → event_too_large (char count still < limit, byte count over)",
      r == "event_too_large", f"{o}/{r}")

# ── ⑬ Non-streaming JSON shape validation (A8 §3) ───────────────────────────────────
def json_reason(doc):
    o, r, _ = run_scanner(I.JsonResponseScanner("r"),
                          doc if isinstance(doc, bytes) else json.dumps(doc).encode())
    return r


check("⑬ {\"type\":\"message\"} (missing content) no longer reads as \"valid but no tools\"",
      json_reason({"type": "message"}) == "invalid_json_shape")
check("⑬ content is not an array → invalid_json_shape",
      json_reason({"content": "nope"}) == "invalid_json_shape")
check("⑬ tool_use input is a scalar → invalid_json_shape",
      json_reason({"content": [{"type": "tool_use", "id": "t1",
                                "name": "Read", "input": 5}]}) == "invalid_json_shape")
check("⑬ tool_use missing id → invalid_json_shape",
      json_reason({"content": [{"type": "tool_use", "name": "Read",
                                "input": {}}]}) == "invalid_json_shape")
check("⑬ duplicate tool ID in one non-streaming response → duplicate_tool_use_id",
      json_reason({"content": [
          {"type": "tool_use", "id": "tdup", "name": "Read", "input": {}},
          {"type": "tool_use", "id": "tdup", "name": "Read", "input": {}}]})
      == "duplicate_tool_use_id")
check("⑬ valid non-streaming: text-block-only gives ok and 0 entries",
      json_reason({"content": [{"type": "text", "text": "hi"}]}) is None)
check("⑦ non-streaming response missing Content-Type → content_type_mismatch (old version accepted it as JSON)",
      picked(False, None) == "FAIL:content_type_mismatch")
check("⑦ empty-string Content-Type is rejected the same way",
      picked(False, "") == "FAIL:content_type_mismatch")

# ── ⑭ Framing validation (A8 §2) ─────────────────────────────────────────────
class _FakeResp:
    def __init__(self, cl=None, te=None, chunked=None):
        self._h = {}
        if te is not None:
            self._h["Transfer-Encoding"] = [te]
        if cl is not None:
            self._h["Content-Length"] = cl if isinstance(cl, list) else [cl]
        self.chunked = (str(te).strip().lower() == "chunked") if chunked is None else chunked

    def getheader(self, k):
        v = self._h.get(k) or self._h.get(k.title())
        return v[0] if v else None

    @property
    def headers(self):
        outer = self

        class _H:
            def get_all(self, k):
                for kk, vv in outer._h.items():
                    if kk.lower() == k.lower():
                        return vv
                return None
        return _H()


for label, resp_obj, want in (
        ("single canonical value", _FakeResp("5"), (5, None)),
        ("0 is legal", _FakeResp("0"), (0, None)),
        ("single chunked", _FakeResp(te="chunked"), (None, None)),
        ("neither CL nor TE", _FakeResp(), (None, "missing_response_framing")),
        ("leading plus +5", _FakeResp("+5"), (None, "invalid_content_length")),
        ("leading zero 007", _FakeResp("007"), (None, "invalid_content_length")),
        ("negative -1", _FakeResp("-1"), (None, "invalid_content_length")),
        ("two conflicting values", _FakeResp(["5", "6"]), (None, "invalid_content_length")),
        ("two identical values still not a single CL", _FakeResp(["5", "5"]),
         (None, "invalid_content_length")),
        ("two identical values in one line", _FakeResp("5, 5"), (None, "invalid_content_length")),
        ("two comma-separated values in one line", _FakeResp("5, 6"), (None, "invalid_content_length")),
        ("CL and TE both present", _FakeResp("5", "chunked"), (None, "conflicting_framing")),
        ("gzip, chunked not supported", _FakeResp(te="gzip, chunked", chunked=True),
         (None, "invalid_transfer_encoding")),
        ("non-chunked TE", _FakeResp(te="gzip", chunked=False),
         (None, "invalid_transfer_encoding")),
        ("chunked unrecognized by the lower layer", _FakeResp(te="chunked", chunked=False),
         (None, "invalid_transfer_encoding"))):
    got = I.validate_framing(resp_obj)
    check(f"⑭ Content-Length {label}", got == want, f"{got} vs {want}")

# ── ⑮ Red arm: the pre-change scanner passed ALL of the bad shapes above ───────────────────
# 🔴 This section is the real acceptance for ⑧⑩⑬. Green only says "it blocks
#    now", not "it used to slip through" — an assertion that can never fire is also
#    green. Criterion = **same bytes, old implementation returns ok.**
_tmp2 = tempfile.mkdtemp(prefix="preseq-inspector-")
_preseq = os.path.join(_tmp2, "preseq_inspector.py")
shutil.copy(os.path.join(WRAPPER, "tests", "fixtures", "inspector-preseq.py"), _preseq)
spec2 = importlib.util.spec_from_file_location("preseq_inspector", _preseq)
preseq = importlib.util.module_from_spec(spec2)
try:
    spec2.loader.exec_module(preseq)
except SystemExit:
    pass
preseq.POLICY = I.POLICY
preseq.log = lambda kind, **f: None


def old_outcome(blob2, json_mode=False):
    sc2 = (preseq.JsonResponseScanner("r") if json_mode
           else preseq.SseResponseScanner("r"))
    try:
        sc2.feed(blob2)
        sc2.finish()
        return "ok"
    except preseq._ScanFailure as sf:
        return sf.reason_code
    except Exception as e:                     # noqa: BLE001
        return type(e).__name__


_OLD_ARMS = [
    ("duplicate tool_use_id in one response",
     seq(MS, CBS_TOOL, {"type": "content_block_stop", "index": 0},
         {"type": "content_block_start", "index": 1,
          "content_block": {"type": "tool_use", "id": "toolu_a", "name": "Read"}},
         {"type": "content_block_stop", "index": 1}, {"type": "message_stop"}), False),
    ("reopening the same index",
     seq(MS, CBS_TOOL, {"type": "content_block_start", "index": 0,
                        "content_block": {"type": "tool_use", "id": "toolu_b", "name": "Read"}},
         {"type": "content_block_stop", "index": 0}, {"type": "message_stop"}), False),
    ("orphan delta",
     seq(MS, {"type": "content_block_delta", "index": 7,
              "delta": {"type": "input_json_delta", "partial_json": "{}"}},
         {"type": "message_stop"}), False),
    ("orphan stop", seq(MS, {"type": "content_block_stop", "index": 7},
                    {"type": "message_stop"}), False),
    ("tool_use missing id",
     seq(MS, {"type": "content_block_start", "index": 0,
              "content_block": {"type": "tool_use", "name": "Read"}},
         {"type": "content_block_stop", "index": 0}, {"type": "message_stop"}), False),
    ("no message_start", seq(CBS_TOOL, {"type": "content_block_stop", "index": 0},
                            {"type": "message_stop"}), False),
    ("duplicate message_stop", seq(MS, {"type": "message_stop"},
                            {"type": "message_stop"}), False),
    ("event name does not match type", mismatch, False),
    ("JSON response missing content", json.dumps({"type": "message"}).encode(), True),
    ("tool input is a scalar",
     json.dumps({"content": [{"type": "tool_use", "id": "t1", "name": "Read",
                              "input": 5}]}).encode(), True),
    ("duplicate tool ID in non-streaming",
     json.dumps({"content": [{"type": "tool_use", "id": "td", "name": "Read", "input": {}},
                             {"type": "tool_use", "id": "td", "name": "Read",
                              "input": {}}]}).encode(), True),
]
_leaked = [n for n, b, j in _OLD_ARMS if old_outcome(b, j) != "ok"]
check(f"⑮ pre-change scanner let all {len(_OLD_ARMS)} bad shapes **through** (scan ok)",
      not _leaked, "all ok, so ⑧⑬ are not vacuous assertions"
      if not _leaked else f"these were already blocked in the old version: {_leaked}")
# pure CR is the reverse: the old version **misreported**, the new one is right
check("⑮ valid pure-CR-delimited stream: old version misreported truncated_stream, new ok",
      old_outcome(lf.replace(b"\n", b"\r")) == "truncated_stream",
      f"old={old_outcome(lf.replace(chr(10).encode(), chr(13).encode()))}")
shutil.rmtree(_tmp2, ignore_errors=True)

# ── ⑪ secret-like content stays out of the logs ──────────────────────────────────────────
decoy = "sk-ant-THIS-LOOKS-LIKE-A-SECRET-BUT-IS-NOT"
leaky = tool_use_stream(path=decoy)
o, r, u = run_scanner(I.SseResponseScanner("r"), leaky)
blob_log = json.dumps(CAPTURED, ensure_ascii=False)
check("⑪ credential-shaped tool input does not appear in logs",
      o == "ok" and decoy not in blob_log, "only sha256 retained")

# ── ⑯ Mutation test: delete the `stream`-is-not-bool guard; the cases must go red ──────────────
# 🔴 `ub-stream-not-bool` / `ub-stream-null` are the "implementation is right
#    but has no regression test" kind A8 named. **An assertion that can never fire
#    is also green** — so here the guard itself is deleted, to confirm the cases
#    really bite on that guard instead of being caught incidentally by another check.
_mut_dir = tempfile.mkdtemp(prefix="mutant-inspector-")
_src = open(os.path.join(WRAPPER, "inspector.py")).read()
_guard = '''    if "stream" in doc and not isinstance(doc["stream"], bool):
        return "block", f"stream is not a bool: {type(doc['stream']).__name__}", inv
'''
_mut_ok = _guard in _src
_mut_path = os.path.join(_mut_dir, "mutant_inspector.py")
open(_mut_path, "w").write(_src.replace(_guard, "", 1))
spec3 = importlib.util.spec_from_file_location("mutant_inspector", _mut_path)
mut = importlib.util.module_from_spec(spec3)
try:
    spec3.loader.exec_module(mut)
except SystemExit:
    pass


def _decide_on(mod, stream_value):
    mod.POLICY = {"capability_path": "c" * 32, "messages_path": "/v1/messages?beta=true",
                  "model": "m", "approved_tools": {}, "max_body_bytes": 2 * 1024 * 1024}
    b = json.dumps({"model": "m", "messages": [], "tools": [],
                    "stream": stream_value}).encode()
    return mod.decide("POST", "/" + "c" * 32 + "/v1/messages?beta=true", b)[0]


check("⑯ mutation precondition: the guard is really in the source (deletable)", _mut_ok)
check("⑯ current impl: stream=\"true\" (string) is blocked",
      _decide_on(I, "true") == "block", _decide_on(I, "true"))
check("⑯ current impl: stream=null is blocked", _decide_on(I, None) == "block")
check("⑯ with the guard deleted both are forwarded - so those two acceptance cases are not vacuous",
      _decide_on(mut, "true") == "forward" and _decide_on(mut, None) == "forward",
      f'mutant: "true"→{_decide_on(mut, "true")} null→{_decide_on(mut, None)}')
check("⑯ valid stream=true is unaffected", _decide_on(I, True) == "forward")
shutil.rmtree(_mut_dir, ignore_errors=True)

# ── Summary ──────────────────────────────────────────────────────────────
width = max(len(n) for n, _, _ in RESULTS)
bad = 0
for name, ok, detail in RESULTS:
    if not ok:
        bad += 1
    print(f"{'✔' if ok else '✘'} {name.ljust(width)}  {detail}")
print()
print(f"SSE_REDGREEN {len(RESULTS) - bad}/{len(RESULTS)}"
      f"{'  ALL_OK' if bad == 0 else '  BROKEN=' + str(bad)}")
# ⚠️ This self-reported boundary was updated on 2026-08-09. Of the five items the
#    old version listed, three were already covered that day by
#    relay_redgreen / loop_arms — **an expired disclaimer and a fake assertion
#    are the same thing**, only the lie points in the more modest direction.
print("Coverage boundary: this file only exercises the scanner classes, no HTTP. HTTP layer (first-chunk-first, mid-stream upstream/downstream disconnects,"
      "client disconnects, illegal Content-Length, missing Content-Type, out-of-scope producing no false failures)"
      "is in tests/relay_redgreen.py; real CLI + loopback closed-loop arms in tests/loop_arms.py.")
print("finish's three-part five-cell checks are covered independently via the single entry point by tests/finish_arms.py + fixtures/finish.")
sys.exit(1 if bad else 0)
