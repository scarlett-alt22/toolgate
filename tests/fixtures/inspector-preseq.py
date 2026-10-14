#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-forward capability upper-bound gate. v2 — rewritten 2026-08-08 per inspector-review2
§D.

It is the only place in this whole apparatus that can see "which tools this round actually
advertised": the CLI's `--output-format json` top level has no tools field, and neither do
the debug logs (measured 08-07).

🔴 **Blocking must happen before forwarding.** The 08-07 first version did post-hoc grading
and got caught by Codex's review: one round genuinely advertised extra Bash, and the model
could already use it at that moment — post-hoc grading cannot undo side effects.

Five changes in v2 vs v1, all aimed at Codex's P0s:
  ① **malformed no longer fails open**. v1 treated a body parse failure as "no tools" and let
     it through; now parse failures are all blocked. **"Can't parse" does not mean "safe".**
  ② **Judge by full-definition hash, not just name**. v1 only looked at the tool name, so
     "same-name Read with a swapped schema" and "duplicate Read" both passed.
  ③ **Approved values are read only from the wrapper-written, hash-locked policy snapshot**,
     never from ambient env. v1 read HB_INSPECTOR_ALLOWED_TOOLS, which let an environment
     variable decide how wide the gate was.
  ④ **capability path**: random ≥128bit prefix; any request with a wrong path is rejected —
     which also separates "some other process happened to connect to this port" from this
     round's requests.
  ⑤ **All 3xx are recorded as upstream errors and never followed**; blocked requests never
     show forward_started_at.

🔴 Logging discipline (spec:306): **never log headers, API keys, prompt/messages bodies,
tool input bodies, or tool result bodies.** Things that must stay as evidence, like paths,
are kept as sha256 only.
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
COUNTS = {"requests": 0, "blocked": 0, "forwarded": 0}


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
    """Canonical bytes of a tool definition. Full definition, not just the name."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ── Upper-bound check: runs before forwarding, returns (decision, reason, inventory) ──
def decide(method, path, raw):
    """Per-request upper bound of spec:72-84. Any single miss is a block, and it **never
    fails open**."""
    inv = {"tools_present": False, "tools_type": None, "tool_names": [],
           "tool_definition_hashes": [], "model": None, "body_bytes": len(raw),
           "stream": None}

    if method != "POST":
        return "block", f"method is not POST: {method}", inv

    split = urlsplit(path)
    want_prefix = "/" + POLICY["capability_path"]
    if not split.path.startswith(want_prefix):
        # Never print the real prefix, lest the log itself become a place that leaks the
        # capability
        return "block", "capability path prefix mismatch", inv
    rest = path[len(want_prefix):]
    if rest != POLICY["messages_path"]:
        return "block", f"path/query is not the approved messages_path: {rest!r}", inv

    if len(raw) > POLICY.get("max_body_bytes", MAX_BODY_BYTES_DEFAULT):
        return "block", f"body exceeds the limit ({len(raw)} bytes)", inv

    # ① malformed is always blocked. Can't parse ≠ safe.
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception as e:
        return "block", f"body is not valid JSON ({type(e).__name__}) - malformed is always blocked, never fails open", inv
    if not isinstance(doc, dict):
        inv["tools_type"] = type(doc).__name__
        return "block", f"body root is not an object, it is {type(doc).__name__}", inv

    inv["model"] = doc.get("model") if isinstance(doc.get("model"), str) else None
    if inv["model"] != POLICY["model"]:
        return "block", f"model is not the approved one: {inv['model']!r}", inv

    # ★2026-08-08 A7 §3: `stream` decides which scanner this response gets,
    # so it must be decidable. Non-bool is always rejected **before forwarding** —
    # a request I can't tell how to observe must not be let through.
    if "stream" in doc and not isinstance(doc["stream"], bool):
        return "block", f"stream is not a bool: {type(doc['stream']).__name__}", inv
    inv["stream"] = bool(doc.get("stream", False))

    if "tools" not in doc:
        # Missing tools field: must not be treated as "no tools". A missing field and an
        # empty array are two different things — the former means this request doesn't look
        # like anything we approved.
        return "block", "body missing tools field (missing field != empty tool set)", inv

    inv["tools_present"] = True
    tools = doc["tools"]
    inv["tools_type"] = type(tools).__name__
    if not isinstance(tools, list):
        return "block", f"tools is not an array, it is {type(tools).__name__}", inv

    approved = POLICY["approved_tools"]          # {name: definition_sha256}
    seen_names = []
    for t in tools:
        if not isinstance(t, dict):
            inv["tool_names"].append(None)
            inv["tool_definition_hashes"].append(None)
            return "block", "tools element is not an object", inv
        name = t.get("name")
        h = sha(canon_tool(t))
        inv["tool_names"].append(name if isinstance(name, str) else None)
        inv["tool_definition_hashes"].append(h)
        if not isinstance(name, str) or not name.strip():
            return "block", f"tool name missing/empty/not a string: {name!r}", inv
        if name in seen_names:
            return "block", f"same request advertised {name!r} more than once", inv
        seen_names.append(name)
        if name not in approved:
            return "block", f"advertised an unapproved tool {name!r}", inv
        # ② Judge by full-definition hash: same name with a swapped schema must be blocked
        if h != approved[name]:
            return "block", (f"{name!r} full-definition hash does not match the approved value"
                             f"(approved {approved[name][:12]}…, this run {h[:12]}…)"), inv

    return "forward", None, inv


# ── Response parsing: keep structural evidence only, never bodies ──────────────────
def scan_request(request_id, raw):
    """Scans tool_results inside the **request**.

    🔴 Found 2026-08-08 during end-to-end: in the Messages API, tool_use comes back inside
    the **response**, while tool_result is carried up by the client in the **next request**.
    Scanning only responses would never see tool_result — half of the lower bound's
    "causal evidence strung on one id" would go missing, and "it read" vs "it read
    successfully" would become indistinguishable.
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
    """Records one tool_use structural-evidence entry. Only id / name / path sha256 /
    whether it hit the sentinel."""
    sentinel_path = POLICY.get("sentinel_path") or ""
    log("tool_use_seen", request_id=request_id,
        tool_use_id=tool_use_id, name=name,
        input_path_sha256=sha(file_path) if isinstance(file_path, str) else None,
        path_match=(file_path == sentinel_path) if isinstance(file_path, str) else False)


# ── Response scanning (★2026-08-08 external review A7 full rewrite) ────────────────
# The old version was `scan_response(request_id, whole_body)`: read the whole body →
# `json.loads` → `return` on failure. The first real traffic exposed two problems:
#   ① The real API's responses are streaming; `json.loads` can't parse them → zero
#      `tool_use_seen` records → the lower bound's causal evidence is halved → judged
#      obligation_failed. **That was the observer's false negative.**
#   ② That `except: return` was **silent**: "can't parse" and "the response never had
#      tool_use" are completely isomorphic in the artifacts — the scanner had the same
#      disease we spent a whole day dissecting.
# Now: incremental, bounded, exactly one closing `response_scan_terminal` per required
# response.
# ⚠️ External review explicitly required relay and scan to change in the same batch: only
#    swapping the scanner is not enough — "read the whole body before relaying" itself had
#    to go.

MAX_SSE_EVENT_BYTES = 1 * 1024 * 1024      # per-SSE-event cap
MAX_TOOL_INPUT_BYTES = 1 * 1024 * 1024     # per-tool-input accumulated partial_json cap
MAX_OPEN_TOOL_BLOCKS = 32                  # cap on simultaneously open tool blocks
MAX_JSON_SHADOW_BYTES = 8 * 1024 * 1024    # non-streaming shadow buffer cap
RELAY_CHUNK = 64 * 1024


class _ScanFailure(Exception):
    """Scan failure. Carries only a closed reason_code — **no exception message, no body**."""
    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code


class SseResponseScanner:
    """Incremental SSE state machine. Conclusions must agree under any network chunking
    boundary.

    tool input gets its id/name from `content_block_start`, then accumulates several
    `input_json_delta.partial_json` fragments, and is only parsed into the complete input
    at `content_block_stop` — so `tool_use_seen` is recorded **exactly once at block_stop**,
    never at start.
    """
    format = "sse"

    def __init__(self, request_id):
        self.request_id = request_id
        self.buf = b""
        self.open_blocks = {}
        self.tool_use_count = 0
        self.unknown_event_count = 0
        self.message_stop_seen = False
        self.bytes_seen = 0
        self.stream_error = None

    def feed(self, chunk):
        self.bytes_seen += len(chunk)
        self.buf += chunk
        while True:
            bound = self._next_boundary()
            if bound is None:
                if len(self.buf) > MAX_SSE_EVENT_BYTES:
                    raise _ScanFailure("event_too_large")
                return
            block, self.buf = self.buf[:bound[0]], self.buf[bound[1]:]
            if len(block) > MAX_SSE_EVENT_BYTES:
                raise _ScanFailure("event_too_large")
            self._handle_event(block)

    def _next_boundary(self):
        a, b = self.buf.find(b"\n\n"), self.buf.find(b"\r\n\r\n")
        cands = [(x, x + n) for x, n in ((a, 2), (b, 4)) if x != -1]
        return min(cands) if cands else None

    def _handle_event(self, block):
        try:
            text = block.decode("utf-8")
        except UnicodeDecodeError:
            raise _ScanFailure("invalid_utf8")
        data_lines = []
        for line in text.replace("\r\n", "\n").split("\n"):
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
        if not data_lines:
            return                                   # event:/id:/comment lines only
        payload = "\n".join(data_lines)
        if payload.strip() == "[DONE]":
            return
        try:
            doc = json.loads(payload)
        except Exception:
            raise _ScanFailure("invalid_sse_json")
        if not isinstance(doc, dict):
            raise _ScanFailure("invalid_sse_json")
        self._dispatch(doc)

    def _dispatch(self, doc):
        kind = doc.get("type")
        if kind == "content_block_start":
            cb = doc.get("content_block") or {}
            if isinstance(cb, dict) and cb.get("type") == "tool_use":
                if len(self.open_blocks) >= MAX_OPEN_TOOL_BLOCKS:
                    raise _ScanFailure("event_too_large")
                self.open_blocks[doc.get("index")] = {
                    "id": cb.get("id"), "name": cb.get("name"), "parts": [], "n": 0}
        elif kind == "content_block_delta":
            d = doc.get("delta") or {}
            if isinstance(d, dict) and d.get("type") == "input_json_delta":
                blk = self.open_blocks.get(doc.get("index"))
                if blk is not None:
                    part = d.get("partial_json")
                    if not isinstance(part, str):
                        raise _ScanFailure("tool_input_invalid")
                    blk["n"] += len(part)
                    if blk["n"] > MAX_TOOL_INPUT_BYTES:
                        raise _ScanFailure("event_too_large")
                    blk["parts"].append(part)
        elif kind == "content_block_stop":
            blk = self.open_blocks.pop(doc.get("index"), None)
            if blk is not None:
                raw = "".join(blk["parts"])
                if raw.strip():
                    try:
                        inp = json.loads(raw)
                    except Exception:
                        raise _ScanFailure("tool_input_invalid")
                    if not isinstance(inp, dict):
                        raise _ScanFailure("tool_input_invalid")
                else:
                    inp = {}                          # parameterless tool, legal
                _emit_tool_use(self.request_id, blk["id"], blk["name"], inp.get("file_path"))
                self.tool_use_count += 1
        elif kind == "message_stop":
            self.message_stop_seen = True
        elif kind == "error":
            # 🔴 An in-stream error is the API's stream error, **not** a parse failure.
            # Only record the safe error type, never the message; postconditions take it
            # from there.
            err = doc.get("error") or {}
            self.stream_error = err.get("type") if isinstance(err, dict) else "unknown"
        elif kind in ("message_start", "message_delta", "ping"):
            pass
        else:
            # The protocol explicitly allows new event types — unknown does not mean bad,
            # just count it.
            self.unknown_event_count += 1

    def finish(self):
        if self.buf.strip():
            raise _ScanFailure("truncated_stream")
        if self.open_blocks:
            raise _ScanFailure("truncated_stream")
        if not self.message_stop_seen:
            raise _ScanFailure("truncated_stream")
        return {"stream_error": self.stream_error}


class JsonResponseScanner:
    """Non-streaming: relay while keeping a **bounded** shadow buffer, then scan the whole
    body as JSON at EOF.

    ⚠️ A true token-level incremental JSON parser is a follow-up item. Only two things must
    hold here: relay no longer "buffers the whole response before sending", and memory no
    longer grows without bound with the response.
    """
    format = "json"

    def __init__(self, request_id):
        self.request_id = request_id
        self.buf = b""
        self.bytes_seen = 0
        self.overflow = False
        self.tool_use_count = 0
        self.unknown_event_count = 0
        self.message_stop_seen = True     # non-streaming has no such concept, always true
        self.stream_error = None

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
        if self.overflow:
            raise _ScanFailure("json_scan_limit_exceeded")
        try:
            doc = json.loads(self.buf.decode("utf-8"))
        except UnicodeDecodeError:
            raise _ScanFailure("invalid_utf8")
        except Exception:
            raise _ScanFailure("invalid_sse_json")
        if not isinstance(doc, dict):
            raise _ScanFailure("invalid_sse_json")
        blocks = doc.get("content")
        for b in blocks if isinstance(blocks, list) else []:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                _emit_tool_use(self.request_id, b.get("id"), b.get("name"), inp.get("file_path"))
                self.tool_use_count += 1
        return {"stream_error": None}


def pick_scanner(request_id, want_stream, media_type):
    """The scan obligation is decided by the **request context**, not by "try parsing
    whatever response shows up".

    External review A7 §3: `stream:true` requires `text/event-stream`; missing/false
    requires JSON. A content-type mismatch is a visible failure, not a silent pass.
    """
    base = (media_type or "").split(";")[0].strip().lower()
    if want_stream:
        if base != "text/event-stream":
            raise _ScanFailure("content_type_mismatch")
        return SseResponseScanner(request_id)
    if base not in ("application/json", "application/vnd.api+json", ""):
        raise _ScanFailure("content_type_mismatch")
    return JsonResponseScanner(request_id)


def check_auth_headers(headers):
    """Verifies the request's credentials before forwarding. Returns None (allow) or one
    rejection reason.

    🔴 Only takes effect under `loopback_dummy`. In real mode the wrapper **does not know**
    what the real credential looks like, and must not — that is between the keychain and
    the CLI; guessing here would only guess wrong.

    ⚠️ It returns a **stable code**, not prose. Two reasons:
      ① Rejection reasons enter the log, and the log must contain neither header values
         **nor header names** — the acceptance suite has a `no_auth_in_log` assertion that
         scans for exactly the strings `authorization`/`x-api-key`/`bearer `; writing prose
         would turn my own log into that assertion's counterexample (the first version
         tripped on this);
      ② codes are machine-judgeable; the oracle never has to match Chinese text.
    """
    if POLICY.get("auth_mode") != "loopback_dummy":
        return None, {}
    expected = POLICY.get("expected_auth_token")
    if not expected:
        return "policy_missing_expected_token", {}

    # Only `get_all` can count "sent two"; `get` just gives you the first.
    got = headers.get_all("authorization") or []
    meta = {"observed_identity_count": len(got)}

    # 🔴 Priority is fixed by external review (A6b ②): alternate identity > count > value.
    # The order is not arbitrary — for a request carrying both an alternate identity and a
    # wrong value, the report must be "it brought a different identity"; that is the more
    # fundamental problem.
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hb-inspector/2"

    def log_message(self, *a):
        pass

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

        with LOG_LOCK:
            COUNTS["requests"] += 1

        decision, reason, inv = decide(method, self.path, raw)

        base = {
            "request_id": request_id, "received_at": received_at, "method": method,
            "path": urlsplit(self.path).path.replace(POLICY["capability_path"], "<cap>"),
            "model": inv["model"], "body_bytes": inv["body_bytes"],
            "tools_present": inv["tools_present"], "tools_type": inv["tools_type"],
            "tool_names": inv["tool_names"],
            "tool_definition_hashes": inv["tool_definition_hashes"],
            "decision": decision, "block_reason": reason,
            "upstream_origin": POLICY["upstream_origin"],
            # One of the three things external review A7 called out to keep: the
            # request-side stream bool. Without it, after the fact you can't tell "the
            # response should have been SSE" from "it was always supposed to be JSON".
            "request_stream": inv.get("stream"),
        }

        if decision == "block":
            with LOG_LOCK:
                COUNTS["blocked"] += 1
            # 🔴 blocked must never show forward_started_at — this one is independently
            # verified by the mock counter
            log("request", **base, forward_started_at=None,
                upstream_status=None, response_complete=False, upstream_error=None)
            payload = json.dumps({"error": {"type": "policy_blocked", "message": reason}}).encode()
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # ── Pre-forward: credential gate (★2026-08-08 external review A5 §2) ────────
        # Only this step proves that **what the CLI actually said** was that public dummy
        # credential, not just the plan claiming dummy. "The plan says dummy" and "the
        # process really used dummy" are two different things — the same shape as terminal
        # self-report vs recomputation from events.
        auth_bad, auth_meta = check_auth_headers(self.headers)
        if auth_bad:
            with LOG_LOCK:
                COUNTS["blocked"] += 1
            # 🔴 `decision` must be recorded as block. That `base["decision"]` above is the
            # body gate's verdict (it said forward), but this request **was actually
            # blocked** — leaving "forward" in the log would make "blocked" and "forwarded"
            # isomorphic in the artifacts, exactly the thing we've been dissecting all along.
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
        # 🔴 The connection target is read only from the policy-pinned upstream_connect —
        # **never parse the origin string again**. The old code did
        # `urlsplit(POLICY["upstream_origin"]).hostname` here, while preflight judged
        # loopback with `startswith("127.0.0.1")` —
        # `http://127.0.0.1@192.0.2.1:9` made the two sides see two different hosts.
        up = POLICY["upstream_connect"]
        conn_cls = (http.client.HTTPSConnection if up["scheme"] == "https"
                    else http.client.HTTPConnection)
        status = None
        upstream_error = None
        complete = False
        headers_sent = False
        scanner = None
        scan_outcome, scan_reason = None, None
        media_type = None

        try:
            conn = conn_cls(up["host"], up["port"], timeout=60)
            fwd_headers = {"Content-Type": "application/json",
                           "Content-Length": str(len(raw)),
                           "anthropic-version": self.headers.get("anthropic-version", "2023-06-01")}
            # Auth headers are passed through verbatim but **never recorded**; only the few
            # required ones are picked here, no wholesale copy.
            for h in ("x-api-key", "authorization", "anthropic-beta"):
                v = self.headers.get(h)
                if v:
                    fwd_headers[h] = v
            conn.request("POST", POLICY["messages_path"], body=raw, headers=fwd_headers)
            resp = conn.getresponse()
            status = resp.status
            media_type = resp.getheader("Content-Type")

            if 300 <= status < 400:
                # ⑤ all 3xx count as upstream errors, never followed
                upstream_error = "redirect_not_followed"
                resp.read()
                conn.close()
            else:
                # Scan obligation is decided by the request context (A7 §3): only responses
                # that should have been Messages 2xx are required to scan clean.
                # 403/502/control-plane responses produce no fake parse failures.
                scan_required = (200 <= status < 300)
                if scan_required:
                    try:
                        scanner = pick_scanner(request_id, inv.get("stream") is True, media_type)
                    except _ScanFailure as sf:
                        scan_outcome, scan_reason = "failed", sf.reason_code

                # ── Scan while relaying, flush every chunk ────────────────────────
                # 🔴 No more `body = resp.read()` buffering the whole body before relaying:
                # that made time-to-first-byte equal the whole response duration and let
                # memory grow without bound with the response.
                declared = resp.getheader("Content-Length")
                self.send_response(status)
                if media_type:
                    self.send_header("Content-Type", media_type)   # keep the upstream's, no longer force json
                if declared is not None:
                    self.send_header("Content-Length", declared)
                    chunked = False
                else:
                    self.send_header("Transfer-Encoding", "chunked")  # either/or, never both
                    chunked = True
                self.end_headers()
                headers_sent = True

                seen = 0
                while True:
                    chunk = resp.read1(RELAY_CHUNK)
                    if not chunk:
                        break
                    seen += len(chunk)
                    # payload bytes unchanged byte-for-byte; only the transfer chunking may
                    # differ
                    if chunked:
                        self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                    else:
                        self.wfile.write(chunk)
                    self.wfile.flush()
                    if scanner is not None and scan_outcome is None:
                        try:
                            scanner.feed(chunk)
                        except _ScanFailure as sf:
                            scan_outcome, scan_reason = "failed", sf.reason_code
                        except Exception:
                            # a scanner exception must not blow up the relay thread — but this
                            # round must not be success
                            scan_outcome, scan_reason = "failed", "scan_internal_error"
                if chunked:
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()

                complete = (declared is None) or (seen == int(declared))
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
                conn.close()
        except Exception as e:
            upstream_error = upstream_error or type(e).__name__
            if scanner is not None and scan_outcome is None:
                scan_outcome, scan_reason = "failed", "truncated_stream"

        with LOG_LOCK:
            COUNTS["forwarded"] += 1
        log("request", **base, forward_started_at=forward_started_at,
            upstream_status=status, response_complete=complete, upstream_error=upstream_error,
            auth_mode=POLICY.get("auth_mode"),
            dummy_auth_match=(POLICY.get("auth_mode") == "loopback_dummy" or None),
            **auth_meta)

        # 🔴 Exactly one closing event per required response. It is the line between
        # "scanned and fine" and "couldn't parse" — finish.py uses it to separate
        # obligation_failed from inspector_failed. A missing event is itself a failure.
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
            # once headers are committed a 502 can't be faked anymore: cut the connection and
            # let response_complete speak
            if upstream_error:
                self.close_connection = True
            return

        if upstream_error or status is None:
            payload = json.dumps({"error": {"type": "upstream_error",
                                            "message": upstream_error or "no status"}}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return


def main():
    global POLICY, LOG_PATH
    # ★2026-08-08 P0: the port used to be read from ambient `HB_INSPECTOR_PORT`, and hb-run.sh
    # starts the inspector inheriting exactly the uncleaned environment — one environment
    # variable could change production behavior.
    # The first fix added a `--test-port N` escape hatch; external review cut it the same day
    # ((b)): **no caller needs it** (hb-run never passes it, acceptance never passes it) — a
    # parameter only an attacker would use is pure exposure.
    # Now production always binds ("127.0.0.1", 0) and lets the kernel pick; the port is read
    # back from the READY line. Tests that need a fixed port use the trusted fake inspector's
    # own flags; it never enters the production binary.
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
            print(f"inspector: policy missing field {k}", file=sys.stderr)
            return 64
    if len(POLICY["capability_path"]) < 32:
        print("inspector: capability_path too short (needs >=128bit random)", file=sys.stderr)
        return 64

    # ── Startup re-verification (★2026-08-08 external review A5 §1) ───────────────
    # One preflight check is not enough: **this process** is the one actually initiating the
    # connect, so it must confirm it itself. But then it simply **doesn't print READY** —
    # hb-run won't start the model until it sees READY, so "not verified" and "verified" are
    # distinguishable in external behavior, not by this code's good intentions.
    up = POLICY["upstream_connect"]
    origin = POLICY["upstream_origin"]
    if not isinstance(up, dict) or set(up) != {"scheme", "host", "port"}:
        print("inspector: upstream_connect malformed", file=sys.stderr)
        return 64
    if POLICY["auth_mode"] not in ("loopback_dummy", "real_keychain_bridge"):
        print(f"inspector: auth_mode illegal {POLICY['auth_mode']!r}", file=sys.stderr)
        return 64
    if POLICY["auth_mode"] == "loopback_dummy":
        # Rebuilt byte-for-byte — the same criterion as the preflight gate, computed
        # independently in each place. Both compute it instead of "trusting that preflight
        # already did" because the policy is a file, and a file can be changed between two
        # processes.
        if up != {"scheme": "http", "host": "127.0.0.1", "port": up.get("port")}:
            print(f"inspector: loopback_dummy connect target must be http/127.0.0.1,"
                  f"got {up!r}", file=sys.stderr)
            return 64
        if not isinstance(up["port"], int) or not 1 <= up["port"] <= 65535:
            print(f"inspector: connect port illegal {up.get('port')!r}", file=sys.stderr)
            return 64
        if origin != f"http://127.0.0.1:{up['port']}":
            print(f"inspector: upstream_origin does not match the pinned connect target:"
                  f"{origin!r}", file=sys.stderr)
            return 64
        if not POLICY.get("expected_auth_token"):
            print("inspector: loopback_dummy requires expected_auth_token", file=sys.stderr)
            return 64
    else:
        if up["scheme"] != "https" or POLICY.get("expected_auth_token") is not None:
            print("inspector: real-mode connect/credential declaration wrong", file=sys.stderr)
            return 64

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    actual = srv.server_address[1]
    log("inspector_ready", port=actual, policy_sha256=sha(raw), pid=os.getpid())
    print(f"READY 127.0.0.1:{actual} policy_sha256={sha(raw)}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        log("inspector_stopping", **COUNTS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
