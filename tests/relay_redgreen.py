#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP-level red/green for the relay layer. Items 7/8/9 of external review A7.

`sse_redgreen.py` only exercises the scanner **class**; it never reaches the relay:
no matter how clearly "relay while forwarding" is written in code, it takes one
measurement to prove it really relays while forwarding. So this file starts a
**real inspector process** against an SSE origin with controllable pacing, and
measures four things:

  ⑧a The first chunk must reach the client before the upstream has finished
     sending (otherwise it's buffering, not relaying)
  ⑧b The payload the client gets is **byte-identical** to what the origin sent,
     with the correct Content-Type
  ⑨  Upstream disconnects mid-stream: no hang, no fake trailer, not marked complete
  ⑦  Out-of-scope responses (non-2xx) produce no fake response_scan failure

⚠️ Not part of the 92 gates; run manually:
       /usr/bin/python3 tests/relay_redgreen.py
"""
import http.client
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)

CAP = secrets.token_hex(16)
MODEL = "claude-haiku-4-5-20251001"
SENTINEL = "/tmp/hb-relay/sentinel.txt"
CHAL = "CHAL-relay-fixed"
DUMMY = "hb-loopback-dummy-v1-public-noncredential"

# Official-shaped SSE, split into chunks; delays can be inserted between them.
# ★2026-08-09: `tool_use_id` is now **attempt-level unique**, and this whole
# fixture starts one inspector process = one attempt. Every cell used to reuse `toolu_relay`,
# so from the second cell on it would legitimately report `duplicate_tool_use_id` — **the fixture itself was manufacturing duplicates**,
# the same disease as the withdrawn loop mock success. Each cell now carries a unique id.
def sse_parts(tool_id):
    return [
    b'event: message_start\ndata: {"type":"message_start","message":{"id":"m"}}\n\n',
    b'event: content_block_start\ndata: {"type":"content_block_start","index":0,'
    b'"content_block":{"type":"tool_use","id":"' + tool_id.encode() + b'","name":"Read"}}\n\n',
    b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    b'"delta":{"type":"input_json_delta","partial_json":"{\\"file_path\\": \\""}}\n\n',
    b'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,'
    b'"delta":{"type":"input_json_delta","partial_json":"' + SENTINEL.encode() + b'\\"}"}}\n\n',
    b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n',
    b'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]


SSE_PARTS = sse_parts("toolu_relay")
SSE_FULL = b"".join(SSE_PARTS)

MODE = {"kind": "sse", "delay": 0.0, "cut_after": None, "tool_id": "toolu_relay"}
ORIGIN_SENT = {"bytes": b"", "first_at": None, "last_at": None}
FRAMING_BODY_RELEASE = threading.Event()


class Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def handle_one_request(self):
        # In cell ⑮ the inspector deliberately cuts the upstream connection, so a BrokenPipe here is inevitable.
        # That is **the behavior under test**, not a fixture fault — keep it from flooding stderr with tracebacks.
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        kind = MODE["kind"]
        if kind == "non2xx":
            body = b'{"error":"nope"}'
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if kind == "bad_cl":
            # ★2026-08-09 A8 §2: non-canonical Content-Length.
            # The old version passed it straight through downstream, only then calling `int(declared)`.
            body = b'{"type":"message","content":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", MODE.get("cl_value", "+31"))
            self.end_headers()
            self.wfile.write(body)
            return
        if kind == "bad_framing":
            # Send headers only; the body is released by the test later. If the inspector
            # called read/drain on the illegal framing, the client waits forever; if it truly reads zero bytes, it gets a 502 immediately.
            body = b'{"type":"message","content":[]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            shape = MODE["framing_shape"]
            if shape == "duplicate_cl":
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Length", str(len(body)))
            elif shape == "comma_same_cl":
                self.send_header("Content-Length", f"{len(body)}, {len(body)}")
            elif shape == "gzip_chunked":
                self.send_header("Transfer-Encoding", "gzip, chunked")
            elif shape == "gzip":
                self.send_header("Transfer-Encoding", "gzip")
            self.end_headers()
            self.wfile.flush()
            FRAMING_BODY_RELEASE.wait(timeout=10)
            try:
                if shape == "gzip_chunked":
                    self.wfile.write(b"%x\r\n" % len(body) + body + b"\r\n0\r\n\r\n")
                else:
                    self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        if kind == "no_ct":
            # ★2026-08-09 A8 §3: a non-streaming response carrying **no** Content-Type at all.
            # The old version accepted the empty media type as JSON — that was making assumptions on the upstream's behalf.
            body = b'{"type":"message","content":[]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        ORIGIN_SENT["bytes"] = b""
        for i, part in enumerate(sse_parts(MODE["tool_id"])):
            if MODE["cut_after"] is not None and i >= MODE["cut_after"]:
                # mid-stream cut: no trailing 0 chunk, just sever the connection
                self.close_connection = True
                ORIGIN_SENT["last_at"] = time.time()
                return
            self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.flush()
            ORIGIN_SENT["bytes"] += part
            if ORIGIN_SENT["first_at"] is None:
                ORIGIN_SENT["first_at"] = time.time()
            if MODE["delay"]:
                time.sleep(MODE["delay"])
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()
        ORIGIN_SENT["last_at"] = time.time()


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))


def main():
    root = tempfile.mkdtemp(prefix="relay-rg-")
    op = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", op), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    policy = {"attempt_id": "relay", "capability_path": CAP,
              "upstream_origin": f"http://127.0.0.1:{op}",
              "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": op},
              "auth_mode": "loopback_dummy", "expected_auth_token": DUMMY,
              "messages_path": "/v1/messages?beta=true", "model": MODEL,
              "max_body_bytes": 2 * 1024 * 1024,
              "approved_tools": [], "required_actions": [],
              "sentinel_path": SENTINEL, "challenge": CHAL}
    ppath = os.path.join(root, "policy.json")
    json.dump(policy, open(ppath, "w"))
    log_path = os.path.join(root, "inspector.jsonl")

    insp = subprocess.Popen(["/usr/bin/python3", os.path.join(WRAPPER, "inspector.py"),
                             ppath, log_path], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, start_new_session=True)
    port = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = insp.stdout.readline()
        if line.startswith("READY"):
            port = int(line.split()[1].split(":")[1]); break
    if port is None:
        print("inspector did not start"); return 1

    body = json.dumps({"model": MODEL, "stream": True, "max_tokens": 16, "tools": [],
                       "messages": [{"role": "user", "content": "hi"}]}).encode()

    def post(read_cb=None):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        c.request("POST", f"/{CAP}/v1/messages?beta=true", body=body,
                  headers={"Content-Type": "application/json",
                           "Authorization": f"Bearer {DUMMY}"})
        r = c.getresponse()
        got, first_at = b"", None
        while True:
            chunk = r.read1(4096)
            if not chunk:
                break
            if first_at is None:
                first_at = time.time()
            got += chunk
        ct = r.getheader("Content-Type")
        c.close()
        return r.status, ct, got, first_at

    def events():
        rows = []
        if os.path.exists(log_path):
            for line in open(log_path):
                if line.strip():
                    rows.append(json.loads(line))
        return rows

    def wait_terminal(since=0, timeout=5.0):
        """Wait for the terminal event to land on disk before asserting.

        ⚠️ The moment the client finishes reading the chunked stream, the inspector is
        still in `scanner.finish()` plus log writing — reading right away sees
        "not there yet". That is a **race in the measurement setup**, not a missing
        artifact; but the two look identical in an assertion, so waiting is mandatory,
        not luck.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            rows = events()[since:]
            if any(r.get("event") == "response_scan_terminal" for r in rows):
                return rows
            time.sleep(0.05)
        return events()[since:]

    try:
        # ── ⑧ Slow origin: first chunk must arrive first ──────────────────────
        MODE.update(kind="sse", delay=0.25, cut_after=None)
        ORIGIN_SENT["first_at"] = ORIGIN_SENT["last_at"] = None
        status, ct, got, first_at = post()
        origin_done = ORIGIN_SENT["last_at"]
        check("⑧a first chunk reached the client before the upstream finished sending",
              first_at is not None and origin_done is not None and first_at < origin_done,
              f"first chunk arrived after {first_at and first_at - ORIGIN_SENT['first_at']:.2f}s,"
              f"upstream finished at {origin_done - ORIGIN_SENT['first_at']:.2f}s")
        check("⑧b client payload byte-identical to origin", got == SSE_FULL,
              f"{len(got)}B vs {len(SSE_FULL)}B")
        check("⑧b Content-Type is the upstream one, not forced to json",
              (ct or "").startswith("text/event-stream"), repr(ct))
        rows = wait_terminal(0)
        term = [r for r in rows if r.get("event") == "response_scan_terminal"]
        uses = [r for r in rows if r.get("event") == "tool_use_seen"]
        check("⑧c scan closed ok with exactly 1 tool_use",
              len(term) == 1 and term[0]["outcome"] == "ok"
              and term[0]["tool_use_count"] == 1 and len(uses) == 1,
              json.dumps({k: term[0].get(k) for k in ("format", "outcome", "tool_use_count")}
                         if term else {}, ensure_ascii=False))
        check("⑧d request side recorded the stream bool",
              any(r.get("request_stream") is True for r in rows if r.get("event") == "request"))

        # ── ⑨ Upstream disconnects mid-stream ────────────────────────────────
        n0 = len(events())
        MODE.update(kind="sse", delay=0.0, cut_after=3, tool_id="toolu_relay_cut")
        t0 = time.time()
        try:
            status2, ct2, got2, _ = post()
            hung = False
        except Exception:
            hung = False
        dur = time.time() - t0
        rows = wait_terminal(n0)
        term2 = [r for r in rows if r.get("event") == "response_scan_terminal"]
        req2 = [r for r in rows if r.get("event") == "request"]
        check("⑨ upstream mid-stream cut does not hang", dur < 20, f"{dur:.1f}s")
        check("⑨ not marked complete", req2 and req2[0].get("response_complete") is not True,
              f"response_complete={req2[0].get('response_complete') if req2 else '?'}")
        check("⑨ scan closed as failed with truncation reason",
              len(term2) == 1 and term2[0]["outcome"] == "failed"
              and term2[0]["reason_code"] == "truncated_stream",
              json.dumps({k: term2[0].get(k) for k in ("outcome", "reason_code")}
                         if term2 else {}, ensure_ascii=False))

        # ── ⑦ out-of-scope: non-2xx produces no fake scan failure ─────────────
        n0 = len(events())
        MODE.update(kind="non2xx", delay=0.0, cut_after=None)
        post()
        rows = events()[n0:]
        term3 = [r for r in rows if r.get("event") == "response_scan_terminal"]
        check("⑦ non-2xx upstream response produces no response_scan_terminal (not a parse failure)",
              len(term3) == 0, f"recorded {len(term3)} rows")
        req3 = [r for r in rows if r.get("event") == "request"]
        check("⑦ but the non-2xx itself is still recorded (failed by postcondition)",
              req3 and req3[0].get("upstream_status") == 500,
              f"status={req3[0].get('upstream_status') if req3 else '?'}")

        # ── ⑮ Client disconnects mid-stream (A8 §2 demands a true raw-socket red case) ──────
        # 🔴 The old version logged it as `upstream_error="BrokenPipeError"` — **blaming
        #    the other side**. The upstream was fine; the CLI walked away. Keep those separate.
        n0 = len(events())
        MODE.update(kind="sse", delay=0.35, cut_after=None, tool_id="toolu_relay_cliskip")
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        req = (f"POST /{CAP}/v1/messages?beta=true HTTP/1.1\r\n"
               f"Host: 127.0.0.1:{port}\r\n"
               f"Authorization: Bearer {DUMMY}\r\n"
               f"Content-Type: application/json\r\n"
               f"Content-Length: {len(body)}\r\n\r\n").encode() + body
        s.sendall(req)
        s.recv(64)                       # read a little, then leave
        s.close()
        rows = wait_terminal(n0, timeout=15)
        term4 = [r for r in rows if r.get("event") == "response_scan_terminal"]
        req4 = [r for r in rows if r.get("event") == "request"]
        check("⑮ mid-stream client disconnect: recorded as client_disconnected, **not** an upstream failure",
              req4 and req4[0].get("client_disconnected") is True
              and req4[0].get("upstream_error") is None,
              json.dumps({k: req4[0].get(k) for k in ("client_disconnected", "upstream_error")}
                         if req4 else {}, ensure_ascii=False))
        check("⑮ scan closed with reason_code=client_disconnected (not impersonating truncated_stream)",
              len(term4) == 1 and term4[0].get("reason_code") == "client_disconnected",
              json.dumps({k: term4[0].get(k) for k in ("outcome", "reason_code")}
                         if term4 else {}, ensure_ascii=False))
        check("⑮ inspector still alive after disconnect (not taken down by its own exception)", insp.poll() is None)

        # ── ⑯ Illegal upstream Content-Length ─────────────────────────
        for label, cl in (("+31 (accepted by Python int(), rejected by HTTP)", "+31"),
                          ("007 leading zero", "007"),
                          ("-1 negative", "-1")):
            n0 = len(events())
            MODE.update(kind="bad_cl", cl_value=cl)
            st, ct5, got5, _ = post()
            rows = events()[n0:]
            req5 = [r for r in rows if r.get("event") == "request"]
            term5 = [r for r in rows if r.get("event") == "response_scan_terminal"]
            check(f"⑯ Content-Length {label} → 502 and not a single byte forwarded",
                  st == 502 and req5
                  and req5[0].get("upstream_error") == "invalid_content_length"
                  and b'"content"' not in got5,
                  f"status={st} upstream_error={req5[0].get('upstream_error') if req5 else '?'}")
            check(f"⑯ Content-Length {label} produces no fake scan ok",
                  not any(t.get("outcome") == "ok" for t in term5),
                  f"terminals={[t.get('outcome') for t in term5]}")

        # ── ⑯b Duplicate CL / non-single chunked TE: close with zero reads ─────
        for label, shape, code in (
                ("Content-Length: 31, 31", "comma_same_cl", "invalid_content_length"),
                ("two identical Content-Length headers", "duplicate_cl", "invalid_content_length"),
                ("Transfer-Encoding: gzip, chunked", "gzip_chunked",
                 "invalid_transfer_encoding"),
                ("Transfer-Encoding: gzip", "gzip", "invalid_transfer_encoding")):
            n0 = len(events())
            FRAMING_BODY_RELEASE.clear()
            MODE.update(kind="bad_framing", framing_shape=shape)
            t0 = time.time()
            st7, _ct7, got7, _ = post()
            dur7 = time.time() - t0
            rows = events()[n0:]
            req7 = [r for r in rows if r.get("event") == "request"]
            check(f"⑯b {label} → 502 / zero forwarding / no body wait",
                  st7 == 502 and dur7 < 2 and req7
                  and req7[0].get("upstream_error") == code
                  and b'"content"' not in got7,
                  f"status={st7} duration={dur7:.2f}s code="
                  f"{req7[0].get('upstream_error') if req7 else '?'}")
            FRAMING_BODY_RELEASE.set()

        # ── ⑰ Non-streaming response missing Content-Type ─────────────────────
        n0 = len(events())
        MODE.update(kind="no_ct")
        nostream_body = json.dumps({"model": MODEL, "stream": False, "max_tokens": 16,
                                    "tools": [],
                                    "messages": [{"role": "user", "content": "hi"}]}).encode()
        c6 = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        c6.request("POST", f"/{CAP}/v1/messages?beta=true", body=nostream_body,
                   headers={"Content-Type": "application/json",
                            "Authorization": f"Bearer {DUMMY}"})
        r6 = c6.getresponse(); r6.read(); c6.close()
        rows = wait_terminal(n0)
        term6 = [r for r in rows if r.get("event") == "response_scan_terminal"]
        check("⑰ non-streaming response missing Content-Type → content_type_mismatch (no longer defaulting to JSON)",
              len(term6) == 1 and term6[0].get("outcome") == "failed"
              and term6[0].get("reason_code") == "content_type_mismatch",
              json.dumps({k: term6[0].get(k) for k in ("outcome", "reason_code")}
                         if term6 else {}, ensure_ascii=False))

        # ── ⑱ Concurrency slots before worker/body ─────────────────────────
        # 8 connections send headers only, no body, each stuck in its own **bounded** worker's body read.
        # The 9th must get a 503 straight from the accept thread; if the gate were still at the handler's tail, it would block too.
        slow = []
        slow_head = (f"POST /{CAP}/v1/messages?beta=true HTTP/1.1\r\n"
                     f"Host: 127.0.0.1:{port}\r\n"
                     f"Authorization: Bearer {DUMMY}\r\n"
                     f"Content-Type: application/json\r\n"
                     f"Content-Length: {len(body)}\r\n\r\n").encode()
        try:
            n0 = len(events())
            for _ in range(8):
                ss = socket.create_connection(("127.0.0.1", port), timeout=5)
                ss.sendall(slow_head)
                slow.append(ss)
            deadline = time.time() + 5
            acquired = []
            while time.time() < deadline:
                acquired = [r for r in events()[n0:]
                            if r.get("event") == "relay_slot_acquired"]
                if len(acquired) >= 8:
                    break
                time.sleep(0.02)
            ninth = socket.create_connection(("127.0.0.1", port), timeout=5)
            ninth.settimeout(3)
            ninth.sendall(slow_head)
            ninth_reply = ninth.recv(4096)
            ninth.close()
            time.sleep(0.1)
            caps = [r for r in events() if r.get("event") == "capacity_rejected"]
            check("⑱ after 8 slow requests fill the slots, the 9th gets an immediate 503 before body read / worker creation",
                  len(acquired) == 8 and b" 503 " in ninth_reply and caps
                  and caps[-1].get("body_bytes_read") == 0
                  and caps[-1].get("worker_created") is False,
                  f"acquired={len(acquired)} reply={ninth_reply.splitlines()[:1]} "
                  f"capacity_events={len(caps)}")
        finally:
            for ss in slow:
                try:
                    ss.close()
                except OSError:
                    pass
    finally:
        FRAMING_BODY_RELEASE.set()
        insp.terminate()
        srv.shutdown()

    width = max(len(n) for n, _, _ in RESULTS)
    bad = sum(1 for _, ok, _ in RESULTS if not ok)
    for name, ok, detail in RESULTS:
        print(f"{'✔' if ok else '✘'} {name.ljust(width)}  {detail}")
    print()
    print(f"RELAY_REDGREEN {len(RESULTS) - bad}/{len(RESULTS)}"
          f"{'  ALL_OK' if bad == 0 else '  BROKEN=' + str(bad)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
