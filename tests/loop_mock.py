#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSE mock for closing the loop: answers according to **this round's plan** so the real
CLI can actually walk the whole lower bound.

Why it's needed: `mock_upstream.py` returns canned responses and doesn't know this round's
random challenge, so a real CLI against it can never reach success — that's by
construction, not a defect. This mock reads `runs/<attempt>/plan.json` after preflight and
sends tool_use per this round's sentinel path, final text per this round's challenge.

🔴 Anti-self-certification (the counter-arm external review A7 item 12 called for):
`--mode selfcert` makes the mock **copy the challenge straight into the final text**,
issuing no tool call at all. That arm must **not** be judged success — otherwise the lower
bound is judging "does the text contain that string", not "did the model really read that
file". A criterion the mock can self-certify is no criterion at all.

Standalone run: loop_mock.py --port 53127 --runs <sandbox>/runs [--mode selfcert]
"""
import argparse
import glob
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = None
STATS = {"requests": 0, "tool_use_sent": 0, "final_sent": 0,
         "no_tools_text_sent": 0, "tool_use_ids": []}

# ★2026-08-09: two **fixture self-certifications** caught by external review A8 §1 — the
# 2026-08-08 `success` died on these (withdrawn):
#   ① every tool_use got the same `toolu_loop_1` back — so **one tool_result could match
#      two tool_uses at once**; the "causal pairing" was manufactured by this mock, not
#      real.
#   ② a request with `tools=[]` got a client tool use back too — a model advertised no
#      tools can't call tools, but this mock could.
# Criterion ([[feedback_fixture_can_self_certify]]): **if this fixture tried to fool me,
# could it?**
_SEQ = {"n": 0}


def latest_plan():
    """Find this round's plan. The attempt directory is created by preflight, so it doesn't
    exist yet when the mock starts."""
    cands = glob.glob(os.path.join(ARGS.runs, "*", "plan.json"))
    if not cands:
        return None
    return json.load(open(max(cands, key=os.path.getmtime)))


def sse(*events):
    out = b""
    for e in events:
        out += b"event: " + e["type"].encode() + b"\ndata: " + json.dumps(e).encode() + b"\n\n"
    return out


def advertised_tools(doc):
    """Which tools this round's request actually advertised. **The mock may only call what
    it was given.**"""
    tools = doc.get("tools")
    if not isinstance(tools, list):
        return []
    return [t.get("name") for t in tools
            if isinstance(t, dict) and isinstance(t.get("name"), str)]


def next_tool_use_id():
    _SEQ["n"] += 1
    tid = f"toolu_loop_{_SEQ['n']}_{os.getpid()}"
    STATS["tool_use_ids"].append(tid)
    return tid


def tool_use_response(sentinel):
    body = json.dumps({"file_path": sentinel})
    mid = len(body) // 2
    return sse(
        {"type": "message_start",
         "message": {"id": f"msg_loop_{_SEQ['n'] + 1}", "type": "message", "role": "assistant",
                     "model": "mock", "content": [], "stop_reason": None,
                     "usage": {"input_tokens": 1, "output_tokens": 1}}},
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "tool_use", "id": next_tool_use_id(),
                           "name": "Read", "input": {}}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": body[:mid]}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "input_json_delta", "partial_json": body[mid:]}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "tool_use"},
         "usage": {"output_tokens": 1}},
        {"type": "message_stop"})


def final_response(challenge):
    return text_response(challenge + "\n" + json.dumps({"ok": True, "read": challenge}))


def text_response(text):
    return sse(
        {"type": "message_start",
         "message": {"id": "msg_loop_2", "type": "message", "role": "assistant",
                     "model": "mock", "content": [], "stop_reason": None,
                     "usage": {"input_tokens": 1, "output_tokens": 1}}},
        {"type": "content_block_start", "index": 0,
         "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
         "usage": {"output_tokens": 1}},
        {"type": "message_stop"})


def has_tool_result(doc):
    for m in doc.get("messages") or []:
        for b in (m.get("content") if isinstance(m.get("content"), list) else []):
            if isinstance(b, dict) and b.get("type") == "tool_result":
                return True
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.endswith("/__mock/stats"):
            body = json.dumps(STATS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        STATS["requests"] += 1
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception:
            doc = {}
        plan = latest_plan() or {}
        sentinel = plan.get("sentinel_path") or "/nonexistent"
        challenge = plan.get("challenge") or "NO-CHALLENGE"

        if ARGS.mode == "selfcert":
            # Counter-arm: no tool calls at all, copy the challenge straight into the final text.
            body = final_response(challenge)
            STATS["final_sent"] += 1
        elif has_tool_result(doc):
            body = final_response(challenge)
            STATS["final_sent"] += 1
        elif "Read" not in advertised_tools(doc):
            # 🔴 A8: this cell used to **return tool_use** — answering a request advertised
            # no tools with a client tool use is something a real model can't do, so using it
            # as causal evidence was fake.
            # Now it returns plain text, making "no tools given means no tool calls" visible
            # in the artifacts.
            # ⚠️ And **deliberately leaves the challenge out**: with no tools this round there's
            # no legitimate way to know that string. Including it would give the positive arm's
            # sentinel one more route that bypasses the file.
            body = text_response("no tools advertised in this request")
            STATS["no_tools_text_sent"] += 1
        else:
            body = tool_use_response(sentinel)
            STATS["tool_use_sent"] += 1

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        # Send in chunks on purpose, so the relay's incremental path really gets exercised
        for i in range(0, len(body), 97):
            part = body[i:i + 97]
            self.wfile.write(b"%x\r\n" % len(part) + part + b"\r\n")
            self.wfile.flush()
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


def main():
    global ARGS
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--runs", required=True)
    p.add_argument("--mode", choices=["normal", "selfcert"], default="normal")
    ARGS = p.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler)
    print(f"READY loop-mock 127.0.0.1:{ARGS.port} mode={ARGS.mode}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
