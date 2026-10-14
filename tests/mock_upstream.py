#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loopback mock upstream — the only "Anthropic" acceptance is allowed to hit.

Raison d'être (spec:348): acceptance must prove the production origin branch was never
executed. So this thing's first duty isn't "return plausible responses", it's **counting**:
  - requests that hit me (a separate count per origin)
  - any sign of an attempt to reach api.anthropic.com → immediate failure, not a warning

🔴 Discipline (spec:306): **never record headers, api keys, prompt/messages bodies,
tool input verbatim, or tool result verbatim.** Only structure: method/path/model/byte
count/tools names and definition hashes. No line in this file touches body text content,
beyond computing sha256 and parsing the tools structure.

Usage:
    mock_upstream.py --port 18901 --role primary   [--script scenario.json]
    mock_upstream.py --port 18902 --role secondary          # 302 target, normally 0 requests

Control plane (doesn't go through the policy path; deliberately a different prefix):
    GET  /__mock/stats   → {"role":..., "requests": N, "events": [...]}
    POST /__mock/reset   → zero the counters
"""
import argparse
import hashlib
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REAL_ANTHROPIC_MARKERS = ("api.anthropic.com", "anthropic.com")


class State:
    def __init__(self, role, script):
        self.role = role
        self.script = script or {}
        self.lock = threading.Lock()
        self.requests = 0
        self.events = []
        self.real_origin_attempts = 0
        self.step = 0


STATE = None


DEFAULT_OK_MESSAGE = {"id": "msg_mock_default", "type": "message", "role": "assistant",
                      "content": [{"type": "text", "text": "ok"}]}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def summarize_body(raw):
    """Extract structure only; keep no body text. A parse failure must be reported as a
    parse failure — never fail-open."""
    out = {
        "body_bytes": len(raw),
        "body_sha256": sha(raw),
        "json_ok": False,
        "root_type": None,
        "model": None,
        "tools_present": False,
        "tools_type": None,
        "tool_names": [],
        "tool_definition_hashes": [],
    }
    try:
        doc = json.loads(raw.decode("utf-8"))
    except Exception:
        return out
    out["json_ok"] = True
    out["root_type"] = type(doc).__name__
    if not isinstance(doc, dict):
        return out
    out["model"] = doc.get("model") if isinstance(doc.get("model"), str) else None
    if "tools" in doc:
        out["tools_present"] = True
        tools = doc["tools"]
        out["tools_type"] = type(tools).__name__
        if isinstance(tools, list):
            for t in tools:
                if isinstance(t, dict):
                    nm = t.get("name")
                    out["tool_names"].append(nm if isinstance(nm, str) else None)
                    canon = json.dumps(t, sort_keys=True, separators=(",", ":")).encode()
                    out["tool_definition_hashes"].append(sha(canon))
                else:
                    out["tool_names"].append(None)
                    out["tool_definition_hashes"].append(None)
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "hb-mock/1"

    def log_message(self, *a):
        pass  # the default log prints the path to stderr; we keep our own structured record

    # ── control plane ─────────────────────────────────────────────
    def _control(self):
        if self.path == "/__mock/stats" and self.command == "GET":
            with STATE.lock:
                payload = json.dumps({
                    "role": STATE.role,
                    "requests": STATE.requests,
                    "real_origin_attempts": STATE.real_origin_attempts,
                    "events": STATE.events,
                }, ensure_ascii=False).encode()
            self._send(200, payload, "application/json")
            return True
        if self.path == "/__mock/reset" and self.command == "POST":
            with STATE.lock:
                STATE.requests = 0
                STATE.events = []
                STATE.real_origin_attempts = 0
                STATE.step = 0
            self._send(200, b'{"ok":true}', "application/json")
            return True
        return False

    def _send(self, code, body, ctype="application/json", extra_headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self._control():
            return
        self._record_and_reply(b"")

    def do_POST(self):
        if self._control():
            return
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        self._record_and_reply(raw)

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self.do_GET()

    # ── data plane ────────────────────────────────────────────────
    def _record_and_reply(self, raw):
        host = (self.headers.get("Host") or "").lower()
        hit_real = any(m in host for m in REAL_ANTHROPIC_MARKERS)

        info = summarize_body(raw)
        with STATE.lock:
            STATE.requests += 1
            if hit_real:
                STATE.real_origin_attempts += 1
            idx = STATE.step
            STATE.step += 1
            STATE.events.append({
                "seq": idx,
                "role": STATE.role,
                "method": self.command,
                "path": self.path,          # path carries no body text; the query stays so spec:363 can be verified
                "host_is_loopback": host.startswith("127.0.0.1") or host.startswith("localhost"),
                "hit_real_origin_marker": hit_real,
                **info,
            })

        # If the request carries `_mock_tool_use`, answer with a tool_use block.
        # The stub doesn't need to "look like a model"; it only needs to give the inspector
        # something to scan.
        echo = None
        try:
            d = json.loads(raw.decode("utf-8"))
            echo = d.get("_mock_tool_use") if isinstance(d, dict) else None
        except Exception:
            pass
        try:
            _d = json.loads(raw.decode("utf-8"))
            if isinstance(_d, dict) and _d.get("_mock_status_500"):
                self._send(500, b'{"error":"mock 500"}'); return
            if isinstance(_d, dict) and _d.get("_mock_redirect"):
                # 302 pointing at the second origin. The inspector must **not follow**,
                # so the second origin's request count must stay 0.
                self._send(302, b'{"redirect":true}',
                           extra_headers={"Location": _d["_mock_redirect"] + "/v1/messages?beta=true"})
                return
            if isinstance(_d, dict) and _d.get("_mock_incomplete"):
                body = b'{"partial":'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body) + 500))
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True
                return
        except Exception:
            pass
        if echo:
            body = json.dumps({"id": "msg_mock", "type": "message", "role": "assistant",
                               "content": [{"type": "tool_use", "id": echo.get("id"),
                                            "name": "Read",
                                            "input": {"file_path": echo.get("file_path")}}]},
                              ensure_ascii=False).encode()
            self._send(200, body)
            return

        behavior = self._behavior_for(idx)
        kind = behavior.get("kind", "ok")

        if kind == "redirect":
            target = behavior["location"]
            self._send(302, b'{"redirect":true}', extra_headers={"Location": target})
            return
        if kind == "incomplete":
            # Declare a longer Content-Length than actually sent, then disconnect —
            # reproduces spec:365 "upstream response incomplete"
            body = behavior.get("partial", b'{"partial":')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body) + 500))
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
            return
        if kind == "status":
            self._send(int(behavior.get("code", 500)), b'{"err":true}')
            return

        # ★2026-08-09: the default 200 used to be `{"ok":true}` (12 bytes). After the
        # scanner gained shape validation it was judged `invalid_json_shape` —
        # **correctly**: that's not a Messages response, the real upstream would never
        # answer that way. A stub answering with a shape the real upstream could never
        # return produces fake passes.
        # Now the default is a protocol-shaped **plain text** message (legal, and containing
        # no tool_use).
        self._send(200, json.dumps(behavior.get("response", DEFAULT_OK_MESSAGE),
                                   ensure_ascii=False).encode())

    def _behavior_for(self, idx):
        steps = STATE.script.get("steps") or []
        if idx < len(steps):
            return steps[idx]
        return STATE.script.get("default", {"kind": "ok"})


def main():
    global STATE
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--role", default="primary")
    ap.add_argument("--script", default=None, help="JSON file: {steps:[{kind:ok|redirect|incomplete|status,...}], default:{...}}")
    ap.add_argument("--ready-file", default=None)
    args = ap.parse_args()

    script = json.load(open(args.script)) if args.script else {}
    STATE = State(args.role, script)

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    if args.ready_file:
        with open(args.ready_file, "w") as f:
            f.write(f"READY {args.role} 127.0.0.1:{args.port}\n")
    print(f"READY {args.role} 127.0.0.1:{args.port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
