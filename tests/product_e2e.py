#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""toolgate's end-to-end: init → watch → diff → approve → enforce.

This group does not test the gate's criteria (that's the 104-case suite's job); it tests
the **product promise**:

  ① `watch` never blocks, but records the tool definitions;
  ② `diff` can say "this is new";
  ③ after `approve`, `enforce` forwards the same definition;
  ④ 🔴 **one extra sentence in the description and enforce blocks** — name unchanged,
     schema unchanged, only the description changed. This cell is what the whole product
     is selling; if it goes red there is nothing else to say;
  ⑤ after a block, `diff` must give a **word-by-word diff**, not "hash mismatch".
     Same data — one is a rejection, the other is intelligence; the product's value is
     entirely in the latter.

    /usr/bin/python3 tests/product_e2e.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PY = sys.executable

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print(("✔ " if ok else "✘ ") + name + (("   " + detail) if detail else ""))


def _ev(t, d):
    return ("event: %s\ndata: %s\n\n" % (t, json.dumps(d))).encode()


SSE_BODY = b"".join([
    _ev("message_start", {"type": "message_start", "message": {
        "id": "m", "type": "message", "role": "assistant", "model": "m",
        "content": [], "stop_reason": None,
        "usage": {"input_tokens": 1, "output_tokens": 1}}}),
    _ev("content_block_start", {"type": "content_block_start", "index": 0,
                                "content_block": {"type": "text", "text": ""}}),
    _ev("content_block_delta", {"type": "content_block_delta", "index": 0,
                                "delta": {"type": "text_delta", "text": "ok"}}),
    _ev("content_block_stop", {"type": "content_block_stop", "index": 0}),
    _ev("message_delta", {"type": "message_delta",
                          "delta": {"stop_reason": "end_turn"}}),
    _ev("message_stop", {"type": "message_stop"}),
])


class Origin(BaseHTTPRequestHandler):
    """Reply SSE when the request has stream=true. Real agents default to streaming —
    testing only non-streaming means never having tested real usage."""

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        try:
            want_stream = bool(json.loads(raw.decode("utf-8")).get("stream"))
        except Exception:
            want_stream = False
        if want_stream:
            body, ctype = SSE_BODY, "text/event-stream"
        else:
            body = json.dumps({"type": "message", "role": "assistant",
                               "model": "claude-haiku-4-5-20251001",
                               "content": [{"type": "text", "text": "ok"}],
                               "stop_reason": "end_turn"}).encode()
            ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def tg(home, *args):
    """Run toolgate once; return (rc, combined output)."""
    env = dict(os.environ)
    env["TOOLGATE_HOME"] = home
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    p = subprocess.run([PY, "-m", "toolgate"] + list(args), cwd=REPO, env=env,
                       capture_output=True, text=True, timeout=120)
    return p.returncode, p.stdout + p.stderr


def main():
    op = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", op), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    home = os.path.join(tempfile.mkdtemp(prefix="toolgate-e2e-"), ".toolgate")
    agent = os.path.join(HERE, "demo_agent.py")

    rc, out = tg(home, "init", "--upstream", "http://127.0.0.1:{}".format(op))
    check("init writes out the config", rc == 0 and os.path.exists(os.path.join(home, "config.json")), out.strip()[:60])

    # ① watch: never blocks, but records
    rc, out = tg(home, "watch", "--", PY, agent)
    surface = os.path.join(home, "surface.jsonl")
    rows = [json.loads(l) for l in open(surface, encoding="utf-8")] if os.path.exists(surface) else []
    check("① watch never blocked (the wrapped command got 200)", "upstream replied 200" in out, "")
    check("① tool definitions were recorded into the tool-surface archive", len(rows) == 1 and rows[0]["name"] == "Read",
          "rows={}".format(len(rows)))

    # ② diff recognizes this as new
    rc, out = tg(home, "diff")
    check("② diff reports 'new'", "NEW" in out and "Read" in out, out.strip()[:80])

    # ③ after approve, enforce forwards the same one
    rc, out = tg(home, "approve")
    approved = json.load(open(os.path.join(home, "approved.json"), encoding="utf-8"))
    names = {e["name"] for e in approved.get("tools", [])}
    check("③ approve writes into the approval store (v2 is a (name,hash) set), and also records the observed model",
          "Read" in names
          and json.load(open(os.path.join(home, "config.json"), encoding="utf-8")).get("model"),
          "names={}".format(sorted(names)))
    rc, out = tg(home, "enforce", "--", PY, agent)
    check("③ enforce forwards the approved definition", "upstream replied 200" in out, "")

    # ④ description changed only — name and schema untouched
    rc, out = tg(home, "enforce", "--", PY, agent, "--mutate")
    # 🔴 The assertion is tightened: not just "it got blocked" but **blocked with the
    #    right category** — same name, changed definition must report contract_drift,
    #    not tool_added. To the user these are two completely different things.
    check("④ 🔴 one sentence added to the description only → enforce blocks, and judges contract_drift (not tool_added)",
          "blocked 403" in out and "contract_drift" in out and "tool_added" not in out,
          out.strip().splitlines()[0] if out.strip() else "")

    # ⑤ after a block, give intelligence, not a hash
    rc, out = tg(home, "watch", "--", PY, agent, "--mutate")
    rc, out = tg(home, "diff")
    ok = ("DRIFT" in out
          and "registered shell tool" in out          # the added sentence is visible in the word diff
          and "+" in out)
    check("⑤ diff gives a word-by-word diff (the added sentence is visible), not just a hash mismatch", ok,
          "" if ok else out.strip()[-200:])

    # ── ⑥ OpenAI Chat Completions walks the same product flow ──
    home2 = os.path.join(tempfile.mkdtemp(prefix="toolgate-e2e-oai-"), ".toolgate")
    rc, out = tg(home2, "init", "--format", "openai-chat",
                 "--upstream", "http://127.0.0.1:{}".format(op))
    rc, out = tg(home2, "watch", "--", PY, agent, "--openai")
    rows2 = [json.loads(l) for l in open(os.path.join(home2, "surface.jsonl"), encoding="utf-8")] \
        if os.path.exists(os.path.join(home2, "surface.jsonl")) else []
    check("⑥ OpenAI shape also walks the product flow (watch records the definition)",
          "upstream replied 200" in out and len(rows2) == 1 and rows2[0]["name"] == "Read",
          "rows={}".format(len(rows2)))
    # 🔴 Same hash across formats — the entire basis of "approve once, honored everywhere"
    same = rows and rows2 and rows[0]["definition_sha256"] == rows2[0]["definition_sha256"]
    check("⑥ 🔴 Anthropic and OpenAI paths compute the same definition hash", bool(same),
          "" if same else "{} vs {}".format(
              rows[0]["definition_sha256"][:12] if rows else "-",
              rows2[0]["definition_sha256"][:12] if rows2 else "-"))
    rc, out = tg(home2, "approve")
    rc, out = tg(home2, "enforce", "--", PY, agent, "--openai", "--mutate")
    check("⑥ a description change under the OpenAI shape is likewise blocked by enforce",
          "blocked 403" in out, "")

    # ── ⑦ Streaming: real agents default to streaming; untested means untested in real use ──
    home3 = os.path.join(tempfile.mkdtemp(prefix="toolgate-e2e-sse-"), ".toolgate")
    rc, out = tg(home3, "init", "--upstream", "http://127.0.0.1:{}".format(op))
    rc, out = tg(home3, "watch", "--", PY, agent, "--stream")
    sp3 = os.path.join(home3, "surface.jsonl")
    rows3 = [json.loads(l) for l in open(sp3, encoding="utf-8")] if os.path.exists(sp3) else []
    check("⑦ streaming passes the gate, keeps content-type, tool surface still recorded",
          "upstream replied 200" in out and "text/event-stream" in out and len(rows3) == 1,
          (out.strip().splitlines() or [""])[0])

    # ── ⑧ The approved manifest only grows: after approving the new variant, the old
    #       variant must still forward ──
    # 🔴 This is the **real** evidence for "only grows". Two entries in approved.json
    #    is not enough — what would actually hurt is: after the new variant is approved,
    #    the old variant gets blocked on its next request.
    home4 = os.path.join(tempfile.mkdtemp(prefix="toolgate-e2e-union-"), ".toolgate")
    tg(home4, "init", "--upstream", "http://127.0.0.1:{}".format(op))
    tg(home4, "watch", "--", PY, agent)                 # variant one
    tg(home4, "approve")
    rc, out = tg(home4, "watch", "--", PY, agent, "--mutate")   # variant two
    drift_seen = "DRIFT" in out
    tg(home4, "approve")
    doc = json.load(open(os.path.join(home4, "approved.json"), encoding="utf-8"))
    n_read = sum(1 for e in doc.get("tools", []) if e["name"] == "Read")
    rc_old, out_old = tg(home4, "enforce", "--", PY, agent)          # old variant
    rc_new, out_new = tg(home4, "enforce", "--", PY, agent, "--mutate")  # new variant
    check("⑧ both same-named variants are in the approval list, and **both still forward** (grows only, never shrinks)",
          drift_seen and n_read == 2
          and "upstream replied 200" in out_old
          and "upstream replied 200" in out_new,
          "drift_seen={} n_read={}".format(drift_seen, n_read))

    srv.shutdown()
    good = sum(1 for r in RESULTS if r)
    print("\nPRODUCT_E2E {}/{}".format(good, len(RESULTS))
          + ("  ALL_OK" if good == len(RESULTS) else "  BROKEN"))
    return 0 if good == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
