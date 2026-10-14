#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red/green arms for observe mode.

This mode, added during productization 2026-08-15, gets its entire value from "on day one
you can already see the tool surface change" — and carries its **entire risk** in this: a
request that should have been blocked now goes through. So this group doesn't test
"observe runs"; it tests four more specific things:

  ① a policy without mode must **still block** (the default sides with safety);
  ② under observe, policy-class decisions forward, but `would_block` must be booked —
     forward-without-record = never installed;
  ③ observe does **not** forward routing-class failures — for those requests we have no
     idea where to forward to;
  ④ a misspelled mode must be rejected at startup, **no falling back to the default** —
     a typo and "I chose observe" must not look the same.

Plus one **positive control**: under observe with an approved tool, `would_block` must
be False. Without it, an implementation that always writes `would_block` as true would
also turn everything above green.

    /usr/bin/python3 tests/observe_mode.py
"""
import http.client
import importlib.util
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
# Use the **current interpreter** by default, not a hardcoded /usr/bin/python3 — the
# latter doesn't exist on Linux, and it would make the version-matrix test forever test
# only one version.
PY3 = os.environ.get("HB_PY3", sys.executable)

CAP = "c" * 40                      # capability_path must be >= 32
DUMMY = "dummy-token-for-observe-arms"
MODEL = "claude-haiku-4-5-20251001"
MPATH = "/v1/messages?beta=true"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"{'✔' if ok else '✘'} {name}" + (f"   {detail}" if detail else ""))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Origin(BaseHTTPRequestHandler):
    """Minimal upstream: always answers with a legal non-streaming response."""

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        body = json.dumps({
            "type": "message", "role": "assistant", "model": MODEL,
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def read_tool_def():
    """This repo's bundled fake CLI Read definition + its canonical hash (reproducible, no
    vendor verbatim)."""
    spec = importlib.util.spec_from_file_location("insp", os.path.join(WRAPPER, "inspector.py"))
    insp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(insp)
    sys.path.insert(0, HERE)
    import fake_cli
    return fake_cli.READ_TOOL, insp.sha(insp.canon_tool(fake_cli.READ_TOOL))


def start_inspector(root, policy):
    ppath = os.path.join(root, "policy.json")
    with open(ppath, "w") as f:
        json.dump(policy, f)
    log_path = os.path.join(root, "inspector.jsonl")
    p = subprocess.Popen([PY3, os.path.join(WRAPPER, "inspector.py"), ppath, log_path],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, start_new_session=True)
    port, deadline = None, time.time() + 15
    while time.time() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        if line.startswith("READY"):
            port = int(line.split()[1].split(":")[1])
            break
    return p, port, log_path


def post(port, path, tools):
    body = json.dumps({"model": MODEL, "stream": False, "max_tokens": 16,
                       "tools": tools,
                       "messages": [{"role": "user", "content": "hi"}]}).encode()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    c.request("POST", path, body=body,
              headers={"Content-Type": "application/json",
                       "Authorization": f"Bearer {DUMMY}"})
    r = c.getresponse()
    r.read()
    c.close()
    return r.status


def events(log_path):
    with open(log_path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def last_request(log_path):
    reqs = [e for e in events(log_path) if e.get("event") == "request"]
    return reqs[-1] if reqs else None


def base_policy(op, mode=None, approved=None, surface=None):
    pol = {"attempt_id": "observe", "capability_path": CAP,
           "upstream_origin": f"http://127.0.0.1:{op}",
           "upstream_connect": {"scheme": "http", "host": "127.0.0.1", "port": op},
           "auth_mode": "loopback_dummy", "expected_auth_token": DUMMY,
           "messages_path": MPATH, "model": MODEL,
           "max_body_bytes": 2 * 1024 * 1024,
           "approved_tools": approved if approved is not None else {},
           "required_actions": []}
    if mode is not None:
        pol["mode"] = mode
    if surface is not None:
        pol["surface_path"] = surface
    return pol


def main():
    read_tool, read_hash = read_tool_def()
    op = free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", op), Origin)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    root = tempfile.mkdtemp(prefix="observe-arms-")
    good_path = f"/{CAP}{MPATH}"

    # ── ① no mode written: must still block ─────────────────────────────
    d = os.path.join(root, "default"); os.makedirs(d)
    p, port, log = start_inspector(d, base_policy(op))          # no mode key
    if port is None:
        print("ABORT: default-mode arm inspector did not start"); return 2
    st = post(port, good_path, [read_tool])
    ev = last_request(log) or {}
    p.kill()
    check("① policy without mode still blocks (default = enforce)",
          st == 403 and ev.get("decision") == "block",
          f"status={st} decision={ev.get('decision')} mode={ev.get('mode')}")

    # ── ② observe: policy-class decisions forward, but must be booked ───
    d = os.path.join(root, "observe"); os.makedirs(d)
    p, port, log = start_inspector(d, base_policy(op, mode="observe"))
    if port is None:
        print("ABORT: observe arm inspector did not start"); return 2
    st = post(port, good_path, [read_tool])
    ev = last_request(log) or {}
    p.kill()
    check("② observe forwards unapproved tools",
          st == 200 and ev.get("decision") == "forward",
          f"status={st} decision={ev.get('decision')}")
    check("② and would_block is booked (forward-without-record = never installed)",
          ev.get("would_block") is True and bool(ev.get("would_block_reason")),
          f"would_block={ev.get('would_block')} reason={str(ev.get('would_block_reason'))[:40]!r}")
    check("② tool-surface evidence still recorded",
          ev.get("tool_definition_hashes") == [read_hash],
          f"hashes={[h[:12] for h in (ev.get('tool_definition_hashes') or [])]}")

    # ── ②b tool-surface archive: observe writes, enforce doesn't, definition verbatim
    # stays out of the log ────────────────────────────────────────────────
    d = os.path.join(root, "surface"); os.makedirs(d)
    sp = os.path.join(d, "surface.jsonl")
    p, port, log = start_inspector(d, base_policy(op, mode="observe", surface=sp))
    if port is None:
        print("ABORT: archive arm inspector did not start"); return 2
    post(port, good_path, [read_tool])
    post(port, good_path, [read_tool])          # second time: must dedupe by hash
    p.kill()
    rows = [json.loads(l) for l in open(sp, encoding="utf-8") if l.strip()] \
        if os.path.exists(sp) else []
    check("②b observe wrote the definition to the tool-surface archive, deduped by hash",
          len(rows) == 1 and rows[0].get("definition") == read_tool
          and rows[0].get("definition_sha256") == read_hash,
          f"rows={len(rows)}")
    # 🔴 The promise: definition verbatim goes only into the archive, never into the event
    # log. Without this test that's just a sentence.
    raw_log = open(log, encoding="utf-8").read()
    marker = read_tool.get("description", "")
    check("②b definition verbatim did not leak into the event log",
          bool(marker) and marker not in raw_log,
          f"description length={len(marker)}")

    # 🔴 This assertion was **reversed** 2026-08-15, because real-traffic testing overturned
    #    the original design:
    #    enforce originally didn't write to the archive (log hygiene being the reason), so
    #    when enforce blocked a request, the user got only a hash and had **no way to know
    #    what was blocked**.
    #    A gate that can't say what it blocked gets switched off outright in real use.
    d = os.path.join(root, "surface-enforce"); os.makedirs(d)
    sp2 = os.path.join(d, "surface.jsonl")
    p, port, _log = start_inspector(d, base_policy(op, mode="enforce", surface=sp2))
    if port is None:
        print("ABORT: enforce archive arm did not start"); return 2
    st = post(port, good_path, [read_tool])
    p.kill()
    rows2 = [json.loads(l) for l in open(sp2, encoding="utf-8")] \
        if os.path.exists(sp2) else []
    check("②b enforce must archive the blocked definition (otherwise no diff possible)",
          st == 403 and len(rows2) == 1 and rows2[0].get("definition") == read_tool,
          f"status={st} rows={len(rows2)}")

    # ── ②c model: null — observe skips, enforce must reject at startup ──
    d = os.path.join(root, "modelnull"); os.makedirs(d)
    pol = base_policy(op, mode="observe"); pol["model"] = None
    p, port, log = start_inspector(d, pol)
    if port is None:
        print("ABORT: model:null observe arm did not start"); return 2
    st = post(port, good_path, [read_tool])
    ev = last_request(log) or {}
    p.kill()
    check("②c observe + model:null → no false model-mismatch signal, observed value recorded",
          st == 200 and ev.get("model") == MODEL
          and "model" not in str(ev.get("would_block_reason") or ""),
          f"status={st} observed_model={ev.get('model')}")

    d = os.path.join(root, "modelnull-enforce"); os.makedirs(d)
    pol = base_policy(op, mode="enforce"); pol["model"] = None
    p, port, _log = start_inspector(d, pol)
    rc = p.wait(timeout=15) if port is None else None
    if port is not None:
        p.kill()
    check("②c enforce + model:null → startup reject (undeclared cannot be enforced)",
          port is None and rc == 64, f"port={port} rc={rc}")

    # ── ③ observe doesn't forward routing-class failures ─────────────────
    d = os.path.join(root, "routing"); os.makedirs(d)
    p, port, log = start_inspector(d, base_policy(op, mode="observe"))
    if port is None:
        print("ABORT: routing arm inspector did not start"); return 2
    st = post(port, f"/{CAP}/v1/WRONG", [read_tool])
    ev = last_request(log) or {}
    p.kill()
    check("③ observe still blocks routing-class failures (no idea where to forward ≠ leniency)",
          st == 403 and ev.get("decision") == "block" and ev.get("would_block") is False,
          f"status={st} decision={ev.get('decision')} would_block={ev.get('would_block')}")

    # ── ④ misspelled mode: startup must reject, no fallback to default ───
    d = os.path.join(root, "typo"); os.makedirs(d)
    p, port, _log = start_inspector(d, base_policy(op, mode="observ"))
    rc = p.wait(timeout=15) if port is None else None
    if port is not None:
        p.kill()
    check("④ misspelled mode → startup reject (exit 64), no fallback to default",
          port is None and rc == 64, f"port={port} rc={rc}")

    # ── positive control: observe + approved tool → would_block must be False ──
    d = os.path.join(root, "control"); os.makedirs(d)
    p, port, log = start_inspector(
        d, base_policy(op, mode="observe", approved={"Read": read_hash}))
    if port is None:
        print("ABORT: positive-control arm inspector did not start"); return 2
    st = post(port, good_path, [read_tool])
    ev = last_request(log) or {}
    p.kill()
    check("positive control: observe + approved tool → would_block=False",
          st == 200 and ev.get("would_block") is False,
          f"status={st} would_block={ev.get('would_block')}")

    srv.shutdown()
    ok = sum(1 for _n, o, _d in RESULTS if o)
    print(f"\nOBSERVE_MODE {ok}/{len(RESULTS)}" + ("  ALL_OK" if ok == len(RESULTS) else "  BROKEN"))
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
