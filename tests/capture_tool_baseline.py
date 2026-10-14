#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture the real CLI's **full canonical tool definitions** and build an independent baseline.

Item 3 from external review A7. Its ruling: writing the hash observed in the field directly
into the profile's `approved_tools` **counts as TOFU / tuning the gate to match the field**
— it only proves "next time looks like this time", not "this definition should be approved".
So the baseline must:
  · be captured in an isolated environment (loopback only, non-essential traffic off,
    the dummy branch never touches the keychain);
  · pin CLI version/SHA + model + settings + HOME fixture, at least 3 reps per arm;
  · store the **full definitions** for a human to read field-by-field, not just one hash;
  · 🔴 **this program modifies no profile.** Promotion to an approved value is a separate
    step that only happens after a human has looked.

Run manually: /usr/bin/python3 tests/capture_tool_baseline.py [--reps 3]
Artifact: tests/baselines/read-definition-<branch>.json
"""
import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
BASELINES = os.path.join(TESTS, "baselines")
sys.path.insert(0, TESTS)
import lib  # noqa: E402
import run_acceptance as RA  # noqa: E402

REAL_CLI = "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
# The "pass-through hash" that lets requests reach the capture point — not an approval
# value; see the comment in one_run.
CAPTURE_ENABLER_SHA256 = "985a6ada4068dd60444e3bd96a9d888f5a30d697704a7efe900c5658362875f2"
CAPTURED = []


class Capture(BaseHTTPRequestHandler):
    """Trusted capture point: keep the tools array only, **no headers, no messages**."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            doc = json.loads(raw.decode("utf-8"))
            CAPTURED.append(doc.get("tools"))
        except Exception:
            CAPTURED.append(None)
        body = b'{"type":"error","error":{"type":"capture_only"}}'
        self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def canonical_loose(obj):
    """Legacy-schema compat field; after the spec:78 fix it should match the gate's canonical bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_gate(obj):
    """🔴 **Authoritative algorithm**: use inspector's `canon_tool` directly; the gate compares with it.

    ★2026-08-09 A8: the previous version of this program only computed the
    `ensure_ascii=False` hash, and `canonical_sha256_inspector` was **patched into the
    JSON by hand afterwards** — so one rerun would drop it, even though it's the one that
    matters. Now import from inspector itself and **do not reimplement the algorithm
    here**: reimplementing it would create a second source of truth.
    """
    sys.path.insert(0, WRAPPER)
    import inspector  # noqa: PLC0415
    return inspector.canon_tool(obj)


def one_run(port, root, rep):
    ws = os.path.join(root, f"ws{rep}"); os.makedirs(ws, 0o700)
    home = os.path.join(root, f"home{rep}"); os.makedirs(home, 0o700)
    inp = os.path.join(root, f"in{rep}"); os.makedirs(inp, 0o700)
    open(os.path.join(inp, "sentinel.txt"), "w").write("S\n")

    ver = subprocess.run([REAL_CLI, "--version"], capture_output=True, text=True).stdout.strip()
    prof = RA.base_profile(ws, home, f"http://127.0.0.1:{port}", inp)
    prof.update(cli_realpath=REAL_CLI, cli_sha256=lib.sha256_file(REAL_CLI),
                cli_version=ver, auth_mode="loopback_dummy", timeout_seconds=60)
    # ⚠️ Setting approved_tools to the currently observed value here is **purely so the
    # request reaches the capture point**: without this, the upper gate would block it
    # before forwarding (which would mean the gate is right, but there'd be nothing to
    # capture).
    # 🔴 This is **not** approval. The baseline this program produces ships with
    # `review_status: UNREVIEWED`, and it modifies no profile — promotion to an approved
    # value is a separate step that only happens after a human has reviewed it field by
    # field.
    if CAPTURE_ENABLER_SHA256:
        prof["approved_tools"] = [{"name": "Read",
                                   "definition_sha256": CAPTURE_ENABLER_SHA256}]
    pp = os.path.join(root, f"p{rep}.json")
    json.dump(prof, open(pp, "w"), ensure_ascii=False, indent=1)
    mp = os.path.join(root, f"m{rep}.json")
    json.dump({"read-shadow-test": {"path": pp, "sha256": lib.sha256_file(pp)}},
              open(mp, "w"), indent=1)
    sb = os.path.join(root, f"sb{rep}")
    lib.build_sandbox(sb, mp)

    env = {k: v for k, v in os.environ.items()
           if k not in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                        "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR")}
    # 🔴 Disable non-essential traffic: external review noted telemetry / feature-flag
    # evaluation may be on by default, and feature flags are one candidate explanation
    # for "why the definitions changed". Capture must rule that out.
    env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    before = len(CAPTURED)
    subprocess.run(["/bin/zsh", os.path.join(sb, "hb-run.sh"), "read-shadow-test", "hi"],
                   cwd=sb, env=env, capture_output=True, text=True, timeout=180)
    # ★A8: per-rep evidence must go into the record. "21 unique" used to live only in
    # a sentence someone typed; the file only had `reps: 3` — which asks the reader to
    # trust that the counting was right.
    seen = [t for t in CAPTURED[before:]]
    reads = [t for ts in seen if ts for t in ts
             if isinstance(t, dict) and t.get("name") == "Read"]
    # Structural fact about the dummy branch: no Library/Keychains should grow inside the
    # dedicated home. This one is **measured** (checked after the run), not asserted.
    kc = os.path.join(home, "Library", "Keychains")
    return {
        "rep": rep,
        "requests_at_capture_point": len(seen),
        "read_definitions": len(reads),
        "gate_hashes": sorted({hashlib.sha256(canonical_gate(r)).hexdigest() for r in reads}),
        "loose_hashes": sorted({hashlib.sha256(canonical_loose(r)).hexdigest() for r in reads}),
        "dedicated_home_keychains_absent": not os.path.lexists(kc),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=3)
    args = ap.parse_args()
    os.makedirs(BASELINES, exist_ok=True)

    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Capture)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    # ⚠️ Must realpath: `mkdtemp` on macOS returns /var/folders/…, which is
    # a symlink to /private/var/…. Preflight requires workspace/home realpaths to match
    # the declaration byte-for-byte — that gate is right; the fixture must be normalized
    # first.
    root = os.path.realpath(tempfile.mkdtemp(prefix="tool-baseline-"))

    per_rep = []
    try:
        for rep in range(args.reps):
            per_rep.append(one_run(port, root, rep))
    finally:
        srv.shutdown()
        shutil.rmtree(root, ignore_errors=True)

    tools_sets = [t for t in CAPTURED if t]
    if not tools_sets:
        print("CAPTURE_FAIL no tools array captured at all"); return 1

    reads = []
    for ts in tools_sets:
        for t in ts:
            if isinstance(t, dict) and t.get("name") == "Read":
                reads.append(t)
    if not reads:
        print("CAPTURE_FAIL captured requests but no Read definition inside"); return 1

    gate_hashes = {hashlib.sha256(canonical_gate(r)).hexdigest() for r in reads}
    loose_hashes = {hashlib.sha256(canonical_loose(r)).hexdigest() for r in reads}
    print(f"captured {len(tools_sets)} requests, including {len(reads)} Read definitions")
    print(f"gate canonical hash deduped: {len(gate_hashes)}")
    for h in sorted(gate_hashes):
        print("   ", h)
    if len(gate_hashes) != 1:
        print("🔴 hash unstable within one branch -- baseline invalid, find out why it changes first")
        return 1

    out = os.path.join(BASELINES, "read-definition-loopback_dummy.json")
    doc = {
        "schema_version": 2,
        "branch": "loopback_dummy",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        # 🔴 The file declares where it is supposed to live. A8's "Dummy Read baseline"
        # caught the program writing to `tests/baselines` while the deliverable was in
        # `baselines` — two same-named files, and which one is the original depended on
        # someone remembering. Write it in; a rerun will line up.
        "baseline_path": os.path.relpath(out, WRAPPER),
        "reps_requested": args.reps,
        "reps_completed": len(per_rep),
        "per_rep": per_rep,                     # ★Per-rep counts and hashes, not just a total
        "cli_realpath": REAL_CLI,
        "cli_sha256": lib.sha256_file(REAL_CLI),
        "cli_version": subprocess.run([REAL_CLI, "--version"], capture_output=True,
                                      text=True).stdout.strip(),
        "capture_harness_sha256": lib.sha256_file(os.path.abspath(__file__)),
        "inspector_sha256": lib.sha256_file(os.path.join(WRAPPER, "inspector.py")),

        # ── Authoritative hash: the algorithm the gate actually compares with ──
        "canonical_sha256_inspector": sorted(gate_hashes)[0],
        "canonical_sha256_ensure_ascii_false": sorted(loose_hashes)[0],
        "canonical_note": ("🔴 canonical_sha256_inspector is authoritative -- it calls "
                           "inspector.canon_tool directly (UTF-8, ensure_ascii=false), "
                           "the single algorithm shared by spec:78 and the upper gate. "
                           "canonical_sha256_ensure_ascii_false is the old-schema compat field, "
                           "it should currently equal the authoritative value; the verifier also recomputes it independently from the definition."),

        # ── Measured vs unmeasurable, written separately ──
        "measured": {
            "capture_point_requests": sum(r["requests_at_capture_point"] for r in per_rep),
            "read_definitions_total": len(reads),
            "gate_hash_unique_count": len(gate_hashes),
            "dedicated_home_keychains_absent_every_rep":
                all(r["dedicated_home_keychains_absent"] for r in per_rep),
        },
        "unmeasured": {
            "external_network_requests":
                "unmeasured -- the previous version hardcoded 0 here. All this program can see is the **capture-point**"
                "request count; it cannot see whether the process sent anything elsewhere. Proving that needs OS-level egress auditing, unavailable under SIP.",
            "keychain_touched":
                "unmeasured -- the previous version hardcoded false. All that can be measured is that no "
                "Library/Keychains grew inside the dedicated home (already in measured); that is necessary but not sufficient: "
                "the CLI going through security(1) or Security.framework never touches that directory.",
        },
        "nonessential_traffic_disabled": True,   # True, because it's an env var we set ourselves
        "definition": reads[0],
        "fields": sorted(reads[0]) if isinstance(reads[0], dict) else None,
        "review_status": "CANDIDATE",
        "review_note": ("not yet human-reviewed field by field (name/description/input_schema). "
                        "🔴 current state is TOFU: profiles/read-shadow-loopback.json's "
                        "approved_tools already uses this hash -- that only proves 'next time looks like this time', "
                        "not 'this definition should be approved'. Until a human has reviewed it, that profile's pinned value "
                        "should likewise be read as candidate, not approved. "
                        "promotion = after a human reviews it field by field, change review_status to REVIEWED and sign with a date, "
                        "a step independent of this program; **this program modifies no profile**."),
    }
    with open(out, "w") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print(f"\nbaseline written: {out}")
    print("🔴 this program modified **no** profile -- promotion to an approved value is a separate step after a human reviews it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
