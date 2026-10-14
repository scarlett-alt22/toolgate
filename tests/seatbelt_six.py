#!/usr/bin/env python3
"""The six Seatbelt cells — A12's gate before production handoff; must run in a
plain local shell.

Codex can't run this: it sits inside an outer Seatbelt itself, and nested
sandbox_apply fails outright with EPERM(71). This script proves up front that
"this shell can really apply", and aborts entirely if it can't — never
misrecording "sandbox didn't engage" as "sandbox blocked it".

## Criterion shape (the most important part of this file)

Every cell has three arms, all mandatory:

  control  no-sandbox control — proves the operation **would have succeeded**.
           Without it, "read failed" might just mean the file doesn't exist,
           and "can't connect" might just mean nothing is listening.
  positive sandbox positive arm — what should be allowed is allowed.
           Without it, a profile with a syntax error that SIGABRTs the whole
           process would let every negative arm "pass". This isn't hypothetical:
           writing this profile really hit it twice (/bin/cat missing
           /usr/lib read permission → 134; /usr/bin/python3 is an xcrun shim).
  negative sandbox negative arm — what should be refused is refused, **and the
           failure must be permission-class**. rc != 0 doesn't count; it has to
           be EPERM/EACCES/sandbox-blocked.

A cell passes = control succeeds AND positive succeeds AND negative is refused
with a permission-class error.
"""

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

WRAPPER = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Default: test the production profile. Mutation tests point HB_SEATBELT_PROFILE at a weakened copy —
# a fully-green test suite that also goes green against a weakened profile proves itself, not the sandbox.
PROFILE = os.environ.get("HB_SEATBELT_PROFILE") or os.path.join(WRAPPER, "sandbox", "hb-read.sb")
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
# /usr/bin/python3 is an xcrun shim; dlopen of libxcrun fails inside the sandbox — use the real binary.
PY3 = "/Library/Developer/CommandLineTools/usr/bin/python3"

# Signature of permission-class failure. Only a hit here counts as "blocked by the sandbox".
PERM_MARKERS = (
    "operation not permitted",
    "permission denied",
    "sandbox blocked",
    "file system sandbox blocked",
    "errno 1",
    "errno 13",
)
# The DNS cell is **indirect evidence**, flagged separately, not mixed into the group above.
# The kernel never returns EPERM directly for getaddrinfo: once deny default kills mach-lookup,
# the resolver can't reach mDNSResponder, so it reports gaierror. That looks identical to "network was down anyway" —
# so this cell's persuasiveness **depends entirely on the control arm** (resolution must succeed without the sandbox).
INDIRECT_MARKERS = ("gaierror", "nodename nor servname", "name or service not known")
# Signature of sandbox-exec failing to apply itself — that's not "blocked", that's "never installed".
APPLY_FAIL = "sandbox_apply"


def is_perm_failure(rc, out, allow_indirect=False):
    low = (out or "").lower()
    if APPLY_FAIL in low:
        return False, "sandbox_apply_failed"
    if rc == 0:
        return False, "succeeded"
    for m in PERM_MARKERS:
        if m in low:
            return True, m
    if allow_indirect:
        for m in INDIRECT_MARKERS:
            if m in low:
                return True, f"indirect:{m}"
    return False, f"non_permission_failure(rc={rc})"


def run(argv, timeout=60, env=None):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def run_control(argv, tries=3):
    """Control-arm only: retries are allowed here.

    The control arm must prove "this operation would have succeeded"; one network
    jitter turning it into rc=1 voids the whole cell (that's how G5.ip died in round one).
    🔴 Positive and negative arms **never retry** — those need this round's real
    behavior; retrying is a backdoor for yourself.
    """
    last = (1, "")
    for _ in range(tries):
        last = run(argv)
        if last[0] == 0:
            return last
    return last


def sb(params, argv, timeout=60):
    """Run inside the sandbox. params are -D key-values."""
    cmd = [SANDBOX_EXEC, "-f", PROFILE]
    for k, v in params.items():
        cmd += ["-D", f"{k}={v}"]
    return run(cmd + argv, timeout=timeout)


# ── Self-proof: this shell can really apply Seatbelt ───────────────────────────────
def assert_can_sandbox():
    rc, out = run([SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"])
    if rc != 0:
        print(json.dumps({
            "abort": "this shell cannot apply seatbelt",
            "rc": rc, "out": out.strip(),
            "meaning": "an outer sandbox already exists (Codex runs this way). Running the six cells in such a shell,"
                       "all negative arms would 'pass' because the process can't start at all — that's fake evidence.",
        }, ensure_ascii=False, indent=2))
        sys.exit(2)
    return {"nested_apply_rc": rc}


# ── Two loopback listeners: one as this round's inspector, one as "another loopback service" ──
class Listener:
    def __init__(self, tag):
        self.tag = tag
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stop:
            try:
                c, _ = self.sock.accept()
                c.sendall(b"OK-" + self.tag.encode())
                c.close()
            except OSError:
                break

    def close(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


# timeout set to 15s: outbound goes through Clash TUN, the public handshake leaves the country, 5s flakes.
# ⚠️ Timeout and EPERM must stay distinguishable — refusal inside the sandbox is an **immediate** PermissionError,
#    failure outside the sandbox is a timeout. The classifier only recognizes the former, so a timeout is never misrecorded as "blocked".
NET_PROBE = r"""
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
s = socket.socket(); s.settimeout(15)
try:
    s.connect((host, port)); print("CONNECTED", s.recv(32)); sys.exit(0)
except Exception as e:
    print(f"BLOCKED {type(e).__name__}: {e}"); sys.exit(1)
"""

DNS_PROBE = r"""
import socket, sys
try:
    print("RESOLVED", socket.gethostbyname(sys.argv[1])); sys.exit(0)
except Exception as e:
    print(f"BLOCKED {type(e).__name__}: {e}"); sys.exit(1)
"""

WRITE_PROBE = r"""
import sys
try:
    with open(sys.argv[1], "w") as f:
        f.write("seatbelt-write-probe")
    print("WROTE", sys.argv[1]); sys.exit(0)
except Exception as e:
    print(f"BLOCKED {type(e).__name__}: {e}"); sys.exit(1)
"""


def main():
    stamp = time.strftime("%Y%m%dT%H%M%S")
    adir = os.path.join(WRAPPER, "runs", "seatbelt", stamp)
    os.makedirs(adir, exist_ok=True)

    meta = {"stamp": stamp, "wrapper": WRAPPER}
    meta["shell_check"] = assert_can_sandbox()
    with open(PROFILE, "rb") as f:
        pbytes = f.read()
    meta["profile_path"] = PROFILE
    meta["profile_sha256"] = hashlib.sha256(pbytes).hexdigest()
    meta["macos"] = run(["/usr/bin/sw_vers", "-productVersion"])[1].strip()

    # Disposable fixture scenery, all built under the attempt directory; touches no live files.
    root = os.path.join(adir, "fixture")
    read_root = os.path.join(root, "input")
    # 🔴 outside must be **outside** READ_ROOT(=root). The first version built it as root/outside,
    # so the "out-of-bounds file" never went out of bounds, and G1/G2's negative arms read it fine — that was the fixture's fault, not the profile's,
    # yet it looked exactly like "the sandbox didn't block". This comment stays because the next person will easily write it the first way again.
    outside = os.path.join(adir, "outside")
    home_dir = os.path.join(root, "home")
    cache_dir = os.path.join(home_dir, "Library", "Caches")
    tmp_dir = os.path.join(root, "tmp")
    for d in (read_root, outside, home_dir, cache_dir, tmp_dir):
        os.makedirs(d, exist_ok=True)
    sentinel = os.path.join(read_root, "sentinel.txt")
    secret = os.path.join(outside, "secret.txt")
    with open(sentinel, "w") as f:
        f.write("SENTINEL-OK\n")
    with open(secret, "w") as f:
        f.write("SHOULD-NOT-BE-READABLE\n")

    probe_dir = os.path.join(root, "probes")
    os.makedirs(probe_dir, exist_ok=True)
    probes = {}
    for name, src in (("net.py", NET_PROBE), ("dns.py", DNS_PROBE), ("write.py", WRITE_PROBE)):
        p = os.path.join(probe_dir, name)
        with open(p, "w") as f:
            f.write(src)
        probes[name] = p

    allowed = Listener("ALLOWED")
    other = Listener("OTHER")

    cli_root = "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code"
    workspace = os.path.join(root, "workspace")
    os.makedirs(workspace, exist_ok=True)
    snapshot_dir = os.path.join(root, "snapshot")
    os.makedirs(snapshot_dir, exist_ok=True)
    params = {
        "INSPECTOR_PORT": str(allowed.port),
        # the probe script needs to read it too, so READ_ROOT gets the fixture root
        "READ_ROOT": root,
        "CLI_ROOT": cli_root,
        "HOME_DIR": home_dir,
        "ATTEMPT_TMP": tmp_dir,
        "WORKSPACE": workspace,
        "SNAPSHOT_DIR": snapshot_dir,
        "CLI_RUNTIME_DIR": f"/private/tmp/claude-{os.getuid()}",
    }
    meta["params"] = dict(params)
    meta["ports"] = {"inspector": allowed.port, "other_loopback": other.port}

    cells = []

    def cell(cid, desc, control, positive, negative, allow_indirect=False):
        """control/positive/negative are all thunk results of (rc, out) triples."""
        c_rc, c_out = control
        p_rc, p_out = positive
        n_rc, n_out = negative
        n_ok, n_why = is_perm_failure(n_rc, n_out, allow_indirect=allow_indirect)
        ok = (c_rc == 0) and (p_rc == 0) and n_ok
        cells.append({
            "cell": cid, "desc": desc, "pass": ok,
            "control": {"rc": c_rc, "out": c_out.strip()[:400], "expect": "success"},
            "positive": {"rc": p_rc, "out": p_out.strip()[:400], "expect": "success"},
            "negative": {"rc": n_rc, "out": n_out.strip()[:400],
                         "expect": "permission-class failure", "classified": n_why},
        })
        print(f"[{'PASS' if ok else 'FAIL'}] {cid}  {desc}")
        if not ok:
            print(f"       control rc={c_rc} positive rc={p_rc} negative={n_why}")

    # ── Cell 1: designated input readable / Cell 2: out-of-bounds unreadable ────────────────────────────
    # These two cells share one arm set: positive reads the sentinel, negative reads the out-of-bounds file, control proves the out-of-bounds file was readable.
    cell("G1", "designated input readable",
         control=run(["/bin/cat", sentinel]),
         positive=sb(params, ["/bin/cat", sentinel]),
         # G1's negative arm is G2 — but each cell records independently, so a dead cell doesn't hide which half died
         negative=sb(params, ["/bin/cat", secret]))

    cell("G2", "out-of-bounds path unreadable",
         control=run(["/bin/cat", secret]),
         positive=sb(params, ["/bin/cat", sentinel]),
         negative=sb(params, ["/bin/cat", secret]))

    # ── Cell 3: input/HOME/tmp/cache all unwritable ──────────────────────────────
    for tag, target in (("input", os.path.join(read_root, ".wprobe")),
                        ("home", os.path.join(home_dir, ".wprobe")),
                        ("tmp", os.path.join(tmp_dir, ".wprobe")),
                        ("cache", os.path.join(cache_dir, ".wprobe"))):
        ctl = run([PY3, probes["write.py"], target])
        if os.path.exists(target):
            os.remove(target)  # the control arm really wrote; wipe it, don't leave it in the artifacts
        cell(f"G3.{tag}", f"{tag} not writable",
             control=ctl,
             positive=sb(params, ["/bin/cat", sentinel]),
             negative=sb(params, [PY3, probes["write.py"], target]))

    # ── Cell 4: only this round's inspector port is reachable ──────────────────────────────────
    cell("G4", "only this round's inspector port reachable, other loopback port unreachable",
         control=run([PY3, probes["net.py"], "127.0.0.1", str(other.port)]),
         positive=sb(params, [PY3, probes["net.py"], "127.0.0.1", str(allowed.port)]),
         negative=sb(params, [PY3, probes["net.py"], "127.0.0.1", str(other.port)]))

    # ── Cell 5: public IP / DNS unreachable ──────────────────────────────────────
    # Control target uses 8.8.8.8:53: this machine's outbound goes through Clash TUN, the handshake leaves the country,
    # the 443 one flaked once in round one (control rc=1 → whole cell voided).
    # ⚠️ Just picking a stable control target; not touching any Clash config.
    cell("G5.ip", "public IP unreachable",
         control=run_control([PY3, probes["net.py"], "8.8.8.8", "53"]),
         positive=sb(params, [PY3, probes["net.py"], "127.0.0.1", str(allowed.port)]),
         negative=sb(params, [PY3, probes["net.py"], "8.8.8.8", "53"]))

    cell("G5.dns", "DNS resolution unreachable",
         control=run([PY3, probes["dns.py"], "api.anthropic.com"]),
         positive=sb(params, [PY3, probes["net.py"], "127.0.0.1", str(allowed.port)]),
         negative=sb(params, [PY3, probes["dns.py"], "api.anthropic.com"]),
         allow_indirect=True)

    allowed.close()
    other.close()

    summary = {
        "meta": meta,
        "cells": cells,
        "total": len(cells),
        "passed": sum(1 for c in cells if c["pass"]),
        "note": "G6 (real CLI launched inside the sandbox) is not in this script, see seatbelt_g6.sh — "
                "it needs the real Claude Code, with different cost and prerequisites from these five cells.",
    }
    summary["verdict"] = "SEATBELT_1_5_PASS" if summary["passed"] == summary["total"] else "SEATBELT_FAIL"

    out = os.path.join(adir, "summary.json")
    with open(out, "w") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"\n{summary['passed']}/{summary['total']}  {summary['verdict']}")
    print(f"artifact: {out}")
    print(f"profile sha256: {meta['profile_sha256']}")
    return 0 if summary["verdict"] == "SEATBELT_1_5_PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
