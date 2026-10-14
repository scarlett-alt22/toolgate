#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red/green for the TOCTOU drift criterion — the four red arms external review
A11 called for.

## Why this file exists

`pf-settings-toctou` / `pf-mcp-toctou` are, by construction, "swap out the one
designated object **after** preflight records the hashes", so "artifact disagrees
with plan" is the injected condition, not a defect. On 2026-08-09 the assertion
was flipped to "flagged means must drift" — **and that version was fail-open**:
A11 proved with in-memory counterexamples that CLI-only drift passed, drift
beyond the target passed, and missing/non-regular objects counted as successful
injection; worse, an early `return` skipped the wrapper-source check entirely.

🔴 **The actual artifacts were fine this whole round**; what was broken was the
grader letting bad samples pass. Those two facts must be kept separate:
"nothing blew up this time" is not "this gate works". So this file feeds bad
samples on purpose and demands they go red.

    /usr/bin/python3 tests/toctou_verifier_redgreen.py
"""
import hashlib
import importlib.util
import os
import shutil
import sys
import tempfile

TESTS = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "va", os.path.join(TESTS, "verify_acceptance.py"))
va = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(va)
except SystemExit:
    pass

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()


def build(root, drift=(), unusable=(), wrapper_drift=False):
    """Build one attempt's artifacts. drift/unusable name exactly which objects to break."""
    adir = os.path.join(root, "runs", "att")
    sandbox = root
    os.makedirs(adir, exist_ok=True)
    names = ("settings", "mcp", "policy", "sentinel", "cli")
    paths, hashes = {}, {}
    for n in names:
        p = os.path.join(root, n + ".txt")
        with open(p, "wb") as f:
            f.write(f"ORIGINAL-{n}\n".encode())
        paths[n] = p
        hashes[n] = sha_bytes(f"ORIGINAL-{n}\n".encode())
    src = {}
    for n in ("inspector.py", "finish.py"):
        p = os.path.join(sandbox, n)
        with open(p, "wb") as f:
            f.write(f"SRC-{n}\n".encode())
        src[n] = sha_bytes(f"SRC-{n}\n".encode())
    hashes["wrapper_sources"] = dict(src)

    for n in drift:                       # swap content after the fact = injection
        with open(paths[n], "wb") as f:
            f.write(f"TAMPERED-{n}\n".encode())
    for n in unusable:                    # swapped to symlink / deleted = does not count as successful injection
        os.remove(paths[n])
        if n != "__absent__":
            os.symlink("/dev/null", paths[n])
    if wrapper_drift:
        with open(os.path.join(sandbox, "inspector.py"), "wb") as f:
            f.write(b"SRC-inspector.py-TAMPERED\n")

    plan = {f"{n}_path": paths[n] for n in ("settings", "mcp", "policy", "sentinel")}
    plan["cli_realpath"] = paths["cli"]
    plan["hashes"] = hashes
    return {"dir": adir, "plan": plan, "terminal": {"hashes": hashes}}


def run(drift=(), unusable=(), wrapper_drift=False, declared=("settings",)):
    root = tempfile.mkdtemp(prefix="toctou-rg-")
    try:
        a = build(root, drift=drift, unusable=unusable, wrapper_drift=wrapper_drift)
        problems = []
        va.validate_plan_hashes(a, problems, "case", list(declared))
        return problems
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ── Green: the correct injection shape ─────────────────────────────────────────────────
check("green: only the declared object drifted → pass", not run(drift=("settings",)),
      "; ".join(run(drift=("settings",))))

# ── The four red arms A11 called for ─────────────────────────────────────────────────
p = run(drift=())
check("red-1: zero drift (injection didn't take) must go red", bool(p), p[0] if p else "🔴 was let through")

p = run(drift=("cli",))
check("red-2: wrong-object drift (only the CLI changed) must go red", bool(p), p[0] if p else "🔴 was let through")

p = run(drift=("settings", "policy"))
check("red-3: one extra drift beyond the target must go red", bool(p), p[0] if p else "🔴 was let through")

p = run(drift=("settings",), wrapper_drift=True)
check("red-4: wrapper source drift must go red (the old version's early return skipped this)",
      any("wrapper source" in x for x in p),
      "; ".join(p) if p else "🔴 was let through")

# ── Two more of the same family ──────────────────────────────────────────────────────
p = run(drift=(), unusable=("settings",))
check("red-5: target turned into a symlink doesn't count as a successful injection", bool(p), p[0] if p else "🔴 was let through")

p = run(drift=("settings",), declared=("nonexistent",))
check("red-6: declaring a nonexistent drift target must go red", bool(p), p[0] if p else "🔴 was let through")

w = max(len(n) for n, _, _ in RESULTS)
bad = sum(1 for _, ok, _ in RESULTS if not ok)
for n, ok, d in RESULTS:
    print(f"{'✔' if ok else '✘'} {n.ljust(w)}  {d[:90]}")
print()
print(f"TOCTOU_VERIFIER {len(RESULTS)-bad}/{len(RESULTS)}"
      f"{'  ALL_OK' if not bad else '  BROKEN='+str(bad)}")
sys.exit(1 if bad else 0)
