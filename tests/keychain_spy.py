#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Access-level Keychains spy — **synthetic fixture version** (rewritten 2026-08-09 per
external review A8 §4).

## What it actually proves (this paragraph is the conclusion; don't write a stronger one
elsewhere)

> **Inside this test interpreter process**, directly calling
> `preflight.assert_no_keychain_bridge` and dummy branch
> `preflight.verify_keychain_bridge` never hits a WATCH prefix via any of the
> monkeypatched Python calls (`os.lstat/stat/open/readlink/listdir/symlink`,
> `builtins.open`) with an absolute string path.

**That's all.** It is **not** proof that "the wrapper never touched the keychain". Not
covered, at minimum:
  · preflight's full `main()` (only two functions are called here, not the whole path);
  · the `hb-run.sh` shell, `inspector.py`, `finish.py`;
  · CLI child processes, `security(1)`, any Security.framework call;
  · other Python call surfaces (`os.scandir`/`pathlib`/`shutil`/`subprocess`…);
  · access via already-open fds, relative paths, or `..` backtracks.
Real end-to-end proof needs OS-level auditing (dtrace/ES), unavailable under SIP.
**The 08-08 version's file header said "the wrapper itself didn't touch it" — stronger
than what it can prove.**

## Why the whole tree is synthetic

★A8 §4 second half: the old version pointed WATCH at `~/Library/Keychains`, while the
sensitivity arm **really** `os.lstat`ed it and the real control arm probed the user's
keychain metadata — so the test **itself violated the "don't touch the keychain this
round" red line** and could only run at chosen times. Now `pwd.getpwuid` is stubbed into
a fixture tree (same trick as `bridge_redgreen.py`), and WATCH lands inside the fixture,
so it can run any time and never touches the operator's live keychain.

Manual run: /usr/bin/python3 tests/keychain_spy.py
"""
import builtins
import json
import os
import shutil
import sys
import tempfile
import types

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
sys.path.insert(0, WRAPPER)

# ── synthetic fixture tree: not one byte here belongs to a real keychain ────
# ⚠️ must realpath: on macOS `/var` is a symlink to `/private/var`,
#    and preflight byte-compares the home from passwd against its realpath — without
#    realpathing, the real control arm would be rejected **before touching anything**,
#    making "zero hits" fake cleanliness.
ROOT = os.path.realpath(tempfile.mkdtemp(prefix="kc-spy-"))
FIXTURE_HOME = os.path.join(ROOT, "realhome")
WATCH = os.path.join(FIXTURE_HOME, "Library", "Keychains")
os.makedirs(WATCH, 0o755)
with open(os.path.join(WATCH, "login.keychain-db"), "wb") as _f:
    _f.write(b"FIXTURE-NOT-A-REAL-KEYCHAIN-v1\n")

REAL_HOME_OF_THIS_MACHINE = os.path.expanduser("~")
TOUCHES = []
REAL_TOUCHES = []          # hits against the **real** keychain — must stay 0 forever
REAL_WATCH = os.path.join(REAL_HOME_OF_THIS_MACHINE, "Library", "Keychains")


def _under(p, root):
    return isinstance(p, str) and (p == root or p.startswith(root + os.sep))


def _watch(fn, label):
    def wrapper(path, *a, **kw):
        try:
            p = os.fspath(path)
        except Exception:
            p = None
        if _under(p, WATCH):
            TOUCHES.append({"call": label, "path": p})
        if _under(p, REAL_WATCH):
            REAL_TOUCHES.append({"call": label, "path": p})
        return fn(path, *a, **kw)
    return wrapper


WRAPPED_CALLS = ["os.lstat", "os.stat", "os.open", "os.readlink",
                 "os.listdir", "os.symlink", "builtins.open"]
for name in ("lstat", "stat", "open", "readlink", "listdir", "symlink"):
    setattr(os, name, _watch(getattr(os, name), "os." + name))
builtins.open = _watch(builtins.open, "builtins.open")

import preflight  # noqa: E402  (must be imported after stubbing, so it covers its calls)

preflight.pwd.getpwuid = lambda _uid: types.SimpleNamespace(
    pw_dir=FIXTURE_HOME, pw_name="fixture-user")

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, bool(ok), detail))


home = os.path.join(ROOT, "dedicated")
os.makedirs(home, 0o700)

# ── ① dummy branch: the covered call surfaces must never hit ──────────────
TOUCHES.clear()
bridge = preflight.assert_no_keychain_bridge(home)
check("① assert_no_keychain_bridge has zero hits on the covered call surfaces", not TOUCHES,
      f"{len(TOUCHES)} hits" + (f": {TOUCHES[:3]}" if TOUCHES else ""))
check("① it yields the 'must-not-exist' baseline, not a bridge baseline",
      bridge.get("mode") == "loopback_dummy"
      and "source" not in bridge and "login_db" not in bridge,
      json.dumps(sorted(bridge), ensure_ascii=False))

# ── ② the three phase reviews of dummy also zero hits ───────────────────
TOUCHES.clear()
bad = None
for _ in range(3):
    bad = preflight.verify_keychain_bridge(bridge)
check("② all three phase re-verifications also zero hits", not TOUCHES and not bad,
      f"{len(TOUCHES)} hits, re-verification result: {bad or 'clean'}")

# ── ③ sensitivity arm: touch the **fixture**, not the user's keychain ────
# An insensitive spy is no spy; but sensitivity testing shouldn't use the real keychain
# as the touched object.
TOUCHES.clear()
try:
    os.lstat(WATCH)
except OSError:
    pass
check("③ sensitivity: deliberately touch the fixture once, the spy must catch it", len(TOUCHES) == 1,
      f"caught {len(TOUCHES)} times — a spy that catches nothing makes ① an empty claim")

# ── ④ control group: the real branch really does touch (so ①'s cleanliness is decided
# by the branch, not by a blind spy) ───────────────────────────────────────
TOUCHES.clear()
home2 = os.path.join(ROOT, "dedicated-real")
os.makedirs(home2, 0o700)
try:
    preflight.prepare_keychain_bridge(home2)
    ran = True
except SystemExit:
    ran = False
check("④ control group: the real branch really does touch the fixture",
      len(TOUCHES) > 0, f"real branch hits: {len(TOUCHES)}, {'ran' if ran else 'rejected'}")

# ── ⑤ 🔴 this cell is new: over the whole run, the real keychain was never touched ──
# The old version couldn't do this — its arms ③④ were touching the real thing.
check("⑤ zero hits against the **real** ~/Library/Keychains over the whole run (so this test can run any time)",
      not REAL_TOUCHES,
      f"real hits: {len(REAL_TOUCHES)}" + (f": {REAL_TOUCHES[:3]}" if REAL_TOUCHES else ""))
check("⑤ fixture and real path are genuinely different (otherwise ⑤ would be a tautology)",
      not _under(WATCH, REAL_WATCH) and WATCH != REAL_WATCH, WATCH)

shutil.rmtree(ROOT, ignore_errors=True)

w = max(len(n) for n, _, _ in RESULTS)
bad_n = sum(1 for _, ok, _ in RESULTS if not ok)
for n, ok, d in RESULTS:
    print(f"{'✔' if ok else '✘'} {n.ljust(w)}  {d}")
print()
print(f"KEYCHAIN_SPY {len(RESULTS)-bad_n}/{len(RESULTS)}"
      f"{'  ALL_OK' if not bad_n else '  BROKEN='+str(bad_n)}")
print("coverage (nothing more, don't extrapolate): " + " / ".join(WRAPPED_CALLS))
print("⚠️ conclusion only covers: the two preflight functions above had zero hits on the covered call surfaces —"
      "preflight main(), shell, inspector, finish, CLI child processes, security(1), "
      "Security.framework, other call surfaces, fds/relative paths — all out of view.")
sys.exit(1 if bad_n else 0)
