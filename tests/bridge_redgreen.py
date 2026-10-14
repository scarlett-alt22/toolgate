#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Red/green matrix for prepare_keychain_bridge / verify_keychain_bridge.

⚠️ **Not part of the 89 acceptance gates**: run_acceptance.py only reads
   cases.json and never runs this file. This is the red/green evidence from the
   day the bridge implementation landed (2026-08-08); run it manually:
       /usr/bin/python3 tests/bridge_redgreen.py
   The formal 8+4 bridge-topology cases live in the authentication group of
   ~/hb-auth-staging/cases/cases.json; when that group merges into the gate,
   every cell in this file should have a matching case there.


🔴 Never touches the real ~/Library/Keychains: pwd.getpwuid is stubbed so that
   it resolves to a fixture tree as the real home, so the "modify login DB
   content" cell modifies the fixture's copy, not the user's real keychain.
   (2026-07-28 lesson: never run a destructive self-test against the only
   production copy.)
Every cell demands: counterexamples must be caught, and **caught for the right
reason** (keyword match against the rejection message).
"""
import os
import shutil
import stat
import sys
import tempfile
import types

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
sys.path.insert(0, WRAPPER)
import preflight  # noqa: E402

ROOT = tempfile.mkdtemp(prefix="bridge-redgreen-", dir=os.path.dirname(os.path.abspath(__file__)))
RESULTS = []


def fake_real_home(path):
    """Replace getpwuid with a fake passwd entry pointing at the fixture tree."""
    def _getpwuid(_uid):
        return types.SimpleNamespace(pw_dir=path, pw_name="fixture-user")
    preflight.pwd.getpwuid = _getpwuid


def new_case(name):
    d = os.path.join(ROOT, name)
    real = os.path.join(d, "realhome")
    ded = os.path.join(d, "dedicated")
    kc = os.path.join(real, "Library", "Keychains")
    os.makedirs(kc, 0o755)
    os.makedirs(ded, 0o700)
    with open(os.path.join(kc, "login.keychain-db"), "wb") as f:
        f.write(b"FIXTURE-NOT-A-REAL-KEYCHAIN-v1\n")
    fake_real_home(real)
    return real, ded, kc


def run(name, fn):
    try:
        detail = fn()
        RESULTS.append((name, "OK", detail))
    except AssertionError as e:
        RESULTS.append((name, "BROKEN", str(e)))


def expect_reject(want_substr, thunk):
    """thunk must exit with config_rejected, and the reason must contain want_substr."""
    import io
    import contextlib
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            thunk()
    except SystemExit as e:
        assert e.code == 78, f"exit code should be 78, got {e.code}"
        msg = err.getvalue()
        assert want_substr in msg, f"wrong rejection reason: expected to contain {want_substr!r}, got {msg.strip()!r}"
        return msg.strip().splitlines()[-1][:110]
    raise AssertionError(f"not rejected -- expected rejection for {want_substr!r}")


# ── 8 specified topologies ────────────────────────────────────────────────
def c_create_absolute():
    real, ded, kc = new_case("create-absolute")
    b = preflight.prepare_keychain_bridge(ded)
    link = os.path.join(ded, "Library", "Keychains")
    assert os.path.islink(link), "symlink was not created"
    assert os.readlink(link) == kc, "readlink is not the absolute source path"
    assert b["link"]["created"] is True, "created should be True"
    assert b["content_hash_checked"] is False, "must not claim the content hash was checked"
    assert verify_clean(b), "drift reported right after creation"
    return f"created={b['link']['created']} readlink={os.readlink(link)[-30:]}"


def c_existing_correct():
    real, ded, kc = new_case("existing-correct")
    b1 = preflight.prepare_keychain_bridge(ded)
    ino1 = b1["link"]["inode"]
    b2 = preflight.prepare_keychain_bridge(ded)
    assert b2["link"]["created"] is False, "second run must not report created"
    assert b2["link"]["inode"] == ino1, "inode changed on idempotent accept (was rebuilt)"
    assert verify_clean(b1) and verify_clean(b2), "drift reported after idempotent run"
    return f"inode_stable={ino1}"


def c_wrong_link():
    real, ded, kc = new_case("wrong-link")
    other = os.path.join(real, "Library", "Decoy")
    os.makedirs(other, 0o755)
    os.makedirs(os.path.join(ded, "Library"), 0o700)
    link = os.path.join(ded, "Library", "Keychains")
    os.symlink(other, link)
    msg = expect_reject("points to the wrong place", lambda: preflight.prepare_keychain_bridge(ded))
    assert os.path.islink(link) and os.readlink(link) == other, "🔴 link was changed after rejection"
    return msg


def c_relative_link():
    real, ded, kc = new_case("relative-link")
    os.makedirs(os.path.join(ded, "Library"), 0o700)
    link = os.path.join(ded, "Library", "Keychains")
    rel = os.path.relpath(kc, os.path.dirname(link))
    os.symlink(rel, link)
    assert os.path.realpath(link) == kc, "precondition not met: this relative link should have resolved correctly"
    msg = expect_reject("points to the wrong place", lambda: preflight.prepare_keychain_bridge(ded))
    assert os.readlink(link) == rel, "🔴 link was touched after rejection"
    return f"rejected despite correct resolve; {msg}"


def c_plain_directory():
    real, ded, kc = new_case("plain-directory")
    link = os.path.join(ded, "Library", "Keychains")
    os.makedirs(link, 0o700)
    with open(os.path.join(link, "keepme.txt"), "w") as f:
        f.write("must survive")
    msg = expect_reject("is not a symlink", lambda: preflight.prepare_keychain_bridge(ded))
    assert os.path.isfile(os.path.join(link, "keepme.txt")), "🔴 directory contents were cleared after rejection"
    return msg


def c_drift_before_cli_spawn():
    real, ded, kc = new_case("drift-before-spawn")
    b = preflight.prepare_keychain_bridge(ded)
    link = os.path.join(ded, "Library", "Keychains")
    decoy = os.path.join(real, "Library", "Decoy")
    os.makedirs(decoy, 0o755)
    os.unlink(link)
    os.symlink(decoy, link)          # simulate the inspector tampering before READY
    bad = preflight.verify_keychain_bridge(b)
    assert bad, "drift before READY was not caught by the pre_cli recheck"
    assert any("readlink" in x or "inode" in x for x in bad), f"caught but for the wrong reason: {bad}"
    return bad[0][:110]


def c_drift_after_cli_spawn():
    real, ded, kc = new_case("drift-after-spawn")
    b = preflight.prepare_keychain_bridge(ded)
    os.rename(kc, kc + ".moved")
    os.makedirs(kc, 0o755)           # same name, different inode
    bad = preflight.verify_keychain_bridge(b)
    assert bad, "source inode changed but not caught"
    return bad[0][:110]


def c_content_refresh_is_not_drift():
    real, ded, kc = new_case("content-refresh")
    b = preflight.prepare_keychain_bridge(ded)
    db = os.path.join(kc, "login.keychain-db")
    before = open(db, "rb").read()
    with open(db, "ab") as f:        # normal system refresh of keychain content (modifying the fixture copy)
        f.write(b"REFRESHED-BY-SYSTEM\n")
    after = open(db, "rb").read()
    assert before != after, "precondition not met: content did not actually change"
    bad = preflight.verify_keychain_bridge(b)
    assert not bad, f"🔴 content change mistaken for topology drift: {bad}"
    return "content changed, size changed, recheck still clean"


# ── Four more groups Codex flagged as missing ─────────────────────────────
def c_library_and_absolute():
    real, ded, kc = new_case("library-and-absolute")
    shutil.rmtree(os.path.join(ded, "Library"), ignore_errors=True)
    assert not os.path.lexists(os.path.join(ded, "Library")), "precondition not met"
    b = preflight.prepare_keychain_bridge(ded)
    st = os.lstat(os.path.join(ded, "Library"))
    assert stat.S_IMODE(st.st_mode) == 0o700, f"Library should be 0700, got {oct(stat.S_IMODE(st.st_mode))}"
    assert verify_clean(b), "drift reported right after creation"
    return "Library and link created together, 0700"


def c_library_invalid():
    real, ded, kc = new_case("library-invalid")
    elsewhere = os.path.join(real, "Elsewhere")
    os.makedirs(elsewhere, 0o755)
    os.symlink(elsewhere, os.path.join(ded, "Library"))
    return expect_reject("Library in the dedicated home is a symlink",
                         lambda: preflight.prepare_keychain_bridge(ded))


def c_source_missing():
    real, ded, kc = new_case("source-missing")
    shutil.rmtree(kc)
    return expect_reject("the real Keychains directory does not exist",
                         lambda: preflight.prepare_keychain_bridge(ded))


def c_db_is_symlink():
    real, ded, kc = new_case("db-is-symlink")
    db = os.path.join(kc, "login.keychain-db")
    os.unlink(db)
    os.symlink("/etc/hosts", db)
    return expect_reject("login keychain DB is a symlink",
                         lambda: preflight.prepare_keychain_bridge(ded))


def c_db_group_writable():
    real, ded, kc = new_case("db-group-writable")
    os.chmod(os.path.join(kc, "login.keychain-db"), 0o664)
    return expect_reject("login keychain DB is group/other writable",
                         lambda: preflight.prepare_keychain_bridge(ded))


def c_identity_drift_same_target():
    real, ded, kc = new_case("identity-drift-same-target")
    b = preflight.prepare_keychain_bridge(ded)
    link = os.path.join(ded, "Library", "Keychains")
    text_before = os.readlink(link)
    db = os.path.join(kc, "login.keychain-db")
    body = open(db, "rb").read()
    os.unlink(db)
    with open(db, "wb") as f:        # same name and content, swapped inode
        f.write(body)
    assert os.readlink(link) == text_before, "precondition not met: link text changed"
    bad = preflight.verify_keychain_bridge(b)
    assert bad, "🔴 link text unchanged, DB inode swapped, yet it passed"
    assert any("login_db.inode" in x for x in bad), f"caught but for the wrong reason: {bad}"
    return bad[0][:110]


def c_real_home_equals_dedicated():
    real, ded, kc = new_case("home-eq-realhome")
    return expect_reject("the dedicated home must not equal the real home",
                         lambda: preflight.prepare_keychain_bridge(real))


def verify_clean(b):
    return not preflight.verify_keychain_bridge(b)


CASES = [
    ("① create-absolute", c_create_absolute),
    ("② existing-correct", c_existing_correct),
    ("③ wrong-link", c_wrong_link),
    ("④ relative-link", c_relative_link),
    ("⑤ plain-directory", c_plain_directory),
    ("⑥ drift-before-cli-spawn", c_drift_before_cli_spawn),
    ("⑦ drift-after-cli-spawn", c_drift_after_cli_spawn),
    ("⑧ content-refresh-is-not-drift", c_content_refresh_is_not_drift),
    ("＋library-and-absolute", c_library_and_absolute),
    ("＋library-invalid", c_library_invalid),
    ("＋source-missing", c_source_missing),
    ("＋db-is-symlink", c_db_is_symlink),
    ("＋db-group-writable", c_db_group_writable),
    ("＋identity-drift-same-target", c_identity_drift_same_target),
    ("＋dedicated==real-home", c_real_home_equals_dedicated),
]

for name, fn in CASES:
    run(name, fn)

width = max(len(n) for n, _, _ in RESULTS)
broken = 0
for name, status, detail in RESULTS:
    mark = "✔" if status == "OK" else "✘"
    if status != "OK":
        broken += 1
    print(f"{mark} {name.ljust(width)}  {detail}")
print()
print(f"BRIDGE_REDGREEN {len(RESULTS) - broken}/{len(RESULTS)}"
      f"{'  ALL_OK' if broken == 0 else '  BROKEN=' + str(broken)}")
print(f"fixture tree: {ROOT} (real ~/Library/Keychains bypassed via getpwuid stub throughout, never read or written)")
sys.exit(1 if broken else 0)
