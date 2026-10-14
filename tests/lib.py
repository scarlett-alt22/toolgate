# -*- coding: utf-8 -*-
"""Shared acceptance helpers: sandbox builds, mock start/stop, attempt artifact reads.

🔴 A hard design rule: **no test backdoors in the production wrapper.**
Tests that need their own manifest/origin get there by copying all runtime sources
into a sandbox and putting the test manifest into that copy's own profiles/manifest.json.
Reason: adding an HB_MANIFEST env var to the gate is drilling a hole in the gate for
acceptance's sake — and 08-07 already proved that `--settings`-style "thought it was
isolation but was actually append" behavior never errors; it just quietly lets you
believe you locked everything down.
"""
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import time
import urllib.request

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
# ★2026-08-08: finish.py has to come along too. build_sandbox used to copy only three,
# so a wrapper built by it would run the CLI fine and only silently explode at finalize
# (stepped on that once that evening).
SOURCES = ["hb-run.sh", "preflight.py", "inspector.py", "finish.py",
           "sandbox_launcher.py"]

# ★2026-08-14: **the third time of the same class** (three files → four → now a directory too).
# The first two times had the same shape: "added a new runtime dependency to the wrapper
# but didn't update the copy-building here",
# and the symptom wasn't an error — the copy exploded at some step, or quietly changed
# behavior.
# The criterion goes here so there's no fourth time: **anything preflight depends on
# fail-closed must appear in SOURCES or SOURCE_DIRS.**
SOURCE_DIRS = ["sandbox"]

def sha256_file(path):
    """Hash file content. 🔴 First lstat to identify the file type, then decide whether to open it.

    Burned 2026-08-08: opening a FIFO with no writer blocks **in the caller's process**
    forever — acceptance hung 81 minutes on the pf-fifo case, and the hang was the test
    itself, not the program under test.
    Same logic as spec:265 requiring preflight to use `lstat + O_NOFOLLOW + fstat`:
    **confirm it's a regular file before reading it.** Finding out after the read is too late.
    """
    import stat as _stat
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return "ABSENT"
    if _stat.S_ISLNK(st.st_mode):
        return "SYMLINK"
    if _stat.S_ISFIFO(st.st_mode):
        return "FIFO"
    if _stat.S_ISDIR(st.st_mode):
        return "DIRECTORY"
    if not _stat.S_ISREG(st.st_mode):
        return "NOT_REGULAR"
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "UNREADABLE"


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def artifact_index(root):
    """Build a closed index of every non-directory object in the case tree; don't follow
    symlinks, don't open FIFOs."""
    out = {}
    if not os.path.isdir(root):
        return out
    import stat as _stat
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            try:
                st = os.lstat(path)
            except OSError as e:
                out[rel] = {"type": "unreadable", "error": type(e).__name__}
                continue
            if _stat.S_ISDIR(st.st_mode):
                continue
            if _stat.S_ISLNK(st.st_mode):
                out[rel] = {"type": "symlink", "target": os.readlink(path)}
            elif _stat.S_ISREG(st.st_mode):
                out[rel] = {"type": "regular", "size": st.st_size,
                            "sha256": sha256_file(path)}
            elif _stat.S_ISFIFO(st.st_mode):
                out[rel] = {"type": "fifo"}
            else:
                out[rel] = {"type": "other", "mode_type": _stat.S_IFMT(st.st_mode)}
    return dict(sorted(out.items()))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ── sandbox ─────────────────────────────────────────────────────────
def build_sandbox(dest, manifest_path, extra_rewrites=None, test_cli_path=None,
                  production_build=False):
    """Copy the wrapper's runtime sources to dest and install this copy's own test manifest.

    Returns a rewrite report: per file, how many substitutions were made and the
    before/after hash.
    Production sources have no manifest override: preflight only derives fixed paths from
    its own location.
    The test copy additionally flips the TEST_BUILD constants (which cannot be enabled at
    runtime) to true and bakes the exact fake CLI realpath+sha into the copy's code;
    an ordinary profile cannot declare these three values.
    ``production_build=True`` keeps the production constants, proving disabled stays denied
    in production copies.
    """
    os.makedirs(dest, exist_ok=True)
    report = {"manifest_used": manifest_path, "files": {}}
    rewrites = list(extra_rewrites or [])
    if not production_build:
        fake_cli = os.path.realpath(test_cli_path or os.path.join(TESTS, "fake_cli.py"))
        rewrites.extend([
            ("TEST_BUILD_SANDBOX_DISABLED = False",
             "TEST_BUILD_SANDBOX_DISABLED = True"),
            ('TEST_BUILD_FAKE_CLI_REALPATH = ""',
             f"TEST_BUILD_FAKE_CLI_REALPATH = {fake_cli!r}"),
            ('TEST_BUILD_FAKE_CLI_SHA256 = ""',
             f"TEST_BUILD_FAKE_CLI_SHA256 = {sha256_file(fake_cli)!r}"),
        ])
    for name in SOURCES:
        src = os.path.join(WRAPPER, name)
        dst = os.path.join(dest, name)
        if not os.path.exists(src):
            report["files"][name] = {"present": False}
            continue
        raw = open(src, "rb").read()
        before = sha256_bytes(raw)
        text = raw.decode("utf-8")
        text2 = text
        extra_counts = {}
        for old, new in rewrites:
            text2, k = re.subn(re.escape(old), lambda _m, repl=new: repl, text2)
            extra_counts[f"{old} -> {new}"] = k
        open(dst, "w").write(text2)
        shutil.copymode(src, dst)
        report["files"][name] = {
            "present": True,
            "sha256_before": before,
            "sha256_after": sha256_bytes(text2.encode()),
            "manifest_rewrites": 0,
            "extra_rewrites": extra_counts,
        }
    # ★2026-08-14: the Seatbelt profile must ride along into the copy, or the copy's
    # preflight will exit 78 on "sandbox profile missing" — that's fail-closed working
    # correctly, but it blocks the tests themselves. **Byte-for-byte copy, no rewrites**:
    # the copy must run the production sandbox rules; change one byte and this suite no
    # longer speaks for production.
    report["source_dirs"] = {}
    for dname in SOURCE_DIRS:
        src_dir = os.path.join(WRAPPER, dname)
        dst_dir = os.path.join(dest, dname)
        if not os.path.isdir(src_dir):
            report["source_dirs"][dname] = {"present": False}
            continue
        shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
        report["source_dirs"][dname] = {
            "present": True,
            "files": {f: sha256_file(os.path.join(dst_dir, f))
                      for f in sorted(os.listdir(dst_dir))
                      if os.path.isfile(os.path.join(dst_dir, f))},
        }

    profiles = os.path.join(dest, "profiles")
    os.makedirs(profiles, exist_ok=True)
    installed = os.path.join(profiles, "manifest.json")
    shutil.copy2(manifest_path, installed)
    report["manifest_installed"] = {
        "path": installed,
        "source_sha256": sha256_file(manifest_path),
        "installed_sha256": sha256_file(installed),
    }
    return report


# ── mock start/stop ─────────────────────────────────────────────────
class Mock:
    def __init__(self, role, script=None):
        self.role = role
        self.port = free_port()
        self.script = script
        self.proc = None

    @property
    def origin(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self, workdir):
        args = ["/usr/bin/python3", os.path.join(TESTS, "mock_upstream.py"),
                "--port", str(self.port), "--role", self.role]
        if self.script:
            p = os.path.join(workdir, f"script-{self.role}.json")
            json.dump(self.script, open(p, "w"))
            args += ["--script", p]
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                self.stats()
                return self
            except Exception:
                time.sleep(0.05)
        raise RuntimeError(f"mock {self.role} failed to start")

    def stats(self):
        with urllib.request.urlopen(f"{self.origin}/__mock/stats", timeout=3) as r:
            return json.loads(r.read())

    def reset(self):
        req = urllib.request.Request(f"{self.origin}/__mock/reset", method="POST", data=b"")
        urllib.request.urlopen(req, timeout=3).read()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ── attempt artifacts ───────────────────────────────────────────────
def read_attempt_artifacts(runs_dir):
    """Read events.jsonl / terminal.json per spec §E.

    Before the implementation lands, honestly return present=False — **never treat "can't
    read" as "no problem"**; that's the same mistake as 08-07's "93/93 success with zero
    discriminating power".
    """
    out = []
    if not os.path.isdir(runs_dir):
        return out
    for d in sorted(os.listdir(runs_dir)):
        adir = os.path.join(runs_dir, d)
        if not os.path.isdir(adir):
            continue
        ev_path = os.path.join(adir, "events.jsonl")
        tm_path = os.path.join(adir, "terminal.json")
        events = []
        if os.path.exists(ev_path):
            for line in open(ev_path):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except Exception:
                        events.append({"_unparseable": True})
        terminal = None
        if os.path.exists(tm_path):
            try:
                terminal = json.load(open(tm_path))
            except Exception:
                terminal = {"_unparseable": True}
        out.append({
            "dir": d,
            "events_present": os.path.exists(ev_path),
            "terminal_present": os.path.exists(tm_path),
            "attempted_count": sum(1 for e in events if e.get("event") == "attempted"),
            "finished_count": sum(1 for e in events if e.get("event") == "finished"),
            "attempt_id": (terminal or {}).get("attempt_id"),
            "outcome": (terminal or {}).get("outcome"),
            "events": events,
            "terminal": terminal,
            "events_sha256": sha256_file(ev_path),
        })
    return out


# ── six legacy states (spec:328-336) ─────────────────────────────────
def real_home():
    """The real user home. Use getpwuid, not $HOME — these processes launch under `env -i`,
    so HOME isn't even in the environment; and this value must match whoever is actually
    running, not be rewritable by the environment."""
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser("~")


# ── this deployment's state invariants (the only list in this repo bound to a specific
# deployment) ─────────────────────────────────────────────────────────
# After a round these files must be byte-identical — that's one of the wrapper's
# postconditions.
# Swap in your own; paths are relative to the **real user home**.
# 🔴 Leaving it empty = checking nothing = disabling this whole postcondition,
# **and it won't complain**.
STATE_INVARIANT_NAMES = [
    ".claude-heartbeat-log.jsonl",
    ".claude-heartbeat-armed.json",
    ".claude-heartbeat-armed-events.jsonl",
    ".claude-nudge-state.json",
    ".claude-heartbeat-items.json",
]

STATE_TARGETS = [os.path.join(real_home(), n) for n in STATE_INVARIANT_NAMES]


def snapshot_state():
    """Record only hashes and stats; never copy any private content (spec:328)."""
    snap = {}
    for p in STATE_TARGETS:
        try:
            st = os.stat(p)
            snap[p] = {"sha256": sha256_file(p), "size": st.st_size, "mtime": st.st_mtime}
        except FileNotFoundError:
            snap[p] = {"sha256": "ABSENT"}
    # The Room cell: spec:337 explicitly forbids guessing the id; without a trusted id it
    # must be recorded as unmeasured
    snap["heartbeat_room_snapshot"] = {"status": "unmeasured",
                                       "reason": "spec:337 — no trusted room id, so no guessing; this cell is not judged before phase 1"}
    return snap


def diff_state(before, after):
    changed = []
    for k, v in before.items():
        if k == "heartbeat_room_snapshot":
            continue
        if after.get(k, {}).get("sha256") != v.get("sha256"):
            changed.append(k)
    return changed
