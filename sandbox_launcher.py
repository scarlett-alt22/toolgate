#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Launch one CLI attempt while binding Seatbelt to verified policy bytes.

The required-sandbox path reads the profile exactly once, verifies that byte
string against plan.json, and passes that same string to both sandbox-exec
invocations with ``-p``.  The inner bootstrap uses a dedicated close-on-exec
pipe: READY followed by EOF proves ``execv`` succeeded, while exec failure adds
FAIL before EOF.  The launcher records ``cli_started`` immediately on the
successful handshake; model stdout is never used as evidence or modified.

This file deliberately has no environment/profile switch for its test fault.
The acceptance builder may rewrite the literal below in its private copy; the
production copy is permanently false.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import select
import signal
import stat
import subprocess
import sys
import time


EXIT_CONFIG_REJECTED = 78
EXIT_TIMEOUT = 142
MAX_POLICY_BYTES = 1024 * 1024

# Test-copy build marker. tests/lib.py may rewrite this exact literal only in a
# private wrapper copy. There is intentionally no argv/env/profile equivalent.
TEST_BREAK_POLICY_AFTER_PROBE = False
BROKEN_TEST_POLICY = b'(version 1)\n(deny default\n'

BOOTSTRAP = r'''import fcntl,os,sys
fd=int(sys.argv[1])
token=sys.argv[2]
cmd=sys.argv[3:]
fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.fcntl(fd, fcntl.F_GETFD) | fcntl.FD_CLOEXEC)
os.write(fd, ("READY "+token+"\n").encode("ascii"))
try:
    os.execv(cmd[0], cmd)
except OSError as exc:
    os.write(fd, ("FAIL "+token+"\n").encode("ascii"))
    msg="HB_BOOTSTRAP_EXEC_FAILED "+token+" "+type(exc).__name__+"\n"
    os.write(2, msg.encode("ascii", "replace"))
    os._exit(127)
'''


def append_event(events_path, attempt_id, kind, **fields):
    record = {
        "event": kind,
        "attempt_id": attempt_id,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        **fields,
    }
    raw = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(events_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        os.write(fd, raw)
    finally:
        os.close(fd)


def read_policy_once(path):
    """Return one immutable byte string after lstat/open/fstat checks."""
    st1 = os.lstat(path)
    if not stat.S_ISREG(st1.st_mode):
        raise ValueError("sandbox profile is not a regular file")
    if st1.st_uid != os.getuid() or st1.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("sandbox profile ownership/mode is unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st2 = os.fstat(fd)
        if not stat.S_ISREG(st2.st_mode) or (st1.st_dev, st1.st_ino) != (st2.st_dev, st2.st_ino):
            raise ValueError("sandbox profile changed identity while opening")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_POLICY_BYTES:
                raise ValueError("sandbox profile is too large")
            chunks.append(chunk)
        st3 = os.fstat(fd)
        if (st2.st_dev, st2.st_ino, st2.st_size, st2.st_mtime_ns) != (
                st3.st_dev, st3.st_ino, st3.st_size, st3.st_mtime_ns):
            raise ValueError("sandbox profile changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def policy_text(raw):
    if b"\0" in raw:
        raise ValueError("sandbox profile contains NUL")
    text = raw.decode("utf-8")
    if text.encode("utf-8") != raw:
        raise ValueError("sandbox profile UTF-8 round-trip changed bytes")
    return text


def parse_params(items):
    out = []
    seen = set()
    for item in items:
        name, sep, value = item.partition("=")
        if not sep or not name or name in seen or not name.replace("_", "").isalnum():
            raise ValueError(f"invalid or duplicate sandbox parameter: {item!r}")
        seen.add(name)
        out.extend(["-D", item])
    return out


def kill_group(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_child(argv, input_bytes, timeout, handshake_rfd, handshake_wfd,
              expected_handshake, on_started):
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=(handshake_wfd,),
        )
    except Exception:
        os.close(handshake_rfd)
        os.close(handshake_wfd)
        raise
    os.close(handshake_wfd)
    old_handlers = {}

    def interrupted(signum, _frame):
        kill_group(proc)
        raise SystemExit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM):
        old_handlers[sig] = signal.signal(sig, interrupted)
    deadline = time.monotonic() + timeout
    try:
        handshake = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([handshake_rfd], [], [], remaining)[0]:
                kill_group(proc)
                stdout, stderr = proc.communicate()
                return EXIT_TIMEOUT, stdout, stderr, True, False
            chunk = os.read(handshake_rfd, 4096)
            if not chunk:
                break
            handshake.extend(chunk)
            if len(handshake) > 4096:
                kill_group(proc)
                stdout, stderr = proc.communicate()
                return EXIT_CONFIG_REJECTED, stdout, stderr, False, False

        started = bytes(handshake) == expected_handshake
        if started:
            # The write end is FD_CLOEXEC. EOF with only READY means execv
            # succeeded; an exec failure writes FAIL before the bootstrap exits.
            on_started()
        remaining = max(0.001, deadline - time.monotonic())
        try:
            stdout, stderr = proc.communicate(input=input_bytes, timeout=remaining)
            return proc.returncode, stdout, stderr, False, started
        except subprocess.TimeoutExpired:
            kill_group(proc)
            stdout, stderr = proc.communicate()
            return EXIT_TIMEOUT, stdout, stderr, True, started
    finally:
        os.close(handshake_rfd)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    parser.add_argument("--timeout", required=True, type=int)
    parser.add_argument("--param", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command or not os.path.isabs(command[0]):
        parser.error("command must begin with an absolute executable path")

    plan_path = os.path.realpath(args.plan)
    with open(plan_path, encoding="utf-8") as f:
        plan = json.load(f)
    adir = os.path.dirname(plan_path)
    if adir != os.path.realpath(plan.get("attempt_dir", "")):
        raise ValueError("plan attempt_dir does not match plan path")
    events_path = os.path.join(adir, "events.jsonl")
    probe_error = os.path.join(adir, "sandbox_probe.err")
    attempt_id = plan["attempt_id"]
    mode = plan["sandbox_mode"]
    if mode not in ("required", "disabled"):
        raise ValueError(f"unsupported sandbox mode {mode!r}")
    if not 1 <= args.timeout <= 300:
        raise ValueError("timeout outside 1..300")

    params = parse_params(args.param)
    expected_sha = plan["hashes"].get("sandbox_profile")
    verified_policy = None
    verified_sha = None
    if mode == "required":
        try:
            raw = read_policy_once(plan["sandbox_profile_path"])
            verified_sha = hashlib.sha256(raw).hexdigest()
            if verified_sha != expected_sha:
                raise ValueError(
                    f"sandbox profile sha mismatch: plan={expected_sha} actual={verified_sha}")
            verified_policy = policy_text(raw)
        except Exception as exc:
            append_event(events_path, attempt_id, "sandbox_apply_failed", stage="load",
                         expected_profile_sha256=expected_sha,
                         actual_profile_sha256=verified_sha,
                         reason=f"{type(exc).__name__}: {exc}")
            print(f"sandbox-launcher: policy load/identity rejected: {exc}", file=sys.stderr)
            return EXIT_CONFIG_REJECTED

        probe_argv = ["/usr/bin/sandbox-exec", "-p", verified_policy, *params,
                      "/usr/bin/true"]
        probe = subprocess.run(probe_argv, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, timeout=30)
        with open(probe_error, "wb") as f:
            f.write(probe.stderr or b"")
        if probe.returncode != 0:
            append_event(events_path, attempt_id, "sandbox_apply_failed", stage="probe",
                         profile_sha256=verified_sha, sandbox_exit=probe.returncode)
            print(f"sandbox-launcher: probe apply failed; see {probe_error}", file=sys.stderr)
            return EXIT_CONFIG_REJECTED
        append_event(events_path, attempt_id, "sandbox_ready",
                     profile_sha256=verified_sha)
    else:
        append_event(events_path, attempt_id, "sandbox_disabled")

    exec_policy = (BROKEN_TEST_POLICY if TEST_BREAK_POLICY_AFTER_PROBE
                   else (verified_policy.encode("utf-8") if verified_policy is not None else None))
    exec_sha = hashlib.sha256(exec_policy).hexdigest() if exec_policy is not None else None
    if TEST_BREAK_POLICY_AFTER_PROBE:
        append_event(events_path, attempt_id, "test_policy_broken_after_probe",
                     ready_profile_sha256=verified_sha, exec_profile_sha256=exec_sha)

    token = "HB-INNER-" + secrets.token_hex(24)
    handshake_rfd, handshake_wfd = os.pipe()
    bootstrap = ["/usr/bin/python3", "-c", BOOTSTRAP,
                 str(handshake_wfd), token, *command]
    if mode == "required":
        child_argv = ["/usr/bin/sandbox-exec", "-p", policy_text(exec_policy),
                      *params, *bootstrap]
    else:
        child_argv = bootstrap

    # This pre-spawn event preserves the old fail-closed accounting property:
    # once execution is attempted, finish.py must require pre_cli/post_cli even
    # if sandbox-exec or exec fails before the CLI can produce evidence.
    append_event(events_path, attempt_id, "cli_exec_attempted",
                 profile_sha256=exec_sha)
    expected_handshake = ("READY " + token + "\n").encode("ascii")

    def record_started():
        append_event(events_path, attempt_id, "cli_started",
                     profile_sha256=exec_sha, inner_bootstrap_handshake=True)

    rc, stdout, stderr, timed_out, started = run_child(
        child_argv, sys.stdin.buffer.read(), args.timeout,
        handshake_rfd, handshake_wfd, expected_handshake, record_started)

    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()

    if mode == "required" and not started:
        append_event(events_path, attempt_id, "sandbox_apply_failed", stage="cli_exec",
                     expected_profile_sha256=expected_sha,
                     actual_profile_sha256=exec_sha,
                     sandbox_exit=rc, inner_bootstrap_handshake=False)
        return EXIT_CONFIG_REJECTED
    if timed_out:
        return EXIT_TIMEOUT
    return rc


if __name__ == "__main__":
    sys.exit(main())
