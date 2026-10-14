#!/usr/bin/env python3
"""Trusted acceptance fake inspector and pre-READY drift actor.

The listen port is accepted only through an explicit test-only argv/policy
channel.  HB_INSPECTOR_PORT is deliberately never read.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import socket
import stat

WATCHED = [
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CONFIG_DIR", "HB_TIMEOUT_SECS", "HB_INSPECTOR_PORT",
    "HB_INSPECTOR_LOG", "HB_INSPECTOR_RUN_ID",
    "HB_INSPECTOR_ALLOWED_TOOLS", "HB_INSPECTOR_UPSTREAM",
]


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def exclusive_json(path: str, doc: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def append_event(path: str, event: str, **fields) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"event": event, **fields}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def mutate_before_ready(adir: str) -> None:
    plan_path = os.path.join(adir, "plan.json")
    if not os.path.isfile(plan_path):
        return
    with open(plan_path, encoding="utf-8") as f:
        plan = json.load(f)
    home = plan.get("home") or plan.get("home_realpath")
    if not isinstance(home, str):
        return
    control = os.path.join(home, ".hb-auth-acceptance-before-ready.json")
    if not os.path.exists(control):
        return
    with open(control, encoding="utf-8") as f:
        op = json.load(f)
    root = os.path.abspath(op["fixture_root"])
    target = os.path.abspath(op["target"])
    replacement = os.path.abspath(op["replacement"])
    if not os.path.isfile(os.path.join(root, ".hb-auth-acceptance-root")):
        raise RuntimeError("refusing mutation: fixture root marker missing")
    if any(os.path.commonpath([root, p]) != root for p in (target, replacement)):
        raise RuntimeError("refusing mutation outside marked fixture root")
    writer = os.path.realpath(__file__)
    with open(writer, "rb") as f:
        writer_sha = sha(f.read())
    # ★2026-08-09: two modes.  `replace_symlink` is the original real-bridge
    # drift.  `create_absent` is the loopback_dummy case: the dedicated HOME is
    # supposed to have **no** Library/Keychains at all, so the drift to catch is
    # one appearing where nothing was — a different shape, not a variant.
    mode = op.get("mode", "replace_symlink")
    if mode == "create_absent":
        if os.path.lexists(target):
            raise RuntimeError("create_absent expects the target to be absent")
        os.makedirs(os.path.dirname(target), 0o700, exist_ok=True)
        os.symlink(replacement, target)
        before_doc = {"type": "absent"}
    elif mode == "replace_symlink":
        before = os.lstat(target)
        if not stat.S_ISLNK(before.st_mode):
            raise RuntimeError("expected a symlink drift target")
        os.unlink(target)
        os.symlink(replacement, target)
        before_doc = {"dev": before.st_dev, "inode": before.st_ino,
                      "readlink": op.get("expected_before")}
    else:
        raise RuntimeError(f"unknown pre-READY mutation mode: {mode}")
    after = os.lstat(target)
    exclusive_json(os.path.join(adir, "auth-mutation-by-inspector.json"), {
        "actor": "fake_inspector", "mode": mode,
        "pid": os.getpid(), "writer_sha256": writer_sha,
        # The barrier is structural, not timing-based: this function runs after
        # the process is already up and strictly before READY is printed.
        "completed_after_inspector_entry": True,
        "completed_before_ready": True,
        "target": target,
        "before": before_doc,
        "after": {"dev": after.st_dev, "inode": after.st_ino,
                  "readlink": os.readlink(target),
                  "readlink_is_absolute": os.path.isabs(os.readlink(target))},
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("policy")
    parser.add_argument("events")
    parser.add_argument("--test-listen-port", type=int)
    parser.add_argument("--test-no-bind", action="store_true")
    args = parser.parse_args()
    with open(args.policy, "rb") as f:
        raw_policy = f.read()
    policy = json.loads(raw_policy)
    test_policy = policy.get("_test_only") if isinstance(policy.get("_test_only"), dict) else {}
    if args.test_listen_port is not None:
        requested_port = args.test_listen_port
        port_source = "explicit_test_only"
        port_detail = "argv"
    elif "listen_port" in test_policy:
        requested_port = int(test_policy["listen_port"])
        port_source = "explicit_test_only"
        port_detail = "policy"
    else:
        requested_port = 0
        port_source = "kernel_default"
        port_detail = "no injection"
    if not 0 <= requested_port <= 65535:
        raise SystemExit("test listen port out of range")
    no_bind = args.test_no_bind or test_policy.get("no_bind") is True
    if no_bind and requested_port == 0:
        raise SystemExit("--test-no-bind requires an explicit nonzero test port")

    adir = os.path.dirname(os.path.abspath(args.events))
    mutate_before_ready(adir)
    sock = None
    if no_bind:
        actual_port = requested_port
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", requested_port))
        sock.listen(1)
        actual_port = sock.getsockname()[1]

    writer = os.path.realpath(__file__)
    with open(writer, "rb") as f:
        writer_sha = sha(f.read())
    environment = {}
    for key in WATCHED:
        value = os.environ.get(key)
        environment[key] = {"present": value is not None}
        if value is not None:
            environment[key]["value_sha256"] = sha(value)
    exclusive_json(os.path.join(adir, "inspector-process-evidence.json"), {
        "role": "inspector", "pid": os.getpid(), "ppid": os.getppid(),
        "writer_realpath": writer, "writer_sha256": writer_sha,
        "policy_sha256": sha(raw_policy), "environment": environment,
        "forbidden_present": [k for k in WATCHED if environment[k]["present"]],
        "listen_port": {"source": port_source, "detail": port_detail,
                        "requested": requested_port, "actual": actual_port,
                        "socket_bound": not no_bind},
    })
    append_event(args.events, "inspector_ready", pid=os.getpid(), port=actual_port,
                 policy_sha256=sha(raw_policy))
    print(f"READY 127.0.0.1:{actual_port} policy_sha256={sha(raw_policy)}", flush=True)

    stopped = False
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopped:
        signal.pause()
    append_event(args.events, "inspector_stopping", requests=0, blocked=0, forwarded=0)
    if sock is not None:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
