#!/usr/bin/env python3
"""Trusted acceptance fake CLI.

It records the environment of the *actual CLI child process*.  The artifact is
written next to plan.json, derived from --settings, so no environment variable
is needed to tell the fake where to report.  Values of credential-shaped
variables are never persisted; only presence and SHA-256 are recorded.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.request
import uuid
from urllib.parse import urlsplit

WATCHED = [
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CONFIG_DIR", "HB_TIMEOUT_SECS", "HB_INSPECTOR_PORT",
    "HB_INSPECTOR_LOG", "HB_INSPECTOR_RUN_ID",
    "HB_INSPECTOR_ALLOWED_TOOLS", "HB_INSPECTOR_UPSTREAM",
    "HOME", "NO_PROXY",
]
SAFE_PLAINTEXT = {"HOME", "NO_PROXY"}

READ_TOOL = {
    "name": "Read",
    "description": "Read a file from the local filesystem.",
    "input_schema": {
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
}


def sha(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def exclusive_json(path: str, doc: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write("\n")


def environment_evidence() -> dict:
    fields = {}
    for key in WATCHED:
        value = os.environ.get(key)
        row = {"present": value is not None}
        if value is not None:
            row["value_sha256"] = sha(value)
            if key in SAFE_PLAINTEXT:
                row["safe_value"] = value
            elif key == "ANTHROPIC_BASE_URL":
                u = urlsplit(value)
                loopback = u.hostname in {"127.0.0.1", "localhost", "::1"}
                row["is_loopback"] = loopback
                if loopback:
                    row["safe_value"] = value
        fields[key] = row
    return fields


def run_positive_protocol(adir: str, sentinel: str, challenge: str) -> None:
    """Runs the same three-request chain as the tests/fake_cli.py happy arm; never writes
    an "I'm done" boolean.

    Success or failure is independently recomputed from inspector.jsonl, the mock counter,
    terminal, and file mtimes.
    """
    plan = json.load(open(os.path.join(adir, "plan.json"), encoding="utf-8"))
    base = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
    if not base or "anthropic.com" in base:
        raise RuntimeError("phase fixture refuses a non-loopback/missing base URL")
    url = base + plan["messages_path"]
    token = os.environ.get("ANTHROPIC_AUTH_TOKEN", "")

    def post(doc: dict) -> None:
        req = urllib.request.Request(
            url, data=json.dumps(doc, separators=(",", ":")).encode(), method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            resp.read()
            if not 200 <= resp.status < 300:
                raise RuntimeError(f"positive protocol status {resp.status}")

    model = plan["model"]
    common = {"model": model, "max_tokens": 1024}
    post({**common, "tools": [],
          "messages": [{"role": "user", "content": "start"}]})
    tool_id = "toolu_phase_" + uuid.uuid4().hex[:12]
    post({**common, "tools": [READ_TOOL],
          "messages": [{"role": "user", "content": "read it"}],
          "_mock_tool_use": {"id": tool_id, "file_path": sentinel}})
    post({**common, "tools": [READ_TOOL],
          "messages": [{"role": "user", "content": [{
              "type": "tool_result", "tool_use_id": tool_id, "content": challenge
          }]}]})
    # The moment the client finishes receiving the body, the handler may still owe the last
    # two fsync'd log lines. Wait until the **artifacts themselves** are closed before
    # continuing, so the oracle can later use file mtimes to prove the mutation landed after
    # the protocol.
    log_path = os.path.join(adir, "inspector.jsonl")
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            rows = [json.loads(line) for line in open(log_path, encoding="utf-8") if line.strip()]
        except (OSError, ValueError):
            rows = []
        if (sum(r.get("event") == "request" for r in rows) == 3
                and sum(r.get("event") == "response_scan_terminal" for r in rows) == 3):
            return
        time.sleep(0.01)
    raise RuntimeError("positive protocol artifacts did not close")


def fixture_mutation(home: str, adir: str, when: str = "after_entry") -> None:
    """Optional drift actor, guarded to a marked harness-owned root.

    ★2026-08-09: gained a `when` barrier.  The post-spawn phase-drift case needs
    the mutation to land **after the CLI has already completed the same protocol
    the positive control completes** — otherwise the counterfactual is wide:
    a red result could mean "post_cli caught the drift" or merely "this arm
    behaved differently all along".  The control file names its own barrier.
    """
    control = os.path.join(home, ".hb-auth-acceptance-after-spawn.json")
    if not os.path.exists(control):
        return
    with open(control, encoding="utf-8") as f:
        op = json.load(f)
    if op.get("when", "after_entry") != when:
        return
    root = os.path.abspath(op["fixture_root"])
    marker = os.path.join(root, ".hb-auth-acceptance-root")
    target = os.path.abspath(op["target"])
    if not os.path.isfile(marker):
        raise RuntimeError("refusing mutation: fixture root marker missing")
    if os.path.commonpath([root, target]) != root or root in {"/", os.path.expanduser("~")}:
        raise RuntimeError("refusing mutation outside marked fixture root")
    writer = os.path.realpath(__file__)
    with open(writer, "rb") as f:
        writer_sha = sha(f.read())
    action = op["action"]
    if action == "create_absent_symlink":
        # loopback_dummy: nothing is supposed to exist here at all.
        if os.path.lexists(target):
            raise RuntimeError("create_absent_symlink expects the target to be absent")
        replacement = os.path.abspath(op["replacement"])
        if os.path.commonpath([root, replacement]) != root:
            raise RuntimeError("refusing to point outside marked fixture root")
        os.makedirs(os.path.dirname(target), 0o700, exist_ok=True)
        os.symlink(replacement, target)
        before_doc = {"type": "absent"}
    else:
        before = os.lstat(target)
        before_doc = {"dev": before.st_dev, "inode": before.st_ino,
                      "mode_type": stat.S_IFMT(before.st_mode)}
        if action == "replace_symlink_with_directory":
            if not stat.S_ISLNK(before.st_mode):
                raise RuntimeError("expected a symlink drift target")
            os.unlink(target)
            os.mkdir(target, 0o700)
        elif action == "rewrite_regular_in_place":
            if not stat.S_ISREG(before.st_mode):
                raise RuntimeError("expected a regular content-refresh target")
            with open(target, "ab") as f:
                f.write(b"ACCEPTANCE-FAKE-OAUTH-REFRESH\n")
                f.flush()
                os.fsync(f.fileno())
        else:
            raise RuntimeError(f"unknown fixture mutation: {action}")
    after = os.lstat(target)
    doc = {
        "actor": "fake_cli", "action": action, "when": when,
        "pid": os.getpid(), "writer_sha256": writer_sha,
        "completed_after_cli_entry": True,
        "completed_before_cli_exit": True,
        "target": target,
        "before": before_doc,
        "after": {"dev": after.st_dev, "inode": after.st_ino,
                  "mode_type": stat.S_IFMT(after.st_mode)},
    }
    if stat.S_ISLNK(after.st_mode):
        link = os.readlink(target)
        doc["after"]["readlink"] = link
        doc["after"]["readlink_is_absolute"] = os.path.isabs(link)
    exclusive_json(os.path.join(adir, "auth-mutation-by-cli.json"), doc)


def main() -> int:
    if "--version" in sys.argv[1:]:
        print("hb-acceptance-fake-cli 1.0")
        return 0
    try:
        idx = sys.argv.index("--settings")
        settings = os.path.abspath(sys.argv[idx + 1])
    except (ValueError, IndexError):
        print("fake_cli: --settings path required", file=sys.stderr)
        return 64
    adir = os.path.dirname(os.path.dirname(settings))
    writer = os.path.realpath(__file__)
    with open(writer, "rb") as f:
        writer_sha = sha(f.read())
    exclusive_json(os.path.join(adir, "cli-started.json"), {
        "role": "cli", "pid": os.getpid(), "ppid": os.getppid(),
        "writer_realpath": writer, "writer_sha256": writer_sha,
    })
    env = environment_evidence()
    exclusive_json(os.path.join(adir, "cli-process-evidence.json"), {
        "role": "cli", "pid": os.getpid(), "ppid": os.getppid(),
        "writer_realpath": writer, "writer_sha256": writer_sha,
        "environment": env,
        "forbidden_present": [k for k in WATCHED
                              if k.startswith("HB_") or k in {
                                  "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                                  "CLAUDE_CONFIG_DIR"
                              } if env[k]["present"]],
    })
    fixture_mutation(os.environ.get("HOME", ""), adir, when="after_entry")

    prompt = sys.stdin.read()
    match = re.search(r"read the file (.+?) and output", prompt, re.IGNORECASE)
    challenge = "ACCEPTANCE-FAKE-CHALLENGE"
    if match:
        try:
            with open(match.group(1).strip(), encoding="utf-8") as f:
                challenge = f.readline().rstrip("\r\n")
        except OSError:
            pass
    sentinel = match.group(1).strip() if match else ""
    control = os.path.join(os.environ.get("HOME", ""),
                           ".hb-auth-acceptance-after-spawn.json")
    if os.path.exists(control):
        run_positive_protocol(adir, sentinel, challenge)
    print(json.dumps({
        "type": "result",
        "is_error": False,
        "stop_reason": "end_turn",
        "permission_denials": [],
        "result": challenge + "\n" + json.dumps({"ok": True, "task": "done"},
                                                  sort_keys=True),
    }, separators=(",", ":")))
    sys.stdout.flush()
    # 🔴 The `before_exit` barrier: everything above is byte-for-byte the
    # positive control.  Only after that does this arm drift — so a red
    # post_cli can only mean post_cli caught it.
    fixture_mutation(os.environ.get("HOME", ""), adir, when="before_exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
