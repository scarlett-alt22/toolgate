# -*- coding: utf-8 -*-
"""Start the inspector, point the wrapped command at it, clean up when it finishes."""
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from urllib.parse import urlsplit

from . import config as cfg_mod

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSPECTOR = os.path.join(REPO, "inspector.py")


def _upstream_connect(url):
    u = urlsplit(url)
    if u.scheme not in ("http", "https"):
        raise SystemExit("upstream must be http:// or https://, got {!r}".format(url))
    port = u.port or (443 if u.scheme == "https" else 80)
    return {"scheme": u.scheme, "host": u.hostname, "port": port}


def build_policy(d, cfg, mode, run_dir):
    """Translate the user-facing config into the inspector's policy.

    🔴 This is the only place where "user config → the gate's criteria" is translated. A wrong
       translation raises no error; it just becomes a looser gate — so the difference between the two modes is spelled out as visibly as possible:
       only observe gets surface_path, and enforce must always have a model.
    """
    up = _upstream_connect(cfg["upstream"])
    _approved_doc = cfg_mod.load_approved(d)
    approved = cfg_mod.approved_map(_approved_doc)
    pol = {
        "attempt_id": os.path.basename(run_dir),
        "capability_path": cfg_mod.new_capability_path(),
        "upstream_origin": cfg["upstream"].rstrip("/"),
        "upstream_connect": up,
        "messages_path": cfg["messages_path"],
        "model": cfg.get("model"),
        "max_body_bytes": cfg.get("max_body_bytes", 2 * 1024 * 1024),
        "approved_tools": approved,
        # Lets the gate report contract_drift (a name you approved has changed) and tool_added (something never seen)
        # separately. Both are blocked; what differs is the wording, not the strictness.
        "approved_names": cfg_mod.approved_names(_approved_doc),
        "required_actions": [],
        "mode": mode,
        "wire_format": cfg.get("wire_format", "anthropic_messages"),
        # The client brings its own credentials; this gate forwards them as-is, without checking or logging them
        "auth_mode": "passthrough" if up["scheme"] == "https" else "loopback_dummy",
    }
    if pol["auth_mode"] == "loopback_dummy":
        # Only reached when upstream points at plain http on this machine (self-test / demo).
        pol["expected_auth_token"] = secrets.token_hex(16)
    if mode == "observe":
        pol["surface_path"] = cfg_mod.surface_path(d)
    return pol


def start_inspector(policy, run_dir):
    ppath = os.path.join(run_dir, "policy.json")
    with open(ppath, "w", encoding="utf-8") as f:
        json.dump(policy, f, ensure_ascii=False, indent=1)
    log_path = os.path.join(run_dir, "inspector.jsonl")
    proc = subprocess.Popen(
        [sys.executable, INSPECTOR, ppath, log_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True)
    port, deadline = None, time.time() + 20
    startup_output = []
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        startup_output.append(line.rstrip())
        if line.startswith("READY"):
            port = int(line.split()[1].split(":")[1])
            break
    if port is None:
        proc.kill()
        # 🔴 Hand over what the inspector itself said, verbatim. A misconfiguration here raises no error;
        #    it just refuses or idles, and hiding the startup output throws away the only clue.
        raise SystemExit("inspector did not start:\n  "
                         + "\n  ".join(startup_output or ["(no output)"]))
    return proc, port, log_path


def run(d, cfg, mode, argv):
    if not argv:
        raise SystemExit("no command given. usage: toolgate watch -- <your command>")
    # 🔴 Second-resolution directory names collide: two runs in the same second share one inspector.jsonl,
    #    so "requests this run" also counts the previous run — the first number the user sees is wrong.
    run_dir = os.path.join(d, "runs", time.strftime("%Y%m%dT%H%M%S")
                           + "-" + secrets.token_hex(3))
    os.makedirs(run_dir, exist_ok=True)
    policy = build_policy(d, cfg, mode, run_dir)
    proc, port, log_path = start_inspector(policy, run_dir)

    base = "http://127.0.0.1:{}/{}{}".format(
        port, policy["capability_path"], cfg.get("base_url_suffix", ""))
    env = dict(os.environ)
    env[cfg.get("base_url_env", "ANTHROPIC_BASE_URL")] = base
    if policy["auth_mode"] == "loopback_dummy":
        env["ANTHROPIC_AUTH_TOKEN"] = policy["expected_auth_token"]

    try:
        rc = subprocess.call(argv, env=env)
    except FileNotFoundError:
        proc.send_signal(signal.SIGTERM)
        raise SystemExit("cannot run: command not found {!r}".format(argv[0]))
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return rc, log_path, run_dir


def read_events(log_path):
    rows = []
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        pass
    return rows
