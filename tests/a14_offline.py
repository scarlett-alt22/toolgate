#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A14 offline red/green checks; never invokes sandbox-exec or a live service.

Checks:
  * the launcher retains the exact bytes it read even if the path is replaced;
  * each of the three verify phases detects sandbox-profile drift;
  * finish accepts applied=true only when ready/exec/start hashes all equal plan;
  * a started-hash mismatch closes as 78/config_rejected.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile


TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
FIXTURE = os.path.join(TESTS, "fixtures", "finish", "base")
sys.path.insert(0, TESTS)
import lib  # noqa: E402
import run_acceptance as RA  # noqa: E402


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PF = load_module("a14_preflight", os.path.join(WRAPPER, "preflight.py"))
LAUNCH = load_module("a14_launcher", os.path.join(WRAPPER, "sandbox_launcher.py"))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def check_read_once():
    with tempfile.TemporaryDirectory(prefix="a14-read-once-") as root:
        path = os.path.join(root, "policy.sb")
        original = b"(version 1)\n(deny default)\n"
        replacement = b"(version 1)\n(allow default)\n"
        with open(path, "wb") as f:
            f.write(original)
        held = LAUNCH.read_policy_once(path)
        os.rename(path, path + ".old")
        with open(path, "wb") as f:
            f.write(replacement)
        assert held == original and held != open(path, "rb").read()
        assert hashlib.sha256(held).hexdigest() == hashlib.sha256(original).hexdigest()
    return "launcher_read_once_path_replacement_keeps_verified_bytes"


def check_disabled_launcher_handshake():
    """Exercise the attempted/started split without invoking Seatbelt."""
    with tempfile.TemporaryDirectory(prefix="a14-disabled-launch-") as root:
        plan = {
            "attempt_id": os.path.basename(root), "attempt_dir": root,
            "sandbox_mode": "disabled", "hashes": {"sandbox_profile": None},
        }
        plan_path = os.path.join(root, "plan.json")
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan, f)
        open(os.path.join(root, "events.jsonl"), "w").close()
        proc = subprocess.run(
            [sys.executable, os.path.join(WRAPPER, "sandbox_launcher.py"),
             "--plan", plan_path, "--timeout", "5", "--", "/usr/bin/true"],
            input=b"", capture_output=True, timeout=20)
        rows = read_jsonl(os.path.join(root, "events.jsonl"))
        names = [row.get("event") for row in rows]
        assert proc.returncode == 0 and proc.stdout == b""
        assert names == ["sandbox_disabled", "cli_exec_attempted", "cli_started"]
        started = rows[-1]
        assert started.get("inner_bootstrap_handshake") is True
    return "disabled_launcher_attempted_then_inner_started_handshake"


def check_disabled_build_identity():
    """Same fake profile: test build accepts preflight, production build rejects."""
    with tempfile.TemporaryDirectory(prefix="a14-build-identity-") as raw_root:
        root = os.path.realpath(raw_root)
        ws = os.path.join(root, "ws")
        home = os.path.join(root, "home")
        inp = os.path.join(root, "input")
        for path in (ws, home, inp):
            os.makedirs(path)
        profile = RA.base_profile(ws, home, "http://127.0.0.1:43127", inp)
        profile_path = os.path.join(root, "profile.json")
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile, f)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump({"read-shadow-test": {
                "path": profile_path, "sha256": sha(profile_path)}}, f)

        test_wrapper = os.path.join(root, "test-wrapper")
        lib.build_sandbox(test_wrapper, manifest_path)
        test_proc = subprocess.run(
            [sys.executable, os.path.join(test_wrapper, "preflight.py"), "read-shadow-test"],
            cwd=test_wrapper, capture_output=True, text=True, timeout=30)
        assert test_proc.returncode == 0

        production_wrapper = os.path.join(root, "production-wrapper")
        lib.build_sandbox(production_wrapper, manifest_path, production_build=True)
        prod_proc = subprocess.run(
            [sys.executable, os.path.join(production_wrapper, "preflight.py"),
             "read-shadow-test"],
            cwd=production_wrapper, capture_output=True, text=True, timeout=30)
        assert prod_proc.returncode == 78
        runs = os.path.join(production_wrapper, "runs")
        attempts = [os.path.join(runs, name) for name in os.listdir(runs)
                    if os.path.isdir(os.path.join(runs, name))]
        assert len(attempts) == 1
        adir = attempts[0]
        with open(os.path.join(adir, "terminal.json"), encoding="utf-8") as f:
            terminal = json.load(f)
        assert terminal["outcome"] == "config_rejected"
        assert terminal["error_type"] == "sandbox_disabled_test_build_required"
    return ["test_build_exact_fake_disabled_preflight_control",
            "production_build_disabled_profile_rc78"]


def phase_plan(root):
    paths = {}
    for name in ("settings", "mcp", "policy", "sentinel", "cli", "sandbox_profile"):
        path = os.path.join(root, name)
        with open(path, "wb") as f:
            f.write((name + "-A14\n").encode())
        paths[name] = path
    attempt_id = os.path.basename(root)
    missing_bridge = os.path.join(root, "home", "Library", "Keychains")
    plan = {
        "attempt_id": attempt_id,
        "settings_path": paths["settings"], "mcp_path": paths["mcp"],
        "policy_path": paths["policy"], "sentinel_path": paths["sentinel"],
        "cli_realpath": paths["cli"],
        "sandbox_mode": "required", "sandbox_profile_path": paths["sandbox_profile"],
        "hashes": {name: sha(path) for name, path in paths.items()},
        "keychain_bridge": {"mode": "loopback_dummy",
                            "link_must_not_exist": missing_bridge,
                            "topology_ok": True},
    }
    plan_path = os.path.join(root, "plan.json")
    with open(plan_path, "w", encoding="utf-8") as f:
        json.dump(plan, f)
    open(os.path.join(root, "events.jsonl"), "w").close()
    return plan_path, paths["sandbox_profile"]


def check_three_phases():
    names = []
    for phase in PF.VERIFY_PHASES:
        with tempfile.TemporaryDirectory(prefix=f"a14-{phase}-") as root:
            plan_path, sandbox_path = phase_plan(root)
            assert PF.verify_snapshot(plan_path, phase) == 0
            with open(sandbox_path, "ab") as f:
                f.write(b"DRIFT\n")
            assert PF.verify_snapshot(plan_path, phase) == 78
            rows = read_jsonl(os.path.join(root, "events.jsonl"))
            tampered = [r for r in rows if r.get("event") == "snapshot_tampered"
                        and r.get("phase") == phase]
            assert len(tampered) == 1
            assert any("sandbox_profile:" in item for item in tampered[0]["mismatches"])
            names.append(f"sandbox_profile_drift_{phase}_rc78")
    return names


def finish_arm(mismatch):
    with tempfile.TemporaryDirectory(prefix="a14-finish-") as root:
        adir = os.path.join(root, "attempt")
        shutil.copytree(FIXTURE, adir)
        plan_path = os.path.join(adir, "plan.json")
        with open(plan_path, encoding="utf-8") as f:
            plan = json.load(f)
        profile = os.path.join(adir, "profile.sb")
        with open(profile, "wb") as f:
            f.write(b"(version 1)\n(deny default)\n")
        profile_sha = sha(profile)
        plan["sandbox_mode"] = "required"
        plan["sandbox_profile_path"] = profile
        plan["hashes"]["sandbox_profile"] = profile_sha
        with open(plan_path, "w", encoding="utf-8") as f:
            json.dump(plan, f, ensure_ascii=False, indent=1)

        events_path = os.path.join(adir, "events.jsonl")
        rows = read_jsonl(events_path)
        ready = {"event": "sandbox_ready", "attempt_id": plan["attempt_id"],
                 "ts": "2026-08-14T00:00:00", "profile_sha256": profile_sha}
        insert_at = next(i for i, row in enumerate(rows)
                         if row.get("event") == "cli_exec_attempted")
        rows.insert(insert_at, ready)
        for row in rows:
            if row.get("event") in ("cli_exec_attempted", "cli_started"):
                row["profile_sha256"] = ("f" * 64 if mismatch
                                          and row.get("event") == "cli_started"
                                          else profile_sha)
        write_jsonl(events_path, rows)

        proc = subprocess.run(
            [sys.executable, os.path.join(WRAPPER, "finish.py"), adir, "0", "0", "143",
             os.path.join(adir, "model.json")],
            capture_output=True, text=True, timeout=20)
        with open(os.path.join(adir, "terminal.json"), encoding="utf-8") as f:
            terminal = json.load(f)
        if mismatch:
            assert proc.returncode == 78
            assert terminal["outcome"] == "config_rejected"
            assert terminal["exit_code"] == 78
            assert terminal["sandbox"]["applied"] is False
            assert terminal["sandbox"]["hashes_match"] is False
            return "terminal_rejects_started_policy_hash_mismatch"
        assert proc.returncode == 0
        assert terminal["outcome"] == "success"
        assert terminal["sandbox"]["applied"] is True
        assert terminal["sandbox"]["hashes_match"] is True
        assert terminal["sandbox"]["profile_sha256"] == profile_sha
        return "terminal_accepts_exact_ready_exec_start_hash_chain"


def main():
    checks = []
    checks.append(check_read_once())
    checks.append(check_disabled_launcher_handshake())
    checks.extend(check_disabled_build_identity())
    checks.extend(check_three_phases())
    checks.append(finish_arm(False))
    checks.append(finish_arm(True))
    for name in checks:
        print("A14_OFFLINE_OK", name)
    print(f"A14_OFFLINE {len(checks)}/{len(checks)} ALL_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
