#!/usr/bin/env python3
"""Independent oracle for pf-ambient-override.

This intentionally does not read terminal.ambient_overrides_cleared.  Its only
inputs are the hostile fixture plus evidence created inside the spawned fake
CLI and fake inspector processes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from urllib.parse import urlsplit


# 🔴 Pinned independently by this oracle, **never read from plan** (A6b ①).
# Written once here and once in production's `preflight.DUMMY_TOKEN`: a mismatch means
# one side was changed.
PINNED_DUMMY_SHA256 = "bb7e4b2f32cd144757ffb95bb5984cdeca501d215b17df561ad46578129debcb"


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict):
        raise AssertionError(f"{path}: root must be object")
    return doc


def sha_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def require_absent(evidence: dict, keys: list[str], role: str) -> None:
    env = evidence.get("environment")
    if not isinstance(env, dict):
        raise AssertionError(f"{role}: missing direct environment evidence")
    bad = []
    for key in keys:
        row = env.get(key)
        if not isinstance(row, dict) or "present" not in row:
            raise AssertionError(f"{role}: no observation for {key}")
        if row["present"] is not False:
            bad.append(key)
    if bad:
        raise AssertionError(f"{role}: hostile ambient reached spawned process: {bad}")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("attempt_dir")
    p.add_argument("--fixture", default=os.path.join(os.path.dirname(__file__),
                                                      "fixtures", "ambient-overrides.json"))
    p.add_argument("--fake-cli", default=os.path.join(os.path.dirname(__file__),
                                                       "fixtures", "fake_cli.py"))
    p.add_argument("--fake-inspector", default=os.path.join(os.path.dirname(__file__),
                                                             "fixtures", "fake_inspector.py"))
    args = p.parse_args()
    fixture = read_json(args.fixture)
    cli = read_json(os.path.join(args.attempt_dir, "cli-process-evidence.json"))
    inspector = read_json(os.path.join(args.attempt_dir,
                                       "inspector-process-evidence.json"))

    if cli.get("role") != "cli" or inspector.get("role") != "inspector":
        raise AssertionError("process roles missing or swapped")
    if not isinstance(cli.get("pid"), int) or not isinstance(inspector.get("pid"), int):
        raise AssertionError("spawned-process pid evidence missing")
    if cli["pid"] == inspector["pid"]:
        raise AssertionError("CLI and inspector evidence came from the same process")
    if cli.get("writer_sha256") != sha_file(args.fake_cli):
        raise AssertionError("CLI evidence was not written by the pinned fake CLI bytes")
    if inspector.get("writer_sha256") != sha_file(args.fake_inspector):
        raise AssertionError("inspector evidence was not written by the pinned fake inspector bytes")

    require_absent(cli, fixture["must_be_absent_in_cli"], "cli")
    require_absent(inspector, fixture["must_be_absent_in_inspector"], "inspector")

    # ★2026-08-08: ANTHROPIC_AUTH_TOKEN is no longer asserted "absent" — under
    # loopback_dummy, hb-run legitimately injects it from the hash-locked plan. The
    # assertion now checks three things, stronger than absence: it is present, it is
    # exactly the approved public constant, and it is not the hostile ambient value.
    approved = fixture.get("must_equal_approved_in_cli") or {}
    if "ANTHROPIC_AUTH_TOKEN" in approved:
        # External review's (A6b ①) ruling: comparing only "CLI env == plan value !=
        # hostile" is **not enough** — plan and env can be wrong together and still be
        # consistent, which would reduce this oracle to confirming the implementation
        # is self-consistent. So the hash is **pinned by this oracle itself**, never
        # read from plan.
        plan_for_auth = read_json(os.path.join(args.attempt_dir, "plan.json"))
        if plan_for_auth.get("auth_mode") != "loopback_dummy":
            raise AssertionError("plan.auth_mode is not loopback_dummy")
        plan_token = plan_for_auth.get("dummy_auth_token") or ""
        if hashlib.sha256(plan_token.encode()).hexdigest() != PINNED_DUMMY_SHA256:
            raise AssertionError("plan dummy credential does not match the pinned constant")

        row = cli["environment"].get("ANTHROPIC_AUTH_TOKEN")
        if not isinstance(row, dict) or row.get("present") is not True:
            raise AssertionError("cli: approved dummy credential was not delivered at all")
        hostile_hash = hashlib.sha256(
            fixture["ambient"]["ANTHROPIC_AUTH_TOKEN"].encode()).hexdigest()
        if row.get("value_sha256") == hostile_hash:
            raise AssertionError("cli: hostile ambient ANTHROPIC_AUTH_TOKEN won")
        if row.get("value_sha256") != PINNED_DUMMY_SHA256:
            raise AssertionError(
                "cli: delivered credential is neither the hostile value nor the pinned "
                "dummy constant — provenance unknown")
        # Alternate identities are not allowed in the CLI; credentials must not appear
        # in the inspector (it doesn't need them, and shouldn't have them).
        api_key = cli["environment"].get("ANTHROPIC_API_KEY") or {}
        if api_key.get("present") is not False:
            raise AssertionError("cli: an alternate identity header source is present")
        insp_tok = inspector["environment"].get("ANTHROPIC_AUTH_TOKEN") or {}
        if insp_tok.get("present") is not False:
            raise AssertionError("inspector: credential leaked into the observer process")

    base = cli["environment"].get("ANTHROPIC_BASE_URL")
    if not isinstance(base, dict) or base.get("present") is not True:
        raise AssertionError("cli: controlled ANTHROPIC_BASE_URL missing")
    value = base.get("safe_value")
    if not isinstance(value, str):
        raise AssertionError("cli: loopback base URL was not recorded as safe plaintext")
    u = urlsplit(value)
    if u.scheme != "http" or u.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise AssertionError(f"cli: base URL is not controlled loopback: {value!r}")
    hostile_hash = hashlib.sha256(
        fixture["ambient"]["ANTHROPIC_BASE_URL"].encode()).hexdigest()
    if base.get("value_sha256") == hostile_hash:
        raise AssertionError("cli: hostile ambient ANTHROPIC_BASE_URL won")

    # ★2026-08-08 re-ruling (external review ruling (b)): the old three assertions
    # demanded the port come from explicit_test_only, requested==43138, actual!=43137.
    # That mis-wrote "an optional test injection point" as "every test must go through
    # the injection point" — while the production spec demands the exact opposite:
    # always request 0 and let the kernel pick.
    # `actual != 43137` especially must go: the kernel could theoretically be assigned
    # 43137 by chance; "different port numbers" was never evidence of ambient
    # isolation. The evidence is **no HB_INSPECTOR_PORT in the subprocess environment
    # at all** (already checked by require_absent above) **plus requested==0**.
    listen = inspector.get("listen_port")
    if not isinstance(listen, dict):
        raise AssertionError("inspector: missing listen_port evidence")
    if listen.get("source") != "kernel_default":
        raise AssertionError(
            f"inspector: listen port source must be kernel_default, got {listen.get('source')!r}")
    if listen.get("requested") != 0:
        raise AssertionError(
            f"inspector: production must request port 0, got {listen.get('requested')!r}")
    if listen.get("socket_bound") is not True:
        raise AssertionError("inspector: kernel-assigned port must come from a real bind")
    actual = listen.get("actual")
    if not isinstance(actual, int) or not 1 <= actual <= 65535:
        raise AssertionError("inspector: invalid actual listen port")

    # plan.json is no longer "check if present": this cell runs the full hb-run, and no
    # plan means it never got to spawn.
    plan_path = os.path.join(args.attempt_dir, "plan.json")
    if not os.path.exists(plan_path):
        raise AssertionError("attempt has no plan.json — hb-run never reached spawn")
    plan = read_json(plan_path)
    cap = plan.get("capability_path")
    if not isinstance(cap, str) or not cap:
        raise AssertionError("plan.json has no capability_path")
    if not u.path.startswith("/" + cap):
        raise AssertionError("cli: loopback base URL is not scoped to this attempt capability")
    if u.port != actual:
        raise AssertionError("cli base URL port and spawned inspector READY port differ")

    print("PASS pf-ambient-override: verified spawned CLI/inspector process environments")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, KeyError) as exc:
        print(f"FAIL pf-ambient-override: {exc}", file=sys.stderr)
        raise SystemExit(1)
