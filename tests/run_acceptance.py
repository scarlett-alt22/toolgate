#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Acceptance runner. Reads cases.json, runs each case, writes runs/acceptance/<ts>/summary.json.

🔴 Three states, and only pass counts:
    pass          — the spec-required behavior was actually measured
    fail          — something else was measured
    unimplemented — **no executor exists for this case yet, i.e. untested**
There is no fourth kind. `unimplemented` deliberately counts neither as passing nor as
failing — it counts as "no evidence", and ALL_PASS requires both fail and unimplemented
to be 0.
Reason, from the 08-07 note: a log that records success once it finishes has no
discriminating power; "couldn't measure" must look different in the artifacts from
"measured and found no problem".

This script does not judge its own success; tests/verify_acceptance.py re-computes
everything independently (spec:392).
"""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402
import exec_attempt  # noqa: E402

TESTS = lib.TESTS
REAL_HOME = lib.real_home()
WRAPPER = lib.WRAPPER
ACC_ROOT = os.path.join(WRAPPER, "runs", "acceptance")

FAKE_CLI = os.path.join(TESTS, "fake_cli.py")
REAL_CLI = "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"

# ★2026-08-08 the decoy credential as ruled by external review (A6 ②).
# **Protocol-wise** it is a valid, secret-looking Bearer; **construction-wise** it is
# public and re-computable: a legit dummy constant + the SHA-256-derived suffix of the
# public phrase `hb-auth-a6-public-decoy-v1`.
# 🔴 Deliberately **not** using any vendor's token prefix (`sk-ant-*` etc.) —
# putting something that looks like a real credential in the repo is a risk in itself,
# even when it's fake.
# ⚠️ The reviewer's stated honesty boundary: given that a Bearer value is inherently an
# opaque string, "syntactically looks like a real token" and "mathematically proven to
# be impossible as valid" cannot both be guaranteed; the safety comes from all three
# together: "public deterministic construction + not a secret + dummy upstream is
# loopback-only".
# 🔴 The dummy constant and hash pinned **by the test side itself** (external review A6b ③).
# Why `plan["dummy_auth_token"]` can't just be trusted: plan and env can be wrong
# together and still be consistent, which would turn this test into "whatever the
# implementation says, I believe". This constant is written **once here and once in
# production**; a mismatch explodes on the spot — that's what turns "both sides agree"
# into an assertion that can fail.
PINNED_DUMMY_LITERAL = "hb-loopback-dummy-v1-public-noncredential"
PINNED_DUMMY_SHA256 = "bb7e4b2f32cd144757ffb95bb5984cdeca501d215b17df561ad46578129debcb"

DECOY_AUTHORIZATION = (
    "Bearer hb-loopback-dummy-v1-public-noncredential.a6-decoy."
    "9553e027002e4aa81ccd170dfb2bdd956110d3a685f570ddab06a28290603227")

# A preflight case should return in milliseconds. 20s is already generous — beyond that
# it is pointlessly waiting somewhere, and pointless waiting is itself a defect
# (spec:355 requires lstat to recognize a FIFO/non-regular and return 78 directly,
# not to read it).
PER_CASE_TIMEOUT = 20


def _run_group(argv, cwd, env, timeout):
    """Run in its own process group; SIGKILL the group on timeout. Return (rc, tail, timed_out).

    Not subprocess.run(timeout=): it only kills the direct child while the grandchild
    still holds the pipe, so capture_output blocks forever (measured: hung 81 minutes
    on 2026-08-08).
    """
    import signal as _sig
    p = subprocess.Popen(argv, cwd=cwd, env=env, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, (out or "")[-300:], False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), _sig.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            out, _ = p.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            out = ""
        return None, (out or "")[-300:], True


def base_profile(workspace, home, origin, sentinel_dir):
    """Field table of spec:222-254. Tests substitute a fake CLI for the real one (pin its own hash)."""
    return {
        "schema_version": 1,
        "profile_id": "read-shadow-test",
        "risk_class": "read_only",
        "workspace": workspace,
        "home": home,
        "model": "claude-haiku-4-5-20251001",
        "timeout_seconds": 120,
        "max_budget_usd": "0.05",
        # ★2026-08-08: acceptance is `loopback_dummy` throughout — the bridge section
        # never executes, so these 89 no longer depend on whether this machine has a
        # login keychain (this morning they did, briefly).
        # ⚠️ Say the cost plainly: the end-to-end path of `prepare_keychain_bridge` is
        # therefore **not in these 89**; its coverage lives in tests/bridge_redgreen.py
        # and the authentication case group in staging.
        "auth_mode": "loopback_dummy",
        # ★2026-08-14: the test topology explicitly disables the sandbox. **Reason:
        # the fixture is not the behavior under test** — fake_cli must write
        # cli-process-evidence.json (pf-ambient-override reads the subprocess's inner
        # environment from it), while the real CLI runs with zero writes (measured in G6).
        # 🔴 Only test builds generated by tests/lib.py may use this: the code constant
        #    pins the exact fake CLI realpath+sha; production builds and any other CLI
        #    are refused. The sandbox itself is covered by seatbelt_six / seatbelt_g6 /
        #    seatbelt_failclosed.
        "sandbox": "disabled",
        "upstream_origin": origin,
        "messages_path": "/v1/messages?beta=true",
        "cli_realpath": FAKE_CLI,
        "cli_sha256": lib.sha256_file(FAKE_CLI),
        "cli_version": "fake-cli/1",
        "permission_template": {
            "defaultMode": "dontAsk",
            "allow": ["Read(//$ATTEMPT_INPUT_RULE/**)"],
            "deny": ["Bash", "Edit", "Write", "mcp__claude-in-chrome__*"],
        },
        "mcp_config": {"mcpServers": {}},
        # 🔴 Must be the canonical hash of the Read definition fake_cli actually sends.
        # A placeholder would make the upper bound never match, and then "blocked
        # correctly" can't be distinguished from "blocks everything" — the positive
        # cases wouldn't prove the gate is selective.
        "approved_tools": [{"name": "Read", "definition_sha256": read_definition_sha256()}],
        "required_actions": [
            {"id": "sentinel_read", "tool": "Read",
             "path": "$ATTEMPT_INPUT_ABS/sentinel.txt", "min_success": 1}
        ],
        "output_schema_sha256": "0" * 64,
        "state_invariants": ["heartbeat_log", "armed_marker", "armed_events",
                             "nudge_state", "item_state", "heartbeat_room"],
    }


def read_definition_sha256():
    """Canonical definition hash of READ_TOOL in fake_cli — must be byte-identical with inspector's algorithm."""
    import hashlib
    sys.path.insert(0, TESTS)
    import fake_cli
    canon = json.dumps(fake_cli.READ_TOOL, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


# ── Upper-bound executor ──────────────────────────────────────────────
# case_id -> what this request looks like. Deliberately constructing illegal requests —
# that is what is under test.
UB_STEPS = {
    # ★2026-08-08 A6 ②: body is **field-identical** with the positive case; the only
    # change is the outbound Authorization value. The positive arm (ub-read-correct-hash)
    # uses the same pinned fake CLI and the same tools shape, so only this one variable
    # differs between the two arms — the more a counter-example looks like the positive
    # case, the stronger it is.
    "ub-decoy-authorization":   {"tools": "read"},
    "ub-empty-tools":           {"tools": "empty"},
    "ub-read-correct-hash":     {"tools": "read"},
    "ub-extra-bash":            {"tools": "extra_bash"},
    "ub-extra-write":           {"tools": "extra_write"},
    "ub-duplicate-read":        {"tools": "duplicate_read"},
    "ub-same-name-diff-schema": {"tools": "same_name_diff_schema"},
    "ub-missing-tools-field":   {"tools": "missing_tools"},
    "ub-tools-not-array":       {"tools": "tools_not_array"},
    "ub-tool-elem-not-object":  {"tools": "elem_not_object"},
    "ub-name-absent":           {"tools": "name_absent"},
    "ub-name-empty":            {"tools": "name_empty"},
    "ub-name-not-string":       {"tools": "name_not_string"},
    "ub-body-bad-json":         {"tools": "bad_json"},
    "ub-body-root-array":       {"tools": "root_array"},
    "ub-json-duplicate-tools-key": {"tools": "duplicate_tools_key"},
    "ub-json-nan":                 {"tools": "json_nan"},
    "ub-json-infinity":            {"tools": "json_infinity"},
    "ub-json-nested-duplicate-key": {"tools": "nested_duplicate_key"},
    # ★2026-08-09 A8 §3: non-bool `stream`. The counter-example hugs the positive case
    # (`ub-empty-tools`, field-identical), adding only this one field.
    "ub-stream-not-bool":       {"tools": "empty", "stream_override": "true"},
    "ub-stream-null":           {"tools": "empty", "stream_override": None},
    "ub-body-oversize":         {"tools": "oversize", "pad_bytes": 3 * 1024 * 1024},
    "ub-wrong-method":          {"tools": "empty", "method": "GET"},
    "ub-wrong-path":            {"tools": "empty", "path_override": "/v1/wrong"},
    "ub-wrong-query":           {"tools": "empty", "path_override": "/v1/messages?beta=false"},
    "ub-wrong-model":           {"tools": "empty", "model_override": "claude-opus-5"},
    "ub-wrong-capability-path": {"tools": "empty", "_bad_cap": True},
}

# These four cases' expected is an **attempt-level** verdict ("must not success"),
# but the terminal protocol wasn't implemented yet → honestly record as untested.
# Inspector-level evidence is still collected into detail.
UB_NEEDS_TERMINAL = {"ub-redirect-302", "ub-inspector-dies",
                     "ub-log-truncated", "ub-response-incomplete"}


def run_upper_bound_case(case, ctx):
    import signal as _sig
    cid = case["id"]
    if cid in UB_NEEDS_TERMINAL:
        # 2026-08-08 afternoon: the terminal protocol is now implemented, so these four
        # are no longer "untestable".
        return exec_attempt.run_upper_attempt_case(case, ctx)
    step = UB_STEPS.get(cid)
    if step is None:
        return ("unimplemented", {"reason": f"no request builder written for {cid}"})

    tmp = os.path.join(ctx["work"], "cases", cid)
    os.makedirs(tmp, exist_ok=True)
    ws = os.path.join(tmp, "ws"); os.makedirs(ws, exist_ok=True)
    home = os.path.join(tmp, "home"); os.makedirs(home, exist_ok=True)

    prof = base_profile(ws, home, ctx["primary"].origin, tmp)
    prof_path = os.path.join(tmp, "profile.json")
    json.dump(prof, open(prof_path, "w"), ensure_ascii=False, indent=1)
    man = {"read-shadow-test": {"path": prof_path, "sha256": lib.sha256_file(prof_path)}}
    man_path = os.path.join(tmp, "manifest.json")
    json.dump(man, open(man_path, "w"), indent=1)

    sandbox = os.path.join(tmp, "sandbox")
    lib.build_sandbox(sandbox, man_path)

    rc, tail, hung = _run_group(["/usr/bin/python3", os.path.join(sandbox, "preflight.py"),
                                 "read-shadow-test"],
                                cwd=sandbox, env=dict(os.environ), timeout=PER_CASE_TIMEOUT)
    if rc != 0:
        return ("fail", {"reason": "upper-bound case's preflight should have passed but was rejected", "rc": rc, "tail": tail})

    arts = lib.read_attempt_artifacts(os.path.join(sandbox, "runs"))
    adir = os.path.join(sandbox, "runs", arts[-1]["dir"])
    plan = json.load(open(os.path.join(adir, "plan.json")))

    insp_log = os.path.join(adir, "inspector.jsonl")
    insp = subprocess.Popen(["/usr/bin/python3", os.path.join(sandbox, "inspector.py"),
                             plan["policy_path"], insp_log],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, start_new_session=True)
    port = None
    deadline = time.time() + 15
    while time.time() < deadline:
        line = insp.stdout.readline()
        if line.startswith("READY"):
            port = int(line.split()[1].split(":")[1])
            break
    if port is None:
        insp.kill()
        return ("fail", {"reason": "inspector did not start"})

    cap = "deadbeef" * 4 if step.get("_bad_cap") else plan["capability_path"]
    scenario = {"steps": [{k: v for k, v in step.items() if not k.startswith("_")}],
                "result": "probe"}
    sc_path = os.path.join(tmp, "scenario.json")
    json.dump(scenario, open(sc_path, "w"))

    before = ctx["primary"].stats()["requests"]
    env = dict(os.environ)
    env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{port}/{cap}"
    # The upper-bound group doesn't go through hb-run (it starts inspector + fake CLI
    # directly), so the harness must play that hb-run step itself: hand the approved
    # dummy credential from plan to the stub. Without it, the new credential gate
    # would 403 every upper-bound case that **should have forwarded** — that wouldn't
    # be the gate judging wrongly; this test path would just be missing a step.
    if plan.get("auth_mode") == "loopback_dummy":
        # First match what plan says against the test-pinned value byte-for-byte, then
        # use **the test side's copy**. The order is deliberate: even if plan is
        # corrupted, the constant entering the subprocess is always the known one.
        got = plan.get("dummy_auth_token") or ""
        if hashlib.sha256(got.encode()).hexdigest() != PINNED_DUMMY_SHA256:
            return ("fail", {"reason": "plan's dummy credential does not match the test-side pinned constant",
                             "plan_sha256_prefix": hashlib.sha256(got.encode()).hexdigest()[:12]})
        env["ANTHROPIC_AUTH_TOKEN"] = PINNED_DUMMY_LITERAL
        env.pop("ANTHROPIC_API_KEY", None)   # alternate identities must not leak in
    if cid == "ub-decoy-authorization":
        # 🔴 The ANTHROPIC_AUTH_TOKEN in the environment **stays the approved dummy**
        # (just set above); only the outbound header value is swapped — external review
        # explicitly requires this: the stub must not self-check or invent its own
        # expectations; it just fires blindly. So the decoy arm proves "the inspector
        # blocked it", not "the stub decided not to send".
        env["HB_FAKE_DECOY_AUTH"] = DECOY_AUTHORIZATION
    _run_group(["/usr/bin/python3", FAKE_CLI, "--scenario", sc_path,
                "--model", prof["model"], "--output-format", "json"],
               cwd=ws, env=env, timeout=PER_CASE_TIMEOUT)
    after = ctx["primary"].stats()["requests"]

    try:
        os.killpg(os.getpgid(insp.pid), _sig.SIGTERM)
        insp.wait(timeout=10)
    except Exception:
        pass

    rows = []
    if os.path.exists(insp_log):
        for line in open(insp_log):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except Exception:
                    pass
    reqs = [r for r in rows if r.get("event") == "request"]

    expected = case["expected"]
    checks = {}
    checks["exactly_one_request_logged"] = len(reqs) == 1
    if reqs:
        r = reqs[0]
        if expected == "forward":
            checks["decision_forward"] = r.get("decision") == "forward"
            checks["upstream_delta_1"] = (after - before) == 1
            checks["has_forward_started_at"] = bool(r.get("forward_started_at"))
        else:
            checks["decision_block"] = r.get("decision") == "block"
            checks["has_block_reason"] = bool(r.get("block_reason"))
            # spec:362 — for a blocked request the upstream delta must be 0
            checks["upstream_delta_0"] = (after - before) == 0
            # spec:306 — a blocked request must not have forward_started_at
            checks["no_forward_started_at"] = r.get("forward_started_at") is None
    # 🔴 No trace of authentication headers may appear in the log
    blob = json.dumps(rows, ensure_ascii=False).lower()
    checks["no_auth_in_log"] = not any(k in blob for k in ("x-api-key", "authorization", "bearer "))

    status = "pass" if all(checks.values()) else "fail"
    return (status, {"expected": expected, "checks": checks,
                     "upstream_delta": after - before,
                     "decision": reqs[0].get("decision") if reqs else None,
                     "block_reason": reqs[0].get("block_reason") if reqs else None,
                     "requests_logged": len(reqs)})


# ── Preflight mutation table: case_id -> how to break a good profile ──
def _set(p, path, val):
    cur = p
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = val


def _set_real_disabled(p, _ctx):
    p["auth_mode"] = "real_keychain_bridge"
    p["upstream_origin"] = "https://api.anthropic.com"
    p["sandbox"] = "disabled"


def _set_real_cli_dummy_disabled(p, _ctx):
    if not os.path.isfile(REAL_CLI):
        raise RuntimeError(f"real CLI fixture missing: {REAL_CLI}")
    version = subprocess.run([REAL_CLI, "--version"], capture_output=True,
                             text=True, timeout=20).stdout.strip()
    p.update({"sandbox": "disabled", "auth_mode": "loopback_dummy",
              "cli_realpath": os.path.realpath(REAL_CLI),
              "cli_sha256": lib.sha256_file(REAL_CLI),
              "cli_version": version})


MUTATIONS = {
    "pf-valid":              lambda p, ctx: None,
    "pf-missing-sandbox":    lambda p, ctx: p.pop("sandbox"),
    "pf-sandbox-invalid":    lambda p, ctx: _set(p, ["sandbox"], "optional"),
    "pf-real-disabled":      _set_real_disabled,
    "pf-real-cli-dummy-disabled": _set_real_cli_dummy_disabled,
    "pf-bad-json":           "RAW:{ this is not json",
    "pf-root-type":          "RAW:[1,2,3]",
    "pf-missing-key":        lambda p, ctx: p.pop("model"),
    "pf-unknown-key":        lambda p, ctx: _set(p, ["surprise"], "extra"),
    "pf-wrong-type":         lambda p, ctx: _set(p, ["timeout_seconds"], "120"),
    "pf-illegal-mode":       lambda p, ctx: _set(p, ["permission_template", "defaultMode"], "acceptEdits"),
    "pf-blank-array-elem":   lambda p, ctx: _set(p, ["permission_template", "deny"], ["Bash", "  "]),
    "pf-dup-array-elem":     lambda p, ctx: _set(p, ["permission_template", "deny"], ["Bash", "Bash"]),
    "pf-empty-array":        lambda p, ctx: _set(p, ["permission_template", "deny"], []),

    "pf-tool-missing":       lambda p, ctx: _set(p, ["approved_tools"], []),
    "pf-tool-dup":           lambda p, ctx: _set(p, ["approved_tools"], [p["approved_tools"][0], dict(p["approved_tools"][0])]),
    "pf-tool-not-string":    lambda p, ctx: _set(p, ["approved_tools"], [{"name": 7, "definition_sha256": "0" * 64}]),
    "pf-model-wrong-type":   lambda p, ctx: _set(p, ["model"], 5),
    "pf-timeout-zero":       lambda p, ctx: _set(p, ["timeout_seconds"], 0),
    "pf-timeout-negative":   lambda p, ctx: _set(p, ["timeout_seconds"], -1),
    "pf-timeout-over":       lambda p, ctx: _set(p, ["timeout_seconds"], 301),
    "pf-budget-wrong-type":  lambda p, ctx: _set(p, ["max_budget_usd"], 0.05),

    "pf-rule-single-slash":  lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(/$ATTEMPT_INPUT_RULE/**)"]),
    "pf-rule-read-star":     lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(*)"]),
    "pf-rule-relative":      lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(relative/path/**)"]),
    "pf-rule-dotdot":        lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(//$ATTEMPT_INPUT_RULE/../**)"]),
    "pf-rule-var-residue":   lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(//~/stuff/**)"]),
    "pf-rule-malformed":     lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(//abc/**"]),
    "pf-rule-unknown-tool":  lambda p, ctx: _set(p, ["permission_template", "allow"], ["Frobnicate(//$ATTEMPT_INPUT_RULE/**)"]),
    "pf-rule-too-broad-glob": lambda p, ctx: _set(p, ["permission_template", "allow"], ["Read(//Users/**)"]),

    # ★2026-08-08 external review A6's main counter-example. Why it's stronger than
    # `https://example.com`: the old `host.startswith("127.0.0.1")` gate **would treat
    # it as loopback and forward**, while what the inspector actually connects to is
    # `urlsplit(...).hostname` = 192.0.2.1 (public, plaintext HTTP).
    # Field-identical with the positive case except upstream_origin — the more a
    # counter-example looks like the positive case, the stronger it is.
    "pf-dummy-origin-userinfo": lambda p, ctx: _set(p, ["upstream_origin"],
                                                   "http://127.0.0.1@192.0.2.1:9"),

    "pf-workspace-eq-home":  lambda p, ctx: _set(p, ["home"], p["workspace"]),
    "pf-home-uncontrolled":  lambda p, ctx: _set(p, ["home"], REAL_HOME),
    "pf-cli-realpath-drift": lambda p, ctx: _set(p, ["cli_realpath"], "/usr/bin/true"),
    "pf-cli-hash-drift":     lambda p, ctx: _set(p, ["cli_sha256"], "f" * 64),
    "pf-cli-version-drift":  lambda p, ctx: _set(p, ["cli_version"], "9.9.9 (nope)"),
}

# These don't change the profile's content; they change the profile file's shape / environment
FILE_SHAPE_CASES = {
    "pf-profile-symlink",
    "pf-fifo", "pf-devfd", "pf-not-regular", "pf-not-canonical",
    "pf-ambient-override",
}

# 🔴 Honestly record "untested", not "passed": the settings/MCP snapshots are created by
# preflight itself inside a random attempt directory; the harness cannot fabricate
# "that path is already a symlink" or "it was changed between spawn and re-check" from
# outside. Testing those would need an injection point in the wrapper, which equals
# opening a hole in the gate.
# The correct approach is O_EXCL creation + hash re-checks before/after spawn (already
# implemented in preflight), but **implemented is not verified** — these four cells stay
# unimplemented until a hook into a real attempt directory exists.
NEEDS_SNAPSHOT_HOOK = {
    "pf-settings-symlink", "pf-mcp-symlink", "pf-settings-toctou", "pf-mcp-toctou",
    # Same for sentinel: preflight now creates its own sentinel with O_EXCL inside a
    # 0700 fresh attempt directory; you can't pre-plant a symlink from outside. Can't
    # fabricate the scenario → record untested, not passed.
    "pf-sentinel-symlink",
}


def run_preflight_case(case, ctx):
    """Run one preflight case. Return (status, detail)."""
    cid = case["id"]
    tmp = os.path.join(ctx["work"], "cases", cid)
    os.makedirs(tmp, exist_ok=True)
    ws = os.path.join(tmp, "ws"); os.makedirs(ws, exist_ok=True)
    home = os.path.join(tmp, "home"); os.makedirs(home, exist_ok=True)
    inp = os.path.join(tmp, "input"); os.makedirs(inp, exist_ok=True)
    with open(os.path.join(inp, "sentinel.txt"), "w") as f:
        f.write("SENTINEL-" + uuid.uuid4().hex + "\n")

    # ★2026-08-08 A6 ③: in dummy mode the dedicated home **already contains** an old
    # real bridge. External review specifically wants the shape "most like an old real
    # bridge" — an absolute symlink, not a plain directory.
    # 🔴 It points at a synthetic directory owned by the harness itself, **never at the
    # real ~/Library/Keychains**: what this case verifies is "presence means reject";
    # a real keychain need not — and must not — be present.
    preset_link = None
    if cid == "pf-dummy-home-has-keychains":
        synthetic = os.path.join(tmp, "synthetic-keychains")
        os.makedirs(synthetic, exist_ok=True)
        with open(os.path.join(synthetic, "canary.txt"), "w") as f:
            f.write("PUBLIC-CANARY-not-a-keychain\n")
        os.makedirs(os.path.join(home, "Library"), exist_ok=True)
        preset_link = os.path.join(home, "Library", "Keychains")
        if not os.path.lexists(preset_link):
            os.symlink(synthetic, preset_link)
        preset_before = (os.lstat(preset_link).st_ino, os.readlink(preset_link))

    prof = base_profile(ws, home, ctx["primary"].origin, inp)
    mut = MUTATIONS.get(cid)
    if cid == "pf-dummy-home-has-keychains":
        mut = lambda p, ctx: None      # profile not mutated: this case's variable is on the filesystem

    prof_path = os.path.join(tmp, "profile.json")
    if isinstance(mut, str) and mut.startswith("RAW:"):
        open(prof_path, "w").write(mut[4:])
    elif callable(mut):
        mut(prof, ctx)
        json.dump(prof, open(prof_path, "w"), ensure_ascii=False, indent=1)
    elif cid in FILE_SHAPE_CASES:
        json.dump(prof, open(prof_path, "w"), ensure_ascii=False, indent=1)
        if cid == "pf-profile-symlink":
            real = prof_path + ".real"
            os.rename(prof_path, real)
            os.symlink(real, prof_path)
        elif cid == "pf-fifo":
            os.remove(prof_path)
            os.mkfifo(prof_path)
        elif cid == "pf-not-regular":
            os.remove(prof_path)
            os.makedirs(prof_path)
        elif cid == "pf-not-canonical":
            prof_path = os.path.join(tmp, ".", "ws", "..", "profile.json")
        elif cid == "pf-devfd":
            prof_path = "/dev/fd/0"
    elif cid in NEEDS_SNAPSHOT_HOOK:
        # 2026-08-08 afternoon: now genuinely race that window instead of declaring it
        # unfabricable. Losing the race records unimplemented — "couldn't win the race"
        # and "won the race and it blocked" must stay distinguishable.
        return exec_attempt.run_snapshot_race_case(case, ctx)
    else:
        return ("unimplemented", {"reason": f"no mutator written for {cid}"})

    # The harness's own manifest: pin profile_id to this case's file + hash.
    # ⚠️ No abspath: pf-not-canonical is exactly about "a non-canonical path lying in
    # the manifest". The 2026-08-08 first version abspath'd here, which normalized it
    # before the test — preflight would of course find nothing wrong; the test had
    # erased the very defect under test.
    man_path_value = prof_path if os.path.isabs(prof_path) else os.path.abspath(prof_path)
    man = {"read-shadow-test": {"path": man_path_value,
                                "sha256": lib.sha256_file(prof_path)}}
    man_path = os.path.join(tmp, "manifest.json")
    json.dump(man, open(man_path, "w"), indent=1)

    sandbox = os.path.join(tmp, "sandbox")
    rewrite = lib.build_sandbox(sandbox, man_path)

    env = dict(os.environ)
    if cid == "pf-ambient-override":
        env.update({"HB_INSPECTOR_PORT": "19999", "HB_TIMEOUT_SECS": "999",
                    "ANTHROPIC_BASE_URL": "http://127.0.0.1:1", "CLAUDE_CONFIG_DIR": "/tmp/nope"})

    before = ctx["primary"].stats()["requests"]
    runs_dir = os.path.join(sandbox, "runs")
    # The preflight group hits preflight.py directly: this group tests "the gate before
    # the model starts"; running the whole hb-run would mix inspector/CLI issues in,
    # and a red result wouldn't say whose it is.
    pf = os.path.join(sandbox, "preflight.py")
    if not os.path.exists(pf):
        return ("fail", {"reason": "no preflight.py in the sandbox"})

    # 🔴 Must start an independent process group and kill by group. Learned 2026-08-08:
    #    `subprocess.run(timeout=)` only kills the direct child (zsh), while the one
    #    blocked on the FIFO is the grandchild preflight.py, which still holds the
    #    stdout pipe → capture_output never sees EOF, and the whole acceptance hung for
    #    81 minutes at case 31. "Timed out but can't reap" is the same class of thing
    #    spec §E guards against.
    rc, tail, timed_out = _run_group(["/usr/bin/python3", pf, "read-shadow-test"],
                                     cwd=sandbox, env=env, timeout=PER_CASE_TIMEOUT)
    if timed_out:
        # A hang = failing to reject where it should, counts as fail; the fact of the
        # hang stays in the artifacts.
        return ("fail", {"reason": f"hb-run did not exit within {PER_CASE_TIMEOUT}s (whole group killed)",
                         "expected": case["expected"], "hung": True})

    after = ctx["primary"].stats()["requests"]
    arts = lib.read_attempt_artifacts(runs_dir)

    expected = case["expected"]
    checks = {}
    checks["rc"] = (rc == 0) if expected == "pass" else (rc == 78)
    checks["mock_delta_zero"] = (after - before) == 0
    checks["one_attempted"] = any(a["attempted_count"] == 1 for a in arts)
    if expected == "rc78":
        # See cases.json's _refinement_20260808: finished(config_rejected) only holds
        # for rejected cases.
        checks["one_finished"] = any(a["finished_count"] == 1 for a in arts)
        checks["outcome_config_rejected"] = any(
            (a.get("outcome") == "config_rejected") for a in arts)
        if case.get("expected_error_type"):
            checks["error_type"] = any(
                (a.get("terminal") or {}).get("error_type") == case["expected_error_type"]
                for a in arts)
    else:
        checks["no_premature_finished"] = all(a["finished_count"] == 0 for a in arts)

    if preset_link is not None:
        # 🔴 A rejection must **not** conveniently modify/delete/follow an object the
        # caller already had. "Reject" and "reject plus clean up the scene" are two
        # different things; the latter means an error state could induce this gate to
        # delete things.
        try:
            after_id = (os.lstat(preset_link).st_ino, os.readlink(preset_link))
        except OSError as e:
            after_id = f"gone:{type(e).__name__}"
        checks["preset_link_untouched"] = (after_id == preset_before)

    status = "pass" if all(checks.values()) else "fail"
    return (status, {
        "rc": rc, "expected": expected, "checks": checks,
        "mock_delta": after - before,
        "artifacts": [{k: a[k] for k in ("dir", "events_present", "terminal_present",
                                         "attempted_count", "finished_count", "outcome")} for a in arts],
        "manifest_rewrites": {k: v.get("manifest_rewrites") for k, v in rewrite["files"].items()},
        "stderr_tail": tail,
    })


def main():
    # Second-granularity directory names would make two gates in the same second share an
    # artifact tree; adding the pid closes this round's identity.
    ts = time.strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}"
    out_dir = os.path.join(ACC_ROOT, ts)
    os.makedirs(out_dir, exist_ok=True)
    work = os.path.join(out_dir, "work")
    os.makedirs(work, exist_ok=True)

    # Point latest at **this round** from the start. If the harness crashes midway, the
    # verifier will see this round missing a summary and refuse; the old version only
    # swapped the symlink at the end, so after a crash acceptance.sh would grab the
    # previous round's summary for its "independent re-computation" (run_rc would catch
    # it in the end, but the evidence identity would already be wrong).
    latest = os.path.join(ACC_ROOT, "latest")
    if os.path.islink(latest) or os.path.exists(latest):
        try:
            os.remove(latest)
        except IsADirectoryError:
            shutil.rmtree(latest)
    os.symlink(out_dir, latest)

    cases_doc = json.load(open(os.path.join(TESTS, "cases.json")))
    state_before = lib.snapshot_state()

    primary = lib.Mock("primary").start(work)
    secondary = lib.Mock("secondary").start(work)
    ctx = {"work": work, "primary": primary, "secondary": secondary}

    results = []
    try:
        for group in cases_doc["groups"]:
            for case in group["cases"]:
                cid = case["id"]
                t0 = time.time()
                case_root = os.path.join(work, "cases", cid)
                os.makedirs(case_root, exist_ok=True)
                mock_before = {"primary": primary.stats(), "secondary": secondary.stats()}
                if cid == "pf-ambient-override":
                    # ★2026-08-08: this one no longer takes the preflight-only path.
                    # The defect it verifies lives in hb-run's subprocess-spawning
                    # section; hitting only preflight.py would never reach it.
                    status, detail = exec_attempt.run_ambient_case(case, ctx)
                elif group["id"] == "preflight":
                    status, detail = run_preflight_case(case, ctx)
                elif group["id"] == "upper_bound":
                    status, detail = run_upper_bound_case(case, ctx)
                elif group["id"] == "lower_bound":
                    status, detail = exec_attempt.run_lower_bound_case(case, ctx)
                elif group["id"] == "terminal":
                    status, detail = exec_attempt.run_terminal_case(case, ctx)
                elif group["id"] == "auth_phase_drift":
                    status, detail = exec_attempt.run_phase_drift_case(case, ctx)
                else:
                    status, detail = ("unimplemented", {
                        "reason": f"{group['id']} executor not implemented — inspector/terminal protocol not rewritten to spec",
                        "blocks_on": "the fail-closed implementation in preflight.py / inspector.py / hb-run.sh"})
                mock_after = {"primary": primary.stats(), "secondary": secondary.stats()}
                observation = {
                    "schema_version": 1,
                    "case_id": cid,
                    "mock_before": {role: {k: snap[k] for k in (
                        "role", "requests", "real_origin_attempts")}
                                    for role, snap in mock_before.items()},
                    "mock_after": {role: {k: snap[k] for k in (
                        "role", "requests", "real_origin_attempts")}
                                   for role, snap in mock_after.items()},
                }
                with open(os.path.join(case_root, "harness-observation.json"), "w") as f:
                    json.dump(observation, f, ensure_ascii=False, indent=1)
                result = {
                    "case_id": cid, "group": group["id"], "spec_line": case["spec_line"],
                    "expected": case["expected"], "status": status,
                    "seconds": round(time.time() - t0, 2), "detail": detail,
                    "artifact_root": os.path.relpath(case_root, out_dir),
                }
                # The index is generated last and embedded in the summary; the verifier
                # re-walks/re-hashes and trusts neither detail nor the runner's status.
                # The index itself is not written into the case tree, avoiding the
                # self-hash paradox.
                result["artifact_index"] = lib.artifact_index(case_root)
                results.append(result)
    finally:
        primary_stats = primary.stats()
        secondary_stats = secondary.stats()
        primary.stop()
        secondary.stop()

    state_after = lib.snapshot_state()
    changed = lib.diff_state(state_before, state_after)

    counts = {}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    summary = {
        "schema_version": 1,
        "started_ts": ts,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cases_file_sha256": lib.sha256_file(os.path.join(TESTS, "cases.json")),
        "total_cases": len(results),
        "counts": counts,
        "all_pass": counts.get("fail", 0) == 0 and counts.get("unimplemented", 0) == 0,
        "anthropic_requests": primary_stats["real_origin_attempts"] + secondary_stats["real_origin_attempts"],
        "mock_primary_requests": primary_stats["requests"],
        "mock_secondary_requests": secondary_stats["requests"],
        "state_before": state_before,
        "state_after": state_after,
        "state_changed": changed,
        "results": results,
    }
    json.dump(summary, open(os.path.join(out_dir, "summary.json"), "w"),
              ensure_ascii=False, indent=1)

    print(f"ANTHROPIC_REQUESTS={summary['anthropic_requests']}")
    print(f"cases={summary['total_cases']} " +
          " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    print(f"state_changed={changed if changed else 'none'}")
    print("ALL_PASS" if summary["all_pass"] else "NOT_ALL_PASS")
    print(f"summary: {os.path.join(out_dir, 'summary.json')}")
    return 0 if summary["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
