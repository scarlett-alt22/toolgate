# -*- coding: utf-8 -*-
"""Runner for the lower-bound and terminal case groups.

Difference from the upper-bound group: upper bounds are **per-request** properties, so
firing one shot at the inspector alone suffices; lower bounds and terminal are
**whole-round** properties, requiring the full hb-run so finish.py can recompute from
events.
"""
import hashlib
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lib  # noqa: E402

TESTS = lib.TESTS
WRAPPER = lib.WRAPPER
FAKE_CLI = os.path.join(TESTS, "fake_cli.py")

# The **full** stdout of the most recent hb-run (run_hb's return value is tail-truncated).
LAST_HB_OUTPUT = {"text": ""}


def read_definition_sha256():
    import fake_cli
    canon = json.dumps(fake_cli.READ_TOOL, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canon).hexdigest()


def schema_hash(keys):
    return hashlib.sha256(json.dumps(sorted(keys), separators=(",", ":")).encode()).hexdigest()


def build_case(ctx, cid, cli_path=None, cli_version="fake-cli/1", overrides=None,
               extra_rewrites=None, case_root=None):
    """Assemble a runnable attempt environment. Returns (sandbox, profile_id)."""
    tmp = case_root or os.path.join(ctx["work"], "cases", cid)
    os.makedirs(tmp, exist_ok=True)
    ws = os.path.join(tmp, "ws"); os.makedirs(ws, exist_ok=True)
    home = os.path.join(tmp, "home"); os.makedirs(home, exist_ok=True)
    cli = cli_path or FAKE_CLI

    prof = {
        "schema_version": 1, "profile_id": cid, "risk_class": "read_only",
        "workspace": os.path.realpath(ws), "home": os.path.realpath(home),
        "model": "claude-haiku-4-5-20251001", "timeout_seconds": 60,
        "max_budget_usd": "0.05",
        # ★2026-08-08: keep in sync with run_acceptance.base_profile — acceptance always
        # goes loopback_dummy, the bridge section doesn't run at all, so this batch of
        # cases doesn't depend on the machine's login keychain.
        "auth_mode": "loopback_dummy",
        # ★2026-08-14: same as run_acceptance.base_profile — the test topology explicitly
        # disables the sandbox, because fake_cli writes cli-process-evidence.json while
        # the real CLI runs with zero writes (G6).
        # Only test build + exact fake CLI realpath/sha may be used; production build
        # always denies.
        "sandbox": "disabled",
        "upstream_origin": ctx["primary"].origin,
        "messages_path": "/v1/messages?beta=true",
        "cli_realpath": os.path.realpath(cli), "cli_sha256": lib.sha256_file(cli),
        "cli_version": cli_version,
        "permission_template": {"defaultMode": "dontAsk",
                                "allow": ["Read(//$ATTEMPT_INPUT_RULE/**)"],
                                "deny": ["Bash", "Edit", "Write", "mcp__claude-in-chrome__*"]},
        "mcp_config": {"mcpServers": {}},
        "approved_tools": [{"name": "Read", "definition_sha256": read_definition_sha256()}],
        "required_actions": [{"id": "sentinel_read", "tool": "Read",
                              "path": "$ATTEMPT_INPUT_ABS/sentinel.txt", "min_success": 1}],
        "output_schema_sha256": schema_hash(["ok", "task"]),
        "state_invariants": ["heartbeat_log", "armed_marker", "armed_events",
                             "nudge_state", "item_state", "heartbeat_room"],
    }
    prof.update(overrides or {})
    ppath = os.path.join(tmp, "profile.json")
    json.dump(prof, open(ppath, "w"), ensure_ascii=False, indent=1)
    man = {cid: {"path": ppath, "sha256": lib.sha256_file(ppath)}}
    mpath = os.path.join(tmp, "manifest.json")
    json.dump(man, open(mpath, "w"), indent=1)

    sandbox = os.path.join(tmp, "sandbox")
    lib.build_sandbox(sandbox, mpath, extra_rewrites=extra_rewrites,
                      test_cli_path=cli)
    import shutil
    shutil.copy(os.path.join(WRAPPER, "finish.py"), sandbox)
    return sandbox, cid


def run_hb(sandbox, profile_id, task="probe task", variant=None, timeout=90,
           kill_after=None, signal_after=None, sig=signal.SIGTERM):
    """Run one hb-run. Returns (rc, tail, hung)."""
    env = dict(os.environ)
    # ★2026-08-08: the stub's knobs moved from env vars to a file.
    # Triggered by a production-side P0 fix — hb-run now spawns the CLI with `env -i` +
    # allowlist, so the environment never reaches the stub.
    # But this isn't "accommodating the fix": **if production doesn't pass it down, the
    # tests must not rely on production to smuggle it down for them** — otherwise the
    # tested path isn't the real path. The file lives in that case's own workspace
    # (hb-run `cd`s into it), so cases stay mutually isolated.
    ws = os.path.join(os.path.dirname(sandbox), "ws")
    if os.path.isdir(ws):
        with open(os.path.join(ws, ".hb_fake_scenario.json"), "w") as _f:
            json.dump({"variant": variant or "happy",
                       "second_origin": os.environ.get("HB_SECOND_ORIGIN", "")}, _f)
    argv = ["/bin/zsh", os.path.join(sandbox, "hb-run.sh"), profile_id, task]
    p = subprocess.Popen(argv, cwd=sandbox, env=env, text=True,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)
    if kill_after is not None:
        time.sleep(kill_after)
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif signal_after is not None:
        time.sleep(signal_after)
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except ProcessLookupError:
            pass
    try:
        out, _ = p.communicate(timeout=timeout)
        # ⚠️ The return value carries only the last 400 chars (for detail), but the **full
        # output must be kept**: the pre_inspector / pre_cli phase verdicts print at the
        # **start** of stdout, and tail-truncation would cut them off — making "those two
        # phases never ran" and "I truncated them away" indistinguishable.
        LAST_HB_OUTPUT["text"] = out or ""
        return p.returncode, (out or "")[-400:], False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        LAST_HB_OUTPUT["text"] = ""
        return None, "", True


def latest_attempt(sandbox):
    runs = os.path.join(sandbox, "runs")
    arts = lib.read_attempt_artifacts(runs)
    return arts[-1] if arts else None


# ── lower bound ───────────────────────────────────────────────────────
LB = {
    "lb-happy":                ("happy",              "success"),
    "lb-subset-no-tooluse":    ("no_tooluse",         "obligation_failed"),
    "lb-challenge-no-tooluse": ("challenge_copied",   "not_success"),
    "lb-read-wrong-path":      ("wrong_path",         "not_success"),
    "lb-result-id-mismatch":   ("id_mismatch",        "not_success"),
    "lb-result-is-error":      ("result_error",       "not_success"),
    "lb-result-no-challenge":  ("result_no_challenge", "not_success"),
    "lb-permission-denial":    ("permission_denial",  "not_success"),
    "lb-challenge-not-first":  ("challenge_not_first", "not_success"),
    "lb-final-json-bad":       ("final_json_bad",     "not_success"),
    # ⚠️ Produce this false with "incomplete response", **never by touching the operator's
    # six state files** — those are live ledgers the operator is using; no acceptance
    # step writes them (state_invariants only reads hashes).
    "lb-postcondition-false":  ("upstream_incomplete", "not_success"),
}


AMBIENT_FIXTURE = os.path.join(TESTS, "fixtures", "ambient-overrides.json")
AMBIENT_FAKE_CLI = os.path.join(TESTS, "fixtures", "fake_cli.py")
AMBIENT_FAKE_INSP = os.path.join(TESTS, "fixtures", "fake_inspector.py")
VERIFY_AMBIENT = os.path.join(TESTS, "verify_ambient.py")


def run_ambient_case(case, ctx):
    """pf-ambient-override — assert that hostile ambient **never reaches the truly spawned
    child processes**.

    ★2026-08-08 rewrite (external review found the old version hollow). The old version's
    two flaws:
      ① it only exercised `preflight.py` — **it never went through hb-run's actual launch
         path** — and that's where the defect lived;
      ② it asserted on terminal's self-reported field `ambient_overrides_cleared`, i.e. it
         tested self-reporting, not facts.
    Now: run the full hb-run, let trusted stubs record their own environ **inside their own
    child processes** as evidence, and let an independent oracle judge
    (`verify_ambient.py`, which explicitly doesn't read that self-reported field).
    The stub and the oracle were written by another agent — not the one who fixed
    production.
    """
    import shutil
    cid = case["id"]
    # Ask the stub its own version; don't hardcode it: it should follow stub changes,
    # hardcoding turns it into a fake contract needing manual sync.
    ver = subprocess.run([AMBIENT_FAKE_CLI, "--version"], text=True,
                         capture_output=True, timeout=30).stdout.strip()
    sandbox, pid = build_case(ctx, cid, cli_path=AMBIENT_FAKE_CLI, cli_version=ver)
    # Replace the production inspector with the trusted fake inspector: this cell must
    # observe the inspector child process's own environment, so it has to record it
    # itself. READY line format matches production's.
    shutil.copy(AMBIENT_FAKE_INSP, os.path.join(sandbox, "inspector.py"))

    with open(AMBIENT_FIXTURE) as f:
        fx = json.load(f)
    saved = {k: os.environ.get(k) for k in fx["ambient"]}
    os.environ.update(fx["ambient"])
    try:
        rc, tail, hung = run_hb(sandbox, pid, timeout=90)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    art = latest_attempt(sandbox)
    if not art:
        return ("fail", {"reason": "no attempt artifacts", "rc": rc, "tail": tail, "hung": hung})
    # lib.read_attempt_artifacts's "dir" is the basename, not the full path
    adir = os.path.join(sandbox, "runs", art["dir"])
    p = subprocess.run(["/usr/bin/python3", VERIFY_AMBIENT, adir,
                        "--fixture", AMBIENT_FIXTURE,
                        "--fake-cli", AMBIENT_FAKE_CLI,
                        "--fake-inspector", AMBIENT_FAKE_INSP],
                       text=True, capture_output=True, timeout=60)
    if p.returncode == 0:
        return ("pass", {"oracle": (p.stdout or "").strip()[:300]})
    return ("fail", {"oracle_rc": p.returncode,
                     "oracle": ((p.stdout or "") + (p.stderr or "")).strip()[:600],
                     "rc": rc, "tail": tail})


# ── phase drift (A6b's two definitions, item 6 of A8 §"minimum closing order") ──
# 🔴 These two used to have **static definitions only, no runner** — A8's words: "they
#    still have only the static definitions you wrote". A case with no runner looks
#    identical to a case that doesn't exist in the acceptance artifacts.
#
# What's proven is the same thing at two positions: in dummy mode, "no Library/Keychains
# inside the dedicated HOME" is **not** a one-time pre-run check — it must hold at all
# three phases. So the trusted stub plants an absolute symlink at each point:
#   · after the inspector process starts but before it prints READY (pre_cli should catch)
#   · after the CLI has run a protocol byte-identical to the positive control, before it
#     exits (post_cli should catch it)
# to see whether the gate holds.
# ⚠️ Both barriers are **structural** (the READY line, the CLI exit protocol), never a
# sleep race.
PHASE_DRIFT_ORACLE = os.path.join(TESTS, "verify_phase_drift.py")
DRIFT_FAKE_CLI = os.path.join(TESTS, "fixtures", "fake_cli.py")
DRIFT_FAKE_INSP = os.path.join(TESTS, "fixtures", "fake_inspector.py")


def _drift_fixture_root(tmp):
    """A fixture tree with a **marker**. The stub refuses any modification outside the
    marked tree."""
    root = os.path.realpath(tmp)
    with open(os.path.join(root, ".hb-auth-acceptance-root"), "w") as f:
        f.write("marked fixture root — drift actors refuse to write outside this tree\n")
    synth = os.path.join(root, "synthetic-Keychains")
    os.makedirs(synth, exist_ok=True)
    with open(os.path.join(synth, "login.keychain-db"), "wb") as f:
        f.write(b"FIXTURE-NOT-A-REAL-KEYCHAIN-v1\n")
    return root, synth


def run_phase_drift_case(case, ctx):
    import shutil
    cid = case["id"]
    before_ready = cid.endswith("before-cli-spawn")

    ver = subprocess.run([DRIFT_FAKE_CLI, "--version"], text=True,
                         capture_output=True, timeout=30).stdout.strip()

    # after_spawn first runs a **drift-free positive control**. Same CLI, same profile
    # builder, same three-request protocol; the only thing missing is the pre-exit symlink.
    # The control must earn success from its own terminal, not self-certify off the
    # fixture's completed_* fields.
    control = None
    if not before_ready:
        control_root = os.path.join(ctx["work"], "cases", cid, "positive-control")
        c_sandbox, c_pid = build_case(ctx, cid, cli_path=DRIFT_FAKE_CLI,
                                      cli_version=ver, case_root=control_root)
        c_home = os.path.realpath(os.path.join(control_root, "home"))
        c_root, _c_synth = _drift_fixture_root(control_root)
        with open(os.path.join(c_home, ".hb-auth-acceptance-after-spawn.json"), "w") as f:
            # Presence of the file enables the protocol; when=never makes both mutation
            # barriers no-ops.
            json.dump({"action": "none", "when": "never", "fixture_root": c_root,
                       "target": os.path.join(c_home, "Library", "Keychains")}, f)
        c_before = ctx["primary"].stats()["requests"]
        c_rc, c_tail, c_hung = run_hb(c_sandbox, c_pid, timeout=90)
        c_after = ctx["primary"].stats()["requests"]
        c_art = latest_attempt(c_sandbox)
        if not c_art:
            return ("fail", {"reason": "after_spawn no-drift positive control produced no attempt artifacts",
                             "rc": c_rc, "tail": c_tail, "hung": c_hung})
        c_adir = os.path.join(c_sandbox, "runs", c_art["dir"])
        with open(os.path.join(c_adir, "hb-run.out"), "w") as _f:
            _f.write(LAST_HB_OUTPUT["text"])
        control = {"attempt_dir": c_adir, "wrapper_rc": c_rc,
                   "mock_delta": c_after - c_before}

    sandbox, pid = build_case(ctx, cid, cli_path=DRIFT_FAKE_CLI, cli_version=ver)
    tmp = os.path.dirname(sandbox)
    home = os.path.realpath(os.path.join(tmp, "home"))
    root, synth = _drift_fixture_root(tmp)
    target = os.path.join(home, "Library", "Keychains")

    # The initial state must be "absent" — that's a precondition of the dummy branch, not
    # the behavior under test.
    initial_absent = not os.path.lexists(target)

    if before_ready:
        shutil.copy(DRIFT_FAKE_INSP, os.path.join(sandbox, "inspector.py"))
        with open(os.path.join(home, ".hb-auth-acceptance-before-ready.json"), "w") as f:
            json.dump({"mode": "create_absent", "fixture_root": root,
                       "target": target, "replacement": synth}, f)
    else:
        with open(os.path.join(home, ".hb-auth-acceptance-after-spawn.json"), "w") as f:
            json.dump({"action": "create_absent_symlink", "when": "before_exit",
                       "fixture_root": root, "target": target,
                       "replacement": synth}, f)

    # ⚠️ target lands inside home, but home is not inside the marked root — the stub only
    # checks "absent" for **target**, and only checks **replacement** is inside the marked
    # root. The before-ready stub checks both, so put home in the same tree too: tmp is
    # the root and home is its subdirectory.
    before_reqs = ctx["primary"].stats()["requests"]
    rc, tail, hung = run_hb(sandbox, pid, timeout=90)
    after_reqs = ctx["primary"].stats()["requests"]

    art = latest_attempt(sandbox)
    if not art:
        return ("fail", {"reason": "no attempt artifacts", "rc": rc, "tail": tail, "hung": hung})
    adir = os.path.join(sandbox, "runs", art["dir"])
    # The two pre_inspector / pre_cli review verdicts print on hb-run's own stdout (only
    # post_cli is redirected into verify.log). Dumped to disk verbatim for the judge to
    # read — the harness does **transport** only, not a word of processing.
    with open(os.path.join(adir, "hb-run.out"), "w") as _f:
        _f.write(LAST_HB_OUTPUT["text"])

    p = subprocess.run(["/usr/bin/python3", PHASE_DRIFT_ORACLE, adir,
                        "--arm", "before_ready" if before_ready else "after_spawn",
                        "--home", home, "--fixture-root", root,
                        "--fake-cli", DRIFT_FAKE_CLI,
                        "--fake-inspector", DRIFT_FAKE_INSP,
                        "--wrapper-rc", str(rc),
                        "--mock-delta", str(after_reqs - before_reqs),
                        "--initial-absent", "1" if initial_absent else "0"]
                       + (["--control-attempt-dir", control["attempt_dir"],
                           "--control-wrapper-rc", str(control["wrapper_rc"]),
                           "--control-mock-delta", str(control["mock_delta"])]
                          if control else []),
                       text=True, capture_output=True, timeout=60)
    if p.returncode == 0:
        return ("pass", {"oracle": (p.stdout or "").strip()[-800:],
                         "mutant_attempt_dir": os.path.relpath(adir, tmp),
                         "control_attempt_dir": (os.path.relpath(control["attempt_dir"], tmp)
                                                 if control else None)})
    return ("fail", {"oracle_rc": p.returncode, "rc": rc,
                     "oracle": ((p.stdout or "") + (p.stderr or "")).strip()[-800:],
                     "tail": tail[-300:] if tail else tail})


def run_lower_bound_case(case, ctx):
    cid = case["id"]
    if cid not in LB:
        return ("unimplemented", {"reason": f"no variant written for {cid}"})
    variant, want = LB[cid]
    sandbox, pid = build_case(ctx, cid)
    before = ctx["primary"].stats()["requests"]
    rc, tail, hung = run_hb(sandbox, pid, variant=variant)
    art = latest_attempt(sandbox)
    if not art or not art["terminal"]:
        return ("fail", {"reason": "no terminal artifacts", "rc": rc, "tail": tail, "hung": hung})
    t = art["terminal"]
    outcome = t.get("outcome")

    checks = {"exactly_one_finished": art["finished_count"] == 1}
    if want == "success":
        checks["outcome_success"] = outcome == "success"
    elif want == "obligation_failed":
        checks["outcome_obligation_failed"] = outcome == "obligation_failed"
    else:
        # The spec only requires "must not be success"
        checks["not_success"] = outcome != "success"
    return ("pass" if all(checks.values()) else "fail",
            {"expected": want, "outcome": outcome, "checks": checks,
             "candidates": t.get("outcome_candidates"),
             "required_actions": t.get("required_actions"),
             "upstream_delta": ctx["primary"].stats()["requests"] - before})


# ── terminal / concurrency ──────────────────────────────────────────
def run_terminal_case(case, ctx):
    cid = case["id"]

    if cid == "tm-blocked-wins":
        bad = os.path.join(TESTS, "bad_cli.py")
        sandbox, pid = build_case(ctx, cid, cli_path=bad, cli_version="bad-cli/1")
        rc, tail, _ = run_hb(sandbox, pid)
        art = latest_attempt(sandbox)
        t = (art or {}).get("terminal") or {}
        checks = {
            "outcome_policy_blocked": t.get("outcome") == "policy_blocked",
            "cli_really_failed": t.get("cli_exit") not in (0, None),
            "blocked_at_least_one": (t.get("blocked_count") or 0) >= 1,
            "exactly_one_finished": (art or {}).get("finished_count") == 1,
        }
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "outcome": t.get("outcome"),
                 "candidates": t.get("outcome_candidates"), "cli_exit": t.get("cli_exit")})

    if cid == "tm-concurrency-20":
        sandbox, pid = build_case(ctx, cid)
        procs = []
        for _ in range(20):
            procs.append(subprocess.Popen(
                ["/bin/zsh", os.path.join(sandbox, "hb-run.sh"), pid, "probe"],
                cwd=sandbox, env={**os.environ, "HB_FAKE_VARIANT": "happy"},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True))
        for p in procs:
            try:
                p.wait(timeout=180)
            except subprocess.TimeoutExpired:
                p.kill()
        arts = lib.read_attempt_artifacts(os.path.join(sandbox, "runs"))
        dirs = {a["dir"] for a in arts}
        ids = {a["attempt_id"] for a in arts if a["attempt_id"]}
        bad_lines = sum(1 for a in arts for e in a["events"] if e.get("_unparseable"))
        checks = {"twenty_dirs": len(dirs) == 20,
                  "twenty_unique_ids": len(ids) == 20,
                  "no_interleaved_lines": bad_lines == 0,
                  "each_one_finished": all(a["finished_count"] == 1 for a in arts)}
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "dirs": len(dirs), "ids": len(ids),
                 "finished_counts": sorted({a["finished_count"] for a in arts})})

    finished_variants = {
        "tm-finished-normal":   dict(variant="happy"),
        "tm-finished-clifail":  dict(variant="cli_nonzero"),
        "tm-finished-timeout":  dict(variant="sleep", overrides={"timeout_seconds": 2}),
        "tm-finished-sigint":   dict(variant="sleep", signal_after=3, sig=signal.SIGINT),
        "tm-finished-sigterm":  dict(variant="sleep", signal_after=3, sig=signal.SIGTERM),
    }
    if cid in finished_variants:
        spec = dict(finished_variants[cid])
        overrides = spec.pop("overrides", None)
        sandbox, pid = build_case(ctx, cid, overrides=overrides)
        run_hb(sandbox, pid, **spec)
        art = latest_attempt(sandbox)
        checks = {"exactly_one_finished": (art or {}).get("finished_count") == 1,
                  "terminal_present": bool((art or {}).get("terminal_present"))}
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "outcome": ((art or {}).get("terminal") or {}).get("outcome"),
                 "finished_count": (art or {}).get("finished_count")})

    if cid == "tm-finished-configfail":
        sandbox, pid = build_case(ctx, cid, overrides={"timeout_seconds": 0})
        rc, tail, _ = run_hb(sandbox, pid)
        art = latest_attempt(sandbox)
        t = (art or {}).get("terminal") or {}
        checks = {"rc78": rc == 78,
                  "exactly_one_finished": (art or {}).get("finished_count") == 1,
                  "outcome_config_rejected": t.get("outcome") == "config_rejected",
                  "request_count_zero": t.get("request_count") == 0}
        return ("pass" if all(checks.values()) else "fail", {"checks": checks, "rc": rc})

    if cid == "tm-abandoned-recovery":
        # In the sandbox, rewrite the staleness threshold from 900s to 0s — this is a
        # **sandbox constant rewrite**, recorded in build_sandbox's report, not an env-var
        # switch for production.
        sandbox, pid = build_case(ctx, cid, extra_rewrites=[("stale_after_seconds=900",
                                                             "stale_after_seconds=0")])
        run_hb(sandbox, pid, variant="sleep", kill_after=3)   # SIGKILL: reaches no trap
        arts1 = lib.read_attempt_artifacts(os.path.join(sandbox, "runs"))
        open_before = [a for a in arts1
                       if a["finished_count"] == 0
                       and not any(e.get("event") == "abandoned" for e in a["events"])]
        run_hb(sandbox, pid, variant="happy")                 # the next launch should backfill it
        arts2 = lib.read_attempt_artifacts(os.path.join(sandbox, "runs"))
        ab = [a for a in arts2 if any(e.get("event") == "abandoned" for e in a["events"])]
        multi = [a for a in arts2
                 if sum(1 for e in a["events"] if e.get("event") == "abandoned") > 1]
        checks = {"had_open_attempt": len(open_before) >= 1,
                  "recovered_to_abandoned": len(ab) >= 1,
                  "exactly_one_abandoned_each": not multi}
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "open_before": len(open_before), "abandoned_after": len(ab)})

    if cid == "tm-log-hash-stable":
        sandbox, pid = build_case(ctx, cid)
        run_hb(sandbox, pid, variant="happy")
        art = latest_attempt(sandbox)
        adir = os.path.join(sandbox, "runs", art["dir"])
        insp = os.path.join(adir, "inspector.jsonl")
        h1 = lib.sha256_file(insp)
        time.sleep(1.5)
        h2 = lib.sha256_file(insp)
        t = art["terminal"] or {}
        checks = {"hash_stable_after_stop": h1 == h2 and h1 not in ("ABSENT",),
                  "terminal_recorded_same_hash": t.get("inspector_log_sha256") == h1}
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "h1": h1[:12], "h2": h2[:12],
                 "terminal_hash": str(t.get("inspector_log_sha256"))[:12]})

    if cid == "tm-fields-complete":
        sandbox, pid = build_case(ctx, cid)
        run_hb(sandbox, pid, variant="happy")
        art = latest_attempt(sandbox)
        t = (art or {}).get("terminal") or {}
        required = ["schema_version", "attempt_id", "profile_id", "started_at", "finished_at",
                    "outcome", "exit_code", "error_type", "detail", "trust_boundary",
                    "hashes", "workspace_realpath", "home_realpath", "model",
                    "timeout_seconds", "upstream_origin", "inspector_exit",
                    "request_count", "blocked_count", "requests", "required_actions",
                    "cli_exit", "cli_timed_out", "cli_is_error",
                    "permission_denials_count", "output_schema_ok",
                    "postconditions", "state_invariants"]
        missing = [k for k in required if k not in t]
        return ("pass" if (not missing and t.get("outcome") == "success") else "fail",
                {"missing_fields": missing, "outcome": t.get("outcome"),
                 "checked": len(required)})

    if cid == "tm-state-invariants":
        sandbox, pid = build_case(ctx, cid)
        run_hb(sandbox, pid, variant="happy")
        art = latest_attempt(sandbox)
        t = (art or {}).get("terminal") or {}
        inv = t.get("state_invariants") or {}
        room = (inv.get("after") or {}).get("heartbeat_room_snapshot", {})
        checks = {"five_files_unchanged": inv.get("changed") == [],
                  "room_unmeasured": room.get("status") == "unmeasured",
                  "before_and_after_recorded": bool(inv.get("before")) and bool(inv.get("after"))}
        # 🔴 Only five files were verified; the Room cell forbids guessing the id per
        # spec:337, so it's unmeasured — this case therefore **cannot** claim "all six
        # were verified".
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "changed": inv.get("changed"),
                 "room": room.get("status"),
                 "caveat": "only five files verified; the sixth cell (Room) is unmeasured, not a pass"})

    return ("unimplemented", {"reason": f"no executor written for {cid}"})


# ── upper-bound attempt-level conclusions for those four cases (only measurable after the
# terminal protocol was built) ──────────────────────────────────────────────────
def run_upper_attempt_case(case, ctx):
    """All four cases ask the same question: **if this happened, the round cannot count as
    success.**

    On the morning of 2026-08-08 they recorded "terminal protocol not yet implemented"; by
    the afternoon the protocol existed, and that sentence went stale — a stale reason left
    in place deceives better than no reason at all.
    """
    import threading
    cid = case["id"]
    sandbox, pid = build_case(ctx, cid)
    runs = os.path.join(sandbox, "runs")
    os.makedirs(runs, exist_ok=True)
    env_extra = {}
    variant = "happy"
    stop = threading.Event()
    acted = {"done": False, "how": None}

    if cid == "ub-redirect-302":
        variant = "upstream_redirect"
        env_extra["HB_SECOND_ORIGIN"] = ctx["secondary"].origin
    elif cid == "ub-response-incomplete":
        variant = "upstream_incomplete"

    def watcher():
        deadline = time.time() + 40
        while time.time() < deadline and not stop.is_set():
            for d in (os.listdir(runs) if os.path.isdir(runs) else []):
                log = os.path.join(runs, d, "inspector.jsonl")
                if not os.path.exists(log):
                    continue
                try:
                    rows = [json.loads(l) for l in open(log) if l.strip()]
                except Exception:
                    continue
                if cid == "ub-inspector-dies":
                    ready = [r for r in rows if r.get("event") == "inspector_ready"]
                    if ready and ready[0].get("pid"):
                        try:
                            os.kill(ready[0]["pid"], signal.SIGKILL)
                            acted["done"] = True; acted["how"] = f"SIGKILL inspector pid={ready[0]['pid']}"
                        except ProcessLookupError:
                            pass
                        return
                elif cid == "ub-log-truncated":
                    if len(rows) >= 2:
                        open(log, "w").close()      # truncate to 0 bytes
                        acted["done"] = True; acted["how"] = "truncated inspector log to 0 bytes"
                        return
            time.sleep(0.002)

    need_watcher = cid in ("ub-inspector-dies", "ub-log-truncated")
    th = None
    if need_watcher:
        th = threading.Thread(target=watcher, daemon=True); th.start()

    sec_before = ctx["secondary"].stats()["requests"]
    old = {k: os.environ.get(k) for k in env_extra}
    os.environ.update(env_extra)
    try:
        rc, tail, _ = run_hb(sandbox, pid, variant=variant, timeout=90)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    stop.set()
    if th:
        th.join(timeout=2)
    sec_after = ctx["secondary"].stats()["requests"]

    art = latest_attempt(sandbox)
    t = (art or {}).get("terminal") or {}
    if need_watcher and not acted["done"]:
        return ("unimplemented", {"reason": "missed the window, this round counts as untested", "rc": rc})

    checks = {"not_success": t.get("outcome") != "success",
              "exactly_one_finished": (art or {}).get("finished_count") == 1}
    if cid == "ub-redirect-302":
        checks["second_origin_zero"] = (sec_after - sec_before) == 0
        rows = []
        for a in [art] if art else []:
            log = os.path.join(sandbox, "runs", a["dir"], "inspector.jsonl")
            if os.path.exists(log):
                rows = [l for l in open(log)]
        blob = "".join(rows).lower()
        checks["no_auth_in_log"] = not any(k in blob for k in ("x-api-key", "authorization", "bearer "))
        checks["redirect_not_followed"] = any(
            r.get("upstream_error") == "redirect_not_followed" for r in (t.get("requests") or []))
    return ("pass" if all(checks.values()) else "fail",
            {"checks": checks, "outcome": t.get("outcome"), "acted": acted["how"],
             "second_origin_delta": sec_after - sec_before,
             "candidates": t.get("outcome_candidates")})


# ── snapshot race: symlink preemption and TOCTOU ────────────────────
def _watch_and_plant(runs_dir, plant, stop):
    """Watch the runs/ directory and strike the moment an attempt directory appears.

    This isn't cheating: **this is the window itself**. After preflight creates the
    directory it reads the manifest, validates the schema, and spawns `<cli> --version`
    once — a real several-tens-of-milliseconds gap in between. Whether someone can slip
    in through this window is exactly what spec:355/356 asks.
    """
    seen = set(os.listdir(runs_dir)) if os.path.isdir(runs_dir) else set()
    while not stop.is_set():
        try:
            now = set(os.listdir(runs_dir))
        except FileNotFoundError:
            time.sleep(0.001); continue
        new = [d for d in now - seen if os.path.isdir(os.path.join(runs_dir, d))]
        if new:
            plant(os.path.join(runs_dir, sorted(new)[0]))
            return True
        time.sleep(0.001)
    return False


def run_snapshot_race_case(case, ctx):
    import threading
    cid = case["id"]
    sandbox, pid = build_case(ctx, cid)
    runs = os.path.join(sandbox, "runs")
    os.makedirs(runs, exist_ok=True)

    planted = {"done": False, "how": None}

    def plant_symlink(adir, name):
        snap = os.path.join(adir, "snapshot")
        try:
            os.makedirs(snap, exist_ok=True)
            target = os.path.join(adir, "elsewhere.json")
            open(target, "w").write("{}")
            os.symlink(target, os.path.join(snap, name))
            planted["done"] = True; planted["how"] = f"symlink {name}"
        except FileExistsError:
            planted["how"] = f"{name} already existed, missed the window"

    def plant_sentinel(adir):
        inp = os.path.join(adir, "input")
        try:
            os.makedirs(inp, exist_ok=True)
            target = os.path.join(adir, "fake-sentinel.txt")
            open(target, "w").write("NOT-THE-REAL-CHALLENGE\n")
            os.symlink(target, os.path.join(inp, "sentinel.txt"))
            planted["done"] = True; planted["how"] = "symlink sentinel"
        except FileExistsError:
            planted["how"] = "sentinel already existed, missed the window"

    stop = threading.Event()
    if cid == "pf-settings-symlink":
        fn = lambda a: plant_symlink(a, "settings.json")
    elif cid == "pf-mcp-symlink":
        fn = lambda a: plant_symlink(a, "mcp.json")
    elif cid == "pf-sentinel-symlink":
        fn = plant_sentinel
    else:
        fn = None

    if fn:
        th = threading.Thread(target=_watch_and_plant, args=(runs, fn, stop), daemon=True)
        th.start()
        rc, tail, _ = run_hb(sandbox, pid, variant="happy", timeout=60)
        stop.set(); th.join(timeout=2)
        art = latest_attempt(sandbox)
        t = (art or {}).get("terminal") or {}
        if not planted["done"]:
            return ("unimplemented", {
                "reason": "missed that window, this round counts as untested (not a pass)",
                "how": planted["how"], "rc": rc})
        checks = {"rejected": rc != 0,
                  "not_success": t.get("outcome") != "success",
                  "exactly_one_finished": (art or {}).get("finished_count") == 1}
        return ("pass" if all(checks.values()) else "fail",
                {"checks": checks, "rc": rc, "outcome": t.get("outcome"),
                 "planted": planted["how"]})

    # TOCTOU: wait for plan.json to land (preflight has already verified it), then modify
    # the snapshot before the CLI is spawned
    target_name = "settings.json" if cid == "pf-settings-toctou" else "mcp.json"

    def tamper():
        deadline = time.time() + 30
        while time.time() < deadline:
            for d in (os.listdir(runs) if os.path.isdir(runs) else []):
                plan = os.path.join(runs, d, "plan.json")
                snap = os.path.join(runs, d, "snapshot", target_name)
                if os.path.exists(plan) and os.path.exists(snap):
                    with open(snap, "a") as f:
                        f.write(" ")          # one byte is enough: the hash changes
                    planted["done"] = True
                    planted["how"] = f"tampered {target_name} after plan landed"
                    return
            time.sleep(0.001)

    th = threading.Thread(target=tamper, daemon=True)
    th.start()
    rc, tail, _ = run_hb(sandbox, pid, variant="happy", timeout=60)
    th.join(timeout=2)
    art = latest_attempt(sandbox)
    t = (art or {}).get("terminal") or {}
    if not planted["done"]:
        return ("unimplemented", {"reason": "missed the window, this round counts as untested", "rc": rc})
    tampered_event = any(e.get("event") == "snapshot_tampered"
                         for e in (art or {}).get("events", []))
    checks = {"detected": tampered_event,
              "outcome_config_rejected": t.get("outcome") == "config_rejected",
              "exactly_one_finished": (art or {}).get("finished_count") == 1}
    return ("pass" if all(checks.values()) else "fail",
            {"checks": checks, "rc": rc, "outcome": t.get("outcome"),
             "planted": planted["how"]})
