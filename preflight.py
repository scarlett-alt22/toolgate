#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fail-closed gate before the model starts. v2 — 2026-08-08, rewritten per inspector-review2 §C.

Why it exists (unchanged): measured 2026-08-07, `claude -p` does **not error** on a broken settings file —
exit 0, empty tool list, clean stderr, it runs to completion as usual. "The config is broken" and "the config is fine but strict"
look identical in the artefacts, and the CLI will never tell you which. This gate has to be done by the wrapper itself,
and it has to happen **before** the model process starts.

Changes in v2 relative to v1, all from Codex's second review:
  · The entry point no longer accepts an arbitrary profile path; it takes `profile_id` + a **hard-coded manifest** (pinned by sha256).
    v1 let the caller supply both actual and expected to certify itself — grading its own paper.
  · Closed schema: one field too many, one too few, or a wrong type is rejected; "contains at least" is not accepted.
  · lstat to identify the file type before opening: symlink / FIFO / directory / non-regular are all rejected.
    (On 2026-08-08 the test scaffolding itself tripped on this once: opening a FIFO with no writer directly
      blocked the calling process for 81 minutes. **By the time you've read it and found it wrong, it's too late.**)
  · It owns the attempt lifecycle: create the directory exclusively → write attempted first → on rejection write finished + terminal itself,
    and terminal must contain request_count=0 (verified with a mock counter, not inferred from "there is no model.json").
  · Scrub ambient variables that would change the profile, and record that in terminal.

Exit codes: 0 pass (plan.json written) / 78 config rejected (the model process must not start) / 64 usage error.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import pwd
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

EXIT_OK, EXIT_CONFIG_REJECTED, EXIT_USAGE = 0, 78, 64

WRAPPER_DIR = os.path.dirname(os.path.abspath(__file__))
# 🔴 The manifest location is a code-level constant derived relative to this wrapper; it belongs to the audited TCB (spec:220).
# No environment variable or argument override is provided; a complete snapshot therefore reads its own profiles/manifest.json.
MANIFEST_PATH = os.path.join(WRAPPER_DIR, "profiles", "manifest.json")
# ★2026-08-08, caught by external review: the plan pinned the hashes of three source files but not finish.py —
# so "which finish graded this run" could not be re-checked. It is the implementation of the criteria; it should be pinned more than anything.
WRAPPER_SOURCES = ["hb-run.sh", "preflight.py", "inspector.py", "finish.py",
                   "sandbox_launcher.py"]

# ★2026-08-14 Seatbelt six cells (the pre-production gate set by A12).
# The profile content hash goes into plan/terminal, on a par with settings/mcp/policy:
# "which sandbox rules were used when it ran" must match "which ones were looked at during acceptance".
# 🔴 Missing file = EXIT_CONFIG_REJECTED, not "then skip the sandbox" —
#    degrading to an unsandboxed run is exactly what this gate exists to prevent.
SANDBOX_PROFILE_REL = os.path.join("sandbox", "hb-read.sb")

def real_home():
    """The real user home directory. Uses getpwuid rather than $HOME — these processes are started with `env -i`,
    so there is no HOME in the environment at all; and this value must match "who is running", not be rewritable by the environment."""
    try:
        import pwd
        return pwd.getpwuid(os.getuid()).pw_dir
    except Exception:
        return os.path.expanduser("~")


# ── This deployment's state invariants (the only deployment-specific list in this repo) ──────────────
# After a run, these files must be byte-for-byte unchanged — one of the wrapper's postconditions.
# Replace them with your own; paths are relative to the **real user home directory**.
# 🔴 Empty = check no state = this whole postcondition is switched off, **and it raises no error**.
STATE_INVARIANT_NAMES = [
    ".claude-heartbeat-log.jsonl",
    ".claude-heartbeat-armed.json",
    ".claude-heartbeat-armed-events.jsonl",
    ".claude-nudge-state.json",
    ".claude-heartbeat-items.json",
]

FORBIDDEN_HOME = real_home()
FIXED_MESSAGES_PATH = "/v1/messages?beta=true"

# Ambient variables that change the startup profile are all scrubbed (spec:267)
AMBIENT_TO_CLEAR = [
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
    "CLAUDE_CONFIG_DIR", "HB_TIMEOUT_SECS", "HB_INSPECTOR_PORT",
    "HB_INSPECTOR_LOG", "HB_INSPECTOR_RUN_ID", "HB_INSPECTOR_ALLOWED_TOOLS",
]

# ── auth_mode (★2026-08-08 external review A5 ruling) ────────────────────────────
# Which identity a headless run speaks with must be a **visible declaration in the profile that preflight can reject**,
# not "on by default in the code". Same root as the ambient rule: this CLI does not error on a wrong config,
# and afterwards the artefacts cannot tell whether this run used real or fake credentials.
AUTH_REAL = "real_keychain_bridge"      # goes through the keychain bridge; the CLI uses the real subscription credentials
AUTH_DUMMY = "loopback_dummy"           # no bridge; injects a fixed fake credential; loopback upstream only
AUTH_MODES = (AUTH_REAL, AUTH_DUMMY)

# 🔴 The fake credential is a **public fixed constant**, not a random string.
# External review's reasoning: a random string looks most like a leaked secret, and its origin alone cannot prove it isn't some real token.
# It is public by design; writing it into the plan/logs leaks nothing.
# ⚠️ The honest boundary: prefix and length alone **cannot mathematically prove** it will never be a valid server-side credential
# (unless the vendor commits to a mutually exclusive token grammar). The real guarantee comes from three things together:
# a public fixed constant + nobody can override it + the upstream can only be loopback.
DUMMY_TOKEN = "hb-loopback-dummy-v1-public-noncredential"

# The upstream in real mode is a **code-level allowlist**; a profile cannot extend it.
REAL_ORIGIN_ALLOWLIST = ("https://api.anthropic.com",)

# ``sandbox=disabled`` is not a profile capability.  Production source keeps
# this marker false and therefore rejects every disabled profile.  The test
# builder rewrites these three exact literals only in its private wrapper copy;
# no environment variable, argv flag, or profile field can grant the identity.
TEST_BUILD_SANDBOX_DISABLED = False
TEST_BUILD_FAKE_CLI_REALPATH = ""
TEST_BUILD_FAKE_CLI_SHA256 = ""

PROFILE_SCHEMA = {
    "schema_version": int, "profile_id": str, "risk_class": str,
    "workspace": str, "home": str, "model": str,
    "timeout_seconds": int, "max_budget_usd": str,
    "auth_mode": str,
    # ★2026-08-14 Seatbelt. The closed schema works both ways (one too many or one too few is rejected),
    # so every profile must state required / disabled **explicitly** —
    # which is exactly what we want: whether the sandbox is on should not depend on an invisible default.
    "sandbox": str,
    "upstream_origin": str, "messages_path": str,
    "cli_realpath": str, "cli_sha256": str, "cli_version": str,
    "permission_template": dict, "mcp_config": dict,
    "approved_tools": list, "required_actions": list,
    "output_schema_sha256": str, "state_invariants": list,
}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
# The approved allow grammar, and **only this one** (spec:239/256)
ALLOW_RULE = re.compile(r"^Read\(//([^()]+)/\*\*\)$")
PLACEHOLDER_ABS = "$ATTEMPT_INPUT_ABS"
PLACEHOLDER_RULE = "$ATTEMPT_INPUT_RULE"

# The three closing phases of the snapshot re-check. The names go into events and terminal; finish.py judges completeness by them.
VERIFY_PHASES = ("pre_inspector", "pre_cli", "post_cli")

_ATTEMPT = {"dir": None, "id": None, "started": None, "profile_id": None,
            "ambient_cleared": [], "keychain_bridge": None}


# ── Artefacts ─────────────────────────────────────────────────────────
def _append_event(kind, **fields):
    if not _ATTEMPT["dir"]:
        return
    rec = {"event": kind, "attempt_id": _ATTEMPT["id"],
           "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), **fields}
    with open(os.path.join(_ATTEMPT["dir"], "events.jsonl"), "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _write_terminal(outcome, exit_code, error_type, detail, extra=None):
    """spec:312-324. The rejection path must also leave a complete terminal, with request_count explicitly 0."""
    if not _ATTEMPT["dir"]:
        return
    doc = {
        "schema_version": 1,
        "attempt_id": _ATTEMPT["id"],
        "profile_id": _ATTEMPT["profile_id"],
        "started_at": _ATTEMPT["started"],
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "outcome": outcome,
        "exit_code": exit_code,
        "error_type": error_type,
        "detail": detail,
        "trust_boundary": "same-uid processes are inside the TCB; "
                          "this does not resist a hostile same-uid injector",
        "ambient_overrides_cleared": _ATTEMPT["ambient_cleared"],
        "request_count": 0,
        "blocked_count": 0,
        "wrapper_source_sha256": {
            n: _sha256_regular(os.path.join(WRAPPER_DIR, n)) for n in WRAPPER_SOURCES
        },
        # The rejection path must also hand over the bridge evidence **already collected** (external review A4 §2):
        # the bridge is a side effect performed before the CLI, and on rejection you need to know what it looked like even more.
        # Take it as far as it got — None means its turn hasn't come yet; a partial dict shows which step it stopped at.
        "keychain_bridge": _ATTEMPT["keychain_bridge"],
    }
    if extra:
        doc.update(extra)
    with open(os.path.join(_ATTEMPT["dir"], "terminal.json"), "w") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    _append_event("finished", outcome=outcome, exit_code=exit_code)


def reject(msg, error_type="config_rejected"):
    print(f"REJECT {msg}", file=sys.stderr)
    _write_terminal("config_rejected", EXIT_CONFIG_REJECTED, error_type, msg)
    sys.exit(EXIT_CONFIG_REJECTED)


# ── File types ────────────────────────────────────────────────────────
def _lstat_regular(path, what):
    """spec:265 — lstat to identify the file type first, then decide whether to open it."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        reject(f"{what} does not exist: {path}")
    except OSError as e:
        reject(f"{what} lstat failed: {path} ({type(e).__name__})")
    if stat.S_ISLNK(st.st_mode):
        reject(f"{what} is a symlink, refusing to follow: {path}")
    if stat.S_ISFIFO(st.st_mode):
        reject(f"{what} is a FIFO: {path} (open would block; identify the type before reading)")
    if stat.S_ISDIR(st.st_mode):
        reject(f"{what} is a directory, not a file: {path}")
    if not stat.S_ISREG(st.st_mode):
        reject(f"{what} is not a regular file: {path}")
    if st.st_uid != os.getuid():
        reject(f"{what} is not owned by the current user: {path}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        reject(f"{what} is group/other writable: {path}")
    return st


def _sha256_regular(path):
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode):
            return "NOT_REGULAR"
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return "ABSENT"


def _read_regular(path, what):
    _lstat_regular(path, what)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st2 = os.fstat(fd)
        if not stat.S_ISREG(st2.st_mode):
            reject(f"{what} is not a regular file after fstat: {path}")
        return os.read(fd, 8 * 1024 * 1024)
    finally:
        os.close(fd)


def _canonical_dir(path, what):
    if not os.path.isabs(path):
        reject(f"{what} must be an absolute path: {path}")
    if path != os.path.normpath(path):
        reject(f"{what} is not canonical (contains . or .. or extra slashes): {path}")
    try:
        st = os.lstat(path)
    except OSError:
        reject(f"{what} does not exist: {path}")
    if stat.S_ISLNK(st.st_mode):
        reject(f"{what} is a symlink: {path}")
    if not stat.S_ISDIR(st.st_mode):
        reject(f"{what} is not a directory: {path}")
    real = os.path.realpath(path)
    if real != path:
        reject(f"{what} realpath does not match the declaration: declared {path}, actual {real}")
    return real


# ── Section validators ────────────────────────────────────────────────
def check_schema(profile):
    if not isinstance(profile, dict):
        reject(f"profile root is not an object, it is {type(profile).__name__}")
    got, want = set(profile), set(PROFILE_SCHEMA)
    if got - want:
        reject(f"profile has unknown fields (closed schema): {sorted(got - want)}")
    if want - got:
        missing = want - got
        reject(f"profile is missing fields: {sorted(missing)}",
               "sandbox_missing" if missing == {"sandbox"} else "config_rejected")
    for k, t in PROFILE_SCHEMA.items():
        v = profile[k]
        if t is int and isinstance(v, bool):
            reject(f"{k} is a bool, not an int")
        if not isinstance(v, t):
            reject(f"{k} has the wrong type: wanted {t.__name__}, got {type(v).__name__}")
    if profile["schema_version"] != 1:
        reject(f"schema_version only supports 1, got {profile['schema_version']}")
    if profile["risk_class"] != "read_only":
        reject(f"only risk_class=read_only is approved, got {profile['risk_class']!r}")
    if not 1 <= profile["timeout_seconds"] <= 300:
        reject(f"timeout_seconds must be in 1..300, got {profile['timeout_seconds']}")
    if not re.match(r"^\d+\.\d{2}$", profile["max_budget_usd"]):
        reject(f"max_budget_usd must be a decimal string such as \"0.05\", got {profile['max_budget_usd']!r}")
    if profile["messages_path"] != FIXED_MESSAGES_PATH:
        reject(f"messages_path must be {FIXED_MESSAGES_PATH}, got {profile['messages_path']!r}")
    if not HEX64.match(profile["output_schema_sha256"]):
        reject("output_schema_sha256 must be 64 lowercase hex characters")
    if not HEX64.match(profile["cli_sha256"]):
        reject("cli_sha256 must be 64 lowercase hex characters")
    for s in ("profile_id", "model", "cli_version", "upstream_origin"):
        if not profile[s].strip():
            reject(f"{s} must not be empty")


def check_auth_mode(mode):
    """auth_mode must be one of two literals. No default — a default turns the declaration back into an implicit convention."""
    if mode not in AUTH_MODES:
        reject(f"auth_mode must be one of {list(AUTH_MODES)}, got {mode!r}")
    return mode


def check_origin(origin, auth_mode):
    """Validate upstream_origin according to auth_mode and return the **normalised connect target**.

    ★2026-08-08 rewritten wholesale (external review A5 §1). The old version used
    `host.startswith("127.0.0.1") or host.startswith("localhost")` to decide loopback,
    while the inspector forwards using `urlsplit(...).hostname`. **Those are not the same thing**;
    three divergences were measured:

        http://127.0.0.1@192.0.2.1:9        old gate: loopback; actually connects to 192.0.2.1 (internet, plaintext)
        http://127.0.0.1.evil.invalid:43137 old gate: loopback; actually connects to that domain
        http://localhost.evil.invalid:43137 same as above

    The first is userinfo: `127.0.0.1` sits before the `@`, so it is a user name, not the host.
    The whole reason this gate exists is "it must be able to tell when the config is wrong", and what it saw and what actually happened were two different things.

    The fix is not a better regex; it is **field-by-field validation + byte-for-byte reconstruction**: after parsing, require
    `origin == f"http://127.0.0.1:{port}"`, and reject every equivalent spelling.
    The returned connect target is pinned into the policy; the inspector only consumes it and never re-parses this string.
    """
    u = urlsplit(origin)

    if auth_mode == AUTH_DUMMY:
        # The first version accepts only this one byte-for-byte canonical shape.
        # ⚠️ Not that `::1` isn't loopback — there is simply no current need to widen the parsing and test surface
        # for multiple equivalent spellings. If IPv6 is ever needed, it goes through a new schema version + its own set of negative cases.
        if u.scheme != "http":
            reject(f"loopback_dummy upstream must be http://, got {origin!r}")
        if u.username is not None or u.password is not None:
            reject(f"upstream_origin must not contain userinfo (the part before `@` is a user name, not a host): {origin!r}")
        if u.hostname != "127.0.0.1":
            reject(f"loopback_dummy upstream host must literally be 127.0.0.1, "
                   f"got {u.hostname!r} (host names / aliases / equivalent spellings are all refused)")
        # ⚠️ `urlsplit` returns a SplitResult, which has **no** `.params` (that is urlparse's ParseResult).
        # The byte-for-byte reconstruction step would catch it too, but let this place state the rejection reason clearly.
        if u.path or u.query or u.fragment:
            reject(f"upstream_origin must not contain path/query/fragment: {origin!r}")
        try:
            port = u.port
        except ValueError:
            reject(f"upstream_origin port is not a valid integer: {origin!r}")
        if port is None or not 1 <= port <= 65535:
            reject(f"loopback_dummy upstream must carry an explicit port in 1..65535: {origin!r}")
        # 🔴 Byte-for-byte reconstruction: this step is the real gate. Leading zeros, case, extra slashes,
        # anything "equivalent after parsing but spelled differently" dies here.
        if origin != f"http://127.0.0.1:{port}":
            reject(f"upstream_origin is not in canonical form; it must be byte-for-byte equal to "
                   f"http://127.0.0.1:{port}, got {origin!r}")
        return {"scheme": "http", "host": "127.0.0.1", "port": port, "is_loopback": True}

    # real mode: a code-level allowlist; a profile cannot extend it.
    # Real credentials may only be sent to this one trusted origin — "any HTTPS" is not the same as safe.
    if origin not in REAL_ORIGIN_ALLOWLIST:
        reject(f"{AUTH_REAL} upstream may only be {list(REAL_ORIGIN_ALLOWLIST)}, got {origin!r}")
    if u.scheme != "https" or u.username is not None or u.password is not None:
        reject(f"origin in the allowlist has the wrong shape (a code bug, not a config problem): {origin!r}")
    return {"scheme": "https", "host": u.hostname, "port": u.port or 443,
            "is_loopback": False}


def check_approved_tools(tools):
    if not tools:
        reject("approved_tools is empty")
    names = []
    for t in tools:
        if not isinstance(t, dict):
            reject(f"approved_tools element is not an object: {t!r}")
        if set(t) != {"name", "definition_sha256"}:
            reject(f"approved_tools element fields must be exactly name/definition_sha256, got {sorted(t)}")
        if not isinstance(t["name"], str) or not t["name"].strip():
            reject(f"approved tool name must be a non-empty string, got {t['name']!r}")
        if t["name"] != "Read":
            reject(f"risk_class=read_only allows only Read, got {t['name']!r} (spec:207)")
        if not isinstance(t["definition_sha256"], str) or not HEX64.match(t["definition_sha256"]):
            reject(f"definition_sha256 of {t['name']} must be 64 lowercase hex characters")
        names.append(t["name"])
    if len(set(names)) != len(names):
        reject(f"approved_tools has duplicates: {names}")
    return {t["name"]: t["definition_sha256"] for t in tools}


def expand_and_check_rules(template, input_abs, approved_names):
    if set(template) != {"defaultMode", "allow", "deny"}:
        reject(f"permission_template must have exactly defaultMode/allow/deny, got {sorted(template)}")
    if template["defaultMode"] != "dontAsk":
        reject(f"defaultMode must be the literal dontAsk, got {template['defaultMode']!r}")

    rule_form = input_abs.lstrip("/")
    out = {}
    for key in ("allow", "deny"):
        arr = template[key]
        if not isinstance(arr, list) or not arr:
            reject(f"permissions.{key} must be a non-empty array")
        seen = []
        for item in arr:
            if not isinstance(item, str) or not item.strip():
                reject(f"permissions.{key} contains an empty/blank/non-string element: {item!r}")
            s = (item.replace(PLACEHOLDER_ABS, input_abs)
                     .replace(PLACEHOLDER_RULE, rule_form))
            for bad in ("$", "~", "..", "<", ">"):
                if bad in s:
                    reject(f"permissions.{key} still contains {bad!r} after expansion: {s!r}")
            seen.append(s)
        if len(set(seen)) != len(seen):
            reject(f"permissions.{key} has duplicates: {seen}")
        out[key] = seen

    for rule in out["allow"]:
        m = ALLOW_RULE.match(rule)
        if not m:
            reject(f"allow rule does not match the approved grammar Read(//<abs>/**): {rule!r}")
        target = "/" + m.group(1)
        if target != input_abs:
            reject(f"allow rule goes beyond this run's input: the rule points at {target}, this run's input is {input_abs}")

    for rule in out["deny"]:
        if "(" in rule:
            inner = rule[rule.index("(") + 1:-1] if rule.endswith(")") else None
            if inner is None:
                reject(f"deny rule has unbalanced parentheses: {rule!r}")
            if inner.startswith("/") and not inner.startswith("//"):
                reject(f"deny rule uses a single-slash absolute path (it would be treated as relative and silently fail to match): {rule!r}")
        tool = rule.split("(")[0]
        if not tool.strip():
            reject(f"deny rule has no tool name: {rule!r}")

    for rule in out["allow"]:
        tool = rule.split("(")[0]
        if tool not in approved_names:
            reject(f"allow rule points at an unapproved tool {tool!r} (approved: {sorted(approved_names)})")
    return out


def check_required_actions(actions, input_abs, approved_names):
    """spec:246-248. The lower-bound criteria rest entirely on this table — if it isn't validated, the lower bound is built on sand.

    Found on 2026-08-08 by pf-sentinel-symlink: the first v2 only checked required_actions with
    `isinstance(list)`, and the tool/path inside could point anywhere. **A table that decides "did this run
    do what it had to" was itself constrained by nothing.**
    """
    if not actions:
        reject("required_actions is empty — with no lower bound the run cannot be judged a success or failure")
    ids = []
    for a in actions:
        if not isinstance(a, dict):
            reject(f"required_actions element is not an object: {a!r}")
        if set(a) != {"id", "tool", "path", "min_success"}:
            reject(f"required_actions element fields must be exactly id/tool/path/min_success, got {sorted(a)}")
        if not isinstance(a["id"], str) or not a["id"].strip():
            reject(f"required_action id must be a non-empty string: {a['id']!r}")
        if a["tool"] not in approved_names:
            reject(f"required_action {a['id']!r} points at an unapproved tool {a['tool']!r}")
        if not isinstance(a["min_success"], int) or isinstance(a["min_success"], bool) or a["min_success"] < 1:
            reject(f"min_success of required_action {a['id']!r} must be an integer ≥1")
        p = a["path"]
        if not isinstance(p, str) or not os.path.isabs(p) or p != os.path.normpath(p):
            reject(f"path of required_action {a['id']!r} must be a canonical absolute path: {p!r}")
        # 🔴 It must fall inside this run's input. Otherwise this run's "done" could be satisfied by some long-lived file
        #    outside the attempt, and that file is not evidence produced by this run.
        if os.path.commonpath([p, input_abs]) != input_abs:
            reject(f"path of required_action {a['id']!r} is not inside this run's input: "
                   f"{p} (this run's input: {input_abs})")
        ids.append(a["id"])
    if len(set(ids)) != len(ids):
        reject(f"required_actions has duplicate ids: {ids}")


def check_cli(profile):
    path = profile["cli_realpath"]
    if not os.path.isabs(path) or path != os.path.normpath(path):
        reject(f"cli_realpath must be a canonical absolute path: {path}")
    real = os.path.realpath(path)
    if real != path:
        reject(f"cli_realpath is not a realpath: declared {path}, actual {real}")
    _lstat_regular(path, "CLI")
    got = _sha256_regular(path)
    if got != profile["cli_sha256"]:
        reject(f"CLI sha256 drift: profile {profile['cli_sha256'][:12]}…, actual {got[:12]}…")
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=20)
        ver = (p.stdout or p.stderr or "").strip().splitlines()[0] if (p.stdout or p.stderr) else ""
    except Exception as e:
        reject(f"failed to get the CLI version: {type(e).__name__}")
    if ver != profile["cli_version"]:
        reject(f"CLI version drift: profile {profile['cli_version']!r}, actual {ver!r}")
    return got


def check_sandbox_mode(profile, auth_mode, origin, cli_sha):
    """Validate sandbox mode and the non-profile test identity for disabled.

    A manifest-pinned ordinary profile can declare ``disabled``, but that
    declaration grants nothing by itself.  Only a rewritten test build, exact
    loopback_dummy topology, and the exact fake CLI realpath+sha tuple may use
    it.  Production source has no runtime switch that can turn the marker on.
    """
    mode = profile["sandbox"]
    if mode not in ("required", "disabled"):
        reject(f"profile.sandbox is invalid ({mode})", "sandbox_mode_invalid")
    if mode == "required":
        return mode
    if auth_mode == AUTH_REAL:
        reject("the sandbox must not be disabled when auth_mode=real_keychain_bridge",
               "sandbox_downgrade_rejected")
    if auth_mode != AUTH_DUMMY or not origin.get("is_loopback"):
        reject("sandbox=disabled only allows loopback_dummy + canonical loopback",
               "sandbox_disabled_topology_rejected")
    if not TEST_BUILD_SANDBOX_DISABLED:
        reject("sandbox=disabled only allows the audited test copy; production builds are always rejected",
               "sandbox_disabled_test_build_required")
    if (profile["cli_realpath"] != TEST_BUILD_FAKE_CLI_REALPATH
            or cli_sha != TEST_BUILD_FAKE_CLI_SHA256):
        reject("with sandbox=disabled, the CLI identity does not match the fake CLI realpath+sha pinned by the test build",
               "sandbox_disabled_cli_mismatch")
    return mode


# ── Keychain bridge ───────────────────────────────────────────────────
# Why it is needed: headless runs use a **dedicated HOME** (pinned by the profile), while the subscription's OAuth credentials are in
# the keychain, and the keychain is found via `$HOME`. The dedicated HOME has no Library/Keychains,
# so the real CLI reports `Not logged in`. The bridge does exactly one thing: place an **absolute symlink** in the dedicated home
# pointing at the real Library/Keychains.
#
# 🔴 Three things it does not do:
#   · It does not read the contents of login.keychain-db or sha256 it — that is credentials,
#     and the contents are legitimately refreshed by the system; treating contents as identity would raise false alarms daily (alert channel capacity drops to zero).
#   · It does not lock/unlock the keychain or touch any ACL.
#   · If the shape is wrong it **always rejects and never repairs**: no unlink, no replace, no recursive cleanup.
#     "Auto-fixing" means a bad state could lure this gate into deleting things.
#
# Identity comes from `pwd.getpwuid(os.geteuid())`, not `$HOME`/`$USER` — the ambient environment has no say.

def _identity(st):
    """A path's "identity" = dev/inode/uid/mode. Excludes size/mtime/content."""
    return {"dev": st.st_dev, "inode": st.st_ino, "uid": st.st_uid,
            "mode": stat.S_IMODE(st.st_mode)}


def _lstat_real_dir(path, what):
    """A real directory: exists, not a symlink, is a directory, owned by us, not group/other writable."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        reject(f"{what} does not exist: {path}")
    except OSError as e:
        reject(f"{what} lstat failed: {path} ({type(e).__name__})")
    if stat.S_ISLNK(st.st_mode):
        reject(f"{what} is a symlink: {path}")
    if not stat.S_ISDIR(st.st_mode):
        reject(f"{what} is not a directory: {path}")
    if st.st_uid != os.getuid():
        reject(f"{what} is not owned by the current user: {path}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        reject(f"{what} is group/other writable: {path}")
    return st


def prepare_keychain_bridge(home):
    """Prepare the absolute Library/Keychains symlink in the dedicated home and return the baseline.

    Follows the six-step order from external review A4 §2. If any step is wrong, `config_rejected`,
    and **before** the snapshot is generated — if any of profile/home/origin/CLI is invalid,
    no bridge side effect should have been left behind first.
    """
    pw = pwd.getpwuid(os.geteuid())
    real_home, account = pw.pw_dir, pw.pw_name
    bridge = {"identity_source": "getpwuid(geteuid())", "passwd_uid": os.geteuid(),
              "passwd_name": account, "real_home": real_home,
              "content_hash_checked": False}
    _ATTEMPT["keychain_bridge"] = bridge

    # 1. The real home from passwd
    if not os.path.isabs(real_home) or real_home != os.path.normpath(real_home):
        reject(f"home in passwd is not a canonical absolute path: {real_home}")
    _lstat_real_dir(real_home, "the real home from passwd")
    if os.path.realpath(real_home) != real_home:
        reject(f"home in passwd: realpath does not match the declaration: {real_home}")
    if real_home == home:
        reject(f"the dedicated home must not equal the real home: {home}")

    source = os.path.join(real_home, "Library", "Keychains")
    library = os.path.join(home, "Library")
    link = os.path.join(library, "Keychains")
    login_db = os.path.join(source, "login.keychain-db")
    bridge.update({"source": {"path": source}, "library": {"path": library},
                   "link": {"path": link}, "login_db": {"path": login_db}})

    # 2. The real Keychains directory
    _lstat_real_dir(source, "the real Keychains directory")
    if os.path.realpath(source) != source:
        reject(f"the real Keychains directory: realpath does not match the declaration: {source}")

    # 3. login DB — identify its type only, **never open, read or hash it**
    _lstat_regular(login_db, "login keychain DB")

    # 4. Library under the dedicated home
    if not os.path.lexists(library):
        try:
            os.mkdir(library, 0o700)
        except FileExistsError:
            pass                      # concurrency: the next line re-identifies the type; no overwrite
        except OSError as e:
            reject(f"failed to create Library in the dedicated home: {library} ({type(e).__name__})")
    _lstat_real_dir(library, "Library in the dedicated home")

    # 5. Library/Keychains — accept only "does not exist" or "an absolute symlink equal byte for byte"
    created = False
    if not os.path.lexists(link):
        try:
            os.symlink(source, link)
            created = True
        except FileExistsError:
            pass                      # concurrency: leave it to the equality check below; no overwrite
        except OSError as e:
            reject(f"failed to create the Keychains symlink: {link} ({type(e).__name__})")
    try:
        st_link = os.lstat(link)
    except OSError as e:
        reject(f"the Keychains link was created but cannot be lstat'ed: {link} ({type(e).__name__})")
    if not stat.S_ISLNK(st_link.st_mode):
        reject(f"Library/Keychains in the dedicated home is not a symlink (rejecting, not repairing): {link}")
    got = os.readlink(link)
    if got != source:
        reject(f"the Keychains symlink points to the wrong place (rejecting, not repairing): expected {source}, got {got!r}")

    # 6. After accepting, take the complete baseline again — the windows between the earlier steps don't count
    st_source = os.lstat(source)
    st_library = os.lstat(library)
    st_link = os.lstat(link)
    st_db = os.lstat(login_db)
    bridge["source"] = {"path": source, "realpath": os.path.realpath(source),
                        **_identity(st_source)}
    bridge["library"] = {"path": library, **_identity(st_library)}
    bridge["link"] = {"path": link, "created": created,
                      "readlink_exact": os.readlink(link), **_identity(st_link)}
    bridge["login_db"] = {"path": login_db, **_identity(st_db)}
    bridge["topology_ok"] = True
    return bridge


def assert_no_keychain_bridge(home):
    """`loopback_dummy` only: the dedicated home **must not contain** Library/Keychains, in any shape.

    The hole pointed out by external review A5 §2: dummy mode merely "skipping creation" is not enough — an **old**
    real bridge would stay there as-is and the CLI would still see it, so "declared fake credentials" and "can actually reach the real keychain"
    could both be true. So dummy's criterion is **persistent absence**, not "I didn't create it".
    Returns the baseline for --verify to reuse.
    """
    link = os.path.join(home, "Library", "Keychains")
    if os.path.lexists(link):
        st = os.lstat(link)
        kind = ("symlink" if stat.S_ISLNK(st.st_mode) else
                "directory" if stat.S_ISDIR(st.st_mode) else
                "regular file" if stat.S_ISREG(st.st_mode) else "other type")
        reject(f"auth_mode={AUTH_DUMMY} but Library/Keychains was found in the dedicated home"
               f" ({kind}): {link} — rejecting; not deleting, not replacing")
    return {"mode": AUTH_DUMMY, "link_must_not_exist": link,
            "content_hash_checked": False, "topology_ok": True}


def verify_no_keychain_bridge(bridge):
    """Re-check for the three phases in dummy mode: that path must stay absent throughout."""
    link = bridge.get("link_must_not_exist")
    if not isinstance(link, str) or not link:
        return ["keychain_bridge: dummy baseline has no link_must_not_exist"]
    if os.path.lexists(link):
        return [f"keychain_bridge: {link} appeared during auth_mode={AUTH_DUMMY}"]
    return []


def verify_keychain_bridge(bridge):
    """Re-check whether the bridge topology is still the original one. Returns a list of mismatches (empty = unchanged).

    🔴 Explicitly not compared: the login DB's sha256 / size / mtime / ctime,
       nor the contents or a directory hash of the whole Keychains directory.
       The system refreshing keychain contents is **not** drift; treating contents as identity = building a channel that raises false alarms daily.
    """
    bad = []
    if not isinstance(bridge, dict) or not bridge.get("topology_ok"):
        return ["keychain_bridge: the plan has no accepted bridge baseline"]
    if bridge.get("mode") == AUTH_DUMMY:
        return verify_no_keychain_bridge(bridge)

    def cmp_identity(name, want, st):
        for k in ("dev", "inode", "uid", "mode"):
            if want.get(k) != _identity(st)[k]:
                bad.append(f"{name}.{k}: expected {want.get(k)!r}, got {_identity(st)[k]!r}")

    for name in ("library", "source"):
        want = bridge[name]
        try:
            st = os.lstat(want["path"])
        except OSError as e:
            bad.append(f"{name}: lstat failed {want['path']} ({type(e).__name__})")
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            bad.append(f"{name}: no longer a real directory {want['path']}")
            continue
        cmp_identity(name, want, st)

    want = bridge["source"]
    if os.path.realpath(want["path"]) != want.get("realpath"):
        bad.append(f"source.realpath: expected {want.get('realpath')!r}, "
                   f"got {os.path.realpath(want['path'])!r}")

    want = bridge["link"]
    try:
        st = os.lstat(want["path"])
    except OSError as e:
        bad.append(f"link: lstat failed {want['path']} ({type(e).__name__})")
    else:
        if not stat.S_ISLNK(st.st_mode):
            bad.append(f"link: no longer a symlink {want['path']}")
        else:
            cmp_identity("link", want, st)
            got = os.readlink(want["path"])
            if got != want.get("readlink_exact"):
                bad.append(f"link.readlink: expected {want.get('readlink_exact')!r}, got {got!r}")

    want = bridge["login_db"]
    try:
        st = os.lstat(want["path"])
    except OSError as e:
        bad.append(f"login_db: lstat failed {want['path']} ({type(e).__name__})")
    else:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            bad.append(f"login_db: no longer a regular file {want['path']}")
        else:
            cmp_identity("login_db", want, st)
    return bad


def _snapshot_state():
    """Prior values of the six legacy state files. Records only hash and size, never content (spec:328)."""
    _home = real_home()
    targets = [os.path.join(_home, n) for n in STATE_INVARIANT_NAMES]
    out = {}
    for t in targets:
        h = _sha256_regular(t)
        try:
            out[t] = {"sha256": h, "size": os.stat(t).st_size}
        except OSError:
            out[t] = {"sha256": h}
    out["heartbeat_room_snapshot"] = {
        "status": "unmeasured",
        "reason": "spec:337 — no trusted room id, so no guessing; this cell is not judged before phase 1"}
    return out


def _recover_stale(runs, stale_after_seconds=900):
    """Turn expired unclosed attempts into exactly one abandoned. Done under an exclusive lock to prevent concurrent duplicates."""
    lock_path = os.path.join(runs, ".recover.lock")
    try:
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        return
    try:
        import fcntl
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return  # someone else is filling it in; let them
        now = time.time()
        for name in os.listdir(runs):
            adir = os.path.join(runs, name)
            ev = os.path.join(adir, "events.jsonl")
            if not os.path.isdir(adir) or not os.path.exists(ev):
                continue
            try:
                rows = [json.loads(l) for l in open(ev) if l.strip()]
            except Exception:
                continue
            if any(r.get("event") in ("finished", "abandoned") for r in rows):
                continue
            if now - os.path.getmtime(ev) < stale_after_seconds:
                continue  # it may really still be running
            with open(ev, "a") as f:
                f.write(json.dumps({"event": "abandoned", "attempt_id": name,
                                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                    "reason": "unclosed and expired; recorded by the next start under an exclusive lock"},
                                   ensure_ascii=False) + "\n")
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass


# ── Main flow ─────────────────────────────────────────────────────────
def verify_snapshot(plan_path, phase):
    """--verify <plan.json> <phase>: re-check whether this run's snapshot + bridge topology is still the verified one.

    spec:269 requires the CLI to consume only **this run's verified** absolute snapshot, re-checked both before spawn
    and after it ends. Without this step, between "what preflight verified" and "what the CLI actually read"
    there is a stretch of time nobody is watching — that is the definition of TOCTOU.
    ⚠️ This does not claim to resist a malicious same-UID process (that needs OS isolation); it guards against
    "the config was changed between two steps and nobody noticed".

    ★2026-08-08 split into phases (external review A4 §2): it originally re-checked only once, **before** the inspector started,
    and could not catch drift the inspector itself creates before READY. The three phases are closed and must all be present;
    finish.py decides which ones are due from the pre-spawn `cli_exec_attempted` — one missing
    means a stretch nobody was watching; `cli_started` is proven separately by the inner handshake.
    phase has no default: a default would let a caller who forgot to pass phase silently leave no trace.
    """
    if phase not in VERIFY_PHASES:
        print(f"preflight: --verify phase must be one of {list(VERIFY_PHASES)}, "
              f"got {phase!r}", file=sys.stderr)
        return EXIT_USAGE
    plan = json.load(open(plan_path))
    want = plan["hashes"]
    checks = {
        "settings": (plan["settings_path"], want["settings"]),
        "mcp": (plan["mcp_path"], want["mcp"]),
        "policy": (plan["policy_path"], want["policy"]),
        "sentinel": (plan["sentinel_path"], want["sentinel"]),
        "cli": (plan["cli_realpath"], want["cli"]),
    }
    if plan.get("sandbox_mode") == "required":
        checks["sandbox_profile"] = (
            plan.get("sandbox_profile_path"), want.get("sandbox_profile"))
    bad = []
    for name, (path, expect) in checks.items():
        got = _sha256_regular(path)
        if got != expect:
            bad.append(f"{name}: expected {expect[:12]}…, got {got[:12]}… ({path})")
    bad += verify_keychain_bridge(plan.get("keychain_bridge"))
    ev = os.path.join(os.path.dirname(plan_path), "events.jsonl")
    if bad:
        with open(ev, "a") as f:
            f.write(json.dumps({"event": "snapshot_tampered",
                                "attempt_id": plan["attempt_id"],
                                "phase": phase,
                                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "mismatches": bad}, ensure_ascii=False) + "\n")
        print(f"SNAPSHOT_TAMPERED phase={phase} " + " | ".join(bad), file=sys.stderr)
        return EXIT_CONFIG_REJECTED
    with open(ev, "a") as f:
        f.write(json.dumps({"event": "snapshot_verified",
                            "attempt_id": plan["attempt_id"],
                            "phase": phase,
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")},
                           ensure_ascii=False) + "\n")
    print(f"SNAPSHOT_OK phase={phase}")
    return EXIT_OK


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--verify":
        if len(sys.argv) != 4:
            print("usage: preflight.py --verify <plan.json> "
                  f"<{'|'.join(VERIFY_PHASES)}>", file=sys.stderr)
            return EXIT_USAGE
        return verify_snapshot(sys.argv[2], sys.argv[3])
    if len(sys.argv) != 2:
        print("usage: preflight.py <profile_id> | "
              f"--verify <plan.json> <{'|'.join(VERIFY_PHASES)}>", file=sys.stderr)
        return EXIT_USAGE
    profile_id = sys.argv[1]

    # 1. Create the attempt directory exclusively, write attempted first (spec:264)
    runs = os.path.join(WRAPPER_DIR, "runs")
    os.makedirs(runs, exist_ok=True)
    # 🔴 First bury the previous corpse (spec:310): SIGKILL / power loss reach no trap,
    # and such an attempt would stay at attempted forever. **It must not be left silently** — "never finished" and "still running"
    # look the same in the directory, the same shape as 08-06's "a 207-hour death and a 114-minute death cannot be told apart".
    _recover_stale(runs)
    attempt_id = str(uuid.uuid4())
    adir = os.path.join(runs, attempt_id)
    os.mkdir(adir, 0o700)
    _ATTEMPT.update({"dir": adir, "id": attempt_id,
                     "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "profile_id": profile_id})
    _append_event("attempted", requested_profile_id=profile_id, pid=os.getpid())

    # 4b. Scrub ambient (do it early so no later step is accidentally affected by it)
    for k in AMBIENT_TO_CLEAR:
        if k in os.environ:
            os.environ.pop(k)
            _ATTEMPT["ambient_cleared"].append(k)

    # 2. Find the profile via the fixed manifest
    raw_man = _read_regular(MANIFEST_PATH, "manifest")
    try:
        manifest = json.loads(raw_man)
    except Exception as e:
        reject(f"manifest is not valid JSON: {e}")
    if not isinstance(manifest, dict) or profile_id not in manifest:
        reject(f"manifest has no profile_id={profile_id!r} (known: {sorted(manifest) if isinstance(manifest, dict) else '?'})")
    entry = manifest[profile_id]
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        reject(f"manifest entry must have exactly path/sha256, got {entry!r}")

    ppath = entry["path"]
    if not os.path.isabs(ppath) or ppath != os.path.normpath(ppath):
        reject(f"profile path in the manifest is not a canonical absolute path: {ppath}")
    raw_profile = _read_regular(ppath, "profile")
    got_sha = hashlib.sha256(raw_profile).hexdigest()
    if got_sha != entry["sha256"]:
        reject(f"profile sha256 does not match the manifest: manifest {entry['sha256'][:12]}…, actual {got_sha[:12]}…")
    try:
        profile = json.loads(raw_profile)
    except Exception as e:
        reject(f"profile is not valid JSON: {e}")

    check_schema(profile)
    if profile["profile_id"] != profile_id:
        reject(f"profile calls itself {profile['profile_id']!r}, the manifest says {profile_id!r}")

    # 3. workspace / home
    ws = _canonical_dir(profile["workspace"], "workspace")
    home = _canonical_dir(profile["home"], "home")
    if ws == home:
        reject("workspace and home must not be the same")
    for label, d in (("workspace", ws), ("home", home)):
        if d == FORBIDDEN_HOME:
            reject(f"{label} must not be {FORBIDDEN_HOME} (it would read ~/.claude in as project-level config)")

    # 4. Remaining scalars + CLI
    auth_mode = check_auth_mode(profile["auth_mode"])
    origin = check_origin(profile["upstream_origin"], auth_mode)
    approved = check_approved_tools(profile["approved_tools"])
    cli_sha = check_cli(profile)
    sandbox_mode = check_sandbox_mode(profile, auth_mode, origin, cli_sha)
    sandbox_profile_path = os.path.join(WRAPPER_DIR, SANDBOX_PROFILE_REL)
    sandbox_sha = None
    if sandbox_mode == "required":
        sandbox_bytes = _read_regular(sandbox_profile_path, "sandbox profile")
        sandbox_sha = hashlib.sha256(sandbox_bytes).hexdigest()

    # 4c. Branch on auth_mode (insertion point set by external review A4 §2: after the CLI identity is verified, before the snapshot).
    # Placed here because of side-effect order: if any of profile/home/origin/tools/CLI is invalid,
    # no symlink should have been left in the dedicated home first.
    if auth_mode == AUTH_REAL:
        keychain_bridge = prepare_keychain_bridge(home)
    else:
        # dummy mode **does not probe** the real ~/Library/Keychains at all — not even an lstat.
        # That way this path also works on a machine with no login keychain.
        keychain_bridge = assert_no_keychain_bridge(home)
    _ATTEMPT["keychain_bridge"] = keychain_bridge

    # 5. Generate this run's snapshot
    snap = os.path.join(adir, "snapshot")
    os.mkdir(snap, 0o700)
    inp = os.path.join(adir, "input")
    os.mkdir(inp, 0o700)
    challenge = "CHAL-" + uuid.uuid4().hex
    sentinel_path = os.path.join(inp, "sentinel.txt")
    with open(os.open(sentinel_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
        f.write(challenge + "\n")

    expanded_actions = []
    for a in profile["required_actions"]:
        if isinstance(a, dict) and isinstance(a.get("path"), str):
            a = dict(a, path=a["path"].replace(PLACEHOLDER_ABS, inp))
        expanded_actions.append(a)
    check_required_actions(expanded_actions, inp, set(approved))

    perms = expand_and_check_rules(profile["permission_template"], inp, set(approved))
    settings_doc = {"permissions": {"defaultMode": "dontAsk",
                                    "allow": perms["allow"], "deny": perms["deny"]}}
    settings_bytes = json.dumps(settings_doc, ensure_ascii=False,
                                separators=(",", ":"), sort_keys=True).encode()
    if set(settings_doc) != {"permissions"}:
        reject("settings root may contain only the permissions key")

    mcp_bytes = json.dumps(profile["mcp_config"], separators=(",", ":"), sort_keys=True).encode()
    if mcp_bytes != b'{"mcpServers":{}}':
        reject(f"mcp_config canonical bytes must be {{\"mcpServers\":{{}}}}, got {mcp_bytes!r}")

    settings_path = os.path.join(snap, "settings.json")
    mcp_path = os.path.join(snap, "mcp.json")
    for path, data in ((settings_path, settings_bytes), (mcp_path, mcp_bytes)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with open(fd, "wb") as f:
            f.write(data)

    # 5b. policy snapshot — the inspector reads approved values **only from here**, never from the ambient env (spec:275).
    # capability_path is a random ≥128-bit prefix per run: requests with the wrong prefix are never recognised,
    # which also separates "some other process happened to connect to this port" from this run's requests.
    policy = {
        "attempt_id": attempt_id,
        "capability_path": secrets.token_hex(16),
        "upstream_origin": profile["upstream_origin"],
        # 🔴 The normalised connect target is pinned here. The inspector **consumes only this**
        # and no longer parses upstream_origin itself — that was the cause of the old bug:
        # whoever judged loopback and whoever actually opened the connection were looking at two different things.
        "upstream_connect": {"scheme": origin["scheme"], "host": origin["host"],
                             "port": origin["port"]},
        "auth_mode": auth_mode,
        # In dummy mode the inspector must verify before forwarding that the credential on the request is really this public constant.
        # In real mode this cell is None: the wrapper does not know, and should not know, what the real credentials look like.
        "expected_auth_token": DUMMY_TOKEN if auth_mode == AUTH_DUMMY else None,
        "messages_path": profile["messages_path"],
        "model": profile["model"],
        "max_body_bytes": 2 * 1024 * 1024,
        "approved_tools": approved,
        "required_actions": [a["id"] for a in expanded_actions],
        "sentinel_path": sentinel_path,
        "challenge": challenge,
    }
    policy_path = os.path.join(snap, "policy.json")
    fd = os.open(policy_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with open(fd, "wb") as f:
        f.write(json.dumps(policy, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode())

    # 6. Record hashes. The sandbox profile was verified before any snapshot/bridge side effect;
    # the launcher will read it once more later and require the actual byte hash to equal this one exactly, then use only
    # those in-memory bytes to run the probe and the CLI.

    hashes = {
        "profile": got_sha,
        "settings": hashlib.sha256(settings_bytes).hexdigest(),
        "mcp": hashlib.sha256(mcp_bytes).hexdigest(),
        "sentinel": _sha256_regular(sentinel_path),
        "policy": _sha256_regular(policy_path),
        "cli": cli_sha,
        "sandbox_profile": sandbox_sha,
        "output_schema": profile["output_schema_sha256"],
        "wrapper_sources": {n: _sha256_regular(os.path.join(WRAPPER_DIR, n))
                            for n in WRAPPER_SOURCES},
    }

    # 7. flags are generated by the wrapper, fixed
    flags = ["--safe-mode", "--settings", settings_path, "--setting-sources", "",
             "--permission-mode", "dontAsk", "--tools", "Read", "--no-chrome",
             "--strict-mcp-config", "--mcp-config", mcp_path,
             "--no-session-persistence", "--max-budget-usd", profile["max_budget_usd"],
             "--model", profile["model"], "--output-format", "json"]

    plan = {
        "attempt_id": attempt_id, "attempt_dir": adir, "profile_id": profile_id,
        "workspace": ws, "home": home, "input_dir": inp,
        "sentinel_path": sentinel_path, "challenge": challenge,
        "settings_path": settings_path, "mcp_path": mcp_path,
        "policy_path": policy_path, "capability_path": policy["capability_path"],
        "cli_realpath": profile["cli_realpath"], "flags": flags,
        # The launcher reads this path exactly once and checks it against hashes.sandbox_profile; the probe
        # and the CLI both consume those in-memory bytes (sandbox-exec -p) and never reopen by path.
        "sandbox_mode": sandbox_mode,
        "sandbox_profile_path": sandbox_profile_path if sandbox_mode == "required" else None,
        "model": profile["model"], "timeout_seconds": profile["timeout_seconds"],
        "upstream_origin": profile["upstream_origin"], "origin_parts": origin,
        "auth_mode": auth_mode,
        # hb-run uses this to decide whether to inject the fake credential into the CLI. Always null in real mode —
        # real credentials don't travel this way; they are in the keychain, and the bridge lets the CLI find them itself.
        "dummy_auth_token": DUMMY_TOKEN if auth_mode == AUTH_DUMMY else None,
        "messages_path": profile["messages_path"],
        "approved_tools": approved, "required_actions": expanded_actions,
        "output_schema_sha256": profile["output_schema_sha256"],
        "state_invariants": profile["state_invariants"],
        "hashes": hashes,
        "state_before": _snapshot_state(),
        "ambient_overrides_cleared": _ATTEMPT["ambient_cleared"],
        # The bridge baseline is kept separately and **does not enter the closed profile schema** — it is a fact measured on site this run,
        # not configuration. --verify compares it field by field in every phase.
        "keychain_bridge": keychain_bridge,
    }
    with open(os.path.join(adir, "plan.json"), "w") as f:
        json.dump(plan, f, ensure_ascii=False, indent=1)

    _append_event("preflight_ok", attempt_dir=adir)
    print("PREFLIGHT_OK")
    print(f"  attempt   = {attempt_id}")
    print(f"  workspace = {ws}")
    print(f"  home      = {home}")
    print(f"  allow     = {perms['allow']}")
    print(f"  cleared   = {_ATTEMPT['ambient_cleared']}")
    print(f"  auth_mode = {auth_mode} → {origin['scheme']}://{origin['host']}:{origin['port']}")
    print(f"PLAN {os.path.join(adir, 'plan.json')}")
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # any unforeseen exception must also fail closed and leave a trace
        reject(f"preflight internal exception: {type(exc).__name__}: {exc}", error_type="internal_error")
