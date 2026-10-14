#!/bin/zsh
# headless heartbeat wrapper v2 — 2026-08-08, rewritten per inspector-review2 §C/§D/§E.
#
# The entry point changed: `hb-run.sh <profile_id> <task-input>`; **arbitrary profile paths are no longer accepted**.
# preflight fetches the profile from a hard-coded manifest by sha256; a caller cannot bring its own copy to self-certify.
#
# Four things the CLI will not do for you (same reasons as v1, each one tightened):
#   1. Validate **before** starting the model (preflight.py); on failure exit 78 and the model process never starts.
#   2. **While** the model runs, the inspector blocks out-of-scope requests **before forwarding** them.
#      ⚠️ It must be before forwarding: grading after the fact cannot undo side effects.
#   3. **After** the model, finish.py **recomputes** the terminal state from events — it trusts nobody's self-report,
#      including the CLI's own is_error (measured 08-07: when a tool call is refused it still reports is_error=false / exit 0).
#   4. Write finished exactly once, success or failure.
#      🔴 EXIT/INT/TERM must all reach it; SIGKILL can't, so the next start fills in `abandoned` (preflight's job).
set -uo pipefail

WRAPPER_DIR="${0:A:h}"
PROFILE_ID="${1:-}"
TASK_INPUT="${2:-}"

if [[ -z "$PROFILE_ID" || -z "$TASK_INPUT" ]]; then
  print -u2 "usage: hb-run.sh <profile_id> <task-input>"
  exit 64
fi

# ── 1. preflight (it creates the attempt dir, writes attempted, and writes terminal itself when it rejects) ──
pf_out="$(/usr/bin/python3 "$WRAPPER_DIR/preflight.py" "$PROFILE_ID" 2>&1)"
pf_rc=$?
print -r -- "$pf_out"
if (( pf_rc != 0 )); then
  exit $pf_rc
fi

PLAN="$(print -r -- "$pf_out" | /usr/bin/grep '^PLAN ' | /usr/bin/tail -1)"
PLAN="${PLAN#PLAN }"
if [[ -z "$PLAN" || ! -r "$PLAN" ]]; then
  print -u2 "hb-run: preflight passed but produced no readable plan — refusing to start the model in this state"
  exit 80
fi

ADIR="${PLAN:h}"
CLI_OUT="$ADIR/model.json"
CLI_ERR="$ADIR/model.stderr"
INSP_LOG="$ADIR/inspector.jsonl"
VERIFY_LOG="$ADIR/verify.log"

jq_get() { /usr/bin/python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$PLAN" "$1"; }

WORKSPACE="$(jq_get workspace)"
HOME_DIR="$(jq_get home)"
POLICY="$(jq_get policy_path)"
CAP="$(jq_get capability_path)"
CLI_BIN="$(jq_get cli_realpath)"
TIMEOUT="$(jq_get timeout_seconds)"

# ── 1a. Child-process environment: an allowlist, not inheritance ──────────────────────────────────────
# ★2026-08-08 P0 (found by external review): until then the ambient scrub **never reached the real child processes**.
# The `os.environ.pop()` in preflight.py cleaned preflight's own process, which exits immediately;
# the inspector and CLI started here **inherited the whole environment as-is**. So a single ambient `CLAUDE_CONFIG_DIR`
# could make the headless process read a different config — and this CLI does not error on a wrong config, it just silently becomes something else.
# The fix is an allowlist (`env -i` + explicit enumeration), not a blocklist: a blocklist only stops the ones you can think of today.
#
# 🔴 `USER` must be passed, and it must come from passwd, not the ambient environment. Measured (08-08):
#   `env -i` without USER → the CLI matches a stale keychain copy with `acct="unknown"`
#   → reports "OAuth session expired and could not be refreshed", **not** "Not logged in".
#   ⚠️ 2026-08-08: retracted a sentence originally written here, "launchd environments usually have no USER,
#   so unattended runs will certainly hit this" — **measured, it is wrong**: a LaunchAgent in the `gui/<uid>` domain
#   has USER/LOGNAME/HOME all set. Taking it from passwd is kept, but its nature is
#   **redundant insurance** (removing one ambient dependency, blocking hostile or mistaken environment overrides),
#   not plugging a hole that is currently leaking. Where the stale `acct=unknown` copy came from is still unknown.
REAL_USER="$(/usr/bin/python3 -c 'import pwd,os;print(pwd.getpwuid(os.geteuid()).pw_name)')"
if [[ -z "$REAL_USER" ]]; then
  print -u2 "hb-run: cannot get the user name from passwd — refusing to start the model with an uncertain identity"
  exit 80
fi
# TMPDIR is not inherited either: give this run its own temp dir, which removes an ambient dependency and helps forensics afterwards.
ATTEMPT_TMP="$ADIR/tmp"
/bin/mkdir -p "$ATTEMPT_TMP"
FIXED_PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

insp_pid=""
finished=0

event_seen() {  # $1=event name; malformed evidence is false/fail-closed
  /usr/bin/python3 -c 'import json,sys
try:
  rows=[json.loads(x) for x in open(sys.argv[1]) if x.strip()]
except Exception:
  rows=[]
raise SystemExit(0 if any(r.get("event")==sys.argv[2] for r in rows) else 1)' \
    "$ADIR/events.jsonl" "$1"
}

finalize() {  # $1=cli_exit $2=timed_out
  (( finished )) && return
  finished=1
  # ── post_cli re-check (the "after it ends" check of spec:269) ────────────────────────
  # 🔴 It lives in finalize rather than the main flow because INT/TERM go through the trap:
  # the main-flow line is never reached, and "interrupted by a signal" is exactly when you most need to know whether the config was touched.
  # The condition is the pre-spawn cli_exec_attempted event. The launcher writes it to disk before the real spawn,
  # preserving what the old cli_spawned ordering guarded against ("it started but the ledger doesn't show it"); cli_started
  # is proven only by the in-sandbox bootstrap/exec handshake, so the two meanings are no longer conflated.
  if event_seen cli_exec_attempted; then
    /usr/bin/python3 "$WRAPPER_DIR/preflight.py" --verify "$PLAN" post_cli >> "$VERIFY_LOG" 2>&1
  fi
  local insp_exit="None"
  if [[ -n "$insp_pid" ]]; then
    # 🔴 terminate, wait, confirm the exit, **then** hash the log (spec:310).
    # In the other order you hash a file that is still being written.
    kill -TERM "$insp_pid" 2>/dev/null
    wait "$insp_pid" 2>/dev/null
    insp_exit=$?
  fi
  /usr/bin/python3 "$WRAPPER_DIR/finish.py" "$ADIR" "${1:-1}" "${2:-0}" "$insp_exit" "$CLI_OUT"
  exit $?
}
trap 'finalize 1 0' INT TERM
trap 'finalize ${cli_rc:-1} ${timed_out:-0}' EXIT

# ── 1b. Re-check snapshot + bridge topology before starting the inspector (spec:269) ──
# Nobody is watching between preflight's check and the CLI reading. Without this step it is a TOCTOU.
if ! /usr/bin/python3 "$WRAPPER_DIR/preflight.py" --verify "$PLAN" pre_inspector; then
  print -u2 "hb-run: snapshot was modified after preflight — refusing to start the inspector"
  finalize 78 0
fi

# ── 2. Start the inspector ──
/usr/bin/env -i \
  PATH="$FIXED_PATH" \
  LANG=en_US.UTF-8 \
  HOME="$HOME_DIR" \
  TMPDIR="$ATTEMPT_TMP" \
  /usr/bin/python3 "$WRAPPER_DIR/inspector.py" "$POLICY" "$INSP_LOG" > "$ADIR/inspector.out" 2>&1 &
insp_pid=$!
port=""
for _ in {1..60}; do
  if [[ -s "$ADIR/inspector.out" ]]; then
    line="$(head -1 "$ADIR/inspector.out")"
    if [[ "$line" == READY* ]]; then
      port="${${line#READY 127.0.0.1:}%% *}"
      break
    fi
  fi
  sleep 0.1
done
if [[ -z "$port" ]]; then
  print -u2 "hb-run: inspector did not come up — refusing to start the model without an observer"
  finalize 1 0
fi

# ── 2b. Re-check once more after READY, before the CLI spawn ────────────────────────────
# ★2026-08-08 a real gap pointed out by external review A4 §2: check 1b runs **before** the inspector starts,
# so it cannot catch drift the inspector itself creates before READY (the trusted stub demonstrated exactly that).
# This cell is the last observation point for "what the CLI is about to read".
if ! /usr/bin/python3 "$WRAPPER_DIR/preflight.py" --verify "$PLAN" pre_cli; then
  print -u2 "hb-run: snapshot/bridge was modified after inspector READY — refusing to start the model"
  finalize 78 0
fi

# ── 3. Start the model ──
# A sentinel instruction is prepended to the task: the model must echo this run's challenge verbatim on its first line before doing any work.
SENTINEL="$(jq_get sentinel_path)"
canary="First, read the file ${SENTINEL} and output its exact contents as the very first line of your reply, with nothing before it. Then do this task:
${TASK_INPUT}"

flags=("${(@f)$(/usr/bin/python3 -c "import json,sys;print('\n'.join(json.load(open(sys.argv[1]))['flags']))" "$PLAN")}")

# ── 3a. Credentials (★2026-08-08 external review A5 §2) ────────────────────────────────
# `loopback_dummy`: inject the **public fixed constant** so the CLI agrees to start.
#   ⚠️ This is not the forbidden shape of "reading the approved value from ambient": the value comes from the hash-locked plan
#   and is passed explicitly via `env -i`, an audited process interface. The two ambient names are still scrubbed.
# `real_keychain_bridge`: **no credential variable at all**. The real credentials are in the keychain,
#   and the CLI finds them itself through the Library/Keychains bridge preflight built.
AUTH_MODE="$(jq_get auth_mode)"
auth_env=()
if [[ "$AUTH_MODE" == "loopback_dummy" ]]; then
  DUMMY_TOKEN="$(jq_get dummy_auth_token)"
  if [[ -z "$DUMMY_TOKEN" || "$DUMMY_TOKEN" == "None" ]]; then
    print -u2 "hb-run: auth_mode=loopback_dummy but no dummy_auth_token was provided — refusing to start the model"
    finalize 78 0
  fi
  auth_env=(ANTHROPIC_AUTH_TOKEN="$DUMMY_TOKEN")
elif [[ "$AUTH_MODE" != "real_keychain_bridge" ]]; then
  print -u2 "hb-run: invalid auth_mode in plan ($AUTH_MODE) — refusing to start the model"
  finalize 78 0
fi

# ── 3c. Single launcher: bind the policy bytes + two-phase apply + inner handshake ─────
# In required mode the launcher opens the profile exactly once, checks the plan hash, and hands those same bytes via
# `sandbox-exec -p` to both the probe and the real CLI. Even if the profile path is replaced afterwards, the policy
# consumed in this run does not change; post_cli still records the path drift as config_rejected.
#
# cli_exec_attempted is written to disk before the real spawn and closes the lifecycle; cli_started can only come from
# the handshake in which the in-sandbox bootstrap reaches exec. A failed second apply is therefore
# attempted=true / started=false / sandbox_apply_failed=true, not cli_failed.
launcher_params=(
  --param "INSPECTOR_PORT=$port"
  --param "READ_ROOT=$(jq_get input_dir)"
  --param "CLI_ROOT=${CLI_BIN:h:h}"
  --param "HOME_DIR=$HOME_DIR"
  --param "ATTEMPT_TMP=$ATTEMPT_TMP"
  --param "WORKSPACE=$WORKSPACE"
  # Only snapshot/ is exposed; the observer's events/terminal are not exposed to the CLI.
  --param "SNAPSHOT_DIR=${$(jq_get settings_path):h}"
  --param "CLI_RUNTIME_DIR=/private/tmp/claude-$(/usr/bin/id -u)"
)

timed_out=0
(
  cd -- "$WORKSPACE" || exit 90
  /usr/bin/env -i \
    HOME="$HOME_DIR" \
    USER="$REAL_USER" \
    LOGNAME="$REAL_USER" \
    PATH="$FIXED_PATH" \
    LANG=en_US.UTF-8 \
    TMPDIR="$ATTEMPT_TMP" \
    ANTHROPIC_BASE_URL="http://127.0.0.1:${port}/${CAP}" \
    NO_PROXY='127.0.0.1,localhost,::1' \
    "${auth_env[@]}" \
    /usr/bin/python3 "$WRAPPER_DIR/sandbox_launcher.py" \
      --plan "$PLAN" --timeout "$TIMEOUT" "${launcher_params[@]}" -- \
      "$CLI_BIN" "${flags[@]}" <<<"$canary"
) > "$CLI_OUT" 2> "$CLI_ERR"
cli_rc=$?
(( cli_rc == 142 )) && timed_out=1

# 3b (the after-the-run re-check) has been folded into finalize — placed here, the INT/TERM path would never reach it.
finalize "$cli_rc" "$timed_out"
