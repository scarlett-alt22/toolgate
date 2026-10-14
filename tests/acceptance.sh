#!/bin/zsh
# Single entry point (spec:341-348). Exits 0 only when it reports ANTHROPIC_REQUESTS=0 and ALL_PASS.
#
# 🔴 It doesn't judge its own success: after the run, tests/verify_acceptance.py must
#    independently recompute it (spec:392). "The test reported itself passed" and
#    "count it a success once the run finished" are the same disease.
set -uo pipefail

HERE="${0:A:h}"
cd "$HERE/.." || exit 2

# The example profile embeds this machine's absolute paths (preflight demands absolute
# realpaths), so it stays out of version control and gets generated on the spot by the
# script. If it's missing, generate one — a fresh clone's first run shouldn't show a
# wall of red, and that red wouldn't even point at a real problem.
# ⚠️ Generate when missing; **also regenerate when the path goes stale** — both cases turn
#    the whole suite red, and the red points at nothing real. Measured 2026-08-15: after
#    the repo directory was renamed, the gitignored example profile still held the old
#    path, so layout and baseline both went red.
#    ⚠️ Only regenerate when the path points somewhere that isn't this repo; content the
#    user edited themselves stays untouched.
need_profile=0
if [[ ! -f profiles/manifest.json ]]; then
  need_profile=1
elif ! grep -q "$PWD/profiles/example-loopback.json" profiles/manifest.json 2>/dev/null; then
  echo "── example profile points elsewhere (repo moved?) → regenerating ──"
  need_profile=1
fi
if (( need_profile )); then
  [[ -f profiles/manifest.json ]] || echo "── first run: generating this machine's example profile ──────────"
  /usr/bin/python3 tools/make-example-profile.py || exit 2
  echo
fi

echo "── snapshot layout ─────────────────────────"
/usr/bin/python3 "$HERE/verify_layout.py"
layout_rc=$?

if (( layout_rc == 0 )); then
  /usr/bin/python3 "$HERE/run_acceptance.py"
  run_rc=$?
else
  echo "SKIP run_acceptance: snapshot layout invalid"
  run_rc=2
fi

echo
echo "── independent recompute ──────────────────────────────"
if (( layout_rc == 0 )); then
  /usr/bin/python3 "$HERE/verify_acceptance.py" runs/acceptance/latest/summary.json
  ver_rc=$?
else
  echo "SKIP verify_acceptance: snapshot layout invalid"
  ver_rc=2
fi

# ★2026-08-09: every tool definition pinned by a profile must trace back to a baseline
# whose provenance can be stated.
# 🔴 It does **not** require that the baseline has been human-reviewed (only a human can
#    review); it requires that status to be spoken out loud every time —
#    A8's words: that hash can only be called a "candidate", and candidate and approved
#    look identical inside a profile file. It lives here because **the single entry point
#    is only an entry point if everything goes through it**.
# ★2026-08-09 (built by Codex A9b, wired in after my review): offline recompute of the
# five cells of finish.py's three-way split.
# 🔴 It used to be "conclusions without inputs" — A8's words: the current package
#    "cannot independently recompute those five cells".
#    Left to manual runs it would slide back into the same hole, so it goes into the
#    single entry point. Fully offline, zero API, ~0.4 seconds.
echo
echo "── TOCTOU drift criterion (A11's four red arms) ─────────"
/usr/bin/python3 "$HERE/toctou_verifier_redgreen.py"
toctou_rc=$?

echo
echo "── A14 policy byte/phase/terminal offline red-green ──"
/usr/bin/python3 "$HERE/a14_offline.py"
a14_rc=$?

echo
echo "── finish three-way five cells ────────────────────────"
/usr/bin/python3 "$HERE/finish_arms.py"
fin_rc=$?

echo
echo "── response scanner red-green ──────────────────"
/usr/bin/python3 "$HERE/sse_redgreen.py"
sse_rc=$?

echo
echo "── HTTP relay / framing / concurrency ─────"
/usr/bin/python3 "$HERE/relay_redgreen.py"
relay_rc=$?

echo
echo "── observe mode red-green (default=enforce, typos rejected) ──"
/usr/bin/python3 "$HERE/observe_mode.py"
obs_rc=$?

echo
echo "── approved manifest set semantics (subset/absence/multi-variant/drift vs added) ──"
/usr/bin/python3 "$HERE/manifest_semantics.py"
mf_rc=$?

echo
echo "── upper gate across three wire formats (one hash across formats) ──"
/usr/bin/python3 "$HERE/wire_formats.py"
wire_rc=$?

echo
echo "── real trace regression (missing fixture reports unqualified, not skipped) ──"
/usr/bin/python3 "$HERE/real_trace_regression.py"
rt_rc=$?

echo
echo "── product end-to-end (init→watch→diff→approve→enforce) ──"
/usr/bin/python3 "$HERE/product_e2e.py"
e2e_rc=$?

echo
echo "── baseline provenance ──────────────────────────────"
/usr/bin/python3 "$HERE/verify_baselines.py"
base_rc=$?

if (( layout_rc == 0 && run_rc == 0 && ver_rc == 0 && toctou_rc == 0 && a14_rc == 0 && fin_rc == 0
      && sse_rc == 0 && relay_rc == 0 && obs_rc == 0 && wire_rc == 0 && mf_rc == 0
      && rt_rc == 0 && e2e_rc == 0 && base_rc == 0 )); then
  echo "VERIFIED_ALL_PASS"
  exit 0
fi
echo "NOT_VERIFIED (layout_rc=$layout_rc run_rc=$run_rc verify_rc=$ver_rc" \
     "toctou_rc=$toctou_rc a14_rc=$a14_rc finish_rc=$fin_rc sse_rc=$sse_rc" \
     "relay_rc=$relay_rc observe_rc=$obs_rc wire_rc=$wire_rc manifest_rc=$mf_rc" \
     "realtrace_rc=$rt_rc e2e_rc=$e2e_rc baseline_rc=$base_rc)"
exit 1
