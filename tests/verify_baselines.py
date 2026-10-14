#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every tool hash pinned by a profile must trace back to a baseline with a provenance
that can be stated.

★2026-08-09 why it exists (A8 "Dummy Read baseline: direction right, but only a
candidate"): the hash in `approved_tools` came **from field observation** — it only
proves "next time looks like this time", not "this definition should be approved".
That's TOFU. And the most dangerous thing about TOFU isn't that it's wrong; it's that
**it looks identical in the file to "a reviewed approval value"**.

So it checks three things, all machine-decidable:
  ① for every profile's every `approved_tools` hash, there is a baseline file whose
     `canonical_sha256_inspector` equals it — **no unexplained pins**;
  ② that baseline's `review_status` must come from the closed vocabulary (`CANDIDATE` /
     `REVIEWED`) — no inventing a word that sounds more reassuring;
  ③ the baseline's self-reported `baseline_path` must be where it actually is —
     A8 caught "the program writes one place, the deliverable is in another", with two
     same-named files and which is the original left to memory.

🔴 **It does not force "must be REVIEWED"**, because only a human can do that step and
   turning it into an assertion would just get it edited away to make the light green.
   What it forces is **that status being read out loud every run**: every unreviewed pin
   gets named in the output on each run.

    /usr/bin/python3 tests/verify_baselines.py
"""
import glob
import hashlib
import importlib.util
import json
import os
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(TESTS)
BASELINES = os.path.join(TESTS, "baselines")
# NOT_ESTABLISHED = this arm is simply not reproducible under the current constraints
# (real branch: isolation conditions and startup prerequisites are mutually exclusive).
# It is **honestly recorded as not established**, not "haven't reviewed it yet".
VALID_STATUS = {"CANDIDATE", "REVIEWED", "NOT_ESTABLISHED"}

problems = []
candidates = []


def load_inspector():
    path = os.path.join(WRAPPER, "inspector.py")
    spec = importlib.util.spec_from_file_location("baseline_runtime_inspector", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


try:
    INSPECTOR = load_inspector()
except Exception as e:                                      # noqa: BLE001
    INSPECTOR = None
    problems.append(f"inspector.canon_tool failed to load: {type(e).__name__}")


def load(path):
    try:
        return json.load(open(path))
    except Exception as e:                                  # noqa: BLE001
        problems.append(f"{os.path.relpath(path, WRAPPER)} unreadable: {type(e).__name__}")
        return None


baselines = {}
for p in sorted(glob.glob(os.path.join(BASELINES, "*.json"))):
    doc = load(p)
    if doc is None:
        continue
    rel = os.path.relpath(p, WRAPPER)
    status = doc.get("review_status")
    # The old schema stuffed a whole essay into review_status — that's not a status, it's
    # an annotation.
    if status not in VALID_STATUS:
        problems.append(f"{rel}: review_status={status!r} not in the closed vocabulary {sorted(VALID_STATUS)}")
    declared = doc.get("baseline_path")
    if declared is not None and os.path.normpath(declared) != os.path.normpath(rel):
        problems.append(f"{rel}: self-reported baseline_path={declared!r} does not match its actual location")
    definition = doc.get("definition")
    declared_hash = doc.get("canonical_sha256_inspector")
    if definition is not None:
        if not isinstance(definition, dict):
            problems.append(f"{rel}: definition is not an object")
            continue
        if INSPECTOR is None:
            continue
        # 🔴 Don't trust the canonical hash written in the file; recompute from the
        # archived definition with the **single runtime algorithm**.
        recomputed = hashlib.sha256(INSPECTOR.canon_tool(definition)).hexdigest()
        if declared_hash != recomputed:
            problems.append(
                f"{rel}: canonical_sha256_inspector self-reports {str(declared_hash)[:12]}..., "
                f"recomputed from the archived definition is {recomputed[:12]}...")
        for rep in doc.get("per_rep") or []:
            if rep.get("gate_hashes") != [recomputed]:
                problems.append(
                    f"{rel}: rep {rep.get('rep')} gate_hashes is not the recomputed value {recomputed[:12]}...")
        # 🔴 ★2026-08-09: a signature must be **bound to specific bytes**.
        #    Without the binding, one CLI upgrade / definition change and this REVIEWED
        #    stamp would silently cover a new definition — the human reviewed A while
        #    the approval takes effect on B. That's worse than no signature at all: it
        #    looks reviewed. So REVIEWED must carry reviewer / reviewed_at /
        #    reviewed_definition_sha256, and the last one must equal the **recomputed value**.
        if status == "REVIEWED":
            missing = [k for k in ("reviewer", "reviewed_at",
                                   "reviewed_definition_sha256") if not doc.get(k)]
            if missing:
                problems.append(f"{rel}: marked REVIEWED but missing {missing} -- "
                                f"a signature that cannot say who reviewed which bytes when is not a signature")
            elif doc["reviewed_definition_sha256"] != recomputed:
                problems.append(
                    f"{rel}: 🔴 signature expired -- the human reviewed "
                    f"{doc['reviewed_definition_sha256'][:12]}..., "
                    f"the archived definition now recomputes to {recomputed[:12]}. "
                    f"a changed definition must be re-reviewed; signatures are not inherited.")
        if recomputed in baselines:
            problems.append(f"{rel}: duplicates the same definition hash as {baselines[recomputed][0]}")
        baselines[recomputed] = (rel, status, doc)
    elif declared_hash:
        problems.append(f"{rel}: has canonical_sha256_inspector but no definition, cannot recompute independently")


man_path = os.path.join(WRAPPER, "profiles", "manifest.json")
man = load(man_path) or {}
pinned = 0
for pid, entry in sorted(man.items()):
    prof = load(entry["path"])
    if prof is None:
        continue
    for t in prof.get("approved_tools") or []:
        pinned += 1
        name, h = t.get("name"), t.get("definition_sha256")
        if h not in baselines:
            problems.append(
                f"profile {pid} pins {name!r} at {str(h)[:12]}..., "
                f"but no baseline in baselines/ has a canonical_sha256_inspector equal to it"
                f" -- this is a pin with no provenance")
            continue
        rel, status, _doc = baselines[h]
        if status == "CANDIDATE":
            candidates.append((pid, name, rel))

print(f"tool definitions pinned by profiles: {pinned}; baselines in baselines/: {len(baselines)}")
for pid, name, rel in candidates:
    print(f"🔴 CANDIDATE: profile {pid}'s {name!r} uses an **unhuman-reviewed** observed value"
          f"({rel}) -- should now be read as candidate, not approved")
if not candidates and not problems:
    print("all pinned definitions point to REVIEWED baselines")

for m in problems:
    print("✘", m)

print()
if problems:
    print(f"VERIFY_BASELINES BROKEN={len(problems)}")
    sys.exit(1)
print(f"VERIFY_BASELINES OK ({len(candidates)} still candidate, "
      f"not a failure -- **read aloud every run** debt")
sys.exit(0)