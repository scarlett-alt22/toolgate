#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline check that a wrapper/snapshot has a self-contained, re-runnable layout."""
import importlib.util
import hashlib
import json
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
PROBLEMS = []


def regular(path, label):
    try:
        st = os.lstat(path)
    except OSError as e:
        PROBLEMS.append(f"{label}: missing/unreadable: {e}")
        return False
    if not stat.S_ISREG(st.st_mode):
        PROBLEMS.append(f"{label}: not a regular file")
        return False
    return True


required = [
    "hb-run.sh", "preflight.py", "inspector.py", "finish.py", "sandbox_launcher.py",
    "tests/lib.py", "tests/cases.json", "tests/acceptance.sh",
    "tests/run_acceptance.py", "tests/verify_acceptance.py",
    "tests/a14_offline.py", "tests/seatbelt_failclosed.py",
    "tests/verify_baselines.py", "tests/finish_arms.py",
    "profiles/manifest.json",
    "tests/fixtures/finish/cases.json", "tests/fixtures/finish/base/events.jsonl",
    "tests/fixtures/finish/base/inspector.jsonl", "tests/fixtures/finish/base/model.json",
    "tests/fixtures/finish/base/plan.json",
]
for rel in required:
    regular(os.path.join(WRAPPER, rel), rel)

cases_path = os.path.join(HERE, "cases.json")
if regular(cases_path, "tests/cases.json(parse)"):
    try:
        case_doc = json.load(open(cases_path, encoding="utf-8"))
        groups = case_doc.get("groups") if isinstance(case_doc, dict) else None
        cases = ([case for group in groups for case in group.get("cases", [])]
                 if isinstance(groups, list) else [])
        if not cases:
            PROBLEMS.append("tests/cases.json: groups must contain cases")
    except Exception as e:
        PROBLEMS.append(f"tests/cases.json: invalid JSON: {e}")

baseline_dir = os.path.join(HERE, "baselines")
try:
    names = sorted(n for n in os.listdir(baseline_dir) if n.endswith(".json"))
except OSError as e:
    PROBLEMS.append(f"tests/baselines: missing/unreadable: {e}")
    names = []
if not names:
    PROBLEMS.append("tests/baselines: no JSON baselines")
for name in names:
    regular(os.path.join(baseline_dir, name), f"tests/baselines/{name}")

manifest_path = os.path.join(WRAPPER, "profiles", "manifest.json")
if regular(manifest_path, "profiles/manifest.json(parse)"):
    try:
        manifest = json.load(open(manifest_path, encoding="utf-8"))
        if not isinstance(manifest, dict) or not manifest:
            PROBLEMS.append("profiles/manifest.json: must be a non-empty object")
        for profile_id, entry in (manifest.items() if isinstance(manifest, dict) else []):
            path = entry.get("path") if isinstance(entry, dict) else None
            declared_sha = entry.get("sha256") if isinstance(entry, dict) else None
            if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
                PROBLEMS.append(f"manifest {profile_id}: entry must be exactly path/sha256")
            if not isinstance(path, str) or not os.path.isabs(path):
                PROBLEMS.append(f"manifest {profile_id}: profile path is not absolute")
                continue
            try:
                inside = os.path.commonpath([os.path.realpath(path), os.path.realpath(WRAPPER)])
            except ValueError:
                inside = ""
            if inside != os.path.realpath(WRAPPER):
                PROBLEMS.append(f"manifest {profile_id}: profile escapes snapshot: {path}")
            if regular(path, f"manifest {profile_id} profile"):
                with open(path, "rb") as f:
                    actual_sha = hashlib.sha256(f.read()).hexdigest()
                if declared_sha != actual_sha:
                    PROBLEMS.append(
                        f"manifest {profile_id}: profile sha mismatch "
                        f"({str(declared_sha)[:12]} vs {actual_sha[:12]})")
    except Exception as e:
        PROBLEMS.append(f"profiles/manifest.json: invalid JSON/schema: {e}")

lib_path = os.path.join(HERE, "lib.py")
if regular(lib_path, "tests/lib.py(import)"):
    try:
        spec = importlib.util.spec_from_file_location("layout_local_lib", lib_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if os.path.realpath(module.TESTS) != os.path.realpath(HERE):
            PROBLEMS.append(f"tests/lib.py TESTS escapes snapshot: {module.TESTS}")
        if os.path.realpath(module.WRAPPER) != os.path.realpath(WRAPPER):
            PROBLEMS.append(f"tests/lib.py WRAPPER escapes snapshot: {module.WRAPPER}")
    except Exception as e:
        PROBLEMS.append(f"tests/lib.py cannot load: {e}")

# A disabled grant must exist only in test-build artifacts; the live/production source
# itself is always false + empty identity. This is not a profile oracle: it reads the
# shipped build's code constants directly, which profiles cannot influence.
preflight_path = os.path.join(WRAPPER, "preflight.py")
if regular(preflight_path, "preflight.py(test-build marker)"):
    try:
        spec = importlib.util.spec_from_file_location("layout_local_preflight", preflight_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if module.TEST_BUILD_SANDBOX_DISABLED is not False:
            PROBLEMS.append("production preflight test-build marker must be false")
        if module.TEST_BUILD_FAKE_CLI_REALPATH != "" or module.TEST_BUILD_FAKE_CLI_SHA256 != "":
            PROBLEMS.append("production preflight fake CLI identity constants must be empty")
    except Exception as e:
        PROBLEMS.append(f"preflight.py cannot load for test-build marker check: {e}")

# The snapshot's own executable sources must not quietly point back at the production
# tree. The literal is split apart so the checker doesn't match itself. What this check
# guards against: executable sources inside the snapshot copy secretly pointing at some
# "production tree". The production tree path is deployment-specific, so it comes from
# an environment variable. **If it's unset, say so plainly** — never skip silently;
# a check that can never fire is no check at all.
production_literal = os.environ.get("HB_PRODUCTION_WRAPPER", "")
if not production_literal:
    # 🔴 An empty string must not be used in an `in` test: `"" in anything` is always
    #    True, which would flag every file as a hit — a perpetually false-positive
    #    check is worse than no check.
    print("NOTE HB_PRODUCTION_WRAPPER is not set → skipping the 'source-points-back-to-production-tree' check")
code_paths = [os.path.join(WRAPPER, n) for n in (
    "hb-run.sh", "preflight.py", "inspector.py", "finish.py", "sandbox_launcher.py")]
for dirpath, _dirnames, filenames in os.walk(HERE):
    code_paths.extend(os.path.join(dirpath, n) for n in filenames
                      if n.endswith((".py", ".sh")))
for path in code_paths if production_literal else []:
    try:
        if production_literal in open(path, encoding="utf-8").read():
            PROBLEMS.append(f"{os.path.relpath(path, WRAPPER)} hard-codes production wrapper path")
    except OSError as e:
        PROBLEMS.append(f"cannot scan {os.path.relpath(path, WRAPPER)}: {e}")

if PROBLEMS:
    for problem in PROBLEMS:
        print("LAYOUT_FAIL", problem)
    sys.exit(1)
print(f"LAYOUT_OK wrapper={WRAPPER} cases={len(cases)} baselines={len(names)}")
