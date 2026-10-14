#!/usr/bin/env python3
"""Discriminative power regression for the six Seatbelt cells — proving the test suite
isn't giving itself a green light.

If a fully-green sandbox test suite also goes fully green against a weakened
profile, it proves itself, not the sandbox. So every cell gets a mutant: remove
the rule in the profile that guards it, and that cell **must** go red while the
others **must** stay green (otherwise the cells are entangled and a red tells
you nothing about who went red).

The upper-bound check (allow default) gets its own cell: with everything open,
all nine cells must go red. Without it, "DNS fails inside the sandbox" could
just mean the probe never ran inside the sandbox at all.

Usage:  python3 tests/seatbelt_mutations.py
Exit 0 = every mutant reddened exactly the expected cells, and only those.
"""

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.dirname(HERE)
PROFILE = os.path.join(WRAPPER, "sandbox", "hb-read.sb")
SIX = os.path.join(HERE, "seatbelt_six.py")
PY3 = "/Library/Developer/CommandLineTools/usr/bin/python3"

ALL_CELLS = {"G1", "G2", "G3.input", "G3.home", "G3.tmp", "G3.cache", "G4", "G5.ip", "G5.dns"}

# (name, weakening rule appended to the profile, cells expected to go red, note)
# None as append means replace the whole thing with allow default.
MUTANTS = [
    ("m1-net-any-ip", '(allow network-outbound (remote ip "*:*"))',
     {"G4", "G5.ip"},
     "open arbitrary IP:port. G5.dns must not go red — DNS goes over a unix socket, outside remote ip's coverage."),
    ("m2-read-all", "(allow file-read*)",
     {"G1", "G2"},
     "whole-disk read fully open. G1 goes red too because its anti-arm is an out-of-bounds read."),
    ("m3-write-all", "(allow file-write*)",
     {"G3.input", "G3.home", "G3.tmp", "G3.cache"},
     "write surface fully open, all four write cells go red."),
    ("m4-network-unrestricted", "(allow network-outbound)",
     {"G4", "G5.ip", "G5.dns"},
     "no remote qualifier — this is the rule that actually gates DNS, all three network cells go red."),
    ("m5-allow-default", None, ALL_CELLS,
     "upper-bound check: fully open must redden all nine cells. Not red means the sandbox wasn't actually under test."),
]


def run_six(profile_path):
    env = dict(os.environ, HB_SEATBELT_PROFILE=profile_path)
    p = subprocess.run([PY3, SIX], capture_output=True, text=True, env=env, timeout=600)
    failed = set()
    for line in p.stdout.splitlines():
        if line.startswith("[FAIL] "):
            failed.add(line.split()[1])
    return failed, p.stdout


def main():
    with open(PROFILE) as f:
        base = f.read()

    print("=== baseline: production profile must be nine-for-nine green ===")
    baseline_failed, _ = run_six(PROFILE)
    if baseline_failed:
        print(f"ABORT: production profile itself is not all green, red cells: {sorted(baseline_failed)}")
        print("mutation testing is meaningless in this state — fix the baseline to green first.")
        return 2
    print("baseline 9/9 green\n")

    results = []
    ok = True
    tmpdir = tempfile.mkdtemp(prefix="hb-seatbelt-mut-")
    for name, append, expect_red, why in MUTANTS:
        path = os.path.join(tmpdir, f"{name}.sb")
        with open(path, "w") as f:
            f.write("(version 1)\n(allow default)\n" if append is None
                    else base + f"\n; MUTANT {name}\n{append}\n")
        got_red, _ = run_six(path)
        passed = got_red == expect_red
        ok = ok and passed
        results.append({
            "mutant": name, "why": why,
            "expected_red": sorted(expect_red), "actual_red": sorted(got_red),
            "unexpected_red": sorted(got_red - expect_red),
            "missed_red": sorted(expect_red - got_red),
            "pass": passed,
        })
        print(f"[{'OK ' if passed else 'BAD'}] {name}")
        print(f"      {why}")
        if not passed:
            print(f"      expected red {sorted(expect_red)}")
            print(f"      actual red {sorted(got_red)}")
            if got_red - expect_red:
                print(f"      🔴 unexpectedly red {sorted(got_red - expect_red)} (cells entangled)")
            if expect_red - got_red:
                print(f"      🔴 missed red {sorted(expect_red - got_red)} (this cell guards nothing)")

    out = os.path.join(WRAPPER, "runs", "seatbelt", "mutations-latest.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    payload = {"baseline_all_green": True, "mutants": results,
               "verdict": "MUTATIONS_PASS" if ok else "MUTATIONS_FAIL"}
    with open(out, "w") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    print(f"\n{payload['verdict']}  →  {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
