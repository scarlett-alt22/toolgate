#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate a working example profile and manifest for this machine.

Why not commit a ready-made JSON: preflight requires workspace / home / cli_realpath to
all be **absolute realpaths** (that gate exists to stop symlinks from pointing the
workspace elsewhere), so these values are necessarily machine-bound. Committing a profile
with someone else's hardcoded paths means the first thing a reader hits after cloning is
a bogus failure.

    python3 tools/make-example-profile.py
"""
import hashlib
import importlib.util
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def canonical_read_hash():
    """The example baseline pins the Read definition of this repo's own bundled fake CLI —
    anyone can reproduce it byte-for-byte."""
    spec = importlib.util.spec_from_file_location("insp", os.path.join(REPO, "inspector.py"))
    insp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(insp)
    sys.path.insert(0, os.path.join(REPO, "tests"))
    import fake_cli
    return hashlib.sha256(insp.canon_tool(fake_cli.READ_TOOL)).hexdigest()


def main():
    tmpl_path = os.path.join(REPO, "profiles", "example-loopback.template.json")
    with open(tmpl_path, encoding="utf-8") as f:
        prof = json.load(f)

    prof["workspace"] = os.path.join(REPO, "workspace")
    prof["home"] = os.path.join(REPO, "example-home")
    prof["cli_realpath"] = os.path.join(REPO, "tests", "fake_cli.py")
    prof["cli_sha256"] = sha(prof["cli_realpath"])
    prof["approved_tools"] = [{"name": "Read", "definition_sha256": canonical_read_hash()}]

    out = os.path.join(REPO, "profiles", "example-loopback.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(prof, f, ensure_ascii=False, indent=1)

    # the manifest pins the profile's own sha — it can only be computed after generation,
    # so the order can't be reversed
    man = {prof["profile_id"]: {"path": out, "sha256": sha(out)}}
    with open(os.path.join(REPO, "profiles", "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f, ensure_ascii=False, indent=1)

    os.makedirs(prof["workspace"], exist_ok=True)
    print(f"wrote {os.path.relpath(out, REPO)} and profiles/manifest.json")
    print(f"approved Read definition sha256 = {prof['approved_tools'][0]['definition_sha256']}")


if __name__ == "__main__":
    main()
