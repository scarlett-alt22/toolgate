# -*- coding: utf-8 -*-
"""The toolgate command line.

Product criterion (written here so the next person to change it sees it):
**On day one, before you understand the threat model, it has to tell you something you could not see before.**
That is why the default is `watch` (observe, block nothing) rather than `enforce`;
and why the output is a **diff** rather than "hash mismatch". Same data: one is a refusal, the other is intelligence.
"""
import argparse
import difflib
import json
import os
import sys

from . import config as cfg_mod
from . import runner

# ── Output helpers (no third-party dependencies: a security tool's dependency surface is its attack surface) ──────
def _c(code, s):
    return s if not sys.stdout.isatty() else "\033[{}m{}\033[0m".format(code, s)


def red(s):
    return _c("31", s)


def green(s):
    return _c("32", s)


def yellow(s):
    return _c("33", s)


def dim(s):
    return _c("2", s)


def canonical_text(defn):
    """Canonical form for humans: sorted keys + indentation. The hash is computed on the compact form; this is only for readability."""
    return json.dumps(defn, ensure_ascii=False, indent=2, sort_keys=True).splitlines()


def observed_pairs(rows):
    """Observation archive → de-duplicated list of (name, hash), in order of first appearance.

    🔴 This must **not** keep only the last entry per name (the original implementation did). One name can legitimately map to several
       definitions (client versions / modes / projects); keeping only the last makes the earlier one vanish from
       the candidates, so after approve it becomes "unapproved" — and legitimate traffic gets blocked.
    """
    out, seen = [], set()
    for r in rows:
        key = (r.get("name"), r.get("definition_sha256"))
        if key[0] and key[1] and key not in seen:
            seen.add(key)
            out.append(r)
    return out


def convergence(d):
    """Has the tool surface converged: returns (number of runs that contributed a new definition, how many the latest run added).

    🔴 This function exists because real traffic forced it: an agent's tool surface is **disclosed gradually across requests**.
       Measured: running the same `claude -p` command twice, the first run advertised only `Agent`, the second only `Bash`.
       So "watch once → approve → enforce" blocks all the remaining legitimate traffic —
       and the user concludes this tool is broken. **The product has to say "still growing" itself, not wait for the user to hit it.**
    """
    rows = cfg_mod.load_surface(d)
    runs_dir = os.path.join(d, "runs")
    all_runs = sorted(os.listdir(runs_dir)) if os.path.isdir(runs_dir) else []
    last = all_runs[-1] if all_runs else None
    contributing = len({r.get("run") for r in rows if r.get("run")})
    new_last = sum(1 for r in rows if last and r.get("run") == last)
    # 🔴 When a row has no `run` field (written by an older version), **never say "converged"** —
    #    a missing field is not evidence of convergence, it only means I don't know. Saying "looks stable" leads straight to
    #    the user switching to enforce and getting blocked.
    unknown = any(not r.get("run") for r in rows)
    return contributing, new_last, len(all_runs), unknown


def _converge_note(d):
    contributing, new_last, total_runs, unknown = convergence(d)
    if unknown:
        print(dim("  Some observations predate run tracking, so whether the surface has "
                  "settled cannot be told from this store. Run `watch` a few more times."))
        return
    if total_runs and new_last:
        print(yellow(
            "  Heads up: the most recent run still discovered {} new definition(s). "
            "A tool surface is revealed request by request, so it is probably not "
            "complete yet — keep running `watch` over your normal usage before you "
            "`enforce`, or enforce will block traffic that was always legitimate."
            .format(new_last)))
    elif total_runs > 1 and not new_last:
        # 🔴 Don't say "settled". A18 ruled on this: the word reads as a guarantee, and it isn't one —
        #    approve closes the **observed candidate list**, not the client's unknown complete catalogue.
        print(dim("  Last run added no definitions ({} runs, {} of them contributed). "
                  "Coverage is workload-dependent: approving closes the observed "
                  "candidate manifest, not the client's full catalog."
                  .format(total_runs, contributing)))


def compute_diff(d):
    """Returns (added, drift, unchanged). The core computation of the product.

    · added     — a (name, hash) never approved. Usually just the first time this tool has been disclosed.
    · drift     — the name was approved, but this hash was not. **This is the reason the gate exists.**
    · unchanged — (name, hash) is already in the approved set.

    🔴 **There is no "gone".** An approved tool absent from this round is **not drift**, just not disclosed this round —
       the tool surface is disclosed gradually across requests. Treating "absent" as an anomaly makes normal use alarm every day,
       and a channel that raises a false alarm every day has a capacity of zero.
    """
    doc = cfg_mod.load_approved(d)
    pairs = cfg_mod.approved_pairs(doc)
    names = set(cfg_mod.approved_names(doc))
    by_name = {}
    for e in cfg_mod.approved_entries(doc):
        by_name.setdefault(e["name"], []).append(e)

    added, drift, unchanged = [], [], []
    for r in observed_pairs(cfg_mod.load_surface(d)):
        key = (r["name"], r["definition_sha256"])
        if key in pairs:
            unchanged.append(r)
        elif r["name"] in names:
            drift.append((r, by_name[r["name"]]))
        else:
            added.append(r)
    added.sort(key=lambda r: r["name"])
    drift.sort(key=lambda t: t[0]["name"])
    return added, drift, unchanged


# ── Subcommands ──────────────────────────────────────────────────────────
def cmd_init(args):
    d = cfg_mod.home(args.dir)
    if os.path.exists(cfg_mod.config_path(d)) and not args.force:
        print("already exists: {} (use --force to overwrite)".format(cfg_mod.config_path(d)))
        return 1
    cfg = dict(cfg_mod.DEFAULT_CONFIG)
    preset = cfg_mod.PRESETS.get(args.format)
    if preset is None:
        print(red("unknown --format {!r}; choose from: {}".format(
            args.format, ", ".join(sorted(cfg_mod.PRESETS)))))
        return 2
    cfg.update(preset)
    if args.upstream:
        cfg["upstream"] = args.upstream
    cfg_mod.save_config(d, cfg)
    print("wrote {}".format(cfg_mod.config_path(d)))
    print()
    print("Next (this blocks nothing — it only watches):")
    print("    toolgate watch -- <however you normally run your agent>")
    return 0


def _summarise(d, log_path, mode, base_url_env="ANTHROPIC_BASE_URL"):
    events = runner.read_events(log_path)
    reqs = [e for e in events if e.get("event") == "request"]
    forwarded = [r for r in reqs if r.get("decision") == "forward"]
    blocked = [r for r in reqs if r.get("decision") == "block"]
    would = [r for r in reqs if r.get("would_block")]
    print()
    print("── this run ──────────────────────────")
    print("  requests {}   forwarded {}   blocked {}".format(len(reqs), len(forwarded), len(blocked)))
    if mode == "observe" and would:
        print("  " + yellow("would be blocked under `enforce`: {}".format(len(would))))
        seen = {}
        for r in would:
            reason = str(r.get("would_block_reason") or "")
            seen[reason] = seen.get(reason, 0) + 1
        for reason, n in sorted(seen.items(), key=lambda kv: -kv[1]):
            print("    {:>3}×  {}".format(n, reason))
    if not reqs:
        # 🔴 This message must name **the variable this config actually uses**. Hard-coding one vendor sends people on the OpenAI preset
        #    looking in entirely the wrong place, and "no traffic" is already the hardest symptom to self-diagnose.
        print("  " + dim("No requests passed through the gate. Does your command "
                         "actually read ${}?".format(base_url_env)))
    return events


def cmd_watch(args, mode="observe"):
    d = cfg_mod.home(args.dir)
    cfg = cfg_mod.load_config(d)
    if mode == "enforce" and cfg.get("model") is None:
        print(red("enforce needs `model` declared in config.json — "
                  "you cannot enforce what you never declared."))
        print("Run `toolgate watch` once, then `toolgate approve` — it fills this in for you.")
        return 2
    rc, log_path, _run_dir = runner.run(d, cfg, mode, args.command)
    _summarise(d, log_path, mode, cfg.get("base_url_env", "ANTHROPIC_BASE_URL"))
    if mode == "observe":
        print()
        _print_diff(d, brief=True)
        _converge_note(d)
    return rc


def cmd_enforce(args):
    return cmd_watch(args, mode="enforce")


def _print_diff(d, brief=False):
    added, drift, unchanged = compute_diff(d)
    if not (added or drift):
        if unchanged:
            print(green("Every observed definition is one you approved ({} of them)."
                        .format(len(unchanged))))
        else:
            print(dim("No tool definitions observed yet. Run `toolgate watch` once."))
        return 0
    print("── tool surface ──────────────────────")
    # 🔴 Report the two kinds separately; to the user they are entirely different things:
    #    NEW   = this tool is disclosed for the first time (the surface is disclosed request by request; usually just not seen yet)
    #    DRIFT = a name you approved now has a different definition — **this is the reason the gate exists**
    for r in added:
        print(yellow("  NEW    {}  {}".format(r["name"], r["definition_sha256"][:12])))
    for r, variants in drift:
        print(red("  DRIFT  {}".format(r["name"])))
        print("         observed {}".format(r["definition_sha256"][:12]))
        print("         approved {}".format(
            ", ".join(v["definition_sha256"][:12] for v in variants)))
        if not brief:
            base = variants[-1]
            for line in difflib.unified_diff(
                    canonical_text(base.get("definition", {})),
                    canonical_text(r.get("definition", {})),
                    fromfile="approved/" + r["name"], tofile="observed/" + r["name"],
                    lineterm=""):
                if line.startswith("+") and not line.startswith("+++"):
                    print("    " + green(line))
                elif line.startswith("-") and not line.startswith("---"):
                    print("    " + red(line))
                else:
                    print("    " + dim(line))
    if brief and drift:
        print(dim("  (run `toolgate diff` for the exact difference)"))
    print()
    print("`toolgate approve` adds these to the approved manifest. It only ever adds — "
          "approving a new variant never removes one you approved before.")
    return 1


def cmd_diff(args):
    return _print_diff(cfg_mod.home(args.dir), brief=False)


def cmd_surface(args):
    d = cfg_mod.home(args.dir)
    rows = cfg_mod.load_surface(d)
    if not rows:
        print(dim("No tool definitions observed yet."))
        return 0
    for r in rows:
        print("{}  {}  first seen {}".format(
            r["definition_sha256"][:12], r.get("name"), r.get("first_seen_at")))
    return 0


def cmd_approve(args):
    d = cfg_mod.home(args.dir)
    added, drift, _unchanged = compute_diff(d)
    if not (added or drift):
        print(green("Nothing to approve."))
        return 0
    doc = cfg_mod.load_approved(d)
    # 🔴 **Add only, never remove.** The approved list is a set of (name, hash); approving a new variant never removes
    #    an earlier approval — otherwise "the next run only showed Bash" would push out the previously approved Agent,
    #    and next time it would be unapproved, though it was legitimate all along.
    entries = cfg_mod.approved_entries(doc)
    import time as _t
    stamp = _t.strftime("%Y-%m-%dT%H:%M:%S")
    for r in added:
        entries.append({"name": r["name"], "definition_sha256": r["definition_sha256"],
                        "definition": r.get("definition"), "approved_at": stamp})
        print(green("approved (new tool)     {}  {}".format(
            r["name"], r["definition_sha256"][:12])))
    for r, _variants in drift:
        entries.append({"name": r["name"], "definition_sha256": r["definition_sha256"],
                        "definition": r.get("definition"), "approved_at": stamp})
        print(green("approved (new variant)  {}  {}".format(
            r["name"], r["definition_sha256"][:12])))
    cfg_mod.save_approved(d, {"version": cfg_mod.SCHEMA_VERSION, "tools": entries})
    print()
    _converge_note(d)

    # While we're at it, fill the observed model into the config — enforce needs it, and the user shouldn't have to copy it by hand
    cfg = cfg_mod.load_config(d)
    if cfg.get("model") is None:
        model = _observed_model(d)
        if model:
            cfg["model"] = model
            cfg_mod.save_config(d, cfg)
            print(dim("also recorded the observed model in config: {}".format(model)))
    print()
    print("You can now run `toolgate enforce -- <your command>`.")
    print(dim("Note: approving means \"this definition is the one I read, and not one "
              "byte of it may change\" — not \"this tool is safe\"."))
    return 0


def _observed_model(d):
    runs = os.path.join(d, "runs")
    if not os.path.isdir(runs):
        return None
    for sub in sorted(os.listdir(runs), reverse=True):
        log = os.path.join(runs, sub, "inspector.jsonl")
        for e in runner.read_events(log):
            if e.get("event") == "request" and e.get("model"):
                return e["model"]
    return None


def cmd_status(args):
    d = cfg_mod.home(args.dir)
    print("state dir  {}".format(d))
    if not os.path.exists(cfg_mod.config_path(d)):
        print(dim("not initialised — run `toolgate init`."))
        return 1
    cfg = cfg_mod.load_config(d)
    print("upstream   {}".format(cfg["upstream"]))
    print("model      {}".format(cfg.get("model") or dim("null (undeclared; enforce will refuse)")))
    approved = cfg_mod.approved_entries(cfg_mod.load_approved(d))
    print("approved   {} definitions across {} names".format(
        len(approved), len({e["name"] for e in approved})))
    observed = latest_by_name(cfg_mod.load_surface(d))
    print("observed   {} tools".format(len(observed)))
    print()
    _converge_note(d)
    return _print_diff(d, brief=True)


def build_parser():
    p = argparse.ArgumentParser(
        prog="toolgate",
        description="Watch and pin the tool definitions your agent advertises on the wire.")
    p.add_argument("--dir", help="state directory (default ./.toolgate or $TOOLGATE_HOME)")
    sub = p.add_subparsers(dest="cmd")

    q = sub.add_parser("init", help="create the config")
    q.add_argument("--upstream", help="upstream API origin (overrides the preset)")
    q.add_argument("--format", default="anthropic",
                   help="wire format preset: anthropic | openai-chat | openai-responses")
    q.add_argument("--force", action="store_true")
    q.set_defaults(func=cmd_init)

    q = sub.add_parser("watch", help="run once in observe mode (blocks nothing)")
    q.add_argument("command", nargs=argparse.REMAINDER)
    q.set_defaults(func=cmd_watch)

    q = sub.add_parser("enforce", help="run once in enforce mode (unapproved definitions are blocked)")
    q.add_argument("command", nargs=argparse.REMAINDER)
    q.set_defaults(func=cmd_enforce)

    q = sub.add_parser("diff", help="observed vs approved, byte-exact difference")
    q.set_defaults(func=cmd_diff)

    q = sub.add_parser("surface", help="list the observed tool definitions")
    q.set_defaults(func=cmd_surface)

    q = sub.add_parser("approve", help="record the currently observed surface as approved")
    q.set_defaults(func=cmd_approve)

    q = sub.add_parser("status", help="current state")
    q.set_defaults(func=cmd_status)
    return p


def main(argv=None):
    p = build_parser()
    args = p.parse_args(argv)
    if not getattr(args, "func", None):
        p.print_help()
        return 0
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]
    return args.func(args)
