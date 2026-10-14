#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake CLI — stands in for the real `claude`, issuing requests per a script.

Why it exists (spec:348 demands mock-only): the real CLI costs money every run, and we
can't control its turn structure — **acceptance needs exactly the bad cases the real CLI
won't manufacture for us** (advertise one extra Bash, same name with a swapped schema,
bad-JSON body, copied challenge…).

It must match the real CLI in two things, or it's not the same thing being tested:
  ① send Messages requests to the ANTHROPIC_BASE_URL address (via the inspector)
  ② finally emit a `--output-format json`-shaped result to stdout,
     with is_error / result / permission_denials — measured 08-07: when blocked, the CLI
     still reported is_error=false / exit 0, and that "lying shape" must be faithfully
     reproduced.

The script comes from --scenario. Each step describes **what this one HTTP request looks
like**; deliberately illegal requests are allowed — they're the upper-bound test subjects.
"""
import argparse
import json
import os


def _stub_scenario():
    """The stub's own knobs (variant / second_origin), read from a file in the workspace.

    ★2026-08-08 moved from env vars to a file: hb-run now spawns the CLI with `env -i` +
    allowlist, so the environment never reaches here — which is correct; the real CLI
    shouldn't take ambient configuration either.
    hb-run `cd`s into that attempt's workspace, so the CWD is each case's own directory.
    Missing file = happy (also the right default for running this stub by hand).
    """
    try:
        with open(os.path.join(os.getcwd(), ".hb_fake_scenario.json")) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError, OSError):
        return {}
import re
import sys
import uuid
import urllib.error
import urllib.request

READ_TOOL = {
    "name": "Read",
    "description": "Read a file from the local filesystem.",
    "input_schema": {
        "type": "object",
        "properties": {"file_path": {"type": "string"}},
        "required": ["file_path"],
    },
}


def auth_headers():
    """Mirror the real CLI: send `ANTHROPIC_AUTH_TOKEN` as a Bearer credential.

    ★2026-08-08 added. Before this the stub sent **no Authorization at all**,
    so the inspector's newly added credential gate was never reached — that gate was
    effectively untested.
    "The stub doesn't send" and "the gate lets through" look identical in the artifacts;
    that's the very shape we've been chasing.

    `HB_FAKE_DECOY_AUTH` exists only for the `ub-decoy-authorization` cell:
    it makes the stub send something **shaped like a real credential but never any real
    token**, so the counter-example and the positive example differ by exactly this one
    variable.
    """
    decoy = os.environ.get("HB_FAKE_DECOY_AUTH")
    if decoy:
        return {"Authorization": decoy}
    token = os.environ.get("ANTHROPIC_AUTH_TOKEN")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def tool_variant(kind):
    """Build the tools field. Each variant maps to one upper-bound case in cases.json."""
    import copy
    read = copy.deepcopy(READ_TOOL)
    if kind == "empty":
        return []
    if kind == "read":
        return [read]
    if kind == "extra_bash":
        return [read, {"name": "Bash", "description": "Run a command.", "input_schema": {"type": "object"}}]
    if kind == "extra_write":
        return [read, {"name": "Write", "description": "Write a file.", "input_schema": {"type": "object"}}]
    if kind == "duplicate_read":
        return [read, copy.deepcopy(READ_TOOL)]
    if kind == "same_name_diff_schema":
        mutated = copy.deepcopy(READ_TOOL)
        mutated["input_schema"]["properties"]["command"] = {"type": "string"}
        return [mutated]
    if kind == "elem_not_object":
        return ["Read"]
    if kind == "name_absent":
        return [{"description": "no name here", "input_schema": {"type": "object"}}]
    if kind == "name_empty":
        r = copy.deepcopy(READ_TOOL); r["name"] = ""; return [r]
    if kind == "name_not_string":
        r = copy.deepcopy(READ_TOOL); r["name"] = 123; return [r]
    raise SystemExit(f"fake_cli: unknown tool variant {kind}")


def build_body(step, model):
    """Return (raw_bytes, note). Deliberately supports producing illegal bodies."""
    kind = step.get("tools", "empty")

    if kind == "missing_tools":
        return json.dumps({"model": model, "messages": []}).encode(), "no tools key"
    if kind == "tools_not_array":
        return json.dumps({"model": model, "messages": [], "tools": {"name": "Read"}}).encode(), "tools is object"
    if kind == "bad_json":
        return b'{"model": "' + model.encode() + b'", "tools": [', "truncated json"
    if kind == "root_array":
        return json.dumps([{"model": model, "tools": []}]).encode(), "root array"
    if kind == "duplicate_tools_key":
        # The first copy carries the unauthorized Bash, the second is empty. A parser taking
        # first/last would see different capability sets; these raw bytes must be rejected
        # directly in the inspector — no side may choose for the other.
        return (b'{"model":' + json.dumps(model).encode()
                + b',"messages":[],"tools":[{"name":"Bash"}],"tools":[]}'), "duplicate tools key"
    if kind == "json_nan":
        return (b'{"model":' + json.dumps(model).encode()
                + b',"messages":[],"tools":[],"max_tokens":NaN}'), "NaN"
    if kind == "json_infinity":
        return (b'{"model":' + json.dumps(model).encode()
                + b',"messages":[],"tools":[],"max_tokens":Infinity}'), "Infinity"
    if kind == "nested_duplicate_key":
        return (b'{"model":' + json.dumps(model).encode()
                + b',"messages":[{"role":"user","content":"a","content":"b"}],'
                  b'"tools":[]}'), "nested duplicate key"
    if kind == "oversize":
        pad = "x" * step.get("pad_bytes", 3 * 1024 * 1024)
        return json.dumps({"model": model, "messages": [{"role": "user", "content": pad}], "tools": []}).encode(), "oversize"

    body = {
        "model": step.get("model_override", model),
        "max_tokens": 1024,
        "messages": step.get("messages", [{"role": "user", "content": "probe"}]),
        "tools": tool_variant(kind),
    }
    # ★2026-08-09 A8 §3: the pre-forwarding rejection of a non-bool `stream` never had a
    # regression case.
    # `"true"` (the string) is the ugliest kind — it looks like true, and the scanner
    # relies on it to decide whether the response reads as SSE or JSON. A request the
    # scanner can't classify must not be let through.
    if "stream_override" in step:
        body["stream"] = step["stream_override"]
    return json.dumps(body).encode(), kind


def run_happy(base, path, model, variant="happy"):
    """The three-round positive case: [] -> [Read]+tool_use -> [Read]+tool_result.

    It **really reads** the sentinel file (the real CLI does too), so the challenge isn't
    made up. The mock side answers a tool_use block via `_mock_tool_use` — the inspector
    doesn't care where the response comes from; it only records the structural evidence.
    """
    import urllib.request as U
    prompt = sys.stdin.read() if not sys.stdin.isatty() else ""
    m = re.search(r"read the file (\S+)", prompt)
    sentinel = m.group(1) if m else ""
    challenge = open(sentinel).read().strip() if sentinel and os.path.exists(sentinel) else ""

    def post(body):
        req = U.Request(base.rstrip("/") + path, data=json.dumps(body).encode(),
                        method="POST",
                        headers={"Content-Type": "application/json", **auth_headers()})
        try:
            with U.urlopen(req, timeout=20) as r:
                return r.status, r.read()
        except Exception as e:
            return getattr(e, "code", None), b""

    tools = [READ_TOOL]
    first = {"model": model, "max_tokens": 1024, "tools": [],
             "messages": [{"role": "user", "content": "start"}]}
    if variant == "upstream_500":
        first["_mock_status_500"] = True
    if variant == "upstream_incomplete":
        first["_mock_incomplete"] = True
    if variant == "upstream_redirect":
        first["_mock_redirect"] = _stub_scenario().get("second_origin", "")
    post(first)

    if variant in ("no_tooluse", "challenge_copied"):
        # The whole run was an approved subset, but no real Read ever happened — the lower
        # bound must judge it a miss.
        post({"model": model, "max_tokens": 1024, "tools": tools,
              "messages": [{"role": "user", "content": "no tool use at all"}]})
        return challenge

    uid = "toolu_" + uuid.uuid4().hex[:12]
    use_path = sentinel if variant != "wrong_path" else os.path.join(os.path.dirname(sentinel), "elsewhere.txt")
    post({"model": model, "max_tokens": 1024, "tools": tools,
          "messages": [{"role": "user", "content": "read it"}],
          "_mock_tool_use": {"id": uid, "file_path": use_path}})

    result_id = uid if variant != "id_mismatch" else "toolu_" + uuid.uuid4().hex[:12]
    content = challenge
    if variant == "result_no_challenge":
        content = "nothing useful here"
    block = {"type": "tool_result", "tool_use_id": result_id, "content": content}
    if variant == "result_error":
        block["is_error"] = True
    post({"model": model, "max_tokens": 1024, "tools": tools,
          "messages": [{"role": "user", "content": [block]}]})
    return challenge


def main():
    # preflight spawns `<cli> --version` to check version drift; the stub must answer it
    if "--version" in sys.argv[1:]:
        print("fake-cli/1", flush=True)
        return 0
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default=None)  # not given = happy mode (hb-run passes the real CLI's flag set)
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    # Accept but ignore all of the real CLI's flags: the wrapper passes them through verbatim,
    # and failing to accept them means testing a fake.
    for flag in ("--settings", "--setting-sources", "--permission-mode", "--tools",
                 "--mcp-config", "--output-format", "--max-budget-usd"):
        ap.add_argument(flag, default=None)
    for flag in ("--safe-mode", "--no-chrome", "--strict-mcp-config", "--no-session-persistence"):
        ap.add_argument(flag, action="store_true")
    args, _unknown = ap.parse_known_args()

    scenario = json.load(open(args.scenario)) if args.scenario else {"mode": "happy"}
    base = os.environ.get("ANTHROPIC_BASE_URL", "")
    if not base:
        print(json.dumps({"is_error": True, "result": "no ANTHROPIC_BASE_URL"}), flush=True)
        return 2

    # 🔴 the stub obeys this too: it must never hit the real origin (spec:348)
    if "anthropic.com" in base:
        sys.stderr.write("fake_cli: refusing — ANTHROPIC_BASE_URL points at the real origin\n")
        return 90

    path = scenario.get("messages_path", "/v1/messages?beta=true")
    if scenario.get("mode") == "happy":
        variant = _stub_scenario().get("variant", "happy")
        if variant == "sleep":
            import time as _t; _t.sleep(600); return 0
        ch = run_happy(base, path, args.model, variant)
        payload = json.dumps({"ok": True, "task": "done"}, sort_keys=True)
        if variant == "final_json_bad":
            payload = json.dumps({"unexpected": 1}, sort_keys=True)
        out = f"{ch}\n{payload}"
        if variant == "challenge_not_first":
            out = f"preamble line\n{ch}\n{payload}"
        denials = [{"tool_name": "Read"}] if variant == "permission_denial" else []
        print(json.dumps({"type": "result", "is_error": False, "stop_reason": "end_turn",
                          "result": out, "permission_denials": denials},
                         ensure_ascii=False), flush=True)
        return 7 if variant == "cli_nonzero" else 0
    statuses = []
    for step in scenario.get("steps", []):
        raw, note = build_body(step, args.model)
        url = base.rstrip("/") + step.get("path_override", path)
        req = urllib.request.Request(
            url, data=raw, method=step.get("method", "POST"),
            headers={"Content-Type": "application/json", "anthropic-version": "2023-06-01",
                     **auth_headers()},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                statuses.append({"note": note, "status": r.status, "bytes": len(r.read())})
        except urllib.error.HTTPError as e:
            statuses.append({"note": note, "status": e.code, "bytes": 0})
        except Exception as e:
            statuses.append({"note": note, "status": None, "error": type(e).__name__})

    # Final stdout: mirrors the real CLI's --output-format json shape.
    # ⚠️ the default is_error=False is **deliberate**: measured 08-07, the blocked real CLI
    #    reported it exactly this way too;
    #    acceptance must prove the shell doesn't judge success off this field.
    final = {
        "type": "result",
        "is_error": scenario.get("is_error", False),
        "stop_reason": scenario.get("stop_reason", "end_turn"),
        "result": scenario.get("result", ""),
        "permission_denials": scenario.get("permission_denials", []),
        "_fake_cli_request_statuses": statuses,
    }
    print(json.dumps(final, ensure_ascii=False), flush=True)
    return scenario.get("exit_code", 0)


if __name__ == "__main__":
    sys.exit(main())
