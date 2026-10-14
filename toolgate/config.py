# -*- coding: utf-8 -*-
"""User-facing configuration and the state directory.

Design constraints (not style preferences):

- **No credentials in the config.** Your API key is carried by the wrapped command itself; this tool forwards it as-is,
  neither checking nor logging it. The config file can therefore go into version control.
- **`model` may be null.** In observe mode it means "not declared yet"; in enforce mode a null
  is rejected by the inspector at startup — no declaration, no right to enforce.
- **What you approved is stored separately** (`approved.json`) from what was observed (`surface.jsonl`).
  Observation is fact, approval is judgement; keep them in one file and sooner or later each contaminates the other.
"""
import json
import os
import secrets

DEFAULT_DIR = ".toolgate"
CONFIG_NAME = "config.json"
SURFACE_NAME = "surface.jsonl"
APPROVED_NAME = "approved.json"

# ── Wire-format presets ──────────────────────────────────────────────────
# 🔴 Why `base_url_suffix` exists: each vendor's SDK appends a different path to the base URL.
#    Anthropic's base is the origin, and the SDK appends `/v1/messages` itself;
#    OpenAI's base conventionally already includes `/v1`, and the SDK only appends `/chat/completions`.
#    Getting this cell wrong raises no error; requests simply never reach the gate — which looks exactly like "no traffic".
PRESETS = {
    "anthropic": {
        "wire_format": "anthropic_messages",
        "upstream": "https://api.anthropic.com",
        "messages_path": "/v1/messages?beta=true",
        "base_url_env": "ANTHROPIC_BASE_URL",
        "base_url_suffix": "",
    },
    "openai-chat": {
        "wire_format": "openai_chat_completions",
        "upstream": "https://api.openai.com",
        "messages_path": "/v1/chat/completions",
        "base_url_env": "OPENAI_BASE_URL",
        "base_url_suffix": "/v1",
    },
    "openai-responses": {
        "wire_format": "openai_responses",
        "upstream": "https://api.openai.com",
        "messages_path": "/v1/responses",
        "base_url_env": "OPENAI_BASE_URL",
        "base_url_suffix": "/v1",
    },
}

DEFAULT_CONFIG = {
    "version": 1,
    "wire_format": "anthropic_messages",
    "base_url_suffix": "",
    # The upstream API. Both observe and enforce modes really forward traffic here.
    "upstream": "https://api.anthropic.com",
    "messages_path": "/v1/messages?beta=true",
    # Which environment variable the client reads its base URL from. For the Anthropic family it is ANTHROPIC_BASE_URL.
    "base_url_env": "ANTHROPIC_BASE_URL",
    # null = not declared yet. observe skips the model check; enforce is rejected at startup.
    "model": None,
    "max_body_bytes": 2 * 1024 * 1024,
    "timeout_seconds": 600,
}


def home(explicit=None):
    """State directory. --dir first, then $TOOLGATE_HOME, finally ./.toolgate."""
    return os.path.abspath(explicit or os.environ.get("TOOLGATE_HOME") or DEFAULT_DIR)


def config_path(d):
    return os.path.join(d, CONFIG_NAME)


def surface_path(d):
    return os.path.join(d, SURFACE_NAME)


def approved_path(d):
    return os.path.join(d, APPROVED_NAME)


def load_config(d):
    p = config_path(d)
    if not os.path.exists(p):
        raise SystemExit(
            "no config at {} — run `toolgate init` first.".format(p))
    with open(p, encoding="utf-8") as f:
        cfg = json.load(f)
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    return merged


def save_config(d, cfg):
    os.makedirs(d, exist_ok=True)
    with open(config_path(d), "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


def load_surface(d):
    """Observed tool definitions (append-only, de-duplicated by hash, written by the inspector)."""
    p = surface_path(d)
    rows = []
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rows.append(json.loads(line))
    return rows


def load_approved(d):
    p = approved_path(d)
    if not os.path.exists(p):
        return {"version": 1, "tools": {}}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_approved(d, approved):
    os.makedirs(d, exist_ok=True)
    with open(approved_path(d), "w", encoding="utf-8") as f:
        json.dump(approved, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


# ── Data model of the approved list (v2, 2026-08-15, spec from external ruling A18 §Q4) ──────
# 🔴 v1 was {name: one hash}: **one name could have only one definition**. That was wrong: the same tool
#    legitimately has different definitions in different contexts (client versions, modes, projects).
#    v2 is a **set of (name, hash)**:
#        tools in the request ⊆ approved set   → forward
#        approved name + new hash               → block (contract_drift)
#        never approved                         → block (tool_added)
#        approved but absent this round         → **not drift**, just not disclosed this round
#    The last line is the easiest to get wrong, and getting it wrong looks like "legitimate traffic suddenly blocked".
SCHEMA_VERSION = 2


def _entries(approved):
    """Accepts v1 (dict) and v2 (list). v1 is read as exactly one definition per name."""
    tools = approved.get("tools")
    if isinstance(tools, dict):          # v1
        return [{"name": n, **rec} for n, rec in tools.items()]
    return list(tools or [])             # v2


def approved_entries(approved):
    return _entries(approved)


def approved_map(approved):
    """{identifier: definition_sha256} for the inspector.

    Keys are only identifiers; the gate looks only at the set of values — so one name can have several approved definitions.
    """
    return {"{}#{}".format(e["name"], e["definition_sha256"][:12]): e["definition_sha256"]
            for e in _entries(approved)}


def approved_names(approved):
    """The set of names ever approved. The gate uses it to report "something you approved has changed" and
    "something new you have never seen" separately — to the user those are entirely different things."""
    return sorted({e["name"] for e in _entries(approved) if e.get("name")})


def approved_pairs(approved):
    return {(e["name"], e["definition_sha256"]) for e in _entries(approved)}


def new_capability_path():
    """A random prefix per run. It is not a security boundary (processes under the same UID can see it);
    it prevents misconnection: something that happens to hit this port will not be counted as this run's traffic."""
    return secrets.token_hex(20)
