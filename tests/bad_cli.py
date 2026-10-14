#!/usr/bin/env python3
# Counter-example fake CLI: advertises one extra Bash (blocked before forwarding),
# then exits non-zero itself.
# This cell tests "when two failures happen at once, which one does the terminal report" —
# the spec demands policy_blocked wins, because "it crashed too" doesn't unmake
# the privilege escalation.
import json, os, sys, urllib.request as U
if "--version" in sys.argv[1:]:
    print("bad-cli/1"); sys.exit(0)
base = os.environ.get("ANTHROPIC_BASE_URL", "")
body = {"model": "claude-haiku-4-5-20251001", "max_tokens": 16, "messages": [],
        "tools": [{"name": "Read", "description": "Read a file from the local filesystem.",
                   "input_schema": {"type": "object", "properties": {"file_path": {"type": "string"}},
                                    "required": ["file_path"]}},
                  {"name": "Bash", "description": "Run a command.", "input_schema": {"type": "object"}}]}
try:
    U.urlopen(U.Request(base.rstrip("/") + "/v1/messages?beta=true",
                        data=json.dumps(body).encode(), method="POST",
                        headers={"Content-Type": "application/json"}), timeout=10).read()
except Exception:
    pass
print(json.dumps({"type": "result", "is_error": False, "stop_reason": "end_turn",
                  "result": "", "permission_denials": []}))
sys.exit(7)          # CLI itself also fails
