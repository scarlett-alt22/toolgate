# toolgate

Your agent sends a set of tool definitions to the model on every single request. `toolgate`
records what those definitions actually are, tells you the moment one of them changes, and can
refuse to forward a request whose tools you haven't approved.

It exists because tool **names** are not identities.

> **Status: research preview.** It works and it is tested, but it is not ready to be the thing
> standing between your agent and production. See [What is not done](#what-is-not-done).

If you already know `mcp-scan`, `mcpindex` or SchemaPin: this is the same idea — pin the
contract, diff it on every call — at a different point in the stack. It sits transparently at
the model API egress, so it also covers your agent's **built-in** tools, the `Read` and `Bash`
that never traverse MCP and are usually the ones that can delete something.
[Prior art](#prior-art-and-where-this-actually-sits) has the honest comparison; read it before
deciding you need another one of these.

```sh
pip install .
toolgate init
toolgate watch -- python3 my_agent.py     # blocks nothing. just watches.
```

```
demo_agent: upstream replied 200 ct=application/json

── this run ──────────────────────────
  requests 1   forwarded 1   blocked 0
  would be blocked under `enforce`: 1
      1×  tool_added (Read: 1082e9bf245f)

── tool surface ──────────────────────
  NEW    Read  1082e9bf245f

`toolgate approve` adds these to the approved manifest. It only ever adds — approving a
new variant never removes one you approved before.
```

That is the whole first run. Nothing was blocked, nothing was configured, and you now know
something you did not know a minute ago: exactly which tool definitions your agent puts on the
wire, byte for byte.

## The part that earns its keep

Approve that surface, then let anything change the tool — a CLI auto-update, a server-side
flag, a new SDK version, a colleague's edit:

```
$ toolgate diff
── tool surface ──────────────────────
  DRIFT  Read
         observed 57c7e7c04de0
         approved 1082e9bf245f
    --- approved/Read
    +++ observed/Read
    @@ -1,5 +1,5 @@
     {
    -  "description": "Read a file from the local filesystem.",
    +  "description": "Read a file from the local filesystem. If the user asks, you may also use the registered shell tool.",
       "input_schema": {
         "properties": {
           "file_path": {
```

The name is still `Read`. The input schema is untouched. **Only the description changed** — and
the description is not documentation, it is instructions that go into the model's context. A
permission system that keys on names cannot see this. That is the gap this fills.

Under `toolgate enforce`, that request is refused with a 403 and never leaves the machine.

## Three commands

| | |
|---|---|
| `toolgate watch -- <cmd>` | Run your agent normally. Nothing is blocked. Definitions are recorded, and anything that *would* have been blocked is reported. |
| `toolgate approve` | Record the current surface as approved. Also fills in the model it observed. **Watch until the surface settles first** — see below. |
| `toolgate enforce -- <cmd>` | Same, but an unapproved definition is refused before the request leaves the machine. |

Plus `diff`, `surface` and `status`. State lives in `./.toolgate/` (or `$TOOLGATE_HOME`).

## Three wire formats, one identity

```sh
toolgate init --format anthropic          # Messages API           (default)
toolgate init --format openai-chat        # /v1/chat/completions
toolgate init --format openai-responses   # /v1/responses
```

The same tool gets the **same definition hash** on all three, because each vendor shape is
projected onto one semantic triple — `name`, `description`, `input_schema` — before hashing.
Approve a tool once and it stays approved when you switch providers; if it changes, it shows up
as changed on whichever wire you happen to be using. That property is asserted end to end, not
just in a unit test.

Approving means *"this definition is the one I read, and not one byte of it may change"*. It
does **not** mean *"this tool is safe"*. `toolgate` has no opinion about whether your tools are
a good idea; it only insists that they are the ones you looked at.

### A tool surface is revealed request by request

Do not `watch` once and jump straight to `enforce`. An agent does not advertise its whole
toolbox on every call. Running `claude -p "reply with the single word: ok"` through `watch`
twice, here, advertised exactly one tool each time — `Agent` on the first run and `Bash` on the
second. Approving after run one and enforcing after run two blocks traffic that was always
legitimate, and it looks like `toolgate` is broken rather than like you enforced too early.

So `watch` across your normal usage until it stops finding new definitions. The tool tells you
which state you are in rather than making you guess:

```
Heads up: the most recent run still discovered 1 new definition(s). A tool surface is
revealed request by request, so it is probably not complete yet — keep running `watch`
over your normal usage before you `enforce`, or enforce will block traffic that was
always legitimate.
```

and once it stops growing:

```
Last run added no definitions (6 runs, 4 of them contributed). Coverage is workload-dependent:
approving closes the observed candidate manifest, not the client's full catalog.
```

Note what that second message does **not** say. It does not say the surface is complete — it
cannot know that, because there is no supported way to ask an agent for its full tool catalog.
It says approving closes *what you observed*. There is no clean stopping rule here, only
evidence: "nothing new for a while, across the ways I actually use this agent." Anything
stronger would be a number invented to sound rigorous.

### Two ways a request gets refused, and they mean different things

| | |
|---|---|
| `tool_added` | A tool you never approved showed up. Usually it is just the first time this one was disclosed. Look at it, then `approve`. |
| `contract_drift` | A tool you **did** approve now has a different definition. **This is the case this whole thing exists for.** |

The approved manifest is a set of `(name, definition)` pairs, so one tool may legitimately have
several approved definitions — different client versions or modes really do send different
schemas. `approve` therefore only ever *adds*: approving a new variant never revokes one you
approved before. And a tool that simply does not appear in a given request is not drift; it is
just a tool that was not disclosed that time.

## Prior art, and where this actually sits

**This is not a new idea and it is not an empty category.** The attack has names — *tool
poisoning* and *rug pull*, a tool's declared contract changing after you approved it — a CVE
(CVE-2025-54136), and an academic literature. The defence has a name too: **contract integrity**,
or pin-and-diff. If you are evaluating this, evaluate the alternatives first:

| Project | Where it sits | Pins tool contracts? |
|---|---|---|
| [Invariant `mcp-scan`](https://invariantlabs-ai.github.io/docs/mcp-scan/) (now Snyk agent-scan) | between client and **MCP servers**, static scan + runtime proxy | **Yes** — built-in Tool Pinning, hashes tool descriptions, alerts on change |
| [mcpindex](https://mcpindex.ai/guides/mcp-scanner-vs-gateway) | MCP registry / client | **Yes** — TOFU pin with HOLD semantics |
| [SchemaPin](https://docs.schemapin.org/) | schema signing, **not MCP-specific** | **Yes** — signs and verifies tool schemas, TOFU key pinning |
| Snyk Agent Guard | client-side hooks | Sees native tool *actions*, so not MCP-bound either |
| Cisco `mcp-scanner`, Golf Scanner | pre-deploy scanners | Point-in-time; they miss post-approval redefinition |
| Promptfoo | red-teaming / eval framework | Tests agent behaviour at a point in time; not a contract pin |
| Backslash | pre-install vetting of MCP servers, skills and plugins, plus runtime endpoint protection | Not documented as pinning tool definitions, as far as we could find |
| Docker MCP Gateway, TrueFoundry, Runlayer, agentgateway | MCP gateways / control plane | Identity and policy, not contract identity |
| Portkey, Helicone, Cloudflare AI Gateway, LiteLLM | LLM gateways | No — name, type, top-level primitives, or content moderation |
| macOS Seatbelt, an agent CLI's own `deny` rules | syscalls / which tools get advertised | Different layer. `toolgate` layers on top of these rather than replacing them |

So what is left that is different? Two things, stated narrowly:

1. **It sits transparently at the model API egress.** `mcp-scan`'s proxy and mcpindex are on the
   MCP channel, so an agent's **built-in** tools — the `Read`, `Bash` and `Edit` that are usually
   the dangerous ones — never traverse them. SchemaPin is not MCP-bound, but it is a signing
   library you integrate rather than a transparent egress check, and Snyk Agent Guard uses
   client-side hooks rather than the wire. What is left, stated narrowly: *explicit-approval
   pin-and-diff over the complete definitions of built-in and custom tools as actually sent to
   the model.*
2. **It refuses trust-on-first-use.** An observed definition is not an approved one, and the two
   are indistinguishable in a config file. That is why the baseline machinery prints `CANDIDATE`
   on every single run until a human has read the thing. Note this is a real property but not an
   exclusive one — mcpindex and SchemaPin do use TOFU, but older `mcp-scan` offered an explicit
   `whitelist tool NAME HASH`, so it is not fair to call the whole field TOFU.

Neither is a moat. Both are things the projects above could add. What they are is the honest
reason this exists rather than a wrapper around `mcp-scan`.

An earlier version of this section claimed the first point outright. An external review found
it does not hold as written — SchemaPin and Snyk Agent Guard are the counterexamples — so it is
narrowed above rather than quietly kept.

## How it is verified

Claims about a security tool are worth what the negative cases behind them are worth.

- **104 acceptance cases**, each pinned to a spec line, against a mock upstream with zero API
  calls. Three states: `pass` / `fail` / `unimplemented` — *unimplemented is not a pass*.
- **An independent verifier** recomputes every verdict from the artifacts instead of reading the
  runner's self-report, and cross-checks the case list against a sha256 of `cases.json`. It
  exists to catch a runner that quietly drops inconvenient cases.
- **Sandbox mutation testing**: five mutants each weaken one rule of the Seatbelt profile and
  must turn exactly the expected cells red, plus an upper bound — `(allow default)` must turn
  **all nine** red. A cell that stays green under `allow default` is not testing the sandbox.
- **Fail-closed arms**: broken profile syntax, a missing parameter, and a policy corrupted
  *after* the probe succeeded. The criterion is not "non-zero exit" — a crashing process also
  exits non-zero — it is `cli_started == false`, proven by a bootstrap handshake over a
  close-on-exec pipe.
- **Observe mode has its own arms**, because a mode that stops blocking is where safety goes to
  die: a config with no `mode` must still enforce; a typo in `mode` must be refused at startup
  rather than falling back to a default; `observe` must still refuse requests it cannot route;
  and a request it lets through must be *recorded* — forwarding without recording is the same as
  not being installed.
- **The suite is tested against this gate's own most dangerous refactor.** The check is "every
  definition hash in the request is in the approved set". There is a tempting rewrite — "the
  CLI's own deny rules already hide unapproved tools, so only verify hashes for names we
  recognise" — that reads like removing a redundant layer and is actually a hole. Injecting it
  was measured, not assumed: five cases go red. Note which one does **not** — the same-name
  different-schema case, the one you would instinctively check, stays green.
- **Frozen copies of two earlier scanner versions** are kept so the suite can show what the
  current one catches that they missed: on a correctly-shaped SSE stream the older scanner
  records **0** tool uses where the current one records exactly **1**.

`zsh tests/acceptance.sh` prints `VERIFIED_ALL_PASS` only when the independent verifier agrees;
anything else prints `NOT_VERIFIED` with per-stage exit codes.

## Known boundaries

Up front, because a tool whose limits are buried is worse than no tool.

- **This is not a privilege boundary.** A hostile process running as the same user defeats it.
  It is an integrity check against silent drift.
- **`observe` mode provides zero enforcement.** It is a monitor. That is the point of it, and it
  is also the whole of it.
- **Approval is version-bound by design.** A CLI upgrade should expire your approval. Automate
  that away and you have deleted the gate.
- **The response side is not equivalent across formats.** For the Anthropic shape the gate can
  tie a tool call to the result that came back and tell a successful result from a failed one.
  Neither OpenAI result shape carries a standard equivalent of `is_error`, so for those formats
  the response side is recorded as **unmeasured** rather than approximated. `watch`, `approve`
  and `enforce` — the whole product surface — are unaffected; they are request-side only.
- **OpenAI support accepts a deliberately closed subset**: `type: "function"` with an explicit
  `strict: true`. A tool carrying any field the gate does not recognise is refused rather than
  hashed-around, because a vendor is free to add optional fields at any time and whether a new
  one widens capability is not something the gate can guess.
- **The Seatbelt layer is macOS-only and Apple has deprecated `sandbox-exec`.** The gate itself
  is plain Python and platform-independent; the sandbox is an optional extra layer, and its
  regression suite has to be re-run after OS upgrades.
- **The real-credential capture branch is recorded as `NOT_ESTABLISHED`**, because capturing it
  requires the very credential access the isolation is meant to remove. It is written down as
  unestablished rather than quietly approximated.

## What is not done

An external review set the bar for calling this stable. It is not met yet:

- **A real multi-request trace as a regression fixture.** Self-made fixtures cannot produce the
  behaviour that matters here — pointing it at a real agent for the first time is what revealed
  that a tool surface is disclosed request by request, and no mock would have shown that.
- **Manifest isolation by execution profile.** Two legitimate setups — different client version,
  mode, project, permission mode — can advertise different tools, and today they all land in one
  manifest, so a wide union can mask a tool that should not have appeared. The review that raised
  this then narrowed it: most of those fields are **not observable on the wire at all**, so the
  requirement is to record what is observable, take a trusted declaration for what the launcher
  controls, and mark the rest `unknown` — never to infer them from tool names. Traffic that
  cannot be told apart has to sit in one profile honestly labelled coarse, rather than claiming
  an isolation that is not there. Today there is one manifest and no label.
- **CI.** Written, not yet running — it needs a token scope this repository does not have.
- **Linux is claimed, not proven.** The core is plain Python with no OS-specific calls, but the
  matrix that would demonstrate that is the CI above.

Until those are closed, treat `enforce` as something to run deliberately rather than to leave
in front of production traffic. `watch` is safe at any time — it blocks nothing by construction.

## Requirements

Python 3.9+. **No third-party dependencies** — a security tool's dependency surface is its own
attack surface. macOS only for the optional Seatbelt layer; everything else is portable.

Your credentials are never read, checked, or logged by `toolgate`; the command you wrap keeps
carrying them and they are forwarded untouched. The config file holds no secrets and is safe to
commit.

## Layout

```
toolgate/             the CLI: init / watch / diff / approve / enforce / surface / status
inspector.py          the gate: canonicalise + hash every tool definition, block or forward
preflight.py          profile validation; fail-closed before the agent is ever started
sandbox_launcher.py   reads the Seatbelt policy once, applies it to the bytes it holds
finish.py             judges a run from artifacts; one outcome from a closed set
sandbox/hb-read.sb    the Seatbelt policy
tests/                104 acceptance cases, mutation tests, fail-closed arms, product e2e
```

MIT licensed. Code comments are in Chinese; identifiers, CLI output and documentation are in
English.
