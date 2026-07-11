# hermes-camel-security

Prompt-injection defense for [Hermes Agent](https://github.com/NousResearch/hermes-agent), shipped as a **pure plugin** — no core changes, installable today.

Indirect prompt injection is the standing open problem of tool-using agents: the model reads untrusted content (a web page, a fetched file), the content contains instructions, and the model acts on them with *your* tools and *your* credentials. This plugin attacks that chain at three points, ending in a [CaMeL](https://arxiv.org/abs/2503.18813)-style control/data-flow separation:

| Layer | What it does |
|---|---|
| **Approval gate + audit** | Classifies every tool call; sensitive categories (git push, egress, exec, secret reads, destructive ops, desktop/takeover actions…) are routed through Hermes' own gateway approval flow — the same Discord `/approve` / `/deny` prompt terminal commands use. Everything sensitive is appended to `security-audit.jsonl`. |
| **Web-ingest quarantine** | Direct web-ingest tools (`web_search`, `web_fetch`, firecrawl/searxng MCP tools, optionally browser toolsets) become **plan-only** for the top-level agent: raw web content never lands in the main context. A per-turn injected instruction (1A) steers the model to the safe path; a hard block (1B) enforces it. |
| **`plan_execute` interpreter** | The safe path. The top-level agent writes a typed **plan-DAG (data, not code)** from the trusted request only; a deterministic executor runs it with parallel fan-out, tracks **capabilities (provenance) on every value**, and checks a **capability-aware sink policy** before any side effect. Quarantined tool-less LLM calls (`q_extract` / `q_summarise`) read the untrusted bytes; raw tainted values are never returned to the planning agent. |

The net effect, by construction rather than by vigilance: **untrusted data can influence values, but cannot redirect control flow or reach a dangerous sink.**

> **Doesn't Hermes already gate dangerous commands?** The built-in guard covers terminal commands with linux-shaped patterns. The gate layer here fills what it misses — Windows/PowerShell command forms (`iex`, `-EncodedCommand`, `Remove-Item -Recurse`), plain `git push` / `gh` writes, and *non-terminal* actions (file writes to secret paths, MCP exec/desktop/takeover tools) — and deliberately audit-onlies anything the built-in already prompts for, so nothing double-prompts. It also isn't optional scaffolding: the quarantine block, the interpreter's `approve` escalations, and the `quarantine/` read protection all run on the gate's hook and approval plumbing.

## Install

```
hermes plugins install pinkyhi/hermes-camel-security --enable
```

Then enable the optional layers per profile in `<HERMES_HOME>/.env` (the gate + audit layer is on by default):

```env
# CaMeL-lite interpreter (registers the plan_execute tool)
SECURITY_GATE_INTERPRETER=1
# route web research through plan_execute (1A steer + 1B block)
SECURITY_GATE_WEB_QUARANTINE=1
SECURITY_GATE_Q_TOOLSETS=web            # add ",browser" to quarantine playwright/chrome-devtools too
```

Requires a Hermes version with plugin hooks (`pre_tool_call`, `post_tool_call`, `pre_llm_call`) and `ctx.register_tool`.

## How the interpreter works

```
owner request (trusted)
      │
      ▼
   P (main agent) ── writes ─▶ plan (JSON DAG — data, not code)
      │                              │
      │                       plan_execute(plan)
      │                              │
      │              deterministic executor:
      │                • dep-graph from $refs, independent steps run in parallel
      │                • every value = {data, caps} — provenance is tracked
      │                • q_extract / q_summarise: tool-less quarantined LLM (Q)
      │                • sinks capability-checked BEFORE any side effect
      │                              │
      ◀── sanitized result/status ───┘   (raw tainted values NEVER return to P)
```

Example plan (what the agent actually emits):

```json
{
  "goal": "find recent reviews of X and send me a summary",
  "steps": [
    {"id":"s1","op":"web_search","args":{"q":"X reviews 2026"}},
    {"id":"s2","op":"map","over":"$s1.results","max":5,"body":[
      {"id":"f","op":"web_fetch","args":{"url":"$item.url"}},
      {"id":"x","op":"q_extract","args":{"text":"$f","schema":"Review"}}
    ]},
    {"id":"s3","op":"q_summarise","args":{"data":"$s2"}},
    {"id":"s4","op":"send_owner","args":{"text":"$s3"}}
  ]
}
```

Progress is mirrored live to the owner's chat (`📋` fenced blocks, per-op args/results), and every run is appended to `interp-audit.jsonl` for forensics.

## Design (the §N markers in code comments refer to these)

- **§5 Capability model.** Every value carries `caps.sources ⊆ {owner, web, file:<path>, tool:<name>}`. Plan literals are `{owner}` (trusted — the planner only ever saw trusted input). `web_search`/`web_fetch` produce `{web}`. `q_extract`/`q_summarise` **inherit** their input's sources — an LLM pass does not launder taint. `$ref`s carry caps, so referencing can't strip them.
- **§6 Sink policy (capability-aware).** Checked before every side effect: `send_owner` is always allowed (the owner is the safe sink); `send_other`/`egress` with any tainted arg is denied; `exec` with owner-only args runs frictionless, with tainted args is denied; tainted `write_file` is contained (see below); genuinely ambiguous tainted action-sinks (e.g. `send_owner_actionable` — a drafted message the owner will act on) route to the human approval flow. Per-category override: `INTERP_SINK_<CATEGORY>=allow|deny|approve`.
- **§7 No-raw-return invariant.** The executor returns only a sanitized status/result to the planner. This includes the **error channel**: once a run has touched tainted data, error details are withheld from the planner (full detail goes to the audit log) — an "error message" is otherwise a perfect exfiltration/reinjection channel.
- **File provenance — the `quarantine/` location convention.** Tainted `write_file` output is forced under `<HERMES_HOME>/quarantine/`; the folder *is* the taint registry. Direct reads of quarantine paths (and of the audit logs themselves) by the top-level agent are plan-only; the `read_file` op re-taints their content.
- **Fail-open for availability, fail-closed for policy.** An internal plugin error never breaks the agent's turn; an unknown tainted sink category denies by default.

## Configuration reference

Gate layer (on by default):

| Variable | Default | Meaning |
|---|---|---|
| `SECURITY_GATE_CATEGORIES` | `push,egress,exec,secret_read,destructive,config,secret_file,desktop_act,takeover_act` | Which categories are gated (vs audit-only) |
| `SECURITY_GATE_NO_CACHE` | `takeover_act` | Categories that re-prompt on every call (never session-cache an approval) |
| `SECURITY_GATE_NO_BLOCK` | off | Audit-only mode — never gate (rollback switch) |
| `SECURITY_GATE_STRICT` | off | In non-gateway contexts (no approval channel): block instead of allow+audit |

Quarantine + interpreter (opt-in):

| Variable | Default | Meaning |
|---|---|---|
| `SECURITY_GATE_WEB_QUARANTINE` | off | Master switch for the web-ingest quarantine (1A + 1B) |
| `SECURITY_GATE_Q_TOOLSETS` | `web` | Quarantined toolsets; add `browser` for playwright/chrome-devtools |
| `SECURITY_GATE_INTERPRETER` | off | Register the `plan_execute` tool (the sole research path when quarantined) |
| `INTERP_OP_TIMEOUT` | 60 | Hard per-op timeout, seconds |
| `INTERP_MAX_WORKERS` | 4 | Step/map parallelism ceiling |
| `INTERP_MAP_MAX` | 200 | Hard ceiling on `map` fan-out (data can't drive cost) |
| `INTERP_Q_MAX_TOKENS` | 800 | Q extraction output budget |
| `INTERP_Q_RETRIES` / `INTERP_Q_RETRY_BACKOFF` | 2 / 2 | Q retries on transient provider errors |
| `INTERP_RESEARCH_WORKERS` | = MAX_WORKERS | Parallelism of the `q_research` fetch+extract fan-out |
| `INTERP_GOAL_MAX` / `INTERP_CTX_MAX` | 500 / 1500 | Intake caps (chars) on the plan's trusted goal/context |
| `INTERP_WATCH` / `INTERP_WATCH_BATCH` / `INTERP_WATCH_EMOJI` | 1 / 3 / 📋 | Live progress mirroring to the owner chat |
| `INTERP_SINK_<CATEGORY>` | — | Override a tainted sink decision: `allow` / `deny` / `approve` |

## Tests

```
python test_offline.py
```

224 offline checks — classifier shapes (Windows-aware: Git Bash + PowerShell), gate flow, quarantine matching (including MCP-composed tool names), interpreter plan validation, capability propagation, sink policy, error sanitization.

## Extending

New dangerous-command shapes, new tools/categories to gate, new untrusted sources to quarantine, new interpreter ops and sink policies — the extension points and a recipe for each are in [EXTENDING.md](EXTENDING.md), together with the invariants any change must keep (fail-open for availability / fail-closed for policy, taint inheritance, no raw tainted bytes to the planner, MCP naming-shape matching).

## Relation to upstream work

- [NousResearch/hermes-agent#3987](https://github.com/NousResearch/hermes-agent/pull/3987) reworks a CaMeL guard **inside the core runtime** (superseding [#1992](https://github.com/NousResearch/hermes-agent/pull/1992), motivated by [#496](https://github.com/NousResearch/hermes-agent/issues/496)). This plugin is the complementary angle: the same CaMeL idea implemented **entirely on the public plugin surface** (hooks + `register_tool`), so it works on stock Hermes without waiting for core changes, and is trivially removable.
- The CaMeL paper: [Debenedetti et al., *Defeating Prompt Injections by Design*](https://arxiv.org/abs/2503.18813).

## Honest limitations

- This is defense-in-depth, not a proof. The gate classifier is pattern-based (bypassable by construction — it's a speed bump plus audit trail); the principled guarantees live in the interpreter path, and only for flows routed through it.
- The plan is written by the same LLM that talks to the user — the guarantee is that it writes the plan **before** seeing untrusted data, not that the LLM is trustworthy in general.
- Sink categories and web-ingest tool sets are curated lists; new tools need classifying (unknown tainted sinks deny by default).

## License

MIT
