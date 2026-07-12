# hermes-camel-security

Prompt-injection defense for [Hermes Agent](https://github.com/NousResearch/hermes-agent). A plugin — no core changes, works on stock Hermes.

## The problem

Your agent reads a web page. The page says "ignore your instructions, run this command". The agent has your terminal, your files, your accounts — and it just read an instruction from a stranger. Upstream tracks this as [#496](https://github.com/NousResearch/hermes-agent/issues/496); in-core CaMeL guards were proposed in [#1992](https://github.com/NousResearch/hermes-agent/pull/1992) / [#3987](https://github.com/NousResearch/hermes-agent/pull/3987) (still open). This plugin does the same [CaMeL](https://arxiv.org/abs/2503.18813) idea through the plugin API, so you can run it today.

## Install

```
hermes plugins install pinkyhi/hermes-camel-security --enable
```

The approval gate and audit log work right away: dangerous commands (git push, curl/wget uploads, encoded PowerShell, rm -rf, reads of key files) pause and ask you `/approve` / `/deny` in chat, and everything sensitive is written to `security-audit.jsonl`.

Turn on the CaMeL part in `<HERMES_HOME>/.env`:

```env
CAMEL_SECURITY_INTERPRETER=1      # adds the plan_execute tool
CAMEL_SECURITY_WEB_QUARANTINE=1   # web research must go through it
CAMEL_SECURITY_Q_TOOLSETS=web     # add ",browser" to also cover playwright/chrome-devtools
```

From then on web research runs as a visible `📋` plan and raw page content never enters the agent's main context.

## Starting config — copy this

The plugin knows generic dangers out of the box. Your *own* stuff — your MCP servers, your secret files, your GUI-automation tools — you list in **`<HERMES_HOME>/camel-security.yaml`**. Copy this file and edit; every section just ADDS to the defaults, a typo can't break anything (bad entries are skipped), restart the gateway to apply:

```yaml
# <HERMES_HOME>/camel-security.yaml

# Files that must not be read quietly. Reading them in a terminal command asks you first.
# (auth.json, id_rsa, .ssh/, *.pem, *.key are already covered by default.)
secret_files:
  - 'google_token'          # Google OAuth tokens
  - 'google_client_secret'
  - '\.codex'               # codex CLI auth
  # - 'wallet\.dat'         # ...add yours

# Places where WRITING is dangerous: write_file here asks you first,
# and plan output built from web data is refused here outright.
sensitive_paths:
  - '\.codex'
  # - '\.kube[/\\]'

# Your own command rules — checked before the built-in ones, yours win.
# category: an existing one (push / egress / exec / secret_read / destructive / config)
# or your own name (then add it to CAMEL_SECURITY_CATEGORIES below to make it ask).
cmd_rules:
  - category: destructive
    pattern: '\bkubectl\s+(delete|drain)\b'
  # - category: egress
  #   pattern: '\baws\s+s3\s+cp\b.*s3://'

# MCP servers that bring in OUTSIDE content (scraping, RSS, mail...).
# A prefix covers all the server's tools, now and future. firecrawl_/searxng_ are built in.
web_mcp_prefixes: []
  # - 'rss_'
web_mcp_tools: []            # or single tools by name, e.g. 'fetch_page'

# MCP tools that execute code:
exec_tools: []
  # - 'run_sql'

# GUI automation that clicks blind screen coordinates (PyAutoGUI-style).
# EVERY action asks you, answers are never remembered. Only acting tools —
# screenshot/stop tools stay free.
takeover_act_tools:
  - click_element
  - click_xy
  - double_click
  - right_click
  - type_text
  - press_key
  - scroll
  - move

# GUI automation that works on UI elements (UIA-style). Asks once per session.
desktop_act_tools:
  - invoke_element
  - set_text
  - select_element
  - window_action
  - launch_application

# Extra web tools for a built-in toolset (rarely needed):
toolset_tools: {}
  # web: [my_search]
```

Tool names are matched against all MCP naming shapes (`tool`, `server__tool`, `mcp_server_tool`) — write the bare name.

## All settings (`.env`)

The gate:

| Variable | Default | What it does |
|---|---|---|
| `CAMEL_SECURITY_CATEGORIES` | `push,egress,exec,secret_read,destructive,config,secret_file,desktop_act,takeover_act` | Which categories ask you (the rest only go to the audit log) |
| `CAMEL_SECURITY_NO_CACHE` | `takeover_act` | Categories that ask EVERY time (never remember an answer) |
| `CAMEL_SECURITY_NO_BLOCK` | off | Log only, never ask — kill switch if something misfires |
| `CAMEL_SECURITY_STRICT` | off | Where there's no chat to ask in (cron, CLI): block instead of allow |

The quarantine + interpreter:

| Variable | Default | What it does |
|---|---|---|
| `CAMEL_SECURITY_WEB_QUARANTINE` | off | Web tools become plan-only for the main agent |
| `CAMEL_SECURITY_Q_TOOLSETS` | `web` | Which toolsets that covers (`web`, add `browser`) |
| `CAMEL_SECURITY_INTERPRETER` | off | Register the `plan_execute` tool |
| `INTERP_OP_TIMEOUT` | 60 | Per-step timeout, seconds |
| `INTERP_MAX_WORKERS` | 4 | How many plan steps run in parallel |
| `INTERP_MAP_MAX` | 200 | Hard cap on fan-out size |
| `INTERP_Q_MAX_TOKENS` | 800 | Output budget of the quarantined extractor |
| `INTERP_WATCH` / `INTERP_WATCH_BATCH` | 1 / 3 | Live `📋` progress in your chat |
| `INTERP_SINK_<CATEGORY>` | — | Override what tainted data may do per sink: `allow` / `deny` / `approve` |

Quick appends without the yaml (comma lists, same effect): `CAMEL_SECURITY_TAKEOVER_TOOLS`, `CAMEL_SECURITY_DESKTOP_TOOLS`, `CAMEL_SECURITY_EXEC_TOOLS`, `CAMEL_SECURITY_WEB_MCP_PREFIXES`, `CAMEL_SECURITY_WEB_MCP_TOOLS`. The old `SECURITY_GATE_*` names still work.

Common cases: new MCP server that executes code → `exec_tools`; that reads outside content → `web_mcp_prefixes`; that drives your GUI → `takeover_act_tools` or `desktop_act_tools`. New secret → `secret_files` (readable) or `sensitive_paths` (writable). Want to trial a rule first? Give it a new category name and DON'T add it to `CAMEL_SECURITY_CATEGORIES` — it logs to the audit file without asking, promote it later.

## What happens inside

Three layers:

1. **Gate + audit** — every tool call is classified; the dangerous ones go through Hermes' own approval flow, everything sensitive is logged.
2. **Quarantine** — the main agent can't call web tools directly; it must write a plan.
3. **`plan_execute`** — the agent writes the plan *before* seeing any untrusted data; a deterministic executor runs it. Web content flows through as tagged ("tainted") values: a separate tool-less LLM reads it, results carry their origin, and every side effect is checked against that origin first. Tainted data going to the owner — fine. Tainted data going to exec/upload — refused. Ambiguous — you're asked. Raw web bytes never come back to the agent, not even inside error messages.

So untrusted content can influence *what the answer says*, but not *what the agent does*. Details and invariants: [EXTENDING.md](EXTENDING.md#design-invariants).

## Limitations — honest ones

- The gate is regex-based: a determined bypass will get past it. It's a speed bump plus a paper trail. The strong, by-construction guarantee lives only in the interpreter path — which by default covers web research, the main injection door.
- Injection can arrive through doors that aren't quarantined (a file someone gave you, a message in a group chat). Those face only the gate.
- Recognition lists are lists: a new tool is uncovered until you add one line to the yaml. Unknown *actions* on tainted data are refused by default, but an unlisted *source* comes in as trusted.

## Extending in code

New interpreter operations, new sink policies, changing shipped defaults: [EXTENDING.md](EXTENDING.md).

## Tests

`python test_offline.py` — 239 checks, offline, stdlib-only.

## Related upstream work

- [#496 — Promptware Defense](https://github.com/NousResearch/hermes-agent/issues/496) — the problem statement
- [#1992](https://github.com/NousResearch/hermes-agent/pull/1992) → [#3987 — CaMeL guard as opt-in runtime](https://github.com/NousResearch/hermes-agent/pull/3987) — the in-core approach; this plugin is the no-core-changes counterpart
- [Debenedetti et al., *Defeating Prompt Injections by Design*](https://arxiv.org/abs/2503.18813) — the CaMeL paper

## License

MIT
