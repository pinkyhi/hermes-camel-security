# Configuring camel-security

Everything site-specific is configuration — the code ships only **generic defaults** (dangerous-command rules, common secret files, firecrawl/searxng ingest prefixes). Two places to configure, both per Hermes profile:

1. **`<HERMES_HOME>/camel-security.yaml`** — *recognition*: your MCP servers, your secret files, your GUI-automation tools, your extra command rules. The [README](README.md#the-starting-camel-securityyaml) shows the recommended starting file — copy it and extend.
2. **`<HERMES_HOME>/.env`** — switches and knobs (what's enabled, how strict), plus quick comma-list appends for the tool lists.

Env switches use the `CAMEL_SECURITY_*` prefix; the legacy `SECURITY_GATE_*` prefix is still read as a fallback. Everything is read at process start — restart the gateway (`hermes gateway restart`) to apply changes.

Merging is **append-only**: your config *adds* recognition on top of the defaults, it never removes them. To make the gate *less* strict, don't edit lists — narrow `CAMEL_SECURITY_CATEGORIES` or set `CAMEL_SECURITY_NO_BLOCK=1` (audit-only). A broken config file or an invalid regex is skipped fail-open: defaults stay intact, the agent keeps working.

## Quick start

A fresh install works with no configuration at all: the gate covers generic dangerous commands (git push, egress, exec, destructive ops, common secret files), and the quarantine + interpreter activate with two `.env` lines (see [README](README.md#install)). Create `camel-security.yaml` from the README's recommended starting file, then teach the gate *your* environment — the full key set:

```yaml
# <HERMES_HOME>/camel-security.yaml — site-specific recognition (append-only)

# Your crown-jewel files, beyond the generic auth.json/id_rsa/.ssh/*.pem/*.key.
# Regex fragments, matched inside terminal commands (cat/type/copy/... of these gates):
secret_files:
  - 'google_token'
  - 'wallet\.dat'

# Paths where writing is sensitive (write_file → approval; tainted plan writes → deny).
# Regex fragments, appended to the built-in matcher:
sensitive_paths:
  - '\.kube[/\\]'

# Your web-ingest MCP servers (anything that brings in EXTERNAL content: scraping,
# RSS, mail...). Vendor prefix, so future tools of that server are covered too.
# Quarantined while the 'web' toolset is (CAMEL_SECURITY_Q_TOOLSETS):
web_mcp_prefixes:
  - 'rss_'
web_mcp_tools:          # or single tools by name
  - 'fetch_page'

# Your code-execution MCP tools (classified `exec`):
exec_tools:
  - 'run_sql'

# Your GUI-automation servers. Two categories, different strictness:
# desktop_act — element-level automation (UIA-style); one approval per session.
desktop_act_tools:
  - invoke_element
  - set_text
# takeover_act — blind screen-coordinate automation (PyAutoGUI-style);
# EVERY action re-prompts, approvals never cache. List only acting tools —
# perception (screenshot) and teardown (stop) don't belong here.
takeover_act_tools:
  - click_xy
  - type_text

# Your own terminal-command rules. Checked BEFORE the built-ins (yours win on
# overlap). `category` can be an existing one or your own name — add new names
# to CAMEL_SECURITY_CATEGORIES in .env, or they stay audit-only:
cmd_rules:
  - category: destructive
    pattern: '\bkubectl\s+(delete|drain)\b'
  - category: egress
    pattern: '\baws\s+s3\s+cp\b.*s3://'

# Extra web-ingest tools for a built-in toolset (rarely needed):
toolset_tools:
  web: [my_search]
```

Tool names are matched robustly against MCP naming shapes (`tool`, `server__tool`, `mcp_server_tool`) — list the **bare** tool name.

For quick one-liners the most common lists also take comma-separated env appends (same append semantics, merged together with the yaml):

```env
CAMEL_SECURITY_TAKEOVER_TOOLS=click_xy,type_text
CAMEL_SECURITY_DESKTOP_TOOLS=invoke_element
CAMEL_SECURITY_EXEC_TOOLS=run_sql
CAMEL_SECURITY_WEB_MCP_PREFIXES=rss_,imap_
CAMEL_SECURITY_WEB_MCP_TOOLS=fetch_page
```

## Switches and knobs (`.env`)

Gate layer (on by default):

| Variable | Default | Meaning |
|---|---|---|
| `CAMEL_SECURITY_CATEGORIES` | `push,egress,exec,secret_read,destructive,config,secret_file,desktop_act,takeover_act` | Which categories gate (everything classified still lands in the audit log) |
| `CAMEL_SECURITY_NO_CACHE` | `takeover_act` | Categories that re-prompt on every call |
| `CAMEL_SECURITY_NO_BLOCK` | off | Audit-only mode — never gate (rollback switch) |
| `CAMEL_SECURITY_STRICT` | off | In non-gateway contexts (no approval channel): block instead of allow+audit |

Quarantine + interpreter (opt-in):

| Variable | Default | Meaning |
|---|---|---|
| `CAMEL_SECURITY_WEB_QUARANTINE` | off | Master switch for the web-ingest quarantine |
| `CAMEL_SECURITY_Q_TOOLSETS` | `web` | Quarantined toolsets; add `browser` for playwright/chrome-devtools |
| `CAMEL_SECURITY_INTERPRETER` | off | Register the `plan_execute` tool |
| `INTERP_OP_TIMEOUT` | 60 | Hard per-op timeout, seconds |
| `INTERP_MAX_WORKERS` | 4 | Step/map parallelism ceiling |
| `INTERP_MAP_MAX` | 200 | Hard ceiling on `map` fan-out |
| `INTERP_Q_MAX_TOKENS` | 800 | Q extraction output budget |
| `INTERP_Q_RETRIES` / `INTERP_Q_RETRY_BACKOFF` | 2 / 2 | Q retries on transient provider errors |
| `INTERP_RESEARCH_WORKERS` | = MAX_WORKERS | `q_research` fetch+extract fan-out parallelism |
| `INTERP_GOAL_MAX` / `INTERP_CTX_MAX` | 500 / 1500 | Intake caps (chars) on the plan's trusted goal/context |
| `INTERP_WATCH` / `INTERP_WATCH_BATCH` / `INTERP_WATCH_EMOJI` | 1 / 3 / 📋 | Live progress mirroring to the owner chat |
| `INTERP_SINK_<CATEGORY>` | — | Override a tainted sink decision: `allow` / `deny` / `approve` |

## Recipes

**Gate a new MCP server's dangerous tools.** Its tools execute code → `exec_tools`. It automates your GUI → `desktop_act_tools` (or `takeover_act_tools` if it clicks blind coordinates). It ingests external content → `web_mcp_prefixes`.

**Protect a new secret.** Readable secret (API-key file) → `secret_files` (gates `cat`/`copy`/... of it). Writable-sensitive location (synced dir, kube config) → `sensitive_paths` (gates `write_file`, and tainted plan output is denied there).

**Gate a new command shape.** `cmd_rules` with an existing category inherits its behavior. With a new category name, add it to `CAMEL_SECURITY_CATEGORIES` to make it prompt; otherwise it's audit-only — a reasonable way to trial a rule before enforcing it.

**Try a rule without enforcement.** Leave its category out of `CAMEL_SECURITY_CATEGORIES`, watch `security-audit.jsonl` for a few days, then add the category.

## What's *not* configurable here

The interpreter's sink *policy* (what tainted data may do) is code plus the `INTERP_SINK_<CATEGORY>` overrides — deliberately. New operations and sink categories are code changes with tests; see [EXTENDING.md](EXTENDING.md).
