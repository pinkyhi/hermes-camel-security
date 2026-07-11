# Extending camel-security

The plugin is built to be extended in three places: the **gate** (what counts as a sensitive action), the **quarantine** (what counts as an untrusted source), and the **interpreter** (what operations plans can use, and what sinks are allowed to do with tainted data). This document maps the extension points and gives a recipe for each.

## Map of the moving parts

| What | Where | Mechanism |
|---|---|---|
| Terminal command rules | `__init__.py` → `_CMD_RULES` | Ordered `(category, regex)` tuple — first match wins |
| Tool-name → category tables | `__init__.py` → `_TERMINAL_TOOLS`, `_MSG_TOOLS`, `_FILE_WRITE_TOOLS`, `_UIA_ACT`, `_TAKEOVER_ACT`, `_MCP_EXEC_TOOLS`, `_MEDIA_READ_TOOLS` | Set membership, matched via `_suffix_match()` (MCP-shape robust) |
| Which categories gate (vs audit-only) | `__init__.py` → `_GATED_DEFAULT` | Overridable per profile: `SECURITY_GATE_CATEGORIES` |
| Which categories never cache an approval | `__init__.py` → `_NO_CACHE_DEFAULT` | Overridable: `SECURITY_GATE_NO_CACHE` |
| Untrusted web-ingest sources | `__init__.py` → `_TOOLSET_TOOLS`, `_WEB_MCP_PREFIXES`, `_WEB_MCP_TOOLS` | Toolset selection via `SECURITY_GATE_Q_TOOLSETS` |
| Classifier dispatch | `__init__.py` → `_classify()` | Ordered if-chain — order is policy (see below) |
| Interpreter operations | `interp.py` → `@_op(name, kind, adds, sink_category)` decorator, `OPS` registry | Anything not in `OPS` is rejected at plan validation |
| Capability propagation | `interp.py` → `Caps`, `Op.adds` | Automatic: output caps = union of input caps + `adds` |
| Sink policy | `interp.py` → `sink_decision()` (+ `_sink_category_for()` for path-dependent refinement) | Fail-closed; per-category env override `INTERP_SINK_<CATEGORY>` |
| Human-approval bridge | `interp.py` → `APPROVAL_FN` (injected by the gate at `register()`) | An `approve` sink decision routes to the host approval flow |
| The op menu the agent sees | `interp.py` → `plan_execute` tool description string | Must be updated when ops change — the model can only plan with ops it knows |
| Tests | `test_offline.py` | Offline, no network, faked ctx/backends |

## Invariants — keep these true, whatever you add

1. **Fail-open for availability, fail-closed for policy.** A bug in the plugin must never break the agent's turn (wrap in `try/except`, return "allow + audit" on internal errors). But an *unknown tainted sink category* must deny — never add a "probably fine" default.
2. **Q never cleans taint.** Any op that transforms data (`q_extract`, `filter`, a new `q_*` you add) must inherit/union its input caps. An LLM pass over web text is still web text.
3. **Raw tainted bytes never reach the planner** — not in results, not in error messages, not in progress lines. If your new op can embed input in an exception, sanitize it (see the §7 error-channel guard).
4. **Match MCP naming shapes.** Hermes registers MCP tools as `mcp_<server>_<tool>` (single underscores); other paths use `<server>__<tool>` or the bare name. Never `==`-match or `startswith`-match a bare tool name — use `_suffix_match()` or containment on a vendor prefix. This was a live bypass once (firecrawl/searxng MCP names sailed past the quarantine); don't reintroduce it.
5. **No double-prompting.** If Hermes' built-in guard (`detect_dangerous_command`/hardline) already gates a command shape, classify it audit-only here.
6. **Over-matching a *source* is safe; under-matching is not.** Wrongly quarantining a web-ish tool costs convenience (it's still usable via a plan). Missing one is a hole. Bias accordingly — and the reverse holds for *sinks*: an over-broad sink rule only adds prompts, an under-broad one silently allows.

## Recipe: gate a new dangerous terminal-command shape

1. Add `("category", re.compile(...))` to `_CMD_RULES`. **Order matters** — first match wins, so put specific/dangerous rules above broad/audit-only ones (that's why `secret_read` sits above `config`, and `script_egress` is last).
2. Cover both shell dialects — Git Bash *and* PowerShell forms (`rm -rf` **and** `Remove-Item -Recurse -Force`). This plugin exists partly because linux-only patterns miss half of Windows.
3. If the category is new, decide: gated (add to `_GATED_DEFAULT`) or audit-only (leave it out — it still lands in `security-audit.jsonl`). Start audit-only if you're unsure about false-positive rate; promote after watching the log.
4. Add matcher tests to `test_offline.py`: positive forms, near-miss negatives, and an overlap check if your rule could shadow / be shadowed by a neighbour.

## Recipe: gate a new tool (non-terminal) or a new action category

1. Add the tool's **base name** to an existing set (`_FILE_WRITE_TOOLS`, `_MCP_EXEC_TOOLS`, …) — or create a new set + a new branch in `_classify()`. Mind the dispatch order in `_classify()`: it is the precedence policy (e.g. quarantine-reads are checked before file-writes so `patch` on a quarantined file classifies as a *read*).
2. New category → decide gated vs audit-only (`_GATED_DEFAULT`) and whether approvals may session-cache (`_NO_CACHE_DEFAULT`). Per-action tools where each call is independently dangerous (the takeover pattern) belong in no-cache.
3. If the tool comes from an MCP server, test all three naming shapes (`tool`, `server__tool`, `mcp_server_tool`) — `_suffix_match()` handles them, direct membership checks don't.

## Recipe: quarantine a new untrusted source

New web-ish built-in toolset → add a `_TOOLSET_TOOLS["<toolset>"]` entry (users opt in via `SECURITY_GATE_Q_TOOLSETS`). New MCP server that ingests external content (RSS, mail, scraping…) → add its vendor prefix to `_WEB_MCP_PREFIXES` (containment match: covers current *and future* tools of that server). One-off tools → `_WEB_MCP_TOOLS`.

Then give the interpreter a way to reach that content safely — usually nothing to do (`web_fetch`/`read_file` already cover URL/file shapes), but a genuinely new transport needs a new read op (next recipe) or the quarantine just makes the source unusable.

## Recipe: add an interpreter read op

```python
@_op("rss_fetch", "read", adds=("web",))
def _rss_fetch(args, in_caps):
    ...
    return feed_items          # caps handled by the registry: in_caps ∪ {web}
```

1. `adds=` declares the provenance the op *introduces* (`web`, `file`, …). Transform-only ops (your `q_*`) take no `adds` — they inherit.
2. The body must be timeout-safe (it runs under `INTERP_OP_TIMEOUT` in a worker) and must not raise exceptions containing raw fetched bytes.
3. Update the `plan_execute` tool description — **the model can only use ops it can see in the menu.** Keep the entry short: name, arg shape, one-line semantics.
4. Add an offline test with the backend faked; assert both the data shape and the output caps.

## Recipe: add an interpreter sink op (side effects)

```python
@_op("send_email", "sink", sink_category="send_other")
def _send_email(args, in_caps, session=None):
    ...
```

1. Pick the `sink_category`. Reusing an existing one (`send_other`, `write_file`, …) inherits its policy. A **new** category is *deny-for-tainted by default* — that's deliberate. To allow or escalate instead, declare it explicitly in `sink_decision()` with a comment saying *why* (see `send_owner_actionable` for the escalate pattern, `write_quarantined` for the containment pattern).
2. If the decision depends on the *argument* (e.g. path), refine the category in `_sink_category_for()` rather than branching inside the policy.
3. `approve` decisions route through `APPROVAL_FN` to the host's human-approval flow automatically — nothing extra to wire.
4. Update the tool-description menu; test three cases minimum: trusted args (should be frictionless), tainted args (deny/approve per policy), and the `INTERP_SINK_<CATEGORY>` override.

## Tuning policy without code

Per profile `.env`: `SECURITY_GATE_CATEGORIES` / `SECURITY_GATE_NO_CACHE` reshape the gate; `SECURITY_GATE_Q_TOOLSETS` widens/narrows the quarantine; `INTERP_SINK_<CATEGORY>=allow|deny|approve` overrides a tainted-branch sink decision. Code changes are only needed for new *recognition* (rules, tools, ops) — never for tightening/loosening what's already recognized.

## Tests

`python test_offline.py` — no network, no Hermes install needed (Hermes imports are lazy, inside functions). Follow the existing `check(name, cond, detail)` style; group new checks under a numbered section. PRs that add a rule/op without matcher/policy tests will be asked to add them.
