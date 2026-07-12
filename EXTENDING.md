# Extending camel-security

**Most extension is configuration, not code.** New command rules, new tools/servers to gate or quarantine, new secret files — all of that is `camel-security.yaml` + env appends, covered in [CONFIGURATION.md](CONFIGURATION.md). This document is for *code* extension: changing what defaults ship, adding interpreter operations, and adding sink categories/policies.

## Map of the moving parts

| What | Where | Mechanism |
|---|---|---|
| Terminal command rules | `__init__.py` → `_CMD_RULES` defaults; user rules via `camel-security.yaml` | Ordered `(category, regex)` tuple — first match wins; user rules prepended by `_rebuild_rules()` |
| Tool-name → category tables | `__init__.py` → `_TERMINAL_TOOLS`, `_MSG_TOOLS`, `_FILE_WRITE_TOOLS`, `_UIA_ACT`, `_TAKEOVER_ACT`, `_MCP_EXEC_TOOLS`, `_MEDIA_READ_TOOLS` defaults; extended by yaml/env in `_rebuild_rules()` | Set membership, matched via `_suffix_match()` (MCP-shape robust) |
| Which categories gate (vs audit-only) | `__init__.py` → `_GATED_DEFAULT` | Overridable per profile: `CAMEL_SECURITY_CATEGORIES` |
| Which categories never cache an approval | `__init__.py` → `_NO_CACHE_DEFAULT` | Overridable: `CAMEL_SECURITY_NO_CACHE` |
| Untrusted web-ingest sources | `__init__.py` → `_TOOLSET_TOOLS`, `_WEB_MCP_PREFIXES`, `_WEB_MCP_TOOLS` | Toolset selection via `CAMEL_SECURITY_Q_TOOLSETS` |
| Classifier dispatch | `__init__.py` → `_classify()` | Ordered if-chain — order is policy (see below) |
| Interpreter operations | `interp.py` → `@_op(name, kind, adds, sink_category)` decorator, `OPS` registry | Anything not in `OPS` is rejected at plan validation |
| Capability propagation | `interp.py` → `Caps`, `Op.adds` | Automatic: output caps = union of input caps + `adds` |
| Sink policy | `interp.py` → `sink_decision()` (+ `_sink_category_for()` for path-dependent refinement) | Fail-closed; per-category env override `INTERP_SINK_<CATEGORY>` |
| Human-approval bridge | `interp.py` → `APPROVAL_FN` (injected by the gate at `register()`) | An `approve` sink decision routes to the host approval flow |
| The op menu the agent sees | `interp.py` → `plan_execute` tool description string | Must be updated when ops change — the model can only plan with ops it knows |
| Tests | `test_offline.py` | Offline, no network, faked ctx/backends |

## Design invariants

The §N markers in code comments refer to these (numbering follows the original design spec):

- **§5 Capability model.** Every value carries `caps.sources ⊆ {owner, web, file:<path>, tool:<name>}`. Plan literals are `{owner}` (trusted — the planner only ever saw trusted input). `web_search`/`web_fetch` produce `{web}`. `q_extract`/`q_summarise` **inherit** their input's sources — an LLM pass does not launder taint. `$ref`s carry caps, so referencing can't strip them.
- **§6 Sink policy (capability-aware).** Checked before every side effect: `send_owner` is always allowed (the owner is the safe sink); `send_other`/`egress` with any tainted arg is denied; `exec` with owner-only args runs frictionless, with tainted args is denied; tainted `write_file` is contained under `quarantine/`; genuinely ambiguous tainted action-sinks (e.g. `send_owner_actionable` — a drafted message the owner will act on) route to the human approval flow. Per-category override: `INTERP_SINK_<CATEGORY>=allow|deny|approve`.
- **§7 No-raw-return invariant.** The executor returns only a sanitized status/result to the planner. This includes the **error channel**: once a run has touched tainted data, error details are withheld from the planner (full detail goes to the audit log) — an "error message" is otherwise a perfect exfiltration/reinjection channel.
- **File provenance — the `quarantine/` location convention.** Tainted `write_file` output is forced under `<HERMES_HOME>/quarantine/`; the folder *is* the taint registry. Direct reads of quarantine paths (and of the audit logs themselves) by the top-level agent are plan-only; the `read_file` op re-taints their content.
- **Fail-open for availability, fail-closed for policy.** An internal plugin error never breaks the agent's turn; an unknown tainted sink category denies by default.

## Engineering invariants — keep these true, whatever you add

1. **Fail-open for availability, fail-closed for policy.** A bug in the plugin must never break the agent's turn (wrap in `try/except`, return "allow + audit" on internal errors). But an *unknown tainted sink category* must deny — never add a "probably fine" default.
2. **Q never cleans taint.** Any op that transforms data (`q_extract`, `filter`, a new `q_*` you add) must inherit/union its input caps. An LLM pass over web text is still web text.
3. **Raw tainted bytes never reach the planner** — not in results, not in error messages, not in progress lines. If your new op can embed input in an exception, sanitize it (see the §7 error-channel guard).
4. **Match MCP naming shapes.** Hermes registers MCP tools as `mcp_<server>_<tool>` (single underscores); other paths use `<server>__<tool>` or the bare name. Never `==`-match or `startswith`-match a bare tool name — use `_suffix_match()` or containment on a vendor prefix. This was a live bypass once (firecrawl/searxng MCP names sailed past the quarantine); don't reintroduce it.
5. **No double-prompting.** If Hermes' built-in guard (`detect_dangerous_command`/hardline) already gates a command shape, classify it audit-only here.
6. **Over-matching a *source* is safe; under-matching is not.** Wrongly quarantining a web-ish tool costs convenience (it's still usable via a plan). Missing one is a hole. Bias accordingly — and the reverse holds for *sinks*: an over-broad sink rule only adds prompts, an under-broad one silently allows.

## Recipe: change what ships as a DEFAULT

Site-specific entries belong in `camel-security.yaml` ([CONFIGURATION.md](CONFIGURATION.md)) — a default should only grow when a rule/tool is generic for *every* Hermes install (a new common secret-file name, a widely-used MCP vendor prefix, a missing PowerShell dialect of an existing rule).

1. Command rules: add to `_CMD_RULES`. **Order matters** — first match wins (that's why `secret_read` sits above `config` and `script_egress` is last; user yaml rules are prepended before all of them). Cover both shell dialects — Git Bash *and* PowerShell (`rm -rf` **and** `Remove-Item -Recurse -Force`).
2. Tool sets: add the **bare** tool name to the right `_DEFAULT`-role set; `_suffix_match()` covers the MCP naming shapes. Keep `_UIA_ACT`/`_TAKEOVER_ACT` defaults empty — GUI-automation fleets are inherently site-specific.
3. New category → decide gated vs audit-only (`_GATED_DEFAULT`) and whether approvals may session-cache (`_NO_CACHE_DEFAULT`). Per-action tools where each call is independently dangerous (the takeover pattern) belong in no-cache. New branches in `_classify()` mind the dispatch order — it is the precedence policy (quarantine-reads before file-writes, so `patch` on a quarantined file classifies as a *read*).
4. All default tables are snapshotted by `_rebuild_rules()` at first run (`_PRISTINE`) and merged with yaml/env on every rebuild — new tables must join that snapshot/merge, or user config will silently stop applying to them.
5. Tests: positive forms, near-miss negatives, all three MCP naming shapes, and an overlap check if a rule could shadow a neighbour.

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

Per profile `.env`: `CAMEL_SECURITY_CATEGORIES` / `CAMEL_SECURITY_NO_CACHE` reshape the gate; `CAMEL_SECURITY_Q_TOOLSETS` widens/narrows the quarantine; `INTERP_SINK_<CATEGORY>=allow|deny|approve` overrides a tainted-branch sink decision. Code changes are only needed for new *recognition* (rules, tools, ops) — never for tightening/loosening what's already recognized.

## Tests

`python test_offline.py` — no network, no Hermes install needed (Hermes imports are lazy, inside functions). Follow the existing `check(name, cond, detail)` style; group new checks under a numbered section. PRs that add a rule/op without matcher/policy tests will be asked to add them.
