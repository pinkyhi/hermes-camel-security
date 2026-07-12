# hermes-camel-security

Prompt-injection defense for [Hermes Agent](https://github.com/NousResearch/hermes-agent) as a **pure plugin** — no core changes, installable today.

## The problem

An agent reads untrusted content (a web page, a fetched file), the content contains instructions, and the agent acts on them with *your* tools and credentials. Upstream tracks this as [#496 (Promptware Defense)](https://github.com/NousResearch/hermes-agent/issues/496); core-runtime CaMeL guards were proposed in [#1992](https://github.com/NousResearch/hermes-agent/pull/1992) and reworked in [#3987](https://github.com/NousResearch/hermes-agent/pull/3987) (open). This plugin is the complementary angle: the same [CaMeL](https://arxiv.org/abs/2503.18813) idea implemented entirely on the public plugin surface, so it runs on stock Hermes without waiting for a core merge.

## How to use it

```
hermes plugins install pinkyhi/hermes-camel-security --enable
```

The approval gate + audit log work immediately, with generic coverage (git push / `gh` writes, curl/wget/PowerShell egress, encoded exec, rm/Remove-Item, common secret files). Enable the CaMeL layers per profile in `<HERMES_HOME>/.env`:

```env
CAMEL_SECURITY_INTERPRETER=1      # register the plan_execute tool
CAMEL_SECURITY_WEB_QUARANTINE=1   # route web research through it
CAMEL_SECURITY_Q_TOOLSETS=web     # add ",browser" to quarantine playwright/chrome-devtools too
```

Then teach it *your* environment (your MCP servers, secret files, GUI-automation tools) in `<HERMES_HOME>/camel-security.yaml` — copy the **recommended starting file from [CONFIGURATION.md](CONFIGURATION.md)** and extend it. Append-only over the defaults, fail-open on mistakes, restart the gateway to apply.

Day to day you'll see: sensitive actions pause for your `/approve` / `/deny` in chat; web research runs as a visible `📋` plan instead of raw page dumps in context; everything sensitive lands in `security-audit.jsonl`.

## What happens inside

Three layers:

1. **Approval gate + audit** — every tool call is classified (`pre_tool_call` hook); sensitive categories route through Hermes' own approval flow, everything is logged.
2. **Web-ingest quarantine** — direct web tools become *plan-only* for the top-level agent: raw web content never enters the main context.
3. **`plan_execute` interpreter** — the safe path:

```
   agent ── writes plan (JSON DAG, data not code) ─▶ deterministic executor
                                                       • tracks provenance on every value
                                                       • tool-less LLM (Q) reads untrusted bytes
                                                       • checks sinks BEFORE side effects
   agent ◀── sanitized status only ────────────────────┘
```

The plan is written **before** any untrusted data is seen; untrusted data flows as tagged values that can influence *results* but cannot redirect *control* or reach a dangerous sink (tainted egress/exec → denied; ambiguous cases → your approval). Raw tainted bytes never return to the agent — including via error messages. Full invariants: [EXTENDING.md](EXTENDING.md#design-invariants).

## Limitations

- Defense-in-depth, not a proof. The gate classifier is pattern-based (a speed bump + audit trail); the by-construction guarantees live in the interpreter path, and only for flows routed through it (web, by default). An injection arriving through an unquarantined channel (a file, a chat message) faces only the gate.
- The planner is the same LLM — the guarantee is that it plans *before* seeing untrusted data, not that it's trustworthy in general.
- Recognition lists are curated: a new tool/server needs a line in `camel-security.yaml` (no code). Unknown tainted *sinks* deny by default; unknown *sources* ingest as trusted until listed.

## Configuration & extension

- [CONFIGURATION.md](CONFIGURATION.md) — all switches, the starting `camel-security.yaml`, recipes.
- [EXTENDING.md](EXTENDING.md) — design invariants, adding interpreter ops / sink policies (code).

## Tests

`python test_offline.py` — 239 offline checks, stdlib-only, no Hermes install needed.

## Related upstream work

- [#496 — Security: Promptware Defense](https://github.com/NousResearch/hermes-agent/issues/496) (the problem statement)
- [#1992](https://github.com/NousResearch/hermes-agent/pull/1992) → [#3987 — CaMeL guard as opt-in runtime](https://github.com/NousResearch/hermes-agent/pull/3987) (the in-core approach; this plugin is the no-core-changes counterpart)
- [Debenedetti et al., *Defeating Prompt Injections by Design*](https://arxiv.org/abs/2503.18813) (the CaMeL paper)

## License

MIT
