# Configuration

RevAI is fully environment-driven. No LLM model, API key, endpoint, or reasoning level is hardcoded in the pipeline scripts. Runtime settings are read from `/opt/revai/config/llm.env`, which the systemd service loads at startup.

The Console (Flask UI) reads the LLM key from that same file through the service environment — **the UI never stores or accepts secrets**. The Settings page only manages non-secret options (model, base URL, reasoning, run configuration); the API key is reported as configured / not configured and must be set in `/opt/revai/config/llm.env`.

The same rule covers the optional **Dynamic analysis (WinRE)** panel: it stores the FlareVM address, SSH user/port, the SSH key **path**, detonation window, mode and snapshot gate — never key material. The runner exports those values as `FLARE_*` for the WinRE invocation (`docs/WINRE-REMOTE.md`).

You can also override settings per run through the React Console **Settings** tab; these are persisted to `/opt/samples/pipeline-config.json` and injected into every stage subprocess.

## LLM configuration (`llm.env`)

| Variable | Required | Description |
|---|---|---|
| `REVAI_LLM_MODEL` | Yes | OpenAI-compatible model name — use whatever your provider exposes. This is the **default** model: the agentic tool loop plus every call that does not ask for a specific role (triage verdict, scripted deep dive, function recovery, reports, v3 sections). |
| `REVAI_LLM_API_URL` | Yes | OpenAI-compatible **base URL** (not the full endpoint). The pipeline appends `/chat/completions` internally. |
| `REVAI_LLM_API_KEY` | Yes | API key for the above endpoint. |
| `REVAI_LLM_REASONING` | No | Provider-specific reasoning control. On the Agnes endpoint, use `enabled` or `disabled`; the Chat Completions API exposes a Thinking on/off flag, not `low` / `medium` / `high` effort levels. Those legacy values remain accepted as aliases for `enabled`. Other providers may support effort levels. After a timeout, RevAI retries once at the same setting with a doubled read window before its final no-thinking fallback. |
| `REVAI_LLM_TEMPERATURE` | No | Temperature for LLM judge calls. Default `0.0` — the value that makes runs reproducible — clamped to `[0.0, 2.0]`. The key **is read and applied**: it is written into every judge request body and into the LangGraph paths. A non-numeric value falls back to the default rather than failing a run. `config/llm.env.template` ships it commented out on purpose: an active non-zero value silently makes runs non-reproducible, and no measurement has shown a benefit. |
| `REVAI_LLM_TIMEOUT` | No | Read timeout (seconds) for LLM judge calls. Default `300`; raise it for very long prompts with Thinking enabled. A timeout earns one retry at the **same** setting with a **doubled** window, then a no-thinking fallback — a slow generation and a provider stall look identical from inside the client, and the longer retry covers both. |
| `REVAI_GHIDRA_CONTEXT_TIMEOUT_S` | No | Per-query timeout (seconds) for the Ghidra / IDAsql lookups that build function-recovery context. Default `120`, floored at `15`; an unparseable value falls back to the default rather than failing a stage. It exists because one hanging context query would otherwise stall a whole recovery run — raise it only on a project large enough that legitimate queries time out. |
| `REVAI_LLM_MAX_TOKENS` | No | Per-request **output** cap (`max_tokens`), per call — not a run budget. Default `32768`. The value is clamped to the configured model's published output limit when RevAI has a provider-specific limit implemented. It remains a guard rail against pathological requests, not a run-wide budget. Raising it is not a substitute for splitting oversized requests — calls that exceeded the prior `16384` limit were rejected as truncated and retried, costing one report stage ~1,331s of its 3,600s budget. Oversized report calls are now split per section. |
| `REVAI_FLOSS_MAX_STRINGS` | No | How many FLOSS strings reach the prompt. Default `300` (was `80`). Indicator-shaped strings — registry paths, URLs, IPs, emails, file paths, `Global\`/`Local\` mutexes, script and executable names — claim this budget **first**, in any FLOSS category, and the artifact records `ioc_shaped_total` / `ioc_shaped_sampled` / `ioc_shaped_dropped` so a truncated indicator set is visible rather than silent. The ordering matters more than the number: taking strings in FLOSS category order starved `static_strings` last, which is where plain registry paths and URLs live. On win32k_dll that dropped all seven real UTF-16 registry paths — including `...\Winlogon\SpecialAccounts\UserList` — from the evidence the report was written from. |
| `REVAI_LLM_STREAM` | No | `1` (default) sends LLM requests with `stream=True` and logs time-to-first-token, total seconds and tokens/sec per call. `0` restores plain non-streaming requests. Streaming is on by default because a non-streaming socket carries no bytes until the response is complete, so "slow" and "dead" are the same observation; with streaming, a slow generation is visible as a slow generation. If the endpoint ignores `stream=True` the client falls back to a plain POST automatically. |
| `REVAI_DEPTH` | No | `1` / `true` / `on` enables **depth mode** — a separate, opt-in run that follows the main pipeline and aims to understand HOW the sample works, not whether it is malicious. Off by default. `full` selects the **full depth profile** (plan #26): the same post-pipeline run on the domain-node substrate — every capability domain investigated by its own bounded tool-calling node, a raised ceiling, and emulation/unpack/solver forced on for the investigation. Long runtimes are expected there by design. Its output is a function map (`understanding.json`), never a verdict, and it never gates the main pipeline. Costs more and takes longer by design. |
| `REVAI_ENABLE_BEHAVIOURAL_MODEL` | No | `1` builds the **behavioural model** stage — what the sample *does*, assembled from the run's own artifacts: capabilities with their provenance, the concrete objects they act on (registry keys, URLs, domains, IPs, files, mutexes), the observations backing each, and the gaps. Off by default, so a run without it is byte-identical. Built deterministically, never authored by the model: a model-authored behavioural model is a plausible story, and a plausible story about a malware sample is the most expensive kind of wrong. Opt out with `REVAI_DISABLE_BEHAVIOURAL_MODEL=1` |
| `REVAI_DOMAIN_GRAPH` | No | `1` / `true` / `yes` / `on` runs the deep dive as named capability-domain nodes instead of one flat ReAct loop. Off by default, so the flat engine stays the validated path until this is exercised on a real sample. If no domain produces a substantive answer, the deep dive falls back to the flat engine automatically and records the fallback in the stage history; there is no setting for this |
| `REVAI_DOMAIN_MAX_STEPS` | No | Super-step ceiling for one capability-domain node. Default `60` — a floor rather than a constant: it rises with `REVAI_DOMAIN_STEP_BUDGET` (`max(60, budget*12+8)`) so a larger ask keeps its runaway bound proportional. LangGraph counts super-steps, not tool calls, and one agent turn can fan out to several tools, so this cannot express "at most N tool calls" — it is the runaway bound, sized to leave a thorough node room to reach an answer. Measured on packed_rook_native: at a ceiling of 20, `persistence` (12 tool calls) and `c2_network` (10) were truncated, and a truncated node can never be reported as `observed`. A non-numeric or zero value falls back to the default rather than disabling the node |
| `REVAI_DOMAIN_STEP_BUDGET` | No | Tool calls each domain node is ASKED to spend. Default `3`. This is a request, not a cap: the runtime ceiling is counted in super-steps, which is not the same unit as tool calls, so a node that overruns is recorded with `over_budget` rather than stopped. Per-domain budgets mean a stubborn injection question can no longer consume the whole run before persistence was ever looked at. A non-numeric or zero value falls back to the default rather than failing a run |
| `REVAI_DISABLE_CAPABILITY_COVERAGE` | No | `1` suppresses the capability-coverage ledger — the deterministic report section that lists, per capability domain, what the deep dive examined and determined, and names the domains left unknown. Off-switch only; the ledger has no other setting. Generated from the analysis record, never authored |
| `REVAI_LOGS_DIR` | No | Root of the per-sample case directories (default `/opt/samples/logs`). `depth_agent.py` reads it to decide whether a sample has been run at all: a sha whose case directory does not exist makes the depth stage exit 3 rather than report an empty map, so a mis-invocation cannot pass for "the sample has no functions". |
| `REVAI_DEPTH_MAX_ATTEMPTS` | No | How many times the depth convergence loop may investigate ONE capability domain. Default `1`. Retrying a region that just came back unknown spins -- the same question, the same tools, the same answer, forever; measured at 27,162,541 LLM calls for three regions before attempts were bounded. A region that stays unknown after its attempts is **costed and declared**, not retried. A non-numeric or zero value falls back to 1 rather than disabling the bound |
| `REVAI_DEPTH_CEILING_SECONDS` | No | Depth mode's ceiling. Default `7200` (2 hours) for the standard profile and `14400` (4 hours) for `REVAI_DEPTH=full` — long runtimes are expected there by design. The ceiling does not truncate — hitting it forces a *consolidate and declare* phase, so a cutoff yields a partial-but-honest map with the remaining unknowns explicitly costed, never nothing. |
| `REVAI_DEPTH_FULL_MAX_STEPS` | No | The deep-dive step budget the full profile asks the domain-node substrate for, per pass. Default `16`. The per-domain tool budget is `REVAI_DOMAIN_STEP_BUDGET` (the full profile asks for `8` when unset); this is the outer step budget for the pass. |
| `REVAI_STEERING_FILE` | No | Path to a file of analyst notes read before the run (L1 light steering). Absent by default. The note is context, not an instruction: tool evidence outranks it and it cannot set a verdict. |
| `REVAI_CASE_DIR` | No | Case directory for a single-stage invocation. `depth_agent.py <target>` accepts either a case directory or a sample sha256 and resolves a sha through the normal `case_dir()` rule; setting this supplies the directory directly. A target that resolves to no directory on disk exits `3` rather than reporting an empty map, so a mis-invocation cannot look like "the sample has no functions". |
| `REVAI_TECHNICAL_SECTIONWISE` | No | Default `1`: the technical report is generated one section per LLM call, with evidence routed to the sections that need it. Set `0` to restore the single-call assembly — which is retained only as a rollback lever, because asking one call for all 13 sections exceeds the per-request output budget and returns a truncated report (measured 2026-10-01 on win32k_dll: 1 of 13 sections, 10 stubs). |
| `REVAI_LLM_PLANNER_MODEL` | No | The **agentic tool loop** (the ReAct planner bound to the deep-dive tool registry) — the call-heavy role. Defaults to `REVAI_LLM_MODEL`. |
| `REVAI_LLM_VERDICT_MODEL` | No | The **judgment role**: every call that renders a judgment about the sample — the quick-scan triage verdict, the scripted deep-dive judge, and the agentic final judge. Defaults to `REVAI_LLM_MODEL`. It does not move function recovery, the reports or the v3 sections, so pinning the strongest model here costs two calls per scripted run and one per agentic run. |

> **Role separation.** All three names are resolved independently (`v2_lib.get_default_model` /
> `get_planner_model` / `get_verdict_model`) and each role pin falls back to `REVAI_LLM_MODEL`, so a
> single-model setup only needs the one value. Every report records the model it was produced with, and
> the run gate plus the quality pack carry the resolved `default` / `planner` / `judgment` names, so the
> routing can be verified per case instead of trusted. The Console can override the default model for
> console-started runs; it never overrides the two role pins.

> **Provider-agnostic.** RevAI works with any OpenAI-compatible chat-completions API — no provider, model, or endpoint is hardcoded. The pipeline normalizes LLM output regardless of the JSON key the model returns for report content (`markdown`, `mark`, `content`, `body`, `text`, `report`, or `output`) via `v2_lib.normalize_llm_json`. Fenced JSON, prose-wrapped JSON, and raw markdown are all tolerated.

If `REVAI_LLM_API_KEY` is not set, the fallback chain is:
1. `REVAI_LLM_API_KEY` from the process environment
2. `/opt/secrets/cadre.env` (legacy lab secrets file)

### Optional: WinRE (the dynamic companion)

WinRE is an optional second product on this same host (`/opt/winre`). Its LLM
configuration stays separate from RevAI in every mode. Resolution order, first
match wins per variable:

1. the process environment (`WINRE_LLM_*`),
2. WinRE's own env file: `WINRE_ENV` when set, otherwise `/opt/winre/.env`.

| Where | What to write |
|---|---|
| `/opt/revai/config/llm.env` | RevAI provider, model, key and reasoning only |
| `/opt/winre/.env` (chmod 600, never commit) | `WINRE_LLM_BASE_URL`, `WINRE_LLM_MODEL`, `WINRE_LLM_API_KEY`, `WINRE_LLM_REASONING` — any value set here wins |
| FlareVM | **nothing** — the Windows VM never holds LLM configuration; all LLM calls happen in the driver process on this host |

RevAI never fills missing WinRE settings from its own configuration. The legacy
`REVAI_WINRE_LLM_SOURCE=inherit` setting is treated as `winre_env`; it cannot
enable sharing. An agentic pass without WinRE's required settings is refused
up front with `winre_llm_unset`. **Test connection** reports the source without
echoing the key. Running WinRE's CLI directly instead of through RevAI:

```bash
/opt/scripts/winre-llm-env.sh --check     # what would be used
eval "$(/opt/scripts/winre-llm-env.sh)"   # export into this shell
```

Full guide: [`WINRE-REMOTE.md`](WINRE-REMOTE.md).

## Optional: IDA Pro

If you have a licensed IDA Pro 9.3 for Linux installed at `/opt/ida` with `idasql` on `PATH`, the pipeline will use it in addition to Ghidra. If not, the pipeline falls back to Ghidra SQL only.

## Environment reload

After editing `/opt/revai/config/llm.env`:

```bash
sudo systemctl restart revai
```

## Troubleshooting

- If the UI shows **"No LLM backend configured"**, check that `llm.env` exists and is loaded by the service.
- If LLM calls fail, confirm the base URL is reachable from REMnux and that the model name matches your provider: `curl <REVAI_LLM_API_URL>/models`.
