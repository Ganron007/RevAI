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
| `REVAI_LLM_REASONING` | No | Reasoning effort (`low` / `medium` / `high` / `max` / `disabled`), if your model supports it. Aborts, timeouts and empty responses retry with a step-down through the effort levels and a final no-thinking attempt, so a flaky thinking mode degrades gracefully. |
| `REVAI_LLM_TEMPERATURE` | No | Temperature for LLM judge calls. Note: this key is **not read by the current code** — the request body pins `temperature: 0.0`, which is what makes runs reproducible. Remove the key or wire it up; do not assume setting it changes anything. |
| `REVAI_LLM_TIMEOUT` | No | Read timeout (seconds) for LLM judge calls. Default `300`; raise it for very long report prompts at high reasoning effort. A timeout earns one retry at the **same** reasoning effort with a **doubled** window, then a no-thinking fallback — a slow generation and a provider stall look identical from inside the client, and the doubling covers both. |
| `REVAI_GHIDRA_CONTEXT_TIMEOUT_S` | No | Per-query timeout (seconds) for the Ghidra / IDAsql lookups that build function-recovery context. Default `120`, floored at `15`; an unparseable value falls back to the default rather than failing a stage. It exists because one hanging context query would otherwise stall a whole recovery run — raise it only on a project large enough that legitimate queries time out. |
| `REVAI_LLM_MAX_TOKENS` | No | Per-request **output** cap (`max_tokens`), per call — not a run budget. Default `32768`. It is a guard rail against a pathological prompt, deliberately set above anything legitimate work has produced, and **not** a tuned limit: there is no provider output ceiling. Asked to "write many thousands of words" the model stops voluntarily at ~6,900 tokens, under both the old `16384` cap and this one. Raising it is not a substitute for splitting an oversized request — the calls that used to overflow `16384` came back `finish_reason=length` and were rejected and retried, which cost one report stage ~1,331s of its 3,600s budget on responses that were discarded. Oversized report calls are now split per section. |
| `REVAI_FLOSS_MAX_STRINGS` | No | How many FLOSS strings reach the prompt. Default `300` (was `80`). Indicator-shaped strings — registry paths, URLs, IPs, emails, file paths, `Global\`/`Local\` mutexes, script and executable names — claim this budget **first**, in any FLOSS category, and the artifact records `ioc_shaped_total` / `ioc_shaped_sampled` / `ioc_shaped_dropped` so a truncated indicator set is visible rather than silent. The ordering matters more than the number: taking strings in FLOSS category order starved `static_strings` last, which is where plain registry paths and URLs live. On win32k_dll that dropped all seven real UTF-16 registry paths — including `...\Winlogon\SpecialAccounts\UserList` — from the evidence the report was written from. |
| `REVAI_LLM_STREAM` | No | `1` (default) sends LLM requests with `stream=True` and logs time-to-first-token, total seconds and tokens/sec per call. `0` restores plain non-streaming requests. Streaming is on by default because a non-streaming socket carries no bytes until the response is complete, so "slow" and "dead" are the same observation; with streaming, a slow generation is visible as a slow generation. If the endpoint ignores `stream=True` the client falls back to a plain POST automatically. |
| `REVAI_DEPTH` | No | `1` / `true` / `on` enables **depth mode** — a separate, opt-in run that follows the main pipeline and aims to understand HOW the sample works, not whether it is malicious. Off by default. Its output is a function map (`understanding.json`), never a verdict, and it never gates the main pipeline. Costs more and takes longer by design. |
| `REVAI_DOMAIN_GRAPH` | No | `1` / `true` / `yes` / `on` runs the deep dive as named capability-domain nodes instead of one flat ReAct loop. Off by default, so the flat engine stays the validated path until this is exercised on a real sample. If no domain produces a substantive answer, the deep dive falls back to the flat engine automatically and records the fallback in the stage history; there is no setting for this |
| `REVAI_DOMAIN_STEP_BUDGET` | No | Tool calls each domain node is ASKED to spend. Default `3`. This is a request, not a cap: the runtime ceiling is counted in super-steps, which is not the same unit as tool calls, so a node that overruns is recorded with `over_budget` rather than stopped. Per-domain budgets mean a stubborn injection question can no longer consume the whole run before persistence was ever looked at. A non-numeric or zero value falls back to the default rather than failing a run |
| `REVAI_DISABLE_CAPABILITY_COVERAGE` | No | `1` suppresses the capability-coverage ledger — the deterministic report section that lists, per capability domain, what the deep dive examined and determined, and names the domains left unknown. Off-switch only; the ledger has no other setting. Generated from the analysis record, never authored |
| `REVAI_LOGS_DIR` | No | Root of the per-sample case directories (default `/opt/samples/logs`). `depth_agent.py` reads it to decide whether a sample has been run at all: a sha whose case directory does not exist makes the depth stage exit 3 rather than report an empty map, so a mis-invocation cannot pass for "the sample has no functions". |
| `REVAI_DEPTH_CEILING_SECONDS` | No | Depth mode's ceiling. Default `7200` (2 hours). The ceiling does not truncate — hitting it forces a *consolidate and declare* phase, so a cutoff yields a partial-but-honest map with the remaining unknowns explicitly costed, never nothing. |
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

WinRE is an optional second product on this same host (`/opt/winre`), and its
agentic passes need an LLM too. **The model is written in one place by default:**
WinRE inherits `llm.env` above, so an operator who filled that file has a working
agentic WinRE with nothing extra to configure. Resolution order, first match wins
per variable:

1. the process environment (`WINRE_LLM_*`),
2. `/opt/winre/.env` — set these to give WinRE its **own** model or provider,
3. `/opt/revai/config/llm.env` (`REVAI_LLM_API_URL` maps to `WINRE_LLM_BASE_URL`,
   plus model, key and reasoning).

| Where | What to write |
|---|---|
| `/opt/revai/config/llm.env` | required for RevAI; also WinRE's default source |
| `/opt/winre/.env` (chmod 600, never commit) | `WINRE_LLM_BASE_URL`, `WINRE_LLM_MODEL`, `WINRE_LLM_API_KEY`, `WINRE_LLM_REASONING` — any value set here wins |
| FlareVM | **nothing** — the Windows VM never holds LLM configuration; all LLM calls happen in the driver process on this host |

Switch it off entirely with **Settings → Dynamic analysis → Share RevAI LLM
config** = `WinRE .env only` (or `REVAI_WINRE_LLM_SOURCE=winre_env`). An agentic
pass with nothing resolved is refused up front with `winre_llm_unset` instead of
failing mid-run, and **Test connection** reports which source is in effect
without echoing the key. Running WinRE's CLI directly instead of through RevAI:

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
