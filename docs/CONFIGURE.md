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
| `REVAI_LLM_MAX_TOKENS` | No | Per-request output cap. Default `16384`. This bounds a call to something that reliably finishes inside the read window at the measured generation rate (30-53 tokens/sec on the current endpoint), so a long request ends in a clean `finish_reason=length` that the pipeline rejects and retries, rather than in a silent stall. It is **not** a provider limit: requests at 32768 and 65536 were measured streaming normally. Very long reports must still be generated in sections (as the v3 sections already are), because a truncated single call yields no usable artifact. Re-measure the generation rate before changing this on a different provider. |
| `REVAI_LLM_STREAM` | No | `1` (default) sends LLM requests with `stream=True` and logs time-to-first-token, total seconds and tokens/sec per call. `0` restores plain non-streaming requests. Streaming is on by default because a non-streaming socket carries no bytes until the response is complete, so "slow" and "dead" are the same observation; with streaming, a slow generation is visible as a slow generation. If the endpoint ignores `stream=True` the client falls back to a plain POST automatically. |
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
