# Configuration

RevAI is fully environment-driven. No LLM model, API key, endpoint, or reasoning level is hardcoded in the pipeline scripts. Runtime settings are read from `/opt/revai/config/llm.env`, which the systemd service loads at startup.

The Console (Flask UI) reads the LLM key from that same file through the service environment — **the UI never stores or accepts secrets**. The Settings page only manages non-secret options (model, base URL, reasoning, run configuration); the API key is reported as configured / not configured and must be set in `/opt/revai/config/llm.env`.

The same rule covers the optional **Dynamic analysis (WinRE)** panel: it stores the FlareVM address, SSH user/port, the SSH key **path**, detonation window, mode and snapshot gate — never key material. The runner exports those values as `FLARE_*` for the WinRE invocation (`docs/WINRE-REMOTE.md`).

You can also override settings per run through the React Console **Settings** tab; these are persisted to `/opt/samples/pipeline-config.json` and injected into every stage subprocess.

## LLM configuration (`llm.env`)

| Variable | Required | Description |
|---|---|---|
| `REVAI_LLM_MODEL` | Yes | OpenAI-compatible model name — use whatever your provider exposes. |
| `REVAI_LLM_API_URL` | Yes | OpenAI-compatible **base URL** (not the full endpoint). The pipeline appends `/chat/completions` internally. |
| `REVAI_LLM_API_KEY` | Yes | API key for the above endpoint. |
| `REVAI_LLM_REASONING` | No | Reasoning effort (`low` / `medium` / `high` / `max` / `disabled`), if your model supports it. Aborts, timeouts and empty responses retry with a step-down through the effort levels and a final no-thinking attempt, so a flaky thinking mode degrades gracefully. |
| `REVAI_LLM_TEMPERATURE` | No | Override temperature for LLM judge calls. Default `0.2`. |
| `REVAI_LLM_TIMEOUT` | No | Read timeout (seconds) for LLM judge calls. Default `300`; raise it for very long report prompts at high reasoning effort. |
| `REVAI_LLM_PLANNER_MODEL` | No | Agentic planner model (defaults to `REVAI_LLM_MODEL`). |
| `REVAI_LLM_VERDICT_MODEL` | No | Verdict / report model (defaults to `REVAI_LLM_MODEL`). |

> **Provider-agnostic.** RevAI works with any OpenAI-compatible chat-completions API — no provider, model, or endpoint is hardcoded. The pipeline normalizes LLM output regardless of the JSON key the model returns for report content (`markdown`, `mark`, `content`, `body`, `text`, `report`, or `output`) via `v2_lib.normalize_llm_json`. Fenced JSON, prose-wrapped JSON, and raw markdown are all tolerated.

If `REVAI_LLM_API_KEY` is not set, the fallback chain is:
1. `REVAI_LLM_API_KEY` from the process environment
2. `/opt/secrets/cadre.env` (legacy lab secrets file)

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
