# Configuration

RevAI is fully environment-driven. No LLM model, API key, endpoint, or reasoning level is hardcoded in the pipeline scripts. Runtime settings are read from `/opt/revai/config/llm.env`, which the systemd service loads at startup.

You can also override settings per run through the React Console **Settings** tab; these are persisted to `/opt/samples/pipeline-config.json` and injected into every stage subprocess.

## LLM configuration (`llm.env`)

| Variable | Required | Description |
|---|---|---|
| `REVAI_LLM_MODEL` | Yes | OpenAI-compatible model name — use whatever your provider exposes. |
| `REVAI_LLM_API_URL` | Yes | OpenAI-compatible **base URL** (not the full endpoint). The pipeline appends `/chat/completions` internally. |
| `REVAI_LLM_API_KEY` | Yes | API key for the above endpoint. |
| `REVAI_LLM_REASONING` | No | Reasoning effort (`low` / `medium` / `high` / `max`), if your model supports it. |
| `REVAI_LLM_TEMPERATURE` | No | Override temperature for LLM judge calls. Default `0.2`. |
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
