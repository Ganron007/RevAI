# Configuration

CADRE-RevAI is fully environment-driven. No LLM model, API key, endpoint, or reasoning level is hardcoded in the pipeline scripts. Runtime settings are read from `/opt/cadre-v3-tools/llm.env`, which the systemd service loads at startup.

You can also override settings per run through the React Console **Settings** tab; these are persisted to `/opt/samples/pipeline-config.json` and injected into every stage subprocess.

## LLM configuration (`llm.env`)

| Variable | Required | Description |
|---|---|---|
| `REVENG_LLM_MODEL` | Yes | OpenAI-compatible model name, e.g. `deepseek-v4-pro`, `gpt-4o`. |
| `REVENG_LLM_API_URL` | Yes | OpenAI-compatible **base URL** (not the full endpoint). The pipeline appends `/chat/completions` internally. Example: `https://api.deepseek.com`. |
| `REVENG_LLM_API_KEY` | Yes | API key for the above endpoint. |
| `REVENG_LLM_REASONING` | No | Reasoning effort. Use `max` for highest reasoning on supported models. |
| `REVENG_LLM_TEMPERATURE` | No | Override temperature for LLM judge calls. Default `0.2`. |

If `REVENG_LLM_API_KEY` is not set, the fallback chain is:
1. `DEEPSEEK_API_KEY` environment variable
2. `/opt/secrets/cadre.env`

## Optional: IDA Pro

If you have a licensed IDA Pro 9.3 for Linux installed at `/opt/ida` with `idasql` on `PATH`, the pipeline will use it in addition to Ghidra. If not, the pipeline falls back to Ghidra SQL only.

## Environment reload

After editing `/opt/cadre-v3-tools/llm.env`:

```bash
sudo systemctl restart revai
```

## Troubleshooting

- If the UI shows **"No LLM backend configured"**, check that `llm.env` exists and is loaded by the service.
- If LLM calls fail, confirm the base URL is reachable from REMnux and that the model name matches your provider: `curl <REVENG_LLM_API_URL>/models`.
