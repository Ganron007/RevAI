# Configuration

CADRE-RevAI is fully environment-driven. No LLM model, API key, endpoint, or reasoning level is hardcoded in the pipeline scripts. Runtime settings are read from `/opt/cadre-v3-tools/llm.env` and `/opt/cadre-v3-tools/rag.env`, which the systemd service loads at startup.

You can also override settings per run through the Flask UI **Settings** tab; these are persisted to `/opt/samples/pipeline-config.json` and injected into every stage subprocess.

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

## RAG configuration (`rag.env`) — optional

Product default is **LLM-only** (`REVENG_RAG=0`). Create `rag.env` only when opting in.

| Variable | Required when RAG on | Description |
|---|---|---|
| `REVENG_RAG` | Yes | `0` (default) or `1` to enable RAG. |
| `REVENG_RAG_BACKEND` | Yes | Must be `remote` in this release. |
| `REVENG_REMOTE_EMBED_URL` | Yes | Base URL of the FastAPI embedding service. |
| `REVENG_RAG_HYBRID` | No | `1` enables BM25 + dense hybrid search. |
| `REVENG_RERANKER_URL` | No | Reranker base URL; leave unset to keep off. |
| `REVENG_EMBED_MODEL` | No | e.g. `BAAI/bge-m3`. |
| `REVENG_RAG_ANN` | No | `1` = FAISS HNSW ANN. Experimental. |
## Optional: agentic function recovery

Set `ENABLE_AGENTIC_RECOVERY=1` in `llm.env` or in the UI to run the optional v4 agentic function-recovery stage between deep dive and report publishing. It is off by default and is gated by sample size.

## Optional: IDA Pro

If you have a licensed IDA Pro 9.3 for Linux installed at `/opt/ida` with `idasql` on `PATH`, the pipeline will use it in addition to Ghidra. If not, the pipeline falls back to Ghidra SQL only.

## Environment reload

After editing `/opt/cadre-v3-tools/llm.env` or `/opt/cadre-v3-tools/rag.env`:

```bash
sudo systemctl restart revai
```

## Troubleshooting

- If the UI shows **"No LLM backend configured"**, check that `llm.env` exists and is loaded by the service.
- If RAG-aware stages fail with embedding errors, verify the remote FastAPI service is reachable from REMnux: `curl http://<host>:8000/health`.
- For reranker errors, ensure `REVENG_RERANKER_URL` is set and the remote service exposes `/rerank`.
