# Deployment Guide

CADRE-RevAI deploys to a single REMnux VM. The `revai/` package is copied to `/opt/scripts/` (the conventional REMnux analysis-scripts location), tests are copied to `/opt/scripts/tests/`, and the optional v4 agentic-recovery package is copied to `/opt/cadre-v4-tools/`.

## Prerequisites

`install/setup-remnux.sh` must have completed successfully. Ghidra, ghidrasql, Malcat, and LLM config must be in place — see [`PREREQUISITES.md`](PREREQUISITES.md) and [`INSTALL.md`](INSTALL.md).

## Configure the environment

1. Copy the LLM template (required) and optionally the RAG template:
   ```bash
   sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
   sudo nano /opt/cadre-v3-tools/llm.env
   # Optional — only if you want opt-in RAG (product default is LLM-only):
   # sudo cp config/rag.env.template /opt/cadre-v3-tools/rag.env
   ```

2. `llm.env` example:
   ```bash
   REVENG_LLM_MODEL=deepseek-v4-pro
   REVENG_LLM_API_URL=https://api.deepseek.com
   REVENG_LLM_API_KEY=<REDACTED_API_KEY>
   REVENG_LLM_REASONING=max
   ```

3. RAG is **off by default** (`REVENG_RAG=0` in `revai.service`). If you opt in:
   ```bash
   REVENG_RAG=1
   REVENG_RAG_BACKEND=remote
   REVENG_REMOTE_EMBED_URL=http://localhost:8000
   REVENG_RAG_HYBRID=1
   ```
   Or enable **Settings -> Enable RAG** in the Flask UI without editing `rag.env`.

## Deploy the pipeline

```bash
./scripts/deploy.sh --restart
```

This command:
- Copies `revai/*` to `/opt/scripts/`.
- Copies `revai/v4/*` to `/opt/cadre-v4-tools/`.
- Copies `tests/*` to `/opt/scripts/tests/`.
- Installs `install/revai.service` and reloads systemd.
- Restarts the `revai` service.
- Sets ownership to `remnux:remnux` on `/opt/scripts/`, `/opt/cadre-v4-tools/`, and `/opt/samples/`.

If you do not want to restart the service, omit `--restart`:

```bash
./scripts/deploy.sh
sudo systemctl start revai
```

## Open the UI

Open `http://<remnux-ip>:5000` in a browser.

## Verification

```bash
python3 /opt/scripts/v2_validate.py --smoke-only
```

Expected output: `V2_SMOKE_OK`.

For a more thorough check, run the verification script:

```bash
./install/verify-remnux.sh
```

## Re-deploying after updates

After pulling updates from this repo, re-run:

```bash
./scripts/deploy.sh --restart
python3 /opt/scripts/v2_validate.py --smoke-only
```

## Important

- Never commit `llm.env`, `rag.env`, or any file containing API keys.
- Never commit sample binaries or third-party training materials.
- The Flask UI is intended for trusted LAN use. Do not expose it to the public internet without additional hardening.
