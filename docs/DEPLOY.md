# Deployment Guide

RevAI deploys to a single REMnux VM. The `revai/` package is copied to `/opt/scripts/` (the conventional REMnux analysis-scripts location), the React Console UI is built and deployed to `/opt/scripts/ui/`, and tests are copied to `/opt/scripts/tests/`.

## Prerequisites

`install/setup-remnux.sh` must have completed successfully. Ghidra, ghidrasql, and LLM config must be in place — see [`PREREQUISITES.md`](PREREQUISITES.md) and [`INSTALL.md`](INSTALL.md). Malcat is optional (pipeline runs with `--skip-malcat`).

## Configure the environment

1. Copy the LLM template (required):
   ```bash
   sudo cp config/llm.env.template /opt/revai/config/llm.env
   sudo nano /opt/revai/config/llm.env
   ```

2. `llm.env` example (any OpenAI-compatible provider — fill with your own values):
   ```bash
   REVAI_LLM_MODEL=<your-model-name>
   REVAI_LLM_API_URL=<provider-base-url>
   REVAI_LLM_API_KEY=<REDACTED_API_KEY>
   REVAI_LLM_REASONING=<low|medium|high|max>
   REVAI_LLM_PLANNER_MODEL=<your-model-name>
   REVAI_LLM_VERDICT_MODEL=<your-model-name>
   ```
   Note: `REVAI_LLM_API_URL` is the **base URL** — the pipeline appends `/chat/completions` internally. Do not include the full endpoint path.

See [`CONFIGURE.md`](CONFIGURE.md) for the full variable reference.

## Deploy the pipeline

```bash
./scripts/deploy.sh --restart
```

This command:
- Copies `revai/*` to `/opt/scripts/`.
- Builds the React Console UI via npm (`revai/ui`) and deploys it to `/opt/scripts/ui/`.
- Copies `tests/*` to `/opt/scripts/tests/`.
- Installs `install/revai.service` and reloads systemd.
- Restarts the `revai` service.
- Sets ownership to `remnux:remnux` on `/opt/scripts/`, `/opt/revai/`, and `/opt/samples/`.

> Building the Console UI requires Node.js (≥18). If `npm` is not on `PATH`, `deploy.sh` skips the UI build and prints a warning — install Node.js and re-run to build it.

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

- Never commit `llm.env` or any file containing API keys.
- Never commit sample binaries or third-party training materials.
- The Flask UI is intended for trusted LAN use. Do not expose it to the public internet without additional hardening.
