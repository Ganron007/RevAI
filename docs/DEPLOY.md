# Deployment Guide

RevAI deploys to a single REMnux VM. The `revai/` package is copied to `/opt/scripts/` (the conventional REMnux analysis-scripts location), the React Console UI is built and deployed to `/opt/scripts/ui/`, tests and docs are copied to `/opt/scripts/tests/` and `/opt/scripts/docs/`, and the operator tools (including `run-watched.sh`, the recommended way to launch a watched run) are installed to `/opt/scripts/`.

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
   # For the Agnes endpoint, use enabled or disabled.
   REVAI_LLM_REASONING=<enabled|disabled>
   # Optional role pins - each falls back to REVAI_LLM_MODEL when blank.
   # The planner drives the agentic tool loop; the verdict pin drives the
   # agentic final judge only.
   REVAI_LLM_PLANNER_MODEL=<tool-loop-model>
   REVAI_LLM_VERDICT_MODEL=<judgment-model>
   ```
   On the Agnes endpoint, `enabled` turns Thinking on and `disabled` turns it
   off. Its Chat Completions API does not define effort levels such as `high`
   or `low`; those older values remain accepted as aliases for `enabled`.
   Note: `REVAI_LLM_API_URL` is the **base URL** — the pipeline appends `/chat/completions` internally. Do not include the full endpoint path.

See [`CONFIGURE.md`](CONFIGURE.md) for the full variable reference.

## Deploy the pipeline

```bash
./scripts/deploy.sh --restart
```

This command:
- Copies `revai/*` to `/opt/scripts/` (flat — includes `skills/`, `prompts/`, `recovery/` and `signatures/`).
- Builds the React Console UI via npm (`revai/ui`) and deploys it to `/opt/scripts/ui/`.
- Copies every `tests/*.py` to `/opt/scripts/tests/` — the helpers (`_layout.py`, `conftest.py`) ship too, or VM collection aborts.
- Copies `docs/` to `/opt/scripts/docs/`, so the VM runs the same documentation checks the repo does.
- Installs the operator tools — `run-watched.sh`, `instrument-live-log.sh`, `validate-ghidrasql-sql.py`, `winre-llm-env.sh`, `verify-release.sh` — to `/opt/scripts/`.
- Deploys the bundled API lookup index to `/opt/revai/api_index/`; an index already on the VM is preserved unless `REVAI_FORCE_API_INDEX=1`.
- Writes the pipeline commit to `/opt/revai/config/REVAI_COMMIT` (the provenance banner every artifact carries).
- Installs `install/revai.service`, reloads systemd and **enables** it (boot persistence).
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

And the full release gate (wiring harness + test suite + optional PE parity + VM
harness when `REVAI_VM_SSH` is set):

```bash
./scripts/verify-release.sh
```

Run a sample end-to-end under the watchdog (reboots when the VM is not fresh,
streams stages, classifies the first anomaly, refuses to start over a live run):

```bash
./scripts/run-watched.sh /path/to/sample
```

> The VM test suite must run from `/opt/scripts` — the flat runtime layout has no
> `revai/` package, and the tests resolve their imports from the working
> directory. Use a venv interpreter (`/tmp/rtvenv/bin/python -m pytest tests/ -q`)
> on PEP-668-managed systems.

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
