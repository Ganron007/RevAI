# Installation

## Requirements

- REMnux 202602 (Ubuntu 24.04 LTS-based) or equivalent Ubuntu 24.04 VM with REMnux tooling installed.
- At least 8 GB RAM and 100 GB disk (200 GB recommended for sample corpora and Ghidra projects).
- An OpenAI-compatible LLM API endpoint.
- A unified FastAPI embedding + reranker service for RAG (optional but recommended).

## What is installed

`install/setup-remnux.sh` installs and configures:

- System packages: `radare2`, `yara`, `ghidra`, `z3`, `python3-*`, `dex2jar`, and common RE utilities.
- Python ecosystem: `pefile`, `lief`, `flare-floss`, `frida-tools`, `yara-x`, `flare-capa`, `speakeasy-emulator`, `volatility3`, `oletools`, `z3-solver`, `angr`, `faiss-cpu`, `sentence-transformers`, `fastapi`, `uvicorn`.
- `uv` and `ghidra-rpc` for Ghidra SQL access.
- `capa-rules` and a flattened YARA rule set under `/opt/samples/rules/flat/`.
- Lab directory layout: `/opt/samples/`, `/opt/scripts/`, `/opt/cadre-v3-tools/`, `/opt/cadre-v4-tools/`, `/opt/revai/config/`.

## Run the setup script

```bash
git clone <this-repo>
cd CADRE-RevAI
sudo ./install/setup-remnux.sh
```

The script is idempotent: running it again will skip already-installed packages and directories.

## Optional: IDA Pro

If you own a licensed copy of IDA Pro 9.3 for Linux:

1. Install it to `/opt/ida`.
2. Ensure `/usr/local/bin/idasql` is available and returns a version:
   ```bash
   idasql --version
   ```
3. The pipeline will automatically use IDA SQL alongside Ghidra SQL. If IDA is absent, the pipeline falls back to Ghidra SQL only.

Do not commit any IDA installer, license, or patched binary to this repo.

## Next step

Configure your environment and deploy: see [`DEPLOY.md`](DEPLOY.md).
