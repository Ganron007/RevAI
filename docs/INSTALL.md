# Installation

## Requirements

- REMnux (Ubuntu 24.04 LTS-based) or equivalent isolated Ubuntu 24.04 analysis VM.
- At least 8 GB RAM and 100 GB disk (200 GB recommended for corpora + Ghidra projects).
- An OpenAI-compatible LLM API endpoint (**required**).
- **Ghidra**, **ghidrasql**, and optionally **Malcat** — see [`PREREQUISITES.md`](PREREQUISITES.md).

## What is installed

`install/setup-remnux.sh` installs and configures:

- System RE packages (radare2, yara, ghidra, python3-*, build tools, common utilities).
- Python deps from `requirements.txt` (Flask UI, triage wrappers, LangGraph + `langchain-openai` for large mode).
- **ghidrasql** via `install/install-ghidrasql.sh` (builds [0xeb/libghidra](https://github.com/0xeb/libghidra) + [0xeb/ghidrasql](https://github.com/0xeb/ghidrasql) when Ghidra is present; uses Ghidra's bundled Gradle wrapper — system Gradle is not required).
- capa-rules + flattened YARA under `/opt/samples/rules/flat/`.
- Lab dirs: `/opt/samples/`, `/opt/scripts/`, `/opt/cadre-v3-tools/`.

**Malcat** is not auto-downloaded (vendor license). Place it at `/opt/malcat` so `/opt/malcat/bin/malcat.mcp.py` exists before audited runs. The pipeline runs without Malcat (`--skip-malcat`); only audited runs require it.

## Run the setup script

```bash
git clone https://github.com/Ganron007/RevAI.git
cd CADRE-RevAI
sudo chmod +x install/*.sh scripts/deploy.sh
sudo ./install/setup-remnux.sh
```

The script is idempotent. If Ghidra was installed later:

```bash
sudo ./install/install-ghidrasql.sh
```

## Optional: IDA Pro

If you own IDA Pro 9.x for Linux:

1. Install to `/opt/ida`.
2. Ensure `idasql --version` works.
3. Pipeline uses IDA SQL alongside Ghidra; otherwise Ghidra-only.

Do not commit IDA installers or licenses.

## Verify

```bash
./install/verify-remnux.sh
```

Expect `Result: PASS` (ghidrasql + Ghidra + deployed scripts + smoke preflight; Malcat optional).

## Next step

Configure LLM and deploy: see [`DEPLOY.md`](DEPLOY.md) · day-to-day: [`OPERATE.md`](OPERATE.md).
