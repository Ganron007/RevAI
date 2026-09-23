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
- **angr** via `pipx` (deobfuscation / symbolic execution; the wrapper runs it from its pipx venv).
- Extended static stack: **GoReSym**, **RIFT**, **FindCrypt** — downloaded and installed to their expected paths when absent.
- **idasql** CLI + IDA plugin — only when IDA Pro is installed (version-matched 9.2/9.3/9.4 build of v0.0.18.1).
- **WinRE (optional dynamic companion)** — off by default: `REVAI_WITH_WINRE=1 sudo -E ./install/setup-remnux.sh` clones the public [WinRE](https://github.com/Ganron007/WinRE) repo to `/opt/winre`, creates its venv and scaffolds `.env`. Without it, RevAI stays static-only (reports byte-identical) and the step just warns.
- capa-rules + flattened YARA under `/opt/samples/rules/flat/`.
- Lab dirs: `/opt/samples/`, `/opt/scripts/`, `/opt/revai/`.

Every optional step soft-fails with a warning: the pipeline reports honestly and
degrades to the remaining engines.

**Malcat** is not auto-downloaded (vendor license). Place it at `/opt/malcat` so `/opt/malcat/bin/malcat.mcp.py` exists before audited runs. The pipeline runs without Malcat (`--skip-malcat`); only audited runs require it.

## revai-tools (in-repo, flat)

The `revai_tools_*` wrappers invoke the **revai-tools** CLI (`cli.py` — stdlib-only
PE/ELF parsers, mitigations-with-consequence, sink-site + provenance audit,
wallet/IOC extraction), which **ships in this repo** flat among the pipeline scripts
(`revai/cli.py`, `revai/mitigations.py`, `revai/sinkcat.py`, …) and deploys to
`/opt/scripts/` with the rest of the pipeline. No external download, no extra
install — the wrappers run `cli.py` from the scripts directory automatically.

Every wrapper is **fail-open**: missing radare2 (sink/audit backends), error,
timeout, or format-mismatch is recorded and never gates a stage.

See [`PREREQUISITES.md`](PREREQUISITES.md) for the full contract.

## Run the setup script

```bash
git clone https://github.com/Ganron007/RevAI.git
cd RevAI
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
2. Run `install/setup-remnux.sh` — it installs the matching **idasql** CLI (`/usr/local/bin/idasql`) and IDA plugin automatically (v0.0.18.1 build for the detected IDA 9.2/9.3/9.4). Verify with `idasql --version`.
3. Pipeline uses IDA SQL alongside Ghidra; otherwise Ghidra-only.

Do not commit IDA installers or licenses.

## Verify

```bash
./install/verify-remnux.sh
```

Expect `Result: PASS` (ghidrasql + Ghidra + deployed scripts + smoke preflight; Malcat optional).

## Next step

Configure LLM and deploy: see [`DEPLOY.md`](DEPLOY.md) · day-to-day: [`OPERATE.md`](OPERATE.md).
