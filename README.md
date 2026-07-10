# CADRE-RevAI

Autonomous malware reverse-engineering pipeline powered by LLM agents, RAG, and deobfuscation. Runs on a single REMnux analysis VM and provides a browser-based UI for triaging, deep-diving, YARA/Sigma generation, and report publishing on Windows PE samples.

## What it does

- **Triage** — file-type identification, YARA/capa/imports/strings analysis, LLM verdict.
- **Deep Dive** — Ghidra SQL-first decompilation, optional IDA SQL, Speakeasy emulation, behavioral extraction.
- **Rule Generation** — YARA + Sigma rules with false-positive control.
- **Reporting** — Markdown reports (executive and technical) with evidence tables.
- **RAG** — hybrid BM25 + dense retrieval over a malware-knowledge corpus via a unified FastAPI embedding service.
- **Deobfuscation** — Z3 MBA simplification, angr symbolic execution, CFF detection/deflatten.
- **HITL** — human-in-the-loop approval gates for high-confidence decisions.
- **Agentic Recovery (optional)** — call-graph-ordered function recovery between deep dive and report publishing.

## Repository layout

```text
CADRE-RevAI/
├── revai/              # Core pipeline package (deploys to /opt/scripts/)
│   ├── app.py          # Flask UI
│   ├── v2_lib.py       # Shared analysis library
│   ├── intake_v2.py    # Sample intake
│   ├── quick_scan_v2.py # Triage
│   ├── deep_dive_v2.py # Deep analysis
│   ├── yara_gen_v2.py  # Rule generation
│   ├── publish_report_v2.py  # Markdown report generator
│   ├── section_publisher.py   # Per-section report publisher
│   ├── v2_validate.py  # Smoke / regression validation
│   ├── ui/templates/   # Flask UI templates
│   ├── mcp-*/          # MCP servers (capa, floss, malcat, yara, decompile)
│   ├── rag/            # RAG searchers and embedder client
│   ├── deobfuscation/  # Z3/angr/CFF helpers
│   ├── cff-deflatten/  # GhidraScript CFF deflatten
│   ├── hitl/           # HITL checkpoint helpers
│   ├── v4/             # Optional agentic function recovery (deploys to /opt/cadre-v4-tools/)
│   └── ...             # Staging and maintenance scripts
├── install/            # setup-remnux.sh, verify-remnux.sh, revai.service
├── config/             # Environment templates (no secrets)
├── scripts/            # deploy.sh
├── docs/               # Installation, configuration, and operation guides
├── tests/              # Smoke and regression tests
└── README.md
```

## Tools & integrations

The pipeline stitches together best-of-breed RE tooling. Everything listed below is either installed automatically by `install/setup-remnux.sh` or clearly optional.

| Category | Tools |
|----------|-------|
| **Static triage** | `pefile`, `lief`, `flare-floss`, `flare-capa`, `yara-x`, `radare2` |
| **Disassembly / decompilation** | **Ghidra** + GhidraSQL skills extension; **IDA Pro 9.3 for Linux** (optional, falls back to Ghidra if absent) |
| **Emulation & behavior** | **Speakeasy** (Windows PE emulation), **Frida** (static hook probes) |
| **Documents & memory** | `oledump`, `oletools`, `volatility3`, `pdfid` |
| **Deobfuscation** | **Z3**, **angr**, **CFF deflatten** (GhidraScript) |
| **RAG / LLM context** | `sentence-transformers`, `faiss-cpu`, FastAPI/uvicorn (remote embedding + reranker service) |
| **MCP servers** | capa, FLOSS, YARA, decompile, malcat (optional remote MCP) |
| **Sandboxing** | `bwrap` (bubblewrap) per-stage sandbox |
| **Platform** | REMnux 202602 / Ubuntu 24.04 LTS, Python 3.12+, systemd |

## Screenshot

The Flask UI runs on `:5000` and is branded CADRE-RevAI end-to-end:

![CADRE-RevAI Pipeline UI](docs/img/ui-screenshot.png)

## Quick start

1. Install a REMnux 202602 VM (or equivalent Ubuntu 24.04 + REMnux tooling).
2. Clone this repo and run the setup script:
   ```bash
   sudo ./install/setup-remnux.sh
   ```
3. Configure your LLM and RAG endpoints:
   ```bash
   sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
   sudo cp config/rag.env.template /opt/cadre-v3-tools/rag.env
   sudo nano /opt/cadre-v3-tools/llm.env
   sudo nano /opt/cadre-v3-tools/rag.env
   ```
4. Deploy the pipeline:
   ```bash
   ./scripts/deploy.sh --restart
   ```
5. Open the UI at `http://<remnux-ip>:5000`.
6. Verify:
   ```bash
   python3 /opt/scripts/v2_validate.py --smoke-only
   ```
   Expected output: `V2_SMOKE_OK`.

See [`docs/INSTALL.md`](docs/INSTALL.md) for the full setup and [`docs/OPERATE.md`](docs/OPERATE.md) for day-to-day use.

## Architecture

```text
Sample drop / intake  →  Triage  →  Deep Dive  →  Rules  →  Reports
                              ↑           ↑           ↑
                              └──── RAG ──┴── Deobfuscation ─┘
```

The pipeline is driven by five Python scripts that read all runtime configuration from environment variables. No model name, API key, endpoint, or reasoning level is hardcoded.

## Optional: IDA Pro

If you have a licensed IDA Pro 9.3 for Linux installed at `/opt/ida` with `idasql` on `PATH`, the pipeline will use it alongside Ghidra. If IDA is absent, the pipeline falls back to Ghidra SQL only.

## Status

The v2/v3 pipeline is verified end-to-end on REMnux. The v4 agentic function-recovery stage is included as an optional preview, gated by `ENABLE_AGENTIC_RECOVERY=1`.

## License

MIT — see [LICENSE](LICENSE).

## Security

Do not commit API keys, secrets, or malware samples to this repository. Keep `llm.env`, `rag.env`, and any runtime data out of git. The `.gitignore` file already excludes common secret and output paths.