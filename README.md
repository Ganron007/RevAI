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

## Tools, techniques & integrations

The pipeline is built from open-source RE tooling, with a few optional commercial add-ons. See the **docs/** folder and per-component `README.md` files for detailed operating procedures.

### Pipeline stages & how they map to tools

| Stage | What it does | Core tools / techniques |
|-------|--------------|---------------------------|
| **Intake** | Hash, file-type, load into Ghidra (+ optional IDA) | `pefile`, `lief`, `file`, `sha256sum`, **Ghidra** `analyzeHeadless`, **idasql** (optional) |
| **Triage** | Static signal + LLM verdict | **flare-capa**, **YARA-X** (`yr`), **FLOSS**, **radare2** (`r2`), **Malcat** (optional), `pefile`/`lief`, import/strings analysis, RAG context injection |
| **Deep Dive** | SQL-first decompilation, emulation, behavior | **Ghidra** + GhidraSQL skills, **Speakeasy** Windows PE emulation, **Frida** static probes, **idasql** (optional), CFF detection, .NET analysis (`dnfile` + `monodis`) |
| **Deobfuscation** | Symbolic execution, MBA, CFF | **Z3** (`z3-solver` / `python3-z3`), **angr**, **CFF deflatten** GhidraScript |
| **RAG** | Hybrid retrieval over malware knowledge | **bge-m3** embeddings via FastAPI/uvicorn, **bge-reranker-v2-m3** reranker (optional), `sentence-transformers` fallback, `faiss-cpu` HNSW ANN (optional), BM25 + dense + RRF hybrid search |
| **Rule Gen** | YARA + Sigma with FP control | Custom string/IOC extraction, `yara-x`, clean-goodware validation, `rule.yar` / `rule.yml` output |
| **Publish** | Markdown report assembly | Jinja-style templating, evidence tables, RAG citations, audit trail |
| **HITL** | Human approval gates | Confidence thresholds, critical-impact tags, Flask `/api/hitl/*` endpoints |
| **Agentic Recovery** | Optional function recovery | Call-graph ordered analysis, signature matching, LLM synthesis (see `revai/v4/v4-agentic-recovery-addendum.md`) |
| **Sandboxing** | Per-stage isolation | `bwrap` (bubblewrap) via `run_agent_sandbox.sh` |

### Tool inventory

| Tool | Role | License / install |
|------|------|-------------------|
| **Ghidra** | Disassembly, decompilation, SQL-first analysis | Free / `apt install ghidra` |
| **GhidraSQL skills** | Ghidra SQL extension for AI agents | Free / `git clone https://github.com/0xeb/ghidrasql-skills` |
| **IDA Pro 9.3 for Linux** | Optional disassembler/decompiler | Commercial (optional) — pipeline falls back to Ghidra if absent |
| **idasql** | IDA database query CLI | Bundled with IDA Pro |
| **flare-capa** | ATT&CK/MBC capability mapping | Free / `pip install flare-capa` |
| **flare-floss** | Obfuscated string extraction | Free / `pip install flare-floss` |
| **YARA-X** | Rule scanning | Free / `pip install yara-x` |
| **radare2** | Low-level disassembly / binary inspection | Free / `apt install radare2` |
| **Malcat** | Fast triage, script/archive/.NET/packer analysis | Commercial license or **free Malcat edition**; used via optional remote MCP. If Malcat is absent, the pipeline falls back to capa + YARA + FLOSS + r2. |
| **Speakeasy** | Windows PE emulation (no VM detonation) | Free / `pip install speakeasy-emulator` |
| **Frida** | Static hook / API trace probes | Free / `pip install frida-tools` |
| **Z3** | SMT solver for MBA / opaque predicates | Free / `apt install z3 python3-z3` or `pip install z3-solver` |
| **angr** | Symbolic execution / path constraints | Free / `pip install angr` |
| **CFF deflatten** | Control-flow flattening detection / recovery | Free / bundled GhidraScript |
| **Volatility 3** | Memory forensics | Free / `pip install volatility3` |
| **oletools / oledump** | Office document analysis | Free / `apt install python3-oletools` |
| **pefile / LIEF** | PE parsing | Free / `pip install pefile lief` |
| **sentence-transformers** | Local CPU embedding fallback (all-MiniLM-L6-v2) | Free / `pip install sentence-transformers` |
| **faiss-cpu** | Optional HNSW ANN index | Free / `pip install faiss-cpu` |
| **FastAPI / uvicorn** | Remote embedding + reranker service host | Free / `pip install fastapi uvicorn` |
| **bwrap** | Stage sandboxing | Free / `apt install bubblewrap` |
| **ghidra-rpc** | Ghidra RPC helper | Free / `uv tool install ghidra-rpc` |
| **REMnux 202602** | Base analysis VM | Free / remnux.org |

### Malcat usage note

Malcat is used heavily in the triage stage for script/document/archive files, .NET assemblies, packer detection, and quick YARA-delta triage. It is **optional**: the `mcp-malcat` server runs on a host that has Malcat installed, and the pipeline calls it via MCP. If you do not have a commercial license, the **free Malcat edition** can still handle a large subset of these tasks (script decompile, entropy, structure carving, and basic packer detection). When Malcat is unavailable, the pipeline falls back to **capa + YARA-X + FLOSS + radare2** for the same signals.

### Utility / support tooling

`install/setup-remnux.sh` also pulls in general-purpose RE utilities that support ad-hoc analysis: `nmap`, `foremost`, `dcfldd`, `stegsnow`, `testdisk`, `pdfid`, `oledump`, `poppler-utils`, `dex2jar`, `curl`, `wget`, `git`, `build-essential`, and the Z3/libssl development headers. These are not hard-wired into the pipeline, but they are available on the VM for manual use.

### RAG models

| Model | Use | Default endpoint |
|-------|-----|------------------|
| **BAAI/bge-m3** | Dense embeddings | `REVENG_REMOTE_EMBED_URL` (default `http://localhost:8000`) |
| **BAAI/bge-reranker-v2-m3** | Cross-encoder reranker | `REVENG_RERANKER_URL` (same host, optional) |
| **all-MiniLM-L6-v2** | Offline CPU embedding fallback | Local `sentence-transformers` |

### Documentation map

- [`docs/INSTALL.md`](docs/INSTALL.md) — full dependency install on REMnux.
- [`docs/DEPLOY.md`](docs/DEPLOY.md) — deploy pipeline, configure env files, start service.
- [`docs/CONFIGURE.md`](docs/CONFIGURE.md) — LLM/RAG/IDA env variables.
- [`docs/OPERATE.md`](docs/OPERATE.md) — day-to-day: staging samples, running stages, tests.
- `revai/deobfuscation/README.md` — Z3/angr/CFF usage.
- `revai/hitl/README.md` — HITL gates and API endpoints.
- `revai/v4/v4-agentic-recovery-addendum.md` — optional agentic recovery design.
- `revai/regression/README.md` — baseline regression samples.

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