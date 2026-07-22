# CADRE-RevAI

<p align="center">
  <img src="assets/revai-logo.svg" alt="RevAI Logo" width="620">
</p>

<p align="center">
  <a href="https://github.com/CADRE-Platform/CADRE-RevAI"><img src="https://img.shields.io/badge/Status-v2.0.0-blue.svg" alt="Status"></a>
  <a href="https://github.com/CADRE-Platform/CADRE-RevAI"><img src="https://img.shields.io/badge/Platform-REMnux%20VM-green.svg" alt="Platform"></a>
  <a href="https://github.com/CADRE-Platform/CADRE-RevAI"><img src="https://img.shields.io/badge/UI-Flask%20Single--Pane-purple.svg" alt="UI"></a>
</p>

> [!WARNING]
> **Malware Sandbox Containment.** CADRE-RevAI is an LLM-assisted malware reverse-engineering pipeline. Because it operates on live malicious binaries, it **must** be executed strictly within an isolated, host-segmented malware analysis environment (such as a dedicated REMnux VM). The authors and contributors accept no liability for any dynamic execution leaks, payload escapes, or network contamination arising from improper containment configurations.

---

## What is CADRE-RevAI?

**CADRE-RevAI** is a contained, SQL-first malware analysis and rule-generation pipeline for Windows PE and Linux ELF binaries. Deployed as a self-contained analysis workspace on a REMnux virtual machine, RevAI automates the evidence-gathering and signature construction lifecycle for compiled binaries.

Rather than relying on raw decompilation or unstructured text scraping, RevAI maps target files to structured SQLite databases representing disassembly metadata from Ghidra or commercial IDA Pro. It runs standard static and dynamic triage tools, then leverages an OpenAI-compatible Large Language Model (LLM) as an expert judge to synthesize deep findings, explain functionality, and generate optimized detection rules.

---

## Architecture & Design Philosophy

RevAI operates on a **"Deterministic Skeleton, Cognitive LLM Union"** philosophy. 

Fully autonomous AI agents that dynamically plan and select tools are often slow, expensive, and prone to loops or hallucinations. Instead, RevAI coordinates tool executions via a reliable, stage-based script pipeline. The LLM is injected as a targeted intelligence layer to parse structured SQL database queries, classify capabilities, and translate technical indicators into high-level reports.

### Data Flow Overview

```
Flask UI → revai service → stage scripts in /opt/scripts/
                              │
                              ├─ intake_v2.py
                              ├─ quick_scan_v2.py       (triage + LLM verdict; RAG off by default)
                              ├─ deep_dive_agentic.py   (V6.3 single-mode agentic deep)
                              ├─ dynamic_run_v2.py      (optional Flare Frida; V6.2)
                              ├─ yara_gen_v2.py
                              ├─ publish_report_v2.py
                              ├─ section_publisher.py
                              └─ audit_pipeline.py
Full spine CLI: pipeline_single_v63.py [--dynamic]
```

The execution core uses Ghidra's headless parser (or commercial IDA Pro instances) to ingest binaries, extract imports/strings/functions, and store them in local SQLite databases. Static analysis tools (capa, FLOSS, YARA-X, Malcat) and sandbox emulation (Speakeasy) populate the database tables. Finally, modular Python executors extract tabular subsets of this data and prompt the LLM to write structured findings.

The custom database mappings are managed by:
* [ghidra_sql_client.py](revai/ghidra_sql_client.py): Interfaces with Ghidra's program database.
* [ida_sql_client.py](revai/ida_sql_client.py): Interfaces with IDA Pro database schemas.

![CADRE-RevAI Architecture](docs/img/architecture_v11.png)

---

## Pipeline Stages

The analysis lifecycle executes through the following stages:

1. **Intake** ([intake_v2.py](revai/intake_v2.py)): Registers the sample, spins up headless Ghidra (or IDA Pro), populates the project database, and prepares workspace folders.
2. **Quick Scan** ([quick_scan_v2.py](revai/quick_scan_v2.py)): Runs static triage scanners and provides the database metrics to the LLM for a high-level verdict.
3. **Deep Dive** ([deep_dive_agentic.py](revai/deep_dive_agentic.py)): V6.3 single mode — LangGraph/agentic SQL-first deep RE for all sample sizes.
4. **Dynamic (optional)** ([dynamic_run_v2.py](revai/dynamic_run_v2.py)): Remnux orchestrates Frida on Flare-VM (lab NIC only; no open internet).
5. **YARA / Sigma Generation** ([yara_gen_v2.py](revai/yara_gen_v2.py)): Translates recovered indicators into signature rules.
6. **Publish Report** ([publish_report_v2.py](revai/publish_report_v2.py) & [section_publisher.py](revai/section_publisher.py)): Collates evidence into master reports.

---

## Feature Matrix

### Core Capabilities

| Capability | What it does |
| :--- | :--- |
| **Static Triage** | Validates headers, parses sections, and matches indicators using capa, YARA, YARA-X, FLOSS, and Malcat. Employs a one-shot LLM pass to yield high-level verdicts. |
| **Deep Analysis** | Queries Ghidra and IDA Pro database tables (functions, instructions, calls) via SQL. Incorporates Speakeasy emulation logs for dynamic behavior reporting. |
| **Signature Engineering** | Programmatically auto-generates optimized YARA and Sigma rules from extracted strings and network/host Indicators of Compromise (IOCs). |
| **Report Generation** | Correlates findings across stages to compile cohesive markdown documentation (`REPORT-MASTER`). |
| **HITL Checkpoints** | Human-in-the-Loop gates pause execution at critical stage boundaries to allow analysts to review low-confidence LLM verdicts or rename symbols manually. |
| **RAG Retrieval** | Integrates local intelligence by running a BM25 + dense hybrid search against a custom vector index of historical malware profiles. |

### Research & Experimental (Opt-in)

* **Z3 Symbolic Deobfuscation** (`ENABLE_DEOBFUSCATION_PASS=1`): Employs Z3 SMT solver and angr hooks to detect and resolve Mixed Boolean-Arithmetic (MBA) expressions, opaque predicates, and flattened control flow.
* **Call-Graph-Ordered Function Recovery** (`ENABLE_AGENTIC_RECOVERY=1`): An experimental, bottom-up function recovery engine ([agentic_recover_v4.py](revai/v4/agentic_recover_v4.py)) that parses function structures recursively from leaves to root, using resolved callee names to build context prompts for the LLM.

---

## Requirements

* **OS**: REMnux 202602 (Ubuntu 24.04 LTS-based) or equivalent isolated Linux environment.
* **Resources**: 8 GB RAM minimum (16 GB recommended); 100 GB storage.
* **API Endpoints**: Any OpenAI-compatible chat completion API endpoint (configured via `llm.env`).
* **Optional**: Licensed IDA Pro 9.x for Linux located at `/opt/ida` (the pipeline defaults to Ghidra if IDA is absent).
* **Optional**: Local FastAPI embedding and reranking services if using the RAG search module.

---

## Quickstart

### 1. Clone & Install
Clone the repository and install system dependencies, Ghidra wrappers, and daemon files:
```bash
git clone https://github.com/CADRE-Platform/CADRE-RevAI.git
cd CADRE-RevAI
sudo ./install/setup-remnux.sh
```

### 2. Configure Environment
Set up credentials and configure LLM endpoints and RAG indices:
```bash
sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
sudo cp config/rag.env.template /opt/cadre-v3-tools/rag.env

sudo nano /opt/cadre-v3-tools/llm.env
sudo nano /opt/cadre-v3-tools/rag.env
```

### 3. Start Daemon
Deploy and run the systemctl background daemon and start the Flask web UI:
```bash
./scripts/deploy.sh --restart
```
Access the browser workspace locally at `http://localhost:5000`.

### 4. Run Verification Suite
Perform an automated end-to-end integration and smoke test run:
```bash
python3 /opt/scripts/v2_validate.py --smoke-only
```
Expected output on success: `V2_SMOKE_OK`.

For detailed operations and debugging guides, see [OPERATE.md](docs/OPERATE.md).

---

## Security Guidelines

* **Sandbox Containment**: Keep your virtual network adapter isolated. Run decompiler pipelines and emulation strictly inside a host-only segmented VM.
* **Credential Safety**: Never commit `.env` configuration files or raw malware samples to version control.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

> Copyright (c) 2026 RevAI contributors.