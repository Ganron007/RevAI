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
> **Malware Analysis Sandbox Containment.** CADRE-RevAI is an advanced autonomous malware reverse-engineering pipeline. Because it operates on live malicious binaries, it **must** be executed strictly within an isolated, host-segmented malware analysis environment (such as a dedicated REMnux VM). The authors and contributors accept no liability for any dynamic execution leaks, payload escapes, or network contamination arising from improper containment configurations.

---

## What is CADRE-RevAI?

**CADRE-RevAI** is an enterprise-grade autonomous malware reverse-engineering and signature engineering platform. Deployed as a self-contained analysis workspace on a REMnux virtual machine, RevAI automates the entire decompilation, deobfuscation, and rule auto-generation lifecycle for Windows PE and Linux ELF binaries. 

Developed as a core utility within the CADRE (Cloud, Agentic, DFIR, and RedTeam Environment) initiative, RevAI integrates advanced static binary parsing, secure sandbox emulation, Z3-driven symbolic deobfuscation, and Large Language Model (LLM) reasoning to programmatically extract indicator databases and construct optimized threat signatures.

---

## Core Capabilities

| Capability | Feature Set |
| :--- | :--- |
| **Intelligent Triage** | Autonomous file-type validation, static structural parsing, YARA-X matching, Capa capability mapping, Malcat heuristic extraction, and LLM-synthesized threat classification. |
| **Deep Dive Decompilation** | Multi-engine decompilation via Ghidra and commercial IDA Pro databases. Emulated dynamic run analysis through Speakeasy captures runtime API, memory, and structural anomalies. |
| **Rule Auto-Generation** | Automated signature engineering translating decompiled constructs and indicators into optimized YARA-X rules, utilizing goodware corpuses to eliminate false positives. |
| **Symbolic Deobfuscation** | Algebraic deobfuscation and Mixed Boolean-Arithmetic (MBA) simplification using Z3 SMT solvers, opaque predicate resolution, and control-flow deflattening. |
| **RAG Retrieval** | Vectorized similarity matching combining BM25 and dense embedding models to index local malware corpuses, powered by a unified FastAPI retrieval service. |
| **HITL Checkpoints** | Human-in-the-Loop (HITL) checkpoints managing high-risk operational steps, including low-confidence classification verification, function signature renaming, and report publishing. |
| **Function Recovery** | AI-assisted recovery of symbol tables and function bodies, mapping control-flow graph (CFG) structures against signature databases for automated identifier renaming. |

---

## Architecture & Data Flow

RevAI is designed as a modular pipeline deployed as a local system daemon. The interface utilizes a Flask workspace dashboard, while the execution core calls Ghidra headless scripts, emulation wrappers, and symbolic engines. Optional commercial static analyzers (Malcat, IDA Pro) and LLM endpoints plug into the pipeline via secure loopback environments.

![CADRE-RevAI Architecture](docs/img/architecture_v11.png)

---

## Directory Layout

* 📁 **`revai/`**: Core reverse engineering package containing intake, triage, decompilation, and Flask template files.
* 📁 **`install/`**: Setup scripts (`setup-remnux.sh`, `verify-remnux.sh`) and daemon templates (`revai.service`).
* 📁 **`config/`**: Configuration templates for local LLMs and embeddings/RAG parameters.
* 📁 **`docs/`**: Operational, deployment, and configuration guides.
* 📁 **`tests/`**: Integration and regression validation tests.

---

## User Interface

The Flask UI exposes a clean, single-pane browser-based workspace to upload binaries, monitor execution stages in real-time, inspect decompiled sources, and review generated signatures.

<p align="center">
  <img src="docs/img/ui-showcase.png" alt="CADRE-RevAI Pipeline UI Showcase" width="100%">
</p>

---

## Quickstart

### 1. VM Installation
Deploys dependencies, installs auxiliary decompilation scripts, and registers system-level packages on a clean REMnux environment:

```bash
sudo ./install/setup-remnux.sh
```

### 2. Environment Configuration
Initializes local configurations and securely maps model API credentials:

```bash
sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
sudo cp config/rag.env.template /opt/cadre-v3-tools/rag.env

sudo nano /opt/cadre-v3-tools/llm.env
sudo nano /opt/cadre-v3-tools/rag.env
```

### 3. Build & Deploy
Assembles application runtimes and launches the systemctl service daemon:

```bash
./scripts/deploy.sh --restart
```

Access the browser interface locally at `http://localhost:5000`.

### 4. Verification Check
Executes the integration and regression suite to programmatically verify the end-to-end binary analysis pipeline:

```bash
python3 /opt/scripts/v2_validate.py --smoke-only
```
Expected output: `V2_SMOKE_OK`.

---

## Security Guidelines

Keep your analysis environment secure:
* **Isolated Sandbox:** Decompile, emulate, and analyze hostile artifacts strictly in an air-gapped or host-segmented virtual environment.
* **Secret Management:** Verify that API keys and local samples are excluded via `.gitignore` rules before pushing repository commits.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

> Copyright (c) 2026 RevAI contributors.