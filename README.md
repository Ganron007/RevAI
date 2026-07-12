# CADRE-RevAI

<p align="center">
  <img src="assets/revai-banner.png" alt="CADRE-RevAI Banner" width="100%">
</p>

<p align="center">
  <strong>Autonomous Malware Reverse Engineering, Decompilation, and Rule Generation</strong>
</p>

<p align="center">
  <a href="https://github.com/AppliedIR/remnux-mcp"><img src="https://img.shields.io/badge/Status-v2.0.0-blue.svg" alt="Status"></a>
  <a href="https://github.com/AppliedIR/remnux-mcp"><img src="https://img.shields.io/badge/Platform-REMnux%20VM-green.svg" alt="Platform"></a>
  <a href="https://github.com/AppliedIR/remnux-mcp"><img src="https://img.shields.io/badge/UI-Flask%20Single--Pane-purple.svg" alt="UI"></a>
</p>

---

## What is CADRE-RevAI?

**CADRE-RevAI** is the specialized reverse-engineering pipeline of the CADRE platform. Running as a self-contained analysis suite on a single **REMnux VM**, it automates the triage, decompilation, deobfuscation, and rule generation process for Windows PE and Linux ELF binaries. 

It orchestrates advanced static parsing, emulator-based behavioral analysis, LLM-driven verdict synthesis, and symbolic code recovery into a unified browser-based workspace.

---

## Core Capabilities

| Capability | Feature Set |
| :--- | :--- |
| **Intelligent Triage** | Automated file-type detection, YARA-X scanning, Capa capability mapping, Malcat heuristic extraction, and LLM-assisted verdicts. |
| **Deep Dive Decompilation** | Ghidra SQL-first decompilation paired with optional commercial IDA SQL integration. Speakeasy emulation tracks behavior, API calls, and memory regions. |
| **Rule Auto-Generation** | Automatically extracts indicators and decompiled patterns to generate optimized YARA-X and Sigma rules, featuring goodware false-positive filters. |
| **Symbolic Deobfuscation** | MBA (Mixed Boolean-Arithmetic) simplification via Z3 solvers, opaque predicate cracking, and GhidraScript Control Flow Flattening (CFF) deflattening. |
| **RAG Retrieval** | Hybrid BM25 + dense neural search over local malware intelligence corpuses via a unified FastAPI embedding service. |
| **HITL Checkpoints** | Human-in-the-Loop approval gates triggered for low-confidence verdicts, function renaming validation, and report publishing. |
| **Function Recovery** | Agentic reconstruction of decompiled functions, matching control-flow graphs (CFGs) against signatures, and automated function renaming. |

---

## Architecture & Data Flow

The Flask web UI controls the pipeline, while host-native triage engines and external API clients interact in a secure REMnux environment:

```mermaid
flowchart TD
    %% Custom Styles (Modern Dark Mode)
    classDef default fill:#0d1117,stroke:#30363d,color:#e6edf3
    classDef ui fill:#1c3d1f,stroke:#2ea043,color:#ffffff,stroke-width:2px
    classDef stage fill:#21262d,stroke:#2ea043,color:#e6edf3,stroke-width:2px
    classDef tool fill:#161b22,stroke:#38bdf8,color:#e6edf3,stroke-width:1px
    classDef service fill:#161b22,stroke:#a371f7,color:#e6edf3,stroke-width:2px
    classDef gate fill:#d29922,stroke:#f0883e,color:#000000,stroke-width:2px
    classDef output fill:#238636,stroke:#3fb950,color:#ffffff,stroke-width:2px
    classDef log fill:#21262d,stroke:#8b949e,color:#e6edf3,stroke-width:1px

    %% Analyst / UI Layer
    Analyst(["Analyst Browser"])
    UI["CADRE-RevAI Flask UI<br/>(Port :5000)"]:::ui
    
    Analyst -->|HTTPS / REST| UI

    %% REMnux VM Boundary
    subgraph REMnux ["REMnux Analysis VM (Local Sandbox)"]
        direction TB
        
        subgraph Pipeline ["Orchestrated Analysis Pipeline"]
            direction LR
            S1["1. Intake"]:::stage
            S2["2. Triage<br/>(YARA-X, Capa, Malcat)"]:::stage
            S3["3. Deep Dive"]:::stage
            S4["4. YARA Gen"]:::stage
            S5["5. Publish"]:::stage
            S6["6. Correlate"]:::stage
            
            S1 --> S2 --> S3 --> S4 --> S5 --> S6
        end
        
        subgraph StaticEngines ["Triage Tools"]
            direction LR
            YaraScan["YARA-X Scan"]:::tool
            CapaScan["Capa Analysis"]:::tool
            FlossScan["FLOSS Strings"]:::tool
            MalcatTriage["Malcat Analyzer"]:::tool
        end
        
        subgraph DeepEngines ["Deep Dive & Deobfuscation"]
            GhidraClient["Ghidra SQL Client"]:::tool
            IdaClient["IDA SQL Client"]:::tool
            Speakeasy["Speakeasy Emulator"]:::tool
            Deobfuscator["Z3 / angr Solver"]:::tool
            v4Recovery["v4 Function Recovery"]:::tool
        end
    end

    %% Edge Connections - UI to VM Pipeline
    UI -->|Triggers Pipeline| S1

    %% Tools mappings to stages
    S2 <-->|Run Scans| StaticEngines
    S3 <-->|Extract Behaviors & Code| DeepEngines

    %% External services
    LLM["LLM AI Agent<br/>(OpenAI / Local Ollama)"]:::service
    RAG["RAG Host<br/>(BM25 + bge-m3 dense)"]:::service
    Malcat["Malcat MCP<br/>(optional facade)"]:::service

    %% Service connections to Pipeline
    S2 -->|Query Verdict| LLM
    S3 -->|Renaming & Recovery Context| LLM
    S3 -->|Query Malware Corpus| RAG
    S3 -->|Decompile Façade| Malcat
    S4 -->|Draft Signatures| LLM

    %% Human-in-the-Loop Gate
    HITL{{"Human-in-the-Loop<br/>Approval Gate"}}:::gate
    S2 -.->|Review Low Confidence| HITL
    S3 -.->|Approve Recovery Context| HITL

    %% Outputs & Deliverables
    Rules["YARA & Sigma Rules"]:::output
    Reports["Markdown Reports"]:::output
    AuditLogs["Audit Logs (JSONL)"]:::log

    %% Output connections
    S4 -->|Generate| Rules
    S5 -->|Generate| Reports
    Pipeline --->|Log event| AuditLogs
```

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
Launch a REMnux virtual machine (or Ubuntu 24.04 instance with REMnux tools) and run the setup installer:

```bash
sudo ./install/setup-remnux.sh
```

### 2. Environment Configuration
Copy templates and configure API keys for your LLM and RAG servers:

```bash
sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
sudo cp config/rag.env.template /opt/cadre-v3-tools/rag.env

sudo nano /opt/cadre-v3-tools/llm.env
sudo nano /opt/cadre-v3-tools/rag.env
```

### 3. Build & Deploy
Compile assets and start the service daemon:

```bash
./scripts/deploy.sh --restart
```

Access the browser interface locally at `http://localhost:5000`.

### 4. Verification Check
Run the regression validation suite to verify the intake pipeline:

```bash
python3 /opt/scripts/v2_validate.py --smoke-only
```
Expected output: `V2_SMOKE_OK`.

---

## Security Guidelines

Keep your analysis environment secure:
* **No Secret Commits:** Do not commit API keys, tokens, or live malware binaries to Git. Environment variables (`llm.env`, `rag.env`) and local samples are pre-excluded in `.gitignore`.
* **Isolated Sandbox:** Ensure REMnux VM networking is properly segmented when analyzing hostile samples.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.