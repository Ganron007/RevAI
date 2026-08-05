# RevAI

<p align="center">
  <img src="assets/revai-logo.svg" alt="RevAI Logo" width="620">
</p>

<p align="center">
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Status-LLM--based-blue.svg" alt="Status"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Platform-REMnux%20VM-green.svg" alt="Platform"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/UI-React%20Console-green.svg" alt="UI"></a>
  <a href="https://doi.org/10.5281/zenodo.21613150"><img src="https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21613150-blue.svg" alt="DOI"></a>
</p>

Part of the [CADRE](https://github.com/Ganron007/CADRE) platform — LLM-assisted malware reverse engineering and signature generation.

> [!WARNING]
> **Malware Sandbox Containment.** RevAI is an LLM-assisted malware reverse-engineering pipeline. Run it only inside an isolated analysis VM (REMnux recommended). The authors accept no liability for payload escapes or network contamination from improper containment.

---

## What is RevAI?

**RevAI** is an LLM-based malware reverse-engineering pipeline for REMnux:

- **LLM-based analysis** — RE tools produce a stage-tagged evidence pack; an OpenAI-compatible LLM writes the verdict and report.
- **Agentic deep dive** — a LangGraph ReAct planner drives SQL-first RE tools (Ghidra/IDA via ghidrasql/idasql, capa, Malcat, FLOSS, YARA, radare2, …) to collect structured evidence.
- **SQL-first RE** — Ghidra (required) and optional IDA Pro populate SQLite via **ghidrasql**/**idasql**; agents query structured evidence instead of scraping disassembly text.
- **Honest quality gate** — `report_quality.py` computes `truly_green = all_green (audit) + quality_green (no deterministic fallbacks / narrative stubs) + zero failed tools`. Every report carries a `source` (`llm_judge` vs `deterministic_fallback`), so a stubbed report can never look green.

> **Reality check.** RevAI is an analyst assistant, not a finished autonomous product. A green stage means the tooling and quality gate passed — it is **not** a guarantee that the analysis is malware-analyst-accurate. Always review the evidence and the report.

---

### Published Research

> [!NOTE]
> **Why LLM-based and not RAG?**
>
> A retrieval-augmented generation configuration was built and empirically evaluated as part of this project. The study found that retrieval contamination degrades malware triage accuracy in RAG-assisted workflows; the published empirical evaluation and evidence-grounded baseline are available here:
>
> **Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline** (2026)
> Zenodo · DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150) · [zenodo.org/records/21613150](https://zenodo.org/records/21613150)

---

**Three ways to run the pipeline:**

| Mode | Script | Stages | Deep Dive |
|------|--------|--------|-----------|
| **Scripted** | `pipeline_single.py` | Fixed order (intake -> quick_scan -> deep_dive -> yara_gen -> publish -> audit) | LangGraph agentic (always) |
| **Agentic** | `stage_orchestrator.py` | LLM decides which stage to call; retries on failure; HITL before publish if verdicts disagree | LangGraph agentic |
| **Web Console** | `http://<host>:5000` | User clicks individual stage buttons, or **Run orch** for full agentic | LangGraph agentic |

All three modes use the same tool stack and LLM backend — only the stage ordering differs:

- **Static analysis** — Ghidra, radare2, capa, YARA, FLOSS
- **Dynamic / emulation** — Speakeasy, scdbg
- **Deobfuscation / symbolic** — z3, angr
- **Format-specific** — LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc

The deep dive always runs through the LangGraph ReAct agent.

> [!NOTE]
> **Malware RE Reports**
>
> Full analysis reports, audits, and verdicts from live malware runs live in [`docs/case-studies/`](docs/case-studies/).

<p align="center">
  <img src="docs/img/ui-screenshot_v2.png" alt="RevAI Console — landing / lab overview" width="100%">
</p>

---

## Architecture

RevAI runs as a local service on REMnux. The Flask app (`app.py`) serves the React Console and drives the stage scripts under `/opt/scripts/`. Ghidra (required) and optional IDA Pro / Malcat feed structured SQL evidence into the agentic deep dive, and the LLM authors the verdict and report from the evidence pack. The quality gate (`report_quality.py`) decides `truly_green`.

<p align="center">
  <img src="docs/img/architecture_v2.svg" alt="RevAI architecture — agentic pipeline with evidence-pack grounding and truly_green gate" width="100%">
</p>

---

## Pipeline

The spine runs seven stages. Orchestration is either the **LangGraph ReAct orchestrator** (`stage_orchestrator.py`, which plans/executes the whole spine — this is what the Console's **Run orch** button drives) or the **deterministic single-mode spine** (`pipeline_single.py`).

```
React Console / CLI
   │
   │  stage_orchestrator.py  (LangGraph ReAct: plan → act → observe)
   │     OR pipeline_single.py (deterministic spine)
   │
   ├─ 1. intake_v2.py            session + Ghidra (optional IDA) → SQLite
   ├─ 2. quick_scan_v2.py        triage tools → evidence-pack → LLM verdict
   ├─ 3. deep_dive_agentic.py    AGENTIC LangGraph ReAct deep dive
   │        (planner agent drives Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA, r2)
   ├─ 4. yara_gen_v2.py          YARA + Sigma generation
   ├─ 5. publish_report_v2.py    REPORT-MASTER (LLM-authored, source-tagged)
   ├─ 6. section_publisher.py    correlate — section Map-Reduce report
   └─ 7. audit_pipeline.py       all_green per-stage audit
            │
            └─ report_quality.py → truly_green quality gate
```

**Verdict generation:** tools → `package_stage_evidence` → LLM. The LLM writes the verdict and report from the stage-tagged evidence pack.

---

## Feature Matrix

| Capability | What it does |
| :--- | :--- |
| **Agentic deep dive** | LangGraph ReAct planner drives Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA, r2 — see [`docs/OPERATE.md`](docs/OPERATE.md) · [`docs/agent-loop-discipline.md`](docs/agent-loop-discipline.md) |
| **Agent-loop discipline** | Budget warnings · redundant-call detection · hallucination check · failure taxonomy — see [`docs/agent-loop-discipline.md`](docs/agent-loop-discipline.md) |
| **Custom CADRE PE Loader** | Own Ghidra loader — import fixup for packed/binder/dropper PEs — see [`docs/cadre-pe-loader.md`](docs/cadre-pe-loader.md) |
| **Tool Stack (24 tools)** | Static triage, format-specific analysis, deobfuscation, emulation — see [`docs/tool-stack.md`](docs/tool-stack.md) · [`docs/OPERATE.md`](docs/OPERATE.md) |
| **Malcat native capa engine** | Measured 10× faster + more reliable than Mandiant capa on hard samples — see [`docs/malcat-capa-engine.md`](docs/malcat-capa-engine.md) |
| Static triage (capa, YARA, FLOSS, Malcat, …) | First-pass evidence collection |
| YARA / Sigma generation | Signature + Sigma rule authoring |
| Master report publish (LLM-authored, source-tagged) | Executive + technical reports |
| Section correlate / Map-Reduce report | Section-wise report assembly |
| Pipeline audit + `truly_green` quality gate | Honest, evidence-grounded green |
| HITL annotate / review gates | Human-approval boundary |
| Orchestrator (LangGraph ReAct) **or** deterministic spine | Two execution modes |

---

## Requirements

* **OS**: REMnux (Ubuntu 24.04-based) or equivalent isolated Linux analysis VM  
* **Resources**: 8 GB RAM minimum (16 GB recommended); ≥100 GB disk  
* **LLM**: Any OpenAI-compatible chat API (`config/llm.env.template` → `/opt/revai/config/llm.env`)  
* **Ghidra + ghidrasql + Malcat**: see [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md)  
* **Optional**: IDA Pro 9.x at `/opt/ida` (otherwise Ghidra-only)  
* **Node.js ≥ 18**: to build the React Console UI (`scripts/deploy.sh` builds it via npm)  

---

## Quickstart

### 1. Clone & install

```bash
git clone https://github.com/Ganron007/RevAI.git
cd RevAI
sudo chmod +x install/*.sh scripts/deploy.sh
sudo ./install/setup-remnux.sh
```

Setup installs Python deps, normalizes Ghidra to `/opt/ghidra`, and builds **ghidrasql**.  
**Malcat** is commercial — install manually to `/opt/malcat` (see prerequisites).

### 2. Configure LLM (required)

```bash
sudo cp config/llm.env.template /opt/revai/config/llm.env
sudo nano /opt/revai/config/llm.env
```

### 3. Deploy pipeline + React Console

```bash
./scripts/deploy.sh --restart
```

`deploy.sh` copies the pipeline to `/opt/scripts/`, **builds the React Console UI via npm and deploys it to `/opt/scripts/ui`**, installs the systemd service, and restarts `revai`.

Open `http://localhost:5000` (or the REMnux lab IP).

### 4. Verify & smoke

```bash
./install/verify-remnux.sh
python3 /opt/scripts/v2_validate.py --smoke-only
```

Expected: verify `Result: PASS` and `V2_SMOKE_OK` (preflight — no malware sample required).

Full ops: [`docs/OPERATE.md`](docs/OPERATE.md) · Install: [`docs/INSTALL.md`](docs/INSTALL.md) · Prerequisites: [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md).

---

## Security Guidelines

* Keep the VM network isolated (host-only / lab NIC).  
* Never commit `.env` files, API keys, or malware samples.  
* The React Console / Flask app is intended for trusted LAN use — do not expose it to the public internet without additional hardening.  

---

## License

MIT — see [LICENSE](LICENSE).

> Copyright (c) 2026 CADRE RE Team.
