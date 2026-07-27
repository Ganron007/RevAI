# CADRE-RevAI

<p align="center">
  <img src="assets/revai-logo.svg" alt="RevAI Logo" width="620">
</p>

<p align="center">
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Status-LLM--only-blue.svg" alt="Status"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Platform-REMnux%20VM-green.svg" alt="Platform"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/UI-React%20Console-green.svg" alt="UI"></a>
</p>

> [!WARNING]
> **Malware Sandbox Containment.** CADRE-RevAI is an LLM-assisted malware reverse-engineering pipeline. Run it only inside an isolated analysis VM (REMnux recommended). The authors accept no liability for payload escapes or network contamination from improper containment.

---

## What is CADRE-RevAI?

**CADRE-RevAI** is an LLM-assisted malware reverse-engineering pipeline for REMnux:

- **LLM-only** — RE tools produce a stage-tagged evidence pack; an OpenAI-compatible LLM writes the verdict and report. There is no local KB / retrieval layer.
- **Agentic deep dive** — a LangGraph ReAct planner (`deep_dive_agentic.py` + `agentic_langgraph.py`) drives SQL-first RE tools (Ghidra/IDA via ghidrasql/idasql, capa, Malcat, FLOSS, YARA, radare2, …) to collect structured evidence.
- **SQL-first RE** — Ghidra (required) and optional IDA Pro populate SQLite via **ghidrasql**/**idasql**; agents query structured evidence instead of scraping disassembly text.
- **Honest quality gate** — `report_quality.py` computes `truly_green = all_green (audit) + quality_green (no deterministic fallbacks / narrative stubs) + zero failed tools`. Every report carries a `source` (`llm_judge` vs `deterministic_fallback`), so a stubbed report can never look green.

<p align="center">
  <img src="docs/img/ui-screenshot_v2.png" alt="CADRE-RevAI Console — landing / lab overview" width="100%">
</p>

> **Reality check.** CADRE-RevAI is an analyst assistant, not a finished autonomous product. A green stage means the tooling and quality gate passed — it is **not** a guarantee that the analysis is malware-analyst-accurate. Always review the evidence and the report.

---

## Why LLM-only? (On RAG)

> [!IMPORTANT]
> **The default pipeline excludes retrieval on the basis of an empirical evaluation conducted within this project.** A retrieval-augmented configuration was implemented following established practice and assessed inside the full end-to-end triage loop on real malware binaries. The evaluation showed no net benefit from retrieval and identified specific, reproducible failure modes in which retrieved or rule-derived text degraded verdict quality; retrieval was therefore removed from the default path. The complete empirical account is the article below:
> **["Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline"](docs/rag/ARTICLE-PUBLICATION.md)**
>
> **Citation.** *Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline* (2026). Published on Zenodo; DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150) · [zenodo.org/records/21613150](https://zenodo.org/records/21613150). The in-repo article is the readable source of truth; the Zenodo record is the published, citable version.

CADRE-RevAI ships **without a retrieval layer by design** — a decision that is evidence-based rather than a default omission. A retrieval-augmented configuration was implemented following established practice and then **evaluated inside a full end-to-end triage loop** across 16 malware samples and four vector configurations. The findings:

- **Tool evidence outweighs retrieval.** High-fidelity static packaging (Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA) drove triage quality more than retrieved text — the retrieval-free path matched or exceeded tools-plus-RAG on hard, out-of-knowledge-base samples.
- **Corpus scale did not translate to accuracy.** A 13.7× corpus expansion did not uniformly improve family or theme labels; generic threat intelligence diluted the high-signal hits.
- **Retrieved context can mislead.** Retrieved passages and YARA rule titles contaminated verdicts — a retrieved aside produced a false "PlugX"; a rule identifier produced a false "APT29 / Cozy Bear." Injected context made some verdicts *worse*.

Accordingly, the model reasons over **the evidence the binary itself exhibits**, behind the `truly_green` honesty gate with per-report source tagging. This is not a rejection of retrieval: it is reintroduced only once a curated, **RE-primary gold knowledge base** (derived from verified analyses) *measurably* outperforms the retrieval-free baseline — evidence-gated, not assumed.

The product position, the narrative article, and the empirical benchmark with its full data are documented in [`docs/rag/`](docs/rag/README.md).

---

## Architecture

RevAI runs as a local service on REMnux. The Flask app (`app.py`) serves the React Console and drives the stage scripts under `/opt/scripts/`. Ghidra (required) and optional IDA Pro / Malcat feed structured SQL evidence into the agentic deep dive, and the LLM authors the verdict and report from the evidence pack. The quality gate (`report_quality.py`) decides `truly_green`.

<p align="center">
  <img src="docs/img/architecture_v2.svg" alt="CADRE-RevAI architecture — agentic pipeline with evidence-pack grounding and truly_green gate" width="100%">
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

**LLM-only means:** tools → `package_stage_evidence` → LLM. The LLM writes the verdict/report from the evidence pack; nothing is retrieved from a local knowledge base.

---

## Feature Matrix

| Capability | Default |
| :--- | :--- |
| Static triage (capa, YARA, FLOSS, Malcat, …) | On |
| Agentic deep dive (`deep_dive_agentic`, LangGraph ReAct) | On |
| YARA / Sigma generation | On |
| Master report publish (LLM-authored, source-tagged) | On |
| Section correlate / Map-Reduce report | On |
| Pipeline audit + `truly_green` quality gate | On |
| HITL annotate / review gates | Available |
| Orchestrator (LangGraph ReAct) **or** deterministic spine | Both available |

---

## Showcase

**The Console in use** — (1) the cases queue with verdicts and keyboard nav, (2) the orchestrator cockpit (stage timeline, agent trace, live console, quality-gate bar), (3) the report reader with catalog and section outline, (4) the in-app help & pipeline guide:

<p align="center">
  <img src="docs/img/ui-showcase-v2.png" alt="CADRE-RevAI Console — cases, orchestrator, report reader, help" width="100%">
</p>

The emerald/dark "Obsidian Ops" Console provides a case queue, an orchestrator command center (stage timeline + agent trace + live log + quality-gate bar), a report reader with TOC, an evidence browser, HITL review, and help.

---

## Requirements

* **OS**: REMnux (Ubuntu 24.04-based) or equivalent isolated Linux analysis VM  
* **Resources**: 8 GB RAM minimum (16 GB recommended); ≥100 GB disk  
* **LLM**: Any OpenAI-compatible chat API (`config/llm.env.template` → `/opt/cadre-v3-tools/llm.env`)  
* **Ghidra + ghidrasql + Malcat**: see [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md)  
* **Optional**: IDA Pro 9.x at `/opt/ida` (otherwise Ghidra-only)  
* **Node.js ≥ 18**: to build the React Console UI (`scripts/deploy.sh` builds it via npm)  

---

## Quickstart

### 1. Clone & install

```bash
git clone https://github.com/Ganron007/RevAI.git
cd CADRE-RevAI
sudo chmod +x install/*.sh scripts/deploy.sh
sudo ./install/setup-remnux.sh
```

Setup installs Python deps, normalizes Ghidra to `/opt/ghidra`, and builds **ghidrasql**.  
**Malcat** is commercial — install manually to `/opt/malcat` (see prerequisites).

### 2. Configure LLM (required)

```bash
sudo cp config/llm.env.template /opt/cadre-v3-tools/llm.env
sudo nano /opt/cadre-v3-tools/llm.env
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

> Copyright (c) 2026 the author.
