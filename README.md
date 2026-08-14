# RevAI

<p align="center">
  <img src="assets/revai-logo.svg" alt="RevAI Logo" width="620">
</p>

<p align="center">
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Status-LLM--assisted-blue.svg" alt="Status"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/Platform-REMnux%20VM-green.svg" alt="Platform"></a>
  <a href="https://github.com/Ganron007/RevAI"><img src="https://img.shields.io/badge/UI-React%20Console-green.svg" alt="UI"></a>
  <a href="https://doi.org/10.5281/zenodo.21613150"><img src="https://img.shields.io/badge/DOI-10.5281%2Fzenodo.21613150-blue.svg" alt="DOI"></a>
</p>

Part of the [CADRE](https://github.com/Ganron007/CADRE) platform — LLM-assisted malware reverse engineering and signature generation.

> [!WARNING]
> **Malware Sandbox Containment.** RevAI is an LLM-assisted malware reverse-engineering pipeline. Run it only inside an isolated analysis VM (REMnux recommended). The authors accept no liability for payload escapes or network contamination from improper containment.

---

## What is RevAI?

**RevAI** is an LLM-assisted malware reverse-engineering pipeline for REMnux. It is **deterministic-first**: format-aware RE tools run deterministically and produce the evidence; the LLM interprets that evidence into verdicts and reports — never the other way around:

- **Deterministic-first analysis** — RE tools produce a stage-tagged evidence pack; an OpenAI-compatible LLM interprets the evidence into the verdict and report. Everything the LLM can claim must trace back to real tool output.
- **Agentic deep dive** — a LangGraph ReAct agent searches SQL-first RE tools (Ghidra/IDA via ghidrasql/idasql, capa, Malcat, FLOSS, YARA, radare2, …) on top of a deterministic checklist and signal extractors (emulation oracle, anti-analysis, dynamic-resolve, unpack pass) that run first.
- **SQL-first RE** — Ghidra (required) and optional IDA Pro populate SQLite via **ghidrasql**/**idasql**; the agent queries structured evidence instead of scraping disassembly text.
- **Honest quality gate** — `report_quality.py` computes `truly_green = all_green (audit) + quality_green (no deterministic fallbacks / narrative stubs) + zero failed tools`. Every report carries a `source` (`llm_judge` vs `deterministic_fallback`), so a stubbed report can never look green.

> **Reality check.** RevAI is an analyst assistant, not a finished autonomous product. A green stage means the tooling and quality gate passed — it is **not** a guarantee that the analysis is malware-analyst-accurate. Always review the evidence and the report.

---

### Published Research

> [!NOTE]
> **Why LLM interpretation and not RAG?**
>
> A retrieval-augmented generation configuration was built and empirically evaluated as part of the parent research project (RevEng) from which RevAI is derived. The study found that retrieval contamination degrades malware triage accuracy in RAG-assisted workflows; the published empirical evaluation and evidence-grounded baseline are available here:
>
> **Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline** (2026)
> Zenodo · DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150) · [zenodo.org/records/21613150](https://zenodo.org/records/21613150)

<p align="center">
  <img src="docs/img/ui-screenshot_v2.png" alt="RevAI Console — landing / lab overview" width="100%">
</p>

---

## Three ways to run the pipeline

All modes run the same 7 stages (+1 optional function-recovery stage), the same tool stack, and the same LLM backend — the difference is *who decides the sequence* and *how failures are handled*:

| Mode | Script / Entry | Stage Sequencing | Failure Handling | Best For |
| :--- | :--- | :--- | :--- | :--- |
| **Scripted** *(default)* | `pipeline_single.py` | • Deterministic fixed order (`intake` → `quick_scan` → `deep_dive` → `yara_gen` → `publish` → `section` → `audit`)<br>• No LLM orchestration | **Zero retries**<br>Failed stage aborts remaining pipeline (predictable, deterministic runtime). | Fast, reproducible runs with known-good samples. |
| **Agentic** | `stage_orchestrator.py` | • LangGraph ReAct planner (LLM) in policy-pinned order<br>• Observes verdicts/evidence between stages<br>• HITL stop before publish if quick/deep verdicts disagree | **1 bounded retry** *(default)*<br>Handles transient failures (timeouts, connection loss, OOM). Calibrated via `REVAI_*` env / console panel (retries, budget, recursion limit, timeout scale). | Large/obfuscated samples where transient tool errors shouldn't waste runs. |
| **Web Console** | `http://<host>:5000` | • Manual stage buttons (human-paced)<br>• **Run orch** button (full agentic path) | **UI-configured**<br>Run config panel sets retries, budget profile (*standard* / *generous* / *unlimited*), and timeout scale before execution. | Day-to-day interactive analysis, live monitoring, and per-sample budget tuning. |

All three modes share the same tool stack, the same LLM backend, and the same stage spine — sequencing and failure handling are the only differences (table above). The full tool list:

- **Static analysis** — Ghidra (SQL-first, required), IDA Pro (SQL, optional), Malcat (optional), radare2, capa, YARA, FLOSS, revai-tools (mitigations-with-consequence, sink-site + provenance audit, wallet/IOC extraction)
- **Dynamic / emulation** — Speakeasy, scdbg
- **Deobfuscation / symbolic** — z3, angr
- **Format-specific** — LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc

The deep dive always runs through the LangGraph ReAct agent.

> **LLM-assisted analysis is inherently probabilistic.** Results can vary between runs, and green means every deterministic gate passed — not that the verdict is objectively correct. Models can misread evidence, and tool limits (packing, obfuscation, emulation) leave gaps the gates cannot fully close. Treat reports as a starting point for analyst review, never as ground truth.

> [!NOTE]
> **Malware RE Reports**
>
> Full analysis reports, audits, and verdicts from live malware runs live in [`docs/case-studies/`](docs/case-studies/). Every scan ships its raw tool output for reference in the sample's `evidence/` folder — refer to it when in doubt.

---

## Architecture

RevAI runs as a local service on REMnux. The Flask app (`app.py`) serves the React Console and drives the stage scripts under `/opt/scripts/`. Ghidra (required) and optional IDA Pro / Malcat feed structured SQL evidence into the agentic deep dive, and the LLM authors the verdict and report from the evidence pack. The quality gate (`report_quality.py`) decides `truly_green`.

> **Detailed Architecture Guide:** For a full breakdown of component layering, the 7-stage spine, Evidence Pack grounding (no RAG), and Human-in-the-Loop approval gate, see [`docs/architecture.md`](docs/architecture.md).

<p align="center">
  <img src="docs/img/architecture_v2.svg" alt="RevAI architecture — agentic pipeline with evidence-pack grounding and truly_green gate" width="100%">
</p>

---

## Pipeline

The spine runs seven stages (plus one optional stage). Orchestration is either the **LangGraph ReAct orchestrator** (`stage_orchestrator.py`, which plans/executes the whole spine — this is what the Console's **Run orch** button drives) or the **deterministic single-mode spine** (`pipeline_single.py`).

```
React Console / CLI
   │
   │  stage_orchestrator.py  (LangGraph ReAct: plan → act → observe)
   │     OR pipeline_single.py (deterministic spine)
   │
   ├─ 1. intake_v2.py            session + Ghidra (optional IDA) → SQLite
   ├─ 2. quick_scan_v2.py        triage tools → evidence-pack → LLM verdict
   ├─ 3. deep_dive_agentic.py    AGENTIC LangGraph ReAct deep dive
   │        (planner agent drives Ghidra/IDA SQL, capa, Malcat, FLOSS, YARA, r2,
   │         revai-tools sec/sinks/audit)
   ├─ 3.5 function_recovery*  OPT-IN agentic function-name recovery
   │        (call-graph tiers → LLM naming → ghidrasql writeback, conf ≥ 0.7)
   ├─ 4. yara_gen_v2.py          YARA + Sigma generation
   ├─ 5. publish_report_v2.py    REPORT-MASTER (LLM-authored, source-tagged)
   ├─ 6. section_publisher.py    correlate — section Map-Reduce report
   └─ 7. audit_pipeline.py       all_green per-stage audit
            │
            └─ report_quality.py → truly_green quality gate
```

*`function_recovery` is optional — enabled via `REVAI_ENABLE_AGENTIC_RECOVERY=1` (legacy `ENABLE_AGENTIC_RECOVERY` honored); recovered names feed the published reports.

**Verdict generation:** tools → `package_stage_evidence` → LLM. The LLM writes the verdict and report from the stage-tagged evidence pack.

---

## Feature Matrix

Distinctive capabilities — the things that set RevAI apart. For the full feature inventory — every feature with its env gate, stage, and produced artifact — see [`docs/FEATURES.md`](docs/FEATURES.md).

| Capability | What makes it distinctive |
| :--- | :--- |
| **Custom CADRE PE Loader** | Own Ghidra loader — recovers import tables on packed/binder/dropper PEs where stock Ghidra returns empty — see [`docs/cadre-pe-loader.md`](docs/cadre-pe-loader.md) |
| **Agent-loop discipline** | Budget warnings · redundant-call detection · hallucination check · failure taxonomy — the agent converges and stays evidence-grounded — see [`docs/agent-loop-discipline.md`](docs/agent-loop-discipline.md) |
| **Malcat native capa engine** | Measured 10× faster + more reliable than Mandiant capa on hard/installer-packed samples — see [`docs/malcat-capa-engine.md`](docs/malcat-capa-engine.md) |
| **In-process yara-x engine** | YARA scanning with no external `yr` binary — a broken scanner can never silently pass the gate — see [`docs/OPERATE.md`](docs/OPERATE.md) |
| **Honest `truly_green` gate** | Green requires audit (`all_green`) **and** report quality (`quality_green`) **and** zero failed tools — plus engine-citation verification and a cross-stage verdict lock. A stubbed or mis-attributed report can never look green |
| **Depth gate (capability coverage)** | Deterministic gate: before green, the deep-dive summary must address **every** capability domain (persistence, C2, evasion, exfiltration, defense impairment, credential access, encryption, entry point, imports, strings) — as evidence or explicit "not observed". A verdict over a thin pass can never go green — see [`docs/architecture.md`](docs/architecture.md#10-quality-verification-gate-truly_green) |
| **Publication-quality gates** | Deterministic cross-report checks: the master must not claim "no dynamic analysis was performed" when the technical report carries Speakeasy/Frida execution evidence; master and technical verdict panels must agree; entropy citations are audited against the file's measured whole-file Shannon entropy. Added after the #2 campaign, where these checks caught factual defects in 15 report pairs the structural gates had passed |
| **Agentic function recovery** | Opt-in stage (`agentic_recover_v4.py`): relevance-based triage (call-hub + string + high-value-import score, hybrid guaranteed slots for API callers/large logic) → call-graph bottom-up tiers → LLM naming (`FUN_…` → `parse_http_header`) → SQL writeback (ghidrasql/idasql, conf ≥ 0.7, never deletes) → names cited in reports |
| **Tool Stack (28 tools)** | 28 format-aware manifest tools + 23 agent-callable tools (incl. revai-tools mitigations-with-consequence, sink-site audit, and wallet/IOC extraction — fail-open, never gates) — see [`docs/tool-stack.md`](docs/tool-stack.md) · [`docs/OPERATE.md`](docs/OPERATE.md) |

---

## Requirements

* **OS**: REMnux (Ubuntu 24.04-based) or equivalent isolated Linux analysis VM  
* **Resources**: 8 GB RAM minimum (16 GB recommended); ≥100 GB disk  
* **LLM**: Any OpenAI-compatible chat API (`config/llm.env.template` → `/opt/revai/config/llm.env`)  
* **Ghidra + ghidrasql** (required) · **Malcat** (optional — pipeline soft-fails without it): see [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md). ghidrasql is by Elias Bachaalany (github.com/0xeb/ghidrasql), used under the Human-Origin Source License v1.0  
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
**Malcat** is commercial (optional — the pipeline soft-fails without it). `setup-remnux.sh` auto-installs it if `internal/malcat.zip` is present; otherwise install manually to `/opt/malcat` (see prerequisites).

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

## What's coming

| Item | What it is | Why |
|------|-----------|-----|
| **Multi-provider matrix** | Run the pipeline across multiple configured LLM providers and benchmark verdict/report consistency | Lets operators compare providers and pick the best fit per workload |
| **Dual-LLM verdict jury** | Verdict interpretation uses a model separate from the report author, plus an independent second-provider vote; disagreement flags a sample for human review | Checker ≠ generator — avoids correlated errors from a single model grading its own work |
| **Deterministic deep-dive engine** (scripted mode) | Optional fixed SQL query plan with rule-based follow-ups — no LLM driving the deep dive; the LLM stays for verdict interpretation and report writing | Reproducible, low-cost deep-dive baseline; the agentic engine remains available in agentic/UI modes |

---

## License

MIT — see [LICENSE](LICENSE).

> Copyright (c) 2026 CADRE RE Team.

---

## Acknowledgements

* **ghidrasql** — SQL interface for Ghidra program databases, by [Elias Bachaalany](https://github.com/0xeb/ghidrasql), used under the Human-Origin Source License v1.0.
* **idasql** — SQL interface for IDA Pro databases, by [Elias Bachaalany](https://github.com/allthingsida/idasql), used under the Human-Origin Source License v1.0.
