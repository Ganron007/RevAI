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

> **Malware Sandbox Containment.** RevAI is an LLM-assisted malware reverse-engineering pipeline. Run it only inside an isolated analysis VM (REMnux recommended). The authors accept no liability for payload escapes or network contamination from improper containment.

---

## What is RevAI?

**RevAI** is an LLM-assisted malware reverse-engineering pipeline for REMnux. It is **deterministic-first**: format-aware RE tools run deterministically and produce the evidence; the LLM interprets that evidence into verdicts and reports — never the other way around:

- **Deterministic-first analysis** — RE tools produce a stage-tagged evidence pack; an OpenAI-compatible LLM interprets the evidence into the verdict and report. Everything the LLM can claim must trace back to real tool output.
- **Agentic deep dive** — a LangGraph ReAct agent searches SQL-first RE tools (Ghidra/IDA via ghidrasql/idasql, capa, Malcat, FLOSS, YARA, radare2, …) on top of a deterministic checklist and signal extractors (emulation oracle, anti-analysis, dynamic-resolve, unpack pass) that run first.
- **SQL-first RE** — Ghidra (required) and optional IDA Pro populate SQLite via **ghidrasql**/**idasql**; the agent queries structured evidence instead of scraping disassembly text.
- **Honest quality gate** — `report_quality.py` computes `truly_green = all_green (audit) + quality_green (no deterministic fallbacks / narrative stubs) + zero failed tools`. Every report carries a `source` (`llm_judge` vs `deterministic_fallback`), so a stubbed report can never look green.

**Optional dynamic companion — [WinRE](https://github.com/Ganron007/WinRE).** RevAI itself is static-first; when live behavior is needed, WinRE (FlareVM-based Windows analysis, static + dynamic, with a remote driver for RevAI) detonates the sample on an isolated Windows VM and returns a versioned artifact pack that RevAI reads for corroboration (`load_dynamic_pack()`). When a pack exists for the sample, reports gain a presence-gated **Dynamic Corroboration (WinRE detonation)** section (window + coverage caveat, runtime indicators, unpack artifact); without one, reports are unchanged. Dynamic evidence corroborates static findings — it never overrides them. Remote-drive setup from the RevAI host: [`docs/WINRE-REMOTE.md`](docs/WINRE-REMOTE.md).

> **Reality check.** RevAI is an analyst assistant, not a finished autonomous product. LLM-assisted analysis is inherently probabilistic: results can vary between runs, and a green stage means the tooling and quality gate passed — **not** that the analysis is malware-analyst-accurate or the verdict objectively correct. Models can misread evidence, and tool limits (packing, obfuscation, emulation) leave gaps the gates cannot fully close. Always review the evidence and the report — treat it as a starting point for analyst review, never as ground truth.

---

### Published Research

> [!NOTE]
> **Why LLM interpretation and not RAG?**
>
> A retrieval-augmented generation configuration was built and empirically evaluated as part of the parent research project (RevEng) from which RevAI is derived. The study found that retrieval contamination degrades malware triage accuracy in RAG-assisted workflows; the published empirical evaluation and evidence-grounded baseline are available here:
>
> **Retrieval Contamination in LLM-Assisted Malware Triage: An Empirical Evaluation and an Evidence-Grounded Baseline** (2026)
> Zenodo · DOI [10.5281/zenodo.21613150](https://doi.org/10.5281/zenodo.21613150) · [zenodo.org/records/21613150](https://zenodo.org/records/21613150)

---

## The Console

RevAI runs as a local service on REMnux. The Flask app (`app.py`) serves the
React Console and drives the stage scripts under `/opt/scripts/`.

<p align="center">
  <img src="docs/img/ui-screenshot_v2.png" alt="RevAI Console — landing / lab overview" width="100%">
</p>

---

## Three ways to run the pipeline

All modes run the same 7 stages (+1 optional function-recovery stage), the same tool stack, and the same LLM backend — the difference is *who decides the sequence* and *how failures are handled*:

| Mode | Script / Entry | Stage Sequencing | Failure Handling |
| :--- | :--- | :--- | :--- |
| **Scripted** *(default)* | `pipeline_single.py` | • Deterministic fixed order (`intake` → `quick_scan` → `deep_dive` → `yara_gen` → `publish` → `section` → `audit`)<br>• No LLM orchestration | **Zero retries**<br>Failed stage aborts remaining pipeline (predictable, deterministic runtime). |
| **Agentic** | `stage_orchestrator.py` | • LangGraph ReAct planner (LLM) in policy-pinned order<br>• Observes verdicts/evidence between stages<br>• HITL stop before publish if quick/deep verdicts disagree | **1 bounded retry** *(default)*<br>Handles transient failures (timeouts, connection loss, OOM). Calibrated via `REVAI_*` env / console panel (retries, budget, recursion limit, timeout scale). |
| **Web Console** | `http://<host>:5000` | • Manual stage buttons (human-paced)<br>• **Run orch** button (full agentic path) | **UI-configured**<br>Run config panel sets retries, budget profile (*standard* / *generous* / *unlimited*), and timeout scale before execution. |

The shared tool stack across all three modes:

- **Static analysis** — Ghidra (SQL-first, required), IDA Pro (SQL, optional), Malcat (optional), radare2, capa, YARA, FLOSS, revai-tools (mitigations-with-consequence, sink-site + provenance audit, wallet/IOC extraction)
- **Dynamic / emulation** — Speakeasy, scdbg
- **Deobfuscation / symbolic** — z3, angr
- **Format-specific** — LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc

The deep dive always runs through the LangGraph ReAct agent.

> [!NOTE]
> **Malware RE Reports**
>
> Full analysis reports, audits, and verdicts from live malware runs live in [`docs/case-studies/`](docs/case-studies/). Every scan ships its raw tool output for reference in the sample's `evidence/` folder — refer to it when in doubt.

---

## Architecture

Deterministic tools gather evidence; the LLM only interprets. Ghidra (required)
plus optional IDA Pro and Malcat expose the binary as structured SQL, the agentic
deep dive queries those databases directly, and the LLM authors the verdict and
report from the assembled evidence pack. The quality gate (`report_quality.py`)
has the final say on `truly_green`.

For a full breakdown of component layering, the 7-stage spine, Evidence Pack
grounding (no RAG), and the Human-in-the-Loop approval gate, see
[`docs/architecture.md`](docs/architecture.md).

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
   │         revai-tools sec/sinks/audit, api_lookup offline API grounding)
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
| **Custom CADRE PE Loader** | Own Ghidra loader — recovers import tables on packed/binder PEs — see [`docs/cadre-pe-loader.md`](docs/cadre-pe-loader.md) |
| **Agent-loop discipline** | Budget warnings · redundant-call detection · hallucination check · failure taxonomy — see [`docs/agent-loop-discipline.md`](docs/agent-loop-discipline.md) |
| **Malcat native capa engine** | Faster + more reliable than Mandiant capa on hard samples — see [`docs/malcat-capa-engine.md`](docs/malcat-capa-engine.md) |
| **In-process yara-x engine** | YARA scanning with no external `yr` binary — see [`docs/OPERATE.md`](docs/OPERATE.md) |
| **Honest `truly_green` gate** | Green requires audit **and** report quality **and** zero failed tools — plus engine-citation verification and a cross-stage verdict lock |
| **Depth gate (capability coverage)** | Deep-dive summary must address every capability domain — as evidence or explicit "not observed" — see [`docs/architecture.md`](docs/architecture.md#10-quality-verification-gate-truly_green) |
| **Publication-quality gates** | Deterministic cross-report checks (dynamic-analysis honesty, verdict-panel agreement, entropy vs measured file entropy) |
| **Agentic function recovery** | Opt-in relevance-based triage → LLM naming (`FUN_…` → `parse_http_header`) → SQL writeback (conf ≥ 0.7, never deletes) → names cited in reports |
| **Tool Stack (28 tools)** | 28 format-aware manifest tools + 25 agent-callable tools (incl. revai-tools, the offline Windows-API lookup index and structural binary comparison — fail-open, never gates) — see [`docs/tool-stack.md`](docs/tool-stack.md) |
| **Offline API grounding** | `api_lookup` answers what a Windows API does and how it is abused from a local SQLite index (reference text + curated malicious-use notes + malapi.io attack categories + FTS search), so the deep-dive agent grounds API claims instead of recalling them — A/W, Nt/Zw, `__imp_`, `@N` spellings all fold. Knowledge only: never verdicts, never capability matching |

---

## Requirements

* **OS**: REMnux (Ubuntu 24.04-based) or equivalent isolated Linux analysis VM  
* **Resources**: 8 GB RAM minimum (16 GB recommended); ≥100 GB disk  
* **LLM**: Any OpenAI-compatible chat API (`config/llm.env.template` → `/opt/revai/config/llm.env`)  
* **Ghidra + ghidrasql** (required) · **Malcat** (optional — pipeline soft-fails without it): see [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md). ghidrasql is by Elias Bachaalany (github.com/0xeb/ghidrasql), used under the Human-Origin Source License v1.0  
* **Optional**: IDA Pro 9.x at `/opt/ida` (otherwise Ghidra-only)  
* **Node.js ≥ 18**: to build the React Console UI (`scripts/deploy.sh` builds it via npm)  
* **Optional**: full Windows-API index for `api_lookup` (~46k APIs) — you build it once from Microsoft's documentation and copy it to the VM: [`docs/api-index.md`](docs/api-index.md)  

---

## Quickstart

### 1. Clone & install

```bash
git clone https://github.com/Ganron007/RevAI.git
cd RevAI
sudo chmod +x install/*.sh scripts/*.sh
sudo ./install/setup-remnux.sh
```

Setup installs Python deps, normalizes Ghidra to `/opt/ghidra`, builds **ghidrasql**, installs **angr** (pipx) plus the extended static stack (**GoReSym**, **RIFT**, **FindCrypt**), and installs the matching **idasql** CLI + plugin when IDA Pro is present. Optional pieces soft-fail with warnings.  
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

### 5. Optional: full Windows-API index

The pipeline ships a small bundled index (369 malapi.io-catalogued APIs). For full
Win32 + kernel coverage (~46k APIs) build it once on a machine with internet and
copy it to the VM:

```bash
./scripts/build-api-index.sh
scp api_index_full.db <user>@<vm>:/opt/revai/api_index/api_index.db
```

Details, licences and troubleshooting: [`docs/api-index.md`](docs/api-index.md).

Full ops: [`docs/OPERATE.md`](docs/OPERATE.md) · Install: [`docs/INSTALL.md`](docs/INSTALL.md) · Prerequisites: [`docs/PREREQUISITES.md`](docs/PREREQUISITES.md).

---

## Security Guidelines

* Keep the VM network isolated (host-only / lab NIC).  
* Never commit `.env` files, API keys, or malware samples.  
* The React Console / Flask app is intended for trusted LAN use — do not expose it to the public internet without additional hardening.  

---

## What's coming…

*Work-in-progress — the roadmap below is where RevAI is headed before the
`v1.0.0` release tag. Items land as they are built, tested, and published.*

| Item | Description |
|------|-------------|
| **Verifiable artifact generation** | A stage that writes config extractors / unpackers / deobfuscation scripts for the sample and runs them — the artifact verifies itself |
| **Interactive steering mode** | A fourth run mode: analyst notes injected mid-run with HITL pause points; deterministic gates stay final |
| **Behavior-prerequisite gate promotion** | Move the advisory claim-vs-import check (G20) to a gate once its residual is reviewed |
| **Deployment rehearsal** | Clean-install test of the setup and deploy scripts on a fresh VM, so the documented path matches reality before release |
| **`v1.0.0` release tag** | Versioned first release once the items above land, including a clean-install deployment rehearsal of the setup scripts on a fresh VM |

---

## License

MIT — see [LICENSE](LICENSE).

> Copyright (c) 2026 CADRE RE Team.

---

## Acknowledgements

* **ghidrasql** — SQL interface for Ghidra program databases, by [Elias Bachaalany](https://github.com/0xeb/ghidrasql), used under the Human-Origin Source License v1.0.
* **idasql** — SQL interface for IDA Pro databases, by [Elias Bachaalany](https://github.com/allthingsida/idasql), used under the Human-Origin Source License v1.0.
