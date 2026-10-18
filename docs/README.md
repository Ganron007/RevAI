# RevAI Documentation

- [`architecture.md`](architecture.md) — System architecture, stage spine, Evidence Pack grounding (no RAG), HITL approval gate, depth gate (capability coverage), optional function-recovery stage.
- [`FEATURES.md`](FEATURES.md) — full feature inventory: every feature with its env gate, stage, and produced artifact.
- [`PREREQUISITES.md`](PREREQUISITES.md) — Ghidra, ghidrasql, CADRE PE Loader, Malcat (optional), LLM.
- [`INSTALL.md`](INSTALL.md) — install dependencies on REMnux.
- [`DEPLOY.md`](DEPLOY.md) — deploy the pipeline and start the service.
- [`CONFIGURE.md`](CONFIGURE.md) — LLM and optional IDA settings.
- [`OPERATE.md`](OPERATE.md) — daily use: staging samples, running stages, the run watchdog (`run-watched.sh`) and its exit contract, `instrument-live-log.sh` for reading a finished run in one command, optional stages + env, depth gate, tests.
- [`cadre-pe-loader.md`](cadre-pe-loader.md) — custom Ghidra PE loader extension (import fixup for packed/binder PEs).
- [`agent-loop-discipline.md`](agent-loop-discipline.md) — budget warnings, redundant-call detection, hallucination check, failure taxonomy.
- [`tool-stack.md`](tool-stack.md) — the 28-tool manifest + agent-callable ToolRegistry (incl. revai-tools sec/sinks/audit and the offline Windows-API lookup index).
- [`api-index.md`](api-index.md) — build the offline Windows-API index for `api_lookup` (bundled 369-API default vs full ~46k-API corpus, deploy, licences, troubleshooting).
- [`WINRE-REMOTE.md`](WINRE-REMOTE.md) — optional Windows dynamic analysis: drive WinRE (static + detonation + debugger passes) from the RevAI host.
- [`malcat-capa-engine.md`](malcat-capa-engine.md) — why Malcat's native capa engine is primary (measured benchmark).
- [`case-studies/`](case-studies/) — real analysis reports produced by the pipeline against live malware samples (published after each verified batch run).

## Repo → VM layout (how deployment works)

The repo is a **source layout**; the VM is a **runtime layout** — they are intentionally
different, and the install/deploy scripts translate between them.

| Repo (source) | → | VM (runtime) | Via |
|---|---|---|---|
| `revai/*.py` | → | `/opt/scripts/` (flat — includes `revai/skills/`, `revai/prompts/`, `revai/recovery/` and `revai/signatures/`, which the skills layer, function recovery and `signature_match` depend on) | `scripts/deploy.sh` |
| `revai/hitl/` | → | `/opt/revai/hitl/` | `scripts/deploy.sh` |
| `revai/ui/` | → | `/opt/scripts/ui/` (npm build) | `scripts/deploy.sh` |
| `docs/` | → | `/opt/scripts/docs/` (so the VM can run the same documentation checks) | `scripts/deploy.sh` |
| `tests/*.py` | → | `/opt/scripts/tests/` (every `tests/*.py`, not just `test_*.py` — the helpers must ship too or VM collection aborts) | `scripts/deploy.sh` |
| `scripts/run-watched.sh`, `scripts/instrument-live-log.sh`, `scripts/validate-ghidrasql-sql.py`, `scripts/winre-llm-env.sh`, `scripts/verify-release.sh` | → | `/opt/scripts/` (operator tools) | `scripts/deploy.sh` |
| pipeline git HEAD | → | `/opt/revai/config/REVAI_COMMIT` (the provenance banner every artifact carries) | `scripts/deploy.sh` |
| `assets/api_index/` | → | `/opt/revai/api_index/` (an existing VM index is preserved unless `REVAI_FORCE_API_INDEX=1`) | `scripts/deploy.sh` |
| `config/llm.env.template` | → | `/opt/revai/config/llm.env` (user fills) | manual copy |
| `extensions/cadre-pe-loader/` | → | `/opt/ghidra/Ghidra/Extensions/CADRE/` | `install/setup-remnux.sh` |
| `extensions/deobfuscation/` | → | `/opt/revai/deobfuscation/` | `install/setup-remnux.sh` |
| `extensions/cff-deflatten/` | → | `/opt/revai/cff-deflatten/` | `install/setup-remnux.sh` |
| upstream downloads (GoReSym, RIFT, FindCrypt) | → | `/opt/goresym/`, `/opt/rift/`, Ghidra `ghidra_scripts/` | `install/setup-remnux.sh` |
| pipx `angr` | → | `/home/remnux/.local/share/pipx/venvs/angr` | `install/setup-remnux.sh` |
| idasql (when IDA Pro present) | → | `/usr/local/bin/idasql` + `/opt/ida/plugins/` | `install/setup-remnux.sh` |
| `extensions/libghidra-patch/` | → | patches `LibGhidraHost.jar` in place | `install/setup-remnux.sh` |
| `ghidra_scripts/` | → | `/opt/ghidra/Ghidra/.../ghidra_scripts/` | `install/setup-remnux.sh` |
| `install/revai.service` | → | `/etc/systemd/system/revai.service` | `scripts/deploy.sh` |

**Why flat `/opt/scripts`?** Runtime scripts reference each other by absolute path
(`SCRIPTS_DIR = Path("/opt/scripts")` in `app.py`, `SCRIPTS` in `pipeline_single.py`).
On the VM all stage scripts must be flat in one dir for those paths to work; the repo
keeps them under `revai/` for organization and `deploy.sh` flattens them.

**Fresh user flow:** `git clone` → `sudo ./install/setup-remnux.sh` → copy+fill
`/opt/revai/config/llm.env` → `./scripts/deploy.sh --restart` → verify. No manual
folder creation needed — the scripts create the full runtime layout automatically.

## Pipeline Modes

RevAI supports three modes of execution, all using the same tool stack and LLM backend:

- **Static analysis** — Ghidra, radare2, capa, YARA, FLOSS
- **Dynamic / emulation** — Speakeasy, scdbg
- **Deobfuscation / symbolic** — z3, angr
- **Format-specific** — LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc

| Mode | Script | Stages | Deep Dive |
|------|--------|--------|-----------|
| **Scripted** | `pipeline_single.py` | Fixed order: intake -> quick_scan -> [winre_dynamic] -> deep_dive -> [function_recovery] -> [artifact_gen] -> [behavioural_model] -> yara_gen -> publish v2 -> section v3 -> audit -> [depth_understanding] | LangGraph agentic (always) |
| **Agentic** | `stage_orchestrator.py` | LLM planner decides which stage to call (15 stage tools, policy-pinned order); retries on failure; HITL before publish if verdicts disagree | LangGraph agentic |
| **Web Console** | `http://<host>:5000` | User clicks individual stage buttons, or **Run orch** for full agentic | LangGraph agentic |

*Bracketed stages are optional: `winre_dynamic` (`REVAI_WINRE_RUN=1`),
`function_recovery` (`REVAI_ENABLE_AGENTIC_RECOVERY=1`), `artifact_gen`
(`REVAI_ENABLE_ARTIFACT_GEN=1`), `behavioural_model`
(`REVAI_ENABLE_BEHAVIOURAL_MODEL=1`) and `depth_understanding`
(`REVAI_DEPTH=1`) each self-skip when their flag is off.

The deep dive always runs through the LangGraph ReAct agent — only the stage ordering differs between modes. Usage details: [`OPERATE.md`](OPERATE.md).

For the project overview, see the top-level [`README.md`](../README.md).

---

## RE agent skills

Reverse-engineering procedure is a cited, versioned artifact the agent LOADS on
demand, never prose it recalls. Six skills ship, including
`report-evidence-methodology` for report writing and claim review. Each has a
version, source provenance in `sources.jsonl`, and explicit scope limits.
Internal knowledge-base paths are provenance, not public links; repository-derived
material is labeled as such. See [OPERATE.md](OPERATE.md).

