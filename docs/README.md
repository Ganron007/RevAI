# RevAI Documentation

- [`architecture.md`](architecture.md) — System architecture, 7-stage spine, Evidence Pack grounding (no RAG), HITL approval gate, depth gate (capability coverage), optional function-recovery stage.
- [`PREREQUISITES.md`](PREREQUISITES.md) — Ghidra, ghidrasql, CADRE PE Loader, Malcat (optional), LLM.
- [`INSTALL.md`](INSTALL.md) — install dependencies on REMnux.
- [`DEPLOY.md`](DEPLOY.md) — deploy the pipeline and start the service.
- [`CONFIGURE.md`](CONFIGURE.md) — LLM and optional IDA settings.
- [`OPERATE.md`](OPERATE.md) — daily use: staging samples, running stages, optional function-recovery stage + env, depth gate, tests.
- [`cadre-pe-loader.md`](cadre-pe-loader.md) — custom Ghidra PE loader extension (import fixup for packed/binder PEs).
- [`agent-loop-discipline.md`](agent-loop-discipline.md) — budget warnings, redundant-call detection, hallucination check, failure taxonomy.
- [`tool-stack.md`](tool-stack.md) — the 24-tool manifest + agent-callable ToolRegistry.
- [`malcat-capa-engine.md`](malcat-capa-engine.md) — why Malcat's native capa engine is primary (measured benchmark).
- [`case-studies/`](case-studies/) — real analysis reports produced by the pipeline against live malware samples (published after each verified batch run).

## Repo → VM layout (how deployment works)

The repo is a **source layout**; the VM is a **runtime layout** — they are intentionally
different, and the install/deploy scripts translate between them.

| Repo (source) | → | VM (runtime) | Via |
|---|---|---|---|
| `revai/*.py` | → | `/opt/scripts/` (flat) | `scripts/deploy.sh` |
| `revai/hitl/` | → | `/opt/revai/hitl/` | `scripts/deploy.sh` |
| `revai/ui/` | → | `/opt/scripts/ui/` (npm build) | `scripts/deploy.sh` |
| `config/llm.env.template` | → | `/opt/revai/config/llm.env` (user fills) | manual copy |
| `extensions/cadre-pe-loader/` | → | `/opt/ghidra/Ghidra/Extensions/CADRE/` | `install/setup-remnux.sh` |
| `extensions/deobfuscation/` | → | `/opt/revai/deobfuscation/` | `install/setup-remnux.sh` |
| `extensions/cff-deflatten/` | → | `/opt/revai/cff-deflatten/` | `install/setup-remnux.sh` |
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
| **Scripted** | `pipeline_single.py` | Fixed order (intake -> quick_scan -> deep_dive -> yara_gen -> publish -> section -> audit) | LangGraph agentic (always) |
| **Agentic** | `stage_orchestrator.py` | LLM decides which stage to call; retries on failure; HITL before publish if verdicts disagree | LangGraph agentic |
| **Web Console** | `http://<host>:5000` | User clicks individual stage buttons, or **Run orch** for full agentic | LangGraph agentic |

The deep dive always runs through the LangGraph ReAct agent — only the stage ordering differs between modes. Usage details: [`OPERATE.md`](OPERATE.md).

For the project overview, see the top-level [`README.md`](../README.md).
