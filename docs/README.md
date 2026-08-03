# CADRE-RevAI Documentation

- [`PREREQUISITES.md`](PREREQUISITES.md) — Ghidra, ghidrasql, CADRE PE Loader, Malcat (optional), LLM.
- [`INSTALL.md`](INSTALL.md) — install dependencies on REMnux.
- [`DEPLOY.md`](DEPLOY.md) — deploy the pipeline and start the service.
- [`CONFIGURE.md`](CONFIGURE.md) — LLM and optional IDA settings.
- [`OPERATE.md`](OPERATE.md) — daily use: staging samples, running stages, tests.
- [`../extensions/cadre-pe-loader/`](../extensions/cadre-pe-loader/) — custom Ghidra PE loader extension (source + build instructions).

## Pipeline Modes

CADRE-RevAI supports three modes of execution, all using the same tool stack and LLM backend:

- **Static analysis** — Ghidra, radare2, capa, YARA, FLOSS
- **Dynamic / emulation** — Speakeasy, scdbg
- **Deobfuscation / symbolic** — z3, angr
- **Format-specific** — LIEF, diec, GoReSym, FindCrypt, ilspycmd, RIFT, pycdc

| Mode | Script | Stages | Deep Dive |
|------|--------|--------|-----------|
| **Scripted** | `pipeline_single.py` | Fixed order (intake -> quick_scan -> deep_dive -> yara_gen -> publish -> audit) | LangGraph agentic (always) |
| **Agentic** | `stage_orchestrator.py` | LLM decides which stage to call; retries on failure; HITL before publish if verdicts disagree | LangGraph agentic |
| **Web Console** | `http://<host>:5000` | User clicks individual stage buttons, or **Run orch** for full agentic | LangGraph agentic |

The deep dive always runs through the LangGraph ReAct agent — only the stage ordering differs between modes. Usage details: [`OPERATE.md`](OPERATE.md).

For the project overview, see the top-level [`README.md`](../README.md).
