# CADRE-RevAI Documentation

- [`PREREQUISITES.md`](PREREQUISITES.md) — Ghidra, ghidrasql, CADRE PE Loader, Malcat (optional), LLM.
- [`INSTALL.md`](INSTALL.md) — install dependencies on REMnux.
- [`DEPLOY.md`](DEPLOY.md) — deploy the pipeline and start the service.
- [`CONFIGURE.md`](CONFIGURE.md) — LLM and optional IDA settings.
- [`OPERATE.md`](OPERATE.md) — daily use: staging samples, running stages, tests.
- [`../extensions/cadre-pe-loader/`](../extensions/cadre-pe-loader/) — custom Ghidra PE loader extension (source + build instructions).
- [`case-studies/`](case-studies/) — real analysis reports produced by the pipeline against live malware samples.

## Pipeline Modes

CADRE-RevAI supports three modes of execution, all using the same tool stack and LLM backend:

| Mode | Script | When to use |
|------|--------|-------------|
| **Scripted** | `pipeline_single.py` | Batch runs, reproducibility, scripted automation |
| **Agentic** | `stage_orchestrator.py` | LLM-driven stage ordering, HITL before publish |
| **Web Console** | `http://<host>:5000` | Interactive analysis, report reader |

See [`case-studies/README.md`](case-studies/README.md) for real examples and [`OPERATE.md`](OPERATE.md) for usage details.

For the project overview, see the top-level [`README.md`](../README.md).
