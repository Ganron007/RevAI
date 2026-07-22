# CADRE-RevAI — V6.1–V6.4 sync (2026-07-22)

One-shot public sync from CADRE-RevEng after:

- **V6.1** LLM-only (RAG off) — 2 std + 1 large E2E
- **V6.2** Flare dynamic Frida (vmnet2-only; no open internet)
- **V6.3** Single-mode agentic RE (`pipeline_single_v63.py`)
- **V6.4** Flask UI stage spine (agentic deep + optional dynamic)

## New / updated scripts

| File | Role |
|------|------|
| `revai/dynamic_run_v2.py` | Remnux→Flare Frida orchestrator |
| `revai/pipeline_single_v63.py` | Single-mode full spine |
| `revai/deep_dive_agentic.py` | Agentic deep (default deep stage) |
| `revai/agentic_langgraph.py` | LangGraph engine |
| `revai/app.py` + `templates/` | Flask UI V6.4 |
| `revai/audit_pipeline.py` | `--mode single` → large audit path |
| `scripts/flare-dynamic/frida_api_trace.py` | Frida 17 tracer for Flare-VM |

Docs: `docs/v6/`.
