# Operation Guide 

## Start and stop the service

```bash
sudo systemctl start revai
sudo systemctl stop revai
sudo systemctl restart revai
sudo journalctl -u revai -f
```

The pipeline runs **LLM-based**: tools produce a stage-tagged evidence pack and the LLM writes the verdict/report.

## Stage a sample

### UI

1. Open `http://<remnux-ip>:5000`.
2. **+ Stage New Sample** → pick file + family → Stage.
3. Run stages in order (or **Run All**).

### Shell

```bash
python3 /opt/scripts/intake_v2.py /path/to/sample.exe --project-name MyFamily
```

Intake auto-sets `pipeline_mode` to `standard` or `large`. Override with:

```bash
CADRE_PIPELINE_MODE=standard python3 /opt/scripts/intake_v2.py /path/to/sample.exe
# or
CADRE_PIPELINE_MODE=large python3 /opt/scripts/intake_v2.py /path/to/sample.exe
```

## Run the full pipeline (orchestrator)

The recommended way to run the whole spine is the **LangGraph ReAct orchestrator** — it plans and executes intake → quick_scan → agentic deep dive → yara → publish → correlate → audit → quality gate, and retries a stage that fails. This is what the Console's **Run orch** button drives.

```bash
# Full agentic spine from a sample path (runs intake first)
python3 /opt/scripts/stage_orchestrator.py /path/to/sample.exe

# Resume the spine for an already-intaken sample
python3 /opt/scripts/stage_orchestrator.py --sha <sha256>

# Deterministic single-mode spine (no planner)
python3 /opt/scripts/pipeline_single.py /path/to/sample.exe
```

The run writes `orchestrator_trace.json` and `quality-gate.json` under `/opt/samples/logs/<sha256>/`; the final `truly_green` is the honest pass/fail.

## Pipeline stages 

1. **intake** — session + Ghidra (optional IDA)  
2. **quick_scan** — triage tools → `evidence-pack.md` → LLM verdict  
3. **deep_dive** — agentic LangGraph ReAct deep dive (`deep_dive_agentic`; `deep_dive_v2` for standard mode)  
3.5. **function_recovery** — *(optional)* agentic function-name recovery (see below)  
4. **yara_gen** — YARA + Sigma  
5. **publish** — REPORT-MASTER (LLM-authored, source-tagged)  
6. **correlate** — section Map-Reduce report  
7. **audit** — `audit_pipeline.py` → `all_green` (incl. depth gate), then `report_quality.py` → `truly_green`

Shell examples:

```bash
python3 /opt/scripts/quick_scan_v2.py <sha256>
python3 /opt/scripts/quick_scan_v2.py <sha256> --skip-malcat   # when Malcat is not installed
python3 /opt/scripts/deep_dive_v2.py <sha256>          # standard
python3 /opt/scripts/deep_dive_agentic.py <sha256>     # large
python3 /opt/scripts/agentic_recover_v4.py <sha256>    # optional stage — see below
python3 /opt/scripts/yara_gen_v2.py --family MyFamily <sha256>
python3 /opt/scripts/publish_report_v2.py --template full <sha256>
python3 /opt/scripts/audit_pipeline.py --mode standard <sha256>
```

## Run configuration (per-run semantics)

**3 modes, 3 config channels** — each mode reads its own configuration source, and they
never cross:

| Mode | Config source |
|---|---|
| Scripted CLI (`pipeline_single.py`) | `REVAI_*` env vars only (shell) |
| Agentic CLI (`stage_orchestrator.py`) | `REVAI_*` env vars only (shell) |
| Web Console | `pipeline-config.json` defaults + **per-run snapshot** |

**Per-run snapshot (console runs only):** when a run starts from the console
(single stage, Run All, or Run orch), the server captures the current run
configuration **once** and pins it to that run. Every stage of the run uses the
snapshot; changing Settings mid-run never affects the in-flight run. The next run
starts fresh from the persisted defaults (Settings page). The snapshot is recorded
in `session.json` (`run_config`) and the task, so the trace/audit shows exactly
what the run used.

CLI runs are unaffected by UI settings — set `REVAI_*` explicitly in the shell.

## Optional stage: agentic function recovery

Recovers meaningful names for decompiled functions (`FUN_00401a30` → `parse_http_header`)
by walking the call graph bottom-up and asking the LLM to name each function with
typed signatures. Enabled per-run with `REVAI_ENABLE_AGENTIC_RECOVERY=1` (the legacy
`ENABLE_AGENTIC_RECOVERY=1` is honored too). It runs between **deep_dive** and
**yara_gen** when enabled; in the orchestrator it is an optional planner tool that
skips itself when the flag is off and is never required for green.

```bash
# Full scripted run WITH recovery
REVAI_ENABLE_AGENTIC_RECOVERY=1 python3 /opt/scripts/pipeline_single.py /path/to/sample.exe

# Standalone stage
REVAI_ENABLE_AGENTIC_RECOVERY=1 python3 /opt/scripts/agentic_recover_v4.py <sha256>
```

Tunables (all optional, defaults shown):

| Env | Default | Meaning |
|---|---|---|
| `REVAI_ENABLE_AGENTIC_RECOVERY` | off | master switch (legacy `ENABLE_AGENTIC_RECOVERY` honored) |
| `REVAI_AGENTIC_RECOVERY_MAX_FUNCS` | 40 | analysis budget — top-N functions by complexity/tier |
| `REVAI_AGENTIC_RECOVERY_TIER_CAP` | 5 | per-tier function cap (bottom-up tiers) |
| `REVAI_AGENTIC_RECOVERY_WORKERS` | 2 | parallel LLM workers |

**Behavior contract (never breaks a run):** results are written to
`function_recovery.json`; only confidence ≥ 0.7 names are written back to the
Ghidra/IDA SQL database (lower-confidence results stay `NEEDS_HUMAN_REVIEW`, never
written); nothing is ever deleted; a failure of the stage is an honest fail only
when the gate is enabled and the flag was on. Recovered names are fed into the
publish prompts, so reports can cite them.

## Depth gate (capability coverage)

`audit_pipeline.py` enforces a deterministic completeness check on the deep-dive
summary: every capability domain (persistence, C2/network, evasion/anti-analysis,
exfiltration, defense impairment, credential access, encryption/obfuscation, entry
point, imports, strings) must be addressed — as evidence or an explicit
"not observed". A summary that never mentions a domain fails the audit
(`depth_coverage` check) and the run goes red. No env switch needed — it is always
on; the deep-dive prompts tell the agent to cover all domains before final_answer.

## Reset outputs

UI **Reset outputs**, or:

```bash
curl -X POST http://<remnux-ip>:5000/api/reset/<sha256>
```

## HITL

Low-confidence findings appear under **Annotate** — Approve / Reject as needed.

## More

- Prerequisites: [`PREREQUISITES.md`](PREREQUISITES.md)  
- Install: [`INSTALL.md`](INSTALL.md)  
- Deploy: [`DEPLOY.md`](DEPLOY.md)  
- Configure: [`CONFIGURE.md`](CONFIGURE.md)  
