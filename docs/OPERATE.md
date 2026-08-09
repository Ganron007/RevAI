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
by triaging candidates by **relevance** (not size), walking the call graph bottom-up,
and asking the LLM to name each function with typed signatures. Enabled per-run with
`REVAI_ENABLE_AGENTIC_RECOVERY=1` (the legacy `ENABLE_AGENTIC_RECOVERY=1` is honored
too). It runs between **deep_dive** and **yara_gen** when enabled; in the orchestrator
it is an optional planner tool that skips itself when the flag is off and is never
required for green.

```bash
# Full scripted run WITH recovery
REVAI_ENABLE_AGENTIC_RECOVERY=1 python3 /opt/scripts/pipeline_single.py /path/to/sample.exe

# Standalone stage
REVAI_ENABLE_AGENTIC_RECOVERY=1 python3 /opt/scripts/agentic_recover_v4.py <sha256>
```

**Triage (deterministic, no LLM):** candidates are scored instead of taking the
largest functions:

```
score = call_in_count * 2 + string_ref_count + high_value_imports * 3
      + anti_analysis_signals
```

- `call_in_count` — call-hub importance (dequeue by relevance, not size)
- `string_ref_count` — behavioral signal (focus on non-library functions)
- `high_value_imports` — distinct high-value API references (evasion, persistence,
  C2, credential theft, defense impairment), matched by **prefix** so `A`/`W`/`Ex`
  variants count (`RegSetValueExW`, `VirtualAllocEx`, bare `VirtualAlloc`)
- `anti_analysis_signals` — deterministic per-function score from
  `anti_analysis_signals.py` (debugger APIs, PEB access via FS:[0x30]/GS:[0x60],
  timing pairs, process scans, VM/analysis-tool artifact strings, TLS callbacks) —
  evasion logic is a prime analysis target

Relevance alone can bury small-but-critical API callers on samples whose string
metrics are unpopulated, so the pool is **hybrid** — guaranteed slots plus score
fill (verified on small darkgate, 2026-08-09): the pure-size pool never analyzed
the `VirtualAlloc` callers; the hybrid pool recovers `allocate_checked_memory` /
`commit_memory_range`; dynamic-import-resolve sites (`dynamic_resolve_detect.py`,
≥2 GetProcAddress/resolver calls — packed-sample core logic) get guaranteed slots
(`resolve_borland_memory_functions` recovered at 0.95). Verified: 19 functions
analyzed vs 13 (size-based) at tier-cap 5, 11/19 conf ≥ 0.7 (was 8/13), $0.0686
with deepseek-v4-flash. Triage queries are deliberately lightweight: a single
SQL statement joining `funcs`/`function_metrics`/`callgraph_edges` hung the
ghidrasql server; equivalent split queries return in seconds.

Tunables (all optional, defaults shown):

| Env | Default | Meaning |
|---|---|---|
| `REVAI_ENABLE_AGENTIC_RECOVERY` | off | master switch (legacy `ENABLE_AGENTIC_RECOVERY` honored) |
| `REVAI_AGENTIC_RECOVERY_MAX_FUNCS` | 200 | analysis budget — top-N candidates (relevance + hybrid slots) |
| `REVAI_AGENTIC_RECOVERY_TIER_CAP` | 20 | per-tier function cap (bottom-up tiers) |
| `REVAI_AGENTIC_RECOVERY_WORKERS` | 8 | parallel LLM workers |
| `REVAI_AGENTIC_RECOVERY_HV_SLOTS` | 8 | guaranteed pool slots for high-value-import callers |
| `REVAI_AGENTIC_RECOVERY_SIZE_SLOTS` | 5 | guaranteed pool slots for largest functions ≥ `MIN_SIZE` |
| `REVAI_AGENTIC_RECOVERY_MIN_SIZE` | 200 | size floor (bytes) for `SIZE_SLOTS` |
| `REVAI_AGENTIC_RECOVERY_RESOLVE_SLOTS` | 3 | guaranteed pool slots for dynamic-import-resolve sites |
| `REVAI_AGENTIC_RECOVERY_ORACLE_SLOTS` | 3 | guaranteed pool slots for emulation-oracle executed functions |

**Analysis-stage extras (all off by default, all opt-in):**

| Env | Default | Meaning |
|---|---|---|
| `REVAI_ENABLE_EMULATION_ORACLE` | off | bounded Speakeasy emulation pass in deep-dive: dynamically resolved imports + executed functions (persisted `deep_dive/03-oracle.json`, surfaced to the agent); oracle-only, never verdicts |
| `REVAI_ENABLE_UNPACK_PASS` | off | emulation-assisted unpacking for samples the packer checklist flags: OEP detection, carved `unpacked_<name>` payload under `logs/<sha>/unpack/`, in-memory IAT readout |
| `ENABLE_DEOBFUSCATION_PASS` | off | angr/z3 verification of MBA/CFF/opaque-predicate claims during deep-dive (angr via pipx venv) |
| `REVAI_AGENTIC_RECOVERY_MAX_FUNCS` | 200 | analysis budget — top-N candidates (relevance + hybrid slots) |
| `REVAI_AGENTIC_RECOVERY_TIER_CAP` | 20 | per-tier function cap (bottom-up tiers) |

All of the above are exposed in the web console **Run configuration** panel (Settings → run config), so they can be toggled per run without shell env. CLI runs set them explicitly.

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
