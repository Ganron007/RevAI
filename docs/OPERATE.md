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
2. **quick_scan** — triage tools (capa, yara, floss, malcat, pe_imports, packer, **revai-tools sec/sinks**) → `evidence-pack.md` → LLM verdict  
3. **deep_dive** — agentic LangGraph ReAct deep dive (`deep_dive_agentic`; `deep_dive_v2` for standard mode) — checklist + agent callable include **revai-tools sec/sinks/audit**  
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
with the configured LLM. Triage queries are deliberately lightweight: a single
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
| `REVAI_AGENTIC_RECOVERY_CONF_THRESHOLD` | 0.7 | minimum confidence for a recovered name to be written back |
| `REVAI_AGENTIC_RECOVERY_SIG_THRESHOLD` | 0.80 | similarity threshold for the signature-DB naming pass |
| `REVAI_AUTO_WRITEBACK` | 0 | `1` lets standard-mode deep dives write recovered names into the Ghidra/IDA DB automatically |
| `REVAI_AGENTIC_RECOVERY_CONF_THRESHOLD` | 0.7 | minimum confidence for a recovered name to be written back |
| `REVAI_AGENTIC_RECOVERY_SIG_THRESHOLD` | 0.80 | similarity threshold for the signature-DB naming pass |
| `REVAI_AUTO_WRITEBACK` | 0 | `1` lets standard-mode deep dives write recovered names into the Ghidra/IDA DB automatically |

**Analysis-stage extras (all off by default, all opt-in):**

| Env | Default | Meaning |
|---|---|---|
| `REVAI_ENABLE_EMULATION_ORACLE` | off | bounded Speakeasy emulation pass in deep-dive: dynamically resolved imports + executed functions (persisted `deep_dive/03-oracle.json`, surfaced to the agent); oracle-only, never verdicts |
| `REVAI_ENABLE_UNPACK_PASS` | off | emulation-assisted unpacking for samples the packer checklist flags: OEP detection, carved `unpacked_<name>` payload under `logs/<sha>/unpack/`, in-memory IAT readout |
| `ENABLE_DEOBFUSCATION_PASS` | off | angr/z3 verification of MBA/CFF/opaque-predicate claims during deep-dive (angr via pipx venv) |
| `REVAI_CAPA_RULES` | `/opt/capa-rules` | capa rule directory (override for a custom ruleset) |
| `REVAI_CAPA_SIGNATURES` | `/opt/capa-signatures` | capa signature directory (override) |
| `REVAI_RUN_MODE` | set by the entry point | case-directory key: `scripted` (pipeline_single), `agentic` (stage_orchestrator), `ui` (Console). Set it explicitly only when driving a stage script by hand |
| `REVAI_STRICT_MD_ENGINE_CITE` | 0 | `1` makes every engine citation in a report mandatory (used for research audits; stricter than the default quality gate) |
| `REVAI_OLLAMA_URL` | `http://127.0.0.1:11434` | endpoint for the optional r2ai decompilation helper |
| `REVAI_SAMPLES` | `/opt/samples` | sample root used by document triage when the corpus lives elsewhere |
| `REVAI_SCRIPTS_DIR` | `/opt/scripts` | pipeline script directory used by the orchestrator when the flat layout differs |
| `REVAI_IDA_QUERY_TIMEOUT` | 120 | per-query timeout for IDA SQL queries (seconds) |
| `REVAI_LLM_PLANNER_REASONING` | disabled | reasoning effort override for the deep-dive planner only |
| `REVAI_LLM_USAGE_JOURNAL` | unset | path to a JSONL file; when set, every LLM call is journalled (used by the provider benchmark) |
| `REVAI_CAPA_RULES` | `/opt/capa-rules` | capa rule directory (override for a custom ruleset) |
| `REVAI_CAPA_SIGNATURES` | `/opt/capa-signatures` | capa signature directory (override) |
| `REVAI_API_INDEX` | unset | override the offline API lookup index path (default: `assets/api_index/api_index.db` in the repo, `/opt/revai/api_index/api_index.db` on the VM). The bundled index covers the 369 malapi.io-catalogued APIs; a full-corpus index (~46k APIs, built from Microsoft's sdk-api + driver-ddi documentation) can be deployed over it — see [`api-index.md`](api-index.md). Absent index degrades `api_lookup` to `available:false` — the pipeline is unaffected |
| `REVAI_FORCE_API_INDEX` | 0 | deploy-time only: `scripts/deploy.sh` keeps an existing VM index (so a full-corpus build survives a deploy); set to 1 to overwrite it with the bundled default |
| `REVAI_IOC_FACTCHECK` | enforce | unverified report IOC claims fail the quality gate; `advisory` records them without failing (escape hatch for a report citing sources outside the evidence pack) |
| `REVAI_DISABLE_IOC_CONFIDENCE` | off | skip the deterministic "Indicator confidence" section in the technical reports |
| `REVAI_DISABLE_DYNAMIC_SECTION` | off | skip the deterministic "Dynamic Analysis (WinRE detonation)" section |
| `REVAI_DISABLE_GAP_SECTION` | off | skip the deterministic "What We Don't Know" section |
| `REVAI_DEEP_STREAM` | off | consume the deep-dive agent graph as a stream instead of one blocking invoke (identical messages; steps observable as they happen) |
| `REVAI_PROGRESS_STREAM_SECONDS` | 300 | duration of the SSE progress feed (`/api/orch/<sha>/progress/stream`) |

All of the above are exposed in the web console **Run configuration** panel (Settings → run config), so they can be toggled per run without shell env. CLI runs set them explicitly.

**Optional dynamic corroboration (WinRE companion — run-config toggle):**

When a sample has been detonated with the optional [WinRE](https://github.com/Ganron007/WinRE)
companion, reports gain a deterministic "Dynamic Corroboration (WinRE detonation)"
block: the window actually used (with a coverage caveat), runtime network
indicators, dropped file paths, and the agentic-dbg unpack artifact (with a
pefile + capa static pass when PE-valid). The block is **presence-gated** — no
pack for the sample means reports are byte-identical to a WinRE-less install. The
Console shows the state for the open case: the orchestrator panel's **winre
dynamic** chip (`pack · N DNS` / `no pack` / `not configured` / `off`) and
`GET /api/winre/status/<sha>` for scripts. —
and corroborates only (`static_yara_wins` never yields).

| Env | Default | Meaning |
|---|---|---|
| `REVAI_WINRE_LOGS` | `/opt/winre/logs` | root scanned for WinRE packs (mode-keyed sections) |
| `winre_dynamic` (Console) | on | Run configuration -> WinRE companion: `On` (default) uses packs when present, `Off` writes static-only reports. Maps to `REVAI_DISABLE_DYNAMIC_CORROBORATION` and `REVAI_DISABLE_DYNAMIC_SECTION` together |
| `winre_logs` (Console) | unset | optional pack root override, for a case whose packs live elsewhere |
| `REVAI_DISABLE_DYNAMIC_CORROBORATION` | unset | set to `1` to suppress the block entirely |

Setup and modes: [`WINRE-REMOTE.md`](WINRE-REMOTE.md).

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

## Deep-dive observability

Two endpoints expose what the deep-dive agent is doing while it runs:

* `GET /api/orch/<sha>/live?mode=<scripted|agentic|ui>` — includes `deep_dive_progress`,
  the tail of `deep_dive/deep-dive-progress.jsonl`: one JSON object per tool start,
  tool end and LLM turn (tool name, input excerpt, output size, token usage). The
  file is rewritten fresh for each deep dive; writing is best-effort and can never
  fail a run.
* `GET /api/graph` — the agent graph as Mermaid plus its tool inventory and an
  explicit caveat: the prebuilt ReAct graph is a two-node loop, so the diagram shows
  *what executes*, not what the model decides. Fail-open.

## Claimed-IOC fact verification (enforced) and behavior prerequisites (advisory)

`report_quality.py` re-checks every literal indicator a report claims against the
raw tool evidence by code (both fanged and defanged forms). An unverified claim
fails the quality gate (`report:unverified_iocs:<n>`); `REVAI_IOC_FACTCHECK=advisory`
records it without failing. Known non-claims are excluded rather than counted:
generic hive keys without a subkey, vendor/telemetry hosts, prose/code identifiers.

Calibration over the 56 published case studies (post-fix): 175 literal claims,
148 verified, **6 unverified** (4 QQ-family domains in the darkgate case, 2
`HKCU\...\Run` claims), 21 excluded artifacts. Three historical cases would now
flag — they were published before the gate existed.

The same pass records **behavior prerequisites** (advisory): a report claiming
injection, persistence or credential access with none of that behavior's defining
APIs in the import surface is listed as unsupported, and for a packed sample it is
stated as "analysis incomplete" instead of a negative. Result:
`advisory.behavior_prerequisites` in the quality payload.

## Deep-dive progress stream

`/api/orch/<sha>/progress/stream` streams the deep-dive progress as server-sent
events (one JSON object per tool start/end and LLM turn), for
`REVAI_PROGRESS_STREAM_SECONDS` seconds. With `REVAI_DEEP_STREAM=1` the agent
consumes its graph as a stream, so steps appear as they happen rather than at the
end of one blocking invoke; the produced messages are identical either way.

## Deterministic report sections (plan #12 alignment)

Three sections are appended by code after the LLM writes the report, so they are
guaranteed present and cannot be paraphrased away (each opt-out above):

1. **Indicator confidence (deterministic)** — the per-indicator tiers from
   `iocs.json`, grouped by Pyramid-of-Pain tier (hashes → IPs → domains → network
   → host artifacts) so the table reads worst-first.
2. **Dynamic Analysis (WinRE detonation)** — presence-gated on a WinRE pack:
   detonation window and coverage caveat, runtime DNS/SNI/HTTP, dropped or written
   files, Frida/Procmon summaries, the agentic-dbg unpack artifact with its
   honesty flags (`static_yara_wins`, raw-memory note when the dump is not
   PE-parsable). Observed behaviour is stated as corroboration only.
3. **Component Inventory** — PE structure with per-section structural roles
   (read from flags and names, never behaviour), imports by module, overlay size and
   the entry-point section.
4. **MBC Vocabulary** — the Malware Behavior Catalog objective/behavior/method
   entries that capa's own rule metadata carries, alongside the ATT&CK mapping.
5. **Appendix: Analysis Environment** — tool versions as reported by this run,
   plus the RevAI provenance; an install-time capture at
   `/opt/revai/config/tool-versions.json` is included when present.
6. **What We Don't Know** — built only from structural gaps (dynamic not run,
   window-bounded coverage, unpack image not statically analyzable) plus the
   report's own explicit negations. Nothing is inferred.

## Verification and release gates

Two layers, both deterministic and safe to run any time:

**1. Wiring/coherence harness** — `python3 revai/verify_pipeline.py` (stdlib only):

* every Python file compiles;
* `TOOL_MANIFEST` entries resolve to real functions, every `ToolRegistry` tool has
  a model-facing description, no description points at a tool that does not exist,
  the LangGraph tool list only names registry tools, and agent-only tools
  (`api_lookup`, `compare_files`) are reachable in the default engine;
* README / architecture / tool-stack / SVG tool counts match the code;
* no private-repo references, lab IPs, model names or literal secrets in published
  files (local-only, gitignored files are excluded by design);
* every `REVAI_*` variable read by code is documented in `docs/` (or allowlisted as
  internal).

The same checks run inside pytest (`tests/test_wiring_coherence.py`), so registry
drift fails the suite instead of waiting for review.

**2. One-command release gate** — `./scripts/verify-release.sh`:

1. the harness above;
2. `pytest tests/` (all unit + regression tests; `test_pipeline.py` skips unless
   `REVAI_PIPELINE_TEST_SHA` names a completed case);
3. parser parity against pefile when `REVAI_PE_PARITY_SAMPLE` points at a real PE;
4. VM harness + smoke + `/api/graph` when `REVAI_VM_SSH` is set.

Interpreters are overridable for the analysis VM:

```bash
REVAI_PYTHON=/tmp/rtvenv/bin/python \
REVAI_PE_PARITY_SAMPLE=/opt/samples/.../sample \
REVAI_VM_SSH=remnux@<vm> ./scripts/verify-release.sh
```

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
