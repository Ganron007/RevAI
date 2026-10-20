# RevAI — Feature Inventory & Status

Inventory of RevAI capabilities: what each feature does, which environment
gate controls it, where it runs, and which artifact it produces. Feature
presence describes the implementation; it does not certify the current source
revision or every sample path. The case studies retain run-specific evidence
and historical results.

## Current validation state — 2026-10-20

RevAI revision `1ff765f` is deployed on the configured reference runtime and
its preflight smoke passes. The full local test suite on that revision reports
**1,095 passed, 14 skipped**. These checks validate code contracts and runtime
wiring; they do not establish sample-level report quality. No fresh malware
sample has passed end-to-end acceptance on this revision. The current
acceptance matrix is maintained separately; historical run sections below
remain tied to their recorded source revisions. The feature inventory is not a
release-acceptance certificate.

## Deterministic extractors (run in quick_scan / deep_dive)

| # | Feature | What it does | Gate (env) | Stage | Artifact |
|---|---------|-------------|-----------|-------|----------|
| G1 | **Emulation oracle** | Bounded Speakeasy emulation; records executed instructions, dynamically resolved imports, executed→function mapping | `REVAI_ENABLE_EMULATION_ORACLE=1` | deep_dive seeds | `deep_dive/03-oracle.json` |
| G2 | **Anti-analysis signals** | Deterministic scan for debugger/VM/timing/TLS anti-analysis patterns | always on (PE/unknown) | quick_scan + deep_dive seeds | `deep_dive/02-signals.json` (`anti_analysis`) |
| G3 | **Unpack pass** | Emulation-assisted unpack/carve when packer checklist flags packed/suspicious | `REVAI_ENABLE_UNPACK_PASS=1` | deep_dive seeds | `deep_dive/02-signals.json` (`unpack`) + `logs/<sha>/unpack/` |
| G4 | **Dynamic-resolve detector** | Finds API-resolve sites (callgraph + runtime-resolved imports from the emulation oracle on packed code) | always on | quick_scan + deep_dive seeds | `deep_dive/02-signals.json` (`dynamic_resolve`, `runtime_resolved_imports`) |
| G5 | **Shellcode/scdbg path** | scdbg emulation of raw shellcode; shellcode checklist tool | always on | deep_dive checklist + agent | agent history `deep-dive-agentic-history.json` |
| G6 | **String extraction** | FLOSS (PE) + Malcat strings with ref counts | always on (format-gated) | quick_scan | `quick_scan/00-tools-raw.json` (`floss`/`malcat`) + `evidence/strings.txt` |
| G7 | **YARA rule gen** | Auto rule from distinctive strings + imphash; generic API/DLL/CRT strings and header bytes filtered (near-universal-condition guard); validation + goodware FP scan | always on | yara_gen | `rule.yar`, `rule.yara.json`, `rule.yml` |
| G8 | **Packer checklist** | Deterministic packer_intake scoring (entropy/sections/imports) | always on | quick_scan + deep_dive | `packer.txt`, gate context for packed policy |
| G9 | **Signals → agent prompt** | Seeds G1–G4 findings into the agent's evidence so it cites them | always on | deep_dive seeds | findings + agent history |
| G10 | **IOC export** | Structured pack: hashes/domains/ips/urls/files/registry/mutexes | always on | yara_gen | `iocs.json` |
| G11 | **revai-tools mitigations** (`revai_tools_sec`) | Mitigations-with-consequence: PE claim-vs-fact (ASLR/DEP/CFG/GS/SEH per section flags) + ELF header-fact findings, each with an exploitation consequence note | always on (PE/ELF, fail-open) | quick_scan phase-A + deep-dive checklist + agent | `quick_scan/00-tools-raw.json`, agent history |
| G12 | **revai-tools sink sites** (`revai_tools_sinks`) | Dangerous-API call sites located inside named functions (radare2-backed); honest 0-site results recorded | always on (PE/ELF/dotnet, fail-open) | quick_scan phase-A + deep-dive checklist + agent | `quick_scan/00-tools-raw.json`, agent history |
| G13 | **revai-tools sink audit** (`revai_tools_audit`) | Sink sites with exploitable argument provenance (constant vs subtraction/register-source) + entry-reachability | always on (PE/ELF/dotnet, fail-open) | deep-dive checklist + agent | deep-dive evidence pack, agent history |
| G14 | **revai-tools IOC extension** (`revai_tools_iocs`) | Crypto wallets (BTC/ETH) + defanged IOC merge into the structured pack | always on (fail-open) | yara_gen | `iocs.json` (`revai_tools` provenance block) |
| G15 | **API lookup index** (`api_lookup`) | Offline Windows-API grounding: reference text, curated malicious-use notes and malapi.io attack categories for any symbol a disassembler shows (A/W, Nt/Zw, `__imp_`, `@N` fold), plus FTS search. Knowledge lookup only — never verdicts, never capability matching (capa owns that) | agent-callable (index presence-gated, fail-open) | deep_dive agent | agent history `deep-dive-agentic-history.json` |
| G16 | **Per-IOC confidence tiers** (`ioc_confidence.py`) | Every indicator in `iocs.json` carries a deterministic tier (high/medium/low) derived from extraction method and context — URL host, structural registry path, strict wallet format, private/reserved address, vendor domain, cross-source corroboration — with the reasons recorded, and rendered as an "Indicator confidence" section in the technical reports | always on (fail-open) | yara_gen + publish | `iocs.json` (`confidence` block), `REPORT-TECHNICAL-v2/v3.md` |
| G17 | **Binary structural comparison** (`compare_files`, `binary_diff.py`) | Loader-vs-payload comparison by measured facts: sizes/hashes, imphash equality, section overlap with entropy deltas, import overlap, exact 64-byte chunk containment. Facts only, no similarity score | agent-callable | deep_dive agent | agent history |
| G18 | **Deep-dive observability** | The ReAct loop becomes visible while it runs: tool start/end + LLM turns stream to `deep-dive-progress.jsonl` and are served by the Console's live poller; `/api/graph` returns the agent graph as Mermaid plus its tool inventory; `/api/orch/<sha>/progress/stream` is a server-sent-events feed of the same stream (`REVAI_DEEP_STREAM=1` makes the engine consume the graph as a stream instead of one blocking invoke) | always on (langgraph engine) | deep_dive agent | `deep_dive/deep-dive-progress.jsonl`, `/api/graph`, SSE endpoint |
| G19 | **Claimed-IOC fact verification** (enforced per report) | Deterministic re-check of literal indicators in each of the four published reports against the same run's raw tool evidence (both fanged and defanged forms); unsupported claims remain in the draft and fail that report's quality gate. Known non-claims are excluded (generic hive keys, vendor/telemetry hosts, prose identifiers) | always on | each publish stage and final audit | `report-*.json` quality checks, `pipeline-audit.json`, gate issue `report:unverified_iocs:<n>` |
| G20 | **Behavior prerequisites** (advisory) | Cross-checks the report's behaviour statements against the deterministic `pe_imports` high-signal map: a **contradiction** (the report denies a behaviour the map shows), an **uncorroborated claim** (no defining API — recorded, never gating, because that map is a curated subset rather than the full import table), corroborated absences, and specificity/observation denials. Promotion to a blocking gate was evaluated on the 56-case published corpus and **rejected on the evidence** (54/54 flags false positives; the contradiction form 11/11 specificity denials) | always on (advisory) | publish/audit quality gate | `pipeline-audit.json` checks, `quality` payload `advisory.behavior_prerequisites` |
| G21 | **Aligned deterministic report sections** (plan #12) | Six report sections appended by code, never by the LLM: **Pyramid-of-Pain tiering** folded into the IOC-confidence table (hashes → IPs → domains → network → host artifacts); **Dynamic Analysis (WinRE detonation)** with sample-launch status, window/coverage, runtime network, captured packet files, sample-process-tree file create/write rows, Frida-decoded path strings, Procmon summaries, unpack artifact + honesty flags (`static_yara_wins`, raw-memory note); **Component Inventory** (PE sections with structural roles, imports by module, overlay, entry point); **MBC Vocabulary** taken from capa's own rule metadata; **Appendix: Analysis Environment** (tool versions as reported by this run — optionally an install-time manifest at `/opt/revai/config/tool-versions.json`); **What We Don't Know** built only from structural gaps and the report's own explicit negations. Presence-gated, opt-out via `REVAI_DISABLE_*` | always on | publish (master v2 + technical v2/v3) | `REPORT-MASTER-v2.md`, `REPORT-TECHNICAL-v2/v3.md` |
| G22 | **Verifiable artifact generation** (plan #11) | The LLM authors one small, sample-specific extraction script (config extractor / static unpacker / deobfuscator) from structural evidence only; the pipeline runs it in a bounded sandbox (isolated interpreter, scrubbed env — no RevAI secrets, rlimits, timeout, network isolation when available) and then **re-derives every claimed value from the sample bytes** with its own code (`raw` / `utf16le` / `xor` / `base64` / `hex` at the claimed offset). Three anti-cheat measurements, not claims: the script must read its input argument, values hardcoded in its source are flagged, and values already visible in the generation prompt are flagged as **not independent**. Report appendix lists only re-derived values | `REVAI_ENABLE_ARTIFACT_GEN=1` | between deep_dive and yara_gen | `artifact_gen/artifact-gen.json`, `03-generated.py`, `05-verification.json`, report "Appendix: Analysis Scripts" |
| — | **angr / z3 probes** | Symbolic execution + SMT solving via `extensions/deobfuscation` | `ENABLE_DEOBFUSCATION_PASS=1` | deep_dive checklist (`z3_solve`, `angr_analyze`) | agent history + deep verdict |

## Analysis stages

| Feature | What it does | Gate | Artifact |
|---------|-------------|------|----------|
| Intake (PE/doc/script) | hashing, staging, Ghidra/IDA import (doc formats: doc_triage/olevba/peepdf), engine validation + source decisions | — | `intake-validation.json`, `source-decisions.json`, `doc-triage.json` |
| quick_scan | capa (malcat→capa-rs→Mandiant chain), yara, floss, malcat deep, pe_imports, packer, revai-tools sec/sinks; LLM verdict + v1 fallback + calibration + citation grounding | — | `verdict.json`, `00-tools-raw.json`, `prompt.txt` |
| winre_dynamic *(optional)* | FlareVM detonation between triage and the deep dive (scripted) / before the deep dive (agentic); one run ID correlates RevAI traces, WinRE status/pack, reports and audit; an explicitly requested run without a fresh matching pack fails the quality gate | `REVAI_WINRE_RUN=1` | `execution-context.json`, `winre-run.json`, deep-dive prompt, dynamic-corroboration report block |
| deep_dive (agentic) | LangGraph ReAct agent; checklist tools + SQL deep (Ghidra/IDA) + signal seeds + revai-tools sec/sinks/audit | `REVAI_AGENTIC_ENGINE=langgraph` | `05-deep-dive.json`, `agentic_deep_dive.json`, `evidence-pack.md` |
| Function recovery | Hybrid oracle/resolve-assisted naming, tiered (max-funcs/tier-cap) | `REVAI_ENABLE_AGENTIC_RECOVERY=1`, `REVAI_AGENTIC_RECOVERY_MAX_FUNCS=200`, `REVAI_AGENTIC_RECOVERY_TIER_CAP=20` | `function-recovery.json` |
| Analysis scripts (opt-in) | Generates a sample-specific extraction script, runs it sandboxed, and re-derives every claimed value from the sample bytes; independence and hardcoding are measured | `REVAI_ENABLE_ARTIFACT_GEN=1` | `artifact_gen/artifact-gen.json`, report "Appendix: Analysis Scripts" |
| Behavioural model (opt-in) | Deterministic model of what the sample does, assembled from the run's own artifacts: capabilities with provenance, the objects they act on, and the gaps | `REVAI_ENABLE_BEHAVIOURAL_MODEL=1` | `behavioural_model.json` |
| Publish v2 | Master + technical LLM reports with quality gate | — | `REPORT-v2.md`, `REPORT-MASTER-v2.md`, `REPORT-TECHNICAL-v2.md` |
| Publish v3 (sections) | Section-by-section reports with cross-section context | — | `REPORT-MASTER-v3.md`, `REPORT-TECHNICAL-v3.md`, `section-results-v3.json` |
| Audit | Independent re-check: tools_all_ok, citations grounded, engine citations, report completeness, depth coverage, verdict lock, cross-report consistency + entropy sanity | — | `pipeline-audit.json`, `AUDIT-REPORT.md`, showcase packs |

## Reliability & policy features (added in the 2026-08-09 run)

| Feature | What it fixes | Status |
|---------|--------------|--------|
| capa format routing | capa only runs on PE/ELF/Mach-O/.NET; raw/scripts/docs skip+fail-open (was aborting on `format=unknown`) | Live |
| Packed-sample policy | packer-flagged stubs: capa clean-0-rule accepted as `packed_stub`; floss/dotnet incomplete = documented soft-fail (recorded, never hidden) | Live |
| r2 UTF-8 decode | r2 output decoded with `errors=replace` (was crashing on non-UTF8 bytes) | Live |
| provider abort handling | `llm_judge` validates `finish_reason`; retries once with a longer window at the same reasoning effort, then uses a provider-supported lower effort (or disables thinking only when the endpoint documents that switch); read timeout is `REVAI_LLM_TIMEOUT` (default 300s) | Live |
| Doc-intake evidence | doc formats now write intake-validation + source-decisions stubs (was failing audit forever) | Live |
| Deep-dive packer context | checklist adds deterministic packer scan so gates share the packed policy | Live |
| Goodware fingerprint | known-good SHA short-circuit → clean verdict, skips LLM | always on |
| revai-tools wrappers | fail-open subprocess integration (`cli.py` runs from the scripts directory); error/timeout/format-mismatch recorded — never gates (was: external analysis completely absent) | Live |
| malcat_analyze body split (v2_lib) | wrapper insertion split `malcat_analyze` (stub → always None); relocated wrappers after the function; verified via `inspect.getsource` | Fixed + deployed |
| Cross-report consistency gates | deterministic master-vs-technical checks: master claiming "no dynamic analysis was performed" while the technical report carries Speakeasy/Frida execution evidence; master/technical verdict-panel mismatch — gate-failing (2026-08-12, #2 campaign) | Live |
| Entropy ground truth + sanity | Malcat's `entropy` field is not whole-file entropy — `malcat_analyze` now annotates computed whole-file Shannon bits/byte (`entropy_malcat_raw` preserves the original); report entropy citations audited against the file's measured entropy (section-scoped and appendix citations exempt) | Live |
| Report protocol repairs | bounded ungated finalize repairs (quality-repair family, not the retry contract): depth-correction re-attempts (up to 3) on empty/aborted output; master completeness nudge (1 retry, strictly-better only); deterministic dynamic-analysis negation repair in publish (only when the tools demonstrably ran; original text preserved in the report JSON) | Live |
| Section-wise technical assembly | the technical report is generated one section per LLM call with evidence routed per section, instead of one call for all 13 sections. A single call cannot hold 13 sections inside the per-request output budget: it returned truncated (`finish_reason=length`) after section 1 and scored 1 of 13 with 10 stubs. Measured on win32k_dll: 13/13 sections, `source: llm_judge`, `quality.ok=true`, 0 missing, 0 stub, 232 KB (was 97 KB), and the stage completes rc=0 in 356s instead of failing. Rollback via `REVAI_TECHNICAL_SECTIONWISE=0` | Live, run-verified |
| Streaming LLM transport | requests stream by default, logging time-to-first-token, total seconds and tokens/sec per call. A non-streaming socket carries no bytes until the response completes, so a healthy slow generation is indistinguishable from a dead one; streaming makes slow visible as slow. `REVAI_LLM_STREAM=0` restores plain POSTs | Live |
| Caller-bounded LLM timeouts | `llm_judge` accepts `timeout_s` and `budget_s`; the same-effort retry window is clamped to what remains of the caller's budget, so a stage cannot be killed by its own inner retry (artifact_gen: 600s + 1200s against a 1800s stage budget) | Live |
| Hollow-success detector | deterministic, artifact-based audit gate measuring whether artifacts contain anything, not merely whether they exist. Reads each report's own declared completeness (`source`, `sections_complete`, `sections_missing`, `sections_stub`) by discovering artifacts rather than enumerating filenames, so a new report version cannot escape the checks. No LLM call, so a check cannot be hollow in the same way | Live |
| Mode-keyed artifact paths | every artifact is written under `case_dir(sha)`, so the writer and the reader agree. A flat-path writer meant the quick-scan tool cache was never reused and capa/FLOSS re-ran on every deep dive | Live |
| Abbreviated-indicator resolution | a registry path abbreviated in prose (`HKCU\...\Run`) is resolved against a concrete evidence path under the same hive with the same trailing subkey, rather than exempted or failed. Ungrounded abbreviations and fabricated paths still fail; defender-guidance references are classified separately and reported | Live |

## Quality gates & platform features

| # | Feature | What it does | Gate | Stage | Artifact |
|---|---------|-------------|------|-------|----------|
| G23 | **First-draft claim preservation** | Published prose is not scrubbed or rewritten to hide unsupported indicators or verdict conflicts. Each draft is checked against its own run's evidence and upstream verdict lock; unsupported claims and downgrades stay visible and fail quality | always on | publish and audit | per-report `quality` and verdict-lock metadata |
| G24 | **Hollow-success detector** | The gate that decides whether a run produced a real artifact or a hollow one: report sidecars, verdict panels, verdict/label agreement, function-recovery result-vs-candidate counts, and stage-log needles. Discovers the publish sidecar instead of naming it; two reports that both parse no verdict panel now emit `verdict.panels_unreadable` rather than passing on nothing to compare; standard-path checks record `None` rather than `False` on the agentic path (`engine_path: "agentic"`), so a green agentic run is not marked false | always on | audit | `pipeline-audit.json` `stages.hollow_success` |
| G25 | **Run watchdog** (`scripts/run-watched.sh`) | Streams a run's stages, attributes each line to the stage that emitted it, classifies the first anomaly with its stage, and can abort before the budget is gone. Exit contract: `0` every stage rc=0 (non-fatal anomalies — llm-empty/429/5xx — are counted and noted, not failed) · `1` a stage failed, a fatal-class signal (stage-kill/llm-timeout) fired, or the audit found hollow output · `2` the watcher killed the run (fatal signal under `--abort-on-error`, or watch timeout) · `3` usage/environment error, including a refused start when a driver for the same sample is already live (a relaunch would quarantine the case dir out from under a running pipeline). Flags: `--sha`, `--mode`, `--abort-on-error`, `--timeout-minutes` (default 240), `--no-reboot`. When the VM has been up longer than the 600 s freshness window the script reboots and exits 0 by design — re-run the same command once SSH is back. The signal log is mode-aware: `pipeline_single.log` on scripted runs, `orchestrator.log` on agentic (the orchestrator never writes the former), with attribution falling back to the orchestrator's `TOOL run_x` lines | operator-invoked | whole run | `logs/_watched_<sha12>.log` |
| G26 | **Deterministic indicator section** | Section 8 is rendered from `iocs.json`, not authored by the model. It lists at most 40 values per category, states how many were omitted, and points to the complete run artifact; indicator values cannot be prose-invented or silently dropped. Cross-checked against G19 | always on | publish (technical v2/v3) | technical report section 8, `iocs.json` |
| G27 | **Published-artifact hygiene** | Human-facing Markdown replaces configured provider/model identifiers with `configured-llm` and masks high-confidence Telegram bot-token and GitHub personal-access-token formats. Raw tool artifacts and raw LLM call records remain available for authorized analysis; report metadata records redaction categories without storing matched secret values. Token masking covers these high-confidence formats, not every possible credential format | always on | publish + audit | `report-*.json` model-redaction and credential-category metadata |
| G28 | **Indicator-first string sampling** | FLOSS's `static_strings` category — where plain registry paths, URLs and mutexes live — was sampled LAST, so a 80-string cap consumed by higher-priority categories left it contributing nothing. `win32k_dll`'s seven real UTF-16 registry paths (including `...\Winlogon\SpecialAccounts\UserList`) never reached the prompt, and the report reconstructed them from training data. Sampling is now shape-first (registry paths, URLs, IPs, emails, file paths, `Global\`/`Local\` mutexes, script/executable names) with the drop counts recorded so a truncated indicator set is visible rather than silent. Import-table noise (`kernel32.dll`) is excluded by design — the import table records those authoritatively | `REVAI_FLOSS_MAX_STRINGS` (default 300) | quick_scan + deep_dive | `*tools-raw.json` `floss.ioc_shaped_*` |
| G29 | **pe_imports high-signal map as a case artifact** | The deterministic high-signal import map is written to the case dir (`quick_scan/pe-imports.json`) next to the other quick-scan artifacts, guarded on real signals and no error — a failed run must never look like evidence of absence. Precondition for any future promotion of G20 to a blocking gate | always on | quick_scan | `quick_scan/pe-imports.json` |
| G30 | **RE agent skills** (loaded, not recalled) | Six versioned reverse-engineering and reporting procedures: re-methodology, unpack-and-verify, obfuscation-recognition, ghidra-sql-recipes, verdict-calibration, and report-evidence-methodology. The deep-dive agent loads analysis procedures through `load_skill`; each report-writing and claim-review call receives the relevant evidence/report method. Methodology is separate from sample evidence and can never be cited as a sample finding. Each skill declares its limits. `sources.jsonl` preserves maintainer-facing attribution metadata; runtime analysis loads the bundled procedure files and does not query those source references | `load_skill` or the report methodology prompt | deep-dive and report stages | agent history, skill provenance, report prompt evidence manifest |
| G31 | **Depth mode** (opt-in, post-pipeline) | A separate run that follows the main pipeline and aims to understand HOW the sample works, not whether it is malicious. Produces a function map (`understanding.json`), never a verdict, and never gates the main pipeline. Terminates on a declared unknown set: every region carries `understood` / `partial` / not-reconstructed / not-explored with a reason and evidence citation. The ceiling consolidates rather than truncates, so a cutoff is a partial-but-honest map. State checkpoints atomically after every region for pause/resume. `REVAI_DEPTH=full` selects the **full profile** (plan #26): the same loop on the domain-node substrate (#20) — every capability domain investigated by its own bounded tool-calling node instead of one evidence-only call — with a raised ceiling, emulation/unpack/solver forced on for the investigation, a required gap section, and the Phase 0 state stream (`re-state.jsonl` + snapshot) emitted beside the map. The main pipeline's deep-dive artifacts are quarantined before a full pass so the published reports' source record survives | `REVAI_DEPTH=1` or `REVAI_DEPTH=full`, `REVAI_DEPTH_CEILING_SECONDS` (default 7200s / 14400s for full), `REVAI_DEPTH_FULL_MAX_STEPS` | after the pipeline | `understanding.json`, cost summary, `re-state.jsonl` + `re-state.json` |
| G32 | **Skills advertised on the default engine** (plan #49) | `load_skill` was bound to the LangGraph graph, but the prompt instruction naming it lived only in the *custom* engine's prompt, so on the engine that runs by default the model was never told the procedures existed -- measured as 42 agent steps, 20 tools, zero skill loads. The grounding block now has ONE definition (`skills.skill_grounding_block()`) used by both prompts, so the two engines cannot disagree about what the agent is told | `load_skill` (agent-callable) or the prompt index | deep-dive agent | agent history + skill provenance |
| G33 | **Honest depth reporting** (plan #50) | A depth run that did no analysis now says so instead of reporting an empty map: it writes `understanding.json` with an explicit `stop_reason` naming plan #20 and warns on stderr. The stage previously recorded `rc=0 ok=True` in 0.1s with no artifact -- indistinguishable in the trace from a completed run | `REVAI_DEPTH=1` | after the pipeline | `understanding.json` (`stop_reason`), stderr warning |
| G34 | **Verdict-panel reader** (plan #51) | The cross-report agreement check read one report layout and went blind on the others. Replaced an enumerated regex with a vocabulary-based extractor that matches the verdict words rather than the punctuation around them, so it reads all five layouts the two publishers emit. Prose that merely discusses verdicts still matches nothing | always on | audit quality gate | `pipeline-audit.json` `stages.hollow_success` |
| G35 | **Configurable stage timeouts** | Publish and audit timeouts are env-overridable (`REVAI_STAGE_TIMEOUT_PUBLISH` / `REVAI_STAGE_TIMEOUT_AUDIT`). Publish defaults to 14,400s (4h) after a 7,200s outer timeout left an incomplete report on a live run; audit defaults to 7,200s (2h) for sequential source-bound semantic claim review. These are outer limits, not expected runtimes. Whole-stage audit failures are not retried automatically; bounded request retries handle transient model transport failures, while a failed audit remains red with its progress recorded | 14,400s publish / 7,200s audit defaults; operator may override | publish, audit | stage trace and `publish/claim-entailment.json` |
| G36 | **CLI/UI parity** | Every feature gate an operator uses is reachable from the CLI and Console, or explicitly exempt by category. Depth mode was CLI-only (`depth_agent.py` appeared nowhere in `app.py`); `REVAI_TI_ENRICH` and `REVAI_DEPTH_CEILING_SECONDS` were absent from persisted settings. The tripwire checks feature-shaped gates | Console run-config / stage buttons | Console | `tests/test_cli_ui_parity.py` |
| G37 | **Sample and report-provenance hash classification** | The analysed sample's own SHA-256 is not counted as a separate indicator. Exact artifact digests, the report-input manifest digest, and the run ID are excluded only when they are bound to the same sample/run and each occurrence is explicitly presented as provenance; the same value remains checked if reported as a malware indicator. Only RevAI's generated execution-identity comment is omitted from IOC scanning; other comments remain visible to the checker | always on | publish/audit quality gate | `pipeline-audit.json` per-report `claimed_ioc_verification.excluded_items` and `excluded_reason_counts` |
| G38 | **Evidence-collection guidance** | The defender-guidance exemption covered inspect/clean verbs but not evidence-collection ones, so a path the report recommended *gathering data about* ("Resolution: execute the sample ... capture ... registry writes under `<path>`") was read as an assertion that the sample wrote there. Same speech act, now classified the same way. A sentence that asserts the write stays a claim and is still verified | always on | publish/audit quality gate | `pipeline-audit.json` per-report `claimed_ioc_verification.guidance_references` |
| G39 | **Capability-domain deep dive** (plan #20) | The deep dive runs as a LangGraph StateGraph with one node per capability domain (surface, persistence, C2/network, evasion, execution/injection, credential access, exfiltration, defense impairment, encryption/obfuscation) instead of one flat ReAct loop that was *asked* to self-check every domain. Each node runs under a runtime super-step ceiling sized to leave room to REACH AN ANSWER (a tighter ceiling truncates the agent mid-investigation, which is not a finding), and its actual tool spend is measured and flagged `over_budget` -- the tool budget is a request rather than a cap, because super-steps and tool calls are not the same unit; a failing node degrades to `not-reconstructed` instead of ending the dive; actual tool spend is recorded per domain. Coverage is reported as four separate facts -- visited, answered, understood, substantive -- because nine nodes visited and empty is not a dive: `complete` says every domain was investigated to a determination, `honest` additionally requires an unrecognised-status-free run with at least one substantive answer. When nothing substantive is produced the path returns falsy and the flat engine runs, so a failure can never surface as a verdict-shaped result. Opt-in via `REVAI_DOMAIN_GRAPH=1`, off by default so the flat engine stays the validated path | `REVAI_DOMAIN_GRAPH=1`, `REVAI_DOMAIN_STEP_BUDGET` (default 3) | deep_dive agent | `agentic_deep_dive.json` (`domain_graph`, `domain_findings`) |
| G40 | **Dynamic-execution evidence gate** | Full reports receive artifact-derived status for Speakeasy, RevAI's static Frida candidate probe, WinRE sample launch, WinRE runtime events, and packet captures. The cross-report gate checks claims against those component-specific facts. It keeps contradictory model prose intact and fails the report-quality gate so reviewers can see the defect; publishers do not rewrite claims after generation. The run-scoped WinRE evidence block includes the bounded detonation window and its coverage limits. | always on | publish prompt + audit quality gate | `report-v2.json` / `report-technical-v2.json` `dynamic_analysis_status`; `pipeline-audit.json` `cross_report_consistency` |
| G41 | **Run-bound, evidence-supported reporting** | Every report-writing call receives the active SHA/run/mode and a hash manifest of all report inputs, plus its section-relevant tool observations and versioned reverse-engineering method. The report gate rejects missing, stale, modified, unapproved, or cross-run inputs; requires concrete source locators on narrative claims and every factual table row; resolves citations to source-specific primary artifacts; and asks the configured model to judge whether the whole claim follows from the located evidence using a forced structured review call bound to that claim's available evidence IDs. A supported/contradicted decision must select evidence IDs that were sent for that claim; audit re-resolves the source fields and verifies the exact request/response artifacts. A selected quick/deep verdict must match every report's verdict exactly; upgrades and downgrades both fail. Missing citations, unresolved rows, unsupported claims, invalid reviews, verdict conflicts, and checker/provider errors fail closed. The first generated draft is retained for assessment: no post-generation citation-repair call can hide first-pass defects. Final report hashes bind the output to the same input manifest. The reviewer uses the same configured model, so this is evidence-constrained corroboration, not independent-provider certification. | always on | report generation + audit quality gate | `publish/report-input-manifest.json`, `publish/report-output-manifest.json`, `publish/claim-entailment.json`, report quality records, `pipeline-audit.json` |


## External integrations

| Feature | Gate | Status |
|---------|------|--------|
| **TI-enrich (VirusTotal + Hybrid Analysis hash lookup)** | `REVAI_TI_ENRICH=1` + `VT_API_KEY` + `HA_API_KEY` in `/opt/secrets/cadre.env` | Implemented; prior campaigns returned provider lookups. Credentials and provider availability are operator-configured. Enrichment never clears local gates. |
| **WinRE dynamic corroboration + optional detonation trigger** | Console Settings → **Dynamic analysis (WinRE)** (enable, FlareVM address/user/port, SSH key *path*, window, mode, snapshot gate + **Test connection**), pack root `REVAI_WINRE_LOGS` (default `/opt/winre/logs`); triggers: per-case **Run WinRE** button, run-config **Detonate with WinRE before publish** (`REVAI_WINRE_RUN`), or CLI; status at `GET /api/winre/status/<sha>` and the orchestrator's **winre dynamic** chip | Implemented and deployed; service smoke passes. Current-source sample acceptance remains pending. Master and technical prompts receive artifact-derived execution status with distinct RevAI and WinRE scopes. A current WinRE pack adds deterministic runtime evidence to the master and technical reports (sample-launch record, window + coverage caveat, network capture, runtime events, sample-process-tree file create/write rows, Frida-decoded runtime paths, and any agentic-dbg artifact). Decoded path strings are not treated as proof of file creation. Without a pack, runtime observations are omitted and WinRE execution is reported as unavailable or unverified. Contradictory claims remain visible and fail the audit. All failures are recorded (`winre-run.json`) and never block the static run. Corroboration only (`static_yara_wins`). |
| LLM (OpenRouter-compatible) | `REVAI_LLM_MODEL` / `REVAI_LLM_API_URL` / `REVAI_LLM_API_KEY` / `REVAI_LLM_REASONING` in `/opt/revai/config/llm.env` | Configured and transport-smoke-tested; current-source sample report quality remains unaccepted. |

## Historical run status (2026-08-09, 16 samples, all features on)

15/16 `all_green`. G1 9/16 · G2 2/16 · G3 7/16 · G4 2/16 · G5 9/16 · G6 11/16 ·
G7/G9/G10 16/16 · G8 11/16 · angr/z3 2/16 · recovery: named functions on 9/16
(tasksche 23, vdaudio 14, darkside 8).

## Historical run status (2026-08-11, revai-tools integration, VM-validated)

Full pipeline on guLoader.exe (REMnux VM 192.168.77.43): `v2_validate.py --smoke-only`
V2_SMOKE_OK · revai-tools tests 10/10 · quick_scan green (sec: real ASLR/DEP-missing
findings; sinks: honest 0 sites; malcat verified fixed) · deep-dive checklist 15/15
tools incl. all three revai_tools (`gate_ok=True hard_failures=[]`) · yara_gen
`iocs.json` carries the `revai_tools` provenance block.

---

## Historical run status (2026-10-05/06 sample campaign — static, both modes)

Three Windows PE samples from the RevEng corpus, each run end-to-end on **both**
the scripted and the agentic spine, on a rebooted VM with all features enabled.
Every stage `rc=0` unless noted.

| Sample | Size | scripted | agentic |
|---|---|---|---|
| SmartApeSG `client32.exe` | 104 KB | all_green | all_green |
| Kelihos `dumped.exe` | 2 MB | all_green | all_green |
| WannaCry | 3.5 MB | all_green (after the reader fix) | all_green |
| test-e2e.exe | 205 KB | n/a — MS-DOS executable, not a PE | n/a |

Feature coverage measured on those runs (not asserted): the deep dive used 21
distinct tools including `load_skill` (3, 6 and 6 references across the three
samples) and `api_lookup` (0, 10, 10); L1 steering reached `steering.json` and
the triage prompt on every run; depth mode wrote `understanding.json` with an
explicit `stop_reason` on every scripted run; the IoC verifier grounded 7 of 9
claims with 0 unverified after two fixes landed mid-campaign; publish took
1422s / 2122s / 2413s across the three sizes.

Seven defects were found by these runs and are fixed as G32-G38 above plus plans
#49-#51. A fourth sample (MS-DOS) was rejected by the tool gate with a
documented reason rather than analysed.

> **Not validated by this campaign:** L3 steering's `/api/steer` endpoint (needs
> the Console), the R1 dynamic-pack ingestion (needs WinRE), and the Console UI
> itself — the wiring is tested, no browser has exercised it.

---

## Historical run status (2026-10-12/13 sample campaign — both modes, reboot before each run)

Four samples, each on its own fresh boot, scripted and agentic spines, all
gates on. Every stage `rc=0` unless noted.

| Sample | scripted | agentic |
|---|---|---|
| wiper `12c39f05` | green — claim entailment **273 claims / 0 violations** after the circular-citation parser fix (the citation parser now reads the `, why:` tail: 3 circular citations visible as-is, 10 with the fix, all fixed at the source) | n/a (adjudication case) |
| coinminer_lolbot `1d60b82e` | green — entailment **319 / 0**; sidecars 17/17 + 13/13 + 13/13 all `source=llm_judge` | green — 8/8 stages rc=0, entailment **264 / 0**, `truly_green=True`, verdict malicious 92, 0 LLM anomalies across 75 judge calls |
| msil_crypt_dotnet `1dcf264b` | **red, then green** — audit rc=1 on a fabricated dynamic-execution claim; fixed structurally, re-run green | **red, then green** — the same claim class recurred in the v3 publisher; gate + scrub fixes landed, final re-run green (13/13 sections, `llm_judge`) |

The results above document the behavior at that time. G40 describes the current
implementation, which supplies artifact-derived execution status to the report
and leaves any contradiction visible for the quality gate to fail.

As of 2026-10-18, the post-generation indicator scrub described in this case
study has been removed from the publisher. Each report now keeps its original
unsupported claims visible and fails its own evidence gate; the historical run
results above are unchanged.

**The red is the value evidence.** The msil scripted audit failed on
`cross_report:dynamic_execution_claimed_but_none_performed` — the technical
report claimed "Frida probing (version 17.18.0) with a hook on
`mscoree.dll!_CorExeMain` ran" when the run record says only a *static* Frida
probe ran (availability + import-derived hook candidates), the emulation
oracle failed, and no detonation pack exists. Every sidecar check passed
(all `llm_judge`, complete, `quality_ok=True`); only the cross-report gate
saw it. The agentic run then produced the same class of claim in the v3
publisher (3 of 4 publish passes across both publishers fabricated it), the
gate caught it every time, and the orchestrator's recovery loop re-ran
publish on its own.

**What the loop exposed, in order** — each fix uncovered the next case:

1. The static probe's output invited the misreading (no self-label; the
   behavioral evidence line printed `Frida probe: 0 hooked calls`, a key the
   tool never produces). Fixed: the output labels itself
   (`probe_kind`/`executed`/`runtime_events`), the renderer states "static
   analysis only, no injection, no execution, no runtime events", and the
   registry description says the probe never runs the sample (G40).
2. Fixing the evidence exposed a **false positive in the gate itself**: the
   claim regex matched inside the truthful sentence "Frida instrumentation
   was **not** performed", and the negation guard only looked *backwards*.
   The guard is now negation-aware on both sides of the matched verb, with
   the context bounded to the current sentence (a negation in the previous
   sentence does not negate a claim in this one).
3. Fixing the gate left one genuine claim in v3, so the G23 pattern was
   extended to this claim class: a deterministic scrub replaces a fabricated
   dynamic-execution sentence with the run's ground truth at publish time and
   records every removal (G40). On the final pass the regenerated report was
   clean and the scrub recorded zero removals — the backstop held without
   needing to fire.
4. The scrub's first wiring crashed the v3 publisher (`NameError` at the
   master_v3 call site — a scrub record assigned to a variable that does not
   exist in that scope). No unit test of the scrub can see that; a
   source-shape tripwire now pins all four call sites and their record keys.

Also validated live in this campaign: the run watchdog found three defects in
itself by being run (the agentic signal log pointed at a file that never
existed, the exit contract mis-classified non-fatal anomalies, the attribution
regex never matched absolute paths), the fresh-boot skip and the mode-aware
signal log fired correctly on every launch, and the layout tripwire caught its
fourteenth instance in a test written the same hour.

> **Not validated by this campaign:** the scrub's replacement path is proven by
> unit tests (the final pass needed zero removals); the agentic planner skipped
> `artifact_gen` and `function_recovery` on msil (optional planner tools —
> selection varies per sample); the Console UI remains operator-driven (item
> #2); dynamic corroboration still needs WinRE.
