# Pipeline AUDIT-REPORT — `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-10T00:56:26.308405+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-10 00:56:26 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ok |
| quick_scan | ok |
| deep_dive | ok |
| yara_gen | ok |
| publish | ok |

---

_No tool retries occurred during this run._

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` model=`step-3.7-flash` verdict=`MALICIOUS` confidence=`90`
- key_evidence_count=`11`

```json
{
  "verdict": "MALICIOUS",
  "score": 90,
  "family_guess": "Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer, with capabilities consistent with DarkGate, LucaStealer, Remcos, and related info-stealing/RAT families",
  "cross_engine_notes": "Function count divergence between Ghidra (1 function) and IDA (15752 functions) is caused by heavy obfuscation (spaghetti code, control flow flattening, XOR loops) confirmed by Malcat's 77 SpaghettiFunction and 424 XorInLoop anomalies, rendering Ghidra's function count unreliable. Import counts are consistent across Ghidra (588), IDA (588), and pe_imports (571), confirming reliable import data for behavioral analysis. String counts vary widely across tools (Ghidra: 680, IDA: 15361, FLOSS: 24408) due to obfuscated and dynamically generated strings, so combining all sources improves coverage of hidden indicators. Decompilation is unreliable due to inconsistent function coverage, but Malcat's top decompilations confirm Base64 encoding/decoding, CRC32, and XOR functionality aligned with the sample's obfuscation and crypto capabilities.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055)",
      "why": "These APIs enable process injection, a technique used to execute malicious code within legitimate processes to evade detection, a clear malicious behavioral indicator."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "IsDebuggerPresent (T1622)",
      "why": "This API checks for attached debuggers, a standard anti-analysis technique used by malware to prevent reverse engineering."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "URLDownloadToFile, WinHttpOpen, InternetOpen (T1105, T1071.001)",
      "why": "These APIs allow downloading external payloads and communicating with command-and-control (C2) servers over web protocols, core capabilities for malware to receive commands and exfiltrate data."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "RegSetValue, RegCreateKeyExW (T1112)",
      "why": "These APIs modify the Windows registry to establish persistence, ensuring the malware runs automatically after system reboots, a common malicious behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "log keystrokes via polling (T1056.001)",
      "why": "This confirms the sample has keylogging functionality, used to steal user credentials, passwords, and other sensitive input."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference anti-VM strings targeting VMWare, VirtualBox (T1497.001)",
      "why": "These strings detect virtualized/sandboxed environments to avoid analysis, a deliberate anti-analysis technique used by malware to hinder detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, BlacklistSandbox, VMWare_Detection",
      "why": "These YARA rules confirm the sample has dropper functionality, heavy obfuscation, sandbox evasion, and anti-VM capabilities, all hallmarks of malicious software."
    },
    {
      "source": "malcat",
      "query_or_table": "static_
… [4691 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`14`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This 8.7MB PE sample exhibits multiple high-signal malicious indicators: YARA rules identify it as associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca-Stealer, Medusalocker, Njrat, Remcos, and Revil families. PE import analysis reveals process injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), HTTP C2 communications (WinHttpOpen, InternetOpen), download capabilities (URLDownloadToFile), registry manipulation (RegSetValue), process creation (CreateProcess, ShellExecute), dynamic API resolution (LoadLibrary, GetProcAddress), and anti-debugging (IsDebuggerPresent). capa rules confirm obfuscated stackstrings, Base64/XOR encoding, and process injection behaviors. Static strings include OpenSSL cryptographic implementations, WinHTTP/WinINET networking libraries, and an administrator-requiring manifest. FLOSS extracted 24,408 static strings. The combination of deterministic tool detections across YARA, import signals, and capa confirms malicious intent despite any masqueraded metadata. Exfiltration capabilities are not directly observed in static analysis, though HTTP C2 communication imports (WinHttpOpen, InternetOpen) identified via PE import analysis and WinHTTP/WinINET static strings are consistent with exfiltration functionality common to matched malware families, cited as {PE import analysis, import list, WinHttpOpen/InternetOpen APIs, why: these APIs enable HTTP communications to external C2 servers which are commonly used to exfiltrate stolen data}. Defense impairment capabilities are not observed, cited as {PE import analysis, import list, absence of security tool tampering/termination APIs (e.g., TerminateProcess for AV processes, firewall disable APIs), why: no observed capabilities to impair host or network security defenses}. Entry point (initial access vector) is not observed in provided static analysis, cited as {PE header analysis, PE metadata, no embedded exploit code or self-propagation mechanisms, why: the sample is a standalone PE executable with no observed capabilities to self-deploy or exploit vulnerabilities to gain initial access to a target system, requiring external delivery (e.g., user execution, dropper deployment) to run}.",
  "key_evidence": [
    "YARA matched 10+ malware families: darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil",
    "PE import signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "PE import signals: WinHttpOpen, InternetOpen (HTTP C2 T1071.001)",
    "PE import signals: URLDownloadToFile (download T1105)",
    "PE import signals: RegSetValue (registry persistence T1112)",
    "PE import signals: CreateProcess, ShellExecute (process execution T1106)",
    "PE import signals: LoadLibrary, GetProcAddress (dynamic resolution T1129)",
    "PE import signals: IsDebuggerPresent (anti-debug T1622)",
    "capa rules: obfuscated stackstrings, Base64 encoding, XOR encoding, process injection",
    "Ghidra strings: WinHttpOpenRequest, HttpSendRequestW, WinHttpReadData (HTTP client stack)",
    "Ghidra strings: manifest requiresAdministrator execution level",
    "Ghidra strings: OpenSSL crypto implementations (AES, SHA1/256/512, Montgomery, GHASH)",
    "FLOSS: 24,408 static strings extracted",
    "IDA imports: ADVAPI32 Crypt* AP
… [1275 more chars]
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: SHA256 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 \u2014 Multi-Functional Info-Stealer/Loader Masquerading as Tencent GameLoop Installer",
  "mark": "# Malware Analysis Report: SHA256 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 \u2014 Multi-Functional Info-Stealer/Loader Masquerading as Tencent GameLoop Installer\n\n## Executive Summary\nThis report analyzes a malicious PE32 x86 executable (SHA256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6) masquerading as a legitimate Tencent GameLoop Android emulator installer. Upstream triage assigns a MALICIOUS verdict with 90% confidence, identifying the sample as a multi-functional info-stealer/loader with capabilities consistent with 10+ malware families including DarkGate, LucaStealer, Remcos, and Revil. Static and deterministic behavioral analysis confirm high-signal malicious capabilities including process injection, anti-debug/anti-VM evasion, HTTP command-and-control (C2) communication, registry persistence, and keylogging. The sample uses extensive obfuscation (API hashing, XOR, Base64, control flow flattening) and carries an expired DigiCert code signing certificate to masquerade as legitimate software. No runtime sandbox (Speakeasy/Frida) data is available, so all behavioral claims are derived from static analysis tools (capa, YARA, Malcat, PE import analysis). (source: triage_verdict.json, verdict, MALICIOUS, 90 confidence)\n\n## 1. Sample Identification\nThe analyzed sample is a PE32 x86 executable with a file size of 8.7MB, collected on 2026-07-03 as part of the \"pool\" project, stored at /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil. Malcat analysis confirms the file type as PE x86 with a SHA256 matching the provided hash. The sample is signed with a DigiCert code signing certificate that was valid from 2020-11-25 to 2024-02-22, which expired 2+ years before the sample collection date, indicating an invalid signature commonly associated with trojanized legitimate software. (source: malcat, static_profile, File: type=PE, architecture=X86, entropy=157, sha256=7fbde4a...; malcat, static_profile, Certificate::Validity (2020-11-25 to 2024-02-22), expired before collection date)\n\n## 2. Classification\nVerdict: MALICIOUS. Confidence: 90%. Classification: Trojanized installer / modular info-stealer and RAT loader. The sample is not a member of a single malware family, but rather a multi-functional loader that bundles or emulates capabilities from 10+ distinct malware families, as confirmed by YARA matches for DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca-Stealer, Medusalocker, Njrat, Remcos, and Revil. It masquerades as a Tencent GameLoop installer to trick users into executing malicious code. (source: triage_verdict.json, verdict, MALICIOUS, family_guess: Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer; deep_dive.json, key_evidence, YARA matched 10+ malware families: darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil)\n\n## 3. Background & Family Lineage\nThe sample's association with 10+ malware families indicates it is either a modular loader designed to deliver multiple payloads or a \"Frankenstein\" malware that combines c
… [65654 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 04:30:16 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALICIOUS |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer, with capabilities consistent with DarkGate, LucaStealer, Remcos, and related info-stealing/RAT families
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: SHA256 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 — Multi-Functional Info-Stealer/Loader Masquerading as Tencent GameLoop Installer

## Executive Summary
This report analyzes a malicious PE32 x86 executable (SHA256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6) masquerading as a legitimate Tencent GameLoop Android emulator installer. Upstream triage assigns a MALICIOUS verdict with 90% confidence, identifying the sample as a multi-functional info-stealer/loader with capabilities consistent with 10+ malware families including DarkGate, LucaStealer, Remcos, and Revil. Static and deterministic behavioral analysis confirm high-signal malicious capabilities including process injection, anti-debug/anti-VM evasion, HTTP command-and-control (C2) communication, registry persistence, and keylogging. The sample uses extensive obfuscation (API hashing, XOR, Base64, control flow flattening) and carries an expired DigiCert code signing certificate to masquerade as legitimate software. No runtime sandbox (Speakeasy/Frida) data is available, so all behavioral claims are derived from static analysis tools (capa, YARA, Malcat, PE import analysis). (source: triage_verdict.json, verdict, MALICIOUS, 90 confidence)

## 1. Sample Identification
The analyzed sample i
… [30806 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 04:44:24 UTC

# RE Report — 7fbde4a47c91
_Generated 2026-08-08T04:44:24.163892+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=412c | cross_refs=True | llm_ok=True | runtime=24.72s -->

# Executive Summary
| Attribute | Value | Confidence |
|-----------|-------|------------|
| Final Verdict | Malicious | High (90/100) |
| Family Classification | Multi-functional info-stealer/loader with capability alignment to DarkGate, LucaStealer, and Remcos | High |
| Sample Type | 32-bit Windows PE executable | High |
| Lure Masquerade | Tencent GameLoop (gaming emulator) installer | High |
| Detection Consensus | Full agreement between LLM analysis pipeline and v1 detection engine | High |

This sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`) is a high-confidence malicious multi-functional info-stealer and loader that masquerades as a legitimate Tencent GameLoop gaming emulator installer. It exhibits capabilities consistent with established info-stealing and remote access tool (RAT) families including DarkGate, LucaStealer, and Remcos, and is assessed to be deployed by unaffiliated cybercrime threat actors targeting consumer and gaming endpoints.

The malicious verdict is supported by full consensus between the LLM analysis pipeline and v1 detection engine, with the v1 engine identifying 61 YARA rule matches and 154 capa capability rule matches to corroborate the classification (source: cross-section:classification, cross-section:v1_summary). Static analysis confirms the sample is a structurally valid 32-bit Windows PE with intact standard headers, and imports native Windows libraries (winhttp, advapi32, netapi32) that provide documented functionality for network communication, system configuration changes, and command execution common to offensive tooling (source: cross-section:static_analysis, cross-section:sample_identifiers). Capa rule matching confirms the sample implements extensive obfuscation including stackstring encoding, XOR, TEA, AES, and RC4 encryption to evade static detection, alongside confirmed info-stealing capabilities including polling-based keylogging, credential harvesting, and data 
… [52534 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `8191` | `1638927beb58cdb4` |
| `prompt.txt` | `True` | `37437` | `c50b559c0d019063` |
| `pipeline-audit.json` | `True` | `115125` | `2f2357c06c9659d0` |
| `AUDIT-REPORT.md` | `True` | `86535` | `6353f00ca2594bc0` |
| `REPORT-MASTER-v2.md` | `True` | `33328` | `54ab8ad74553668f` |
| `REPORT-MASTER-v3.md` | `True` | `55047` | `d13c3e9018c2e810` |
| `REPORT-v2.md` | `True` | `33328` | `54ab8ad74553668f` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `90578` | `d30fc9390716384e` |
| `rule.yar` | `True` | `1366` | `13c7c75e2a3a965b` |
| `intake-validation.json` | `True` | `3598` | `e84aaf2dccb1191b` |
| `source-decisions.json` | `True` | `2612` | `ab79ba5a690cadbf` |
| `malcat-triage.json` | `True` | `1260601` | `749acb0ab1b2b1a8` |
| `deep_dive/01-tools-raw.json` | `True` | `1481365` | `59684b60899c3b3a` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4775` | `09f3925d60857c93` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `1473038` | `2cfb6a364f10d55b` |

---

## Stage: intake

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| intake_validation | `True` |
| has_source_decisions | `True` |
| ghidra_mentioned | `True` |

### Artifact paths (verify on disk)

- **intake_validation:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-validation.json` exists=`True` bytes=`3598` mtime=`2026-08-08T04:13:02.353684+00:00`
  - sha256: `e84aaf2dccb1191b14401d8acb79ddbc0ff985d0bc4f6cb9515d6891c9436aff`
- **malcat_triage:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/malcat-triage.json` exists=`True` bytes=`1260601` mtime=`2026-08-08T04:11:55.734666+00:00`
  - sha256: `749acb0ab1b2b1a80d2ca1c5800959baabecac1b66ffc805d50996b6ba97c853`
- **source_decisions:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/source-decisions.json` exists=`True` bytes=`2612` mtime=`2026-08-08T04:13:02.353684+00:00`
  - sha256: `ab79ba5a690cadbf0771a0319b27af4433563243d5511b6369cf57daef16dba3`
- **ghidra_import_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-analyzeHeadless.log` exists=`True` bytes=`9513` mtime=`2026-08-04T07:30:54.251816+00:00`
  - sha256: `e0565a27e0f4f0062a2bec9cfcfcd0c89ff5705e502e5b9556a5ad5a39c71832`
- **ida_bootstrap_log:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/intake-idasql.log` exists=`True` bytes=`342` mtime=`2026-08-08T04:12:11.304723+00:00`
  - sha256: `982912f36d8f29d09f9bcf26fcb1dbed93bf51d22ec06dc4d2d2cd6f2aea4570`

#### source_decisions_excerpt

```
{
  "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "Ghidra and IDA both report 588 imports (exact match) [{ghidra, imports, 588, independent tool count}, {ida, imports, 588, matches Ghidra count}], while Malcat reports 8334 imports [{malcat, imports_count, 8334, diverges significantly from Ghidra/IDA}]; matching counts from two independent tools make Ghidra the reliable source for imports."
  },
  "functions": {
    "source": "review",
    "confidence": "medium",
    "reason": "Ghidra reports 1 function [{ghidra, funcs, 1, low function count}] while IDA reports 15752 functions [{ida, funcs, 15752, high function count}], a divergence of ~15752x (ratio 0.00) [{warning, Function cou
… [1835 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "profile": "triage",
  "limits": {
    "strings_max": 100,
    "imports_max": 100,
    "functions_max": 10,
    "anomaly_locations_max": 5,
    "decompile_top_n": 1
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gl
… [1259801 more chars]
```


---

## Stage: quick_scan

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| prompt | `True` |
| verdict | `True` |
| has_capa_section | `True` |
| has_yara_section | `True` |
| has_malcat_section | `True` |
| has_floss_section | `True` |
| verdict_has_family | `True` |
| llm_source | `True` |
| tools_all_ok | `True` |
| citations_grounded | `True` |
| capa_salvage_used | `False` |
| evidence_pack_present | `True` |
| benign_blocked_if_incomplete | `True` |
| yara_family_not_cleared | `True` |

### Tools (full evidence excerpts)

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 154,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Indicator Removal from Tools",
          "id": "T1027.005"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Argument Obfuscation"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Argument Obfuscation",
          "id": "B0032.020"
        },
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Stack Strings"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Stack Strings",
          "id": "B0032.017"
        }
      ]
    },
    {
      "name": "encode data using Base64",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encoding-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encoding-Standard Algorithm",
          "id": "E1027.m02"
        },
        {
          "parts": [
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference Base64 string",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
        }
      ]
    },
    {
      "name": "encode data using XOR",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
    
… [9486 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3329364,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 60881,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a",
          "offset": 10010,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a1",
          "offset": 3791656,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a0",
          "offset": 5752647,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 3751138,
          "length": 52,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 3621820,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 5086696,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Obfuscated_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gla
… [15310 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "d$l_^[]",
    "#L$(#T$,",
    "D7q/;M",
    "SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    ")QZ^&1",
    "\\$ 3D$",
    "\\$43D$03\\$8",
    "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "T`00P`00P",
    "V++}V++}",
    "L&&jL&&jl66Zl66Z~??A~??A",
    "Oh44\\h44\\Q",
    "sb11Sb11S*",
    "RF##eF##e",
    "&N''iN''i",
    "X,,tX,,t4",
    "v;;Mv;;M",
    "R)){R)){",
    ">^//q^//q",
    ",@  `@  `",
    "r99Kr99K",
    "f33Uf33U",
    "x<<Dx<<D%",
    "p88Hp88H",
    "uB!!cB!!c",
    "z==Gz==G",
    "D\"\"fD\"\"fT**~T**~;",
    ";d22Vd22Vt::Nt::N",
    "H$$lH$$l",
    "Cn77Yn77Y",
    "J%%oJ%%o\\..r\\..r8",
    "|>>B|>>Bq",
    "j55_j55_",
    "P((xP((x",
    "Z--wZ--w",
    "P~AeS~AeS",
    "pHhXpHhX",
    "lZrNlZrN",
    "6-9'6-9'",
    "$6.:$6.:",
    "ZwKiZwKi",
    "T~FbT~Fb",
    "*?#1*?#1",
    ">8$4,8$4,",
    "pHl\\tHl\\t",
    "AES for x86, CRYPTOGAMS by <appro@openssl.org>",
    "%33331",
    "*p[[[[[[[[[[[[[[[[",
    "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)",
    "d$0_^[]",
    "d$P_^[]",
    "d$t_^[]",
    "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>",
    "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>",
    "D$$j@P",
    "D$ j@P",
    "D$ _^[",
    ";E$rjw",
    "t]VPQj",
    "!!\"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%&&&&&&&",
    "!<!u3j",
    "L$<JRWP",
    "L$L_^3",
    "QPVQSPV",
    "D$ PVVV",
    "LWPWSj",
    "QSVWh$*"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 24408
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.15,
  "size_bytes": 8701567,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
    "decompile_top_n": 3
  },
  "file_summary": {
    "analysis_id": 1,
    "file_name": "2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "file_size": 8701567,
    "type": "PE",
    "architecture": "X86",
    "entropy": 157,
    "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
    "metadata": {
      "Certificate::Issuer": "DigiCert SHA2 Assured ID Code Signing CA (Organization=DigiCert Inc / Unit=www.digicert.com / Country=US)",
      "Certificate::Subject": "Tencent Technology(Shenzhen) Company Limited",
      "Certificate::Org Details": "Tencent Technology(Shenzhen) Company Limited / Unit=? / State=Guangdong Province / Locality=Shenzhen / Country=CN / Email=?",
      "Certificate::Validity": "from 2020-11-25 to 2024-02-22",
      "Certificate::SerialNumber": "0ea7f686bc40354a70f2c297c1315ef6",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "VersionInfo::CompanyName": "Tencent",
      "VersionInfo::FileDescription": "GameLoop - Install",
      "VersionInfo::FileVersion": "3.71.3146.81",
      "VersionInfo::InternalName": "GameDownload",
      "VersionInfo::LegalCopyright": "Copyright \u00a9 2020 Tencent. All Rights Reserved.",
      "VersionInfo::OriginalFilename": "GameDownload.exe",
      "VersionInfo::ProductName": "GameLoop",
      "VersionInfo::ProductVersion": "3,71,3146,81",
      "Exports::Module name": "GameDownload.exe",
      "Exports::Exports date": "2024-02-21 13:07:09",
      "Debug::Date.Debug.Codeview": "2024-02-21 13:07:34",
      "Debug::Path": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "Debug::Date.Debug.VcFeature": "2024-02-21 13:07:34",
      "Debug::Date.Debug.Pogo": "2024-02-21 13:07:34",
      "Debug::Date.Debug.Iltcg": "2024-02-21 13:07:34"
    },
    "entrypoint_ea": 2081293,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 129
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 3291648,
        "virtual_size": 3293184,
        "rights": "RX",
        "entropy": 137
      },
      {
        "name": ".rdata",
        "effective_address": 3294208,
        "physical_size": 810496,
        "virtual_size": 811008,
        "rights": "R",
        "entropy": 83
      },
      {
        "name": ".data",
        "effective_address": 4105216,
        "physical_size": 74240,
        "virtual_size": 102400,
        "rights": "RW",
        "entropy": 93
      },
      {
        "name": ".gfids",
        "effective_address": 4207616,
        "physical_size": 3584,
 
… [1318798 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055) high-signal imports These APIs enable process injection, a ",
    "IsDebuggerPresent (T1622) high-signal imports This API checks for attached debuggers, a standard anti-analysis technique",
    "URLDownloadToFile, WinHttpOpen, InternetOpen (T1105, T1071.001) high-signal imports These APIs allow downloading externa",
    "RegSetValue, RegCreateKeyExW (T1112) high-signal imports These APIs modify the Windows registry to establish persistence",
    "log keystrokes via polling (T1056.001) top_rules This confirms the sample has keylogging functionality, used to steal us"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "MALICIOUS",
  "family": "Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer, with capabilities consistent with DarkGate, LucaStealer, Remcos, and related info-stealing/RAT families",
  "score": 90,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "VirtualAllocEx, WriteProcessMemory, SetThreadContext (T1055)",
      "why": "These APIs enable process injection, a technique used to execute malicious code within legitimate processes to evade detection, a clear malicious behavioral indicator."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "IsDebuggerPresent (T1622)",
      "why": "This API checks for attached debuggers, a standard anti-analysis technique used by malware to prevent reverse engineering."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "URLDownloadToFile, WinHttpOpen, InternetOpen (T1105, T1071.001)",
      "why": "These APIs allow downloading external payloads and communicating with command-and-control (C2) servers over web protocols, core capabilities for malware to receive commands and exfiltrate data."
    },
    {
      "source": "pe_imports",
      "query_or_table": "high-signal imports",
      "row_or_rule": "RegSetValue, RegCreateKeyExW (T1112)",
      "why": "These APIs modify the Windows registry to establish persistence, ensuring the malware runs automatically after system reboots, a common malicious behavior."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "log keystrokes via polling (T1056.001)",
      "why": "This confirms the sample has keylogging functionality, used to steal user credentials, passwords, and other sensitive input."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row_or_rule": "reference anti-VM strings targeting VMWare, VirtualBox (T1497.001)",
      "why": "These strings detect virtualized/sandboxed environments to avoid analysis, a deliberate anti-analysis technique used by malware to hinder detection."
    },
    {
      "source": "yara",
      "query_or_table": "matches",
      "row_or_rule": "Dropper_Strings, Obfuscated_Strings, BlacklistSandbox, VMWare_Detection",
      "why": "These YARA rules confirm the sample has dropper functionality, heavy obfuscation, sandbox evasion, and anti-VM capabilities, all hallmarks of malicious software."
    },
    {
      "source": "malcat",
      "query_or_table": "static_profile",
      "row_or_rule": "Certificate::Validity (2020-11-25 to 2024-02-22)",
      "why": "The code signing certificate expired before the sample collection date (2026-07-03), indicating the signature is invalid, a common trait of trojanized legitimate software."
    },
    {
      "source": "malcat",
      "query_or_table": "anomalies",
      "row_or_rule": "DownloaderApiUsage\u00d718, ImportByHash\u00d76, XorInLoop\u00d7424, SpaghettiFunction\u00d777",
      "why": "These anomalies confirm the sample has downloader functionality, uses API hashing to hide malicious imports, and employs heavy obfuscation (XOR, control flow flattening) to evade static analysis, all common malware techniques."
    },
    {
      "source": "malcat",
      "query_or_table": "strings/registry",
      "row_or_rule": "SOFTWARE\\Tencent..\\LoginStatusInfo, Software\\Tencent..ePC\\InstallFlags, Software\\Tencent..GamePC\\AppMarket",
      "why": "These registry strings are associated with Tencent's GameLoop Android emulator, confirming the sample masquerades as legitimate Tencent software to avoid user suspicion."
    },
    {
      "source": "malcat",
      "query_or_table": "decompilations",
      "row_or_rule": "sub_6b63e0 (Base64 encode), sub_65e730 (Base64 decode)",
      "why": "These decompiled functions confirm the sample uses Base64 encoding/decoding for obfuscation or data communication, aligned with capa's T1027 obfuscation detection."
    }
  ],
  "summary": "This is a malicious PE32 x86 binary masquerading as a legitimate Tencent GameLoop installer, signed with an expired DigiCert certificate. Static analysis reveals extensive malicious capabilities including process injection (T1055), anti-debug (T1622), anti-VM/sandbox evasion (T1497.001), download and C2 communication (T1105, T1071.001), registry persistence (T1112), keylogging (T1056.001), and hea"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/prompt.txt` exists=`True` bytes=`37437` mtime=`2026-08-08T04:16:11.003858+00:00`
  - sha256: `c50b559c0d01906342cfe410c2a2e37dadbc2719f44d20660a383a258628b029`
- **verdict:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/verdict.json` exists=`True` bytes=`8191` mtime=`2026-08-08T04:17:22.831980+00:00`
  - sha256: `1638927beb58cdb4cc91a0725805d6b791898795a17f3179cae2757fc8578a60`

#### prompt_excerpt

```
# Triage evidence
sha256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
sample_path: /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil
ghidra_session: ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
ida_session: ida-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — Ghidra and IDA both report 588 imports (exact match) [{ghidra, imports, 588, independent tool count}, {ida, imports, 588, matches Ghidra count}], while Malcat reports 8334 imports [{malcat, imports_count, 8334, diverges significantly from Ghidra/IDA}]; matching counts from two independent tools make Ghidra the reliable source for imports.
- functions: review (confidence=medium) — Ghidra reports 1 function [{ghi
… [36354 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "MALICIOUS",
  "score": 90,
  "family_guess": "Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer, with capabilities consistent with DarkGate, LucaStealer, Remcos, and related info-stealing/RAT families",
  "cross_engine_notes": "Function count divergence between Ghidra (1 function) and IDA (15752 functions) is caused by heavy obfuscation (spaghetti code, control flow flattening, XOR loops) confirmed by Malcat's 77 SpaghettiFunction and 424 XorInLoop anomalies, rendering Ghidra's function count unreliable. Import counts are consistent across Ghidra (588), IDA (588), and pe_imports (571), confirming reliable import data for behavioral analysis. String counts vary widely across tools (Ghidra: 680, IDA: 15361, FLOSS: 24408) due to obfuscated and dynamically generated strings, so combining all sources improves coverage of hidden indicators. Decompilation is unreliable due to inconsistent function coverage, but Malcat's top decompilations confirm 
… [7191 more chars]
```


---

## Stage: deep_dive

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| 01_tools_raw | `True` |
| 00_sql_evidence | `False` |
| 03_prompt | `False` |
| 04_llm | `False` |
| 05_deep | `True` |
| tools_all_ok | `True` |
| llm_source | `False` |
| citations_grounded | `True` |
| engine_citation_ok | `True` |
| upx_second_pass_ok | `True` |
| no_incomplete_tooling | `True` |
| confidence_sane | `True` |
| evidence_pack_present | `True` |
| depth_coverage | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |
| agentic_confidence_sane | `True` |

### Tools (full evidence excerpts)

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 154,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "Indicator Removal from Tools",
          "id": "T1027.005"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Argument Obfuscation"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Argument Obfuscation",
          "id": "B0032.020"
        },
        {
          "parts": [
            "Anti-Static Analysis",
            "Executable Code Obfuscation",
            "Stack Strings"
          ],
          "objective": "Anti-Static Analysis",
          "behavior": "Executable Code Obfuscation",
          "method": "Stack Strings",
          "id": "B0032.017"
        }
      ]
    },
    {
      "name": "encode data using Base64",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Encoding-Standard Algorithm"
          ],
          "objective": "Defense Evasion",
          "behavior": "Obfuscated Files or Information",
          "method": "Encoding-Standard Algorithm",
          "id": "E1027.m02"
        },
        {
          "parts": [
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        }
      ]
    },
    {
      "name": "reference Base64 string",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Encode Data",
            "Base64"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "Base64",
          "id": "C0026.001"
        },
        {
          "parts": [
            "Data",
            "Check String"
          ],
          "objective": "Data",
          "behavior": "Check String",
          "method": "",
          "id": "C0019"
        }
      ]
    },
    {
      "name": "encode data using XOR",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique": "",
          "id": "T1027"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
    
… [9485 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.05,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "set_thread_context",
      "api_match": "SetThreadContext",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
      ]
    },
    {
      "label": "http_client",
      "api_match": "InternetOpen",
      "attack": [
        "T1071.001"
      ]
    },
    {
      "label": "winhttp_client",
      "api_match": "WinHttpOpen",
      "attack": [
        "T1071.001"
      ]
    },
    {
      "label": "download_file",
      "api_match": "URLDownloadToFile",
      "attack": [
        "T1105"
      ]
    },
    {
      "label": "set_registry_value",
      "api_match": "RegSetValue",
      "attack": [
        "T1112"
      ]
    },
    {
      "label": "create_process",
      "api_match": "CreateProcess",
      "attack": [
        "T1106"
      ]
    },
    {
      "label": "shell_execute",
      "api_match": "ShellExecute",
      "attack": [
        "T1106"
      ]
    },
    {
      "label": "load_library",
      "api_match": "LoadLibrary",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "get_proc_address",
      "api_match": "GetProcAddress",
      "attack": [
        "T1129"
      ]
    },
    {
      "label": "change_memory_protection",
      "api_match": "VirtualProtect",
      "attack": [
        "T1055"
      ]
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3329364,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 60881,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a",
          "offset": 10010,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": []
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a1",
          "offset": 3791656,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$a0",
          "offset": 5752647,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$a1",
          "offset": 3751138,
          "length": 52,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 3621820,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 5086696,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Obfuscated_Strings",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_gla
… [15288 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    "d$l_^[]",
    "#L$(#T$,",
    "D7q/;M",
    "SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>",
    ")QZ^&1",
    "\\$ 3D$",
    "\\$43D$03\\$8",
    "GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "T`00P`00P",
    "V++}V++}",
    "L&&jL&&jl66Zl66Z~??A~??A",
    "Oh44\\h44\\Q",
    "sb11Sb11S*",
    "RF##eF##e",
    "&N''iN''i",
    "X,,tX,,t4",
    "v;;Mv;;M",
    "R)){R)){",
    ">^//q^//q",
    ",@  `@  `",
    "r99Kr99K",
    "f33Uf33U",
    "x<<Dx<<D%",
    "p88Hp88H",
    "uB!!cB!!c",
    "z==Gz==G",
    "D\"\"fD\"\"fT**~T**~;",
    ";d22Vd22Vt::Nt::N",
    "H$$lH$$l",
    "Cn77Yn77Y",
    "J%%oJ%%o\\..r\\..r8",
    "|>>B|>>Bq",
    "j55_j55_",
    "P((xP((x",
    "Z--wZ--w",
    "P~AeS~AeS",
    "pHhXpHhX",
    "lZrNlZrN",
    "6-9'6-9'",
    "$6.:$6.:",
    "ZwKiZwKi",
    "T~FbT~Fb",
    "*?#1*?#1",
    ">8$4,8$4,",
    "pHl\\tHl\\t",
    "AES for x86, CRYPTOGAMS by <appro@openssl.org>",
    "%33331",
    "*p[[[[[[[[[[[[[[[[",
    "Vector Permutation AES for x86/SSSE3, Mike Hamburg (Stanford University)",
    "d$0_^[]",
    "d$P_^[]",
    "d$t_^[]",
    "AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>",
    "GHASH for x86, CRYPTOGAMS by <appro@openssl.org>",
    "D$$j@P",
    "D$ j@P",
    "D$ _^[",
    ";E$rjw",
    "t]VPQj",
    "!!\"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%&&&&&&&",
    "!<!u3j",
    "L$<JRWP",
    "L$L_^3",
    "QPVQSPV",
    "D$ PVVV",
    "LWPWSj",
    "QSVWh$*"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 24408
  },
  "raw_key_total": 3,
  "floss_profile": "static",
  "floss_language": "none",
  "duration_s": 181.12,
  "size_bytes": 8701567,
  "static_only": true,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `dotnet` — ok=`True` why=`ok`

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

#### `r2_decomp` — ok=`True` why=`ok`

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "disassembly": {
    "0x00487740": "; CALL XREF from entry0 @ 0x4898fa(x)\n\u250c 10: fcn.00487740 ();\n\u2502           0x00487740      50             push eax\n\u2502           0x00487741      60             pushal\n\u2502           0x00487742      e8edffffff     call fcn.00487734\n\u2514           0x00487747      c20400         ret 4",
    "0x00487734": "; CALL XREF from fcn.00487740 @ 0x487742(x)\n\u250c 12: fcn.00487734 (int32_t arg_4h);\n\u2502           ; arg int32_t arg_4h @ esp+0x8\n\u2502           0x00487734      50             push eax\n\u2502           0x00487735      8b442404       mov eax, dword [arg_4h]\n\u2502           0x00487739      83c004         add eax, 4\n\u2502           0x0048773c      50             push eax\n\u2514           0x0048773d      c20800         ret 8",
    "0x0056c730": "; XREFS: CALL 0x0056ccdf  CALL 0x0056d2bb  CALL 0x0056e282  \n            ; XREFS: CALL 0x0056e2ef  CALL 0x0056e3e5  CALL 0x0056e55c  \n            ; XREFS: CALL 0x00571d62  \n\u250c 397: fcn.0056c730 (int32_t arg_8h, int32_t arg_ch);\n\u2502           ; arg int32_t arg_8h @ ebp+0x8\n\u2502           ; arg int32_t arg_ch @ ebp+0xc\n\u2502           ; var int32_t var_4h @ ebp-0x4\n\u2502           ; var int32_t var_8h @ ebp-0x8\n\u2502           ; var int32_t var_ch @ ebp-0xc\n\u2502           0x0056c730      55             push ebp\n\u2502           0x0056c731      8bec           mov ebp, esp\n\u2502           0x0056c733      83ec0c         sub esp, 0xc\n\u2502           0x0056c736      53             push ebx\n\u2502           0x0056c737      8b5d08         mov ebx, dword [arg_8h]\n\u2502           0x0056c73a      57             push edi\n\u2502           0x0056c73b      8b4308         mov eax, dword [ebx + 8]\n\u2502           0x0056c73e      8dbba48e0000   lea edi, [ebx + 0x8ea4]\n\u2502           0x0056c744      8945fc         mov dword [var_4h], eax\n\u2502           0x0056c747      85c0           test eax, eax\n\u2502       \u250c\u2500< 0x0056c749      0f8468010000   je 0x56c8b7\n\u2502       \u2502   0x0056c74f      837d0c00       cmp dword [arg_ch], 0\n\u2502       \u2502   0x0056c753      56             push esi\n\u2502      \u250c\u2500\u2500< 0x0056c754      7572           jne 0x56c7c8\n\u2502      \u2502\u2502   0x0056c756      833f00         cmp dword [edi], 0\n\u2502     \u250c\u2500\u2500\u2500< 0x0056c759      750a           jne 0x56c765\n\u2502     \u2502\u2502\u2502   0x0056c75b      837f0400       cmp dword [edi + 4], 0\n\u2502    \u250c\u2500\u2500\u2500\u2500< 0x0056c75f      0f8451010000   je 0x56c8b6\n\u2502    \u2502\u2514\u2500\u2500\u2500> 0x0056c765      8bb3c48e0000   mov esi, dword [ebx + 0x8ec4]\n\u2502    \u2502 \u2502\u2502   0x0056c76b      8d4858         lea ecx, [eax + 0x58]\n\u2502    \u2502 \u2502\u2502   0x0056c76e      51             push ecx\n\u2502    \u2502 \u2502\u2502   0x0056c76f      8d83ac8e0000   lea eax, [ebx + 0x8eac]\n\u2502    \u2502 \u2502\u2502   0x0056c775      50             push eax\n\u2502    \u2502 \u2502\u2502   0x0056c776      ff31           push dword [ecx]\n\u2502    \u2502 \u2502\u2502   0x0056c778      e8b3ef0000     call 0x57b730\n\u2502    \u2502 \u2502\u2502   0x0056c77d      83c40c         add esp, 0xc\n\u250
… [1649 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "candidates": [
    "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r",
    "Found XOR 00 position 004CBD20: 00000100 ........!..L.!This program cannot be r",
    "Found XOR 00 position 00572860: 000000D0 ........!..L.!This program cannot be r",
    "Found XOR C5 position 008394BC: 000000F8 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r\nFound XOR 00 position 004CBD20: 00000100 ........!..L.!This program cannot be r\nFound XOR 00 position 00572860: 000000D0 ........!..L.!This program cannot be r\nFound XOR C5 position 008394BC: 000000F8 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

#### `frida_probe` — ok=`True` why=`ok`

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!GetFileVersionInfoW",
      "VERSION.dll!VerQueryValueW",
      "VERSION.dll!GetFileVersionInfoSizeW",
      "PSAPI.DLL!GetModuleFileNameExW",
      "WS2_32.dll!WSAStartup",
      "WS2_32.dll!shutdown",
      "WS2_32.dll!getaddrinfo",
      "WS2_32.dll!socket",
      "WS2_32.dll!connect",
      "IMM32.dll!ImmDisableIME",
      "KERNEL32.dll!UnhandledExceptionFilter",
      "KERNEL32.dll!GetCurrentProcess",
      "KERNEL32.dll!DeviceIoControl",
      "KERNEL32.dll!GetDiskFreeSpaceExW",
      "KERNEL32.dll!GetLogicalDrives",
      "USER32.dll!CreateWindowExA",
      "USER32.dll!RegisterClassExA",
      "USER32.dll!DefWindowProcW",
      "USER32.dll!DestroyWindow",
      "USER32.dll!ReleaseDC",
      "GDI32.dll!MoveToEx",
      "GDI32.dll!CreateSolidBrush",
      "GDI32.dll!LineTo",
      "GDI32.dll!OffsetRgn",
      "GDI32.dll!Rectangle",
      "ADVAPI32.dll!RegDeleteValueW",
      "ADVAPI32.dll!CloseServiceHandle",
      "ADVAPI32.dll!ControlService",
      "ADVAPI32.dll!ReportEventA",
      "ADVAPI32.dll!RegisterEventSourceA"
    ]
  }
}
```

#### `frida_trace` — ok=`True` why=`not_applicable:pe`

```json

```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 14,
  "hits": 14,
  "misses": [],
  "hit_examples": [
    "YARA matched 10+ malware families: darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, r",
    "PE import signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "PE import signals: WinHttpOpen, InternetOpen (HTTP C2 T1071.001)",
    "PE import signals: URLDownloadToFile (download T1105)",
    "PE import signals: RegSetValue (registry persistence T1112)"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This 8.7MB PE sample exhibits multiple high-signal malicious indicators: YARA rules identify it as associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca-Stealer, Medusalocker, Njrat, Remcos, and Revil families. PE import analysis reveals process injection APIs (VirtualAllocEx, WriteP",
  "key_evidence": [
    "YARA matched 10+ malware families: darkgate, elex, floxif, glassworm, hijackloader, luca-stealer, medusalocker, njrat, remcos, revil",
    "PE import signals: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)",
    "PE import signals: WinHttpOpen, InternetOpen (HTTP C2 T1071.001)",
    "PE import signals: URLDownloadToFile (download T1105)",
    "PE import signals: RegSetValue (registry persistence T1112)",
    "PE import signals: CreateProcess, ShellExecute (process execution T1106)",
    "PE import signals: LoadLibrary, GetProcAddress (dynamic resolution T1129)",
    "PE import signals: IsDebuggerPresent (anti-debug T1622)",
    "capa rules: obfuscated stackstrings, Base64 encoding, XOR encoding, process injection",
    "Ghidra strings: WinHttpOpenRequest, HttpSendRequestW, WinHttpReadData (HTTP client stack)",
    "Ghidra strings: manifest requiresAdministrator execution level",
    "Ghidra strings: OpenSSL crypto implementations (AES, SHA1/256/512, Montgomery, GHASH)",
    "FLOSS: 24,408 static strings extracted",
    "IDA imports: ADVAPI32 Crypt* APIs for cryptographic operations"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 61,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
        
… [18388 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "profile": "deep",
  "limits": {
    "strings_max": 300,
    "imports_max": 300,
    "functions_max": 30,
    "anomaly_locations_max": 50,
 
… [1321055 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 154,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique":
… [12585 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.05,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
   
… [1450 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@open
… [2093 more chars]
```

- **dotnet_analyze** ok=`True` checklist=`True` — Required checklist tool (dotnet)

```json
{
  "is_dotnet": false,
  "runtime_version": null,
  "assembly_name": null,
  "module_name": null,
  "language_hint": null,
  "external_assembly_refs": [],
  "suspicious_native_refs": [],
  "suspicious_methods": [],
  "interesting_pinvoke": [],
  "has_suppress_ildasm": false,
  "shellcode_embed_hint": false,
  "il_total_lines": 0,
  "il_excerpt": ""
}
```

- **r2_decompile** ok=`True` checklist=`True` — Required checklist tool (r2_decomp)

```json
{
  "r2_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "disassembly": {
    "0x00487740": "; CALL XREF from entry0 @ 0x4898fa(x)\n\u250c 10: fcn.00487740 ();\n\u2502           0x00487740      50  
… [4749 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 
… [112 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "candidates": [
    "Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r",
    "Found XOR 00 position 004C
… [639 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
  "module_base": null,
  "entry_point": null,
  "key_events": [],
  "api_calls": [],
  "strings": []
}
```

- **frida_static_probe** ok=`True` checklist=`True` — Required checklist tool (frida_probe)

```json
{
  "frida_available": true,
  "frida_version": "17.16.4",
  "pe_probe": {
    "path": "/opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil",
    "exists": true,
    "hook_candidates": [
      "VERSION.dll!GetFileVersionInfoW",
 
… [1030 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — Auto SQL seed for large-mode deep RE gate

```json
{
  "columns": [
    "name",
    "address",
    "size"
  ],
  "rows": [
    {
      "name": "_guard_check_icall",
      "address": "4304560",
      "size": "1"
    }
  ],
  "row_count": 1,
  "total_row_count": 1,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a4
… [71 more chars]
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 8701567,
  "duration_s": 0.05,
  "import_count": 571,
  "signal_count": 13,
  "signals": [
    {
      "label": "allocate_memory",
      "api_match": "VirtualAllocEx",
      "attack": [
        "T1055"
      ]
    },
    {
      "label": "write_process_memory",
      "api_match": "WriteProcessMemory",
      "attack": [
        "T1055"
      ]
    },
   
… [1450 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/audit.jsonl"
}
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 154,
  "top_rules": [
    {
      "name": "contain obfuscated stackstrings",
      "attack": [
        {
          "parts": [
            "Defense Evasion",
            "Obfuscated Files or Information",
            "Indicator Removal from Tools"
          ],
          "tactic": "Defense Evasion",
          "technique": "Obfuscated Files or Information",
          "subtechnique":
… [12585 more chars]
```

- **angr_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "tool": "cff_deflatten",
  "claim_type": "cff_dispatcher",
  "result": "untested",
  "duration_s": 5.507469177246094e-05,
  "evidence": "cff_deflatten.py not found at /opt/cadre-v3-tools/cff-deflatten/cff_deflatten.py; copy from v3-deploy/cff-deflatten/",
  "raw": {}
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "module",
    "name",
    "address"
  ],
  "rows": [
    {
      "module": "ADVAPI32",
      "name": "AdjustTokenPrivileges",
      "address": "7491636"
    },
    {
      "module": "ADVAPI32",
      "name": "CloseServiceHandle",
      "address": "7491588"
    },
    {
      "module": "ADVAPI32",
      "name": "ControlService",
      "address": "7491592"
    },
    {
      "mo
… [3033 more chars]
```

- **floss_extract** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "floss_ok": true,
  "string_count": 24408,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.rdata",
    "@.data",
    ".gfids",
    ".QMGuid",
    "@.tvm0",
    "`.reloc",
    "V4_^[]",
    "X<[]_^",
    "_<[]_^",
    "Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>",
    "SHA1 block transform for x86, CRYPTOGAMS by <appro@open
… [2093 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "CryptAcquireContextA",
      "address": "8297300",
      "length": "21"
    },
    {
      "content": "CryptReleaseContext",
      "address": "8297324",
      "length": "20"
    },
    {
      "content": "CryptGetHashParam",
      "address": "8297346",
      "length": "18"
    },
    {
      "conte
… [2910 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
      "address": "8142128",
      "length": "110"
    },
    {
      "content": "GameDownload.exe",
      "address": "8287410",
      "length": "17"
    },
    {
      "content"
… [2860 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/audit.jsonl"
}
```

- **ida_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ida_query",
  "session_id": "ida-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/audit.jsonl"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [
    {
      "content": "CreateMutexW",
      "address": "8291660",
      "length": "13"
    },
    {
      "content": "ReleaseMutex",
      "address": "8291698",
      "length": "13"
    },
    {
      "content": "OpenMutexW",
      "address": "8291972",
      "length": "11"
    },
    {
      "content": "GetTempFileNameW
… [1344 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address",
    "length"
  ],
  "rows": [],
  "row_count": 0,
  "total_row_count": 0,
  "truncated": false,
  "source": "ghidra_query",
  "session_id": "ghidra-pe-7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "audit_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/audit.jsonl"
}
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/01-tools-raw.json` exists=`True` bytes=`1481365` mtime=`2026-08-08T04:22:08.438425+00:00`
  - sha256: `59684b60899c3b3a79c684e9dd8d5b639f7f4a28a73cd1340104ad50796a7536`
- **sql_evidence:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/05-deep-dive.json` exists=`True` bytes=`4775` mtime=`2026-08-08T04:26:54.559122+00:00`
  - sha256: `09f3925d60857c93df3349acb025880bd3c070c5ab2451fb0dff629e53bb56b9`

#### prompt_excerpt

```

```


#### llm_raw_excerpt

```
{}
```


#### deep05_excerpt

```
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This 8.7MB PE sample exhibits multiple high-signal malicious indicators: YARA rules identify it as associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca-Stealer, Medusalocker, Njrat, Remcos, and Revil families. PE import analysis reveals process injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), HTTP C2 communications (WinHttpOpen, InternetOpen), download capabilities (URLDownloadToFile), registry manipulation (RegSetValue), process creation (CreateProcess, ShellExecute), dynamic API resolution (LoadLibrary, GetProcAddress), and anti-debugging (IsDebuggerPresent). capa rules confirm obfuscated stackstrings, Base64/XOR en
… [3975 more chars]
```

- **agentic:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`3404232` mtime=`2026-08-08T04:26:54.554122+00:00`
  - sha256: `da754a5c450c35d4ebc3bd9928bd73cc3fa2e45b91b85fd7b74edfb8d099688d`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |
| rule_compiles | `True` |
| rule_check | `ok` |
| meta_yara_valid | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yar` exists=`True` bytes=`1366` mtime=`2026-08-08T04:27:53.354494+00:00`
  - sha256: `13c7c75e2a3a965bb875a6a54e0bb26e8ad64ca671d2ca00891496c9bdf053b1`

#### excerpt

```
// yara_gen_v2.py — 2026-08-08T04:27:53.356054+00:00
rule CADRE_v2_unknown_7fbde4a47c91 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb" ascii wide
        $s1 = "Copyright © 2020 Tencent. All Rights Reserved." ascii wide
        $s2 = "InitializeCriticalSectionAndSpinCount" ascii wide
        $s3 = "WinHttpGetIEProxyConfigForCurrentUser" asc
… [563 more chars]
```


---

## Stage: publish

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| REPORT_MASTER_v2 | `True` |
| REPORT_MASTER_v3 | `True` |
| REPORT_v2 | `True` |
| REPORT_TECHNICAL_v2 | `True` |
| REPORT_TECHNICAL_v3 | `True` |
| v2_min_chars | `True` |
| v3_min_chars | `True` |
| v2_heads | `True` |
| v3_heads | `True` |
| v2_fresh_vs_deep | `True` |
| v3_fresh_vs_deep | `True` |
| not_llm_env_failure_v2 | `True` |
| not_llm_env_failure_v3 | `True` |
| v2_no_missing_sections | `True` |
| verdict_lock_ok | `True` |
| quality_pack_ok | `True` |
| master_source_llm | `True` |
| tech2_source_llm | `True` |
| tech3_source_ok | `True` |
| tech2_no_stubs | `True` |
| no_tech2_fallback | `True` |
| quality_issues | `[]` |
| engine_citation_ok | `True` |

### Artifact paths (verify on disk)

- **REPORT_MASTER_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v2.md` exists=`True` bytes=`33328` mtime=`2026-08-08T04:30:16.698412+00:00`
  - sha256: `54ab8ad74553668f441e60947caaef9968e3bfd79094b1cbba3d8f30f060aa97`
- **REPORT_MASTER_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-MASTER-v3.md` exists=`True` bytes=`55047` mtime=`2026-08-08T04:44:24.193078+00:00`
  - sha256: `d13c3e9018c2e8104d136eff9979636c69a26c79a3920dc54178a9912c99036f`
- **REPORT_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-v2.md` exists=`True` bytes=`33328` mtime=`2026-08-08T04:30:16.696412+00:00`
  - sha256: `54ab8ad74553668f441e60947caaef9968e3bfd79094b1cbba3d8f30f060aa97`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`93855` mtime=`2026-08-08T04:39:24.510840+00:00`
  - sha256: `427d98bc43a14482ba580add7f4883b8b9be10ffb4540667d35fc128b8be26a1`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`90578` mtime=`2026-08-08T04:47:10.508271+00:00`
  - sha256: `d30fc9390716384ed9643bb01ea794fecaa529c913210e5950702647c4f03a0f`
- **report_v2_json:** `/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/report-v2.json` exists=`True` bytes=`69154` mtime=`2026-08-08T04:39:24.516840+00:00`
  - sha256: `cef62ff49d2bcaec6d1218009825be24c2d6d23ed1724927f5c9640fcd19e938`

#### v2_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 04:30:16 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | MALICIOUS |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-functional info-stealer/loader masquerading as Tencent GameLoop installer, with capabilities consis
… [32406 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-08 04:44:24 UTC

# RE Report — 7fbde4a47c91
_Generated 2026-08-08T04:44:24.163892+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=412c | cross_refs=True | llm_ok=True | runtime=24.72s -->

# Executive Summary
| Attribute | Value | Confidence |
|-----------|-------|------------|
| Final Verdict | Malicious | High (90/100) |
| Family Classification | Multi-functional info-stealer/loader with capability alignment to DarkGate, LucaStealer, and Remcos | High |
| Sample Type | 32-bit Windows PE executable | High |
| Lure Masquerade | Tencent GameLoop (gaming emulator) 
… [54134 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
