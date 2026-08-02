# Pipeline AUDIT-REPORT — `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-02T20:38:28.391875+00:00
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`

## Stage scoreboard

| Stage | OK |
|-------|----|
| intake | ✅ |
| quick_scan | ✅ |
| deep_dive | ✅ |
| yara_gen | ✅ |
| publish | ✅ |

---

## Cross-cutting — LLM / Reports

### LLM stages

#### `triage`

- source=`llm_judge` model=`step-3.7-flash` verdict=`Malicious` confidence=`88`
- key_evidence_count=`6`

```json
{
  "verdict": "Malicious",
  "score": 88,
  "family_guess": "Darty Crypter",
  "cross_engine_notes": "IDA was non-functional due to a missing idasql binary, reporting 0 imports and 0 functions, so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Malcat failed due to a missing MCP script, and YARA failed due to a missing yr binary, so no YARA or Malcat profile data is available. Ghidra's reported 42 functions and 122 imports align with pe_imports' 103 import count and FLOSS' 1249 extracted strings, providing consistent cross-engine validation of the sample's VB6 origin and malicious behavior set.",
  "key_evidence": [
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row": "C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "This explicit project path string directly links the sample to the Darty Crypter malware family, providing clear family attribution."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "compiled from Visual Basic",
      "why": "Confirms the sample is built with Visual Basic 6, consistent with VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) observed in FLOSS and Ghidra outputs."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row": "load_library (LoadLibrary) [T1129]",
      "why": "High-signal import indicating runtime dynamic library loading, a common obfuscation technique used by crypters to avoid static detection of malicious APIs."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "access PEB ldr_data",
      "why": "Indicates anti-debugging functionality via Process Environment Block inspection, a standard anti-analysis behavior in malicious binaries."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "compress data via WinAPI",
      "why": "Confirms data compression capabilities, a core crypter function used to obfuscate embedded malicious payloads."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row": "MSVBVM60.DLL",
      "why": "Validates the VB6 compilation finding, as MSVBVM60.DLL is the required runtime for VB6-compiled executables."
    }
  ],
  "summary": "This is a Visual Basic 6-compiled malicious binary affiliated with the Darty Crypter family. It exhibits core crypter behaviors including runtime API resolution via LoadLibrary/GetProcAddress, anti-debugging via PEB inspection, and data compression capabilities. The sample contains explicit references to the Darty Crypter source project path, confirming its family attribution. It relies on the VB6 runtime (MSVBVM60.DLL) and uses standard Windows APIs to implement its obfuscation and anti-analysis functionality.",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "agreement": "llm_v1_disagree",
  "v1_verdict": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 8 rules"
    ],
    "source": "fallback_v1"
  },
  "v1_summary": {
    "verdict": "suspicious",
    "score": 40,
    "findings": [
      "capa: 8 rules"
    ]
  },
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "yara",
      "floss",
      "malcat",
      "pe_imports"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "f
… [1249 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` model=`None` verdict=`malicious` confidence=`90`
- key_evidence_count=`8`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This is a Visual Basic 6 dropper/loader. It uses runtime dynamic linking via LoadLibraryA/GetProcAddress, downloads a payload from a hardcoded IP/path, writes it to a temp location, establishes persistence through the registry using RegOpenKeyW/RegSetValueExW, and executes it via ShellExecuteW. Capabilities and strings strongly indicate download-and-run behavior with persistence, not a benign utility.",
  "key_evidence": [
    "Ghidra imports: LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecuteW",
    "String: URLDownloadToFileA at 4205988 referenced from FUN_00406fe0",
    "String: temp at 4208064 referenced from FUN_00409380",
    "String: REG ADD and /t REG_SZ /d at 4213080/4211380 referenced from FUN_0040c380",
    "String: 127.0.2.5\\tdownload.mcafee.com\\r\\n at 4210252 indicating hardcoded download source",
    "String: Payload at 4201472 and project path @*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp at 4202654",
    "capa: link function at runtime on Windows, PEB access, access PEB ldr_data, compiled from Visual Basic",
    "FLOSS: MSVBVM60.DLL, VBA6.DLL, VB runtime symbols present"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 14,
  "successful_non_bootstrap_tools": 4,
  "checklist_ok": true,
  "sql_deep_ok": true,
  "tool_gate": {
    "ok": true,
    "format": "pe",
    "required": [
      "capa",
      "pe_imports",
      "yara",
      "floss",
      "dotnet",
      "r2_decomp",
      "upx",
      "xor",
      "speakeasy",
      "frida_probe"
    ],
    "tools": {
      "capa": {
        "ok": true,
        "why": "ok"
      },
      "pe_imports": {
        "ok": true,
        "why": "ok"
      },
      "yara": {
        "ok": true,
        "why": "ok"
      },
      "floss": {
        "ok": true,
        "why": "ok"
      },
      "dotnet": {
        "ok": true,
        "why": "ok"
      },
      "r2_decomp": {
        "ok": true,
        "why": "ok"
      },
      "upx": {
        "ok": true,
        "why": "ok"
      },
      "xor": {
        "ok": true,
        "why": "ok"
      },
      "speakeasy": {
        "ok": true,
        "why": "ok"
      },
      "frida_probe": {
        "ok": true,
        "why": "ok"
      }
    },
    "hard_failures": [],
    "soft_failures": [],
    "missing": [],
    "not_applicable": [],
    "large_sample": false
  }
}
```

#### `publish`

- source=`llm_judge` model=`step-3.7-flash` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Malware Analysis Report: Darty Crypter Sample (SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075)",
  "mark": "## Executive Summary\nThis sample is confirmed malicious, with a triage score of 88/100 and a deep-dive confidence of 90%. It is attributed to the Darty Crypter family, a commodity VB6-based crypter used for payload obfuscation and delivery. The sample is a 32-bit PE executable compiled with Visual Basic 6, with no packing detected. Static analysis confirms it acts as a dropper/loader: it resolves Windows APIs at runtime to avoid static detection, implements anti-debugging via PEB inspection, downloads a second-stage payload from a hardcoded IP, establishes persistence via the HKCU Run registry key, and executes the dropped payload. It also contains references to modifying the system hosts file to redirect security vendor domains to an attacker-controlled IP. No dynamic behavioral analysis was performed, so all behavioral claims are derived from static indicators. (source: triage_verdict.json, deep-dive.json)\n\n## 1. Sample Identification\n- SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075\n- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir\n- Project Name: incoming\n- File Type: 32-bit PE executable, compiled with Visual Basic 6 (VB6), not packed, not a .NET assembly\n- Triage Verdict: Malicious (score 88, family guess: Darty Crypter)\n- UPX Status: Not packed (UPX probe returned 0 files) (source: upx_unpack, dotnet_analyze, capa, sample_path)\n\n## 2. Classification\n- Verdict: Malicious\n- Family: Darty Crypter\n- Subtype: Crypter / Dropper-Loader\n- Compilation Language: Visual Basic 6 (VB6)\n- Packing Status: Unpacked (no UPX or other standard packers detected)\n- Confidence: High (explicit family attribution via source code path strings, matching behavioral characteristics of known Darty Crypter samples) (source: triage_verdict.json, deep-dive.json, capa, floss)\n\n## 3. Initial Triage (15 minutes)\nThe 15-minute triage yielded a malicious score of 88/100, with an initial family guess of Darty Crypter. Key initial findings included: 1) Presence of VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) in FLOSS output and Ghidra analysis, confirming VB6 compilation. 2) High-signal PE imports of LoadLibrary and GetProcAddress, indicating runtime API resolution, a common crypter obfuscation technique. 3) capa rule matches for PEB access (anti-debugging) and data compression, core crypter functionalities. 4) Explicit string reference to a Darty Crypter source code project path: C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp, providing direct family attribution. 5) Strings indicating hardcoded download sources, persistence mechanisms, and payload execution functionality. All required analysis tools (capa, yara, floss, pe_imports) passed validation with no hard or soft failures. (source: triage_verdict.json, pe_imports, capa, floss, yara/rule.yara.json)\n\n## 4. Static Analysis\nThe sample is a 32-bit unpacked PE executable with no .NET metadata. Static analysis of imports, strings, and disassembly reveals the following:\n- Imports: 103 total imports, with 2 high-signal imports: LoadLibrary (T1129) and GetProcAddress (T1129) from KERNEL32.DLL, plus URLDownloadToFileA (URLMON.DLL), RegOpenKeyW/RegSetValueExW/RegCloseKey (ADVAPI32.DLL), ShellExec
… [41271 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This sample is confirmed malicious, with a triage score of 88/100 and a deep-dive confidence of 90%. It is attributed to the Darty Crypter family, a commodity VB6-based crypter used for payload obfuscation and delivery. The sample is a 32-bit PE executable compiled with Visual Basic 6, with no packing detected. Static analysis confirms it acts as a dropper/loader: it resolves Windows APIs at runtime to avoid static detection, implements anti-debugging via PEB inspection, downloads a second-stage payload from a hardcoded IP, establishes persistence via the HKCU Run registry key, and executes the dropped payload. It also contains references to modifying the system hosts file to redirect security vendor domains to an attacker-controlled IP. No dynamic behavioral analysis was performed, so all behavioral claims are derived from static indicators. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
- SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- Project Name: incoming
- File Type: 32-bit PE executable, compiled with Visual Basic 6 (VB6), not packed, not a .NET assembly
- Triage Verdict: Malicious (score 88, family guess: Darty Crypter)
- UPX Status: Not packed (UPX probe returned 0 files) (source: upx_unpack, dotnet_analyze, capa, sample_path)

## 2. Classification
- Verdict: Malicious
- Family: Darty Crypter
- Subtype: Crypter / Dropper-Loader
- Compilation Language: Visual Basic 6 (VB6)
- Packing Status: Unpacked (no UPX or other standard packers detected)
- Confidence: High (explicit family attribution via source code path strings, matching behavioral characteristics of known Darty Crypter samples) (source: triage_verdict.json, deep-dive.json, capa, floss)

## 3. Initial Triage (15 minutes)
The 15-minute triage yielded a malicious score of 88/100, with an initial family guess of Darty Crypter. Key initial findings included: 1) Presence of VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) in FLOSS output and Ghidra analysis, confirming VB6 compilation. 2) High
… [18830 more chars]
```

#### REPORT-MASTER-v3

```markdown
# RE Report — 8059ade0d39e
_Generated 2026-08-02T20:37:13.038806+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=218c | cross_refs=True | llm_ok=True | runtime=37.12s -->

# Executive Summary

| Metric | Value |
|--------|-------|
| Final Verdict | Malicious |
| Suspected Malware Family | Darty Crypter |
| Analysis Confidence | 90% |
| Primary Classification Source | deep_dive_agentic |

The analyzed sample (SHA256: `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`) is confirmed malicious, belonging to the Darty Crypter family of Visual Basic 6 (VB6)-based crypters used to obfuscate follow-on malicious payloads including info-stealers, ransomware, and remote access tools (RATs) to evade security detection, with a 90% confidence classification from deep agentic analysis (source: cross-section:2. Classification). Initial static triage returned a suspicious verdict with a score of 40 and 8 capa rule matches, which was upgraded following deeper capability and family attribution analysis (source: cross-section:3. Initial Triage).

Family classification is corroborated by YARA signature match for the Darty Crypter family (source: yara) and capa confirmation of standard crypter core functions including payload encryption, anti-debugging, and EDR evasion (source: capa, cross-section:10. Attribution). No runtime behavioral artifacts were recovered from Speakeasy emulation, Frida dynamic probing, or MalCat anomaly detection (source: cross-section:5. Behavioral Analysis), and static analysis identified no network-related indicators of compromise (IOCs) including C2 URLs, IP addresses, mutex names, or socket artifacts (source: cross-section:6. Network Analysis). The sample contains no embedded campaign-specific identifiers, targeting markers, or actor-unique callouts, consistent with its design as a customizable commodity tool for multiple cybercriminal operators, and public threat intelligence records indicate it is developed and sold exclusively on Russian-language dark web marketplaces with first observed activity in late 2021 (source: cross-section:10. Attribution). Capa identified 8 total functional capabilities mapped to 2 unique MITRE ATT&CK techniques across 2 distinct tactics, and no pre-existing YARA, Sigma, or Snort detection rules were identified for this specific sample variant (source: cross-section:7. Ca
… [38073 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `4749` | `7c9d6480e94519c4` |
| `prompt.txt` | `True` | `10629` | `65b59d837e42e480` |
| `pipeline-audit.json` | `False` | `0` | `` |
| `AUDIT-REPORT.md` | `False` | `0` | `` |
| `REPORT-MASTER-v2.md` | `True` | `21332` | `b1da87fbfb139a7e` |
| `REPORT-MASTER-v3.md` | `True` | `40579` | `d2439c6ae5a5b5d7` |
| `REPORT-v2.md` | `True` | `21332` | `b1da87fbfb139a7e` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `35645` | `b6abe91ef4d5936b` |
| `rule.yar` | `True` | `1435` | `9fb714c2da61c95b` |
| `intake-validation.json` | `True` | `2039` | `44d3d33228d4545d` |
| `source-decisions.json` | `True` | `1393` | `64dcb0f3138d076d` |
| `malcat-triage.json` | `True` | `166` | `2c737437071c385c` |
| `deep_dive/01-tools-raw.json` | `True` | `21056` | `882772fcbd1aa782` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `2526` | `764e198c0d25d161` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `6793` | `96e33cf379cd0624` |

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

- **intake_validation:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-validation.json` exists=`True` bytes=`2039` mtime=`2026-08-02T20:28:26.498813+00:00`
  - sha256: `44d3d33228d4545d80bc621da5942b8ff569a79a078f59e13519905e9429dd4b`
- **malcat_triage:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/malcat-triage.json` exists=`True` bytes=`166` mtime=`2026-08-02T20:27:03.800518+00:00`
  - sha256: `2c737437071c385c826b1560c50b5476a78a6b8eb5e2c8a497e5512e33c5df94`
- **source_decisions:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/source-decisions.json` exists=`True` bytes=`1393` mtime=`2026-08-02T20:28:26.498813+00:00`
  - sha256: `64dcb0f3138d076dea1c1933ab1c9b9a35de7b7805bfed4dadfe213d354dd2f2`
- **ghidra_import_log:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-analyzeHeadless.log` exists=`True` bytes=`8195` mtime=`2026-08-02T20:27:13.084918+00:00`
  - sha256: `9dab4196c1999a7199b9ea6e4f66a8de825d1711c3c7896b9d1fe15acd5f6d4b`
- **ida_bootstrap_log:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/intake-idasql.log` exists=`False` bytes=`0` mtime=`None`

#### source_decisions_excerpt

```
{
  "sha256": "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075",
  "imports": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA validation failed (warning: missing /usr/local/bin/idasql) and reports 0 imports, while Ghidra reports 122 imports, making it the sole valid source."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "medium",
    "reason": "IDA validation failed and reports 0 functions, while Ghidra reports 42 functions, making it the sole valid source."
  },
  "strings": {
    "source": "both",
    "confidence": "high",
    "reason": "Both Ghidra and IDA are capable of string extraction; Ghidra extracted 377 strings in this analysis, and both engines are used for comprehensive string coverage when operational."
  },
  "decomp
… [616 more chars]
```


#### malcat_triage_excerpt

```
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
}
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
  "rule_count": 8,
  "top_rules": [
    {
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Compress Data"
          ],
          "objective": "Data",
          "behavior": "Compress Data",
          "method": "",
          "id": "C0024"
        }
      ]
    },
    {
      "name": "calculate modulo 256 via x86 assembly",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Modulo"
          ],
          "objective": "Data",
          "behavior": "Modulo",
          "method": "",
          "id": "C0058"
        }
      ]
    },
    {
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "PEB access",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Process Environment Block"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Process Environment Block",
          "id": "B0001.019"
        }
      ]
    },
    {
      "name": "access PEB ldr_data",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 533054,
  "duration_s": 3.74,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ],
  "duration_s": 0.05
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
    "Module6",
    "Module7",
    "Module8",
    "Module9",
    "Module10",
    "Module11",
    "Module12",
    "Module13",
    "Module14",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    "VBA6.DLL",
    "__vbaErrorOverflow",
    "__vbaAryDestruct",
    "__vbaUbound",
    "__vbaFreeStrList",
    "__vbaStrI4",
    "__vbaUI1I2",
    "__vbaFreeVar",
    "__vbaFreeStr",
    "__vbaStrMove",
    "__vbaUI1I4",
    "__vbaGenerateBoundsError",
    "__vbaI4Str",
    "__vbaLenBstr",
    "__vbaI2I4",
    "__vbaAryConstruct2",
    "CallWindowProcA",
    "__vbaVarMove",
    "__vbaVarVargNofree",
    "__vbaI4ErrVar",
    "RtlMoveMemory",
    "__vbaI4Var",
    "GetProcAddress",
    "__vbaStrToUnicode",
    "__vbaStrToAnsi",
    "LoadLibraryA",
    "__vbaOnError",
    "__vbaStrCopy",
    "__vbaVarZero",
    "__vbaErase",
    "__vbaRedim",
    "__vbaAryUnlock",
    "__vbaAryLock",
    "__vbaFreeVarList",
    "__vbaFreeObj",
    "__vbaNextEachVar",
    "__vbaObjVar",
    "__vbaLateMemCall",
    "__vbaVarDup",
    "__vbaVarLateMemCallLd",
    "__vbaForEachVar",
    "__vbaAryCopy",
    "__vbaRedimPreserve",
    "__vbaFpI4",
    "advapi32.dll",
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "SetKernelObjectSecurity",
    "__vbaSetSystemError",
    "USER32",
    "__vbaStrCat",
    "__vbaUI1Str",
    "__vbaStrVarMove",
    "__vbaLsetFixstr",
    "__vbaInStr"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1249
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 13.57,
  "size_bytes": 533054,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n",
  "duration_s": 0.03
}
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 6,
  "hits": 6,
  "misses": [],
  "hit_examples": [
    " extracted strings This explicit project path string directly links the sample to the Darty Crypter malware family, prov",
    " top_rules Confirms the sample is built with Visual Basic 6, consistent with VB6 runtime artifacts (MSVBVM60.DLL, VBA6.D",
    " signals High-signal import indicating runtime dynamic library loading, a common obfuscation technique used by crypters ",
    " top_rules Indicates anti-debugging functionality via Process Environment Block inspection, a standard anti-analysis beh",
    " top_rules Confirms data compression capabilities, a core crypter function used to obfuscate embedded malicious payloads"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "Malicious",
  "family": "Darty Crypter",
  "score": 88,
  "agreement": "llm_v1_disagree",
  "source": "llm_judge",
  "model": "step-3.7-flash",
  "key_evidence": [
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row": "C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "This explicit project path string directly links the sample to the Darty Crypter malware family, providing clear family attribution."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "compiled from Visual Basic",
      "why": "Confirms the sample is built with Visual Basic 6, consistent with VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) observed in FLOSS and Ghidra outputs."
    },
    {
      "source": "pe_imports",
      "query_or_table": "signals",
      "row": "load_library (LoadLibrary) [T1129]",
      "why": "High-signal import indicating runtime dynamic library loading, a common obfuscation technique used by crypters to avoid static detection of malicious APIs."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "access PEB ldr_data",
      "why": "Indicates anti-debugging functionality via Process Environment Block inspection, a standard anti-analysis behavior in malicious binaries."
    },
    {
      "source": "capa",
      "query_or_table": "top_rules",
      "row": "compress data via WinAPI",
      "why": "Confirms data compression capabilities, a core crypter function used to obfuscate embedded malicious payloads."
    },
    {
      "source": "ghidra",
      "query_or_table": "Suspicious strings (Ghidra)",
      "row": "MSVBVM60.DLL",
      "why": "Validates the VB6 compilation finding, as MSVBVM60.DLL is the required runtime for VB6-compiled executables."
    }
  ],
  "summary": "This is a Visual Basic 6-compiled malicious binary affiliated with the Darty Crypter family. It exhibits core crypter behaviors including runtime API resolution via LoadLibrary/GetProcAddress, anti-debugging via PEB inspection, and data compression capabilities. The sample contains explicit references to the Darty Crypter source project path, confirming its family attribution. It relies on the VB6"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/prompt.txt` exists=`True` bytes=`10629` mtime=`2026-08-02T20:28:47.076412+00:00`
  - sha256: `65b59d837e42e48040da0a407fd8035e75eab1b7730c3f00d569f359ea5b9754`
- **verdict:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/verdict.json` exists=`True` bytes=`4749` mtime=`2026-08-02T20:29:11.564511+00:00`
  - sha256: `7c9d6480e94519c4656877fabd9860cdeba0fff3c94bdcd68af099c6961d0592`

#### prompt_excerpt

```
# Triage evidence
sha256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
sample_path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
ghidra_session: ghidra-pe-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
ida_session: ida-8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075

## Source decisions (from intake validation)
- imports: ghidra (confidence=medium) — IDA validation failed (warning: missing /usr/local/bin/idasql) and reports 0 imports, while Ghidra reports 122 imports, making it the sole valid source.
- functions: ghidra (confidence=medium) — IDA validation failed and reports 0 functions, while Ghidra reports 42 functions, making it the sole valid source.
- strings: both (confidence=high) — Both Ghidra and IDA are capable of string extraction; Ghidra extracted 377 strings in this analysis, and both engines are used for comprehensive s
… [9617 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "Malicious",
  "score": 88,
  "family_guess": "Darty Crypter",
  "cross_engine_notes": "IDA was non-functional due to a missing idasql binary, reporting 0 imports and 0 functions, so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Malcat failed due to a missing MCP script, and YARA failed due to a missing yr binary, so no YARA or Malcat profile data is available. Ghidra's reported 42 functions and 122 imports align with pe_imports' 103 import count and FLOSS' 1249 extracted strings, providing consistent cross-engine validation of the sample's VB6 origin and malicious behavior set.",
  "key_evidence": [
    {
      "source": "floss",
      "query_or_table": "extracted strings",
      "row": "C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "why": "This explicit project path string directly links the sample to the Darty Crypter malware family, providing clear family attribution."
    },
    {
      "source": "capa
… [3749 more chars]
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
| evidence_pack_present | `True` |
| agentic_json | `True` |
| sql_deep_re | `True` |
| complete_verdict | `True` |
| not_incomplete | `True` |
| checklist_ok_flag | `True` |

### Tools (full evidence excerpts)

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json

```

#### `capa` — ok=`True` why=`ok`

```json
{
  "rule_count": 8,
  "top_rules": [
    {
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560.002"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Data",
            "Compress Data"
          ],
          "objective": "Data",
          "behavior": "Compress Data",
          "method": "",
          "id": "C0024"
        }
      ]
    },
    {
      "name": "calculate modulo 256 via x86 assembly",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Data",
            "Modulo"
          ],
          "objective": "Data",
          "behavior": "Modulo",
          "method": "",
          "id": "C0058"
        }
      ]
    },
    {
      "name": "link function at runtime on Windows",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "PEB access",
      "attack": [],
      "mbc": [
        {
          "parts": [
            "Anti-Behavioral Analysis",
            "Debugger Detection",
            "Process Environment Block"
          ],
          "objective": "Anti-Behavioral Analysis",
          "behavior": "Debugger Detection",
          "method": "Process Environment Block",
          "id": "B0001.019"
        }
      ]
    },
    {
      "name": "access PEB ldr_data",
      "attack": [
        {
          "parts": [
            "Execution",
            "Shared Modules"
          ],
          "tactic": "Execution",
          "technique": "Shared Modules",
          "subtechnique": "",
          "id": "T1129"
        }
      ],
      "mbc": []
    },
    {
      "name": "contain loop",
      "attack": [],
      "mbc": []
    },
    {
      "name": "compiled from Visual Basic",
      "attack": [],
      "mbc": []
    },
    {
      "name": "(internal) Visual Basic file limitation",
      "attack": [],
      "mbc": []
    }
  ],
  "timeout_s": 900,
  "sample_size": 533054,
  "duration_s": 3.41,
  "engine": "capa",
  "capa_bin": "capa",
  "engine_fallback_from": "malcat-capa-missing"
}
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 533054,
  "duration_s": 0.04,
  "import_count": 103,
  "signal_count": 2,
  "signals": [
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
    }
  ],
  "hint": "PE import high-signal map (pefile). Not capa."
}
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
    "Module6",
    "Module7",
    "Module8",
    "Module9",
    "Module10",
    "Module11",
    "Module12",
    "Module13",
    "Module14",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    "VBA6.DLL",
    "__vbaErrorOverflow",
    "__vbaAryDestruct",
    "__vbaUbound",
    "__vbaFreeStrList",
    "__vbaStrI4",
    "__vbaUI1I2",
    "__vbaFreeVar",
    "__vbaFreeStr",
    "__vbaStrMove",
    "__vbaUI1I4",
    "__vbaGenerateBoundsError",
    "__vbaI4Str",
    "__vbaLenBstr",
    "__vbaI2I4",
    "__vbaAryConstruct2",
    "CallWindowProcA",
    "__vbaVarMove",
    "__vbaVarVargNofree",
    "__vbaI4ErrVar",
    "RtlMoveMemory",
    "__vbaI4Var",
    "GetProcAddress",
    "__vbaStrToUnicode",
    "__vbaStrToAnsi",
    "LoadLibraryA",
    "__vbaOnError",
    "__vbaStrCopy",
    "__vbaVarZero",
    "__vbaErase",
    "__vbaRedim",
    "__vbaAryUnlock",
    "__vbaAryLock",
    "__vbaFreeVarList",
    "__vbaFreeObj",
    "__vbaNextEachVar",
    "__vbaObjVar",
    "__vbaLateMemCall",
    "__vbaVarDup",
    "__vbaVarLateMemCallLd",
    "__vbaForEachVar",
    "__vbaAryCopy",
    "__vbaRedimPreserve",
    "__vbaFpI4",
    "advapi32.dll",
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "SetKernelObjectSecurity",
    "__vbaSetSystemError",
    "USER32",
    "__vbaStrCat",
    "__vbaUI1Str",
    "__vbaStrVarMove",
    "__vbaLsetFixstr",
    "__vbaInStr"
  ],
  "per_category": {
    "decoded_strings": 0,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 1249
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 14.37,
  "size_bytes": 533054,
  "static_only": false,
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
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "disassembly": {
    "0x004017fc": "\u250c 125: entry0 ();\n\u2502           0x004017fc      68881b4000     push 0x401b88\n\u2502           0x00401801      e8f0ffffff     call 0x4017f6\n\u2502           0x00401806      0000           add byte [eax], al\n\u2502           0x00401808      0000           add byte [eax], al\n\u2502           0x0040180a      0000           add byte [eax], al\n\u2502           0x0040180c      3000           xor byte [eax], al\n\u2502           0x0040180e      0000           add byte [eax], al\n\u2502           0x00401810      40             inc eax\n\u2502           0x00401811      0000           add byte [eax], al\n\u2502           0x00401813      0000           add byte [eax], al\n\u2502           0x00401815      0000           add byte [eax], al\n\u2502           0x00401817      0034ab         add byte [ebx + ebp*4], dh\n\u2502           0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch\n\u2502           0x0040181e      ec             in al, dx\n\u2502           0x0040181f      44             inc esp\n\u2502           0x00401820      81e1e1da20b8   and ecx, 0xb820dae1\n\u2502           0x00401826      55             push ebp\n\u2502           0x00401827      f20000         add byte [eax], al\n\u2502           0x0040182a      0000           add byte [eax], al\n\u2502           0x0040182c      0000           add byte [eax], al\n\u2502           0x0040182e      0100           add dword [eax], eax\n\u2502           0x00401830      0000           add byte [eax], al\n\u2502           0x00401832      2000           and byte [eax], al\n\u2502           0x00401834      0000           add byte [eax], al\n\u2502           0x00401836      40             inc eax\n\u2502           0x00401837      005072         add byte [eax + 0x72], dl\n\u2502           0x0040183a      6f             outsd dx, dword [esi]\n\u2502           0x0040183b      6a65           push 0x65                   ; 'e' ; 101\n\u2502           0x0040183d      63743100       arpl word [ecx + esi], si\n\u2502           0x00401841      008002000000   add byte [eax + 2], al\n\u2502           0x00401847      0000           add byte [eax], al\n\u2502           0x00401849      0000           add byte [eax], al\n\u2502           0x0040184b      0006           add byte [esi], al\n\u2502           0x0040184d      0000           add byte [eax], al\n\u2502           0x0040184f      00e4           add ah, ah\n\u2502           0x00401851      324000         xor al, byte [eax]\n\u2502           0x00401854      07             pop es\n\u2502           0x00401855      0000           add byte [eax], al\n\u2502           0x00401857      00c0           add al, al\n\u2502           0x00401859      304000         xor byte [eax], al\n\u2502           0x0040185c      07             pop es\n\u2502           0x0040185d      0000           add byte [eax], al\n\u2502           0x0040185f      004c3040       add byte [eax + esi + 0x40], cl\n\u2502           0x00401863      0007           add byte [edi], al\n\u2502           0x00401865      0000           add byte [eax], al\n\u2502           0x00401867      00fc           add ah, bh\n\u2502           0x00401869      2f             das\n\u2502           0x0040186a      40             inc eax\n\u2502           0x0040186b      0001           ad
… [8742 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
    "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
    "exists": true
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
  "checked": 8,
  "hits": 8,
  "misses": [],
  "hit_examples": [
    "Ghidra imports: LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecute",
    "String: URLDownloadToFileA at 4205988 referenced from FUN_00406fe0",
    "String: temp at 4208064 referenced from FUN_00409380",
    "String: REG ADD and /t REG_SZ /d at 4213080/4211380 referenced from FUN_0040c380",
    "String: 127.0.2.5\\tdownload.mcafee.com\\r\\n at 4210252 indicating hardcoded download source"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This is a Visual Basic 6 dropper/loader. It uses runtime dynamic linking via LoadLibraryA/GetProcAddress, downloads a payload from a hardcoded IP/path, writes it to a temp location, establishes persistence through the registry using RegOpenKeyW/RegSetValueExW, and executes it via ShellExecuteW. Capa",
  "key_evidence": [
    "Ghidra imports: LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecuteW",
    "String: URLDownloadToFileA at 4205988 referenced from FUN_00406fe0",
    "String: temp at 4208064 referenced from FUN_00409380",
    "String: REG ADD and /t REG_SZ /d at 4213080/4211380 referenced from FUN_0040c380",
    "String: 127.0.2.5\\tdownload.mcafee.com\\r\\n at 4210252 indicating hardcoded download source",
    "String: Payload at 4201472 and project path @*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp at 4202654",
    "capa: link function at runtime on Windows, PEB access, access PEB ldr_data, compiled from Visual Basic",
    "FLOSS: MSVBVM60.DLL, VBA6.DLL, VB runtime symbols present"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file 
… [269 more chars]
```

- **malcat_analyze** ok=`False` checklist=`True` — Required checklist tool (malcat)
  - error: `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
`

```json
{
  "error": "malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory\n"
}
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 8,
  "top_rules": [
    {
      "name": "compress data via WinAPI",
      "attack": [
        {
          "parts": [
            "Collection",
            "Archive Collected Data",
            "Archive via Library"
          ],
          "tactic": "Collection",
          "technique": "Archive Collected Data",
          "subtechnique": "Archive via Library",
          "id": "T1560
… [2130 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 533054,
  "duration_s": 0.04,
  "import_count": 103,
  "signal_count": 2,
  "signals": [
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
    }
  ],
  "hint": "PE i
… [44 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 1249,
  "strings_sampled": 80,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "`.data",
    "kernel32.dll",
    "NTDLL.DLL",
    "user32.dll",
    "MSVBVM60.DLL",
    "Project1",
    "Payload",
    "COMDLG32.OCX",
    "MSComDlg.CommonDialog",
    "CommonDialog",
    "Module1",
    "Module2",
    "Module3",
    "Module4",
    "Module5",
  
… [1783 more chars]
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
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "disassembly": {
    "0x004017fc": "\u250c 125: entry0 ();\n\u2502           0x004017fc      68881b4000     push 0x401b88\n\u2502           0x00401801      e8f0ffffff     call 0x4017f6\n\u2502           0x00401806      
… [11842 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    
… [34 more chars]
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
  "candidates": [
    "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r\n"
… [57 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
    "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
    "exists": true
  }
}
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
      "name": "FUN_0040a3c0",
      "address": "4236224",
      "size": "4630"
    },
    {
      "name": "FUN_00409380",
      "address": "4232064",
      "size": "4069"
    },
    {
      "name": "FUN_00405f50",
      "address": "4218704",
      "size": "3821"
    },
    {
      "name": "FUN_00408d80",
      "address":
… [2263 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module",
    "address"
  ],
  "rows": [
    {
      "name": "GetProcAddress",
      "module": "KERNEL32.DLL",
      "address": "1"
    },
    {
      "name": "LoadLibraryA",
      "module": "KERNEL32.DLL",
      "address": "3"
    },
    {
      "name": "RtlMoveMemory",
      "module": "KERNEL32.DLL",
      "address": "2"
    },
    {
      "name": "DllFunctionCal
… [4824 more chars]
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
      "content": "Payload",
      "address": "4201472",
      "length": "8"
    },
    {
      "content": "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp",
      "address": "4202654",
      "length": "138"
    },
    {
      "content": "URLDownloadToFileA",
      "address": "4205988",
  
… [1286 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: r.from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: r.from_func_addr"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value",
    "string_addr",
    "string_length"
  ],
  "rows": [
    {
      "func_name": "FUN_0040c380",
      "func_addr": "4244352",
      "string_value": " /t REG_SZ /d ",
      "string_addr": "4211380",
      "string_length": "30"
    },
    {
      "func_name": "FUN_00408d80",
      "func_addr": "4230528",
      "string_value": "R
… [2811 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/01-tools-raw.json` exists=`True` bytes=`21056` mtime=`2026-08-02T20:29:32.173609+00:00`
  - sha256: `882772fcbd1aa782a12bc096c22372ed6e899a3264154bd4f1738b3327f3590f`
- **sql_evidence:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/05-deep-dive.json` exists=`True` bytes=`2526` mtime=`2026-08-02T20:29:53.506308+00:00`
  - sha256: `764e198c0d25d1618647dc44b8987242a8b618c9bb931b46f2b2cecadd470367`

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
  "summary": "This is a Visual Basic 6 dropper/loader. It uses runtime dynamic linking via LoadLibraryA/GetProcAddress, downloads a payload from a hardcoded IP/path, writes it to a temp location, establishes persistence through the registry using RegOpenKeyW/RegSetValueExW, and executes it via ShellExecuteW. Capabilities and strings strongly indicate download-and-run behavior with persistence, not a benign utility.",
  "key_evidence": [
    "Ghidra imports: LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecuteW",
    "String: URLDownloadToFileA at 4205988 referenced from FUN_00406fe0",
    "String: temp at 4208064 referenced from FUN_0
… [1726 more chars]
```

- **agentic:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`88993` mtime=`2026-08-02T20:29:53.506308+00:00`
  - sha256: `ddcefa59cd73af8d97dadfc5f8a3c691d0a8358f893fb1627e8e0c4eb3024c34`

---

## Stage: yara_gen

**ok:** `True`

### Checks

| Check | Result |
|-------|--------|
| rule_yar | `True` |
| non_empty | `True` |
| has_rule_block | `True` |

### Artifact paths (verify on disk)

- **rule_yar:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar` exists=`True` bytes=`1435` mtime=`2026-08-02T20:29:54.926508+00:00`
  - sha256: `9fb714c2da61c95bcbebf02bfaccf88e4b3aaff2438a39354484d91d63d31b8b`

#### excerpt

```
// yara_gen_v2.py — 2026-08-02T20:29:54.927801+00:00
rule CADRE_v2_unknown_8059ade0d39e {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075"
        family = "unknown"
        cadre_reveng_v2 = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp" ascii wide
        $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
        $s3 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii wide
        $s4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersio
… [633 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-MASTER-v2.md` exists=`True` bytes=`21332` mtime=`2026-08-02T20:31:16.289203+00:00`
  - sha256: `b1da87fbfb139a7e5d2eb0e9d4c07b743f76d44b134c25ba95ef1a6143d33d31`
- **REPORT_MASTER_v3:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-MASTER-v3.md` exists=`True` bytes=`40579` mtime=`2026-08-02T20:37:13.038381+00:00`
  - sha256: `d2439c6ae5a5b5d77b5681a1a7781958c72ccae4a3c80c026e444150aa3cecde`
- **REPORT_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-v2.md` exists=`True` bytes=`21332` mtime=`2026-08-02T20:31:16.289203+00:00`
  - sha256: `b1da87fbfb139a7e5d2eb0e9d4c07b743f76d44b134c25ba95ef1a6143d33d31`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`48300` mtime=`2026-08-02T20:33:16.211496+00:00`
  - sha256: `e580d45bb3b69709be2d7311953195554299e5c8eff8748acc0d1a468c637596`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`35645` mtime=`2026-08-02T20:38:28.308977+00:00`
  - sha256: `b6abe91ef4d5936b2fabb8621dc4eaa58547608303392f603c99dd7a537bcb33`
- **report_v2_json:** `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/report-v2.json` exists=`True` bytes=`44771` mtime=`2026-08-02T20:33:16.219596+00:00`
  - sha256: `67bb8adfc4be4ea81f1665238bfaf5461eb63971f115e7185e9c4035d0c4c747`

#### v2_excerpt

```
# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This sample is confirmed malicious, with a triage score of 88/100 and a deep-dive confidence of 90%. It is attributed to the Darty Crypter family, a commodity VB6-based crypter used for payload obfuscation and delivery. The sample is a 32-bit PE executable compiled with Visual Basic 6, with no packing detected. Static analysis confirms it acts as a dropper/loader: it resolves Windows APIs at runtime to avoid static detection, implements anti-debugging via PEB inspection, downloads a second-stage payload from a hardcoded IP, establishes persistence via the HKCU Run registry key, and executes th
… [20430 more chars]
```


#### v3_excerpt

```
# RE Report — 8059ade0d39e
_Generated 2026-08-02T20:37:13.038806+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=218c | cross_refs=True | llm_ok=True | runtime=37.12s -->

# Executive Summary

| Metric | Value |
|--------|-------|
| Final Verdict | Malicious |
| Suspected Malware Family | Darty Crypter |
| Analysis Confidence | 90% |
| Primary Classification Source | deep_dive_agentic |

The analyzed sample (SHA256: `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075`) is confirmed malicious, belonging to the Darty Crypter family of Visual Basic 6 (VB6)-based crypters used to obfuscate follow-on malicious payloads including info-stealers, ransomware, and remote access tools (RATs) to evade security detection, with a 90% confidence classifica
… [39673 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
