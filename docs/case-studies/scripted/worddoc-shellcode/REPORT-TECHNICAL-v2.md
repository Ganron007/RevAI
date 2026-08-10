> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 22:11:47 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

This report details the analysis of a 509-byte raw shellcode binary (SHA256: 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f). The sample is identified as a Cobalt Strike x86-64 staged shellcode beacon with high confidence (90%). The verdict is **malicious** (score: 85) based on strong behavioral-intent evidence from YARA rule matches and embedded configuration strings.

The shellcode contains an embedded beacon configuration with the C2 server `tunnelcs.fax-email.us` and Cobalt Strike watermark `15914547`. It exhibits hallmarks of position-independent shellcode: zero imports, zero detected functions, high entropy (100), and a single CODE segment. The shellcode resolves Windows APIs dynamically via PEB walking, a technique common in advanced shellcode to avoid static import tables.

Key evidence includes YARA rule matches for `Cobalt_functions` (offsets 163 and 420), `contains_base64` (offset 372), and `domain` (offset 2). The embedded string at address 330 (`.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.`) confirms the Cobalt Strike beacon configuration and C2 communication setup.

## 2. Sample Metadata

| Attribute | Value | Source |
|---|---|---|
| SHA256 | 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f | malcat |
| File Path | /opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin | malcat |
| File Size | 509 bytes | malcat |
| File Type | Raw shellcode (binary) | malcat |
| Architecture | x86-64 (metapc) | deep_dive_agentic |
| Entropy | 100 | malcat |
| Verdict | Malicious (score: 85) | llm_judge |
| Family Guess | Cobalt Strike | llm_judge |
| Analysis Date | 2026-08-09 | rule.yara.json |

## 3. File Layout & Structural Analysis

The file is a single, flat binary with no PE/ELF headers, consistent with raw shellcode. Malcat analysis reveals a single unnamed region spanning the entire file with maximum entropy.

**File Layout Table (source: malcat):**

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| (unnamed) | 0 | 509 | 509 | 100 | - |

The single region at EA 0 with physical and virtual size of 509 bytes and entropy of 100 indicates the entire file is treated as a monolithic block of code/data. The lack of section names or rights flags is typical for raw shellcode that does not conform to standard executable formats. The maximum entropy (100) suggests the content is either encrypted, compressed, or contains high-entropy shellcode instructions, which is neutral but common in obfuscated payloads.

## 4. Static Code Analysis

### 4.1 Disassembly Entry Point

The radare2 disassembly shows the beginning of the shellcode at address 0x00000000. The first instruction is `cld` (clear direction flag), a standard prologue for shellcode to ensure string operations move forward. This is followed by a `call` instruction with a large relative offset.

**Radare2 Disassembly (source: radare2):**
```asm
┌ 7: fcn.00000000 ();
│           0x00000000      fc             cld
│           0x00000001      e82e2e2e2e     call 0x2e2e2e34
└           0x00000006      60             invalid
```

The `cld` instruction at 0x00000000 is a common shellcode prologue to ensure the direction flag is clear for subsequent string operations (e.g., `rep movsb`). The `call 0x2e2e2e34` at 0x00000001 is a relative call with a large offset (0x2E2E2E2E). This is a classic shellcode technique: the `call` pushes the return address (0x00000006) onto the stack, which the shellcode can then pop and use as a pointer to its own data (a "getpc" or "call/pop" technique). The `invalid` instruction at 0x00000006 is likely data that follows the call, not executed code. This pattern is highly indicative of position-independent shellcode that needs to locate its own address in memory.

### 4.2 Function and Import Analysis

IDA analysis detected zero functions and zero imports, which is consistent with raw shellcode that does not use standard function prologues or an import table.

**IDA Database Summary (source: ida):**

| Metric | Value | Query |
|---|---|---|
| Functions Count | 0 | `SELECT count(*) AS funcs FROM funcs` |
| Strings Count | 13 | `SELECT count(*) AS strings FROM strings` |
| Imports | 0 | `SELECT module, name FROM imports LIMIT 50` |

The absence of functions (funcs_count=0) indicates the shellcode does not contain standard function prologues (e.g., `push rbp; mov rbp, rsp`). This is typical for shellcode that uses a flat, linear execution flow or jumps between code blocks without formal function boundaries. The zero imports (imports_count=0) confirm the shellcode does not rely on a static import table; instead, it resolves Windows APIs dynamically at runtime, likely by walking the Process Environment Block (PEB) to locate loaded DLLs and their export tables. This is a common technique in shellcode to avoid static analysis and evade detection.

### 4.3 String Analysis

IDA extracted 13 strings from the binary. The most significant string is the embedded Cobalt Strike beacon configuration at address 330.

**High-Signal Strings (source: ida):**

| Address | String | Significance |
|---|---|---|
| 330 | `.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.` | Cobalt Strike beacon config with watermark 15914547 and C2 domain tunnelcs.fax-email.us |

The string at address 330 is a Cobalt Strike beacon configuration marker. The format `.aaa.stage.<watermark>.<C2_domain>.<padding>` is characteristic of Cobalt Strike's staged payload delivery. The watermark `15914547` is a unique identifier for the Cobalt Strike team server or license. The domain `tunnelcs.fax-email.us` is the command and control (C2) server the beacon will communicate with. The `XXXXXXXXXXXXXXXXXXXXX` padding is likely a placeholder for additional configuration data that gets filled in at runtime. This string provides direct evidence of malicious intent: the shellcode is designed to establish a C2 channel with a specific Cobalt Strike infrastructure.

### 4.4 YARA Rule Matches

Three YARA rules matched on the sample, providing behavioral-intent evidence.

**YARA Matches (source: yara):**

| Rule | Namespace | Match strings (trimmed) | Significance |
|---|---|---|---|
| domain | - | $domain_regex@2 len=4 | Domain regex pattern detected at offset 2 |
| contains_base64 | - | $a@372 len=20 | Base64-encoded payload data at offset 372 |
| Cobalt_functions | - | $h1@163 len=4; $h4@420 len=4 | Known Cobalt Strike shellcode hash patterns at offsets 163 and 420 |

The `Cobalt_functions` rule matches at offsets 163 and 420 indicate the presence of known Cobalt Strike shellcode hash patterns. These hashes are used by Cobalt Strike to resolve API functions dynamically; their presence is strong evidence that this shellcode is part of the Cobalt Strike framework. The `contains_base64` match at offset 372 suggests the shellcode contains base64-encoded data, which could be additional configuration, payload, or encoded API strings. The `domain` match at offset 2 indicates a domain regex pattern, likely related to the C2 domain embedded in the configuration string.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis tools (Speakeasy, Frida) were not applicable for this sample, as it is raw shellcode without a PE header or standard executable structure. No runtime behavior was observed.

**Dynamic Analysis Status:**
- Speakeasy: not observed (not applicable for raw shellcode)
- Frida: not observed (not applicable for raw shellcode)

The shellcode's behavior can only be inferred from static analysis. Based on the embedded configuration and YARA matches, we assess the shellcode would, if executed:
1. Resolve Windows APIs dynamically via PEB walking (e.g., `kernel32.dll`, `ws2_32.dll` for network functions).
2. Establish a TCP connection to the C2 server `tunnelcs.fax-email.us`.
3. Download and execute additional payloads (staged delivery indicated by the `stage` marker).
4. Beacon back to the C2 server for further commands.

These inferences are based on the Cobalt Strike beacon configuration and are not directly observed runtime behavior.

## 6. Network Indicators & C2

The shellcode contains an embedded C2 domain and Cobalt Strike watermark, indicating command and control communication setup.

**C2 Indicators:**

| Indicator | Type | Source | Evidence |
|---|---|---|---|
| tunnelcs.fax-email.us | Domain (C2) | ida | String at address 330: `.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.` |
| 15914547 | Cobalt Strike Watermark | ida | Embedded in configuration string at address 330 |

The domain `tunnelcs.fax-email.us` is the C2 server the beacon is configured to communicate with. The watermark `15914547` is a unique identifier for the Cobalt Strike team server, which can be used to track the threat actor's infrastructure. The `stage` marker indicates this is a staged payload, meaning the shellcode will download additional components (the actual beacon DLL) from the C2 server before executing them. This is a common Cobalt Strike technique to minimize the initial payload size and evade detection.

## 7. Capabilities Assessment

Based on static analysis, the shellcode possesses the following capabilities:

| Capability | Status | Evidence | Confidence |
|---|---|---|---|
| Dynamic API Resolution | Present (likely) | Zero imports (source: ida), shellcode pattern (source: radare2) | High |
| C2 Communication | Present (configured) | Embedded C2 domain (source: ida), YARA domain match (source: yara) | High |
| Staged Payload Delivery | Present (configured) | `stage` marker in config string (source: ida) | High |
| Anti-Analysis (Obfuscation) | Present (likely) | High entropy (source: malcat), base64-encoded data (source: yara) | Medium |
| Process Injection | Not observed | No evidence in static analysis | Low |
| Persistence | Not observed | No evidence in static analysis | Low |
| Credential Theft | Not observed | No evidence in static analysis | Low |

The shellcode's primary capability is to establish a C2 channel with a Cobalt Strike server and download additional payloads. The dynamic API resolution capability allows it to avoid static import tables and evade detection. The high entropy and base64-encoded data suggest some level of obfuscation, but this is neutral and common in shellcode. No evidence of process injection, persistence, or credential theft was found in the static analysis.

## 8. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| SHA256 | 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f | Malicious shellcode sample |
| Domain | tunnelcs.fax-email.us | Cobalt Strike C2 server |
| Watermark | 15914547 | Cobalt Strike team server identifier |
| YARA Rule | Cobalt_functions | Matches Cobalt Strike shellcode patterns |
| YARA Rule | contains_base64 | Matches base64-encoded payload data |
| YARA Rule | domain | Matches domain regex pattern |
| String | .aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX. | Cobalt Strike beacon configuration |

## 9. Detection Engineering

### 9.1 YARA Rules

The following YARA rules were generated for this sample:

**Generated YARA Meta (source: rule.yara.json):**
```json
{
  "sha256": "9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f",
  "family": "Cobalt Strike",
  "imphash": null,
  "generated_at": "2026-08-09T13:45:23.453029+00:00",
  "string_count": 13,
  "strings": [
    ".aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX..",
    ".Sj.Sj.hH...j.Phj",
    "d.R0.R..R..r(.",
    "iPhdnsaThLw&.",
    "a.....@..C...",
    ".D$$[[aYZQ",
    "RW.R..B<.",
    "P.H..X .",
    "f..K.X..",
    "a.....HH",
    "Rule matches strings at offsets 163 and 420 associated with Cobalt Strike, a known malicious tool used for command and c",
    "Extremely high entropy indicates possible encryption, compression, or obfuscation, which is a neutral signal but common ",
    "No functions detected, which is typical for position-independent shellcode or raw binary without structured code, aligni"
  ],
  "rule_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/rule.yar",
  "sigma_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/rule.yml",
  "iocs_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/iocs.json",
  "yara_valid": true,
  "yara_check": "ok"
}
```

### 9.2 Detection Recommendations

1. **Network Detection:** Monitor for DNS queries and HTTP/HTTPS connections to `tunnelcs.fax-email.us`. Implement firewall rules to block this domain.
2. **Endpoint Detection:** Use the generated YARA rules to scan for similar shellcode samples in memory and on disk. Focus on the `Cobalt_functions` rule for Cobalt Strike shellcode patterns.
3. **Memory Scanning:** Implement memory scanning for shellcode patterns, particularly the `call/pop` technique observed at the entry point and the embedded configuration string.
4. **Behavioral Monitoring:** Monitor for processes that resolve APIs dynamically via PEB walking, especially those that establish network connections shortly after.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Not observed (shellcode may download PowerShell payloads) |
| Execution | Native API | T1106 | Dynamic API resolution via PEB walking (source: ida, zero imports) |
| Defense Evasion | Obfuscated Files or Information | T1027 | High entropy (source: malcat), base64-encoded data (source: yara) |
| Defense Evasion | Process Injection | T1055 | Not observed |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 domain `tunnelcs.fax-email.us` (source: ida) |
| Command and Control | Ingress Tool Transfer | T1105 | Staged payload delivery indicated by `stage` marker (source: ida) |
| Command and Control | Encrypted Channel | T1573 | Not observed (but likely given Cobalt Strike capabilities) |

The primary MITRE ATT&CK techniques are Execution via Native API (T1106) for dynamic API resolution, Defense Evasion via Obfuscated Files or Information (T1027) for the high entropy and base64 encoding, and Command and Control via Application Layer Protocol (T1071.001) for the embedded C2 domain. The staged payload delivery (T1105) indicates the shellcode will download additional components. Techniques like Process Injection (T1055) and Encrypted Channel (T1573) are not directly observed but are common in Cobalt Strike and may be present in the downloaded payloads.

## 11. What We Don't Know

1. **Full Payload:** The shellcode is staged, meaning it downloads additional components from the C2 server. The actual beacon DLL or payload is not present in this sample. We do not know the full capabilities of the final payload.
2. **Execution Context:** We do not know how this shellcode is delivered or executed. It could be injected into a process, delivered via a document exploit, or loaded by a dropper. The delivery mechanism is unknown.
3. **Runtime Behavior:** Dynamic analysis was not possible for this raw shellcode. We do not know the exact API calls it makes, the network protocol it uses (HTTP, HTTPS, DNS, etc.), or how it handles errors.
4. **Threat Actor:** While we have a Cobalt Strike watermark (15914547), we do not know which threat actor is using this infrastructure. The watermark could be associated with multiple actors.
5. **Additional Configuration:** The configuration string contains padding (`XXXXXXXXXXXXXXXXXXXXX`), which may hold additional settings (e.g., sleep time, jitter, kill date). These are unknown.
6. **Anti-Analysis Techniques:** Beyond high entropy and base64 encoding, we do not know if the shellcode employs additional anti-debugging or anti-VM techniques.

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Source | Key Findings |
|---|---|---|
| Malcat | malcat | File summary: 509 bytes, entropy 100, single region. Top strings extracted. |
| IDA | ida_query | Zero functions, zero imports, 13 strings. Key string at address 330. |
| YARA | yara | 3 rules matched: domain, contains_base64, Cobalt_functions. |
| Radare2 | radare2 | Disassembly at entry point: `cld; call 0x2e2e2e34`. |
| XOR Search | xorsearch | No XOR patterns found (return code 1). |
| Ghidra | (failed) | Analysis failed due to startup errors, no data. |
| Speakeasy | not_applicable | Not applicable for raw shellcode. |
| Frida | not_applicable | Not applicable for raw shellcode. |
| capa | not_applicable | Not applicable for raw shellcode. |
| UPX | not_applicable | Not applicable (not packed with UPX). |

## 13. Appendix B: Analysis Environment

| Component | Details |
|---|---|
| Sample Path | /opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin |
| Project Name | 7 - Malware Lab Samples |
| Analysis Date | 2026-08-09 |
| Tools Used | Malcat, IDA, YARA, Radare2, XOR Search |
| Analysis Type | Static analysis (dynamic not applicable) |
| Environment | Linux-based analysis environment (paths suggest /opt/samples) |
| Report Version | v2 (V5.16 evidence-first rules) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f  
**sample_path:** /opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin  
**project_name:** 7 - Malware Lab Samples

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Cobalt Strike
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed due to startup errors, providing no data. IDA and Malcat both indicate no functions or imports, consistent with raw shellcode. YARA rules detect Cobalt Strike-related patterns, providing behavioral evidence of malicious intent. Malcat's high entropy (100) is neutral but common in encrypted or packed code.
- **summary**: This 509-byte shellcode binary exhibits high entropy and no imports or functions, but YARA rules identify signatures for Cobalt Strike functions, strongly indicating malicious use for command and control or payload execution. The lack of structural features from IDA and Malcat supports its nature as raw shellcode, while the YARA match provides critical behavioral evidence of threat actor tooling.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `Cobalt_functions` | Rule matches strings at offsets 163 and 420 associated with Cobalt Strike, a known malicious tool used for command and c |
| malcat | file_summary | `entropy 100` | Extremely high entropy indicates possible encryption, compression, or obfuscation, which is a neutral signal but common  |
| ida | IDA database summary | `funcs_count 0` | No functions detected, which is typical for position-independent shellcode or raw binary without structured code, aligni |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Cobalt Strike x86-64 staged shellcode beacon. The 509-byte payload contains an embedded beacon configuration with C2 server tunnelcs.fax-email.us, Cobalt Strike watermark 15914547, and the 'stage' marker typical of Cobalt Strike's staged payload delivery. YARA rules Cobalt_functions and contains_base64 triggered on known shellcode patterns. The file has zero imports (position-independent shellcode resolves APIs dynamically via PEB walking), high entropy (100), and a single CODE segment — all hallmarks of shellcode. The base64-encoded data and domain pattern further confirm C2 communication setup.

### deep key_evidence
- `"IDA string at addr 330: '.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.' \u2014 Cobalt Strike beacon config with watermark 15914547 and C2 domain tunnelcs.fax-email.us"`
- `"YARA rule 'Cobalt_functions' matched at offsets 163 and 420 \u2014 known Cobalt Strike shellcode hash patterns"`
- `"YARA rule 'contains_base64' matched at offset 372 \u2014 base64-encoded payload data"`
- `"YARA rule 'domain' matched at offset 2 \u2014 domain regex pattern in raw shellcode"`
- `"File is 509 bytes, x86-64 (metapc), single CODE segment, entropy 100 \u2014 position-independent shellcode"`
- `"Zero imports (imports_count=0) \u2014 shellcode resolves Windows APIs dynamically via PEB walking"`
- `"Zero functions detected (functions_count=0) \u2014 no standard function prologues, raw shellcode execution flow"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f
size: 509
type: ?
architecture: NONE
entropy: 100
file_name: shellcode.bin
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
|  | 0 | 509 | 509 | 100 | - |

### Top Strings (37 extracted; showing 37)
| EA | String |
|---|---|
| 287 | `.Sj.Sj.hH...j.Phj` |
| 330 | `.aaa.stage.15914..XXXXXXXXXXXXXX..` |
| 264 | `a.....HH` |
| 396 | `H..A...` |
| 246 | `a.....@..C...` |
| 228 | `a.....@..C...` |
| 11 | `d.R0.R..R..r(.` |
| 2 | `....`.` |
| 110 | `f..K.X..` |
| 450 | `..?.` |
| 149 | `.h....h` |
| 196 | `a...` |
| 210 | `@...` |
| 317 | `...@.0` |
| 273 | `a......` |
| 46 | `RW.R..B<.` |
| 119 | `....` |
| 495 | `...|.` |
| 479 | `...Rh` |
| 467 | `WWWC.` |
| 439 | `_.G..` |
| 416 | `...hD` |
| 75 | `<I.4..` |
| 158 | `..j.hX` |
| 65 | `P.H..X .` |
| 56 | `.@x.` |
| 445 | `.u9.` |
| 136 | `X_Z..` |
| 104 | `X.X$.` |
| 180 | `iPhdnsaThLw&.` |
| 124 | `.D$$[[aYZQ` |
| 473 | `RWS.` |
| 490 | `[_Z=` |
| 457 | `.|$.1` |
| 404 | `_~.h` |
| 33 | `<a|., ` |
| 99 | `;}$u` |


## YARA Matches (pipeline)
Total matches: 3

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@2 len=4 |
| contains_base64 | - | $a@372 len=20 |
| Cobalt_functions | - | $h1@163 len=4; $h4@420 len=4 |

## Generated YARA Meta
```json
{
  "sha256": "9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f",
  "family": "Cobalt Strike",
  "imphash": null,
  "generated_at": "2026-08-09T13:45:23.453029+00:00",
  "string_count": 13,
  "strings": [
    ".aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX..",
    ".Sj.Sj.hH...j.Phj",
    "d.R0.R..R..r(.",
    "iPhdnsaThLw&.",
    "a.....@..C...",
    ".D$$[[aYZQ",
    "RW.R..B<.",
    "P.H..X .",
    "f..K.X..",
    "a.....HH",
    "Rule matches strings at offsets 163 and 420 associated with Cobalt Strike, a known malicious tool used for command and c",
    "Extremely high entropy indicates possible encryption, compression, or obfuscation, which is a neutral signal but common ",
    "No functions detected, which is typical for position-independent shellcode or raw binary without structured code, aligni"
  ],
  "rule_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/rule.yar",
  "sigma_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/rule.yml",
  "iocs_path": "/opt/samples/logs/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/iocs.json",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 13:45:23 UTC"
  },
  "publish_target": "revai_publish"
}
```

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 7: fcn.00000000 ();
│           0x00000000      fc             cld
│           0x00000001      e82e2e2e2e     call 0x2e2e2e34
└           0x00000006      60             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}

## Audit Trail (recent)
- `{"source": "ida_query", "sql": "SELECT * FROM welcome", "ts": 1786282621.259841}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786282621.261474}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786282621.2628062}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786282621.264019}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', address) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786282621.265216}`
- `{"source": "ida_query", "sql": "SELECT name, address, size FROM funcs LIMIT 15", "ts": 1786282621.2660797}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786282652.1118546}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings ORDER BY address LIMIT 50", "ts": 1786282722.7283938}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%stage%' OR content LIKE '%tunnel%' OR content LIKE '%email%' OR content LIKE '%.us%' OR content LIKE '%aaa%' OR address BETWEEN 325 AND 400", "ts": 1786282735.1414425}`
- `{"source": "ida_query", "sql": "SELECT * FROM welcome", "ts": 1786282942.413984}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786282942.4149556}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786282942.415812}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786282942.4165342}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', address) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786282942.4173236}`
- `{"source": "ida_query", "sql": "SELECT name, address, size FROM funcs LIMIT 15", "ts": 1786282942.4180076}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786282971.785533}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings ORDER BY address LIMIT 50", "ts": 1786283084.472171}`
- `{"source": "ida_query", "sql": "SELECT * FROM segments", "ts": 1786283093.5303278}`
- `{"source": "ida_query", "sql": "SELECT * FROM db_info", "ts": 1786283093.5315802}`
- `{"source": "agentic_recover_v4", "phase": "start", "ts": 1786283110.0892532}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786283123.441687}`
- `{"source": "yara_gen_v2", "ts": 1786283123.45322}`
- `{"source": "publish_report_v2", "ts": 1786283190.9600375}`
- `{"source": "publish_report_v2_technical", "ts": 1786283233.5246627}`
- `{"source": "publish_report_v2", "ts": 1786283945.3623621}`
- `{"source": "publish_report_v2_technical", "ts": 1786284043.1151102}`
- `{"source": "publish_report_v2", "ts": 1786284135.9738166}`
- `{"source": "publish_report_v2_technical", "ts": 1786284204.914774}`
- `{"source": "publish_report_v2", "ts": 1786285091.5602524}`
- `{"source": "publish_report_v2_technical", "ts": 1786285206.219666}`
