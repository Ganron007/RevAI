# Pipeline AUDIT-REPORT — `38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73`

> Public-showcase grade evidence pack: tools, RAG, LLM, REPORT-MASTER-v2/v3.

- **Mode:** single
- **Audited at:** 2026-08-13T13:36:38.206149+00:00
- **Provenance:** `unknown` · engine `langgraph` · flags: budget=True redundant=True hallucination=True taxonomy=True · 2026-08-13 13:36:38 UTC
- **all_green:** `True`
- **Strict standard:** `False`
- **Session mode:** `single`
- **Sample:** `/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe`
- **Showcase pack:** `/opt/samples/logs/_showcase_audits/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73`

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

- source=`llm_judge` verdict=`malicious` confidence=`85`
- key_evidence_count=`11`

```json
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Trioris",
  "cross_engine_notes": "Multiple tools detect anti-debugging, network communication, data theft, and obfuscation. Ghidra, IDA, and MalCat confirm PE structure and anomalies. Capa identifies behavioral intent (credit card parsing, C2). VirusTotal shows high detection rate (55/72) with threat family 'Trioris/Cerbu'.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "Anti-debugging capability, common in malware to evade analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "Ability to create new processes, often used for process injection or launching malicious payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAlloc)",
      "why": "Dynamic memory allocation, common in code injection or unpacking."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "change_memory_protection (VirtualProtect)",
      "why": "Changing memory protection to execute injected code or modify existing code."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "parse credit card information",
      "why": "Indicates data theft targeting financial information, a clear malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "send data",
      "why": "Network communication capability for data exfiltration or C2."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "receive data",
      "why": "Network communication capability for command and control."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "resolve DNS",
      "why": "Network communication for domain resolution, typical of C2 infrastructure."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "reference HTTP User-Agent string",
      "why": "HTTP communication, likely for command and control or data exfiltration."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "anti_dbg",
      "why": "Anti-debugging technique detected, indicating evasion."
    },
    {
      "source": "external TI",
      "query_or_table": "VirusTotal",
      "row_or_rule": "55/72 detections, threat family trioris/cerbu",
      "why": "High detection rate and identified threat family confirm malicious nature."
    }
  ],
  "summary": "The sample is a PE x86 executable exhibiting multiple malicious behaviors: anti-debugging (IsDebuggerPresent, anti_dbg YARA), process creation and memory manipulation (CreateProcess, VirtualAlloc, VirtualProtect), network communication (send/receive data, DNS resolution, HTTP User-Agent), and data theft (credit card parsing). Obfuscation techniques (XorInLoop, DynamicString) are present but considered neutral alone; however, combined with behavioral indicators, they support malicious intent. VirusTotal reports 55/72 detections with threat family 'Trioris/Cerbu'. The sample is signed with an invalid signature, further raising suspicion.",
  "source": "llm_judge",
  "mo
… [3468 more chars]
```

#### `deep_dive`

- source=`deep_dive_agentic` verdict=`malicious` confidence=`90`
- key_evidence_count=`15`

```json
{
  "source": "deep_dive_agentic",
  "engine": "langgraph",
  "verdict": "malicious",
  "confidence": 90,
  "summary": "This PE is a trojan with HTTP-based C2 communication to the Russian domain 'twoyden.ru', SOCKS5 proxy/relay capability, system fingerprinting (VM detection, OS info), registry persistence via 'Software\\ClearSystem', anti-debug checks, RC4/XOR encryption, obfuscated stack strings, and privilege escalation via requireAdministrator manifest. It masquerades its User-Agent as 'NSISDL/1.2' while conducting HTTP POST/GET requests with full proxy awareness. Exfiltration is supported via HTTP POST requests to 'twoyden.ru' for data sending {Network_traffic_analysis, HTTP_POST_requests, twoyden.ru, exfiltration_capability}. Credential access techniques were not observed in the analysis {Dynamic_analysis, API_calls, absence_of_credential_functions, not_observed}.",
  "key_evidence": [
    "Domain 'twoyden.ru' referenced in FUN_00409aa5 (Ghidra string_refs, addr 0x00409aa5)",
    "HTTP/1.1 C2 communication with POST method, Host/Content-Type/Content-Length headers in FUN_004060ce (Ghidra string_refs)",
    "User-Agent: NSISDL/1.2 spoofing in FUN_004060ce to disguise C2 traffic as NSIS downloader (Ghidra strings, addr 4357332)",
    "Custom 'My-User-Agent:' header in FUN_0040aac8 (Ghidra string_refs, addr 0x0040aac8)",
    "Registry persistence via 'Software\\ClearSystem' keys with 'value_vm' and 'value_os' values (FUN_0040399b, FUN_00403a25)",
    "System fingerprinting: reads InstallDate from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, stores OS/VM info (Ghidra string_refs FUN_00403a25)",
    "Build/config string '/S pid=129 subid=10 mr=0 lang=ru' indicating Russian-locale targeting (Ghidra strings, addr 4359000)",
    "SOCKS5 proxy relay capability: 'socks' string present (Ghidra strings, addr 4356372), full WSA socket APIs (WSAConnect, WSASocketA, WSASend, WSARecv, WSAEventSelect)",
    "Proxy-aware HTTP: reads ProxyServer/ProxyOverride from Internet Settings registry, handles proxy-authenticate/www-authenticate responses (FUN_004095b5, FUN_0040791d)",
    "Anti-debug: IsDebuggerPresent import (pe_import_signals T1622), YARA anti-debug rule matches at offsets 169872/170594/169284",
    "Capa: obfuscated stackstrings (T1027.005), XOR encoding (T1027/C0026.002), RC4 KSA encryption (C0027.009/C0028.002)",
    "requireAdministrator manifest requesting elevated privileges (Ghidra strings, addr 4396736)",
    "Code injection capability: VirtualAlloc + VirtualProtect imports (pe_import_signals T1055), CreateProcessW for child process spawning",
    "Dynamic API resolution via LoadLibraryExW + GetProcAddress (pe_import_signals T1129)",
    "31 capa rules matched including network communication, file discovery, registry operations, process creation, and anti-analysis techniques"
  ],
  "incomplete_tooling": false,
  "successful_tool_calls": 28,
  "successful_non_bootstrap_tools": 14,
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
        "why": "o
… [577 more chars]
```

#### `publish`

- source=`llm_judge` verdict=`None` confidence=`None`
- key_evidence_count=`0`

```json
{
  "title": "Trioris/Cerbu Trojan Analysis Report",
  "markdown": "> **RevAI provenance** \u2014 commit `unknown` \u00b7 engine `langgraph` \u00b7 agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True \u00b7 generated 2026-08-13 13:19:21 UTC\n\n# Verdict sources (multi-source)\n\n| Source | Verdict |\n|--------|--------|\n| **Final** | **malicious** |\n| Triage upstream (quick \u222a deep) | malicious |\n| Quick scan | malicious |\n| Deep dive | malicious |\n| Publish LLM (claimed) | malicious |\n\n- **Locked over publish LLM:** no\n\n## Executive Summary\n\nThis report details the analysis of a malicious Windows executable (SHA256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73) identified as a variant of the Trioris/Cerbu trojan family. The sample exhibits a comprehensive set of malicious capabilities, including HTTP-based command and control (C2) communication with the Russian domain 'twoyden.ru', SOCKS5 proxy/relay functionality, system fingerprinting, registry-based persistence, anti-analysis techniques, and data exfiltration capabilities. The binary is a 32-bit x86 PE executable with a high entropy of 6.82 bits/byte, indicating significant obfuscation or packing, though it is not UPX-packed. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this assessment, so all findings are based on static analysis, disassembly, and tool-based heuristics. The sample's malicious nature is confirmed by multiple behavioral indicators, including credit card parsing, C2 communication, and anti-debugging measures, aligning with the upstream triage verdict of 'malicious' with a score of 85/100. We assess with high confidence that this is a trojan designed for data theft and remote control, likely targeting Russian-speaking users based on embedded configuration strings.\n\n## 1. Sample Identification\n\nThe sample under analysis is a Windows Portable Executable (PE) file. Key identifiers are as follows:\n\n| Attribute | Value |\n|---|---|\n| SHA256 | 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73 |\n| File Path | /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe |\n| Project Name | day6 |\n| File Type | PE x86 executable |\n| Architecture | X86 (32-bit) |\n| Entropy | 6.82 bits/byte (whole-file Shannon entropy) |\n| Imphash | b5f4ee827c576f7005f9e544e6955bfb |\n| Packed | Not UPX-packed (source: UPX unpack evidence) |\n| .NET | Not a .NET assembly (source: dotnet_analyze) |\n| Signed | Invalid signature (source: triage verdict) |\n\nThe filename 'trojan_4982.exe' suggests it was part of a malware corpus collection. The high entropy value (6.82 bits/byte) indicates significant code obfuscation or compression, though not via UPX. The imphash can be used for clustering with other samples from the same family. (source: MalCat evidence, triage verdict)\n\n## 2. Classification\n\n**Verdict: MALICIOUS**\n\n**Family: Trioris/Cerbu**\n\n**Confidence: High (90%)**\n\nThe classification is based on multiple converging lines of evidence:\n\n1. **Behavioral Intent**: The sample contains code for parsing credit card information (source: capa rule 'parse credit card information'), which is a clear indicator of data theft intent. This is not a neutral capability; it is specifically designed for financial fraud.\n2. **C2 Communication**: HTTP-based communication with the 
… [19720 more chars]
```

### REPORT-MASTER excerpts

#### REPORT-MASTER-v2

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:19:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a malicious Windows executable (SHA256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73) identified as a variant of the Trioris/Cerbu trojan family. The sample exhibits a comprehensive set of malicious capabilities, including HTTP-based command and control (C2) communication with the Russian domain 'twoyden.ru', SOCKS5 proxy/relay functionality, system fingerprinting, registry-based persistence, anti-analysis techniques, and data exfiltration capabilities. The binary is a 32-bit x86 PE executable with a high entropy of 6.82 bits/byte, indicating significant obfuscation or packing, though it is not UPX-packed. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this assessment, so all findings are based on static analysis, disassembly, and tool-based heuristics. The sample's malicious nature is confirmed by multiple behavioral indicators, including credit card parsing, C2 communication, and anti-debugging measures, aligning with the upstream triage verdict of 'malicious' with a score of 85/100. We assess with high confidence that this is a trojan designed for data theft and remote control, likely targeting Russian-speaking users based on embedded configuration strings.

## 1. Sample Identification

The sample under analysis is a Windows Portable Executable (PE) file. Key identifiers are as follows:

| Attribute | Value |
|---|---|
| SHA256 | 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73 |
| File Path | /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe |
| Project Name | day6 |
| File Type | PE x86 executable |
| Architecture | X86 (32-bit) |
| Entropy | 6.82 bits/byte (whole-file Shannon entropy) |
| Imphash | b5f4ee827c576f7005f9e544e6955bfb |
| Packed | Not UPX-packed (source: UPX unpack evidence) |
| .NET | Not a .NET assembly (source: dotnet_analyze) |
| Signed | Invalid sign
… [17853 more chars]
```

#### REPORT-MASTER-v3

```markdown
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:31:34 UTC

# RE Report — 38b1bbc48c35
_Generated 2026-08-13T13:31:34.260418+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=234c | cross_refs=True | llm_ok=True | runtime=42.05s -->

## Executive Summary

**Top-line verdict:** Malicious | **Family:** Trioris | **Confidence:** High (90%) | **Summary:** This sample is identified as the Trioris malware family, a malicious tool likely designed for data theft and persistence. High-confidence detection is supported by multiple YARA matches and CAPA rules indicating encryption, network, and anti-analysis capabilities.

The analysis concludes with strong agreement between the language model (LLM) and v1 tools, reinforcing the malicious verdict (source: v1_summary, llm_and_v1_agree). The v1_summary shows a high threat score of 290, based on 20 YARA matches and 31 CAPA rules (source: v1_summary, yara, capa), which collectively indicate behaviors consistent with known malware patterns such as RC4 encryption, XOR encoding, and HTTP status checks (source: cross-section:Capability Assessment, capa). Deep dive analysis from an agentic source provides a confidence level of 90%, suggesting reliable identification (source: deep_confidence, deep_dive_agentic).

| Attribute       | Value                                      | Evidence Source                          |
|-----------------|--------------------------------------------|------------------------------------------|
| Verdict         | Malicious                                  | v1_summary, llm_and_v1_agree            |
| Family Guess    | Trioris                                    | deep_dive_agentic, cross-section:Classification |
| Confidence      | 90% (High)                                 | deep_confidence                          |
| Key Findings    | YARA: 20 matches, CAPA: 31 rules           | v1_summary                               |

This assessment is hedged as likely malicious based on static analysis; dynamic analysis was not specified in the provided evidence, so runtime behavior remains inferred from capabilities like registry modification and obfuscated strings (source: cross-section:Behavioral Analysis, malcat). Overall, the sample warrants containme
… [38553 more chars]
```

### Artifact inventory

| Artifact | exists | bytes | sha256 |
|----------|--------|-------|--------|
| `verdict.json` | `True` | `6968` | `c89037caa09ac636` |
| `prompt.txt` | `True` | `32695` | `60c14efb080b51bf` |
| `pipeline-audit.json` | `True` | `116584` | `a0146b7e258cbfcd` |
| `AUDIT-REPORT.md` | `True` | `86231` | `8e1d14f2822f1d93` |
| `REPORT-MASTER-v2.md` | `True` | `20360` | `67c7af0d816d7cfc` |
| `REPORT-MASTER-v3.md` | `True` | `41075` | `cd7e77aca926f29c` |
| `REPORT-v2.md` | `True` | `20360` | `67c7af0d816d7cfc` |
| `REPORT-TECHNICAL.md` | `False` | `0` | `` |
| `REPORT-TECHNICAL-v3.md` | `True` | `62414` | `b9e57961e113d588` |
| `rule.yar` | `True` | `1073` | `23ca9a5941d4af00` |
| `intake-validation.json` | `True` | `3055` | `7dd1369fea88509d` |
| `source-decisions.json` | `True` | `2143` | `1e00b1f54129c500` |
| `malcat-triage.json` | `True` | `121019` | `a278faadef4c8a44` |
| `deep_dive/01-tools-raw.json` | `True` | `204244` | `86c00b75a963c1f9` |
| `deep_dive/01-tools-gate.json` | `True` | `921` | `f3d89b0704908331` |
| `deep_dive/05-deep-dive.json` | `True` | `4077` | `54a927f78274a782` |
| `deep_dive/03-prompt.txt` | `False` | `0` | `` |
| `quick_scan/00-tools-raw.json` | `True` | `196221` | `c7a412f4cacc6f65` |

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

- **intake_validation:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/intake-validation.json` exists=`True` bytes=`3055` mtime=`2026-08-12T21:36:55.939851+00:00`
  - sha256: `7dd1369fea88509dca82b720cb11f042e21f0466547780a64dc39f7e7c562cc4`
- **malcat_triage:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/malcat-triage.json` exists=`True` bytes=`121019` mtime=`2026-08-13T13:14:08.004000+00:00`
  - sha256: `a278faadef4c8a447046426f4a3878c5aece5f001ade0a3b1dd51d01627878f4`
- **source_decisions:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/source-decisions.json` exists=`True` bytes=`2143` mtime=`2026-08-12T21:36:55.940851+00:00`
  - sha256: `1e00b1f54129c50010d8ef2fc6fd5168223e70f984af18d1d9dd9a8616d58bd7`
- **ghidra_import_log:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/intake-analyzeHeadless.log` exists=`True` bytes=`9048` mtime=`2026-08-12T21:35:48.657001+00:00`
  - sha256: `aa2c4478ab2e73e48164d49be44d4c1c971420ea38f81617dfbf08ddb4ec2648`
- **ida_bootstrap_log:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/intake-idasql.log` exists=`True` bytes=`215` mtime=`2026-08-12T21:35:52.265001+00:00`
  - sha256: `7a6cd04caa7c2b890a9e03d340533b5d218f1183735f83f855e7ef8d80c05691`

#### source_decisions_excerpt

```
{
  "sha256": "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73",
  "imports": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra and IDA both report 143 imports, indicating consistency and reliability; malcat's count of 674 diverges significantly, suggesting potential overcounting or different analysis methods. Evidence: {tool summaries, ghidra imports: 143, ida imports: 143, malcat imports_count: 674}."
  },
  "functions": {
    "source": "ghidra",
    "confidence": "high",
    "reason": "Ghidra reports 747 functions and IDA reports 770, which are close and reasonable for the file size; malcat's count of 10 is extremely low and likely inaccurate. Evidence: {tool summaries, ghidra funcs: 747, ida funcs: 770, malcat functions_count: 10}."
  },
  "stri
… [1366 more chars]
```


#### malcat_triage_excerpt

```
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
    "file_name": "trojan_4982.exe",
    "file_path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
    "file_size": 235184,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.82,
    "sha256": "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73",
    "metadata": {
      "Certificate::ProgramName": "Microsoft Windows",
      "Certificate::Issuer": "Microso
… [120219 more chars]
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
  "rule_count": 31,
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
            "XOR"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "XOR",
          "id": "C0026.002"
        }
      ]
    },
    {
      "name": "encrypt data using RC4 KSA",
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
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Encryption Key",
            "RC4 KSA"
          ],
          "objective": "Cryptography",
          "behavior": "Encryption Key",
          "method": "RC4 KSA",
          "id": "C0028.002"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File
… [5500 more chars]
```

#### `yara` — ok=`True` why=`ok`

```json
{
  "rule_count": 20,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 182084,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 157710,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 138188,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$c4",
          "offset": 45729,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 45739,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 45752,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 45762,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 227622,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 18194,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 28,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "o
… [7550 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 987,
  "strings_sampled": 80,
  "strings": [
    "HARDWARE\\ACPI\\krb.mainsetup.vbox|HARDWARE\\ACPI\\DSDT\\VBOX__|HARDWARE\\ACPI\\FADT\\VBOX__|HARDWARE\\ACPI\\RSDT\\VBOX__|HARDWARE\\ACPI\\SSDT\\VBOX__|HARDWARE\\ACPI\\DSDT\\VirtualBox|HARDWARE\\ACPI\\DSDT\\Parallels Work",
    "`.rdata",
    "@.data",
    "@.reloc",
    "</tq<\\tm<.um",
    ",j*Yf;",
    "j*XVf9",
    "s-9>w)+>",
    "tM9>t3",
    "C 93tr",
    "<0r><9w:",
    "RRPQRh",
    "Gf94xu",
    "<p|u<3",
    "PSSSSSS",
    "Yj8Yjx",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "j/_j\\[f;",
    "t3h<3B",
    "t\"hH3B",
    "QQSVWd",
    "PP9E u",
    "PPPPPPPP",
    "jA[jZZ+",
    "htHjlZ;",
    "HHtXHHt",
    "nt'joZ;",
    "YYjgXf9",
    ">0t<NAj0X",
    "~pjCXf",
    "v\tN+D$",
    "HHtVHHt",
    "uaPPPS",
    "YY_^[]",
    "tHHt*Ht#",
    "j@j _W",
    "QQSVWh",
    "j\"_f9y",
    ",SVWj0X",
    "Wj0XPV",
    "SSPQSW",
    "?:uBGW",
    "} kE$<",
    "~';_t|%3",
    "PWWWWV",
    "PSSSSV",
    "URPQQh",
    ";t$,v-",
    "UQPXY]Y[",
    "Ht+Ht$Ht",
    "+t\"HHt",
    "bWWWWj",
    "permission denied",
    "file exists",
    "no such device",
    "filename too long",
    "device or resource busy",
    "io error",
    "directory not empty",
    "invalid argument",
    "no space on device",
    "no such file or directory",
    "function not supported",
    "no lock available",
    "not enough memory",
    "resource unavailable try again",
    "cross device link",
    "operation canceled",
    "too many files open",
    "permission_denied",
    "address_in_use",
    "address_not_available",
    "address_family_not_supported",
    "connection_already_in_progress",
    "bad_file_descriptor",
    "connection_aborted",
    "connection_refused",
    "connection_reset"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 986
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 70.18,
  "size_bytes": 235184,
  "static_only": false,
  "size_exceeded_deobfuscate_limit": false
}
```

#### `malcat` — ok=`True` why=`not_applicable:pe`

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
    "file_name": "trojan_4982.exe",
    "file_path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
    "file_size": 235184,
    "type": "PE",
    "architecture": "X86",
    "entropy": 6.82,
    "sha256": "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73",
    "metadata": {
      "Certificate::ProgramName": "Microsoft Windows",
      "Certificate::Issuer": "Microsoft Windows Production PCA 2011 (Organization=Microsoft Corporation / Unit=? / Country=US)",
      "Certificate::Subject": "Microsoft Windows",
      "Certificate::Org Details": "Microsoft Corporation / Unit=? / State=Washington / Locality=Redmond / Country=US / Email=?",
      "Certificate::Validity": "from 2015-08-18 to 2016-11-18",
      "Certificate::SerialNumber": "33000000bce120fdd27cc8ee930000000000bc",
      "Certificate::HashAlgorithm": "SHA256",
      "Certificate::CryptAlgorithm": "RSA",
      "VersionInfo::CompanyName": " ",
      "VersionInfo::FileDescription": "new_era",
      "VersionInfo::FileVersion": "1.1.0.1",
      "VersionInfo::InternalName": "new_era.exe",
      "VersionInfo::LegalCopyright": "Copyright  (C) 2016",
      "VersionInfo::OriginalFilename": "new_era.exe",
      "VersionInfo::ProductName": "new_era",
      "VersionInfo::ProductVersion": "1.1.0.1"
    },
    "entrypoint_ea": 57943,
    "layout": [
      {
        "name": "header",
        "effective_address": 0,
        "physical_size": 1024,
        "virtual_size": 0,
        "rights": "",
        "entropy": 32
      },
      {
        "name": ".text",
        "effective_address": 1024,
        "physical_size": 133632,
        "virtual_size": 135168,
        "rights": "RX",
        "entropy": 140
      },
      {
        "name": ".rdata",
        "effective_address": 136192,
        "physical_size": 37376,
        "virtual_size": 40960,
        "rights": "R",
        "entropy": 74
      },
      {
        "name": ".data",
        "effective_address": 177152,
        "physical_size": 8704,
        "virtual_size": 20480,
        "rights": "RW",
        "entropy": 58
      },
      {
        "name": ".rsrc",
        "effective_address": 197632,
        "physical_size": 2560,
        "virtual_size": 4096,
        "rights": "R",
        "entropy": 111
      },
      {
        "name": ".reloc",
        "effective_address": 201728,
        "physical_size": 7680,
        "virtual_size": 8192,
        "rights": "R",
        "entropy": 123
      },
      {
        "name": "overlay",
        "effective_address": 209920,
        "physical_size": 44208,
        "virtual_size": 0,
        "rights": "",
        "entropy": 186
      }
    ],
    "kesakode_verdict": [],
    "entropy_malcat_raw": 134,
    "entropy_source": "whole_file_shannon_revai"
  },
  "views": {
    "anomalies": [
      {
        "name": "BigStringHiScore",
        "desc": "string has more than 256 characters and high interest score",
        "category": "strings",
        "level": 3,
        "num_hits": 1
      },
      {
        "name": "DynamicString",
        "desc": "string is constructed dynamically",
        "
… [146421 more chars]
```

### LLM citation grounding

```json
{
  "ok": true,
  "checked": 11,
  "hits": 11,
  "misses": [],
  "hit_examples": [
    "check_debugger (IsDebuggerPresent) pe_imports signals Anti-debugging capability, common in malware to evade analysis. pe",
    "create_process (CreateProcess) pe_imports signals Ability to create new processes, often used for process injection or l",
    "allocate_memory (VirtualAlloc) pe_imports signals Dynamic memory allocation, common in code injection or unpacking. pe_i",
    "change_memory_protection (VirtualProtect) pe_imports signals Changing memory protection to execute injected code or modi",
    "parse credit card information capa rules Indicates data theft targeting financial information, a clear malicious intent."
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "verdict": "malicious",
  "family": "Trioris",
  "score": 85,
  "agreement": "llm_and_v1_agree",
  "source": "llm_judge",
  "model": "mimo-v2.5-pro",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "Anti-debugging capability, common in malware to evade analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "Ability to create new processes, often used for process injection or launching malicious payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "allocate_memory (VirtualAlloc)",
      "why": "Dynamic memory allocation, common in code injection or unpacking."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "change_memory_protection (VirtualProtect)",
      "why": "Changing memory protection to execute injected code or modify existing code."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "parse credit card information",
      "why": "Indicates data theft targeting financial information, a clear malicious intent."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "send data",
      "why": "Network communication capability for data exfiltration or C2."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "receive data",
      "why": "Network communication capability for command and control."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "resolve DNS",
      "why": "Network communication for domain resolution, typical of C2 infrastructure."
    },
    {
      "source": "capa",
      "query_or_table": "capa rules",
      "row_or_rule": "reference HTTP User-Agent string",
      "why": "HTTP communication, likely for command and control or data exfiltration."
    },
    {
      "source": "yara",
      "query_or_table": "YARA matches",
      "row_or_rule": "anti_dbg",
      "why": "Anti-debugging technique detected, indicating evasion."
    },
    {
      "source": "external TI",
      "query_or_table": "VirusTotal",
      "row_or_rule": "55/72 detections, threat family trioris/cerbu",
      "why": "High detection rate and identified threat family confirm malicious nature."
    }
  ],
  "summary": "The sample is a PE x86 executable exhibiting multiple malicious behaviors: anti-debugging (IsDebuggerPresent, anti_dbg YARA), process creation and memory manipulation (CreateProcess, VirtualAlloc, VirtualProtect), network communication (send/receive data, DNS resolution, HTTP User-Agent), and data theft (credit card parsing). Obfuscation techniques (XorInLoop, DynamicString) are present but consid"
}
```

### Artifact paths (verify on disk)

- **prompt:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/prompt.txt` exists=`True` bytes=`32695` mtime=`2026-08-13T13:15:46.644954+00:00`
  - sha256: `60c14efb080b51bf005e6b05a2fc14e6db2815374f029c6d6717d929c720a928`
- **verdict:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/verdict.json` exists=`True` bytes=`6968` mtime=`2026-08-13T13:16:49.173630+00:00`
  - sha256: `c89037caa09ac63672261cd8d5ba01edb23db750e6868a2da7fc98134b01a1fd`

#### prompt_excerpt

```
# Triage evidence
sha256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
sample_path: /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe
ghidra_session: ghidra-pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
ida_session: ida-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73

## Source decisions (from intake validation)
- imports: ghidra (confidence=high) — Ghidra and IDA both report 143 imports, indicating consistency and reliability; malcat's count of 674 diverges significantly, suggesting potential overcounting or different analysis methods. Evidence: {tool summaries, ghidra imports: 143, ida imports: 143, malcat imports_count: 674}.
- functions: ghidra (confidence=high) — Ghidra reports 747 functions and IDA reports 770, which are close and reasonable for the file size; malcat's count of 10 is extremely low and likely inaccurate. Evidence: {tool summaries, ghidra funcs: 747, i
… [31637 more chars]
```


#### verdict_excerpt

```
{
  "verdict": "malicious",
  "score": 85,
  "family_guess": "Trioris",
  "cross_engine_notes": "Multiple tools detect anti-debugging, network communication, data theft, and obfuscation. Ghidra, IDA, and MalCat confirm PE structure and anomalies. Capa identifies behavioral intent (credit card parsing, C2). VirusTotal shows high detection rate (55/72) with threat family 'Trioris/Cerbu'.",
  "key_evidence": [
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "check_debugger (IsDebuggerPresent)",
      "why": "Anti-debugging capability, common in malware to evade analysis."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "create_process (CreateProcess)",
      "why": "Ability to create new processes, often used for process injection or launching malicious payloads."
    },
    {
      "source": "pe_imports",
      "query_or_table": "pe_imports signals",
      "row_or_rule": "
… [5968 more chars]
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
  "rule_count": 31,
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
            "XOR"
          ],
          "objective": "Data",
          "behavior": "Encode Data",
          "method": "XOR",
          "id": "C0026.002"
        }
      ]
    },
    {
      "name": "encrypt data using RC4 KSA",
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
            "Cryptography",
            "Encrypt Data",
            "RC4"
          ],
          "objective": "Cryptography",
          "behavior": "Encrypt Data",
          "method": "RC4",
          "id": "C0027.009"
        },
        {
          "parts": [
            "Cryptography",
            "Encryption Key",
            "RC4 KSA"
          ],
          "objective": "Cryptography",
          "behavior": "Encryption Key",
          "method": "RC4 KSA",
          "id": "C0028.002"
        }
      ]
    },
    {
      "name": "get common file path",
      "attack": [
        {
          "parts": [
            "Discovery",
            "File and Directory Discovery"
          ],
          "tactic": "Discovery",
          "technique": "File and Directory Discovery",
          "subtechnique": "",
          "id": "T1083"
        }
      ],
      "mbc": [
        {
          "parts": [
            "Discovery",
            "File
… [5499 more chars]
```

#### `pe_imports` — ok=`True` why=`ok`

```json
{
  "engine": "pe_imports",
  "sample_size": 235184,
  "duration_s": 0.03,
  "import_count": 143,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
    },
    {
      "label": "allocate_memory",
      "api_match": "VirtualAlloc",
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
  "rule_count": 20,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 182084,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 157710,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 138188,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$c4",
          "offset": 45729,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 45739,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 45752,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 45762,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 227622,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": []
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 18194,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 28,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "o
… [7528 more chars]
```

#### `floss` — ok=`True` why=`ok`

```json
{
  "floss_ok": true,
  "string_count": 987,
  "strings_sampled": 80,
  "strings": [
    "HARDWARE\\ACPI\\krb.mainsetup.vbox|HARDWARE\\ACPI\\DSDT\\VBOX__|HARDWARE\\ACPI\\FADT\\VBOX__|HARDWARE\\ACPI\\RSDT\\VBOX__|HARDWARE\\ACPI\\SSDT\\VBOX__|HARDWARE\\ACPI\\DSDT\\VirtualBox|HARDWARE\\ACPI\\DSDT\\Parallels Work",
    "`.rdata",
    "@.data",
    "@.reloc",
    "</tq<\\tm<.um",
    ",j*Yf;",
    "j*XVf9",
    "s-9>w)+>",
    "tM9>t3",
    "C 93tr",
    "<0r><9w:",
    "RRPQRh",
    "Gf94xu",
    "<p|u<3",
    "PSSSSSS",
    "Yj8Yjx",
    "SVWjA_jZ+",
    "uBjAYjZ+",
    "uHjAXf;",
    "j/_j\\[f;",
    "t3h<3B",
    "t\"hH3B",
    "QQSVWd",
    "PP9E u",
    "PPPPPPPP",
    "jA[jZZ+",
    "htHjlZ;",
    "HHtXHHt",
    "nt'joZ;",
    "YYjgXf9",
    ">0t<NAj0X",
    "~pjCXf",
    "v\tN+D$",
    "HHtVHHt",
    "uaPPPS",
    "YY_^[]",
    "tHHt*Ht#",
    "j@j _W",
    "QQSVWh",
    "j\"_f9y",
    ",SVWj0X",
    "Wj0XPV",
    "SSPQSW",
    "?:uBGW",
    "} kE$<",
    "~';_t|%3",
    "PWWWWV",
    "PSSSSV",
    "URPQQh",
    ";t$,v-",
    "UQPXY]Y[",
    "Ht+Ht$Ht",
    "+t\"HHt",
    "bWWWWj",
    "permission denied",
    "file exists",
    "no such device",
    "filename too long",
    "device or resource busy",
    "io error",
    "directory not empty",
    "invalid argument",
    "no space on device",
    "no such file or directory",
    "function not supported",
    "no lock available",
    "not enough memory",
    "resource unavailable try again",
    "cross device link",
    "operation canceled",
    "too many files open",
    "permission_denied",
    "address_in_use",
    "address_not_available",
    "address_family_not_supported",
    "connection_already_in_progress",
    "bad_file_descriptor",
    "connection_aborted",
    "connection_refused",
    "connection_reset"
  ],
  "per_category": {
    "decoded_strings": 1,
    "stack_strings": 0,
    "tight_strings": 0,
    "language_strings": 0,
    "language_strings_missed": 0,
    "static_strings": 986
  },
  "raw_key_total": 3,
  "floss_profile": "full",
  "floss_language": "none",
  "duration_s": 44.54,
  "size_bytes": 235184,
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
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "disassembly": {
    "0x0040ee57": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_24h @ ebp-0x24\n\u2502       \u254e   0x0040ee57      e852950000     call 0x4183ae\n\u2502       \u2514\u2500< 0x0040ee5c      e97ffeffff     jmp 0x40ece0\n..",
    "0x0040ada5": "; CALL XREF from entry0 @ 0x40edd8(x)\n\u250c 1000: int main (char **argv, char **envp, int32_t envp, int32_t arg_78h, int32_t arg_28h_2, int32_t arg_28h, int32_t arg_30h, int32_t arg_48h);\n\u2502           ; arg char **argv @ esp+0x78\n\u2502           ; arg char **envp @ esp+0x7c\n\u2502           ; arg int32_t envp @ esp+0x80\n\u2502           ; arg int32_t arg_78h @ esp+0x84\n\u2502           ; arg int32_t arg_28h_2 @ esp+0x88\n\u2502           ; arg int32_t arg_28h @ esp+0x8c\n\u2502           ; arg int32_t arg_30h @ esp+0x90\n\u2502           ; arg int32_t arg_48h @ esp+0xb0\n\u2502           ; var int32_t var_10h_5 @ esp+0x20\n\u2502           ; var int32_t var_14h_7 @ esp+0x24\n\u2502           ; var int32_t var_10h_4 @ esp+0x28\n\u2502           ; var int32_t var_1ch_5 @ esp+0x2c\n\u2502           ; var int32_t var_10h_3 @ esp+0x30\n\u2502           ; var int32_t var_10h_2 @ esp+0x34\n\u2502           ; var int32_t var_1ch_4 @ esp+0x38\n\u2502           ; var int32_t var_14h_6 @ esp+0x3c\n\u2502           ; var int32_t var_10h @ esp+0x40\n\u2502           ; var int32_t var_14h_5 @ esp+0x44\n\u2502           ; var int32_t var_1ch_6 @ esp+0x48\n\u2502           ; var int32_t var_14h_4 @ esp+0x4c\n\u2502           ; var int32_t var_14h_3 @ esp+0x50\n\u2502           ; var int32_t var_34h @ esp+0x54\n\u2502           ; var int32_t var_18h_2 @ esp+0x58\n\u2502           ; var int32_t var_14h_2 @ esp+0x5c\n\u2502           ; var int32_t var_1ch_3 @ esp+0x60\n\u2502           ; var int32_t var_18h @ esp+0x64\n\u2502           ; var int32_t var_14h @ esp+0x68\n\u2502           ; var int32_t var_1ch_2 @ esp+0x6c\n\u2502           ; var int32_t var_1ch @ esp+0x70\n\u2502           0x0040ada5      55             push ebp\n\u2502           0x0040ada6      8bec           mov ebp, esp\n\u2502           0x0040ada8      83e4f8         and esp, 0xfffffff8\n\u2502           0x0040adab      b8e4350000     mov eax, 0x35e4\n\u2502           0x0040adb0      e8db940000     call 0x414290\n\u2502           0x0040adb5      a1c0c44200     mov eax, dword [0x42c4c0]   ; [0x42c4c0:4]=0xbb40e64e\n\u2502           0x0040adba      33c4           xor eax, esp\n\u2502           0x0040adbc      898424e035..   mov dword [esp + 0x35e0], eax ; [0x35e0:4]=-1\n\u2502           0x0040adc3      53             push ebx\n\u2502           0x0040adc4      56             push esi\n\u2502           0x0040adc5      33c0           xor eax, eax\n\u2502           0x0040adc7      8d4c2448       lea ecx, [arg_48h]\n\u2502           0x0040adcb      57             push edi\n\u2502           0x0040adcc      89442428       mov dword [arg_28h], eax\n\u2502           0x0040add0      e851e9ffff     call 0x409726\n\u2502           0x0040add5      33ff           xor edi, edi\n\u2502           0x0040add7      8d4c244c       lea ecx, [arg_48h]\n\u2502           0x0040addb      47             inc edi\n\u2502           0x0040addc      e8008effff     call 0x403be1\n\u2502 
… [485 more chars]
```

#### `upx` — ok=`True` why=`ok`

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

#### `xor` — ok=`True` why=`ok`

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ......................................"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ......................................\n",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 0
}
```

#### `speakeasy` — ok=`True` why=`ok`

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
    "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!WaitForSingleObject",
      "KERNEL32.dll!OutputDebugStringW",
      "KERNEL32.dll!GetProcessHeap",
      "KERNEL32.dll!WideCharToMultiByte",
      "KERNEL32.dll!InitializeCriticalSectionAndSpinCount",
      "USER32.dll!CharNextW",
      "USER32.dll!MessageBoxW",
      "USER32.dll!LoadStringW",
      "USER32.dll!CharLowerW",
      "USER32.dll!LoadIconW",
      "ADVAPI32.dll!RegQueryValueExW",
      "ADVAPI32.dll!RegCloseKey",
      "ADVAPI32.dll!ConvertSidToStringSidW",
      "ADVAPI32.dll!RegOpenKeyExW",
      "ADVAPI32.dll!GetTokenInformation",
      "SHELL32.dll!SHGetFolderPathW",
      "ole32.dll!CoUninitialize",
      "ole32.dll!CoInitialize",
      "ole32.dll!CoCreateInstance",
      "SHLWAPI.dll!StrToIntW",
      "SHLWAPI.dll!StrDupW",
      "SHLWAPI.dll!StrCatW",
      "SHLWAPI.dll!PathQuoteSpacesW",
      "SHLWAPI.dll!StrCpyW",
      "WS2_32.dll!WSAResetEvent",
      "WS2_32.dll!WSASetLastError",
      "WS2_32.dll!WSAEnumNetworkEvents",
      "WS2_32.dll!WSACreateEvent",
      "WS2_32.dll!freeaddrinfo",
      "RPCRT4.dll!UuidCreateSequential"
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
  "checked": 15,
  "hits": 15,
  "misses": [],
  "hit_examples": [
    "Domain 'twoyden.ru' referenced in FUN_00409aa5 (Ghidra string_refs, addr 0x00409aa5)",
    "HTTP/1.1 C2 communication with POST method, Host/Content-Type/Content-Length headers in FUN_004060ce (Ghidra string_refs",
    "User-Agent: NSISDL/1.2 spoofing in FUN_004060ce to disguise C2 traffic as NSIS downloader (Ghidra strings, addr 4357332)",
    "Custom 'My-User-Agent:' header in FUN_0040aac8 (Ghidra string_refs, addr 0x0040aac8)",
    "Registry persistence via 'Software\\ClearSystem' keys with 'value_vm' and 'value_os' values (FUN_0040399b, FUN_00403a25)"
  ],
  "reason": ""
}
```

### LLM / outcome preview

```json
{
  "source": "deep_dive_agentic",
  "confidence": 90,
  "summary": "This PE is a trojan with HTTP-based C2 communication to the Russian domain 'twoyden.ru', SOCKS5 proxy/relay capability, system fingerprinting (VM detection, OS info), registry persistence via 'Software\\ClearSystem', anti-debug checks, RC4/XOR encryption, obfuscated stack strings, and privilege escal",
  "key_evidence": [
    "Domain 'twoyden.ru' referenced in FUN_00409aa5 (Ghidra string_refs, addr 0x00409aa5)",
    "HTTP/1.1 C2 communication with POST method, Host/Content-Type/Content-Length headers in FUN_004060ce (Ghidra string_refs)",
    "User-Agent: NSISDL/1.2 spoofing in FUN_004060ce to disguise C2 traffic as NSIS downloader (Ghidra strings, addr 4357332)",
    "Custom 'My-User-Agent:' header in FUN_0040aac8 (Ghidra string_refs, addr 0x0040aac8)",
    "Registry persistence via 'Software\\ClearSystem' keys with 'value_vm' and 'value_os' values (FUN_0040399b, FUN_00403a25)",
    "System fingerprinting: reads InstallDate from SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion, stores OS/VM info (Ghidra string_refs FUN_00403a25)",
    "Build/config string '/S pid=129 subid=10 mr=0 lang=ru' indicating Russian-locale targeting (Ghidra strings, addr 4359000)",
    "SOCKS5 proxy relay capability: 'socks' string present (Ghidra strings, addr 4356372), full WSA socket APIs (WSAConnect, WSASocketA, WSASend, WSARecv, WSAEventSelect)",
    "Proxy-aware HTTP: reads ProxyServer/ProxyOverride from Internet Settings registry, handles proxy-authenticate/www-authenticate responses (FUN_004095b5, FUN_0040791d)",
    "Anti-debug: IsDebuggerPresent import (pe_import_signals T1622), YARA anti-debug rule matches at offsets 169872/170594/169284",
    "Capa: obfuscated stackstrings (T1027.005), XOR encoding (T1027/C0026.002), RC4 KSA encryption (C0027.009/C0028.002)",
    "requireAdministrator manifest requesting elevated privileges (Ghidra strings, addr 4396736)",
    "Code injection capability: VirtualAlloc + VirtualProtect imports (pe_import_signals T1055), CreateProcessW for child process spawning",
    "Dynamic API resolution via LoadLibraryExW + GetProcAddress (pe_import_signals T1129)",
    "31 capa rules matched including network communication, file discovery, registry operations, process creation, and anti-analysis techniques"
  ],
  "model": null,
  "llm_audit": null
}
```

### Agentic tool-call history (excerpts)

- **yara_scan** ok=`True` checklist=`True` — Required checklist tool (yara)

```json
{
  "rule_count": 20,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
      "path": "/opt/sampl
… [10628 more chars]
```

- **malcat_analyze** ok=`True` checklist=`True` — Required checklist tool (malcat)

```json
{
  "analysis_id": 1,
  "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
    "file_name": "trojan_4982.exe",
    "file_
… [149364 more chars]
```

- **capa_analyze** ok=`True` checklist=`True` — Required checklist tool (capa)

```json
{
  "rule_count": 31,
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
… [8599 more chars]
```

- **pe_import_signals** ok=`True` checklist=`True` — Required checklist tool (pe_imports)

```json
{
  "engine": "pe_imports",
  "sample_size": 235184,
  "duration_s": 0.03,
  "import_count": 143,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "l
… [555 more chars]
```

- **floss_extract** ok=`True` checklist=`True` — Required checklist tool (floss)

```json
{
  "floss_ok": true,
  "string_count": 987,
  "strings_sampled": 80,
  "strings": [
    "HARDWARE\\ACPI\\krb.mainsetup.vbox|HARDWARE\\ACPI\\DSDT\\VBOX__|HARDWARE\\ACPI\\FADT\\VBOX__|HARDWARE\\ACPI\\RSDT\\VBOX__|HARDWARE\\ACPI\\SSDT\\VBOX__|HARDWARE\\ACPI\\DSDT\\VirtualBox|HARDWARE\\ACPI\\DSDT\\Parallels Work",
    "`.rdata",
    "@.data",
    "@.reloc",
    "</tq<\\tm<.um",
    ",j*Yf;",
    "j*X
… [1781 more chars]
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
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "disassembly": {
    "0x0040ee57": "\u250c 300: entry0 ();\n\u2502       \u254e   ; var int32_t var_4h @ ebp-0x4\n\u2502       \u254e   ; var int32_t var_1ch @ ebp-0x1c\n\u2502       \u254e   ; var int32_t var_24h @ ebp-0x24\n\u2502       \u254e   0x0040ee57
… [3585 more chars]
```

- **upx_unpack** ok=`True` checklist=`True` — Required checklist tool (upx)

```json
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "upx_probe_stdout": "                       Ultimate Packer for eXecutables\n                          Copyright (C) 1996 - 2026\nUPX 5.1.0       Markus Oberhumer, Laszlo Molnar & John Reiser    Jan 7th 2026\n\n\nTested 0 file"
}
```

- **xor_string_search** ok=`True` checklist=`True` — Required checklist tool (xor)

```json
{
  "xorsearch_ok": true,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "candidates": [
    "Found XOR 00 position 00000000: 00000100 ......................................"
  ],
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ......................................\n",
  "xorsearch_stderr": "",
  "xorsearc
… [18 more chars]
```

- **speakeasy_emulate** ok=`True` checklist=`True` — Required checklist tool (speakeasy)

```json
{
  "speakeasy_ok": true,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
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
    "path": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
    "exists": true,
    "hook_candidates": [
      "KERNEL32.dll!WaitForSingleObject",
      "KERNEL32.dll!OutputDebugStringW",
      "KERNEL32.dll!GetProcessHeap",
      "KERNEL32.dll!WideCharToMultiByte
… [940 more chars]
```

- **shellcode_extract** ok=`False` checklist=`True` — Required checklist tool (shellcode)
  - error: `no high-entropy executable/writable shellcode-size section found`

```json
{
  "shellcode_ok": false,
  "sample": "/opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe",
  "sections_analyzed": [
    {
      "name": ".text",
      "size": 133632,
      "entropy": 6.6627,
      "executable": true,
      "writable": false
    },
    {
      "name": ".rdata",
      "size": 37376,
      "entropy": 4.7076,
      "executable"
… [519 more chars]
```

- **revai_tools_sec** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sec)

```json
{
  "format": "pe",
  "findings": [
    {
      "name": "Address Space Layout Randomization",
      "present": true,
      "claimed": true,
      "note": "claim only: DYNAMIC_BASE set but no .reloc section \u2014 loads at preferred base",
      "consequence": "Without ASLR the image loads at a fixed base \u2014 a predictable address for ret2libc-style exploitation and ROP gadget pivots."
    },
  
… [1821 more chars]
```

- **revai_tools_sinks** ok=`True` checklist=`True` — Required checklist tool (revai_tools_sinks)

```json
{
  "format": "pe",
  "entry_point": "0x1000",
  "sink_count": 7,
  "sinks": [
    {
      "api": "createprocessw",
      "dll": "KERNEL32.dll",
      "class": "command_execution",
      "address": "0x40a8f0",
      "function": "fcn.0040a63d"
    },
    {
      "api": "heapalloc",
      "dll": "KERNEL32.dll",
      "class": "integer_overflow_size",
      "address": "0x4012d4",
      "function": "m
… [957 more chars]
```

- **revai_tools_audit** ok=`True` checklist=`True` — Required checklist tool (revai_tools_audit)

```json
{
  "format": "pe",
  "findings": [],
  "engine": "revai_tools_audit",
  "source": "revai_tools"
}
```

- **signal_extractors** ok=`True` checklist=`True` — Deterministic anti-analysis + dynamic-import-resolve signals

```json
{
  "anti_analysis_summary": {
    "categories": {},
    "total_signals": 0,
    "functions_with_signals": 0,
    "elapsed_s": 6.47,
    "note": "Deterministic; TLS callbacks are pre-entry-point candidates."
  },
  "dynamic_resolve_summary": {
    "resolver_funcs": 0,
    "resolve_sites": 0,
    "peb_module_walkers": 0,
    "ordinal_imports": 5,
    "min_resolve_calls": 2,
    "elapsed_s": 3.51,
 
… [101 more chars]
```

- **packer_scan** ok=`True` checklist=`True` — Deterministic packer checklist (packed-context for gate)

```json
{
  "label": "suspicious",
  "name": null,
  "score": 3
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
      "name": "FUN_004145e4",
      "address": "4277732",
      "size": "3099"
    },
    {
      "name": "FUN_00412067",
      "address": "4268135",
      "size": "3044"
    },
    {
      "name": "FUN_00415dda",
      "address": "4283866",
      "size": "2912"
    },
    {
      "name": "FUN_00409aa5",
      "address":
… [2274 more chars]
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
      "content": "R6033\r\n- Attempt to use MSIL code from this assembly during native code initialization\nThis indicates a bug in your application. It is most likely the result of calling an MSIL-compiled (/clr) function from a native constructor or from DllMain.\r\n",
      "address": "4352528",
      "length": "
… [6411 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "module"
  ],
  "rows": [
    {
      "name": "OpenProcessToken",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "RegCloseKey",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "RegOpenKeyExW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "RegQueryValueExW",
      "module": "ADVAPI32.DLL"
    },
    {
      "name": "CreateFileW",
  
… [3124 more chars]
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
      "content": ".com",
      "address": "4338516",
      "length": "10"
    },
    {
      "content": "twoyden.ru",
      "address": "4356928",
      "length": "22"
    },
    {
      "content": "1.1.0.1",
      "address": "4396356",
      "length": "16"
    },
    {
      "content": "1.1.0.1",
      "address": "4
… [341 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_00409aa5",
      "address": "4233893",
      "size": "2823",
      "cyclomatic_complexity": "161",
      "instruction_count": "660",
      "call_out_count": "146",
      "string_ref_count": "16"
    },
 
… [4556 more chars]
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
      "content": " Base Class Array'",
      "address": "4356140",
      "length": "19"
    },
    {
      "content": " Base Class Descriptor at (",
      "address": "4356112",
      "length": "28"
    },
    {
      "content": " Class Hierarchy Descriptor'",
      "address": "4356160",
      "length": "29"
    },
 
… [5685 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_004060ce",
      "func_addr": "4219086",
      "string_value": " HTTP/1.1\r\n"
    },
    {
      "func_name": "FUN_004060ce",
      "func_addr": "4219086",
      "string_value": " HTTP/1.1\r\n"
    },
    {
      "func_name": "FUN_0040aac8",
      "func_addr": "4238024",
      "str
… [1363 more chars]
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json"
}
```

- **ghidra_decompile** ok=`False` checklist=`False` — langgraph tool call
  - error: `session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json`

```json
{
  "error": "session registry not found: /opt/samples/sessions/pe-38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73.json"
}
```

- **pe_import_signals** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "engine": "pe_imports",
  "sample_size": 235184,
  "duration_s": 0.06,
  "import_count": 143,
  "signal_count": 6,
  "signals": [
    {
      "label": "check_debugger",
      "api_match": "IsDebuggerPresent",
      "attack": [
        "T1622"
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
      "l
… [555 more chars]
```

- **capa_analyze** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "rule_count": 31,
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
… [8599 more chars]
```

- **ghidra_query** ok=`False` checklist=`False` — langgraph tool call
  - error: `ghidrasql SQL error: no such column: e.from_func_addr`

```json
{
  "error": "ghidrasql SQL error: no such column: e.from_func_addr"
}
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "func_name",
    "func_addr",
    "string_value"
  ],
  "rows": [
    {
      "func_name": "FUN_0040399b",
      "func_addr": "4209051",
      "string_value": "Software\\ClearSystem"
    },
    {
      "func_name": "FUN_0040399b",
      "func_addr": "4209051",
      "string_value": "value_vm"
    },
    {
      "func_name": "FUN_00403a25",
      "func_addr": "4209189",
      "
… [4874 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "content",
    "address"
  ],
  "rows": [
    {
      "content": "connection_already_in_progress",
      "address": "4336144"
    },
    {
      "content": "connection_aborted",
      "address": "4336196"
    },
    {
      "content": "connection_refused",
      "address": "4336216"
    },
    {
      "content": "connection_reset",
      "address": "4336236"
    },
    {
     
… [1495 more chars]
```

- **ghidra_query** ok=`True` checklist=`False` — langgraph tool call

```json
{
  "columns": [
    "name",
    "address",
    "size",
    "cyclomatic_complexity",
    "instruction_count",
    "call_out_count",
    "string_ref_count"
  ],
  "rows": [
    {
      "name": "FUN_004113a5",
      "address": "4264869",
      "size": "651",
      "cyclomatic_complexity": "35",
      "instruction_count": "173",
      "call_out_count": "34",
      "string_ref_count": "34"
    },
    
… [1421 more chars]
```

### Artifact paths (verify on disk)

- **tools_raw:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/01-tools-raw.json` exists=`True` bytes=`204244` mtime=`2026-08-13T13:14:08.016000+00:00`
  - sha256: `86c00b75a963c1f9081aba36241fa8fa75abf71bbe0352dc5092f11b9f77eb22`
- **sql_evidence:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/00-sql-evidence.json` exists=`False` bytes=`0` mtime=`None`
- **prompt:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/03-prompt.txt` exists=`False` bytes=`0` mtime=`None`
- **llm_raw:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/04-llm-raw.json` exists=`False` bytes=`0` mtime=`None`
- **deep05:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/05-deep-dive.json` exists=`True` bytes=`4077` mtime=`2026-08-12T21:51:37.035984+00:00`
  - sha256: `54a927f78274a782f0a4a3e9a7dcf1d06a5ed4566d0b7999ffe2ec797e669d32`

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
  "summary": "This PE is a trojan with HTTP-based C2 communication to the Russian domain 'twoyden.ru', SOCKS5 proxy/relay capability, system fingerprinting (VM detection, OS info), registry persistence via 'Software\\ClearSystem', anti-debug checks, RC4/XOR encryption, obfuscated stack strings, and privilege escalation via requireAdministrator manifest. It masquerades its User-Agent as 'NSISDL/1.2' while conducting HTTP POST/GET requests with full proxy awareness. Exfiltration is supported via HTTP POST requests to 'twoyden.ru' for data sending {Network_traffic_analysis, HTTP_POST_requests, twoyden.ru, exfiltration_capability}. Credential access techniques were not observed in the anal
… [3277 more chars]
```

- **agentic:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/deep_dive/agentic_deep_dive.json` exists=`True` bytes=`598691` mtime=`2026-08-12T21:51:37.034984+00:00`
  - sha256: `1729a2facd4c8696a937a298865c6f4c1349866c74a1bfd9fb1f806ffe79bf93`

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

- **rule_yar:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar` exists=`True` bytes=`1073` mtime=`2026-08-12T21:51:39.937984+00:00`
  - sha256: `23ca9a5941d4af00e659a5f1676f9dcd12a7d8926fb54435130d1fbaa917c6b3`

#### excerpt

```
// yara_gen_v2.py — 2026-08-12T21:51:39.938491+00:00
import "pe"
rule CADRE_v2_trioris_cerbu_trojan_38b1bbc48c35 {
    meta:
        description = "RevAI v2 auto rule for Trioris/Cerbu trojan"
        sha256 = "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73"
        family = "trioris_cerbu_trojan"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "</tq<\\tm<.um" ascii wide
        $s1 = "s-9>w)+>" ascii wide
        $s2 = "<0r><9w:" ascii wide
        $s3 = "SVWjA_jZ+" ascii wide
        $s4 = "uBjAYjZ+" ascii wide
        $s5 = "j/_j\\[f;" ascii wide
        $s6 = "PPPPPPPP" ascii wide
        $s7 = ">0t<NAj0X" ascii wide
        $s8 = "tHHt*Ht#" asci
… [271 more chars]
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

- **REPORT_MASTER_v2:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/REPORT-MASTER-v2.md` exists=`True` bytes=`20360` mtime=`2026-08-13T13:19:21.388581+00:00`
  - sha256: `67c7af0d816d7cfc237d6c52c3bf64e3de7ab0003c6e9b1503adb5225bfa435d`
- **REPORT_MASTER_v3:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/REPORT-MASTER-v3.md` exists=`True` bytes=`41075` mtime=`2026-08-13T13:31:34.268532+00:00`
  - sha256: `cd7e77aca926f29c8ec36aee4e278b7cb3538a0a6b6c384540a2a4985c2f41af`
- **REPORT_v2:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/REPORT-v2.md` exists=`True` bytes=`20360` mtime=`2026-08-13T13:19:21.388581+00:00`
  - sha256: `67c7af0d816d7cfc237d6c52c3bf64e3de7ab0003c6e9b1503adb5225bfa435d`
- **REPORT_TECHNICAL_v2:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/REPORT-TECHNICAL-v2.md` exists=`True` bytes=`59371` mtime=`2026-08-13T13:22:31.212515+00:00`
  - sha256: `f4b2aec111a3f1cf0f7c3bba8391e232573962fc223787ddbc7fdcc428a15f57`
- **REPORT_TECHNICAL_v3:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/REPORT-TECHNICAL-v3.md` exists=`True` bytes=`62414` mtime=`2026-08-13T13:36:38.156113+00:00`
  - sha256: `b9e57961e113d588a340d511f5a276f8da0edbdf246c88722af61fa9dc18d04c`
- **report_v2_json:** `/opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/report-v2.json` exists=`True` bytes=`23220` mtime=`2026-08-13T13:22:31.217515+00:00`
  - sha256: `d41a7757c5d0c5d80ab57c9a20d9a3e82a97e28fd9bbc817dfbe3525cb3072d5`

#### v2_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:19:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a malicious Windows executable (SHA256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73) identified as a variant of the Trioris/Cerbu trojan family. The sample exhibits a comprehensive set of malicious capabilities, including HTTP-based command and control (C2) communication with the Russian domain 'twoyden.ru', SOCKS5 proxy/relay functionality, system fingerprint
… [19453 more chars]
```


#### v3_excerpt

```
> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:31:34 UTC

# RE Report — 38b1bbc48c35
_Generated 2026-08-13T13:31:34.260418+00:00_  
_Pipeline: section-based Map-Reduce, 3 pass-1 LLM calls + 14 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=234c | cross_refs=True | llm_ok=True | runtime=42.05s -->

## Executive Summary

**Top-line verdict:** Malicious | **Family:** Trioris | **Confidence:** High (90%) | **Summary:** This sample is identified as the Trioris malware family, a malicious tool likely designed for data theft and persistence. High-confidence detection is supported by multiple YARA matches and CAPA rules indicating encryption, network, and anti-analysis capabilities.

The analysis concludes with
… [40153 more chars]
```


---

## Manual verification checklist (public showcase)

1. Open every **Artifact path** and confirm bytes/mtime/sha256 match this report.
2. For each tool: confirm raw excerpt matches on-disk JSON (`01-tools-raw.json`).
3. For each LLM stage: `key_evidence` strings appear in tool/SQL JSON (citation grounding).
4. Confirm REPORT-MASTER-v2 **and** REPORT-MASTER-v3 are fresh vs deep_dive mtime.
5. If capa salvaged: malcat `capa_summary` exists and LLM cited it.
6. Showcase pack under `/opt/samples/logs/_showcase_audits/<sha>/` is complete.
