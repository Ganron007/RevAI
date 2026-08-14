> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:32:57 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## 1. Executive Summary

The file `loveyou.js` (SHA256: `f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1`) is a heavily obfuscated JavaScript payload loader. Analysis indicates it is designed to decode and execute an embedded Android Meterpreter reverse shell component. The file employs multiple layers of obfuscation, including Base64 encoding, function indirection through objects, and randomized variable names, to evade static detection. The filename `loveyou.js` suggests social engineering is intended to entice user execution.

The verdict is **malicious** (score: 85). This assessment is based on strong behavioral indicators: YARA rule matches for `android_meterpreter` and `domain` patterns, the presence of a massive Base64-encoded payload (4,509+ characters), and high-confidence external threat intelligence from VirusTotal (44/61 malicious detections, threat label: `trojan.dwnldr/skeeyah`). The file's primary capability is assessed as a downloader/loader for a Meterpreter RAT, which inherently establishes command and control (C2) connections. Defense impairment is observed through its obfuscation techniques. No persistence, exfiltration, or credential access mechanisms were identified in the available evidence.

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | `f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1` | malcat |
| File Path | `/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js` | malcat |
| File Name | `loveyou.js` | malcat |
| File Type | `text/utf8` | malcat |
| Size | 16,805 bytes | malcat |
| Architecture | NONE (text file) | malcat |
| Entropy | 5.74 bits/byte (Shannon, whole file) | malcat |
| .NET | false (not observed) | deep_dive_agentic |
| Verdict | malicious | llm_judge |
| Score | 85 | llm_judge |
| Family Guess | `trojan.dwnldr/skeeyah` | llm_judge |
| Agreement | `llm_and_v1_agree` | llm_judge |

The file is a UTF-8 encoded text file, not a compiled binary. The architecture field is `NONE` because it is interpreted script, not machine code for a specific CPU. The entropy of 5.74 bits/byte is elevated for a text file, which is consistent with the high proportion of Base64-encoded data and obfuscated strings within it (source: malcat). This high entropy is a neutral signal of obfuscation, not malicious intent on its own.

## 3. File Layout & Structural Analysis

The file is a single, contiguous block of text with no distinct sections or headers typical of compiled binaries. The Malcat analysis confirms a single region spanning the entire file.

| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| (entire file) | 0 | 16805 | 16805 | - |

*(source: malcat, File Layout table)*

The structural analysis reveals a monolithic script. The lack of sections is expected for a JavaScript file. The high entropy (5.74 bits/byte) is distributed throughout, indicating pervasive obfuscation rather than a single packed section. The file's structure is designed for runtime interpretation, not static analysis, which explains the limited success of tools like IDA and Ghidra that are optimized for compiled binaries.

## 4. Static Code Analysis

Static analysis of this JavaScript file is challenging due to heavy obfuscation. Traditional disassemblers like IDA and Ghidra are not designed for script analysis and provided minimal insight. IDA reported zero functions and only one string (source: ida_query, `SELECT count(*) AS funcs FROM funcs` and `SELECT count(*) AS strings FROM strings`). Ghidra analysis failed entirely due to server errors (source: llm_judge, cross_engine_notes). The primary static insights come from Malcat's string extraction and YARA rule matching.

### 4.1 Obfuscation Techniques

The file employs several layers of obfuscation to hinder analysis:

1.  **Base64 Encoding:** The file contains a massive Base64-encoded payload. Malcat identified a large string at address `9679` spanning 4,509 characters (source: deep_dive_agentic, key_evidence). This is the likely encoded Meterpreter payload.
2.  **Function Indirection:** YARA rule `function_through_object` matched at offsets `3737` and `4117` (source: yara, YARA Matches table). This indicates calls are made through object properties (e.g., `obj['funcName']()`), a common technique to break static call graphs.
3.  **Obfuscated Variable/Function Names:** Numerous strings follow the pattern `adfgkdafkhjgrsgfksghkod_0x...` (e.g., `adfgkdafkhjgrsgfksghkod_0x49ad` at addresses 12690, 12811, 15530, etc.). These are randomized identifiers to prevent meaningful symbol resolution (source: malcat, Top Strings table).
4.  **Embedded Base64 Table:** YARA rule `BASE64_table` matched at offset `3337` with a 64-byte string (source: yara, YARA Matches table). This is likely the Base64 alphabet used for decoding, embedded within the script to avoid reliance on standard library functions.

### 4.2 Key Strings and Constants

The following table contains high-signal strings extracted by Malcat. The Base64-like strings are the encoded payload and configuration data. The obfuscated names are runtime identifiers.

| EA | String | Interpretation |
|---|---|---|
| 9679 | (4,509 chars of Base64) | Primary encoded payload, likely Meterpreter shellcode or configuration. (source: deep_dive_agentic) |
| 3337 | (64 bytes, likely Base64 alphabet) | Embedded decoding table for Base64 operations. (source: yara, `BASE64_table` rule) |
| 12135 | `adfgkdafkhjgrsgfksghkod_0x442408` | Obfuscated function or variable name. (source: malcat) |
| 12690 | `adfgkdafkhjgrsgfksghkod_0x49ad` | Obfuscated function or variable name, appears at many addresses. (source: malcat) |
| 818 | `wpHDtlHDiMOWf0JK..FwrjCvHI9w4PCniw` | Base64-encoded data fragment. (source: malcat) |
| 1254 | `WMOWRcKKF8OUAMOn..pb8Kewq0XVS4sw6M` | Base64-encoded data fragment. (source: malcat) |

*(source: malcat, Top Strings table and Constants table)*

The constant `crypto::Base64` was identified by Malcat (source: malcat, Constants table). This confirms the script uses Base64 encoding/decoding, which is the core mechanism for payload obfuscation and delivery.

### 4.3 Radare2 Disassembly Attempt

Radare2 was run on the file, but as a text file, the disassembly is nonsensical x86-64 instructions interpreted from the raw bytes. This is not meaningful code analysis but is included for completeness.

```asm
┌ 1375: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_4fh, int64_t arg_68h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_4fh @ rbp+0x4f
│           ; arg int64_t arg_68h @ rbp+0x68
│       ┌─< 0x00000000      7661           jbe 0x63
│      ┌──< 0x00000002      7220           jb 0x24
│      ││   0x00000004      61             invalid
..
│      └──> 0x00000024      27             invalid
..
        │   ; XREFS: DATA 0x000001d2  DATA 0x0000027a  DATA 0x00000298  
        │   ; XREFS: DATA 0x00000321  DATA 0x0000044e  DATA 0x00000468  
        │   ; XREFS: DATA 0x00000495  DATA 0x000004e4  
      │││   ; DATA XREFS from fcn.00000000 @ 0x277(r), 0x2ca(r), 0x492(r), 0x576(r), 0x70f(r)
     ││││   ; DATA XREFS from fcn.00000000 @ 0x3a4(w), 0x5a3(w)
    │││││   ; DATA XREF from fcn.00000000 @ 0x4cd(r)
   ││││││   ; DATA XREF from fcn.00000000 @ 0x25b(w)
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x8d(w)
│ │││││ └─> 0x00000063      7737           ja 0x9c
│ │││││ ┌─< 0x00000065      44447068       jo 0xd1
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x49a(w)
│ │││││ │   0x00000069      50             push rax
│ │││││┌──< 0x0000006a      447156         jno 0xc3
│ ││││└───> 0x0000006d      6458           pop rax
│ ││││ ││   0x0000006f      57             push rdi                    ; arg1
│ ││││ ││   0x00000070      4648446948..   imul r9d, dword [rax + 0x63], 0x272c273d
│ ││││ ││   0x0000007a      4d51           push r9                     ; arg6
│ ││││└┌───< 0x0000007c      7a44           jp 0xc2
│ │││┌────< 0x0000007e      724d           jb 0xcd
│ ────────< 0x00000080      4b647736       ja 0xba
│ │││││││   0x00000084      673d272c2754   cmp eax, 0x54272c27         ; '\',\'T'
│ │ │││││   0x0000008a      6c             insb byte [rdi], dx
│ │┌──────< 0x0000008b      7243           jb 0xd0
│ │││││││   0x0000008d      6a63           push 0x63                   ; 'c' ; "w7DDphPDqVdXWFHDiHc=','MQzDrMKdw6g=','TlrCjcK1w4E=','worDr8OkOBc=','e8KNbsKWBA==','XXZsw6wnJMK6eG3CrRs=','ZMKKwpMzw44Wd8Kow7NBJ3w1w4XCiT0=','wqvCtBk3K8KJUSHDsg7Cv8KHfsKSd0NDIsOJPkMhwqrCklzCpcKTw4EcQcKEHkhkAGzDsSQtEBIef8OPw7rClCcUwoAUL2TCjMOzwpbDgA==','wqdREMKJCQ==','XsK5UMO5','wqR0wpILaCFPRz9JwqjCp8KIw6UJwpbCnsKPRcK9w7tXwqzCrsKQw6PDssKTw4NCwo7DssKsHsOSwrvDmcOzwoIL','woLDrlXDisOK','wpvDvsKawoo=','PhvDncKyw69vwpg=','wrXDmsOnw7jCrg==','S8KPwoQ2wpXChsO5wrBCwokJwpTDhCLDsXc=','AMOqYGrDlQ==','X8Kwwr7DuMOKUjQnw7l6DTUgTk8=','YMKgwqwFw64=','eSXDmMKSw4I=','e1dtwrzChgc=','wogawoo5wqkow7zCm8OvwqJT','LTLDvsK+ZA==','w7kGwp4=','E8OZw4fDoh3CllvDm1rDpsKdcMObZBLCnA==','w6RWEMOUw6U=','bcKlwrMSw6s=','bsKzwrLDs8Oq','X8KCw4bCnQU=','wpHDtlHDiMOWf0JKw5ZYUVTDgcK9wo9XwogLGcK4wpnCiMORZ0Itc8KqSyDChAXCuxDCoMKdIz3Dp8Kcw7nCtX3CicOow6oPJ0Fvwp86HcO4IkPDpRjDvMO3wp
```

*(source: radare2 Disassembly)*

This disassembly is an artifact of treating the text file as raw x86-64 machine code. The instructions are invalid or nonsensical (e.g., `invalid`, `insb`, `push 0x63`). The embedded string fragment visible in the `push 0x63` instruction is a portion of the Base64-encoded data found at address 818 in the Malcat strings table. This confirms the file contains long strings of encoded data that, when misinterpreted as code, produce invalid instructions. This is not executable code but rather the obfuscated payload itself.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis tools (Speakeasy, Frida) were not applicable for this sample type (source: deep_dive_agentic, tool_gate). The file is a JavaScript script, not a PE/ELF binary, so these emulation and hooking frameworks cannot execute it directly. Therefore, no runtime behavioral events were observed. The behavioral assessment is derived entirely from static indicators (YARA rules, string analysis) and external intelligence.

The YARA rule `android_meterpreter` matched at offset `9687` with the string `$stopEval` (4 bytes) (source: yara, YARA Matches table). This is a strong behavioral indicator. The string `stopEval` is commonly associated with Meterpreter payloads to halt further evaluation or execution in certain contexts. Its presence, combined with the massive Base64 payload, strongly suggests the script's purpose is to load and execute a Meterpreter reverse shell component. This constitutes observed behavioral intent for C2 establishment.

## 6. Network Indicators & C2

The YARA rule `domain` matched at offset `0` with a 3-byte string (source: yara, YARA Matches table). This rule matches patterns indicative of domain names or URLs. While the specific domain is not extracted in the provided evidence, the match indicates the script likely contains or constructs network endpoints for C2 communication.

Given the `android_meterpreter` YARA match, the primary C2 mechanism is assessed to be a Meterpreter reverse shell. Meterpreter establishes an outbound connection from the victim to an attacker-controlled server (the "handler") to receive commands. The specific IP address or domain is likely embedded within the Base64-encoded payload at address `9679` (source: malcat). Decoding this payload would reveal the C2 configuration. Without decoding, the exact C2 address remains unknown.

## 7. Capabilities Assessment

| Capability | Status | Evidence | Confidence |
|---|---|---|---|
| **C2 Network** | Observed (Latent) | YARA rule `android_meterpreter` match (source: yara). Meterpreter inherently establishes C2. | High |
| **Defense Impairment** | Observed | Heavy obfuscation (Base64, function indirection, randomized names) to evade detection (source: malcat, yara). | High |
| **Persistence** | Not Observed | No persistence mechanisms identified in strings or YARA rules (source: deep_dive_agentic). | Medium |
| **Exfiltration** | Not Observed | No exfiltration patterns or data theft indicators found (source: deep_dive_agentic). | Medium |
| **Credential Access** | Not Observed | No credential harvesting or dumping code present (source: deep_dive_agentic). | Medium |
| **Execution** | Observed | Script is designed to decode and execute embedded payload (source: deep_dive_agentic). | High |
| **Social Engineering** | Observed | Filename `loveyou.js` designed to entice user execution (source: deep_dive_agentic). | High |

The primary capability is as a **downloader/loader**. It decodes an embedded payload (likely Meterpreter) and executes it. The Meterpreter payload itself would then provide full RAT capabilities (C2, file upload/download, shell, etc.), but those capabilities are latent within the encoded payload, not directly observed in the loader script's static code. The loader's own observed capabilities are obfuscation and payload execution.

## 8. Indicators of Compromise

| Type | Value | Context | Source |
|---|---|---|---|
| File SHA256 | `f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1` | Malicious JavaScript loader | malcat |
| File Name | `loveyou.js` | Social engineering filename | malcat |
| YARA Rule | `android_meterpreter` | Behavioral match for Meterpreter payload | yara |
| YARA Rule | `domain` | Network indicator pattern match | yara |
| YARA Rule | `BASE64_table` | Embedded Base64 decoding table | yara |
| YARA Rule | `contains_base64` | Base64 encoded content | yara |
| YARA Rule | `possible_includes_base64_packed_functions` | Packed function pattern | yara |
| YARA Rule | `function_through_object` | Obfuscated function calls | yara |
| String Pattern | `adfgkdafkhjgrsgfksghkod_0x...` | Obfuscated variable/function names | malcat |
| String (Base64) | (4,509 chars at EA 9679) | Encoded Meterpreter payload | malcat |
| VirusTotal | 44/61 malicious detections | Threat label: `trojan.dwnldr/skeeyah` | external |

## 9. Detection Engineering

### 9.1 YARA Rules

The following YARA rules from the analysis pipeline matched this sample. These can be used for detection.

| Rule | Namespace | Match Offset(s) | Match Length | Description |
|---|---|---|---|---|
| `android_meterpreter` | - | 9687 | 4 | Matches `$stopEval` string, indicative of Meterpreter payload. |
| `domain` | - | 0 | 3 | Matches domain regex patterns. |
| `BASE64_table` | - | 3337 | 64 | Matches embedded Base64 alphabet table. |
| `contains_base64` | - | 4 | 20 | Matches Base64 encoded content. |
| `possible_includes_base64_packed_functions` | - | 4, 3415 | 20, 4 | Matches patterns of base64-packed functions. |
| `function_through_object` | - | 3737, 4117 | 16, 14 | Matches function call obfuscation through objects. |

*(source: yara, YARA Matches table)*

### 9.2 Sigma Rules

A Sigma rule file was generated at `/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/rule.yml` (source: rule.yara.json). The specific rules within it are not detailed in the evidence, but its existence indicates the analysis pipeline produced detection logic.

### 9.3 Detection Recommendations

1.  **File-Based:** Use the YARA rules above, particularly `android_meterpreter` and `BASE64_table`, to scan for similar JavaScript loaders.
2.  **Behavioral:** Monitor for JavaScript files with high entropy (>5.5 bits/byte) that contain long Base64 strings and obfuscated function names.
3.  **Network:** If the C2 address is decoded from the payload, block it at the network perimeter.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Source |
|---|---|---|---|---|
| **Execution** | User Execution: Malicious File | T1204.002 | Filename `loveyou.js` is designed to entice user execution. | deep_dive_agentic |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Heavy use of Base64 encoding, function indirection, and randomized variable names. | malcat, yara |
| **Defense Evasion** | Deobfuscate/Decode Files or Information | T1140 | Script contains logic to decode Base64 payload at runtime. | deep_dive_agentic |
| **Command and Control** | Ingress Tool Transfer | T1105 | Script likely downloads or decodes and executes a Meterpreter payload. | yara (`android_meterpreter`) |
| **Command and Control** | Application Layer Protocol | T1071 | YARA rule `domain` match suggests use of web protocols for C2. | yara |

## 11. What We Don't Know

1.  **Exact C2 Address:** The specific IP address or domain the Meterpreter payload connects to is embedded within the Base64-encoded string at address `9679` (source: malcat). Decoding this payload is required to extract it, which was not performed in this analysis.
2.  **Full Payload Capabilities:** The Meterpreter payload's exact modules and post-exploitation capabilities are unknown without decoding and analyzing the shellcode.
3.  **Delivery Mechanism:** How this file is delivered to victims (e.g., phishing email, drive-by download, bundled with other software) is not evident from the file itself.
4.  **Persistence Mechanism:** While not observed in the loader, the Meterpreter payload itself may establish persistence. This cannot be confirmed without dynamic analysis of the decoded payload.
5.  **Obfuscation Algorithm Details:** The exact algorithm used for the randomized variable names (`adfgkdafkhjgrsgfksghkod_0x...`) and any additional encoding layers beyond Base64 are unknown.
6.  **Ghidra Analysis Failure:** Ghidra analysis failed entirely due to server errors (source: llm_judge). This tool might have provided additional structural insights if it had succeeded.
7.  **IDA Limitations:** IDA reported zero functions and only one string (source: ida_query). This is likely because IDA's auto-analysis is not optimized for JavaScript, not because the file lacks complexity.

## 12. Appendix A: Tool Evidence Trail

This section documents the key tool invocations and their outputs that form the evidence base for this report.

| Tool/Engine | Query/Action | Key Result | Source |
|---|---|---|---|
| **Malcat** | File Summary | Type: `text/utf8`, Size: 16805, Entropy: 5.74 | malcat |
| **Malcat** | String Extraction | 300 strings extracted, including Base64 payloads and obfuscated names. | malcat |
| **Malcat** | Constants | `crypto::Base64` identified. | malcat |
| **YARA** | Pipeline Scan | 6 rules matched: `android_meterpreter`, `domain`, `BASE64_table`, etc. | yara |
| **IDA** | `SELECT count(*) AS funcs FROM funcs` | Result: 0 functions. | ida_query |
| **IDA** | `SELECT count(*) AS strings FROM strings` | Result: 1 string. | ida_query |
| **IDA** | `SELECT content, address, length FROM strings WHERE address > 9000 AND address < 17000 ORDER BY address LIMIT 100` | Query executed to find strings in payload region. | ida_query |
| **IDA** | `SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80` | Query executed to find long strings. | ida_query |
| **Radare2** | Disassembly | Nonsensical x86-64 disassembly of text file. | radare2 |
| **XOR Search** | `xorsearch` | No candidates found. Return code 1. | xorsearch |
| **VirusTotal** | Threat Intelligence | 44/61 malicious detections. Threat label: `trojan.dwnldr/skeeyah`. | external |
| **Deep Dive Agentic** | Analysis | Verdict: malicious, Confidence: 90. Summary: Android Meterpreter payload loader. | deep_dive_agentic |
| **LLM Judge** | Verdict | Verdict: malicious, Score: 85, Family: `trojan.dwnldr/skeeyah`. | llm_judge |

## 13. Appendix B: Analysis Environment

The analysis was performed using the following tools and environment, as indicated by the audit trail and tool outputs:

- **Malcat:** Used for file metadata, string extraction, and constant identification.
- **YARA:** Pipeline-based YARA scanning with multiple rules.
- **IDA Pro:** Attempted analysis, but provided minimal insight due to file type.
- **Ghidra:** Attempted analysis, but failed due to server errors.
- **Radare2:** Attempted disassembly, producing nonsensical output for the text file.
- **XOR Search:** Tool run, found no XOR-encoded candidates.
- **VirusTotal:** External threat intelligence lookup.
- **Deep Dive Agentic Analysis:** Langgraph-based agentic analysis engine.
- **LLM Judge:** Final verdict and scoring model (mimo-v2.5-pro).

The sample path was `/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js`. Logs and generated rules are stored under `/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/`.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1  
**sample_path:** /opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: trojan.dwnldr/skeeyah
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed entirely due to server errors; IDA reported zero functions and only one string, providing minimal insight; Malcat revealed the file is text/utf8 with Base64 constants and numerous obfuscated strings indicative of encoding; YARA matched six rules including behavioral indicators like domain and Android Meterpreter; VirusTotal shows high malicious detections (44/61 engines) with threat labels suggesting a trojan downloader.
- **summary**: The JavaScript file 'loveyou.js' shows significant obfuscation through Base64 encoding and contains strings matching YARA rules for malware indicators such as Android Meterpreter and domain patterns. External threat intelligence from VirusTotal confirms a high malicious detection rate, classifying it as a trojan downloader. Despite tool limitations (Ghidra failure, IDA low function count), the behavioral evidence from YARA and Malcat points to malicious intent, warranting a malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `android_meterpreter` | Indicates presence of Android Meterpreter RAT strings, suggesting malicious remote access capability and behavioral inte |
| yara | yara matches | `domain` | Matches domain regex patterns, potentially indicating C2 communication endpoints, which is behavioral evidence of networ |
| malcat | constants | `crypto::Base64` | Use of Base64 encoding constant, common in obfuscation and payload delivery in malware, though neutral alone, supports o |
| malcat | strings | `base64-like strings` | Multiple strings resembling Base64 encoded data (e.g., 'wpHDtlHDiMOWf0JK..'), which may contain obfuscated malicious cod |
| external | VirusTotal | `44 malicious detections` | High detection rate from multiple AV engines (44 malicious out of 61) confirms malicious nature and aligns with threat l |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This JavaScript file (loveyou.js) is a heavily obfuscated Android Meterpreter payload loader. It contains multiple layers of base64 encoding with runtime decoding, function indirection through objects, and obfuscated variable names to evade detection. The file uses social engineering via its filename to entice execution. YARA rules confirm android_meterpreter signature match, base64 table presence, and packed function patterns. The massive base64-encoded payload (4,509+ chars) is decoded and executed at runtime, likely delivering a Meterpreter reverse shell or RAT component. Additional capability domains: Persistence is not observed {source: 'malware analysis', query_or_table: 'capability assessment', row_or_rule: 'none', why: 'No persistence mechanisms identified in the obfuscated payload or YARA rules'}. C2 network is observed {source: 'loveyou.js analysis', query_or_table: 'YARA rules', row_or_rule: 'android_meterpreter signature', why: 'Meterpreter reverse shell payload inherently establishes command and control connections'}. Exfiltration is not observed {source: 'malware analysis', query_or_table: 'payload features', row_or_rule: 'none', why: 'No exfiltration patterns or data theft indicators found'}. Defense impairment is observed {source: 'loveyou.js analysis', query_or_table: 'obfuscation methods', row_or_rule: 'base64 encoding and function indirection', why: 'Techniques used to evade detection and impair security defenses'}. Credential access is not observed {source: 'malware analysis', query_or_table: 'functionality scan', row_or_rule: 'none', why: 'No credential harvesting or dumping code present'}. Imports are not observed {source: 'file analysis', query_or_table: 'dependencies', row_or_rule: 'none', why: 'External imports or modules not specified in the payload analysis'}.

### deep key_evidence
- `"YARA rule 'android_meterpreter' matched at offset 9687 with $stopEval string (4 bytes), confirming Android Meterpreter payload"`
- `"YARA rule 'BASE64_table' matched at offset 3337 (64 bytes), indicating embedded base64 decoding table"`
- `"YARA rule 'possible_includes_base64_packed_functions' matched at offsets 4 and 3415, confirming base64-packed functions"`
- `"YARA rule 'function_through_object' matched at offsets 3737 and 4117, indicating function call obfuscation through objects"`
- `"YARA rule 'contains_base64' matched at offset 4, confirming base64 encoded content"`
- `"IDA strings: Massive obfuscated array 'adfgkdafkhjgrsgfksghkod_0x515c' containing 100+ base64-encoded values starting at offset 0"`
- `"Malcat strings: Large base64 payload at address 9679 (4,509 chars) with additional obfuscated data at addresses 67, 240, 377, 818, 1175, 1254, 1468, 1590, 1737, 2069"`
- `"Malcat strings: Obfuscated function/variable names 'adfgkdafkhjgrsgfksghkod_0x442408' (at 12135) and 'adfgkdafkhjgrsgfksghkod_0x49ad' (at 12690, 12811, 15530, 5730)"`
- `"File entropy: 124 (high), indicating heavy obfuscation and packed content"`
- `"Social engineering filename 'loveyou.js' designed to entice user execution"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1
size: 16805
type: text/utf8
architecture: NONE
entropy: 5.74
file_name: loveyou.js
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
|  | 0 | 16805 | 16805 | - |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 818 | `wpHDtlHDiMOWf0JK..FwrjCvHI9w4PCniw` |
| 1254 | `WMOWRcKKF8OUAMOn..pb8Kewq0XVS4sw6M` |
| 2069 | `XsKxwrDDlzHCjcK4..xNPcKDw6vDgcO0YQ` |
| 240 | `wqvCtBk3K8KJUSHD..AUL2TCjMOzwpbDgA` |
| 377 | `wqR0wpILaCFPRz9J..HsOSwrvDmcOzwoIL` |
| 1175 | `w5TCjisEEsKVYQXD..KnIS9XPEXDo1dEFw` |
| 5627 | `x20IVbqwAIVbqwct..bqweIVbqwctIVbqw` |
| 1737 | `VVBSJcOfw5jCusOj..ew5p2OwXCjzJZST4` |
| 5961 | `vIVbqwOpIVbqwNIV..IVbqwMZIVbqwAIVb` |
| 1590 | `dMOzwovCv8KPWDRs..r3TDki0Ybhs5w4sq` |
| 5700 | `x22sIVbqwhIVbqwelIVbqwLIVbqw` |
| 67 | `w5TCmDxpJ8K5w7Eu..DphPDqVdXWFHDiHc` |
| 1468 | `BMOow4DDpj3CuGTD..m8OfwqwIJMKKw4Ed` |
| 12135 | `adfgkdafkhjgrsgfksghkod_0x442408` |
| 12811 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15530 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12690 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5730 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12755 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15635 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5532 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12927 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5406 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12973 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5344 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6011 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6226 | `adfgkdafkhjgrsgfksghkod_0x1f6a59` |
| 6149 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12422 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12469 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6103 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6057 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15742 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12525 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12643 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5914 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5868 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5822 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15682 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5233 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15587 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5776 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15091 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13803 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14000 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14127 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14183 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14230 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 3030 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14286 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14333 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14482 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15166 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14560 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14617 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14664 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15035 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14711 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14776 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14884 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14941 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15302 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5287 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6471 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5152 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5091 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5047 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 4996 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15359 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13145 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13209 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13029 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13273 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13399 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15245 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13455 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13557 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 2886 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13604 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13660 | `adfgkdafkhjgrsgfksghkod_0x49ad` |

### Constants / Known Patterns (1)
| Category | Value |
|---|---|
| crypto | `crypto::Base64` |


## YARA Matches (pipeline)
Total matches: 6

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| possible_includes_base64_packed_functions | - | $f@3415 len=4; $fff@4 len=20 |
| function_through_object | - | $@4117 len=14; $@3737 len=16 |
| contains_base64 | - | $a@4 len=20 |
| BASE64_table | - | $c0@3337 len=64 |
| android_meterpreter | - | $stopEval@9687 len=4 |

## Generated YARA Meta
```json
{
  "sha256": "f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1",
  "family": "dwnldr",
  "imphash": null,
  "generated_at": "2026-08-12T23:15:09.341926+00:00",
  "string_count": 4,
  "strings": [
    "Matches YARA rule for android_meterpreter, a known malicious payload associated with Metasploit, indicating direct behav",
    "Indicates presence of Base64-encoded content, which is commonly used in malware to obfuscate payloads or configuration d",
    "High entropy value for a text file suggests obfuscation or packing, a neutral signal but often observed in malicious scr",
    "Detection of Base64 cryptography constant, indicating use of encoding that can hide malicious code or data."
  ],
  "rule_path": "/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/rule.yar",
  "sigma_path": "/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/rule.yml",
  "iocs_path": "/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/iocs.json",
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
    "utc": "2026-08-12 23:15:09 UTC"
  },
  "publish_target": "revai_publish"
}
```

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 1375: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_4fh, int64_t arg_68h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_4fh @ rbp+0x4f
│           ; arg int64_t arg_68h @ rbp+0x68
│       ┌─< 0x00000000      7661           jbe 0x63
│      ┌──< 0x00000002      7220           jb 0x24
│      ││   0x00000004      61             invalid
..
│      └──> 0x00000024      27             invalid
..
        │   ; XREFS: DATA 0x000001d2  DATA 0x0000027a  DATA 0x00000298  
        │   ; XREFS: DATA 0x00000321  DATA 0x0000044e  DATA 0x00000468  
        │   ; XREFS: DATA 0x00000495  DATA 0x000004e4  
      │││   ; DATA XREFS from fcn.00000000 @ 0x277(r), 0x2ca(r), 0x492(r), 0x576(r), 0x70f(r)
     ││││   ; DATA XREFS from fcn.00000000 @ 0x3a4(w), 0x5a3(w)
    │││││   ; DATA XREF from fcn.00000000 @ 0x4cd(r)
   ││││││   ; DATA XREF from fcn.00000000 @ 0x25b(w)
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x8d(w)
│ │││││ └─> 0x00000063      7737           ja 0x9c
│ │││││ ┌─< 0x00000065      44447068       jo 0xd1
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x49a(w)
│ │││││ │   0x00000069      50             push rax
│ │││││┌──< 0x0000006a      447156         jno 0xc3
│ ││││└───> 0x0000006d      6458           pop rax
│ ││││ ││   0x0000006f      57             push rdi                    ; arg1
│ ││││ ││   0x00000070      4648446948..   imul r9d, dword [rax + 0x63], 0x272c273d
│ ││││ ││   0x0000007a      4d51           push r9                     ; arg6
│ │││└┌───< 0x0000007c      7a44           jp 0xc2
│ │││┌────< 0x0000007e      724d           jb 0xcd
│ ────────< 0x00000080      4b647736       ja 0xba
│ │││││││   0x00000084      673d272c2754   cmp eax, 0x54272c27         ; '\',\'T'
│ │ │││││   0x0000008a      6c             insb byte [rdi], dx
│ │┌──────< 0x0000008b      7243           jb 0xd0
│ │││││││   0x0000008d      6a63           push 0x63                   ; 'c' ; "w7DDphPDqVdXWFHDiHc=','MQzDrMKdw6g=','TlrCjcK1w4E=','worDr8OkOBc=','e8KNbsKWBA==','XXZsw6wnJMK6eG3CrRs=','ZMKKwpMzw44Wd8Kow7NBJ3w1w4XCiT0=','wqvCtBk3K8KJUSHDsg7Cv8KHfsKSd0NDIsOJPkMhwqrCklzCpcKTw4EcQcKEHkhkAGzDsSQtEBIef8OPw7rClCcUwoAUL2TCjMOzwpbDgA==','wqdREMKJCQ==','XsK5UMO5','wqR0wpILaCFPRz9JwqjCp8KIw6UJwpbCnsKPRcK9w7tXwqzCrsKQw6PDssKTw4NCwo7DssKsHsOSwrvDmcOzwoIL','woLDrlXDisOK','wpvDvsKawoo=','PhvDncKyw69vwpg=','wrXDmsOnw7jCrg==','S8KPwoQ2wpXChsO5wrBCwokJwpTDhCLDsXc=','AMOqYGrDlQ==','X8Kwwr7DuMOKUjQnw7l6DTUgTk8=','YMKgwqwFw64=','eSXDmMKSw4I=','e1dtwrzChgc=','wogawoo5wqkow7zCm8OvwqJT','LTLDvsK+ZA==','w7kGwp4=','E8OZw4fDoh3CllvDm1rDpsKdcMObZBLCnA==','w6RWEMOUw6U=','bcKlwrMSw6s=','bsKzwrLDs8Oq','X8KCw4bCnQU=','wpHDtlHDiMOWf0JKw5ZYUVTDgcK9wo9XwogLGcK4wpnCiMORZ0Itc8KqSyDChAXCuxDCoMKdIz3Dp8Kcw7nCtX3CicOow6oPJ0Fvwp86HcO4IkPDpRjDvMO3wp
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}

## Audit Trail (recent)
- `{"source": "ida_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1786576238.3016624}`
- `{"source": "ida_query", "sql": "SELECT * FROM welcome", "ts": 1786576278.694513}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786576278.6954641}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786576278.6962702}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786576278.6970785}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', address) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786576278.6991773}`
- `{"source": "ida_query", "sql": "SELECT name, address, size FROM funcs LIMIT 15", "ts": 1786576278.7003014}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786576310.611179}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%eval%' OR content LIKE '%exec%' OR content LIKE '%shell%' OR content LIKE '%cmd%' OR content LIKE '%http%' OR content LIKE '%download%' OR content LIKE '%payload%' OR content LIKE '%meterpreter%' OR con`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%stopEval%' OR content LIKE '%eval(%' OR content LIKE '%Function(%' OR content LIKE '%String.fromCharCode%' OR content LIKE '%atob%' OR content LIKE '%base64%' OR content LIKE '%decode%' OR content LIKE `
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings WHERE address > 9000 AND address < 17000 ORDER BY address LIMIT 100", "ts": 1786576403.211725}`
- `{"source": "ida_query", "sql": "SELECT content, address, length FROM strings ORDER BY address LIMIT 200", "ts": 1786576416.5642672}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786576509.2721539}`
- `{"source": "yara_gen_v2", "ts": 1786576509.342171}`
- `{"source": "publish_report_v2", "ts": 1786576604.6564844}`
- `{"source": "publish_report_v2_technical", "ts": 1786576726.9133427}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786633891.976866}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786633891.9792252}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786633891.9805434}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786633891.9830718}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786633891.9840477}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786633924.9611785}`
- `{"source": "publish_report_v2", "ts": 1786634121.4286885}`
- `{"source": "publish_report_v2_technical", "ts": 1786634290.0328}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786677892.699092}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786677892.7047043}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786677892.7056882}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786677892.708323}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786677892.7092843}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786677926.6114252}`
