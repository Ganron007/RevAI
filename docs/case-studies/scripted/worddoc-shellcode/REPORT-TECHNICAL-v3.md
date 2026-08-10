> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 22:19:41 UTC

## 1. Executive Summary

This report details the analysis of a 509-byte raw shellcode binary (SHA256: 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f). The sample is identified as malicious with high confidence (score: 85) and is assessed to be a Cobalt Strike x86-64 staged shellcode beacon. The analysis is evidence-driven, relying on static indicators and YARA rule matches due to the absence of standard PE structure, imports, or functions. Key findings include the presence of a hardcoded Cobalt Strike beacon configuration containing the C2 domain `tunnelcs.fax-email.us` and watermark `15914547`, as well as signatures for Cobalt Strike shellcode functions and base64-encoded data. The file's high entropy (100) and lack of imports are consistent with position-independent shellcode that dynamically resolves APIs at runtime. The primary threat is command and control (C2) communication and payload staging for further malicious activity.

## 2. Sample Metadata

| Attribute | Value |
|---|---|
| **SHA256** | `9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f` |
| **File Path** | `/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin` |
| **Project Name** | 7 - Malware Lab Samples |
| **File Size** | 509 bytes |
| **File Type** | Raw Shellcode (x86-64) |
| **Architecture** | NONE (Malcat), x86-64 (metapc) (Deep Dive) |
| **Entropy** | 100 (source: malcat, file_summary, entropy 100) |
| **Verdict** | Malicious |
| **Score** | 85 |
| **Family Guess** | Cobalt Strike |
| **Analysis Confidence** | 90 |

## 3. File Layout & Structural Analysis

The binary is a single, monolithic block of code with no standard PE headers, sections, or import tables. This structure is characteristic of raw shellcode designed to be position-independent and executed directly in memory.

**Malcat File Summary** (source: malcat, file_summary):
```
sha256: 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f
size: 509
type: ?
architecture: NONE
entropy: 100
file_name: shellcode.bin
```

**File Layout (sections/regions)** (source: malcat, File Layout):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
|  | 0 | 509 | 509 | 100 | - |

The entire file is mapped as a single region starting at effective address (EA) 0 with a physical and virtual size of 509 bytes. The entropy of 100 is extremely high, which is a strong indicator of encryption, compression, or obfuscation. For shellcode, this is expected as the payload is often encoded or encrypted to evade static detection. The lack of rights flags is consistent with a raw binary file not being loaded by a standard executable loader.

## 4. Static Code Analysis

Static analysis is limited due to the shellcode's nature. Disassembly reveals a minimal prologue, and string analysis uncovers critical embedded configuration data.

**Radare2 Disassembly** (source: radare2, Disassembly):
The initial bytes show a `cld` instruction to clear the direction flag, followed by a `call` instruction. This is a common shellcode pattern to get the current instruction pointer (EIP/RIP) by calling the next instruction, which pushes the return address onto the stack. The `invalid` opcode at 0x00000006 suggests the disassembler encountered data or encoded instructions after the initial call.
```asm
┌ 7: fcn.00000000 ();
│           0x00000000      fc             cld
│           0x00000001      e82e2e2e2e     call 0x2e2e2e34
└           0x00000006      60             invalid
```
This prologue is typical for position-independent code that needs to locate its own base address in memory. The `call` instruction is likely a trick to push the address of the subsequent data onto the stack for later use.

**IDA Database Summary** (source: ida, IDA database summary):
- `funcs_count 0`: No standard functions were detected. This is expected for raw shellcode, which does not follow standard function prologues/epilogues and has a linear or custom execution flow.
- `imports_count 0`: No import table entries. This confirms the shellcode resolves all required Windows API functions dynamically at runtime, typically by walking the Process Environment Block (PEB) to find loaded DLLs like `kernel32.dll` and `ntdll.dll`.

**High-Signal Strings** (source: malcat, Top Strings):
The most significant string is found at EA 330:
` .aaa.stage.15914..XXXXXXXXXXXXXX..`
This string is a truncated representation of the full Cobalt Strike beacon configuration. The deep-dive analysis (source: deep_dive_agentic) provides the full interpretation: `'.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.'`. This contains:
- `.aaa.stage.`: A marker for a staged payload.
- `15914547`: The Cobalt Strike watermark, a unique identifier for the Cobalt Strike team server.
- `tunnelcs.fax-email.us`: The command and control (C2) domain.
- `XXXXXXXXXXXXXXXXXXXXX`: Likely padding or a placeholder for additional configuration data.

This string is direct evidence of Cobalt Strike beacon configuration embedded within the shellcode.

## 5. Behavioral & Dynamic Analysis

No dynamic analysis was performed in this report. The sample is raw shellcode, and executing it would require a controlled environment with a target process (e.g., `rundll32.exe`) and memory injection. Tools like Speakeasy or Frida were not applicable or not observed for this sample type.

**Speakeasy Emulation**: Not observed.
**Frida Runtime Instrumentation**: Not observed.

The behavioral intent is inferred from static indicators: the shellcode is designed to be injected into a process, resolve APIs dynamically, and establish a connection to the C2 domain `tunnelcs.fax-email.us` to receive further commands or stage additional payloads.

## 6. Network Indicators & C2

The primary network indicator is the hardcoded C2 domain extracted from the embedded beacon configuration.

**C2 Domain**: `tunnelcs.fax-email.us` (source: deep_dive_agentic, IDA string at addr 330)
**Cobalt Strike Watermark**: `15914547` (source: deep_dive_agentic, IDA string at addr 330)

The domain `fax-email.us` is a suspicious top-level domain often used in malicious campaigns. The subdomain `tunnelcs` suggests a tunneling or C2 service. The watermark `15914547` is a numeric identifier that can be used to track specific Cobalt Strike deployments or threat actor groups.

The shellcode likely uses HTTP/HTTPS for C2 communication, as is standard for Cobalt Strike beacons. The base64-encoded data detected by YARA (offset 372) may contain additional C2 configuration or encoded commands.

## 7. Capabilities Assessment

Based on the evidence, the shellcode possesses the following capabilities:

1.  **Position-Independent Execution**: Can run from any memory address without relocation. (Evidence: zero imports, zero functions, high entropy, single CODE segment - source: ida, malcat).
2.  **Dynamic API Resolution**: Resolves Windows API functions at runtime by walking the PEB. (Evidence: zero imports - source: ida, IDA database summary, funcs_count 0).
3.  **C2 Communication**: Contains an embedded configuration to connect to the C2 domain `tunnelcs.fax-email.us`. (Evidence: string at EA 330 - source: deep_dive_agentic).
4.  **Staged Payload Delivery**: The `.stage.` marker indicates this is a staged shellcode beacon, meaning it will download and execute a larger, more feature-rich beacon payload from the C2 server. (Evidence: string at EA 330 - source: deep_dive_agentic).
5.  **Obfuscation**: The high entropy (100) suggests the main body of the shellcode is encoded or encrypted, with a small stub to decode it in memory. (Evidence: entropy 100 - source: malcat, file_summary).

**capa Capability Rules**: No rules matched (source: capa, Capability Rules). This is expected as capa is designed for PE files and may not analyze raw shellcode effectively.

## 8. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| **SHA256** | `9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f` | Malicious shellcode sample |
| **Domain** | `tunnelcs.fax-email.us` | Cobalt Strike C2 server |
| **Watermark** | `15914547` | Cobalt Strike team server identifier |
| **YARA Rule** | `Cobalt_functions` | Matches known Cobalt Strike shellcode patterns at offsets 163 and 420 (source: yara, yara matches) |
| **YARA Rule** | `contains_base64` | Matches base64-encoded data at offset 372 (source: yara, yara matches) |
| **YARA Rule** | `domain` | Matches domain regex pattern at offset 2 (source: yara, yara matches) |

## 9. Detection Engineering

**YARA Rules** (source: yara, YARA Matches):
The following YARA rules from the pipeline matched the sample:

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@2 len=4 |
| contains_base64 | - | $a@372 len=20 |
| Cobalt_functions | - | $h1@163 len=4; $h4@420 len=4 |

**Detection Recommendations**:
1.  **Network Detection**: Create Snort/Suricata rules to detect DNS queries or HTTP/HTTPS connections to `tunnelcs.fax-email.us`.
2.  **Endpoint Detection**: Deploy YARA rules `Cobalt_functions` and `contains_base64` to scan memory and files for Cobalt Strike shellcode.
3.  **Behavioral Detection**: Monitor for processes (e.g., `rundll32.exe`, `msbuild.exe`) that exhibit dynamic API resolution patterns (e.g., calls to `GetProcAddress` after walking the PEB) and make outbound connections to suspicious domains.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Execution** | Shared Modules | T1129 | Shellcode is designed to be loaded and executed within the address space of another process. |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | High entropy (100) indicates the shellcode payload is encoded or encrypted (source: malcat, file_summary). |
| **Defense Evasion** | Process Injection | T1055 | Raw shellcode is a common payload for process injection techniques. |
| **Discovery** | Process Discovery | T1057 | Shellcode likely enumerates processes to find a suitable host for injection. |
| **Command and Control** | Application Layer Protocol | T1071 | C2 communication likely uses HTTP/HTTPS, as indicated by the embedded domain (source: deep_dive_agentic). |
| **Command and Control** | Ingress Tool Transfer | T1105 | The staged beacon will download additional payloads from the C2 server. |

## 11. What We Don't Know

1.  **Exact Injection Vector**: The method by which this shellcode is delivered and injected into a target process is unknown. It could be delivered via a document exploit, a dropper, or a network exploitation framework.
2.  **Full Beacon Configuration**: Only a partial configuration string was extracted. The complete set of beacon settings (sleep time, jitter, C2 fallback domains, named pipes, etc.) is not available from static analysis alone.
3.  **Post-Exploitation Activity**: What commands or modules the beacon would download and execute after establishing C2 is unknown. This requires dynamic analysis or access to the C2 server.
4.  **Threat Actor Attribution**: While the watermark `15914547` identifies a specific Cobalt Strike deployment, it does not directly attribute the activity to a named threat actor group without additional intelligence.
5.  **XOR Key**: The XOR search tool failed (source: xor, XOR Search), so if the shellcode body is XOR-encoded, the key is unknown.

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Engine | Status | Key Output |
|---|---|---|---|
| **Malcat** | - | Success | File summary, entropy, strings, layout |
| **IDA Pro** | - | Success | Database summary (0 functions, 0 imports), string extraction |
| **YARA-X** | yara-x | Success | 3 rule matches (domain, contains_base64, Cobalt_functions) |
| **Radare2** | - | Success | Initial disassembly of entry point |
| **capa** | ? | Not Applicable | 0 rules matched (expected for shellcode) |
| **FLOSS** | - | Not Applicable | 0 strings extracted (expected for shellcode) |
| **Ghidra** | - | Failed | Startup errors, no data provided |
| **XOR Search** | - | Failed | Return code 1, no candidates found |
| **Speakeasy** | - | Not Observed | No emulation performed |
| **Frida** | - | Not Observed | No runtime instrumentation performed |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled malware lab environment. The sample was analyzed statically using the tools listed in Appendix A. No dynamic analysis (execution) was conducted. The sample path is `/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin`. The project name is `7 - Malware Lab Samples`.
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
- **model**: mimo-v2.5-pro

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


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

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
  "rule_count": 3,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 2,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$a",
          "offset": 372,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Cobalt_functions",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$h1",
          "offset": 163,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$h4",
          "offset": 420,
          "length": 4,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = note: did you mean `\\{` instead of `{`?",
    "/opt/samples/rules/flat/Android_FakeBank_Fanta.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_FakeBank_Fanta.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_AliPay_smsStealer.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_AliPay_smsStealer.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found"
  ],
  "incomplete": true
}
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

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
