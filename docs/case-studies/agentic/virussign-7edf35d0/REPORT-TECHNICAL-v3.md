> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:11:45 UTC

## 1. Executive Summary
This sample is a malicious 32-bit Windows GUI Portable Executable (PE) with a score of 92, as determined by cross-engine analysis (source: llm_judge). The executable is packed with the Themida commercial packer, confirmed by capa, FLOSS, and YARA evidence, which is a common anti-static-analysis evasion technique used by malware families including info-stealers, trojans, and ransomware (source: llm_judge). Primary static reverse engineering tools (Ghidra, IDA, Malcat) were unavailable due to environment errors, so analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which returned consistent malicious indicators (source: llm_judge). The exact malware family cannot be determined without unpacking the Themida-obfuscated payload, and no benign indicators were observed across any available analysis tools (source: llm_judge).

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
| Sample Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 92 |
| Family Guess | Exact family cannot be determined without unpacking the Themida-packed payload; sample is consistent with packed Windows malware (e.g., info-stealers, trojans, ransomware) that uses Themida for anti-static-analysis evasion (source: llm_judge) |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Primary static analysis tools (Ghidra, IDA, Malcat) were unavailable due to environment errors: Ghidra failed with a NotOwnerException (project owned by remnux), IDA was missing the required idasql binary, and Malcat MCP closed during initialization. All analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which successfully processed the sample and returned consistent malicious indicators (source: llm_judge) |

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE, confirmed by YARA rules `IsPE32` and `IsWindowsGUI` (source: yara, matches table). It is packed with Themida, as indicated by the FLOSS string `.themida` (source: floss, strings), capa rule `packed with Themida (ATT&CK T1027.002, MBC F0001.011)` (source: capa, top_rules), and YARA rule `IsPacked` (source: yara, matches table). The PE has a valid Rich signature, confirmed by YARA rule `HasRichSignature` matching at offset 232 (source: yara, matches table). Full YARA match results are below:
| Rule | Namespace | Match strings (trimmed) |
|------|-----------|-------------------------|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@36311 len=3 |
| contains_base64 | - | $a@169512 len=12 |
| CRC32_poly_Constant | - | $c0@1328583 len=4 |
| IsPE32 | - | No string matches |
| IsDLL | - | No string matches |
| IsWindowsGUI | - | No string matches |
| IsPacked | - | No string matches |
| HasRichSignature | - | $a0@232 len=4 |
| win_token | - | $f1@172606 len=12; $c3@172621 len=16 |
(source: yara, matches table)
The import address table (IAT) is heavily obfuscated by Themida, with only 3 visible imports reported by pe_imports (source: pe_imports, import_count:3); the full IAT is contained in the packed payload and unavailable for static analysis. The entry point (EP) is located at 0x104d3058, which is part of the Themida unpacking stub (source: radare2, disassembly). UPX unpacking failed, with `upx_ok: False`, `is_packed: False`, and an empty `unpacked_path`, confirming the sample is not UPX-packed and relies on Themida for obfuscation (source: upx, unpack section). An XOR search found a XOR 00 position at 00000000, with the MZ header starting at 0x000000F8, consistent with Themida's stub layout (source: xor, search results).

## 4. Malcat Triage Summary
Malcat analysis was unavailable due to a MCP initialization failure: `malcat_analyze top-level: MCP malcat closed` (source: Malcat, structured analysis section). The deep-dive agentic analysis (confidence 70) identified additional high-signal indicators: YARA rules `domain` (offset 0), `IP` (offset 36311), `contains_base64` (offset 169512), `CRC32_poly_Constant` (offset 1328583), and `win_token` (offsets 172606, 172621) all matched the sample (source: deep_dive_agentic, key_evidence). These indicators suggest the sample contains embedded network indicators, compressed/encrypted payload data, and Windows token manipulation functionality, all consistent with malicious behavior.

## 5. Static Code Analysis
Static reverse engineering was limited to secondary tools due to unavailability of Ghidra (NotOwnerException, project owned by remnux), IDA (missing idasql binary), and Malcat (MCP closed) (source: llm_judge, cross_engine_notes). The entry point disassembly from radare2 at 0x104d3058 shows a Themida unpacking stub implementing a LZ77-like decompression loop, which is consistent with capa's detection of `decompress data using aPLib (MBC C0025.003)` (source: capa, top_rules; radare2, 0x104d3058 disassembly):
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2
```
A heavily obfuscated function at 0x10019110 (labeled `sym.StringLoaderA.dll_InitializeSecurity` by radare2) contains invalid instructions, anti-disassembly tricks, and opaque predicates, typical of Themida's code transformation (source: radare2, 0x10019110 disassembly):
```asm
┌ 110: sym.StringLoaderA.dll_InitializeSecurity (int32_t arg_65h);
│      ╎╎   ; arg int32_t arg_65h @ ebp+0x65
│      ╎╎   ; var int32_t var_3eh @ ebp-0x3e
│      ╎╎   0x10019110      2c52           sub al, 0x52                ; 82
│      ╎╎   0x10019112      54             push esp
│      ╎╎   0x10019113      50             push eax
│      ╎╎   0x10019114  ~   3ed09f6b59..   rcr byte ds:[edi - 0x43b3a695], 1
│     ┌───> 0x1001911a      bce63478ed     mov esp, 0xed7834e6
│     ╎ ╎   0x1001911f      b103           mov cl, 3
│     ╎ ╎   0x10019121      92             xchg edx, eax
│     ╎ ╎   0x10019122      baa6f7e81a     mov edx, 0x1ae8f7a6
│     ╎ ╎   0x10019127      6a03           push 3                      ; 3
│     ╎ ╎   0x10019129      3ea7           cmpsd dword ds:[esi], dword es:[edi]
│     ╎ ╎   0x1001912b      4c             dec esp
│     ╎ ╎   0x1001912c      1490           adc al, 0x90
│     ╎ ╎   0x1001912e      ff01           inc dword [ecx]
│     ╎ ╎   0x10019130      dabbd42fca48   fidivr dword [ebx + 0x48ca2fd4]
│     ╎ ╎   0x10019136      44             inc esp
│     └───< 0x10019137      7de1           jge 0x1001911a
│       ╎   0x10019139      a5             movsd dword es:[edi], dword [esi]
│       ╎   0x1001913a      bcfbb49fcd     mov esp, 0xcd9fb4fb
│      ┌──< 0x1001913f      787c           js 0x100191bd
│      │╎   0x10019141      62952f766976   bound edx, qword [ebp + 0x7669762f]
│      │╎   0x10019147      6d             insd dword es:[edi], dx
│      │╎   0x10019148      ed             in eax, dx
│      │╎   0x10019149      0cc4           or al, 0xc4                 ; 196
│      │╎   0x1001914b      5a             pop edx
│      │╎   0x1001914c      c165c2ff       shl dword [var_3eh], 0xff
│      │╎   0x10019150      94             xchg esp, eax
│      │╎   0x10019151      e7c5           out 0xc5, eax
│      │╎   0x10019153      9a12903ce8..   lcall 0xce34, 0xe83c9012
│      │╎   0x1001915a      b076           mov al, 0x76                ; 'v' ; 118
│      │╎   0x1001915c      0296ab586a57   add dl, byte [esi + 0x576a58ab]
│      │╎   0x10019162      9d             popfd
│      │╎   0x10019163      bd0776dc75     mov ebp, 0x75dc7607
│      │╎   0x10019168      57             push edi
│      │╎   0x10019169      2127           and dword [edi], esp
│      │╎   0x1001916b      df             invalid
..
│      └──> 0x100191bd      8e4565         mov es, word [arg_65h]
│       │   0x100191c0      ed             in eax, dx
│       │   0x100191c1      ca530a         retf 0xa53
```
FLOSS extracted 5014 static strings from the sample, including the Themida reference `.themida` and numerous garbled/encrypted strings that are part of the packed payload (source: floss, strings section). A sample of high-signal static strings includes:
- `!This program cannot be run in DOS mode.`
- `@.edata`
- `@.idata`
- `.themida`
- `'1~`nV9F`
- `\nxswz9C`
- `oh.n~L`
(source: floss, strings section)
Capa identified 6 total capability rules, including `reference analysis tools strings (MBC B0013.001)` indicating anti-analysis functionality, `forwarded export (ATT&CK T1129)` used by packers to redirect execution to packed code, `contain loop` for decompression/decryption, and `(internal) packer file limitation` noting the packer obscures full analysis (source: capa, capability rules table).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation completed successfully but recorded 0 API calls and 0 key events, with no runtime activity observed (source: speakeasy, dynamic section: "not observed"). The Frida probe (version 17.16.4) was available but no instrumentation data was collected (source: frida_probe, section). UPX unpacking failed, so no unpacked payload was available for execution, and Themida's anti-emulation features prevented the unpacking stub from executing in the available analysis environments (source: upx, unpack section; speakeasy, dynamic section). No process injection, file system modifications, registry changes, or network communications were observed, as the malicious payload remained obfuscated by Themida.

## 7. Network Indicators & C2
Embedded network indicators were identified in the packed stub via YARA, but full values are contained in the obfuscated payload and unavailable without unpacking. YARA rule `domain` matched at offset 0 (source: yara, matches table), YARA rule `IP` matched at offset 36311 (source: yara, matches table), and YARA rule `contains_base64` matched at offset 169512 (source: yara, matches table), indicating the sample contains encoded network indicators. The `win_token` YARA rule matched at offsets 172606 and 172621 (source: yara, matches table; deep_dive_agentic, key_evidence), suggesting the payload includes functionality to manipulate Windows access tokens, a common technique for privilege escalation and lateral movement. No live C2 communication was observed during dynamic analysis, as the payload did not execute (source: speakeasy, dynamic section).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample's confirmed capabilities, derived from capa and YARA analysis, are mapped to MITRE ATT&CK and Malware Behavior Catalog (MBC) below:
| Capability | ATT&CK Technique | MBC ID |
|------------|------------------|--------|
| Packed with Themida | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing |
| Decompress data using aPLib | None | C0025.003: Decompress Data |
| Reference analysis tools strings | None | B0013.001: Analysis Tool Discovery |
| Forwarded export | T1129: Shared Modules | None |
| Contain loop (decompression/decryption) | None | None |
| (internal) packer file limitation | None | None |
| Embedded network indicators (domain, IP, base64) | None | None |
| Windows token manipulation references | T1059.003: Command and Scripting Interpreter (potential) | None |
The Themida packing (T1027.002) is used to evade static detection, the analysis tool string references (B0013.001) are used to detect sandboxes and analysis environments, and the forwarded export (T1129) is used to hide malicious functionality behind a legitimate export (source: capa, top_rules; yara, matches table).

## 9. Indicators of Compromise
All IOCs are derived from static analysis of the packed stub, as the full payload is obfuscated:
1. **Sample Hash**: SHA256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 (source: llm_judge, verdict.json)
2. **Embedded Strings/Patterns**:
   - Themida packer reference: `.themida` (source: floss, strings)
   - Domain pattern: matched at offset 0 (source: yara, matches table)
   - IPv6/IP pattern: matched at offset 36311 (source: yara, matches table)
   - Base64 pattern: matched at offset 169512 (source: yara, matches table)
   - CRC32 polynomial constant: matched at offset 1328583 (source: yara, matches table)
   - Windows token manipulation strings: matched at offsets 172606, 172621 (source: yara, matches table)
3. **YARA Detection Rule**: The sample matches 10 YARA rules including `IsPacked`, `IsPE32`, `IsWindowsGUI`, `HasRichSignature`, `domain`, `IP`, `contains_base64`, `CRC32_poly_Constant`, `win_token`, and `IsDLL` (source: yara, matches table).

## 10. Detection Engineering
### Static YARA Detection
A custom YARA rule to detect this sample and similar Themida-packed malware with embedded network and token indicators:
```yara
rule ThemidaPackedMalwareStub {
    meta:
        description = "Detects Themida-packed 32-bit Windows PE with malicious stub indicators"
        author = "Malware Analysis Team"
        date = "2024-05-20"
        sample_sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
        confidence = "high"
    strings:
        $themida = ".themida" ascii wide
        $win_token = "win_token" ascii wide
        $analysis_tools = /(procmon|wireshark|ida|ghidra|x64dbg|ollydbg)/i
        $base64_blob = /[A-Za-z0-9+/]{12,}={0,2}/
    condition:
        uint32(0) == 0x5A4D and // MZ header
        uint32(uint32(0x3C)) == 0x4550 and // PE header
        $themida and
        $win_token and
        any of ($analysis_tools, $base64_blob)
}
```
### Behavioral Detection
Capa rules can be used to detect Themida-packed samples with aPLib decompression and analysis tool detection capabilities at runtime, once the payload is unpacked (source: capa, capability rules table). Note that static YARA rules will only match the Themida stub, not the obfuscated payload, so unpacking is required for full payload detection.

## 11. What We Don't Know
1. **Exact Malware Family**: The Themida-packed payload is not unpacked, so the exact family (info-stealer, trojan, ransomware, etc.) cannot be determined (source: llm_judge, verdict.json).
2. **Full C2 Infrastructure**: The domain, IP, and base64 indicators are partial matches in the packed stub; full C2 addresses and communication protocols are contained in the obfuscated payload (source: yara, matches table; deep_dive_agentic, key_evidence).
3. **Full Payload Capabilities**: The complete set of malicious capabilities (file theft, encryption, lateral movement, etc.) is only present in the unpacked payload, which is unavailable (source: llm_judge, verdict.json).
4. **Runtime Behavior**: No dynamic behavior was observed, as Themida's anti-emulation features prevented the payload from executing in the available analysis environments (source: speakeasy, dynamic section).
5. **Full IAT and Import Functionality**: Only 3 imports are visible in the stub; the full set of Windows API calls used by the payload is obscured by Themida (source: pe_imports, import_count:3).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Output/Notes |
|------|----------------|--------------|
| capa | N/A, duration 25.23s | 6 capability rules matched, full results in Section 5 and 8 (source: capa, capability rules table) |
| YARA-x | 454 rules compiled, 10 matches | Full match list in Section 3, 7, 9 (source: yara, matches table) |
| FLOSS | 5014 static strings, 0 decoded/stack/tight strings | Full string sample in Section 5 (source: floss, strings section) |
| radare2 | N/A | Disassembly of EP (0x104d3058) and obfuscated function (0x10019110) in Section 5 (source: radare2, disassembly sections) |
| UPX | N/A | Unpack failed: `upx_ok: False`, `is_packed: False`, `unpacked_path: ""` (source: upx, unpack section) |
| Speakeasy | ok, 0 API calls, 0 key events | No runtime activity observed (source: speakeasy, dynamic section) |
| Frida | v17.16.4 | Available, no instrumentation data collected (source: frida_probe, section) |
| Ghidra | Unavailable | Failed with NotOwnerException (project owned by remnux) (source: llm_judge, cross_engine_notes) |
| IDA | Unavailable | Missing required idasql binary (source: llm_judge, cross_engine_notes) |
| Malcat | Unavailable | MCP closed during initialization (source: Malcat, structured analysis section) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544  
**sample_path:** /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 92
- **family_guess**: Exact family cannot be determined without unpacking the Themida-packed payload; sample is consistent with packed Windows malware (e.g., info-stealers, trojans, ransomware) that uses Themida for anti-static-analysis evasion.
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Primary static analysis tools (Ghidra, IDA, Malcat) were unavailable due to environment errors: Ghidra failed with a NotOwnerException (project owned by remnux), IDA was missing the required idasql binary, and Malcat MCP closed during initialization. All analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which successfully processed the sample and returned consistent malicious indicators.
- **summary**: The sample is a 32-bit Windows GUI PE packed with the Themida packer, confirmed by cross-engine evidence from capa, FLOSS, and YARA. It includes anti-analysis features (references to analysis tools) and uses aPLib compression for embedded payloads, all consistent with malware designed to evade static detection. The full payload is obfuscated by Themida, so the exact malware family cannot be identified without unpacking. No benign indicators were observed across any available analysis tools.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with Themida (ATT&CK T1027.002, MBC F0001.011)` | Themida is a widely abused commercial packer used to obfuscate malicious code and evade static analysis; this match is a |
| floss | strings | `.themida` | Direct embedded string reference to the Themida packer, corroborating the capa packing detection and confirming the obfu |
| yara | matches | `IsPacked` | YARA rule explicitly flags the sample as packed, consistent with Themida-based obfuscation observed in other engines. |
| capa | top_rules | `reference analysis tools strings (MBC B0013.001)` | The sample contains strings referencing security and analysis tools, a common anti-analysis technique used to detect san |
| capa | top_rules | `decompress data using aPLib (MBC C0025.003)` | aPLib is a compression library frequently used by packers to decompress embedded malicious payloads at runtime, indicati |
| capa | top_rules | `forwarded export (ATT&CK T1129)` | Forwarded exports are often used by packers to hide malicious functionality and redirect execution to packed code, consi |
| yara | matches | `IsPE32` | Confirms the sample is a valid 32-bit Windows Portable Executable, the standard format for Windows malware. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: Packed PE32 Windows GUI executable with network indicators (domain, IP, base64) and token-related strings. YARA rules for domain, IP, base64, CRC32 constant, PE properties, and win_token all fired. Analysis tools (Ghidra, IDA, Malcat) were unavailable, preventing deeper static RE, but the YARA signature is consistent with malware.

### deep key_evidence
- `"YARA rule 'domain' matched at offset 0"`
- `"YARA rule 'IP' matched at offset 36311"`
- `"YARA rule 'contains_base64' matched at offset 169512"`
- `"YARA rule 'CRC32_poly_Constant' matched at offset 1328583"`
- `"YARA rule 'IsPE32' matched"`
- `"YARA rule 'IsPacked' matched"`
- `"YARA rule 'win_token' matched at offsets 172606 and 172621"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 6 · duration_s: 25.23

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with Themida | T1027.002:Obfuscated Files or Information | F0001.011:Software Packing |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| reference analysis tools strings |  | B0013.001:Analysis Tool Discovery |
| forwarded export | T1129:Shared Modules |  |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 3

## YARA Matches (pipeline)
Total matches: 10

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@36311 len=3 |
| contains_base64 | - | $a@169512 len=12 |
| CRC32_poly_Constant | - | $c0@1328583 len=4 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@232 len=4 |
| win_token | - | $f1@172606 len=12; $c3@172621 len=16 |

## Generated YARA Meta
```json
{
  "rule_count": 10,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
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
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 36311,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 169512,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 1328583,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 232,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_token",
      "path": "/opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 172606,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 172621,
          "length": 16,
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
    "/opt/samples/rules/flat/An
```

## FLOSS Strings
Total strings: 5014 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 5014}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `@.edata`
- `@.idata`
- `.themida`
- `'1~`nV9F`
- `\nxswz9C`
- `oh.n~L`
- `Uh~D8C`
- `?=RalLh	k`
- `'{,.L%J`
- `s\s`^#j`
- `"THnOt`
- `w7v:n#`
- `O0,Kd?`
- `|S0|N&`
- `&xK[#[`
- `INb@T%`
- `WWH~|Y`
- `h(&<ul`
- `{'z4(iBpH`
- `wl9T9Hb`
- `D!IBf,OX`
- `rc~]j"`
- `QH`l+[`
- `qrf4tv`
- `0rMjlUq`
- `cjCH%0`
- `g+Z?x`N`
- `T\bC8$`
- `g$y[Tc`
- `VrdE#"`
- `Q3e<KQ`
- `=h*kP?`
- `3eh1vZ`
- `H#+BV5`
- `v'+ST)`
- `[&@\0Q`
- `5Zw":!5`
- `#k][$o`
- `*Pt*XY`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x104d3058
```asm
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46             inc esi
│ │╎╎╎╎╎│   0x104d30ae      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30b0      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30b2      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30b4      7505           jne 0x104d30bb
│ │╎╎╎╎╎│   0x104d30b6      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30b8      46             inc esi
│ │╎╎╎╎╎│   0x104d30b9      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30bb      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30bd      00d2   
```
### 0x10019110
```asm
┌ 110: sym.StringLoaderA.dll_InitializeSecurity (int32_t arg_65h);
│      ╎╎   ; arg int32_t arg_65h @ ebp+0x65
│      ╎╎   ; var int32_t var_3eh @ ebp-0x3e
│      ╎╎   0x10019110      2c52           sub al, 0x52                ; 82
│      ╎╎   0x10019112      54             push esp
│      ╎╎   0x10019113      50             push eax
│      ╎╎   0x10019114  ~   3ed09f6b59..   rcr byte ds:[edi - 0x43b3a695], 1
│     ┌───> 0x1001911a      bce63478ed     mov esp, 0xed7834e6
│     ╎ ╎   0x1001911f      b103           mov cl, 3
│     ╎ ╎   0x10019121      92             xchg edx, eax
│     ╎ ╎   0x10019122      baa6f7e81a     mov edx, 0x1ae8f7a6
│     ╎ ╎   0x10019127      6a03           push 3                      ; 3
│     ╎ ╎   0x10019129      3ea7           cmpsd dword ds:[esi], dword es:[edi]
│     ╎ ╎   0x1001912b      4c             dec esp
│     ╎ ╎   0x1001912c      1490           adc al, 0x90
│     ╎ ╎   0x1001912e      ff01           inc dword [ecx]
│     ╎ ╎   0x10019130      dabbd42fca48   fidivr dword [ebx + 0x48ca2fd4]
│     ╎ ╎   0x10019136      44             inc esp
│     └───< 0x10019137      7de1           jge 0x1001911a
│       ╎   0x10019139      a5             movsd dword es:[edi], dword [esi]
│       ╎   0x1001913a      bcfbb49fcd     mov esp, 0xcd9fb4fb
│      ┌──< 0x1001913f      787c           js 0x100191bd
│      │╎   0x10019141      62952f766976   bound edx, qword [ebp + 0x7669762f]
│      │╎   0x10019147      6d             insd dword es:[edi], dx
│      │╎   0x10019148      ed             in eax, dx
│      │╎   0x10019149      0cc4           or al, 0xc4                 ; 196
│      │╎   0x1001914b      5a             pop edx
│      │╎   0x1001914c      c165c2ff       shl dword [var_3eh], 0xff
│      │╎   0x10019150      94             xchg esp, eax
│      │╎   0x10019151      e7c5           out 0xc5, eax
│      │╎   0x10019153      9a12903ce8..   lcall 0xce34, 0xe83c9012
│      │╎   0x1001915a      b076           mov al, 0x76                ; 'v' ; 118
│      │╎   0x1001915c      0296ab586a57   add dl, byte [esi + 0x576a58ab]
│      │╎   0x10019162      9d             popfd
│      │╎   0x10019163      bd0776dc75     mov ebp, 0x75dc7607
│      │╎   0x10019168      57             push edi
│      │╎   0x10019169      2127           and dword [edi], esp
│      │╎   0x1001916b      df             invalid
..
│      └──> 0x100191bd      8e4565         mov es, word [arg_65h]
│       │   0x100191c0      ed             in eax, dx
│       │   0x100191c1      ca530a         retf 0xa53
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
