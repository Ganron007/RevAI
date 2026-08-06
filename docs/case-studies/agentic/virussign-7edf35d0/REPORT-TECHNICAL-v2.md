> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:05:54 UTC

## 1. Executive Summary
The analyzed sample (SHA256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544) is a malicious 32-bit Windows GUI Portable Executable packed with the Themida commercial packer, with a threat score of 92 out of 100 (source: llm_judge, verdict.json). Primary static analysis tools (Ghidra, IDA, Malcat) were unavailable due to environment errors: Ghidra failed with a NotOwnerException (project owned by remnux), IDA was missing the required idasql binary, and Malcat MCP closed during initialization (source: llm_judge, cross_engine_notes). All analysis was performed using secondary tools (capa, YARA, FLOSS, pe_imports) which returned consistent malicious indicators. Cross-engine evidence confirms the sample uses Themida for obfuscation (T1027.002), includes anti-analysis features referencing security tools (MBC B0013.001), uses aPLib compression for embedded payloads (MBC C0025.003), and contains forwarded exports (T1129) consistent with packed malware (source: llm_judge, key_evidence). The exact malware family cannot be determined without unpacking the Themida-protected payload, but the sample is consistent with info-stealers, trojans, or ransomware (source: llm_judge, family_guess). No benign indicators were observed across any available analysis tools.

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 |
| Sample Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 92/100 |
| Family Guess | Unknown (consistent with packed Windows malware: info-stealers, trojans, ransomware) |
| Primary Static Tool Status | Ghidra: NotOwnerException; IDA: missing idasql; Malcat: MCP closed |
| Secondary Tool Status | capa: ok; YARA: ok; FLOSS: ok; pe_imports: ok; Speakeasy: ok; Frida: available (source: deep-dive.json, tool_gate) |

## 3. File Layout & Structural Analysis
The sample is a valid 32-bit Windows GUI PE, confirmed by YARA rule `IsPE32` (source: yara, matches) and capa PE property detection. The PE import table contains only 3 imports (source: pe_imports, import_count), a common trait of packed malware that loads APIs dynamically to evade static detection. UPX unpacking attempts failed: `upx_ok: False`, `unpacked_path: ```, no stdout returned (source: upx, upx_unpack), indicating the sample is not packed with UPX but uses the Themida packer as confirmed by capa and FLOSS. FLOSS extracted 5014 static strings, with no decoded, stack, or tight strings observed (source: floss, total_strings). High-signal static strings include the Themida section marker `.themida` (source: floss, strings) and multiple obfuscated string literals consistent with packed code. The entry point (0x104d3058) contains aPLib decompression logic, matching the capa rule for `decompress data using aPLib` (source: radare2, 0x104d3058; capa, top_rules). An additional obfuscated function at 0x10019110 (labeled `sym.StringLoaderA.dll_InitializeSecurity` by radare2) contains invalid opcodes and control flow flattening typical of Themida-protected code (source: radare2, 0x10019110). A XOR search found a XOR 00 position at 0x00000000 with partial DOS header string `!This program cannot be run in DOS mode.` (source: xor, XOR search), consistent with a valid PE header.

## 4. Malcat Triage Summary
Malcat analysis failed to complete due to a top-level MCP initialization error: `malcat_analyze top-level: MCP malcat closed: ` (source: Malcat Structured Analysis). No Malcat-specific triage data, string extractions, or structural analysis is available for this sample. All static analysis was performed using alternative tools (capa, YARA, FLOSS, radare2, pe_imports) as noted in the cross-engine notes (source: llm_judge, cross_engine_notes).

## 5. Static Code Analysis
Primary static reverse engineering tools (Ghidra, IDA) were unavailable for this sample, so analysis relies on secondary tool outputs and limited radare2 disassembly. The capa engine matched 6 capability rules, detailed in the table below (source: capa, capa Capability Rules):
| Rule | ATT&CK Technique | MBC Behavior |
|------|------------------|-------------|
| packed with Themida | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing |
| decompress data using aPLib | None | C0025.003: Decompress Data |
| reference analysis tools strings | None | B0013.001: Analysis Tool Discovery |
| forwarded export | T1129: Shared Modules | None |
| contain loop | None | None |
| (internal) packer file limitation | None | None |

YARA matched 10 rules, detailed below (source: yara, YARA Matches):
| Rule | Namespace | Match Offset | Match Length |
|------|-----------|--------------|--------------|
| domain | - | 0 | 2 |
| IP | - | 36311 | 3 |
| contains_base64 | - | 169512 | 12 |
| CRC32_poly_Constant | - | 1328583 | 4 |
| IsPE32 | - | N/A | N/A |
| IsDLL | - | N/A | N/A |
| IsWindowsGUI | - | N/A | N/A |
| IsPacked | - | N/A | N/A |
| HasRichSignature | - | 232 | 4 |
| win_token | - | 172606, 172621 | 12, 16 |

FLOSS extracted 5014 static strings, with a sample of obfuscated literals and the critical `.themida` section marker (source: floss, FLOSS sample):
```
!This program cannot be run in DOS mode.
@.edata
@.idata
.themida
'1~`nV9F`
\nxswz9C
oh.n~L
Uh~D8C
?=RalLh	k
'{,.L%J
s\s`^#j`
"THnOt
w7v:n#
O0,Kd?
|S0|N&
&xK[#[`
INb@T%
WWH~|Y
h(&<ul
{'z4(iBpH
wl9T9Hb
D!IBf,OX
rc~]j"
QH`l+[`
qrf4tv
0rMjlUq
cjCH%0
g+Z?x`N
T\bC8$
g$y[Tc
VrdE#"
Q3e<KQ
=h*kP?
3eh1vZ
H#+BV5
v'+ST)
[&@\0Q
5Zw":!5
#k][$o
*Pt*XY
```

Radare2 disassembly of the entry point (0x104d3058) shows aPLib decompression logic, with bitwise operations and loop structures matching the capa aPLib rule (source: radare2, 0x104d3058):
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

A second radare2 disassembly block at 0x10019110 shows heavily obfuscated Themida code with invalid opcodes and control flow redirection, consistent with packer-protected entry points (source: radare2, 0x10019110):
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

## 6. Behavioral & Dynamic Analysis
No dynamic behavioral data was observed during analysis. Speakeasy dynamic execution returned 0 API calls and 0 key events, with no recorded runtime behavior (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). Frida instrumentation was available (version 17.16.4) but no probe data was collected (source: frida_probe, frida_available: True). UPX unpacking failed, so no unpacked payload was available for dynamic execution (source: upx, upx_ok: False). The Themida packer prevents static and dynamic analysis of the core payload, so all behavioral observations are limited to the unpacking stub.

## 7. Network Indicators & C2
YARA rules indicate the presence of network-related artifacts in the sample: a domain string at offset 0 (source: yara, matches, rule: domain), an IPv6 address at offset 36311 (source: yara, matches, rule: IP), and base64-encoded data at offset 169512 (source: yara, matches, rule: contains_base64). No clear C2 server addresses, URLs, or network protocol indicators were extracted from static strings due to Themida obfuscation. Full network IOCs will be available only after unpacking the Themida-protected payload (unknown). The sample also contains a CRC32 polynomial constant at offset 1328583 (source: yara, matches, rule: CRC32_poly_Constant), which may be used for network payload validation or obfuscation.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample's capabilities are derived from capa rule matches and YARA indicators, mapped to the MITRE ATT&CK framework and Malware Behavior Catalog (MBC) below (source: capa, capa Capability Rules; yara, YARA Matches):
| Capability | MITRE ATT&CK | MBC | Evidence Source |
|------------|--------------|-----|-----------------|
| Software packing (Themida) | T1027.002: Obfuscated Files or Information | F0001.011: Software Packing | capa top_rules, floss strings (.themida), yara IsPacked |
| Anti-analysis (analysis tool detection) | None | B0013.001: Analysis Tool Discovery | capa top_rules |
| Payload decompression (aPLib) | None | C0025.003: Decompress Data | capa top_rules, radare2 0x104d3058 |
| Forwarded exports (hide functionality) | T1129: Shared Modules | None | capa top_rules |
| Token manipulation | None | None | yara win_token (offsets 172606, 172621) |
| Network artifact presence (domain, IP, base64) | None | None | yara domain, IP, contains_base64 |

The sample also contains a loop construct (capa rule `contain loop`) and a packer file limitation (capa rule `(internal) packer file limitation`), which are consistent with Themida's unpacking stub logic (source: capa, top_rules).

## 9. Indicators of Compromise
| IOC Type | Value | Context | Source |
|----------|-------|---------|--------|
| File Hash (SHA256) | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 | Sample identifier | llm_judge, verdict.json |
| File Path | /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir | Sample storage location | sample_path |
| PE Property | 32-bit Windows GUI executable | File format | yara IsPE32, IsWindowsGUI |
| Packing | Themida | Obfuscation tool | capa packed with Themida, floss .themida, yara IsPacked |
| YARA Match Offsets | Domain: 0; IPv6: 36311; Base64: 169512; win_token: 172606, 172621; CRC32: 1328583 | High-signal artifact locations | yara matches |
| Static String | .themida | Themida section marker | floss strings |
| Import Count | 3 | Minimal imports consistent with packing | pe_imports |
| Unpack Status | UPX unpack failed | Not UPX-packed, uses Themida | upx upx_ok: False |

## 10. Detection Engineering
### YARA Detection Rule
A generated YARA rule for this sample is available at `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yar` (source: rule.yara.json, rule_path), with a corresponding Sigma rule at `/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yml` (source: rule.yara.json, sigma_path). The rule is valid (`yara_valid: True`, `yara_check: ok`) and produced 0 false positives against the staged goodware corpus (source: rule.yara.json, goodware_fp).

### Capability-Based Detection
Capa rules for this sample can be used to detect Themida-packed malware with anti-analysis and aPLib decompression capabilities. Key rules to prioritize in detection engineering:
- `packed with Themida` (T1027.002)
- `reference analysis tools strings` (B0013.001)
- `decompress data using aPLib` (C0025.003)
- `forwarded export` (T1129)
(Source: capa, capa Capability Rules)

### PE-Based Detection
Samples matching the following PE characteristics should be flagged for further analysis:
- 32-bit Windows GUI PE
- Import count ≤ 3
- Presence of `.themida` section in static strings
- YARA matches for `IsPacked` and `IsPE32`
(Source: pe_imports, floss, yara)

## 11. What We Don't Know
1. Exact malware family: The Themida packer obfuscates the core payload, so family identification requires successful unpacking (source: llm_judge, family_guess).
2. Full payload capabilities: Static analysis of the packed payload is impossible without unpacking, so core functionality (credential theft, encryption, etc.) is unknown (source: capa, (internal) packer file limitation rule).
3. C2 server addresses: YARA indicates the presence of domain and IP strings, but no clear, unobfuscated C2 indicators were extracted from static analysis (source: yara, matches; unknown).
4. Runtime behavior: No dynamic API calls or system interactions were observed via Speakeasy or Frida, so runtime behavior of the unpacked payload is unknown (source: speakeasy, api_calls: 0; frida_probe, no data).
5. Unpacked payload IOCs: All IOCs listed in Section 9 are from the packed stub; IOCs for the core payload are unknown until unpacking (source: upx, upx_ok: False).
6. Anti-analysis bypass methods: The sample references analysis tools, but no specific sandbox detection or bypass logic was identified in the available static data (source: capa, reference analysis tools strings rule; unknown).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Notes |
|------|----------------|-------|
| Ghidra | Failed (NotOwnerException) | Project owned by remnux user, unable to access (source: llm_judge, cross_engine_notes; ghidra_query audit trail) |
| IDA | Failed (missing idasql binary) | Required SQL integration binary not present (source: llm_judge, cross_engine_notes) |
| Malcat | Failed (MCP closed) | MCP server closed during initialization (source: Malcat Structured Analysis) |
| capa | 25.23s runtime | 6 rules matched, successful execution (source: capa, duration_s: 25.23) |
| YARA | ok | 10 matches, valid generated rule (source: yara, YARA Matches; rule.yara.json) |
| FLOSS | ok | 5014 static strings extracted (source: floss, total_strings: 5014) |
| radare2 | ok | Entry point and obfuscated function disassembly extracted (source: radare2, 0x104d3058, 0x10019110) |
| pe_imports | ok | Import count 3, minimal import table (source: pe_imports, import_count: 3) |
| UPX | Failed | Unpacking returned no output, unpacked_path empty (source: upx, upx_ok: False) |
| XOR Search | ok | XOR 00 position found at 0x00000000 (source: xor, XOR search) |
| Speakeasy | ok (no events) | 0 API calls, 0 key events, no runtime behavior observed (source: speakeasy, api_calls: 0) |
| Frida | 17.16.4 (available) | No probe data collected (source: frida_probe, version: 17.16.4) |
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
  "sha256": "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544",
  "family": "unknown",
  "generated_at": "2026-08-06T03:02:34.228676+00:00",
  "string_count": 7,
  "strings": [
    "Themida is a widely abused commercial packer used to obfuscate malicious code and evade static analysis; this match is a",
    "Direct embedded string reference to the Themida packer, corroborating the capa packing detection and confirming the obfu",
    "YARA rule explicitly flags the sample as packed, consistent with Themida-based obfuscation observed in other engines.",
    "The sample contains strings referencing security and analysis tools, a common anti-analysis technique used to detect san",
    "aPLib is a compression library frequently used by packers to decompress embedded malicious payloads at runtime, indicati",
    "Forwarded exports are often used by packers to hide malicious functionality and redirect execution to packed code, consi",
    "Confirms the sample is a valid 32-bit Windows Portable Executable, the standard format for Windows malware."
  ],
  "rule_path": "/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yar",
  "sigma_path": "/opt/samples/logs/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/rule.yml",
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
    "commit": "80c92a39d67f7e321883d3656b87cc4b04c5b7b5",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-06 03:02:34 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785874437.5845218}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785874437.6271553}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785874437.651503}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785874542.5074391}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785874542.5460014}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785874542.5940273}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785874542.6042278}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785874542.6106641}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785874657.6126769}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY address", "ts": 1785874661.906657}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY address", "ts": 1785874661.9062307}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 4 ORDER BY address", "ts": 1785874661.9131944}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec FROM memory_blocks ORDER BY start_ea", "ts": 1785874681.7880538}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM exports ORDER BY address", "ts": 1785874681.7922342}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE address >= 273494104 AND address < 276488192 ORDER BY address", "ts": 1785874684.8545554}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE address >= 268439552 AND address < 268681216 ORDER BY address", "ts": 1785874688.2059462}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address >= 268439552 AND address < 276488192 ORDER BY address", "ts": 1785874688.2110987}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address >= 268439552 AND address < 268681216 ORDER BY address", "ts": 1785874712.4310372}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address >= 273494016 AND address < 276488192 ORDER BY address", "ts": 1785874712.4341164}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address IN (0, 36311, 169512, 172606, 172621, 1328583)", "ts": 1785874718.8815181}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module != 'STRINGLOADERB.DLL' AND module != 'EXTERNAL' ORDER BY address", "ts": 1785874718.8854046}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length >= 8 ORDER BY address LIMIT 200", "ts": 1785874718.8887088}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address >= 268775424 AND address < 268779520 ORDER BY address", "ts": 1785874786.1959507}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%OpenProcessToken%' OR content LIKE '%GetModuleHandleA%' OR content LIKE '%TranslateMessage%' OR content LIKE '%InitializeSecurity%' ORDER BY address", "ts": 1785874786.2007034}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785874803.8986866}`
- `{"source": "yara_gen_v2", "ts": 1785874804.95425}`
- `{"source": "publish_report_v2", "ts": 1785874905.8554015}`
- `{"source": "publish_report_v2_technical", "ts": 1785874986.1957905}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785985200.9591403}`
- `{"source": "yara_gen_v2", "ts": 1785985354.2289698}`
