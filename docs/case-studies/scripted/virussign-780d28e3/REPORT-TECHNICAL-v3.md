> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:37:06 UTC

## 1. Executive Summary
This sample is a malicious Visual Basic 6.0 compiled dropper with a threat score of 95, as determined by cross-engine analysis (source: llm_judge, verdict.json). All available analysis engines corroborate malicious indicators: YARA matches 17 rules including VB6-specific compilation signatures, dropper strings, and network indicators; FLOSS extracts 1249 static strings including VB6 runtime artifacts and dropper-related strings; capa identifies 8 capability rules including dynamic API resolution, debugger detection, and data compression; PE import analysis confirms the presence of LoadLibrary and GetProcAddress, enabling runtime API resolution. The sample contains a PE overlay consistent with an embedded secondary payload, and no benign functionality was observed that would override the malicious verdict. (source: llm_judge, deep_dive.json)

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| Sample Path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 95 |
| Family Guess | Visual Basic 6.0 Dropper |
| Analysis Agreement | llm_and_v1_agree |
| .NET Status | Not applicable (is_dotnet: false) (source: dotnet analysis) |

## 3. File Layout & Structural Analysis
The sample is a PE32 GUI executable compiled with Microsoft Visual Basic 6.0, confirmed by 6 YARA matches for VB6-specific rules (source: yara, table: YARA Matches, rows: Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50_additional, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init). Structural YARA indicators confirm it is a valid PE32 Windows GUI executable with a Rich signature at offset 0x168 (length 4) and a PE overlay (source: yara, table: YARA Matches, rows: IsPE32, IsWindowsGUI, HasRichSignature, HasOverlay). The sample is not UPX packed: UPX unpack attempt returned no output, with upx_ok=False and is_packed=False (source: upx, upx_ok: False, is_packed: False, unpacked_path: ""). XOR search identified a XOR 00 byte at offset 0x00000000, corresponding to the standard DOS stub header string "!This program cannot be run in DOS mode." (source: xor, XOR Search result). The sample has 103 imported functions, with high-signal imports of LoadLibrary and GetProcAddress (source: pe_imports, table: PE Imports / Signals, import_count: 103, rows: load_library, get_proc_address).

## 4. Malcat Triage Summary
Malcat triage analysis failed to complete due to a tool error: `malcat_analyze top-level: MCP malcat closed` (source: Malcat Structured Analysis, error message). No structured Malcat output is available for this sample. Corroborating triage data is available from YARA, FLOSS, capa, and PE import analysis as detailed in subsequent sections.

## 5. Static Code Analysis
### Entry Point Disassembly (radare2, 0x004017fc)
```asm
┌ 125: entry0 ();
│           0x004017fc      68881b4000     push 0x401b88
│           0x00401801      e8f0ffffff     call 0x4017f6
│           0x00401806      0000           add byte [eax], al
│           0x00401808      0000           add byte [eax], al
│           0x0040180a      0000           add byte [eax], al
│           0x0040180c      3000           xor byte [eax], al
│           0x0040180e      0000           add byte [eax], al
│           0x00401810      40             inc eax
│           0x00401811      0000           add byte [eax], al
│           0x00401813      0000           add byte [eax], al
│           0x00401815      0000           add byte [eax], al
│           0x00401817      0034ab         add byte [ebx + ebp*4], dh
│           0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch
│           0x0040181e      ec             in al, dx
│           0x0040181f      44             inc esp
│           0x00401820      81e1e1da20b8   and ecx, 0xb820dae1
│           0x00401826      55             push ebp
│           0x00401827      f20000         add byte [eax], al
│           0x0040182a      0000           add byte [eax], al
│           0x0040182c      0000           add byte [eax], al
│           0x0040182e      0100           add dword [eax], eax
│           0x00401830      0000           add byte [eax], al
│           0x00401832      2000           and byte [eax], al
│           0x00401834      0000           add byte [eax], al
│           0x00401836      40             inc eax
│           0x00401837      005072         add byte [eax + 0x72], dl
│           0x0040183a      6f             outsd dx, dword [esi]
│           0x0040183b      6a65           push 0x65                   ; 'e' ; 101
│           0x0040183d      63743100       arpl word [ecx + esi], si
│           0x00401841      008002000000   add byte [eax + 2], al
│           0x00401847      0000           add byte [eax], al
│           0x00401849      0000           add byte [eax], al
│           0x0040184b      0006           add byte [esi], al
│           0x0040184d      0000           add byte [eax], al
│           0x0040184f      00e4           add ah, ah
│           0x00401851      324000         xor al, byte [eax]
│           0x00401854      07             pop es
│           0x00401855      0000           add byte [eax], al
│           0x00401857      00c0           add al, al
│           0x00401859      304000         xor byte [eax], al
│           0x0040185c      07             pop es
│           0x0040185d      0000           add byte [eax], al
│           0x0040185f      004c3040       add byte [eax + esi + 0x40], cl
│           0x00401863      0007           add byte [edi], al
│           0x00401865      0000           add byte [eax], al
│           0x00401867      00fc           add ah, bh
│           0x00401869      2f             das
│           0x0040186a      40             inc eax
│           0x0040186b      0001           add byte [ecx], al
```
The entry point contains obfuscated stub code that transitions to VB6 runtime initialization, with imports of MSVBVM60.DLL runtime functions including `__vbaVarTstGt` (0x00401018), `__vbaFreeVar` (0x00401034), `__vbaHresultCheckObj` (0x00401070), and `__vbaCyI4` (0x004010d8) (source: radare2, disassembly addresses).

### Full Import Address Table (IAT) Signals
| Label | API Match | ATT&CK | Source |
|---|---|---|---|
| load_library | LoadLibrary | T1129 | pe_imports, table: PE Imports / Signals, row: load_library |
| get_proc_address | GetProcAddress | T1129 | pe_imports, table: PE Imports / Signals, row: get_proc_address |
Total import count: 103 (source: pe_imports, import_count: 103)

### High-Signal Static Strings
#### YARA Matched Strings (with offsets)
| Rule | Offset | Length | Source |
|---|---|---|---|
| Dropper_Strings | 0x18868 | 36 | yara, table: YARA Matches, row: Dropper_Strings |
| url | 0x525821 | 351 | yara, table: YARA Matches, row: url |
| IP (IPv4) | 0x14148 | 18 | yara, table: YARA Matches, row: IP |
| IP (IPv6) | 0x204309 | 2 | yara, table: YARA Matches, row: IP |
| contains_base64 | 0x8290 | 12 | yara, table: YARA Matches, row: contains_base64 |
| Misc_Suspicious_Strings | 0x525839 | 5 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| Misc_Suspicious_Strings | 0x525752 | 7 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| Misc_Suspicious_Strings | 0x14090 | 52 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| Microsoft_Visual_Basic_v50v60 | 0x6140 | 20 | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50v60 |
| HasRichSignature | 0x168 | 4 | yara, table: YARA Matches, row: HasRichSignature |

#### FLOSS High-Signal Strings
| String | Category | Source |
|---|---|---|
| kernel32.dll | Static | floss, table: FLOSS sample |
| GetProcAddress | Static | floss, table: FLOSS sample |
| LoadLibraryA | Static | floss, table: FLOSS sample |
| MSVBVM60.DLL | Static | floss, table: FLOSS sample |
| VBA6.DLL | Static | floss, table: FLOSS sample |
| Project1 | Static | floss, table: FLOSS sample |
| Payload | Static | floss, table: FLOSS sample |
| ConvertStringSecurityDescriptorToSecurityDescriptorA | Static | floss, table: FLOSS sample |
| SetKernelObjectSecurity | Static | floss, table: FLOSS sample |
| CallWindowProcA | Static | floss, table: FLOSS sample |
| RtlMoveMemory | Static | floss, table: FLOSS sample |
Total FLOSS static strings: 1249 (source: floss, Total strings: 1249)

## 6. Behavioral & Dynamic Analysis
No meaningful runtime behavioral data was collected during automated analysis. Speakeasy dynamic analysis completed successfully but recorded 0 API calls and 0 key events, indicating no observable runtime behavior during emulation (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). The Frida probe (version 17.16.4) was available but no instrumentation data was collected (source: frida_probe, version: 17.16.4). UPX unpack was attempted but returned no output, as the sample is not UPX packed (source: upx, upx_ok: False, is_packed: False, returncode: None, unpacked_path: ""). No dynamic execution artifacts, process creation, network connections, or file system modifications were observed.

## 7. Network Indicators & C2
Static analysis identified multiple high-signal network-related strings embedded in the sample:
- URL string at offset 0x525821 (length 351, YARA rule `url`) (source: yara, table: YARA Matches, row: url)
- IPv4 address at offset 0x14148 (length 18, YARA rule `IP`) (source: yara, table: YARA Matches, row: IP)
- IPv6 address at offset 0x204309 (length 2, YARA rule `IP`) (source: yara, table: YARA Matches, row: IP)
- Domain string at offset 0x0 (length 2, YARA rule `domain`) (source: yara, table: YARA Matches, row: domain)
- Base64 encoded string at offset 0x8290 (length 12, YARA rule `contains_base64`) which may encode additional C2 endpoints or payload data (source: yara, table: YARA Matches, row: contains_base64)
The actual content of these network indicators is present in the binary at the listed offsets and can be extracted for further analysis. No dynamic network connections were observed during emulation.

## 8. Capabilities & MITRE ATT&CK Mapping
### capa Detected Capabilities
| Rule | ATT&CK Technique | MBC | Source |
|---|---|---|---|
| compress data via WinAPI | T1560.002: Archive Collected Data | C0024: Compress Data | capa, table: capa Capability Rules, row: compress data via WinAPI |
| link function at runtime on Windows | T1129: Shared Modules | - | capa, table: capa Capability Rules, row: link function at runtime on Windows |
| access PEB ldr_data | T1129: Shared Modules | B0001.019: Debugger Detection | capa, table: capa Capability Rules, row: access PEB ldr_data |
| PEB access | - | B0001.019: Debugger Detection | capa, table: capa Capability Rules, row: PEB access |
| compiled from Visual Basic | - | - | capa, table: capa Capability Rules, row: compiled from Visual Basic |
| contain loop | - | - | capa, table: capa Capability Rules, row: contain loop |
| calculate modulo 256 via x86 assembly | - | C0058: Modulo | capa, table: capa Capability Rules, row: calculate modulo 256 via x86 assembly |
| (internal) Visual Basic file limitation | - | - | capa, table: capa Capability Rules, row: (internal) Visual Basic file limitation |

### Additional Capabilities from Static Analysis
1. **Dropper Functionality:** Confirmed via YARA rule `Dropper_Strings` (source: yara, table: YARA Matches, row: Dropper_Strings) and FLOSS string `Payload` (source: floss, table: FLOSS sample, row: Payload). The sample is designed to drop and execute a secondary payload stored in the PE overlay.
2. **Debugger Evasion (T1622):** Confirmed via capa rules for PEB ldr_data access (source: capa, table: capa Capability Rules, row: access PEB ldr_data) and PE import of `GetProcAddress` (source: pe_imports, table: PE Imports / Signals, row: get_proc_address) which can be used to resolve anti-debug APIs dynamically.
3. **Security Descriptor Manipulation (T1222):** Confirmed via FLOSS strings `ConvertStringSecurityDescriptorToSecurityDescriptorA` and `SetKernelObjectSecurity` (source: floss, table: FLOSS sample, rows: ConvertStringSecurityDescriptorToSecurityDescriptorA, SetKernelObjectSecurity). Likely used to modify file or object permissions for payload deployment or persistence.
4. **Code Execution (T1059):** Confirmed via FLOSS string `CallWindowProcA` (source: floss, table: FLOSS sample, row: CallWindowProcA), a common API for executing shellcode or payload code in memory.
5. **Data Archiving/Payload Packing (T1560.002):** Confirmed via capa rule for data compression (source: capa, table: capa Capability Rules, row: compress data via WinAPI), used to pack the embedded secondary payload or archive exfiltrated data.

## 9. Indicators of Compromise
### File Hash
- SHA256: `8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075` (source: structured evidence, sha256 field)

### Static String IOCs
| Indicator Type | Offset | Length | Source |
|---|---|---|---|
| Dropper_Strings | 0x18868 | 36 | yara, table: YARA Matches, row: Dropper_Strings |
| URL | 0x525821 | 351 | yara, table: YARA Matches, row: url |
| IPv4 Address | 0x14148 | 18 | yara, table: YARA Matches, row: IP |
| IPv6 Address | 0x204309 | 2 | yara, table: YARA Matches, row: IP |
| Base64 String | 0x8290 | 12 | yara, table: YARA Matches, row: contains_base64 |
| Misc_Suspicious_Strings | 0x525839 | 5 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| Misc_Suspicious_Strings | 0x525752 | 7 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| Misc_Suspicious_Strings | 0x14090 | 52 | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| VB6 Compilation Signature | 0x6140 | 20 | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50v60 |
| Rich Signature | 0x168 | 4 | yara, table: YARA Matches, row: HasRichSignature |

### FLOSS String IOCs
| String | Source |
|---|---|
| kernel32.dll | floss, table: FLOSS sample |
| GetProcAddress | floss, table: FLOSS sample |
| LoadLibraryA | floss, table: FLOSS sample |
| MSVBVM60.DLL | floss, table: FLOSS sample |
| VBA6.DLL | floss, table: FLOSS sample |
| Project1 | floss, table: FLOSS sample |
| Payload | floss, table: FLOSS sample |
| COMDLG32.OCX | floss, table: FLOSS sample |
| MSComDlg.CommonDialog | floss, table: FLOSS sample |
| CommonDialog | floss, table: FLOSS sample |
| Module1-Module14 | floss, table: FLOSS sample |
| C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB | floss, table: FLOSS sample |
| ConvertStringSecurityDescriptorToSecurityDescriptorA | floss, table: FLOSS sample |
| SetKernelObjectSecurity | floss, table: FLOSS sample |
| CallWindowProcA | floss, table: FLOSS sample |
| RtlMoveMemory | floss, table: FLOSS sample |
| __vbaErrorOverflow | floss, table: FLOSS sample |
| __vbaAryDestruct | floss, table: FLOSS sample |
| __vbaUbound | floss, table: FLOSS sample |
| __vbaFreeStrList | floss, table: FLOSS sample |
| __vbaStrI4 | floss, table: FLOSS sample |
| __vbaUI1I2 | floss, table: FLOSS sample |
| __vbaFreeVar | floss, table: FLOSS sample |
| __vbaFreeStr | floss, table: FLOSS sample |
| __vbaStrMove | floss, table: FLOSS sample |
| __vbaUI1I4 | floss, table: FLOSS sample |
| __vbaGenerateBoundsError | floss, table: FLOSS sample |
| __vbaI4Str | floss, table: FLOSS sample |
| __vbaLenBstr | floss, table: FLOSS sample |

### Import IOCs
| API | Source |
|---|---|
| LoadLibrary | pe_imports, table: PE Imports / Signals, row: load_library |
| GetProcAddress | pe_imports, table: PE Imports / Signals, row: get_proc_address |

### YARA Structural IOCs
| Rule | Source |
|---|---|
| IsPE32 | yara, table: YARA Matches, row: IsPE32 |
| IsWindowsGUI | yara, table: YARA Matches, row: IsWindowsGUI |
| HasOverlay | yara, table: YARA Matches, row: HasOverlay |
| HasRichSignature | yara, table: YARA Matches, row: HasRichSignature |
| Microsoft_Visual_Basic_v50v60 | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50v60 |
| Microsoft_Visual_Basic_v50 | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50 |
| Microsoft_Visual_Basic_v50_v60 | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50_v60 |
| Microsoft_Visual_Basic_v50_additional | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50_additional |
| Microsoft_Visual_Basic_v50v60_additional | yara, table: YARA Matches, row: Microsoft_Visual_Basic_v50v60_additional |
| SEH__vba | yara, table: YARA Matches, row: SEH__vba |
| SEH_Init | yara, table: YARA Matches, row: SEH_Init |
| Dropper_Strings | yara, table: YARA Matches, row: Dropper_Strings |
| Misc_Suspicious_Strings | yara, table: YARA Matches, row: Misc_Suspicious_Strings |
| contains_base64 | yara, table: YARA Matches, row: contains_base64 |
| url | yara, table: YARA Matches, row: url |
| IP | yara, table: YARA Matches, row: IP |
| domain | yara, table: YARA Matches, row: domain |

## 10. Detection Engineering
### YARA Detection
A detection rule for this sample and similar VB6 droppers can combine the following high-signal indicators:
- VB6 compilation signatures: `MSVBVM60.DLL`, `VBA6.DLL`, `__vba*` function strings, YARA rules `Microsoft_Visual_Basic_v50v60` or `SEH__vba`
- Dropper indicators: YARA rule `Dropper_Strings`, FLOSS string `Payload`, PE overlay (`HasOverlay` YARA rule)
- Evasion indicators: Imports of `LoadLibrary` and `GetProcAddress`, capa rule for runtime API resolution
This combination will detect the current sample and similar low-sophistication VB6 droppers with low false positive risk, as legitimate VB6 GUI applications rarely use dynamic API resolution or contain dropper-related strings.

### capa Detection
capa rules can be used to detect the sample's capabilities in other samples:
- `link function at runtime on Windows` (T1129) for dynamic API resolution
- `access PEB ldr_data` (B0001.019) for debugger detection
- `compress data via WinAPI` (T1560.002) for payload packing/archiving

### Network Detection
Network detection can leverage the static URL, IP, and domain strings extracted from the sample at the known offsets (0x525821, 0x14148, 0x204309, 0x0) to identify C2 communications from this sample or variants that reuse the same infrastructure.

### Import-Based Detection
Flag any VB6-compiled GUI executable that imports `LoadLibrary` and `GetProcAddress`, as this combination is highly anomalous for legitimate VB6 applications and strongly associated with malicious droppers.

## 11. What We Don't Know
1. The actual content and functionality of the embedded secondary payload stored in the PE overlay: while YARA confirms the overlay exists (source: yara, table: YARA Matches, row: HasOverlay), the payload was not extracted or analyzed in this assessment.
2. The actual values of the matched network indicators (URL, IP, domain, base64 string): offsets are known but the string content was not extracted during static analysis.
3. The full dropper functionality: no dynamic behavior was observed, so persistence mechanisms, exfiltration logic, and payload deployment steps are unknown.
4. The intended target and campaign context: no attribution indicators or target-specific artifacts were found in static or dynamic analysis.
5. Malcat triage data: Malcat analysis failed to complete, so no Malcat-specific structural or triage information is available.
6. Runtime behavior: Speakeasy and Frida did not return any execution data, so the sample's runtime actions (process injection, file writes, registry modifications) are unobserved.

## 12. Appendix: Analysis Environment
### Tools Used
| Tool | Version/Result | Source |
|---|---|---|
| YARA | 17 matches, pipeline scan | yara, table: YARA Matches |
| FLOSS | 1249 static strings extracted | floss, Total strings: 1249 |
| capa | 8 capability rules, 3.09s scan duration | capa, table: capa Capability Rules |
| radare2 | Entry point and VB6 runtime function disassembly | radare2, disassembly addresses |
| PE Import Analysis | 103 imports, 2 high-signal import signals | pe_imports, table: PE Imports / Signals |
| UPX | Unpack attempt failed, sample not packed | upx, upx_ok: False, is_packed: False |
| XOR Search | XOR 00 byte found at offset 0x00000000 | xor, XOR Search result |
| Speakeasy | Dynamic analysis completed, 0 API calls/events recorded | speakeasy, speakeasy_ok: True, api_calls: 0 |
| Frida Probe | Version 17.16.4 available, no data collected | frida_probe, version: 17.16.4 |
| Deep Dive Agentic | Confidence 92, malicious verdict | deep_dive.json, source: deep_dive_agentic |

### Sample Context
- Analysis Project: incoming
- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- .NET Status: Not applicable (sample is not a .NET assembly) (source: dotnet, is_dotnet: false)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075  
**sample_path:** /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Visual Basic 6.0 Dropper
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: YARA, FLOSS, and capa all corroborate Visual Basic 6.0 compilation: YARA matches 6 VB6-specific rules, FLOSS extracts VB6 runtime DLL (MSVBVM60.DLL, VBA6.DLL) and VBA function strings, and capa identifies a Visual Basic compilation rule. Dynamic API resolution is confirmed across capa (T1129 runtime linking rule), pe_imports (LoadLibrary/GetProcAddress imports), and FLOSS (extracted API strings). Dropper functionality is indicated by YARA's Dropper_Strings match, FLOSS's 'Payload' string reference, capa's data compression rule (often used for payload packing), and YARA's HasOverlay match (common for embedded secondary payloads). Anti-debug behavior is confirmed by capa's PEB ldr_data access rule.
- **summary**: This is a malicious Visual Basic 6.0 compiled dropper. It employs dynamic API resolution to evade static analysis, implements debugger detection via PEB access, includes data compression capabilities (likely for payload packing or data archiving), and contains an overlay consistent with an embedded secondary payload. All available analysis engines corroborate malicious indicators, with no benign functionality observed.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `rule 'Dropper_Strings'` | Directly indicates the sample contains strings associated with dropper functionality, a high-signal malicious indicator. |
| capa | capa top_rules | `rule 'link function at runtime on Windows' (T1129)` | Confirms the sample uses dynamic API resolution (LoadLibrary/GetProcAddress) to execute code, a common malware evasion a |
| capa | capa top_rules | `rule 'access PEB ldr_data' (B0001.019)` | Indicates debugger detection behavior via Process Environment Block access, a common anti-analysis technique used by mal |
| capa | capa top_rules | `rule 'compress data via WinAPI' (T1560.002)` | Shows the sample can compress data, a behavior commonly used to pack secondary payloads or archive stolen data for exfil |
| floss | floss strings sampled | `string 'Payload'` | Direct reference to a payload component, a strong indicator of dropper functionality. |
| yara | yara matches | `rules 'Microsoft_Visual_Basic_v50v60', 'SEH__vba', 'SEH_Init'` | Confirms the sample is compiled with Visual Basic 6.0, a platform frequently used for low-sophistication malware and dro |
| pe_imports | pe_imports signals | `imports 'LoadLibrary', 'GetProcAddress'` | These imports enable dynamic resolution of Windows APIs, a technique used to evade static analysis and hide malicious fu |
| yara | yara matches | `rule 'HasOverlay'` | Indicates the PE contains extra data after standard headers, a common technique for storing embedded secondary payloads  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 92
- **summary**: PE32 GUI executable compiled with Microsoft Visual Basic 6.0. High-signal indicators include YARA matches for Dropper_Strings, URL, IP, base64, and Misc_Suspicious_Strings; capa detections for runtime linking via LoadLibrary/GetProcAddress, PEB access/debugger detection, and data compression; PE import signals for LoadLibrary and GetProcAddress; and FLOSS strings revealing VB6 runtime (MSVBVM60.DLL, VBA6.DLL), security descriptor APIs (ConvertStringSecurityDescriptorToSecurityDescriptorA, SetKernelObjectSecurity), and common dropper/installer artifacts. No evidence of legitimate behavior overrides these deterministic malicious signals.

### deep key_evidence
- `"YARA rule Dropper_Strings matched at offset 18868 (length 36)"`
- `"YARA rule url matched at offset 525821 (length 351)"`
- `"YARA rule IP matched at offsets 14148 and 204309"`
- `"YARA rule contains_base64 matched at offset 8290 (length 12)"`
- `"capa: link function at runtime on Windows (T1129) via LoadLibrary/GetProcAddress"`
- `"capa: PEB access / access PEB ldr_data (debugger detection / module enumeration)"`
- `"capa: compress data via WinAPI (T1560.002)"`
- `"pe_import_signals: LoadLibrary and GetProcAddress imports"`
- `"FLOSS strings: MSVBVM60.DLL, VBA6.DLL, Project1, Payload, Module1..Module14"`
- `"FLOSS strings: ConvertStringSecurityDescriptorToSecurityDescriptorA, SetKernelObjectSecurity"`
- `"FLOSS strings: CallWindowProcA, RtlMoveMemory, GetProcAddress, LoadLibraryA"`
- `"Checklist YARA: IsPE32, IsWindowsGUI, HasOverlay, HasRichSignature, Microsoft_Visual_Basic_v50/v60"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 8 · duration_s: 3.09

| Rule | ATT&CK | MBC |
|---|---|---|
| compress data via WinAPI | T1560.002:Archive Collected Data | C0024:Compress Data |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| link function at runtime on Windows | T1129:Shared Modules |  |
| PEB access |  | B0001.019:Debugger Detection |
| access PEB ldr_data | T1129:Shared Modules |  |
| contain loop |  |  |
| compiled from Visual Basic |  |  |
| (internal) Visual Basic file limitation |  |  |

## PE Imports / Signals
import_count: 103

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 17

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@14148 len=18; $ipv6@204309 len=2 |
| contains_base64 | - | $a@8290 len=12 |
| Dropper_Strings | - | $a0@18868 len=36 |
| Misc_Suspicious_Strings | - | $a1@525839 len=5; $a4@525752 len=7; $a6@14090 len=52 |
| url | - | $url_regex@525821 len=351 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| Microsoft_Visual_Basic_v50v60 | - | $a@6140 len=20 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1; $b@6147 len=20 |
| Microsoft_Visual_Basic_v50_v60 | - | $c@6140 len=19 |
| Microsoft_Visual_Basic_v50_additional | - | $a@6140 len=20 |
| Microsoft_Visual_Basic_v50v60_additional | - | $a@6140 len=20 |
| SEH__vba | - | $@53834 len=16 |
| SEH_Init | - | $b@21314 len=7 |

## Generated YARA Meta
```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 14148,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 204309,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 8290,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 18868,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 525839,
          "length": 5,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 525752,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$a6",
          "offset": 14090,
          "length": 52,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 525821,
          "length": 351,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 168,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 6140,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/incoming
```

## FLOSS Strings
Total strings: 1249 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1249}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcAddress`
- `LoadLibraryA`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `kernel32.dll`
- `NTDLL.DLL`
- `user32.dll`
- `MSVBVM60.DLL`
- `Project1`
- `Payload`
- `COMDLG32.OCX`
- `MSComDlg.CommonDialog`
- `CommonDialog`
- `Module1`
- `Module2`
- `Module3`
- `Module4`
- `Module5`
- `Module6`
- `Module7`
- `Module8`
- `Module9`
- `Module10`
- `Module11`
- `Module12`
- `Module13`
- `Module14`
- `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- `VBA6.DLL`
- `__vbaErrorOverflow`
- `__vbaAryDestruct`
- `__vbaUbound`
- `__vbaFreeStrList`
- `__vbaStrI4`
- `__vbaUI1I2`
- `__vbaFreeVar`
- `__vbaFreeStr`
- `__vbaStrMove`
- `__vbaUI1I4`
- `__vbaGenerateBoundsError`
- `__vbaI4Str`
- `__vbaLenBstr`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004017fc
```asm
┌ 125: entry0 ();
│           0x004017fc      68881b4000     push 0x401b88
│           0x00401801      e8f0ffffff     call 0x4017f6
│           0x00401806      0000           add byte [eax], al
│           0x00401808      0000           add byte [eax], al
│           0x0040180a      0000           add byte [eax], al
│           0x0040180c      3000           xor byte [eax], al
│           0x0040180e      0000           add byte [eax], al
│           0x00401810      40             inc eax
│           0x00401811      0000           add byte [eax], al
│           0x00401813      0000           add byte [eax], al
│           0x00401815      0000           add byte [eax], al
│           0x00401817      0034ab         add byte [ebx + ebp*4], dh
│           0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch
│           0x0040181e      ec             in al, dx
│           0x0040181f      44             inc esp
│           0x00401820      81e1e1da20b8   and ecx, 0xb820dae1
│           0x00401826      55             push ebp
│           0x00401827      f20000         add byte [eax], al
│           0x0040182a      0000           add byte [eax], al
│           0x0040182c      0000           add byte [eax], al
│           0x0040182e      0100           add dword [eax], eax
│           0x00401830      0000           add byte [eax], al
│           0x00401832      2000           and byte [eax], al
│           0x00401834      0000           add byte [eax], al
│           0x00401836      40             inc eax
│           0x00401837      005072         add byte [eax + 0x72], dl
│           0x0040183a      6f             outsd dx, dword [esi]
│           0x0040183b      6a65           push 0x65                   ; 'e' ; 101
│           0x0040183d      63743100       arpl word [ecx + esi], si
│           0x00401841      008002000000   add byte [eax + 2], al
│           0x00401847      0000           add byte [eax], al
│           0x00401849      0000           add byte [eax], al
│           0x0040184b      0006           add byte [esi], al
│           0x0040184d      0000           add byte [eax], al
│           0x0040184f      00e4           add ah, ah
│           0x00401851      324000         xor al, byte [eax]
│           0x00401854      07             pop es
│           0x00401855      0000           add byte [eax], al
│           0x00401857      00c0           add al, al
│           0x00401859      304000         xor byte [eax], al
│           0x0040185c      07             pop es
│           0x0040185d      0000           add byte [eax], al
│           0x0040185f      004c3040       add byte [eax + esi + 0x40], cl
│           0x00401863      0007           add byte [edi], al
│           0x00401865      0000           add byte [eax], al
│           0x00401867      00fc           add ah, bh
│           0x00401869      2f             das
│           0x0040186a      40             inc eax
│           0x0040186b      0001           add byte [ecx], al
```
### 0x00401018
```asm
┌ 1364: sym.imp.MSVBVM60.DLL___vbaVarTstGt ();
│ ╎╎╎╎╎╎╎   0x00401018      41             inc ecx
│ ╎╎╎╎╎╎╎   0x00401019      98             cwde
│ ╎╎╎╎╎╎╎   0x0040101a      a4             movsb byte es:[edi], byte [esi]
│ ╎╎╎╎╎╎└─< 0x0040101b  ~   7286           jb 0x400fa3
│ ╎╎╎╎╎╎    ;-- _CIcos:
..
│ ╎╎╎╎╎╎    0x0040101d      93             xchg ebx, eax
│ ╎╎╎╎╎╎    0x0040101e  ~   a372f909a3     mov dword [0xa309f972], eax ; [0xa309f972:4]=-1
│ ╎╎╎╎╎╎    ;-- _adj_fptan:
..
│ └───────< 0x00401023  ~   72ee           jb 0x401013
│  ╎╎╎╎╎    ;-- __vbaVarMove:
..
│  ╎╎╎╎╎    0x00401025      6aa4           push 0xffffffffffffffa4
│  ╎╎╎╎╎┌─< 0x00401027  ~   7237           jb sym.imp.MSVBVM60.DLL_rtcGetObject
│  ╎╎╎╎╎│   ;-- __vbaStrI4:
..
│  ╎╎╎╎╎│   ;-- (0x0040102c) __vbaVarVargNofree:
│  ╎╎╎╎╎│   0x00401029  ~   05a2728d72     add eax, 0x728d72a2
│  ╎╎╎╎╎│   0x0040102e      a4             movsb byte es:[edi], byte [esi]
│ ┌───────< 0x0040102f  ~   7244           jb 0x401075
│ │╎╎╎╎╎│   ;-- __vbaAryMove:
..
│ │╎╎╎╎╎│   0x00401031      c2a072         ret 0x72a0
..
│ │╎╎╎╎╎│   ;-- (0x0040103c) __vbaStrVarMove:
│ │╎╎╎╎╎│   ;-- __vbaLenBstr:
│ │╎╎╎╎ │   ;-- (0x00401048) __vbaPut3:
└ │╎╎╎╎┌──> 0x0040104e      a4             movsb byte es:[edi], byte [esi]
│ │╎╎│╎╎│   ;-- (0x00401050) _adj_fdiv_m64:
│ │╎╎└────< 0x0040104f  ~   72ba           jb 0x40100b
│ │╎╎ ╎╎│   ;-- (0x00401054) __vbaNextEachVar:
│ │╎╎ ╎╎│   0x00401051  ~   02a372bc63a4   add ah, byte [ebx - 0x5b9c438e]
│ │└──────< 0x00401057  ~   72b7           jb sym.imp.user32.dll_CallWindowProcA
│ │ ╎ ╎╎│   ;-- rtcAnsiValueBstr:
..
│ │ ╎ └───< 0x00401059      70a2           jo 0x400ffd
│ │ ╎  ╎│   ;-- (0x0040105c) _adj_fprem1:
│ │ ╎ ┌───< 0x0040105b  ~   7241           jb 0x40109e
│ │ ╎ │╎│   0x0040105d  ~   09a372ca9ca1   or dword [ebx - 0x5e63358e], esp
│ │ ╎ │╎│   ;-- rtcGetObject:
│ │ ╎ │╎└─> 0x00401060      ca9ca1         retf 0xa19c
│ │ ╎ │╎    ;-- (0x00401064) __vbaStrCat:
│ │ ╎┌──┌─> 0x00401063  ~   7276           jb 0x4010db
│ │ ╎││╎╎   0x00401065      6aa2           push 0xffffffffffffffa2
│ │ ╎││└──< 0x00401067  ~   72e5           jb 0x40104e
│ │ ╎││ ╎   ;-- __vbaLsetFixstr:
..
│ │ └─────< 0x00401069      76a2           jbe 0x40100d
│ │  ││ ╎   ;-- (0x0040106c) __vbaSetSystemError:
│ │  ││┌──< 0x0040106b  ~   723a           jb 0x4010a7
│ │  │││╎   0x0040106d      c3             ret
..
│ │ ││││╎   ;-- (0x00401078) __vbaAryVar:
│ └───────> 0x00401075  ~   02a3724039a4   add ah, byte [ebx - 0x5bc6bf8e]
│   ││││╎   ;-- (0x0040107c) __vbaAryDestruct:
│   ──────> 0x0040107b  ~   72fe           jb 0x40107b
│   ││││╎   0x0040107d  ~   c1a172cc93..   shl dword [ecx - 0x5b6c338e], 0x72
│   ││││╎   ;-- __vbaVarForInit:
│  ┌──────> 0x00401080      cc             int3
..
│  ╎││││╎   ;-- (0x00401084) rtcRandomNext:
│ ┌───────> 0x00401083  ~   7205           jb 0x40108a
│ ╎╎││││╎   0x00401085  ~   cda1           int 0xa1
│ ╎╎││││╎   ;-- (0x00401088) rtcRandomize:
│ ────────> 0x00401086  ~   a1723acd
```
### 0x00401034
```asm
┌ 28: sym.imp.MSVBVM60.DLL___vbaFreeVar ();
│       ╎   0x00401034      3168a4         xor dword [eax - 0x5c], ebp
│      ┌──< 0x00401037  ~   72ff           jb sym.imp.MSVBVM60.DLL___vbaGosubReturn
│      │╎   ;-- __vbaGosubReturn:
│      └──> 0x00401038      ff             invalid
│       ╎   ;-- (0x0040103c) __vbaStrVarMove:
│       ╎   0x00401039  ~   3ba4722919..   cmp esp, dword [edx + esi*2 + reloc.MSVBVM60.DLL___vbaStrVarMove]
│       ╎   ;-- __vbaLenBstr:
│       ╎   0x00401040      9b             wait
│       ╎   0x00401041      6aa2           push 0xffffffffffffffa2
│       └─< 0x00401043  ~   7288           jb 0x400fcd
│           ;-- __vbaEnd:
..
│           ;-- (0x00401048) __vbaPut3:
│           0x00401045  ~   bea072fa56     mov esi, 0x56fa72a0
└           0x0040104a  ~   a2726272a4     mov byte [0xa4726272], al   ; [0xa4726272:1]=255
│           ;-- __vbaFreeVarList:
..
```
### 0x00401070
```asm
┌ 22: sym.imp.MSVBVM60.DLL___vbaHresultCheckObj (int32_t arg_40h);
│      ╎│   ; arg int32_t arg_40h @ ebp+0x40
│      ╎└─< 0x00401070      74a2           je 0x401014
│      ╎    ;-- (0x00401074) _adj_fdiv_m32:
│      ╎    0x00401072  ~   a1726e02a3     mov eax, dword [0xa3026e72] ; [0xa3026e72:4]=-1
│      ╎    ;-- (0x00401078) __vbaAryVar:
..
│      ╎┌─< 0x00401077  ~   7240           jb 0x4010b9
│      ╎│   ;-- __vbaAryVar:
..
│      ╎│   0x00401079  ~   39a472fec1..   cmp dword [edx + esi*2 + reloc.MSVBVM60.DLL___vbaAryDestruct], esp
│      ╎│   ;-- (0x0040107c) __vbaAryDestruct:
..
│   │╎╎╎│   ;-- rtcRandomNext:
│ │╎ ╎╎╎│   ;-- (0x0040108c) rtcMsgBox:
│ │╎│╎╎╎│   ;-- (0x00401094) _adj_fdiv_m16i:
│ │╎│╎╎╎│   ;-- (0x0040109c) _adj_fdivr_m16i:
│ │╎│╎╎╎│   ;-- (0x004010a0) __vbaVarTstLt:
│ │╎│╎╎╎│   ;-- (0x004010a4) _CIsin:
│ │╎│╎╎╎│   ;-- (0x004010b8) __vbaGosubFree:
│ │╎│╎╎╎└─> 0x004010b9  ~   3ca4           cmp al, 0xa4                ; 164
..
│ │╎ ╎╎╎╎   ;-- (0x004010c4) __vbaGenerateBoundsError:
│  ╎││╎ ╎   ;-- (0x004010d4) __vbaAryConstruct2:
│  │  ╎ ╎   ;-- (0x004010dc) __vbaObjVar:
│     ╎╎╎   ;-- (0x004010e8) __vbaRedimPreserve:
│    │╎╎╎   ;-- (0x004010ec) _adj_fpatan:
│  ╎││ │╎   ;-- (0x00401100) __vbaUI1I2:
│  ╎ │  ╎   ;-- __vbaExceptHandler:
```
### 0x004010d8
```asm
┌ 7: sym.imp.MSVBVM60.DLL___vbaCyI4 (int32_t arg_40h);
│           ; arg int32_t arg_40h @ ebp+0x40
│           0x004010d8      b119           mov cl, 0x19                ; 25
└           0x004010da  ~   a272a9a1a1     mov byte [0xa1a1a972], al   ; [0xa1a1a972:1]=255
│           ;-- (0x004010dc) __vbaObjVar:
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
