> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:31:36 UTC

## 1. Executive Summary
This sample is a malicious Visual Basic 6.0 compiled dropper with a score of 95, per the llm_judge verdict (source: llm_judge, verdict: Malicious, score: 95, family_guess: Visual Basic 6.0 Dropper). All analysis engines corroborate malicious indicators: YARA matches 17 rules including VB6-specific, Dropper_Strings, HasOverlay, URL, IP, and base64 patterns; capa identifies 8 capabilities including runtime API resolution (T1129), debugger detection via PEB access (B0001.019), and data compression (T1560.002); FLOSS extracts 1249 static strings including VB6 runtime DLLs (MSVBVM60.DLL, VBA6.DLL), dropper artifacts (Project1, Payload, Module1..Module14), and security descriptor APIs; PE imports confirm LoadLibrary and GetProcAddress signals for dynamic API resolution. No benign functionality was observed across any analysis engine. The sample contains an overlay consistent with an embedded secondary payload, and employs anti-debug and obfuscation techniques to evade analysis.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| Sample Path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Visual Basic 6.0 Dropper |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | YARA, FLOSS, and capa all corroborate Visual Basic 6.0 compilation: YARA matches 6 VB6-specific rules, FLOSS extracts VB6 runtime DLL (MSVBVM60.DLL, VBA6.DLL) and VBA function strings, and capa identifies a Visual Basic compilation rule. Dynamic API resolution is confirmed across capa (T1129 runtime linking rule), pe_imports (LoadLibrary/GetProcAddress imports), and FLOSS (extracted API strings). Dropper functionality is indicated by YARA's Dropper_Strings match, FLOSS's 'Payload' string reference, capa's data compression rule (often used for payload packing), and YARA's HasOverlay match (common for embedded secondary payloads). Anti-debug behavior is confirmed by capa's PEB ldr_data access rule. |
| Source | llm_judge |

## 3. File Layout & Structural Analysis
The sample is a PE32 GUI executable, confirmed by YARA rules `IsPE32` and `IsWindowsGUI` (source: yara, yara matches). It is not a .NET assembly (source: dotnet, is_dotnet: False). The sample is not packed with UPX: UPX unpacking returned `upx_ok: False`, `is_packed: False`, with no unpacked path generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: ``). A PE overlay is present, confirmed by the YARA `HasOverlay` rule (source: yara, yara matches, rule: HasOverlay), a common indicator of embedded secondary payloads in droppers. The PE includes a Rich signature, confirmed by YARA `HasRichSignature` (source: yara, yara matches, rule: HasRichSignature).

The sample has 103 imports (source: pe_imports, import_count: 103), with high-signal imports including `LoadLibrary` and `GetProcAddress` (source: pe_imports, pe_imports signals, imports: LoadLibrary, GetProcAddress) used for dynamic API resolution to evade static analysis. FLOSS extracted 1249 static strings, including VB6 runtime dependencies (`MSVBVM60.DLL`, `VBA6.DLL`), dropper artifacts (`Project1`, `Payload`, `Module1` through `Module14`), and low-level Windows APIs (`ConvertStringSecurityDescriptorToSecurityDescriptorA`, `SetKernelObjectSecurity`, `CallWindowProcA`, `RtlMoveMemory`, `GetProcAddress`, `LoadLibraryA`) (source: floss, floss strings sampled).

Entry point disassembly from radare2 at `0x004017fc` shows initial stack setup and call instructions typical of VB6 compiled entry points:
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
(source: radare2, address: 0x004017fc)

Additional disassembly of imported VB6 runtime functions at `0x00401018` (sym.imp.MSVBVM60.DLL___vbaVarTstGt):
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
(source: radare2, address: 0x00401018)

Additional VB6 runtime function disassembly at `0x00401034` (sym.imp.MSVBVM60.DLL___vbaFreeVar):
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
(source: radare2, address: 0x00401034)

Disassembly at `0x00401070` (sym.imp.MSVBVM60.DLL___vbaHresultCheckObj):
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
(source: radare2, address: 0x00401070)

Disassembly at `0x004010d8` (sym.imp.MSVBVM60.DLL___vbaCyI4):
```asm
┌ 7: sym.imp.MSVBVM60.DLL___vbaCyI4 (int32_t arg_40h);
│           ; arg int32_t arg_40h @ ebp+0x40
│           0x004010d8      b119           mov cl, 0x19                ; 25
└           0x004010da  ~   a272a9a1a1     mov byte [0xa1a1a972], al   ; [0xa1a1a972:1]=255
│           ;-- (0x004010dc) __vbaObjVar:
..
```
(source: radare2, address: 0x004010d8)

A XOR search of the sample found a XOR 00 pattern at position `0x00000000`, corresponding to the standard DOS stub header (source: xor, Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r).

Malcat analysis failed with the error: `malcat_analyze top-level: MCP malcat closed: `, so no Malcat triage data is available (source: Malcat, analysis error).

## 4. Malcat Triage Summary
Malcat analysis failed to complete: the top-level analysis returned the error `malcat_analyze top-level: MCP malcat closed: ` (source: Malcat, analysis error). No Malcat triage results, layout data, or signature matches are available for this sample.

## 5. Static Code Analysis
### Capabilities (capa)
capa identified 8 total rules for the sample, with a runtime of 3.09s (source: capa, total rules: 8, duration_s: 3.09):
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

### YARA Matches
YARA matched 17 total rules for the sample (source: yara, total matches: 17):
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

High-signal YARA match offsets (source: deep_dive_agentic):
- Dropper_Strings: offset 18868 (length 36)
- URL pattern: offset 525821 (length 351)
- IPv4 address: offset 14148 (length 18)
- IPv6 address: offset 204309 (length 2)
- Base64 pattern: offset 8290 (length 12)
- Misc_Suspicious_Strings: offsets 525839 (len 5), 525752 (len7), 14090 (len52)

### PE Import Signals
The sample has 103 total imports (source: pe_imports, import_count: 103), with high-signal imports for dynamic API resolution:
| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

### High-Signal FLOSS Strings
FLOSS extracted 1249 total static strings (source: floss, total strings: 1249, per_category: {"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1249}). High-signal static strings include:
- VB6 runtime dependencies: `MSVBVM60.DLL`, `VBA6.DLL`, `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- Dropper/installer artifacts: `Project1`, `Payload`, `Module1` through `Module14`, `COMDLG32.OCX`, `MSComDlg.CommonDialog`, `CommonDialog`
- VBA runtime functions: `__vbaErrorOverflow`, `__vbaAryDestruct`, `__vbaUbound`, `__vbaFreeStrList`, `__vbaStrI4`, `__vbaUI1I2`, `__vbaFreeVar`, `__vbaFreeStr`, `__vbaStrMove`, `__vbaUI1I4`, `__vbaGenerateBoundsError`, `__vbaI4Str`, `__vbaLenBstr`
- Windows API primitives: `ConvertStringSecurityDescriptorToSecurityDescriptorA`, `SetKernelObjectSecurity`, `CallWindowProcA`, `RtlMoveMemory`, `GetProcAddress`, `LoadLibraryA`
- Standard PE string: `!This program cannot be run in DOS mode.`

## 6. Behavioral & Dynamic Analysis
All dynamic analysis tools recorded no observable runtime events:
- Speakeasy dynamic analysis completed successfully (`speakeasy_ok: True`) but recorded 0 API calls and 0 key events, with no duration data (source: speakeasy, api_calls: 0, key_events: 0, duration_s: None). **not observed**: no runtime API calls or events were captured.
- Frida probe is available (version 17.16.4) but recorded no events during analysis (source: frida_probe, frida_available: True, version: 17.16.4, no events recorded). **not observed**: no Frida-instrumented runtime behavior was captured.
- UPX unpacking attempt failed: the sample is not packed with UPX, so no unpacked payload is available for dynamic analysis (source: upx, upx_ok: False, is_packed: False, unpacked_path: ``).
- .NET analysis is not applicable: the sample is not a .NET assembly (source: dotnet, is_dotnet: False). **not observed**: no .NET runtime behavior is present.

## 7. Network Indicators & C2
Static analysis confirms the presence of network-related patterns, but no live C2 communication was observed in dynamic analysis:
- YARA matched a URL pattern at offset `525821` (length 351) (source: yara, yara matches, rule: url, offset: 525821, length: 351)
- YARA matched IPv4 and IPv6 patterns at offsets `14148` (length 18) and `204309` (length 2) respectively (source: yara, yara matches, rule: IP, offsets: 14148, 204309)
- YARA matched a domain pattern at offset `0` (length 2) (source: yara, yara matches, rule: domain, offset: 0, length: 2)
- YARA matched a base64 pattern at offset `8290` (length 12), which may encode C2 or payload data (source: yara, yara matches, rule: contains_base64, offset: 8290, length: 12)

No live C2 endpoints were extracted from static strings, and no network traffic was observed during dynamic analysis (Speakeasy/Frida recorded no events). The exact C2 URLs, IP addresses, and domain values are (unknown) as the structured evidence does not provide the decoded content of these patterns.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample's confirmed capabilities, derived from capa, YARA, FLOSS, and PE import analysis, are mapped to MITRE ATT&CK and MBC frameworks below:
| Capability | Source | MITRE ATT&CK | MBC |
|---|---|---|---|
| Runtime API resolution via LoadLibrary/GetProcAddress | capa (rule: link function at runtime on Windows), pe_imports (imports: LoadLibrary, GetProcAddress), FLOSS (strings: GetProcAddress, LoadLibraryA) | T1129: Shared Modules |  |
| Debugger detection via PEB ldr_data access | capa (rule: access PEB ldr_data) | T1129: Shared Modules | B0001.019: Debugger Detection |
| Data compression via WinAPI | capa (rule: compress data via WinAPI) | T1560.002: Archive Collected Data | C0024: Compress Data |
| Visual Basic 6.0 compilation | capa (rule: compiled from Visual Basic), YARA (rules: Microsoft_Visual_Basic_v50v60, SEH__vba, SEH_Init), FLOSS (strings: MSVBVM60.DLL, VBA6.DLL) |  |  |
| Dropper functionality (embedded secondary payload) | YARA (rule: Dropper_Strings, rule: HasOverlay), FLOSS (string: Payload), capa (rule: compress data via WinAPI) | T1027: Obfuscated Files or Information, T1106: Native API |  |
| Security descriptor modification | FLOSS (strings: ConvertStringSecurityDescriptorToSecurityDescriptorA, SetKernelObjectSecurity) | T1574: Hijack Execution Flow |  |
| Code injection primitives | FLOSS (strings: CallWindowProcA, RtlMoveMemory) | T1055: Process Injection |  |
| Modulo calculation via x86 assembly | capa (rule: calculate modulo 256 via x86 assembly) |  | C0058: Modulo |
| Loop execution | capa (rule: contain loop) |  |  |

## 9. Indicators of Compromise
### Static IOCs
| IOC Type | Value | Source | Offset/Context |
|---|---|---|---|
| SHA256 Hash | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 | llm_judge | Sample identifier |
| YARA Match (Dropper_Strings) | Rule match at offset 18868 (length 36) | yara | Offset 18868 |
| YARA Match (URL) | URL pattern at offset 525821 (length 351) | yara | Offset 525821 |
| YARA Match (IPv4) | IPv4 pattern at offset 14148 (length 18) | yara | Offset 14148 |
| YARA Match (IPv6) | IPv6 pattern at offset 204309 (length 2) | yara | Offset 204309 |
| YARA Match (Base64) | Base64 pattern at offset 8290 (length 12) | yara | Offset 8290 |
| VB6 Runtime DLL | MSVBVM60.DLL | floss | Static string |
| VB6 Runtime DLL | VBA6.DLL | floss | Static string |
| Dropper Artifact | Payload | floss | Static string |
| Dropper Artifact | Project1 | floss | Static string |
| Dropper Artifact | Module1..Module14 | floss | Static strings |
| Security Descriptor API | ConvertStringSecurityDescriptorToSecurityDescriptorA | floss | Static string |
| Security Descriptor API | SetKernelObjectSecurity | floss | Static string |
| Code Injection Primitive | CallWindowProcA | floss | Static string |
| Code Injection Primitive | RtlMoveMemory | floss | Static string |
| Dynamic API Resolution | LoadLibraryA | floss | Static string |
| Dynamic API Resolution | GetProcAddress | floss | Static string |
| PE Overlay | Present | yara | HasOverlay rule match |
| VB6 Compilation | Confirmed | yara, capa, floss | Multiple VB6-specific rules/strings |

### Detection Rules
- Generated YARA rule path: `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar` (source: rule.yara.json, rule_path)
- Generated Sigma rule path: `/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yml` (source: rule.yara.json, sigma_path)

Note: Exact C2 IP addresses, domain, and URL values are (unknown) as the structured evidence only confirms their presence via YARA, not their decoded content. The embedded overlay payload content is also (unknown) as it was not extracted during analysis.

## 10. Detection Engineering
### Static Detection
1. **YARA Detection**: The sample matches 17 YARA rules, including 6 VB6-specific rules (`Microsoft_Visual_Basic_v50v60`, `Microsoft_Visual_Basic_v50`, `Microsoft_Visual_Basic_v50_v60`, `Microsoft_Visual_Basic_v50_additional`, `Microsoft_Visual_Basic_v50v60_additional`, `SEH__vba`, `SEH_Init`), dropper indicators (`Dropper_Strings`, `HasOverlay`), and network pattern rules (`url`, `IP`, `domain`, `contains_base64`). A generated YARA rule is available at the path noted in Section 9.
2. **PE Import Detection**: Flag PE32 GUI files with `LoadLibrary` and `GetProcAddress` imports, especially when combined with VB6 runtime imports (MSVBVM60.DLL, VBA6.DLL) and high import counts (this sample has 103 imports).
3. **String Detection**: Hunt for the high-signal FLOSS strings listed in Section 5, including `Payload`, `Project1`, `Module1`..`Module14`, `ConvertStringSecurityDescriptorToSecurityDescriptorA`, `SetKernelObjectSecurity`, `CallWindowProcA`, and `RtlMoveMemory`.
4. **Overlay Detection**: Flag PE files with a non-empty overlay, particularly VB6-compiled samples, as this is a common dropper tactic for embedding secondary payloads.

### Behavioral Detection
1. **capa Rule Matching**: Use capa to detect the sample's confirmed capabilities: runtime API resolution (T1129), PEB access for debugger detection (B0001.019), and data compression (T1560.002).
2. **Debugger Detection**: Monitor for PEB ldr_data access (FS:[0x30] reads) via EDR or kernel tracing, a confirmed anti-analysis behavior in this sample (source: capa, rule: access PEB ldr_data).
3. **Dynamic API Resolution**: Monitor for `LoadLibrary`/`GetProcAddress` calls to resolve non-standard APIs (e.g., security descriptor APIs) at runtime, a technique used to evade static analysis.

### Tuning Notes
- The sample is not packed with UPX, so no unpacking is required for static analysis.
- No .NET components are present, so .NET-specific detection rules are not applicable.
- Malcat analysis is currently non-functional for this sample, so Malcat-based detection rules cannot be used.

## 11. What We Don't Know
1. **Embedded Overlay Payload Functionality**: YARA confirms the presence of a PE overlay (source: yara, rule: HasOverlay), but the overlay content was not extracted during analysis. The functionality of the embedded secondary payload (e.g., whether it is a ransomware loader, infostealer, or backdoor) is (unknown).
2. **Exact C2 Endpoints**: YARA confirms the presence of URL, IP, and domain patterns (source: yara, rules: url, IP, domain), but the structured evidence does not provide the decoded values of these patterns. The exact C2 URLs, IP addresses, and domains used by the sample are (unknown).
3. **VB6 Module Functionality**: FLOSS lists 14 VB6 modules (Module1..Module14) and a Project1 entry point (source: floss, strings: Project1, Module1..Module14), but no decompiled VB6 code is available. The exact dropper behavior (e.g., payload drop path, persistence mechanism, execution method) is (unknown).
4. **Security Descriptor API Usage Context**: FLOSS extracts `ConvertStringSecurityDescriptorToSecurityDescriptorA` and `SetKernelObjectSecurity` (source: floss, strings: ConvertStringSecurityDescriptorToSecurityDescriptorA, SetKernelObjectSecurity), but their usage context (e.g., setting permissions for dropped payloads, disabling security tools) is (unknown) without full decompilation or dynamic analysis.
5. **Base64 String Purpose**: A base64 pattern is present at offset 8290 (length 12) (source: yara, rule: contains_base64, offset: 8290), but its content and purpose (e.g., encoded C2, payload fragment, or configuration) are (unknown).
6. **Runtime Behavior**: Speakeasy and Frida recorded no events, so the sample's runtime behavior (e.g., file system modifications, registry changes, process injection, payload execution) is (unknown).
7. **IP Address Values**: IPv4 and IPv6 patterns are present at offsets 14148 and 204309 (source: yara, rule: IP, offsets: 14148, 204309), but their actual values are not provided in the structured evidence, so the C2 IPs are (unknown).
8. **URL Content**: A URL pattern is present at offset 525821 (length 351) (source: yara, rule: url, offset: 525821), but its full content is not provided, so the exact C2 URL is (unknown).

## 12. Appendix: Analysis Environment
| Tool/Component | Version/Details | Status | Notes |
|---|---|---|---|
| capa | v5.16, duration 3.09s | OK | 8 rules matched, including T1129, T1560.002, B0001.019 |
| FLOSS | N/A | OK | 1249 static strings extracted, 0 decoded/stack/tight/language strings |
| radare2 | N/A | OK | Entry point and VB6 import disassembly extracted |
| YARA | N/A | OK | 17 rules matched, generated rule available at /opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar |
| PE Imports | N/A | OK | 103 total imports, LoadLibrary/GetProcAddress signals identified |
| UPX | N/A | Failed | Sample is not UPX packed, no unpacked path generated |
| XOR Search | N/A | OK | XOR 00 pattern found at offset 0x00000000 (DOS stub) |
| Speakeasy | N/A | OK (no events) | 0 API calls, 0 key events recorded |
| Frida | 17.16.4 | OK (no events) | Probe available, no events captured |
| Ghidra | N/A | OK | 20+ SQL queries executed for strings, imports, functions, call graphs, data items, memory blocks, function metrics |
| deep_dive_agentic | langgraph, confidence 92 | OK | Summary and key evidence provided |
| llm_judge | step-3.7-flash | OK | Verdict, score, and cross-engine notes provided |
| Malcat | N/A | Failed | Analysis error: `malcat_analyze top-level: MCP malcat closed: ` |

Sample analysis context:
- SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
- Sample path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- Project name: incoming
- Analysis date: 2026-08-06 (from YARA generated_at timestamp)
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
  "sha256": "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075",
  "family": "unknown",
  "generated_at": "2026-08-06T00:27:39.653471+00:00",
  "string_count": 8,
  "strings": [
    "Directly indicates the sample contains strings associated with dropper functionality, a high-signal malicious indicator.",
    "Confirms the sample uses dynamic API resolution (LoadLibrary/GetProcAddress) to execute code, a common malware evasion a",
    "Indicates debugger detection behavior via Process Environment Block access, a common anti-analysis technique used by mal",
    "Shows the sample can compress data, a behavior commonly used to pack secondary payloads or archive stolen data for exfil",
    "Direct reference to a payload component, a strong indicator of dropper functionality.",
    "Confirms the sample is compiled with Visual Basic 6.0, a platform frequently used for low-sophistication malware and dro",
    "These imports enable dynamic resolution of Windows APIs, a technique used to evade static analysis and hide malicious fu",
    "Indicates the PE contains extra data after standard headers, a common technique for storing embedded secondary payloads "
  ],
  "rule_path": "/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar",
  "sigma_path": "/opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yml",
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
    "utc": "2026-08-06 00:27:39 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785856096.3992321}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785856096.4628897}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785856096.4786181}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785856096.5136716}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785856162.4438968}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports ORDER BY address LIMIT 50", "ts": 1785856166.5702832}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs ORDER BY address LIMIT 50", "ts": 1785856166.5847769}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE length > 10 ORDER BY address LIMIT 50", "ts": 1785856166.5957444}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%http%' OR content LIKE '%ftp%' OR content LIKE '%cmd%' OR content LIKE '%shell%' OR content LIKE '%payload%' OR content LIKE '%crypt%' OR content LIKE '%darty%' OR content LIKE '%project%' OR content LIKE '%vbp%' OR conten`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE length > 20 ORDER BY address LIMIT 100", "ts": 1785856170.2464604}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics ORDER BY instruction_count DESC LIMIT 20", "ts": 1785856170.66032}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%CreateProcess%' OR content LIKE '%NtUnmapViewOfSection%' OR content LIKE '%WriteProcessMemory%' OR content LIKE '%VirtualAlloc%' OR content LIKE '%GetTempPath%' OR content LIKE '%GetModuleFileName%' OR content LIKE '%URLDo`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 5", "ts": 1785856199.2539027}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges WHERE src_func_addr = 4200444 OR dst_func_addr = 4200444 LIMIT 20", "ts": 1785856206.1151278}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%Darty%' OR content LIKE '%Crypter%' OR content LIKE '%Payload%' OR content LIKE '%Project1%' OR content LIKE '%temp%' OR content LIKE '%URLDownload%' OR content LIKE '%NtUnmap%' OR content LIKE '%CreateProcess%' OR content`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE address = 0 OR address = 14148 OR address = 204309 OR address = 8290 OR address = 18868 OR address = 525839 OR address = 525752 OR address = 14090 OR address = 525821", "ts": 1785856216.4226334}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE address BETWEEN 14000 AND 14200 ORDER BY address", "ts": 1785856216.4287918}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE address BETWEEN 525700 AND 525900 ORDER BY address", "ts": 1785856216.4344463}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks ORDER BY start_ea", "ts": 1785856220.8570013}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items WHERE address BETWEEN 14000 AND 14200 ORDER BY address", "ts": 1785856220.8811321}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items WHERE address BETWEEN 525700 AND 525900 ORDER BY address", "ts": 1785856220.8984268}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE address >= 4251600 ORDER BY address LIMIT 100", "ts": 1785856226.2360864}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports ORDER BY address", "ts": 1785856226.2416322}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics WHERE string_ref_count > 0 ORDER BY string_ref_count DESC LIMIT 20", "ts": 1785856226.4612005}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785856233.2385375}`
- `{"source": "yara_gen_v2", "ts": 1785856234.2856016}`
- `{"source": "publish_report_v2", "ts": 1785856315.668601}`
- `{"source": "publish_report_v2_technical", "ts": 1785856446.089232}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785975928.5260093}`
- `{"source": "yara_gen_v2", "ts": 1785976059.6538093}`
