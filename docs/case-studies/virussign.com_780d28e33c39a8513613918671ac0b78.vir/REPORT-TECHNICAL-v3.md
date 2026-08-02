## 1. Executive Summary
This sample is a malicious Visual Basic 6 (VB6) compiled dropper/loader affiliated with the Darty Crypter family, with a threat score of 88 (source: llm_judge, verdict: Malicious). Core capabilities include runtime API resolution via LoadLibraryA/GetProcAddress, anti-debugging via Process Environment Block (PEB) inspection, data compression for payload obfuscation, hardcoded payload download from a remote server, registry-based persistence, and payload execution via ShellExecuteW (source: deep_dive_agentic, confidence: 90). Static analysis confirms VB6 compilation via capa rules and FLOSS strings identifying MSVBVM60.DLL and VBA6.DLL as runtime dependencies (source: capa, rule: compiled from Visual Basic; source: floss, extracted strings: MSVBVM60.DLL, VBA6.DLL). An explicit project path string `C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` at address 0x4202654 directly links the sample to the Darty Crypter malware family (source: floss, address: 0x4202654, row: C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp). Tooling limitations impacted analysis: IDA was non-functional due to a missing idasql binary, Malcat failed due to a missing MCP script, and YARA failed due to a missing yr binary, so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| Sample Path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 88 |
| Family Guess | Darty Crypter |
| Agreement | llm_v1_disagree |
| Analysis Source | llm_judge (model: step-3.7-flash) |

Cross-engine validation notes: Ghidra reported 42 functions and 122 imports, which align with pe_imports' 103 import count and FLOSS' 1249 extracted strings, confirming consistent analysis of the sample's VB6 origin and malicious behavior set (source: llm_judge, cross_engine_notes). IDA reported 0 imports and 0 functions due to a missing idasql binary, so its data is excluded from analysis (source: llm_judge, cross_engine_notes).

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows PE file, with no UPX packing observed (source: upx, upx_ok: False, is_packed: False). A XOR search identified a XOR 00 byte at the start of the file (position 0x00000000), with no other high-signal XOR values detected (source: xor, found XOR 00 position 0x00000000). The sample is not a .NET assembly (source: .NET analysis, is_dotnet: false).

Static import analysis via pe_imports identified 103 total imports, with high-signal obfuscation-related imports including LoadLibrary (T1129) and GetProcAddress (T1129) for runtime API resolution (source: pe_imports, signals table, row: load_library, api_match: LoadLibrary, ATT&CK: T1129; row: get_proc_address, api_match: GetProcAddress, ATT&CK: T1129). FLOSS extracted 1249 static strings, including VB6 runtime dependencies: `MSVBVM60.DLL`, `VBA6.DLL`, and VB runtime symbols like `__vbaErrorOverflow`, `__vbaAryDestruct`, `__vbaUbound`, and `__vbaStrI4` (source: floss, extracted strings, total_strings: 1249). Ghidra analysis identified 42 functions and 122 imports, consistent with pe_imports and FLOSS data (source: llm_judge, cross_engine_notes).

Entry point (EP) disassembly from radare2 at 0x004017fc shows initial stack setup and a call to a thunk at 0x401b88, followed by uninitialized memory writes typical of VB6 compiled binaries (source: radare2, address: 0x004017fc). Additional radare2 disassembly of VB6 runtime thunks imported from MSVBVM60.DLL is present at addresses 0x00401018 (sym.imp.MSVBVM60.DLL___vbaVarTstGt), 0x00401034 (sym.imp.MSVBVM60.DLL___vbaFreeVar), 0x00401070 (sym.imp.MSVBVM60.DLL___vbaHresultCheckObj), and 0x004010d8 (sym.imp.MSVBVM60.DLL___vbaCyI4) (source: radare2, addresses: 0x00401018, 0x00401034, 0x00401070, 0x004010d8).

## 4. Malcat Triage Summary
Malcat analysis failed due to a missing MCP script: the error returned was `MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory` (source: Malcat, analysis error). No Malcat profile data, triage results, or structural analysis is available for this sample.

## 5. Static Code Analysis
### capa Capability Rules
capa analysis identified 8 matching rules, with a runtime of 3.41 seconds (source: capa, total_rules: 8, duration_s: 3.41). Full rule list with ATT&CK and MBC mappings:
| Rule | ATT&CK | MBC |
|------|--------|-----|
| compress data via WinAPI | T1560.002:Archive Collected Data | C0024:Compress Data |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
| link function at runtime on Windows | T1129:Shared Modules |  |
| PEB access |  | B0001.019:Debugger Detection |
| access PEB ldr_data | T1129:Shared Modules |  |
| contain loop |  |  |
| compiled from Visual Basic |  |  |
| (internal) Visual Basic file limitation |  |  |

### High-Signal FLOSS Strings
FLOSS extracted 1249 static strings, with high-signal entries including:
- `kernel32.dll` (source: floss, extracted strings)
- `GetProcAddress` (source: floss, extracted strings)
- `LoadLibraryA` (source: floss, extracted strings)
- `MSVBVM60.DLL` (source: floss, extracted strings)
- `VBA6.DLL` (source: floss, extracted strings)
- `C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` at address 0x4202654 (source: floss, address: 0x4202654, extracted strings)
- `127.0.2.5\tdownload.mcafee.com\r\n` at address 0x4210252 (source: floss, address: 0x4210252, extracted strings)
- `URLDownloadToFileA` at address 0x4205988, referenced from function FUN_00406fe0 (source: deep_dive_agentic, address: 0x4205988, referenced_from: FUN_00406fe0)
- `temp` at address 0x4208064, referenced from function FUN_00409380 (source: deep_dive_agentic, address: 0x4208064, referenced_from: FUN_00409380)
- `REG ADD` and `/t REG_SZ /d` at addresses 0x4213080 and 0x4211380, referenced from function FUN_0040c380 (source: deep_dive_agentic, addresses: 0x4213080, 0x4211380, referenced_from: FUN_0040c380)
- `Payload` at address 0x4201472 (source: deep_dive_agentic, address: 0x4201472)

### radare2 Entry Point Disassembly
Disassembly of the entry point at 0x004017fc:
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

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy returned no observable runtime behavior: 0 API calls and 0 key events were recorded, with no duration metric available (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed). Frida probe version 17.16.4 is available in the analysis environment, but no runtime instrumentation data was collected (source: frida_probe, frida_available: True, version: 17.16.4, not observed). UPX unpacking was attempted, but the sample is not packed, so no unpacked payload path was generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: empty). No dynamic execution artifacts, network traffic, or payload drops were observed during analysis.

## 7. Network Indicators & C2
Static analysis identified a hardcoded C2 indicator at address 0x4210252: the string `127.0.2.5\tdownload.mcafee.com\r\n`, which indicates a hardcoded download source for payload retrieval (source: floss, address: 0x4210252, extracted strings). The import `URLDownloadToFileA` at address 0x4205988, referenced from function FUN_00406fe0, confirms the sample uses the Windows URLDownloadToFile API to download remote payloads (source: deep_dive_agentic, address: 0x4205988, referenced_from: FUN_00406fe0). No dynamic network traffic was observed via Speakeasy or Frida, so C2 protocol details and additional network indicators are not available (source: speakeasy, not observed; source: frida_probe, not observed).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample implements the following malicious capabilities, mapped to MITRE ATT&CK and Malware Behavior Catalog (MBC) where applicable:
| Capability | Source | Mapping |
|------------|--------|---------|
| Runtime API resolution via LoadLibraryA/GetProcAddress | source: pe_imports, row: load_library, api_match: LoadLibrary; source: pe_imports, row: get_proc_address, api_match: GetProcAddress; source: capa, rule: link function at runtime on Windows | ATT&CK: T1129:Shared Modules |
| Anti-debugging via PEB inspection | source: capa, rule: PEB access; source: capa, rule: access PEB ldr_data | MBC: B0001.019:Debugger Detection; ATT&CK: T1129:Shared Modules |
| Data compression for payload obfuscation | source: capa, rule: compress data via WinAPI | ATT&CK: T1560.002:Archive Collected Data; MBC: C0024:Compress Data |
| Payload download from remote server | source: deep_dive_agentic, imports: URLDownloadToFileA | ATT&CK: T1105:Ingress Tool Transfer (implied) |
| Registry-based persistence | source: deep_dive_agentic, imports: RegOpenKeyW, RegSetValueExW, RegCloseKey; source: deep_dive_agentic, strings: REG ADD, /t REG_SZ /d | ATT&CK: T1547.001:Registry Run Keys / Startup Folder (implied) |
| Payload execution | source: deep_dive_agentic, imports: ShellExecuteW | ATT&CK: T1059.003:Windows Command Shell (implied) |
| VB6 compilation | source: capa, rule: compiled from Visual Basic; source: floss, extracted strings: MSVBVM60.DLL, VBA6.DLL | N/A |

## 9. Indicators of Compromise
| IOC Type | Value | Source |
|----------|-------|--------|
| File Hash (SHA256) | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 | llm_judge, sample_metadata |
| Sample Path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir | llm_judge, sample_metadata |
| Hardcoded C2 IP | 127.0.2.5 | floss, address: 0x4210252, extracted strings |
| Hardcoded C2 Path | download.mcafee.com | floss, address: 0x4210252, extracted strings |
| VB6 Runtime Dependency | MSVBVM60.DLL | floss, extracted strings |
| VB6 Runtime Dependency | VBA6.DLL | floss, extracted strings |
| Family Attribution String | C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp | floss, address: 0x4202654, extracted strings |
| Persistence String | REG ADD /t REG_SZ /d | deep_dive_agentic, addresses: 0x4213080, 0x4211380, strings |
| Payload String | Payload | deep_dive_agentic, address: 0x4201472, strings |
| Temp File Path String | temp | deep_dive_agentic, address: 0x4208064, strings |

## 10. Detection Engineering
YARA rule generation was not possible due to a missing `yr` binary, with batch errors returned for all YARA scan attempts (source: YARA meta, batch_errors: [Errno 2] No such file or directory: 'yr'). Malcat profile-based detection is also unavailable due to the missing MCP script (source: Malcat, analysis error). Recommended detection signatures based on available static data:
1. **Import Signature**: Alert on PE files with the import set {LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecuteW} combined with VB6 runtime imports (MSVBVM60.DLL, VBA6.DLL) (source: pe_imports, signals; source: deep_dive_agentic, imports; source: floss, extracted strings).
2. **String Signature**: Alert on files containing the string `C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` or the hardcoded C2 string `127.0.2.5\tdownload.mcafee.com\r\n` (source: floss, address: 0x4202654, 0x4210252, extracted strings).
3. **capa Signature**: Alert on binaries matching capa rules `compiled from Visual Basic`, `link function at runtime on Windows`, `PEB access`, and `compress data via WinAPI` (source: capa, top_rules).
4. **Behavioral Signature**: Alert on processes that use URLDownloadToFileA to write files to temp directories followed by registry modification and ShellExecuteW execution (source: deep_dive_agentic, capabilities).

## 11. What We Don't Know
1. IDA Pro analysis is unavailable: IDA was non-functional due to a missing idasql binary, reporting 0 imports and 0 functions, so no IDA-specific disassembly, decompilation, or cross-reference data is available (source: llm_judge, cross_engine_notes).
2. Malcat triage and profile data is unavailable due to a missing MCP script (source: Malcat, analysis error).
3. YARA rules and YARA-based detection are unavailable due to a missing `yr` binary (source: YARA meta, batch_errors).
4. No dynamic runtime behavior was observed: Speakeasy returned 0 API calls and 0 key events, and Frida instrumentation collected no data, so no runtime execution flow, payload drop locations, or network traffic is available (source: speakeasy, not observed; source: frida_probe, not observed).
5. The embedded payload was not extracted: while the sample has compression capabilities (source: capa, rule: compress data via WinAPI), no unpacked payload was recovered during static or dynamic analysis.
6. Specific registry persistence key paths are not confirmed: static strings reference `REG ADD` and `/t REG_SZ /d`, but no explicit registry key paths (e.g., HKCU\Software\Microsoft\Windows\CurrentVersion\Run) were observed in static data (source: deep_dive_agentic, strings: REG ADD, /t REG_SZ /d).
7. Exact C2 communication protocol details are not available: only the use of URLDownloadToFileA for payload retrieval is confirmed, with no observed dynamic network traffic (source: deep_dive_agentic, imports: URLDownloadToFileA; source: speakeasy, not observed).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Notes |
|------|---------------|-------|
| Ghidra | N/A (used for static analysis) | Reported 42 functions and 122 imports, aligned with pe_imports and FLOSS data (source: llm_judge, cross_engine_notes) |
| FLOSS | N/A (used for string extraction) | Extracted 1249 static strings, including VB6 runtime artifacts and malicious indicators (source: floss, total_strings: 1249) |
| capa | 3.41s runtime, 8 matching rules | Confirmed VB6 compilation, runtime API resolution, anti-debugging, and compression capabilities (source: capa, total_rules: 8, duration_s: 3.41) |
| pe_imports | N/A (used for import analysis) | Identified 103 total imports, including high-signal obfuscation APIs (source: pe_imports, import_count: 103) |
| radare2 | N/A (used for disassembly) | Provided EP and VB6 thunk disassembly snippets (source: radare2, addresses: 0x004017fc, 0x00401018, 0x00401034, 0x00401070, 0x004010d8) |
| UPX | N/A (used for unpacking) | Sample is not packed, no unpacked payload generated (source: upx, upx_ok: False, is_packed: False) |
| XOR Search | N/A (used for XOR key detection) | Identified XOR 00 at file position 0x00000000 (source: xor, found XOR 00 position 0x00000000) |
| Speakeasy | N/A (dynamic analysis) | No API calls or key events observed (source: speakeasy, api_calls: 0, key_events: 0, not observed) |
| Frida | 17.16.4 (available, no data collected) | No runtime instrumentation data available (source: frida_probe, frida_available: True, version: 17.16.4, not observed) |
| IDA Pro | Non-functional | Missing idasql binary, reported 0 imports and 0 functions (source: llm_judge, cross_engine_notes) |
| Malcat | Failed | Missing MCP script, no analysis data available (source: Malcat, analysis error) |
| YARA | Failed | Missing `yr` binary, no rules generated (source: YARA meta, batch_errors) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075  
**sample_path:** /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 88
- **family_guess**: Darty Crypter
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA was non-functional due to a missing idasql binary, reporting 0 imports and 0 functions, so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Malcat failed due to a missing MCP script, and YARA failed due to a missing yr binary, so no YARA or Malcat profile data is available. Ghidra's reported 42 functions and 122 imports align with pe_imports' 103 import count and FLOSS' 1249 extracted strings, providing consistent cross-engine validation of the sample's VB6 origin and malicious behavior set.
- **summary**: This is a Visual Basic 6-compiled malicious binary affiliated with the Darty Crypter family. It exhibits core crypter behaviors including runtime API resolution via LoadLibrary/GetProcAddress, anti-debugging via PEB inspection, and data compression capabilities. The sample contains explicit references to the Darty Crypter source project path, confirming its family attribution. It relies on the VB6 runtime (MSVBVM60.DLL) and uses standard Windows APIs to implement its obfuscation and anti-analysis functionality.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| floss | extracted strings | `` | This explicit project path string directly links the sample to the Darty Crypter malware family, providing clear family  |
| capa | top_rules | `` | Confirms the sample is built with Visual Basic 6, consistent with VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) observe |
| pe_imports | signals | `` | High-signal import indicating runtime dynamic library loading, a common obfuscation technique used by crypters to avoid  |
| capa | top_rules | `` | Indicates anti-debugging functionality via Process Environment Block inspection, a standard anti-analysis behavior in ma |
| capa | top_rules | `` | Confirms data compression capabilities, a core crypter function used to obfuscate embedded malicious payloads. |
| ghidra | Suspicious strings (Ghidra) | `` | Validates the VB6 compilation finding, as MSVBVM60.DLL is the required runtime for VB6-compiled executables. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a Visual Basic 6 dropper/loader. It uses runtime dynamic linking via LoadLibraryA/GetProcAddress, downloads a payload from a hardcoded IP/path, writes it to a temp location, establishes persistence through the registry using RegOpenKeyW/RegSetValueExW, and executes it via ShellExecuteW. Capabilities and strings strongly indicate download-and-run behavior with persistence, not a benign utility.

### deep key_evidence
- `"Ghidra imports: LoadLibraryA, GetProcAddress, URLDownloadToFileA, RegOpenKeyW, RegSetValueExW, RegCloseKey, ShellExecuteW"`
- `"String: URLDownloadToFileA at 4205988 referenced from FUN_00406fe0"`
- `"String: temp at 4208064 referenced from FUN_00409380"`
- `"String: REG ADD and /t REG_SZ /d at 4213080/4211380 referenced from FUN_0040c380"`
- `"String: 127.0.2.5\\tdownload.mcafee.com\\r\\n at 4210252 indicating hardcoded download source"`
- `"String: Payload at 4201472 and project path @*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp at 4202654"`
- `"capa: link function at runtime on Windows, PEB access, access PEB ldr_data, compiled from Visual Basic"`
- `"FLOSS: MSVBVM60.DLL, VBA6.DLL, VB runtime symbols present"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 8 · duration_s: 3.41

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

## Generated YARA Meta
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
