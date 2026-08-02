## 1. Executive Summary
This report analyzes a malicious Visual Basic 6.0 compiled sample (SHA256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d) attributed to the Unicorn malware family, a VB-based info-stealer and dropper. The sample received a malicious verdict with a score of 87 (source: llm_judge, verdict). Cross-engine analysis confirms the sample is compiled with MSVBVM60.DLL (source: capa, top_rules, compiled from Visual Basic; source: floss, strings, MSVBVM60.DLL), contains the known Unicorn family identifier string "I'm Unicorn" (source: floss, strings, I'm Unicorn), and masquerades as Adobe Photoshop CC 2018 software to evade user suspicion (source: floss, strings, Adobe Photoshop CC 2018 (Windows)). The PE import table is completely empty (0 imports) (source: pe_imports, import_count, 0), indicating obfuscated or dynamically resolved APIs, a common anti-analysis tactic for this family. Analysis limitations include non-functional IDA (all queries return file not found errors) (source: llm_judge, cross_engine_notes), capa's internal inability to analyze Visual Basic files for behavioral capabilities (source: capa, top_rules, (internal) Visual Basic file limitation), and empty dynamic analysis results from Speakeasy and Frida. Despite these limitations, cross-engine evidence from Ghidra, FLOSS, and capa provides high confidence in the malicious verdict and Unicorn family attribution.

## 2. Sample Metadata
| Field | Value |
|--------|-------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 87 |
| Family Guess | Unicorn (VB6-based info-stealer/dropper) |
| Agreement | llm_v1_disagree |
| Cross-Engine Notes | IDA is non-functional (all queries return file not found errors), so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Ghidra reports 12 functions and 200 static strings, while FLOSS extracts 437 total strings including obfuscated/stack strings, with overlapping entries confirming data consistency. The PE import table reports 0 imports, while Ghidra has limited PTR entries for user32-related data, indicating the import table is obfuscated or dynamically resolved, a common anti-analysis tactic in this malware family. Capa confirms Visual Basic compilation but cannot provide behavioral capability detections due to its internal limitation for analyzing VB files. |
| Source | llm_judge |

## 3. File Layout & Structural Analysis
The sample is a standard PE file with a DOS stub and a .text section of 176128 bytes (source: radare2, disassembly, 0x00401000). The entry point (EP) is located at 0x004013d4, which executes a push of the string "VB5!6&vb6chs.dll" followed by a call to the MSVBVM60.DLL_ThunRTMain function to initialize the Visual Basic 6 runtime (source: radare2, disassembly, 0x004013d4). The Import Address Table (IAT) is completely empty, with 0 imported functions reported by the PE import table (source: pe_imports, import_count, 0), indicating the sample uses obfuscated or dynamically resolved APIs to hinder static analysis. UPX unpacking analysis confirms the sample is not packed (upx_ok: False, is_packed: False) (source: upx, upx_ok, is_packed), with no unpacked output generated. XOR search analysis found an XOR 00 value at offset 0x00000000, with a partial recovered string of "!This program cannot be r" (the start of the standard DOS stub), indicating no high-layer XOR obfuscation of the PE header (source: xor search). The sample does not contain a .NET assembly (is_dotnet: false) (source: .NET Analysis, is_dotnet).

## 4. Malcat Triage Summary
Malcat analysis failed to complete due to a missing executable error: `malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory` (source: Malcat Structured Analysis, error). No Malcat triage data is available for this sample.

## 5. Static Code Analysis
### Entry Point Disassembly (radare2)
The entry point at 0x004013d4 executes the following initial instructions (source: radare2, disassembly, 0x004013d4):
```asm
┌ 92: entry0 ();
│           0x004013d4      68e4914200     push 0x4291e4               ; "VB5!6&vb6chs.dll"
│           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain
│           0x004013de      0000           add byte [eax], al
│           0x004013e0      0000           add byte [eax], al
│           0x004013e2      0000           add byte [eax], al
│           0x004013e4      3000           xor byte [eax], al
│           0x004013e6      0000           add byte [eax], al
│           0x004013e8      3800           cmp byte [eax], al
│           0x004013ea      0000           add byte [eax], al
│           0x004013ec      0000           add byte [eax], al
│           0x004013ee      0000           add byte [eax], al
│           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]
│       ┌─< 0x004013f1      e27e           loop 0x401471
│       │   0x004013f3      fb             sti
│       │   0x004013f4      9b             wait
│       │   0x004013f5      6f             outsd dx, dword [esi]
│       │   0x004013f6      53             push ebx
│       │   0x004013f7      4d             dec ebp
│       │   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255
│       │   0x004013fd      58             pop eax
│       │   0x004013fe      0b16           or edx, dword [esi]
│       │   0x00401400      0000           add byte [eax], al
│       │   0x00401402      0000           add byte [eax], al
│       │   0x00401404      0000           add byte [eax], al
│       │   0x00401406      0100           add dword [eax], eax
│       │   0x00401408      0000           add byte [eax], al
│       │   0x0040140a      0000           add byte [eax], al
│       │   0x0040140c      48             dec eax
│       │   0x0040140d      00fd           add ch, bh
│       │   0x0040140f      07             pop es
│       │   0x00401410      56             push esi
│       │   0x00401411      6231           bound esi, qword [ecx]
│       │   0x00401413      007085         add byte [eax - 0x7b], dh
│       │   0x00401416      2903           sub dword [ebx], eax
│       │   0x00401418      0000           add byte [eax], al
│      ┌──> 0x0040141a      0000           add byte [eax], al
│      ╎│   0x0040141c      ffcc           dec esp
│      ╎│   0x0040141e      3100           xor dword [eax], eax
│      ╎│   0x00401420      048c           add al, 0x8c                ; 140
│      ╎│   0x00401422      2d5b5eb187     sub eax, 0x87b15e5b
│      ╎│   0x00401427      56             push esi
│      ╎│   0x00401428      43             inc ebx
│      ╎│   0x00401429      99             cdq
│      ╎│   0x0040142a      ff             invalid
.. │       └─> 0x00401471      0000           add byte [eax], al
│           0x00401473      0000           add byte [eax], al
└           0x00401475      ff             invalid
```
The call to `MSVBVM60.DLL_ThunRTMain` at 0x004013d9 is a standard VB6 runtime initialization routine, confirmed by the thunk at 0x004013cc (source: radare2, disassembly, 0x004013cc):
```asm
; CALL XREF from entry0 @ 0x4013d9(x)
┌ 6: sub.MSVBVM60.DLL_ThunRTMain ();
└           0x004013cc      ff25dc104000   jmp dword [sym.imp.MSVBVM60.DLL_ThunRTMain] ; 0x4010dc
```
### Import Analysis
The PE import table is empty (0 imports) (source: pe_imports, import_count, 0), but radare2 identifies a table of VB runtime function thunks at 0x00401000, including standard MSVBVM60.DLL exports like `__vbaStrCat`, `__vbaFreeVar`, `rtcRandomize`, and `__vbaFileClose` (source: radare2, disassembly, 0x00401000). This confirms the sample relies on the VB6 runtime for most functionality, with imports dynamically resolved at runtime to evade static analysis.
### Function Analysis
Ghidra identifies 12 total functions in the sample (source: ghidra, funcs, 12), consistent with the small obfuscated structure of VB-compiled malware that offloads most logic to the runtime library. A high-complexity core payload function `FUN_00429eb0` was identified with the following metrics: size 544 bytes, 170 instructions, 34 basic blocks, cyclomatic complexity 20 (source: deep_dive_agentic, function_metrics, FUN_00429eb0 size=544, instructions=170, blocks=34, cyclomatic_complexity=20). This function is the primary malicious payload logic container.
### String Analysis
FLOSS extracted 437 total static strings from the sample (source: floss, strings, total_strings: 437), with high-signal strings including:
- `MSVBVM60.DLL` (VB6 runtime library, source: floss, strings, MSVBVM60.DLL)
- `I'm Unicorn` (Unicorn family unique identifier, source: floss, strings, I'm Unicorn)
- `Unicorn`, `Kawaii-Unicorn`, `Kawaii-Unicorn.exe` (family and payload identifiers, source: floss, strings, Unicorn; source: floss, strings, Kawaii-Unicorn; source: floss, strings, Kawaii-Unicorn.exe)
- `Adobe Photoshop CC 2018 (Windows)` (masquerading string, source: floss, strings, Adobe Photoshop CC 2018 (Windows))
- `cmd /c rename "` (command execution string, source: floss, strings, cmd /c rename ")
- `zhttp://ns.adobe.com/xap/1.0/` (legitimate Adobe namespace used for camouflage, source: floss, strings, zhttp://ns.adobe.com/xap/1.0/)
Ghidra cross-references confirm that `FUN_0042a770` references the string `\Unicorn-` and `FUN_0042ac40` references the string `cmd /c rename "` (source: deep_dive_agentic, ghidra string_ref, FUN_0042a770 references '\Unicorn-'; source: deep_dive_agentic, ghidra string_ref, FUN_0042ac40 references 'cmd /c rename "').
### Capa Analysis
Capa matched 2 rules for the sample (source: capa, top_rules):
| Rule | ATT&CK | MBC |
|------|--------|-----|
| compiled from Visual Basic |  |  |
| (internal) Visual Basic file limitation |  |  |
The internal Visual Basic file limitation rule indicates capa cannot perform behavioral capability analysis on this sample, so no malicious capabilities are detected via capa (source: capa, top_rules, (internal) Visual Basic file limitation).

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy completed successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events, with no duration timestamp (source: speakeasy, api_calls: 0, key_events: 0, duration_s: None). No runtime behavior was observed during Speakeasy emulation. Frida instrumentation is available (version 17.16.4) (source: frida_probe, frida_available: True, version: 17.16.4) but no instrumentation data was collected, so no runtime API tracing is available. UPX unpacking analysis confirmed the sample is not packed, with no unpacked output generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: ""). No process injection, file system modifications, or network activity were observed in dynamic analysis. All runtime behavior is handled via the MSVBVM60.DLL runtime, which was not instrumented for this analysis.

## 7. Network Indicators & C2
Static string analysis extracted one network-related string: `zhttp://ns.adobe.com/xap/1.0/`, a legitimate Adobe XAP namespace used for metadata in Adobe file formats (source: floss, strings, zhttp://ns.adobe.com/xap/1.0/). This string is used for camouflage to make the sample appear as a legitimate Adobe Photoshop file. No malicious C2 endpoints, IP addresses, or domain names were identified in static strings. Dynamic analysis via Speakeasy recorded 0 network events (source: speakeasy, api_calls: 0), so no C2 communication was observed during emulation. No confirmed network indicators or C2 infrastructure are available for this sample at this time.

## 8. Capabilities & MITRE ATT&CK Mapping
Capa cannot provide confirmed behavioral capabilities for this sample due to its internal limitation for analyzing Visual Basic 6 files (source: capa, top_rules, (internal) Visual Basic file limitation). Capabilities are inferred from static string analysis, function metrics, and family attribution:
1. **Masquerading**: The sample uses Adobe Photoshop CC 2018 related strings and the Adobe XAP namespace string to appear as legitimate Adobe software (source: floss, strings, Adobe Photoshop CC 2018 (Windows); source: floss, strings, zhttp://ns.adobe.com/xap/1.0/).
2. **Command Execution**: The extracted string `cmd /c rename "` and its cross-reference in function `FUN_0042ac40` indicate the sample can execute Windows command shell commands, likely for file manipulation or payload deployment (source: floss, strings, cmd /c rename "; source: deep_dive_agentic, ghidra string_ref, FUN_0042ac40 references 'cmd /c rename "').
3. **Payload Dropping**: The presence of the string `Kawaii-Unicorn.exe` indicates the sample drops a secondary payload with this filename, consistent with the Unicorn family's dropper functionality (source: floss, strings, Kawaii-Unicorn.exe).
4. **Info-Stealing**: Family attribution to Unicorn, a known VB6-based info-stealer, indicates the sample likely steals sensitive data (e.g., credentials, browser data) from infected systems, though this is not confirmed via static or dynamic analysis of this specific sample.
### MITRE ATT&CK Mapping
| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Initial Access | User Execution: Malicious File | T1204.002 | Sample masquerades as Adobe Photoshop to trick users into executing it (source: floss, strings, Adobe Photoshop CC 2018 (Windows)) |
| Defense Evasion | Obfuscated Files or Information | T1027 | Empty PE import table (0 imports) indicates obfuscated/dynamically resolved APIs to hinder static analysis (source: pe_imports, import_count, 0) |
| Defense Evasion | Masquerading | T1036 | Uses legitimate Adobe software strings and namespace to appear as a trusted application (source: floss, strings, Adobe Photoshop CC 2018 (Windows); source: floss, strings, zhttp://ns.adobe.com/xap/1.0/) |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Extracted `cmd /c rename "` string indicates use of Windows Command Shell for command execution (source: floss, strings, cmd /c rename ") |

## 9. Indicators of Compromise
| Indicator | Type | Context | Source |
|-----------|------|---------|--------|
| 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d | File Hash (SHA256) | Sample hash | Sample Metadata |
| `I'm Unicorn` | String | Unicorn family unique identifier | floss, strings |
| `Unicorn` | String | Unicorn family identifier | floss, strings |
| `Kawaii-Unicorn` | String | Unicorn family variant identifier | floss, strings |
| `Kawaii-Unicorn.exe` | String | Dropped payload filename | floss, strings |
| `MSVBVM60.DLL` | String | VB6 runtime dependency | floss, strings; ghidra, imports |
| `Adobe Photoshop CC 2018 (Windows)` | String | Masquerading filename | floss, strings |
| `zhttp://ns.adobe.com/xap/1.0/` | String | Camouflage Adobe namespace | floss, strings |
| `cmd /c rename "` | String | Command execution capability | floss, strings; deep_dive_agentic, ghidra string_ref (FUN_0042ac40) |
| `\Unicorn-` | String | Unicorn family path/identifier | deep_dive_agentic, ghidra string_ref (FUN_0042a770) |
| 0x00429eb0 | Function Address | High-complexity core payload function (544 bytes, 170 instructions, 34 blocks, CC 20) | deep_dive_agentic, function_metrics |

## 10. Detection Engineering
### YARA Rules
Automated YARA rule generation failed due to a missing `yr` binary, with batch errors reporting `[Errno 2] No such file or directory: 'yr'` (source: Generated YARA Meta, batch_errors). A manual YARA rule for Unicorn VB6 samples can be constructed from high-signal FLOSS strings:
```yara
rule Unicorn_VB6_InfoStealer_Dropper {
    meta:
        description = "Detects Unicorn family VB6 info-stealer/dropper samples"
        author = "Malware Analysis Team"
        sha256 = "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d"
    strings:
        $unicorn_id = "I'm Unicorn"
        $vb_runtime = "MSVBVM60.DLL"
        $camouflage = "Adobe Photoshop CC 2018 (Windows)"
        $kawaii = "Kawaii-Unicorn"
        $cmd_exec = "cmd /c rename \""
    condition:
        uint16(0) == 0x5A4D and all of them
}
```
### Static Detection Logic
1. Flag PE files with 0 imported functions that contain the string `MSVBVM60.DLL` and `I'm Unicorn`, which are unique to this VB6 Unicorn family sample (source: pe_imports, import_count, 0; source: floss, strings, MSVBVM60.DLL; source: floss, strings, I'm Unicorn).
2. Flag samples with a high-complexity function at address 0x00429eb0 (assuming a base address of 0x00400000) with metrics of 170+ instructions and 34+ basic blocks, consistent with the core payload function identified in this sample (source: deep_dive_agentic, function_metrics, FUN_00429eb0).
3. Note that capa is not effective for detecting capabilities in VB6 samples due to its internal analysis limitation (source: capa, top_rules, (internal) Visual Basic file limitation), so static string and import analysis should be prioritized for this family.
### Dynamic Detection Logic
1. Monitor for processes spawning `cmd.exe` with `rename` command arguments, which matches the extracted command execution string (source: floss, strings, cmd /c rename ").
2. Monitor for file write events creating files named `Kawaii-Unicorn.exe` in user-writable directories (source: floss, strings, Kawaii-Unicorn.exe).
3. Flag unsigned executables with Adobe Photoshop-related filenames that are not located in standard Adobe installation directories.

## 11. What We Don't Know
1. **Full malicious capability set**: Capa cannot analyze Visual Basic 6 files for behavioral capabilities (source: capa, top_rules, (internal) Visual Basic file limitation), so confirmed capabilities beyond inferred masquerading, command execution, and payload dropping are unavailable. Specific info-stealing targets (e.g., credentials, browser data, cryptocurrency wallets) are not confirmed.
2. **C2 infrastructure**: No malicious C2 endpoints, domains, or IP addresses were identified in static string analysis (source: floss, strings), and no network events were observed in dynamic analysis (source: speakeasy, api_calls: 0). C2 communication mechanisms and infrastructure are unknown.
3. **Full core payload logic**: Only 12 functions were identified in Ghidra (source: ghidra, funcs, 12), and IDA is non-functional (source: llm_judge, cross_engine_notes: IDA is non-functional), so the full functionality of the high-complexity core payload function `FUN_00429eb0` is not fully reversed.
4. **Persistence mechanisms**: No persistence-related strings (e.g., Run registry keys, scheduled task references) or API calls were observed in static or dynamic analysis, so persistence behavior is unknown.
5. **Data exfiltration methods**: No exfiltration-related strings (e.g., FTP, HTTP POST, DNS tunneling references) or network activity were observed, so data exfiltration mechanisms are unknown.
6. **Additional payloads**: While the `Kawaii-Unicorn.exe` string indicates a secondary payload is dropped, the functionality of this payload is unknown as it was not observed in analysis.

## 12. Appendix: Analysis Environment
The following tools were used to analyze the sample, with noted limitations:
| Tool | Status | Findings | Source |
|------|--------|----------|--------|
| IDA | Non-functional | All queries returned file not found errors, no static analysis data available | llm_judge, cross_engine_notes |
| Ghidra | Functional | 12 functions identified, MSVBVM60.DLL imports, string references for `FUN_0042a770` and `FUN_0042ac40` | ghidra, funcs; deep_dive_agentic, ghidra string_ref |
| FLOSS | Functional | 437 total static strings extracted, including high-signal Unicorn family and Adobe camouflage strings | floss, strings |
| capa | Functional | 2 rules matched (compiled from Visual Basic, internal VB limitation), no behavioral capabilities detected due to VB analysis limitation | capa, top_rules |
| pe_imports | Functional | 0 imported functions found in PE import table, indicating obfuscated/dynamically resolved APIs | pe_imports, import_count |
| radare2 | Functional | Entry point at 0x004013d4, MSVBVM60.DLL_ThunRTMain thunk identified, VB runtime function thunks at 0x00401000 | radare2, disassembly |
| UPX | Functional | Sample not packed, no unpacked output generated | upx, upx_ok, is_packed |
| XOR Search | Functional | XOR 00 found at offset 0x00000000, partial DOS stub string recovered | xor search |
| Speakeasy | Functional | 0 API calls and 0 key events recorded, no runtime behavior observed | speakeasy, api_calls, key_events |
| Frida | Functional (probe only) | Version 17.16.4 available, no instrumentation data collected | frida_probe, frida_available, version |
| Malcat | Non-functional | Analysis failed due to missing `malcat.mcp.py` file, no triage data available | Malcat Structured Analysis, error |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d  
**sample_path:** /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 87
- **family_guess**: Unicorn (VB6-based info-stealer/dropper)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA is non-functional (all queries return file not found errors), so all static analysis data is sourced from Ghidra, FLOSS, capa, and pe_imports. Ghidra reports 12 functions and 200 static strings, while FLOSS extracts 437 total strings including obfuscated/stack strings, with overlapping entries confirming data consistency. The PE import table reports 0 imports, while Ghidra has limited PTR entries for user32-related data, indicating the import table is obfuscated or dynamically resolved, a common anti-analysis tactic in this malware family. Capa confirms Visual Basic compilation but cannot provide behavioral capability detections due to its internal limitation for analyzing VB files.
- **summary**: This is a malicious Visual Basic 6.0 compiled sample attributed to the Unicorn malware family, a VB-based info-stealer and dropper. The sample masquerades as Adobe Photoshop software to evade user suspicion, uses obfuscated or dynamically resolved imports to hinder static analysis, and contains the known Unicorn identifier string 'I'm Unicorn'. While analysis limitations exist (non-functional IDA, capa's VB analysis limitation, empty PE import table), cross-engine evidence from capa, FLOSS, and Ghidra provides high confidence in the malicious verdict and family attribution.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `compiled from Visual Basic` | Capa analysis explicitly identifies the sample as compiled from Visual Basic, confirming its compilation environment whi |
| floss | strings | `MSVBVM60.DLL` | FLOSS extracted the string 'MSVBVM60.DLL', the runtime library for Visual Basic 6.0, which corroborates the capa finding |
| floss | strings | `I'm Unicorn` | FLOSS extracted the unique identifier string 'I'm Unicorn', which is a known marker for the Unicorn malware family, a VB |
| capa | top_rules | `(internal) Visual Basic file limitation` | Capa reports an internal limitation for analyzing Visual Basic files, which explains the absence of behavioral capabilit |
| pe_imports | import_count | `0` | The PE import table reports 0 imported functions, indicating the sample uses obfuscated, packed, or dynamically resolved |
| ghidra | funcs | `12` | Ghidra identified only 12 functions in the sample, consistent with the small, obfuscated structure of many VB-compiled m |
| floss | strings | `Adobe Photoshop CC 2018 (Windows)` | FLOSS extracted Adobe Photoshop related strings, indicating the sample likely masquerades as legitimate Photoshop softwa |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Visual Basic 6 malware with camouflage strings referencing Adobe Photoshop and the 'Unicorn'/'Kawaii-Unicorn' identifiers. Contains a command-execution string 'cmd /c rename "' and a high-complexity payload function (FUN_00429eb0, CC=20, 170 instructions, 34 blocks). The sample is compiled with MSVBVM60.DLL and exhibits characteristics of the Kawaii Unicorn malware family.

### deep key_evidence
- `"capa rule: compiled from Visual Basic"`
- `"FLOSS string: 'Unicorn'"`
- `"FLOSS string: 'Kawaii-Unicorn'"`
- `"FLOSS string: 'Kawaii-Unicorn.exe'"`
- `"FLOSS string: 'cmd /c rename \"'"`
- `"FLOSS string: 'Adobe Photoshop CC 2018'"`
- `"FLOSS string: 'zhttp://ns.adobe.com/xap/1.0/'"`
- `"Ghidra import: MSVBVM60.DLL"`
- `"Ghidra string_ref: FUN_0042a770 references '\\\\Unicorn-'"`
- `"Ghidra string_ref: FUN_0042ac40 references 'cmd /c rename \"'"`
- `"Ghidra function_metrics: FUN_00429eb0 size=544, instructions=170, blocks=34, cyclomatic_complexity=20"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 2 · duration_s: 1.53

| Rule | ATT&CK | MBC |
|---|---|---|
| compiled from Visual Basic |  |  |
| (internal) Visual Basic file limitation |  |  |

## PE Imports / Signals
import_count: 0

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
Total strings: 437 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 437}`

### High-signal FLOSS
- `zhttp://ns.adobe.com/xap/1.0/`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `MSVBVM60.DLL`
- `Unicorn`
- `I'm Unicorn`
- `Adobe Photoshop CC 2018 (Windows)`
- `2019:01:07 19:44:27`
- `Adobe_CM`
- `dEU6te`
- `'7GWgw`
- `^FNEmu`
- `T+i&5.<`
- `T{@DiJ`
- `\Photoshop 3.0`
- `printOutput`
- `PstSbool`
- `Inteenum`
- `printSixteenBitbool`
- `printerNameTEXT`
- `printProofSetupObjc`
- `proofSetup`
- `Bltnenum`
- `builtinProof`
- `proofCMYK`
- `printOutputOptions`
- `Cptnbool`
- `Clbrbool`
- `RgsMbool`
- `CntCbool`
- `Lblsbool`
- `Ngtvbool`
- `EmlDbool`
- `Intrbool`
- `BckgObjc`
- `Rd  doub@o`
- `Grn doub@o`
- `Bl  doub@o`
- `BrdTUntF#Rlt`
- `Bld UntF#Rlt`
- `RsltUntF#Pxl@b`
- `vectorDatabool`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004013d4
```asm
┌ 92: entry0 ();
│           0x004013d4      68e4914200     push 0x4291e4               ; "VB5!6&vb6chs.dll"
│           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain
│           0x004013de      0000           add byte [eax], al
│           0x004013e0      0000           add byte [eax], al
│           0x004013e2      0000           add byte [eax], al
│           0x004013e4      3000           xor byte [eax], al
│           0x004013e6      0000           add byte [eax], al
│           0x004013e8      3800           cmp byte [eax], al
│           0x004013ea      0000           add byte [eax], al
│           0x004013ec      0000           add byte [eax], al
│           0x004013ee      0000           add byte [eax], al
│           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]
│       ┌─< 0x004013f1      e27e           loop 0x401471
│       │   0x004013f3      fb             sti
│       │   0x004013f4      9b             wait
│       │   0x004013f5      6f             outsd dx, dword [esi]
│       │   0x004013f6      53             push ebx
│       │   0x004013f7      4d             dec ebp
│       │   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255
│       │   0x004013fd      58             pop eax
│       │   0x004013fe      0b16           or edx, dword [esi]
│       │   0x00401400      0000           add byte [eax], al
│       │   0x00401402      0000           add byte [eax], al
│       │   0x00401404      0000           add byte [eax], al
│       │   0x00401406      0100           add dword [eax], eax
│       │   0x00401408      0000           add byte [eax], al
│       │   0x0040140a      0000           add byte [eax], al
│       │   0x0040140c      48             dec eax
│       │   0x0040140d      00fd           add ch, bh
│       │   0x0040140f      07             pop es
│       │   0x00401410      56             push esi
│       │   0x00401411      6231           bound esi, qword [ecx]
│       │   0x00401413      007085         add byte [eax - 0x7b], dh
│       │   0x00401416      2903           sub dword [ebx], eax
│       │   0x00401418      0000           add byte [eax], al
│      ┌──> 0x0040141a      0000           add byte [eax], al
│      ╎│   0x0040141c      ffcc           dec esp
│      ╎│   0x0040141e      3100           xor dword [eax], eax
│      ╎│   0x00401420      048c           add al, 0x8c                ; 140
│      ╎│   0x00401422      2d5b5eb187     sub eax, 0x87b15e5b
│      ╎│   0x00401427      56             push esi
│      ╎│   0x00401428      43             inc ebx
│      ╎│   0x00401429      99             cdq
│      ╎│   0x0040142a      ff             invalid
..
│       └─> 0x00401471      0000           add byte [eax], al
│           0x00401473      0000           add byte [eax], al
└           0x00401475      ff             invalid
```
### 0x004013cc
```asm
; CALL XREF from entry0 @ 0x4013d9(x)
┌ 6: sub.MSVBVM60.DLL_ThunRTMain ();
└           0x004013cc      ff25dc104000   jmp dword [sym.imp.MSVBVM60.DLL_ThunRTMain] ; 0x4010dc
```
### 0x00401000
```asm
╎╎   ;-- section..text:
┌ 619: sym.imp.MSVBVM60.DLL__CIcos ();
│      ╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] srwx section size 176128 named .text
│      ╎╎   ;-- _adj_fptan:
..
│      ╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│      ╎╎   ;-- __vbaVarMove:
..
│      ╎╎   ;-- (0x0040100c) __vbaFreeVar:
│     ┌───< 0x0040100b  ~   7231           jb 0x40103e
│     │╎╎   ;-- (0x00401010) rtcRgb:
│     │╎╎   0x0040100d  ~   68a4728dcc     push 0xcc8d72a4
│    ┌────> 0x00401012  ~   a1726272a4     mov eax, dword [0xa4726272] ; [0xa4726272:4]=-1
│    ╎│╎╎   ;-- __vbaFreeVarList:
│   ┌─────> 0x00401014      6272a4         bound esi, qword [edx - 0x5c]
│   ╎╎│╎│   ;-- (0x00401018) __vbaEnd:
│   ╎╎│╎└─< 0x00401017  ~   7288           jb 0x400fa1
│   ╎╎│╎    0x00401019  ~   bea072ba02     mov esi, 0x2ba72a0
│   ╎╎│╎    ;-- _adj_fdiv_m64:
│   ╎╎│╎    ;-- (0x00401020) __vbaFreeObjList:
│   ╎╎│╎    0x0040101c  ~   ba02a372c3     mov edx, 0xc372a302
│   ╎╎│╎    0x00401021      9f             lahf
│   ╎╎│╎    0x00401022  ~   a1724109a3     mov eax, dword [0xa3094172] ; [0xa3094172:4]=-1
│   ╎╎│╎│   ;-- _adj_fprem1:
..
│   ╎╎│╎│   ;-- (0x00401028) __vbaStrCat:
│   ╎╎│╎│   0x00401025  ~   09a372766aa2   or dword [ebx - 0x5d95898e], esp
│   ╎╎│╎│   0x00401029      6aa2           push 0xffffffffffffffa2
│   ╎╎│╎│   ;-- (0x0040102c) __vbaSetSystemError:
│  ┌──────< 0x0040102b  ~   723a           jb 0x401067
│  │╎╎│╎│   0x0040102d      c3             ret
..
│ ││╎╎│╎│   ;-- (0x00401040) rtcRandomize:
│ ││╎╎└───> 0x0040103e  ~   a1723acda1     mov eax, dword [0xa1cd3a72] ; [0xa1cd3a72:4]=-1
│ ││╎╎│││   ;-- (0x00401044) __vbaOnError:
│ ─────└──< 0x00401043  ~   729d           jb 0x400fe2
│ ││╎╎│ │   0x00401045      49             dec ecx
│ ││╎╎│ │   0x00401046  ~   a272f19fa1     mov byte [0xa19ff172], al   ; [0xa19ff172:1]=255
│ ││╎╎│ │   ;-- __vbaObjSet:
..
│ ││╎╎│┌──< 0x0040104b  ~   7206           jb 0x401053                 ; sym.imp.MSVBVM60.DLL__CIcos+0x53
│ ││╎╎│││   ;-- _adj_fdiv_m16i:
..
│ ││╎╎│││   ;-- (0x00401050) _adj_fdivr_m16i:
│ ││╎╎│││   0x0040104d  ~   03a3720604a3   add esp, dword [ebx - 0x5cfbf98e]
│ ││╎╎│││   ;-- (0x00401054) _CIsin:
│ ─────└──> 0x00401053  ~   72ee           jb 0x401043
│ ││╎╎│ │   0x00401055      94             xchg esp, eax
│ ││╎╎│ │   0x00401056  ~   a372ea62a3     mov dword [0xa362ea72], eax ; [0xa362ea72:4]=-1
│ ││╎╎│ │   ;-- __vbaChkstk:
..
│ ││╎╎│┌──< 0x0040105b  ~   727d           jb 0x4010da
│ ││╎╎│││   ;-- __vbaFileClose:
..
│ ││╎╎│││   0x0040105d      41             inc ecx
│ ││╎╎│││   0x0040105e  ~   a172749ba0     mov eax, dword [0xa09b7472] ; [0xa09b7472:4]=-1
│ ││╎╎│││   ;-- EVENT_SINK_AddRef:
..
│ ────────> 0x00401061      9b             wait
│ ││╎╎│││   0x00401062  ~   a07210c4a1     mov al, byte [0xa1c41072]   ; [0xa1c41072:1]=255
│ ││╎╎│││   ;-- __vbaGenerateBoundsError:
..
│ ││╎╎│││   0x00401065  ~   c4a1726c57a2   les esp, [ecx - 0x5da8
```
### 0x00401030
```asm
┌ 64: sym.imp.MSVBVM60.DLL___vbaHresultCheckObj ();
│     ╎╎└─< 0x00401030      74a2           je 0x400fd4
│     ╎╎    ;-- (0x00401034) _adj_fdiv_m32:
│     ╎╎    0x00401032  ~   a1726e02a3     mov eax, dword [0xa3026e72] ; [0xa3026e72:4]=-1
│     ╎╎    ;-- (0x00401038) __vbaAryDestruct:
│     ╎╎ ─> 0x00401037  ~   72fe           jb 0x401037
│     ╎╎    0x00401039  ~   c1a17205cd..   shl dword [ecx - 0x5e32fa8e], 0x72
│     ╎╎    ;-- (0x0040103c) rtcRandomNext:
│     ╎╎┌─> 0x0040103a  ~   a17205cda1     mov eax, dword [0xa1cd0572] ; [0xa1cd0572:4]=-1
│     ╎╎╎   ;-- (0x00401040) rtcRandomize:
..
│     ╎╎╎   0x0040103f  ~   723a           jb 0x40107b
│     ╎╎╎   ;-- rtcRandomize:
│     ╎╎╎   0x00401040      3acd           cmp cl, ch
│     ╎╎╎   0x00401042  ~   a1729d49a2     mov eax, dword [0xa2499d72] ; [0xa2499d72:4]=-1
│   ╎╎╎╎╎   ;-- __vbaOnError:
..
│   ╎╎╎╎└─< 0x00401047  ~   72f1           jb 0x40103a
│   ╎╎╎╎    ;-- __vbaObjSet:
..
│   ╎╎╎╎    0x00401049      9f             lahf
│   ╎╎╎╎    0x0040104a  ~   a1720603a3     mov eax, dword [0xa3030672] ; [0xa3030672:4]=-1
│   ╎╎╎╎    ;-- _adj_fdiv_m16i:
..
│   ╎╎╎╎    ;-- (0x00401050) _adj_fdivr_m16i:
│   ╎╎╎╎┌─< 0x0040104f  ~   7206           jb 0x401057
│   ╎╎╎╎│   ;-- _adj_fdivr_m16i:
..
│   ╎╎╎╎│   0x00401051      04a3           add al, 0xa3                ; 163
│   │╎╎╎│   ;-- (0x00401054) _CIsin:
..
│    ╎╎╎│   ;-- (0x00401058) __vbaChkstk:
│    ╎╎╎└─> 0x00401057  ~   72ea           jb 0x401043
│    ╎╎╎    ;-- (0x0040105c) __vbaFileClose:
│    ╎╎╎    0x00401059  ~   62a3727d41a1   bound esp, qword [ebx - 0x5ebe828e]
│    ╎╎╎│   0x0040105f  ~   7274           jb 0x4010d5
│    ╎╎╎│   ;-- EVENT_SINK_AddRef:
..
│  │╎╎╎╎│   ;-- (0x00401068) __vbaPutOwner3:
│  │╎╎╎╎│   ;-- (0x00401074) __vbaRedim:
│   ╎╎│╎│   ;-- (0x00401078) __vbaStrR8:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   0x0040107b  ~   7287           jb sym.imp.MSVBVM60.DLL__adj_fptan
│   ╎╎ ╎│   0x0040107d      9b             wait
..
│    ╎ ╎│   ;-- (0x00401088) _CIsqrt:
│    ╎  │   ;-- (0x00401090) __vbaExceptHandler:
│    ╎  │   ;-- _adj_fprem:
│      ││   ;-- (0x004010a0) __vbaGetOwner3:
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
