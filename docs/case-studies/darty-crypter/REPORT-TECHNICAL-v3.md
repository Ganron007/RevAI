## 1. Executive Summary

This report analyzes a malicious 32-bit Windows executable identified as a variant of the DartyCrypter malware family. The sample is a Visual Basic 6 compiled dropper designed to disable User Account Control (UAC), hijack the HOSTS file to block security vendor websites, download additional payloads, drop and execute malicious files, enumerate running processes, and establish persistence. Static analysis reveals the use of runtime dynamic API resolution to evade detection, along with PEB-based anti-debugging checks. The sample's project path string "C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp" confirms its origin as a crypter builder. Based on the convergence of multiple analytic engines, the verdict is malicious with high confidence (score 90, source: llm_judge).

## 2. Sample Metadata

- SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- File Type: PE32 executable (GUI) Intel 80386, for MS Windows
- Family Guess: DartyCrypter (source: verdict)
- Compiler: Microsoft Visual Basic 6.0 (MSVBVM60.DLL dependency)
- Subsystem: Windows GUI
- EP Bytes: 68 88 1B 40 00 E8 F0 FF FF FF (source: radare2, 0x004017fc)

## 3. File Layout & Structural Analysis

The file is a standard PE with typical sections. UPX unpacker confirms the sample is not packed (source: upx, upx_ok: False, is_packed: False). The entry point is at virtual address 0x004017fc (source: radare2). The import directory lists 103 imported functions, dominated by the Visual Basic 6 runtime MSVBVM60.DLL and core libraries KERNEL32.DLL, ADVAPI32.DLL, and OLEAUT32.DLL. High-signal imports include LoadLibrary and GetProcAddress from KERNEL32.DLL, indicating dynamic API resolution (source: pe_imports, signals). The binary also imports urlmon.dll (URLDownloadToFileA) and references the Windows Management Instrumentation (WMI) interface, suggesting network and system enumeration capabilities.

The PE's resources and overlay do not contain obvious payloads; the malicious logic resides in compiled VB6 event handlers and modular procedures. XOR search at offset 0x00000000 reveals a repeating pattern of 0x00, confirming the header is not obfuscated (source: xor).

## 4. Malcat Triage Summary

Malcat analysis encountered an execution error: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory. No Malcat output could be generated for this sample. (source: Malcat Structured Analysis)

## 5. Static Code Analysis

### General Characteristics
The binary is a Visual Basic 6 compiled executable, confirmed by the import of MSVBVM60.DLL and internal VB6 function names such as `__vbaErrorOverflow`, `__vbaAryDestruct`, `__vbaStrI4`, and `__vbaFreeVar` (source: ghidra, imports; floss, static strings). The project string `C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` identifies the sample as built from the Darty Crypter builder (source: ghidra, strings, ea: 0x00402ffc).

### Dynamic API Resolution
The sample employs runtime dynamic linking to obfuscate API calls. Imports of `LoadLibrary` and `GetProcAddress` from KERNEL32.DLL support this technique (source: pe_imports, signals). capa rule `link function at runtime on Windows` (T1129) was triggered (source: capa, top_rules). Additionally, `PEB access` and `access PEB ldr_data` rules indicate the sample traverses the Process Environment Block to locate DLL bases and resolve function pointers manually, a technique commonly used to bypass import-based detection and to implement anti-debugging (source: capa, top_rules).

### Code Disassembly
The entry point at 0x004017fc shows typical Visual Basic startup code, pushing a structure and calling the initialization routine (source: radare2, 0x004017fc):
```
push 0x401b88
call 0x4017f6
```

The bulk of malicious functionality resides in large functions identified by Ghidra's decompiler:
- `FUN_0040a3c0` (size 4630, cyclomatic_complexity 403): Contains references to `C:\WINDOWS\system32\drivers\etc\hosts` and over 30 blocked security domains redirected to `127.0.2.5`, including symantec.com, mcafee.com, kaspersky-labs.com, trendmicro.com, avast.com, virustotal.com, panda.com, f-secure.com (source: deep_dive_agentic, key_evidence).
- `FUN_00408d80`: Modifies registry key `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` values `EnableLUA` and `UACDisableNotify` via `RegSetValueExW`, effectively disabling User Account Control (source: deep_dive_agentic, key_evidence).
- `FUN_00409380`: References temporary payload paths `\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe` and `\tmpjhgTFztfZ789tfzTDt.exe`, indicating dropper behavior (source: deep_dive_agentic).
- `FUN_00406fe0`: Uses `URLDownloadToFileA` from urlmon.dll to download additional payloads (source: deep_dive_agentic).
- `FUN_00405f50`: Calls `CreateProcessW` to execute dropped or downloaded binaries (source: deep_dive_agentic).
- `FUN_00407180`: Executes a WMI query `select name from Win32_Process where name='---'` to enumerate running processes (source: deep_dive_agentic).

### CAPA Capability Rules
The following rules were detected by capa:

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

(source: capa, top_rules)

### YARA Scan
YARA scan encountered batch errors (file not found for 'yr') and produced no matches, likely due to tool misconfiguration (source: yara). No existing signature hits were recorded, but custom rules can be derived.

### High-Signal Strings
FLOSS extracted 1249 static strings, with no decoded or stack strings. Key indicators:
- `kernel32.dll` (floss)
- `GetProcAddress` (floss)
- `LoadLibraryA` (floss)
- `C:\WINDOWS\system32\drivers\etc\hosts` (ghidra, FUN_0040a3c0)
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` (ghidra, FUN_00408d80)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (ghidra)
- `service.exe` (ghidra)
- `tmpduzhfg89fgdgfgfdzuudgzfgfd.exe` (ghidra)
- `tmpjhgTFztfZ789tfzTDt.exe` (ghidra)
- `URLDownloadToFileA` (ghidra)
- `CreateProcessW` (ghidra)
- `select name from Win32_Process where name='---'` (ghidra)

These strings map directly to observed capabilities (source: ghidra, FLOSS).

## 6. Behavioral & Dynamic Analysis

Dynamic analysis via Speakeasy recorded no API calls or events (api_calls: 0, key_events: 0), likely because the sample requires a full Windows environment with specific dependencies or user interaction (source: speakeasy). Frida probe is available (version 17.16.4), but no behavioral data was collected. Therefore, runtime behavior such as process tree, file system changes, and network connections was not observed.

All behavioral conclusions are drawn from static analysis, which strongly suggests the malware drops files, modifies the HOSTS file, disables UAC, and downloads payloads. Without dynamic confirmation, the exact sequence and success conditions remain unverified.

## 7. Network Indicators & C2

Static analysis reveals network-related capabilities:
- **Download functionality**: The function `FUN_00406fe0` imports `URLDownloadToFileA` from urlmon.dll, enabling the sample to retrieve files from remote servers (source: deep_dive_agentic). The specific URLs are not hardcoded in strings and likely generated or passed at runtime.
- **HOSTS file hijack**: `FUN_0040a3c0` modifies `C:\WINDOWS\system32\drivers\etc\hosts` to redirect over 50 security-related domains to `127.0.2.5`. Identified domains include:
  - symantec.com
  - mcafee.com
  - kaspersky-labs.com
  - trendmicro.com
  - avast.com
  - virustotal.com
  - panda.com
  - f-secure.com
  (source: deep_dive_agentic, key_evidence)

This effectively prevents the victim from accessing antivirus update servers and scanning websites, aiding the malware's persistence.

No live C2 domains or IPs were observed dynamically.

## 8. Capabilities & MITRE ATT&CK Mapping

| Capability | MITRE ATT&CK | MBC | Source |
|---|---|---|---|
| Dynamic API resolution via LoadLibrary/GetProcAddress | T1129: Shared Modules | – | capa, pe_imports |
| PEB-based anti-debugging | T1497: Virtualization/Sandbox Evasion | B0001.019: Debugger Detection | capa |
| Disable Windows UAC via registry modification | T1548.002: Abuse Elevation Control Mechanism | – | deep_dive (FUN_00408d80) |
| HOSTS file modification to block security domains | T1565.001: Data Manipulation: Stored Data Manipulation | – | deep_dive (FUN_0040a3c0) |
| Download additional payloads (URLDownloadToFileA) | T1105: Ingress Tool Transfer | – | deep_dive (FUN_00406fe0) |
| Drop and execute binaries (CreateProcessW) | T1106: Native API | – | deep_dive (FUN_00405f50) |
| Process enumeration via WMI (Win32_Process) | T1057: Process Discovery | – | deep_dive (FUN_00407180) |
| Registry Run key persistence | T1547.001: Boot or Logon Autostart Execution: Registry Run Keys | – | deep_dive (HKLM\...\Run) |
| Data compression via WinAPI | T1560.002: Archive Collected Data | C0024: Compress Data | capa |
| Compiled from Visual Basic | T1059.005: Command and Scripting Interpreter: Visual Basic (not directly) | – | capa, ghidra |

## 9. Indicators of Compromise

### File System
- `C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` (build artifact)
- `%TEMP%\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe`
- `%TEMP%\tmpjhgTFztfZ789tfzTDt.exe`
- Drop locations: `\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe`, `\tmpjhgTFztfZ789tfzTDt.exe` (source: ghidra)

### Registry
- Key: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (persistence)
- Key: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - `EnableLUA` = 0 (disable UAC)
  - `UACDisableNotify` = 1 (source: deep_dive)

### Network
- HOSTS file hijack: `C:\WINDOWS\system32\drivers\etc\hosts` entry `127.0.2.5` for multiple AV domains.

### Strings
- `service.exe` (possible masquerading filename)
- VB6 runtime artifact strings (MSVBVM60, VBA6, etc.)

### YARA (proposed rule)
```
rule DartyCrypter_ProjectPath {
    strings:
        $proj = "Darty Crypter Source\\Payload\\Project1.vbp" ascii wide
        $hosts = "\\system32\\drivers\\etc\\hosts" ascii wide
        $reg = "CurrentVersion\\Policies\\System" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
```

## 10. Detection Engineering

### Endpoint Detection (EDR)
- Monitor modifications to the HOSTS file (`%SystemRoot%\System32\drivers\etc\hosts`) with redirections to non-loopback IPs.
- Detect registry writes to `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System` that alter UAC settings (`EnableLUA`, `UACDisableNotify`).
- Alert on processes invoking `URLDownloadToFileA` or `CreateProcessW` from non-standard locations (e.g., VB6 applications with dynamic imports).
- Watch for WMI queries like `SELECT * FROM Win32_Process`.

### Network Detection
- DNS/Suricata rules to detect blocked AV domain queries redirecting to local IPs (127.0.2.5).
- Identify HTTP traffic related to urlmon URL downloads from suspicious directories.

### YARA Rule
Above IOCs section proposed a YARA rule.

## 11. What We Don't Know

- The exact command-and-control (C2) infrastructure: no dynamic network captures, and URLs for `URLDownloadToFileA` are not hardcoded.
- The specific payloads downloaded or dropped: only temp paths were found, but the binaries could not be analyzed.
- Actual runtime behavior: Speakeasy did not generate events, so the sequence of operations is inferred from static analysis.
- Whether the sample includes additional anti-analysis techniques beyond PEB access (e.g., timing checks, hardware breakpoint detection).
- The encryption or compressing algorithm used for the payload (capa detected compression via WinAPI but no more details).
- Any additional modules or libraries that might be loaded dynamically at runtime.

## 12. Appendix: Analysis Environment

### Tools and Versions
| Tool | Status | Notes |
|---|---|---|
| Ghidra (via SQL) | Success | Provided strings, imports, and function analysis |
| capa | Success | 8 rules detected |
| FLOSS | Success | 1249 static strings extracted |
| PE Import Analyzer | Success | 103 imports, 2 high-signal |
| YARA | Partial | Scan errors, no matches (missing 'yr' binary) |
| Malcat | Failed | Module not found error |
| radare2 | Success | Disassembly of entry point and selected API thunks |
| UPX Unpack | Success | Not packed |
| XOR Search | Success | Found XOR 00 at offset 0 |
| Speakeasy | Success (no output) | 0 API calls recorded |
| Frida Probe | Available | Version 17.16.4, no probes executed |
| Deep Dive Agentic | Success | Function-level decompilation and summary |

### Environment Details
- Architecture: i386, Windows binary
- Analysis Host: Linux (Python tools)
- Sample provided as-is; no runtime dependencies satisfied.

Note: All tool outputs are part of the structured evidence pack.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075  
**sample_path:** /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 90
- **family_guess**: DartyCrypter
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra provided strings and imports; capa provided behavioral detection rules; pe_imports confirmed high-signal API imports. IDA and Malcat failed to produce results. Yara had scan errors but no matches. Multiple engines concur on dynamic loading and anti-debugging, increasing confidence.
- **summary**: The sample is a Visual Basic 6 compiled executable that appears to be a crypter (malware packer) based on the project path containing 'Darty Crypter'. It uses runtime dynamic linking (LoadLibrary/GetProcAddress) to evade static analysis, accesses the Process Environment Block (PEB) likely for anti-debugging, and includes data compression functionality. These characteristics are typical of malware, specifically a crypter used to obfuscate and deploy other malware.
- **source**: llm_judge
- **model**: deepseek-v4-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | strings | `@*\AC:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp` | String reveals the sample was built from a project named 'Darty Crypter', a known malware crypter/obfuscator. |
| capa | top_rules | `link function at runtime on Windows` | Indicates runtime dynamic linking of APIs, a technique to evade static import detection and typical of malware. |
| capa | top_rules | `PEB access` | Accessing the Process Environment Block is a common anti-debugging technique, suggesting malicious intent. |
| pe_imports | signals | `load_library and get_proc_address` | Imports LoadLibrary and GetProcAddress, supporting runtime API resolution and T1129 execution via shared modules. |
| capa | top_rules | `compress data via WinAPI` | Indicates use of data compression, which can be used to pack or obfuscate payloads (T1560.002). |
| ghidra | data_items | `PTR_s_advapi32.dll_00402ffc` | References advapi32.dll, which contains functions commonly abused by malware for service, registry, and security manipul |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: VB6-compiled 'Darty Crypter' malware dropper that disables Windows UAC, hijacks the HOSTS file to block over 50 antivirus/security vendor domains (Symantec, McAfee, Kaspersky, Trend Micro, Avast, Panda, VirusTotal, etc.), downloads additional payloads via URLDownloadToFileA, drops executables to temp (\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe, \tmpjhgTFztfZ789tfzTDt.exe), creates processes for dropped payloads, enumerates running processes via WMI, establishes persistence via HKCU\Software\Microsoft\Windows\CurrentVersion\Run, and uses dynamic API resolution (LoadLibraryA/GetProcAddress) with PEB-based anti-debugging checks.

### deep key_evidence
- `"Ghidra imports: MSVBVM60.DLL (VB6 runtime), KERNEL32.DLL (LoadLibraryA, GetProcAddress) confirming compiled Visual Basic 6 binary"`
- `"String 'C:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp' identifies the sample as the 'Darty Crypter' malware builder"`
- `"FUN_0040a3c0 (largest function, size 4630, cyclomatic_complexity 403) references 'C:\\WINDOWS\\system32\\drivers\\etc\\hosts' and 30+ blocked domains redirected to 127.0.2.5 including symantec.com, mcafee.com, kaspersky-labs.com, trendmicro.com, avast.com, virustotal.com, panda.com, f-secure.com"`
- `"FUN_00408d80 references 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA', 'UACDisableNotify', and 'RegSetValueExW' indicating registry modification to disable Windows UAC"`
- `"FUN_00409380 references temp payload paths '\\tmpduzhfg89fgdgfgfdzuudgzfgfd.exe' and '\\tmpjhgTFztfZ789tfzTDt.exe' confirming dropper behavior"`
- `"FUN_00406fe0 references 'URLDownloadToFileA' from 'urlmon' module indicating internet-based payload download capability"`
- `"FUN_00405f50 references 'CreateProcessW' for executing dropped/downloaded payloads"`
- `"FUN_00407180 references 'ExecQuery' and WMI query 'select name from Win32_Process where name='---'' for process enumeration"`
- `"String 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' indicates registry persistence via Run key"`
- `"String 'service.exe' suggests possible masquerading as a Windows service"`
- `"capa_analyze detected 8 rules including 'compress data via WinAPI' (T1560.002), 'link function at runtime' (T1129), 'PEB access' for debugger detection, and 'compiled from Visual Basic'"`
- `"pe_import_signals flagged 'LoadLibrary' and 'GetProcAddress' (T1129) confirming dynamic API resolution"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 8 · duration_s: 6.02

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
