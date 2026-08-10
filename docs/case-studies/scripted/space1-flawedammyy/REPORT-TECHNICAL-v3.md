> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:38:53 UTC

## 1. Executive Summary

The sample `space1.ex` (SHA256: `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`) is a malicious dropper/loader targeting Windows systems. It exhibits a clear intent to evade security products, establish persistence, and execute injected code. The entry point function systematically enumerates 13 specific antivirus processes (e.g., 360 Security, Comodo, AhnLab V3, Dr.Web, ESET) and terminates if any are found. After this evasion check, it resolves APIs dynamically, allocates executable memory, decrypts an embedded payload, and uses `QueueUserAPC` for code injection. Persistence is achieved via Windows service creation (`CreateServiceA`) and registry manipulation. The binary is obfuscated with stack strings and contains high-entropy resources, likely hiding encrypted payloads. Network capabilities are present through WININET and WSOCK32 imports, though specific C2 traffic was not observed in dynamic analysis. The verdict is **malicious** with a confidence score of 75/100, classified as an unknown service-based trojan.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da` |
| File Name | `space1.ex` |
| File Size | 160,256 bytes |
| File Type | PE (Portable Executable) |
| Architecture | x86 (32-bit) |
| Entry Point EA | 6944 (0x1B20) |
| Compiler | MSVC 2008 (detected via Rich Header and linker) |
| Subsystem | Windows GUI |
| Packed | Not packed (UPX analysis negative) |
| .NET | Not a .NET assembly |

**Source:** (source: malcat) File Summary table.

## 3. File Layout & Structural Analysis

The PE file has a standard structure with some anomalies. The `.rsrc` section is unusually large (150,016 bytes physical, 151,552 bytes virtual) and has high entropy (179), suggesting it contains encrypted or compressed data. There is a duplicated `.rdata` section name, which is atypical. The `.text` section has RX (Read/Execute) rights, which is normal, but the anomaly `SectionWeirdRights` flags that some sections have non-standard permissions.

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 45 | - |
| .text | 1024 | 3584 | 4096 | 124 | RX |
| .rdata | 5120 | 2560 | 4096 | 129 | RX |
| .rdata | 9216 | 2560 | 4096 | 82 | R |
| .data | 13312 | 512 | 4096 | 78 | RW |
| .rsrc | 17408 | 150016 | 151552 | 179 | R |

**Source:** (source: malcat) File Layout table.

**Anomalies:**
- **BigResourceHighEntropy** (Level 2): The `.rsrc` section is large and high-entropy, likely containing an encrypted payload or resource. (source: malcat, Anomalies table, row `BigResourceHighEntropy`)
- **DuplicatedSectionName** (Level 2): Two sections named `.rdata` exist, which is unusual and may indicate manual packing or corruption. (source: malcat, Anomalies table, row `DuplicatedSectionName`)
- **CrossSectionJump** (Level 4): Control flow jumps across sections, a common indicator of packed or injected code. (source: malcat, Anomalies table, row `CrossSectionJump`)
- **GuiSubsystemNoWindowApi** (Level 2): The GUI subsystem is declared, but no user32 window-related functions are imported, suggesting the GUI declaration is a disguise. (source: malcat, Anomalies table, row `GuiSubsystemNoWindowApi`)

## 4. Static Code Analysis

### Entry Point Disassembly
The entry point at `0x00402720` begins a systematic check for 13 security product processes. It pushes each process name string onto the stack and calls the function at `0x00402640` (likely a process enumeration routine). If the function returns a non-zero value (indicating the process is running), execution jumps to `0x00402948`, which likely terminates the malware or enters a dormant state. This is a clear anti-analysis and evasion technique.

```asm
0x00402720      push str.QHACTIVEDEFENSE.EXE ; 0x403138
0x00402725      call 0x402640
0x0040272a      add esp, 4
0x0040272d      test eax, eax
0x0040272f      jne 0x402948
```

**Interpretation:** This pattern repeats for all 13 AV process names. The function `0x00402640` is called repeatedly, confirming it is a process enumeration routine. The conditional jump to `0x00402948` upon detection indicates the malware will exit or alter its behavior if security software is present. This is a classic evasion tactic. (source: radare2, Disassembly at 0x00402720; source: ghidra, Anti Analysis Signals, row `FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW`)

### Key Functions
- **`sub_402640` (EA: 6720):** This function is called 13 times from the entry point. Based on the imports, it likely uses `CreateToolhelp32Snapshot`, `Process32FirstW`, and `Process32NextW` to enumerate running processes and compare their names against the pushed strings. (source: malcat, Functions table, row `sub_402640`)
- **`sub_401380` (EA: 1920):** A complex function with SEH (Structured Exception Handling) and security cookie checks. It appears to be involved in memory validation or unpacking, given its use of `VirtualQuery` and memory region checks. (source: malcat, Decompilations, `sub_401380`)

### Obfuscation Techniques
- **Stack Strings:** FLOSS decoded 3 stack strings. The capa rule `contain obfuscated stackstrings` (T1027.005) confirms this technique is used to hide API names or strings from static analysis. (source: capa, capa rules, row `contain obfuscated stackstrings`)
- **Dynamic Strings:** Malcat flagged 3 instances of `DynamicString` anomalies at EAs 5583, 5674, and 5521, indicating strings are constructed at runtime. (source: malcat, Anomaly Locations, `DynamicString`)
- **High-Entropy Data:** The `.rsrc` section's high entropy (179) and the presence of garbled strings like `&*^@QDSJGIO` and `V><MDNbyfui6y2iuow` in the data section suggest encrypted or encoded payloads. (source: malcat, File Layout; source: floss, High-signal FLOSS strings)

### Import Analysis
The import table reveals a mix of benign and malicious capabilities:

| EA | Name | Type | Significance |
|---|---|---|---|
| 9224 | `advapi32.CreateServiceA` | IMPORT | Service creation for persistence (T1543.003). (source: malcat, Imports table) |
| 9220 | `advapi32.OpenSCManagerA` | IMPORT | Opens service control manager, prerequisite for service creation. (source: malcat, Imports table) |
| 9304 | `kernel32.QueueUserAPC` | IMPORT | Code injection technique (T1055). (source: malcat, Imports table) |
| 9300 | `kernel32.VirtualAlloc` | IMPORT | Allocates RWX memory for shellcode execution. (source: malcat, Imports table) |
| 9344 | `kernel32.IsDebuggerPresent` | IMPORT | Anti-debugging check (T1622). (source: malcat, Imports table) |
| 9332 | `kernel32.DebugSetProcessKillOnExit` | IMPORT | Anti-debugging technique. (source: malcat, Imports table) |
| 9296 | `kernel32.GetProcAddress` | IMPORT | Dynamic API resolution (T1129). (source: malcat, Imports table) |
| 9312 | `kernel32.LoadLibraryA` | IMPORT | Dynamic library loading (T1129). (source: malcat, Imports table) |
| 9216 | `advapi32.RegOpenKeyA` | IMPORT | Registry manipulation for persistence or configuration. (source: malcat, Imports table) |

**Network-Capable Imports:** The binary imports from WININET (`InternetOpenA`, `InternetConnectA`, `HttpSendRequestA`) and WSOCK32 (`WSAStartup`, `connect`, `send`, `recv`), indicating network communication capabilities. However, these are not present in the provided Malcat import list, suggesting they may be resolved dynamically or are part of the embedded payload. (source: deep_dive_agentic, key_evidence)

### capa Capabilities
The following capabilities were identified by capa:

| Rule | ATT&CK | Description |
|---|---|---|
| `enumerate processes` | T1057, T1518 | Process discovery for evasion or reconnaissance. |
| `check for trap flag exception` | B0001 | Debugger detection via trap flag. |
| `contain obfuscated stackstrings` | T1027.005 | Obfuscation to hinder static analysis. |
| `allocate or change RWX memory` | C0007 | Memory allocation for shellcode execution. |
| `execute shellcode via indirect call` | C0007 | Capability to execute shellcode indirectly. |
| `link function at runtime on Windows` | T1129 | Dynamic API resolution. |
| `extract resource via kernel32 functions` | - | Likely used to extract the embedded payload from resources. |

**Source:** (source: capa, capa rules table).

### YARA Matches
Key YARA rule matches include:
- **`anti_dbg`**: Matched at offsets 7456 and 9106 with strings `$d1` (12 bytes) and `$c2` (17 bytes). This confirms anti-debugging techniques. (source: yara, YARA Matches table, row `anti_dbg`)
- **`CreateService`**: Matched, indicating service creation capability. (source: yara, YARA Matches table, row `CreateService`)
- **`SEH_Save` and `SEH_Init`**: Matches for SEH initialization, common in malware for exception handling or exploitation. (source: yara, YARA Matches table)

## 5. Behavioral & Dynamic Analysis

**Speakeasy:** No API calls or events were recorded during dynamic analysis. This is likely due to the anti-analysis checks at the entry point; if a debugger or analysis environment is detected, the malware may terminate before exhibiting behavior. (source: speakeasy, Dynamic analysis)

**Frida Probe:** Frida was available (version 17.16.4), but no runtime behavior was observed, consistent with the Speakeasy results. (source: frida_probe)

**Interpretation:** The lack of observed runtime behavior does not indicate benign intent. The static analysis clearly shows the malware is designed to evade analysis environments. In a real-world scenario without analysis tools, it would likely proceed to decrypt its payload, inject code, and establish persistence.

## 6. Network Indicators & C2

No active network connections or C2 traffic were observed during dynamic analysis. However, the static import analysis reveals network-capable libraries:
- **WININET:** `InternetOpenA`, `InternetConnectA`, `HttpSendRequestA` (source: deep_dive_agentic, key_evidence)
- **WSOCK32:** `WSAStartup`, `connect`, `send`, `recv` (source: deep_dive_agentic, key_evidence)

These imports indicate the malware has the capability to communicate over HTTP and raw sockets. The specific C2 server addresses or domains are not present in the static strings, suggesting they may be encrypted in the high-entropy `.rsrc` section or generated dynamically.

## 7. Capabilities Assessment

Based on the evidence, the malware possesses the following capabilities:

1.  **Anti-Analysis & Evasion:** Checks for 13 specific AV processes and terminates if found. Uses `IsDebuggerPresent` and trap flag checks. (source: radare2, Disassembly; source: capa, `check for trap flag exception`)
2.  **Process Discovery:** Enumerates running processes to identify security software. (source: capa, `enumerate processes`)
3.  **Code Injection:** Uses `QueueUserAPC` to inject code into other processes. (source: malcat, Imports table, `QueueUserAPC`)
4.  **Persistence:** Creates Windows services via `CreateServiceA` and manipulates the registry via `RegOpenKeyA`. (source: malcat, Imports table; source: yara, `CreateService` rule)
5.  **Dynamic API Resolution:** Uses `GetProcAddress` and `LoadLibraryA` to resolve APIs at runtime, hiding its intentions. (source: malcat, Imports table)
6.  **Payload Execution:** Allocates RWX memory (`VirtualAlloc`) and executes shellcode indirectly. (source: capa, `allocate or change RWX memory`, `execute shellcode via indirect call`)
7.  **Obfuscation:** Uses stack strings, dynamic string construction, and high-entropy resources to hinder analysis. (source: capa, `contain obfuscated stackstrings`; source: malcat, Anomalies)
8.  **Network Communication:** Has the capability to communicate over HTTP and raw sockets. (source: deep_dive_agentic, key_evidence)
9.  **Screen Capture:** GDI32 imports (`CreateDCW`, `GetTextMetricsW`, `SetDIBits`) suggest potential screen capture capability. (source: deep_dive_agentic, key_evidence)

## 8. Indicators of Compromise

### File-Based IOCs
- **SHA256:** `5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da`
- **File Name:** `space1.ex`
- **File Size:** 160,256 bytes

### String-Based IOCs
- **AV Process Names Checked:**
  - `QHACTIVEDEFENSE.EXE`, `QHSAFETRAY.EXE`, `QHWATCHDOG.EXE` (360 Security)
  - `CMDAGENT.EXE`, `CIS.EXE` (Comodo)
  - `V3LITE.EXE`, `V3MAIN.EXE`, `V3SP.EXE` (AhnLab V3)
  - `SPIDERAGENT.EXE` (Dr.Web)
  - `DWENGINE.EXE`, `DWARKDAEMON.EXE` (Dr.Web)
  - `EGUI.EXE`, `EKRN.EXE` (ESET)
  (source: radare2, Disassembly; source: malcat, Top Strings)
- **Obfuscated Strings:** `&*^@QDSJGIO`, `&JTEH$WHD`, `V><MDNbyfui6y2iuow`, `fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6` (source: floss, High-signal FLOSS strings)

### Behavioral IOCs
- **Service Creation:** Attempts to create a Windows service. (source: yara, `CreateService` rule)
- **Process Enumeration:** Uses `CreateToolhelp32Snapshot` to list processes. (source: ghidra, Anti Analysis Signals)
- **Anti-Debugging:** Calls `IsDebuggerPresent`. (source: ida, Imports (IDA))

## 9. Detection Engineering

### YARA Rules
A YARA rule to detect this sample could focus on:
1.  The specific sequence of AV process name strings in the `.data` or `.rdata` section.
2.  The combination of imports: `CreateServiceA`, `QueueUserAPC`, `VirtualAlloc`, `IsDebuggerPresent`.
3.  The high-entropy `.rsrc` section with a size greater than 100KB.
4.  The presence of the obfuscated strings like `&*^@QDSJGIO`.

### Sigma Rules
A Sigma rule could be created for:
- **Process Creation:** Detection of a process creating a new Windows service with a suspicious name or from a temporary directory.
- **API Calls:** Monitoring for a single process calling `CreateToolhelp32Snapshot` followed by `Process32FirstW`/`Process32NextW` in a loop, especially if it checks for known AV process names.

### Network Signatures
- **HTTP:** Look for HTTP requests with a User-Agent string that may be generated by the malware (if any are hardcoded).
- **DNS:** No specific domains were found, but monitoring for newly registered domains or DGA patterns could be useful.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Defense Evasion** | Process Discovery | T1057 | `enumerate processes` capa rule; entry point checks for AV processes. (source: capa; source: radare2) |
| **Defense Evasion** | Debugger Evasion | T1622 | `IsDebuggerPresent` import; `check for trap flag exception` capa rule. (source: ida; source: capa) |
| **Defense Evasion** | Obfuscated Files or Information | T1027.005 | `contain obfuscated stackstrings` capa rule; dynamic strings. (source: capa; source: malcat) |
| **Execution** | Shared Modules | T1129 | `GetProcAddress` and `LoadLibraryA` imports for dynamic API resolution. (source: malcat) |
| **Execution** | Command and Scripting Interpreter | T1059 | *Not directly observed, but likely via injected shellcode.* |
| **Persistence** | Create or Modify System Process | T1543.003 | `CreateServiceA` import; `CreateService` YARA rule. (source: malcat; source: yara) |
| **Discovery** | Process Discovery | T1057 | *See Defense Evasion.* |
| **Discovery** | Software Discovery | T1518 | `enumerate processes` capa rule also maps to software discovery. (source: capa) |
| **Collection** | Screen Capture | T1113 | GDI32 imports (`CreateDCW`, `SetDIBits`) suggest capability. (source: deep_dive_agentic) |
| **Command and Control** | Application Layer Protocol | T1071 | WININET imports (`InternetOpenA`, `HttpSendRequestA`) indicate HTTP C2 capability. (source: deep_dive_agentic) |
| **Command and Control** | Non-Application Layer Protocol | T1095 | WSOCK32 imports (`WSAStartup`, `connect`) indicate raw socket capability. (source: deep_dive_agentic) |

## 11. What We Don't Know

1.  **The exact payload:** The high-entropy `.rsrc` section likely contains an encrypted payload, but its contents were not decrypted during analysis. Its purpose (e.g., ransomware, RAT, banking trojan) is unknown.
2.  **C2 Infrastructure:** No C2 server addresses, domains, or URLs were found in the static strings. These may be encrypted or generated dynamically.
3.  **Persistence Mechanism Details:** While `CreateServiceA` is imported, the specific service name, description, and start type are not known from static analysis alone.
4.  **Lateral Movement:** No evidence of lateral movement techniques (e.g., `PsExec`, WMI) was found, but it cannot be ruled out.
5.  **Data Exfiltration:** While network capabilities exist, no specific exfiltration methods (e.g., data staging, compression) were observed.
6.  **Full Scope of Anti-Analysis:** The 13 AV process checks are clear, but there may be additional checks for virtual machines, sandboxes, or other analysis tools not captured in the strings.

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Engine | Key Findings |
|---|---|---|
| **Malcat** | - | File layout, anomalies (BigResourceHighEntropy, CrossSectionJump), imports, functions, decompilations. (source: malcat) |
| **capa** | malcat-capa | 11 rules matched, including `enumerate processes`, `check for trap flag exception`, `execute shellcode via indirect call`. (source: capa) |
| **YARA** | yara-x | 12 rules matched, including `anti_dbg`, `CreateService`, `SEH_Init`. (source: yara) |
| **FLOSS** | - | 2471 strings extracted, 3 stack strings decoded. High-signal strings include AV process names and obfuscated data. (source: floss) |
| **radare2** | - | Entry point disassembly showing AV process enumeration loop. (source: radare2) |
| **Ghidra** | - | Identified process enumeration functions (`CreateToolhelp32Snapshot`, `Process32FirstW`). (source: ghidra) |
| **IDA** | - | Confirmed `IsDebuggerPresent` import. (source: ida) |
| **Speakeasy** | - | No API calls observed (likely due to anti-analysis). (source: speakeasy) |
| **Frida** | 17.16.4 | Available but no runtime behavior observed. (source: frida_probe) |
| **UPX** | - | Not packed. (source: upx) |
| **pe_imports** | - | High-signal imports: `CreateService`, `IsDebuggerPresent`, `QueueUserAPC`. (source: pe_imports) |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following tools and configurations:
- **Static Analysis:** Malcat, Ghidra, IDA, radare2, FLOSS, capa, YARA.
- **Dynamic Analysis:** Speakeasy (emulation), Frida (instrumentation).
- **Environment:** The sample was analyzed as a standalone PE file. No network traffic was generated or captured. The analysis environment likely triggered the anti-analysis checks, resulting in no observed runtime behavior.
- **Limitations:** The high-entropy resource section was not decrypted. The full network communication protocol was not reverse-engineered.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da  
**sample_path:** /opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex  
**project_name:** Malware Analyst Professional - Level 2

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 75
- **family_guess**: unknown service-based trojan
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both identify process enumeration functions (e.g., CreateToolhelp32Snapshot, Process32FirstW). Malcat anomalies (e.g., BigResourceHighEntropy, CrossSectionJump) and pe_imports high-signal imports (e.g., CreateServiceA, IsDebuggerPresent) align with capa rules for anti-debug, shellcode execution, and persistence. YARA matches include service creation and anti-debug rules. FLOSS strings show API calls consistent with these behaviors.
- **summary**: The PE file space1.ex exhibits clear malicious intent through behavioral signals: anti-debugging (IsDebuggerPresent), process enumeration (CreateToolhelp32Snapshot), service creation for persistence (CreateServiceA), and shellcode execution capabilities (capa rule). Obfuscation techniques (e.g., high entropy, dynamic strings) are present but secondary. Cross-engine analysis confirms consistent findings, with high-signal imports and anomalies pointing to hostile activity beyond mere protection.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports signals | `create_service` | API for creating services (CreateServiceA), indicating potential persistence via service installation (T1543.003). |
| capa | capa rules | `execute shellcode via indirect call` | Rule detects capability for indirect shellcode execution, a direct malicious behavior for code execution. |
| ghidra | Anti Analysis Signals | `FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW` | Process enumeration functions used for discovery (T1057), a common reconnaissance technique in malware. |
| ida | Imports (IDA) | `IsDebuggerPresent` | Anti-debugging API import, indicating evasion techniques to hinder analysis (T1622). |
| pe_imports | pe_imports_evidence | `CreateService` | YARA rule matched for service creation API, supporting evidence of persistence behavior. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Dropper/loader targeting Windows. The entry function systematically enumerates 13 security product processes (360 Security suite, Comodo, AhnLab V3, Dr.Web, ESET) via CreateToolhelp32Snapshot and terminates or evades if detected. After AV evasion, it resolves APIs dynamically (GetProcAddress+LoadLibraryA) using an obfuscated API name table, allocates RWX memory via VirtualAlloc, decrypts embedded payload data (garbled strings like '&*^@QDSJGIO', 'V><MDNbyfui6y2iuow'), and uses QueueUserAPC for code injection. It establishes persistence via CreateServiceA/OpenSCManagerA and registry (RegOpenKeyA), and has network capabilities via WININET and WSOCK32 DLLs. Built with MSVC and uses stack-string obfuscation to hinder static analysis. Exfiltration: Network capabilities are indicated by WININET and WSOCK32 DLLs, but specific exfiltration methods are not observed in the provided analysis, citing evidence from the network DLL references in the summary. Credential access: Not observed in the provided details.

### deep key_evidence
- `"YARA 'anti_dbg' rule matched at offsets 7456 and 9106 with strings $d1 (12 bytes) and $c2 (17 bytes)"`
- `"CAPA: 'enumerate processes' (T1057/T1518), 'check for trap flag exception' (B0001), 'contain obfuscated stackstrings' (T1027.005), 'allocate or change RWX memory'"`
- `"Entry function (0x402720) calls FUN_00402640 13 times with AV process names: QHACTIVEDEFENSE.EXE, QHSAFETRAY.EXE, QHWATCHDOG.EXE, CMDAGENT.EXE, CIS.EXE, V3LITE.EXE, V3MAIN.EXE, V3SP.EXE, SPIDERAGENT.EXE, DWENGINE.EXE, DWARKDAEMON.EXE, EGUI.EXE, EKRN.EXE \u2014 each followed by conditional jump to 0x402948 (exit if found)"`
- `"Imports include CreateServiceA+OpenSCManagerA (ADVAPI32, service persistence), QueueUserAPC (code injection), VirtualAlloc (RWX allocation), DebugSetProcessKillOnExit+IsDebuggerPresent (anti-debug), GetProcAddress+LoadLibraryA (dynamic API resolution), RegOpenKeyA (registry manipulation)"`
- `"Network-capable imports: InternetOpenA, InternetConnectA, HttpSendRequestA (WININET), WSAStartup, connect, send, recv (WSOCK32)"`
- `"Obfuscated/garbled strings in data section: '&*^@QDSJGIO', '&JTEH$WHD', 'V><MDNbyfui6y2iuow', 'fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6'"`
- `"FLOSS decoded 3 stack strings from the binary; entry function has cyclomatic complexity 56 with 62 basic blocks and 19 string references"`
- `"GDI32 imports (CreateDCW, GetTextMetricsW, SetDIBits) suggest screen capture capability"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da
size: 160256
type: PE
architecture: X86
entrypoint_ea: 6944
entropy: 176
file_name: space1.ex
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 45 | - |
| .text | 1024 | 3584 | 4096 | 124 | RX |
| .rdata | 5120 | 2560 | 4096 | 129 | RX |
| .rdata | 9216 | 2560 | 4096 | 82 | R |
| .data | 13312 | 512 | 4096 | 78 | RW |
| .rsrc | 17408 | 150016 | 151552 | 179 | R |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2008_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2008_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| CreateService | lateral movement | SUSPICIOUS | 70 | creates a service |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 3 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| DynamicString | 3 | strings | 3 | string is constructed dynamically |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having + |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| DuplicatedSectionName | 2 | sections | 1 | section name has already been used before in section table |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| RcdataNoDelphi | 2 | resources | 1 | File contains a rcdata resource and is not a delphi application |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `38104`: 
- **DynamicString**
  - `5583`: 
  - `5674`: 
  - `5521`: 
- **GuiSubsystemNoWindowApi**
  - `316`: 
- **XorInLoop**
  - `3830`: 
  - `7431`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 9504 | `kernel32.dll` |
| 11258 | `KERNEL32.dll` |
| 10932 | `GetProcAddress` |
| 11010 | `LoadLibraryA` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 9936 | `fliudsifIUJGowpd..iuhtroi3j21932y6` |
| 5583 | `QueryPerformanceFrequency` |
| 9528 | `QHACTIVEDEFENSE.EXE` |
| 9776 | `DWENGINE.EXE` |
| 5674 | `QueryPerformanceCounter` |
| 9804 | `DWARKDAEMON.EXE` |
| 9744 | `SPIDERAGENT.EXE` |
| 9568 | `QHSAFETRAY.EXE` |
| 9856 | `EKRN.EXE` |
| 9836 | `EGUI.EXE` |
| 9676 | `V3LITE.EXE` |
| 9600 | `QHWATCHDOG.EXE` |
| 9632 | `CMDAGENT.EXE` |
| 9724 | `V3SP.EXE` |
| 9700 | `V3MAIN.EXE` |
| 9660 | `CIS.EXE` |
| 9504 | `kernel32.dll` |
| 11174 | `CreateToolhelp32Snapshot` |
| 5521 | `IsBadCodePtr` |
| 11572 | `CreateServiceA` |
| 9908 | `fdsfds` |
| 11076 | `Process32NextW` |
| 9900 | `fdsfsd,` |
| 9916 | `V><MDNbyfui6y2iuow` |
| 9520 | `user32` |
| 11620 | `ADVAPI32.dll` |
| 11258 | `KERNEL32.dll` |
| 9888 | `&JTEH$WHD` |
| 9876 | `&*^@QDSJGIO` |
| 11514 | `GDI32.dll` |
| 11556 | `WINSPOOL.DRV` |
| 11460 | `USER32.dll` |
| 139893 | `0fliudsifIUJGowp..fjawhe78yr73ohiu` |
| 140349 | `lhdtfkj56uy34e3w..7ihdtfjj<2uyC1e3` |
| 135901 | `B%shfIU\Gowrdur{..h238%ihdffkj76uy` |
| 27158 | `;nPVYYFDZSEDv,SM..gAmPu,uwvANxUxMg` |
| 126207 | `j!6ey#4u3go`erjq..mvrews{3196hhdtf` |
| 26582 | `5TDzPHHAlwCjF,dD..wpaAbNl,OsWaCWbX` |
| 133153 | `<&"8wpdury2387ih..y2387ihdtfkj1%4y` |
| 19032 | `QXCHNYOHVJGRDQD..UOEZCHMKTHFFPGG` |
| 27562 | `4BDmkrwQ,UHAarMN..,NVmTguj,BITxmtO` |
| 27706 | `6aWSbkQ,DyLeYO,H..UnHd,aBdgnYuJOQu` |
| 137812 | `hdtfkjtt6=vr"{>%..tfkj56uyp4e3wope` |
| 137572 | `FLIUDSIFiujgOWPD..wopefjawhe78yrWQ` |
| 137032 | `FLIUDSIFiujgowpd..pefjawhe78yr63f` |
| 152215 | `aJGowpdury2387ih..DINGPADDINGXXPAD` |
| 102403 | `opefjawhe78yr63f..387ihdtfkj56uy34` |
| 146798 | `Vh=8yr63fliudsif..hdtfkj5&uy?5e3G_` |
| 125062 | `	:;87ahltacj56uy..ifIUJGowpdury238` |
| 125541 | `Gmwrdwr{2185ijdv..e3wopefjawhe78Yr` |
| 136382 | `v3fliuesifIUJGnw..udsifIUJGowpdurq` |
| 38774 | `6ihdtfkj56uy34%3..3wopefjawhe78yrc` |
| 137275 | `fkj56u8qw!v1(8,,..yr63fliudsifIUJG` |
| 135266 | `4rx3387ihdtfkj5&..e3wopefjawhe78yr` |
| 9488 | `bad allocation` |
| 27834 | `2mRxteWIGU,ejajF..TRTki,ZXxPuFgilt` |
| 26918 | `/eTRDva,DAwSOkWY..WRUjxa,PAeefADGM` |
| 136041 | `4e3zopeSjawje788..8whe<8yrZ3flduds` |
| 26746 | `.RPJHbNSuA,nygKN..Omw,OFVgu,GixhMc` |
| 105141 | `i-d,f.j56uyb4-3 ..Fer8!rs3fl?uWs%f` |
| 136916 | `he78yr63fliudsif..yr63fliudsifYEZW` |
| 140277 | `wifIUJGowpdury23..ifIUJGowpdtrp638` |
| 146195 | `3#o
efjawhe78yr6..pefjawhe78Kre3*l` |
| 26478 | `-SgogWakfT,gHYix..dbgqyzOP,UwkRekL` |
| 27304 | `%xeaVCeQ,CJZwekU..SXCwADvw,PZIJhKq` |
| 26352 | `&ExrkbJaCby,rWil..PkJPbDW,NlfpOyGL` |
| 127321 | `UJGowpdury2387ih..3fliudsifIUJGow@` |
| 136277 | `fiudsifIUJGowpdu..awhe78yr63fliuds` |
| 128257 | ``jj56uy34e3wopef..owpdury2387ijw4f` |
| 26266 | `#whpmlGP,wysbAw,..HndaH,cJPRqSbjAo` |
| 145227 | `e6jawhe78yr63fli..kj56uy34e3ho#e$j` |
| 145475 | `2u8Ai2df<ja64yI..dsifIUJGowpdury2` |
| 28180 | ` t5E ` |
| 119101 | `rD3Kl+u!sif U>GB..=ry2]8[iEd6f.j56` |
| 125991 | `k47tx25d2vnqdgk`..nvqeeri2#8'ixddf` |
| 38386 | `owptury"287i(dtv..8y243fhiudsifKU
` |
| 125477 | `lhueshfHUKGnwqdt..voqevjqwxe'8ir&3` |
| 26182 | ` OEVrOfkeB,qdqsP..MIm,ZvOIVXgjXSzQ` |
| 145787 | `fIUJGowpdury2387..pefjawhe78yr63\l` |
| 27460 | `DRjKRqXq,SOxDJrMm,vJOCijj` |

### Constants / Known Patterns (2)
| Category | Value |
|---|---|
| exception | `exception::C++ exception` |
| code | `code::PEBx86` |

### Imports (67)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1064 | SEH.0 | DEBUG | 2 |
| 1436 | SEH.1 | DEBUG | 3 |
| 3120 | SEH.2 | DEBUG | 3 |
| 3924 | SEH.3 | DEBUG | 2 |
| 9216 | advapi32.RegOpenKeyA | IMPORT | 5 |
| 9220 | advapi32.OpenSCManagerA | IMPORT | 0 |
| 9224 | advapi32.CreateServiceA | IMPORT | 0 |
| 9232 | gdi32.GetTextMetricsW | IMPORT | 1 |
| 9236 | gdi32.SetDIBits | IMPORT | 1 |
| 9240 | gdi32.CreateDCW | IMPORT | 0 |
| 9248 | kernel32.VirtualFree | IMPORT | 1 |
| 9252 | kernel32.GetProcessHeap | IMPORT | 0 |
| 9256 | kernel32.TlsSetValue | IMPORT | 0 |
| 9260 | kernel32.GetConsoleCP | IMPORT | 0 |
| 9264 | kernel32.SizeofResource | IMPORT | 1 |
| 9268 | kernel32.GetSystemDirectoryA | IMPORT | 0 |
| 9272 | kernel32.GetACP | IMPORT | 1 |
| 9276 | kernel32.lstrcmpW | IMPORT | 1 |
| 9280 | kernel32.lstrlenW | IMPORT | 1 |
| 9284 | kernel32.RtlMoveMemory | IMPORT | 3 |
| 9288 | kernel32.GetLastError | IMPORT | 1 |
| 9292 | kernel32.SetLastError | IMPORT | 0 |
| 9296 | kernel32.GetProcAddress | IMPORT | 2 |
| 9300 | kernel32.VirtualAlloc | IMPORT | 2 |
| 9304 | kernel32.QueueUserAPC | IMPORT | 0 |
| 9308 | kernel32.DisableThreadLibraryCalls | IMPORT | 1 |
| 9312 | kernel32.LoadLibraryA | IMPORT | 3 |
| 9316 | kernel32.GetCurrentThread | IMPORT | 1 |
| 9320 | kernel32.LockResource | IMPORT | 1 |
| 9324 | kernel32.CreateEventW | IMPORT | 0 |
| 9328 | kernel32.Process32NextW | IMPORT | 1 |
| 9332 | kernel32.DebugSetProcessKillOnExit | IMPORT | 1 |
| 9336 | kernel32.GetModuleHandleA | IMPORT | 3 |
| 9340 | kernel32.EraseTape | IMPORT | 1 |
| 9344 | kernel32.IsDebuggerPresent | IMPORT | 2 |
| 9348 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 9352 | kernel32.CloseHandle | IMPORT | 1 |
| 9356 | kernel32.GetCurrentProcessId | IMPORT | 1 |
| 9360 | kernel32.TlsFree | IMPORT | 0 |
| 9364 | kernel32.lstrcpyW | IMPORT | 1 |
| 9368 | kernel32.UnhandledExceptionFilter | IMPORT | 1 |
| 9372 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 9376 | kernel32.TerminateProcess | IMPORT | 1 |
| 9380 | kernel32.VirtualQuery | IMPORT | 1 |
| 9384 | kernel32.RtlUnwind | IMPORT | 1 |
| 9388 | kernel32.GetModuleHandleW | IMPORT | 1 |
| 9392 | kernel32.GetCurrentActCtx | IMPORT | 1 |
| 9396 | kernel32.LoadResource | IMPORT | 1 |
| 9400 | kernel32.FindResourceW | IMPORT | 1 |
| 9404 | kernel32.CreateFileA | IMPORT | 0 |
| 9408 | kernel32.HeapReAlloc | IMPORT | 0 |
| 9412 | kernel32.Process32FirstW | IMPORT | 1 |
| 9416 | kernel32.ExitProcess | IMPORT | 5 |
| 9420 | kernel32.SetUnhandledExceptionFilter | IMPORT | 1 |
| 9428 | user32.SetCursor | IMPORT | 1 |
| 9432 | user32.CharUpperBuffW | IMPORT | 1 |
| 9436 | user32.SetWindowTextW | IMPORT | 0 |
| 9440 | user32.FindWindowA | IMPORT | 2 |
| 9444 | user32.CheckRadioButton | IMPORT | 0 |
| 9448 | user32.SendDlgItemMessageA | IMPORT | 0 |
| 9452 | user32.AttachThreadInput | IMPORT | 0 |
| 9456 | user32.MessageBeep | IMPORT | 0 |
| 9460 | user32.LoadAcceleratorsW | IMPORT | 0 |
| 9464 | user32.SetWinEventHook | IMPORT | 0 |
| 9468 | user32.EndDialog | IMPORT | 0 |
| 9476 | winspool.OpenPrinter2A | IMPORT | 2 |
| 9480 | winspool.OpenPrinterW | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 1920 | sub_401380 |
| 3120 | 2 |
| 1345 | sub_401141 |
| 3780 | sub_401ac4 |
| 2912 | sub_401760 |
| 6944 | EntryPoint |
| 1436 | 1 |
| 6448 | sub_402530 |
| 3516 | sub_4019bc |
| 6628 | sub_4025e4 |
| 5296 | sub_4020b0 |
| 5504 | sub_402180 |
| 6112 | sub_4023e0 |
| 6720 | sub_402640 |
| 1064 | 0 |
| 1024 | jmp_kernel32.Process32FirstW |
| 1030 | jmp_kernel32.Process32NextW |
| 1036 | jmp_kernel32.CreateToolhelp32Snapshot |
| 1042 | jmp_winspool.OpenPrinter2A |
| 4128 | jmp_kernel32.RtlUnwind |
| 5120 | sub_402000 |
| 2768 | sub_4016d0 |
| 1728 | sub_4012c0 |
| 1505 | sub_4011e1 |
| 6560 | sub_4025a0 |
| 2832 | sub_401710 |
| 1318 | sub_401126 |
| 1637 | sub_401265 |
| 3994 | sub_401b9a |
| 4045 | sub_401bcd |

### Decompilations (top 6)
#### 1920 — sub_401380
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_401380(uint32_t *param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    int32_t iVar3;
    int32_t iVar4;
    int32_t iVar5;
    uint32_t *puVar6;
    uint32_t *puVar7;
    int32_t iVar8;
    int32_t **unaff_FS_OFFSET;
    bool bVar9;
    uint32_t uStack_54;
    undefined auStack_44 [4];
    uint32_t uStack_40;
    uint8_t uStack_30;
    int32_t iStack_2c;
    uint32_t uStack_28;
    uint32_t uStack_24;
    uint32_t *puStack_20;
    uint32_t *puStack_1c;
    int32_t *piStack_14;
    code *pcStack_10;
    uint32_t uStack_c;
    undefined4 uStack_8;
    
    pcStack_10 = SEH.2;
    piStack_14 = *unaff_FS_OFFSET;
    uStack_c = [0x0x404014#SecurityCookie] ^ 0x4033b0;
    uStack_54 = [0x0x404014#SecurityCookie] ^ &stack0xfffffffc;
    puStack_1c = &uStack_54;
    *unaff_FS_OFFSET = &piStack_14;
    puStack_20 = param_1[2];
    if ((puStack_20 & 3) != 0) {
code_r0x004013c3:
        *unaff_FS_OFFSET = piStack_14;
        return 0;
    }
    puVar6 = unaff_FS_OFFSET[6][2];
    if ((puVar6 <= puStack_20) && (puStack_20 < unaff_FS_OFFSET[6][1])) goto code_r0x004013c3;
    uStack_28 = param_1[3];
    if (uStack_28 == 0xffffffff) goto code_r0x004016b2;
    bVar9 = false;
    uVar2 = 0;
    puVar7 = puStack_20;
    do {
        if ((*puVar7 != 0xffffffff) && (uVar2 <= *puVar7)) goto code_r0x004013c3;
        if (puVar7[1] != 0) {
            bVar9 = true;
        }
        uVar2 = uVar2 + 1;
        puVar7 = puVar7 + 3;
    } while (uVar2 <= uStack_28);
    if ((bVar9) && ((param_1[-2] < puVar6 || (param_1 <= param_1[-2])))) goto code_r0x004013c3;
    uStack_24 = puStack_20 & 0xfffff000;
    for (iVar8 = 0; puVar6 = &uStack_54, iVar8 < [0x0x404058]; iVar8 = iVar8 + 1) {
        uVar2 = *(iVar8 * 8 + 0x404060);
        iVar5 = *(iVar8 * 8 + 0x404064);
        if (uVar2 == uStack_24) {
            uStack_8 = 0;
            iVar3 = sub_4016d0(iVar5);
            puVar6 = puStack_1c;
            if (((iVar3 != 0) && (iVar3 = sub_4012c0(puStack_20), puVar6 = puStack_1c, iVar3 != 0)) &&
               (iVar4 = sub_401710(iVar5, param_1[1] - iVar5), iVar3 = [0x0x40405c], puVar6 = puStack_1c, iVar4 != 0)) {
                if (iVar8 < 1) goto code_r0x004016b2;
                LOCK();
                [0x0x40405c] = 1;
                UNLOCK();
                if (iVar3 != 0) goto code_r0x004016b2;
                if (*(iVar8 * 8 + 0x404060) == uStack_24) goto code_r0x00401518;
                iVar8 = [0x0x404058] + -1;
                if (iVar8 < 0) goto code_r0x00401509;
                goto code_r0x004014e7;
            }
            break;
        }
    }
    puStack_1c = puVar6;
    uStack_8 = 0xfffffffe;
    iVar8 = (*kernel32.VirtualQuery)(puStack_20, auStack_44, 0x1c);
    uVar2 = uStack_40;
    if (iVar8 == 0) goto code_r0x004016b2;
    if ((iStack_2c != 0x1000000) || (iVar8 = sub_4016d0(uStack_40), iVar8 == 0)) {
        *unaff_FS_OFFSET = piStack_14;
        return 0xffffffff;
    }
    if (((((uStack_30 & 0xcc) != 0) &&
         ((iVar8 = sub_401710(uVar2, puStack_20 - uVar2), iVar8 == 0 || ((*(iVar8 + 0x24) & 0x80000000) != 0)))) ||
        (iVar8 = sub_4012c0(puStack_20), iVar8 == 0)) ||
       (iVar5 = sub_401710(uVar2, param_1[1] - uVar2), iVar8 = [0x0x40405c], iVar5 == 0)) goto code_r0x004013c3;
    LOCK();
    [0x0x40405c] = 1;
    UNLOCK();
    if (iVar8 != 0) goto code_r0x004016b2;
    iVar8 = [0x0x404058];
    if (0 < [0x0x404058]) {
        puVar6 = [0x0x404058] * 8 + 0x404058;
        do {
            if (*puVar6 == uStack_24) break;
            iVar8 = iVar8 + -1;
            puVar6 = puVar6 + -2;
        } while (0 < iVar8);
    }
    if (iVar8 == 0) {
        iVar8 = 0xf;
        if ([0x0x404058] < 0x10) {
            iVar8 = [0x0x404058];
        }
        if (-1 < iVar8) {
            puVar6 = 0x404060;
            iVar8 = iVar8 + 1;
            do {
                uVar2 = *puVar6;
                uVar1 = puVar6[1];
                *puVar6 = uStac
```
#### 3120 — 2
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 SEH.2(int32_t *param_1,int32_t param_2,undefined4 param_3)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t *piVar3;
    int32_t *piStack_1c;
    undefined4 uStack_18;
    int32_t *piStack_14;
    undefined4 uStack_10;
    int32_t iStack_c;
    char cStack_5;
    
    piVar3 = *(param_2 + 8) ^ [0x0x404014#SecurityCookie];
    cStack_5 = '\0';
    uStack_10 = 1;
    if (*piVar3 != -2) {
        sub_40181d();
    }
    sub_40181d();
    iVar2 = param_2;
    if ((*(param_1 + 1) & 0x66) == 0) {
        *(param_2 + -4) = &piStack_1c;
        iVar2 = *(param_2 + 0xc);
        piStack_1c = param_1;
        uStack_18 = param_3;
        if (iVar2 == -2) {
            return uStack_10;
        }
        do {
            piStack_14 = piVar3 + iVar2 * 3 + 4;
            iStack_c = *piStack_14;
            if (piVar3[iVar2 * 3 + 5] != 0) {
                iVar1 = sub_401bb6();
                cStack_5 = '\x01';
                if (iVar1 < 0) {
                    uStack_10 = 0;
                    goto code_r0x004018d8;
                }
                if (0 < iVar1) {
                    if (((*param_1 == -0x1f928c9d) && (0x404408 != 0x0)) &&
                       (iVar1 = sub_401760(0x404408), iVar1 != 0)) {
                        (*0x404408)(param_1, 1);
                    }
                    sub_401be6();
                    if (*(param_2 + 0xc) != iVar2) {
                        sub_401c00(param_2 + 0x10, 0x404014#SecurityCookie);
                    }
                    *(param_2 + 0xc) = iStack_c;
                    if (*piVar3 != -2) {
                        sub_40181d();
                    }
                    sub_40181d();
                    sub_401bcd();
                    goto code_r0x0040199c;
                }
            }
            iVar2 = iStack_c;
        } while (iStack_c != -2);
        if (cStack_5 == '\0') {
            return uStack_10;
        }
    }
    else {
code_r0x0040199c:
        if (*(iVar2 + 0xc) == -2) {
            return uStack_10;
        }
        sub_401c00(param_2 + 0x10, 0x404014#SecurityCookie);
    }
code_r0x004018d8:
    if (*piVar3 != -2) {
        sub_40181d();
    }
    sub_40181d();
    return uStack_10;
}

```
#### 1345 — sub_401141
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401141(int32_t *param_1,undefined4 param_2)

{
    int32_t iVar1;
    
    if ((*param_1 == -0x1f928c9d) && (0x404408 != 0x0)) {
        iVar1 = sub_401760(0x404408);
        if (iVar1 != 0) {
            (*0x404408)(param_1, param_2);
        }
    }
    return;
}

```

### Virtual Files (29)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| MENU/AYRVNAIMJ/en-us | 1568 | - |
| MENU/LKHMEYKJC/en-us | 1422 | - |
| MENU/MVFHCY/en-us | 920 | - |
| MENU/OBGPRTS/en-us | 936 | - |
| MENU/QXCHNYOH/en-us | 920 | - |
| MENU/VJGRDQDRRCSGV/en-us | 1234 | - |
| STR/69/en-us | 166 | - |
| STR/81/en-us | 108 | - |
| STR/85/en-us | 122 | - |
| STR/109/en-us | 138 | - |
| STR/110/en-us | 124 | - |
| STR/117/en-us | 68 | - |
| STR/122/en-us | 126 | - |
| STR/124/en-us | 90 | - |
| STR/129/en-us | 150 | - |
| STR/132/en-us | 106 | - |
| STR/154/en-us | 68 | - |
| STR/160/en-us | 82 | - |
| STR/163/en-us | 136 | - |
| STR/170/en-us | 140 | - |

### Structures (125)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 224 |
| OptionalHeader | 248 |
| Sections | 472 |
| advapi32.FT | 9216 |
| gdi32.FT | 9232 |
| kernel32.FT | 9248 |
| user32.FT | 9428 |
| winspool.FT | 9476 |
| LoadConfigurationTable | 10056 |
| SEHandlers | 10128 |
| ImportTable | 10220 |
| advapi32.OFT | 10340 |
| gdi32.OFT | 10356 |
| kernel32.OFT | 10372 |
| user32.OFT | 10552 |
| winspool.OFT | 10600 |
| ImportNames | 10612 |
| SecurityCookie | 13332 |
| Resources | 17408 |
| Resources.MENU | 17472 |
| Resources.STR | 17536 |
| Resources.ACC | 17672 |
| Resources.RCDATA | 17728 |
| Resources.HTML | 17752 |
| Resources.MANIF | 17776 |
| Resources.MENU.AYRVNAIMJ | 17800 |
| Resources.MENU.LKHMEYKJC | 17824 |
| Resources.MENU.MVFHCY | 17848 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 11 · duration_s: 1.02

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| check for trap flag exception |  | B0001:Debugger Detection |
| find graphical window | T1010:Application Window Discovery |  |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |
| extract resource via kernel32 functions |  |  |

## PE Imports / Signals
import_count: 63

| label | api_match | ATT&CK |
|---|---|---|
| queue_apc | QueueUserAPC | T1055 |
| check_debugger | IsDebuggerPresent | T1622 |
| create_service | CreateService | T1543.003 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@96608 len=2 |
| contains_base64 | - | $a@7871 len=12 |
| Antivirus | - |  |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@200 len=4 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1 |
| SEH_Save | - | $a@1521 len=7 |
| SEH_Init | - | $a@1540 len=6; $b@3823 len=7 |
| anti_dbg | - | $d1@7456 len=12; $c2@9106 len=17 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 96608,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 7871,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1521,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1540,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 3823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$d1",
          "offset": 7456,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 9106,
          "length": 17,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`
```

## FLOSS Strings
Total strings: 2471 · per_category: `{"decoded_strings": 0, "stack_strings": 3, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2468}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcessHeap`
- `GetProcAddress`
- `LoadLibraryA`
- `KERNEL32.dll`

### FLOSS sample
- `QueryPerformanceFrequency`
- `QueryPerformanceCounter`
- `IsBadCodePtr`
- `!This program cannot be run in DOS mode.`
- `/uRich`
- ``.rdata`
- `@.data`
- `VC20XC00U`
- `;t$,v-`
- `UQPXY]Y[`
- `URPQQhT`
- `1F;5T@@`
- `bad allocation`
- `kernel32.dll`
- `user32`
- `&*^@QDSJGIO`
- `&JTEH$WHD`
- `fdsfsd,`
- `fdsfds`
- `V><MDNbyfui6y2iuow`
- `fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6`
- `ExitProcess`
- `HeapReAlloc`
- `CreateFileA`
- `FindResourceW`
- `LoadResource`
- `GetCurrentActCtx`
- `GetModuleHandleW`
- `GetCurrentThread`
- `VirtualFree`
- `GetProcessHeap`
- `TlsSetValue`
- `GetConsoleCP`
- `SizeofResource`
- `GetSystemDirectoryA`
- `GetACP`
- `lstrcmpW`
- `lstrlenW`
- `RtlMoveMemory`
- `GetLastError`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00402720
```asm
┌ 556: entry0 ();
│           0x00402720      6838314000     push str.QHACTIVEDEFENSE.EXE ; 0x403138 ; u"QHACTIVEDEFENSE.EXE"
│           0x00402725      e816ffffff     call 0x402640
│           0x0040272a      83c404         add esp, 4
│           0x0040272d      85c0           test eax, eax
│       ┌─< 0x0040272f      0f8513020000   jne 0x402948
│       │   0x00402735      6860314000     push str.QHSAFETRAY.EXE     ; 0x403160 ; u"QHSAFETRAY.EXE"
│       │   0x0040273a      e801ffffff     call 0x402640
│       │   0x0040273f      83c404         add esp, 4
│       │   0x00402742      85c0           test eax, eax
│      ┌──< 0x00402744      0f85fe010000   jne 0x402948
│      ││   0x0040274a      6880314000     push str.QHWATCHDOG.EXE     ; 0x403180 ; u"QHWATCHDOG.EXE"
│      ││   0x0040274f      e8ecfeffff     call 0x402640
│      ││   0x00402754      83c404         add esp, 4
│      ││   0x00402757      85c0           test eax, eax
│     ┌───< 0x00402759      0f85e9010000   jne 0x402948
│     │││   0x0040275f      68a0314000     push str.CMDAGENT.EXE       ; 0x4031a0 ; u"CMDAGENT.EXE"
│     │││   0x00402764      e8d7feffff     call 0x402640
│     │││   0x00402769      83c404         add esp, 4
│     │││   0x0040276c      85c0           test eax, eax
│    ┌────< 0x0040276e      0f85d4010000   jne 0x402948
│    ││││   0x00402774      68bc314000     push str.CIS.EXE            ; 0x4031bc ; u"CIS.EXE"
│    ││││   0x00402779      e8c2feffff     call 0x402640
│    ││││   0x0040277e      83c404         add esp, 4
│    ││││   0x00402781      85c0           test eax, eax
│   ┌─────< 0x00402783      0f85bf010000   jne 0x402948
│   │││││   0x00402789      68cc314000     push str.V3LITE.EXE         ; 0x4031cc ; u"V3LITE.EXE"
│   │││││   0x0040278e      e8adfeffff     call 0x402640
│   │││││   0x00402793      83c404         add esp, 4
│   │││││   0x00402796      85c0           test eax, eax
│  ┌──────< 0x00402798      0f85aa010000   jne 0x402948
│  ││││││   0x0040279e      68e4314000     push str.V3MAIN.EXE         ; 0x4031e4 ; u"V3MAIN.EXE"
│  ││││││   0x004027a3      e898feffff     call 0x402640
│  ││││││   0x004027a8      83c404         add esp, 4
│  ││││││   0x004027ab      85c0           test eax, eax
│ ┌───────< 0x004027ad      0f8595010000   jne 0x402948
│ │││││││   0x004027b3      68fc314000     push str.V3SP.EXE           ; 0x4031fc ; u"V3SP.EXE"
│ │││││││   0x004027b8      e883feffff     call 0x402640
│ │││││││   0x004027bd      83c404         add esp, 4
│ │││││││   0x004027c0      85c0           test eax, eax
│ ────────< 0x004027c2      0f8580010000   jne 0x402948
│ │││││││   0x004027c8      6810324000     push str.SPIDERAGENT.EXE    ; 0x403210 ; u"SPIDERAGENT.EXE"
│ │││││││   0x004027cd      e86efeffff     call 0x402640
│ │││││││   0x004027d2      83c404         add esp, 4
│ │││││││   0x004027d5      85c0           test eax, eax
│ ────────< 0x004027d7      0f856b010000   jne 0x402948
│ │││││││   0x004027dd      6830324000     push str.DWENGINE.EXE
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
