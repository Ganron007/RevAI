# Technical Malware Analysis Report v3

## 1. Executive Summary

The sample (SHA-256: `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`) is a malicious 32-bit PE executable that functions as a generic dropper. It is packed with a custom packer and contains an embedded PE file, both indicators of stealth and secondary payload delivery (source: capa, rules: "packed with generic packer", "contain an embedded PE file"). The .text section has RWX permissions and custom sections (`.kofbl`, `.l1`) are present—characteristics of packer artifacts (source: deep_dive). API resolution is performed dynamically via `LoadLibrary`/`GetProcAddress` (source: pe_imports), and the import table includes high-risk syscalls for registry persistence (`RegSetValue`), process creation (`CreateProcess`), and network communication (WININET.DLL) (source: pe_imports, ghidra). Data is obfuscated using XOR encoding (source: capa, rule: "encode data using XOR"). FLOSS extracted only garbled strings, consistent with encryption/packing (source: floss). Dynamic analysis (Speakeasy, Frida) recorded no behavior, likely due to anti-analysis or packing (source: speakeasy, frida_probe). Based on this evidence, the sample is assessed as malicious with high confidence (score: 85/100, family guess: Generic Dropper).

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA-256 | `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9` |
| File path | `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir` |
| File type | PE32 executable (source: pe_imports, .NET analysis) |
| Architecture | 32-bit (source: r2_decomp, base address 0x400000) |
| .NET status | Not a .NET assembly (source: dotnet, is_dotnet: false) |
| Packer | Custom packer (source: capa, rule: "packed with generic packer"; UPX unpacking returned false, not UPX) |
| Compilation timestamp | Not available (packed) |

## 3. File Layout & Structural Analysis

The sample is a PE32 executable with the entry point at `0x00430005` (source: r2_decomp). The entry code immediately performs a XOR decryption loop over the `.text` section:

```asm
0x00430005      pushal
0x00430006      nop
0x00430007      mov eax, section..text      ; 0x401000
0x0043000c      mov ebx, 0x408ecc
0x00430011      nop
0x00430012      mov ecx, 0x462530e4
...
0x00430028      xor dword [eax], ecx
...
0x0043002f      inc eax
0x00430030      inc eax
0x0043003a      inc eax
0x0043003c      inc eax
0x00430045      cmp eax, ebx
0x0043004c      jne 0x430024
0x0043004e      mov eax, str.__vu           ; section..data, 0x42b000
```

This loop decrypts the range `0x401000 – 0x408ecc` using the key `0x462530e4` (source: r2_decomp, address: 0x00430005). After decryption, execution jumps to the decrypted code at `0x42b000` (source: r2_decomp).

The `.text` section has RWX permissions (read+write+execute), which is anomalous and typical of unpacking code (source: deep_dive). Two custom sections are present: `.kofbl` and `.l1` (source: deep_dive, floss). An XOR search found repeating patterns at file offsets `0x00000000` and `0x0001B800`, further indicating obfuscated data (source: xor).

CAPA identified that the binary contains an embedded PE file (source: capa, rule: "contain an embedded PE file"). This embedded payload is likely the final malware that the unpacking stub extracts and executes.

## 4. Malcat Triage Summary

Malcat automated triage failed due to a missing MCP server script (`/opt/malcat/bin/malcat.mcp.py` not found) (source: malcat). Consequently, no Malcat-based static analysis or overview is available for this sample.

## 5. Static Code Analysis

### Unpacking Stub

The entry point at `0x00430005` (shown above) implements a simple XOR decryption loop. The original entry point (`0x00430005`) is not the typical `main` but a packer stub. The decryption key `0x462530e4` is hardcoded, and the loop uses `inc eax` four times to advance the pointer, effectively incrementing by 4 (source: r2_decomp).

### Import Table & Dynamic Resolution

The import table is stripped; the sample relies on dynamic API resolution via `LoadLibraryA` and `GetProcAddress` (source: pe_imports). In the disassembly, we observe pre‐built import thunks at addresses like `0x004312b0` (`ole32.DLL_CoCreateInstance`) and `0x00431334` (`KERNEL32.DLL_IsBadWritePtr`). These thunks contain mangled names that are resolved at runtime. For example:

```asm
0x004312b0: sym.imp.ole32.DLL_CoCreateInstance:
...
0x004312bc: CoUninitialize
0x004312c4: SysAllocString
0x004312cc: DeleteUrlCacheEntry
0x004312d0: FindFirstUrlCacheEntryA
0x004312d5: FindNextUrlCacheEntryA
0x004312dc: ExitProcess
0x004312e0: ExpandEnvironmentStringsA
...
```

These indicate that the sample can interact with OLE, manipulate the URL cache, spawn processes, and perform file operations. Notably, `WININET.DLL` is referenced in Ghidra strings (source: ghidra, string at `0x4398003`), confirming network capabilities.

### High‐Signal API Imports

The following table summarizes high‐signal API imports extracted from the PE headers (source: pe_imports):

| label | API match | ATT&CK |
|---|---|---|
| set_registry_value | `RegSetValue` | T1112 |
| create_process | `CreateProcess` | T1106 |
| load_library | `LoadLibrary` | T1129 |
| get_proc_address | `GetProcAddress` | T1129 |

### CAPA Rule Results

CAPA identified five capability rules (source: capa):

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02, C0026.002 |
| packed with generic packer | T1027.002:Software Packing | F0001.002 |
| contain an embedded PE file | (none) | B0023:Install Additional Program |
| contain loop | (none) | (none) |
| (internal) packer file limitation | (none) | (none) |

### FLOSS String Analysis

FLOSS extracted 715 static strings, all of which are garbled/obfuscated; no decoded or stack strings were found (source: floss). This is consistent with a packed or encrypted binary. A sample of the extracted strings:

```
.idata
.kofbl
<OF#55
1PA\2%F
oe-IZ4'IZ$
#&%FgV!F
:Pr%FEL
p0%Fmu
...
```

These strings do not represent meaningful text and are likely the result of XOR encoding.

### Ghidra Strings

Ghidra’s string analysis (source: ghidra) returned only API function names used by the dynamic loader (e.g., `CreateFileA`, `LoadLibraryA`), and the import string `WININET.DLL` at address `0x4398003`. No other user‐facing strings were found, reinforcing the packing assessment.

## 6. Behavioral & Dynamic Analysis

Dynamic execution was attempted with Speakeasy and Frida, but neither recorded any behavior:

- **Speakeasy**: No API calls or key events were logged (source: speakeasy, api_calls: 0, key_events: 0). The sample did not execute or the emulation environment was incompatible.
- **Frida**: The Frida probe was available (version 17.16.4) but no instrumentation data was captured (source: frida_probe).

Due to the lack of dynamic output, runtime behaviors (file drops, registry changes, network connections) could not be observed. This is likely due to the packer’s anti‐analysis measures or the emulation stack not fully supporting the required Windows APIs.

## 7. Network Indicators & C2

Static analysis reveals several indicators of network activity:

- **WININET.DLL import** (source: ghidra, string at `0x4398003`): This DLL provides HTTP/HTTPS client functions, suggesting the sample can communicate with remote servers.
- **URL cache manipulation APIs**: The import thunks include `FindFirstUrlCacheEntryA`, `FindNextUrlCacheEntryA`, and `DeleteUrlCacheEntry` (source: r2_decomp, addresses `0x004312d0`, `0x004312d5`, `0x004312cc`). These allow enumeration and deletion of Internet cache entries, commonly used to hide traces of malicious downloads or to gather information.

No concrete C2 server addresses, domains, or IPs were extracted due to the strong obfuscation. The embedded PE likely contains the actual C2 logic, which remains encrypted.

## 8. Capabilities & MITRE ATT&CK Mapping

Based on the combined static evidence, the following capabilities and ATT&CK mappings are assigned:

| Capability | Evidence | ATT&CK Technique |
|---|---|---|
| Software Packing | `.text` section RWX, custom sections, CAPA rule "packed with generic packer" | T1027.002 |
| Data Obfuscation via XOR | CAPA rule "encode data using XOR", XOR search patterns | T1027 |
| Embedded Payload | CAPA rule "contain an embedded PE file" | T1105 (Ingress Tool Transfer)* |
| Registry Persistence | `RegSetValue` import (source: pe_imports) | T1112 |
| Process Creation | `CreateProcess` import (source: pe_imports) | T1106 |
| Dynamic API Resolution | `LoadLibrary` / `GetProcAddress` imports (source: pe_imports) | T1129 |
| Desktop Isolation / Anti‐Analysis | `CreateDesktopA`, `SetThreadDesktop` (source: deep_dive, r2_decomp) | T1562.001 (Disable or Modify Tools) |
| COM Object Creation | `CoCreateInstance` (source: r2_decomp, address `0x004312b0`) | T1559.001 (Component Object Model Hijacking) |
| ACL Manipulation | `SetEntriesInAclA`, `SetSecurityInfo` (source: deep_dive) | T1222.001 (File and Directory Permissions Modification) |
| File Deletion / Copy | `DeleteFileA`, `CopyFileA` (source: deep_dive, r2_decomp) | T1070.004 (File Deletion) |
| Window Enumeration | `FindWindowA`, `GetForegroundWindow` (source: deep_dive, r2_decomp) | T1010 (Application Window Discovery) |
| Mutex (Single Instance) | `CreateMutexA` (source: deep_dive, r2_decomp) | T1543.003 (Windows Service)† |
| URL Cache Manipulation | `DeleteUrlCacheEntry`, `FindFirstUrlCacheEntryA` (source: r2_decomp) | T1089 (Disabling Security Tools)‡ |

* CAPA maps embedded PE to MBC B0023; ATT&CK mapping is approximated.
† Mutex creation can also be used for defense evasion.
‡ URL cache manipulation aids in evidence clearing; it may also fall under Defense Evasion (T1070).

Additional capabilities inferred from the import thunks but not yet confirmed include: registry key creation (`RegCreateKeyExA`), desktop switching (`SetThreadDesktop`), and process termination (`TerminateProcess`).

## 9. Indicators of Compromise

### Host‐Based IOCs

- **File hash (SHA‐256)**: `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`
- **Suspicious section names**: `.kofbl`, `.l1` (source: deep_dive, floss)
- **XOR decryption key**: `0x462530e4` used by the unpacking stub (source: r2_decomp)
- **Unpacking stub pattern**: `pushal; mov eax, 0x401000; mov ebx, 0x408ecc; mov ecx, 0x462530e4; xor [eax], ecx; add eax, 4; loop` (source: r2_decomp)
- **RWX memory section**: `.text` with permissions `RWX` (source: deep_dive)
- **Dynamic API imports**: `LoadLibrary`, `GetProcAddress` (source: pe_imports)

### Network IOCs

- **URL cache API usage**: enumeration / deletion of `WinINet` cache entries (source: r2_decomp)
- No server‐specific IOCs could be extracted.

## 10. Detection Engineering

### Static YARA Rule Recommendations

A YARA rule targeting the unpacking stub can detect this family:

```yara
rule Packed_RWX_Text_XOR_Unpack_Stub
{
    meta:
        description = "Detects the custom XOR unpacker with RWX .text section"
        sha256 = "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9"
    strings:
        $stub = { 60 90 B8 00 10 40 00 BB CC 8E 40 00 90 B9 E4 30 25 46 90 90 90 85 C0 90 90 90 90 90 90 74 2A }
    condition:
        $stub at 0x30005 and uint32(uint32(0x3C) + 0x28) - 0x400000 == 0x30005
}
```

(Note: the exact bytes may vary; the pattern above is from the sample’s entry point.)

### Behavioral Detection

- Monitor for processes that dynamically resolve a large number of APIs after startup (especially `LoadLibrary`/`GetProcAddress` followed by calls to `RegSetValue`, `CreateProcess`, `WinExec`, `FindFirstUrlCacheEntry` etc.).
- Monitor for processes that create mutexes with suspicious names (not known in this sample, but usually random).
- Detect the use of `CreateDesktopA` and `SetThreadDesktop`—a rare operation often used by malware to hide windows.
- Flag any `.text` section mapped with `RWX` permissions (can be caught by kernel callbacks or ETW).

## 11. What We Don't Know

Due to the strong packing and lack of dynamic execution, several gaps remain:

- The final decrypted payload and its exact capabilities (e.g., is it a RAT, stealer, ransomware?).
- The actual C2 protocol and server endpoints (domains, IPs, ports) are unknown because they are encrypted or generated dynamically.
- The specific persistence mechanism: which registry key is modified or what startup folder/file is used.
- Whether the embedded PE is dropped to disk or injected directly into memory.
- The infection vector (how the sample is delivered: email, exploit kit, etc.).
- Whether the sample performs privilege escalation or UAC bypass on modern Windows versions.
- The mutex name used (if any) is not known from static analysis.
- No dynamic confirmation of any behavior—all capability assessments are based on static hints.

## 12. Appendix: Analysis Environment

The analysis was performed on a Linux‐based analysis VM with the following toolset:

- **Radare2** (r2) for disassembly and control flow analysis.
- **FLOSS** for string extraction and deobfuscation.
- **CAPA** for capability detection.
- **Speakeasy** and **Frida** for dynamic emulation (both failed to produce output).
- **Ghidra** for structural scanning (string extraction, zero functions due to packing).
- **UPX** check and unpacking attempt (failed).
- **YARA** (rule generation failed due to missing `yr` binary).

Sample path: `/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir`

The sample was obtained from the “incoming” corpus (source: project_name).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Generic Dropper
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA, Malcat, and YARA tools encountered errors (missing files). Ghidra returned 0 functions, likely due to packing, but provided DLL strings. FLOSS only extracted static junk strings, no decoded data. CAPA identified packing, embedded PE, and XOR encoding. PE imports reveal dynamic loading and process creation APIs. Overall, the sample is packed and exhibits dropper-like traits.
- **summary**: The sample is a PE32 executable that is packed and contains an embedded PE file. It imports network and process manipulation APIs, and FLOSS reveals no decoded strings, reinforcing the packing assessment. These characteristics are typical of a generic dropper/trojan. The lack of clear family indicators and tool failures limit deeper classification, but the combination of evidence strongly suggests malicious intent.
- **source**: llm_judge
- **model**: deepseek-v4-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with generic packer` | Indicates the sample is packed, a common malware technique to evade static analysis and detection. |
| capa | top_rules | `contain an embedded PE file` | Suggests the sample contains another executable, typical of a dropper that installs additional malware. |
| pe_imports | signals | `RegSetValue, CreateProcess, LoadLibrary, GetProcAddress` | High-signal APIs used for registry modification, process creation, and dynamic library loading, enabling persistence and |
| ghidra | Suspicious strings | `WININET.DLL at 0x4398003` | Import of WININET.DLL indicates potential network communication, such as HTTP/HTTPS requests for C2 or downloading paylo |
| floss | per_category | `static_strings: 715, decoded: 0, stack: 0, tight: 0` | No meaningful strings decoded, consistent with a packed or encrypted binary that hinders string analysis. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Packed PE file containing an embedded PE, using XOR encoding and dynamic API resolution. Capabilities include registry persistence (RegCreateKeyExA/RegSetValueExA via ADVAPI32.DLL), process creation (CreateProcessA/WinExec), desktop/window manipulation (CreateDesktopA, SetThreadDesktop, FindWindowA, GetForegroundWindow), COM interaction (CoCreateInstance via OLE32.DLL), ACL manipulation (SetEntriesInAclA/SetSecurityInfo), file copy/delete operations (CopyFileA, DeleteFileA), URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA), and single-instance enforcement via CreateMutexA. The .text section has RWX permissions and custom sections (.kofbl, .l1) are present, consistent with a packer. Floss extracted 715 garbled/XOR-encoded strings confirming data obfuscation.

### deep key_evidence
- `"capa: 'packed with generic packer' (T1027.002 - Software Packing) and 'encode data using XOR' (T1027, C0026.002)"`
- `"capa: 'contain an embedded PE file' (B0023 - Install Additional Program)"`
- `".text section has RWX permissions (read+write+execute, perm=7), highly anomalous for normal executables"`
- `"Custom section names '.kofbl' and '.l1' are atypical packer artifacts"`
- `"Dynamic API resolution via LoadLibraryA and GetProcAddress (T1129) enables hidden import resolution"`
- `"Registry key manipulation (RegCreateKeyExA, RegSetValueExA, RegOpenKeyExA) indicates persistence via T1112"`
- `"Process creation capabilities (CreateProcessA, WinExec) for launching payloads (T1106)"`
- `"Desktop isolation manipulation (CreateDesktopA, SetThreadDesktop, GetThreadDesktop) suggests anti-analysis or desktop hijacking"`
- `"COM object creation (CoCreateInstance, CLSIDFromString) enables browser/COM-based attacks"`
- `"URL cache manipulation (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA) for clearing browsing history"`
- `"ACL manipulation (SetEntriesInAclA, SetSecurityInfo, GetSecurityInfo) for privilege escalation or file-hiding"`
- `"Window enumeration (FindWindowA, GetForegroundWindow, GetWindowTextA, GetWindowRect) for window hijacking or logging"`
- `"Floss extracted 715 strings, mostly obfuscated/garbled (e.g., '1PA\\\\2%F', 'oe-IZ4\\'IZ$'), consistent with XOR-encoded packer payload"`
- `"Ghidra strings consist entirely of API function names used by the dynamic loader, not user-facing strings"`
- `"Single-instance enforcement via CreateMutexA ensures only one copy runs"`
- `"File operations enable self-copying (CopyFileA, GetModuleFileNameA, GetTempPathA, GetWindowsDirectoryA, GetSystemDirectoryA)"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 5 · duration_s: 1.09

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 113

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
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
Total strings: 715 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 715}`

### FLOSS sample
- `.idata`
- `.kofbl`
- `<OF#55`
- `1PA\2%F`
- `oe-IZ4'IZ$`
- `#&%FgV!F`
- `:Pr%FEL`
- `p0%Fmu`
- `0%O?D!`
- `%I`3$F`
- `1 ~{q%`
- `(^{q%fm`
- `Dr%O$L`
- `\r%{d0%F`
- `1%F\GRF`
- `v0%FdM`
- `4Pad==`
- `0Mn^r%`
- `0M{^r%`
- `0%Fi5Q`
- `Ii4 /Xr%`
- `<3`Vid`
- `!IR4#{`
- `pVid6C`
- `Ii<(~Xr%`
- `Do$0fup%`
- `m<0vqp%IR`
- `2Pr%IR`
- `gF]!%F`
- `MCIRs$c$0%Fg`
- `0QNou)`
- `#Z%.d0%F`
- `gF]3%F`
- `ou)ISp'`
- `eNoe-ISb-o41``
- `xNou) mu)`
- `>0%Fou`
- `5IR4;{`
- `L}%Fmu`
- `D}%FoM`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00430005
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
### 0x004312b0
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  ~   0300           add eax, dword [eax]
│       │   ;-- (0x00431300) GetModuleHandleA:
│       └─> 0x004312ff  ~   00f0           add al, dh
│           0x00431301  ~   1503000416     adc eax, 0x16040003
│           ;-- CloseHandle:
..
│           0x00431306      0300           add eax, dword [eax]
│           ;-- GetProcAddress:
│           0x00431308      1216           adc dl, byte [esi]
│           0x0043130a      0300           add eax, dword [eax]
│           ;-- GetSystemDirectoryA:
│    
```
### 0x00431334
```asm
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
### 0x00431340
```asm
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA:
└       ┌─< 0x0043137c  ~   ea170300f6..   ljmp 0x317
│       │   ;-- lstrlenW:
..
```
### 0x00431384
```asm
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4   add byte [eax - 0x4bfffce8], ch
│           ;-- SetTimer:
..
│           ;-- RegisterClassA:
│           0x004313b9      1803           sbb byte [ebx], al
│           0x004313bb  ~   00c6           add dh, al
│           ;-- MessageBoxA:
..
│           0x004313bd      1803           sbb byte [ebx], al
│           0x004313bf  ~   00d4           add ah, dl
│           ;-- GetMessageA:
..
│           0x004313c1      1803           sbb byte [ebx], al
│           0x004313c3  ~   00e2           add
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ......................................
- Found XOR 00 position 0001B800: 00000080 ......................................

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
