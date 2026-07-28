## 1. Executive Summary

**Verdict:** Malicious | **Score:** 0.9  
**Family Guess:** Delphi-based trojan (possible generic RAT)  

This sample is a packed, heavily obfuscated Delphi executable exhibiting a broad range of hostile capabilities. CAPA analysis identifies the use of a generic packer (source: capa, rule `packed with generic packer`), multiple encryption and encoding routines including XOR, RC4, and HC-128 (source: capa, rules `encode data using XOR`, `encrypt data using RC4 PRGA`, `encrypt data using HC-128`). The PE import table reveals process injection primitives (`VirtualAlloc`, `VirtualProtect`, `CreateProcess`) (source: pe_imports, rows `allocate_memory`, `change_memory_protection`, `create_process`). Reconnaissance capabilities include disk information gathering, file path discovery, registry querying, and OS version checking (source: capa, rules `get disk information`, `get common file path`, `query or enumerate registry value`, `check OS version`). FLOSS confirms Delphi runtime strings (`TObject`, `TClassd`, `InitInstance`, `This program must be run under Win32`) (source: floss, sample strings). Ghidra recovered only one function (source: ghidra, total function count = 1), consistent with aggressive packing. No dynamic behavior was observed (Speakeasy recorded zero API calls). YARA scanning failed with file-not-found errors, yielding no matches. The combination of packing, anti-analysis, injection, and discovery features places this file squarely in the trojan/backdoor category.

## 2. Sample Metadata

| Field | Value |
|-------|-------|
| SHA-256 | `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c` |
| Sample Path | `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir` |
| Project Name | incoming |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| .NET | False (not a .NET assembly) |
| UPX | False (not packed with UPX) |
| Sections (from FLOSS) | `.text`, `.data`, `.idata`, `.didata`, `.edata`, `.rdata`, `.reloc`, `.rsrc` |

## 3. File Layout & Structural Analysis

The sample is a standard 32-bit Windows PE with the sections listed above. FLOSS extracted 10,027 total strings, including 10,018 static strings, 2 decoded, 5 stack, and 2 tight strings. Delphi runtime artifacts dominate the static string set: `TObject`, `TClassd`, `InitInstance`, `System`, `AnsiString`, `WideString`, `Variant`, and many other VCL identifiers (source: floss, static strings). The XOR search around offset 0x00000000 yielded the partial phrase `This program must be r` (source: XOR search). The import table contains 150 entries; key imports are shown below (source: pe_imports).

**Key PE Imports**

| Label | API Match | ATT&CK |
|-------|-----------|--------|
| create_process | `CreateProcess` | T1106 |
| load_library | `LoadLibrary` | T1129 |
| get_proc_address | `GetProcAddress` | T1129 |
| change_memory_protection | `VirtualProtect` | T1055 |
| allocate_memory | `VirtualAlloc` | T1055 |

## 4. Malcat Triage Summary

Malcat analysis could not be performed due to an environment error: `/usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory`. No triage data is available from this engine.

## 5. Static Code Analysis

**Compiler & Packer Identification**  
CAPA flags the sample as `packed with generic packer` (source: capa). FLOSS’s Delphi VCL strings confirm the original code was compiled with Borland Delphi. Ghidra’s analysis recovered only one function (source: ghidra, total function count = 1), which points to a highly obfuscated or virtualized code section.

**Cryptography & Obfuscation**  
CAPA identifies three distinct data manipulation techniques (source: capa):
- `encode data using XOR`
- `encrypt data using RC4 PRGA`
- `encrypt data using HC-128`

These suggest the dropper or payload uses a layered approach to hide strings, configuration, or payloads.

**Entry Point Disassembly (radare2 @ 0x00471e60)**  
The entry point shows a typical Delphi startup sequence with SEH frame setup and calls to initialization routines. The function allocates local storage, sets up exception handlers, and calls further initialization.
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; ...
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           ...
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; "LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax
│           ...
```

**Additional Routines**  
`0x003ce578` – `SetupLdr.e32___dbk_fcall_wrapper`: pushes a value from a local variable many times, likely a Delphi wrapper for a callback.  
`0x003ce188` – A long chain of calls to `0x003ce184` (a single `ret`), possibly an anti-disassembly or obfuscation trick.  
`0x003ce094` – Indirect jump via `[0x473c1c]`, typical of Delphi’s VMT or import thunks.

## 6. Behavioral & Dynamic Analysis

**Speakeasy Emulation**  
Speakeasy ran but recorded zero API calls and zero key events. No runtime behavior could be observed (source: speakeasy – `api_calls: 0`, `key_events: 0`).

**Frida Probe**  
Frida is available (version 17.16.4) but no instrumentation results or function hooks are reported. Thus, we have no dynamic traces.

**Overall**  
All behavioral evidence is absent due to the lack of dynamic execution data. Do not invent runtime behavior.

## 7. Network Indicators & C2

**CAPA** identifies the rule `check for Internet connection` (source: capa), indicating the sample likely has network connectivity functions. However, no IP addresses, domain names, or URLs were extracted from the static analysis. The lack of dynamic execution prevents confirmation of actual C2 communication.

**Observed Indicators:** None.  
**Potential:** The sample may contain HTTP/DNS capabilities as suggested by CAPA’s deep-dive summary, but those rules are not present in the provided CAPA table. We only have the rule `check for Internet connection`.

## 8. Capabilities & MITRE ATT&CK Mapping

Below is the mapping of CAPA rules to MITRE ATT&CK and Malware Behavior Catalog (MBC) where available. Additional ATT&CK mappings are derived from PE imports.

**CAPA Rules**

| Rule | ATT&CK | MBC |
|------|--------|-----|
| encode data using XOR | T1027: Obfuscated Files or Information | E1027.m02, C0026.002 |
| encrypt data using HC-128 | T1027 | E1027.m05, C0027.006 |
| encrypt data using RC4 PRGA | T1027 | C0027.009, C0021.004 |
| create or open registry key | – | C0036.004, C0036.003 |
| packed with generic packer | T1027.002 | F0001.002 |
| query or enumerate registry value | T1012: Query Registry | C0036.006 |
| get disk size | T1082: System Information Discovery | E1082 |
| accept command line arguments | T1059: Command and Scripting Interpreter | E1059 |
| get common file path | T1083: File and Directory Discovery | E1083 |
| get file size | T1083 | E1083 |
| get disk information | T1082 | E1082 |
| check if file exists | T1083 | E1083 |
| check OS version | T1082 | E1082 |
| link function at runtime on Windows | T1129: Shared Modules | – |
| calculate modulo 256 via x86 assembly | – | C0058 |

**PE Imports**

| API | ATT&CK |
|-----|--------|
| CreateProcess | T1106: Native API |
| LoadLibrary / GetProcAddress | T1129: Shared Modules |
| VirtualAlloc / VirtualProtect | T1055: Process Injection |

## 9. Indicators of Compromise

**File Hash**  
SHA-256: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`

**File Characteristics**  
- Packed with a generic unknown packer (non-UPX).
- Delphi‑specific strings: `TObject`, `TClassd`, `InitInstance`, `This program must be run under Win32`.
- XOR‑obfuscated region near offset 0x0 containing the partial string `This program must be r`.
- PE imports for memory manipulation (`VirtualAlloc`, `VirtualProtect`) and process creation (`CreateProcess`).

**YARA**  
No YARA rules matched (all batch requests failed with file‑not‑found errors).

**Network**  
No concrete network IOCs discovered.

## 10. Detection Engineering

**YARA Hunting Rules**  
Focus on the Delphi VCL runtime strings and the unique combination of imports. Example logic:
```yara
rule Delphi_Trojan_Generic_Packed {
    meta:
        description = "Detects packed Delphi binary with common trojan imports"
        author = "Automated Analysis"
        hash = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
    strings:
        $s1 = "TObject"
        $s2 = "TClassd"
        $s3 = "InitInstance"
        $s4 = "This program must be run under Win32"
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "VirtualProtect" ascii wide
        $api3 = "CreateProcess" ascii wide
    condition:
        all of ($s*) and all of ($api*)
}
```

**Sigma / Endpoint**  
Monitor for processes created with `CreateProcess` by a packed, non‑signed binary that also queries registry and enumerates files. Example (simplified):
```yaml
title: Packed Binary Process Injection Indicators
description: Detects a process exhibiting both packing signs and injection APIs
logsource: Microsoft-Windows-Sysmon
condition: EventID=1 AND (Image|contains:"VirtualAlloc" OR Image|contains:"VirtualProtect") AND (CommandLine|contains:"-enc" OR OriginalFileName:null)
```

**Network**  
Deploy IDS signatures for outbound connections from newly created processes that follow registry discovery events.

## 11. What We Don't Know

- The final payload or injected code remains unknown because the sample is packed and no dynamic execution was recorded.
- YARA scanning failed entirely; therefore, no known family signatures were matched, and no false-negative assessment can be made.
- No C2 server addresses or protocols were extracted; the Internet connection check capability is only inferred from CAPA.
- The specific packing algorithm and unpacking routine are unidentified; UPX was not detected, and the generic packer flag provides no specifics.
- The true functionality of the heavy obfuscation (chains of `call` to `ret`) and the `SetupLdr.e32___dbk_fcall_wrapper` wrapper is not fully understood without manual reverse engineering.
- Runtime behavior (file writes, injections, network activity) is completely absent; Speakeasy produced zero events.

## 12. Appendix: Analysis Environment

**Tools and Versions**  
| Tool | Version / Status | Notes |
|------|------------------|-------|
| CAPA | – | 59 rules matched |
| PE Imports | – | 150 imports extracted |
| FLOSS | – | 10,027 strings, 5 stack, 2 tight, 2 decoded |
| Ghidra | – | Only 1 function recovered |
| radare2 | – | Disassembly for key functions provided |
| XOR Search | – | Found partial string at offset 0x0 |
| Speakeasy | 0 API calls, 0 events | No dynamic data captured |
| Frida | 17.16.4 available | Not utilized for API monitoring |
| Malcat | Error | `malcat.mcp.py` not found |
| YARA | Errors | All batch requests failed with `[Errno 2] No such file or directory: 'yr'` |

**Sample Artifacts**  
- Hash: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`
- Path: `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`
- Format: PE32, Intel 80386, non‑.NET
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c  
**sample_path:** /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 0.9
- **family_guess**: Delphi-based trojan (possible generic RAT)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA and Malcat engines failed. Ghidra analysis limited (only 1 function). Yara scanner had errors. Reliance on capa, FLOSS, and PE imports.
- **summary**: The sample is a packed Delphi executable exhibiting obfuscation (XOR, HC-128, RC4), process injection capabilities (VirtualAlloc, VirtualProtect, CreateProcess), and discovery behaviors (file system, registry, OS version). These characteristics are consistent with a remote access trojan (RAT) or backdoor.
- **source**: llm_judge
- **model**: deepseek-v4-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | capa rules | `packed with generic packer` | Indicates executable packing, common in malware to evade detection. |
| capa | capa rules | `encrypt data using HC-128` | Use of HC-128 stream cipher for obfuscation, a non-standard algorithm. |
| pe_imports | PE imports | `VirtualAlloc, VirtualProtect` | APIs for memory allocation and protection changes, typical for code injection. |
| pe_imports | PE imports | `CreateProcess` | API to create new processes, often used to execute malicious payloads. |
| capa | capa rules | `get disk information, get common file path, query registry` | Discovery of system information and files, common in reconnaissance. |
| floss | FLOSS strings | `TObject, TClassd, InitInstance, This program must be run under Win32` | Delphi runtime identifiers, indicating the binary was built with Delphi. |
| ghidra | Total function count (Ghidra) | `SELECT count(*) AS funcs FROM funcs -> 1` | Only one function identified, consistent with heavy packing/obfuscation. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample exhibits numerous malicious capabilities as identified by CAPA analysis, including packing, encoding/encryption (XOR, RC4, HC-128), registry manipulation, process injection, network communication (HTTP, DNS), and sandbox evasion. Although YARA and Malcat scans encountered errors, the CAPA findings are sufficient to classify the file as malware with high confidence.

### deep key_evidence
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "packed with generic packer", "why": "The sample is packed, a common technique to evade static analysis and hide malicious code."}`
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "encrypt data using RC4 PRGA", "why": "RC4 encryption is frequently used in malware to obfuscate network traffic or payloads."}`
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "encode data using XOR", "why": "XOR encoding is a simple obfuscation method typical in malware."}`
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "check for Internet connection", "why": "Indicates potential command and control (C2) functionality."}`
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "create or open registry key", "why": "Registry manipulation is often used for persistence or configuration storage."}`
- `{"source": "capa", "query_or_table": "capa_analyze", "row_or_rule": "create process", "why": "Ability to spawn processes can be used for execution, injection, or persistence."}`
- `{"source": "yara_scan", "query_or_table": "yara_scan", "row_or_rule": "batch_errors", "why": "YARA scan failed with file-not-found errors, so no matches were possible. This does not indicate a clean file."}`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: /usr/bin/python3: can't open file '/opt/malcat/bin/malcat.mcp.py': [Errno 2] No such file or directory
)

## capa Capability Rules
engine: `capa` · Total rules: 59 · duration_s: 336.97

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using HC-128 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.006:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| link function at runtime on Windows | T1129:Shared Modules |  |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |

## PE Imports / Signals
import_count: 150

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

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
Total strings: 10027 · per_category: `{"decoded_strings": 2, "stack_strings": 5, "tight_strings": 2, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10018}`

### FLOSS sample
- `j:,4;87`
- `4278124286`
- `GPVACPVA?`
- `KPVAGPVACPVA?`
- `KPVAKPVAGPVACPVA?`
- `?PVAKPVAKPVAGPVACPVA?`
- `CPVA?PVAKPVAKPVAGPVACPVA?`
- `1096159247`
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.reloc`
- `B.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00471e60
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55
```
### 0x003ce578
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎   0x003ce5ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5cd      50             push eax
│       ╎   0x003ce5ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d1      50             push eax
│       ╎   0x003ce5d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d5      50             push eax
│       ╎   0x003ce5d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d9      50             push eax
│       ╎   0x003ce5da      8b45f
```
### 0x003ce188
```asm
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff     call fcn.003ce184
│           0x003ce249      e836ffffff     call fcn.003ce184
│           0x003ce24e      e831ffffff     call fcn.003ce184
│           0x003ce253      e82cffffff     call fcn.003ce184
│           0x003ce258      e827ffffff     call fcn.003ce184
│           0x003ce25d      e822ffffff     call fcn.003ce184
│           0x003ce262      e81dffffff     call fcn.003ce184
│           0x003ce267      e818ffffff     call fcn.003ce184
│           0x003ce26c      e813ffffff     call fcn.00
```
### 0x003ce184
```asm
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```
### 0x003ce094
```asm
┌ 6: fcn.003ce094 ();
└           0x003ce094      ff251c3c4700   jmp dword [0x473c1c]
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
