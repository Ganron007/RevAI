> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:51:26 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

**SHA256:** 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
**Project:** Hexorcist 1 - Weeks 1-8
**Analyst Date:** 2026-08-09

---

## 1. Executive Summary

This report analyzes a 32-bit Windows PE executable (`nspack.exe`, 55,021 bytes) that is packed with nSpack v2.x. The sample masquerades as Windows Calculator (`CALC.EXE`) by embedding forged Microsoft Corporation version information, a common social-engineering tactic to appear legitimate. Multiple independent tools—YARA, FLOSS, MalCat, and packer-intake analysis—consistently identify nSpack packing through signature matches, embedded strings, and structural anomalies (source: yara, floss, malcat, packer_intake).

The binary imports APIs associated with dynamic loading (`LoadLibraryA`, `GetProcAddress`), memory manipulation (`VirtualAlloc`, `VirtualProtect`, `VirtualFree`), and registry access (`RegOpenKeyExA`). Both code sections (`nsp0`, `nsp1`) have Read-Write-Execute (RWX) permissions, which is characteristic of self-modifying unpacking stubs (source: malcat, File Layout table). The packer uses aPLib decompression to extract the hidden payload at runtime (source: malcat-capa, rule `decompress data using aPLib`).

**Verdict: SUSPICIOUS (score: 50).** The sample exhibits strong packing and obfuscation indicators but lacks definitive behavioral-intent evidence such as C2 communication, data destruction, credential theft, or persistence mechanisms. The actual payload is compressed/encrypted and only accessible after runtime unpacking. Static analysis reveals only the packer stub; the true malicious (or benign) nature of the embedded payload cannot be determined without dynamic execution in a controlled environment.

---

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | `2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5` | malcat |
| File Name | `nspack.exe` | malcat |
| File Size | 55,021 bytes | malcat |
| File Type | PE (Portable Executable) | malcat |
| Architecture | x86 (32-bit) | malcat |
| Entry Point EA | 27 | malcat |
| Entropy | 52 (overall) | malcat |
| Packer | nSpack v2.x | yara, floss, malcat |
| Imphash | `4ddd9e53a5be88aaffc4455bfc877c19` | rule.yara.json |
| Family Guess | nSpack | llm_judge |
| Verdict | Suspicious (score 50) | llm_judge |
| .NET | No | dotnet |

The sample's import hash (`4ddd9e53a5be88aaffc4455bfc877c19`) and the presence of the string `!packed by nspack$@` (source: floss) provide strong fingerprinting for the nSpack packer family. The forged version info identifies the file as `Microsoft Windows Calculator` version `5.1.2600.0` by `Microsoft Corporation` (source: malcat, Top Strings EA 124648, 124732, 125116), which is a deliberate masquerade on a packed binary.

---

## 3. File Layout & Structural Analysis

The PE file contains two non-standard sections with names characteristic of nSpack (`nsp0`, `nsp1`). Both sections have RWX permissions, which is a strong indicator of self-modifying code used during unpacking (source: malcat, File Layout table).

### Section Table

| Name | EA | Physical Size | Virtual Size | Entropy | Rights | Source |
|---|---|---|---|---|---|---|
| nsp0 | 0 | 512 | 122,880 | 52 | RWX | malcat |
| nsp1 | 122,880 | 54,509 | 65,536 | 0 | RWX | malcat |

The `nsp0` section has a physical size of only 512 bytes but a virtual size of 122,880 bytes, indicating a massive expansion at runtime—consistent with unpacking stubs that allocate memory and decompress code into this region. The `nsp1` section contains the compressed payload (54,509 bytes physical) with a virtual size of 65,536 bytes. The entropy of 0 for `nsp1` is anomalous and may reflect how MalCat reports entropy for compressed/encrypted sections (source: malcat).

### Structural Anomalies

MalCat identified 16 anomalies, several of which are high-signal indicators of packing (source: malcat, Anomalies table):

| Anomaly | Level | Category | Hits | Interpretation |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 2 | Control flow jumps across sections, typical of packed executables where the stub transfers control to decompressed code |
| SectionWX | 3 | sections | 2 | Both nsp0 and nsp1 are writable and executable—classic self-modifying code indicator |
| SectionNameUnknown | 3 | sections | 2 | `nsp0`/`nsp1` are non-standard section names specific to nSpack |
| Packed | 2 | packers | 2 | Deterministic packing detection |
| UnreferencedImports | 3 | imports | 11 | More than half of imports are unreferenced statically; they are resolved dynamically at runtime by the packer stub |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | GUI subsystem declared but no user32 window APIs imported statically—window APIs are likely resolved dynamically |
| UnsignedMicrosoft | 4 | integrity | 3 | Version info claims Microsoft origin but no digital signature present |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | Non-zero data between PE header and first section—common in packed executables |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | Huge difference between physical and virtual sizes in nsp0 |

The `GuiSubsystemNoWindowApi` anomaly at EA 156 (source: malcat, Anomaly Locations) indicates the binary declares itself as a GUI application but does not statically import any window-management APIs, suggesting dynamic resolution.

### Carved and Virtual Files

MalCat carved 8 DIB (Device-Independent Bitmap) resources and identified 11 virtual files including icons, a group icon, version info, and a manifest (source: malcat, Carved Files and Virtual Files tables). The manifest references `Microsoft.Windows.Shell.calc` and `Microsoft.Windows.Common-Controls` v6.0.0.0, further reinforcing the Calculator masquerade (source: malcat, Top Strings EA 125372).

---

## 4. Static Code Analysis

### Entry Point and Packer Stub

The entry point is at EA 27, which immediately jumps to the main packer stub at `0x01025a56` (source: radare2, disassembly at 0x0100101b). The stub begins with `pushfd` / `pushal` to save all registers and flags, then uses a `call`/`pop` sequence to obtain the current instruction pointer (EIP)—a classic position-independent code (PIC) technique used by packers to calculate relative addresses (source: radare2, disassembly at 0x01025a56).

```asm
┌ 5: entry0 ();
└       ┌─< 0x0100101b      e9364a0200     jmp fcn.01025a56
```
(source: radare2)

The main stub at `0x01025a56` performs the following operations:
1. Saves CPU state (`pushfd`, `pushal`)
2. Obtains EIP via `call`/`pop ebp` pattern
3. Adjusts base pointer for position-independent addressing
4. Calls `VirtualAlloc` (via resolved import at `[var_1c6h]`) to allocate RWX memory
5. Copies and decompresses the payload into allocated memory
6. Transfers execution to the decompressed code

```asm
│       ╎   0x01025a56      9c             pushfd
│       ╎   0x01025a57      60             pushal
│       ╎   0x01025a58      e800000000     call 0x1025a5d
│       ╎   0x01025a5d      5d             pop ebp
│       ╎   0x01025a5e      b807000000     mov eax, 7
│       ╎   0x01025a63      2be8           sub ebp, eax
```
(source: radare2, 0x01025a56)

The `call`/`pop ebp` at 0x01025a58-0x01025a5d is the `maldoc_getEIP_method_1` technique detected by YARA (source: yara, rule `maldoc_getEIP_method_1`, offset 27736). This confirms the packer uses position-independent code.

### Memory Allocation and Decompression

The stub allocates memory with `VirtualProtect` PAGE_EXECUTE_READWRITE (0x40) permissions, then calls the decompression routine (source: radare2, 0x01025aac-0x01025aba):

```asm
│     │ ╎   0x01025aac      6a40           push 0x40                   ; PAGE_EXECUTE_READWRITE
│     │ ╎   0x01025aae      6800100000     push 0x1000
│     │ ╎   0x01025ab3      6800100000     push 0x1000
│     │ ╎   0x01025ab8      6a00           push 0
│     │ ╎   0x01025aba      ff953afeffff   call dword [var_1c6h]
```
(source: radare2)

This calls `VirtualAlloc` with `MEM_COMMIT` and `PAGE_EXECUTE_READWRITE` permissions, allocating executable memory for the decompressed payload. The use of RWX permissions enables the unpacked code to run directly from allocated memory.

### Decompression Routine (LZ77/aPLib)

The function at EA 16932223 (recovered name: `lz77_decompress`, confidence 0.7) implements LZ77 decompression, reading a bitstream from compressed data and writing literals or back-references to decompressed output (source: recovered function names). The decompilation at EA 150911 (`sub_1025d7f`) shows the core decompression logic with carry-flag checking and back-reference copying (source: malcat, Decompilations).

```c
void sub_1025d7f(uint8_t *param_1, uint8_t *param_2)
{
    // ... bitstream reading with carry flag checks ...
    // Back-reference copy loop:
    for (; iVar5 != 0; iVar5 = iVar5 + -1) {
        *param_2 = *puVar4;
        puVar4 = puVar4 + 1;
        param_2 = param_2 + 1;
    }
}
```
(source: malcat, Decompilations, EA 150911)

The function at EA 16932360 (recovered name: `carry_check_loop`, confidence 0.4) repeatedly calls `sub_1025dfe` in a loop and uses CARRY4 to check for carry conditions, looping until no carry is detected (source: recovered function names). This is consistent with bitstream parsing in LZ77/aPLib decompression.

capa confirms aPLib decompression capability (source: malcat-capa):

| Rule | ATT&CK | MBC |
|---|---|---|
| decompress data using aPLib | - | C0025.003:Decompress Data |

### Import Address Table (IAT)

The binary imports 11 functions, many of which are associated with unpacking and dynamic resolution (source: malcat, Imports table):

| EA | Name | Type | Refs | Interpretation |
|---|---|---|---|---|
| 149636 | kernel32.LoadLibraryA | IMPORT | 1 | Dynamic library loading—used to resolve additional APIs at runtime |
| 149640 | kernel32.GetProcAddress | IMPORT | 0 | Dynamic function resolution—resolves API addresses by name |
| 149644 | kernel32.VirtualProtect | IMPORT | 0 | Memory permission changes—used to make decompressed code executable |
| 149648 | kernel32.VirtualAlloc | IMPORT | 0 | Memory allocation—allocates space for decompressed payload |
| 149652 | kernel32.VirtualFree | IMPORT | 0 | Memory deallocation—cleanup after unpacking |
| 149656 | kernel32.ExitProcess | IMPORT | 0 | Process termination |
| 149664 | shell32.ShellAboutW | IMPORT | 1 | Shell dialog—possibly used for masquerading as Calculator |
| 149672 | msvcrt.__CxxFrameHandler | IMPORT | 1 | C++ exception handling |
| 149680 | advapi32.RegOpenKeyExA | IMPORT | 1 | Registry access—potential persistence or configuration reading |
| 149688 | gdi32.SetBkColor | IMPORT | 1 | GDI drawing—GUI-related decoy or payload requirement |
| 149696 | user32.GetMenu | IMPORT | 1 | Menu retrieval—GUI-related decoy or payload requirement |

The import of `RegOpenKeyExA` (source: malcat, Imports EA 149680) indicates registry access capability. While this could be used for persistence (e.g., reading/writing Run keys), no specific registry key targets are visible in the static analysis. The `ShellAboutW` import is notable as it could display a fake "About" dialog to reinforce the Calculator masquerade.

The PE imports signals table maps these to MITRE ATT&CK techniques (source: pe_imports):

| Label | API Match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

### Function Metrics

Only 7 functions were identified statically by MalCat (source: malcat, Functions table), and Ghidra reports only 4 functions (source: verdict cross_engine_notes). This low function count is consistent with a packed binary where the real payload is compressed and not statically visible.

| EA | Name | Source |
|---|---|---|
| 27 | EntryPoint | malcat |
| 150102 | sub_1025a56 | malcat |
| 150911 | sub_1025d7f | malcat |
| 151070 | sub_1025e1e | malcat |
| 151038 | sub_1025dfe | malcat |
| 151048 | sub_1025e08 | malcat |
| 151066 | sub_1025e1a | malcat |

The main decompression function `sub_1025d7f` has cyclomatic complexity 18 with 27 basic blocks, indicating obfuscated control flow in the packer stub (source: deep_dive_agentic, key_evidence).

### Import Resolution Table (Disassembly)

The disassembly at `0x01025884` shows the import resolution area where the packer stores API addresses for dynamic resolution (source: radare2):

```asm
│           ;-- (0x01025888) GetProcAddress:
│           0x01025884  ~   9a590200a9..   lcall 0x259, 0xa9000259
│           ;-- VirtualProtect:
│           0x01025891      59             pop ecx
│           ;-- VirtualFree:
│           0x01025894      da5902         ficomp dword [ecx + 2]
│           ;-- ExitProcess:
│           0x01025899      59             pop ecx
│           ;-- ShellAboutW:
│           0x010258a0      f65902         neg byte [ecx + 2]
│           ;-- __CxxFrameHandler:
│           0x010258aa      0200           add al, byte [eax]
│           ;-- RegOpenKeyExA:
│           0x010258b0      185a02         sbb byte [edx + 2], bl
│           ;-- SetBkColor:
│           0x010258b9      5a             pop edx
│           ;-- GetMenu:
│           0x010258c0      355a020000     xor eax, 0x25a
```
(source: radare2, 0x01025884)

This area contains the resolved API addresses that the packer stub uses during unpacking. The addresses are filled in at runtime after `LoadLibraryA`/`GetProcAddress` resolution.

---

## 5. Behavioral & Dynamic Analysis

### Speakeasy Emulation

Speakeasy emulation completed successfully but recorded zero API calls and zero key events (source: speakeasy). This is expected for a packed binary—the emulator likely could not trigger the unpacking logic or the sample detected the emulation environment.

**Result: not observed** — no runtime behavior was captured.

### Frida Probe

Frida identified 10 hook candidates matching the imported APIs (source: frida_probe):

- `KERNEL32.DLL!LoadLibraryA`
- `KERNEL32.DLL!GetProcAddress`
- `KERNEL32.DLL!VirtualProtect`
- `KERNEL32.DLL!VirtualAlloc`
- `KERNEL32.DLL!VirtualFree`
- `SHELL32.DLL!ShellAboutW`
- `MSVCRT.DLL!__CxxFrameHandler`
- `ADVAPI32.DLL!RegOpenKeyExA`
- `GDI32.DLL!SetBkColor`
- `USER32.DLL!GetMenu`

These are the APIs the packer stub would call during unpacking. No actual runtime hooking was performed; these are candidates for dynamic analysis.

### UPX Analysis

UPX analysis returned `upx_ok: False`, `is_packed: False` (source: upx). This confirms the sample is NOT packed with UPX but with nSpack, a different packer. The UPX tool correctly identified that its own unpacking methods are not applicable.

---

## 6. Network Indicators & C2

### YARA Network Indicators

YARA rules detected potential network-related patterns (source: yara):

| Rule | Match Offset | Length | Interpretation |
|---|---|---|---|
| IP | 3242 | 7 | IPv4 address pattern detected |
| IP | 6033 | 2 | IPv6 address pattern detected |
| domain | 0 | 2 | Domain regex pattern detected |

The `IP` rule match at offset 3242 with length 7 suggests an embedded IPv4 address. However, without runtime unpacking, we cannot determine if this IP is part of the packer stub, a decoy, or the actual C2 infrastructure. The match could also be a false positive from compressed/encrypted data that coincidentally matches the pattern.

### YARA Registry Indicators

The `win_registry` rule matched at offsets 27512 and 27674 (source: yara), indicating the binary contains registry-related strings or code patterns. Combined with the `RegOpenKeyExA` import (source: malcat, Imports EA 149680), this suggests the sample may interact with the Windows registry, potentially for persistence or configuration. However, the specific registry keys targeted are not visible in the static analysis.

### YARA Base64 Indicator

The `contains_base64` rule matched at offset 3112 with length 16 (source: yara), suggesting the binary contains base64-encoded data. This could be encoded configuration, C2 addresses, or other embedded data that is decoded at runtime.

### Assessment

No definitive C2 communication was observed. The IP, domain, and base64 matches are present in the packed data and may be part of the compressed payload that is only accessible after runtime unpacking. Without dynamic execution, we cannot confirm whether these indicators represent actual C2 infrastructure.

---

## 7. Capabilities Assessment

### Observed Capabilities (Static Evidence)

| Capability | Evidence | Source | Confidence |
|---|---|---|---|
| Packing/Obfuscation | nSpack v2.x signatures, `!packed by nspack$@` string, RWX sections | yara, floss, malcat | High |
| aPLib Decompression | capa rule `decompress data using aPLib` (C0025.003) | malcat-capa | High |
| Dynamic API Resolution | `LoadLibraryA` and `GetProcAddress` imports | malcat | High |
| Memory Manipulation | `VirtualAlloc`, `VirtualProtect`, `VirtualFree` imports | malcat | High |
| Registry Access | `RegOpenKeyExA` import, `win_registry` YARA match | malcat, yara | Medium |
| Masquerading | Forged Microsoft Calculator version info | malcat | High |
| Position-Independent Code | `maldoc_getEIP_method_1` YARA match, call/pop EIP pattern | yara, radare2 | High |

### Latent Capabilities (Present but Not Observed in Action)

| Capability | Evidence | Source | Assessment |
|---|---|---|---|
| C2 Communication | IP/domain YARA matches in packed data | yara | Cannot confirm without unpacking |
| Persistence | `RegOpenKeyExA` import, registry YARA matches | malcat, yara | Possible but not observed |
| Credential Access | No credential APIs detected | analysis | Not observed |
| Data Exfiltration | No exfiltration patterns detected | analysis | Not observed |
| Defense Evasion | RWX sections, dynamic resolution | malcat | Likely (evasion of static analysis) |

### What the Packer Does

The nSpack packer stub performs the following sequence:
1. Saves CPU state and obtains EIP for position-independent addressing
2. Resolves `VirtualAlloc` and other APIs dynamically
3. Allocates RWX memory for the decompressed payload
4. Uses aPLib/LZ77 decompression to extract the hidden payload
5. Transfers execution to the decompressed code

The actual payload—whether malicious or benign—is hidden inside the compressed `nsp1` section and is only revealed at runtime.

---

## 8. Indicators of Compromise

### File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | `2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5` | malcat |
| Imphash | `4ddd9e53a5be88aaffc4455bfc877c19` | rule.yara.json |
| File Name | `nspack.exe` | malcat |
| Packer String | `!packed by nspack$@` | floss |
| Version Info | `Microsoft Windows Calculator` v5.1.2600.0 | malcat |

### YARA Signatures

| Rule | Namespace | Match Details | Source |
|---|---|---|---|
| nSpackV2xLiuXingPing | - | `$a0@27734 len=17` | yara |
| NsPackV2XLiuXingPing | - | `$a0@53 len=8` | yara |
| NsPackv23NorthStar | - | `$a0@27734 len=85; $a1@27734 len=141` | yara |
| maldoc_getEIP_method_1 | - | `$a@27736 len=6` | yara |
| win_registry | - | `$f1@27512 len=12; $c2@27674 len=13` | yara |
| IP | - | `$ipv4@3242 len=7; $ipv6@6033 len=2` | yara |
| contains_base64 | - | `$a@3112 len=16` | yara |
| domain | - | `$domain_regex@0 len=2` | yara |
| IsPE32 | - | (structural) | yara |
| IsWindowsGUI | - | (structural) | yara |
| HasModified_DOS_Message | - | (structural) | yara |
| suspicious_packer_section | - | (structural) | yara |

### MalCat Signatures

| Rule | Category | Type | Reliability | Source |
|---|---|---|---|---|
| MSVC_2002_linker | compiler | INFO | 60 | malcat |
| nspack_23_02 | packer | INFO | 50 | malcat |
| nspack_23_03 | packer | INFO | 50 | malcat |

### Network IOCs (Unconfirmed)

| Type | Offset | Length | Source | Note |
|---|---|---|---|---|
| IPv4 pattern | 3242 | 7 | yara | In packed data; requires unpacking to confirm |
| IPv6 pattern | 6033 | 2 | yara | In packed data; requires unpacking to confirm |
| Domain pattern | 0 | 2 | yara | In packed data; requires unpacking to confirm |
| Base64 data | 3112 | 16 | yara | In packed data; requires unpacking to confirm |

---

## 9. Detection Engineering

### YARA Rule (Generated)

A YARA rule was generated for this sample (source: rule.yara.json). Key strings for detection:

```
!packed by nspack$@
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
name="Microsoft.Windows.Shell.calc"
```

The rule targets the nSpack packer signature, the forged Calculator manifest, and structural characteristics.

### Detection Recommendations

1. **Packer Detection:** Monitor for executables with `nsp0`/`nsp1` section names and RWX permissions. The combination of non-standard section names with write+execute permissions is a strong packing indicator.

2. **String-Based Detection:** The string `!packed by nspack$@` is a reliable indicator of nSpack packing. Combine with forged version info (e.g., Calculator metadata on non-Calculator binaries) for higher confidence.

3. **Behavioral Detection:** Monitor for `VirtualAlloc` with `PAGE_EXECUTE_READWRITE` followed by `VirtualProtect` calls, which indicate unpacking activity. The sequence of `LoadLibraryA` -> `GetProcAddress` -> `VirtualAlloc` -> `VirtualProtect` is characteristic of packer stubs.

4. **Import Anomaly Detection:** Flag executables where more than half of imports are unreferenced statically (source: malcat, `UnreferencedImports` anomaly), as this indicates dynamic resolution.

5. **Sigma Rule:** A Sigma rule was generated at `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yml` (source: rule.yara.json).

---

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence | Source |
|---|---|---|---|
| Defense Evasion | T1027 - Obfuscated Files or Information | nSpack packing, high entropy, compressed payload | yara, malcat, packer_intake |
| Defense Evasion | T1027.002 - Software Packing | nSpack v2.x packer detected | yara, floss, malcat |
| Defense Evasion | T1055 - Process Injection | `VirtualAlloc`, `VirtualProtect` for RWX memory | pe_imports |
| Defense Evasion | T1140 - Deobfuscate/Decode Files or Information | aPLib decompression routine | malcat-capa |
| Discovery | T1129 - Shared Modules | `LoadLibraryA`, `GetProcAddress` for dynamic loading | pe_imports |
| Persistence | (Potential) | `RegOpenKeyExA` import, `win_registry` YARA match | malcat, yara |
| Execution | T1106 - Native API | Dynamic API resolution via `GetProcAddress` | pe_imports |

Note: The Persistence mapping is speculative—`RegOpenKeyExA` could be used for reading configuration rather than writing persistence keys. Without runtime evidence, we cannot confirm persistence behavior.

---

## 11. What We Don't Know

1. **Actual Payload Content:** The real payload is compressed inside the `nsp1` section and only accessible after runtime unpacking. We cannot determine whether the payload is malicious, benign, or a legitimate application protected with nSpack.

2. **C2 Infrastructure:** YARA detected IP and domain patterns in the packed data, but these cannot be confirmed as actual C2 addresses without unpacking and runtime analysis.

3. **Persistence Mechanism:** The `RegOpenKeyExA` import suggests registry access, but the specific keys and operations (read vs. write) are unknown without dynamic analysis.

4. **Runtime Behavior:** Speakeasy emulation recorded zero events. The sample may have anti-emulation checks, or the emulation environment did not trigger the unpacking logic. True runtime behavior remains unobserved.

5. **Payload Intent:** Without unpacking, we cannot determine if this is a legitimate nSpack-protected application, a cracked game, a trojanized Calculator, or a completely different payload masquerading as Calculator.

6. **Anti-Analysis Techniques:** The sample may contain anti-debugging, anti-VM, or anti-sandbox techniques that were not triggered during static analysis. The RWX sections and dynamic resolution could be part of such techniques.

7. **Network Communication:** No network traffic was observed. The IP/domain indicators may be false positives from compressed data, or they may represent actual C2 infrastructure that only activates under specific conditions.

8. **Ghidra Function Count Discrepancy:** Ghidra reports 4 functions while MalCat reports 7. This discrepancy is likely due to packing obfuscation affecting function boundary detection differently across tools (source: verdict cross_engine_notes).

---

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used

| Tool | Version/Status | Result | Source |
|---|---|---|---|
| MalCat | Active | Full analysis with sections, imports, anomalies, YARA | malcat |
| YARA (Pipeline) | Active | 12 rule matches | yara |
| FLOSS | Active | 169 strings extracted | floss |
| capa (malcat-capa) | Active | 1 rule matched | malcat-capa |
| radare2 | Active | Disassembly of entry point and packer stub | radare2 |
| Ghidra | Active | Function analysis, cross-references | ghidra_query |
| IDA | Active | String extraction, function analysis | ida_query |
| Speakeasy | Active | 0 API calls (not observed) | speakeasy |
| Frida | Active | 10 hook candidates identified | frida_probe |
| UPX | Active | Not UPX packed | upx |
| XOR Search | Active | XOR 00 at position 0 | xor |
| .NET Analysis | Active | Not .NET | dotnet |
| Packer Intake | Active | Packed label with high entropy | packer_intake |
| LLM Judge (mimo-v2.5-pro) | Active | Suspicious verdict, score 50 | llm_judge |
| Deep Dive Agentic | Active | Malicious verdict, confidence 90 | deep_dive_agentic |
| Agentic Recover v4 | Active | 2 functions recovered | agentic_recover_v4 |

### Key Evidence Citations

| Claim | Source | Evidence |
|---|---|---|
| nSpack packing | yara | `nSpackV2xLiuXingPing` rule match at offset 27734 |
| nSpack packing | floss | String `!packed by nspack$@` |
| nSpack packing | malcat | `Packed×2` anomaly, `nspack_23_02`/`nspack_23_03` signatures |
| Forged Calculator metadata | malcat | Version info strings at EA 124648-125280 |
| aPLib decompression | malcat-capa | Rule `decompress data using aPLib` (C0025.003) |
| RWX sections | malcat | `nsp0` and `nsp1` both have RWX permissions |
| Dynamic API resolution | malcat | `LoadLibraryA` and `GetProcAddress` imports |
| Registry access | malcat | `RegOpenKeyExA` import at EA 149680 |
| Position-independent code | yara | `maldoc_getEIP_method_1` match at offset 27736 |
| IP address pattern | yara | `IP` rule match at offset 3242 |
| Base64 data | yara | `contains_base64` match at offset 3112 |
| Registry patterns | yara | `win_registry` matches at offsets 27512, 27674 |

### Audit Trail (Recent)

The following Ghidra and IDA queries were executed during analysis (source: audit trail):

- `ghidra_query`: Function analysis for addresses 16932350-16932378, 16932223-16932354
- `ghidra_query`: String cross-reference analysis
- `ghidra_query`: Call edge analysis for function relationships
- `ghidra_query`: Pseudocode generation for recovered functions
- `ida_query`: String extraction (80 longest strings)
- `agentic_recover_v4`: LLM-based function name recovery (2 functions recovered)
- `yara_gen_v2`: YARA rule generation

---

## 13. Appendix B: Analysis Environment

| Component | Details |
|---|---|
| Sample Path | `/opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe` |
| Project | Hexorcist 1 - Weeks 1-8 |
| Analysis Framework | RevAI (langgraph engine) |
| LLM Model | mimo-v2.5-pro |
| Frida Version | 17.16.4 |
| YARA Rule Path | `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yar` |
| Sigma Rule Path | `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yml` |
| IOCs Path | `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/iocs.json` |
| Analysis Date | 2026-08-09 |
| Tool Gate | All required tools passed (capa, yara, floss, pe_imports, malcat, r2_decomp, upx, xor, speakeasy, frida_probe, dotnet) |

### Verdict Disagreement Note

The LLM Judge (mimo-v2.5-pro) assessed the sample as **Suspicious (score 50)**, while the Deep Dive Agentic analysis assessed it as **Malicious (confidence 90)**. The disagreement stems from different interpretations of the evidence:

- **LLM Judge (Suspicious):** The sample shows packing and obfuscation but lacks definitive behavioral-intent evidence. Packing alone is a neutral signal.
- **Deep Dive (Malicious):** The combination of masquerading (Calculator), registry access, RWX sections, and dynamic resolution suggests hostile intent, even without observed runtime behavior.

The Suspicious verdict is more conservative and appropriate given the VERDICT CALIBRATION rules: obfuscation/packing are neutral signals that appear identically in benign software. Without behavioral-intent evidence (C2, data destruction, credential theft, persistence confirmation), the sample cannot be classified as definitively malicious.

---
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5  
**sample_path:** /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe  
**project_name:** Hexorcist 1 - Weeks 1-8

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 50
- **family_guess**: nSpack
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Multiple tools (packer_intake, yara, floss, malcat) consistently identify nSpack packing. Ghidra reports fewer functions and strings (4 vs 7 in IDA) due to packing obfuscation, while IDA and MalCat agree on imports including memory manipulation APIs. No clear behavioral-intent evidence (e.g., C2, data destruction) is found across engines.
- **summary**: The sample is packed with nSpack, evidenced by YARA signatures, floss strings, and packer analysis, with high entropy and section anomalies. It imports APIs for dynamic loading and memory protection (e.g., LoadLibraryA, VirtualProtect), but no overt malicious behavior like C2 communication or data destruction is detected. Thus, it is classified as suspicious, likely a packed executable without clear hostile intent.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| packer_intake | label | `packed` | Deterministic analysis flags the sample as packed with high entropy exec sections (e.g., nsp1 entropy 6.961), section mi |
| yara | - | `nSpackV2xLiuXingPing rule match` | YARA rule specifically detects nSpack packer signature, confirming the packer identification. |
| floss | - | `!packed by nspack$@` | String explicitly states 'packed by nspack', providing direct evidence of nSpack packing. |
| pe_imports | - | `load_library (LoadLibraryA) with attack T1129` | Import of LoadLibraryA enables dynamic library loading, a common technique in packed and potentially malicious code for  |
| malcat | - | `Packed×2` | MalCat detects multiple packing anomalies, reinforcing the obfuscation indication from other tools. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE executable packed with nSpack v2.x that masquerades as Windows Calculator (calc.exe). The binary uses forged Microsoft Corporation version info to disguise itself. It contains aPLib decompression routines, VirtualAlloc/VirtualProtect for memory manipulation, dynamic API resolution via LoadLibraryA/GetProcAddress, and registry access (RegOpenKeyExA). Both code sections (nsp0/nsp1) have RWX permissions indicating self-modifying unpacking code. YARA rules detect embedded IP addresses, registry keys, base64-encoded data, and position-independent code techniques. The actual malicious payload is compressed/encrypted and only revealed at runtime after unpacking. Persistence mechanisms were not observed {analysis tools, behavior monitoring, no persistence indicators, lacking registry key modifications for auto-start}. Exfiltration techniques were not identified {analysis tools, network traffic analysis, no exfiltration patterns, missing data transfer calls}. Defense impairment is suggested by RWX code sections {disassembly analysis, section attributes, nsp0/nsp1 with RWX, enables self-modifying code to evade detection} and dynamic API resolution {API hooking analysis, LoadLibraryA/GetProcAddress calls, hinders static analysis and signature-based detection}. Credential access methods were not observed {analysis tools, API call tracing, no credential access APIs, lacking functions like CryptUnprotectData or token manipulation}.

### deep key_evidence
- `"YARA rules nSpackV2xLiuXingPing and NsPackv23NorthStar matched; string '!packed by nspack$@' at file offset confirms nSpack v2.x packer"`
- `"Version info masquerades as 'Microsoft Windows Calculator' (CALC.EXE) v5.1.2600.0 by Microsoft Corporation \u2014 forged metadata on a packed binary"`
- `"Imports include VirtualAlloc, VirtualFree, VirtualProtect, LoadLibraryA, GetProcAddress, RegOpenKeyExA \u2014 APIs associated with unpacking, dynamic resolution, and registry access"`
- `"capa detected 'decompress data using aPLib' (C0025.003) \u2014 the packer uses aPLib to decompress the hidden payload at runtime"`
- `"Sections nsp0 (122880 bytes) and nsp1 (61520 bytes) both have RWX permissions (is_read=1, is_write=1, is_exec=1) \u2014 classic self-modifying code indicator"`
- `"YARA win_registry rule hit at offsets 27512 and 27674; IP rule hit at offset 3242; contains_base64 hit at offset 3112; maldoc_getEIP_method_1 hit at offset 27736"`
- `"Main function FUN_01025d7f has cyclomatic complexity 18 with 27 basic blocks indicating obfuscated control flow in the packer stub"`
- `"Only 4 functions identified statically \u2014 the real payload is hidden inside the compressed nsp1 section and not accessible without runtime unpacking"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
size: 55021
type: PE
architecture: X86
entrypoint_ea: 27
entropy: 52
file_name: nspack.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| nsp0 | 0 | 512 | 122880 | 52 | RWX |
| nsp1 | 122880 | 54509 | 65536 | 0 | RWX |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2002_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| nspack_23_02 | packer | INFO | 50 |  |
| nspack_23_03 | packer | INFO | 50 |  |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 2 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| PointerToRawDataNotAligned | 4 | sections | 1 | PointerToRawData is not aligned to FileAlignment |
| SizeOfRawDataNotAligned | 4 | sections | 2 | SizeOfRawData is not aligned to FileAlignment |
| UnsignedMicrosoft | 4 | integrity | 3 | Version information tells us it is a microsoft file but no certificate has been found |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 11 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| InvalidSizeOfUninitializedData | 2 | sections | 1 | SizeOfUninitializedData is not the sum of all uninitalized data sections (raw or virtual) |
| Packed | 2 | packers | 2 | File is packed using a legit or less-legit obfuscator |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `156`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 149844 | `KERNEL32.DLL` |
| 149931 | `GetProcAddress` |
| 149916 | `LoadLibraryA` |
| 149948 | `VirtualProtect` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 125372 | `<?xml version="1..>
</assembly>
` |
| 149880 | `ADVAPI32.DLL` |
| 149857 | `SHELL32.DLL` |
| 149844 | `KERNEL32.DLL` |
| 149893 | `GDI32.DLL` |
| 149903 | `USER32.DLL` |
| 149869 | `MSVCRT.DLL` |
| 124986 | ` Microsoft Corpo..rights reserved.` |
| 124732 | `Windows Calculat..application file` |
| 125116 | `CALC.EXE` |
| 124836 | `5.1.2600.0 (xpcl..ent.010817-1148)` |
| 124648 | `Microsoft Corporation` |
| 124470 | `VS_VERSION_INFO` |
| 124598 | `040904B0` |
| 125082 | `OriginalFilename` |
| 125280 | `5.1.2600.0` |
| 126338 | ```````` |
| 126402 | ```````` |
| 126912 | `fDDDDDD@offffff@n`` |
| 126274 | ``````` |
| 126951 | `@offffff@n` |
| 129984 | `xrssssvvvv` |
| 126290 | `opopopopowwpf@` |
| 130032 | `^zwurqqqqqsssssvvvv;` |
| 124910 | `InternalName` |
| 130367 | `YYYYXXV` |
| 124698 | `FileDescription` |
| 126934 | `p@offffff@n`` |
| 126522 | `fffff@` |
| 126498 | ``wwwwwwwfffff@` |
| 126490 | `fffff@` |
| 126466 | ``wwwwwwwfffff@` |
| 126354 | `opopopopopopf@` |
| 126418 | `opopopopopopf@` |
| 125250 | `ProductVersion` |
| 124562 | `StringFileInfo` |
| 124810 | `FileVersion` |
| 126993 | `ffffffa` |
| 124622 | `CompanyName` |
| 130429 | `XXXXXVX` |
| 126241 | `dDDDDDDDDDDDDD@` |
| 125342 | `Translation` |
| 124936 | `CALC` |
| 125206 | ` Operating System` |
| 126962 | `wwwff@o` |
| 124954 | `LegalCopyright` |
| 126545 | `ffffffffffffffa` |
| 126450 | `fffffffffffff@` |
| 126386 | `fffffffffffff@` |
| 126322 | `fffffffffffff@` |
| 126258 | `fffffffffffff@` |
| 125168 | `Microsoft` |
| 150022 | `__CxxFrameHandler` |
| 130083 | `^;LLZZzxxwtrqqrZ` |
| 132740 | `edddc` |
| 129755 | `hbbbe` |
| 149931 | `GetProcAddress` |
| 128154 | `B--B5J` |
| 125142 | `ProductName` |
| 128560 | `6=cc=4` |
| 130140 | `f^NLLL` |
| 125310 | `VarFileInfo` |
| 149916 | `LoadLibraryA` |
| 149948 | `VirtualProtect` |
| 143587 | `988` |
| 129265 | `MM8L` |
| 173184 | `RGGI` |
| 128935 | `>887` |
| 128784 | `]::9` |
| 171181 | `MQ5Q` |
| 172848 | `BtqB` |
| 126981 | `ff@o` |
| 176988 | `X^h^` |
| 126973 | `ff@n` |
| 156950 | `A<<` |
| 152223 | `@9A@` |
| 163075 | `Gt`t` |
| 163322 | `FX-F` |
| 149965 | `VirtualAlloc` |
| 149980 | `VirtualFree` |

### Imports (11)
| EA | Name | Type | Refs |
|---|---|---|---|
| 149636 | kernel32.LoadLibraryA | IMPORT | 1 |
| 149640 | kernel32.GetProcAddress | IMPORT | 0 |
| 149644 | kernel32.VirtualProtect | IMPORT | 0 |
| 149648 | kernel32.VirtualAlloc | IMPORT | 0 |
| 149652 | kernel32.VirtualFree | IMPORT | 0 |
| 149656 | kernel32.ExitProcess | IMPORT | 0 |
| 149664 | shell32.ShellAboutW | IMPORT | 1 |
| 149672 | msvcrt.__CxxFrameHandler | IMPORT | 1 |
| 149680 | advapi32.RegOpenKeyExA | IMPORT | 1 |
| 149688 | gdi32.SetBkColor | IMPORT | 1 |
| 149696 | user32.GetMenu | IMPORT | 1 |

### Functions (7)
| EA | Name |
|---|---|
| 27 | EntryPoint |
| 150102 | sub_1025a56 |
| 150911 | sub_1025d7f |
| 151070 | sub_1025e1e |
| 151038 | sub_1025dfe |
| 151048 | sub_1025e08 |
| 151066 | sub_1025e1a |

### Decompilations (top 6)
#### 27 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```
#### 150102 — sub_1025a56
```c
sub_1025a56 {
    // Error while decompiling : not a valid ea
}

```
#### 150911 — sub_1025d7f
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1025d7f(uint8_t *param_1,uint8_t *param_2)

{
    char cVar1;
    undefined4 uVar3;
    uint8_t *puVar4;
    int32_t extraout_ECX;
    int32_t extraout_ECX_00;
    int32_t extraout_ECX_01;
    int32_t extraout_ECX_02;
    int32_t extraout_ECX_03;
    int32_t iVar5;
    uint8_t *puVar6;
    undefined in_CF;
    bool bVar7;
    uint8_t uVar8;
    uint8_t uVar2;
    
    do {
        puVar6 = param_1 + 1;
        *param_2 = *param_1;
        param_2 = param_2 + 1;
        while (sub_1025dfe(), param_1 = puVar6, in_CF) {
            bVar7 = false;
            sub_1025dfe();
            if (bVar7) {
                uVar8 = false;
                uVar3 = sub_1025dfe();
                if (!uVar8) {
                    puVar4 = CONCAT31(uVar3 >> 8, *puVar6) >> 1;
                    if (puVar4 == 0x0) {
                        return;
                    }
                    iVar5 = extraout_ECX + 2 + ((*puVar6 & 1) != 0);
                    puVar6 = puVar6 + 1;
                    goto code_r0x01025df4;
                }
                do {
                    uVar3 = sub_1025dfe();
                    uVar2 = uVar3;
                    bVar7 = CARRY1(uVar2 * '\x02', uVar8);
                    in_CF = CARRY1(uVar2, uVar2) || bVar7;
                    cVar1 = uVar2 * '\x02' + uVar8;
                    puVar4 = CONCAT31(uVar3 >> 8, cVar1);
                    uVar8 = in_CF;
                } while (!CARRY1(uVar2, uVar2) && !bVar7);
                iVar5 = extraout_ECX_00;
                if (cVar1 != '\0') goto code_r0x01025df3;
                *param_2 = 0;
                param_2 = param_2 + 1;
            }
            else {
                func_0x01025e0a();
                if (extraout_ECX_01 == 2) {
                    puVar4 = sub_1025e08();
                    iVar5 = extraout_ECX_02;
                }
                else {
                    puVar6 = puVar6 + 1;
                    puVar4 = sub_1025e08();
                    if (puVar4 < 0x7d00) {
                        iVar5 = extraout_ECX_03;
                        if (0x4ff < puVar4) goto code_r0x01025df3;
                        if (0x7f < puVar4) goto code_r0x01025df4;
                    }
                    iVar5 = extraout_ECX_03 + 1;
code_r0x01025df3:
                    iVar5 = iVar5 + 1;
                }
code_r0x01025df4:
                in_CF = param_2 < puVar4;
                puVar4 = param_2 + -puVar4;
                for (; iVar5 != 0; iVar5 = iVar5 + -1) {
                    *param_2 = *puVar4;
                    puVar4 = puVar4 + 1;
                    param_2 = param_2 + 1;
                }
            }
        }
    } while( true );
}

```

### Carved Files (8)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

### Virtual Files (11)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 744 | - |
| ICO/2/en-us | 296 | - |
| ICO/3/en-us | 3752 | - |
| ICO/4/en-us | 2216 | - |
| ICO/5/en-us | 1384 | - |
| ICO/6/en-us | 9640 | - |
| ICO/7/en-us | 4264 | - |
| ICO/8/en-us | 1128 | - |
| GRPICO/SC/en-us | 118 | - |
| VER/1/en-us | 908 | - |
| MANIF/1/en-us | 667 | - |

### Structures (85)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 64 |
| OptionalHeader | 88 |
| Sections | 312 |
| Resources | 122880 |
| Resources.ICO | 122960 |
| Resources.ICO.1 | 123040 |
| Resources.ICO.1.en-us | 123064 |
| Resources.ICO.2 | 123080 |
| Resources.ICO.2.en-us | 123104 |
| Resources.ICO.3 | 123120 |
| Resources.ICO.3.en-us | 123144 |
| Resources.ICO.4 | 123160 |
| Resources.ICO.4.en-us | 123184 |
| Resources.ICO.5 | 123200 |
| Resources.ICO.5.en-us | 123224 |
| Resources.ICO.6 | 123240 |
| Resources.ICO.6.en-us | 123264 |
| Resources.ICO.7 | 123280 |
| Resources.ICO.7.en-us | 123304 |
| Resources.ICO.8 | 123320 |
| Resources.ICO.8.en-us | 123344 |
| Resources.MENU | 123360 |
| Resources.MENU.106 | 123408 |
| Resources.MENU.106.en-us | 123432 |
| Resources.MENU.107 | 123448 |
| Resources.MENU.107.en-us | 123472 |
| Resources.MENU.108 | 123488 |
| Resources.MENU.108.en-us | 123512 |
| Resources.MENU.109 | 123528 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.82

| Rule | ATT&CK | MBC |
|---|---|---|
| decompress data using aPLib |  | C0025.003:Decompress Data |

## PE Imports / Signals
import_count: 11

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3242 len=7; $ipv6@6033 len=2 |
| contains_base64 | - | $a@3112 len=16 |
| nSpackV2xLiuXingPing | - | $a0@27734 len=17 |
| NsPackV2XLiuXingPing | - | $a0@53 len=8 |
| NsPackv23NorthStar | - | $a0@27734 len=85; $a1@27734 len=141 |
| maldoc_getEIP_method_1 | - | $a@27736 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasModified_DOS_Message | - |  |
| suspicious_packer_section | - |  |
| win_registry | - | $f1@27512 len=12; $c2@27674 len=13 |

## Generated YARA Meta
```json
{
  "sha256": "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5",
  "family": "nSpack",
  "imphash": "4ddd9e53a5be88aaffc4455bfc877c19",
  "generated_at": "2026-08-09T14:40:33.656928+00:00",
  "string_count": 24,
  "strings": [
    "!packed by nspack$@",
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>",
    "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">",
    "<assemblyIdentity",
    "name=\"Microsoft.Windows.Shell.calc\"",
    "processorArchitecture=\"x86\"",
    "version=\"5.1.0.0\"",
    "type=\"win32\"/>",
    "<description>Windows Shell</description>",
    "<dependency>",
    "<dependentAssembly>",
    "type=\"win32\"",
    "name=\"Microsoft.Windows.Common-Controls\"",
    "version=\"6.0.0.0\"",
    "publicKeyToken=\"6595b64144ccf1df\"",
    "language=\"*\"",
    "</dependentAssembly>",
    "</dependency>",
    "</assembly>",
    "dDDDDDDDDDDDDD@",
    "fffffffffffff@",
    "opopopopowwpf@",
    "opopopopopopf@",
    "`wwwwwwwfffff@"
  ],
  "rule_path": "/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yar",
  "sigma_path": "/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yml",
  "iocs_path": "/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/iocs.json",
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
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 14:40:33 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 169 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 169}`

### High-signal FLOSS
- `KERNEL32.DLL`
- `LoadLibraryA`
- `GetProcAddress`
- `VirtualProtect`

### FLOSS sample
- `!packed by nspack$@`
- `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
- `<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">`
- `<assemblyIdentity`
- `name="Microsoft.Windows.Shell.calc"`
- `processorArchitecture="x86"`
- `version="5.1.0.0"`
- `type="win32"/>`
- `<description>Windows Shell</description>`
- `<dependency>`
- `<dependentAssembly>`
- `type="win32"`
- `name="Microsoft.Windows.Common-Controls"`
- `version="6.0.0.0"`
- `publicKeyToken="6595b64144ccf1df"`
- `language="*"`
- `</dependentAssembly>`
- `</dependency>`
- `</assembly>`
- `dDDDDDDDDDDDDD@`
- `fffffffffffff@`
- `opopopopowwpf@`
- `opopopopopopf@`
- ``wwwwwwwfffff@`
- `fffff@`
- `ffffffffffffffa`
- `fDDDDDD@offffff@n``
- `p@offffff@n``
- `@offffff@n`
- `wwwff@o`
- `ffffffa`
- `B--B5J`
- `|||ddcO87`
- `c||cO87`
- `=||ccOM7`
- `6=cc=4`
- ``NfOM79|?4`
- ``~bbbi`
- `xrssssvvvv`
- `^zwurqqqqqsssssvvvv;`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0100101b
```asm
┌ 5: entry0 ();
└       ┌─< 0x0100101b      e9364a0200     jmp fcn.01025a56
```
### 0x01025a56
```asm
╎   ; CODE XREF from entry0 @ 0x100101b(x)
├ 648: fcn.01025a56 ();
│       ╎   ; var int32_t var_1beh @ ebp-0x1be
│       ╎   ; var int32_t var_1c2h @ ebp-0x1c2
│       ╎   ; var int32_t var_1c6h @ ebp-0x1c6
│       ╎   ; var int32_t var_1cah @ ebp-0x1ca
│       ╎   ; var int32_t var_1fah @ ebp-0x1fa
│       ╎   ; var int32_t var_202h @ ebp-0x202
│       ╎   ; var int32_t var_212h @ ebp-0x212
│       ╎   ; var int32_t var_22ah @ ebp-0x22a
│       ╎   ; var int32_t var_23eh @ ebp-0x23e
│       ╎   ; var int32_t var_246h @ ebp-0x246
│       ╎   ; var int32_t var_26eh @ ebp-0x26e
│       ╎   ; var int32_t var_27eh @ ebp-0x27e
│       ╎   0x01025a56      9c             pushfd
│       ╎   0x01025a57      60             pushal
│       ╎   0x01025a58      e800000000     call 0x1025a5d
│       ╎   ; CALL XREF from fcn.01025a56 @ 0x1025a58(x)
│       ╎   0x01025a5d      5d             pop ebp
│       ╎   0x01025a5e      b807000000     mov eax, 7
│       ╎   0x01025a63      2be8           sub ebp, eax
│       ╎   0x01025a65      8db5d6fdffff   lea esi, [var_22ah]
│       ╎   0x01025a6b      8b06           mov eax, dword [esi]
│       ╎   0x01025a6d      83f800         cmp eax, 0
│      ┌──< 0x01025a70      7411           je 0x1025a83
│      │╎   0x01025a72  ~   8db5fefdffff   lea esi, [var_202h]
..
│      │╎   0x01025a78      8b06           mov eax, dword [esi]
│      │╎   0x01025a7a      83f801         cmp eax, 1                  ; 1
│     ┌───< 0x01025a7d      0f844b020000   je 0x1025cce
│     │└──> 0x01025a83  ~   c70601000000   mov dword [esi], 1
..
│     │ ╎   0x01025a89      8bd5           mov edx, ebp
│     │ ╎   0x01025a8b      8b8592fdffff   mov eax, dword [var_26eh]
│     │ ╎   0x01025a91      2bd0           sub edx, eax
│     │ ╎   0x01025a93      899592fdffff   mov dword [var_26eh], edx
│     │ ╎   0x01025a99      0195c2fdffff   add dword [var_23eh], edx
│     │ ╎   0x01025a9f      8db506feffff   lea esi, [var_1fah]
│     │ ╎   0x01025aa5      0116           add dword [esi], edx
│     │ ╎   0x01025aa7      8b36           mov esi, dword [esi]
│     │ ╎   0x01025aa9      8bfd           mov edi, ebp
│     │ ╎   0x01025aab      60             pushal
│     │ ╎   0x01025aac      6a40           push 0x40                   ; pe_nt_image_headers32
│     │ ╎   0x01025aae      6800100000     push 0x1000
│     │ ╎   0x01025ab3      6800100000     push 0x1000
│     │ ╎   0x01025ab8      6a00           push 0
│     │ ╎   0x01025aba      ff953afeffff   call dword [var_1c6h]
│     │ ╎   0x01025ac0      85c0           test eax, eax
│     │┌──< 0x01025ac2      0f8456030000   je 0x1025e1e
│     ││╎   0x01025ac8      8985bafdffff   mov dword [var_246h], eax
│     ││╎   0x01025ace      e800000000     call 0x1025ad3
│     ││╎   ; CALL XREF from fcn.01025a56 @ 0x1025ace(x)
│     ││╎   0x01025ad3      5b             pop ebx
│     ││╎   0x01025ad4      b954030000     mov ecx, 0x354              ; 852
│     ││╎   0x01025ad9      03d9           add ebx, ecx
│     ││╎   0
```
### 0x01025884
```asm
│           ;-- (0x01025888) GetProcAddress:
┌ 532: sym.imp.KERNEL32.DLL_LoadLibraryA (int32_t arg_53h, int32_t arg_59h, int32_t arg_78h);
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_59h @ ebp+0x59
│           ; arg int32_t arg_78h @ ebp+0x78
│           ; var int32_t var_48h @ ebp-0x48
│           ; var int32_t var_1beh @ ebp-0x1be
│           ; var int32_t var_1c2h @ ebp-0x1c2
│           ; var int32_t var_1c6h @ ebp-0x1c6
│           ; var int32_t var_1cah @ ebp-0x1ca
│           ; var int32_t var_1fah @ ebp-0x1fa
│           ; var int32_t var_202h @ ebp-0x202
│           ; var int32_t var_212h @ ebp-0x212
│           ; var int32_t var_22ah @ ebp-0x22a
│           ; var int32_t var_23eh @ ebp-0x23e
│           ; var int32_t var_246h @ ebp-0x246
│           ; var int32_t var_26eh @ ebp-0x26e
│           ; var int32_t var_27eh @ ebp-0x27e
│           0x01025884  ~   9a590200a9..   lcall 0x259, 0xa9000259
│           0x0102588b  ~   00ba590200cb   add byte [edx - 0x34fffda7], bh
│           ;-- VirtualProtect:
..
│           0x01025891      59             pop ecx
│           0x01025892      0200           add al, byte [eax]
│           ;-- VirtualFree:
│           0x01025894      da5902         ficomp dword [ecx + 2]
│           0x01025897  ~   00e8           add al, ch
│           ;-- ExitProcess:
..
│           0x01025899      59             pop ecx
│           0x0102589a      0200           add al, byte [eax]
│           0x0102589c      0000           add byte [eax], al
│           0x0102589e      0000           add byte [eax], al
│           ;-- ShellAboutW:
│           0x010258a0      f65902         neg byte [ecx + 2]
│           0x010258a3      0000           add byte [eax], al
│           0x010258a5      0000           add byte [eax], al
│           0x010258a7  ~   00045a         add byte [edx + ebx*2], al
│           ;-- __CxxFrameHandler:
..
│           0x010258aa      0200           add al, byte [eax]
│           0x010258ac      0000           add byte [eax], al
│           0x010258ae      0000           add byte [eax], al
│           ;-- RegOpenKeyExA:
│           0x010258b0      185a02         sbb byte [edx + 2], bl
│           0x010258b3      0000           add byte [eax], al
│           0x010258b5      0000           add byte [eax], al
│           0x010258b7  ~   0028           add byte [eax], ch
│           ;-- SetBkColor:
..
│           0x010258b9      5a             pop edx
│           0x010258ba      0200           add al, byte [eax]
│           0x010258bc      0000           add byte [eax], al
│           0x010258be      0000           add byte [eax], al
│           ;-- GetMenu:
│           0x010258c0      355a020000     xor eax, 0x25a              ; 602
│           0x010258c5      0000           add byte [eax], al
│           0x010258c7      0000           add byte [eax], al
│           0x010258c9      0000           add byte [eax], al
│           0x010258cb      0000           add byte [eax], al
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000040 PE..L.....};..........................

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `KERNEL32.DLL!LoadLibraryA`
  - `KERNEL32.DLL!GetProcAddress`
  - `KERNEL32.DLL!VirtualProtect`
  - `KERNEL32.DLL!VirtualAlloc`
  - `KERNEL32.DLL!VirtualFree`
  - `SHELL32.DLL!ShellAboutW`
  - `MSVCRT.DLL!__CxxFrameHandler`
  - `ADVAPI32.DLL!RegOpenKeyExA`
  - `GDI32.DLL!SetBkColor`
  - `USER32.DLL!GetMenu`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '16932350' AND x.from_ea <= '16932360'\n              AND s.length > 2\n            ORDER BY s.length DESC\n        `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '16932360' AND x.from_ea <= '16932362'\n              AND s.length > 2\n            ORDER BY s.length DESC\n        `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '16932350' AND x.from_ea <= '16932360'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '16932360' AND x.from_ea <= '16932362'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '16932350' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '16932360' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '16932350' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '16932360' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '16924158' AND address <= '16940542'\n            ORDER BY ABS(CAST(address AS INTEGER) - 16932350) ASC\n            LIMIT 7\n            ", "ts": 1786286277.0568008}`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '16924168' AND address <= '16940552'\n            ORDER BY ABS(CAST(address AS INTEGER) - 16932360) ASC\n            LIMIT 7\n            ", "ts": 1786286277.058342}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786286315.4866586}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786286339.6610596}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '16932362' AND is_stale = '0' LIMIT 1", "ts": 1786286339.9272788}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '16932362' AND x.from_ea <= '16932378'\n              AND s.length > 2\n            ORDER BY s.length DESC\n        `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '16932362' AND x.from_ea <= '16932378'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '16932362' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '16932362' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '16924170' AND address <= '16940554'\n            ORDER BY ABS(CAST(address AS INTEGER) - 16932362) ASC\n            LIMIT 7\n            ", "ts": 1786286339.9465694}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786286394.778608}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '16932223' AND is_stale = '0' LIMIT 1", "ts": 1786286395.057358}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '16932223' AND x.from_ea <= '16932354'\n              AND s.length > 2\n            ORDER BY s.length DESC\n        `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '16932223' AND x.from_ea <= '16932354'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '16932223' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '16932223' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 17`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '16924031' AND address <= '16940415'\n            ORDER BY ABS(CAST(address AS INTEGER) - 16932223) ASC\n            LIMIT 7\n            ", "ts": 1786286395.09021}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786286430.9778166}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786286430.9815133}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786286431.109361}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786286433.639563}`
- `{"source": "yara_gen_v2", "ts": 1786286433.657076}`
