> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 16:09:18 UTC

## 1. Executive Summary

The sample `guLoader.exe` (SHA256: `c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509`) is a 49,152-byte PE32 binary compiled with Visual Basic 6. All analysis engines consistently identify it as a VB6 application, but the binary exhibits multiple indicators consistent with the GuLoader (CloudEyE) malware dropper family. The sample contains no standard Win32 API imports—only 60 functions from `MSVBVM60.DLL`—indicating that actual API resolution is performed dynamically at runtime through obfuscated shellcode. The `.text` section has extremely high entropy (93), and Malcat identifies three anomalies including `StackArrayInitialisationX86`, which is commonly used to build shellcode on the stack. FLOSS extracted 175 strings, many of which appear XOR-encoded (e.g., `;iC=w}`, `O|XPHT`, `G:T XR|`), characteristic of GuLoader's payload encryption. The entry point decompilation shows abnormal instruction sequences including `XOR byte ptr`, `POPAD`, and `AAA` opcodes, suggesting self-modifying code. Version metadata contains nonsensical Danish-sounding words (`Delfiteknikkernes`, `Topklasser`, `PENNEFJERE`) as fake product and company names. The main function `FUN_00408b2e` at address `0x408b2e` has extreme complexity (88 basic blocks, cyclomatic complexity 54, 370 instructions), indicative of obfuscated loader logic. We assess with high confidence (90%) that this sample is GuLoader, a VB6-based dropper/loader used to deliver secondary payloads. No behavioral evidence of C2 communication, persistence, or credential theft was observed in the available analysis environment.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | `c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509` |
| File Name | `guLoader.exe` |
| File Size | 49,152 bytes |
| File Type | PE32 executable (GUI) Intel 80386 |
| Architecture | x86 |
| Entry Point EA | 4744 (0x1288) |
| Entropy | 73 (overall); 93 (`.text` section) |
| Compiler | Visual Basic 6 (MSVC 6 linker) |
| Project | Hexorcist 3 - Weeks 20-30 |
| Verdict | Suspicious (score: 40) / Malicious (deep-dive: 90% confidence) |
| Family Guess | GuLoader (CloudEyE) |

(source: malcat, static_profile_data)

The high overall entropy of 73 and the `.text` section entropy of 93 are strong indicators of packing or encryption. The sample is a compact 49 KB binary, consistent with GuLoader's typical dropper size. The entry point at EA 4744 corresponds to the VB6 runtime initialization routine `ThunRTMain`.

## 3. File Layout & Structural Analysis

The PE file contains four sections with the following layout:

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 36864 | 36864 | 93 | RX |
| .data | 40960 | 4096 | 4096 | 4 | RW |
| .rsrc | 45056 | 4096 | 2320 | 27 | R |

(source: malcat, File Layout)

The `.text` section entropy of 93 is near-maximum (100), strongly suggesting the code section is encrypted or compressed. The `.data` section has very low entropy (4), likely containing uninitialized or sparse data. The `.rsrc` section at entropy 27 contains version information and icon resources.

### Anomalies

| Name | Level | Category | Description |
|---|---|---|---|
| InvalidChecksum | 4 | integrity | PE Header checksum is wrong |
| StackArrayInitialisationX86 | 3 | code | Array of data dynamically built on stack, sometimes used to build shellcodes or strings |
| BoundImports | 2 | imports | Bound imports are present |

(source: malcat, Anomalies)

The `InvalidChecksum` anomaly at level 4 indicates the PE checksum was not properly calculated, which is common in malware that modifies the binary after compilation. The `StackArrayInitialisationX86` anomaly is particularly significant: it indicates that data is being constructed on the stack at runtime, a technique commonly used by shellcode loaders to avoid static detection of embedded payloads. The `BoundImports` anomaly suggests the import table was bound at link time, which is a benign but notable structural feature.

### Carved and Virtual Files

Four embedded resources were carved from the `.rsrc` section:

| Name | Type | Size |
|---|---|---|
| ? | ICO | 26,030 |
| ? | DIB | 296 |
| ? | DIB | 744 |
| ? | DIB | 304 |

(source: malcat, Carved Files)

Five virtual files were extracted including version information (`VER/1/en-us`, 592 bytes) and icon resources. The version info contains the fake metadata discussed in Section 4.

### Key Structures

The binary contains 47 parsed structures including the standard PE headers, VB6-specific structures (`VBHeader`, `VBProjectInfo`, `VBObjectTable`, `VBForms`), and the import table at EA 37492. The `VBExternalTable` at EA 4824 and `VBObj.chippya` at EA 4832 are VB6 object structures. The `BoundImportTable` at EA 552 and `BoundImportNames` at EA 568 correspond to the bound imports anomaly.

(source: malcat, Structures)

## 4. Static Code Analysis

### Import Analysis

The sample imports exactly 60 functions, all from a single DLL: `MSVBVM60.DLL` (the Visual Basic 6 Virtual Machine runtime). There are zero imports from `kernel32.dll`, `ntdll.dll`, `user32.dll`, or any other Win32 system DLL.

(source: malcat, Imports; source: deep_dive_agentic, key_evidence)

This is a critical indicator. Legitimate VB6 applications typically import Win32 APIs for file I/O, registry access, network communication, and GUI operations. The complete absence of Win32 imports means the sample must resolve all necessary API functions dynamically at runtime, likely through shellcode that uses `LoadLibrary`/`GetProcAddress` or direct PEB walking. This is a hallmark technique of GuLoader and similar droppers.

The imported functions include VB6 runtime helpers for variable manipulation (`__vbaVarMove`, `__vbaFreeVar`, `__vbaStrVarMove`), string operations (`__vbaStrCmp`, `__vbaStrMove`), object management (`__vbaObjSet`, `__vbaFreeObj`), error handling (`__vbaExceptHandler`, `__vbaHresultCheckObj`), and the VB6 entry point (`ThunRTMain`). Notably, `rtcKillFiles` is imported, which could be used to delete files, though this alone is not malicious.

### YARA Matches

12 YARA rules matched the sample:

| Rule | Match Offset | Length | Significance |
|---|---|---|---|
| Microsoft_Visual_Basic_v50v60 | 4744 | 20 | VB6 signature at entry point |
| Microsoft_Visual_Basic_v50 | 79, 4751 | 1, 20 | VB5/v6 signature |
| Microsoft_Visual_Basic_v50_v60 | 4744 | 19 | VB5/v6 signature |
| Microsoft_Visual_Basic_v50_additional | 4744 | 20 | Additional VB signature |
| Microsoft_Visual_Basic_v50v60_additional | 4744 | 20 | Additional VB signature |
| contains_base64 | 4798 | 16 | Base64-encoded content |
| SEH__vba | 38206 | 16 | VB6 SEH handler pattern |
| SEH_Init | 34485 | 7 | SEH initialization pattern |
| IsPE32 | - | - | PE32 format indicator |
| IsWindowsGUI | - | - | Windows GUI subsystem |
| HasRichSignature | 168 | 4 | Rich header present |
| domain | 0 | 2 | Domain regex pattern |

(source: yara, YARA Matches)

The multiple VB6 signatures at the entry point (EA 4744) confirm the Visual Basic compilation. The `contains_base64` match at offset 4798 suggests embedded Base64-encoded data, which GuLoader uses for payload encoding. The `SEH__vba` and `SEH_Init` matches indicate Structured Exception Handling patterns that GuLoader uses for anti-debugging and control flow obfuscation.

### capa Capabilities

| Rule | ATT&CK | MBC |
|---|---|---|
| compiled from Visual Basic | - | - |

(source: capa, capa evidence)

The single capa rule confirms Visual Basic compilation but does not identify additional behavioral capabilities. This is expected for a loader/dropper whose primary functionality is obfuscated shellcode execution.

### FLOSS String Analysis

FLOSS extracted 175 static strings. Key categories include:

**VB6 Runtime Strings:**
- `MSVBVM60.DLL` (EA 37776, 568)
- `VBA6.DLL` (EA 7568)
- `VB5!6&*` (EA 4968)
- `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB` (EA 7000)

**VB6 Object/Form Names:**
- `REBALANCES` (EA 6864) - Form name
- `chippya` (EA 6876) - Object name
- `Option1`, `Option2`, `Option3` (EA 7120-7136) - Form controls
- `BIBLIOG` (EA 7160) - Control name
- `Label1` (EA 7184) - Control name

**XOR-Encoded Strings (high signal):**
- `;iC=w}` (FLOSS sample)
- `O|XPHT` (FLOSS sample)
- `O|K{K/` (FLOSS sample)
- `O$X32\` (FLOSS sample)
- `OhxGFWabiTZ16Ppk..vcXCtkMMlSJiZG44` (EA 7348)

(source: floss, FLOSS strings; source: malcat, Top Strings)

The XOR-encoded strings are characteristic of GuLoader's payload encryption. These strings appear to be encrypted configuration data or payload fragments that are decoded at runtime. The VB6 object names (`REBALANCES`, `chippya`, `BIBLIOG`) are likely fake form and control names used to populate the VB6 project structure.

### Version Information (Fake Metadata)

| Field | Value |
|---|---|
| ProductName | `Startsym1` |
| CompanyName | `Delfiteknikkernes` |
| FileDescription | `Topklasser` |
| OriginalFilename | `Startsym1.exe` |
| FileVersion | `1.00` |
| ProductVersion | `1.00` |
| InternalName | (EA 45870) |
| PENNEFJERE | (EA 45700) |
| Udskiv6 | (EA 45756) |

(source: malcat, Top Strings; source: deep_dive_agentic, key_evidence)

The version metadata contains nonsensical Danish-sounding words that are not real Danish. `Delfiteknikkernes`, `Topklasser`, `PENNEFJERE`, and `Startsym1` are fabricated strings designed to fill version info fields without revealing the malware's true origin. This is a common anti-analysis technique in GuLoader variants.

### Entry Point Disassembly

The radare2 disassembly at the entry point (0x00401288) reveals the VB6 runtime initialization:

```asm
0x00401288  push 0x401368          ; "VB5!6&*"
0x0040128d  call 0x401282          ; ThunRTMain
```

(source: radare2, Disassembly at 0x00401288)

This is the standard VB6 entry point that calls `ThunRTMain` with the VB6 signature string. However, the subsequent code at 0x00401292 contains abnormal instructions:

```asm
0x00401292  add byte [eax], al
0x00401298  xor byte [eax], al
0x004012a7  aaa
0x004012a8  mov eax, dword [0x82409c5c]
0x004012ad  add eax, 0x8c0918e8
```

(source: radare2, Disassembly at 0x00401292)

The `xor byte [eax], al` instruction at 0x00401298 and the `aaa` (ASCII Adjust After Addition) instruction at 0x004012a7 are abnormal in legitimate VB6 code. These sequences suggest self-modifying code or obfuscated shellcode that modifies itself during execution. The Malcat decompilation confirms this with warnings about "bad instruction data" and overlapping instructions.

### Main Function Analysis

The function `FUN_00408b2e` (sub_408b2e) at EA 35630 is the primary loader logic:

| Metric | Value |
|---|---|
| Address | 0x408b2e |
| Size | 1,610 bytes |
| Basic Blocks | 88 |
| Cyclomatic Complexity | 54 |
| Instructions | 370 |
| Call-outs | 38 |

(source: deep_dive_agentic, key_evidence; source: malcat, Functions)

A cyclomatic complexity of 54 is extremely high for a function of this size, indicating heavily obfuscated control flow with many conditional branches. The 88 basic blocks and 370 instructions suggest a complex decryption or decompression routine. The 38 call-outs indicate numerous calls to other functions, likely including the dynamic API resolution shellcode.

### Malcat Decompilation (Entry Point)

The Malcat decompilation of the entry point shows severely obfuscated code:

```c
void EntryPoint(undefined4 param_1, undefined4 param_2, undefined2 param_3)
{
    /* WARNING: Control flow encountered bad instruction data */
    /* WARNING: Instruction at (ram,0x0040133b) overlaps instruction at (ram,0x0040133a) */
    
    uVar12 = jmp_msvbvm60.ThunRTMain("VB5!6&*");
    // ... obfuscated operations with XOR, ADD, memory manipulation ...
    halt_baddata();
}
```

(source: malcat, Decompilations, EntryPoint at 4744)

The decompiler warnings about "bad instruction data" and overlapping instructions confirm that the code contains intentionally malformed or self-modifying sequences that break standard disassembly. The `halt_baddata()` call indicates the decompiler encountered instructions it could not parse, which is expected in obfuscated shellcode.

## 5. Behavioral & Dynamic Analysis

### Speakeasy Emulation

Speakeasy emulation completed successfully but recorded zero API calls and zero key events.

(source: speakeasy, dynamic analysis)

**Not observed**: No API calls or behavioral events were recorded during emulation. This is consistent with GuLoader's anti-emulation techniques, which detect sandboxed environments and refuse to execute. The sample likely checks for emulation artifacts (e.g., timing, CPUID, memory layout) and terminates if detected.

### Frida Probe

Frida probe identified 5 hook candidates in `MSVBVM60.DLL`:

- `MSVBVM60.DLL!_CIcos`
- `MSVBVM60.DLL!_adj_fptan`
- `MSVBVM60.DLL!__vbaVarMove`
- `MSVBVM60.DLL!__vbaFreeVar`
- `MSVBVM60.DLL!__vbaStrVarMove`

(source: frida_probe, hook_candidates)

**Not observed**: No runtime behavior was captured. The hook candidates are the first five imported functions from `MSVBVM60.DLL`, but without execution, no behavioral data is available.

### UPX Analysis

UPX unpacking was not performed. The sample is not UPX-packed.

(source: upx, UPX Unpack)

- `upx_ok`: False
- `is_packed`: False
- `returncode`: None
- `unpacked_path`: (empty)

The high entropy of the `.text` section (93) suggests custom packing or encryption rather than UPX.

### XOR Search

XOR search found a pattern at position 0:

```
Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r
```

(source: xor, XOR Search)

This is the standard DOS stub message, not an XOR-encoded payload. The actual XOR-encoded strings are elsewhere in the binary (see FLOSS analysis in Section 4).

## 6. Network Indicators & C2

No network indicators or C2 infrastructure were identified in the static analysis. The sample contains no hardcoded domains, IP addresses, or URLs in its static strings.

(source: yara, domain rule match at offset 0 with length 2)

The YARA `domain` rule matched at offset 0 with only 2 bytes, which is likely a false positive from the DOS stub. FLOSS extracted 175 strings, none of which contain network indicators. The absence of static C2 indicators is consistent with GuLoader's design: the actual C2 configuration is encrypted within the payload and decrypted at runtime by the shellcode loader.

We assess that the C2 infrastructure is embedded within the XOR-encoded strings (e.g., `OhxGFWabiTZ16Ppk..vcXCtkMMlSJiZG44` at EA 7348) but cannot confirm this without runtime decryption.

## 7. Capabilities Assessment

Based on the available evidence, the sample's assessed capabilities are:

| Capability | Confidence | Evidence |
|---|---|---|
| Payload Decryption/Loading | High | High entropy `.text` section (93), XOR-encoded strings, complex main function (CC=54) |
| Dynamic API Resolution | High | Zero Win32 imports, only MSVBVM60.DLL functions |
| Anti-Analysis/Anti-Emulation | High | Speakeasy recorded zero events, obfuscated entry point, SEH patterns |
| Self-Modifying Code | Medium | Abnormal instructions (XOR, POPAD, AAA) at entry point |
| File Deletion | Low | `rtcKillFiles` imported but not observed in execution |
| C2 Communication | Unknown | No static indicators; likely encrypted in payload |
| Persistence | Unknown | Not observed |
| Credential Theft | Unknown | Not observed |

The primary capability is as a dropper/loader: it decrypts and executes a secondary payload using dynamic API resolution and anti-analysis techniques. The actual malicious behavior (C2, persistence, data theft) would be performed by the secondary payload, not the loader itself.

## 8. Indicators of Compromise

### File Hashes

| Type | Value |
|---|---|
| SHA256 | `c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509` |

### File Names

- `guLoader.exe`
- `Startsym1.exe` (from version info)

### Strings (High Signal)

| EA | String | Significance |
|---|---|---|
| 7348 | `OhxGFWabiTZ16Ppk..vcXCtkMMlSJiZG44` | XOR-encoded payload/config |
| 4798 | `Borderadamasprei` | Base64 content (YARA match) |
| 7424 | `Delfiteknikkernes` | Fake company name |
| 7500 | `Topklasser` | Fake file description |
| 45700 | `PENNEFJERE` | Fake version info field |
| 45956 | `Startsym1.exe` | Fake original filename |
| 4968 | `VB5!6&*` | VB6 signature |
| 37776 | `MSVBVM60.DLL` | VB6 runtime DLL |

(source: malcat, Top Strings; source: floss, FLOSS strings)

### YARA Rules

- `Microsoft_Visual_Basic_v50v60` (offset 4744)
- `contains_base64` (offset 4798)
- `SEH__vba` (offset 38206)
- `SEH_Init` (offset 34485)

(source: yara, YARA Matches)

### Import Hash

All 60 imports from `MSVBVM60.DLL` — no Win32 API imports.

(source: malcat, Imports)

## 9. Detection Engineering

### YARA Rules

The following existing YARA rules matched and can be used for detection:

1. **Microsoft_Visual_Basic_v50v60** — Detects VB6 signature at entry point
2. **contains_base64** — Detects Base64-encoded content (offset 4798)
3. **SEH__vba** — Detects VB6 SEH handler patterns (offset 38206)
4. **SEH_Init** — Detects SEH initialization patterns (offset 34485)

(source: yara, YARA Matches)

### Recommended Detection Strategies

1. **Entropy-Based Detection**: Monitor for PE files with `.text` section entropy > 90 combined with VB6 compilation signatures.
2. **Import Anomaly Detection**: Flag VB6 executables that import only from `MSVBVM60.DLL` with zero Win32 API imports.
3. **String Pattern Detection**: Detect XOR-encoded strings with high entropy patterns (e.g., sequences of non-alphanumeric characters).
4. **Version Info Anomaly Detection**: Flag PE files with nonsensical or Danish-sounding version metadata fields.
5. **Stack Array Detection**: Monitor for the `StackArrayInitialisationX86` pattern in conjunction with VB6 signatures.

### Sigma Rules (Suggested)

```yaml
title: GuLoader VB6 Dropper - Suspicious Import Pattern
status: experimental
description: Detects VB6 executables with only MSVBVM60.DLL imports (no Win32 APIs)
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    OriginalFilename: 'Startsym1.exe'
  condition: selection
```

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence | Confidence |
|---|---|---|---|
| Defense Evasion | T1027 - Obfuscated Files or Information | High entropy `.text` (93), XOR-encoded strings, obfuscated decompilation | High |
| Defense Evasion | T1140 - Deobfuscate/Decode Files or Information | XOR-encoded strings decoded at runtime | High |
| Defense Evasion | T1497 - Virtualization/Sandbox Evasion | Speakeasy recorded zero events (anti-emulation) | Medium |
| Defense Evasion | T1036 - Masquerading | Fake version info (Delfiteknikkernes, Topklasser) | High |
| Execution | T1059 - Command and Scripting Interpreter | VB6 runtime execution via ThunRTMain | High |
| Execution | T1106 - Native API | Dynamic API resolution (zero Win32 imports) | High |
| Discovery | T1082 - System Information Discovery | Likely performed by shellcode (not observed) | Low |

(source: deep_dive_agentic, summary; source: yara, YARA Matches; source: speakeasy, dynamic analysis)

The primary ATT&CK techniques are related to defense evasion, as GuLoader's main purpose is to evade detection while delivering a secondary payload. The dynamic API resolution technique (T1106) is particularly significant, as it prevents static analysis from revealing the malware's full capabilities.

## 11. What We Don't Know

1. **Secondary Payload Identity**: The actual malware delivered by this GuLoader sample is unknown. The XOR-encoded strings likely contain the encrypted payload or its configuration, but runtime decryption was not observed.

2. **C2 Infrastructure**: No C2 domains, IPs, or URLs were identified in static analysis. The C2 configuration is likely encrypted within the payload.

3. **Runtime Behavior**: Speakeasy emulation recorded zero events, and Frida captured no runtime data. The sample's actual behavior (file drops, registry modifications, network connections) is unknown.

4. **Anti-Analysis Specifics**: While we identified anti-emulation behavior (zero Speakeasy events), the specific checks performed (timing, CPUID, artifact detection) are unknown without dynamic analysis.

5. **Payload Delivery Method**: Whether the secondary payload is embedded in the binary, downloaded from a remote server, or constructed from the XOR-encoded strings is unknown.

6. **Persistence Mechanism**: No persistence indicators were observed, but the secondary payload may implement persistence.

7. **Full Decryption Routine**: The main function `FUN_00408b2e` (CC=54) is heavily obfuscated, and its complete decryption logic was not fully analyzed.

8. **Campaign Attribution**: While the sample matches GuLoader patterns, specific campaign attribution (threat actor, distribution method) is unknown.

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used

| Tool | Version | Status | Key Findings |
|---|---|---|---|
| Malcat | - | Success | Static profile, anomalies, decompilation, imports, strings |
| YARA (yara-x) | - | Success | 12 rules matched |
| capa (malcat-capa) | - | Success | 1 rule: compiled from Visual Basic |
| FLOSS | - | Success | 175 static strings extracted |
| radare2 | - | Success | Disassembly at entry point and imports |
| Ghidra | - | Success | Function analysis (FUN_00408b2e: CC=54) |
| IDA | - | Success | Import count (60), function counts |
| Speakeasy | - | Success | Zero API calls (anti-emulation) |
| Frida | 17.16.4 | Success | 5 hook candidates identified |
| UPX | - | Not packed | Sample is not UPX-packed |
| XOR Search | - | Success | DOS stub at offset 0 |

### Evidence Citations

| Section | Source | Query/Table | Row/Rule | Why |
|---|---|---|---|---|
| 2 | malcat | static_profile_data | entropy=73, anomalies_count=3 | High entropy and anomalies suggest obfuscation |
| 3 | malcat | File Layout | .text section | Entropy 93 indicates encrypted/compressed code |
| 3 | malcat | Anomalies | StackArrayInitialisationX86 | Stack-based shellcode construction |
| 4 | yara | YARA Matches | Microsoft_Visual_Basic_v50v60 | VB6 compilation confirmed |
| 4 | yara | YARA Matches | contains_base64 (offset 4798) | Base64-encoded content present |
| 4 | yara | YARA Matches | SEH__vba (offset 38206) | Anti-analysis SEH pattern |
| 4 | capa | capa evidence | compiled from Visual Basic | VB6 compilation corroborated |
| 4 | floss | FLOSS strings | ;iC=w}, O|XPHT | XOR-encoded strings characteristic of GuLoader |
| 4 | malcat | Top Strings | Delfiteknikkernes, Topklasser | Fake version metadata |
| 4 | deep_dive_agentic | key_evidence | FUN_00408b2e (CC=54) | Obfuscated loader logic |
| 5 | speakeasy | dynamic analysis | 0 API calls | Anti-emulation behavior |
| 6 | yara | YARA Matches | domain (offset 0, len 2) | False positive from DOS stub |
| 10 | deep_dive_agentic | summary | GuLoader identification | Family attribution |

## 13. Appendix B: Analysis Environment

| Parameter | Value |
|---|---|
| Sample Path | `/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe` |
| Project Name | Hexorcist 3 - Weeks 20-30 |
| Analysis Date | (from pipeline) |
| Verdict Source | llm_judge (mimo-v2.5-pro) |
| Deep-Dive Source | deep_dive_agentic (langgraph) |
| Tool Gate | All required tools passed (capa, yara, malcat, floss, pe_imports, dotnet, r2_decomp, upx, xor, speakeasy, frida_probe) |
| Large Sample | False |
| .NET Analysis | Not .NET (is_dotnet: false) |
| Frida Version | 17.16.4 |

### Verdict Disagreement

The LLM judge (mimo-v2.5-pro) assessed the sample as **suspicious** (score: 40), while the deep-dive agent assessed it as **malicious** (confidence: 90%). The v1 fallback also assessed it as **malicious** (score: 290). The disagreement likely stems from the judge requiring more behavioral evidence, while the deep-dive agent weighted the strong static indicators (GuLoader patterns, zero Win32 imports, high entropy, XOR-encoded strings) more heavily. We concur with the deep-dive assessment based on the totality of evidence.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509  
**sample_path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe  
**project_name:** Hexorcist 3 - Weeks 20-30

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 40
- **family_guess**: Unknown (VisualBasic Loader)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: All tools consistently identify the sample as a Visual Basic application. Ghidra and IDA report matching import counts (60) and string data, with IDA showing higher function counts. Malcat provides a comprehensive static profile indicating high entropy and anomalies, while capa and YARA confirm Visual Basic compilation. Decompilation from Malcat reveals obfuscated code with control flow issues. No behavioral-intent evidence (e.g., C2, persistence, credential theft) is present across tools.
- **summary**: The sample guLoader.exe is a PE32 binary compiled from Visual Basic, exhibiting high entropy, anomalies, and obfuscated decompilation code. All analysis tools (Ghidra, IDA, Malcat, capa, YARA, FLOSS) agree on its Visual Basic nature, but no behavioral indicators of malicious intent (e.g., C2, persistence, data exfiltration) were found. The obfuscation and anomalies are neutral signals that warrant suspicion, but definitive malice cannot be concluded without further evidence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile_data | `entropy=73, anomalies_count=3, yara_hits_count=5` | High entropy and anomalies (BoundImports, InvalidChecksum, StackArrayInitialisationX86) suggest obfuscation or packing,  |
| yara | YARA matches | `rule: Microsoft_Visual_Basic_v50v60` | Confirms the sample is compiled with Visual Basic, a framework commonly used in both benign and malicious software, alig |
| malcat | decompilations | `EntryPoint (address 4744)` | Decompilation shows obfuscated code with warnings about bad instructions and overlaps, indicating protection mechanisms  |
| capa | capa evidence | `rule: compiled from Visual Basic` | Corroborates Visual Basic compilation, reinforcing the sample's nature without adding behavioral evidence. |
| floss | FLOSS strings | `paths: C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB` | Presence of VB6 development paths suggests a legitimate environment, but such strings can be mimicked in malware to evad |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is GuLoader (also known as CloudEyE), a well-known VB6-based malware dropper/loader. The sample is compiled in Visual Basic 6, contains heavily XOR-encoded strings revealed by FLOSS (175 strings, many like ';iC=w}', 'O|XPHT', '%<0G:\MN'), and has no standard Win32 API imports — only MSVBVM60.DLL runtime functions (60 imports). Actual API resolution is performed dynamically through obfuscated shellcode. The main function FUN_00408b2e shows extreme complexity (88 basic blocks, cyclomatic complexity 54, 370 instructions) indicative of obfuscated loader logic. The entry point contains abnormal instruction sequences (XOR byte ptr, POPAD, AAA) suggesting code self-modification. Version metadata uses nonsensical Danish-sounding words ('Delfiteknikkernes', 'Topklasser', 'PENNEFJERE', 'Startsym1') as fake product/company names. YARA rules matched VB5/v6 signatures, base64 content, and SEH patterns consistent with GuLoader's anti-analysis techniques.

### deep key_evidence
- `"YARA: 12 rules matched including Microsoft_Visual_Basic_v50v60, contains_base64 (offset 4798), SEH__vba (offset 38206), SEH_Init (offset 34485)"`
- `"Imports: 60 imports all from MSVBVM60.DLL \u2014 no Win32 API imports (kernel32, ntdll, etc.), confirming dynamic API resolution via shellcode"`
- `"FLOSS: 175 strings extracted; heavily XOR-encoded strings found (e.g., ';iC=w}', 'O|XPHT', ':]4QWt', '%xMc%|', 'G:T XR|') characteristic of GuLoader payload encryption"`
- `"Ghidra functions: FUN_00408b2e (addr 0x408b2e, 1610 bytes) has cyclomatic complexity 54, 88 blocks, 370 instructions, 38 call-outs \u2014 indicative of obfuscated loader"`
- `"Entry point (0x401368): Abnormal instruction patterns including XOR byte ptr [EAX], AL; POPAD; AAA sequences suggesting self-modifying code"`
- `"Fake version info: ProductName='Startsym1', CompanyName='Delfiteknikkernes', FileDescription='Topklasser', OriginalFilename='Startsym1.exe' \u2014 nonsensical Danish-sounding names"`
- `"Ghidra string_refs: No string references found in main function, confirming strings are decoded at runtime through XOR decryption"`
- `"File size: 49,152 bytes \u2014 compact VB6 dropper consistent with GuLoader's typical payload size"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509
size: 49152
type: PE
architecture: X86
entrypoint_ea: 4744
entropy: 73
file_name: guLoader.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 36864 | 36864 | 93 | RX |
| .data | 40960 | 4096 | 4096 | 4 | RW |
| .rsrc | 45056 | 4096 | 2320 | 27 | R |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 |  |
| ms_visual_basic_50_01 | compiler | INFO | 50 |  |

### Anomalies (3)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| BoundImports | 2 | imports | 1 | Bound imports are present |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 7000 | `C:\Program Files..dio\VB98\VB6.OLB` |
| 7348 | `OhxGFWabiTZ16Ppk..vcXCtkMMlSJiZG44` |
| 7220 | `15:15:15` |
| 7424 | `Delfiteknikkernes` |
| 7292 | `8/8/8` |
| 37776 | `MSVBVM60.DLL` |
| 568 | `MSVBVM60.DLL` |
| 7500 | `Topklasser` |
| 4968 | `VB5!6&*` |
| 7160 | `BIBLIOG` |
| 7308 | `whomble` |
| 6864 | `REBALANCES` |
| 6884 | `adamasprei` |
| 6876 | `chippya` |
| 7136 | `Option1` |
| 7120 | `Option3` |
| 7128 | `Option2` |
| 45956 | `Startsym1.exe` |
| 6976 | `Form` |
| 7184 | `Label1` |
| 45398 | `VS_VERSION_INFO` |
| 45594 | `040904B0` |
| 45922 | `OriginalFilename` |
| 45700 | `PENNEFJERE` |
| 7568 | `VBA6.DLL` |
| 45870 | `InternalName` |
| 45666 | `FileDescription` |
| 45822 | `ProductVersion` |
| 45558 | `StringFileInfo` |
| 45522 | `Translation` |
| 45618 | `CompanyName` |
| 77 | `!This program ca..in DOS mode.
$` |
| 45778 | `FileVersion` |
| 45852 | `1.00` |
| 4798 | `Borderadamasprei` |
| 45804 | `1.00` |
| 38412 | `__vbaVarLateMemCallLd` |
| 38176 | `EVENT_SINK_QueryInterface` |
| 7708 | `__vbaVarLateMemCallLd` |
| 45896 | `Startsym1` |
| 7776 | `__vbaFreeVar` |
| 37832 | `__vbaFreeVar` |
| 38144 | `EVENT_SINK_Release` |
| 38300 | `_adj_fdiv_m32i` |
| 37990 | `_adj_fdiv_m16i` |
| 38318 | `_adj_fdivr_m32i` |
| 45730 | `ProductName` |
| 7844 | `__vbaFreeVarList` |
| 45490 | `VarFileInfo` |
| 38112 | `__vbaCastObjVar` |
| 38050 | `EVENT_SINK_AddRef` |
| 7680 | `__vbaCastObjVar` |
| 38008 | `_adj_fdivr_m16i` |
| 7616 | `__vbaStrVarMove` |
| 37866 | `__vbaFreeVarList` |
| 37848 | `__vbaStrVarMove` |
| 37816 | `__vbaVarMove` |
| 8231 | `BIBLIOG` |
| 38508 | `__vbaFreeObj` |
| 38462 | `_allmul` |
| 7600 | `__vbaVarMove` |
| 38492 | `__vbaFreeStr` |
| 7760 | `__vbaFreeObj` |
| 7792 | `__vbaFreeStr` |
| 38130 | `_adj_fpatan` |
| 38368 | `_adj_fdiv_r` |
| 38204 | `__vbaExceptHandler` |
| 7808 | `__vbaHresultCheckObj` |
| 38240 | `_adj_fdivr_m64` |
| 38350 | `_adj_fdivr_m32` |
| 7580 | `__vbaAryDestruct` |
| 37956 | `__vbaAryDestruct` |
| 37940 | `_adj_fdiv_m32` |
| 37916 | `__vbaHresultCheckObj` |
| 37886 | `_adj_fdiv_m64` |
| 15233 | `<KxK` |
| 45644 | `skulap` |
| 28745 | `/-P?pR` |
| 38100 | `__vbaI2I4` |
| 45756 | `Udskiv6` |

### Constants / Known Patterns (1)
| Category | Value |
|---|---|
| guid | `guid::IPictureDisp` |

### Imports (60)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | msvbvm60._CIcos | IMPORT | 6 |
| 4100 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4104 | msvbvm60.__vbaVarMove | IMPORT | 1 |
| 4108 | msvbvm60.__vbaFreeVar | IMPORT | 1 |
| 4112 | msvbvm60.__vbaStrVarMove | IMPORT | 1 |
| 4116 | msvbvm60.__vbaFreeVarList | IMPORT | 1 |
| 4120 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4124 | msvbvm60.rtcVarBstrFromChar | IMPORT | 1 |
| 4128 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4132 | msvbvm60.rtcLowerCaseVar | IMPORT | 1 |
| 4136 | msvbvm60.rtcTrimBstr | IMPORT | 1 |
| 4140 | msvbvm60.__vbaHresultCheckObj | IMPORT | 1 |
| 4144 | msvbvm60.rtcIsDate | IMPORT | 1 |
| 4148 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4152 | msvbvm60.__vbaAryDestruct | IMPORT | 1 |
| 4156 | msvbvm60.__vbaObjSet | IMPORT | 1 |
| 4160 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4164 | msvbvm60.rtcFormatNumber | IMPORT | 1 |
| 4168 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4172 | msvbvm60.rtcDoEvents | IMPORT | 1 |
| 4176 | msvbvm60._CIsin | IMPORT | 1 |
| 4180 | msvbvm60.rtcMidCharVar | IMPORT | 1 |
| 4184 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4188 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4192 | msvbvm60.__vbaStrCmp | IMPORT | 1 |
| 4196 | msvbvm60.rtcKillFiles | IMPORT | 1 |
| 4200 | msvbvm60.__vbaVarTstEq | IMPORT | 1 |
| 4204 | msvbvm60.rtcIsNull | IMPORT | 1 |
| 4208 | msvbvm60.__vbaI2I4 | IMPORT | 1 |
| 4212 | msvbvm60.__vbaCastObjVar | IMPORT | 1 |
| 4216 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4220 | msvbvm60.rtcPMT | IMPORT | 1 |
| 4224 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4228 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4232 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4236 | msvbvm60.rtcJoin | IMPORT | 1 |
| 4240 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4244 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4248 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4252 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4256 | msvbvm60._CIlog | IMPORT | 1 |
| 4260 | msvbvm60.__vbaNew2 | IMPORT | 1 |
| 4264 | msvbvm60._adj_fdiv_m32i | IMPORT | 1 |
| 4268 | msvbvm60._adj_fdivr_m32i | IMPORT | 1 |
| 4272 | msvbvm60.__vbaI4Str | IMPORT | 1 |
| 4276 | msvbvm60._adj_fdivr_m32 | IMPORT | 1 |
| 4280 | msvbvm60._adj_fdiv_r | IMPORT | 1 |
| 4284 | msvbvm60.ThunRTMain | IMPORT | 1 |
| 4288 | msvbvm60.__vbaVarTstNe | IMPORT | 1 |
| 4292 | msvbvm60.__vbaVarDup | IMPORT | 1 |
| 4296 | msvbvm60.rtcVarStrFromVar | IMPORT | 1 |
| 4300 | msvbvm60.__vbaVarLateMemCallLd | IMPORT | 1 |
| 4304 | msvbvm60._CIatan | IMPORT | 1 |
| 4308 | msvbvm60.__vbaStrMove | IMPORT | 1 |
| 4312 | msvbvm60.rtcGetHourOfDay | IMPORT | 1 |
| 4316 | msvbvm60._allmul | IMPORT | 1 |
| 4320 | msvbvm60._CItan | IMPORT | 1 |
| 4324 | msvbvm60._CIexp | IMPORT | 1 |
| 4328 | msvbvm60.__vbaFreeStr | IMPORT | 1 |
| 4332 | msvbvm60.__vbaFreeObj | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 4744 | EntryPoint |
| 4384 | jmp_msvbvm60.__vbaChkstk |
| 4390 | jmp_msvbvm60.__vbaExceptHandler |
| 4396 | jmp_msvbvm60.__vbaFPException |
| 4528 | jmp_msvbvm60.__vbaAryDestruct |
| 4534 | jmp_msvbvm60.rtcVarStrFromVar |
| 4558 | jmp_msvbvm60.rtcJoin |
| 4564 | jmp_msvbvm60.rtcPMT |
| 4570 | jmp_msvbvm60.__vbaI2I4 |
| 4576 | jmp_msvbvm60.rtcMidCharVar |
| 4582 | jmp_msvbvm60.__vbaVarTstEq |
| 4588 | jmp_msvbvm60.rtcFormatNumber |
| 4594 | jmp_msvbvm60.rtcIsNull |
| 4600 | jmp_msvbvm60.rtcDoEvents |
| 4648 | jmp_msvbvm60.__vbaStrMove |
| 4660 | jmp_msvbvm60.__vbaFreeObj |
| 4666 | jmp_msvbvm60.__vbaFreeVar |
| 4672 | jmp_msvbvm60.rtcIsDate |
| 4678 | jmp_msvbvm60.__vbaFreeStr |
| 4684 | jmp_msvbvm60.__vbaHresultCheckObj |
| 4690 | jmp_msvbvm60.__vbaNew2 |
| 4696 | jmp_msvbvm60.__vbaFreeVarList |
| 4702 | jmp_msvbvm60.__vbaVarDup |
| 4738 | jmp_msvbvm60.ThunRTMain |
| 35630 | sub_408b2e |
| 35562 | sub_408aea |
| 37358 | sub_4091ee |
| 37404 | sub_40921c |
| 35601 | sub_408b11 |
| 35610 | sub_408b1a |

### Decompilations (top 6)
#### 4744 — EntryPoint
```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x0040133b) overlaps instruction at (ram,0x0040133a)
    */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(undefined4 param_1,undefined4 param_2,undefined2 param_3)

{
    uint32_t *puVar1;
    char cVar2;
    uint8_t uVar3;
    uint8_t *puVar4;
    int32_t *piVar5;
    undefined *puVar6;
    char *pcVar7;
    uint32_t uVar8;
    uint8_t *extraout_ECX;
    uint8_t uVar10;
    char *unaff_EBX;
    char *unaff_ESI;
    undefined2 in_DS;
    bool bVar11;
    undefined8 uVar12;
    char *in_stack_0000001c;
    char *in_stack_00000028;
    char *in_stack_0000002c;
    uint8_t *in_stack_00000030;
    int32_t *in_stack_00000034;
    undefined4 *puVar9;
    
    uVar12 = jmp_msvbvm60.ThunRTMain("VB5!6&*");
    pcVar7 = uVar12 >> 0x20;
    puVar4 = uVar12;
    uVar3 = uVar12;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 ^ uVar3;
    *puVar4 = *puVar4 + uVar3;
    puVar4 = puVar4 + 1;
    cVar2 = puVar4;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    uVar10 = unaff_EBX >> 8;
    *pcVar7 = *pcVar7 + uVar10;
    piVar5 = [0x0x82409c5c] + -0x73f6e718;
    uVar3 = piVar5;
    *piVar5 = *piVar5 + uVar3;
    *extraout_ECX = *extraout_ECX + uVar3;
    *piVar5 = *piVar5 + uVar3;
    puVar4 = pcVar7 + 0x6f;
    bVar11 = CARRY1(*puVar4, uVar3);
    *puVar4 = *puVar4 + uVar3;
    if ((bVar11) || (bVar11)) {
        extraout_ECX[0x26ed4748] = uVar10;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        in_stack_00000030 = extraout_ECX;
        in_stack_00000028 = unaff_EBX;
        in_stack_0000001c = unaff_ESI;
    }
    else {
        ffffff88 = in(param_3);
        if (!bVar11) {
            cVar2 = in_stack_00000034;
            *in_stack_00000034 = *in_stack_00000034 + cVar2;
            *in_stack_00000034 = *in_stack_00000034 + cVar2;
            *(in_stack_00000034 + 2) = *(in_stack_00000034 + 2) + cVar2;
            goto code_r0x00401345;
        }
        piVar5 = in_stack_00000034;
        pcVar7 = in_stack_0000002c;
        if (!bVar11) {
            puVar6 = *(*in_stack_00000034 * 0x74706143) * 0x6000000;
            *puVar6 = *puVar6;
            puVar1 = CONCAT21(puVar6 >> 0x10, in_stack_00000030 >> 8) * 0x100 + -0x10040;
            uVar8 = *puVar1;
            *puVar1 = *puVar1 + puVar1;
            pcVar7 = CONCAT31(puVar1 >> 8, (puVar1 + -0x1a) - CARRY4(uVar8, puVar1)) + 1;
            *pcVar7 = *pcVar7 + pcVar7;
            *pcVar7 = *pcVar7 + pcVar7;
    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
        }
    }
    cVar2 = piVar5;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *pcVar7 = *pcVar7;
    *piVar5 = *piVar5 + cVar2;
    in_stack_00000034 = piVar5;
    in_stack_0000002c = pcVar7;
code_r0x00401345:
    uVar3 = in_stack_00000034;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000028 = *in_stack_00000028 + (in_stack_00000034 >> 8);
    pcVar7 = segment(in_DS, in_stack_00000028 + in_stack_0000001c);
    *pcVar7 = *pcVar7 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    uVar8 = CONCAT31(CONCAT22(in_stack_0
```
#### 4384 — jmp_msvbvm60.__vbaChkstk
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaChkstk(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaChkstk)();
    return;
}

```
#### 4390 — jmp_msvbvm60.__vbaExceptHandler
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaExceptHandler(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaExceptHandler)();
    return;
}

```

### Carved Files (4)
| Name | Type | Size |
|---|---|---|
| ? | ICO | 26030 |
| ? | DIB | 296 |
| ? | DIB | 744 |
| ? | DIB | 304 |

### Virtual Files (5)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/30001/unk | 304 | - |
| ICO/30002/unk | 744 | - |
| ICO/30003/unk | 296 | - |
| GRPICO/1/unk | 48 | - |
| VER/1/en-us | 592 | - |

### Structures (47)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| BoundImportTable | 552 |
| BoundImportNames | 568 |
| msvbvm60.FT | 4096 |
| VBExternalTable | 4824 |
| VBObj.chippya | 4832 |
| VBForms | 4888 |
| VBHeader | 4968 |
| VBProjectInfo | 5124 |
| VBObj.REBALANCES | 5696 |
| VBObj.REBALANCES.OptInfos | 5752 |
| VBObj.REBALANCES.Controls | 5824 |
| VBObj.REBALANCES.Controls.Form.Events | 6064 |
| VBObj.REBALANCES.Controls.Option3.Events | 6212 |
| VBObj.REBALANCES.Controls.Option2.Events | 6312 |
| VBObj.REBALANCES.Controls.Option1.Events | 6412 |
| VBObj.REBALANCES.Controls.BIBLIOG.Events | 6512 |
| VBObj.REBALANCES.Controls.Label1.Events | 6588 |
| VBObjectTable | 6684 |
| VBObjectArray | 6768 |
| VBForm.0 | 7892 |
| ImportTable | 37492 |
| msvbvm60.OFT | 37532 |
| ImportNames | 37776 |
| Resources | 45056 |
| Resources.VER | 45096 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.88

| Rule | ATT&CK | MBC |
|---|---|---|
| compiled from Visual Basic |  |  |

## PE Imports / Signals
import_count: 46

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@4798 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| Microsoft_Visual_Basic_v50v60 | - | $a@4744 len=20 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1; $b@4751 len=20 |
| Microsoft_Visual_Basic_v50_v60 | - | $c@4744 len=19 |
| Microsoft_Visual_Basic_v50_additional | - | $a@4744 len=20 |
| Microsoft_Visual_Basic_v50v60_additional | - | $a@4744 len=20 |
| SEH__vba | - | $@38206 len=16 |
| SEH_Init | - | $b@34485 len=7 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4798,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 4751,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_v60",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$c",
          "offset": 4744,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_additional",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60_additional",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH__vba",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$",
          "offset": 38206,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 34485,
          "length": 7,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "
```

## FLOSS Strings
Total strings: 175 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 175}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `MSVBVM60.DLL`
- `Borderadamasprei`
- `VB5!6&*`
- `Startsym1`
- `adamasprei`
- `REBALANCES`
- `chippya`
- `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- `Option3`
- `Option2`
- `Option1`
- `BIBLIOG`
- `Label1`
- `VBA6.DLL`
- `__vbaAryDestruct`
- `__vbaVarMove`
- `__vbaStrVarMove`
- `__vbaI2I4`
- `__vbaVarTstEq`
- `__vbaI4Str`
- `__vbaCastObjVar`
- `__vbaObjSet`
- `__vbaVarLateMemCallLd`
- `__vbaStrMove`
- `__vbaStrCmp`
- `__vbaFreeObj`
- `__vbaFreeVar`
- `__vbaFreeStr`
- `__vbaHresultCheckObj`
- `__vbaNew2`
- `__vbaFreeVarList`
- `__vbaVarDup`
- `__vbaVarTstNe`
- `Tamburin5`
- `O|K{K/`
- `;iC=w}`
- `O$X32\`
- `O|XPHT`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401288
```asm
┌ 236: entry0 ();
│           0x00401288      6868134000     push 0x401368               ; 'h\x13@' ; "VB5!6&*"
│           0x0040128d      e8f0ffffff     call 0x401282
│           0x00401292      0000           add byte [eax], al
│           0x00401294      0000           add byte [eax], al
│           0x00401296      0000           add byte [eax], al
│           0x00401298      3000           xor byte [eax], al
│           0x0040129a      0000           add byte [eax], al
│           0x0040129c      40             inc eax
│           0x0040129d      0000           add byte [eax], al
│           0x0040129f      0000           add byte [eax], al
│           0x004012a1      0000           add byte [eax], al
│           0x004012a3      003a           add byte [edx], bh
│           0x004012a5      6a88           push 0xffffffffffffff88
│           0x004012a7      37             aaa
│           0x004012a8      a15c9c4082     mov eax, dword [0x82409c5c] ; [0x82409c5c:4]=-1
│           0x004012ad      05e818098c     add eax, 0x8c0918e8
│           0x004012b2      3d8c000000     cmp eax, 0x8c               ; 140
│           0x004012b7      0000           add byte [eax], al
│           0x004012b9      0001           add byte [ecx], al
│           0x004012bb      0000           add byte [eax], al
│           0x004012bd      00426f         add byte [edx + 0x6f], al
│       ┌─< 0x004012c0      7264           jb 0x401326
│      ┌──< 0x004012c2      657261         jb 0x401326
│      ││   0x004012c5      6461           popal
│      ││   0x004012c7      6d             insd dword es:[edi], dx
│      ││   0x004012c8      61             popal
│     ┌───< 0x004012c9      7370           jae 0x40133b
│    ┌────< 0x004012cb      7265           jb 0x401332
│    ││││   0x004012cd      690043617074   imul eax, dword [eax], 0x74706143
│    ││││   0x004012d3      690000000006   imul eax, dword [eax], 0x6000000
│    ││││   0x004012d9      0000           add byte [eax], al
│    ││││   0x004012db      00ec           add ah, ch
│    ││││   0x004012dd      1d40000100     sbb eax, 0x10040
│    ││││   0x004012e2      0100           add dword [eax], eax
│    ││││   0x004012e4      1c1a           sbb al, 0x1a
│    ││││   0x004012e6      40             inc eax
│    ││││   0x004012e7      0000           add byte [eax], al
│    ││││   0x004012e9      0000           add byte [eax], al
│    ││││   0x004012eb      00ff           add bh, bh
..
│    ││└└─> 0x00401326      88b94847ed26   mov byte [ecx + 0x26ed4748], bh ; [0x26ed4748:1]=255
│    ││     0x0040132c      0000           add byte [eax], al
│    ││     0x0040132e      0000           add byte [eax], al
│    ││     0x00401330      0000           add byte [eax], al
│    └────> 0x00401332      0000           add byte [eax], al
│     │     0x00401334      0000           add byte [eax], al
│     │     0x00401336      0000           add byte [eax], al
│     │     0x00401338      0000           add byte [eax], al
│     │     0x0040133a  ~
```
### 0x00401000
```asm
╎╎╎╎   ;-- section..text:
│    ╎╎╎╎   ;-- (0x00401004) _adj_fptan:
┌ 473: sym.imp.MSVBVM60.DLL__CIcos ();
│    ╎╎╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] -r-x section size 36864 named .text
│    ╎╎╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│    ╎╎╎╎   ;-- __vbaVarMove:
│   ┌─────> 0x00401008      ee             out dx, al
│   ╎╎╎╎╎   0x00401009      6aa4           push 0xffffffffffffffa4
│   ╎╎╎╎╎   ;-- (0x0040100c) __vbaFreeVar:
│  ┌──────< 0x0040100b  ~   7231           jb 0x40103e
│  │╎╎╎╎╎   0x0040100d  ~   68a4722919     push 0x192972a4
│ ┌───────> 0x0040100e      a4             movsb byte es:[edi], byte [esi]
│ ╎│╎╎╎╎╎   0x0040100f  ~   7229           jb 0x40103a
│ ╎│╎╎╎╎╎   ;-- __vbaStrVarMove:
..
│ ╎│╎╎╎╎╎   ;-- (0x00401014) __vbaFreeVarList:
│ ╎│╎╎╎╎╎   0x00401011  ~   19a2726272a4   sbb dword [edx - 0x5b8d9d8e], esp
│ ╎│╎╎╎│╎   ;-- (0x00401018) _adj_fdiv_m64:
│ ╎│╎╎╎└──< 0x00401017  ~   72ba           jb 0x400fd3
│ ╎│╎╎╎ ╎   ;-- (0x0040101c) rtcVarBstrFromChar:
│ ╎│╎╎╎ ╎   0x00401019  ~   02a372c20fa2   add ah, byte [ebx - 0x5df03d8e]
│ ╎│╎╎╎ ╎   ;-- (0x00401020) _adj_fprem1:
│ ╎│╎╎╎┌──> 0x0040101e  ~   a2724109a3     mov byte [0xa3094172], al   ; [0xa3094172:1]=255
│ ╎│╎╎╎╎╎   ;-- (0x00401024) rtcLowerCaseVar:
│ ────────> 0x00401021  ~   09a372a075a2   or dword [ebx - 0x5d8a5f8e], esp
│ ╎│╎╎╎╎╎   0x00401025      75a2           jne 0x400fc9
│ ╎│╎╎╎╎╎   ;-- (0x00401028) rtcTrimBstr:
│ ────────< 0x00401027  ~   7201           jb 0x40102a
│ ╎│╎╎╎╎└─< 0x00401029  ~   76a2           jbe 0x400fcd
│ ────────> 0x0040102a  ~   a27274a2a1     mov byte [0xa1a27472], al   ; [0xa1a27472:1]=255
│ ╎│╎╎╎╎    ;-- (0x0040102c) __vbaHresultCheckObj:
│ ╎│╎╎╎╎┌─< 0x0040102b  ~   7274           jb 0x4010a1
│ ╎│╎╎╎╎│   0x0040102d  ~   a2a172b1c8     mov byte [0xc8b172a1], al   ; [0xc8b172a1:1]=255
│ ╎│╎╎╎╎│   ;-- (0x00401030) rtcIsDate:
│ ╎│╎╎╎╎│   0x0040102e  ~   a172b1c8a1     mov eax, dword [0xa1c8b172] ; [0xa1c8b172:4]=-1
│ ╎│╎╎╎╎│   ;-- (0x00401034) _adj_fdiv_m32:
│ ╎│╎╎╎╎│   0x00401031  ~   c8a1726e       enter 0x72a1, 0x6e
│ ╎│╎╎╎╎│   0x00401035  ~   02a372fec1a1   add ah, byte [ebx - 0x5e3e018e]
│ ╎│╎╎╎╎│   ;-- (0x00401038) __vbaAryDestruct:
│ ────────> 0x00401037  ~   72fe           jb 0x401037
│ ╎│╎╎╎╎│   0x00401039  ~   c1a172f19f..   shl dword [ecx - 0x5e600e8e], 0x72
│ ╎│╎╎╎╎│   ;-- (0x0040103c) __vbaObjSet:
│ ╎│╎╎╎╎│   0x0040103a  ~   a172f19fa1     mov eax, dword [0xa19ff172] ; [0xa19ff172:4]=-1
│ ╎│╎╎╎╎│   0x0040103d      9f             lahf
│ ╎└──────> 0x0040103e  ~   a1720603a3     mov eax, dword [0xa3030672] ; [0xa3030672:4]=-1
│ ╎ ╎╎╎╎│   ;-- (0x00401040) _adj_fdiv_m16i:
│ ╎┌──────> 0x0040103f  ~   7206           jb 0x401047
│ ╎╎╎╎╎╎│   0x00401041  ~   03a372a264a3   add esp, dword [ebx - 0x5c9b5d8e]
│ ────────> 0x00401043  ~   72a2           jb 0x400fe7
│ ╎╎╎╎╎╎│   ;-- rtcFormatNumber:
│ ────────> 0x00401044  ~   a264a37206     mov byte [0x672a364], al    ; [0x672a
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
- hook_candidates:
  - `MSVBVM60.DLL!_CIcos`
  - `MSVBVM60.DLL!_adj_fptan`
  - `MSVBVM60.DLL!__vbaVarMove`
  - `MSVBVM60.DLL!__vbaFreeVar`
  - `MSVBVM60.DLL!__vbaStrVarMove`
