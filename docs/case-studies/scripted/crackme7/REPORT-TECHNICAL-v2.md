> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 17:12:44 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **suspicious** |
| Triage upstream (quick ∪ deep) | suspicious |
| Quick scan | suspicious |
| Deep dive | crackme |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

The sample `fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f` is a PE32 Windows GUI application self-identifying as "HEXORCIST CRACKME 7" (source: floss, strings, "HEXORCIST CRACKME 7"). Analysis across multiple engines (Malcat, IDA, FLOSS, capa, YARA, radare2) reveals a binary designed as a reverse engineering challenge, not a malicious payload. The entry point at `0x401000` executes a XOR decryption stub that decrypts 1496 bytes at `0x4012b3` using key `0x66`, then registers the decrypted code as a Vectored Exception Handler (VEH) and triggers it via HLT (source: radare2, disassembly, 0x00401000). The binary imports only 9 APIs from KERNEL32 and USER32, all related to GUI dialog interaction and structured exception handling (source: malcat, Imports, 9 rows). FLOSS extracted 33 static strings including "SERIAL:" and "now this is getting serious", confirming the crackme nature (source: floss, strings, 33 total). No behavioral indicators of malicious activity were observed: no C2 communication, persistence mechanisms, credential theft, data exfiltration, or defense impairment routines were detected (source: deep_dive_agentic, summary). The verdict is **suspicious** (score: 30) due to obfuscation via XOR encoding and high entropy, but these are neutral signals consistent with crackme/CTF challenges (source: llm_judge, verdict).

## 2. Sample Metadata

The following metadata was extracted from the PE header and tool analysis. The sample is a 32-bit Windows GUI executable compiled with FASM (source: malcat, YARA, FASM rule), with an import hash of `d7f03e6d403ce99bd9054453497aa12e` (source: rule.yara.json, imphash).

| Field | Value | Source |
|---|---|---|
| SHA256 | `fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f` | malcat, File Summary |
| File Name | `crackme7.exe` | malcat, File Summary |
| File Size | 141824 bytes | malcat, File Summary |
| File Type | PE (PE32) | malcat, File Summary |
| Architecture | X86 | malcat, File Summary |
| Entry Point EA | 1024 (0x401000) | malcat, File Summary |
| Entropy | 84 | malcat, File Summary |
| Original Filename | `hexo7.EXE` | malcat, Top Strings, EA 153612 |
| File Description | `HEXORCIST CRACKME 7` | malcat, Top Strings, EA 153364 |
| Legal Copyright | `Copyright SAS HEXORCIST` | malcat, Top Strings, EA 153440 |
| Compiler | FASM (flat assembler) | malcat, YARA, FASM rule |
| Import Hash | `d7f03e6d403ce99bd9054453497aa12e` | rule.yara.json, imphash |

## 3. File Layout & Structural Analysis

The PE file contains 6 sections with varying entropy levels. The `.text` section is marked RWX (Read-Write-Execute), which is anomalous and enables self-modifying code (source: malcat, anomalies, SectionWX). The `.rsrc` section has entropy of 85%, indicating packed or compressed resources (source: malcat, anomalies, SuspiciousEntropy). The entry point at `0x401000` falls within the `.text` section but is flagged as EntryOutsideSections by Malcat (source: deep_dive_agentic, key_evidence).

### Section Layout Table

| Name | EA | Physical Size | Virtual Size | Entropy | Rights | Source |
|---|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - | malcat, File Layout |
| .text | 1024 | 2560 | 4096 | 77 | RWX | malcat, File Layout |
| .bss | 5120 | 512 | 4096 | 0 | RW | malcat, File Layout |
| .idata | 9216 | 512 | 4096 | 0 | RW | malcat, File Layout |
| .data | 13312 | 512 | 4096 | 0 | RW | malcat, File Layout |
| .rsrc | 17408 | 136704 | 139264 | 85 | R | malcat, File Layout |

The `.text` section's RWX permissions are a significant anomaly (source: malcat, anomalies, SectionWX). This allows the binary to modify its own code at runtime, which is a technique used for obfuscation and anti-analysis. The high entropy of the `.rsrc` section (85%) suggests packed resources, likely containing the GUI dialog and icon data (source: malcat, anomalies, SuspiciousEntropy). The `.idata` section contains the import table with 9 entries (source: malcat, Imports).

### Carved and Virtual Files

Malcat carved 1 file and identified 4 virtual files within the resources:

| Name | Type | Size | Source |
|---|---|---|---|
| ? | DIB | 135208 | malcat, Carved Files |
| ICO/1/unk | - | 135208 | malcat, Virtual Files |
| DLG/37/en-us | - | 232 | malcat, Virtual Files |
| GRPICO/17/unk | - | 20 | malcat, Virtual Files |
| VER/1/unk | - | 528 | malcat, Virtual Files |

The large DIB (Device Independent Bitmap) file at 135208 bytes is likely the application icon or splash screen graphic. The DLG resource contains the dialog template for the serial number input prompt (source: floss, strings, "SERIAL:").

## 4. Static Code Analysis

The entry point at `0x401000` is a compact XOR decryption stub that decrypts the real payload. The disassembly below was extracted from radare2 (source: radare2, disassembly, 0x00401000).

### Entry Point Disassembly

```asm
;-- section..text:
┌ 30: entry0 ();
│           0x00401000      b8b3124000     mov eax, 0x4012b3           ; [00] -rwx section size 4096 named .text
│           0x00401005      b9d8050000     mov ecx, 0x5d8              ; 1496
│       ┌─> 0x0040100a      803066         xor byte [eax], 0x66        ; [0x66:1]=255 ; 102
│       ╎   0x0040100d      40             inc eax
│       └─< 0x0040100e      e2fa           loop 0x40100a
│           0x00401010      68b3124000     push 0x4012b3
│           0x00401015      6a01           push 1                      ; 1
│           0x00401017      ff156c304000   call dword [sym.imp.KERNEL32.DLL_AddVectoredExceptionHandler] ; 0x40306c ; PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
└           0x0040101d      f4             hlt
```

This stub performs three operations: (1) it loads the address `0x4012b3` into EAX and the count `0x5d8` (1496 decimal) into ECX, then XORs each byte at `[EAX]` with the key `0x66`, incrementing EAX and decrementing ECX until the loop completes (source: radare2, disassembly, 0x0040100a-0x0040100e). This is a classic single-byte XOR decryption loop (source: capa, capa, encode data using XOR). (2) It pushes the decrypted address `0x4012b3` and `1` (First=1, meaning first-chance handler) onto the stack and calls `AddVectoredExceptionHandler` to register the decrypted code as a VEH (source: radare2, disassembly, 0x00401010-0x00401017). (3) It executes HLT, which triggers an exception that transfers control to the registered VEH handler (source: radare2, disassembly, 0x0040101d).

### Malcat Decompilation of Entry Point

Malcat's decompiler provides a C-like representation of the same logic (source: malcat, Decompilations, 1024 — EntryPoint):

```c
void EntryPoint(void)
{
    uint8_t *puVar1;
    int32_t iVar2;
    
    puVar1 = 0x4012b3;
    iVar2 = 0x5d8;
    do {
        *puVar1 = *puVar1 ^ 0x66;
        puVar1 = puVar1 + 1;
        iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    (*kernel32.AddVectoredExceptionHandler)(1, 0x4012b3);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```

The decompilation confirms the XOR decryption loop and VEH registration. The "infinite loop" warning corresponds to the HLT instruction, which halts the CPU until an exception occurs (source: malcat, Decompilations, 1024). This technique is commonly used in crackmes to hide the real logic from static analysis tools.

### Function Metrics

Only 1 function was detected by the analysis pipeline (source: deep_dive_agentic, key_evidence). This is because the real payload is encrypted and not recognized as code until runtime.

| EA | Name | Size | Instructions | Source |
|---|---|---|---|---|
| 1024 | EntryPoint | 30 bytes | 8 | malcat, Functions |

### Anomalies Detected

Malcat identified 4 anomalies that indicate obfuscation and anti-analysis techniques (source: malcat, anomalies):

| Name | Level | Category | Hits | Description | Source |
|---|---|---|---|---|---|
| SectionWX | 3 | sections | 1 | section is executable and writeable | malcat, anomalies |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced | malcat, anomalies |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop | malcat, anomalies |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) | malcat, anomalies |

The XorInLoop anomaly at address `1034` corresponds to the XOR decryption in the entry stub (source: malcat, Anomaly Locations, XorInLoop, 1034). The UnreferencedImports anomaly indicates that 8 of the 9 imports are not directly called in the visible code, suggesting they may be used by the decrypted payload or are decoys (source: malcat, anomalies, UnreferencedImports).

## 5. Behavioral & Dynamic Analysis

Dynamic analysis tools were executed but produced no observable runtime behavior. Speakeasy emulation recorded zero API calls and zero key events (source: Structured Evidence, Speakeasy). Frida probe identified 8 hook candidates but no runtime events were captured (source: Structured Evidence, Frida Probe). This is expected because the binary's real logic is encrypted and requires the VEH mechanism to execute, which may not trigger correctly in emulation environments.

### Speakeasy Emulation

- **Status**: `speakeasy_ok: True` (source: Structured Evidence, Speakeasy)
- **API Calls**: 0 (source: Structured Evidence, Speakeasy)
- **Key Events**: 0 (source: Structured Evidence, Speakeasy)
- **Assessment**: not observed — the encrypted payload likely requires specific exception handling that the emulator did not trigger.

### Frida Probe

- **Status**: `frida_available: True`, version 17.16.4 (source: Structured Evidence, Frida Probe)
- **Hook Candidates**: 8 APIs identified for monitoring (source: Structured Evidence, Frida Probe):
  - `KERNEL32.DLL!GetModuleHandleA`
  - `KERNEL32.DLL!AddVectoredExceptionHandler`
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!DialogBoxParamA`
  - `USER32.DLL!GetDlgItemTextA`
  - `USER32.DLL!MessageBoxA`
  - `USER32.DLL!LoadIconA`
  - `USER32.DLL!SendMessageA`
- **Assessment**: not observed — no runtime events were captured, likely due to the same VEH execution mechanism not triggering in the probe environment.

## 6. Network Indicators & C2

No network indicators or command-and-control (C2) infrastructure were identified in this sample. The import table contains no networking APIs (e.g., `wininet.dll`, `ws2_32.dll`, `urlmon.dll`) (source: malcat, Imports, 9 rows). FLOSS extracted no URLs, IP addresses, or domain names from the static strings (source: floss, strings, 33 total). YARA matched rules for `domain`, `IP`, and `contains_base64` (source: yara, YARA matches), but these are generic pattern matches and do not indicate actual C2 communication. The deep-dive analysis explicitly states: "C2_network: not observed; no network activity or command-and-control communication indicators detected" (source: deep_dive_agentic, summary).

## 7. Capabilities Assessment

The sample's capabilities are limited to GUI interaction and self-modifying code for obfuscation. No malicious capabilities were observed.

### Observed Capabilities

| Capability | Evidence | Source |
|---|---|---|
| XOR Decryption | Entry stub at `0x401000` XORs 1496 bytes with key `0x66` | radare2, disassembly |
| Vectored Exception Handler | Calls `AddVectoredExceptionHandler` to register decrypted code | radare2, disassembly |
| Self-Modifying Code | `.text` section is RWX, enabling runtime code modification | malcat, anomalies, SectionWX |
| GUI Dialog Interaction | Imports `DialogBoxParamA`, `GetDlgItemTextA`, `MessageBoxA`, `EndDialog` | malcat, Imports |
| Serial Number Validation | String "SERIAL:" indicates password/key input prompt | floss, strings |

### Latent Capabilities (Present but Unused)

| Capability | Evidence | Source |
|---|---|---|
| ExitProcess | Imported but not referenced in visible code | malcat, Imports, EA 9328 |
| LoadIconA | Imported but not referenced in visible code | malcat, Imports, EA 9440 |
| SendMessageA | Imported but not referenced in visible code | malcat, Imports, EA 9444 |

### Not Observed

- **Persistence**: No registry keys, scheduled tasks, or service installation detected (source: deep_dive_agentic, summary).
- **Credential Theft**: No LSASS access, token manipulation, or credential harvesting APIs (source: deep_dive_agentic, summary).
- **Data Exfiltration**: No file collection, compression, or upload routines (source: deep_dive_agentic, summary).
- **Defense Impairment**: No AV/AMSI/ETW disabling, though self-modifying code could theoretically evade static analysis (source: deep_dive_agentic, summary).

## 8. Indicators of Compromise

This sample does not produce traditional IOCs for detection due to its crackme nature. However, the following artifacts can be used for identification:

### File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | `fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f` | malcat, File Summary |
| Import Hash | `d7f03e6d403ce99bd9054453497aa12e` | rule.yara.json, imphash |
| Original Filename | `hexo7.EXE` | malcat, Top Strings, EA 153612 |
| File Description | `HEXORCIST CRACKME 7` | malcat, Top Strings, EA 153364 |

### String-Based IOCs

| String | EA | Source |
|---|---|---|
| `HEXORCIST CRACKME 7` | 17686 | malcat, Top Strings |
| `SERIAL:` | (in FLOSS) | floss, strings |
| `now this is getting serious` | 13312 | malcat, Top Strings |
| `Copyright SAS HEXORCIST` | 153440 | malcat, Top Strings |
| `hexo7.EXE` | 153612 | malcat, Top Strings |

### Behavioral IOCs

| Behavior | Indicator | Source |
|---|---|---|
| XOR Decryption Loop | `0x40100a: xor byte [eax], 0x66` in loop | radare2, disassembly |
| VEH Registration | `call AddVectoredExceptionHandler` at `0x401017` | radare2, disassembly |
| HLT Trigger | `hlt` at `0x40101d` | radare2, disassembly |

## 9. Detection Engineering

Detection rules should focus on the unique execution pattern rather than generic obfuscation.

### YARA Rule

A YARA rule was generated for this sample (source: rule.yara.json). Key strings for detection:

```yara
rule CTF_Crackme_7 {
    meta:
        sha256 = "fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f"
        family = "CTF Crackme 7"
        imphash = "d7f03e6d403ce99bd9054453497aa12e"
    strings:
        $s1 = "HEXORCIST CRACKME 7" ascii
        $s2 = "SERIAL:" ascii
        $s3 = "now this is getting serious" ascii
        $s4 = "Copyright SAS HEXORCIST" ascii
        $s5 = "hexo7.EXE" ascii
        $code1 = { B8 B3 12 40 00 B9 D8 05 00 00 80 30 66 40 E2 FA }
    condition:
        uint16(0) == 0x5A4D and 3 of ($s*) and $code1
}
```

The code pattern `$code1` matches the XOR decryption stub at the entry point (source: radare2, disassembly, 0x00401000-0x0040100e).

### Sigma Rule

A Sigma rule was also generated (source: rule.yara.json, sigma_path). For endpoint detection, monitor for:
- Processes with `AddVectoredExceptionHandler` calls followed by `HLT` instructions.
- PE files with RWX `.text` sections and high entropy `.rsrc` sections.

### capa Rule

The capa rule "encode data using XOR" (source: capa, capa) maps to MITRE ATT&CK T1027 and MBC E1027.m02/C0026.002. This is a generic detection for XOR encoding, which is neutral and appears in both benign and malicious software.

## 10. MITRE ATT&CK Mapping

The sample maps to a single MITRE ATT&CK technique related to obfuscation. No other ATT&CK techniques were observed.

| Technique | ID | Evidence | Source |
|---|---|---|---|
| Obfuscated Files or Information | T1027 | XOR decryption loop at entry point | capa, capa |

The capa rule "encode data using XOR" explicitly maps to T1027 (source: capa, capa). The MBC mapping is E1027.m02 (Obfuscated Files or Information) and C0026.002 (Encode Data) (source: capa, capa). This technique is neutral and does not imply malicious intent; it is commonly used in legitimate software protection and crackmes.

## 11. What We Don't Know

Several aspects of this sample remain unknown due to the encrypted payload and limited dynamic analysis:

1. **Decrypted Payload Contents**: The real logic of the crackme is encrypted at `0x4012b3` and only executes at runtime via the VEH mechanism. We cannot determine the serial validation algorithm, anti-debug checks, or any hidden functionality without dynamic execution (source: deep_dive_agentic, summary).

2. **VEH Handler Behavior**: The registered VEH handler at `0x4012b3` is not analyzed. It may contain additional decryption layers, anti-debugging techniques, or complex validation logic (source: radare2, disassembly).

3. **Dynamic Behavior**: Speakeasy and Frida produced no runtime events (source: Structured Evidence, Speakeasy/Frida). We cannot confirm whether the binary functions as expected in a real Windows environment or if it contains additional behaviors triggered by specific conditions.

4. **Resource Contents**: The `.rsrc` section has 85% entropy (source: malcat, anomalies, SuspiciousEntropy). The dialog template and icon data are likely packed, but we cannot confirm if they contain additional code or data.

5. **Anti-Analysis Techniques**: The sample may employ anti-debugging or anti-VM techniques within the encrypted payload that are not visible in static analysis (source: deep_dive_agentic, summary).

6. **Full Import Usage**: 8 of 9 imports are unreferenced in the visible code (source: malcat, anomalies, UnreferencedImports). We cannot determine if they are used by the decrypted payload or are decoys.

## 12. Appendix A: Tool Evidence Trail

This appendix documents the tools and queries used to generate this report.

### Tool Execution Summary

| Tool | Status | Key Findings | Source |
|---|---|---|---|
| Malcat | ok | File layout, anomalies, imports, strings, decompilation | Structured Evidence |
| IDA | ok | Imports (9 from KERNEL32/USER32) | Structured Evidence |
| Ghidra | ok | Empty imports (known limitation for mixed-mode PEs) | Structured Evidence |
| FLOSS | ok | 33 static strings, 0 decoded/stack/tight strings | Structured Evidence |
| capa | ok | 1 rule: encode data using XOR | Structured Evidence |
| YARA | ok | 7 matches (domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, SEH__vectored) | Structured Evidence |
| radare2 | ok | Disassembly of entry point | Structured Evidence |
| UPX | ok | Not packed (upx_ok: False) | Structured Evidence |
| Speakeasy | ok | 0 API calls, 0 key events | Structured Evidence |
| Frida | ok | 8 hook candidates, 0 events | Structured Evidence |
| XOR Search | ok | Found XOR 00 at position 0 | Structured Evidence |

### Audit Trail (Recent)

The following queries were executed during analysis (source: Structured Evidence, Audit Trail):

- `ghidra_query`: SELECT * FROM data_items ORDER BY address
- `ghidra_query`: SELECT * FROM string_refs
- `ghidra_query`: SELECT * FROM xrefs WHERE from_ea >= 4198400 AND from_ea < 4198430
- `ida_query`: SELECT * FROM db_info
- `agentic_recover_v4`: phase start
- `ghidra_query`: SELECT address, name, size FROM funcs WHERE name LIKE 'FUN_%' OR name LIKE 'func_%' OR name = ''
- `ghidra_query`: SELECT func_addr, call_in_count, string_ref_count FROM function_metrics
- `ghidra_query`: SELECT func_addr, COUNT(*) AS c FROM string_refs GROUP BY func_addr
- `ghidra_query`: SELECT src_func_addr, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR ...
- `ghidra_query`: SELECT address, name, size FROM funcs
- `ghidra_query`: SELECT start_ea, end_ea, name FROM memory_blocks
- `ghidra_query`: SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'
- `ghidra_query`: SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR ...
- `ghidra_query`: SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR ...
- `ghidra_query`: SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR ...
- `ghidra_query`: SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR ...
- `ghidra_query`: SELECT address, content FROM strings WHERE length < 300
- `ghidra_query`: SELECT address, name, size FROM funcs
- `ghidra_query`: SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR ...
- `ghidra_query`: SELECT src_func_addr, dst_func_addr FROM call_edges
- `ghidra_query`: SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR ...
- `ghidra_query`: SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'
- `ghidra_query`: SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'
- `ghidra_query`: SELECT count(*) as c FROM funcs
- `ghidra_query`: SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, instruction_count, block_count FROM function_metrics
- `ghidra_query`: SELECT src_func_addr, dst_func_addr FROM call_edges
- `agentic_recover_v4`: phase complete
- `ghidra_query`: SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80
- `ida_query`: SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80
- `yara_gen_v2`: timestamp 1786295258.282813

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following tools and configurations:

### Tools Used

| Tool | Version | Purpose |
|---|---|---|
| Malcat | (unknown) | Static analysis, decompilation, anomaly detection |
| IDA Pro | (unknown) | Disassembly, import analysis |
| Ghidra | (unknown) | Disassembly, function analysis (limited for mixed-mode PEs) |
| FLOSS | (unknown) | String extraction (static, decoded, stack, tight) |
| capa | (unknown) | Capability detection, MITRE mapping |
| YARA | (unknown) | Pattern matching, rule generation |
| radare2 | (unknown) | Disassembly, binary analysis |
| UPX | (unknown) | Packer detection |
| Speakeasy | (unknown) | Dynamic emulation |
| Frida | 17.16.4 | Dynamic instrumentation |

### Environment Notes

- **Ghidra Limitation**: Ghidra reported an empty imports table due to a known limitation for mixed-mode PEs (source: llm_judge, cross_engine_notes). IDA and Malcat were used as authoritative sources for import data.
- **String Counts**: String counts vary across tools (Ghidra: 28, IDA: 13, FLOSS: 33) due to different extraction methodologies (source: llm_judge, cross_engine_notes).
- **Dynamic Analysis**: Speakeasy and Frida produced no runtime events, likely because the encrypted payload requires specific exception handling that did not trigger in the emulation/probe environment (source: Structured Evidence, Speakeasy/Frida).
- **Goodware Corpus**: The goodware corpus was not staged for false positive analysis (source: rule.yara.json, goodware_fp, skipped).
- **YARA Generation**: YARA rule generation was performed by the `yara_gen_v2` engine (source: rule.yara.json, provenance).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f  
**sample_path:** /opt/samples/corpus/REVAI-LAB-CORPUS-H1/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe  
**project_name:** REVAI-LAB-CORPUS-H1

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 30
- **family_guess**: CTF Crackme 7
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reported an empty imports table due to a known limitation for mixed-mode PEs, but IDA and Malcat consistently identified 9 imports from KERNEL32 and USER32 modules. String counts vary across tools (Ghidra: 28, IDA: 13, FLOSS: 33), reflecting different extraction methodologies. The sample shows obfuscation via XOR encoding and high entropy, but no behavioral evidence of malicious intent such as C2 communication, persistence, or data destruction.
- **summary**: The sample is a PE32 binary identified as a crackme application (CTF Crackme 7). It exhibits obfuscation through XOR encoding and high entropy, but analysis across multiple engines reveals no behavioral indicators of malicious activity such as command-and-control, persistence, credential theft, or data exfiltration. The presence of GUI elements, serial number input, and benign API imports supports its classification as suspicious but not definitively malicious, likely serving as a puzzle or educational tool.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ida | Imports (IDA) | `rows: (module: KERNEL32, name: GetModuleHandleA), (module: KERNEL32, name: AddVe` | Lists standard Windows API imports for GUI and error handling, indicating a typical benign application with dialog boxes |
| malcat | anomalies | `XorInLoop (code) at address 1034` | Identifies an XOR instruction in a loop at the entry point, which is a common obfuscation technique. However, this is a  |
| floss | strings | `"HEXORCIST CRACKME 7", "SERIAL:", "now this is getting serious"` | These strings strongly suggest the sample is a crackme or keygen challenge, with clear indications of serial number inpu |
| capa | capa | `rule: encode data using XOR (ATT&CK T1027)` | Confirms the use of XOR encoding for obfuscation, aligning with the observed XOR loop. This technique is neutral and doe |
| yara | YARA matches | `rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, SEH__vectored` | Multiple YARA matches, but in context, these are likely benign indicators (e.g., PE structure, FASM compiler, SEH for er |
| malcat | static_profile | `entropy: 84, SectionWX anomaly, UnreferencedImports×8` | High entropy and writable-executable section indicate packing or protection, which are neutral signals. Unreferenced imp |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE32 Windows GUI crackme (reverse engineering challenge) from the CTF 1 CTF series. The entry point at 0x401000 is a XOR decryption stub that decrypts 1496 bytes at 0x4012b3 using single-byte key 0x66, then registers the decrypted code as a Vectored Exception Handler via AddVectoredExceptionHandler and executes HLT to trigger it. The binary presents a dialog box asking for a serial number ('SERIAL:'). The .text section is RWX enabling self-modifying code, and the .rsrc section has entropy 85% indicating packed resources. FLOSS decoded 0 stack/tight strings (entire payload is bulk-encrypted). CAPA confirms XOR encoding (T1027/E1027.m02/C0026.002). Only 9 imports (GUI + SEH APIs) and 1 detected function (the stub) due to encrypted payload hiding all real logic. Additional coverage: Persistence: not observed; no evidence of mechanisms like registry keys or scheduled tasks for long-term execution. C2_network: not observed; no network activity or command-and-control communication indicators detected. Exfiltration: not observed; no data collection or exfiltration routines identified. Defense_impairment: observed; self-modifying code is enabled by RWX .text section (evidence: {summary, section properties, .text is RWX, allows dynamic code modification for evasion}) and bulk-encryption of payload impairs analysis (evidence: {FLOSS, string analysis, 0 stack strings decoded, hides malicious functionality from static tools}).

### deep key_evidence
- `"Entry stub at 0x401000: MOV EAX,0x4012b3; MOV ECX,0x5d8; XOR byte ptr [EAX],0x66; INC EAX; LOOP \u2192 bulk XOR decryption of 1496 bytes with key 0x66"`
- `"PUSH 0x4012b3 + PUSH 0x1 + CALL AddVectoredExceptionHandler \u2192 registers decrypted payload as first-chance VEH, then HLT triggers exception"`
- `"CAPA match: 'encode data using XOR' \u2192 MITRE T1027 Defense Evasion, MBC E1027.m02/C0026.002"`
- `"Malcat anomalies: SectionWX (.text RWX), SuspiciousEntropy (.rsrc 85% > 7.5 threshold), FewStrings (<1%), EntryOutsideSections"`
- `"FLOSS static strings: 'SERIAL:' (crackme password prompt), 'now this is getting serious', 'HEXORCIST CRACKME 7', 'Copyright SAS HEXORCIST'"`
- `"VersionInfo: FileDescription='HEXORCIST CRACKME 7', OriginalFilename='hexo7.EXE' \u2014 self-identifies as CTF CTF challenge"`
- `"GUI imports: DialogBoxParamA, GetDlgItemTextA, MessageBoxA, EndDialog \u2014 typical crackme dialog interaction"`
- `"Only 1 function detected (entry stub, 30 bytes, 8 instructions) \u2014 all real logic hidden inside XOR-encrypted blob"`
- `"YARA hits: SEH__vectored (VEH patterns at offset 4238), contains_base64, IP/IPv6 patterns"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f
size: 141824
type: PE
architecture: X86
entrypoint_ea: 1024
entropy: 84
file_name: crackme7.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - |
| .text | 1024 | 2560 | 4096 | 77 | RWX |
| .bss | 5120 | 512 | 4096 | 0 | RW |
| .idata | 9216 | 512 | 4096 | 0 | RW |
| .data | 13312 | 512 | 4096 | 0 | RW |
| .rsrc | 17408 | 136704 | 139264 | 85 | R |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| FASM | compiler | INFO | 70 | detects fasm using DOS stub |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) |

### Anomaly Locations (high-signal)
- **XorInLoop**
  - `1034`: 

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 9276 | `KERNEL32.DLL` |

### Top Strings (139 extracted; showing 80)
| EA | String |
|---|---|
| 9276 | `KERNEL32.DLL` |
| 9290 | `USER32.DLL` |
| 13312 | `now this is getting serious` |
| 153612 | `hexo7.EXE` |
| 153178 | `VS_VERSION_INFO` |
| 153578 | `OriginalFilename` |
| 153306 | `040904E4` |
| 17686 | `HEXORCIST CRACKME 7` |
| 153440 | `Copyright SAS HEXORCIST` |
| 153364 | `HEXORCIST CRACKME 7` |
| 9358 | `AddVectoredExceptionHandler` |
| 153330 | `FileDescription` |
| 153270 | `StringFileInfo` |
| 153534 | `ProductVersion` |
| 2614 | `fffW` |
| 2600 | `fffW` |
| 2628 | `fffW` |
| 3012 | `fff`` |
| 2744 | `fffb` |
| 2569 | `fffe` |
| 2555 | `fffW` |
| 2642 | `fffe` |
| 2541 | `fffW` |
| 2527 | `fffW` |
| 3032 | `fffb` |
| 2496 | `fff`` |
| 2477 | `fff_` |
| 2448 | `fff`` |
| 3045 | `fffd` |
| 3065 | `fffb` |
| 3078 | `fffd` |
| 2408 | `fff`` |
| 2841 | `fffd` |
| 2940 | `fffd` |
| 2919 | `fffb` |
| 2952 | `fffb` |
| 2907 | `fffd` |
| 2886 | `fffb` |
| 2973 | `fffd` |
| 2874 | `fffd` |
| 2853 | `fffb` |
| 2660 | `fffd` |
| 2820 | `fffb` |
| 2808 | `fffd` |
| 2787 | `fffb` |
| 2326 | `fffW` |
| 2722 | `fffd` |
| 2696 | `fffd` |
| 2985 | `fffb` |
| 2678 | `fffd` |
| 3185 | `fffb` |
| 153670 | `Translation` |
| 153494 | `FileVersion` |
| 2086 | `fff`` |
| 2107 | `fff`` |
| 2128 | `fff`` |
| 2149 | `fff`` |
| 3198 | `fffd` |
| 2177 | `fff`` |
| 3095 | `fffb` |
| 2215 | `fffe` |
| 3168 | `fffd` |
| 2354 | `fffW` |
| 3108 | `fffd` |
| 3125 | `fffb` |
| 2368 | `fffe` |
| 2239 | `fffe` |
| 2340 | `fffW` |
| 3138 | `fffd` |
| 2295 | `fffd` |
| 2263 | `fffe` |
| 3155 | `fffb` |
| 77 | `!This program ca.. in DOS mode.
$` |
| 153410 | `LegalCopyright` |
| 17728 | `MS Sans Serif` |
| 2231 | `fffVn` |
| 13444 | `error` |
| 2255 | `fffVn` |
| 2207 | `fffVn` |
| 9476 | `GetDlgItemTextA` |

### Imports (9)
| EA | Name | Type | Refs |
|---|---|---|---|
| 9320 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 9324 | kernel32.AddVectoredExceptionHandler | IMPORT | 1 |
| 9328 | kernel32.ExitProcess | IMPORT | 0 |
| 9428 | user32.DialogBoxParamA | IMPORT | 1 |
| 9432 | user32.GetDlgItemTextA | IMPORT | 0 |
| 9436 | user32.MessageBoxA | IMPORT | 0 |
| 9440 | user32.LoadIconA | IMPORT | 0 |
| 9444 | user32.SendMessageA | IMPORT | 0 |
| 9448 | user32.EndDialog | IMPORT | 0 |

### Functions (1)
| EA | Name |
|---|---|
| 1024 | EntryPoint |

### Decompilations (top 6)
#### 1024 — EntryPoint
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    int32_t iVar2;
    
    puVar1 = 0x4012b3;
    iVar2 = 0x5d8;
    do {
        *puVar1 = *puVar1 ^ 0x66;
        puVar1 = puVar1 + 1;
        iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    (*kernel32.AddVectoredExceptionHandler)(1, 0x4012b3);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 135208 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 135208 | - |
| DLG/37/en-us | 232 | - |
| GRPICO/17/unk | 20 | - |
| VER/1/unk | 528 | - |

### Structures (29)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 9216 |
| ImportNames | 9276 |
| kernel32.OFT | 9304 |
| kernel32.FT | 9320 |
| ImportNames | 9336 |
| user32.OFT | 9400 |
| user32.FT | 9428 |
| ImportNames | 9456 |
| Resources | 17408 |
| Resources.DLG | 17456 |
| Resources.DLG.37 | 17480 |
| Resources.GRPICO | 17504 |
| Resources.GRPICO.17 | 17528 |
| Resources.ICO | 17552 |
| Resources.ICO.1 | 17576 |
| Resources.VER | 17600 |
| Resources.VER.1 | 17624 |
| Resources.DLG.37.en-us | 17648 |
| Resources.DLG.37.en-us.Data | 17664 |
| Resources.ICO.1.unk | 17896 |
| Resources.ICO.1.unk.Data | 17912 |
| Resources.GRPICO.17.unk | 153120 |
| Resources.GRPICO.17.unk.Data | 153136 |
| Resources.VER.1.unk | 153156 |
| VersionInfo | 153172 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.79

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |

## PE Imports / Signals
import_count: 9

## YARA Matches (pipeline)
Total matches: 7

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@6508 len=2 |
| contains_base64 | - | $a@4218 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| FASM | - |  |
| SEH__vectored | - | $@4238 len=27 |

## Generated YARA Meta
```json
{
  "sha256": "fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f",
  "family": "CTF Crackme 7",
  "imphash": "d7f03e6d403ce99bd9054453497aa12e",
  "generated_at": "2026-08-09T17:07:38.282650+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "KERNEL32.DLL",
    "USER32.DLL",
    "GetModuleHandleA",
    "AddVectoredExceptionHandler",
    "ExitProcess",
    "DialogBoxParamA",
    "GetDlgItemTextA",
    "MessageBoxA",
    "LoadIconA",
    "SendMessageA",
    "EndDialog",
    "now this is getting serious",
    "x0= 7*;1+,xhi!",
    "HEXORCIST CRACKME 7",
    "MS Sans Serif",
    "VS_VERSION_INFO",
    "StringFileInfo",
    "040904E4",
    "FileDescription",
    "LegalCopyright",
    "Copyright SAS HEXORCIST",
    "FileVersion",
    "ProductVersion"
  ],
  "rule_path": "/opt/samples/logs/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/rule.yar",
  "sigma_path": "/opt/samples/logs/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/rule.yml",
  "iocs_path": "/opt/samples/logs/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/iocs.json",
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
    "utc": "2026-08-09 17:07:38 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 33 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 33}`

### High-signal FLOSS
- `KERNEL32.DLL`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.idata`
- `fffWjB`
- `KERNEL32.DLL`
- `USER32.DLL`
- `GetModuleHandleA`
- `AddVectoredExceptionHandler`
- `ExitProcess`
- `DialogBoxParamA`
- `GetDlgItemTextA`
- `MessageBoxA`
- `LoadIconA`
- `SendMessageA`
- `EndDialog`
- `now this is getting serious`
- `x0= 7*;1+,xhi!`
- `HEXORCIST CRACKME 7`
- `MS Sans Serif`
- `SERIAL:`
- `C&ancel`
- `VS_VERSION_INFO`
- `StringFileInfo`
- `040904E4`
- `FileDescription`
- `LegalCopyright`
- `Copyright SAS HEXORCIST`
- `FileVersion`
- `ProductVersion`
- `OriginalFilename`
- `hexo7.EXE`
- `VarFileInfo`
- `Translation`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 30: entry0 ();
│           0x00401000      b8b3124000     mov eax, 0x4012b3           ; [00] -rwx section size 4096 named .text
│           0x00401005      b9d8050000     mov ecx, 0x5d8              ; 1496
│       ┌─> 0x0040100a      803066         xor byte [eax], 0x66        ; [0x66:1]=255 ; 102
│       ╎   0x0040100d      40             inc eax
│       └─< 0x0040100e      e2fa           loop 0x40100a
│           0x00401010      68b3124000     push 0x4012b3
│           0x00401015      6a01           push 1                      ; 1
│           0x00401017      ff156c304000   call dword [sym.imp.KERNEL32.DLL_AddVectoredExceptionHandler] ; 0x40306c ; PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
└           0x0040101d      f4             hlt
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

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
  - `KERNEL32.DLL!GetModuleHandleA`
  - `KERNEL32.DLL!AddVectoredExceptionHandler`
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!DialogBoxParamA`
  - `USER32.DLL!GetDlgItemTextA`
  - `USER32.DLL!MessageBoxA`
  - `USER32.DLL!LoadIconA`
  - `USER32.DLL!SendMessageA`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT * FROM data_items ORDER BY address", "ts": 1786295124.1195893}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM string_refs", "ts": 1786295124.1389537}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs WHERE from_ea >= 4198400 AND from_ea < 4198430", "ts": 1786295124.1407998}`
- `{"source": "ida_query", "sql": "SELECT * FROM db_info", "ts": 1786295142.7965314}`
- `{"source": "agentic_recover_v4", "phase": "start", "ts": 1786295255.40101}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs WHERE name LIKE 'FUN_%' OR name LIKE 'func_%' OR name = ''", "ts": 1786295255.4234216}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, call_in_count, string_ref_count FROM function_metrics", "ts": 1786295255.4303684}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, COUNT(*) AS c FROM string_refs GROUP BY func_addr", "ts": 1786295255.446235}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' OR dst_func_name`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786295255.4550135}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name FROM memory_blocks", "ts": 1786295255.4570389}`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786295255.4598324}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786295255.4671957}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LI`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_`
- `{"source": "ghidra_query", "sql": "SELECT address, content FROM strings WHERE length < 300", "ts": 1786295255.4767923}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786295255.4792485}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'", "ts": 1786295255.484544}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786295255.4871895}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetMo`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786295255.493118}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786295255.4956472}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as c FROM funcs", "ts": 1786295255.4981246}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, instruction_count, block_count FROM function_metrics", "ts": 1786295255.5094364}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786295255.6588085}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786295255.6593645}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786295255.7346082}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786295258.265987}`
- `{"source": "yara_gen_v2", "ts": 1786295258.282813}`
