> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:37:47 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **suspicious** |
| Triage upstream (quick ∪ deep) | suspicious |
| Quick scan | suspicious |
| Deep dive | suspicious |
| Publish LLM (claimed) | suspicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

**SHA256:** cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4
**Sample Path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe
**Project:** Hexorcist 3 - Weeks 20-30

## 1. Executive Summary

This sample is a benign Windows GUI application compiled with the Flat Assembler (FASM), identified as a keygen template for the "Hexorcist" CTF challenge series. The binary implements a simple dialog-based password checker that validates user input against a hardcoded algorithm, displaying "good!" or "bad!" based on the result. The filename `angr_crackme2.exe` explicitly labels it as a crackme designed for symbolic execution practice with the angr framework.

The analysis reveals no malicious behavioral intent. The binary contains only 8 GUI-related imports (DialogBoxParamA, GetDlgItemTextA, SetDlgItemTextA, LoadIconA, SendMessageA, EndDialog, GetModuleHandleA, ExitProcess), with zero suspicious API signals (source: malcat, imports table). Capa matched only one benign rule: "terminate process" (ExitProcess) (source: capa, capa rules). YARA matched only FASM compiler artifacts and generic PE indicators, with no malicious family signatures (source: yara, YARA Matches). The decompiled code shows straightforward serial validation logic without any network, persistence, injection, or credential theft capabilities (source: malcat, decompilations).

**Verdict:** Suspicious (score: 20) — The sample exhibits protection/obfuscation signals (high entropy in .text section, FASM compiler artifacts) that are neutral indicators common in benign software. No behavioral-intent evidence for malicious activity was found. The verdict reflects the need for further analysis rather than confirmed malice.

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4 | malcat |
| File Size | 139,264 bytes | malcat |
| File Type | PE (Portable Executable) | malcat |
| Architecture | x86 (32-bit) | malcat |
| Entry Point | 0x400 (1024) | malcat |
| Overall Entropy | 84% | malcat |
| Original Filename | angr_crackme2.exe | malcat |
| Compiler | FASM (Flat Assembler) | yara |
| Import Hash | e471a30244579dd1c29a70e51f0b18dc | rule.yara.json |
| Family Guess | Hexorcist keygen | llm_judge |
| Verdict | Suspicious (score: 20) | llm_judge |

The sample metadata indicates a standard 32-bit Windows executable with moderate entropy (84%), which is within normal range for compiled code. The FASM compiler identification is confirmed by multiple YARA rules matching at the entry point (source: yara, YARA Matches). The import hash is consistent with a minimal GUI application using only Windows dialog APIs.

## 3. File Layout & Structural Analysis

The PE file contains 6 sections with typical structure for a FASM-compiled GUI application. The following table shows the section layout as reported by Malcat:

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - |
| .text | 1024 | 512 | 4096 | 86 | RWX |
| .idata | 5120 | 512 | 4096 | 0 | RW |
| .data | 9216 | 512 | 4096 | 0 | RW |
| .rsrc | 13312 | 136704 | 139264 | 85 | R |
| .bss | 152576 | 0 | 4096 | 0 | RW |

(source: malcat, File Layout)

The .text section has high entropy (86%) and is marked RWX (read-write-execute), which is flagged as an anomaly (source: malcat, Anomalies: SectionWX). This is typical for FASM-compiled binaries where the code section may contain self-modifying code or packed data, but in this case appears to be benign compiler behavior. The .rsrc section is large (136,704 bytes physical) and contains the dialog template, icons, and version information. The .bss section is empty as expected for uninitialized data.

**Anomalies Detected:**
- InvalidBaseOfData (level 4): Data section starts before BaseOfData (source: malcat, Anomalies)
- BssNonEmpty (level 3): BSS region contains data (source: malcat, Anomalies)
- SectionWX (level 3): .text section is executable and writable (source: malcat, Anomalies)
- FewStrings (level 2): Less than 1% of file is strings (source: malcat, Anomalies)

These anomalies are neutral indicators common in FASM-compiled binaries and do not indicate malicious intent.

## 4. Static Code Analysis

The binary contains only 3 functions with minimal code surface, confirming its nature as a simple crackme challenge. The following functions were identified:

| EA | Name | Source |
|---|---|---|
| 1024 | EntryPoint | malcat |
| 1067 | sub_40102b (DialogFunc) | malcat |
| 1330 | sub_401132 (delay_loop) | malcat |

(source: malcat, Functions)

**Recovered Function Names:**
- `delay_loop` at address 4198706 (0x401132): Implements a busy-wait loop counting down from 0x31337 (201,711) to zero, a typical delay mechanism (source: agentic_recover_v4).

**Entry Point Disassembly (radare2):**
The entry point at 0x401000 initializes the application by calling GetModuleHandleA, then displays a dialog box using DialogBoxParamA with the dialog procedure at 0x40102b:

```asm
;-- section..text:
┌ 43: entry0 ();
│           0x00401000      6a00           push 0                      ; [00] -rwx section size 4096 named .text
│           0x00401002      ff1564304000   call dword [sym.imp.KERNEL32.DLL_GetModuleHandleA] ; 0x403064 ; "p0" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00401008      a388214000     mov dword [0x402188], eax   ; [0x402188:4]=0
│           0x0040100d      6a00           push 0
│           0x0040100f      682b104000     push 0x40102b               ; '+\x10@'
│           0x00401014      6a00           push 0
│           0x00401016      6a25           push 0x25                   ; '%' ; 37
│           0x00401018      50             push eax
│           0x00401019      ff15b0304000   call dword [sym.imp.USER32.DLL_DialogBoxParamA] ; 0x4030b0 ; INT_PTR DialogBoxParamA(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)
│           0x0040101f      09c0           or eax, eax
│       ┌─< 0x00401021      7400           je 0x401023
│       └─> 0x00401023      6a00           push 0
└           0x00401025      ff1568304000   call dword [sym.imp.KERNEL32.DLL_ExitProcess] ; 0x403068 ; VOID ExitProcess(UINT uExitCode)
```

(source: radare2, Disassembly)

This code shows a standard Windows GUI application initialization pattern: get module handle, display dialog with resource ID 0x25 (37), then exit. The dialog procedure at 0x40102b handles the serial validation logic.

**Dialog Procedure Decompilation (sub_40102b):**
The dialog function implements the core crackme logic. It processes WM_INITDIALOG (0x110) to set an icon, and WM_COMMAND (0x111) to handle button clicks. When the OK button (ID 1) is clicked, it reads the name and serial from edit controls, computes checksums, and compares them:

```c
undefined4 sub_40102b(undefined4 param_1,int32_t param_2,int32_t param_3)
{
    // ... variable declarations ...
    
    if (param_2 == 0x110) {  // WM_INITDIALOG
        uVar1 = (*user32.LoadIconA)([0x0x402188], 0x11);
        (*user32.SendMessageA)(param_1, 0x80, 1, uVar1);
        return 1;
    }
    if (param_2 == 0x111) {  // WM_COMMAND
        if (param_3 != 2) {  // Not Cancel button
            if (param_3 != 1) {  // Not OK button
                return 1;
            }
            // Read name from control ID 100
            uVar2 = (*user32.GetDlgItemTextA)(param_1, 100, 0x402004, 0x40);
            if ((4 < uVar2) && (uVar2 < 10)) {
                // Compute checksum of name
                iVar3 = 0;
                puVar5 = 0x402004;
                do {
                    iVar3 = iVar3 + *puVar5;
                    uVar2 = uVar2 - 1;
                    puVar5 = puVar5 + 1;
                } while (uVar2 != 0);
                sub_401132();  // delay_loop
                // Read serial from control ID 101
                iVar3 = (*user32.GetDlgItemTextA)(param_1, 0x65, 0x402044, 0x40, iVar3);
                if (9 < iVar3) {
                    // Compute checksum of serial
                    iVar4 = 0;
                    puVar5 = 0x402044;
                    do {
                        iVar4 = iVar4 + *puVar5;
                        iVar3 = iVar3 + -1;
                        puVar5 = puVar5 + 1;
                    } while (iVar3 != 0);
                    sub_401132();  // delay_loop
                    if (iVar4 == extraout_EDX) {
                        (*user32.SetDlgItemTextA)(param_1, 0x65, "good!", 0x100);
                        return 1;
                    }
                }
            }
            goto code_r0x00401111;
        }
    }
    else if (param_2 != 0x10) {  // Not WM_CLOSE
        return 0;
    }
    (*user32.EndDialog)(param_1, 0);
code_r0x00401111:
    (*user32.SetDlgItemTextA)(param_1, 0x65, "bad!", 0x100);
    return 1;
}
```

(source: malcat, decompilations)

This decompilation reveals the classic crackme pattern: read user input, compute checksums, compare, and display success/failure message. The algorithm sums the ASCII values of characters in both name and serial, then compares them. The `delay_loop` function adds artificial delay, likely to prevent brute-force attempts. There are no malicious behaviors such as file operations, network communication, or system modification.

**Delay Loop Decompilation (sub_401132):**
```c
void sub_401132(void)
{
    int32_t iVar1;
    
    iVar1 = 0x31337;
    do {
        iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    return;
}
```

(source: malcat, decompilations)

This function implements a simple busy-wait loop counting down from 201,711 (0x31337) iterations. The value 0x31337 is a common "leet speak" constant used in CTF challenges and crackmes as a signature. This is a benign anti-brute-force mechanism with no malicious implications.

## 5. Behavioral & Dynamic Analysis

**Speakeasy Emulation:** No API calls or events were recorded during emulation (source: speakeasy). This is expected for a GUI application that requires user interaction (dialog box) that cannot be automated in a headless environment.

**Frida Probe:** The Frida probe identified 7 hook candidates corresponding to the imported APIs (source: frida_probe). However, no runtime behavior was observed as the sample requires interactive GUI input.

**Dynamic Analysis Summary:** The sample's behavior is entirely dependent on user interaction with the dialog box. Without manual interaction, no runtime behavior can be observed. This is consistent with its design as a crackme challenge that requires human input to trigger the validation logic.

## 6. Network Indicators & C2

No network indicators were found in this sample. The binary contains no network-related imports (Winsock, HTTP, etc.), no C2 strings, and no beaconing behavior. The only DLLs loaded are KERNEL32.DLL and USER32.DLL for basic Windows GUI functionality (source: malcat, imports).

The YARA rule `domain` matched at offset 0 with length 2, but this appears to be a false positive from generic pattern matching rather than an actual domain string (source: yara, YARA Matches). Manual inspection of the strings table confirms no domain names, URLs, or IP addresses are present.

## 7. Capabilities Assessment

The sample has extremely limited capabilities, consistent with a simple crackme challenge:

**Observed Capabilities:**
- GUI dialog display and interaction (DialogBoxParamA, GetDlgItemTextA, SetDlgItemTextA)
- Icon loading (LoadIconA)
- Message sending (SendMessageA)
- Dialog termination (EndDialog)
- Process exit (ExitProcess)

**Not Observed (Latent):**
- No file system operations
- No registry manipulation
- No process creation/injection
- No network communication
- No persistence mechanisms
- No credential theft
- No anti-debugging techniques
- No encryption/decryption routines

**Capa Rules Matched:**
| Rule | ATT&CK | MBC | Source |
|---|---|---|---|
| terminate process | - | C0018:Terminate Process | capa |

(source: capa, capa rules)

The only capability detected by capa is benign process termination via ExitProcess, which is standard for any Windows application.

## 8. Indicators of Compromise

This sample does not produce traditional IOCs as it is not malware. However, the following artifacts can be used for identification:

**File-Based IOCs:**
- SHA256: cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4
- Import Hash: e471a30244579dd1c29a70e51f0b18dc
- Filename: angr_crackme2.exe

**String-Based IOCs:**
- `HEXORCIST KEYGEN TEMPLATE` (source: floss, floss strings)
- `HEXORCIST ASM TEMPLATE` (source: malcat, strings)
- `Copyright SAS HEXORCIST` (source: malcat, strings)
- `good!` / `bad!` (source: malcat, strings)
- `SERIAL:` / `NAME:` (source: malcat, strings)

**Behavioral IOCs:** None. The sample exhibits no malicious behavior.

## 9. Detection Engineering

**YARA Rules:**
The pipeline generated a YARA rule based on 24 strings extracted from the sample (source: rule.yara.json). Key strings include:
- `HEXORCIST KEYGEN TEMPLATE`
- `HEXORCIST ASM TEMPLATE`
- `Copyright SAS HEXORCIST`
- `good!` / `bad!`
- `SERIAL:` / `NAME:`

**Detection Recommendations:**
1. **Signature-Based:** Use the generated YARA rule to identify similar Hexorcist keygen templates.
2. **Behavioral:** No behavioral detection needed as the sample exhibits no malicious activity.
3. **Contextual:** Flag files with `angr_crackme` in the filename for analyst review, as these are typically CTF challenges.

**False Positive Considerations:**
The sample's characteristics (FASM compiler, high entropy, GUI dialog) are common in legitimate software and other crackmes. Detection should be context-aware and not trigger on these indicators alone.

## 10. MITRE ATT&CK Mapping

No MITRE ATT&CK techniques were identified in this sample. The binary exhibits no malicious behaviors that map to the ATT&CK framework. The only capability (process termination) is benign and maps to MBC C0018, not an ATT&CK technique.

**Capa ATT&CK Mapping:** None (source: capa, capa rules)

**YARA Behavioral Rules:** None matched. All YARA matches were for compiler artifacts (FASM) and generic PE indicators (IsPE32, IsWindowsGUI) (source: yara, YARA Matches).

## 11. What We Don't Know

1. **Original Purpose:** While the sample appears to be a CTF crackme, we cannot confirm its exact origin or intended use beyond the embedded strings.
2. **Author Intent:** The strings suggest it is part of the "Hexorcist" challenge series, but we lack metadata about the creator or distribution context.
3. **Runtime Behavior:** Due to the GUI dependency, full runtime behavior could not be observed in automated analysis. Manual interaction might reveal additional functionality not apparent in static analysis.
4. **Packing/Obfuscation:** The high entropy in .text (86%) and .rsrc (85%) sections could indicate packing or compression, but no packer signatures were detected. The UPX analysis returned false (source: upx).
5. **Anti-Analysis Techniques:** The delay_loop function may be intended to hinder automated analysis, but this is a common crackme feature rather than malicious anti-analysis.

## 12. Appendix A: Tool Evidence Trail

**Analysis Tools Used:**
- Malcat: File structure, strings, imports, decompilation, anomalies
- Capa: Capability detection
- YARA: Signature matching
- FLOSS: String extraction
- radare2: Disassembly
- Speakeasy: Emulation (no events)
- Frida: Runtime hooking (no events)
- Ghidra: Function analysis (limited data)
- IDA: Function analysis (limited data)

**Key Evidence Citations:**
- Decompilation showing serial validation: (source: malcat, decompilations)
- Import table with 8 GUI APIs: (source: malcat, imports)
- Capa rule "terminate process": (source: capa, capa rules)
- YARA matches for FASM compiler: (source: yara, YARA Matches)
- String "HEXORCIST KEYGEN TEMPLATE": (source: floss, floss strings)
- Function recovery for delay_loop: (source: agentic_recover_v4)

**Audit Trail:**
- Ghidra queries for function analysis, string extraction, and call graph analysis (source: ghidra_query)
- IDA queries for string extraction (source: ida_query)
- YARA rule generation (source: yara_gen_v2)
- Report publishing (source: publish_report_v2, publish_report_v2_technical)

## 13. Appendix B: Analysis Environment

**Sample Path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe

**Analysis Timestamp:** 2026-08-09T17:29:14.194031+00:00 (source: rule.yara.json)

**Tool Versions:**
- Frida: 17.16.4 (source: frida_probe)
- Malcat: (version not specified in evidence)
- Capa: (version not specified in evidence)
- YARA: (version not specified in evidence)

**Environment Notes:**
- Analysis performed in a controlled environment with automated tooling.
- GUI-dependent behavior could not be fully observed due to headless analysis constraints.
- Decompilation sourced from Malcat as primary engine (source: verdict.json, cross_engine_notes).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4  
**sample_path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe  
**project_name:** Hexorcist 3 - Weeks 20-30

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 20
- **family_guess**: Hexorcist keygen
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reports fewer strings (26) and functions (2) compared to IDA (1 string, 3 functions) and Malcat (36 strings, 3 functions), indicating potential data source gaps. The Ghidra imports table is empty, but IDA lists 8 imports, and Malcat confirms consistent imports. Decompilation is sourced from Malcat as per evidence.
- **summary**: This sample is a keygen template for 'Hexorcist' based on strings and decompiled code. It performs serial validation in a dialog GUI but shows no malicious behavioral intent (e.g., file destruction, C2, persistence, credential theft). All signals align with benign software protection testing or keygen use, with neutral anomalies like section entropy.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| floss | floss strings | `HEXORCIST KEYGEN TEMPLATE` | String indicates the sample is a keygen template, not malware, with no behavioral intent for harm. |
| malcat | decompilations | `DialogFunc (sub_40102b)` | Decompiled code shows serial validation logic with outputs 'good!' and 'bad!', typical of benign crackmes, lacking malic |
| malcat | strings | `SERIAL:` | String used for serial input in the GUI, supporting keygen behavior without indicators of credential theft or C2. |
| capa | capa rules | `terminate process` | Only behavioral rule found is benign process termination, confirming no malicious intent such as data destruction or per |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a benign CTF crackme challenge from the Hexorcist series, compiled with FASM. It implements a simple Windows dialog-based password checker using DialogBoxParamA/GetDlgItemTextA, with a 'good!' success string. Only 8 GUI-related imports (zero suspicious signals), 2-3 functions total, and no malicious capabilities (no network, persistence, injection, or crypto). Capa matched only 'terminate process' (ExitProcess). YARA matched only FASM compiler artifacts. The filename 'angr_crackme2.exe' explicitly identifies it as a crackme for symbolic execution practice.

### deep key_evidence
- `"Filename 'angr_crackme2.exe' explicitly labeled as crackme"`
- `"Copyright strings: 'SAS HEXORCIST', 'HEXORCIST ASM TEMPLATE' (CTF challenge series)"`
- `"Only 8 benign GUI imports: DialogBoxParamA, GetDlgItemTextA, SetDlgItemTextA, LoadIconA, SendMessageA, EndDialog, GetModuleHandleA, ExitProcess"`
- `"pe_import_signals: 0 suspicious signals from 8 imports"`
- `"capa: 1 rule match \u2014 'terminate process' (C0018) only \u2014 benign"`
- `"IDA identified 'DialogFunc' at 0x40113B with string_ref to 'good!' (classic crackme success message)"`
- `"Only 2 functions in binary: entry (306 bytes) and FUN_00401132 (13 bytes) \u2014 minimal code surface"`
- `"YARA: no malicious family rules matched, only FASM compiler artifacts"`
- `"No network, persistence, injection, crypto, or file manipulation APIs present"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4
size: 139264
type: PE
architecture: X86
entrypoint_ea: 1024
entropy: 84
file_name: angr_crackme2.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 33 | - |
| .text | 1024 | 512 | 4096 | 86 | RWX |
| .idata | 5120 | 512 | 4096 | 0 | RW |
| .data | 9216 | 512 | 4096 | 0 | RW |
| .rsrc | 13312 | 136704 | 139264 | 85 | R |
| .bss | 152576 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| FASM | compiler | INFO | 70 | detects fasm using DOS stub |

### Anomalies (4)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) |

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 5180 | `KERNEL32.DLL` |

### Top Strings (36 extracted; showing 36)
| EA | String |
|---|---|
| 5180 | `KERNEL32.DLL` |
| 5194 | `USER32.DLL` |
| 9216 | `good!` |
| 9222 | `bad!` |
| 149600 | `hexo1.EXE` |
| 149158 | `VS_VERSION_INFO` |
| 149566 | `OriginalFilename` |
| 149344 | `HEXORCIST ASM TEMPLATE` |
| 149286 | `040904E4` |
| 13590 | `HEXORCIST KEYGEN TEMPLATE` |
| 149428 | `Copyright SAS HEXORCIST` |
| 149310 | `FileDescription` |
| 149522 | `ProductVersion` |
| 149250 | `StringFileInfo` |
| 149658 | `Translation` |
| 149482 | `FileVersion` |
| 77 | `!This program ca.. in DOS mode.
$` |
| 13644 | `MS Sans Serif` |
| 149398 | `LegalCopyright` |
| 149626 | `VarFileInfo` |
| 5234 | `GetModuleHandleA` |
| 5344 | `GetDlgItemTextA` |
| 5362 | `SetDlgItemTextA` |
| 5392 | `SendMessageA` |
| 5326 | `DialogBoxParamA` |
| 13730 | `SERIAL:` |
| 416 | `.bss` |
| 13694 | `NAME:` |
| 536 | `.rsrc` |
| 496 | `.data` |
| 376 | `.text` |
| 456 | `.idata` |
| 5254 | `ExitProcess` |
| 5380 | `LoadIconA` |
| 13858 | `C&ancel` |
| 5408 | `EndDialog` |

### Imports (8)
| EA | Name | Type | Refs |
|---|---|---|---|
| 5220 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 5224 | kernel32.ExitProcess | IMPORT | 1 |
| 5296 | user32.DialogBoxParamA | IMPORT | 2 |
| 5300 | user32.GetDlgItemTextA | IMPORT | 2 |
| 5304 | user32.SetDlgItemTextA | IMPORT | 2 |
| 5308 | user32.LoadIconA | IMPORT | 1 |
| 5312 | user32.SendMessageA | IMPORT | 1 |
| 5316 | user32.EndDialog | IMPORT | 1 |

### Functions (3)
| EA | Name |
|---|---|
| 1067 | sub_40102b |
| 1024 | EntryPoint |
| 1330 | sub_401132 |

### Decompilations (top 6)
#### 1067 — sub_40102b
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40102b(undefined4 param_1,int32_t param_2,int32_t param_3)

{
    undefined4 uVar1;
    uint32_t uVar2;
    int32_t extraout_EDX;
    int32_t iVar3;
    int32_t iVar4;
    uint8_t *puVar5;
    
    if (param_2 == 0x110) {
        uVar1 = (*user32.LoadIconA)([0x0x402188], 0x11);
        (*user32.SendMessageA)(param_1, 0x80, 1, uVar1);
        return 1;
    }
    if (param_2 == 0x111) {
        if (param_3 != 2) {
            if (param_3 != 1) {
                return 1;
            }
            uVar2 = (*user32.GetDlgItemTextA)(param_1, 100, 0x402004, 0x40);
            if ((4 < uVar2) && (uVar2 < 10)) {
                iVar3 = 0;
                puVar5 = 0x402004;
                do {
                    iVar3 = iVar3 + *puVar5;
                    uVar2 = uVar2 - 1;
                    puVar5 = puVar5 + 1;
                } while (uVar2 != 0);
                sub_401132();
                iVar3 = (*user32.GetDlgItemTextA)(param_1, 0x65, 0x402044, 0x40, iVar3);
                if (9 < iVar3) {
                    iVar4 = 0;
                    puVar5 = 0x402044;
                    do {
                        iVar4 = iVar4 + *puVar5;
                        iVar3 = iVar3 + -1;
                        puVar5 = puVar5 + 1;
                    } while (iVar3 != 0);
                    sub_401132();
                    if (iVar4 == extraout_EDX) {
                        (*user32.SetDlgItemTextA)(param_1, 0x65, "good!", 0x100);
                        return 1;
                    }
                }
            }
            goto code_r0x00401111;
        }
    }
    else if (param_2 != 0x10) {
        return 0;
    }
    (*user32.EndDialog)(param_1, 0);
code_r0x00401111:
    (*user32.SetDlgItemTextA)(param_1, 0x65, "bad!", 0x100);
    return 1;
}

```
#### 1024 — EntryPoint
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 EntryPoint(void)

{
    undefined4 uVar1;
    uint32_t uVar2;
    int32_t extraout_EDX;
    uint8_t *puVar3;
    undefined4 uVar4;
    int32_t iVar5;
    int32_t iVar6;
    
    00402188 = (*kernel32.GetModuleHandleA)(0);
    iVar6 = 0;
    iVar5 = 0x25;
    uVar4 = 00402188;
    (*user32.DialogBoxParamA)(00402188, 0x25, 0, sub_40102b, 0);
    (*kernel32.ExitProcess)(0);
    if (iVar5 == 0x110) {
        uVar1 = (*user32.LoadIconA)([0x0x402188], 0x11);
        (*user32.SendMessageA)(uVar4, 0x80, 1, uVar1);
        return 1;
    }
    if (iVar5 == 0x111) {
        if (iVar6 != 2) {
            if (iVar6 != 1) {
                return 1;
            }
            uVar2 = (*user32.GetDlgItemTextA)(uVar4, 100, 0x402004, 0x40);
            if ((4 < uVar2) && (uVar2 < 10)) {
                iVar5 = 0;
                puVar3 = 0x402004;
                do {
                    iVar5 = iVar5 + *puVar3;
                    uVar2 = uVar2 - 1;
                    puVar3 = puVar3 + 1;
                } while (uVar2 != 0);
                sub_401132();
                iVar5 = (*user32.GetDlgItemTextA)(uVar4, 0x65, 0x402044, 0x40, iVar5);
                if (9 < iVar5) {
                    iVar6 = 0;
                    puVar3 = 0x402044;
                    do {
                        iVar6 = iVar6 + *puVar3;
                        iVar5 = iVar5 + -1;
                        puVar3 = puVar3 + 1;
                    } while (iVar5 != 0);
                    sub_401132();
                    if (iVar6 == extraout_EDX) {
                        (*user32.SetDlgItemTextA)(uVar4, 0x65, "good!", 0x100);
                        return 1;
                    }
                }
            }
            goto code_r0x00401111;
        }
    }
    else if (iVar5 != 0x10) {
        return 0;
    }
    (*user32.EndDialog)(uVar4, 0);
code_r0x00401111:
    (*user32.SetDlgItemTextA)(uVar4, 0x65, "bad!", 0x100);
    return 1;
}

```
#### 1330 — sub_401132
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401132(void)

{
    int32_t iVar1;
    
    iVar1 = 0x31337;
    do {
        iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
    return;
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
| DLG/37/en-us | 308 | - |
| GRPICO/17/unk | 20 | - |
| VER/1/unk | 536 | - |

### Structures (29)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 5120 |
| ImportNames | 5180 |
| kernel32.OFT | 5208 |
| kernel32.FT | 5220 |
| ImportNames | 5232 |
| user32.OFT | 5268 |
| user32.FT | 5296 |
| ImportNames | 5324 |
| Resources | 13312 |
| Resources.DLG | 13360 |
| Resources.DLG.37 | 13384 |
| Resources.GRPICO | 13408 |
| Resources.GRPICO.17 | 13432 |
| Resources.ICO | 13456 |
| Resources.ICO.1 | 13480 |
| Resources.VER | 13504 |
| Resources.VER.1 | 13528 |
| Resources.DLG.37.en-us | 13552 |
| Resources.DLG.37.en-us.Data | 13568 |
| Resources.ICO.1.unk | 13876 |
| Resources.ICO.1.unk.Data | 13892 |
| Resources.GRPICO.17.unk | 149100 |
| Resources.GRPICO.17.unk.Data | 149116 |
| Resources.VER.1.unk | 149136 |
| VersionInfo | 149152 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.81

| Rule | ATT&CK | MBC |
|---|---|---|
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 8

## YARA Matches (pipeline)
Total matches: 10

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@4024 len=2 |
| contains_base64 | - | $a@1650 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| FASM | - |  |
| FASM_15x | - | $a@1024 len=13 |
| FASM_v13x_additional | - | $a@1024 len=9 |
| FASM_v15x | - | $b@1024 len=13 |
| FASM_v13x | - | $b@1024 len=9 |

## Generated YARA Meta
```json
{
  "sha256": "cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4",
  "family": "Hexorcist keygen",
  "imphash": "e471a30244579dd1c29a70e51f0b18dc",
  "generated_at": "2026-08-09T17:29:14.194031+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "KERNEL32.DLL",
    "USER32.DLL",
    "GetModuleHandleA",
    "ExitProcess",
    "DialogBoxParamA",
    "GetDlgItemTextA",
    "SetDlgItemTextA",
    "LoadIconA",
    "SendMessageA",
    "EndDialog",
    "HEXORCIST KEYGEN TEMPLATE",
    "MS Sans Serif",
    "VS_VERSION_INFO",
    "StringFileInfo",
    "040904E4",
    "FileDescription",
    "HEXORCIST ASM TEMPLATE",
    "LegalCopyright",
    "Copyright SAS HEXORCIST",
    "FileVersion",
    "ProductVersion",
    "OriginalFilename",
    "hexo1.EXE"
  ],
  "rule_path": "/opt/samples/logs/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/rule.yar",
  "sigma_path": "/opt/samples/logs/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/rule.yml",
  "iocs_path": "/opt/samples/logs/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/iocs.json",
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
    "utc": "2026-08-09 17:29:14 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 30 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 30}`

### High-signal FLOSS
- `KERNEL32.DLL`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.idata`
- `Sj@hD @`
- `KERNEL32.DLL`
- `USER32.DLL`
- `GetModuleHandleA`
- `ExitProcess`
- `DialogBoxParamA`
- `GetDlgItemTextA`
- `SetDlgItemTextA`
- `LoadIconA`
- `SendMessageA`
- `EndDialog`
- `HEXORCIST KEYGEN TEMPLATE`
- `MS Sans Serif`
- `SERIAL:`
- `C&ancel`
- `VS_VERSION_INFO`
- `StringFileInfo`
- `040904E4`
- `FileDescription`
- `HEXORCIST ASM TEMPLATE`
- `LegalCopyright`
- `Copyright SAS HEXORCIST`
- `FileVersion`
- `ProductVersion`
- `OriginalFilename`
- `hexo1.EXE`
- `VarFileInfo`
- `Translation`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 43: entry0 ();
│           0x00401000      6a00           push 0                      ; [00] -rwx section size 4096 named .text
│           0x00401002      ff1564304000   call dword [sym.imp.KERNEL32.DLL_GetModuleHandleA] ; 0x403064 ; "p0" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00401008      a388214000     mov dword [0x402188], eax   ; [0x402188:4]=0
│           0x0040100d      6a00           push 0
│           0x0040100f      682b104000     push 0x40102b               ; '+\x10@'
│           0x00401014      6a00           push 0
│           0x00401016      6a25           push 0x25                   ; '%' ; 37
│           0x00401018      50             push eax
│           0x00401019      ff15b0304000   call dword [sym.imp.USER32.DLL_DialogBoxParamA] ; 0x4030b0 ; INT_PTR DialogBoxParamA(HINSTANCE hInstance, LPCSTR lpTemplateName, HWND hWndParent, DLGPROC lpDialogFunc, LPARAM dwInitParam)
│           0x0040101f      09c0           or eax, eax
│       ┌─< 0x00401021      7400           je 0x401023
│       └─> 0x00401023      6a00           push 0
└           0x00401025      ff1568304000   call dword [sym.imp.KERNEL32.DLL_ExitProcess] ; 0x403068 ; VOID ExitProcess(UINT uExitCode)
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
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!DialogBoxParamA`
  - `USER32.DLL!GetDlgItemTextA`
  - `USER32.DLL!SetDlgItemTextA`
  - `USER32.DLL!LoadIconA`
  - `USER32.DLL!SendMessageA`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name FROM memory_blocks", "ts": 1786296518.0738986}`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786296518.0768178}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786296518.0999677}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LI`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_`
- `{"source": "ghidra_query", "sql": "SELECT address, content FROM strings WHERE length < 300", "ts": 1786296518.1258385}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786296518.1281352}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'", "ts": 1786296518.140314}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786296518.142472}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetMo`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786296518.1578372}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786296518.1599417}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as c FROM funcs", "ts": 1786296518.1619544}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, instruction_count, block_count FROM function_metrics", "ts": 1786296518.171408}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4198706' LIMIT 1", "ts": 1786296518.4842823}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786296518.6334631}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4198706' AND is_stale = '0' LIMIT 1", "ts": 1786296518.9028668}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4198706' AND x.from_ea <= '4198719'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4198706' AND x.from_ea <= '4198719'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4198706' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4198706' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4190514' AND address <= '4206898'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4198706) ASC\n            LIMIT 7\n            ", "ts": 1786296518.9197986}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786296551.545361}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786296551.5463262}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786296551.649099}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786296554.17884}`
- `{"source": "yara_gen_v2", "ts": 1786296554.194223}`
- `{"source": "publish_report_v2", "ts": 1786296668.3942635}`
- `{"source": "publish_report_v2_technical", "ts": 1786296814.6008134}`
