# Technical Evidence Pack

**sha256:** 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b  
**sample_path:** /opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Poison/Symmi
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: MalCat anomalies align with capa and YARA detections for hooking and obfuscation. Ghidra and IDA report consistent function and string counts, while MalCat provides detailed behavioral evidence through decompilations and high-signal imports. External VirusTotal detections corroborate local findings with high confidence.
- **summary**: The sample exhibits clear behavioral-intent evidence through hooking APIs (SetWindowsHookExA) and obfuscation (XOR loops, spaghetti functions). Combined with dynamic API resolution (LoadLibrary, VirtualAlloc) and strong external VirusTotal detections, it is identified as malicious malware, likely belonging to the Poison or Symmi trojan families. Obfuscation alone is neutral, but the presence of hooking and evasion techniques elevates the threat level.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | decompilations | `sub_401000` | Decompiled code shows calls to SetWindowsHookExA and GetMessageA, indicating potential keylogging or UI hooking, which i |
| capa | top_rules | `set application hook` | Capa rule detects hooking behavior, corroborating MalCat decompilation and suggesting malicious intent for system monito |
| yara | matches | `win_hook` | YARA rule matches for Windows hook setup, confirming hooking capability and aligning with other tool detections. |
| malcat | anomalies | `XorInLoop×8` | Indicates use of XOR obfuscation for data encoding, commonly associated with malware for payload encryption or evasion. |
| capa | top_rules | `encode data using XOR` | Capa rule maps to ATT&CK T1027, confirming obfuscation techniques that are neutral but supportive of evasion strategies  |
| pe_imports | signals | `load_library` | LoadLibrary API used for dynamic library loading, a common technique in malware to resolve APIs at runtime and evade sta |
| pe_imports | signals | `allocate_memory` | VirtualAlloc for memory allocation, often used in process injection or shellcode execution, indicating potential malicio |
| malcat | anomalies | `SpaghettiFunction×7` | Spaghetti code patterns suggest obfuscated control flow, which can hinder analysis and is often seen in malware. |
| malcat | high-signal imports | `kernel32.VirtualAlloc ×4` | High-signal import indicating repeated memory allocation, potentially for staging malicious payloads or shellcode. |
| external TI | hash_lookup | `VirusTotal detections` | 56 malicious detections with threat labels like 'trojan.poison/symmi', supporting local evidence of malicious intent and |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE DLL (vbprop.exe) masquerading as Trend Micro Internet Security while implementing Windows hooking (SetWindowsHookExA/CallNextHookEx/UnhookWindowsHookEx) consistent with keylogger/spyware functionality. Protected by Armadillo v4.x packer with XOR-based obfuscation. The .data section is marked executable (RWX), and the binary uses VirtualAlloc for runtime memory allocation alongside dynamic API resolution via LoadLibraryA/GetProcAddress. Multiple functions exhibit extreme cyclomatic complexity (up to 139 in FUN_0040166e with 223 blocks), indicative of heavy obfuscation or control-flow flattening. Contains network indicators (IP address at offset 0xF500) and base64-encoded data. Persistence mechanisms are not observed in the provided tool or SQL sources.

### deep key_evidence
- `"YARA: Armadillo_v4x rule matched - known software protector/packer used for anti-analysis"`
- `"YARA: IP address pattern detected at file offset 62720 (0xF500)"`
- `"YARA: Base64-encoded content detected at offset 25104"`
- `"YARA: SEH_Save detected - Structured Exception Handling for anti-debugging"`
- `"CAPA: 'encode data using XOR' (T1027) - Defense Evasion via obfuscated files/information"`
- `"CAPA: 'set application hook' - Windows hooking capability detected"`
- `"CAPA: 'terminate process' - Process termination capability"`
- `"FLOSS: Imports SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx from USER32.dll - classic keylogger/spyware hooking APIs"`
- `"FLOSS: Imports VirtualAlloc, VirtualFree for dynamic memory allocation (shellcode/runtime code injection)"`
- `"FLOSS: Imports WriteFile, SetFilePointer for data exfiltration to disk"`
- `"FLOSS: Imports GetActiveWindow, GetLastActivePopup, DispatchMessageA, TranslateMessage, GetMessageA - message loop processing for hook callbacks"`
- `"Ghidra: .data section (0x404800-0x4097FF) marked as executable (is_read=1, is_write=1, is_exec=1) - anomalous RWX memory"`
- `"Ghidra: FUN_0040166e has cyclomatic_complexity=139, 223 blocks, 622 instructions, 30 call-outs - extreme complexity indicating obfuscation"`
- `"Ghidra: FUN_00404920 and FUN_00405300 each have cyclomatic_complexity=62 with 63 blocks and identical sizes (664 bytes) - likely obfuscation-duplicated code"`
- `"Ghidra: FUN_00401000 (first export) references repetitive strings 'us7jsus7j...', 'q5y8q5y8...', 'v9i02ks3k7a8...' - XOR keys or obfuscation padding"`
- `"Ghidra: Exports include hook-related APIs (SetWindowsHookExA, CallNextHookEx, UnhookWindowsHookEx) and process control (ExitProcess, TerminateProcess, GetCurrentProcess)"`
- `"Ghidra: Entry point calls FUN_00401000 along with multiple indirect calls (sub_0) suggesting dynamic resolution"`
- `"Masquerade: VersionInfo claims 'Trend Micro Internet Security' / 'Trend Micro Inc.' / 'Copyright (C) 1995-2009 Trend Micro Incorporated' - forged metadata impersonating legitimate security software"`
- `"Masquerade: References 'Build 1366 - 7/29/2009' as private build info to appear legitimate"`
- `"YARA: Microsoft_Visual_Cpp_v60 and Armadillo signatures both match at overlapping offsets, confirming VC6 binary wrapped in Armadillo protector"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b
size: 65729
type: PE
architecture: X86
entrypoint_ea: 5146
entropy: 5.18
file_name: vbprop.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 20480 | 20480 | 136 | RX |
| .rdata | 24576 | 4096 | 4096 | 60 | R |
| .data | 28672 | 20480 | 20480 | 61 | RWX |
| .rsrc | 49152 | 16384 | 16384 | 90 | R |
| overlay | 65536 | 193 | 0 | 4 | - |
| .bss | 65729 | 0 | 20480 | 0 | RW |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| msvc_uv_55 | compiler | INFO | 50 |  |
| msvc_60_07 | compiler | INFO | 50 | Visual Studio 6.0 |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having + |
| XorInLoop | 3 | code | 8 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SpaghettiFunction | 1 | code | 7 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `308`: 
- **NoChecksum**
  - `304`: 
- **SpaghettiFunction**
  - `5742`: 
  - `8489`: 
  - `9303`: 
  - `18480`: 
  - `18720`: 
- **XorInLoop**
  - `4597`: 
  - `4616`: 
  - `4641`: 
  - `12720`: 
  - `18524`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 26104 | `KERNEL32.dll` |
| 26852 | `GetProcAddress` |
| 26870 | `LoadLibraryA` |

### Top Strings (168 extracted; showing 80)
| EA | String |
|---|---|
| 35836 | `v9i02ks3k7a8v9i0..k7a8v9i02ks3k7a8` |
| 35780 | `us7jsus7jus7jsus..7jsus7jus7jsus7j` |
| 35900 | `q5y8q5y8q5y8q5y8..q5y8q5y8q5y8q5y8` |
| 25760 | `user32.dll` |
| 24912 | `__GLOBAL_HEAP_SELECTED` |
| 24936 | `__MSVCRT_HEAP_SELECT` |
| 25688 | `<program name unknown>` |
| 25656 | `Runtime Error!

Program: ` |
| 25712 | `GetLastActivePopup` |
| 25732 | `GetActiveWindow` |
| 25748 | `MessageBoxA` |
| 26104 | `KERNEL32.dll` |
| 25448 | `
abnormal program termination
` |
| 26232 | `USER32.dll` |
| 24888 | `(null)` |
| 25572 | `R6002
- floatin..int not loaded
` |
| 36962 | `         (((((  ..               H` |
| 62832 | `Copyright (C) 19..rights reserved.` |
| 25028 | `R6028
- unable ..nitialize heap
` |
| 24904 | `(null)` |
| 24960 | `runtime error ` |
| 24980 | `TLOSS error
` |
| 24996 | `SING error
` |
| 25012 | `DOMAIN error
` |
| 63256 | `Trend Micro Internet Security` |
| 63120 | `VBProp.dll` |
| 62632 | `VBProp Dynamic Link Library` |
| 62354 | `VS_VERSION_INFO` |
| 62720 | `17.50.0.1366` |
| 62482 | `040904e4` |
| 63086 | `OriginalFilename` |
| 63016 | `Copyright (C) Trend Micro Inc.` |
| 63176 | `Build 1366 - 7/29/2009` |
| 62982 | `LegalTrademarks` |
| 62754 | `InternalName` |
| 62598 | `FileDescription` |
| 24861 | `ppxxxx` |
| 24853 | ``h````` |
| 26442 | `FreeEnvironmentStringsA` |
| 26468 | `FreeEnvironmentStringsW` |
| 63322 | `ProductVersion` |
| 62446 | `StringFileInfo` |
| 62556 | `Trend Micro Inc.` |
| 63446 | `Translation` |
| 26516 | `GetEnvironmentStrings` |
| 26540 | `GetEnvironmentStringsW` |
| 77 | `!This program ca..in DOS mode.
$` |
| 26614 | `GetEnvironmentVariableA` |
| 62530 | `CompanyName` |
| 62694 | `FileVersion` |
| 63370 | `SpecialBuild` |
| 26162 | `TranslateMessage` |
| 26392 | `UnhandledExceptionFilter` |
| 26798 | `FlushFileBuffers` |
| 63396 | `1366` |
| 26280 | `GetCurrentProcess` |
| 62802 | `LegalCopyright` |
| 62506 | `Comments` |
| 26120 | `UnhookWindowsHookEx` |
| 63150 | `PrivateBuild` |
| 26782 | `SetStdHandle` |
| 26722 | `SetFilePointer` |
| 26852 | `GetProcAddress` |
| 26670 | `HeapCreate` |
| 63414 | `VarFileInfo` |
| 63230 | `ProductName` |
| 26420 | `GetModuleFileNameA` |
| 26086 | `GetModuleHandleA` |
| 26142 | `DispatchMessageA` |
| 26260 | `TerminateProcess` |
| 26870 | `LoadLibraryA` |
| 26182 | `GetMessageA` |
| 26584 | `GetStdHandle` |
| 26362 | `GetLastError` |
| 26566 | `SetHandleCount` |
| 26216 | `CallNextHookEx` |
| 26886 | `MultiByteToWideChar` |
| 26318 | `GetCommandLineA` |
| 26350 | `HeapFree` |
| 26494 | `WideCharToMultiByte` |

### Constants / Known Patterns (11)
| Category | Value |
|---|---|
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_runtime` |

### Imports (130)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4765 | _exit | DEBUG | 4 |
| 4782 | __exit | DEBUG | 3 |
| 4799 | _doexit | DEBUG | 2 |
| 4952 | __initterm | DEBUG | 4 |
| 4978 | _sprintf | DEBUG | 2 |
| 5060 | _fclose | DEBUG | 1 |
| 5146 | _WinMainCRTStartup | DEBUG | 1 |
| 5429 | _fast_error_exit | DEBUG | 1 |
| 5465 | __flsbuf | DEBUG | 2 |
| 7692 | _write_char | DEBUG | 4 |
| 7745 | _write_multi_char | DEBUG | 3 |
| 7794 | _write_string | DEBUG | 3 |
| 7850 | _get_int_arg | DEBUG | 10 |
| 7879 | _get_short_arg | DEBUG | 1 |
| 7893 | _free | DEBUG | 6 |
| 7998 | __close | DEBUG | 1 |
| 8177 | __freebuf | DEBUG | 1 |
| 8220 | _fflush | DEBUG | 2 |
| 8279 | __flush | DEBUG | 2 |
| 8380 | _flsall | DEBUG | 2 |
| 8489 | __XcptFilter | DEBUG | 1 |
| 8877 | __wincmdln | DEBUG | 1 |
| 8965 | __setenvp | DEBUG | 1 |
| 9150 | __setargv | DEBUG | 1 |
| 9303 | _parse_cmdline | DEBUG | 2 |
| 9739 | ___crtGetEnvironmentStringsA | DEBUG | 1 |
| 10045 | __ioinit | DEBUG | 1 |
| 10472 | __GetLinkerVersion | DEBUG | 1 |
| 10517 | ___heap_select | DEBUG | 1 |
| 10845 | __heap_init | DEBUG | 1 |
| 11404 | __FF_MSGBANNER | DEBUG | 2 |
| 11461 | __NMSG_WRITE | DEBUG | 4 |
| 11800 | __lseek | DEBUG | 2 |
| 11954 | __write | DEBUG | 3 |
| 12383 | __getbuf | DEBUG | 1 |
| 12451 | __isatty | DEBUG | 1 |
| 12489 | ___initstdio | DEBUG | 1 |
| 12654 | ___endstdio | DEBUG | 1 |
| 12688 | _strlen | DEBUG | 6 |
| 12811 | _malloc | DEBUG | 9 |
| 12873 | __heap_alloc | DEBUG | 1 |
| 12989 | _wctomb | DEBUG | 2 |
| 13104 | __aulldiv | DEBUG | 1 |
| 13216 | __aullrem | DEBUG | 1 |
| 13333 | ___sbh_heap_init | DEBUG | 1 |
| 13405 | ___sbh_find_block | DEBUG | 1 |
| 13448 | ___sbh_free_block | DEBUG | 1 |
| 14257 | ___sbh_alloc_block | DEBUG | 2 |
| 15211 | ___sbh_alloc_new_group | DEBUG | 1 |
| 15462 | ___old_sbh_new_region | DEBUG | 2 |
| 15786 | ___old_sbh_release_region | DEBUG | 1 |
| 15872 | ___old_sbh_decommit_pages | DEBUG | 1 |
| 16066 | ___old_sbh_find_block | DEBUG | 1 |
| 16153 | ___old_sbh_free_block | DEBUG | 1 |
| 16222 | ___old_sbh_alloc_block | DEBUG | 2 |
| 16742 | ___old_sbh_alloc_block_from_page | DEBUG | 2 |
| 17034 | __dosmaperr | DEBUG | 3 |
| 17137 | __free_osfhnd | DEBUG | 1 |
| 17259 | __get_osfhandle | DEBUG | 6 |
| 17320 | __commit | DEBUG | 1 |
| 17407 | __ismbblead | DEBUG | 1 |
| 17473 | __setmbcp | DEBUG | 1 |
| 17956 | _CPtoLCID | DEBUG | 2 |
| 18007 | _setSBCS | DEBUG | 1 |
| 18048 | _setSBUpLow | DEBUG | 1 |
| 18437 | ___initmbctable | DEBUG | 4 |
| 19541 | _strtol | DEBUG | 1 |
| 19564 | _strtoxl | DEBUG | 1 |
| 20096 | found_bx | DEBUG | 1 |
| 20432 | _strncmp | DEBUG | 1 |
| 20496 | __alloca_probe | DEBUG | 4 |
| 20543 | ___crtMessageBoxA | DEBUG | 1 |
| 20688 | _strncpy | DEBUG | 1 |
| 20942 | _calloc | DEBUG | 2 |
| 21119 | __fcloseall | DEBUG | 1 |
| 21216 | __callnewh | DEBUG | 2 |
| 22080 | _memset | DEBUG | 4 |
| 22168 | ___crtLCMapStringA | DEBUG | 3 |
| 22716 | _strncnt | DEBUG | 1 |
| 22759 | ___crtGetStringTypeA | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 4096 | sub_401000 |
| 23410 | jmp_kernel32.RtlUnwind |
| 11006 | sub_402afe |
| 10972 | sub_402adc |
| 5381 | sub_401505 |
| 8371 | sub_4020b3 |
| 11110 | sub_402b66 |
| 11377 | sub_402c71 |
| 21207 | sub_4052d7 |
| 10940 | sub_402abc |
| 5464 | sub_401558 |
| 11154 | sub_402b92 |
| 11461 | __NMSG_WRITE |
| 20096 | found_bx |
| 18480 | sub_404830 |
| 20688 | _strncpy |
| 12688 | _strlen |
| 11180 | sub_402bac |
| 22168 | ___crtLCMapStringA |
| 22759 | ___crtGetStringTypeA |
| 10045 | __ioinit |
| 5146 | EntryPoint |
| 11954 | __write |
| 14257 | ___sbh_alloc_block |
| 9739 | ___crtGetEnvironmentStringsA |
| 10517 | ___heap_select |
| 15462 | ___old_sbh_new_region |
| 17473 | __setmbcp |
| 4799 | _doexit |
| 7998 | __close |

### Decompilations (top 6)
#### 4096 — sub_401000
```c

/* WARNING: Possible PIC construction at 0x0040115a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0040115f) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401000(void)

{
    code *pcVar1;
    code *pcVar2;
    code *pcVar3;
    uint8_t uVar4;
    uint8_t uVar5;
    undefined4 uVar6;
    int32_t iVar7;
    uint8_t uVar8;
    uint8_t uVar9;
    uint8_t uVar10;
    int32_t iVar11;
    int32_t iVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint8_t uVar15;
    undefined4 unaff_EBX;
    undefined4 *puVar16;
    undefined4 *puVar17;
    undefined4 uVar18;
    undefined uStack_1b4;
    undefined4 uStack_1b3;
    undefined4 uStack_12c;
    undefined4 **ppuStack_128;
    undefined4 uStack_124;
    undefined4 uStack_120;
    undefined4 uStack_11c;
    int32_t *piStack_118;
    int32_t *piStack_114;
    undefined4 *puStack_10c;
    int32_t iStack_108;
    int32_t iStack_104;
    undefined4 uStack_100;
    undefined4 uStack_fc;
    undefined4 uStack_f8;
    undefined4 uStack_f4;
    undefined *puStack_f0;
    undefined4 uStack_ec;
    undefined uStack_c4;
    undefined4 auStack_c3 [48];
    
    uStack_c4 = 0;
    puVar16 = auStack_c3;
    for (iVar11 = 0x30; iVar11 != 0; iVar11 = iVar11 + -1) {
        *puVar16 = 0;
        puVar16 = puVar16 + 1;
    }
    *puVar16 = 0;
    puStack_f0 = &uStack_c4;
    uStack_ec = "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j";
    uStack_f4 = 0x40102b;
    _sprintf();
    uStack_ec = 0;
    puStack_f0 = 0x0;
    uStack_f4 = 0x401038;
    uStack_f4 = (*kernel32.GetModuleHandleA)();
    uStack_f8 = 0x4010b0;
    uStack_fc = 0xe;
    uStack_100 = 0x401046;
    00406000 = (*user32.SetWindowsHookExA)();
    pcVar1 = user32.GetMessageA;
    uStack_100 = 0;
    iStack_104 = 0;
    puStack_10c = &uStack_f4;
    iStack_108 = 0;
    iVar11 = (*user32.GetMessageA)();
    pcVar3 = user32.DispatchMessageA;
    pcVar2 = user32.TranslateMessage;
    uVar18 = [0x0x406000];
    while (00406000 = uVar18, iVar11 != 0) {
        piStack_114 = &iStack_104;
        piStack_118 = 0x401076;
        (*pcVar2)();
        piStack_118 = &iStack_108;
        uStack_11c = 0x40107d;
        (*pcVar3)();
        uStack_11c = 0;
        uStack_120 = 0;
        ppuStack_128 = &puStack_10c;
        uStack_124 = 0;
        uStack_12c = 0x40108a;
        iVar11 = (*pcVar1)();
        uVar18 = [0x0x406000];
    }
    piStack_114 = 0x40109c;
    (*user32.UnhookWindowsHookEx)();
    piStack_114 = 0x0;
    piStack_118 = 0x4010a3;
    _exit();
    iVar7 = iStack_104;
    iVar11 = iStack_108;
    uVar6 = piStack_114;
    if (iStack_108 == 0) {
        if (iStack_104 == 0x200) {
            puVar16 = &uStack_1b3;
            for (iVar12 = 0x21; iVar12 != 0; iVar12 = iVar12 + -1) {
                *puVar16 = 0;
                puVar16 = puVar16 + 1;
            }
            *puVar16 = 0;
            uVar18 = "q5y8q5y8q5y8q5y8q5y8q5y8q5y8q5y8q5y8q5y8q5y8q5y8";
        }
        else {
            if (iStack_104 != 0x201) {
                if (iStack_104 == 0x202) {
                    (*user32.UnhookWindowsHookEx)([0x0x406000], piStack_114, uVar18);
                    uVar5 = [0x0x40dbc0];
                    uVar8 = [0x0x40dbbc] ^ 0x10;
                    uVar15 = [0x0x40dbbd] ^ 0xd1;
                    uVar10 = [0x0x40dbbf] ^ 0x41;
                    uVar9 = [0x0x40dbbe] ^ 0xc1;
                    puVar16 = 0x40c030;
                    puVar17 = 0x406004;
                    for (iVar11 = 0x6e2; iVar11 != 0; iVar11 = iVar11 + -1) {
                        *puVar17 = *puVar16;
                        puVar16 = puVar16 + 1;
                        puVar17 = puVar17 + 1;
                    }
                    *puVar17 = *puVar16;
                    uVar14 = 0;
                    do {
                        uVar13 = uVar14 + 1;
                        *(uVar14 + 0x406004) = ~*(uVar14 + 0x406004);
                        uVar4 = [0x0x40dbbc];
                        uVar
```
#### 23410 — jmp_kernel32.RtlUnwind
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_kernel32.RtlUnwind(void)

{
    /* WARNING: Treating indirect jump as call */
    (*kernel32.RtlUnwind)();
    return;
}

```
#### 11006 — sub_402afe
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402afe(int32_t param_1,int32_t param_2)

{
    int32_t iVar1;
    int32_t iVar2;
    undefined4 *unaff_FS_OFFSET;
    undefined4 uStack_1c;
    code *pcStack_18;
    undefined4 uStack_14;
    int32_t iStack_10;
    
    iStack_10 = param_1;
    pcStack_18 = sub_402adc;
    uStack_1c = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = &uStack_1c;
    while( true ) {
        iVar1 = *(param_1 + 8);
        iVar2 = *(param_1 + 0xc);
        if ((iVar2 == -1) || (iVar2 == param_2)) break;
        uStack_14 = *(iVar1 + iVar2 * 0xc);
        *(param_1 + 0xc) = uStack_14;
        if (*(iVar1 + 4 + iVar2 * 0xc) == 0) {
            sub_402b92(0x101);
            (**(iVar1 + 8 + iVar2 * 0xc))();
        }
    }
    *unaff_FS_OFFSET = uStack_1c;
    return;
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 3240 |
| ? | DIB | 9640 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/zh-cn | 3240 | - |
| ICO/2/zh-cn | 9640 | - |
| GRPICO/102/zh-cn | 34 | - |
| VER/1/zh-cn | 1128 | - |

### Structures (27)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 216 |
| OptionalHeader | 240 |
| Sections | 464 |
| kernel32.FT | 24576 |
| user32.FT | 24752 |
| ImportTable | 25820 |
| kernel32.OFT | 25880 |
| user32.OFT | 26056 |
| ImportNames | 26084 |
| Resources | 49152 |
| Resources.ICO | 49192 |
| Resources.GRPICO | 49224 |
| Resources.VER | 49248 |
| Resources.ICO.1 | 49272 |
| Resources.ICO.2 | 49296 |
| Resources.GRPICO.102 | 49320 |
| Resources.VER.1 | 49344 |
| Resources.ICO.1.zh-cn | 49368 |
| Resources.ICO.2.zh-cn | 49384 |
| Resources.GRPICO.102.zh-cn | 49400 |
| Resources.VER.1.zh-cn | 49416 |
| Resources.ICO.1.zh-cn.Data | 49432 |
| Resources.ICO.2.zh-cn.Data | 52672 |
| Resources.GRPICO.102.zh-cn.Data | 62312 |
| VersionInfo | 62348 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 0.88

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| terminate process |  | C0018:Terminate Process |
| set application hook |  |  |

## PE Imports / Signals
import_count: 49

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@62720 len=22 |
| contains_base64 | - | $a@25104 len=12 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@200 len=4 |
| Microsoft_Visual_Cpp_v60 | - | $a@4182 len=1; $b@5146 len=79; $c@5146 len=35 |
| Installer_VISE_Custom_additional | - | $a@5146 len=64 |
| Microsoft_Visual_Cpp_v50v60_MFC_additional | - | $a@5146 len=22 |
| Microsoft_Visual_Cpp_50 | - | $a@5146 len=22 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@4464 len=4; $b@5146 len=22 |
| Installer_VISE_Custom | - | $a@5146 len=64 |
| Armadillo_v4x | - | $a@4112 len=55 |
| Microsoft_Visual_Cpp | - | $b@5146 len=29 |
| SEH_Save | - | $a@11021 len=7 |
| SEH_Init | - | $b@5168 len=7 |
| win_hook | - | $f1@25760 len=10; $c1@26120 len=19; $c2@26196 len=17; $c3@26216 len=14 |
| win_files_operation | - | $f1@26104 len=12; $c1@26710 len=9; $c2@26722 len=14; $c3@26710 len=9 |

## Generated YARA Meta
```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 62720,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 25104,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
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
      "rule": "Microsoft_Visual_Cpp_v60",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4182,
          "length": 1,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 5146,
          "length": 79,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 5146,
          "length": 35,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Installer_VISE_Custom_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC_additional",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_50",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_v50v60_MFC",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4464,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 5146,
          "length": 22,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Installer_VISE_Custom",
      "path": "/opt/samples/corpus/malware/65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b/vbprop.exe",
      "strings": [
    
```

## FLOSS Strings
Total strings: 132 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 132}`

### High-signal FLOSS
- `KERNEL32.dll`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `"~Richj`
- `.rdata`
- `@.data`
- `HHtpHHtl`
- `SS@SSPVSS`
- `t#SSUP`
- `t$$VSS`
- `_^][YY`
- `DSUVWh`
- `t.;t$$t(`
- `VC20XC00U`
- ``h`````
- `ppxxxx`
- `(null)`
- `__GLOBAL_HEAP_SELECTED`
- `__MSVCRT_HEAP_SELECT`
- `runtime error`
- `TLOSS error`
- `SING error`
- `DOMAIN error`
- `- unable to initialize heap`
- `- not enough space for lowio initialization`
- `- not enough space for stdio initialization`
- `- pure virtual function call`
- `- not enough space for _onexit/atexit table`
- `- unable to open console device`
- `- unexpected heap error`
- `- unexpected multithread lock error`
- `- not enough space for thread data`
- `abnormal program termination`
- `- not enough space for environment`
- `- not enough space for arguments`
- `- floating point not loaded`
- `Microsoft Visual C++ Runtime Library`
- `Runtime Error!`
- `Program:`
- `<program name unknown>`
- `GetLastActivePopup`
- `GetActiveWindow`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040141a
```asm
┌ 235: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_5ch @ ebp-0x5c
│           ; var int32_t var_60h @ ebp-0x60
│           ; var int32_t var_64h @ ebp-0x64
│           ; var int32_t var_68h @ ebp-0x68
│           0x0040141a      55             push ebp
│           0x0040141b      8bec           mov ebp, esp
│           0x0040141d      6aff           push 0xffffffffffffffff
│           0x0040141f      68d0b04000     push 0x40b0d0
│           0x00401424      68b42b4000     push 0x402bb4
│           0x00401429      64a100000000   mov eax, dword fs:[0]
│           0x0040142f      50             push eax
│           0x00401430      6489250000..   mov dword fs:[0], esp
│           0x00401437      83ec58         sub esp, 0x58
│           0x0040143a      53             push ebx
│           0x0040143b      56             push esi
│           0x0040143c      57             push edi
│           0x0040143d      8965e8         mov dword [var_18h], esp
│           0x00401440      ff152cb04000   call dword [sym.imp.KERNEL32.dll_GetVersion] ; 0x40b02c ; DWORD GetVersion(void)
│           0x00401446      33d2           xor edx, edx
│           0x00401448      8ad4           mov dl, ah
│           0x0040144a      891540974000   mov dword [0x409740], edx   ; [0x409740:4]=0
│           0x00401450      8bc8           mov ecx, eax
│           0x00401452      81e1ff000000   and ecx, 0xff               ; 255
│           0x00401458      890d3c974000   mov dword [0x40973c], ecx   ; [0x40973c:4]=0
│           0x0040145e      c1e108         shl ecx, 8
│           0x00401461      03ca           add ecx, edx
│           0x00401463      890d38974000   mov dword [0x409738], ecx   ; [0x409738:4]=0
│           0x00401469      c1e810         shr eax, 0x10
│           0x0040146c      a334974000     mov dword [0x409734], eax   ; [0x409734:4]=0
│           0x00401471      33f6           xor esi, esi
│           0x00401473      56             push esi
│           0x00401474      e8e4150000     call 0x402a5d
│           0x00401479      59             pop ecx
│           0x0040147a      85c0           test eax, eax
│       ┌─< 0x0040147c      7508           jne 0x401486
│       │   0x0040147e      6a1c           push 0x1c                   ; 28
│       │   0x00401480      e8b0000000     call 0x401535
│       │   0x00401485      59             pop ecx
│       └─> 0x00401486      8975fc         mov dword [var_4h], esi
│           0x00401489      e8af120000     call 0x40273d
│           0x0040148e      ff1528b04000   call dword [sym.imp.KERNEL32.dll_GetCommandLineA] ; 0x40b028 ; LPSTR GetCommandLineA(void)
│           0x00401494      a364ac4000     mov dword [0x40ac64], eax   ; [0x40ac64:4]=0
│           0x00401499      e86d110000     call 0x40260b
│           0x0040149e   
```
### 0x00401000
```asm
;-- section..text:
            ; CALL XREF from entry0 @ 0x4014e3(x)
┌ 669: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_8h @ ebp-0x4
│           ; var int32_t var_ch @ esp+0x40
│           ; var int32_t var_dh @ esp+0x41
│           ; var int32_t var_b0h_2 @ esp+0xd4
│           ; var int32_t var_b8h_2 @ esp+0xd8
│           ; var int32_t var_14h @ esp+0xe8
│           ; var int32_t var_b0h @ esp+0xec
│           ; var int32_t var_b8h @ esp+0xf0
│           ; var int32_t var_c0h @ esp+0xf4
│           ; var int32_t var_10h @ esp+0x100
│           ; var int32_t var_24h @ esp+0x130
│           ; var int32_t var_25h @ esp+0x131
│           0x00401000      81ece0000000   sub esp, 0xe0               ; [00] -r-x section size 20480 named .text
│           0x00401006      56             push esi
│           0x00401007      57             push edi
│           0x00401008      b930000000     mov ecx, 0x30               ; '0' ; 48
│           0x0040100d      33c0           xor eax, eax
│           0x0040100f      8d7c2425       lea edi, [var_25h]
│           0x00401013      c644242400     mov byte [var_24h], 0
│           0x00401018      f3ab           rep stosd dword es:[edi], eax
│           0x0040101a      66ab           stosw word es:[edi], ax
│           0x0040101c      8d442424       lea eax, [var_24h]
│           0x00401020      68c4db4000     push 0x40dbc4               ; "us7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7jus7jsus7j"
│           0x00401025      50             push eax
│           0x00401026      e847030000     call 0x401372
│           0x0040102b      83c408         add esp, 8
│           0x0040102e      6a00           push 0
│           0x00401030      6a00           push 0
│           0x00401032      ff1500b04000   call dword [sym.imp.KERNEL32.dll_GetModuleHandleA] ; 0x40b000 ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00401038      50             push eax
│           0x00401039      68b0104000     push 0x4010b0
│           0x0040103e      6a0e           push 0xe                    ; 14
│           0x00401040      ff15b0b04000   call dword [sym.imp.USER32.dll_SetWindowsHookExA] ; 0x40b0b0 ; "R\xb6" ; HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId)
│           0x00401046      8b35b4b04000   mov esi, dword [sym.imp.USER32.dll_GetMessageA] ; [0x40b0b4:4]=0xb644 reloc.USER32.dll_GetMessageA ; "D\xb6"
│           0x0040104c      6a00           push 0
│           0x0040104e      6a00           push 0
│           0x00401050      8d4c2410       lea ecx, [var_10h]
│           0x00401054      6a00           push 0
│           0x00401056      51             push ecx
│           0x00401057      a300604000     mov dword [section..bss], eax ; [0x406000:4]=0
│           0x0040105c      ffd6           call esi
│           0x0040105e      85c0           test eax, eax
│       ┌─< 0x00401060      742d           je 0x40108f
│       │   0x00401062      8b3db8b04000   mov 
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!GetModuleHandleA`
  - `KERNEL32.dll!GetStringTypeA`
  - `KERNEL32.dll!LCMapStringW`
  - `KERNEL32.dll!LCMapStringA`
  - `KERNEL32.dll!MultiByteToWideChar`
  - `USER32.dll!SetWindowsHookExA`
  - `USER32.dll!GetMessageA`
  - `USER32.dll!TranslateMessage`
  - `USER32.dll!DispatchMessageA`
  - `USER32.dll!UnhookWindowsHookEx`
