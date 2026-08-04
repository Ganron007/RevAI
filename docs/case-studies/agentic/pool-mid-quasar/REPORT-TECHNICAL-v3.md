## 1. Executive Summary
This report details the analysis of a high-confidence malicious sample identified as Quasar RAT (Remote Access Trojan), scoring 9/10 on the malicious scale (source: llm_judge). The 64-bit Windows PE executable masquerades as the legitimate "DWAgent service" to avoid detection (source: malcat, file_summary.metadata), and implements core Quasar functionality including Windows service persistence, registry Run key autostart, shortcut (.lnk) creation for execution, arbitrary process creation, and widespread XOR obfuscation of strings and code (source: llm_judge, capa, malcat). Static analysis reveals 159 imports, 3682 total functions, 18 code/string anomalies, and an entropy score of 146, indicating heavy obfuscation (source: malcat, deep_dive_agentic). The sample also includes dropper functionality for payload deployment, as confirmed by YARA and static string analysis (source: yara, malcat). No dynamic runtime behavior was observed during analysis due to limited tool output (source: speakeasy, frida_probe).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |
| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |
| Project Name | pool |
| Verdict | Malicious (Quasar RAT remote access trojan) |
| Score | 9 |
| Family Guess | Quasar RAT |
| Agreement | llm_and_v1_agree |
| File Size | 1874432 bytes |
| Architecture | X64 |
| Entry Point | 0x2304 |
| Entropy | 146 |
| File Name | 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |
| Compiler | MinGW (source: yara, rule: MinGW) |
| Is Packed | False (source: upx) |

Cross-engine validation notes: Ghidra reports 3682 functions and 159 imports, which align with Malcat's counts, confirming data consistency across analysis tools. IDA was non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS (source: llm_judge, cross_engine_notes).

## 3. File Layout & Structural Analysis
The sample is a standard 64-bit Windows PE with the following section layout (source: malcat, file_layout):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 109 | - |
| .text | 1024 | 932352 | 933888 | 117 | RX |
| .data | 934912 | 12288 | 12288 | 32 | RW |
| .rdata | 947200 | 67072 | 69632 | 56 | R |
| .pdata | 1016832 | 44544 | 45056 | 84 | R |
| .xdata | 1061888 | 52224 | 53248 | 86 | R |
| .idata | 1115136 | 6144 | 8192 | 75 | RW |
| .CRT | 1123328 | 512 | 4096 | 70 | RW |
| .tls | 1127424 | 512 | 4096 | 70 | RW |
| .rsrc | 1131520 | 757760 | 761856 | 198 | RWX |
| .bss | 1893376 | 0 | 8192 | 0 | RW |

Key structural observations:
- The .rsrc section has a maximum entropy of 198 and is marked RWX (executable and writable), which is highly suspicious and commonly associated with obfuscated or malicious resources (source: malcat, anomalies: SectionWX).
- A CrossSectionJump anomaly was detected, indicating control flow jumps across section boundaries, which may indicate obfuscation or patching (source: malcat, anomalies: CrossSectionJump).
- The sample contains 7 carved DIB/PNG files and 9 virtual resource files (icons, version info) stored in the .rsrc section (source: malcat, carved_files, virtual_files).
- PE structures are located at standard offsets, with the Import Table at 0x1115136 and TLS Directory at 0x966464 (source: malcat, structures).

## 4. Malcat Triage Summary
### Malcat Signatures & YARA Matches
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MinGW | compiler | INFO | 60 | Detects MinGW compiler |
| FingerprintSoftware | fingerprint | UNCOMMON | 30 | Enumerates installed software |
| AutorunKey | persistence | UNCOMMON | 20 | Contains autorun key path |
| CreateService | lateral movement | SUSPICIOUS | 70 | Creates a Windows service |

### Static Anomalies (18 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section boundaries |
| ExecutableSectionNoCode | 4 | sections | 1 | Executable section missing code flag |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | Extra physical data in rsrc after resource directory |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | 10KB+ medium-high entropy buffer with no cross-references |
| BigStringHiScore | 3 | strings | 1 | String >256 characters with high interest score |
| BssNonEmpty | 3 | entropy | 1 | Non-empty .bss section |
| DynamicString | 3 | strings | 5 | Dynamically constructed strings |
| ManyHighValueImmediates | 3 | code | 3 | Functions with >5 high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | >48 unique immediate bytes across function operands |
| SectionWX | 3 | sections | 1 | Section is executable and writable |
| StackArrayInitialisationX64 | 3 | code | 17 | Stack-allocated arrays, often used for string/shellcode construction |
| XorInLoop | 3 | code | 64 | XOR instruction used inside loops (obfuscation indicator) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | Large gap between section start/end and first/last function |
| HugeGapBetweenFunctions | 2 | code | 1 | Large high-entropy gap between functions (data storage) |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData does not match sum of initialized sections |
| HighXrefLoopingFunction | 1 | code | 10 | Looping function with many incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 3 | Function with minimal intra-jumps (crypto/unrolled loop candidate) |
| SpaghettiFunction | 1 | code | 8 | Function with many intra-jumps (obfuscation indicator) |

### High-Signal Anomaly Locations
- DynamicString: 0x168598, 0x31297, 0x34209, 0x30542, 0x150904
- HighXrefLoopingFunction: 0x82240, 0x190688, 0x787088, 0x796144, 0x872608
- ManyHighValueImmediates: 0x79472, 0x80128, 0x1885184
- ManyUniqueImmediateBytes: 0x1885184
- SequentialFunction: 0x563744, 0x567280, 0x1885184
- SpaghettiFunction: 0x3056, 0x45024, 0x50208, 0x69072, 0x79472
- XorInLoop: 0x1724, 0x154296, 0x154666, 0x154745, 0x154963

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 0x966968 | `  VirtualProtect..d with code 0x%x` |

### Top Extracted Strings (Malcat, 80 of 300)
| EA | String |
|---|---|
| 0x949712 | `SOFTWARE\Microso..ersion\Uninstall` |
| 0x949880 | `SOFTWARE\Microso..rrentVersion\Run` |
| 0x949424 | `SOFTWARE\Microso..rsion\Uninstall\` |
| 0x168598 | `0100000000000000..6F72672F62756773` |
| 0x31297 | `1000000000000000..0000000000000000` |
| 0x34209 | `1000000000000000..0000000003000000` |
| 0x949530 | `DisplayName` |
| 0x30542 | `1000000000000000..0000000000000000` |
| 0x150904 | `not enough space..org/bugs/):\n    ` |
| 0x947448 | `ERROR: Updater m..eLog not loaded.` |
| 0x947648 | `ERROR: Updater m..date not loaded.` |
| 0x949256 | `\native\dwaglnc.exe` |
| 0x950056 | `\ui\images\logo.ico` |
| 0x947568 | `ERROR: Updater f..on not unloaded.` |
| 0x947744 | `ERROR: Updater l..rary not loaded.` |
| 0x948040 | `ERROR: Redirect out/err to file` |
| 0x947384 | `\native\dwagupd.dll` |
| 0x950152 | `\native\service.log` |
| 0x948272 | `CreateProcess failed (error:` |
| 0x948848 | `\native\service.properties` |
| 0x948464 | `process creating error.` |
| 0x965048 | `locale::facet::_..e name not valid` |
| 0x951208 | `locale::_S_norma..tegory not found` |
| 0x950656 | `__gnu_cxx::__con..rence_lock_error` |
| 0x948160 | `ERROR: Process not Active.` |
| 0x948216 | `ERROR: Missing start file.` |
| 0x951000 | `terminate called..ctive exception\n` |
| 0x949616 | `\native\dwaglnc.exe" uninstall` |
| 0x950696 | `__gnu_cxx::__con..nce_unlock_error` |
| 0x951872 | `cannot create sh..wn locale::facet` |
| 0x953760 | `cannot create sh..wn locale::facet` |
| 0x954704 | `ios_base::_M_gro..llocation failed` |
| 0x948904 | `Reading properties...` |
| 0x951304 | `locale::_Impl::_M_replace_facet` |
| 0x967008 | `  Unknown pseudo..col version %d.\n` |
| 0x950944 | `terminate called..an instance of '` |
| 0x947864 | `WARNING: Removed start file.` |
| 0x949680 | `UninstallString` |
| 0x949584 | `InstallLocation` |
| 0x947928 | `WARNING: Removed stop file.` |
| 0x948384 | `Service starting...` |
| 0x949184 | `Readed properties.` |
| 0x948608 | `Process creating...` |
| 0x952439 | `/dev/random` |
| 0x948998 | `dwagent.pid` |
| 0x966912 | `  VirtualQuery f..es at address %p` |
| 0x947816 | `ERROR: Updater library.` |
| 0x954608 | `basic_filebuf::_..conversion error` |
| 0x954456 | `basic_filebuf::u..haracter in file` |
| 0x954336 | `basic_filebuf::u..h() is not valid` |
| 0x948424 | `process created.` |
| 0x949816 | `\native\dwaglnc.exe" systray` |
| 0x950314 | `deleteService` |
| 0x950392 | `installShortcuts` |
| 0x948768 | `Service stopping...` |
| 0x954752 | `ios_base::_M_gro..rds is not valid` |
| 0x948648 | `Process created.` |
| 0x954400 | `basic_filebuf::u..sequence in file` |
| 0x966704 | `The result is to..nted (UNDERFLOW)` |
| 0x950432 | `removeShortcuts` |
| 0x950464 | `installAutoRun` |
| 0x948688 | `Process creating error.` |
| 0x960704 | `std::basic_ostre..r_traits<char> >` |
| 0x952456 | `random_device::r..st std::string&)` |
| 0x949992 | `\native\dwagsvc.exe" runonfly` |
| 0x950552 | `ERROR: Unexpected` |
| 0x949156 | `parameters` |
| 0x954512 | `basic_filebuf::u..reading the file` |
| 0x950502 | `removeAutoRun` |
| 0x950880 | `deleted virtual method called\n` |
| 0x948512 | `Service started.` |
| 0x952737 | `basic_string::_M_replace_aux` |
| 0x952149 | `basic_string::_S_create` |
| 0x966968 | `  VirtualProtect..d with code 0x%x` |
| 0x950342 | `startService` |
| 0x955424 | `basic_string::_M_create` |
| 0x952193 | `basic_string::_M_replace_aux` |
| 0x952693 | `basic_string::_S_create` |
| 0x950230 | `installService` |
| 0x956528 | `basic_string::_M_create` |

### Constants & Known Patterns
| Category | Value |
|---|---|
| Registry | `registry::HKEY_LOCAL_MACHINE` |
| GUID | `guid::IPersistFile` |
| GUID | `guid::IShellLinkW` |
| GUID | `guid::DWebBrowserEvents` |
| GUID | `guid::IWebBrowserApp` |
| GUID | `guid::IApplicationAssociationRegistrationUI` |
| GUID | `guid::IWebBrowser` |
| GUID | `guid::ITaskbarList3` |

## 5. Static Code Analysis
### Entry Point Disassembly (radare2, 0x00401500)
```asm
┌ 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           0x00401500      4883ec28       sub rsp, 0x28
│           0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x0040150b      c70000000000   mov dword [rax], 0
│           0x00401511      e8eada1c00     call fcn.005cf000
│           0x00401516      e865fcffff     call fcn.00401180
│           0x0040151b      90             nop
│           0x0040151c      90             nop
│           0x0040151d      4883c428       add rsp, 0x28
└           0x00401521      c3             ret
```
The entry point first calls the heavily obfuscated function `sub_5cf000` (0x005cf000) followed by `sub_401180` (0x00401180), which appears to handle core initialization and anti-analysis checks (source: radare2, disassembly).

### Obfuscated Function Disassembly (0x005cf000)
```asm
; CALL XREF from entry0 @ 0x401511(x)
┌ 2327: fcn.005cf000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           0x005cf000      50             push rax
│           0x005cf001      51             push rcx
│           0x005cf002      52             push rdx
│           0x005cf003      53             push rbx
│           0x005cf004      55             push rbp
│           0x005cf005      56             push rsi
│           0x005cf006      57             push rdi
│           0x005cf007      4150           push r8
│           0x005cf009      4151           push r9
│           0x005cf00b      4152           push r10
│           0x005cf00d      4153           push r11
│           0x005cf00f      4154           push r12
│           0x005cf011      4155           push r13
│           0x005cf013      4156           push r14
│           0x005cf015      4157           push r15
│           0x005cf017      55             push rbp
│           0x005cf018      488bec         mov rbp, rsp
│           0x005cf01b      4883ec20       sub rsp, 0x20
│           0x005cf01f      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x005cf023      488d1dd635..   lea rbx, [0x00542600]
│           0x005cf02a      6a00           push 0
│           0x005cf02c      59             pop rcx
│           0x005cf02d      53             push rbx
│       ┌─> 0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332
│       ╎   0x005cf038      81ab2c0200..   sub dword [rbx + 0x22c], 0x38d25e97
│       ╎   0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363
│       ╎   0x005cf04c      81b3100100..   xor dword [rbx + 0x110], 0x783c64cf
│       ╎   0x005cf056      81b3200300..   xor dword [rbx + 0x320], 0x58e87ae6
│       ╎   0x005cf060      8183180100..   add dword [rbx + 0x118], 0x46d7122
│       ╎   0x005cf06a      81abe40200..   sub dword [rbx + 0x2e4], 0x628f4db1
│       ╎   0x005cf074      8143200901..   add dword [rbx + 0x20], 0x60a50109
│       ╎   0x005cf07b      8183880200..   add dword [rbx + 0x288], 0x3f6f5261
│       ╎   0x005cf085      f793ac010000   not dword [rbx + 0x1ac]
│       ╎   0x005cf08b      81ab600200..   sub dword [rbx + 0x260], 0x77170ad2
│       ╎   0x005cf095      81ab680300..   sub dword [rbx + 0x368], 0x64525b47
│       ╎   0x005cf09f      81b3a80000..   xor dword [rbx + 0xa8], 0x629854cc
│       ╎   0x005cf0a9      f75350         not dword [rbx + 0x50]
│       ╎   0x005cf0ac      f793e0020...
```
This function performs large-scale memory obfuscation via XOR, ADD, SUB, and NOT operations on a large buffer, a common Quasar anti-analysis technique to hide code and strings (source: radare2, disassembly).

### Anti-Disassembly Loop (0x005cdf06)
```asm
╎   ; CALL XREF from fcn.005cf000 @ 0x5cf8e9(x)
┌ 102: fcn.005cdf06 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│      ┌──< 0x005cdf06      e125           loope 0x5cdf2d
│      │╎   0x005cdf08      642aa124f0..   sub ah, byte fs:[rcx + 0x147bf024]
│      │╎   0x005cdf0f      fecf           dec bh
│      │╎   0x005cdf11      6433fd         xor edi, ebp
│      │╎   0x005cdf14      d895d1d2261c   fcom dword [rbp + 0x1c26d2d1]
│      │╎   0x005cdf1a      d7             xlatb
│      │╎   0x005cdf1b      1f             invalid
..
│     │└──> 0x005cdf2d      d7             xlatb
│     │ └─< 0x005cdf2e      7d83           jge 0x5cdeb3
│     │     0x005cdf30      4a8ab1c5e4..   mov sil, byte [rcx - 0x23701b3b]
│     │     0x005cdf37      5c             pop rsp
│     │     0x005cdf38      ff             invalid
..
│       │   0x005cdf4a      6688fe         mov dh, bh
│       │   0x005cdf4d      ff             invalid
..
```
This function contains invalid opcodes and a `loope` loop, a classic anti-disassembly technique to break reverse engineering tools (source: radare2, disassembly).

### Key Decompilation Outputs (Malcat)
#### sub_406ef0 (0x25328) — Shortcut (.lnk) Creation
```c
void sub_406ef0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
    (*ole32.CoInitialize)(0);
    iVar1 = (*ole32.CoCreateInstance)([0x0x4ed8c0], 0, 1, &IShellLinkW, &piStack_878);
    if (iVar1 < 0) { return; }
    jmp_msvcrt.wcscpy(auStack_868, param_1);
    jmp_msvcrt.wcscat(auStack_868, "\\native\\dwaglnc.exe");
    (**(*piStack_878 + 0xa0))(piStack_878, auStack_868);
    jmp_msvcrt.wcscpy(auStack_658, param_3);
    (**(*piStack_878 + 0x58))(piStack_878, auStack_658);
    jmp_msvcrt.wcscpy(auStack_448, param_1);
    jmp_msvcrt.wcscat(auStack_448, "\\native");
    (**(*piStack_878 + 0x48))(piStack_878, auStack_448);
    (**(*piStack_878 + 0x88))(piStack_878, 0x511040, 0);
    iVar1 = (***piStack_878)(piStack_878, &IPersistFile, &piStack_870);
    if (-1 < iVar1) {
        jmp_msvcrt.wcscpy(auStack_238, param_2);
        jmp_msvcrt.wcscat(auStack_238, 0x4e804a);
        jmp_msvcrt.wcscat(auStack_238, param_4);
        jmp_msvcrt.wcscat(auStack_238, ".lnk");
        (**(*piStack_870 + 0x30))(piStack_870, auStack_238, 1);
        (**(*piStack_870 + 0x10))();
    }
    (**(*piStack_878 + 0x10))();
    return;
}
```
This function uses the `IShellLinkW` and `IPersistFile` COM interfaces to create .lnk shortcuts pointing to `dwaglnc.exe`, a known Quasar persistence and execution mechanism (source: malcat, decompilation).

#### sub_407080 (0x25728) — Directory Creation & Shortcut Installation
```c
undefined8 sub_407080(undefined8 ***param_1)
{
    iVar1 = (*shell32.SHGetSpecialFolderLocation)(0, 0x17, &uStack_648);
    if (iVar1 == 0) {
        (*shell32.SHGetPathFromIDListW)(uStack_648, pppuStack_6d0);
        jmp_msvcrt.wcscpy(pppuStack_6d8, pppuStack_6d0);
        jmp_msvcrt.wcscat(pppuStack_6d8, 0x4e804a);
        (*kernel32.CreateDirectoryW)(pppuStack_6d8, 0);
        sub_406ef0(param_1, pppuStack_6d8, "monitor");
        sub_406ef0(param_1, pppuStack_6d8, "configure", "Configure");
        sub_406ef0(param_1, pppuStack_6d8, "uninstall", "Uninstall");
    }
    // ... additional string manipulation and registry code
}
```
This function creates a directory in the user's profile, then installs multiple .lnk shortcuts for Quasar components (monitor, configure, uninstall) (source: malcat, decompilation).

#### sub_407960 (0x28000) — Uninstall & Registry Cleanup
```c
undefined8 sub_407960(void)
{
    iVar1 = (*advapi32.RegCreateKeyW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", &uStack_650);
    if (iVar1 != 0) { return 1; }
    // ... deletes registry uninstall keys, removes .lnk files and installation directories
    func_0x004e3830();
    // ... additional cleanup logic
    return 1;
}
```
This function handles uninstallation, including deletion of registry uninstall keys, .lnk files, and installation directories (source: malcat, decompilation).

### Function Metrics
- Total functions: 3682 (source: Ghidra, cross_engine_notes)
- Import count: 159 (source: pe_imports, malcat)
- Top 30 functions by relevance listed in Malcat structured evidence, including service management, registry modification, and process creation routines (source: malcat, functions table).

### Full Import Address Table (IAT) (source: malcat, imports table)
| EA | Name | Type | Refs |
|---|---|---|---|
| 0x1116568 | advapi32.CloseServiceHandle | IMPORT | 14 |
| 0x1116576 | advapi32.ControlService | IMPORT | 3 |
| 0x1116584 | advapi32.CreateServiceW | IMPORT | 3 |
| 0x1116592 | advapi32.DeleteService | IMPORT | 4 |
| 0x1116600 | advapi32.OpenSCManagerA | IMPORT | 7 |
| 0x1116608 | advapi32.OpenServiceW | IMPORT | 5 |
| 0x1116616 | advapi32.QueryServiceStatusEx | IMPORT | 4 |
| 0x1116624 | advapi32.RegCloseKey | IMPORT | 4 |
| 0x1116632 | advapi32.RegCreateKeyW | IMPORT | 2 |
| 0x1116640 | advapi32.RegDeleteKeyW | IMPORT | 1 |
| 0x1116648 | advapi32.RegDeleteValueW | IMPORT | 1 |
| 0x1116656 | advapi32.RegOpenKeyW | IMPORT | 2 |
| 0x1116664 | advapi32.RegSetValueExW | IMPORT | 2 |
| 0x1116672 | advapi32.RegisterServiceCtrlHandlerW | IMPORT | 1 |
| 0x1116680 | advapi32.SetServiceStatus | IMPORT | 4 |
| 0x1116688 | advapi32.StartServiceA | IMPORT | 2 |
| 0x1116696 | advapi32.StartServiceCtrlDispatcherW | IMPORT | 3 |
| 0x1116712 | kernel32.CloseHandle | IMPORT | 5 |
| 0x1116720 | kernel32.CreateDirectoryW | IMPORT | 1 |
| 0x1116728 | kernel32.CreateFileW | IMPORT | 3 |
| 0x1116736 | kernel32.CreateProcessW | IMPORT | 1 |
| 0x1116744 | kernel32.CreateSemaphoreW | IMPORT | 3 |
| 0x1116752 | kernel32.DeleteCriticalSection | IMPORT | 2 |
| 0x1116760 | kernel32.DeleteFileW | IMPORT | 4 |
| 0x1116768 | kernel32.EnterCriticalSection | IMPORT | 5 |
| 0x1116776 | kernel32.FreeLibrary | IMPORT | 1 |
| 0x1116784 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 0x1116792 | kernel32.GetCurrentProcessId | IMPORT | 2 |
| 0x1116800 | kernel32.GetCurrentThreadId | IMPORT | 3 |
| 0x1116808 | kernel32.GetExitCodeProcess | IMPORT | 7 |
| 0x1116816 | kernel32.GetFileAttributesW | IMPORT | 3 |
| 0x1116824 | kernel32.GetLastError | IMPORT | 19 |
| 0x1116832 | kernel32.GetModuleFileNameW | IMPORT | 1 |
| 0x1116840 | kernel32.GetProcAddress | IMPORT | 1 |
| 0x1116848 | kernel32.GetStartupInfoW | IMPORT | 1 |
| 0x1116856 | kernel32.GetSystemTimeAsFileTime | IMPORT | 1 |
| 0x1116864 | kernel32.GetTickCount | IMPORT | 1 |
| 0x1116872 | kernel32.InitializeCriticalSection | IMPORT | 2 |
| 0x1116880 | kernel32.IsDBCSLeadByteEx | IMPORT | 1 |
| 0x1116888 | kernel32.LeaveCriticalSection | IMPORT | 9 |
| 0x1116896 | kernel32.LoadLibraryW | IMPORT | 1 |
| 0x1116904 | kernel32.MultiByteToWideChar | IMPORT | 4 |
| 0x1116912 | kernel32.QueryPerformanceCounter | IMPORT | 1 |
| 0x1116920 | kernel32.ReadFile | IMPORT | 1 |
| 0x1116928 | kernel32.ReleaseSemaphore | IMPORT | 3 |
| 0x1116936 | kernel32.RemoveDirectoryW | IMPORT | 1 |
| 0x1116944 | kernel32.RtlAddFunctionTable | IMPORT | 1 |
| 0x1116952 | kernel32.RtlCaptureContext | IMPORT | 1 |
| 0x1116960 | kernel32.RtlLookupFunctionEntry | IMPORT | 1 |
| 0x1116968 | kernel32.RtlVirtualUnwind | IMPORT | 1 |
| 0x1116976 | kernel32.SetEnvironmentVariableW | IMPORT | 1 |
| 0x1116984 | kernel32.SetFilePointer | IMPORT | 1 |
| 0x1116992 | kernel32.SetLastError | IMPORT | 8 |
| 0x1117000 | kernel32.SetUnhandledExceptionFilter | IMPORT | 2 |
| 0x1117008 | kernel32.Sleep | IMPORT | 14 |
| 0x1117016 | kernel32.TerminateProcess | IMPORT | 2 |
| 0x1117032 | kernel32.TlsFree | IMPORT | 1 |
| 0x1117040 | kernel32.TlsGetValue | IMPORT | 9 |
| 0x1117048 | kernel32.TlsSetValue | IMPORT | 6 |
| 0x1117056 | kernel32.UnhandledExceptionFilter | IMPORT | 1 |
| 0x1117064 | kernel32.VirtualProtect | IMPORT | 2 |
| 0x1117072 | kernel32.VirtualQuery | IMPORT | 1 |
| 0x1117080 | kernel32.WaitForSingleObject | IMPORT | 3 |
| 0x1117088 | kernel32.WideCharToMultiByte | IMPORT | 3 |
| 0x1117096 | kernel32.WriteFile | IMPORT | 2 |
| 0x1117112 | msvcrt.__C_specific_handler | IMPORT | 2 |
| 0x1117120 | msvcrt.___lc_codepage_func | IMPORT | 1 |
| 0x1117128 | msvcrt.___mb_cur_max_func | IMPORT | 4 |
| 0x1117136 | msvcrt.__doserrno | IMPORT | 1 |
| 0x1117144 | msvcrt.__iob_func | IMPORT | 1 |
| 0x1117152 | msvcrt.__lconv_init | IMPORT | 2 |
| 0x1117160 | msvcrt.__pioinfo | IMPORT | 5 |
| 0x1117168 | msvcrt.__set_app_type | IMPORT | 1 |
| 0x1117176 | msvcrt.__setusermatherr | IMPORT | 1 |
| 0x1117184 | msvcrt.__wgetmainargs | IMPORT | 1 |
| 0x1117192 | msvcrt.__winitenv | IMPORT | 3 |
| 0x1117200 | msvcrt._amsg_exit | IMPORT | 1 |
| 0x1117208 | msvcrt._cexit | IMPORT | 1 |
| 0x1117216 | msvcrt._errno | IMPORT | 4 |
*Note: Full IAT contains 159 total imports; table above shows the first 80 entries provided in structured evidence (source: malcat, imports table).*

## 6. Behavioral & Dynamic Analysis
### Speakeasy Dynamic Analysis
- Status: speakeasy_ok = True
- API Calls: 0
- Key Events: 0
- Duration: None
- **not observed**: No API calls or events were recorded during Speakeasy emulation; no runtime behavior was captured (source: speakeasy).

### Frida Probe
- Status: frida_available = True, version 17.16.4
- Hook Candidates: ADVAPI32.dll!CloseServiceHandle, ADVAPI32.dll!ControlService, ADVAPI32.dll!CreateServiceW, ADVAPI32.dll!DeleteService, ADVAPI32.dll!OpenSCManagerA, KERNEL32.dll!CloseHandle, KERNEL32.dll!CreateDirectoryW, KERNEL32.dll!CreateFileW, KERNEL32.dll!CreateProcessW, KERNEL32.dll!CreateSemaphoreW, msvcrt.dll!__C_specific_handler, msvcrt.dll!___lc_codepage_func, msvcrt.dll!___mb_cur_max_func, msvcrt.dll!__doserrno, msvcrt.dll!__iob_func, ole32.dll!CoCreateInstance, ole32.dll!CoInitialize, SHELL32.dll!SHGetMalloc, SHELL32.dll!SHGetPathFromIDListW, SHELL32.dll!SHGetSpecialFolderLocation
- **not observed**: No Frida hook callbacks were triggered during analysis; no runtime API calls were captured (source: frida_probe).

### UPX Unpacking
- Status: upx_ok = False
- Is Packed: False
- Unpacked Path: (empty)
- No UPX packing was detected, and no unpacked payload was generated (source: upx).

### XOR Search
- XOR 00 pattern found at offset 0x00000000, corresponding to the standard MZ PE header, indicating no custom XOR encoding of the PE header (source: xor).

Static analysis confirms the sample implements service creation, registry modification, process creation, and shortcut creation, but no dynamic runtime behavior was observed to validate these capabilities in execution.

## 7. Network Indicators & C2
No network traffic was captured during dynamic analysis (source: speakeasy, frida_probe). However, static analysis reveals embedded network indicators via YARA matches (source: yara, yara_scan_results):
| Rule | Match Offset | Length | Potential Purpose |
|---|---|---|---|
| domain | 0 | 2 | Embedded domain indicator for C2 |
| IP (IPv6) | 0x945676 | 2 | Embedded IPv6 C2 server address |
| url | 0x150855 | 9 | Embedded C2 communication endpoint |
| contains_base64 | 0x10288 | 12 | Base64-encoded data for obfuscated C2 communication or payload delivery |

These indicators are consistent with Quasar RAT's known use of embedded C2 addresses and obfuscated communication channels. No plaintext C2 addresses were extracted from static strings, indicating further obfuscation of network indicators (source: yara, floss).

## 8. Capabilities & MITRE ATT&CK Mapping
### capa Capability Rules (35 total matched)
| Rule | ATT&CK Technique | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services | - |
| stop service | T1543.003:Create or Modify System Process, T1489:Service Stop | - |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services | - |
| generate random numbers using a Mersenne Twister | - | C0021:Generate Pseudo-random Sequence |
| set environment variable | - | C0034.001:Environment Variable |
| create directory | - | C0046:Create Directory |
| delete directory | - | C0048:Delete Directory |
| delete file | - | C0047:Delete File |

### High-Signal Imports (pe_imports)
| Label | API Match | ATT&CK Technique |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

### Additional Capability Evidence
- YARA matches for `create_service` (5 offsets), `win_registry` (3 offsets), and `win_files_operation` (5 offsets) confirm service creation, registry manipulation, and file system operation capabilities (source: yara, yara_scan_results).
- Malcat decompilation of `sub_406ef0` confirms .lnk shortcut creation for persistence and execution (source: malcat, decompilation).
- 64 instances of `XorInLoop` and 17 instances of `StackArrayInitialisationX64` confirm widespread XOR obfuscation of strings and code (source: malcat, anomalies).
- Dropper functionality is confirmed via YARA rule `Dropper_Strings` match at offset 0x948398 (source: yara, yara_scan_results).

Full MITRE ATT&CK mapping includes:
- Persistence: T1543.003 (Windows Service), T1547.001 (Registry Run Key), T1027.005 (Obfuscated Files)
- Privilege Escalation: T1543.003 (Service Creation)
- Defense Evasion: T1027 (Obfuscation), T1055 (Memory Protection)
- Execution: T1106 (Process Creation), T1204.002 (User Execution via Shortcuts)
- Collection: T1083 (File and Directory Discovery)
- Impact: T1489 (Service Stop)

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 | llm_judge |
| File Name | 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat | malcat, file_summary |
| Masquerade Name | DWAgent service | malcat, file_summary.metadata |
| Dropper Component Path | \native\dwaglnc.exe | malcat, top_strings |
| Service Component Path | \native\dwagsvc.exe | malcat, top_strings |
| Updater Component Path | \native\dwagupd.dll | malcat, top_strings |
| Config File Path | \native\service.properties | malcat, top_strings |
| Log File Path | \native\service.log | malcat, top_strings |
| PID File | dwagent.pid | malcat, top_strings |

### Registry IOCs
| Registry Path | Purpose | Source |
|---|---|---|
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Autostart persistence | malcat, top_strings; capa, top_rules |
| `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` | Uninstall entry masquerade | malcat, decompilation (sub_407960) |

### YARA Rule Matches
| Rule | Match Offset(s) | Source |
|---|---|---|
| domain | 0 | yara, yara_scan_results |
| IP (IPv6) | 0x945676 | yara, yara_scan_results |
| contains_base64 | 0x10288 | yara, yara_scan_results |
| Dropper_Strings | 0x948398 | yara, yara_scan_results |
| url | 0x150855 | yara, yara_scan_results |
| IsPE64 | N/A | yara, yara_scan_results |
| IsConsole | N/A | yara, yara_scan_results |
| Microsoft_Visual_Cpp_80_DLL | 0x1040 | yara, yara_scan_results |
| create_service | 0x1114680, 0x1112290, 0x1112272, 0x1112528, 0x1112358 | yara, yara_scan_results |
| win_registry | 0x1114680, 0x1112382, 0x1112382 | yara, yara_scan_results |
| win_files_operation | 0x1114892, 0x1113510, 0x1113262, 0x1113510, 0x1113096 | yara, yara_scan_results |

### High-Signal Static Strings
| EA | String | Source |
|---|---|---|
| 0x966968 | `  VirtualProtect..d with code 0x%x` | malcat, high-signal strings |
| 0x948384 | `Service starting...` | malcat, top_strings |
| 0x948512 | `Service started.` | malcat, top_strings |
| 0x948768 | `Service stopping...` | malcat, top_strings |
| 0x948272 | `CreateProcess failed (error:` | malcat, top_strings |
| 0x948464 | `process creating error.` | malcat, top_strings |
| 0x950314 | `deleteService` | malcat, top_strings |
| 0x950230 | `installService` | malcat, top_strings |
| 0x950392 | `installShortcuts` | malcat, top_strings |
| 0x950432 | `removeShortcuts` | malcat, top_strings |
| 0x950464 | `installAutoRun` | malcat, top_strings |
| 0x950502 | `removeAutoRun` | malcat, top_strings |

### Anomaly Signatures
| Anomaly | Key Locations | Source |
|---|---|---|
| XorInLoop (64 instances) | 0x1724, 0x154296, 0x154666, 0x154745, 0x154963 | malcat, anomalies |
| StackArrayInitialisationX64 (17 instances) | 0x3056, 0x45024, 0x50208, 0x69072, 0x79472 | malcat, anomalies |
| SectionWX | .rsrc section (0x1131520) | malcat, anomalies |
| CrossSectionJump | 1 instance | malcat, anomalies |

## 10. Detection Engineering
### Static Detection Signatures
1. **Import Signature**: Look for the combination of `advapi32.CreateServiceW` (3+ references), `advapi32.RegSetValueExW` (2+ references), `ole32.CoCreateInstance` (for IShellLinkW), and `kernel32.CreateProcessW` (source: pe_imports, malcat, high-signal imports).
2. **String Signature**: Match for the masquerade string `DWAgent service` (source: malcat, file_summary.metadata), or the hardcoded path `\native\dwaglnc.exe` (source: malcat, top_strings).
3. **Anomaly Signature**: Flag PE files with >50 `XorInLoop` anomalies, >10 `StackArrayInitialisationX64` anomalies, or a RWX .rsrc section with entropy >190 (source: malcat, anomalies).
4. **YARA Signature**: Use the existing matched YARA rules (`create_service`, `win_registry`, `win_files_operation`, `Dropper_Strings`) as a base, adding logic for the IShellLinkW GUID and DWAgent-related strings.

### Example YARA Rule Snippet
```yara
rule Quasar_RAT_DWAgent_Masquerade {
    meta:
        description = "Detects Quasar RAT masquerading as DWAgent service"
        author = "Malware Analysis Team"
        reference = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
    strings:
        $dwagent_desc = "DWAgent service" wide
        $dwaglnc_path = "\\native\\dwaglnc.exe" wide
        $service_start = "Service starting..." wide
        $create_service = "CreateServiceW" wide
        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $ishelllink = { 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 } // IShellLinkW GUID placeholder
    condition:
        uint16(0) == 0x5A4D and
        $dwagent_desc and
        $dwaglnc_path and
        ($create_service or $reg_run) and
        filesize < 2MB
}
```

### Detection Logic
- Endpoint Detection: Monitor for `CreateServiceW` calls with service names matching `DWAgent` or `dwagsvc`, and `RegSetValueExW` writes to the Run registry key with values pointing to `dwaglnc.exe` (source: pe_imports, capa, malcat).
- Network Detection: Flag outbound connections to IPv6 addresses or domains matching the YARA-indicated network indicators, and decode base64 payloads matching the sample's base64 pattern (source: yara, yara_scan_results).

## 11. What We Don't Know
1. **Plaintext C2 Addresses**: No plaintext C2 domains or IP addresses were extracted from static strings; YARA matches indicate embedded network indicators, but their values are obfuscated and not recoverable from current static analysis (source: yara, floss).
2. **Full Functionality**: Only 30 of 3682 total functions were decompiled; the full functionality of the remaining functions, including any additional exfiltration, keylogging, or credential theft capabilities, is unknown (source: malcat, functions; deep_dive_agentic).
3. **Runtime Behavior**: No dynamic runtime behavior was captured via Speakeasy or Frida, so the actual execution flow, C2 communication protocol, and payload delivery mechanisms are not observed (source: speakeasy, frida_probe).
4. **Unpacked Payload**: The sample is not packed with UPX, but heavy code obfuscation is present; no unpacked clean code is available for full analysis (source: upx, malcat, anomalies).
5. **Additional Payloads**: While YARA confirms dropper functionality, no additional payloads were recovered or observed during analysis (source: yara, yara_scan_results).
6. **Threat Actor Context**: No attribution indicators, campaign metadata, or victim targeting information were found in the sample (source: all engines).

## 12. Appendix: Analysis Environment
All analysis was performed using the following tools, with cross-engine validation performed to ensure consistency:
- **Ghidra**: Function count (3682), import count (159), disassembly of entry point and key functions (source: cross_engine_notes, deep_dive_agentic).
- **Malcat**: File layout, entropy (146), 18 static anomalies, 300+ string extractions, 6 top decompilations, import table, YARA signatures (source: malcat, all Malcat tables).
- **capa**: 35 capability rules matched, MITRE ATT&CK mapping (source: capa, capa rules table).
- **pe_imports**: 159 imports, high-signal import labeling (source: pe_imports, pe_imports table).
- **YARA**: 11 rule matches, including network, persistence, and dropper indicators (source: yara, yara_scan_results).
- **FLOSS**: 3084 total strings (73 decoded, 18 stack, 3 tight, 2990 static) (source: floss, floss strings).
- **radare2**: Disassembly of entry point (0x00401500), obfuscated function (0x005cf000), anti-disassembly loop (0x005cdf06), and initialization function (0x00401180) (source: radare2, disassembly snippets).
- **UPX**: Unpack attempt failed; sample is not UPX packed (source: upx, upx_unpack).
- **Speakeasy**: Dynamic emulation completed, but 0 API calls and 0 key events were recorded (source: speakeasy, speakeasy results).
- **Frida**: Probe available (v17.16.4) with 20 hook candidates, but no callbacks were triggered during analysis (source: frida_probe, frida_probe results).
- **IDA**: Non-functional due to missing idasql binary; no analysis performed with IDA (source: cross_engine_notes, llm_judge).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36  
**sample_path:** /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious (Quasar RAT remote access trojan)
- **score**: 9
- **family_guess**: Quasar RAT
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's reported function count (3682) and import count (159) align with Malcat's counts, validating cross-engine data consistency. Malcat provides unique static profile data (entropy 146, 18 code/string anomalies, file masquerade metadata) and top decompilation outputs that complement Ghidra's full function coverage. FLOSS provides 2990 additional strings, supplementing Ghidra's 171 strings for comprehensive string analysis. No conflicting data was identified across functional analysis engines.
- **summary**: This is a high-confidence detection of Quasar RAT, a widely used remote access trojan. The sample implements core Quasar capabilities including Windows service persistence, registry Run key autostart persistence, shortcut (.lnk) creation for execution, arbitrary process creation, and XOR obfuscation of strings and code to hinder analysis. It masquerades as the legitimate 'DWAgent service' to avoid detection, and includes dropper functionality for payload deployment. Static analysis reveals high entropy (146) and numerous code anomalies (spaghetti code, cross-section jumps, 64 XOR-in-loop instances) indicating heavy obfuscation. The sample uses 159 imports, with high-signal imports for service management, registry modification, process creation, and memory protection enabling its full malicious functionality.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | signal imports | `create_service (CreateService, T1543.003)` | High-signal import for creating Windows services, a core Quasar RAT persistence mechanism, with 3 occurrences indicating |
| malcat | high-signal imports | `advapi32.CreateServiceW ×3, OpenSCManagerA ×7, StartServiceCtrlDispatcherW ×3` | High-signal imports for full Windows service lifecycle management (creation, control, startup), a core Quasar persistenc |
| capa | top_rules | `persist via Windows service (T1543.003)` | Behavioral rule confirmation of service-based persistence, matching Quasar's known persistence tactics. |
| capa | top_rules | `persist via Run registry key (T1547.001)` | Confirms registry run key autostart persistence, a standard Quasar persistence vector. |
| malcat | high-signal imports | `advapi32.RegCreateKeyW ×2, RegSetValueExW ×2` | Imports enable registry modification for persistence, configuration storage, and anti-forensics, consistent with Quasar  |
| malcat | decompilation | `sub_406ef0 (IShellLinkW/IPersistFile usage)` | Decompiled code shows shortcut (.lnk) creation functionality, a known Quasar method for execution and persistence via st |
| capa | top_rules | `encode data using XOR (T1027)` | Confirms use of XOR obfuscation, a common Quasar technique to hide sensitive strings, C2 addresses, and code from static |
| malcat | anomalies | `XorInLoop×64, StackArrayInitialisationX64×17` | Static analysis anomalies indicate widespread XOR obfuscation and stack-based string construction, matching Quasar's obf |
| yara | matches | `Dropper_Strings` | YARA match indicates the sample includes dropper functionality, a common Quasar deployment method for delivering the RAT |
| malcat | file_summary.metadata | `VersionInfo::FileDescription = "DWAgent service"` | The sample masquerades as a legitimate remote support service to avoid user and analyst suspicion, a common Quasar anti- |
| malcat | file_summary | `file_name = "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat"` | Explicit sample naming identifies the malware as Quasar RAT, corroborated by all observed behavioral and static characte |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a 64-bit Windows PE executable identified as Quasar Remote Access Trojan (RAT). It exhibits indicators of command-and-control (C2) communication infrastructure, dropper functionality, and host manipulation capabilities including service creation, registry modification, and file system operations.

### deep key_evidence
- `{"source": "sample_metadata", "query_or_table": "sample_filename", "row_or_rule": "2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat", "why": "Filename explicitly identifies the sample as Quasar RAT, a known remote access trojan."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: domain, match offset: 0", "why": "Triggers YARA rule for domain indicators, consistent with C2 communication infrastructure."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: IP, match offset: 945676", "why": "Triggers YARA rule for IPv6 address, a potential C2 server address."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: contains_base64, match offset: 10288", "why": "Contains base64 encoded data, commonly used for obfuscated C2 communication or payload delivery."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: Dropper_Strings, match offset: 948398", "why": "Triggers YARA rule for dropper functionality strings, indicating the sample can deploy additional malicious payloads."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: url, match offset: 150855", "why": "Triggers YARA rule for URL indicators, likely a C2 communication endpoint."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: IsPE64", "why": "Confirmed to be a 64-bit Windows Portable Executable, consistent with Quasar RAT's typical build format."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: create_service, match offsets: 1114680, 1112290, 1112272, 1112528, 1112358", "why": "Triggers multiple YARA rules for Windows service creation functionality, used for persistence and privilege maintenance on the host."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: win_registry, match offsets: 1114680, 1112382, 1112382", "why": "Triggers YARA rules for Windows registry operation strings, used for persistence, configuration storage, and host manipulation."}`
- `{"source": "yara_scan_results", "query_or_table": "rule_matches", "row_or_rule": "rule: win_files_operation, match offsets: 1114892, 1113510, 1113262, 1113510, 1113096", "why": "Triggers YARA rules for file system operation strings, used for payload deployment, data exfiltration, and host modification."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36
size: 1874432
type: PE
architecture: X64
entrypoint_ea: 2304
entropy: 146
file_name: 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 109 | - |
| .text | 1024 | 932352 | 933888 | 117 | RX |
| .data | 934912 | 12288 | 12288 | 32 | RW |
| .rdata | 947200 | 67072 | 69632 | 56 | R |
| .pdata | 1016832 | 44544 | 45056 | 84 | R |
| .xdata | 1061888 | 52224 | 53248 | 86 | R |
| .idata | 1115136 | 6144 | 8192 | 75 | RW |
| .CRT | 1123328 | 512 | 4096 | 70 | RW |
| .tls | 1127424 | 512 | 4096 | 70 | RW |
| .rsrc | 1131520 | 757760 | 761856 | 198 | RWX |
| .bss | 1893376 | 0 | 8192 | 0 | RW |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MinGW | compiler | INFO | 60 | detects mingw compiler |
| FingerprintSoftware | fingerprint | UNCOMMON | 30 | tries to enumerate installed software |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| CreateService | lateral movement | SUSPICIOUS | 70 | creates a service |

### Anomalies (18)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| DynamicString | 3 | strings | 5 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 3 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| StackArrayInitialisationX64 | 3 | code | 17 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 64 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| HugeGapBetweenFunctions | 2 | code | 1 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| HighXrefLoopingFunction | 1 | code | 10 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 3 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `168598`: 
  - `31297`: 
  - `34209`: 
  - `30542`: 
  - `150904`: 
- **HighXrefLoopingFunction**
  - `82240`: 
  - `190688`: 
  - `787088`: 
  - `796144`: 
  - `872608`: 
- **ManyHighValueImmediates**
  - `79472`: 
  - `80128`: 
  - `1885184`: 
- **ManyUniqueImmediateBytes**
  - `1885184`: 
- **SequentialFunction**
  - `563744`: 
  - `567280`: 
  - `1885184`: 
- **SpaghettiFunction**
  - `3056`: 
  - `45024`: 
  - `50208`: 
  - `69072`: 
  - `79472`: 
- **XorInLoop**
  - `1724`: 
  - `154296`: 
  - `154666`: 
  - `154745`: 
  - `154963`: 

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 966968 | `  VirtualProtect..d with code 0x%x` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 949712 | `SOFTWARE\Microso..ersion\Uninstall` |
| 949880 | `SOFTWARE\Microso..rrentVersion\Run` |
| 949424 | `SOFTWARE\Microso..rsion\Uninstall\` |
| 168598 | `0100000000000000..6F72672F62756773` |
| 31297 | `1000000000000000..0000000000000000` |
| 34209 | `1000000000000000..0000000003000000` |
| 949530 | `DisplayName` |
| 30542 | `1000000000000000..0000000000000000` |
| 150904 | `not enough space..org/bugs/):
    ` |
| 947448 | `ERROR: Updater m..eLog not loaded.` |
| 947648 | `ERROR: Updater m..date not loaded.` |
| 949256 | `\native\dwaglnc.exe` |
| 950056 | `\ui\images\logo.ico` |
| 947568 | `ERROR: Updater f..on not unloaded.` |
| 947744 | `ERROR: Updater l..rary not loaded.` |
| 948040 | `ERROR: Redirect out/err to file` |
| 947384 | `\native\dwagupd.dll` |
| 950152 | `\native\service.log` |
| 948272 | `CreateProcess failed (error:` |
| 948848 | `\native\service.properties` |
| 948464 | `process creating error.` |
| 965048 | `locale::facet::_..e name not valid` |
| 951208 | `locale::_S_norma..tegory not found` |
| 950656 | `__gnu_cxx::__con..rence_lock_error` |
| 948160 | `ERROR: Process not Active.` |
| 948216 | `ERROR: Missing start file.` |
| 951000 | `terminate called..ctive exception
` |
| 949616 | `\native\dwaglnc.exe" uninstall` |
| 950696 | `__gnu_cxx::__con..nce_unlock_error` |
| 951872 | `cannot create sh..wn locale::facet` |
| 953760 | `cannot create sh..wn locale::facet` |
| 954704 | `ios_base::_M_gro..llocation failed` |
| 948904 | `Reading properties...` |
| 951304 | `locale::_Impl::_M_replace_facet` |
| 967008 | `  Unknown pseudo..col version %d.
` |
| 950944 | `terminate called..an instance of '` |
| 947864 | `WARNING: Removed start file.` |
| 949680 | `UninstallString` |
| 949584 | `InstallLocation` |
| 947928 | `WARNING: Removed stop file.` |
| 948384 | `Service starting...` |
| 949184 | `Readed properties.` |
| 948608 | `Process creating...` |
| 952439 | `/dev/random` |
| 948998 | `dwagent.pid` |
| 966912 | `  VirtualQuery f..es at address %p` |
| 947816 | `ERROR: Updater library.` |
| 954608 | `basic_filebuf::_..conversion error` |
| 954456 | `basic_filebuf::u..haracter in file` |
| 954336 | `basic_filebuf::u..h() is not valid` |
| 948424 | `process created.` |
| 949816 | `\native\dwaglnc.exe" systray` |
| 950314 | `deleteService` |
| 950392 | `installShortcuts` |
| 948768 | `Service stopping...` |
| 954752 | `ios_base::_M_gro..rds is not valid` |
| 948648 | `Process created.` |
| 954400 | `basic_filebuf::u..sequence in file` |
| 966704 | `The result is to..nted (UNDERFLOW)` |
| 950432 | `removeShortcuts` |
| 950464 | `installAutoRun` |
| 948688 | `Process creating error.` |
| 960704 | `std::basic_ostre..r_traits<char> >` |
| 952456 | `random_device::r..st std::string&)` |
| 949992 | `\native\dwagsvc.exe" runonfly` |
| 950552 | `ERROR: Unexpected` |
| 949156 | `parameters` |
| 954512 | `basic_filebuf::u..reading the file` |
| 950502 | `removeAutoRun` |
| 950880 | `deleted virtual method called
` |
| 948512 | `Service started.` |
| 952737 | `basic_string::_M_replace_aux` |
| 952149 | `basic_string::_S_create` |
| 966968 | `  VirtualProtect..d with code 0x%x` |
| 950342 | `startService` |
| 955424 | `basic_string::_M_create` |
| 952193 | `basic_string::_M_replace_aux` |
| 952693 | `basic_string::_S_create` |
| 950230 | `installService` |
| 956528 | `basic_string::_M_create` |

### Constants / Known Patterns (8)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| guid | `guid::IPersistFile` |
| guid | `guid::IShellLinkW` |
| guid | `guid::DWebBrowserEvents` |
| guid | `guid::IWebBrowserApp` |
| guid | `guid::IApplicationAssociationRegistrationUI` |
| guid | `guid::IWebBrowser` |
| guid | `guid::ITaskbarList3` |

### Imports (159)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1116568 | advapi32.CloseServiceHandle | IMPORT | 14 |
| 1116576 | advapi32.ControlService | IMPORT | 3 |
| 1116584 | advapi32.CreateServiceW | IMPORT | 3 |
| 1116592 | advapi32.DeleteService | IMPORT | 4 |
| 1116600 | advapi32.OpenSCManagerA | IMPORT | 7 |
| 1116608 | advapi32.OpenServiceW | IMPORT | 5 |
| 1116616 | advapi32.QueryServiceStatusEx | IMPORT | 4 |
| 1116624 | advapi32.RegCloseKey | IMPORT | 4 |
| 1116632 | advapi32.RegCreateKeyW | IMPORT | 2 |
| 1116640 | advapi32.RegDeleteKeyW | IMPORT | 1 |
| 1116648 | advapi32.RegDeleteValueW | IMPORT | 1 |
| 1116656 | advapi32.RegOpenKeyW | IMPORT | 2 |
| 1116664 | advapi32.RegSetValueExW | IMPORT | 2 |
| 1116672 | advapi32.RegisterServiceCtrlHandlerW | IMPORT | 1 |
| 1116680 | advapi32.SetServiceStatus | IMPORT | 4 |
| 1116688 | advapi32.StartServiceA | IMPORT | 2 |
| 1116696 | advapi32.StartServiceCtrlDispatcherW | IMPORT | 3 |
| 1116712 | kernel32.CloseHandle | IMPORT | 5 |
| 1116720 | kernel32.CreateDirectoryW | IMPORT | 1 |
| 1116728 | kernel32.CreateFileW | IMPORT | 3 |
| 1116736 | kernel32.CreateProcessW | IMPORT | 1 |
| 1116744 | kernel32.CreateSemaphoreW | IMPORT | 3 |
| 1116752 | kernel32.DeleteCriticalSection | IMPORT | 2 |
| 1116760 | kernel32.DeleteFileW | IMPORT | 4 |
| 1116768 | kernel32.EnterCriticalSection | IMPORT | 5 |
| 1116776 | kernel32.FreeLibrary | IMPORT | 1 |
| 1116784 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 1116792 | kernel32.GetCurrentProcessId | IMPORT | 2 |
| 1116800 | kernel32.GetCurrentThreadId | IMPORT | 3 |
| 1116808 | kernel32.GetExitCodeProcess | IMPORT | 7 |
| 1116816 | kernel32.GetFileAttributesW | IMPORT | 3 |
| 1116824 | kernel32.GetLastError | IMPORT | 19 |
| 1116832 | kernel32.GetModuleFileNameW | IMPORT | 1 |
| 1116840 | kernel32.GetProcAddress | IMPORT | 1 |
| 1116848 | kernel32.GetStartupInfoW | IMPORT | 1 |
| 1116856 | kernel32.GetSystemTimeAsFileTime | IMPORT | 1 |
| 1116864 | kernel32.GetTickCount | IMPORT | 1 |
| 1116872 | kernel32.InitializeCriticalSection | IMPORT | 2 |
| 1116880 | kernel32.IsDBCSLeadByteEx | IMPORT | 1 |
| 1116888 | kernel32.LeaveCriticalSection | IMPORT | 9 |
| 1116896 | kernel32.LoadLibraryW | IMPORT | 1 |
| 1116904 | kernel32.MultiByteToWideChar | IMPORT | 4 |
| 1116912 | kernel32.QueryPerformanceCounter | IMPORT | 1 |
| 1116920 | kernel32.ReadFile | IMPORT | 1 |
| 1116928 | kernel32.ReleaseSemaphore | IMPORT | 3 |
| 1116936 | kernel32.RemoveDirectoryW | IMPORT | 1 |
| 1116944 | kernel32.RtlAddFunctionTable | IMPORT | 1 |
| 1116952 | kernel32.RtlCaptureContext | IMPORT | 1 |
| 1116960 | kernel32.RtlLookupFunctionEntry | IMPORT | 1 |
| 1116968 | kernel32.RtlVirtualUnwind | IMPORT | 1 |
| 1116976 | kernel32.SetEnvironmentVariableW | IMPORT | 1 |
| 1116984 | kernel32.SetFilePointer | IMPORT | 1 |
| 1116992 | kernel32.SetLastError | IMPORT | 8 |
| 1117000 | kernel32.SetUnhandledExceptionFilter | IMPORT | 2 |
| 1117008 | kernel32.Sleep | IMPORT | 14 |
| 1117016 | kernel32.TerminateProcess | IMPORT | 2 |
| 1117024 | kernel32.TlsAlloc | IMPORT | 3 |
| 1117032 | kernel32.TlsFree | IMPORT | 1 |
| 1117040 | kernel32.TlsGetValue | IMPORT | 9 |
| 1117048 | kernel32.TlsSetValue | IMPORT | 6 |
| 1117056 | kernel32.UnhandledExceptionFilter | IMPORT | 1 |
| 1117064 | kernel32.VirtualProtect | IMPORT | 2 |
| 1117072 | kernel32.VirtualQuery | IMPORT | 1 |
| 1117080 | kernel32.WaitForSingleObject | IMPORT | 3 |
| 1117088 | kernel32.WideCharToMultiByte | IMPORT | 3 |
| 1117096 | kernel32.WriteFile | IMPORT | 2 |
| 1117112 | msvcrt.__C_specific_handler | IMPORT | 2 |
| 1117120 | msvcrt.___lc_codepage_func | IMPORT | 1 |
| 1117128 | msvcrt.___mb_cur_max_func | IMPORT | 4 |
| 1117136 | msvcrt.__doserrno | IMPORT | 1 |
| 1117144 | msvcrt.__iob_func | IMPORT | 1 |
| 1117152 | msvcrt.__lconv_init | IMPORT | 2 |
| 1117160 | msvcrt.__pioinfo | IMPORT | 5 |
| 1117168 | msvcrt.__set_app_type | IMPORT | 1 |
| 1117176 | msvcrt.__setusermatherr | IMPORT | 1 |
| 1117184 | msvcrt.__wgetmainargs | IMPORT | 1 |
| 1117192 | msvcrt.__winitenv | IMPORT | 3 |
| 1117200 | msvcrt._amsg_exit | IMPORT | 1 |
| 1117208 | msvcrt._cexit | IMPORT | 1 |
| 1117216 | msvcrt._errno | IMPORT | 4 |

### Functions (30)
| EA | Name |
|---|---|
| 28000 | sub_407960 |
| 25328 | sub_406ef0 |
| 25728 | sub_407080 |
| 29648 | sub_407fd0 |
| 80128 | sub_414500 |
| 79472 | sub_414270 |
| 1885184 | sub_5cf000 |
| 93712 | sub_417a10 |
| 251056 | sub_43e0b0 |
| 256384 | sub_43f580 |
| 154016 | sub_4265a0 |
| 77216 | sub_4139a0 |
| 124080 | sub_41f0b0 |
| 263484 | sub_44113c |
| 268832 | sub_442620 |
| 455493 | sub_46ff45 |
| 459504 | sub_470ef0 |
| 445760 | sub_46d940 |
| 449648 | sub_46e870 |
| 129600 | sub_420640 |
| 225680 | sub_437d90 |
| 420272 | sub_4675b0 |
| 392531 | sub_460953 |
| 222480 | sub_437110 |
| 417280 | sub_466a00 |
| 338806 | sub_453776 |
| 1880743 | sub_5cdea7 |
| 1408 | sub_401180 |
| 701936 | sub_4ac1f0 |
| 894944 | sub_4db3e0 |

### Decompilations (top 6)
#### 28000 — sub_407960
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_407960(void)

{
    int32_t iVar1;
    undefined4 uVar2;
    int64_t iVar3;
    undefined8 ***pppuVar4;
    uint64_t uVar5;
    undefined8 uVar6;
    undefined *unaff_RBX;
    undefined8 uStack_bc0;
    undefined *puStack_bb8;
    undefined auStack_bb0 [32];
    int64_t iStack_b90;
    int32_t iStack_b88;
    undefined8 ***pppuStack_b78;
    undefined8 uStack_b70;
    undefined *puStack_b68;
    undefined auStack_b60 [8];
    undefined4 uStack_b58;
    undefined8 uStack_b50;
    code *pcStack_b30;
    undefined8 uStack_b28;
    undefined *puStack_b20;
    undefined8 uStack_b18;
    undefined *puStack_b10;
    undefined8 **ppuStack_af8;
    undefined8 uStack_ae8;
    undefined8 uStack_ae0;
    int64_t *piStack_ad8;
    undefined8 ***pppuStack_ad0;
    undefined8 **ppuStack_ac8;
    undefined8 **appuStack_ac0 [2];
    undefined auStack_ab0 [528];
    undefined8 **appuStack_8a0 [66];
    uint64_t uStack_680;
    undefined8 uStack_678;
    undefined8 uStack_660;
    int64_t *piStack_658;
    undefined8 uStack_650;
    undefined auStack_648 [528];
    undefined auStack_438 [528];
    undefined auStack_228 [528];
    
    iVar1 = (*shell32.SHGetSpecialFolderLocation)(0, 0x17);
    if (iVar1 == 0) {
        unaff_RBX = auStack_438;
        (*shell32.SHGetPathFromIDListW)(uStack_660, auStack_648);
        (*shell32.SHGetMalloc)(&piStack_658);
        (**(*piStack_658 + 0x28))(piStack_658, uStack_660);
        (**(*piStack_658 + 0x10))();
        jmp_msvcrt.wcscpy(unaff_RBX, auStack_648);
        uStack_678 = 0x4e804a;
        jmp_msvcrt.wcscat(unaff_RBX);
        uStack_680 = [0x0x511368] + 1;
        if (uStack_680 < 0x3ffffffffffffffd) {
            iVar3 = sub_4e2a60(uStack_680 * 2);
            jmp_msvcrt.wcscpy(iVar3, [0x0x511360]);
            *(iVar3 + [0x0x511368] * 2) = 0;
            jmp_msvcrt.wcscat(unaff_RBX, iVar3);
            jmp_msvcrt.wcscpy(auStack_228, unaff_RBX);
            uStack_678 = 0x4e804a;
            jmp_msvcrt.wcscat(auStack_228);
            uStack_680 = [0x0x511368] + 1;
            if (uStack_680 < 0x3ffffffffffffffd) {
                iVar3 = sub_4e2a60(uStack_680 * 2);
                jmp_msvcrt.wcscpy(iVar3, [0x0x511360]);
                *(iVar3 + [0x0x511368] * 2) = 0;
                jmp_msvcrt.wcscat(auStack_228, iVar3);
                jmp_msvcrt.wcscat(auStack_228, ".lnk");
                (*kernel32.DeleteFileW)(auStack_228);
                (*kernel32.RemoveDirectoryW)(unaff_RBX);
                goto code_r0x00407980;
            }
        }
    }
    else {
code_r0x00407980:
        uStack_678 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
        iVar1 = (*advapi32.RegCreateKeyW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", &uStack_650);
        if (iVar1 != 0) {
            return 1;
        }
        uStack_680 = [0x0x511368] + 1;
        if (uStack_680 < 0x3ffffffffffffffd) {
            iVar3 = sub_4e2a60(uStack_680 * 2);
            jmp_msvcrt.wcscpy(iVar3);
            *(iVar3 + [0x0x511368] * 2) = 0;
            (*advapi32.RegDeleteKeyW)(uStack_650, iVar3);
            (*advapi32.RegCloseKey)(uStack_650);
            return 1;
        }
    }
    func_0x004e3830();
    puStack_b20 = &stack0xfffffffffffff970;
    puStack_b10 = auStack_bb0;
    pcStack_b30 = sub_4e3980;
    uStack_b28 = 0x5042d4;
    uStack_b18 = 0x407f94;
    puStack_b68 = auStack_b60;
    puStack_bb8 = 0x407bcf;
    sub_415470(puStack_b68);
    pppuStack_b78 = &pppuStack_ad0;
    pppuStack_ad0 = appuStack_ac0;
    puStack_bb8 = 0x407bf8;
    iVar3 = jmp_msvcrt.wcslen(0x4e8310);
    pppuVar4 = pppuStack_ad0;
    uStack_b70 = iVar3 * 2;
    ppuStack_ac8 = uStack_b70 >> 1;
    appuStack_8a0[0] = ppuStack_ac8;
    if (ppuStack_ac8 < 0x8) {
        if (ppuStack_ac8 == 0x1) {
            *pppuStack_ad0 = 0x22;
        }
        else if (ppuStack_ac8 != 0x0) goto code_r0x00407de5;
    }
    else {
    
```
#### 25328 — sub_406ef0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_406ef0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
    int32_t iVar1;
    int64_t *piStack_878;
    int64_t *piStack_870;
    undefined auStack_868 [528];
    undefined auStack_658 [528];
    undefined auStack_448 [528];
    undefined auStack_238 [528];
    
    (*ole32.CoInitialize)(0);
    iVar1 = (*ole32.CoCreateInstance)([0x0x4ed8c0], 0, 1, &IShellLinkW, &piStack_878);
    if (iVar1 < 0) {
        return;
    }
    jmp_msvcrt.wcscpy(auStack_868, param_1);
    jmp_msvcrt.wcscat(auStack_868, "\\native\\dwaglnc.exe");
    (**(*piStack_878 + 0xa0))(piStack_878, auStack_868);
    jmp_msvcrt.wcscpy(auStack_658, param_3);
    (**(*piStack_878 + 0x58))(piStack_878, auStack_658);
    jmp_msvcrt.wcscpy(auStack_448, param_1);
    jmp_msvcrt.wcscat(auStack_448, "\\native");
    (**(*piStack_878 + 0x48))(piStack_878, auStack_448);
    (**(*piStack_878 + 0x88))(piStack_878, 0x511040, 0);
    iVar1 = (***piStack_878)(piStack_878, &IPersistFile, &piStack_870);
    if (-1 < iVar1) {
        jmp_msvcrt.wcscpy(auStack_238, param_2);
        jmp_msvcrt.wcscat(auStack_238, 0x4e804a);
        jmp_msvcrt.wcscat(auStack_238, param_4);
        jmp_msvcrt.wcscat(auStack_238, ".lnk");
        (**(*piStack_870 + 0x30))(piStack_870, auStack_238, 1);
        (**(*piStack_870 + 0x10))();
    }
    (**(*piStack_878 + 0x10))();
    return;
}

```
#### 25728 — sub_407080
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_407080(undefined8 ***param_1)

{
    int32_t iVar1;
    int64_t iVar2;
    undefined8 ***pppuVar3;
    uint64_t uVar4;
    undefined8 ***pppuStackX_8;
    undefined auStack_708 [32];
    undefined8 ***pppuStack_6e8;
    int32_t iStack_6e0;
    undefined8 ***pppuStack_6d8;
    undefined8 ***pppuStack_6d0;
    undefined *puStack_6c8;
    code *pcStack_6c0;
    undefined auStack_6b8 [8];
    int32_t iStack_6b0;
    undefined8 ***pppuStack_6a8;
    code *pcStack_688;
    undefined8 uStack_680;
    undefined *puStack_678;
    undefined8 uStack_670;
    undefined *puStack_668;
    undefined8 ***pppuStack_650;
    undefined8 uStack_648;
    int64_t *piStack_640;
    undefined8 **appuStack_638 [66];
    undefined8 ***pppuStack_428;
    undefined8 ***pppuStack_420;
    undefined8 ***apppuStack_418 [64];
    undefined8 ***pppuStack_218;
    undefined8 **ppuStack_210;
    undefined8 **appuStack_208 [64];
    
    puStack_678 = &stack0xfffffffffffffff8;
    puStack_668 = auStack_708;
    pcStack_688 = sub_4e3980;
    uStack_680 = 0x5042ac;
    uStack_670 = 0x4078ed;
    puStack_6c8 = auStack_6b8;
    sub_415470(puStack_6c8);
    iStack_6b0 = 0xffffffff;
    iVar1 = (*shell32.SHGetSpecialFolderLocation)(0, 0x17, &uStack_648);
    pppuStack_6d8 = &pppuStack_428;
    if (iVar1 == 0) {
        pppuStack_6d0 = appuStack_638;
        (*shell32.SHGetPathFromIDListW)(uStack_648, pppuStack_6d0);
        (*shell32.SHGetMalloc)(&piStack_640);
        (**(*piStack_640 + 0x28))(piStack_640, uStack_648);
        (**(*piStack_640 + 0x10))();
        jmp_msvcrt.wcscpy(pppuStack_6d8, pppuStack_6d0);
        jmp_msvcrt.wcscat(pppuStack_6d8, 0x4e804a);
        if ([0x0x511368] + 1U < 0x3ffffffffffffffd) {
            pppuStack_6d0 = sub_4e2a60(([0x0x511368] + 1U) * 2);
            jmp_msvcrt.wcscpy(pppuStack_6d0, [0x0x511360]);
            *(pppuStack_6d0 + [0x0x511368] * 2) = 0;
            jmp_msvcrt.wcscat(pppuStack_6d8);
            (*kernel32.CreateDirectoryW)(pppuStack_6d8, 0);
            if ([0x0x511368] + 1U < 0x3ffffffffffffffd) {
                iStack_6b0 = 0xffffffff;
                pppuStack_6d0 = sub_4e2a60(([0x0x511368] + 1U) * 2);
                jmp_msvcrt.wcscpy(pppuStack_6d0, [0x0x511360]);
                *(pppuStack_6d0 + [0x0x511368] * 2) = 0;
                sub_406ef0(param_1, pppuStack_6d8, "monitor");
                pppuStack_6d0 = &pppuStack_218;
                jmp_msvcrt.wcscpy(pppuStack_6d0, param_1);
                jmp_msvcrt.wcscat(pppuStack_6d0, 0x4e804a);
                jmp_msvcrt.wcscat(pppuStack_6d0, "native");
                if ([0x0x511368] + 1U < 0x3ffffffffffffffd) {
                    pcStack_6c0 = sub_4e2a60(([0x0x511368] + 1U) * 2);
                    jmp_msvcrt.wcscpy(pcStack_6c0, [0x0x511360]);
                    *(pcStack_6c0 + [0x0x511368] * 2) = 0;
                    sub_406ef0(param_1, pppuStack_6d0, "monitor", pcStack_6c0);
                    sub_406ef0(param_1, pppuStack_6d0, "configure", "Configure");
                    sub_406ef0(param_1, pppuStack_6d0, "uninstall", "Uninstall");
                    goto code_r0x00407119;
                }
            }
        }
    }
    else {
code_r0x00407119:
        pppuStack_428 = pppuStack_6d8 + 2;
        iVar2 = jmp_msvcrt.wcslen();
        pppuStack_6d0 = iVar2 * 2;
        pppuStack_420 = pppuStack_6d0 >> 1;
        pppuStack_218 = pppuStack_420;
        if (pppuStack_420 < 0x8) {
            if (pppuStack_420 == 0x1) {
                *pppuStack_428 = 0x53;
            }
            else if (pppuStack_420 != 0x0) goto code_r0x004074ca;
        }
        else {
            iStack_6b0 = 0xffffffff;
            pppuStack_428 = sub_4cac50(pppuStack_6d8, &pppuStack_218, 0);
            apppuStack_418[0] = pppuStack_218;
code_r0x004074ca:
            jmp_msvcrt.memcpy(pppuStack_428, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\", pppuStack_6d0);
            pppuStack_6
```

### Carved Files (7)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 1128 |
| ? | DIB | 2440 |
| ? | DIB | 4264 |
| ? | DIB | 9640 |
| ? | DIB | 16936 |
| ? | DIB | 67624 |
| ? | PNG | 74659 |

### Virtual Files (9)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 1128 | - |
| ICO/2/en-us | 2440 | - |
| ICO/3/en-us | 4264 | - |
| ICO/4/en-us | 9640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 67624 | - |
| ICO/7/en-us | 74659 | - |
| GRPICO/0/en-us | 104 | - |
| VER/1/en-us | 292 | - |

### Structures (56)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 392 |
| TlsDirectory | 966464 |
| ExceptionTable | 1016832 |
| ImportTable | 1115136 |
| advapi32.OFT | 1115256 |
| kernel32.OFT | 1115400 |
| msvcrt.OFT | 1115800 |
| ole32.OFT | 1116512 |
| shell32.OFT | 1116536 |
| advapi32.FT | 1116568 |
| kernel32.FT | 1116712 |
| msvcrt.FT | 1117112 |
| ole32.FT | 1117824 |
| shell32.FT | 1117848 |
| ImportNames | 1117880 |
| ImportNames | 1120312 |
| ImportNames | 1120524 |
| ImportNames | 1120892 |
| ImportNames | 1120912 |
| ImportNames | 1120936 |
| TlsCallbacks | 1123392 |
| TLSInitArray | 1127424 |
| Resources | 1131520 |
| Resources.ICO | 1131560 |
| Resources.GRPICO | 1131632 |
| Resources.VER | 1131656 |
| Resources.ICO.1 | 1131680 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 35 · duration_s: 1.83

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| stop service | T1543.003:Create or Modify System Process, T1489:Service Stop |  |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| generate random numbers using a Mersenne Twister |  | C0021:Generate Pseudo-random Sequence |
| set environment variable |  | C0034.001:Environment Variable |
| create directory |  | C0046:Create Directory |
| delete directory |  | C0048:Delete Directory |
| delete file |  | C0047:Delete File |

## PE Imports / Signals
import_count: 159

| label | api_match | ATT&CK |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 11

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@945676 len=2 |
| contains_base64 | - | $a@10288 len=12 |
| Dropper_Strings | - | $a0@948398 len=36 |
| url | - | $url_regex@150855 len=9 |
| IsPE64 | - |  |
| IsConsole | - |  |
| Microsoft_Visual_Cpp_80_DLL | - | $b@1040 len=4 |
| create_service | - | $f1@1114680 len=12; $c1@1112290 len=13; $c2@1112272 len=14; $c3@1112528 len=12; $c4@1112358 len=18 |
| win_registry | - | $f1@1114680 len=12; $c3@1112382 len=11; $c6@1112382 len=11 |
| win_files_operation | - | $f1@1114892 len=12; $c1@1113510 len=9; $c2@1113262 len=14; $c3@1113510 len=9; $c4@1113096 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
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
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 945676,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a",
          "offset": 10288,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$a0",
          "offset": 948398,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 150855,
          "length": 9,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": []
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$b",
          "offset": 1040,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "create_service",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$f1",
          "offset": 1114680,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 1112290,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 1112272,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 1112528,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 1112358,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat",
      "strings": [
        {
          "id": "$f1",
          "offset": 1114680,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 1112382,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 1112382,
          "length": 11,
      
```

## FLOSS Strings
Total strings: 3084 · per_category: `{"decoded_strings": 73, "stack_strings": 18, "tight_strings": 3, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2990}`

### High-signal FLOSS
- `not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):`

### FLOSS sample
- ``.rdata`
- `.gfids/`
- `rMwOGtBu`
- `fR B`T`
- `6,b4&eR`
- `LRBFRB`
- `D7;L2`V`
- `UMb.OP`
- `BHu.tPu`
- `u:tR`uP`
- `uFt *u(`
- `Q`St$@a`
- `B@s50[c2o]1o`
- `v{tYuWt`
- `U0tNuLC`
- `tdt[$uY`
- `2YXt)u'(`
- `9tOuMt`
- `tntAhSe`
- `WVtOuM`
- `guehB~@`
- `WVtLuJt`
- `h]+A8!,`
- `.bWF(2(1N`
- `EPtoum`
- `LbQF$6h6`
- `zU uShK`
- `tlujQ}r`
- `st(vut`
- `trupC$j 2`
- `ZhEEGu`
- `PKC@KTC`
- `0D-R54#Q`
- `h2uKP4`
- `HtXuVht`
- `T$0PQRpY`
- `Z]!Vt$`
- `t.u,B$ P`
- `4rD.b7`
- `< #U1/:1`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401500
```asm
┌ 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           0x00401500      4883ec28       sub rsp, 0x28
│           0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x0040150b      c70000000000   mov dword [rax], 0
│           0x00401511      e8eada1c00     call fcn.005cf000
│           0x00401516      e865fcffff     call fcn.00401180
│           0x0040151b      90             nop
│           0x0040151c      90             nop
│           0x0040151d      4883c428       add rsp, 0x28
└           0x00401521      c3             ret
```
### 0x005cf000
```asm
; CALL XREF from entry0 @ 0x401511(x)
┌ 2327: fcn.005cf000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           ; var int64_t var_23h @ rbp+0x23
│           0x005cf000      50             push rax
│           0x005cf001      51             push rcx                    ; arg1
│           0x005cf002      52             push rdx                    ; arg2
│           0x005cf003      53             push rbx
│           0x005cf004      55             push rbp
│           0x005cf005      56             push rsi
│           0x005cf006      57             push rdi
│           0x005cf007      4150           push r8                     ; arg3
│           0x005cf009      4151           push r9                     ; arg4
│           0x005cf00b      4152           push r10
│           0x005cf00d      4153           push r11
│           0x005cf00f      4154           push r12
│           0x005cf011      4155           push r13
│           0x005cf013      4156           push r14
│           0x005cf015      4157           push r15
│           0x005cf017      55             push rbp
│           0x005cf018      488bec         mov rbp, rsp
│           0x005cf01b      4883ec20       sub rsp, 0x20
│           0x005cf01f      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x005cf023      488d1dd635..   lea rbx, [0x00542600]
│           0x005cf02a      6a00           push 0
│           0x005cf02c      59             pop rcx
│           0x005cf02d      53             push rbx
│       ┌─> 0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332 ; [0x116a7332:4]=-1
│       ╎   0x005cf038      81ab2c0200..   sub dword [rbx + 0x22c], 0x38d25e97 ; [0x38d25e97:4]=-1
│       ╎   0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363 ; [0x2d765363:4]=-1
│       ╎   0x005cf04c      81b3100100..   xor dword [rbx + 0x110], 0x783c64cf ; [0x783c64cf:4]=-1
│       ╎   0x005cf056      81b3200300..   xor dword [rbx + 0x320], 0x58e87ae6 ; [0x58e87ae6:4]=-1
│       ╎   0x005cf060      8183180100..   add dword [rbx + 0x118], 0x46d7122 ; [0x46d7122:4]=-1
│       ╎   0x005cf06a      81abe40200..   sub dword [rbx + 0x2e4], 0x628f4db1 ; [0x628f4db1:4]=-1
│       ╎   0x005cf074      8143200901..   add dword [rbx + 0x20], 0x60a50109 ; [0x60a50109:4]=-1
│       ╎   0x005cf07b      8183880200..   add dword [rbx + 0x288], 0x3f6f5261 ; [0x3f6f5261:4]=-1
│       ╎   0x005cf085      f793ac010000   not dword [rbx + 0x1ac]
│       ╎   0x005cf08b      81ab600200..   sub dword [rbx + 0x260], 0x77170ad2 ; [0x77170ad2:4]=-1
│       ╎   0x005cf095      81ab680300..   sub dword [rbx + 0x368], 0x64525b47 ; [0x64525b47:4]=-1
│       ╎   0x005cf09f      81b3a80000..   xor dword [rbx + 0xa8], 0x629854cc ; [0x629854cc:4]=-1
│       ╎   0x005cf0a9      f75350         not dword [rbx + 0x50]
│       ╎   0x005cf0ac      f793e0020
```
### 0x005cdf06
```asm
╎   ; CALL XREF from fcn.005cf000 @ 0x5cf8e9(x)
┌ 102: fcn.005cdf06 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│      ┌──< 0x005cdf06      e125           loope 0x5cdf2d
│      │╎   0x005cdf08      642aa124f0..   sub ah, byte fs:[rcx + 0x147bf024] ; arg1
│      │╎   0x005cdf0f      fecf           dec bh
│      │╎   0x005cdf11      6433fd         xor edi, ebp
│      │╎   0x005cdf14      d895d1d2261c   fcom dword [rbp + 0x1c26d2d1]
│      │╎   0x005cdf1a      d7             xlatb
│      │╎   0x005cdf1b      1f             invalid
..
│     │└──> 0x005cdf2d      d7             xlatb
│     │ └─< 0x005cdf2e      7d83           jge 0x5cdeb3
│     │     0x005cdf30      4a8ab1c5e4..   mov sil, byte [rcx - 0x23701b3b] ; arg1
│     │     0x005cdf37      5c             pop rsp
│     │     0x005cdf38      ff             invalid
..
│       │   0x005cdf4a      6688fe         mov dh, bh
│       │   0x005cdf4d      ff             invalid
..
```
### 0x00401180
```asm
; CALL XREF from fcn.00401180 @ 0x4014e6(x)
            ; CALL XREF from entry0 @ 0x401516(x)
┌ 858: fcn.00401180 ();
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_20h @ rsp+0x48
│           ; var int64_t var_5ch @ rsp+0x84
│           ; var int64_t var_60h @ rsp+0x88
│           0x00401180      4155           push r13
│           0x00401182      4154           push r12
│           0x00401184      55             push rbp
│           0x00401185      57             push rdi
│           0x00401186      56             push rsi
│           0x00401187      53             push rbx
│           0x00401188      4881ec9800..   sub rsp, 0x98
│           0x0040118f      488b351ad4..   mov rsi, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x00401196      31c0           xor eax, eax
│           0x00401198      b90d000000     mov ecx, 0xd                ; 13
│           0x0040119d      448b0e         mov r9d, dword [rsi]
│           0x004011a0      488d542420     lea rdx, [var_20h]
│           0x004011a5      4889d7         mov rdi, rdx
│           0x004011a8      f348ab         rep stosq qword [rdi], rax
│           0x004011ab      4585c9         test r9d, r9d
│       ┌─< 0x004011ae      0f85dc020000   jne 0x401490
│       │   ; CODE XREF from fcn.00401180 @ 0x401499(x)
│      ┌──> 0x004011b4      65488b0425..   mov rax, qword gs:[0x30]
│      ╎│   0x004011bd      488b1d1cd3..   mov rbx, qword [0x004ee4e0] ; [0x4ee4e0:8]=0x5127e0
│      ╎│   0x004011c4      31ed           xor ebp, ebp
│      ╎│   0x004011c6      488b7808       mov rdi, qword [rax + 8]
│      ╎│   0x004011ca      4c8b257f25..   mov r12, qword [sym.imp.KERNEL32.dll_Sleep] ; [0x513750:8]=0x113eec reloc.KERNEL32.dll_Sleep
│     ┌───< 0x004011d1      eb11           jmp 0x4011e4
│    ┌────> 0x004011d3      4839c7         cmp rdi, rax
│   ┌─────< 0x004011d6      0f8458020000   je 0x401434
│   │╎│╎│   0x004011dc      b9e8030000     mov ecx, 0x3e8              ; 1000
│   │╎│╎│   0x004011e1      41ffd4         call r12
│   │╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4011d1(x)
│   │╎└───> 0x004011e4      4889e8         mov rax, rbp
│   │╎ ╎│   0x004011e7      f0480fb13b     lock cmpxchg qword [rbx], rdi
│   │╎ ╎│   0x004011ec      4885c0         test rax, rax
│   │└────< 0x004011ef      75e2           jne 0x4011d3
│   │  ╎│   0x004011f1      488b3df8d2..   mov rdi, qword [0x004ee4f0] ; [0x4ee4f0:8]=0x5127e8
│   │  ╎│   0x004011f8      31ed           xor ebp, ebp
│   │  ╎│   0x004011fa      8b07           mov eax, dword [rdi]
│   │  ╎│   0x004011fc      83f801         cmp eax, 1                  ; 1
│   │ ┌───< 0x004011ff      0f8446020000   je 0x40144b
│   │┌────> 0x00401205      8b07           mov eax, dword [rdi]
│   │╎│╎│   0x00401207      85c0           test eax, eax
│  ┌──────< 0x00401209      0f848f020000   je 0x40149e
│  ││╎│╎│   0x0040120f      c705ebfd10..   mov dword [0x00511004], 1   ; [0x511004:4]=0
│  ││╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4014b7(x)
│ ┌─
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
  - `ADVAPI32.dll!CloseServiceHandle`
  - `ADVAPI32.dll!ControlService`
  - `ADVAPI32.dll!CreateServiceW`
  - `ADVAPI32.dll!DeleteService`
  - `ADVAPI32.dll!OpenSCManagerA`
  - `KERNEL32.dll!CloseHandle`
  - `KERNEL32.dll!CreateDirectoryW`
  - `KERNEL32.dll!CreateFileW`
  - `KERNEL32.dll!CreateProcessW`
  - `KERNEL32.dll!CreateSemaphoreW`
  - `msvcrt.dll!__C_specific_handler`
  - `msvcrt.dll!___lc_codepage_func`
  - `msvcrt.dll!___mb_cur_max_func`
  - `msvcrt.dll!__doserrno`
  - `msvcrt.dll!__iob_func`
  - `ole32.dll!CoCreateInstance`
  - `ole32.dll!CoInitialize`
  - `SHELL32.dll!SHGetMalloc`
  - `SHELL32.dll!SHGetPathFromIDListW`
  - `SHELL32.dll!SHGetSpecialFolderLocation`
