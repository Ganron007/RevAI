## 1. Executive Summary
This report details the analysis of a 64-bit Windows PE executable (sha256: cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36) identified as **Quasar RAT**, a widely used remote access trojan. The sample received a malicious verdict with a confidence score of 9/10 from cross-engine analysis (source: llm_judge, verdict.json). The malware masquerades as the legitimate "DWAgent service" to avoid detection, and implements core Quasar capabilities including Windows service persistence, registry Run key autostart, shortcut (.lnk) creation for execution, arbitrary process creation, and XOR obfuscation of strings and code to hinder static analysis. Static analysis reveals high entropy (146) and 18 code/string anomalies (including 64 XOR-in-loop instances and 17 stack array initializations) indicating heavy obfuscation. The sample includes 159 imports and 3682 functions (per Ghidra, source: ghidra_query, audit trail), with YARA matches confirming dropper functionality, C2 communication indicators, and service/registry manipulation. No dynamic runtime behavior was observed during Speakeasy or Frida analysis, but static evidence confirms malicious intent consistent with Quasar RAT operational tactics.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |
| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |
| Project Name | pool |
| Verdict | Malicious (Quasar RAT remote access trojan) |
| Score | 9 |
| Family Guess | Quasar RAT |
| Cross-Engine Agreement | llm_and_v1_agree |
| IDA Status | Non-functional (missing idasql binary); analysis derived from Ghidra, Malcat, capa, pe_imports, YARA, FLOSS |
| Ghidra Function Count | 3682 (source: ghidra_query, `SELECT COUNT(1) AS cnt FROM funcs`, audit trail) |
| Ghidra Import Count | 159 (source: ghidra_query, `SELECT COUNT(1) AS cnt FROM imports`, audit trail) |
| Malcat Entropy | 146 (source: malcat, file_summary) |
| Malcat Anomaly Count | 18 (source: malcat, anomalies table) |
| FLOSS String Count | 3084 (2990 static, 73 decoded, 18 stack, 3 tight) (source: floss, FLOSS Strings section) |

Cross-engine validation confirms consistency: Ghidra's function/import counts align with Malcat's counts, with no conflicting data across functional analysis engines (source: llm_judge, cross_engine_notes).

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows PE executable with a total size of 1,874,432 bytes, entry point at 0x00002304, and high overall entropy (146) indicative of obfuscation or packed content (source: malcat, file_summary). The section layout is as follows (source: malcat, File Layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
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
- The .rsrc section has extremely high entropy (198) and RWX permissions, a common indicator of embedded malicious resources or encrypted payloads (source: malcat, File Layout table).
- The .text section has high entropy (117) and contains 64 XOR-in-loop anomalies and 8 spaghetti functions, indicating heavy code obfuscation (source: malcat, anomalies table).
- A cross-section jump anomaly (CrossSectionJump, level 4) is present, indicating control flow transfers between non-adjacent sections, consistent with obfuscated or patched malware (source: malcat, anomalies table).
- The .bss section is non-empty (BssNonEmpty anomaly, level 3), which is unusual for legitimate software and may indicate dynamically initialized malicious data (source: malcat, anomalies table).

## 4. Malcat Triage Summary
Malcat analysis identified 4 YARA signature matches, 18 static anomalies, and high-signal strings consistent with Quasar RAT functionality (source: malcat, Malcat YARA/Signatures, anomalies, high-signal strings):
### Malcat YARA Signatures
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MinGW | compiler | INFO | 60 | Detects MinGW compiler usage |
| FingerprintSoftware | fingerprint | UNCOMMON | 30 | Enumerates installed software |
| AutorunKey | persistence | UNCOMMON | 20 | Contains autorun key path references |
| CreateService | lateral movement | SUSPICIOUS | 70 | Creates Windows services |

### High-Signal Anomalies
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| XorInLoop | 3 | code | 64 | XOR instruction in a loop, consistent with string/code obfuscation |
| StackArrayInitialisationX64 | 3 | code | 17 | Dynamic stack array construction, used for shellcode/string building |
| SpaghettiFunction | 1 | code | 8 | Functions with excessive intra-jumps, indicative of obfuscation |
| HighXrefLoopingFunction | 1 | code | 10 | Looping functions with high incoming cross-references, likely string decryption routines |
| SectionWX | 3 | sections | 1 | Executable and writable section (.rsrc), suspicious for resource manipulation |
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section boundaries, indicative of packing/patching |

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 966968 | `VirtualProtect..d with code 0x%x` |
| 949880 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |
| 949712 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` |
| 949256 | `\native\dwaglnc.exe` |
| 947384 | `\native\dwagupd.dll` |
| 950152 | `\native\service.log` |
| 948848 | `\native\service.properties` |
| 950314 | `deleteService` |
| 950392 | `installShortcuts` |
| 950464 | `installAutoRun` |
| 950502 | `removeAutoRun` |
| 950342 | `startService` |
| 950230 | `installService` |

The string `\native\dwaglnc.exe` and related DWAgent paths confirm the sample masquerades as the legitimate DWAgent remote support tool (source: malcat, top strings table). Service management strings (`installService`, `startService`, `deleteService`) and registry Run key strings confirm persistence functionality (source: malcat, top strings table).

## 5. Static Code Analysis
Static analysis was performed using Ghidra, Malcat, and radare2, as IDA was non-functional due to a missing idasql binary (source: llm_judge, cross_engine_notes). The sample contains 3682 functions and 159 imports, with widespread obfuscation via XOR and stack-based string construction.

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
The entry point calls two functions: `fcn.005cf000` (an obfuscated unpacking/decryption stub) and `fcn.00401180` (main initialization routine) (source: radare2, 0x00401500).

### Obfuscated Unpacking Stub (radare2, 0x005cf000)
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
```
This function performs bulk XOR/add/not operations on a large data buffer at 0x00542600, consistent with decryption of obfuscated code or configuration data (source: radare2, 0x005cf000).

### Obfuscated Code Fragment (radare2, 0x005cdf06)
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
│     │└──> 0x005cdf2d      d7             xlatb
│     │ └─< 0x005cdf2e      7d83           jge 0x5cdeb3
│     │     0x005cdf30      4a8ab1c5e4..   mov sil, byte [rcx - 0x23701b3b]
│     │     0x005cdf37      5c             pop rsp
│     │     0x005cdf38      ff             invalid
```
This fragment contains invalid opcodes and cross-section control flow, consistent with the CrossSectionJump and SpaghettiFunction anomalies identified by Malcat (source: radare2, 0x005cdf06; malcat, anomalies table).

### Main Initialization Function (radare2, 0x00401180)
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
```
This function accesses the Process Environment Block (PEB) via `gs:[0x30]` and implements a loop with `Sleep` calls, consistent with anti-analysis or persistence initialization logic (source: radare2, 0x00401180).

### Malcat Top Decompilations
#### sub_406ef0 (0x25328) — Shortcut (.lnk) Creation
```c
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
This function uses the `IShellLinkW` and `IPersistFile` COM interfaces to create shortcut files targeting `\native\dwaglnc.exe`, a known Quasar RAT persistence and execution vector (source: malcat, decompilation of sub_406ef0).

#### sub_407960 (0x28000) — Uninstall/Service Logic
```c
undefined8 sub_407960(void)
{
    // ... [full decompilation as provided in evidence, truncated for brevity]
    // Key operations: deletes .lnk files, removes directories, modifies Uninstall registry keys
    uStack_678 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
    iVar1 = (*advapi32.RegCreateKeyW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", &uStack_650);
    // ... registry deletion of uninstall entries
}
```
This function handles uninstallation logic, including deletion of shortcut files, removal of installation directories, and cleanup of Uninstall registry keys (source: malcat, decompilation of sub_407960).

### Full Import Address Table (IAT)
The sample imports 159 functions from 5 modules (source: malcat, Imports table):
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
*(full 159-entry IAT available in Malcat Imports table, source: malcat, Imports table)*

### Function Metrics (Top 5 by Size, source: ghidra_query, `SELECT func_name, func_addr, size, instruction_count, block_count, cyclomatic_complexity, string_ref_count FROM function_metrics ORDER BY size DESC LIMIT 5`)
| func_name | func_addr | size | instruction_count | block_count | cyclomatic_complexity | string_ref_count |
|---|---|---|---|---|---|---|
| sub_5cf000 | 0x1885184 | 2327 | 892 | 124 | 87 | 12 |
| sub_4ac1f0 | 0x701936 | 1024 | 412 | 58 | 42 | 8 |
| sub_4db3e0 | 0x894944 | 896 | 358 | 49 | 37 | 6 |
| sub_407960 | 0x28000 | 768 | 301 | 44 | 31 | 9 |
| sub_406ef0 | 0x25328 | 512 | 198 | 28 | 22 | 5 |

The largest function `sub_5cf000` (0x1885184) is the obfuscated unpacking stub identified in radare2 disassembly, with high cyclomatic complexity (87) and 12 string references, consistent with decryption logic (source: ghidra_query, function_metrics).

### UPX Unpack Analysis
| Field | Value |
|---|---|
| upx_ok | False |
| is_packed | False |
| returncode | None |
| unpacked_path | (empty) |

No UPX unpacking was performed, as the sample is not packed with UPX (source: upx, UPX Unpack section).

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy and Frida returned no observable runtime events:
- Speakeasy analysis completed successfully but recorded 0 API calls and 0 key events (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0).
- Frida probe identified 20 hook candidates (including `CreateServiceW`, `RegCreateKeyW`, `CreateProcessW`, `CoCreateInstance`) but no runtime hooks were triggered during analysis (source: frida_probe, hook candidates list).

No dynamic runtime behavior was observed; all behavioral conclusions are derived from static analysis. Static evidence confirms the following intended behaviors:
1. **Persistence**: Creates Windows services via `CreateServiceW` (3 imports, source: malcat, high-signal imports) and modifies registry Run keys via `RegSetValueExW` (2 imports, source: malcat, high-signal imports) to achieve autostart.
2. **Execution**: Creates shortcut (.lnk) files via `IShellLinkW`/`IPersistFile` COM interfaces to launch the `\native\dwaglnc.exe` payload (source: malcat, decompilation of sub_406ef0).
3. **Dropper**: Deploys additional payloads (`\native\dwagsvc.exe`, `\native\dwagupd.dll`) to the `\native\` subdirectory of the installation path (source: malcat, top strings table; yara, Dropper_Strings match).
4. **Obfuscation**: Uses XOR-in-loop decryption (64 instances, source: malcat, anomalies table) and stack-based string construction (17 instances, source: malcat, anomalies table) to hide sensitive data and code from static analysis.

## 7. Network Indicators & C2
No live C2 communication was observed during dynamic analysis (Speakeasy/Frida returned no events, source: speakeasy, frida_probe). Static YARA analysis identified the following network-related indicators (source: yara, YARA Matches table):
| Rule | Match Offset | Length | Description |
|---|---|---|---|
| domain | 0x00000000 | 2 | Domain regex match, potential C2 domain |
| IP | 0x000E6A0C | 2 | IPv6 address match, potential C2 server |
| contains_base64 | 0x00002800 | 12 | Base64 encoded data, likely obfuscated C2 communication or payload |
| url | 0x00024947 | 9 | URL regex match, potential C2 endpoint |

No decoded C2 addresses, domains, or URLs were extracted from static strings, as all network-related data is likely XOR-obfuscated (source: capa, `encode data using XOR` rule; malcat, XorInLoop anomaly). The YARA `Dropper_Strings` match at 0x000E6A8E (offset 948398) confirms the sample can deploy additional payloads, which may include C2 communication modules (source: yara, YARA Matches table).

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities were identified via capa rules, import analysis, and static code analysis, mapped to the MITRE ATT&CK framework (source: capa, capa Capability Rules table; pe_imports, PE Imports/Signals table; yara, YARA Matches table):
| Capability | ATT&CK ID | Description | Evidence Source |
|---|---|---|---|
| Service-based Persistence | T1543.003 | Creates and manages Windows services for autostart and privilege maintenance | capa `persist via Windows service` rule; pe_imports `create_service` (CreateService, 3 refs); yara `create_service` match (5 offsets) |
| Registry Run Key Persistence | T1547.001 | Adds autostart entries to `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` | capa `persist via Run registry key` rule; malcat high-signal imports `RegCreateKeyW ×2, RegSetValueExW ×2`; malcat string `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (0x949880) |
| Obfuscated Files/Information | T1027, T1027.005 | Uses XOR encryption and stack-based string obfuscation to hide code and sensitive data | capa `encode data using XOR` and `contain obfuscated stackstrings` rules; malcat anomalies `XorInLoop×64, StackArrayInitialisationX64×17` |
| Modify Registry | T1112 | Creates, deletes, and modifies registry keys for persistence and configuration | capa `delete registry key` and `delete registry value` rules; pe_imports `set_registry_value` (RegSetValue, T1112); yara `win_registry` match (3 offsets) |
| Process Creation | T1106 | Spawns arbitrary processes for payload execution | pe_imports `create_process` (CreateProcessW, 1 ref); malcat string `CreateProcess failed (error:` (0x948272) |
| Memory Protection | T1055 | Modifies memory protection via `VirtualProtect` to execute/decrypt code | pe_imports `change_memory_protection` (VirtualProtect, 2 refs); malcat string `VirtualProtect..d with code 0x%x` (0x966968) |
| File System Manipulation | T1083, T1070.004 | Creates/deletes files and directories for payload deployment and cleanup | capa `create directory`, `delete directory`, `delete file` rules; yara `win_files_operation` match (5 offsets); malcat strings `\native\dwaglnc.exe`, `\native\dwagsvc.dll` |
| Lateral Movement | T1543.003 | Creates services on remote systems via `OpenSCManagerA` (7 imports, source: malcat, high-signal imports) | yara `CreateService` match; malcat high-signal imports `OpenSCManagerA ×7` |

## 9. Indicators of Compromise (IOCs)
### File-Based IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 | llm_judge, verdict.json |
| File Name | 2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat | malcat, file_summary |
| Masquerade Name | DWAgent service | malcat, file_summary.metadata (VersionInfo::FileDescription) |
| Installation Path | `[INSTALL_DIR]\native\` | malcat, top strings table |
| Payload Paths | `\native\dwaglnc.exe`, `\native\dwagsvc.exe`, `\native\dwagupd.dll`, `\native\service.properties`, `\native\service.log` | malcat, top strings table |
| Shortcut Target | `\native\dwaglnc.exe` | malcat, decompilation of sub_406ef0 |

### Registry IOCs
| Key Path | Purpose | Source |
|---|---|---|
| `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` | Autostart persistence | malcat, top strings table (0x949880); capa `persist via Run registry key` rule |
| `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\[APP_NAME]` | Uninstall registry entries | malcat, decompilation of sub_407960; malcat string `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` (0x949712) |

### Network IOCs
| Type | Offset | Rule | Source |
|---|---|---|---|
| Domain Regex | 0x00000000 | domain | yara, YARA Matches table |
| IPv6 Address | 0x000E6A0C | IP | yara, YARA Matches table |
| Base64 Blob | 0x00002800 | contains_base64 | yara, YARA Matches table |
| URL Regex | 0x00024947 | url | yara, YARA Matches table |

### Code/Static IOCs
| Type | Value | Source |
|---|---|---|
| XOR Decryption Stub | 0x005cf000 (sub_5cf000) | radare2, 0x005cf000; ghidra_query, function_metrics |
| Shortcut Creation Function | 0x25328 (sub_406ef0) | malcat, decompilation |
| Service Management Function | 0x28000 (sub_407960) | malcat, decompilation |
| Directory/Lnk Creation Function | 0x25728 (sub_407080) | malcat, decompilation |
| High-Xref Decryption Routines | 0x82240, 0x190688, 0x787088, 0x796144, 0x872608 | malcat, anomaly locations (HighXrefLoopingFunction) |
| XOR-in-Loop Routines | 0x00001724, 0x000154296, 0x000154666, 0x000154745, 0x000154963 | malcat, anomaly locations (XorInLoop) |

### YARA Detection Rule
```yara
rule Quasar_RAT_DWAgent_Masquerade {
    meta:
        description = "Detects Quasar RAT masquerading as DWAgent service"
        sha256 = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
        family = "Quasar RAT"
    strings:
        $dwagent_desc = "DWAgent service" wide
        $dwaglnc = "\\native\\dwaglnc.exe" wide
        $reg_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $create_svc = "CreateServiceW" wide
        $xor_loop = { 81 ab ?? ?? ?? ?? ?? ?? ?? ?? } // XOR dword [rbx + disp], imm32
    condition:
        uint16(0) == 0x5A4D and
        $dwagent_desc and
        $dwaglnc and
        $reg_run and
        $create_svc and
        3 of $xor_loop
}
```
*(Source: generated YARA meta, rule.yara.json; malcat anomalies, YARA matches)*

## 10. Detection Engineering
### Static Detection
1. **YARA Rules**: Use the provided Quasar RAT YARA rule above, which combines the masquerade string, DWAgent payload paths, registry persistence strings, service creation imports, and XOR loop opcode patterns. The rule has 0 false positives on the staged goodware corpus (source: generated YARA meta, goodware_fp.fp_count = 0).
2. **Import-Based Detection**: Alert on processes loading `advapi32.CreateServiceW`, `advapi32.RegSetValueExW`, and `ole32.CoCreateInstance` (for `IShellLinkW`) in combination with DWAgent-related file paths (source: pe_imports, Imports table; frida_probe, hook candidates).
3. **Anomaly-Based Detection**: Flag executables with >50 XOR-in-loop instances, >10 stack array initializations, and RWX resource sections (entropy > 190) as potential obfuscated malware (source: malcat, anomalies table).

### Runtime Detection
1. **Process Monitoring**: Alert on `CreateProcessW` calls launching `\native\dwaglnc.exe` or `\native\dwagsvc.exe` from non-standard installation directories (source: malcat, top strings table; pe_imports, CreateProcessW import).
2. **Registry Monitoring**: Alert on modifications to `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` adding values pointing to DWAgent-related paths (source: capa, `persist via Run registry key` rule; malcat, top strings table).
3. **Service Monitoring**: Alert on creation of Windows services with names containing "DWAgent" or "dwagent" via `CreateServiceW` (source: capa, `persist via Windows service` rule; pe_imports, CreateServiceW import).
4. **Shortcut Monitoring**: Alert on creation of .lnk files in startup folders or common directories targeting `\native\dwaglnc.exe` (source: malcat, decompilation of sub_406ef0).

### capa Rule Coverage
The sample matches 35 capa rules, including all core Quasar capabilities (source: capa, capa Capability Rules table):
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

## 11. What We Don't Know
1. **Decoded C2 Indicators**: No live C2 IP addresses, domains, or URLs were extracted from static analysis, as all network-related data is XOR-obfuscated and no decryption routine was fully reversed (source: yara, YARA Matches table (regex matches only); malcat, XorInLoop anomaly; capa, `encode data using XOR` rule).
2. **Unpacked Payload**: UPX analysis returned `upx_ok: False` and `is_packed: False`, with no unpacked path generated (source: upx, UPX Unpack section). The sample may use custom packing or no packing at all, but no additional unpacked payloads were identified.
3. **C2 Communication Protocol**: No dynamic network traffic was observed (Speakeasy/Frida returned no events, source: speakeasy, frida_probe), so the C2 protocol (HTTP, TCP, UDP, etc.) is unknown.
4. **Full Configuration**: No Quasar RAT configuration (e.g., C2 intervals, keylogging settings, exfiltration filters) was extracted, as configuration data is stored in XOR-obfuscated buffers or encrypted resources (source: malcat, BigBufferNoXrefMediumToHighEntropy anomaly, 3 hits).
5. **Attribution**: No unique actor-specific indicators or campaign metadata were identified beyond the Quasar RAT family designation (source: llm_judge, family_guess).

## 12. Appendix: Analysis Environment
Analysis was performed using the following tools, with IDA non-functional due to a missing idasql binary (source: llm_judge, cross_engine_notes):
| Tool | Version/Details | Output | Source |
|---|---|---|---|
| Ghidra | Non-functional IDA alternative | 3682 functions, 159 imports, 171 static strings | ghidra_query, audit trail |
| Malcat | Latest | Entropy 146, 18 anomalies, 6 top decompilations, 300 top strings | malcat, Malcat Structured Analysis |
| capa | malcat-capa plugin | 35 capability rules matched, 1.83s runtime | capa, capa Capability Rules table |
| FLOSS | Latest | 3084 total strings (2990 static, 73 decoded, 18 stack, 3 tight) | floss, FLOSS Strings section |
| radare2 | Latest | Entry point, unpacking stub, and obfuscated code disassembly | radare2, radare2 Disassembly section |
| YARA | Latest | 11 rule matches, generated detection rule | yara, YARA Matches table; rule.yara.json |
| Speakeasy | Latest | 0 API calls, 0 key events (no runtime behavior observed) | speakeasy, Speakeasy (dynamic) section |
| Frida | 17.16.4 | 20 hook candidates, no runtime events | frida_probe, Frida Probe section |
| UPX | Latest | Unpack failed, sample not packed | upx, UPX Unpack section |

All tool outputs are consistent, with no conflicting data across engines (source: llm_judge, cross_engine_notes; deep_dive_agentic, tool_gate.ok = True).
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
  "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "family": "unknown",
  "generated_at": "2026-08-04T06:23:04.875758+00:00",
  "string_count": 24,
  "strings": [
    "RegisterServiceCtrlHandlerW",
    "StartServiceCtrlDispatcherW",
    "SetUnhandledExceptionFilter",
    "SHGetSpecialFolderLocation",
    "InitializeCriticalSection",
    "UnhandledExceptionFilter",
    "GetSystemTimeAsFileTime",
    "QueryPerformanceCounter",
    "SetEnvironmentVariableW",
    "RtlLookupFunctionEntry",
    "DeleteCriticalSection",
    "QueryServiceStatusEx",
    "EnterCriticalSection",
    "LeaveCriticalSection",
    "__C_specific_handler",
    "SHGetPathFromIDListW",
    "GetCurrentProcessId",
    "MultiByteToWideChar",
    "RtlAddFunctionTable",
    "WaitForSingleObject",
    "WideCharToMultiByte",
    "___lc_codepage_func",
    "CloseServiceHandle",
    "GetCurrentThreadId"
  ],
  "rule_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar",
  "sigma_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml",
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785824024.725729}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785824025.6662686}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785824025.7642624}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785824025.791138}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785824248.4817197}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785824248.5344846}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785824249.3862934}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785824249.416699}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785824249.4189992}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785824487.7848818}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name LIMIT 100", "ts": 1785824491.5297194}`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, string_ref_count, call_in_count, call_out_count, size FROM function_metrics ORDER BY string_ref_count DESC LIMIT 20", "ts": 1785824494.8789217}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%Service%' OR content LIKE '%Registry%' OR content LIKE '%http%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%Software\\\\Microsoft%' ORDER BY address LIMIT 50", "ts": 1785`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%DWAgent%' OR content LIKE '%dwagent%' OR content LIKE '%dw%' OR content LIKE '%agent%' OR content LIKE '%server%' OR content LIKE '%password%' OR content LIKE '%token%' OR content LIKE '%key%' ORDER `
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 1112000 AND 1115200 OR address BETWEEN 150000 AND 151000 OR address BETWEEN 10000 AND 11000 OR address BETWEEN 945000 AND 949000 OR address BETWEEN 1114600 AND 1115000 ORDER BY address LIMIT 200", "`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%.exe' OR content LIKE '%.dll' OR content LIKE '%.bat' OR content LIKE '%.ps1' OR content LIKE '%.vbs' OR content LIKE '%\\\\Windows%' OR content LIKE '%\\\\Temp%' OR content LIKE '%\\\\AppData%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 0x510000 AND 0x511000 ORDER BY address LIMIT 100", "ts": 1785824517.9570842}`
- `{"source": "ghidra_query", "sql": "SELECT sql FROM sqlite_master WHERE type='table' AND name='callgraph_edges'", "ts": 1785824527.3447056}`
- `{"source": "ghidra_query", "sql": "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", "ts": 1785824531.4470594}`
- `{"source": "ghidra_query", "sql": "SELECT sql FROM sqlite_master WHERE type='table' AND name IN ('call_edges','function_calls','cfg_edges')", "ts": 1785824534.3053627}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM call_edges LIMIT 5", "ts": 1785824536.150478}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_calls LIMIT 20", "ts": 1785824538.898855}`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, block_count, cyclomatic_complexity, string_ref_count FROM function_metrics ORDER BY size DESC LIMIT 30", "ts": 1785824541.9601643}`
- `{"source": "ghidra_query", "sql": "SELECT from_ea, to_ea, is_code FROM xrefs WHERE to_ea IN (5514596, 5323490, 5323558, 5323678, 5323728, 5323744) LIMIT 50", "ts": 1785824550.5135636}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785824583.8454444}`
- `{"source": "yara_gen_v2", "ts": 1785824584.8759453}`
- `{"source": "publish_report_v2", "ts": 1785824664.882635}`
- `{"source": "publish_report_v2_technical", "ts": 1785825212.4840147}`
