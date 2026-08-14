> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:07:52 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report

## 1. Executive Summary

This report details the analysis of the sample `raas.exe` (SHA256: `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505`). The verdict is **malicious** with a confidence score of 90/100. The sample is identified as a Ransomware-as-a-Service (RaaS) component belonging to the **Shaitan/Troldesh** family, confirmed by VirusTotal external threat intelligence (62 malicious detections) and consistent behavioral indicators across multiple analysis engines.

The binary exhibits a sophisticated, multi-stage attack methodology. It begins with extensive anti-analysis and anti-debugging checks, targeting virtual machines (VMware, VirtualBox), debuggers (OllyDbg, IDA Pro, WinDbg), and security tools (ProcessHacker, Wireshark). It employs process injection via `VirtualAllocEx` and `VirtualProtect` to execute malicious code within legitimate processes. The core functionality involves a hybrid encryption scheme: RC4 for file encryption, AES for key wrapping, and RSA for asymmetric key exchange, which is characteristic of modern ransomware. The sample also performs direct disk access (`\\.\PhysicalDrive0`) to bypass filesystem-level protections and contains network communication capabilities (WSAStartup, connect, send, recv) for command-and-control (C2) operations.

Static analysis reveals high cyclomatic complexity in several functions, indicating control flow obfuscation. The binary is packed, as indicated by YARA rule matches and the presence of an overlay with medium-to-high entropy. Dynamic analysis via Speakeasy and Frida probes recorded zero API calls or events, which is a strong indicator of anti-analysis evasion succeeding in the analysis environment.

## 2. Sample Metadata

| Attribute | Value | Source |
|---|---|---|
| SHA256 | `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505` | (source: malcat) |
| File Name | `raas.exe` | (source: malcat) |
| File Size | 173,923 bytes | (source: malcat) |
| File Type | PE (Portable Executable) | (source: malcat) |
| Architecture | x86 (32-bit) | (source: malcat) |
| Entry Point EA | 1564 (0x61C) | (source: malcat) |
| Entropy | 7.39 bits/byte (whole file) | (source: malcat) |
| Imphash | `b53f6e0803fd24f3dd50f45f3b463d3f` | (source: rule.yara.json) |
| Family Guess | `ransomware.shaitan/troldesh` | (source: verdict.json) |
| Verdict | Malicious (Score: 90) | (source: verdict.json) |

The high entropy (7.39) is consistent with packed or encrypted content. The imphash provides a fingerprint for tracking related samples.

## 3. File Layout & Structural Analysis

The PE file structure is analyzed by MalCat. The layout table below shows the sections and their properties.

| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 54272 | 57344 | RX |
| .rdata | 58368 | 22016 | 24576 | R |
| .data | 82944 | 10240 | 20480 | RW |
| .reloc | 103424 | 3584 | 4096 | R |
| overlay | 107520 | 82787 | 0 | - |

*(source: malcat, query_or_table: File Layout)*

The `.text` section is executable and readable (RX), containing the main code. The `.rdata` section holds read-only data, likely including import tables and constants. The `.data` section is readable and writable (RW), used for global variables. The `.reloc` section contains relocation information. Notably, there is a large **overlay** section starting at EA 107520 with a physical size of 82,787 bytes. This overlay has medium-to-high entropy (anomaly: `UnknownOverlayMediumToHighEntropy`), which is a common indicator of packed or appended data, such as encrypted payloads or configuration data used by the ransomware.

The presence of a `RichHeader` at EA 128 and standard PE structures (`MZ`, `PE`, `OptionalHeader`, `Sections`) confirms a valid PE format. The `ImportTable` at EA 78220 and `SecurityCookie` at EA 83968 are standard for MSVC-compiled binaries.

## 4. Static Code Analysis

Static analysis reveals a complex binary with significant obfuscation and malicious capabilities.

### 4.1 Entry Point and Initial Execution Flow

The entry point is at EA 1564. The radare2 disassembly of the initial code block shows the setup of the stack frame and early function calls.

```asm
┌ 426: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_130h @ ebp-0x130
│           ; var int32_t var_338h @ ebp-0x338
│           0x0040121c      55             push ebp
│           0x0040121d      8bec           mov ebp, esp
│           0x0040121f      81ec38030000   sub esp, 0x338
│           0x00401225      8d55e0         lea edx, [var_20h]
│           0x00401228      53             push ebx
│           0x00401229      56             push esi
│           0x0040122a      57             push edi
│           0x0040122b      6a1c           push 0x1c                   ; 28
│           0x0040122d      59             pop ecx
│           0x0040122e      e817210000     call 0x40334a
│           0x00401233      8d45e0         lea eax, [var_20h]
│           0x00401236      50             push eax
│           0x00401237      ff15f4f04000   call dword [sym.imp.KERNEL32.dll_GetModuleHandleW] ; 0x40f0f4 ; "r@\x01" ; HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
│           0x0040123d      85c0           test eax, eax
│       ┌─< 0x0040123f      0f8579010000   jne 0x4013be
│       │   0x00401245      ff15fcf04000   call dword [sym.imp.KERNEL32.dll_GetProcessHeap] ; 0x40f0fc ; "L@\x01" ; HANDLE GetProcessHeap(void)
│       │   0x0040124b      8325c08741..   and dword [0x4187c0], 0     ; [0x4187c0:4]=0
│       │   0x00401252      8325c48741..   and dword [0x4187c4], 0     ; [0x4187c4:4]=0
│       │   0x00401259      a3c8874100     mov dword [0x4187c8], eax   ; [0x4187c8:4]=0
│       │   0x0040125e      e873190000     call 0x402bd6
│       │   0x00401263      85c0           test eax, eax
│      ┌──< 0x00401265      0f8553010000   jne 0x4013be
│      ││   0x0040126b      2145fc         and dword [var_4h], eax
│      ││   0x0040126e      8d85c8fcffff   lea eax, [var_338h]
│      ││   0x00401274      6804010000     push 0x104                  ; 260
│      ││   0x00401279      50             push eax
│      ││   0x0040127a      6a00           push 0
│      ││   0x0040127c      ff1508f14000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameW] ; 0x40f108 ; DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
│      ││   0x00401282      51             push ecx
│      ││   0x00401283      8d55e8         lea edx, [var_18h]
│      ││   0x00401286      8d8dc8fcffff   lea ecx, [var_338h]
│      ││   0x0040128c      e8f7feffff     call 0x401188
│      ││   0x00401291      85c0           test eax, eax
│     ┌───< 0x00401293      0f8425010000   je 0x4013be
│     │││   0x00401299      33c9           xor ecx, ecx
│    ┌────> 0x0040129b      8a81b82c4100   mov al, byte [ecx + 0x412cb8]
│    ╎│││   0x004012a1
```
*(source: radare2, query_or_table: Disassembly)*

This code initializes the stack, calls `GetModuleHandleW` to check for an existing module, and then calls `GetProcessHeap` and a function at `0x402bd6`. The function at `0x402bd6` is a critical anti-analysis dispatcher (see Section 4.2). If the anti-analysis checks pass (return 0), execution proceeds to `GetModuleFileNameW` to get its own path, followed by further processing. This flow suggests the binary first determines if it is running in a clean environment before proceeding with its payload.

### 4.2 Anti-Analysis Dispatcher (sub_402bd6)

The decompilation of `sub_402bd6` reveals a comprehensive anti-analysis toolkit. This function orchestrates multiple checks for debuggers, virtual machines, and security tools.

```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_402bd6(void)

{
    int32_t iVar1;
    code *pcVar2;
    undefined4 uVar3;
    int32_t iVar4;
    undefined auStack_160 [36];
    undefined auStack_13c [36];
    undefined auStack_118 [32];
    undefined auStack_f8 [28];
    undefined auStack_dc [56];
    undefined auStack_a4 [28];
    undefined auStack_88 [52];
    undefined auStack_54 [24];
    undefined auStack_3c [24];
    undefined auStack_24 [16];
    undefined auStack_14 [12];
    undefined *puStack_8;
    
    sub_40334a();
    sub_403302();
    iVar1 = (*kernel32.LoadLibraryW)(auStack_3c);
    if ((iVar1 != 0) && (pcVar2 = (*kernel32.GetProcAddress)(iVar1, auStack_14), pcVar2 != 0x0)) {
        (*pcVar2)(1);
    }
    sub_40334a();
    sub_40334a();
    pcVar2 = kernel32.GetModuleHandleW;
    iVar1 = (*kernel32.GetModuleHandleW)(auStack_88);
    if ((iVar1 == 0) && (iVar1 = (*pcVar2)(auStack_a4), iVar1 == 0)) {
        sub_40334a();
        pcVar2 = user32.FindWindowW;
        iVar4 = 0;
        iVar1 = (*user32.FindWindowW)(auStack_24, 0);
        if (iVar1 == 0) {
            sub_40334a();
            iVar1 = (*pcVar2)(auStack_13c, 0);
            if (iVar1 == 0) {
                sub_40334a();
                iVar1 = (*pcVar2)(auStack_160, 0);
                if (iVar1 == 0) {
                    sub_40334a();
                    iVar1 = (*pcVar2)(auStack_f8, 0);
                    if (iVar1 == 0) {
                        sub_40334a();
                        iVar1 = (*pcVar2)(auStack_dc, 0);
                        if (iVar1 == 0) {
                            sub_40334a();
                            iVar1 = (*pcVar2)(auStack_54, 0);
                            if (((((iVar1 == 0) && (([0x0x7ffe02d4] & 3) == 0)) && (iVar1 = sub_4026c2(), iVar1 == 0)) &&
                                (((iVar1 = sub_4019ac(), iVar1 == 0 && (iVar1 = sub_401a61(), iVar1 == 0)) &&
                                 ((iVar1 = sub_401d4c(), iVar1 == 0 &&
                                  ((iVar1 = sub_402373(), iVar1 == 0 && (iVar1 = sub_40204f(), iVar1 == 0)))))))) &&
                               ((iVar1 = sub_402543(), iVar1 == 0 && (iVar1 = sub_40258b(), iVar1 == 0)))) {
                                sub_40334a();
                                puStack_8 = auStack_118;
                                do {
                                    iVar1 = sub_401724();
                                    if (iVar1 != 0) {
                                        return 1;
                                    }
                                    iVar4 = iVar4 + 1;
                                } while (iVar4 == 0);
                                iVar1 = sub_4025d3();
                                if ((((iVar1 == 0) && (iVar1 = sub_4022ed(), iVar1 == 0)) &&
                                    (iVar1 = sub_402b15(), iVar1 == 0)) && (iVar1 = sub_402b9f(), iVar1 == 0)) {
                                    (*kernel32.AddVectoredExceptionHandler)(1, sub_402b77);
                                    [0x0x417468] = 1;
                                    pcVar2 = swi(3);
                                    uVar3 = (*pcVar2)();
                                    return uVar3;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 1;
}
```
*(source: malcat, query_or_table: Decompilations, row_or_rule: 8150 — sub_402bd6)*

This function is a master orchestrator. It first attempts to load a library and call an exported function (likely a sandbox or debugger detection DLL). It then uses `GetModuleHandleW` to check for the presence of specific modules (e.g., `SbieDll.dll` for Sandboxie). It uses `FindWindowW` to search for windows belonging to debuggers (e.g., `WinDbgFrameClass`, `Immunity Debugger`) and analysis tools. If all these checks pass, it proceeds to call a series of sub-functions (`sub_4026c2`, `sub_4019ac`, `sub_401a61`, `sub_401d4c`, `sub_402373`, `sub_40204f`, `sub_402543`, `sub_40258b`) which likely perform additional anti-VM, anti-debug, and environment checks. The final block installs a vectored exception handler (`AddVectoredExceptionHandler`) and triggers a software interrupt (`swi(3)`), a technique often used to detect emulators or to alter execution flow in a debugger. If any check fails, the function returns 1, indicating a hostile environment was detected.

### 4.3 Registry Manipulation (sub_401d4c, sub_40204f)

The decompilations of `sub_401d4c` and `sub_40204f` show extensive interaction with the Windows Registry, specifically targeting `HKEY_LOCAL_MACHINE` (0x80000002).

```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_401d4c(void)

{
    code *pcVar1;
    undefined2 uVar2;
    int32_t iVar3;
    int32_t iVar4;
    undefined4 extraout_ECX;
    undefined4 extraout_ECX_00;
    undefined4 extraout_ECX_01;
    undefined4 extraout_ECX_02;
    undefined4 extraout_ECX_03;
    undefined4 extraout_ECX_04;
    undefined4 uVar5;
    undefined4 uVar6;
    int32_t iVar7;
    undefined4 **ppuStack_950;
    undefined4 uStack_94c;
    undefined *puStack_948;
    undefined4 uStack_944;
    undefined4 uStack_940;
    undefined4 *puStack_93c;
    undefined4 auStack_928 [11];
    undefined auStack_8fc [20];
    undefined auStack_8e8 [76];
    undefined auStack_89c [68];
    undefined auStack_858 [8];
    undefined auStack_850 [19];
    undefined uStack_83d;
    undefined2 auStack_83c [9];
    undefined uStack_829;
    undefined2 auStack_828 [9];
    undefined uStack_815;
    undefined2 auStack_814 [9];
    undefined auStack_801 [2049];
    
    iVar7 = 0x800;
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        auStack_801[iVar4] = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    puStack_93c = 0x401d77;
    sub_40334a();
    puStack_93c = 0x401d83;
    sub_40334a();
    pcVar1 = advapi32.RegOpenKeyExW;
    puStack_93c = auStack_928;
    puStack_948 = auStack_89c;
    uVar6 = 1;
    uStack_940 = 1;
    uStack_944 = 0;
    uStack_94c = 0x80000002;
    auStack_928[0] = 0x80000002;
    ppuStack_950 = 0x401da8;
    iVar4 = (*advapi32.RegOpenKeyExW)();
    if (iVar4 == 0) {
        ppuStack_950 = 0x401db9;
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_00;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(&stack0xfffff6d4, uVar5, auStack_814), iVar4 != -1)) {
        iVar3 = 0;
        ppuStack_950 = 0x401df3;
        iVar4 = sub_403189();
        if (0 < iVar4) {
            do {
                ppuStack_950 = 0x401e04;
                uVar2 = sub_4032b2();
                auStack_814[iVar3] = uVar2;
                iVar3 = iVar3 + 1;
                ppuStack_950 = 0x401e19;
                iVar4 = sub_403189();
            } while (iVar3 < iVar4);
        }
        ppuStack_950 = 0x401e29;
        sub_40334a();
        ppuStack_950 = 0x401e39;
        iVar4 = sub_403255();
        if (iVar4 != 0) {
            return 1;
        }
    }
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        *(auStack_814 + iVar4 + -1) = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    ppuStack_950 = 0x401e62;
    sub_40334a();
    ppuStack_950 = 0x401e6e;
    sub_40334a();
    ppuStack_950 = &puStack_93c;
    puStack_93c = 0x80000002;
    iVar4 = (*pcVar1)(0x80000002, auStack_8e8, 0, 1);
    if (iVar4 == 0) {
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_02;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX_01;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(auStack_928, uVar5, auStack_828, uVar5), iVar4 != -1)) {
        iVar3 = 0;
        iVar4 = sub_403189();
        if (0 < iVar4) {
            do {
                uVar2 = sub_4032b2();
                auStack_828[iVar3] = uVar2;
                iVar3 = iVar3 + 1;
                iVar4 = sub_403189();
            } while (iVar3 < iVar4);
        }
        sub_40334a();
        iVar4 = sub_403255();
        if (iVar4 != 0) {
            return 1;
        }
    }
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        *(auStack_828 + iVar4 + -1) = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    sub_40334a();
    sub_40334a();
    ppuStack_950 = 0x80000002;
    iVar4 = (*pcVar1)(0x80000002, auStack_8fc, 0, 1, &ppuStack_950);
    if (iVar4 == 0) {
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_04;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX_03;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(&puStack_93c, uVar5, auStack_83c, uVar5), iVar4 != -1)) {
        iVar3 = 0;
    
```
*(source: malcat, query_or_table: Decompilations, row_or_rule: 4428 — sub_401d4c)*

This function repeatedly opens registry keys under `HKEY_LOCAL_MACHINE` using `RegOpenKeyExW`, queries values, and processes them. The pattern of opening a key, checking a condition, and then performing an action (like returning 1) suggests it is checking for specific registry artifacts that indicate the presence of virtual machines, security software, or previous infection markers. The use of large stack buffers (`auStack_801[2049]`) for string manipulation is typical of obfuscated code that builds strings dynamically to avoid static detection.

### 4.4 Cryptographic API Usage

MalCat identifies the use of cryptographic APIs as an anomaly (`CryptoApiUsage`). The Ghidra SQL query confirms the presence of a full crypto API chain: `CryptAcquireContextW`, `CryptCreateHash`, `CryptHashData`, `CryptGetHashParam` from `ADVAPI32.DLL`.

*(source: malcat, query_or_table: Anomalies, row_or_rule: CryptoApiUsage)*
*(source: ghidra_query, sql: "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30")*

This chain is used for hashing data, likely for integrity checks or as part of the encryption key derivation process. The capa rule `hash data via WinCrypt` confirms this capability.

*(source: capa, query_or_table: capa Capability Rules, row_or_rule: hash data via WinCrypt)*

### 4.5 Network Communication Stack

Ghidra analysis reveals a network communication stack: `WSAStartup`, `connect`, `send`, `recv`, `closesocket` from `WS2_32.DLL`.

*(source: ghidra_query, sql: "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30")*

These APIs are used to establish network connections, send and receive data, and close sockets. This is indicative of command-and-control (C2) communication capability, allowing the ransomware to receive commands, exfiltrate data, or download additional payloads.

### 4.6 File Operations and Direct Disk Access

The binary imports critical file operation APIs: `CreateFileW`, `ReadFile`, `WriteFile`, `DeleteFileW`, `MoveFileExW`.

*(source: ghidra_query, sql: "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30")*

Furthermore, FLOSS strings reveal the presence of `\\.\PhysicalDrive0`, which is a direct disk access path.

*(source: floss, query_or_table: High-signal FLOSS)*

This combination indicates the ransomware can read, encrypt, delete, and move files. The direct disk access via `\\.\PhysicalDrive0` is a technique to bypass filesystem-level protections and access raw disk sectors, which can be used to encrypt the Master Boot Record (MBR) or other critical disk structures.

### 4.7 Process Injection

The PE import signals table shows the presence of `VirtualAllocEx` and `VirtualProtect`.

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| change_memory_protection | VirtualProtect | T1055 |

*(source: pe_imports, query_or_table: PE Imports / Signals)*

These APIs are fundamental to process injection techniques. `VirtualAllocEx` allocates memory in a remote process, and `VirtualProtect` changes memory protection to allow code execution. This allows the ransomware to inject its malicious code into a legitimate process to evade detection.

### 4.8 Anti-Debugging and Anti-VM Strings

FLOSS extracted numerous strings targeting analysis environments.

**Anti-VM Strings:**
- `VMware Tools`, `vmhgfs.sys`, `vmmouse.sys`, `VBoxMouse.sys`, `xenservice`, `prl_tools`, `VMSrvc`
*(source: floss, query_or_table: FLOSS sample)*

**Anti-Sandbox Strings:**
- `SANDBOX`, `MALWARE`, `MALTEST`, `TEQUILABOOMBOOM`, `SbieDll.dll`, `joeboxcontrol`, `IVIRTUALBOX`
*(source: floss, query_or_table: FLOSS sample)*

**Anti-Debug Strings:**
- `ollydbg.exe`, `Immunity Debugger`, `idaq.exe`, `idaq64.exe`, `WinDbgFrameClass`, `windbg.exe`
*(source: floss, query_or_table: FLOSS sample)*

**Anti-Analysis Tools:**
- `ProcessHacker.exe`, `ProcMon.exe`, `Wireshark.exe`, `HookExplorer.exe`, `ImportREC.exe`, `PETools.exe`, `LordPE.exe`
*(source: floss, query_or_table: FLOSS sample)*

These strings are used by the anti-analysis dispatcher (`sub_402bd6`) to detect and evade specific environments. The presence of these strings is a strong indicator of malicious intent to avoid analysis.

### 4.9 YARA Rule Matches

The YARA pipeline matched 19 rules. Key behavioral rules include:

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| anti_dbg | - | `$d1@76904 len=12; $c2@76338 len=17; $c3@76868 len=17` |
| inject_thread | - | `$c1@76020 len=11; $c2@75984 len=14; $c3@72624 len=20; $c7@76020 len=11` |
| win_registry | - | `$f1@77130 len=12; $c3@77118 len=11; $c6@77118 len=11` |
| win_files_operation | - | `$f1@76904 len=12; $c1@75686 len=9; $c2@76816 len=14; $c3@75686 len=9; $c4@75698 len=8` |
| IsPacked | - | |
| HasOverlay | - | |

*(source: yara, query_or_table: YARA Matches)*

The `anti_dbg` rule confirms anti-debugging behavior. The `inject_thread` rule confirms process injection capabilities. The `win_registry` and `win_files_operation` rules confirm registry and file manipulation. The `IsPacked` and `HasOverlay` rules confirm the binary is packed and contains an overlay, consistent with the structural analysis.

### 4.10 Capa Capability Rules

Capa identified 27 capabilities. Key rules include:

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery | |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get session user name | T1033:System Owner/User Discovery, T1087:Account Discovery | |
| check for PEB NtGlobalFlag flag | | B0001.036:Debugger Detection |
| execute anti-debugging instructions | | B0001.034:Debugger Detection |
| hash data with CRC32 | | C0032.001:Checksum |
| hash data via WinCrypt | | C0029:Cryptographic Hash |

*(source: capa, query_or_table: capa Capability Rules)*

These rules confirm the binary's capabilities in encryption (RC4, XOR), discovery (file, process, registry, environment), and anti-debugging (PEB NtGlobalFlag, anti-debug instructions). The `encrypt data using RC4 PRGA` rule is particularly significant for ransomware, as RC4 is a common stream cipher used for file encryption.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis was performed using Speakeasy and Frida probes. Both tools executed successfully but recorded **zero API calls or events**.

- **Speakeasy:** `speakeasy_ok: True`, `api_calls: 0`, `key_events: 0`.
*(source: speakeasy)*
- **Frida Probe:** `frida_available: True`, `hook_candidates` listed but no events recorded.
*(source: frida_probe)*

The absence of observed runtime behavior is a significant finding. It indicates that the sample's anti-analysis techniques successfully detected the analysis environment and terminated or altered its execution path before performing any malicious actions. This is consistent with the extensive anti-VM, anti-debug, and anti-sandbox strings and checks identified in static analysis. The sample likely checks for artifacts of the Speakeasy emulator or Frida instrumentation and exits cleanly if detected.

## 6. Network Indicators & C2

The binary contains a network communication stack (`WSAStartup`, `connect`, `send`, `recv`, `closesocket`) from `WS2_32.DLL`.

*(source: ghidra_query, sql: "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30")*

This indicates the capability for C2 communication. However, no specific C2 domains, IP addresses, or URLs were extracted from the static strings. The YARA rule `domain` matched at offset 167971, but the matched string is not provided in the evidence. The `IP` rule matched at offset 167971 for an IPv6 address. Without dynamic analysis triggering the network code, the exact C2 infrastructure remains unknown. The network capability is present but latent in this analysis.

## 7. Capabilities Assessment

Based on static analysis, the sample possesses the following confirmed capabilities:

1.  **Anti-Analysis:** Extensive checks for VMs, debuggers, sandboxes, and security tools. Uses `FindWindowW`, `GetModuleHandleW`, and registry queries. Installs vectored exception handlers. (source: yara `anti_dbg`, capa `check for PEB NtGlobalFlag flag`, floss strings)
2.  **Process Injection:** Uses `VirtualAllocEx` and `VirtualProtect` to inject code into other processes. (source: pe_imports `allocate_memory`, yara `inject_thread`)
3.  **Encryption:** Employs RC4 PRGA for file encryption and XOR encoding for obfuscation. Uses cryptographic APIs for hashing. (source: capa `encrypt data using RC4 PRGA`, `encode data using XOR`, `hash data via WinCrypt`)
4.  **File System Manipulation:** Can create, read, write, delete, and move files. Has direct disk access capability. (source: ghidra file operations, floss `\\.\PhysicalDrive0`, yara `win_files_operation`)
5.  **Registry Manipulation:** Can query and enumerate registry values. (source: capa `query or enumerate registry value`, yara `win_registry`)
6.  **Network Communication:** Contains socket APIs for C2 communication. (source: ghidra network stack)
7.  **Discovery:** Can enumerate processes, get file paths, check file existence, get disk size, and query environment variables. (source: capa rules)
8.  **Obfuscation:** Uses XOR encoding, obfuscated stack strings, and high cyclomatic complexity functions. (source: capa `encode data using XOR`, malcat `SpaghettiFunction` anomaly)

## 8. Indicators of Compromise

### File-Based IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | `c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505` | (source: malcat) |
| Imphash | `b53f6e0803fd24f3dd50f45f3b463d3f` | (source: rule.yara.json) |
| File Name | `raas.exe` | (source: malcat) |

### String-Based IOCs (High-Signal)
| String | Context | Source |
|---|---|---|
| `\\.\PhysicalDrive0` | Direct disk access path | (source: floss) |
| `ollydbg.exe` | Debugger name | (source: floss) |
| `Immunity Debugger` | Debugger name | (source: floss) |
| `idaq.exe` | IDA Pro process name | (source: floss) |
| `WinDbgFrameClass` | WinDbg window class | (source: floss) |
| `ProcessHacker.exe` | Security tool | (source: floss) |
| `Wireshark.exe` | Network analyzer | (source: floss) |
| `SbieDll.dll` | Sandboxie DLL | (source: floss) |
| `VMware Tools` | VMware artifact | (source: floss) |
| `VBoxMouse.sys` | VirtualBox artifact | (source: floss) |
| `SANDBOX` | Sandbox indicator | (source: floss) |
| `MALWARE` | Sandbox indicator | (source: floss) |

### YARA Rule Matches (Behavioral)
| Rule | Source |
|---|---|
| `anti_dbg` | (source: yara) |
| `inject_thread` | (source: yara) |
| `win_registry` | (source: yara) |
| `win_files_operation` | (source: yara) |
| `IsPacked` | (source: yara) |
| `HasOverlay` | (source: yara) |

## 9. Detection Engineering

### YARA Rule
A YARA rule was generated based on the analysis. The rule includes 24 strings extracted from the sample, focusing on anti-analysis artifacts.

```json
{
  "sha256": "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "family": "ransomware.shaitan/troldesh",
  "imphash": "b53f6e0803fd24f3dd50f45f3b463d3f",
  "generated_at": "2026-08-12T21:21:56.683281+00:00",
  "string_count": 24,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    "WinDbgFrameClass",
    "Identifier",
    "ProcessHacker.exe",
    "tcpview.exe",
    "drivers\\vmhgfs.sys",
    "autoruns.exe",
    "Immunity Debugger",
    "C:\\InsideTm",
    "autorunsc.exe",
    "filemon.exe",
    "Zeta Debugger",
    "ntdll.dll",
    "procmon.exe"
  ],
  "rule_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yar",
  "sigma_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yml",
  "iocs_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/iocs.json",
  "yara_valid": true,
  "yara_check": "ok"
}
```
*(source: rule.yara.json)*

### Sigma Rule
A Sigma rule path is provided at `/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yml`.

### Detection Recommendations
1.  **Static Detection:** Use the generated YARA rule to detect samples with matching anti-analysis strings.
2.  **Behavioral Detection:** Monitor for processes that call `VirtualAllocEx` followed by `VirtualProtect` on remote processes.
3.  **Registry Monitoring:** Alert on queries to registry keys associated with VM detection (e.g., `HARDWARE\DESCRIPTION\System`, `HARDWARE\DEVICEMAP\Scsi`).
4.  **File System Monitoring:** Watch for direct disk access via `\\.\PhysicalDrive0` and rapid file operations (create, write, delete, move) indicative of ransomware activity.
5.  **Network Monitoring:** Inspect outbound connections from processes that also exhibit anti-analysis behavior.

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Defense Evasion | Obfuscated Files or Information | T1027 | capa: `encode data using XOR`, `encrypt data using RC4 PRGA` |
| Defense Evasion | Process Injection | T1055 | pe_imports: `VirtualAllocEx`, `VirtualProtect`; yara: `inject_thread` |
| Defense Evasion | Debugger Evasion | T1622 | pe_imports: `IsDebuggerPresent`; yara: `anti_dbg`; capa: `check for PEB NtGlobalFlag flag`, `execute anti-debugging instructions` |
| Discovery | Process Discovery | T1057 | capa: `enumerate processes` |
| Discovery | File and Directory Discovery | T1083 | capa: `get common file path`, `check if file exists`, `get file size` |
| Discovery | System Information Discovery | T1082 | capa: `query environment variable`, `get disk size` |
| Discovery | Query Registry | T1012 | capa: `query or enumerate registry value` |
| Discovery | System Owner/User Discovery | T1033 | capa: `get session user name` |
| Execution | Command and Scripting Interpreter | T1059 | capa: `accept command line arguments` |
| Impact | Data Encrypted for Impact | T1486 | capa: `encrypt data using RC4 PRGA` (ransomware behavior) |

## 11. What We Don't Know

1.  **C2 Infrastructure:** No specific C2 domains, IPs, or URLs were extracted. The network capability is present but the exact endpoints are unknown. (reason: no dynamic execution triggered network code, no static strings found)
2.  **Encryption Key Management:** The exact mechanism for key generation, storage, and exchange (e.g., RSA public key embedding) is not fully analyzed. (reason: requires deeper reverse engineering of crypto functions)
3.  **Ransom Note:** No ransom note content or file name was identified. (reason: likely generated dynamically or stored encrypted)
4.  **Lateral Movement:** No evidence of lateral movement techniques (e.g., SMB exploitation, PsExec) was observed. (reason: may be a payload component, not the initial dropper)
5.  **Persistence Mechanism:** No specific persistence mechanism (e.g., registry run key, scheduled task) was identified. (reason: may be implemented by a dropper or loader)
6.  **Full Anti-Analysis Logic:** The complete logic of the anti-analysis dispatcher (`sub_402bd6`) and its sub-functions is not fully decompiled. (reason: obfuscated control flow, large function size)
7.  **Overlay Content:** The content and purpose of the 82KB overlay are unknown. (reason: medium-to-high entropy suggests encrypted or compressed data)
8.  **Dynamic Behavior:** The exact runtime behavior in a real victim environment is unknown. (reason: anti-analysis techniques prevented execution in the analysis environment)

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Status | Key Findings |
|---|---|---|
| MalCat | Used | File layout, anomalies, decompilations, imports, strings |
| Ghidra | Used | SQL queries for functions, strings, imports, call edges |
| IDA | Used | Function count (226), string count, imports |
| Radare2 | Used | Entry point disassembly |
| Capa | malcat-capa | 27 capability rules |
| YARA | Pipeline | 19 rule matches |
| FLOSS | Used | 579 strings (70 decoded, 509 static) |
| PE Imports | Used | 83 imports, 6 signals |
| Speakeasy | Ran, 0 events | No runtime behavior observed |
| Frida Probe | Ran, 0 events | No runtime behavior observed |
| UPX | Not packed | `upx_ok: False`, `is_packed: False` |
| XOR Search | Found | XOR 00 at position 0 |
| VirusTotal | External TI | 62 malicious detections, family: shaitan/troldesh |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment. Specific details about the OS version, VM configuration, and network settings are not provided in the evidence. The sample was analyzed at the path `/opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe`. The project name is `malware`.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505  
**sample_path:** /opt/samples/corpus/malware/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/raas.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 90
- **family_guess**: ransomware.shaitan/troldesh
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA agree on function counts (248 and 226) and similar suspicious strings, while MalCat provides detailed anomalies including crypto usage and obfuscation. Capa and YARA detect encryption, anti-debugging, and injection behaviors. VirusTotal external TI strongly classifies as ransomware with high detection rate.
- **summary**: The sample exhibits clear behavioral-intent evidence: anti-debugging via IsDebuggerPresent and related strings, process injection with VirtualAllocEx and VirtualProtect, encryption capabilities via RC4 PRGA and XOR encoding, registry manipulation, and file operations. External threat intelligence confirms it as ransomware from the shaitan/troldesh family. Combined with high-signal YARA rules and capa detections, the verdict is malicious with high confidence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| virustotal | external TI hash enrich | `threat_class suggested_threat_label` | VirusTotal classifies as ransomware.shaitan/troldesh with 62 malicious detections, indicating confirmed malicious behavi |
| pe_imports | pe_imports signals | `allocate_memory (VirtualAllocEx)` | API for memory allocation in process injection, a technique for malicious code execution (T1055). |
| ida | imports | `IsDebuggerPresent` | Anti-debugging API to detect and evade analysis environments (T1622), showing defense evasion intent. |
| capa | capa top_rules | `encrypt data using RC4 PRGA` | Encryption technique commonly used in ransomware to encrypt user files, indicating destructive behavior (T1027). |
| floss | floss strings | `ollydbg.exe` | Strings targeting debuggers and analysis tools (e.g., ollydbg.exe, idaq.exe), indicating anti-analysis and sandbox evasi |
| yara | yara matches | `anti_dbg` | YARA rule detecting anti-debugging behaviors, confirming defense evasion intent. |
| malcat | malcat anomalies | `CryptoApiUsage` | Anomaly indicating use of cryptographic APIs, potentially for malicious file encryption or data obfuscation. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a sophisticated ransomware sample ('raas.exe' - Ransomware-as-a-Service) with extensive anti-analysis capabilities. The binary employs a multi-layered encryption scheme (RC4 for file encryption, AES for key wrapping, RSA public key for asymmetric key exchange), characteristic of modern ransomware. It contains a comprehensive anti-analysis toolkit targeting VMs (VMware, VirtualBox, Xen, Parallels), debuggers (OllyDbg, IDA Pro, WinDbg, Immunity Debugger), sandboxes (Sandboxie, JoeBox), and security tools (ProcessHacker, ProcMon, Wireshark). The sample uses XOR encoding, RC4 PRGA, CRC32 hashing, and obfuscated stack strings for defense evasion. It performs process injection via VirtualAllocEx/VirtualProtect, direct disk access through \\.\PhysicalDrive0, and file operations (read, encrypt, delete, move) targeting victim data. Network APIs (WSAStartup, connect, send, recv) indicate C2 communication capability. High cyclomatic complexity functions (123, 113, 98) suggest control flow flattening/obfuscation. The binary is packed with overlay data. Exfiltration capability is not explicitly observed in the analysis, but network APIs {source: 'binary analysis', query_or_table: 'network APIs', row_or_rule: 'WSAStartup, connect, send, recv', why: 'indicate C2 communication potential for data transfer'}. Imports are observed with critical Windows APIs {source: 'binary analysis', query_or_table: 'import table', row_or_rule: 'VirtualAllocEx, VirtualProtect', why: 'support process injection and memory manipulation'} and network functions {source: 'binary analysis', query_or_table: 'network APIs', row_or_rule: 'WSAStartup, connect, send, recv', why: 'enable C2 communication'}.

### deep key_evidence
- `"CAPA: encrypt data using RC4 PRGA (T1027, C0027.009) - ransomware file encryption"`
- `"CAPA: encrypt data using AES via WinAPI (T1027) with RSA public key reference - hybrid encryption chain"`
- `"CAPA: encode data using XOR (T1027, C0026.002), contain obfuscated stackstrings - defense evasion"`
- `"CAPA: resolve function by hash (T1027) - shellcode-style dynamic API resolution"`
- `"PE_IMPORT_SIGNALS: VirtualAllocEx + VirtualProtect (T1055) - process injection capabilities"`
- `"PE_IMPORT_SIGNALS: IsDebuggerPresent (T1622) + NtQueryInformationProcess - anti-debugging"`
- `"FLOSS: anti-VM strings (VMware Tools, vmhgfs.sys, vmmouse.sys, VBoxMouse.sys, xenservice, prl_tools, VMSrvc)"`
- `"FLOSS: anti-sandbox strings (SANDBOX, MALWARE, MALTEST, TEQUILABOOMBOOM, SbieDll.dll, joeboxcontrol, IVIRTUALBOX)"`
- `"FLOSS: anti-debug strings (ollydbg.exe, Immunity Debugger, idaq.exe, idaq64.exe, WinDbgFrameClass, windbg.exe)"`
- `"FLOSS: anti-analysis tools (ProcessHacker.exe, ProcMon.exe, Wireshark.exe, HookExplorer.exe, ImportREC.exe, PETools.exe, LordPE.exe)"`
- `"Ghidra SQL: full crypto API chain - CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptGetHashParam (ADVAPI32.DLL)"`
- `"Ghidra SQL: network stack - WSAStartup, connect, send, recv, closesocket (WS2_32.DLL) - C2 communication"`
- `"Ghidra SQL: file operations - CreateFileW, ReadFile, WriteFile, DeleteFileW, MoveFileExW - file encryption workflow"`
- `"Ghidra SQL: direct disk access via \\\\.\\PhysicalDrive0 - bypass filesystem for encryption"`
- `"Ghidra SQL: AddVectoredExceptionHandler - SEH-based anti-debugging"`
- `"Ghidra SQL: high cyclomatic complexity functions (123, 113, 98) - control flow obfuscation/flattening"`
- `"YARA: IsPacked rule matched - binary is packed"`
- `"YARA: CRC32_poly_Constant at offset 1226 - integrity checking or hash-based resolution"`
- `"YARA: maldoc_find_kernel32_base_method_1 - PEB-based shellcode API resolution technique"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505
size: 173923
type: PE
architecture: X86
entrypoint_ea: 1564
entropy: 7.39
file_name: raas.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
| .text | 1024 | 54272 | 57344 | RX |
| .rdata | 58368 | 22016 | 24576 | R |
| .data | 82944 | 10240 | 20480 | RW |
| .reloc | 103424 | 3584 | 4096 | R |
| overlay | 107520 | 82787 | 0 | - |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| visual_studio_2013_update_1__12_0__also_has_this_build_number_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| HugeStringHexa | 4 | strings | 1 | string has more than 1024 characters and hexa encoding |
| PossiblePackerApiDynamicImport | 4 | imports | 1 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| XorInLoop | 3 | code | 10 | XOR instruction in a loop |
| CryptoApiUsage | 2 | imports | 3 | Crypto-related apis are used |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| HighXrefLoopingFunction | 1 | code | 1 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SpaghettiFunction | 1 | code | 5 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **CryptoApiUsage**
  - `1171`: 
  - `1160`: 
  - `1115`: 
- **GuiSubsystemNoWindowApi**
  - `316`: 
- **HighXrefLoopingFunction**
  - `10058`: 
- **NoChecksum**
  - `312`: 
- **SpaghettiFunction**
  - `2097`: 
  - `26860`: 
  - `27920`: 
  - `38976`: 
  - `44457`: 
- **XorInLoop**
  - `1223`: 
  - `1269`: 
  - `1341`: 
  - `2677`: 
  - `10007`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 64948 | `GetProcessWindowStation` |
| 79976 | `KERNEL32.dll` |
| 80084 | `CryptCreateHash` |
| 80062 | `CryptReleaseContext` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 58900 | `mscoree.dll` |
| 75624 | `ntdll.dll` |
| 79162 | `CreateToolhelp32Snapshot` |
| 64848 | `USER32.DLL` |
| 73584 | `Microsoft Enhanc..ider (Prototype)` |
| 64948 | `GetProcessWindowStation` |
| 87264 | `15ab0ab39185fe4d..bc2f22ed4dbd7059` |
| 79144 | `Process32NextW` |
| 64920 | `GetUserObjectInformationW` |
| 73720 | `Microsoft Enhanc..graphic Provider` |
| 64900 | `GetLastActivePopup` |
| 58924 | `CorExitProcess` |
| 64884 | `GetActiveWindow` |
| 73416 | `CONOUT$` |
| 73488 | `Microsoft Enhanc..ic Provider v1.0` |
| 64872 | `MessageBoxW` |
| 75608 | `RtlGetVersion` |
| 73444 | `e+000` |
| 73476 | `1#QNAN` |
| 59076 | `ko-KR` |
| 73452 | `1#SNAN` |
| 80280 | `SHELL32.dll` |
| 80202 | `ADVAPI32.dll` |
| 79976 | `KERNEL32.dll` |
| 80248 | `SHLWAPI.dll` |
| 80004 | `USER32.dll` |
| 59088 | `zh-TW` |
| 59064 | `zh-CN` |
| 63048 | `         (((((  ..               H` |
| 73468 | `1#INF` |
| 73460 | `1#IND` |
| 70372 | `sr-SP-Cyrl` |
| 70760 | `sr-BA-Cyrl` |
| 69764 | `kk-KZ` |
| 76008 | `jQwRES[jBKA]EH^B[[fE_RW@O` |
| 70952 | `en-TT` |
| 69524 | `et-EE` |
| 69824 | `tt-RU` |
| 70152 | `nn-NO` |
| 70596 | `bs-BA-Latn` |
| 69596 | `az-AZ-Latn` |
| 69980 | `kok-IN` |
| 70836 | `sms-FI` |
| 70684 | `sr-BA-Latn` |
| 70176 | `sr-SP-Latn` |
| 70260 | `uz-UZ-Cyrl` |
| 69800 | `uz-UZ-Latn` |
| 70212 | `az-AZ-Cyrl` |
| 77488 | `mnsAmwtvf:rnt` |
| 69908 | `ml-IN` |
| 69896 | `kn-IN` |
| 69884 | `te-IN` |
| 70080 | `de-CH` |
| 69920 | `mr-IN` |
| 69932 | `sa-IN` |
| 69944 | `mn-MN` |
| 69956 | `cy-GB` |
| 69968 | `gl-ES` |
| 69996 | `syr-SY` |
| 70012 | `div-MV` |
| 70044 | `ns-ZA` |
| 70056 | `mi-NZ` |
| 70068 | `ar-IQ` |
| 69464 | `ur-PK` |
| 69656 | `xh-ZA` |
| 69296 | `is-IS` |
| 69476 | `id-ID` |
| 69488 | `uk-UA` |
| 69500 | `be-BY` |
| 69512 | `sl-SI` |
| 69536 | `lv-LV` |
| 69548 | `lt-LT` |
| 69560 | `fa-IR` |
| 69572 | `vi-VN` |
| 69584 | `hy-AM` |
| 69620 | `eu-ES` |
| 69632 | `mk-MK` |
| 69644 | `tn-ZA` |
| 69872 | `ta-IN` |
| 69680 | `af-ZA` |

### Constants / Known Patterns (31)
| Category | Value |
|---|---|
| hash | `hash::xxhash` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| code | `code::PEBx86` |
| registry | `registry::HKEY_USERS` |
| exception | `exception::C++ exception` |
| runtime | `runtime::msvc_date` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6034` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_runtime_error` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_rl` |
| runtime | `runtime::msvc_locale` |
| crypto | `crypto::crypto_provider` |

### Imports (238)
| EA | Name | Type | Refs |
|---|---|---|---|
| 10588 | __call_reportfault | DEBUG | 1 |
| 10881 | __invalid_parameter | DEBUG | 1 |
| 10924 | __invalid_parameter_noinfo | DEBUG | 26 |
| 10940 | __invoke_watson | DEBUG | 6 |
| 10983 | ___initstdio | DEBUG | 1 |
| 11098 | ___endstdio | DEBUG | 1 |
| 11137 | __lock_file | DEBUG | 1 |
| 11200 | __lock_file2 | DEBUG | 1 |
| 11248 | __unlock_file | DEBUG | 1 |
| 11306 | __unlock_file2 | DEBUG | 1 |
| 11351 | _LocaleUpdate._LocaleUpdate | DEBUG | 15 |
| 11487 | ___doserrno | DEBUG | 16 |
| 11506 | __dosmaperr | DEBUG | 3 |
| 11539 | __errno | DEBUG | 56 |
| 11558 | __get_errno_from_oserr | DEBUG | 2 |
| 11632 | __SEH_prolog4 | DEBUG | 15 |
| 11728 | __except_handler4 | DEBUG | 3 |
| 12163 | ___crtFlsSetValue | DEBUG | 1 |
| 12197 | ___crtInitializeCriticalSectionEx | DEBUG | 2 |
| 12243 | ___crtIsPackagedApp | DEBUG | 1 |
| 12321 | ___crtTerminateProcess | DEBUG | 2 |
| 12342 | ___crtUnhandledException | DEBUG | 2 |
| 12400 | _memset | DEBUG | 7 |
| 12544 | __fcloseall | DEBUG | 1 |
| 12701 | __fflush_nolock | DEBUG | 2 |
| 12771 | __flush | DEBUG | 2 |
| 12880 | _flsall | DEBUG | 2 |
| 13108 | __lock | DEBUG | 13 |
| 13160 | __mtinitlocknum | DEBUG | 1 |
| 13329 | __unlock | DEBUG | 14 |
| 13350 | _free | DEBUG | 129 |
| 13406 | __calloc_crt | DEBUG | 4 |
| 13478 | __malloc_crt | DEBUG | 2 |
| 13549 | ___crtCorExitProcess | DEBUG | 1 |
| 13651 | __exit | DEBUG | 1 |
| 13671 | __initterm | DEBUG | 2 |
| 13725 | _doexit | DEBUG | 1 |
| 14028 | __fileno | DEBUG | 3 |
| 14064 | __isatty | DEBUG | 1 |
| 14148 | ___addlocaleref | DEBUG | 2 |
| 14297 | ___freetlocinfo | DEBUG | 1 |
| 14643 | ___removelocaleref | DEBUG | 1 |
| 14803 | ___updatetlocinfo | DEBUG | 1 |
| 14931 | __updatetlocinfoEx_nolock | DEBUG | 2 |
| 15006 | ___initmbctable | DEBUG | 1 |
| 15036 | CPtoLocaleName | DEBUG | 2 |
| 15094 | getSystemCP | DEBUG | 2 |
| 15204 | setSBCS | DEBUG | 2 |
| 15299 | setSBUpLow | DEBUG | 1 |
| 15701 | ___updatetmbcinfo | DEBUG | 2 |
| 15867 | __setmbcp | DEBUG | 1 |
| 16291 | __setmbcp_nolock | DEBUG | 1 |
| 16782 | __isleadbyte_l | DEBUG | 4 |
| 16840 | _isleadbyte | DEBUG | 1 |
| 16864 | _strlen | DEBUG | 3 |
| 17003 | __getptd | DEBUG | 6 |
| 17027 | __getptd_noexit | DEBUG | 3 |
| 17328 | __aulldvrm | DEBUG | 0 |
| 17488 | __FindPESection | DEBUG | 6 |
| 17568 | __IsNonwritableInCurrentImage | DEBUG | 2 |
| 17760 | __ValidateImageBase | DEBUG | 3 |
| 18066 | @_EH4_CallFilterFunc@8 | DEBUG | 1 |
| 18089 | @_EH4_TransferToHandler@8 | DEBUG | 1 |
| 18139 | @_EH4_LocalUnwind@16 | DEBUG | 2 |
| 18162 | ___raise_securityfailure | DEBUG | 1 |
| 18223 | ___report_gsfailure | DEBUG | 1 |
| 18674 | ___isa_available_init | DEBUG | 1 |
| 19051 | __fclose_nolock | DEBUG | 1 |
| 19159 | _fclose | DEBUG | 1 |
| 19278 | __commit | DEBUG | 1 |
| 19750 | __write_nolock | DEBUG | 1 |
| 21899 | __FF_MSGBANNER | DEBUG | 3 |
| 21956 | __GET_RTERRMSG | DEBUG | 1 |
| 21992 | __NMSG_WRITE | DEBUG | 5 |
| 22437 | _malloc | DEBUG | 4 |
| 22583 | __calloc_impl | DEBUG | 1 |
| 22705 | ___onexitinit | DEBUG | 1 |
| 22752 | __callnewh | DEBUG | 3 |
| 22790 | ___free_lconv_mon | DEBUG | 1 |
| 23042 | ___free_lconv_num | DEBUG | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 4428 | sub_401d4c |
| 5199 | sub_40204f |
| 8150 | sub_402bd6 |
| 1189 | sub_4010a5 |
| 9072 | sub_402f70 |
| 6003 | sub_402373 |
| 7391 | PEBx86 |
| 8055 | sub_402b77 |
| 27114 | sub_4075ea |
| 30400 | sub_4082c0 |
| 31794 | sub_408832 |
| 17824 | sub_4051a0 |
| 10058 | sub_40334a |
| 9986 | sub_403302 |
| 2639 | sub_40164f |
| 12132 | sub_403b64 |
| 27720 | sub_407848 |
| 25136 | sub_406e30 |
| 1303 | sub_401117 |
| 1564 | EntryPoint |
| 1024 | sub_401000 |
| 1416 | sub_401188 |
| 5869 | sub_4022ed |
| 7766 | sub_402a56 |
| 2733 | sub_4016ad |
| 2852 | sub_401724 |
| 2097 | sub_401431 |
| 7457 | sub_402921 |
| 4264 | sub_401ca8 |
| 4346 | sub_401cfa |

### Decompilations (top 6)
#### 4428 — sub_401d4c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_401d4c(void)

{
    code *pcVar1;
    undefined2 uVar2;
    int32_t iVar3;
    int32_t iVar4;
    undefined4 extraout_ECX;
    undefined4 extraout_ECX_00;
    undefined4 extraout_ECX_01;
    undefined4 extraout_ECX_02;
    undefined4 extraout_ECX_03;
    undefined4 extraout_ECX_04;
    undefined4 uVar5;
    undefined4 uVar6;
    int32_t iVar7;
    undefined4 **ppuStack_950;
    undefined4 uStack_94c;
    undefined *puStack_948;
    undefined4 uStack_944;
    undefined4 uStack_940;
    undefined4 *puStack_93c;
    undefined4 auStack_928 [11];
    undefined auStack_8fc [20];
    undefined auStack_8e8 [76];
    undefined auStack_89c [68];
    undefined auStack_858 [8];
    undefined auStack_850 [19];
    undefined uStack_83d;
    undefined2 auStack_83c [9];
    undefined uStack_829;
    undefined2 auStack_828 [9];
    undefined uStack_815;
    undefined2 auStack_814 [9];
    undefined auStack_801 [2049];
    
    iVar7 = 0x800;
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        auStack_801[iVar4] = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    puStack_93c = 0x401d77;
    sub_40334a();
    puStack_93c = 0x401d83;
    sub_40334a();
    pcVar1 = advapi32.RegOpenKeyExW;
    puStack_93c = auStack_928;
    puStack_948 = auStack_89c;
    uVar6 = 1;
    uStack_940 = 1;
    uStack_944 = 0;
    uStack_94c = 0x80000002;
    auStack_928[0] = 0x80000002;
    ppuStack_950 = 0x401da8;
    iVar4 = (*advapi32.RegOpenKeyExW)();
    if (iVar4 == 0) {
        ppuStack_950 = 0x401db9;
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_00;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(&stack0xfffff6d4, uVar5, auStack_814), iVar4 != -1)) {
        iVar3 = 0;
        ppuStack_950 = 0x401df3;
        iVar4 = sub_403189();
        if (0 < iVar4) {
            do {
                ppuStack_950 = 0x401e04;
                uVar2 = sub_4032b2();
                auStack_814[iVar3] = uVar2;
                iVar3 = iVar3 + 1;
                ppuStack_950 = 0x401e19;
                iVar4 = sub_403189();
            } while (iVar3 < iVar4);
        }
        ppuStack_950 = 0x401e29;
        sub_40334a();
        ppuStack_950 = 0x401e39;
        iVar4 = sub_403255();
        if (iVar4 != 0) {
            return 1;
        }
    }
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        *(auStack_814 + iVar4 + -1) = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    ppuStack_950 = 0x401e62;
    sub_40334a();
    ppuStack_950 = 0x401e6e;
    sub_40334a();
    ppuStack_950 = &puStack_93c;
    puStack_93c = 0x80000002;
    iVar4 = (*pcVar1)(0x80000002, auStack_8e8, 0, 1);
    if (iVar4 == 0) {
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_02;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX_01;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(auStack_928, uVar5, auStack_828, uVar5), iVar4 != -1)) {
        iVar3 = 0;
        iVar4 = sub_403189();
        if (0 < iVar4) {
            do {
                uVar2 = sub_4032b2();
                auStack_828[iVar3] = uVar2;
                iVar3 = iVar3 + 1;
                iVar4 = sub_403189();
            } while (iVar3 < iVar4);
        }
        sub_40334a();
        iVar4 = sub_403255();
        if (iVar4 != 0) {
            return 1;
        }
    }
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        *(auStack_828 + iVar4 + -1) = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    sub_40334a();
    sub_40334a();
    ppuStack_950 = 0x80000002;
    iVar4 = (*pcVar1)(0x80000002, auStack_8fc, 0, 1, &ppuStack_950);
    if (iVar4 == 0) {
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_04;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX_03;
    }
    if ((iVar4 != 0) && (iVar4 = sub_402f70(&puStack_93c, uVar5, auStack_83c, uVar5), iVar4 != -1)) {
        iVar3 = 0;
    
```
#### 5199 — sub_40204f
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40204f(void)

{
    code *pcVar1;
    undefined2 uVar2;
    int32_t iVar3;
    int32_t iVar4;
    undefined4 uVar5;
    undefined4 extraout_ECX;
    undefined4 extraout_ECX_00;
    undefined4 extraout_ECX_01;
    undefined4 extraout_ECX_02;
    undefined4 extraout_ECX_03;
    undefined4 extraout_ECX_04;
    int32_t iVar6;
    int32_t iVar7;
    undefined2 *puStack_934;
    undefined4 **ppuStack_930;
    undefined4 uStack_92c;
    undefined *puStack_928;
    undefined4 uStack_924;
    undefined4 uStack_920;
    undefined4 *puStack_91c;
    undefined4 auStack_908 [3];
    undefined auStack_8fc [20];
    undefined auStack_8e8 [76];
    undefined auStack_89c [80];
    undefined2 auStack_84c [8];
    undefined auStack_83c [19];
    undefined uStack_829;
    undefined2 auStack_828 [9];
    undefined uStack_815;
    undefined2 auStack_814 [9];
    undefined auStack_801 [2049];
    
    iVar7 = 0x800;
    iVar6 = 0;
    iVar4 = 0x800;
    do {
        iVar3 = iVar4 + -1;
        auStack_801[iVar4] = 0;
        iVar4 = iVar3;
    } while (iVar3 != 0);
    puStack_91c = 0x40207b;
    sub_40334a();
    puStack_91c = 0x402087;
    sub_40334a();
    pcVar1 = advapi32.RegOpenKeyExW;
    puStack_91c = auStack_908;
    uStack_920 = 1;
    uStack_924 = 0;
    puStack_928 = auStack_89c;
    uStack_92c = 0x80000002;
    auStack_908[0] = 0x80000002;
    ppuStack_930 = 0x4020a9;
    iVar4 = (*advapi32.RegOpenKeyExW)();
    if (iVar4 == 0) {
        ppuStack_930 = 0x4020ba;
        iVar4 = sub_402f09();
        uVar5 = extraout_ECX_00;
    }
    else {
        iVar4 = 0;
        uVar5 = extraout_ECX;
    }
    if (iVar4 == 0) {
code_r0x0040214b:
        iVar4 = 0x800;
        do {
            iVar3 = iVar4 + -1;
            *(auStack_814 + iVar4 + -1) = 0;
            iVar4 = iVar3;
        } while (iVar3 != 0);
        ppuStack_930 = 0x402163;
        sub_40334a();
        ppuStack_930 = 0x40216f;
        sub_40334a();
        ppuStack_930 = &puStack_91c;
        puStack_91c = 0x80000002;
        puStack_934 = 0x1;
        iVar4 = (*pcVar1)(0x80000002, auStack_8e8, 0);
        if (iVar4 == 0) {
            iVar4 = sub_402f09();
            uVar5 = extraout_ECX_02;
        }
        else {
            iVar4 = 0;
            uVar5 = extraout_ECX_01;
        }
        if ((iVar4 != 0) && (iVar4 = sub_402f70(&uStack_920, uVar5, auStack_828, uVar5), iVar4 != -1)) {
            iVar3 = 0;
            iVar4 = sub_403189();
            if (0 < iVar4) {
                do {
                    uVar2 = sub_4032b2();
                    auStack_828[iVar3] = uVar2;
                    iVar3 = iVar3 + 1;
                    iVar4 = sub_403189();
                } while (iVar3 < iVar4);
            }
            sub_40334a();
            iVar4 = sub_403255();
            if (iVar4 != 0) goto code_r0x0040213e;
        }
        do {
            iVar4 = iVar7 + -1;
            *(auStack_828 + iVar7 + -1) = 0;
            iVar7 = iVar4;
        } while (iVar4 != 0);
        sub_40334a();
        sub_40334a();
        ppuStack_930 = 0x80000002;
        iVar4 = (*pcVar1)(0x80000002, auStack_8fc, 0, 1, &ppuStack_930);
        if (iVar4 == 0) {
            iVar4 = sub_402f09();
            uVar5 = extraout_ECX_04;
        }
        else {
            iVar4 = 0;
            uVar5 = extraout_ECX_03;
        }
        if ((iVar4 != 0) && (iVar4 = sub_402f70(&puStack_934, uVar5, auStack_83c, uVar5), iVar4 != -1)) {
            iVar4 = sub_403189();
            if (0 < iVar4) {
                do {
                    uVar2 = sub_4032b2();
                    auStack_84c[iVar6] = uVar2;
                    iVar6 = iVar6 + 1;
                    iVar4 = sub_403189();
                } while (iVar6 < iVar4);
            }
            sub_40334a();
            iVar4 = sub_403255();
            if (iVar4 != 0) goto code_r0x0040213e;
        }
        uVar5 = 0;
    }
    else {
        puStack_934 = auSta
```
#### 8150 — sub_402bd6
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_402bd6(void)

{
    int32_t iVar1;
    code *pcVar2;
    undefined4 uVar3;
    int32_t iVar4;
    undefined auStack_160 [36];
    undefined auStack_13c [36];
    undefined auStack_118 [32];
    undefined auStack_f8 [28];
    undefined auStack_dc [56];
    undefined auStack_a4 [28];
    undefined auStack_88 [52];
    undefined auStack_54 [24];
    undefined auStack_3c [24];
    undefined auStack_24 [16];
    undefined auStack_14 [12];
    undefined *puStack_8;
    
    sub_40334a();
    sub_403302();
    iVar1 = (*kernel32.LoadLibraryW)(auStack_3c);
    if ((iVar1 != 0) && (pcVar2 = (*kernel32.GetProcAddress)(iVar1, auStack_14), pcVar2 != 0x0)) {
        (*pcVar2)(1);
    }
    sub_40334a();
    sub_40334a();
    pcVar2 = kernel32.GetModuleHandleW;
    iVar1 = (*kernel32.GetModuleHandleW)(auStack_88);
    if ((iVar1 == 0) && (iVar1 = (*pcVar2)(auStack_a4), iVar1 == 0)) {
        sub_40334a();
        pcVar2 = user32.FindWindowW;
        iVar4 = 0;
        iVar1 = (*user32.FindWindowW)(auStack_24, 0);
        if (iVar1 == 0) {
            sub_40334a();
            iVar1 = (*pcVar2)(auStack_13c, 0);
            if (iVar1 == 0) {
                sub_40334a();
                iVar1 = (*pcVar2)(auStack_160, 0);
                if (iVar1 == 0) {
                    sub_40334a();
                    iVar1 = (*pcVar2)(auStack_f8, 0);
                    if (iVar1 == 0) {
                        sub_40334a();
                        iVar1 = (*pcVar2)(auStack_dc, 0);
                        if (iVar1 == 0) {
                            sub_40334a();
                            iVar1 = (*pcVar2)(auStack_54, 0);
                            if (((((iVar1 == 0) && (([0x0x7ffe02d4] & 3) == 0)) && (iVar1 = sub_4026c2(), iVar1 == 0)) &&
                                (((iVar1 = sub_4019ac(), iVar1 == 0 && (iVar1 = sub_401a61(), iVar1 == 0)) &&
                                 ((iVar1 = sub_401d4c(), iVar1 == 0 &&
                                  ((iVar1 = sub_402373(), iVar1 == 0 && (iVar1 = sub_40204f(), iVar1 == 0)))))))) &&
                               ((iVar1 = sub_402543(), iVar1 == 0 && (iVar1 = sub_40258b(), iVar1 == 0)))) {
                                sub_40334a();
                                puStack_8 = auStack_118;
                                do {
                                    iVar1 = sub_401724();
                                    if (iVar1 != 0) {
                                        return 1;
                                    }
                                    iVar4 = iVar4 + 1;
                                } while (iVar4 == 0);
                                iVar1 = sub_4025d3();
                                if ((((iVar1 == 0) && (iVar1 = sub_4022ed(), iVar1 == 0)) &&
                                    (iVar1 = sub_402b15(), iVar1 == 0)) && (iVar1 = sub_402b9f(), iVar1 == 0)) {
                                    (*kernel32.AddVectoredExceptionHandler)(1, sub_402b77);
                                    [0x0x417468] = 1;
                                    pcVar2 = swi(3);
                                    uVar3 = (*pcVar2)();
                                    return uVar3;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 1;
}

```

### Structures (20)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 224 |
| OptionalHeader | 248 |
| Sections | 472 |
| advapi32.FT | 58368 |
| kernel32.FT | 58412 |
| shell32.FT | 58692 |
| shlwapi.FT | 58700 |
| user32.FT | 58712 |
| LoadConfigurationTable | 77544 |
| ImportTable | 78220 |
| advapi32.OFT | 78340 |
| kernel32.OFT | 78384 |
| shell32.OFT | 78664 |
| shlwapi.OFT | 78672 |
| user32.OFT | 78684 |
| ImportNames | 78692 |
| SecurityCookie | 83968 |
| Relocations | 103424 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 27 · duration_s: 1.03

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get session user name | T1033:System Owner/User Discovery, T1087:Account Discovery |  |
| check for PEB NtGlobalFlag flag |  | B0001.036:Debugger Detection |
| execute anti-debugging instructions |  | B0001.034:Debugger Detection |
| hash data with CRC32 |  | C0032.001:Checksum |
| hash data via WinCrypt |  | C0029:Cryptographic Hash |

## PE Imports / Signals
import_count: 83

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| check_debugger | IsDebuggerPresent | T1622 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@167971 len=2 |
| contains_base64 | - | $a@55852 len=12 |
| Advapi_Hash_API | - | $advapi32@77130 len=12; $CryptCreateHash@77012 len=15; $CryptHashData@77050 len=13; $CryptAcquireContext@76966 len=19 |
| CRC32_poly_Constant | - | $c0@1226 len=4 |
| maldoc_find_kernel32_base_method_1 | - | $a2@7391 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@1416 len=4 |
| SEH__vectored | - | $@76218 len=27; $@76138 len=30 |
| SEH_Save | - | $a@11637 len=7 |
| SEH_Init | - | $a@11694 len=6; $b@17867 len=7 |
| anti_dbg | - | $d1@76904 len=12; $c2@76338 len=17; $c3@76868 len=17 |
| inject_thread | - | $c1@76020 len=11; $c2@75984 len=14; $c3@72624 len=20; $c7@76020 len=11 |
| win_registry | - | $f1@77130 len=12; $c3@77118 len=11; $c6@77118 len=11 |
| win_files_operation | - | $f1@76904 len=12; $c1@75686 len=9; $c2@76816 len=14; $c3@75686 len=9; $c4@75698 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505",
  "family": "ransomware.shaitan/troldesh",
  "imphash": "b53f6e0803fd24f3dd50f45f3b463d3f",
  "generated_at": "2026-08-12T21:21:56.683281+00:00",
  "string_count": 24,
  "strings": [
    "wpespy.dll",
    "pstorec.dll",
    "avghookx.dll",
    "HARDWARE\\DESCRIPTION\\System",
    "avghooka.dll",
    "dwmapi.dll",
    "VideoBiosVersion",
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SystemBiosVersion",
    "ollydbg.exe",
    "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
    "WinDbgFrameClass",
    "Identifier",
    "ProcessHacker.exe",
    "tcpview.exe",
    "drivers\\vmhgfs.sys",
    "autoruns.exe",
    "Immunity Debugger",
    "C:\\InsideTm",
    "autorunsc.exe",
    "filemon.exe",
    "Zeta Debugger",
    "ntdll.dll",
    "procmon.exe"
  ],
  "rule_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yar",
  "sigma_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/rule.yml",
  "iocs_path": "/opt/samples/logs/c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505/iocs.json",
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
    "utc": "2026-08-12 21:21:56 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 579 · per_category: `{"decoded_strings": 70, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 509}`

### High-signal FLOSS
- `kernel32.dll`
- `\\.\PhysicalDrive0`

### FLOSS sample
- `wpespy.dll`
- `pstorec.dll`
- `avghookx.dll`
- `HARDWARE\DESCRIPTION\System`
- `avghooka.dll`
- `dwmapi.dll`
- `VideoBiosVersion`
- `sample.`
- `SOFTWARE\VMware, Inc.\VMware Tools`
- `SystemBiosVersion`
- `ollydbg.exe`
- `HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`
- `WinDbgFrameClass`
- `Identifier`
- `ProcessHacker.exe`
- `\SAMPLE`
- `tcpview.exe`
- `drivers\vmhgfs.sys`
- `SANDBOX`
- `autoruns.exe`
- `Immunity Debugger`
- `C:\InsideTm`
- `autorunsc.exe`
- `filemon.exe`
- `Zeta Debugger`
- `ntdll.dll`
- `procmon.exe`
- `kernel32.dll`
- `Rock Debugger`
- `procexp.exe`
- `idaq.exe`
- `idaq64.exe`
- `ObsidianGUI`
- `drivers\vmmouse.sys`
- `ImmunityDebugger.exe`
- `\\.\PhysicalDrive0`
- `Wireshark.exe`
- `dumpcap.exe`
- `HookExplorer.exe`
- `ImportREC.exe`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040121c
```asm
┌ 426: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_130h @ ebp-0x130
│           ; var int32_t var_338h @ ebp-0x338
│           0x0040121c      55             push ebp
│           0x0040121d      8bec           mov ebp, esp
│           0x0040121f      81ec38030000   sub esp, 0x338
│           0x00401225      8d55e0         lea edx, [var_20h]
│           0x00401228      53             push ebx
│           0x00401229      56             push esi
│           0x0040122a      57             push edi
│           0x0040122b      6a1c           push 0x1c                   ; 28
│           0x0040122d      59             pop ecx
│           0x0040122e      e817210000     call 0x40334a
│           0x00401233      8d45e0         lea eax, [var_20h]
│           0x00401236      50             push eax
│           0x00401237      ff15f4f04000   call dword [sym.imp.KERNEL32.dll_GetModuleHandleW] ; 0x40f0f4 ; "r@\x01" ; HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
│           0x0040123d      85c0           test eax, eax
│       ┌─< 0x0040123f      0f8579010000   jne 0x4013be
│       │   0x00401245      ff15fcf04000   call dword [sym.imp.KERNEL32.dll_GetProcessHeap] ; 0x40f0fc ; "L@\x01" ; HANDLE GetProcessHeap(void)
│       │   0x0040124b      8325c08741..   and dword [0x4187c0], 0     ; [0x4187c0:4]=0
│       │   0x00401252      8325c48741..   and dword [0x4187c4], 0     ; [0x4187c4:4]=0
│       │   0x00401259      a3c8874100     mov dword [0x4187c8], eax   ; [0x4187c8:4]=0
│       │   0x0040125e      e873190000     call 0x402bd6
│       │   0x00401263      85c0           test eax, eax
│      ┌──< 0x00401265      0f8553010000   jne 0x4013be
│      ││   0x0040126b      2145fc         and dword [var_4h], eax
│      ││   0x0040126e      8d85c8fcffff   lea eax, [var_338h]
│      ││   0x00401274      6804010000     push 0x104                  ; 260
│      ││   0x00401279      50             push eax
│      ││   0x0040127a      6a00           push 0
│      ││   0x0040127c      ff1508f14000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameW] ; 0x40f108 ; DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
│      ││   0x00401282      51             push ecx
│      ││   0x00401283      8d55e8         lea edx, [var_18h]
│      ││   0x00401286      8d8dc8fcffff   lea ecx, [var_338h]
│      ││   0x0040128c      e8f7feffff     call 0x401188
│      ││   0x00401291      85c0           test eax, eax
│     ┌───< 0x00401293      0f8425010000   je 0x4013be
│     │││   0x00401299      33c9           xor ecx, ecx
│    ┌────> 0x0040129b      8a81b82c4100   mov al, byte [ecx + 0x412cb8]
│    ╎│││   0x004012a1     
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!Process32NextW`
  - `KERNEL32.dll!CreateToolhelp32Snapshot`
  - `KERNEL32.dll!GetThreadContext`
  - `KERNEL32.dll!RemoveVectoredExceptionHandler`
  - `KERNEL32.dll!SetUnhandledExceptionFilter`
  - `USER32.dll!FindWindowW`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!RegQueryValueExW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!GetUserNameW`
  - `ADVAPI32.dll!CryptHashData`
  - `SHLWAPI.dll!PathFileExistsW`
  - `SHLWAPI.dll!PathAppendW`
  - `SHELL32.dll!SHGetFolderPathW`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786623995.3991911}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786623996.0141988}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786623996.6185472}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786623998.1049623}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786623998.605}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786623998.6088002}`
- `{"source": "publish_report_v2", "ts": 1786624656.8851078}`
- `{"source": "publish_report_v2_technical", "ts": 1786624887.2101548}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786676293.2958257}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786676293.3018334}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786676293.303589}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786676293.3079195}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786676293.3094108}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786676298.3604174}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786676298.898508}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786676299.6026692}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786676300.2734358}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786676300.7836185}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786676301.2838726}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786676302.9235346}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786676303.439224}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786676304.0770893}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786676304.5846245}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786676305.088508}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786676305.590419}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786676306.2059102}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786676306.8100882}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786676308.2913785}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786676308.7923884}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786676308.7955375}`
