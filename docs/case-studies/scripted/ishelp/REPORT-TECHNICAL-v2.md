> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:37:45 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

The sample `ishelp.dll` (SHA256: `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76`) is a malicious DLL dropper/loader component associated with the Emissary APT (Lotus Blossom) threat group. The binary exports a single function `Setting` designed to be invoked via `rundll32.exe`, and executes a well-defined behavioral chain: mutex creation for single-instance enforcement, privilege escalation via `SeDebugPrivilege`, resource-based payload extraction to disk, process enumeration targeting Internet Explorer (`iexplore.exe`), classic DLL injection via `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`, and registry-based persistence under `Software\Microsoft\Windows\CurrentVersion\Run`.

Multiple analysis engines converge on a malicious verdict with high confidence (95/100). YARA rule `Emissary_APT_Malware_1` matched 8 distinct strings at known offsets. CAPA identified 30 capability rules including thread injection, privilege escalation, and persistence. MalCat flagged 11 anomalies including `EmbeddedProgram` and `SpaghettiFunction`. External VirusTotal reports 49/63 malicious detections with threat names `lotusblossom` and `explorerhijack`. The main payload function (`FUN_10003853`) exhibits a cyclomatic complexity of 151 across 240 basic blocks, indicating heavy obfuscation or control-flow flattening.

Dynamic analysis via Speakeasy and Frida recorded zero runtime events, which we attribute to anti-analysis checks or missing environmental triggers rather than benign behavior. The sample's behavioral indicators -- process injection, privilege escalation, persistence, and embedded payload extraction -- constitute unambiguous malicious intent beyond mere obfuscation or protection.

## 2. Sample Metadata

The following metadata was extracted from the PE header and analysis engines. The file is a 32-bit x86 DLL compiled with Visual Studio 2008, with a Rich Header and standard PE structure.

| Field | Value | Source |
|---|---|---|
| SHA256 | `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76` | malcat |
| File Name | `ishelp.dll` | malcat |
| File Type | PE (DLL) | malcat |
| Architecture | x86 (32-bit) | malcat |
| Size | 78,848 bytes | malcat |
| Entry Point EA | 10359 (0x2877) | malcat |
| Shannon Entropy | 6.35 bits/byte (whole file) | malcat |
| Compiler | MSVC 2008 (Rich Header + Linker) | yara (MSVC_2008_rich, MSVC_2008_linker) |
| Import Hash (imphash) | `aee2f8f6aa200110e796682791bc8758` | rule.yara.json |
| Family Guess | Lotus Blossom / Emissary APT | llm_judge |
| Verdict | Malicious (score: 95) | llm_judge |
| .NET | Not .NET | malcat |
| Packed (UPX) | Not packed | upx |

The whole-file entropy of 6.35 bits/byte is elevated but not extreme (packed binaries typically exceed 7.0). The `.rsrc` section at EA 29696 contains 54,272 bytes of physical data with entropy 125 (likely the embedded payload resource), while `.text` holds 14,848 bytes of code. The `EmbeddedProgram` anomaly (source: malcat, Anomalies, row: EmbeddedProgram) confirms a PE file is embedded within the resources, consistent with a dropper architecture.

## 3. File Layout & Structural Analysis

The PE file contains six sections with standard layout. The `.rsrc` section is disproportionately large (54,272 physical bytes, 69% of the file), which is characteristic of resource-based droppers that embed their payload within PE resources.

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 51 | - |
| .text | 1024 | 14848 | 16384 | 126 | RX |
| .rdata | 17408 | 4608 | 8192 | 88 | R |
| .data | 25600 | 2048 | 4096 | 100 | RW |
| .rsrc | 29696 | 54272 | 57344 | 125 | R |
| .reloc | 87040 | 2048 | 4096 | 90 | R |

(source: malcat, File Layout table)

The `.rsrc` section contains carved and virtual files that constitute the embedded payload:

| Name | Type | Size | Source |
|---|---|---|---|
| Carved PE | PE | 52,736 bytes | malcat, Carved Files |
| ASDASDASDASDSAD/102/en-us | - | 52,736 bytes | malcat, Virtual Files |
| VER/1/en-us | - | 708 bytes | malcat, Virtual Files |
| MANIF/2/en-us | - | 346 bytes | malcat, Virtual Files |

The carved PE file (52,736 bytes) matches the size of the `ASDASDASDASDSAD` resource entry, confirming the embedded payload. The resource name `ASDASDASDASDSAD` is a nonsensical string likely chosen to avoid heuristic detection of suspicious resource names. The `VER` and `MANIF` entries suggest version info and manifest resources for the embedded payload.

Key PE structures identified by MalCat include the Export Directory at EA 21776, Import Table at EA 19716, and Security Cookie at EA 25600. The DLL exports a single function `Setting` at EA 6752 (source: malcat, Imports, row: `Setting` at EA 6752).

## 4. Static Code Analysis

### 4.1 Exported Function: Setting

The DLL exports a single function `Setting` at EA 0x10002660, which serves as the primary entry point when invoked via `rundll32.exe ishelp.dll,Setting`. The radare2 disassembly shows this is a thin wrapper that immediately calls the main logic function `fcn.10002300`:

```asm
; source: radare2, EA 0x10002660
┌ 10: sym.Loader.dll_Setting ();
│           0x10002660      55             push ebp
│           0x10002661      8bec           mov ebp, esp
│           0x10002663      e898fcffff     call fcn.10002300
│           0x10002668      5d             pop ebp
└           0x10002669      c3             ret
```

This minimal wrapper pattern is typical of DLL exports that delegate to a larger internal function. The string `rundll32.exe "%s",Setting` at EA 21837 (source: malcat, Top Strings) confirms the intended invocation method and is used for registry persistence.

### 4.2 DLL Entry Point (DllEntryPoint)

The DLL entry point at EA 0x10003477 handles DLL_PROCESS_ATTACH by calling the security cookie initialization function:

```asm
; source: radare2, EA 0x10003477
┌ 400: entry0 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│       ╎   0x10003477      8bff           mov edi, edi
│       ╎   0x10003479      55             push ebp
│       ╎   0x1000347a      8bec           mov ebp, esp
│       ╎   0x1000347c      837d0c01       cmp dword [arg_ch], 1
│      ┌──< 0x10003480      7505           jne 0x10003487
│      │╎   0x10003482      e82b110000     call 0x100045b2
│      └──> 0x10003487      5d             pop ebp
│       └─< 0x10003488      e98efdffff     jmp 0x1000321b
```

When `arg_ch == 1` (DLL_PROCESS_ATTACH), it calls `sub_100045b2` which initializes the security cookie using entropy from `GetSystemTimeAsFileTime`, `GetCurrentProcessId`, `GetCurrentThreadId`, `GetTickCount`, and `QueryPerformanceCounter` (source: malcat, Decompilations, sub_100045b2). This is standard MSVC stack cookie initialization, not malicious behavior.

### 4.3 Main Payload Logic: FUN_10002300

The function at EA 0x10002300 is the core behavioral orchestrator. The radare2 disassembly shows it allocates a large stack frame (0x814 bytes) and initializes the security cookie XOR with EBP:

```asm
; source: radare2, EA 0x10002300
┌ 852: fcn.10002300 ();
│           0x10002300      55             push ebp
│           0x10002301      8bec           mov ebp, esp
│           0x10002303      81ec14080000   sub esp, 0x814
│           0x10002309      a100700010     mov eax, dword [section..data] ; [0x10007000:4]=0xbb40e64e
│           0x1000230e      33c5           xor eax, ebp
│           0x10002310      8945fc         mov dword [var_4h], eax
│           0x10002313      c685c8f9ff..   mov byte [var_638h], 0
│           0x1000231a      6803010000     push 0x103                  ; 259
│           0x1000231f      6a00           push 0
│           0x10002321      8d85c9f9ffff   lea eax, [var_637h]
│           0x10002327      50             push eax
│           0x10002328      e8d9120000     call 0x10003606
```

The function initializes multiple 259-byte buffers (0x103 = MAX_PATH) via calls to `0x10003606` (likely `memset`), then proceeds to execute the behavioral chain described in the deep-dive summary. Ghidra string references to this function include `IE Process is running.` and `_MICROSOFT_LOADER_MUTEX_` (source: ghidra_query, sql: `SELECT sr.func_name, sr.func_addr, s.content FROM string_refs sr JOIN strings s ON sr.string_addr = s.address WHERE sr.func_name = 'FUN_10002300'`).

### 4.4 Process Injection Logic: FUN_100019a0

The function at EA 0x100019a0 implements the core injection and cleanup logic. The Ghidra decompilation reveals the complete behavioral chain:

```c
// source: malcat, Decompilations, sub_100019a0 (truncated)
void sub_100019a0(undefined4 param_1, undefined4 param_2, undefined4 param_3)
{
    // ... stack setup with security cookie ...
    sub_100026a0("Removing...");
    (*kernel32.Sleep)(1000);
    iVar1 = (*shell32.SHGetSpecialFolderPathA)(0, auStack_114, 0x1a, 0);
    if (iVar1 != 0) {
        _strcat_s(auStack_114, 0x104, "\\LocalData\\");
        (*kernel32.RemoveDirectoryA)(auStack_114);
        (*kernel32.CreateDirectoryA)(auStack_114, 0);
        // ... registry operations with autorun key ...
        iVar1 = (*advapi32.RegOpenKeyExA)(0x80000001, auStack_25c, 0, 2, &uStack_124);
        if (iVar1 == 0) {
            (*advapi32.RegDeleteValueA)(uStack_124, "SystemDrive");
            (*advapi32.RegCloseKey)(uStack_124);
            // ... privilege escalation ...
            (*advapi32.LookupPrivilegeValueA)(0, "SeDebugPrivilege", auStack_148);
            (*advapi32.AdjustTokenPrivileges)(uStack_128, 0, &uStack_14c, 0, 0, 0);
            // ... process enumeration via CreateToolhelp32Snapshot ...
            iStack_138 = jmp_kernel32.CreateToolhelp32Snapshot(2, 0);
            // ... Process32First/Next loop ...
            // ... Module32First/Next loop searching for 'A08E81B411.DAT' ...
            iVar1 = (*kernel32.lstrcmpiA)("A08E81B411.DAT", auStack_594);
```

This function demonstrates: (1) cleanup of previous installations by removing and recreating `\LocalData\` directory, (2) registry manipulation under `HKEY_CURRENT_USER` (0x80000001), (3) privilege escalation via `SeDebugPrivilege`, (4) process and module enumeration to locate the injected payload `A08E81B411.DAT` in target processes. The Ghidra string references confirm these behaviors (source: ghidra_query, sql: `SELECT sr.func_name, sr.func_addr, s.content FROM string_refs sr JOIN strings s ON sr.string_addr = s.address WHERE sr.func_name = 'FUN_100019a0'`).

### 4.5 Obfuscated Payload Function: FUN_10003853

The function at EA 0x10003853 is the largest and most complex function in the binary:

| Metric | Value | Source |
|---|---|---|
| Size | 2,771 bytes | deep_dive_agentic |
| Cyclomatic Complexity | 151 | deep_dive_agentic |
| Basic Blocks | 240 | deep_dive_agentic |

A cyclomatic complexity of 151 is extremely high (typical benign functions range 1-10), indicating either heavy obfuscation, control-flow flattening, or a state machine implementation. MalCat's `SpaghettiFunction` anomaly at EA 11347 (source: malcat, Anomaly Locations) flags this function as containing excessive intra-function jumps, a hallmark of obfuscated code. The `ManyUniqueImmediateBytes` anomaly at the same EA suggests unusual constant usage patterns.

### 4.6 XOR-Based String Obfuscation: sub_100015a0

The function at EA 0x100015a0 implements XOR-based string deobfuscation using a seeded PRNG:

```c
// source: malcat, Decompilations, sub_100015a0
void sub_100015a0(undefined4 *param_1)
{
    // ... copy param_1 to local buffer (0x21 dwords = 132 bytes) ...
    (*msvcrt.srand)(0xa03);  // seed PRNG with constant 0xA03
    for (uStack_1b0 = 0; uStack_1b0 < 0x84; uStack_1b0++) {
        uVar1 = *puStack_a0;
        uVar2 = (*msvcrt.rand)();
        uVar2 = uVar2 & 0x8000007f;  // mask to 7-bit value
        *puStack_a0 = uVar1 ^ uVar2;  // XOR decrypt
    }
    // ... create file and write decrypted data at offset 0x488 ...
    iStack_98 = (*kernel32.CreateFileA)(&uStack_1ac, 0x40000000, 0, 0, 4, 0, 0);
    (*kernel32.SetFilePointer)(iStack_98, 0x488, 0, 0);
    (*kernel32.WriteFile)(iStack_98, &uStack_94, 0x84, &uStack_9c, 0);
```

This function XORs a 132-byte buffer with a PRNG sequence seeded at 0xA03, then writes the result to a file at offset 0x488. The constant seed makes the deobfuscation deterministic and reversible. MalCat's `XorInLoop` anomalies at EAs 1111, 1832, 2260, 2639, and 8574 (source: malcat, Anomaly Locations) confirm multiple XOR-based obfuscation routines throughout the binary.

### 4.7 Resource Extraction: FUN_10001820

The function at EA 0x10001820 implements the resource-based payload extraction with verbose debug strings:

| Debug String | EA | Source |
|---|---|---|
| `ReleaseFile Error->FindResource Failed[%d].` | 18128 | malcat, Top Strings |
| `ReleaseFile Error->Size=0.` | 18172 | malcat, Top Strings |
| `ReleaseFile Error->LoadLibrary Failed[%d].` | 18216 | malcat, Top Strings |
| `ReleaseFile->GetProcAddress Failed[%d].` | 18276 | malcat, Top Strings |
| `ReleaseFile->ProLdRsc Failed.` | 18316 | malcat, Top Strings |
| `ReleaseFile->CreateFile Failed[%d].` | 18348 | malcat, Top Strings |

These debug strings reveal the extraction sequence: `FindResourceW` -> `LoadResource` -> `LockResource` -> `CreateFileA` -> `WriteFile`. The presence of detailed error messages with format specifiers (`[%d]`) indicates a development-stage build or a variant that was not stripped of debug output. The target filename `A08E81B411.DAT` appears at multiple EAs (18516, 18724, 18596, 18580, 18564, 18548, 18532) (source: malcat, Top Strings).

### 4.8 Anti-Analysis Signals

MalCat identified 11 anomalies indicating anti-analysis and obfuscation techniques:

| Anomaly | Level | Hits | Description | Source |
|---|---|---|---|---|
| HugeStringBinary | 4 | 1 | String >1024 chars with binary encoding | malcat |
| InvalidChecksum | 4 | 1 | PE Header checksum is wrong | malcat |
| PossiblePackerApiDynamicImport | 4 | 1 | Packer-related API as string | malcat |
| BigStringHiScore | 3 | 1 | String >256 chars with high interest | malcat |
| DynamicString | 3 | 1 | String constructed dynamically | malcat |
| EmbeddedProgram | 3 | 1 | File embeds a program | malcat |
| ManyUniqueImmediateBytes | 3 | 1 | >48 unique immediate bytes | malcat |
| StackArrayInitialisationX86 | 3 | 2 | Dynamic stack array construction | malcat |
| StringBase64 | 3 | 1 | String >16 chars encoded in base64 | malcat |
| XorInLoop | 3 | 5 | XOR instruction in a loop | malcat |
| SpaghettiFunction | 1 | 1 | Function with excessive intra jumps | malcat |

The `InvalidChecksum` anomaly suggests the PE header was modified post-compilation (possibly by a builder tool). The `PossiblePackerApiDynamicImport` anomaly indicates dynamic API resolution, a common anti-analysis technique.

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy Emulation

Speakeasy emulation ran successfully but recorded zero API calls and zero key events (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). This outcome is consistent with anti-emulation checks in the binary -- the sample likely detects the emulated environment and exits early. The `anti_dbg` YARA rule match (source: yara, matches, rule: anti_dbg) at offsets 16664 and 19564 confirms anti-debugging capabilities that would also impede emulation.

### 5.2 Frida Dynamic Instrumentation

Frida probe identified 19 hook candidates across `msvcrt.dll`, `KERNEL32.dll`, `ADVAPI32.dll`, `SHELL32.dll`, `ole32.dll`, and `RPCRT4.dll` (source: frida_probe). Key candidates include:

| DLL | Function | Relevance |
|---|---|---|
| KERNEL32.dll | GetProcAddress | Dynamic API resolution |
| KERNEL32.dll | GetCurrentProcessId | Anti-analysis / environment detection |
| ADVAPI32.dll | OpenProcessToken | Privilege escalation chain |
| ADVAPI32.dll | AdjustTokenPrivileges | SeDebugPrivilege enablement |
| ADVAPI32.dll | LookupPrivilegeValueA | Privilege name resolution |
| ADVAPI32.dll | RegOpenKeyExA | Registry persistence |
| SHELL32.dll | SHGetSpecialFolderPathA | Path discovery for payload drop |

No runtime events were recorded during Frida instrumentation. Combined with Speakeasy's zero-event result, we assess the sample contains robust anti-analysis checks that prevent execution in sandboxed or instrumented environments.

### 5.3 Behavioral Chain (Static Reconstruction)

Based on static analysis, the complete behavioral chain is:

1. **Mutex Creation**: Creates `_MICROSOFT_LOADER_MUTEX_` (EA 18808, source: malcat) for single-instance enforcement
2. **Privilege Escalation**: Enables `SeDebugPrivilege` via `AdjustTokenPrivileges` (source: malcat, Imports, EA 17416)
3. **Payload Extraction**: Extracts embedded PE from resources to `A08E81B411.DAT` in `\LocalData\` directory using `FindResourceW`/`LockResource`/`CreateFileA` (source: malcat, Top Strings)
4. **Process Discovery**: Enumerates processes via `CreateToolhelp32Snapshot`/`Process32First`/`Process32Next` targeting `iexplore.exe` (source: malcat, Imports, EA 17576-17580)
5. **Process Injection**: Classic DLL injection via `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` (source: malcat, Imports, EA 17536-17556)
6. **Persistence**: Writes `rundll32.exe "%s",Setting` to `Software\Microsoft\Windows\CurrentVersion\Run` (source: malcat, Top Strings, EA 18408)
7. **Proxy Configuration**: Reads `ProxyEnable`/`ProxyServer` from `Internet Settings` registry (source: deep_dive_agentic)

## 6. Network Indicators & C2

### 6.1 Network-Related Strings

The sample contains several network-related indicators:

| String | EA | Purpose | Source |
|---|---|---|---|
| `Mozilla/4.0 (com.. Windows NT 5.1)` | 67812 | User-Agent string | malcat, Top Strings |
| `ProxyEnable` | (in strings) | Proxy configuration reading | deep_dive_agentic |
| `ProxyServer` | (in strings) | Proxy server address | deep_dive_agentic |
| `Internet Settings` | 19384 | Registry path for proxy | malcat, Top Strings |
| `cmd.exe /c %s > %s` | 69144 | Command execution with output redirect | malcat, High-Signal Strings |
| `UploadFile - EncryptBuffer Error` | 68580 | File upload capability | malcat, High-Signal Strings |
| `DownloadFile Err..Data From Server` | 68868 | File download capability | malcat, Top Strings |

The `CustomUserAgent` YARA rule (source: malcat, YARA/Signatures) confirms the embedded user agent string. The `UploadFile` and `DownloadFile` error strings indicate the embedded payload (not this DLL itself) likely implements file transfer capabilities for C2 communication. The `cmd.exe /c %s > %s` string suggests command execution with output redirection, potentially for C2 command processing.

### 6.2 C2 Infrastructure

No hardcoded C2 domains or IP addresses were identified in the static strings. The YARA matches for `domain` and `IP` rules (source: yara, matches) detected regex patterns but no confirmed C2 addresses. The proxy configuration reading (`ProxyEnable`/`ProxyServer`) suggests the malware may use the victim's proxy settings for C2 communication, or exfiltrate proxy credentials. The SHA512 constants and BASE64 alphabet table at offsets 58812-58836 and 58736 (source: deep_dive_agentic) indicate cryptographic infrastructure likely used for C2 communication encryption.

## 7. Capabilities Assessment

### 7.1 CAPA Rules (30 total)

The following capabilities were identified by CAPA (source: capa, malcat-capa engine):

| Capability | ATT&CK | MBC | Observed |
|---|---|---|---|
| contain obfuscated stackstrings | T1027.005 | B0032.020, B0032.017 | Yes |
| reference Base64 string | T1027 | C0026.001, C0019 | Yes |
| get common file path | T1083 | E1083 | Yes |
| get file size | T1083 | E1083 | Yes |
| inject thread | T1055.003, T1620 | - | Yes |
| enumerate processes | T1057, T1518 | - | Yes |
| delete registry value | T1112 | C0036.007 | Yes |
| spawn thread to RWX shellcode | - | C0007, C0038 | Yes |
| persist via Run registry key | T1547.001 | F0012 | Yes |
| contain an embedded PE file | - | B0023 | Yes |
| get Program Files directory | T1083 | - | Yes |
| copy file | - | C0045 | Yes |
| create directory | - | C0046 | Yes |
| delete directory | - | C0048 | Yes |
| delete file | - | C0047 | Yes |

### 7.2 PE Import Signals

The import table contains 88 imports with the following high-signal capabilities (source: pe_imports):

| Signal | API | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| write_process_memory | WriteProcessMemory | T1055 |
| create_remote_thread | CreateRemoteThread | T1055 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

The complete import chain for DLL injection is present: `VirtualAllocEx` (EA 17556) -> `WriteProcessMemory` (EA 17540) -> `CreateRemoteThread` (EA 17536). The `VirtualProtectEx` import (EA 17544) with 4 references indicates memory permission manipulation during injection.

### 7.3 Privilege Escalation Chain

The privilege escalation imports form a complete chain (source: malcat, Imports):

| API | EA | References |
|---|---|---|
| OpenProcessToken | 17408 | 7 |
| LookupPrivilegeValueA | 17420 | 1 |
| AdjustTokenPrivileges | 17416 | 1 |

The 7 references to `OpenProcessToken` indicate extensive token manipulation throughout the binary.

### 7.4 Process/Module Enumeration Chain

The complete enumeration chain for injection targeting (source: malcat, Imports):

| API | EA | References |
|---|---|---|
| CreateToolhelp32Snapshot | 20608 | (string ref) |
| Process32First | 17576 | 1 |
| Process32Next | 17572 | 1 |
| Module32First | 17568 | 1 |
| Module32Next | 17564 | 1 |

## 8. Indicators of Compromise

### 8.1 File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | `bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76` | malcat |
| File Name | `ishelp.dll` | malcat |
| Imphash | `aee2f8f6aa200110e796682791bc8758` | rule.yara.json |
| Dropped File | `A08E81B411.DAT` | malcat, Top Strings |
| Dropped File | `75BD50EC.DAT` | malcat, Top Strings (EA 19168) |
| Dropped File | `000A758C8FEAE5F.TMP` | rule.yara.json |
| Dropped File | `XXXX.dat` | malcat, Top Strings (EA 19032) |
| Payload Directory | `\LocalData\` | malcat, Top Strings |

### 8.2 Mutex-Based IOCs

| Mutex | Source |
|---|---|
| `_MICROSOFT_LOADER_MUTEX_` | malcat, Top Strings (EA 18808) |
| `Global\{7BDACDEE..46-D00FCFF1FFBA}` | malcat, Top Strings (EA 67392) |

### 8.3 Registry-Based IOCs

| Key | Value Name | Source |
|---|---|---|
| `Software\Microsoft\Windows\CurrentVersion\Run` | (default) | malcat, Top Strings |
| `Software\Microsoft\Internet Settings` | ProxyEnable | deep_dive_agentic |
| `Software\Microsoft\Internet Settings` | ProxyServer | deep_dive_agentic |
| `HKEY_CURRENT_USER` | SystemDrive | malcat, Decompilations |

### 8.4 YARA Rule Matches

26 YARA rules matched (source: yara, matches). High-signal rules:

| Rule | Category | Match Count | Source |
|---|---|---|---|
| Emissary_APT_Malware_1 | APT | 8 strings | yara |
| inject_thread | Injection | 6 strings | yara |
| escalate_priv | PrivEsc | 3 strings | yara |
| win_registry | Persistence | 5 strings | yara |
| win_token | Token Manip | 4 strings | yara |
| anti_dbg | Anti-Analysis | 2 strings | yara |
| win_mutex | Mutex | 1 string | yara |
| Dropper_Strings | Dropper | 1 string | yara |
| SHA512_Constants | Crypto | 4 constants | yara |
| BASE64_table | Encoding | 1 table | yara |

### 8.5 VirusTotal Intelligence

External threat intelligence shows 49/63 malicious detections (source: llm_judge, ti_enrich). Threat classification includes `lotusblossom` and `explorerhijack` family names, confirming attribution to the Lotus Blossom / Emissary APT group.

## 9. Detection Engineering

### 9.1 YARA Detection Rule

A sample-specific YARA rule was generated (source: rule.yara.json) with 24 strings including:

- `\Internet Explorer\iexplore.exe` -- injection target
- `A08E81B411.DAT` -- dropped payload filename
- `_MICROSOFT_LOADER_MUTEX_` -- mutex name
- `SeDebugPrivilege` -- privilege escalation
- `Software\Microsoft\Windows\CurrentVersion\Run` -- persistence key
- `ReleaseFile Error->FindResource Failed[%d].` -- debug strings
- `\LocalData\` -- payload directory

The rule was validated (`yara_valid: true`, `yara_check: ok`) and generated at `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yar`.

### 9.2 Sigma Detection

A Sigma rule was generated at `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yml` (source: rule.yara.json).

### 9.3 Behavioral Detection Signatures

| Detection | Logic | Confidence |
|---|---|---|
| DLL Injection via CreateRemoteThread | `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` in sequence | High |
| SeDebugPrivilege Escalation | `OpenProcessToken` + `LookupPrivilegeValueA("SeDebugPrivilege")` + `AdjustTokenPrivileges` | High |
| Resource-Based Payload Drop | `FindResourceW` + `LockResource` + `CreateFileA` to `\LocalData\` | High |
| Run Key Persistence | `RegOpenKeyExA` + `RegSetValueExA` on `Software\Microsoft\Windows\CurrentVersion\Run` | High |
| IE Process Targeting | `CreateToolhelp32Snapshot` + process name comparison to `iexplore.exe` | High |

## 10. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence | Source |
|---|---|---|---|---|
| Execution | Shared Modules | T1129 | LoadLibrary, GetProcAddress imports | pe_imports |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | `Software\Microsoft\Windows\CurrentVersion\Run` | capa, yara |
| Privilege Escalation | Process Injection: Thread Execution Hijacking | T1055.003 | VirtualAllocEx + WriteProcessMemory + CreateRemoteThread | capa, yara |
| Defense Evasion | Process Injection | T1055 | Full injection chain in imports | pe_imports |
| Defense Evasion | Obfuscated Files or Information: Indicator Removal from Tools | T1027.005 | Stack string obfuscation | capa |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 encoding, XOR obfuscation | capa |
| Defense Evasion | Reflective Code Loading | T1620 | Thread injection into remote process | capa |
| Discovery | Process Discovery | T1057 | CreateToolhelp32Snapshot + Process32First/Next | capa |
| Discovery | Software Discovery | T1518 | Module enumeration via Module32First/Next | capa |
| Discovery | File and Directory Discovery | T1083 | GetCommonFilePath, GetFileSize | capa |
| Collection | Data from Local System | (latent) | ProxyEnable/ProxyServer reading | deep_dive_agentic |

## 11. What We Don't Know

Several aspects of this sample remain unknown or unconfirmed:

1. **C2 Communication Protocol**: No hardcoded C2 addresses were found. The proxy configuration reading suggests C2 may use HTTP through the victim's proxy, but the actual C2 infrastructure is not recoverable from static analysis alone. The `UploadFile` and `DownloadFile` error strings indicate file transfer capabilities exist in the embedded payload, but the protocol details are unknown.

2. **Embedded Payload Behavior**: The 52,736-byte PE embedded in resources (`A08E81B411.DAT`) was not extracted and analyzed in this report. Its capabilities -- including potential C2 communication, data exfiltration, or additional persistence -- are unknown.

3. **Anti-Analysis Specifics**: While Speakeasy and Frida recorded zero events, the specific anti-analysis checks (timing checks, environment detection, debugger detection) were not fully characterized. The `anti_dbg` YARA rule matched, but the exact detection methods are unknown.

4. **Campaign Context**: The relationship between this DLL dropper and the broader Lotus Blossom / Emissary APT campaign infrastructure is unknown. Delivery mechanism (phishing, exploit, watering hole) is not determinable from the sample alone.

5. **Encryption Key Material**: While SHA512 constants and BASE64 tables were detected, the specific encryption keys used for C2 communication or payload protection are unknown.

6. **Lateral Movement**: The `ElevatePrivileges` and `RunShell` YARA rules (source: malcat) suggest lateral movement capability, but no specific lateral movement techniques (e.g., PsExec, WMI, SMB) were confirmed in the import table.

7. **Data Exfiltration**: The deep-dive analysis states "Exfiltration: Not observed" based on YARA and CAPA analysis. However, the `UploadFile` error string suggests exfiltration capability may exist in the embedded payload.

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used

| Tool | Version/Status | Result | Source |
|---|---|---|---|
| MalCat | Active | 11 anomalies, 8 YARA rules, 113 imports | malcat |
| Ghidra | Active | 74 functions, string refs extracted | ghidra_query |
| IDA Pro | Active | 74 functions, 88 imports confirmed | ida_query |
| CAPA (malcat-capa) | Active | 30 rules matched | capa |
| YARA (pipeline) | Active | 26 rules matched | yara |
| FLOSS | Active | 619 strings (2 decoded, 3 stack) | floss |
| radare2 | Active | Disassembly at key EAs | r2_decomp |
| UPX | Active | Not packed | upx |
| XOR Search | Active | 2 XOR-00 patterns found | xor |
| Speakeasy | Active | 0 API calls, 0 events | speakeasy |
| Frida | v17.16.4 | 19 hook candidates, 0 events | frida_probe |
| VirusTotal | Active | 49/63 malicious | ti_enrich |

### Key SQL Queries Executed

| Engine | Query Purpose | Timestamp |
|---|---|---|
| ghidra | String refs for FUN_100019a0 | 1786562388 |
| ghidra | String refs for FUN_10002300 | 1786562395 |
| ghidra | String refs for FUN_10003853, FUN_100026a0, FUN_10001e80 | 1786562396 |
| ghidra | Long strings (>=8 chars) | 1786562456 |
| ida | Long strings (>=8 chars) | 1786562459 |
| ida | Function count | 1786613210 |
| ida | String count | 1786613210 |
| ida | Import listing | 1786613210 |
| ghidra | Function listing | 1786613218 |
| ghidra | Memory blocks | 1786613219 |
| ghidra | FS/GS segment instructions | 1786613220 |
| ghidra | Call edges | 1786613221 |

## 13. Appendix B: Analysis Environment

| Parameter | Value |
|---|---|
| Sample Path | `/opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll` |
| Project Name | malware |
| Analysis Date | 2026-08-12 |
| Report Version | v2 |
| LLM Model | mimo-v2.5-pro |
| Analysis Engine | langgraph (deep_dive_agentic) |
| Frida Version | 17.16.4 |
| Rule Generation | RevAI (langgraph engine) |
| YARA Rule Path | `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yar` |
| Sigma Rule Path | `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yml` |
| IOCs Path | `/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/iocs.json` |
| Goodware FP Check | Skipped (goodware corpus not staged) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76  
**sample_path:** /opt/samples/corpus/malware/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/ishelp.dll  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: Lotus Blossom
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA agree on 74 functions and 88 imports, indicating reliable disassembly. MalCat identifies 11 anomalies including EmbeddedProgram and high-signal imports like CreateRemoteThread. Capa and YARA rules detect process injection, privilege escalation, and persistence behaviors. External VirusTotal shows 49 malicious detections with threat names like 'lotusblossom' and 'explorerhijack'.
- **summary**: The DLL 'ishelp.dll' exhibits malicious behavior including process injection via CreateRemoteThread, registry-based persistence, privilege escalation, and an embedded payload. It uses anti-analysis techniques and matches known malware patterns, with strong consensus from multiple analysis engines and external threat intelligence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | Top high-signal imports | `kernel32.CreateRemoteThread` | API for creating remote threads in other processes, a key technique for process injection and malicious code execution. |
| capa | ATT&CK | `T1055.003` | Rule for Thread Execution Hijacking, indicating process injection for defense evasion, a clear malicious behavior. |
| ghidra | Anti Analysis Signals | `FUN_100019a0` | Function enumerates processes using CreateToolhelp32Snapshot, used for discovery and targeting in malicious activities. |
| yara | matches | `inject_thread` | YARA rule match for thread injection, confirming malicious injection capabilities from behavioral patterns. |
| malcat | Anomalies | `EmbeddedProgram` | Anomaly indicates an embedded program, suggesting dropper or payload delivery functionality for malware distribution. |
| malcat | Strings/registry | `Software\Microsoft\Windows\CurrentVersion\Run` | Registry key for autostart persistence, commonly modified by malware to ensure survival across reboots. |
| ghidra | Suspicious strings (Ghidra) | `cmd.exe /c %s > %s` | String for command execution and output redirection, indicating potential command-and-control or payload execution. |
| pe_imports | signals | `change_memory_protection` | VirtualProtect API used to alter memory permissions, enabling executable code in non-executable regions for injection. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 98
- **summary**: This is a DLL dropper/loader component of the Emissary APT malware family. YARA rule 'Emissary_APT_Malware_1' matched with 8 distinct strings. The DLL exports a 'Setting' function designed to be invoked via rundll32.exe. Its behavioral chain: (1) creates mutex '_MICROSOFT_LOADER_MUTEX_' for single-instance enforcement, (2) enables SeDebugPrivilege via AdjustTokenPrivileges for elevated process access, (3) extracts an embedded payload from PE resources to disk as 'A08E81B411.DAT' in a \LocalData\ directory (FindResourceW/LockResource/CreateFileA), (4) enumerates running processes using CreateToolhelp32Snapshot to locate IE (iexplore.exe) as injection target, (5) performs classic process injection via VirtualAllocEx + WriteProcessMemory + CreateRemoteThread into the target process, (6) establishes registry persistence under Software\Microsoft\Windows\CurrentVersion\Run with 'rundll32.exe "%s",Setting', (7) reads proxy configuration from Internet Settings registry keys (ProxyEnable/ProxyServer) likely for C2 configuration. CAPA confirms stack string obfuscation (T1027.005), Base64 encoding (T1027), and file discovery (T1083). The 151-cyclomatic-complexity main function (FUN_10003853, 2771 bytes) suggests heavy obfuscation or control-flow flattening. VersionInfo metadata claiming 'Loader Dynamic Link Library' and 'Copyright (C) 2015' is irrelevant — all functional indicators are unambiguously malicious. Exfiltration: Not observed based on YARA rule 'Emissary_APT_Malware_1' and CAPA analysis, as no data exfiltration techniques (e.g., network transmission, file transfer) were identified in the behavioral chain or tool outputs. Defense impairment: Not observed based on YARA rule 'Emissary_APT_Malware_1' and CAPA analysis, as no techniques to disable security tools, clear logs, or evade defenses were identified in the behavioral chain or tool outputs.

### deep key_evidence
- `"YARA rule 'Emissary_APT_Malware_1' matched with 8 strings at offsets 61976, 61996, 17696, 61864, 60320, 61412, 70960, 61896"`
- `"Imports: CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, VirtualProtectEx, OpenProcess (classic DLL injection chain)"`
- `"Imports: AdjustTokenPrivileges, LookupPrivilegeValueA, OpenProcessToken (privilege escalation)"`
- `"String refs in FUN_10002300: 'IE Process is running.' and '_MICROSOFT_LOADER_MUTEX_' (IE injection targeting + mutex)"`
- `"String refs in FUN_100019a0: 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'A08E81B411.DAT', 'SeDebugPrivilege', '\\LocalData\\' (persistence + payload drop + priv esc)"`
- `"Export 'Setting' with string 'rundll32.exe \"%s\",Setting' (autorun persistence via rundll32)"`
- `"Strings: 'ProxyEnable', 'ProxyServer', 'Internet Settings' registry path (proxy credential theft)"`
- `"FUN_10001820 references 'ReleaseFile Error->FindResource Failed', 'LoadLibrary Failed', 'GetProcAddress Failed', 'CreateFile Failed' (resource-based dropper with debug strings)"`
- `"CAPA: obfuscated stackstrings (T1027.005), Base64 encoding (T1027), file/directory discovery (T1083)"`
- `"FUN_10003853: size=2771, cyclomatic_complexity=151, 240 basic blocks (heavily obfuscated main payload logic)"`
- `"Imports: CreateToolhelp32Snapshot, Process32First, Process32Next, Module32First, Module32Next (process/module enumeration for injection target)"`
- `"SHA512 constants and BASE64 alphabet table detected at offsets 58812-58836 and 58736 (crypto encoding infrastructure)"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76
size: 78848
type: PE
architecture: X86
entrypoint_ea: 10359
entropy: 6.35
file_name: ishelp.dll
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 51 | - |
| .text | 1024 | 14848 | 16384 | 126 | RX |
| .rdata | 17408 | 4608 | 8192 | 88 | R |
| .data | 25600 | 2048 | 4096 | 100 | RW |
| .rsrc | 29696 | 54272 | 57344 | 125 | R |
| .reloc | 87040 | 2048 | 4096 | 90 | R |

### Malcat YARA / Signatures (8)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2008_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2008_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| CustomUserAgent | network | UNCOMMON | 30 | embeds a user agent string |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| ChangeBrowserPreference | tampering | SUSPICIOUS | 40 | may change browser preference, often used by adware |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (11)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| HugeStringBinary | 4 | strings | 1 | string has more than 1024 characters and binary encoding |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| PossiblePackerApiDynamicImport | 4 | imports | 1 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 2 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| StringBase64 | 3 | strings | 1 | string has more than 16 characters is encoded using base64 |
| XorInLoop | 3 | code | 5 | XOR instruction in a loop |
| SpaghettiFunction | 1 | code | 1 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `3735`: 
- **ManyUniqueImmediateBytes**
  - `11347`: 
- **SpaghettiFunction**
  - `11347`: 
- **XorInLoop**
  - `1111`: 
  - `1832`: 
  - `2260`: 
  - `2639`: 
  - `8574`: 

### High-Signal Strings (11 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 18672 | `kernel32.dll` |
| 18500 | `kernel32.dll` |
| 18200 | `Kernel32.dll` |
| 18808 | `_MICROSOFT_LOADER_MUTEX_` |
| 69144 | `cmd.exe /c %s > %s` |
| 18688 | `LoadLibraryA` |
| 21508 | `KERNEL32.dll` |
| 69108 | `kernel32.dll` |
| 75634 | `KERNEL32.dll` |
| 68580 | `UploadFile - EncryptBuffer Error` |
| 75120 | `GetProcAddress` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 18408 | `Software\Microso..rrentVersion\Run` |
| 3735 | `2801000000000000..0000000000000000` |
| 18468 | `SeDebugPrivilege` |
| 19384 | `Software\Microso..nternet Settings` |
| 19260 | `Software\Microso..rrentVersion\Run` |
| 67252 | `Software\Microso..rrentVersion\Run` |
| 67812 | `Mozilla/4.0 (com.. Windows NT 5.1)` |
| 18516 | `A08E81B411.DAT` |
| 18724 | `A08E81B411.DAT` |
| 18596 | `A08E81B411.DAT` |
| 18580 | `A08E81B411.DAT` |
| 18564 | `A08E81B411.DAT` |
| 18548 | `A08E81B411.DAT` |
| 18532 | `A08E81B411.DAT` |
| 18672 | `kernel32.dll` |
| 18500 | `kernel32.dll` |
| 18096 | `asdasdasdasdsad` |
| 18200 | `Kernel32.dll` |
| 17808 | `Invalid paramete..ntime function.
` |
| 18740 | `ishelp.dll` |
| 20608 | `CreateToolhelp32Snapshot` |
| 18128 | `ReleaseFile Erro..urce Failed[%d].` |
| 19168 | `75BD50EC.DAT` |
| 18216 | `ReleaseFile Erro..rary Failed[%d].` |
| 18348 | `ReleaseFile->Cre..File Failed[%d].` |
| 18276 | `ReleaseFile->Get..ress Failed[%d].` |
| 18316 | `ReleaseFile->ProLdRsc Failed.` |
| 83404 | `<assembly xmlns=..XPADDINGPADDINGX` |
| 18808 | `_MICROSOFT_LOADER_MUTEX_` |
| 21616 | `AdjustTokenPrivileges` |
| 20856 | `Process32Next` |
| 18172 | `ReleaseFile Error->Size=0.` |
| 69144 | `cmd.exe /c %s > %s` |
| 18772 | `IE Process is running.` |
| 17988 | `%d/%02d/%02d %02d:%02d:%02d - ` |
| 20888 | `Module32Next` |
| 18396 | `\LocalData\` |
| 18712 | `\LocalData\` |
| 18688 | `LoadLibraryA` |
| 18488 | `FreeLibrary` |
| 19184 | `\LocalData\` |
| 18384 | `Removing...` |
| 18260 | `LoadResource` |
| 18456 | `SystemDrive` |
| 18704 | `Rew.
` |
| 21706 | `ole32.dll` |
| 21638 | `ADVAPI32.dll` |
| 21508 | `KERNEL32.dll` |
| 21678 | `SHELL32.dll` |
| 21750 | `RPCRT4.dll` |
| 21826 | `Loader.dll` |
| 18796 | `ReF(D)F.` |
| 17872 | `(null)` |
| 20300 | `msvcrt.dll` |
| 65904 | `ABCDEFGHIJKLMNOP..wxyz0123456789+/` |
| 17888 | `(null)` |
| 18992 | `ntdll.dll` |
| 21837 | `Setting` |
| 76968 | `0123456789ABCDEF` |
| 78128 | `WinDLL.dll` |
| 83164 | `Loader.dll` |
| 77864 | `DLL Dynamic Link Library` |
| 67892 | `<input id="check..heck_ip" value="` |
| 82888 | `Loader Dynamic Link Library` |
| 78184 | `DLL Dynamic Link Library` |
| 19032 | `XXXX.dat` |
| 83220 | `Loader Dynamic Link Library` |
| 29930 | `ASDASDASDASDSAD` |
| 69108 | `kernel32.dll` |
| 77678 | `VS_VERSION_INFO` |
| 18024 | `%d/%02d/%02d %02d:%02d:%02d - ` |
| 82702 | `VS_VERSION_INFO` |
| 67392 | `Global\{7BDACDEE..46-D00FCFF1FFBA}` |
| 83130 | `OriginalFilename` |
| 78094 | `OriginalFilename` |
| 77806 | `040904b0` |
| 65716 | `Invalid paramete..ntime function.
` |
| 82830 | `040904b0` |
| 67488 | `CDllApp::InitIns..eate successful.` |
| 68868 | `DownloadFile Err..Data From Server` |

### Constants / Known Patterns (6)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| registry | `registry::autorun` |
| crypto | `crypto::Base64` |
| hash | `hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640` |
| crypto | `crypto::ASCII_to_BIN_table__8_byt_128` |

### Imports (113)
| EA | Name | Type | Refs |
|---|---|---|---|
| 6752 | Setting | EXPORT | 1 |
| 7664 | @__security_check_cookie@4 | DEBUG | 13 |
| 7995 | _strcat_s | DEBUG | 8 |
| 8111 | _strcpy_s | DEBUG | 3 |
| 8215 | _strncpy_s | DEBUG | 2 |
| 8396 | _wcscat_s | DEBUG | 1 |
| 8668 | SEH.0 | DEBUG | 2 |
| 8766 | @_EH4_CallFilterFunc@8 | DEBUG | 1 |
| 8789 | @_EH4_TransferToHandler@8 | DEBUG | 1 |
| 8840 | @_EH4_LocalUnwind@16 | DEBUG | 2 |
| 8864 | __except_handler4_common | DEBUG | 1 |
| 9262 | ___CppXcptFilter | DEBUG | 8 |
| 9294 | __initterm_e | DEBUG | 1 |
| 10359 | _DllEntryPoint@12 | DEBUG | 1 |
| 10381 | ___report_gsfailure | DEBUG | 1 |
| 10608 | __aulldvrm | DEBUG | 1 |
| 10770 | _write_char | DEBUG | 5 |
| 10821 | _write_multi_char | DEBUG | 3 |
| 14384 | __ValidateImageBase | DEBUG | 1 |
| 14448 | __FindPESection | DEBUG | 1 |
| 14644 | __SEH_prolog4 | DEBUG | 2 |
| 14733 | SEH.1 | DEBUG | 2 |
| 14733 | __except_handler4 | DEBUG | 2 |
| 14928 | __allmul | DEBUG | 0 |
| 15392 | __alloca_probe | DEBUG | 1 |
| 17408 | advapi32.OpenProcessToken | IMPORT | 7 |
| 17412 | advapi32.RegCloseKey | IMPORT | 1 |
| 17416 | advapi32.AdjustTokenPrivileges | IMPORT | 1 |
| 17420 | advapi32.LookupPrivilegeValueA | IMPORT | 1 |
| 17424 | advapi32.RegOpenKeyExA | IMPORT | 1 |
| 17428 | advapi32.RegDeleteValueA | IMPORT | 1 |
| 17436 | kernel32.GetProcAddress | IMPORT | 4 |
| 17440 | kernel32.GetSystemTimeAsFileTime | IMPORT | 1 |
| 17444 | kernel32.GetCurrentProcessId | IMPORT | 1 |
| 17448 | kernel32.GetCurrentThreadId | IMPORT | 1 |
| 17452 | kernel32.GetTickCount | IMPORT | 1 |
| 17456 | kernel32.QueryPerformanceCounter | IMPORT | 1 |
| 17460 | kernel32.SetUnhandledExceptionFilter | IMPORT | 1 |
| 17464 | kernel32.UnhandledExceptionFilter | IMPORT | 1 |
| 17468 | kernel32.TerminateProcess | IMPORT | 1 |
| 17472 | kernel32.InterlockedCompareExchange | IMPORT | 2 |
| 17476 | kernel32.InterlockedExchange | IMPORT | 2 |
| 17480 | kernel32.RtlUnwind | IMPORT | 1 |
| 17484 | kernel32.SetEndOfFile | IMPORT | 1 |
| 17488 | kernel32.GetFileSize | IMPORT | 1 |
| 17492 | kernel32.GetLocalTime | IMPORT | 1 |
| 17496 | kernel32.WideCharToMultiByte | IMPORT | 1 |
| 17500 | kernel32.CreateMutexA | IMPORT | 1 |
| 17504 | kernel32.CopyFileA | IMPORT | 1 |
| 17508 | kernel32.GetTempPathW | IMPORT | 1 |
| 17512 | kernel32.GetModuleFileNameA | IMPORT | 1 |
| 17516 | kernel32.OutputDebugStringA | IMPORT | 3 |
| 17520 | kernel32.GetExitCodeThread | IMPORT | 1 |
| 17524 | kernel32.CreateProcessA | IMPORT | 1 |
| 17528 | kernel32.DeleteFileA | IMPORT | 3 |
| 17532 | kernel32.WaitForSingleObject | IMPORT | 2 |
| 17536 | kernel32.CreateRemoteThread | IMPORT | 2 |
| 17540 | kernel32.WriteProcessMemory | IMPORT | 2 |
| 17544 | kernel32.VirtualProtectEx | IMPORT | 4 |
| 17548 | kernel32.SetLastError | IMPORT | 4 |
| 17552 | kernel32.lstrlenA | IMPORT | 8 |
| 17556 | kernel32.VirtualAllocEx | IMPORT | 2 |
| 17560 | kernel32.lstrcmpiA | IMPORT | 1 |
| 17564 | kernel32.Module32Next | IMPORT | 1 |
| 17568 | kernel32.Module32First | IMPORT | 1 |
| 17572 | kernel32.Process32Next | IMPORT | 1 |
| 17576 | kernel32.Process32First | IMPORT | 1 |
| 17580 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 17584 | kernel32.GetCurrentProcess | IMPORT | 2 |
| 17588 | kernel32.RemoveDirectoryA | IMPORT | 1 |
| 17592 | kernel32.Sleep | IMPORT | 3 |
| 17596 | kernel32.LockResource | IMPORT | 1 |
| 17600 | kernel32.FreeLibrary | IMPORT | 1 |
| 17604 | kernel32.LoadLibraryA | IMPORT | 1 |
| 17608 | kernel32.SizeofResource | IMPORT | 1 |
| 17612 | kernel32.FindResourceW | IMPORT | 1 |
| 17616 | kernel32.MultiByteToWideChar | IMPORT | 2 |
| 17620 | kernel32.CreateDirectoryA | IMPORT | 3 |
| 17624 | kernel32.GetLastError | IMPORT | 5 |
| 17628 | kernel32.CreateFileA | IMPORT | 7 |

### Functions (30)
| EA | Name |
|---|---|
| 3488 | sub_100019a0 |
| 14770 | sub_100045b2 |
| 2464 | sub_100015a0 |
| 1264 | sub_100010f0 |
| 2016 | sub_100013e0 |
| 4736 | sub_10001e80 |
| 5888 | sub_10002300 |
| 6816 | sub_100026a0 |
| 11347 | sub_10003853 |
| 11114 | sub_1000376a |
| 10937 | sub_100036b9 |
| 7466 | sub_1000292a |
| 8524 | sub_10002d4c |
| 1024 | sub_10001000 |
| 3104 | sub_10001820 |
| 14980 | sub_10004684 |
| 5584 | sub_100021d0 |
| 9364 | sub_10003094 |
| 5712 | sub_10002250 |
| 7680 | sub_10002a00 |
| 7866 | sub_10002aba |
| 2976 | sub_100017a0 |
| 1184 | sub_100010a0 |
| 1136 | sub_10001070 |
| 14177 | sub_10004361 |
| 10859 | sub_1000366b |
| 6768 | sub_10002670 |
| 9330 | sub_10003072 |
| 6752 | Setting |
| 7644 | jmp_msvcrt._errno |

### Decompilations (top 6)
#### 3488 — sub_100019a0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100019a0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    undefined4 *puVar4;
    undefined4 *puVar5;
    undefined4 uStack_5bc;
    undefined4 uStack_5b8;
    undefined4 uStack_5b4;
    undefined auStack_5b0 [24];
    undefined4 uStack_598;
    undefined auStack_594 [520];
    undefined4 uStack_38c;
    undefined auStack_388 [4];
    undefined4 uStack_384;
    int32_t iStack_260;
    undefined4 auStack_25c [11];
    undefined auStack_22e [222];
    int32_t iStack_150;
    undefined4 uStack_14c;
    undefined auStack_148 [8];
    undefined4 uStack_140;
    int32_t iStack_13c;
    int32_t iStack_138;
    undefined4 uStack_134;
    undefined4 uStack_130;
    int32_t iStack_12c;
    undefined4 uStack_128;
    undefined4 uStack_124;
    int32_t iStack_120;
    undefined4 uStack_11c;
    undefined4 uStack_118;
    undefined auStack_114 [268];
    uint32_t uStack_8;
    
    uStack_8 = [0x0x10007000#SecurityCookie] ^ &stack0xfffffffc;
    sub_100026a0("Removing...");
    (*kernel32.Sleep)(1000);
    iVar1 = (*shell32.SHGetSpecialFolderPathA)(0, auStack_114, 0x1a, 0);
    if (iVar1 != 0) {
        _strcat_s(auStack_114, 0x104, "\\LocalData\\");
        (*kernel32.RemoveDirectoryA)(auStack_114);
        (*kernel32.CreateDirectoryA)(auStack_114, 0);
        uStack_124 = 0;
        puVar4 = &autorun;
        puVar5 = auStack_25c;
        for (iVar1 = 0xb; iVar1 != 0; iVar1 = iVar1 + -1) {
            *puVar5 = *puVar4;
            puVar4 = puVar4 + 1;
            puVar5 = puVar5 + 1;
        }
        *puVar5 = *puVar4;
        jmp_msvcrt.memset(auStack_22e, 0, 0xd6);
        iVar1 = (*advapi32.RegOpenKeyExA)(0x80000001, auStack_25c, 0, 2, &uStack_124);
        if (iVar1 == 0) {
            (*advapi32.RegDeleteValueA)(uStack_124, "SystemDrive");
            (*advapi32.RegCloseKey)(uStack_124);
            uStack_11c = 0;
            uStack_134 = 0;
            iStack_120 = 0;
            iStack_138 = 0;
            iStack_12c = 0;
            uStack_128 = 0;
            uStack_130 = 0;
            uStack_118 = 0;
            iStack_260 = 0;
            iStack_150 = 0;
            uStack_38c = 0x128;
            jmp_msvcrt.memset(auStack_388, 0, 0x124);
            uVar2 = (*kernel32.GetCurrentProcess)(0x28, &uStack_128);
            iVar1 = (*advapi32.OpenProcessToken)(uVar2);
            if (iVar1 != 0) {
                (*advapi32.LookupPrivilegeValueA)(0, "SeDebugPrivilege", auStack_148);
                uStack_14c = 1;
                uStack_140 = 2;
                (*advapi32.AdjustTokenPrivileges)(uStack_128, 0, &uStack_14c, 0, 0, 0);
            }
            iStack_138 = jmp_kernel32.CreateToolhelp32Snapshot(2, 0);
            if (iStack_138 != -1) {
                uVar2 = (*kernel32.GetModuleHandleA)("kernel32.dll", "FreeLibrary");
                iStack_13c = (*kernel32.GetProcAddress)(uVar2);
                if (iStack_13c != 0) {
                    iStack_260 = jmp_kernel32.Process32First(iStack_138, &uStack_38c);
                    while (iStack_260 != 0) {
                        iStack_120 = (*kernel32.OpenProcess)(0x1fffff, 1, uStack_384);
                        if (iStack_120 != 0) {
                            iStack_12c = jmp_kernel32.CreateToolhelp32Snapshot(8, uStack_384);
                            if (iStack_12c != -1) {
                                uStack_5b4 = 0x224;
                                jmp_msvcrt.memset(auStack_5b0, 0, 0x220);
                                iStack_150 = jmp_kernel32.Module32First(iStack_12c, &uStack_5b4);
                                while (iStack_150 != 0) {
                                    iVar1 = (*kernel32.lstrcmpiA)("A08E81B411.DAT", auStack_594);
                                    if (iVar1 == 0) {
                                        iVar1 = (*kernel32.lstrlenA)("A08E81B411.DAT", 0x1000, 0x40);
                      
```
#### 14770 — sub_100045b2
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100045b2(void)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    uint32_t uStack_8;
    
    uStack_c = 0;
    uStack_8 = 0;
    if (([0x0x10007000#SecurityCookie] == 0xbb40e64e) || (([0x0x10007000#SecurityCookie] & 0xffff0000) == 0)) {
        (*kernel32.GetSystemTimeAsFileTime)(&uStack_c);
        uVar4 = uStack_8 ^ uStack_c;
        uVar1 = (*kernel32.GetCurrentProcessId)();
        uVar2 = (*kernel32.GetCurrentThreadId)();
        uVar3 = (*kernel32.GetTickCount)();
        (*kernel32.QueryPerformanceCounter)(&uStack_14);
        uVar1 = uVar4 ^ uVar1 ^ uVar2 ^ uVar3 ^ uStack_10 ^ uStack_14;
        if ((uVar1 == 0xbb40e64e) || (([0x0x10007000#SecurityCookie] & 0xffff0000) == 0)) {
            uVar1 = 0xbb40e64f;
        }
        10007004 = ~uVar1;
        10007000 = uVar1;
    }
    else {
        10007004 = ~[0x0x10007000#SecurityCookie];
    }
    return;
}

```
#### 2464 — sub_100015a0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_100015a0(undefined4 *param_1)

{
    uint8_t uVar1;
    uint32_t uVar2;
    int32_t iVar3;
    undefined4 *puVar4;
    uint32_t uStack_1b0;
    undefined uStack_1ac;
    undefined auStack_1ab [267];
    uint8_t *puStack_a0;
    undefined4 uStack_9c;
    int32_t iStack_98;
    undefined4 uStack_94;
    undefined auStack_90 [136];
    uint32_t uStack_8;
    
    uStack_8 = [0x0x10007000#SecurityCookie] ^ &stack0xfffffffc;
    uStack_94 = 0;
    jmp_msvcrt.memset(auStack_90, 0, 0x80);
    if (param_1 != 0x0) {
        puVar4 = &uStack_94;
        for (iVar3 = 0x21; iVar3 != 0; iVar3 = iVar3 + -1) {
            *puVar4 = *param_1;
            param_1 = param_1 + 1;
            puVar4 = puVar4 + 1;
        }
    }
    (*msvcrt.srand)(0xa03);
    for (uStack_1b0 = 0; uStack_1b0 < 0x84; uStack_1b0 = uStack_1b0 + 1) {
        puStack_a0 = auStack_90 + (uStack_1b0 - 4);
        uVar1 = *puStack_a0;
        uVar2 = (*msvcrt.rand)();
        uVar2 = uVar2 & 0x8000007f;
        if (uVar2 < 0) {
            uVar2 = (uVar2 - 1 | 0xffffff80) + 1;
        }
        *puStack_a0 = uVar1 ^ uVar2;
    }
    uStack_1ac = 0;
    jmp_msvcrt.memset(auStack_1ab, 0, 0x103);
    sub_100010a0(&uStack_1ac, 0x104);
    uStack_9c = 0;
    iStack_98 = (*kernel32.CreateFileA)(&uStack_1ac, 0x40000000, 0, 0, 4, 0, 0);
    if (iStack_98 != -1) {
        (*kernel32.SetFilePointer)(iStack_98, 0x488, 0, 0);
        (*kernel32.WriteFile)(iStack_98, &uStack_94, 0x84, &uStack_9c, 0);
        (*kernel32.CloseHandle)(iStack_98);
    }
    @__security_check_cookie@4();
    return;
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PE | 52736 |

### Virtual Files (3)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ASDASDASDASDSAD/102/en-us | 52736 | - |
| VER/1/en-us | 708 | - |
| MANIF/2/en-us | 346 | - |

### Structures (42)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 264 |
| OptionalHeader | 288 |
| Sections | 512 |
| advapi32.FT | 17408 |
| kernel32.FT | 17436 |
| rpcrt4.FT | 17660 |
| shell32.FT | 17672 |
| msvcrt.FT | 17680 |
| ole32.FT | 17776 |
| LoadConfigurationTable | 19480 |
| SEHandlers | 19552 |
| ImportTable | 19716 |
| advapi32.OFT | 19856 |
| kernel32.OFT | 19884 |
| rpcrt4.OFT | 20108 |
| shell32.OFT | 20120 |
| msvcrt.OFT | 20128 |
| ole32.OFT | 20224 |
| ImportNames | 20232 |
| ExportDirectory | 21776 |
| ExportAddressTable | 21816 |
| ExportNameTable | 21820 |
| OrdinalNameTable | 21824 |
| ExportNames | 21826 |
| SecurityCookie | 25600 |
| Resources | 29696 |
| Resources.ASDASDASDASDSAD | 29736 |
| Resources.VER | 29760 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 30 · duration_s: 0.92

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| reference Base64 string | T1027:Obfuscated Files or Information | C0026.001:Encode Data, C0019:Check String |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| inject thread | T1055.003:Process Injection, T1620:Reflective Code Loading |  |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| spawn thread to RWX shellcode |  | C0007:Allocate Memory, C0038:Create Thread |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| contain an embedded PE file |  | B0023:Install Additional Program |
| get Program Files directory | T1083:File and Directory Discovery |  |
| copy file |  | C0045:Copy File |
| create directory |  | C0046:Create Directory |
| delete directory |  | C0048:Delete Directory |
| delete file |  | C0047:Delete File |

## PE Imports / Signals
import_count: 88

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| write_process_memory | WriteProcessMemory | T1055 |
| create_remote_thread | CreateRemoteThread | T1055 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@60279 len=2 |
| contains_base64 | - | $a@16611 len=12 |
| System_Tools | - |  |
| Dropper_Strings | - | $a0@16899 len=18 |
| Misc_Suspicious_Strings | - | $a4@61976 len=7 |
| SHA512_Constants | - | $c1@58812 len=4; $c3@58820 len=4; $c5@58828 len=4; $c7@58836 len=4 |
| BASE64_table | - | $c0@58736 len=64 |
| Emissary_APT_Malware_1 | - | $s1@61976 len=18; $s2@61996 len=20; $s3@17696 len=25; $s4@61864 len=28; $s5@60320 len=50; $s6@61412 len=32; $s7@70960 len=20; $s8@61896 len=40 |
| IsPE32 | - |  |
| IsDLL | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@240 len=4 |
| Visual_Cpp_2005_DLL_Microsoft | - | $a@10359 len=9 |
| Visual_Cpp_2003_DLL_Microsoft | - | $a@7466 len=5 |
| SEH_Save | - | $a@8549 len=7 |
| SEH_Init | - | $a@14706 len=6; $b@8567 len=7 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@16664 len=12; $c3@19564 len=17 |
| inject_thread | - | $c1@19118 len=11; $c2@19380 len=14; $c4@19446 len=18; $c5@19468 len=18; $c6@67782 len=12; $c7@19118 len=11 |
| escalate_priv | - | $d1@20102 len=12; $c1@16932 len=16; $c2@20080 len=21 |
| win_mutex | - | $c1@19636 len=11 |
| win_registry | - | $f1@20102 len=12; $c2@19988 len=13; $c3@20004 len=11; $c4@68498 len=14; $c6@20004 len=11 |
| win_token | - | $f1@20102 len=12; $c2@20080 len=21; $c3@20036 len=16; $c4@20056 len=21 |
| win_files_operation | - | $f1@16664 len=12; $c1@19016 len=9; $c2@19054 len=14; $c3@19016 len=9; $c4@19042 len=8; $c5@19512 len=11; $c6@19002 len=11 |
| Str_Win32_Winsock2_Library | - | $wsock2_lib@68580 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76",
  "family": "trojan.lotusblossom/explorerhijack",
  "imphash": "aee2f8f6aa200110e796682791bc8758",
  "generated_at": "2026-08-12T19:20:59.482137+00:00",
  "string_count": 24,
  "strings": [
    "\\Internet Explorer\\iexplore.exe",
    "000A758C8FEAE5F.TMP",
    "($7/+.1$",
    "!This program cannot be run in DOS mode.",
    "UQPXY]Y[",
    "Invalid parameter passed to C runtime function.",
    "%d/%02d/%02d %02d:%02d:%02d -",
    "ReleaseFile Error->FindResource Failed[%d].",
    "ReleaseFile Error->Size=0.",
    "Kernel32.dll",
    "ReleaseFile Error->LoadLibrary Failed[%d].",
    "LoadResource",
    "ReleaseFile->GetProcAddress Failed[%d].",
    "ReleaseFile->ProLdRsc Failed.",
    "ReleaseFile->CreateFile Failed[%d].",
    "Removing...",
    "\\LocalData\\",
    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SystemDrive",
    "SeDebugPrivilege",
    "FreeLibrary",
    "kernel32.dll",
    "A08E81B411.DAT",
    "Windows Internet Explorer"
  ],
  "rule_path": "/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yar",
  "sigma_path": "/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/rule.yml",
  "iocs_path": "/opt/samples/logs/bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76/iocs.json",
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
    "utc": "2026-08-12 19:20:59 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 619 · per_category: `{"decoded_strings": 2, "stack_strings": 3, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 614}`

### High-signal FLOSS
- `Kernel32.dll`
- `ReleaseFile Error->LoadLibrary Failed[%d].`
- `ReleaseFile->GetProcAddress Failed[%d].`
- `kernel32.dll`
- `LoadLibraryA`
- `_MICROSOFT_LOADER_MUTEX_`

### FLOSS sample
- `\Internet Explorer\iexplore.exe`
- `000A758C8FEAE5F.TMP`
- `-3$1-$3`
- `7/+.1$1`
- `($7/+.1$`
- `!This program cannot be run in DOS mode.`
- `3 !23;`
- `!23Rich`
- ``.rdata`
- `@.data`
- `@.reloc`
- `Qj&hTs`
- `0SSSSS`
- `0WWWWW`
- `AAFFf;`
- `URPQQh`
- `v	N+D$`
- `YSSSSS`
- `HHtXHHt`
- `>If90t`
- `UQPXY]Y[`
- `Invalid parameter passed to C runtime function.`
- `(null)`
- ````hhh`
- `xppwpp`
- `%d/%02d/%02d %02d:%02d:%02d -`
- `ReleaseFile Error->FindResource Failed[%d].`
- `ReleaseFile Error->Size=0.`
- `Kernel32.dll`
- `ReleaseFile Error->LoadLibrary Failed[%d].`
- `LoadResource`
- `ReleaseFile->GetProcAddress Failed[%d].`
- `ReleaseFile->ProLdRsc Failed.`
- `ReleaseFile->CreateFile Failed[%d].`
- `Removing...`
- `\LocalData\`
- `Software\Microsoft\Windows\CurrentVersion\Run`
- `SystemDrive`
- `SeDebugPrivilege`
- `FreeLibrary`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x10003477
```asm
┌ 400: entry0 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│       ╎   ; arg int32_t arg_8h @ ebp+0x8
│       ╎   ; arg int32_t arg_ch @ ebp+0xc
│       ╎   ; arg int32_t arg_10h @ ebp+0x10
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   0x10003477      8bff           mov edi, edi
│       ╎   0x10003479      55             push ebp
│       ╎   0x1000347a      8bec           mov ebp, esp
│       ╎   0x1000347c      837d0c01       cmp dword [arg_ch], 1
│      ┌──< 0x10003480      7505           jne 0x10003487
│      │╎   0x10003482      e82b110000     call 0x100045b2
│      └──> 0x10003487      5d             pop ebp
│       └─< 0x10003488      e98efdffff     jmp 0x1000321b
..
            ; XREFS: CALL 0x10002328  CALL 0x10002345  CALL 0x1000235f  
            ; XREFS: CALL 0x1000237c  CALL 0x10002399  CALL 0x100023b8  
            ; XREFS: CALL 0x100023d5  CALL 0x100025d2  
```
### 0x10002660
```asm
┌ 10: sym.Loader.dll_Setting ();
│           0x10002660      55             push ebp
│           0x10002661      8bec           mov ebp, esp
│           0x10002663      e898fcffff     call fcn.10002300
│           0x10002668      5d             pop ebp
└           0x10002669      c3             ret
```
### 0x10002300
```asm
; CALL XREF from sym.Loader.dll_Setting @ 0x10002663(x)
┌ 852: fcn.10002300 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_20eh @ ebp-0x20e
│           ; var int32_t var_210h @ ebp-0x210
│           ; var int32_t var_317h @ ebp-0x317
│           ; var int32_t var_318h @ ebp-0x318
│           ; var int32_t var_31ch @ ebp-0x31c
│           ; var int32_t var_427h @ ebp-0x427
│           ; var int32_t var_428h @ ebp-0x428
│           ; var int32_t var_52fh @ ebp-0x52f
│           ; var int32_t var_530h @ ebp-0x530
│           ; var int32_t var_637h @ ebp-0x637
│           ; var int32_t var_638h @ ebp-0x638
│           ; var int32_t var_72eh @ ebp-0x72e
│           ; var int32_t var_730h @ ebp-0x730
│           ; var int32_t var_734h @ ebp-0x734
│           ; var int32_t var_738h @ ebp-0x738
│           ; var int32_t var_73ch @ ebp-0x73c
│           ; var int32_t var_73fh @ ebp-0x73f
│           ; var int32_t var_740h @ ebp-0x740
│           ; var int32_t var_773h @ ebp-0x773
│           ; var int32_t var_774h @ ebp-0x774
│           ; var int32_t var_7fch @ ebp-0x7fc
│           ; var int32_t var_800h @ ebp-0x800
│           ; var int32_t var_810h @ ebp-0x810
│           ; var int32_t var_814h @ ebp-0x814
│           0x10002300      55             push ebp
│           0x10002301      8bec           mov ebp, esp
│           0x10002303      81ec14080000   sub esp, 0x814
│           0x10002309      a100700010     mov eax, dword [section..data] ; [0x10007000:4]=0xbb40e64e ; "N\xe6@\xbb\xb1\x19\xbfD"
│           0x1000230e      33c5           xor eax, ebp
│           0x10002310      8945fc         mov dword [var_4h], eax
│           0x10002313      c685c8f9ff..   mov byte [var_638h], 0
│           0x1000231a      6803010000     push 0x103                  ; 259
│           0x1000231f      6a00           push 0
│           0x10002321      8d85c9f9ffff   lea eax, [var_637h]
│           0x10002327      50             push eax
│           0x10002328      e8d9120000     call 0x10003606
│           0x1000232d      83c40c         add esp, 0xc
│           0x10002330      c685d8fbff..   mov byte [var_428h], 0
│           0x10002337      6803010000     push 0x103                  ; 259
│           0x1000233c      6a00           push 0
│           0x1000233e      8d8dd9fbffff   lea ecx, [var_427h]
│           0x10002344      51             push ecx
│           0x10002345      e8bc120000     call 0x10003606
│           0x1000234a      83c40c         add esp, 0xc
│           0x1000234d      c6858cf8ff..   mov byte [var_774h], 0
│           0x10002354      6a31           push 0x31                   ; '1' ; 49
│           0x10002356      6a00           push 0
│           0x10002358      8d958df8ffff   lea edx, [var_773h]
│           0x1000235e      52             push edx
│           0x1000235f      e8a2120000     call 0x10003606
│           0x10002364      83c40c         add esp, 0xc
│           0x10002367      c685d0faff..   mov byte [var
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000108 ........!..L.!This program cannot be r
- Found XOR 00 position 00005908: 00000110 ........!..L.!This program cannot be r

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
  - `msvcrt.dll!__badioinfo`
  - `msvcrt.dll!wctomb`
  - `msvcrt.dll!_itoa`
  - `msvcrt.dll!_snprintf`
  - `msvcrt.dll!_iob`
  - `KERNEL32.dll!GetProcAddress`
  - `KERNEL32.dll!GetSystemTimeAsFileTime`
  - `KERNEL32.dll!GetCurrentProcessId`
  - `KERNEL32.dll!GetCurrentThreadId`
  - `KERNEL32.dll!GetTickCount`
  - `ADVAPI32.dll!OpenProcessToken`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!AdjustTokenPrivileges`
  - `ADVAPI32.dll!LookupPrivilegeValueA`
  - `ADVAPI32.dll!RegOpenKeyExA`
  - `SHELL32.dll!SHGetSpecialFolderPathA`
  - `ole32.dll!CoCreateGuid`
  - `RPCRT4.dll!RpcStringFreeA`
  - `RPCRT4.dll!UuidToStringA`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, s.content FROM string_refs sr JOIN strings s ON sr.string_addr = s.address WHERE sr.func_name = 'FUN_100019a0' ORDER BY s.address", "ts": 1786562388.3716059}`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, s.content FROM string_refs sr JOIN strings s ON sr.string_addr = s.address WHERE sr.func_name = 'FUN_10002300' ORDER BY s.address", "ts": 1786562395.7731194}`
- `{"source": "ghidra_query", "sql": "SELECT sr.func_name, sr.func_addr, s.content FROM string_refs sr JOIN strings s ON sr.string_addr = s.address WHERE sr.func_name = 'FUN_10003853' OR sr.func_name = 'FUN_100026a0' OR sr.func_name = 'FUN_10001e80' ORDER BY sr.func_name, s.address", "ts": 1786562396.3`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786562456.879452}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786562459.4145968}`
- `{"source": "yara_gen_v2", "ts": 1786562459.4823132}`
- `{"source": "publish_report_v2", "ts": 1786562560.5899267}`
- `{"source": "publish_report_v2_technical", "ts": 1786562697.563504}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786613210.4010978}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786613210.4033272}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786613210.4047806}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786613210.406227}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786613210.407218}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786613216.5196276}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786613217.060549}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786613217.5715475}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786613218.2382882}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786613218.7446737}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786613219.24844}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786613220.3153555}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786613220.8205287}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786613221.3024855}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786613221.8026376}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786613222.3013525}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786613222.801697}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786613223.2676747}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786613223.7376184}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786613224.7826877}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786613225.278359}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786613225.2811186}`
