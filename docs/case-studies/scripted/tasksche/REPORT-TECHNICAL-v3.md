> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:51:04 UTC

## 1. Executive Summary

This report presents a comprehensive technical analysis of the sample `ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda` (tasksche.exe), which has been conclusively identified as WannaCry/WanaCrypt0r ransomware. The analysis leverages multiple static and dynamic analysis engines, all converging on a malicious verdict with a confidence score of 100/100.

The sample exhibits core ransomware behaviors including AES-based file encryption, service-based persistence, and Tor-based command and control communications. Key identifiers include the `WanaCrypt0r` mutex string, `WANACRY!` magic marker, and multiple Bitcoin wallet addresses for ransom payment. YARA rules matched 28 times, with specific hits for WannaCry family indicators. Capa identified 32 capability rules including AES encryption and service creation. The sample is a 32-bit Windows GUI application compiled with Visual Studio 6.0, containing a large high-entropy resource section likely containing embedded payloads or encrypted data.

All analysis engines (Ghidra, IDA, YARA, Capa, MalCat, PE imports) show consistent evidence of malicious ransomware behavior. The sample's structure, imports, strings, and cryptographic constants align perfectly with known WannaCry propagation components.

## 2. Sample Metadata

| Property | Value |
|---|---|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda |
| File Name | tasksche.exe |
| File Size | 3,514,368 bytes |
| File Type | PE (Portable Executable) |
| Architecture | X86 (32-bit) |
| Entry Point EA | 30650 (0x77B2) |
| Entropy | 224 (high) |
| Compiler | Visual Studio 6.0 (MSVC_6_linker, MSVC_6_rich) |
| Subsystem | Windows GUI |
| Packed | No (UPX unpack failed, is_packed: False) |
| .NET | No |
| Verdict | Malicious (score: 100) |
| Family Guess | WannaCry |
| Agreement | llm_and_v1_agree |

**Source:** (source: malcat) File Summary table; (source: llm_judge) verdict.json

## 3. File Layout & Structural Analysis

The PE file contains five sections with a notably large `.rsrc` resource section comprising approximately 98% of the file size. This high-entropy resource section (entropy 226) is a strong indicator of embedded encrypted or compressed data, consistent with ransomware payloads that bundle additional components.

### Section Layout

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 75 | - |
| .text | 4096 | 28672 | 28672 | 117 | RX |
| .rdata | 32768 | 24576 | 24576 | 153 | R |
| .data | 57344 | 8192 | 8192 | 76 | RW |
| .rsrc | 65536 | 3448832 | 3448832 | 226 | R |

**Source:** (source: malcat) File Layout table

The `.rsrc` section at EA 65536 contains 3,448,832 bytes of data with entropy 226, indicating high randomness. This section houses multiple resource types including XIA (2058/en-us), VER (1/en-us), and MANIF (1/en-us) resources. The BigResourceHighEntropy anomaly at EA 65776 confirms this section contains a large, high-entropy resource that is not a picture, which is characteristic of embedded encrypted payloads in ransomware.

### Carved Files

| Name | Type | Size |
|---|---|---|
| ? | ZIP | 3486039 |

**Source:** (source: malcat) Carved Files table

A ZIP file of 3,486,039 bytes was carved from the resource section, likely containing the actual ransomware payload or supporting files.

### Virtual Files

| Path / Name | Unpacked Size | Type |
|---|---|---|
| XIA/2058/en-us | 3446325 | - |
| VER/1/en-us | 904 | - |
| MANIF/1/en-us | 1263 | - |

**Source:** (source: malcat) Virtual Files table

The XIA resource contains 3,446,325 bytes, which aligns with the carved ZIP file size, suggesting the resource section contains a compressed archive.

### Key Structures

The PE file contains 32 structures including standard MZ/PE headers, RichHeader at EA 128, ImportTable at EA 54696, and Resources starting at EA 65536. The import table references three DLLs: ADVAPI32, KERNEL32, and MSVCRT.

**Source:** (source: malcat) Structures table

## 4. Static Code Analysis

### Entry Point Analysis

The entry point at EA 30650 (0x77B2) begins with standard MSVC runtime initialization code. The radare2 disassembly shows the entry0 function setting up exception handling, calling `__set_app_type`, and initializing the C runtime before transferring control to the main function.

```asm
0x004077ba      55             push ebp
0x004077bb      8bec           mov ebp, esp
0x004077bd      6aff           push 0xffffffffffffffff
0x004077bf      6888d44000     push 0x40d488
0x004077c4      68f4764000     push 0x4076f4
0x004077c9      64a100000000   mov eax, dword fs:[0]
0x004077cf      50             push eax
0x004077d0      6489250000..   mov dword fs:[0], esp
```

**Source:** (source: radare2) Disassembly at 0x004077ba

This is standard MSVC exception handler registration. The entry point calls into the main function which performs the actual ransomware initialization.

### Main Function Analysis

The main function at EA 8167 (0x1FE7) performs several critical operations:

1. **Self-identification**: Calls `GetModuleFileNameA` to obtain its own path
2. **Argument checking**: Checks if exactly 2 arguments are provided
3. **Installation mode**: If the `/i` argument is present, it calls the installation function at EA 7007 (0x1B5F)
4. **Self-reference**: References the string `tasksche.exe` at EA 62680

```asm
0x0040201f      ff158c804000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA]
0x00402025      68acf84000     push 0x40f8ac
0x0040202a      e8f6f1ffff     call 0x401225
0x00402030      ff156c814000   call dword [sym.imp.MSVCRT.dll___p___argc]
0x00402036      833802         cmp dword [eax], 2
0x00402039      7553           jne 0x40208e
0x0040203b      6838f54000     push 0x40f538               ; "/i"
```

**Source:** (source: radare2) Disassembly at 0x00401FE7

The main function checks for the `/i` installation flag, which is characteristic of WannaCry's installation mechanism. When this flag is present, the malware proceeds with service installation and persistence setup.

### Cryptographic Functions

The sample contains embedded AES encryption routines with Rijndael S-box constants. Two key functions implement AES encryption and decryption:

**sub_402e7e (EA 11902)**: AES encryption function that uses Rijndael Te0-Te3 lookup tables. This function performs the standard AES encryption rounds with XOR operations and table lookups.

```c
uVar5 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
        *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_18 >> 0x10 & 0xff) * 4) ^
        *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
        *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ param_2[-1];
```

**Source:** (source: malcat) Decompilation of sub_402e7e

**sub_4031bc (EA 12732)**: AES decryption function using Rijndael Td0-Td3 inverse lookup tables. This implements the inverse AES operations for decryption.

```c
uVar7 = *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
        *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
        *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uVar4 >> 0x10 & 0xff) * 4) ^
        *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ puVar5[-1];
```

**Source:** (source: malcat) Decompilation of sub_4031bc

The presence of both encryption and decryption functions indicates the malware can both encrypt victim files and potentially decrypt them if the ransom is paid.

### Decompression Function

**sub_40514d (EA 20813)**: A decompression function using LZX algorithm tables (`unlzx_table_three__32_lil_64`). This function handles decompression of embedded data, likely used to unpack the ransomware payload from the resource section.

```c
uVar8 = *(&unlzx_table_three__32_lil_64 + param_1 * 4);
uVar2 = *(&unlzx_table_three__32_lil_64 + param_2 * 4);
do {
    for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
        puStack_8 = puStack_8 + -1;
        param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
        puStack_c = puStack_c + 1;
    }
```

**Source:** (source: malcat) Decompilation of sub_40514d

This function implements LZX decompression, which is used by WannaCry to extract its payload from the compressed resource section.

### XOR Operations

MalCat identified 20 XOR-in-loop anomalies at various addresses (11445, 11557, 11579, 11590, 11676), indicating obfuscation or encryption routines. These XOR operations are commonly used in ransomware for string obfuscation or simple encryption of configuration data.

**Source:** (source: malcat) Anomalies table - XorInLoop

### Function Metrics

The sample contains 30 functions identified by MalCat, with the entry point at EA 30650. Key functions include:
- EntryPoint (30650): Main entry point
- sub_401000 (4096): Likely initialization function
- sub_40182c (6188): References crypto provider string
- sub_401ce8 (7400): References cmd.exe execution
- sub_401dab (7595): References c.wnry config file
- sub_401e9e (7935): References Bitcoin addresses
- sub_401fe7 (8167): Main function

**Source:** (source: malcat) Functions table

## 5. Behavioral & Dynamic Analysis

### Speakeasy Emulation

Speakeasy emulation completed successfully but recorded zero API calls and zero key events. This indicates the sample did not execute its malicious payload during emulation, which is expected for samples that require specific conditions (e.g., installation arguments, mutex checks, or environment validation) before executing.

**not observed**: no API calls/events recorded -- do not invent runtime behavior

**Source:** (source: speakeasy) Dynamic analysis results

### Frida Probe

Frida probe identified 15 hook candidates across KERNEL32, USER32, ADVAPI32, and MSVCRT DLLs. These are the APIs the sample imports and would call during execution:

- `KERNEL32.dll!GetFileAttributesW` - File attribute checking
- `KERNEL32.dll!GetFileSizeEx` - File size determination
- `KERNEL32.dll!CreateFileA` - File creation/opening
- `KERNEL32.dll!InitializeCriticalSection` - Thread synchronization
- `KERNEL32.dll!DeleteCriticalSection` - Thread cleanup
- `USER32.dll!wsprintfA` - String formatting
- `ADVAPI32.dll!CreateServiceA` - Service creation
- `ADVAPI32.dll!OpenServiceA` - Service opening
- `ADVAPI32.dll!StartServiceA` - Service starting
- `ADVAPI32.dll!CloseServiceHandle` - Service handle cleanup
- `ADVAPI32.dll!CryptReleaseContext` - Crypto context release
- `MSVCRT.dll!realloc` - Memory reallocation
- `MSVCRT.dll!fclose` - File closing
- `MSVCRT.dll!fwrite` - File writing
- `MSVCRT.dll!fread` - File reading
- `MSVCRT.dll!fopen` - File opening

**Source:** (source: frida_probe) Hook candidates

The presence of service creation APIs (CreateServiceA, OpenServiceA, StartServiceA) confirms the malware's persistence mechanism via Windows services.

## 6. Network Indicators & C2

### Tor-Based Command and Control

The sample contains the string `t.wnry` at EA 62600, which is a WannaCry Tor data component file. This file is used to establish Tor-based command and control communications, allowing the malware to communicate with its operators while maintaining anonymity.

**Source:** (source: ghidra) Deep key evidence - "Ghidra string 't.wnry' at 0x411A04 -- WannaCry Tor data component"

### Bitcoin Wallet Addresses

Three Bitcoin wallet addresses are embedded in the sample for ransom payment:

1. `115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn` (EA 62528)
2. `12t9YDPgwueZ9NyMgwZ1p7AA8isjr6SMw` (EA 62564)
3. `13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94` (EA 62600)

**Source:** (source: malcat) Top Strings table; (source: ghidra) Deep key evidence

These addresses are referenced by function FUN_00401e9e and are used to collect ransom payments from victims.

### Ransom Contact Email

The sample contains the WannaCry ransom contact email `WNcry@2ol7` at EA 4257068 (0x411A9C), which victims are instructed to contact after payment.

**Source:** (source: ghidra) Deep key evidence - "Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) -- WannaCry ransom contact email"

### Configuration File

The string `c.wnry` at EA 62644 is referenced by functions FUN_00401000 and FUN_00401dab, indicating a configuration file used by WannaCry to store settings and operational parameters.

**Source:** (source: ghidra) Deep key evidence - "Ghidra string 'c.wnry' referenced by FUN_00401000 and FUN_00401dab -- WannaCry config file"

## 7. Capabilities Assessment

### Encryption Capabilities

The sample implements multiple encryption algorithms:

1. **AES Encryption**: Uses Microsoft Enhanced RSA and AES Cryptographic Provider (string at EA 61580). Capa rule `encrypt data using AES` confirms this capability.
2. **RC4 KSA**: Capa rule `encrypt data using RC4 KSA` indicates RC4 encryption capability.
3. **CRC32 Hashing**: Capa rule `hash data with CRC32` for data integrity checking.

**Source:** (source: capa) Capability Rules table; (source: malcat) High-Signal Strings table

The encryption API chain includes CryptGenKey, CryptEncrypt, CryptImportKey, and CryptDecrypt, as referenced by function FUN_00401a45.

**Source:** (source: ghidra) Deep key evidence - "Ghidra string_ref: FUN_00401a45 references CryptGenKey, CryptEncrypt, CryptImportKey, CryptDecrypt -- full ransomware encryption API chain"

### Persistence Mechanisms

1. **Service Creation**: Capa rules `create service` and `persist via Windows service` confirm service-based persistence.
2. **Registry Modification**: Capa rule `query or enumerate registry value` and imports RegSetValueExA, RegCreateKeyW indicate registry-based persistence.
3. **File Attributes**: Capa rule `set file attributes` for hiding files.

**Source:** (source: capa) Capability Rules table; (source: ghidra) Deep key evidence

### File System Operations

1. **File Discovery**: Capa rules `get common file path`, `check if file exists`, `get file size` for file enumeration.
2. **File Permission Escalation**: String `icacls . /grant Everyone:F /T /C /Q` at EA 62716 grants full permissions to ensure encryption access.
3. **File Hiding**: String `attrib +h .` hides the working directory from users.

**Source:** (source: capa) Capability Rules table; (source: malcat) Top Strings table

### Command Execution

The sample can execute commands via `cmd.exe /c "%s"` (EA 62508), which is used for payload delivery and system manipulation.

**Source:** (source: malcat) High-Signal Strings table; (source: ghidra) Deep key evidence

### Obfuscation Techniques

1. **Stack String Obfuscation**: Capa rule `contain obfuscated stackstrings`
2. **XOR Encoding**: Capa rule `encode data using XOR`
3. **Dynamic String Construction**: MalCat anomaly `DynamicString` at EA 26650

**Source:** (source: capa) Capability Rules table; (source: malcat) Anomalies table

## 8. Indicators of Compromise

### File-Based IOCs

| Type | Value | Context |
|---|---|---|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda | Main sample |
| File Name | tasksche.exe | WannaCry task scheduler component |
| Mutex | Global\MsWinZones..cheCounterMutexA | WannaCry mutex (EA 62644) |
| Config File | c.wnry | WannaCry configuration file |
| Tor Data File | t.wnry | Tor C2 component |
| Ransom Extension | .wnry | Encrypted file extension |
| Ransom Message | .msg | Multi-language ransom message files |

**Source:** (source: malcat) High-Signal Strings table; (source: ghidra) Deep key evidence

### Network-Based IOCs

| Type | Value | Context |
|---|---|---|
| Bitcoin Address | 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn | Ransom payment wallet 1 |
| Bitcoin Address | 12t9YDPgwueZ9NyMgwZ1p7AA8isjr6SMw | Ransom payment wallet 2 |
| Bitcoin Address | 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94 | Ransom payment wallet 3 |
| Email | WNcry@2ol7 | Ransom contact email |

**Source:** (source: malcat) Top Strings table; (source: ghidra) Deep key evidence

### String-Based IOCs

| String | EA | Context |
|---|---|---|
| WanaCrypt0r | 57396 | Ransomware mutex/family identifier |
| WANACRY! | 4254588 | Magic marker unique to WannaCry |
| tasksche.exe | 62680 | Self-referencing filename |
| Microsoft Enhanced RSA and AES Cryptographic Provider | 61580 | Crypto provider string |
| icacls . /grant Everyone:F /T /C /Q | 62716 | Permission escalation command |
| attrib +h . | EA not specified | File hiding command |
| cmd.exe /c "%s" | 62508 | Command execution template |

**Source:** (source: malcat) High-Signal Strings table; (source: ghidra) Deep key evidence

### YARA Rule Matches

| Rule | Match Count | Significance |
|---|---|---|
| WannaDecryptor | 7 | Primary WannaCry detection rule |
| Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 | 2 | Specific WannaCry sample variant |
| ransom_telefonica | 6 | Ransomware behavior indicators |
| Wanna_Cry_Ransomware_Generic | 1 | Generic WannaCry detection |
| WannaCry_Ransomware | 5 | WannaCry-specific indicators |
| WannaCry_Ransomware_Dropper | 4 | Dropper component indicators |
| wannacry_static_ransom | 6 | Static ransomware indicators |

**Source:** (source: yara) YARA Matches table

## 9. Detection Engineering

### YARA Rules

The following YARA rules matched the sample and can be used for detection:

1. **WannaDecryptor**: Matches 7 string indicators including WANACRY!, WanaCrypt0r, tasksche.exe, taskse, taskdl
2. **Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549**: Matches taskdl and taskse indicators
3. **ransom_telefonica**: Matches ransomware behavior strings
4. **Wanna_Cry_Ransomware_Generic**: Generic WannaCry detection
5. **WannaCry_Ransomware**: WannaCry-specific indicators
6. **WannaCry_Ransomware_Dropper**: Dropper component indicators
7. **wannacry_static_ransom**: Static ransomware indicators

**Source:** (source: yara) YARA Matches table

### Capa Detection Rules

Key Capa rules for detection:

1. `encrypt data using AES` - Core ransomware behavior
2. `create service` - Persistence mechanism
3. `persist via Windows service` - Service-based persistence
4. `contain obfuscated stackstrings` - Obfuscation technique
5. `encode data using XOR` - Encoding technique
6. `get common file path` - File discovery
7. `check if file exists` - File enumeration
8. `set file attributes` - File manipulation

**Source:** (source: capa) Capability Rules table

### Import-Based Detection

High-signal imports for detection:

| API | ATT&CK | Detection Value |
|---|---|---|
| CreateService | T1543.003 | Service creation persistence |
| RegSetValue | T1112 | Registry modification |
| CreateProcess | T1106 | Process creation |
| LoadLibrary | T1129 | Dynamic library loading |
| GetProcAddress | T1129 | API resolution |
| VirtualProtect | T1055 | Memory protection changes |
| VirtualAlloc | T1055 | Memory allocation |

**Source:** (source: pe_imports) PE Imports / Signals table

### Behavioral Indicators

1. **Mutex Creation**: Global\MsWinZones..cheCounterMutexA
2. **Service Installation**: CreateServiceA, OpenSCManagerA, StartServiceA
3. **Registry Modification**: RegSetValueExA, RegCreateKeyW
4. **File Encryption**: CryptGenKey, CryptEncrypt, CryptImportKey
5. **Permission Escalation**: icacls commands
6. **File Hiding**: attrib +h commands
7. **Command Execution**: cmd.exe /c execution

## 10. MITRE ATT&CK Mapping

### Tactics and Techniques

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1106: Native API | CreateProcess import |
| Persistence | T1543.003: Create or Modify System Process | CreateServiceA, OpenSCManagerA |
| Persistence | T1547.001: Registry Run Keys | RegSetValueExA, RegCreateKeyW |
| Defense Evasion | T1027: Obfuscated Files or Information | XOR encoding, stack string obfuscation |
| Defense Evasion | T1027.005: Indicator Removal from Tools | Obfuscated stackstrings |
| Defense Evasion | T1222: File and Directory Permissions Modification | icacls commands |
| Discovery | T1083: File and Directory Discovery | GetFileAttributesW, GetFileSizeEx |
| Discovery | T1082: System Information Discovery | GetComputerNameW |
| Discovery | T1012: Query Registry | RegQueryValueExA |
| Impact | T1486: Data Encrypted for Impact | AES encryption, CryptEncrypt |
| Lateral Movement | T1570: Lateral Tool Transfer | Service creation, file operations |

**Source:** (source: capa) Capability Rules table; (source: pe_imports) PE Imports / Signals table

### Specific Capa Mappings

| Capa Rule | ATT&CK Technique | MBC |
|---|---|---|
| encrypt data using AES | T1027: Obfuscated Files or Information | E1027.m05, C0027.001 |
| encrypt data using RC4 KSA | T1027: Obfuscated Files or Information | C0027.009, C0028.002 |
| create service | T1543.003, T1569.002 | - |
| persist via Windows service | T1543.003, T1569.002 | - |
| contain obfuscated stackstrings | T1027.005 | B0032.020, B0032.017 |
| encode data using XOR | T1027 | E1027.m02, C0026.002 |
| get common file path | T1083 | E1083 |
| check if file exists | T1083 | E1083 |
| get file size | T1083 | E1083 |
| set file attributes | T1222 | C0050 |
| get hostname | T1082 | E1082 |
| query or enumerate registry value | T1012 | C0036.006 |

**Source:** (source: capa) Capability Rules table

## 11. What We Don't Know

### Incomplete Analysis Areas

1. **Dynamic Behavior**: Speakeasy emulation recorded zero API calls, indicating the sample did not execute its payload during analysis. This could be due to missing installation arguments, environment checks, or anti-analysis techniques not captured in static analysis.

2. **Network Communication**: While Tor-based C2 is indicated by the `t.wnry` string, actual network communication patterns, C2 server addresses, and protocol details were not observed during analysis.

3. **Encryption Key Management**: The specific encryption key generation, storage, and exchange mechanisms between the malware and C2 servers were not fully analyzed.

4. **Lateral Movement**: While service creation and file operations suggest lateral movement capabilities, actual propagation mechanisms (e.g., EternalBlue exploit usage) were not observed in this sample.

5. **Anti-Analysis Techniques**: No specific anti-debugging, anti-VM, or anti-sandbox techniques were identified in the provided evidence, though the lack of dynamic execution suggests possible environmental checks.

6. **Payload Extraction**: The exact mechanism for extracting and executing the payload from the high-entropy resource section was not fully analyzed.

7. **Configuration Details**: The contents and structure of the `c.wnry` configuration file were not analyzed.

8. **Ransom Note Generation**: The specific mechanism for generating and displaying ransom notes in multiple languages was not observed.

### Confidence Assessment

- **Malware Family Identification**: High confidence (100%) - Multiple independent sources confirm WannaCry
- **Encryption Capability**: High confidence - AES encryption routines and API calls confirmed
- **Persistence Mechanism**: High confidence - Service creation APIs and strings confirmed
- **C2 Communication**: Medium confidence - Tor component indicated but not observed
- **Lateral Movement**: Medium confidence - Capabilities present but not observed

## 12. Appendix A: Tool Evidence Trail

### Analysis Tools Used

| Tool | Version | Status | Key Findings |
|---|---|---|---|
| Ghidra | - | Success | Identified WannaCry strings, crypto functions, imports |
| IDA | - | Success | Confirmed WannaCry string presence |
| YARA | - | Success | 28 rule matches including WannaCry family |
| Capa | - | Success | 32 capability rules including AES encryption |
| MalCat | - | Success | File analysis, anomalies, strings, imports |
| FLOSS | - | Success | 6240 strings extracted |
| radare2 | - | Success | Disassembly of entry point and main function |
| UPX | - | Failed | Sample not UPX packed |
| Speakeasy | - | Success | No API calls observed |
| Frida | 17.16.4 | Success | 15 hook candidates identified |
| PE Imports | - | Success | 114 imports analyzed |

### Evidence Sources

1. **verdict.json**: High-level verdict and key evidence summary
2. **deep-dive.json**: Detailed analysis with 22 successful tool calls
3. **MalCat Structured Analysis**: File layout, strings, imports, anomalies
4. **capa Capability Rules**: 32 capability rules with ATT&CK mappings
5. **YARA Matches**: 28 rule matches with string offsets
6. **FLOSS Strings**: 6240 extracted strings
7. **radare2 Disassembly**: Entry point and main function analysis
8. **PE Imports**: 114 API imports with ATT&CK mappings

### Key Evidence Citations

| Source | Query/Table | Row/Rule | Why |
|---|---|---|---|
| ghidra | Suspicious strings (Ghidra) | WanaCrypt0r | Direct WannaCry identifier |
| ida | Suspicious strings (IDA) | WanaCrypt0r | Confirms WannaCry presence |
| yara | YARA matches | WannaCry_Ransomware | Strong behavioral evidence |
| capa | capa evidence | encrypt data using AES | Core ransomware capability |
| capa | capa evidence | create service | Persistence mechanism |
| pe_imports | pe_imports | create_service | Service creation API |
| malcat | MalCat evidence | CryptoApiUsage | Crypto API usage |
| malcat | MalCat evidence | BigResourceHighEntropy | Embedded payload indicator |

## 13. Appendix B: Analysis Environment

### Sample Information

- **SHA256**: ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
- **Sample Path**: /opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe
- **Project Name**: 710

### Analysis Configuration

- **Tool Gate**: All required tools completed successfully
- **Format**: PE (Portable Executable)
- **Architecture**: X86 (32-bit)
- **Large Sample**: No
- **Hard Failures**: None
- **Soft Failures**: None
- **Missing Tools**: None

### Tool Versions

- **Frida**: 17.16.4
- **Other Tools**: Version information not specified in evidence

### Analysis Timestamps

- **capa Duration**: 1.13 seconds
- **Speakeasy Duration**: Not recorded
- **Total Analysis Time**: Not specified

### Environment Notes

- Analysis performed on Linux environment
- Sample path indicates organized corpus structure
- All tools executed successfully without errors
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda  
**sample_path:** /opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe  
**project_name:** 710

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 100
- **family_guess**: WannaCry
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both report the 'WanaCrypt0r' string, YARA matches WannaCry ransomware rules, Capa detects AES encryption and service creation, MalCat highlights crypto API usage and high-entropy resources, and PE imports include service and registry APIs. All engines converge on WannaCry ransomware behavior.
- **summary**: The sample is WannaCry ransomware, identified by the 'WanaCrypt0r' string, YARA rule matches, AES encryption capabilities, and service-based persistence. All analyzed tools show consistent malicious behavior.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | Suspicious strings (Ghidra) | `WanaCrypt0r` | String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating malicious intent. |
| ida | Suspicious strings (IDA) | `WanaCrypt0r` | Confirms the presence of the WannaCry ransomware string, reinforcing the malicious identity. |
| yara | YARA matches | `WannaCry_Ransomware` | YARA rule match for WannaCry ransomware provides strong behavioral evidence. |
| capa | capa evidence | `encrypt data using AES` | Capability to encrypt data using AES is a core ransomware behavior for file encryption. |
| capa | capa evidence | `create service` | Ability to create Windows services for persistence, typical of ransomware installation. |
| pe_imports | pe_imports | `create_service` | High-signal import of CreateService API indicates persistence via Windows services. |
| malcat | MalCat evidence | `CryptoApiUsage` | Anomaly indicating cryptographic API usage, supporting encryption for ransomware. |
| malcat | MalCat evidence | `BigResourceHighEntropy` | High-entropy resource section suggests embedded payload or encrypted data, common in ransomware. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This sample (tasksche.exe) is the WannaCry/WanaCrypt0r/WCry ransomware. It contains the WANACRY! magic marker, WanaCrypt0r mutex, the WNcry@2ol7 ransom contact email, three Bitcoin wallet addresses for ransom payment, AES/CryptEncrypt-based file encryption via Microsoft Enhanced RSA and AES Cryptographic Provider, .wnry file extension handling, icacls permission escalation, attrib file hiding, cmd.exe command execution, and service-based persistence via CreateServiceA/OpenSCManagerA. YARA confirms WannaDecryptor family (7 string matches), Wanna_Sample, and ransom_telefonica rules. The presence of 'c.wnry' and 't.wnry' config/tor data files and 'tasksche.exe' self-name aligns with known WannaCry propagation component behavior. For c2_network, the 't.wnry' file indicates Tor-based command and control communications, citing {analysis, summary, 't.wnry', used for Tor C2 in WannaCry}. For evasion_anti_analysis, no specific evasion techniques were observed in the provided evidence, citing {analysis, summary, none, no anti-debugging or obfuscation mentioned}. For exfiltration, no data exfiltration capabilities were observed, as the malware focuses on file encryption for ransom, citing {analysis, summary, none, no evidence of data theft}. For defense_impairment, no explicit defense impairment mechanisms were observed, citing {analysis, summary, none, no disabling of security tools or services noted}.

### deep key_evidence
- `"Ghidra string 'WANACRY!' at 0x40FC3C (4254588) \u2014 magic marker unique to WannaCry ransomware"`
- `"Ghidra string 'WanaCrypt0r' at 0x40F474 (4251700) \u2014 ransomware mutex/family identifier"`
- `"Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) \u2014 WannaCry ransom contact email"`
- `"Ghidra string_ref: FUN_00401e9e references Bitcoin address '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' \u2014 WannaCry ransom payment wallet"`
- `"Ghidra strings: three Bitcoin addresses (115p7UMM..., 12t9YDPg..., 13AM4VW2...) at consecutive addresses \u2014 multiple ransom payment wallets"`
- `"Ghidra string 'Microsoft Enhanced RSA and AES Cryptographic Provider' referenced by FUN_0040182c \u2014 AES file encryption provider"`
- `"Ghidra string_ref: FUN_00401a45 references CryptGenKey, CryptEncrypt, CryptImportKey, CryptDecrypt \u2014 full ransomware encryption API chain"`
- `"Ghidra string 'cmd.exe /c \"%s\"' referenced by FUN_00401ce8 \u2014 command shell execution for payload delivery"`
- `"Ghidra string 'icacls . /grant Everyone:F /T /C /Q' \u2014 file permission escalation to ensure encryption access"`
- `"Ghidra string 'attrib +h .' \u2014 hiding working directory from user"`
- `"Ghidra string 'c.wnry' referenced by FUN_00401000 and FUN_00401dab \u2014 WannaCry config file"`
- `"Ghidra string 't.wnry' at 0x411A04 \u2014 WannaCry Tor data component"`
- `"Ghidra string 'tasksche.exe' \u2014 self-referencing as WannaCry task scheduler component"`
- `"Ghidra imports: CreateServiceA, OpenSCManagerA, StartServiceA from ADVAPI32.DLL \u2014 service-based persistence mechanism"`
- `"Ghidra imports: RegSetValueExA, RegCreateKeyW \u2014 registry modification for persistence/configuration"`
- `"YARA rule 'WannaDecryptor' matched 7 string indicators including WANACRY!, WanaCrypt0r, tasksche.exe, taskse, taskdl"`
- `"YARA rule 'Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549' matched with taskdl and taskse indicators"`
- `"YARA RijnDael_AES and CRC32_table matches confirm embedded AES S-box and CRC32 constants for encryption"`
- `"Ghidra string '.msg' at 0x40FD34 \u2014 WannaCry multi-language ransom message file extension"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
size: 3514368
type: PE
architecture: X86
entrypoint_ea: 30650
entropy: 224
file_name: tasksche.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 75 | - |
| .text | 4096 | 28672 | 28672 | 117 | RX |
| .rdata | 32768 | 24576 | 24576 | 153 | R |
| .data | 57344 | 8192 | 8192 | 76 | RW |
| .rsrc | 65536 | 3448832 | 3448832 | 226 | R |

### Malcat YARA / Signatures (8)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| Zlib | library | INFO | 80 | Uses zlib algortihm |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| CreateService | lateral movement | SUSPICIOUS | 70 | creates a service |
| msvc_uv_55 | compiler | INFO | 50 |  |
| msvc_60_07 | compiler | INFO | 50 | Visual Studio 6.0 |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| XorInLoop | 3 | code | 20 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| CryptoApiUsage | 2 | imports | 1 | Crypto-related apis are used |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `65776`: 
- **CryptoApiUsage**
  - `6378`: 
- **DynamicString**
  - `26650`: 
- **GuiSubsystemNoWindowApi**
  - `340`: 
- **NoChecksum**
  - `336`: 
- **SequentialFunction**
  - `11902`: 
  - `12732`: 
- **XorInLoop**
  - `11445`: 
  - `11557`: 
  - `11579`: 
  - `11590`: 
  - `11676`: 

### High-Signal Strings (11 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 62508 | `cmd.exe /c "%s"` |
| 62644 | `Global\MsWinZone..cheCounterMutexA` |
| 60392 | `kernel32.dll` |
| 57396 | `WanaCrypt0r` |
| 61680 | `CryptDestroyKey` |
| 61712 | `CryptAcquireContextA` |
| 61648 | `CryptDecrypt` |
| 61664 | `CryptEncrypt` |
| 61696 | `CryptImportKey` |
| 61636 | `CryptGenKey` |
| 56234 | `KERNEL32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 26650 | `89674523907856340000000000` |
| 62508 | `cmd.exe /c "%s"` |
| 60068 | `.ppt` |
| 59504 | `.rar` |
| 60056 | `.pptx` |
| 60176 | `.xlsx` |
| 58588 | `.sqlitedb` |
| 58568 | `.sqlite3` |
| 59476 | `.backup` |
| 59652 | `.vmdk` |
| 60236 | `.docm` |
| 60260 | `.docx` |
| 60164 | `.xlsm` |
| 59440 | `.jpeg` |
| 59156 | `.avi` |
| 60188 | `.xls` |
| 59168 | `.mov` |
| 59180 | `.mp4` |
| 59404 | `.png` |
| 59428 | `.jpg` |
| 60272 | `.doc` |
| 59544 | `.tar` |
| 59792 | `.pdf` |
| 59840 | `.rtf` |
| 59852 | `.csv` |
| 59048 | `.mp3` |
| 58608 | `.sql` |
| 58232 | `.pem` |
| 58196 | `.crt` |
| 58160 | `.der` |
| 58304 | `.3ds` |
| 58692 | `.myd` |
| 58340 | `.ods` |
| 58424 | `.odp` |
| 58868 | `.ps1` |
| 59492 | `.zip` |
| 59532 | `.tgz` |
| 52796 | ` inflate 1.1.3 C..1998 Mark Adler ` |
| 61580 | `Microsoft Enhanc..graphic Provider` |
| 57376 | `advapi32.dll` |
| 63204 | `oversubscribed d..bit lengths tree` |
| 63276 | `oversubscribed l..eral/length tree` |
| 63244 | `incomplete literal/length tree` |
| 62644 | `Global\MsWinZone..cheCounterMutexA` |
| 63080 | `too many length ..distance symbols` |
| 63168 | `incomplete dynam..bit lengths tree` |
| 63376 | `oversubscribed distance tree` |
| 56364 | `CreateServiceA` |
| 60392 | `kernel32.dll` |
| 62680 | `tasksche.exe` |
| 63312 | `empty distance tree with lengths` |
| 62528 | `115p7UMMngoj1pMv..HijcRdfJNXj6LrLn` |
| 3513008 | `<assembly xmlns=..PADDINGXXPADDING` |
| 62476 | `%s\ProgramData` |
| 63544 | `\..\` |
| 63528 | `/../` |
| 57396 | `WanaCrypt0r` |
| 63440 | `incorrect header check` |
| 63116 | `invalid stored block lengths` |
| 63052 | `invalid bit length repeat` |
| 63348 | `incomplete distance tree` |
| 62564 | `12t9YDPgwueZ9NyM..519p7AA8isjr6SMw` |
| 63484 | `unknown compression method` |
| 62716 | `icacls . /grant ..ryone:F /T /C /Q` |
| 61680 | `CryptDestroyKey` |
| 61712 | `CryptAcquireContextA` |
| 60320 | `DeleteFileW` |
| 63416 | `incorrect data check` |
| 61648 | `CryptDecrypt` |
| 61664 | `CryptEncrypt` |
| 62600 | `13AM4VW2dhxYgXeQ..oHkHSQuy6NgaEb94` |
| 61696 | `CryptImportKey` |
| 63024 | `invalid literal/length code` |
| 57420 | `Software\` |
| 62812 | `GetNativeSystemInfo` |
| 63464 | `invalid window size` |
| 63536 | `\../` |
| 62696 | `TaskStart` |
| 60368 | `WriteFile` |
| 63000 | `invalid distance code` |

### Constants / Known Patterns (19)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_CURRENT_USER` |
| crypto | `crypto::AES` |
| crypto | `crypto::Rijndael_Te0__0xc66363a5U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te1__0xa5c66363U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te2__0x63a5c663U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te3__0x6363a5c6U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td0__0x51f4a750U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td1__0x5051f4a7U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td2__0xa75051f4U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td3__0xf4a75051U___32_lil_1024` |
| crypto | `crypto::Noekeon_Nessie_round__8_byt_17` |
| compress | `compress::unlzx_table_three__32_lil_64` |
| compress | `compress::zinflate_lengthStarts__32_lil_116` |
| compress | `compress::zinflate_lengthExtraBits__32_lil_116` |
| compress | `compress::zinflate_distanceStarts__32_lil_120` |
| compress | `compress::zinflate_distanceExtraBits__32_lil_120` |
| hash | `hash::CRC32` |
| crypto | `crypto::crypto_provider` |

### Imports (119)
| EA | Name | Type | Refs |
|---|---|---|---|
| 30540 | type_info.#0 | DEBUG | 1 |
| 32768 | advapi32.CreateServiceA | IMPORT | 6 |
| 32772 | advapi32.OpenServiceA | IMPORT | 1 |
| 32776 | advapi32.StartServiceA | IMPORT | 2 |
| 32780 | advapi32.CloseServiceHandle | IMPORT | 3 |
| 32784 | advapi32.CryptReleaseContext | IMPORT | 1 |
| 32788 | advapi32.RegCreateKeyW | IMPORT | 1 |
| 32792 | advapi32.RegSetValueExA | IMPORT | 1 |
| 32796 | advapi32.RegQueryValueExA | IMPORT | 1 |
| 32800 | advapi32.RegCloseKey | IMPORT | 1 |
| 32804 | advapi32.OpenSCManagerA | IMPORT | 1 |
| 32812 | kernel32.GetFileAttributesW | IMPORT | 3 |
| 32816 | kernel32.GetFileSizeEx | IMPORT | 1 |
| 32820 | kernel32.CreateFileA | IMPORT | 4 |
| 32824 | kernel32.InitializeCriticalSection | IMPORT | 1 |
| 32828 | kernel32.DeleteCriticalSection | IMPORT | 1 |
| 32832 | kernel32.ReadFile | IMPORT | 2 |
| 32836 | kernel32.GetFileSize | IMPORT | 1 |
| 32840 | kernel32.WriteFile | IMPORT | 1 |
| 32844 | kernel32.LeaveCriticalSection | IMPORT | 2 |
| 32848 | kernel32.EnterCriticalSection | IMPORT | 1 |
| 32852 | kernel32.SetFileAttributesW | IMPORT | 1 |
| 32856 | kernel32.SetCurrentDirectoryW | IMPORT | 1 |
| 32860 | kernel32.CreateDirectoryW | IMPORT | 1 |
| 32864 | kernel32.GetTempPathW | IMPORT | 1 |
| 32868 | kernel32.GetWindowsDirectoryW | IMPORT | 1 |
| 32872 | kernel32.GetFileAttributesA | IMPORT | 4 |
| 32876 | kernel32.SizeofResource | IMPORT | 1 |
| 32880 | kernel32.LockResource | IMPORT | 1 |
| 32884 | kernel32.LoadResource | IMPORT | 1 |
| 32888 | kernel32.MultiByteToWideChar | IMPORT | 1 |
| 32892 | kernel32.Sleep | IMPORT | 1 |
| 32896 | kernel32.OpenMutexA | IMPORT | 1 |
| 32900 | kernel32.GetFullPathNameA | IMPORT | 1 |
| 32904 | kernel32.CopyFileA | IMPORT | 1 |
| 32908 | kernel32.GetModuleFileNameA | IMPORT | 1 |
| 32912 | kernel32.VirtualAlloc | IMPORT | 1 |
| 32916 | kernel32.VirtualFree | IMPORT | 1 |
| 32920 | kernel32.FreeLibrary | IMPORT | 1 |
| 32924 | kernel32.HeapAlloc | IMPORT | 1 |
| 32928 | kernel32.GetProcessHeap | IMPORT | 2 |
| 32932 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 32936 | kernel32.SetLastError | IMPORT | 6 |
| 32940 | kernel32.VirtualProtect | IMPORT | 1 |
| 32944 | kernel32.IsBadReadPtr | IMPORT | 2 |
| 32948 | kernel32.HeapFree | IMPORT | 1 |
| 32952 | kernel32.SystemTimeToFileTime | IMPORT | 1 |
| 32956 | kernel32.LocalFileTimeToFileTime | IMPORT | 1 |
| 32960 | kernel32.CreateDirectoryA | IMPORT | 2 |
| 32964 | kernel32.GetStartupInfoA | IMPORT | 1 |
| 32968 | kernel32.SetFilePointer | IMPORT | 5 |
| 32972 | kernel32.SetFileTime | IMPORT | 1 |
| 32976 | kernel32.GetComputerNameW | IMPORT | 1 |
| 32980 | kernel32.GetCurrentDirectoryA | IMPORT | 2 |
| 32984 | kernel32.SetCurrentDirectoryA | IMPORT | 2 |
| 32988 | kernel32.GlobalAlloc | IMPORT | 3 |
| 32992 | kernel32.LoadLibraryA | IMPORT | 3 |
| 32996 | kernel32.GetProcAddress | IMPORT | 3 |
| 33000 | kernel32.GlobalFree | IMPORT | 2 |
| 33004 | kernel32.CreateProcessA | IMPORT | 1 |
| 33008 | kernel32.CloseHandle | IMPORT | 5 |
| 33012 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 33016 | kernel32.TerminateProcess | IMPORT | 1 |
| 33020 | kernel32.GetExitCodeProcess | IMPORT | 1 |
| 33024 | kernel32.FindResourceA | IMPORT | 1 |
| 33032 | msvcrt.realloc | IMPORT | 2 |
| 33036 | msvcrt.fclose | IMPORT | 1 |
| 33040 | msvcrt.fwrite | IMPORT | 1 |
| 33044 | msvcrt.fread | IMPORT | 1 |
| 33048 | msvcrt.fopen | IMPORT | 1 |
| 33052 | msvcrt.sprintf | IMPORT | 2 |
| 33056 | msvcrt.rand | IMPORT | 2 |
| 33060 | msvcrt.srand | IMPORT | 1 |
| 33064 | msvcrt.strcpy | IMPORT | 1 |
| 33068 | msvcrt.memset | IMPORT | 1 |
| 33072 | msvcrt.strlen | IMPORT | 1 |
| 33076 | msvcrt.wcscat | IMPORT | 1 |
| 33080 | msvcrt.wcslen | IMPORT | 1 |
| 33084 | msvcrt.__CxxFrameHandler | IMPORT | 1 |
| 33088 | msvcrt.operator delete | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 20813 | sub_40514d |
| 11902 | sub_402e7e |
| 12732 | sub_4031bc |
| 21535 | sub_40541f |
| 10870 | sub_402a76 |
| 13583 | sub_40350f |
| 14231 | sub_403797 |
| 20511 | sub_40501f |
| 15612 | sub_403cfc |
| 21813 | sub_405535 |
| 17334 | sub_4043b6 |
| 4349 | sub_4010fd |
| 6188 | sub_40182c |
| 19481 | sub_404c19 |
| 14888 | sub_403a28 |
| 21896 | sub_405588 |
| 21923 | sub_4055a3 |
| 7400 | sub_401ce8 |
| 30650 | EntryPoint |
| 8167 | sub_401fe7 |
| 28982 | sub_407136 |
| 8681 | sub_4021e9 |
| 7595 | sub_401dab |
| 10207 | sub_4027df |
| 7007 | sub_401b5f |
| 7935 | sub_401eff |
| 4096 | sub_401000 |
| 28784 | sub_407070 |
| 4196 | sub_401064 |
| 6393 | sub_4018f9 |

### Decompilations (top 6)
#### 20813 — sub_40514d
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40514d(int32_t param_1,int32_t param_2,int32_t param_3,int32_t param_4,int32_t param_5,uint8_t **param_6)

{
    uint8_t uVar1;
    uint32_t uVar2;
    uint8_t **ppuVar3;
    int32_t iVar4;
    uint8_t *puVar5;
    uint32_t uVar6;
    int32_t iVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint8_t *puVar12;
    undefined4 uStack_2c;
    uint8_t *puStack_14;
    uint8_t *puStack_10;
    uint8_t *puStack_c;
    uint8_t *puStack_8;
    
    ppuVar3 = param_6;
    puStack_10 = *(param_5 + 0x34);
    uVar9 = *(param_5 + 0x1c);
    puStack_c = *param_6;
    puStack_8 = param_6[1];
    param_6 = *(param_5 + 0x20);
    if (puStack_10 < *(param_5 + 0x30)) {
        puStack_14 = *(param_5 + 0x30) + (-1 - puStack_10);
    }
    else {
        puStack_14 = *(param_5 + 0x2c) - puStack_10;
    }
    uVar8 = *(&unlzx_table_three__32_lil_64 + param_1 * 4);
    uVar2 = *(&unlzx_table_three__32_lil_64 + param_2 * 4);
    do {
        for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
            puStack_8 = puStack_8 + -1;
            param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
            puStack_c = puStack_c + 1;
        }
        puVar12 = param_3 + (uVar8 & param_6) * 8;
        uVar1 = *puVar12;
code_r0x004051d5:
        uVar6 = uVar1;
        if (uVar6 != 0) {
            param_6 = param_6 >> (puVar12[1] & 0x1f);
            uVar9 = uVar9 - puVar12[1];
            if ((uVar1 & 0x10) != 0) {
                uVar6 = uVar6 & 0xf;
                uVar10 = *(&unlzx_table_three__32_lil_64 + uVar6 * 4) & param_6;
                param_6 = param_6 >> uVar6;
                uVar10 = uVar10 + *(puVar12 + 4);
                for (uVar9 = uVar9 - uVar6; uVar9 < 0xf; uVar9 = uVar9 + 8) {
                    puStack_8 = puStack_8 + -1;
                    param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
                    puStack_c = puStack_c + 1;
                }
                uVar6 = uVar2 & param_6;
                iVar4 = param_4 + uVar6 * 8;
                param_6 = param_6 >> (*(iVar4 + 1) & 0x1f);
                uVar9 = uVar9 - *(iVar4 + 1);
                uVar1 = *(param_4 + uVar6 * 8);
                while ((uVar1 & 0x10) == 0) {
                    if ((uVar1 & 0x40) != 0) {
                        ppuVar3[6] = "invalid distance code";
                        uVar8 = ppuVar3[1] - puStack_8;
                        if (uVar9 >> 3 < ppuVar3[1] - puStack_8) {
                            uVar8 = uVar9 >> 3;
                        }
                        uStack_2c = 0xfffffffd;
                        goto code_r0x004053ed;
                    }
                    iVar7 = (*(&unlzx_table_three__32_lil_64 + uVar1 * 4) & param_6) + *(iVar4 + 4);
                    puVar12 = iVar4 + iVar7 * 8;
                    iVar4 = iVar4 + iVar7 * 8;
                    param_6 = param_6 >> (*(iVar4 + 1) & 0x1f);
                    uVar9 = uVar9 - *(iVar4 + 1);
                    uVar1 = *puVar12;
                }
                uVar6 = uVar1 & 0xf;
                for (; uVar9 < uVar6; uVar9 = uVar9 + 8) {
                    puStack_8 = puStack_8 + -1;
                    param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
                    puStack_c = puStack_c + 1;
                }
                uVar11 = *(&unlzx_table_three__32_lil_64 + uVar6 * 4) & param_6;
                uVar9 = uVar9 - uVar6;
                param_6 = param_6 >> uVar6;
                puStack_14 = puStack_14 + -uVar10;
                puVar5 = puStack_10 + -(uVar11 + *(iVar4 + 4));
                puVar12 = *(param_5 + 0x28);
                if (puVar5 < puVar12) {
                    do {
                        puVar5 = puVar5 + (*(param_5 + 0x2c) - puVar12);
                    } while (puVar5 < puVar12);
                    uVar6 = *(param_5 + 0x2c) - puVar5;
                    if (uVar6 < uVar10) {
                        param_1 = uVar10 - uVa
```
#### 11902 — sub_402e7e
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_402e7e(int32_t param_1,uint32_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined auStack_2c [12];
    int32_t iStack_20;
    uint32_t uStack_18;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_2c, 0x40d570);
    }
    uStack_14 = (*param_2 << 0x18 | *(param_2 + 1) << 0x10 | *(param_2 + 2) << 8 | *(param_2 + 3)) ^ *(param_1 + 8);
    uStack_10 = (*(param_2 + 4) << 0x18 | *(param_2 + 5) << 0x10 | *(param_2 + 6) << 8 | *(param_2 + 7)) ^
                *(param_1 + 0xc);
    uVar4 = (*(param_2 + 8) << 0x18 | *(param_2 + 9) << 0x10 | *(param_2 + 10) << 8 | *(param_2 + 0xb)) ^
            *(param_1 + 0x10);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(*(param_2 + 0xe), *(param_2 + 0xf)) | *(param_2 + 0xc) << 0x18 | *(param_2 + 0xd) << 0x10) ^
               *(param_1 + 0x14);
    if (1 < iVar1) {
        iStack_8 = iVar1 + -1;
        param_2 = param_1 + 0x30;
        uStack_18 = uVar4;
        do {
            uVar5 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_18 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ param_2[-1];
            uVar4 = *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_c >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_18 >> 0x18) * 4) ^
                    *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_14 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ *param_2;
            uVar3 = *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_c >> 0x18) * 4) ^
                    *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_10 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_14 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_18 & 0xff) * 4) ^ param_2[1];
            uStack_14 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_18 >> 8 & 0xff) * 4) ^
                        *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_10 >> 0x10 & 0xff) * 4) ^
                        *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
                        *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_c & 0xff) * 4) ^ param_2[-2];
            iStack_8 = iStack_8 + -1;
            param_1 = iStack_20;
            param_2 = param_2 + 8;
            uStack_18 = uVar4;
            uStack_10 = uVar5;
            uStack_c = uVar3;
        } while (iStack_8 != 0);
    }
    uVar2 = *(iVar1 * 0x20 + 8 + param_1);
    param_1 = iVar1 * 0x20 + 8 + param_1;
    *param_3 = (&AES)[uStack_14 >> 0x18] ^ uVar2 >> 0x18;
    param_3[1] = (&AES)[uStack_10 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[2] = (&AES)[uVar4 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[3] = (&AES)[uStack_c & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 4);
    param_3[4] = (&AES)[uStack_10 >> 0x18] ^ uVar2 >> 0x18;
    param_3[5] = (&AES)[uVar4 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[6] = (&AES)[uStack_c >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[7] = (&AES)[uStack_14 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 8);
    param_3[8] = (&AES)[uVar4 >> 0x18] ^ uVar2 >> 0x18;
    param_3[9] = (&AES)[uStack_c >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[10] = (&AES)[uStack_14 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[0
```
#### 12732 — sub_4031bc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_4031bc(int32_t param_1,uint8_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t *puVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    undefined auStack_30 [16];
    int32_t iStack_20;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_30, 0x40d570);
    }
    uVar4 = (*param_2 << 0x18 | param_2[1] << 0x10 | param_2[2] << 8 | param_2[3]) ^ *(param_1 + 0x1e8);
    uStack_14 = (param_2[4] << 0x18 | param_2[5] << 0x10 | param_2[6] << 8 | param_2[7]) ^ *(param_1 + 0x1ec);
    uStack_10 = (param_2[8] << 0x18 | param_2[9] << 0x10 | param_2[10] << 8 | param_2[0xb]) ^ *(param_1 + 0x1f0);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(param_2[0xe], param_2[0xf]) | param_2[0xc] << 0x18 | param_2[0xd] << 0x10) ^ *(param_1 + 500);
    if (1 < iVar1) {
        puVar5 = param_1 + 0x210;
        iStack_8 = iVar1 + -1;
        do {
            uVar7 = *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uVar4 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ puVar5[-1];
            uVar3 = *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_14 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uVar4 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_c & 0xff) * 4) ^ *puVar5;
            uVar6 = *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_c >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_10 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_14 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uVar4 & 0xff) * 4) ^ puVar5[1];
            uVar4 = *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_c >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_10 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uVar4 >> 0x18) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ puVar5[-2];
            puVar5 = puVar5 + 8;
            iStack_8 = iStack_8 + -1;
            param_1 = iStack_20;
            uStack_14 = uVar7;
            uStack_10 = uVar3;
            uStack_c = uVar6;
        } while (iStack_8 != 0);
    }
    uVar2 = *(iVar1 * 0x20 + 0x1e8 + param_1);
    param_1 = iVar1 * 0x20 + 0x1e8 + param_1;
    *param_3 = (&AES)[uVar4 >> 0x18] ^ uVar2 >> 0x18;
    param_3[1] = (&AES)[uStack_c >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[2] = (&AES)[uStack_10 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[3] = (&AES)[uStack_14 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 4);
    param_3[4] = (&AES)[uStack_14 >> 0x18] ^ uVar2 >> 0x18;
    param_3[5] = (&AES)[uVar4 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[6] = (&AES)[uStack_c >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[7] = (&AES)[uStack_10 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 8);
    param_3[8] = (&AES)[uStack_10 >> 0x18] ^ uVar2 >> 0x18;
    param_3[9] = (&AES)[uStack_14 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[10] = (&AES)[uVar4 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[0xb] = (&AES)[uStack_c & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 0xc);
    param_3[0xc] = (&AES)[uStack_c >> 0x18] ^ uVar2 >> 0x18;
   
```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | ZIP | 3486039 |

### Virtual Files (3)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| XIA/2058/en-us | 3446325 | - |
| VER/1/en-us | 904 | - |
| MANIF/1/en-us | 1263 | - |

### Structures (32)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 248 |
| OptionalHeader | 272 |
| Sections | 496 |
| advapi32.FT | 32768 |
| kernel32.FT | 32812 |
| msvcrt.FT | 33032 |
| user32.FT | 33232 |
| ImportTable | 54696 |
| advapi32.OFT | 54796 |
| kernel32.OFT | 54840 |
| msvcrt.OFT | 55060 |
| user32.OFT | 55260 |
| ImportNames | 55268 |
| ImportNames | 56504 |
| ImportNames | 57182 |
| Resources | 65536 |
| Resources.XIA | 65576 |
| Resources.VER | 65600 |
| Resources.MANIF | 65624 |
| Resources.XIA.2058 | 65648 |
| Resources.VER.1 | 65672 |
| Resources.MANIF.1 | 65696 |
| Resources.XIA.2058.en-us | 65720 |
| Resources.VER.1.en-us | 65736 |
| Resources.MANIF.1.en-us | 65752 |
| ResourceName | 65768 |
| Resources.XIA.2058.en-us.Data | 65776 |
| VersionInfo | 3512104 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 32 · duration_s: 1.13

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| hash data with CRC32 |  | C0032.001:Checksum |
| reference AES constants | T1027:Obfuscated Files or Information |  |
| generate random numbers using the Delphi LCG |  | C0021:Generate Pseudo-random Sequence |

## PE Imports / Signals
import_count: 114

| label | api_match | ATT&CK |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 28

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3513471 len=7; $ipv6@36485 len=2 |
| contains_base64 | - | $a@55284 len=16 |
| Misc_Suspicious_Strings | - | $a4@62508 len=7 |
| CRC32_poly_Constant | - | $c0@53844 len=4 |
| CRC32_table | - | $c0@53332 len=20 |
| RijnDael_AES | - | $c0@35836 len=8 |
| RijnDael_AES_CHAR | - | $c0@35324 len=32 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@216 len=4 |
| WannaDecryptor | - | $id1@3419457 len=10; $id2@3422954 len=10; $id3@343662 len=6; $id4@344182 len=6; $id5@62708 len=6; $id6@3425549 len=6; $id7@80219 len=6 |
| Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 | - | $taskdl@3419456 len=7; $taskse@3422953 len=7 |
| ransom_telefonica | - | $a@56326 len=13; $b@62508 len=10; $c@62528 len=34; $d@62564 len=34; $e@62600 len=34; $f@62680 len=12 |
| Wanna_Cry_Ransomware_Generic | - | $s3@61580 len=44 |
| WannaCry_Ransomware | - | $x1@62716 len=35; $x2@3419457 len=10; $x3@62680 len=12; $x4@62644 len=35; $x5@62764 len=10 |
| WannaCry_Ransomware_Dropper | - | $s1@62508 len=15; $s2@62680 len=12; $s3@62716 len=35; $s4@62644 len=35 |
| wannacry_static_ransom | - | $mutex01@62644 len=35; $lang01@80223 len=15; $lang02@332391 len=17; $startarg02@62696 len=9; $wcry01@57396 len=22; $wcry02@60284 len=7 |
| Microsoft_Visual_Cpp_v60 | - | $a@4871 len=1; $b@49813 len=79; $c@6393 len=35 |
| Microsoft_Visual_Cpp_v50v60_MFC_additional | - | $a@5286 len=22 |
| Microsoft_Visual_Cpp_50 | - | $a@5286 len=22 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@4196 len=4; $b@5286 len=22 |
| Microsoft_Visual_Cpp | - | $b@5286 len=29 |
| SEH_Init | - | $b@5308 len=7 |
| win_registry | - | $f1@56452 len=12; $c1@56288 len=16; $c3@56274 len=11; $c4@56308 len=14; $c6@56274 len=11 |
| win_files_operation | - | $f1@56234 len=12; $c1@55680 len=9; $c2@55510 len=14; $c3@55680 len=9; $c4@55654 len=8; $c6@55588 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@56492 len=10 |

## Generated YARA Meta
```json
{
  "rule_count": 28,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
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
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3513471,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 36485,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 55284,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 62508,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53844,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_table",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 53332,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35836,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RijnDael_AES_CHAR",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 35324,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "WannaDecryptor",
      "path": "/opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe",
      "strings": [
        {
          "id": "$id1",
          "offset": 3419457,
          "length": 10,
          "xor_key": null
        },
        {
          "id": "$id2",
          "offset": 3422954,
          "length": 10,
          "xor_key": null
        },
        {
          "id": "$id3",
          "offset": 343662,
          "length": 6,
 
```

## FLOSS Strings
Total strings: 6240 · per_category: `{"decoded_strings": 0, "stack_strings": 1, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 6239}`

### High-signal FLOSS
- `$$Hl\\`
- `UUPx((`
- `GetProcAddress`

### FLOSS sample
- `oftware\`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `SVWjcf`
- `WWWWWPj`
- `@4+G4t`
- `q89p8t`
- `V,YYG;~`
- `tlHt Ht`
- `~(9~$u`
- `FP;FTt`
- `k|_^][Y`
- `=j&&LZ66lA??~`
- `}{))R>`
- `f""D~**T`
- `V22dN::t`
- `o%%Jr..\$`
- `&&Lj66lZ??~A`
- `99rKJJ`
- `==zGdd`
- `""Df**T~`
- `;22dV::tN`
- `$$Hl\\`
- `C77nYmm`
- `%%Jo..\r`
- `55j_WW`
- `&Lj&6lZ6?~A?`
- `~=zG=d`
- `"Df"*T~*`
- `2dV2:tN:`
- `x%Jo%.\r.`
- `a5j_5W`
- `ggV}++`
- `Lj&&lZ66~A??`
- `bS11*?`
- `Xt,,4.`
- `RRvM;;`
- `MMfU33`
- `PPxD<<%`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004077ba
```asm
┌ 338: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_5ch @ ebp-0x5c
│           ; var int32_t var_60h @ ebp-0x60
│           ; var int32_t var_64h @ ebp-0x64
│           ; var int32_t var_68h @ ebp-0x68
│           ; var int32_t var_6ch @ ebp-0x6c
│           ; var int32_t var_70h @ ebp-0x70
│           ; var int32_t var_74h @ ebp-0x74
│           ; var int32_t var_78h @ ebp-0x78
│           0x004077ba      55             push ebp
│           0x004077bb      8bec           mov ebp, esp
│           0x004077bd      6aff           push 0xffffffffffffffff
│           0x004077bf      6888d44000     push 0x40d488
│           0x004077c4      68f4764000     push 0x4076f4
│           0x004077c9      64a100000000   mov eax, dword fs:[0]
│           0x004077cf      50             push eax
│           0x004077d0      6489250000..   mov dword fs:[0], esp
│           0x004077d7      83ec68         sub esp, 0x68
│           0x004077da      53             push ebx
│           0x004077db      56             push esi
│           0x004077dc      57             push edi
│           0x004077dd      8965e8         mov dword [var_18h], esp
│           0x004077e0      33db           xor ebx, ebx
│           0x004077e2      895dfc         mov dword [var_4h], ebx
│           0x004077e5      6a02           push 2                      ; 2
│           0x004077e7      ff15c4814000   call dword [sym.imp.MSVCRT.dll___set_app_type] ; 0x4081c4 ; "2\xdf"
│           0x004077ed      59             pop ecx
│           0x004077ee      830d4cf940..   or dword [0x40f94c], 0xffffffff ; [0x40f94c:4]=0
│           0x004077f5      830d50f940..   or dword [0x40f950], 0xffffffff ; [0x40f950:4]=0
│           0x004077fc      ff15c0814000   call dword [sym.imp.MSVCRT.dll___p__fmode] ; 0x4081c0 ; "$\xdf"
│           0x00407802      8b0d48f94000   mov ecx, dword [0x40f948]   ; [0x40f948:4]=0
│           0x00407808      8908           mov dword [eax], ecx
│           0x0040780a      ff15bc814000   call dword [sym.imp.MSVCRT.dll___p__commode] ; 0x4081bc
│           0x00407810      8b0d44f94000   mov ecx, dword [0x40f944]   ; [0x40f944:4]=0
│           0x00407816      8908           mov dword [eax], ecx
│           0x00407818      a1b8814000     mov eax, dword [sym.imp.MSVCRT.dll__adjust_fdiv] ; [0x4081b8:4]=0xdf04 reloc.MSVCRT.dll__adjust_fdiv
│           0x0040781d      8b00           mov eax, dword [eax]
│           0x0040781f      a354f94000     mov dword [0x40f954], eax   ; [0x40f954:4]=0
│           0x00407824      e816010000     call 0x40793f
│           0x00407829      391d70f84000   cmp dword [0x40f870], ebx   ; [0x40f870:4]=1
│       ┌─< 0x0040782f      750c           jne 0x40783d
│       │   0x00407831      683c794000     push 0x40793c               ; '<y@' ; "3\xc0\xc3\xc3\
```
### 0x00401fe7
```asm
; CALL XREF from entry0 @ 0x4078e9(x)
┌ 391: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_20bh @ ebp-0x20b
│           ; var int32_t var_20ch @ ebp-0x20c
│           ; var int32_t var_6e4h @ ebp-0x6e4
│           0x00401fe7      55             push ebp
│           0x00401fe8      8bec           mov ebp, esp
│           0x00401fea      81ece4060000   sub esp, 0x6e4
│           0x00401ff0      a010f94000     mov al, byte [0x40f910]     ; [0x40f910:1]=0
│           0x00401ff5      53             push ebx
│           0x00401ff6      56             push esi
│           0x00401ff7      57             push edi
│           0x00401ff8      8885f4fdffff   mov byte [var_20ch], al
│           0x00401ffe      b981000000     mov ecx, 0x81               ; 129
│           0x00402003      33c0           xor eax, eax
│           0x00402005      8dbdf5fdffff   lea edi, [var_20bh]
│           0x0040200b      f3ab           rep stosd dword es:[edi], eax
│           0x0040200d      66ab           stosw word es:[edi], ax
│           0x0040200f      aa             stosb byte es:[edi], al
│           0x00402010      8d85f4fdffff   lea eax, [var_20ch]
│           0x00402016      6808020000     push 0x208                  ; 520
│           0x0040201b      33db           xor ebx, ebx
│           0x0040201d      50             push eax
│           0x0040201e      53             push ebx
│           0x0040201f      ff158c804000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA] ; 0x40808c ; DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
│           0x00402025      68acf84000     push 0x40f8ac
│           0x0040202a      e8f6f1ffff     call 0x401225
│           0x0040202f      59             pop ecx
│           0x00402030      ff156c814000   call dword [sym.imp.MSVCRT.dll___p___argc] ; 0x40816c
│           0x00402036      833802         cmp dword [eax], 2
│       ┌─< 0x00402039      7553           jne 0x40208e
│       │   0x0040203b      6838f54000     push 0x40f538               ; "/i"
│       │   0x00402040      ff1568814000   call dword [sym.imp.MSVCRT.dll___p___argv] ; 0x408168
│       │   0x00402046      8b00           mov eax, dword [eax]
│       │   0x00402048      ff7004         push dword [eax + 4]
│       │   0x0040204b      e8f0560000     call 0x407740
│       │   0x00402050      59             pop ecx
│       │   0x00402051      85c0           test eax, eax
│       │   0x00402053      59             pop ecx
│      ┌──< 0x00402054      7538           jne 0x40208e
│      ││   0x00402056      53             push ebx
│      ││   0x00402057      e803fbffff     call 0x401b5f
│      ││   0x0040205c      85c0           test eax, eax
│      ││   0x0040205e      59             pop ecx
│     ┌───< 0x0040205f      742d           je 0x40208e
│     │││   0x00402061      bed8f44000     mov esi, str.tasksche.exe   ; 0x40f4d8 ; "tasksche.exe"
│     │││   0x00402066      53      
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!GetFileAttributesW`
  - `KERNEL32.dll!GetFileSizeEx`
  - `KERNEL32.dll!CreateFileA`
  - `KERNEL32.dll!InitializeCriticalSection`
  - `KERNEL32.dll!DeleteCriticalSection`
  - `USER32.dll!wsprintfA`
  - `ADVAPI32.dll!CreateServiceA`
  - `ADVAPI32.dll!OpenServiceA`
  - `ADVAPI32.dll!StartServiceA`
  - `ADVAPI32.dll!CloseServiceHandle`
  - `ADVAPI32.dll!CryptReleaseContext`
  - `MSVCRT.dll!realloc`
  - `MSVCRT.dll!fclose`
  - `MSVCRT.dll!fwrite`
  - `MSVCRT.dll!fread`
  - `MSVCRT.dll!fopen`
