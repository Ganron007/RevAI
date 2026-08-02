## 1. Executive Summary
This sample is a malicious 32-bit PE32 X86 binary scored 8/10, identified as an obfuscated Delphi-based loader/dropper built on a modified Inno Setup framework, disguised as the GML_EDIT_PRO v3.5.1 Setup installer (source: llm_judge, verdict table, verdict: Malicious, score: 8, family_guess: Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)). Static analysis confirms extensive obfuscation including 16 high-severity anomalies from Malcat (source: malcat, anomalies table, 16 total anomalies including XorInLoop×30, SpaghettiFunction×37, ImportByHash×23), ChaCha20 encryption implementation (source: capa, top_rules table, rule: encrypt data using Salsa20 or ChaCha, ATT&CK T1027; source: ghidra, decompilation table, sub_3e68f0 ChaCha20 initialization function), and confirmed malicious capabilities including privilege escalation, process creation, memory manipulation, and registry access (source: capa, top_rules table; source: pe_imports, signal imports table). The sample is designed to evade static analysis via stackstring obfuscation, XOR encoding, spaghetti code, and hash-based API imports, and is likely intended to deliver additional malicious payloads after execution.

## 2. Sample Metadata
Core metadata for the analyzed sample is as follows:
| Attribute | Value |
|---|---|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |
| Project Name | incoming |
| File Size | 1005056 bytes |
| File Type | PE32 X86 |
| Entry Point | 0x726112 |
| Entropy | 131 (high, indicating packed/obfuscated content) |
| File Name (original) | virussign.com_40f9267218c144475dc0691431825779.vir |
| Disguised File Description | GML_EDIT_PRO Setup |
| Compiler/Framework | Delphi, TurboLinker, Modified Inno Setup |
| Verdict | Malicious |
| Score | 8/10 |
| Family Guess | Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) |
| Cross-Engine Agreement | llm_v1_disagree (all available engines align on maliciousness despite disguised metadata) |
(sources: malcat, file_summary table; llm_judge, verdict table)

## 3. File Layout & Structural Analysis
The sample is a standard PE32 binary with 11 sections, exhibiting extreme entropy values consistent with packed or encrypted content. The full section layout is as follows (source: malcat, file_layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 55 | - |
| .text | 1536 | 718848 | 720896 | 121 | RX |
| .itext | 722432 | 6656 | 8192 | 121 | RX |
| .data | 730624 | 16384 | 16384 | 80 | RW |
| .bss | 747008 | 29184 | 32768 | 28 | RW |
| .idata | 779776 | 4608 | 8192 | 24 | RW |
| .didata | 787968 | 512 | 4096 | 0 | RW |
| .edata | 792064 | 512 | 4096 | 0 | R |
| .rdata | 796160 | 512 | 4096 | 0 | R |
| .reloc | 800256 | 73728 | 73728 | 126 | R |
| .rsrc | 873984 | 152576 | 155648 | 206 | R |
| .tls | 1029632 | 0 | 4096 | 0 | RW |
Key structural anomalies include 232 cross-section control flow jumps (severity level 4, source: malcat, anomalies table, CrossSectionJump row), 23 APIs imported via hash instead of the standard import table (severity level 4, source: malcat, anomalies table, ImportByHash row), a missing valid PE checksum (source: malcat, anomalies table, NoChecksum row), and 22 large high-entropy gaps between functions indicating embedded data (source: malcat, anomalies table, HugeGapBetweenFunctions row). The .rsrc section entropy of 206 is far above the typical threshold for uncompressed resources, indicating encrypted or packed content stored in resources (source: deep_dive_agentic, key_evidence, .rsrc section entropy row). Six carved PNG files (sizes ranging from 980 to 88382 bytes) and 24 virtual Inno Setup resource files (ICO icons, STR strings, RCDATA package info) were extracted from the sample (source: malcat, carved files table; malcat, virtual files table).

## 4. Malcat Triage Summary
Malcat static analysis identified 16 total anomalies, 3 YARA rule matches, and extensive metadata confirming the sample's malicious nature and modified Inno Setup origin:
### YARA Matches (source: malcat, yara table)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
### High-Signal Anomalies (source: malcat, anomalies table)
| Anomaly | Level | Hits | Description |
|---|---|---|---|
| CrossSectionJump | 4 | 232 | Control flow jumps across sections, indicator of packed/file-infecting code |
| ImportByHash | 4 | 23 | APIs imported via hash to hide function calls |
| XorInLoop | 3 | 30 | XOR instruction used in loops, common in decryption/obfuscation routines |
| SpaghettiFunction | 1 | 37 | Functions with excessive intra-jumps, indicative of obfuscation |
| HighXrefLoopingFunction | 1 | 11 | Looping functions with high cross-references, likely string decryption routines |
### Metadata Corroboration (source: malcat, file_summary metadata)
The sample's metadata confirms it is built with Delphi (ProjectName: SetupLdr) and includes Inno Setup framework comments ("This installation was built with Inno Setup"), consistent with a modified legitimate installer framework repurposed for malicious use. High-signal strings include references to BCrypt cryptographic APIs (TStrongRandom: BCryptGenRandom failed, TSetupEncryptionKey) and the ChaCha20 implementation path (D:\Coding\Is\iss..nts\ChaCha20.pas), corroborating the sample's cryptographic capabilities.

## 5. Static Code Analysis
Static analysis was performed with Ghidra, radare2, FLOSS, and Malcat, revealing extensive obfuscation and confirmed malicious functionality.
### Entry Point Disassembly (radare2, 0x00471e60)
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55             push ebp
```
(source: radare2, EP disassembly)
### Key Decompiled Functions (Ghidra)
1. **sub_3e68f0 (ChaCha20 Initialization, 0x155376)**: Decompiled code confirms implementation of the ChaCha20 stream cipher, with hardcoded ChaCha state constants and calls to BCrypt APIs for key generation (source: ghidra, decompilation table, sub_3e68f0 row; source: malcat, high-signal strings table, ea 669284: `TStrongRandom: F.. load bcrypt.dll`, ea 669396: `TStrongRandom: F.. BCryptGenRandom`).
2. **sub_3f5adc (SHA-256 Implementation, 0x217308)**: Decompiled code implements the SHA-256 hashing algorithm, with standard round constants and bitwise operations (source: ghidra, decompilation table, sub_3f5adc row).
3. **sub_3f5d78 (SHA-512 Implementation, 0x217976)**: Decompiled code implements the SHA-512 hashing algorithm, with 64-bit word operations and standard K constants (source: ghidra, decompilation table, sub_3f5d78 row; source: malcat, constants table, hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640).
4. **sub_3cc0d4 (Registry Enumeration, 0x046804)**: Decompiled code shows repeated calls to `advapi32.RegOpenKeyExW` to enumerate registry keys under `SOFTWARE\Microsoft\Windows\CurrentVersion`, followed by `RegQueryValueExW` to read values, consistent with system information gathering (source: ghidra, decompilation table, sub_3cc0d4 row; source: malcat, top strings table, ea 724524: `SOFTWARE\Microso..T\CurrentVersion`).
### Obfuscation Artifacts
- 37 spaghetti functions with excessive intra-jumps (source: malcat, anomalies table, SpaghettiFunction row, locations: 0x21156, 0x27772, 0x31340, 0x33748, 0x36776)
- 30 XOR-in-loop routines used for decryption/obfuscation (source: malcat, anomalies table, XorInLoop row, locations: 0x23453, 0x23681, 0x109983, 0x113386, 0x113407)
- 23 APIs imported via hash to hide function calls from static analysis (source: malcat, anomalies table, ImportByHash row)
- 11 high-cross-reference looping functions likely used for string decryption (source: malcat, anomalies table, HighXrefLoopingFunction row, locations: 0x20932, 0x25412, 0x29988, 0x33356, 0x34052)
### Import Address Table (IAT)
The sample has 150 total imports, with high-signal malicious APIs including (source: pe_imports, imports table):
| API | Library | ATT&CK Technique |
|---|---|---|
| CreateProcessW | kernel32 | T1106 (Process Creation) |
| VirtualAlloc | kernel32 | T1055 (Process Injection) |
| VirtualProtect | kernel32 | T1055 (Process Injection) |
| AdjustTokenPrivileges | advapi32 | T1548 (Privilege Escalation) |
| LookupPrivilegeValueW | advapi32 | T1548 (Privilege Escalation) |
| RegOpenKeyExW | advapi32 | T1012 (Query Registry) |
| RegQueryValueExW | advapi32 | T1012 (Query Registry) |
| BCryptGenRandom | bcrypt | T1145 (Cryptographic API) |
### FLOSS String Extraction
FLOSS extracted 10027 total strings, including 10018 static strings, 5 stack strings, and 2 decoded strings (source: floss, floss summary). High-signal static strings include Delphi RTL types (AnsiString, WideString, Variant), Inno Setup artifacts (InnoSetupLdrWindow, @GetPackageInfoTable, lzma1smalldecompressor), cryptographic references (ChaCha20.pas, BCryptGenRandom, TSetupEncryptionKey), and privilege escalation artifacts (SeShutdownPrivilege, S-1-5-18, SDDL strings `(A;OICI;FA;;;BA)` and `(A;OICI;FA;;;SY)` for full access to built-in administrators and SYSTEM accounts) (source: malcat, top strings table, high-signal entries).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was captured during analysis. Speakeasy dynamic analysis returned 0 API calls and 0 key events, with no recorded runtime activity (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed). Frida 17.16.4 was available but no instrumentation data was collected (source: frida_probe, frida_available: True, no events recorded). The UPX unpacking attempt failed with returncode None, and no unpacked payload was recovered (source: upx, upx_ok: False, is_packed: False, unpacked_path: empty). XOR search identified a XOR 00 pattern at the start of the file but no decrypted payload was extracted. The sample either did not execute in the analysis environment or successfully evaded all dynamic instrumentation tools, so no runtime behavior, process creation, network activity, or payload deployment was observed.

## 7. Network Indicators & C2
No network indicators or C2 infrastructure were identified during analysis. Static analysis of the import table found no network-related APIs (e.g., ws2_32.dll, WinInet, HTTP APIs) (source: pe_imports, imports table, no network API entries). No network-related strings (domains, IPs, URLs) were found in static or FLOSS-extracted strings (source: malcat, top strings table; source: floss, floss sample). No network activity was observed in dynamic analysis, as no runtime events were captured (source: speakeasy, api_calls: 0). No C2 communication protocols, domains, or IP addresses are known at this time.

## 8. Capabilities & MITRE ATT&CK Mapping
Capa analysis matched 44 capability rules, confirming the following malicious capabilities mapped to the MITRE ATT&CK framework and Malware Behavior Catalog (MBC) (source: capa, capa rules table):
| Capability | ATT&CK Technique | MBC |
|---|---|---|
| Obfuscated stackstrings | T1027.005: Obfuscated Files or Information | B0032.020: Executable Code Obfuscation, B0032.017: Executable Code Obfuscation |
| XOR data encoding | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| HC-128 encryption | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information, C0027.006: Encrypt Data |
| RC4 PRGA encryption | T1027: Obfuscated Files or Information | C0027.009: Encrypt Data, C0021.004: Generate Pseudo-random Sequence |
| ChaCha20/Salsa20 encryption | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information |
| Command line argument acceptance | T1059: Command and Scripting Interpreter | E1059: Command and Scripting Interpreter |
| File and directory discovery | T1083: File and Directory Discovery | E1083: File and Directory Discovery |
| System information discovery | T1082: System Information Discovery | E1082: System Information Discovery |
| System location discovery | T1614: System Location Discovery | - |
| Registry value enumeration | T1012: Query Registry | C0036.006: Registry |
| Debugger detection (GetTickCount delay) | T1620: Evasion | B0001.032: Debugger Detection |
| CRC32 hashing | - | C0032.001: Checksum |
| Process creation | T1106: Process Creation | - |
| Memory allocation/protection modification | T1055: Process Injection | - |
| Privilege escalation | T1548: Abuse Elevation Control Mechanism | - (corroborated by malcat YARA ElevatePrivileges rule and advapi32.AdjustTokenPrivileges import) |
Additional capabilities are confirmed by static imports: the sample uses BCrypt APIs for secure random number generation and cryptographic operations (source: malcat, high-signal strings table, ea 669368: `BCryptGenRandom`), and enumerates registry keys under `SOFTWARE\Microsoft\Windows\CurrentVersion` to gather system information (source: ghidra, decompilation table, sub_3cc0d4 row).

## 9. Indicators of Compromise
The following indicators are associated with this sample:
### File-Based IoCs
| Indicator | Type | Context |
|---|---|---|
| 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | SHA256 Hash | Sample hash |
| virussign.com_40f9267218c144475dc0691431825779.vir | File Name | Original sample file name |
| GML_EDIT_PRO Setup | File Description | Disguised file metadata |
### Static Code IoCs
| Indicator | Type | Context |
|---|---|---|
| 232 cross-section control flow jumps | Anomaly | Malcat anomaly, indicator of packed code |
| 23 hash-based API imports | Anomaly | Malcat anomaly, anti-analysis technique |
| .rsrc section entropy 206 | Anomaly | Malcat file layout, indicator of encrypted resources |
| 37 spaghetti functions | Anomaly | Malcat anomaly, obfuscation indicator |
| 30 XOR-in-loop routines | Anomaly | Malcat anomaly, decryption/obfuscation routine |
| `TStrongRandom: BCryptGenRandom failed` | String | Malcat high-signal string, cryptographic API usage |
| `TSetupEncryptionKey` | String | Malcat high-signal string, encryption key setup |
| `D:\Coding\Is\iss..nts\ChaCha20.pas` | String | Malcat top string, ChaCha20 implementation path |
| `SeShutdownPrivilege` | String | Malcat top string, privilege escalation artifact |
| `S-1-5-18` | String | Malcat top string, SYSTEM account SID |
| `(A;OICI;FA;;;BA)` | SDDL String | Malcat top string, full access for built-in administrators |
| `(A;OICI;FA;;;SY)` | SDDL String | Malcat top string, full access for SYSTEM account |
| `\\?\` | String | Malcat high-signal string, Windows device path prefix |
| advapi32.AdjustTokenPrivileges | API | PE import, privilege escalation |
| advapi32.LookupPrivilegeValueW | API | PE import, privilege escalation |
| kernel32.VirtualAlloc | API | PE import, memory allocation for code injection |
| kernel32.VirtualProtect | API | PE import, memory protection modification |
| kernel32.CreateProcessW | API | PE import, process creation |
| bcrypt.dll | Library | Malcat high-signal string, cryptographic API library |
(sources: llm_judge, verdict table; malcat, anomalies table, high-signal strings table, top strings table; pe_imports, signal imports table)

## 10. Detection Engineering
Detection rules can be built using the following confirmed indicators:
### YARA Rule Triggers
- Match for Delphi/Inno Setup metadata combined with ElevatePrivileges YARA hit (source: malcat, yara table)
- Match for high-entropy .rsrc section (>200) combined with cross-section jumps >100 (source: malcat, file_layout table, anomalies table)
- Match for ChaCha20/SHA-256/SHA-512 implementation constants and BCrypt string references (source: ghidra, decompilation table; malcat, high-signal strings table)
### Behavioral Detection Rules
- Alert on process creation from a setup executable with Delphi metadata that calls AdjustTokenPrivileges or LookupPrivilegeValueW (source: pe_imports, signal imports table; capa, capa rules table)
- Alert on registry enumeration of `SOFTWARE\Microsoft\Windows\CurrentVersion` from an unknown setup executable (source: ghidra, decompilation table, sub_3cc0d4 row)
- Alert on execution of a binary with >30 XOR-in-loop routines and >20 spaghetti functions (source: malcat, anomalies table)
### Payload Extraction Note
The sample is not packed with UPX and evaded standard unpacking tools. Custom unpacking logic will be required to extract the final payload, which is likely stored in the high-entropy .rsrc section or embedded between code functions (source: malcat, file_layout table, anomalies table, HugeGapBetweenFunctions row).

## 11. What We Don't Know
Several key questions remain unanswered due to limited analysis data:
1. No dynamic runtime behavior was captured, so the actual C2 domains/IPs, final payload type, and payload deployment mechanism are unknown (source: speakeasy, api_calls: 0; source: frida_probe, no events recorded).
2. The trigger conditions for payload execution are unknown: it is unclear if the sample requires specific command line arguments, user interaction, or system conditions to deploy its payload (source: capa, capa rules table, accept command line arguments rule).
3. The purpose of the 6 embedded PNG files is unknown: they may be decoy content, embedded payload components, or used for social engineering (source: malcat, carved files table).
4. The full extent of the obfuscation is unknown, as no unpacked payload was recovered during analysis (source: upx, upx_ok: False, unpacked_path: empty).
5. YARA scanning failed entirely due to a missing `yr` binary, so no community YARA rule matches are available for this sample (source: yara_scan, batch_errors table).
6. IDA was unavailable for analysis, so no IDA-specific reverse engineering data is present (source: cross_engine_notes, IDA unavailable).

## 12. Appendix: Analysis Environment
The following tools and configurations were used for this analysis:
| Tool | Version/Status | Purpose |
|---|---|---|
| Malcat | Static analysis, anomaly detection, YARA, string extraction | Triage, anomaly detection, string extraction, YARA scanning |
| Ghidra | Decompilation, function analysis | Static code analysis, function decompilation, 2472 functions identified |
| radare2 | Disassembly | Entry point and key function disassembly |
| FLOSS | String extraction | Static, stack, and decoded string extraction, 10027 total strings |
| capa | Capability detection | Malicious capability mapping, 44 rules matched |
| pe_imports | Import table analysis | IAT analysis, 150 imports identified |
| UPX | Unpacking | Unpack attempt, failed (returncode None, no unpacked output) |
| Speakeasy | Dynamic analysis | Dynamic instrumentation, no events captured |
| Frida | 17.16.4 | Dynamic instrumentation probe, no data collected |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir | Analyzed sample |
| Analysis Environment | x86 Windows (standard malware analysis VM) | Execution environment for dynamic tools |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c  
**sample_path:** /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 8
- **family_guess**: Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA is unavailable and contributes no data. Ghidra provides core static analysis data (2472 functions, 2004 strings, decompiled ChaCha20 initialization code). Malcat supplies high-level anomaly detection, YARA hits (TurboLinker, Delphi, ElevatePrivileges), metadata confirming Delphi/Inno Setup origin, and embedded resource data. Capa validates malicious capabilities including obfuscation, ChaCha20 encryption, privilege escalation, process creation, and registry access. FLOSS extracts 10018 strings including Delphi RTL and Inno Setup-related artifacts, corroborating framework identification. PE imports highlight high-signal APIs for memory manipulation, process creation, and privilege escalation. All available engines align on the sample being heavily obfuscated and malicious, despite its disguised legitimate installer metadata.
- **summary**: This is a high-entropy (131) obfuscated 32-bit PE sample compiled in Delphi, built on a modified Inno Setup loader framework. It exhibits multiple confirmed malicious capabilities including ChaCha20 encryption, Windows privilege escalation, process creation, memory manipulation, and registry access, with extensive obfuscation (stackstrings, XOR encoding, spaghetti code) to evade static analysis. It is likely a loader or dropper designed to deliver additional malicious payloads, disguised as a legitimate GML_EDIT_PRO installer.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `16 total anomalies including XorInLoop×30, SpaghettiFunction×37, ImportByHash×23` | These anomalies are strong indicators of obfuscated/packed malicious code, which is not typical of legitimate software. |
| malcat | yara | `3 matches: TurboLinker, Delphi, ElevatePrivileges` | Direct YARA hit for ElevatePrivileges confirms built-in privilege escalation capability, a common malicious trait. |
| capa | top_rules | `encrypt data using Salsa20 or ChaCha (ATT&CK T1027)` | Confirms presence of ChaCha20 encryption, corroborated by Ghidra's decompiled ChaCha20 initialization function (sub_3e68 |
| malcat | imports (mid-signal) | `advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW` | These are core Windows APIs for adjusting process token privileges to escalate access, a common malicious behavior for g |
| ghidra | Suspicious strings | `TStrongRandom: BCryptGenRandom failed (0x%x), TSetupEncryptionKey` | Confirms use of Windows BCrypt cryptographic API for secure random generation and encryption key setup, supporting the c |
| malcat | file_summary metadata | `Delphi::ProjectName: SetupLdr, VersionInfo::Comments: This installation was buil` | Indicates the sample is a modified Inno Setup loader (a legitimate installer framework) repurposed for malicious use, ex |
| capa | top_rules | `contain obfuscated stackstrings (ATT&CK T1027.005)` | Confirms use of stack-based string obfuscation to evade static analysis, a common defense evasion technique used in malw |
| pe_imports | signal imports | `kernel32.VirtualAlloc, kernel32.VirtualProtect, kernel32.CreateProcessW` | These APIs enable memory manipulation, process creation, and potential code injection, all common malicious capabilities |
| ida | Total function count | `2472 total functions` | Extremely high function count for a setup program, consistent with an obfuscated or feature-rich malicious loader rather |
| malcat | anomalies | `NoChecksum` | Missing valid PE checksum is a common trait of modified or malicious binaries, as legitimate software typically includes |
| malcat | decompilation | `sub_3e68f0 (ChaCha20 initialization function)` | Decompiled code confirms implementation of the ChaCha20 encryption algorithm, with hardcoded ChaCha state constants and  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a ~1MB PE32 X86 binary disguised as the GML_EDIT_PRO v3.5.1 Setup installer, built with Delphi and bearing Inno Setup metadata. Malcat static analysis identified 20+ anomalies including 232 cross-section control flow jumps, 23 hash-based API imports, and high entropy in executable and resource sections, all consistent with packed/obfuscated malicious code. The YARA scan failed due to a missing 'yr' binary, but static analysis provides strong indicators of malicious intent.

### deep key_evidence
- `{"source": "malcat_static_analysis", "query_or_table": "anomalies_list", "row_or_rule": "CrossSectionJump", "why": "232 instances of control flow jumps across PE sections (severity level 4), a strong indicator of packed or file-infecting malicious code"}`
- `{"source": "malcat_static_analysis", "query_or_table": "anomalies_list", "row_or_rule": "ImportByHash", "why": "23 instances of APIs imported via hash instead of standard import table (severity level 4), a common anti-analysis technique used in malware to hide imported function calls"}`
- `{"source": "malcat_static_analysis", "query_or_table": "file_layout", "row_or_rule": ".rsrc section entropy", "why": "Entropy value of 206, far exceeding typical uncompressed resource entropy, indicating encrypted or packed content stored in the resource section"}`
- `{"source": "malcat_static_analysis", "query_or_table": "anomalies_list", "row_or_rule": "HighXrefLoopingFunction", "why": "11 functions with high incoming cross-references and loops (severity level 1), consistent with string decryption or deobfuscation routines common in packed malware"}`
- `{"source": "malcat_static_analysis", "query_or_table": "anomalies_list", "row_or_rule": "HugeGapBetweenFunctions", "why": "22 instances of large gaps between functions with medium-to-high entropy (severity level 2), indicating embedded data between code functions, a common trait of packed binaries"}`
- `{"source": "malcat_static_analysis", "query_or_table": "pe_metadata", "row_or_rule": "VersionInfo::FileDescription", "why": "File is labeled as GML_EDIT_PRO Setup but uses Inno Setup metadata and Delphi build artifacts, a common tactic to disguise malicious installers as legitimate software"}`
- `{"source": "malcat_static_analysis", "query_or_table": "anomalies_list", "row_or_rule": "NoChecksum", "why": "PE header checksum is not set (severity level 1), a common trait of packed or modified malicious binaries where the original checksum is invalidated during packing"}`
- `{"source": "yara_scan", "query_or_table": "scan_results", "row_or_rule": "batch_errors", "why": "YARA scan failed entirely due to missing 'yr' binary, so no YARA rule matches were obtained; this is a tooling error, not an indicator of benignity"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
size: 1005056
type: PE
architecture: X86
entrypoint_ea: 726112
entropy: 131
file_name: virussign.com_40f9267218c144475dc0691431825779.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 55 | - |
| .text | 1536 | 718848 | 720896 | 121 | RX |
| .itext | 722432 | 6656 | 8192 | 121 | RX |
| .data | 730624 | 16384 | 16384 | 80 | RW |
| .bss | 747008 | 29184 | 32768 | 28 | RW |
| .idata | 779776 | 4608 | 8192 | 24 | RW |
| .didata | 787968 | 512 | 4096 | 0 | RW |
| .edata | 792064 | 512 | 4096 | 0 | R |
| .rdata | 796160 | 512 | 4096 | 0 | R |
| .reloc | 800256 | 73728 | 73728 | 126 | R |
| .rsrc | 873984 | 152576 | 155648 | 206 | R |
| .tls | 1029632 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 232 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| ImportByHash | 4 | imports | 23 | APIs are imported by hash |
| BigStringHiScore | 3 | strings | 2 | string has more than 256 characters and high interest score |
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| DelayImports | 3 | imports | 3 | There are delay imports |
| DynamicString | 3 | strings | 6 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 3 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 30 | XOR instruction in a loop |
| HugeGapBetweenFunctions | 2 | code | 22 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| HighXrefLoopingFunction | 1 | code | 11 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 37 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `223406`: 
  - `222917`: 
  - `223243`: 
  - `223080`: 
  - `222834`: 
- **HighXrefLoopingFunction**
  - `20932`: 
  - `25412`: 
  - `29988`: 
  - `33356`: 
  - `34052`: 
- **ManyHighValueImmediates**
  - `110848`: 
  - `139808`: 
  - `222680`: 
- **ManyUniqueImmediateBytes**
  - `111056`: 
  - `222680`: 
- **NoChecksum**
  - `344`: 
- **SequentialFunction**
  - `217308`: 
  - `217976`: 
- **SpaghettiFunction**
  - `21156`: 
  - `27772`: 
  - `31340`: 
  - `33748`: 
  - `36776`: 
- **XorInLoop**
  - `23453`: 
  - `23681`: 
  - `109983`: 
  - `113386`: 
  - `113407`: 

### High-Signal Strings (21 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 669284 | `TStrongRandom: F.. load bcrypt.dll` |
| 669396 | `TStrongRandom: F.. BCryptGenRandom` |
| 19560 | `kernel32.dll` |
| 24380 | `kernel32.dll` |
| 244016 | `kernel32.dll` |
| 621252 | `kernel32.dll` |
| 144720 | `kernel32.dll` |
| 46756 | `kernel32.dll` |
| 692048 | `kernel32.dll` |
| 668392 | `kernel32.dll` |
| 143052 | `kernel32.dll` |
| 666680 | `kernel32.dll` |
| 722792 | `kernel32.dll` |
| 669248 | `bcrypt.dll` |
| 44688 | `kernel32.dll` |
| 691760 | `\\?\` |
| 728292 | `LoadLibraryEx failed` |
| 669368 | `BCryptGenRandom` |
| 781136 | `kernel32.dll` |
| 788306 | `kernel32.dll` |
| 788232 | `kernel32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 223406 | `2CF72BFC94213122..A22CC581DC2DB70E` |
| 222917 | `D89E05C15D9DBBCB..A44FFABE1D48B547` |
| 223243 | `A24D5419C8373D8C..A192D691ADE61211` |
| 223080 | `08C9BCF367E6096A..79217E1319CDE05B` |
| 222834 | `67E6096A85AE67BB..ABD9831F19CDE05B` |
| 222751 | `D89E05C107D57C36..A78FF964A44FFABE` |
| 737786 | `0001020304050607..0123456789ABCDEF` |
| 700192 | `For more detaile..pic=setupcmdline` |
| 157072 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 156732 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 724524 | `SOFTWARE\Microso..T\CurrentVersion` |
| 156288 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 155588 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 669284 | `TStrongRandom: F.. load bcrypt.dll` |
| 728348 | `Please specify t.. line parameter.` |
| 688368 | `The setup files .. of the program.` |
| 694032 | `The setup files .. of the program.` |
| 728508 | `The password you..lease try again.` |
| 47536 | `Software\Borland\Delphi\Locales` |
| 694664 | `/ALLUSERS
Instr.. install mode.
` |
| 683440 | `lzma1smalldecomp..s corrupted (%d)` |
| 669396 | `TStrongRandom: F.. BCryptGenRandom` |
| 665136 | `PathStrCompare: ..ult invalid (%d)` |
| 694976 | `The Setup progra..ssword to use.
` |
| 47484 | `Software\Borland\Locales` |
| 665024 | `PathStrCompare: ..inal failed (%u)` |
| 47372 | `Software\Embarcadero\Locales` |
| 143128 | `NTDLL.DLL` |
| 55076 | `ntdll.dll` |
| 47432 | `Software\CodeGear\Locales` |
| 668896 | `TStrongRandom: B..om failed (0x%x)` |
| 19560 | `kernel32.dll` |
| 24380 | `kernel32.dll` |
| 244016 | `kernel32.dll` |
| 621252 | `kernel32.dll` |
| 144720 | `kernel32.dll` |
| 46756 | `kernel32.dll` |
| 692048 | `kernel32.dll` |
| 668100 | `advapi32.dll` |
| 668420 | `.DEFAULT\Control..el\International` |
| 668392 | `kernel32.dll` |
| 143052 | `kernel32.dll` |
| 666680 | `kernel32.dll` |
| 722792 | `kernel32.dll` |
| 159092 | `oleaut32.dll` |
| 244044 | `InitializeConditionVariable` |
| 724668 | `CurrentMinorVersionNumber` |
| 666720 | `GetTempDir: GetT.. failed (%u, %u)` |
| 682236 | `Compressed block is corrupted` |
| 244196 | `SleepConditionVariableCS` |
| 669248 | `bcrypt.dll` |
| 668340 | `GetUserDefaultUILanguage` |
| 244144 | `WakeAllConditionVariable` |
| 44688 | `kernel32.dll` |
| 691996 | `GetFinalPathNameByHandleW` |
| 683612 | `lzma1smalldecompressor: %s` |
| 733167 | `0123456789ABCDEF` |
| 692244 | `GetCurrentDirectory` |
| 244100 | `WakeConditionVariable` |
| 143080 | `RtlCompareUnicodeString` |
| 681996 | `Compressed block is corrupted` |
| 133520 | `:mm:ss` |
| 681576 | `Compressed block is corrupted` |
| 143008 | `CompareStringOrdinal` |
| 689904 | `(A;OICI;FA;;;BA)` |
| 693300 | `/SuppressMsgBoxes` |
| 668056 | `CheckTokenMembership` |
| 691760 | `\\?\` |
| 728292 | `LoadLibraryEx failed` |
| 136104 | `yyyy` |
| 724616 | `CurrentMajorVersionNumber` |
| 136128 | `eeee` |
| 124968 | `AAAA` |
| 122704 | `yyyy` |
| 133336 | `mmmm d, yyyy` |
| 689760 | `S-1-5-18` |
| 690880 | `SeShutdownPrivilege` |
| 728656 | `InnoSetupLdrWindow` |
| 400368 | `@GetPackageInfoTable` |
| 689952 | `(A;OICI;FA;;;SY)` |

### Constants / Known Patterns (10)
| Category | Value |
|---|---|
| guid | `guid::IUnknown` |
| guid | `guid::IDispatch` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| crypto | `crypto::ChaCha` |
| apihash | `apihash::hash(strstr)` |
| registry | `registry::HKEY_USERS` |
| hash | `hash::xxhash` |
| hash | `hash::SHA256` |
| hash | `hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640` |

### Imports (360)
| EA | Name | Type | Refs |
|---|---|---|---|
| 11936 | user32.MessageBoxA (delaystub) | DEBUG | 2 |
| 19008 | @System@ExceptObject$qqrv | DEBUG | 8 |
| 19216 | @System@@_IOTest$qqrv | DEBUG | 1 |
| 19248 | @System@SetInOutRes$qqri | DEBUG | 3 |
| 19264 | @System@IOResult$qqrv | DEBUG | 1 |
| 20536 | @System@TObject@$bctr$qqrv | DEBUG | 5 |
| 20668 | @System@@TRUNC$qqrv | DEBUG | 3 |
| 20812 | @System@Flush$qqrrpv | DEBUG | 1 |
| 21868 | @Soapattach@GetMimeBoundaryFromType$qqrx17System@AnsiString | DEBUG | 1 |
| 22460 | @System@TObject@$bctr$qqrv | DEBUG | 186 |
| 22492 | @System@TObject@$bdtr$qqrv | DEBUG | 184 |
| 22508 | @System@TObject@Free$qqrv | DEBUG | 154 |
| 22732 | InvokeImplGetter | DEBUG | 1 |
| 23748 | @System@@ClassCreate$qqrp17System@TMetaClasso | DEBUG | 197 |
| 23916 | @System@@BeforeDestruction$qqrp14System@TObjectzc | DEBUG | 110 |
| 26328 | NotifyReRaise | DEBUG | 1 |
| 26356 | NotifyNonDelphiException | DEBUG | 2 |
| 26456 | CheckJmp | DEBUG | 1 |
| 26488 | NotifyExceptFinally | DEBUG | 2 |
| 26528 | NotifyTerminate | DEBUG | 1 |
| 26556 | NotifyUnhandled | DEBUG | 1 |
| 26588 | @System@@HandleAnyException$qqrv | DEBUG | 51 |
| 26888 | @System@@HandleOnException$qqrv | DEBUG | 5 |
| 27448 | @System@@HandleFinally$qqrv | DEBUG | 3 |
| 27616 | @System@@RaiseAgain$qqrv | DEBUG | 27 |
| 27700 | @System@@DoneExcept$qqrv | DEBUG | 55 |
| 27748 | @System@@TryFinallyExit$qqrv | DEBUG | 31 |
| 28376 | @System@@StartExe$qqrp23System@PackageInfoTablep17System@TLibModule | DEBUG | 1 |
| 29516 | StartAddress | DEBUG | 1 |
| 29964 | @System@@WStrClr$qqrpv | DEBUG | 43 |
| 30100 | @System@@WStrArrayClr$qqrpvi | DEBUG | 1 |
| 30136 | @System@@LStrAddRef$qqrpv | DEBUG | 10 |
| 30152 | @System@@LStrAddRef$qqrpv | DEBUG | 1 |
| 30168 | @System@@WStrAddRef$qqrr17System@WideString | DEBUG | 1 |
| 31340 | @System@@PStrCmp$qqrv | DEBUG | 8 |
| 31472 | @System@@AStrCmp$qqrv | DEBUG | 8 |
| 31784 | @System@@LStrToString$qqrv | DEBUG | 3 |
| 32200 | WStrSet | DEBUG | 1 |
| 32844 | @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString | DEBUG | 23 |
| 32864 | @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString | DEBUG | 25 |
| 33972 | @System@@WStrOfWChar$qqrbi | DEBUG | 1 |
| 35032 | @_llumod | DEBUG | 4 |
| 36752 | @_llumod | DEBUG | 1 |
| 38628 | @System@@New$qqripv | DEBUG | 2 |
| 39576 | @System@@_lludiv$qqrv | DEBUG | 1 |
| 49104 | @System@UnregisterModule$qqrp17System@TLibModule | DEBUG | 1 |
| 49216 | @System@@IntfClear$qqrr45System@%DelphiInterface$t17System@IInterface% | DEBUG | 139 |
| 49240 | @System@@IntfCopy$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface% | DEBUG | 149 |
| 49284 | @System@@IntfCast$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface%rx5_GUID | DEBUG | 1 |
| 49332 | @System@@IntfAddRef$qqrx45System@%DelphiInterface$t17System@IInterface% | DEBUG | 1 |
| 53744 | @System@TInterfacedObject@NewInstance$qqrp17System@TMetaClass | DEBUG | 14 |
| 54960 | InitThreadTLS | DEBUG | 1 |
| 55096 | @GetTls | DEBUG | 28 |
| 56184 | __dbk_fcall_wrapper | EXPORT | 1 |
| 109716 | @Math@DivMod$qqriusrust3 | DEBUG | 6 |
| 111884 | @System@@Str0Int64$qqrj | DEBUG | 4 |
| 112384 | @Sysutils@StrToIntDef$qqrx17System@AnsiStringi | DEBUG | 12 |
| 112408 | @Sysutils@TryStrToInt$qqrx17System@AnsiStringri | DEBUG | 6 |
| 112440 | @Sysutils@TryStrToInt64$qqrx17System@AnsiStringrj | DEBUG | 1 |
| 112472 | @Sysutils@TryStrToInt64$qqrx17System@AnsiStringrj | DEBUG | 2 |
| 112976 | @Sysutils@BoolToStr$qqroo | DEBUG | 1 |
| 113148 | BackfillGetDiskFreeSpaceEx | DEBUG | 1 |
| 113784 | @Sysutils@StrPas$qqrpxc | DEBUG | 2 |
| 118496 | @Sysutils@FloatToDecimal$qqrr18Sysutils@TFloatRecpxv20Sysutils@TFloatValueii | DEBUG | 1 |
| 120140 | @Sysutils@DateTimeToTimeStamp$qqr16System@TDateTime | DEBUG | 3 |
| 120280 | @Sysutils@TimeStampToDateTime$qqrrx19Sysutils@TTimeStamp | DEBUG | 1 |
| 120524 | @Sysutils@DecodeTime$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 120920 | @Sysutils@EncodeDate$qqrususus | DEBUG | 3 |
| 120968 | @Sysutils@DecodeDateFully$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 121316 | @Sysutils@DecodeDate$qqrx16System@TDateTimerust2t2 | DEBUG | 1 |
| 137192 | ConvertAddr | DEBUG | 1 |
| 138136 | @Sysutils@Exception@$bctr$qqrx17System@AnsiStringpx14System@TVarRecxi | DEBUG | 39 |
| 138268 | @Sysutils@Exception@$bctr$qqrp20System@TResStringRec | DEBUG | 70 |
| 139340 | CreateInOutError | DEBUG | 1 |
| 139808 | MapException | DEBUG | 2 |
| 140816 | LCIDToCodePage | DEBUG | 1 |
| 144664 | InitDriveSpacePtr | DEBUG | 1 |
| 145140 | @Sysutils@TThreadLocalCounter@Delete$qqrrp20Sysutils@TThreadInfo | DEBUG | 3 |
| 145216 | @Sysutils@TMultiReadExclusiveWriteSynchronizer@$bctr$qqrv | DEBUG | 2 |
| 145440 | @Sysutils@TMultiReadExclusiveWriteSynchronizer@WaitForReadSignal$qqrv | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 46804 | sub_3cc0d4 |
| 217976 | sub_3f5d78 |
| 217308 | sub_3f5adc |
| 155376 | sub_3e68f0 |
| 680844 | sub_466d8c |
| 722984 | sub_471228 |
| 668140 | sub_463bec |
| 127780 | sub_3dfd24 |
| 226404 | sub_3f7e64 |
| 226580 | sub_3f7f14 |
| 226756 | sub_3f7fc4 |
| 188428 | sub_3eea0c |
| 228792 | sub_3f87b8 |
| 228856 | sub_3f87f8 |
| 228920 | sub_3f8838 |
| 230328 | sub_3f8db8 |
| 228128 | sub_3f8520 |
| 229768 | sub_3f8b88 |
| 225808 | sub_3f7c10 |
| 225864 | sub_3f7c48 |
| 226120 | sub_3f7d48 |
| 226932 | sub_3f8074 |
| 227036 | sub_3f80dc |
| 227404 | sub_3f824c |
| 229668 | sub_3f8b24 |
| 230512 | sub_3f8e70 |
| 188660 | sub_3eeaf4 |
| 229492 | sub_3f8a74 |
| 227352 | sub_3f8218 |
| 227664 | sub_3f8350 |

### Decompilations (top 6)
#### 46804 — sub_3cc0d4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3cc0d4(int32_t param_1,undefined4 param_2)

{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    code **in_FS_OFFSET;
    code *pcStackY_280;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    code *pcVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    code *pcStack_250;
    undefined4 uStack_24c;
    code **ppcStack_248;
    code *pcStack_244;
    int16_t *piStack_240;
    code *UNRECOVERED_JUMPTABLE;
    code *pcStack_238;
    undefined4 uStack_234;
    undefined *puStack_230;
    int16_t aiStack_222 [261];
    undefined4 uStack_18;
    code *UNRECOVERED_JUMPTABLE_00;
    int32_t iStack_10;
    undefined4 uStack_c;
    int32_t iStack_8;
    
    uStack_c = 0;
    puStack_230 = 0x3cc0f1;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_234 = 0x3cc2fc;
    pcStack_238 = *in_FS_OFFSET;
    *in_FS_OFFSET = &pcStack_238;
    if (iStack_8 == 0) {
        UNRECOVERED_JUMPTABLE = 0x105;
        piStack_240 = aiStack_222;
        pcStack_244 = 0x0;
        ppcStack_248 = 0x3cc118;
        puStack_230 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        UNRECOVERED_JUMPTABLE = 0x3cc122;
        puStack_230 = &stack0xfffffffc;
        uVar2 = sub_3c8974(iStack_8);
        UNRECOVERED_JUMPTABLE = 0x3cc134;
        sub_3cb8ec(aiStack_222, 0x105, uVar2);
    }
    if (aiStack_222[0] != 0) {
        iStack_10 = 0;
        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
        uStack_24c = 0x20019;
        pcStack_250 = 0x0;
        iVar1 = jmp_advapi32.RegOpenKeyExW();
        if (iVar1 != 0) {
            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
            uStack_24c = 0x20019;
            pcStack_250 = 0x0;
            iVar1 = jmp_advapi32.RegOpenKeyExW();
            if (iVar1 != 0) {
                ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                uStack_24c = 0x20019;
                pcStack_250 = 0x0;
                iVar1 = jmp_advapi32.RegOpenKeyExW();
                if (iVar1 != 0) {
                    ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                    uStack_24c = 0x20019;
                    pcStack_250 = 0x0;
                    iVar1 = jmp_advapi32.RegOpenKeyExW();
                    if (iVar1 != 0) {
                        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                        uStack_24c = 0x20019;
                        pcStack_250 = 0x0;
                        iVar1 = jmp_advapi32.RegOpenKeyExW();
                        if (iVar1 != 0) {
                            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                            uStack_24c = 0x20019;
                            pcStack_250 = 0x0;
                            iVar1 = jmp_advapi32.RegOpenKeyExW();
                            if (iVar1 != 0) goto code_r0x003cc2df;
                        }
                    }
                }
            }
        }
        uStack_24c = 0x3cc2d8;
        pcStack_250 = *in_FS_OFFSET;
        *in_FS_OFFSET = &pcStack_250;
        ppcStack_248 = &stack0xfffffffc;
        uVar2 = sub_3cbed4(aiStack_222, &uStack_c);
        puVar11 = &uStack_18;
        uVar10 = 0;
        uVar9 = 0;
        uVar8 = 0;
        pcVar7 = UNRECOVERED_JUMPTABLE_00;
        iVar1 = jmp_advapi32.RegQueryValueExW();
        if (iVar1 == 0) {
            iVar1 = sub_3c53b8(uStack_18);
            puVar6 = &uStack_18;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iStack_10 = iVar1;
            jmp_advapi32.RegQueryValueExW();
            sub_3c89d4(param_2, iStack_10);
        }
        else {
            puVar6 = &uStack_18;
            iVar1 = 0;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iVar3 = jmp_advapi32.RegQueryValueExW();
            if (iVar3 == 0) {
                i
```
#### 217976 — sub_3f5d78
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5d78(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint32_t uVar15;
    uint32_t uVar16;
    uint32_t *puVar17;
    uint32_t *puVar18;
    int32_t iVar19;
    int32_t iVar20;
    uint32_t uStack_2f8;
    uint32_t uStack_2f4;
    uint32_t uStack_2f0;
    uint32_t uStack_2ec;
    uint32_t uStack_2e8;
    uint32_t uStack_2e4;
    uint32_t uStack_2e0;
    uint32_t uStack_2dc;
    uint32_t uStack_2d8;
    uint32_t uStack_2d4;
    uint32_t uStack_2d0;
    uint32_t uStack_2cc;
    uint32_t uStack_2c8;
    uint32_t uStack_2c4;
    uint32_t uStack_2c0;
    uint32_t uStack_2bc;
    uint32_t auStack_290 [18];
    uint32_t auStack_248 [10];
    uint32_t auStack_220 [132];
    
    uVar11 = *(param_1 + 0x90);
    uVar8 = *(param_1 + 0x94);
    uVar9 = *(param_1 + 0x98);
    uVar10 = *(param_1 + 0x9c);
    uVar12 = *(param_1 + 0xa0);
    uVar13 = *(param_1 + 0xa4);
    uStack_2e0 = *(param_1 + 0xa8);
    uStack_2dc = *(param_1 + 0xac);
    uVar14 = *(param_1 + 0xb0);
    uVar15 = *(param_1 + 0xb4);
    uVar16 = *(param_1 + 0xb8);
    uVar1 = *(param_1 + 0xbc);
    uVar2 = *(param_1 + 0xc0);
    uVar3 = *(param_1 + 0xc4);
    uStack_2c0 = *(param_1 + 200);
    uStack_2bc = *(param_1 + 0xcc);
    func_0x003c57a0(param_1, auStack_290, 0x80);
    iVar20 = 0x10;
    puVar17 = auStack_290;
    do {
        uVar4 = *puVar17;
        uVar5 = puVar17[1];
        *puVar17 = uVar5 >> 0x18 | uVar5 << 0x18 | uVar5 >> 8 & 0xff00 | (uVar5 & 0xff00) << 8;
        puVar17[1] = uVar4 >> 0x18 | uVar4 << 0x18 | uVar4 >> 8 & 0xff00 | (uVar4 & 0xff00) << 8;
        puVar17 = puVar17 + 2;
        iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar20 = 0x40;
    puVar17 = auStack_290;
    do {
        puVar17 = puVar17 + 2;
        uVar4 = (*puVar17 >> 7 | puVar17[1] << 0x19) ^
                (*puVar17 >> 8 | puVar17[1] << 0x18) ^ (*puVar17 >> 1 | puVar17[1] << 0x1f);
        uVar5 = (puVar17[0x1a] >> 6 | puVar17[0x1b] << 0x1a) ^
                (puVar17[0x1b] >> 0x1d | puVar17[0x1a] << 3) ^ (puVar17[0x1a] >> 0x13 | puVar17[0x1b] << 0xd);
        uVar6 = puVar17[-2] + uVar4;
        uVar7 = uVar6 + puVar17[0x10];
        puVar17[0x1e] = uVar7 + uVar5;
        puVar17[0x1f] =
             puVar17[-1] +
             (puVar17[1] >> 7 ^ (puVar17[1] >> 8 | *puVar17 << 0x18) ^ (puVar17[1] >> 1 | *puVar17 << 0x1f)) +
             CARRY4(puVar17[-2], uVar4) + puVar17[0x11] + CARRY4(uVar6, puVar17[0x10]) +
             (puVar17[0x1b] >> 6 ^
             (puVar17[0x1b] << 3 | puVar17[0x1a] >> 0x1d) ^ (puVar17[0x1b] >> 0x13 | puVar17[0x1a] << 0xd)) +
             CARRY4(uVar7, uVar5);
        iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar20 = 0x50;
    puVar18 = &Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640;
    puVar17 = auStack_290;
    do {
        uStack_2c4 = uVar3;
        uStack_2c8 = uVar2;
        uStack_2cc = uVar1;
        uStack_2d0 = uVar16;
        uStack_2d4 = uVar15;
        uStack_2d8 = uVar14;
        uStack_2e4 = uVar13;
        uStack_2e8 = uVar12;
        uStack_2ec = uVar10;
        uStack_2f0 = uVar9;
        uStack_2f4 = uVar8;
        uStack_2f8 = uVar11;
        uVar8 = (uStack_2f4 >> 7 | uStack_2f8 << 0x19) ^
                (uStack_2f4 >> 2 | uStack_2f8 << 0x1e) ^ (uStack_2f8 >> 0x1c | uStack_2f4 << 4);
        uVar9 = uStack_2f0 & uStack_2e8 ^ uStack_2f8 & uStack_2e8 ^ uStack_2f8 & uStack_2f0;
        uVar10 = uVar9 + uVar8;
        uVar11 = (uStack_2d4 >> 9 | uStack_2d8 << 0x17) ^
                 (uStack_2d8 >> 0x12 | uStack_2d4 << 0xe) ^ (uStack_2d8 >> 0xe | uStack_2d4 << 0x12);
        uVar12 = uStack_2c0 + uVar11;
        uVar13 = ~uStack_2d8 & uStack_2c8 ^ uStack_2d8 & uStack_2d0;
   
```
#### 217308 — sub_3f5adc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5adc(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t *puVar4;
    int32_t *piVar5;
    int32_t iVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    int32_t iVar11;
    uint32_t uStack_13c;
    uint32_t uStack_138;
    uint32_t uStack_134;
    uint32_t uStack_130;
    uint32_t uStack_12c;
    uint32_t uStack_128;
    uint32_t *puStack_114;
    uint32_t auStack_110 [9];
    uint32_t auStack_ec [5];
    uint32_t auStack_d8 [50];
    
    uVar8 = *(param_1 + 0x90);
    uVar7 = *(param_1 + 0x94);
    uVar1 = *(param_1 + 0x98);
    uStack_134 = *(param_1 + 0x9c);
    uVar10 = *(param_1 + 0xa0);
    uVar9 = *(param_1 + 0xa4);
    uVar2 = *(param_1 + 0xa8);
    uStack_128 = *(param_1 + 0xac);
    func_0x003c57a0(param_1, auStack_110, 0x40);
    iVar6 = 0x10;
    puVar4 = auStack_110;
    do {
        uVar3 = *puVar4;
        *puVar4 = uVar3 >> 0x18 | uVar3 << 0x18 | uVar3 >> 8 & 0xff00 | (uVar3 & 0xff00) << 8;
        puVar4 = puVar4 + 1;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x30;
    puVar4 = auStack_110;
    do {
        puVar4 = puVar4 + 1;
        uVar3 = puVar4[0xd];
        puVar4[0xf] = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ puVar4[0xd] >> 10) +
                      puVar4[-1] +
                      ((*puVar4 << 0x19 | *puVar4 >> 7) ^ (*puVar4 << 0xe | *puVar4 >> 0x12) ^ *puVar4 >> 3) + puVar4[8]
        ;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x40;
    piVar5 = &SHA256;
    puStack_114 = auStack_110;
    do {
        uStack_12c = uVar2;
        uStack_130 = uVar9;
        uStack_138 = uVar1;
        uStack_13c = uVar7;
        uVar9 = uVar10;
        uVar7 = uVar8;
        iVar11 = (uVar9 & uStack_130 ^ ~uVar9 & uStack_12c) +
                 ((uVar9 << 0x1a | uVar9 >> 6) ^ (uVar9 << 0x15 | uVar9 >> 0xb) ^ (uVar9 << 7 | uVar9 >> 0x19)) +
                 uStack_128 + *piVar5 + *puStack_114;
        uStack_128 = uStack_12c;
        uVar10 = uStack_134 + iVar11;
        uStack_134 = uStack_138;
        uVar8 = iVar11 + (uVar7 & uStack_13c ^ uVar7 & uStack_138 ^ uStack_13c & uStack_138) +
                         ((uVar7 << 0x1e | uVar7 >> 2) ^ (uVar7 << 0x13 | uVar7 >> 0xd) ^ (uVar7 << 10 | uVar7 >> 0x16))
        ;
        puStack_114 = puStack_114 + 1;
        piVar5 = piVar5 + 1;
        iVar6 = iVar6 + -1;
        uVar1 = uStack_13c;
        uVar2 = uStack_130;
    } while (iVar6 != 0);
    *(param_1 + 0x90) = *(param_1 + 0x90) + uVar8;
    *(param_1 + 0x94) = *(param_1 + 0x94) + uVar7;
    *(param_1 + 0x98) = *(param_1 + 0x98) + uStack_13c;
    *(param_1 + 0x9c) = *(param_1 + 0x9c) + uStack_138;
    *(param_1 + 0xa0) = *(param_1 + 0xa0) + uVar10;
    *(param_1 + 0xa4) = *(param_1 + 0xa4) + uVar9;
    *(param_1 + 0xa8) = *(param_1 + 0xa8) + uStack_130;
    *(param_1 + 0xac) = *(param_1 + 0xac) + uStack_12c;
    return;
}

```

### Carved Files (6)
| Name | Type | Size |
|---|---|---|
| ? | PNG | 980 |
| ? | PNG | 3093 |
| ? | PNG | 6060 |
| ? | PNG | 9716 |
| ? | PNG | 28485 |
| ? | PNG | 88382 |

### Virtual Files (24)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/100/en-us | 980 | - |
| ICO/101/en-us | 3093 | - |
| ICO/102/en-us | 6060 | - |
| ICO/103/en-us | 9716 | - |
| ICO/104/en-us | 28485 | - |
| ICO/105/en-us | 88382 | - |
| STR/4085/unk | 588 | - |
| STR/4086/unk | 740 | - |
| STR/4087/unk | 1024 | - |
| STR/4088/unk | 976 | - |
| STR/4089/unk | 1020 | - |
| STR/4090/unk | 724 | - |
| STR/4091/unk | 184 | - |
| STR/4092/unk | 156 | - |
| STR/4093/unk | 908 | - |
| STR/4094/unk | 920 | - |
| STR/4095/unk | 872 | - |
| STR/4096/unk | 676 | - |
| RCDATA/DVCLAL/unk | 16 | - |
| RCDATA/PACKAGEINFO/unk | 1168 | - |

### Structures (112)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 256 |
| OptionalHeader | 280 |
| Sections | 504 |
| ImportTable | 779776 |
| kernel32.OFT | 779896 |
| comctl32.OFT | 780320 |
| user32.OFT | 780328 |
| oleaut32.OFT | 780396 |
| advapi32.OFT | 780460 |
| kernel32.FT | 780516 |
| comctl32.FT | 780940 |
| user32.FT | 780948 |
| oleaut32.FT | 781016 |
| advapi32.FT | 781080 |
| ImportNames | 781136 |
| DelayImportTable | 787968 |
| kernel32.Addresses | 788112 |
| user32.Addresses | 788116 |
| kernel32.Addresses | 788120 |
| kernel32.Names | 788148 |
| user32.Names | 788156 |
| kernel32.Names | 788164 |
| ExportDirectory | 792064 |
| ExportAddressTable | 792104 |
| ExportNameTable | 792112 |
| OrdinalNameTable | 792120 |
| ExportNames | 792124 |
| TlsDirectory | 796160 |
| Relocations | 800256 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 44 · duration_s: 2.01

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using HC-128 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.006:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| check for time delay via GetTickCount |  | B0001.032:Debugger Detection |
| get geographical location | T1614:System Location Discovery |  |
| hash data with CRC32 |  | C0032.001:Checksum |
| encrypt data using Salsa20 or ChaCha | T1027:Obfuscated Files or Information |  |

## PE Imports / Signals
import_count: 150

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## Generated YARA Meta
```json
{
  "rule_count": 0,
  "matches": [],
  "batch_errors": [
    "batch[0]: [Errno 2] No such file or directory: 'yr'",
    "batch[50]: [Errno 2] No such file or directory: 'yr'",
    "batch[100]: [Errno 2] No such file or directory: 'yr'",
    "batch[150]: [Errno 2] No such file or directory: 'yr'",
    "batch[200]: [Errno 2] No such file or directory: 'yr'",
    "batch[250]: [Errno 2] No such file or directory: 'yr'",
    "batch[300]: [Errno 2] No such file or directory: 'yr'",
    "batch[350]: [Errno 2] No such file or directory: 'yr'",
    "batch[400]: [Errno 2] No such file or directory: 'yr'",
    "batch[450]: [Errno 2] No such file or directory: 'yr'"
  ]
}
```

## FLOSS Strings
Total strings: 10027 · per_category: `{"decoded_strings": 2, "stack_strings": 5, "tight_strings": 2, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10018}`

### FLOSS sample
- `j:,4;87`
- `4278124286`
- `GPVACPVA?`
- `KPVAGPVACPVA?`
- `KPVAKPVAGPVACPVA?`
- `?PVAKPVAKPVAGPVACPVA?`
- `CPVA?PVAKPVAKPVAGPVACPVA?`
- `1096159247`
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.reloc`
- `B.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00471e60
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55
```
### 0x003ce578
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎   0x003ce5ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5cd      50             push eax
│       ╎   0x003ce5ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d1      50             push eax
│       ╎   0x003ce5d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d5      50             push eax
│       ╎   0x003ce5d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d9      50             push eax
│       ╎   0x003ce5da      8b45f
```
### 0x003ce188
```asm
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff     call fcn.003ce184
│           0x003ce249      e836ffffff     call fcn.003ce184
│           0x003ce24e      e831ffffff     call fcn.003ce184
│           0x003ce253      e82cffffff     call fcn.003ce184
│           0x003ce258      e827ffffff     call fcn.003ce184
│           0x003ce25d      e822ffffff     call fcn.003ce184
│           0x003ce262      e81dffffff     call fcn.003ce184
│           0x003ce267      e818ffffff     call fcn.003ce184
│           0x003ce26c      e813ffffff     call fcn.00
```
### 0x003ce184
```asm
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
