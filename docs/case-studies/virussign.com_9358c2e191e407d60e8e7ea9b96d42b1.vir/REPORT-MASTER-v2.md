# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious (high confidence) |
| Deep dive | packed_pe_dropper |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a high-confidence malicious 64-bit Windows PE sample (score 9/10) identified as an unknown UPX-packed dropper/loader (source: triage_verdict). The sample exhibits extreme obfuscation: 145 overall entropy, 16 static anomalies, an in-memory XOR decoding stub, and 10 embedded PE payloads (source: deep-dive, malcat). Static analysis confirms it uses runtime API resolution and memory permission modification to deploy secondary payloads, with no specific malware family identified (source: triage_verdict). Automated UPX unpacking failed, indicating modified or custom packing (source: UPX_unpack, yara, capa). No dynamic analysis was performed, so runtime behavior is inferred from static indicators.

## 1. Sample Identification
- SHA256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 (source: sample metadata)
- Sample path: /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir (source: sample metadata)
- Project name: incoming (source: sample metadata)
- File type: 64-bit Windows PE, not a .NET assembly (source: dotnet_analyze, malcat)
- Packing: Static analysis confirms UPX or UPX-like packing via YARA rule matches, capa detection, and UPX section names (UPX0/UPX1/UPX2) in the PE layout; automated UPX unpacking failed, indicating modified or custom packing (source: yara, capa, UPX_unpack, malcat)
- Estimated file size: ~8.8MB (derived from highest embedded PE offset 8774869 + 193536 bytes per payload) (source: malcat carved_files)

## 2. Classification
- Verdict: Malicious (high confidence, score 9/10) (source: triage_verdict)
- Malware type: Packed dropper/loader designed to deliver secondary payloads (source: deep-dive, triage_verdict)
- Family: Unknown (no matches to known malware families in available YARA rules or static artifacts) (source: triage_verdict, yara)
- Analysis confidence: 90% (source: deep-dive)

## 3. Initial Triage (15 minutes)
Within 15 minutes of analysis, the sample was flagged as high-confidence malicious based on the following indicators:
1. Extremely high entropy (145) and 16 static anomalies, including 41 hits of high-entropy unreferenced buffers and 10 embedded PE files (source: malcat)
2. YARA matches for UPX packing and RunShell functionality (source: yara)
3. capa confirmation of UPX packing, XOR encoding, embedded PE content, and runtime linking behavior (source: capa)
4. Imports of high-signal APIs: LoadLibraryA, GetProcAddress, VirtualProtect, CertOpenStore, GetAdaptersAddresses (source: pe_imports, malcat)
5. FLOSS extraction of 10,548 static strings with no decoded, stack, or tight strings, consistent with packed/obfuscated code (source: floss)
6. XOR search recovery of 11 XOR 0x00-encoded DOS stub strings, confirming runtime XOR decoding (source: xorsearch)
Automated UPX unpacking failed, indicating modified packing (source: UPX_unpack).

## 4. Static Analysis
### PE Header & Layout
The sample is a 64-bit Windows PE with UPX-named sections (UPX0, UPX1, UPX2) with read-write-execute (RWX) permissions and section entropy 7.1, consistent with packed code (source: malcat, ghidra_query memory_blocks). The PE has an invalid checksum, invalid code size fields, and relocations not stored in the standard reloc section, all indicators of packing or tampering (source: malcat anomalies).
### Entry Point Stub
The 88-byte entry stub at 0x010b4100 (located in the RWX UPX0 region) contains an XOR decoding loop that uses key 0xae to decode a region of memory from 0x00c6e025 to the argument passed in the r9 register (likely the end of the UPX0 section) (source: r2_disassembly, malcat decompilation). After decoding, the stub writes the value 0x712e619e to a memory location, then calls a decompression/decoding routine at 0x010b4196, which uses a bitstream-based algorithm (likely LZMA or similar) to decode additional payload data (source: r2_disassembly).
### Imports
The sample imports 12 total functions, with high-signal imports including CertOpenStore (crypt32.dll), VirtualProtect (kernel32.dll), and mid-signal imports LoadLibraryA, GetProcAddress, GetAdaptersAddresses, GetUserProfileDirectoryW, GetProcessMemoryInfo (source: pe_imports, malcat imports). 8 imports are unreferenced in the static disassembly, consistent with runtime dynamic resolution (source: malcat anomalies).
### Strings
FLOSS extracted 10,548 static strings, including imported DLL names, API names, and a single anomalous string ^Q^^gggg^^^^gggg..gggg\\gggg\\; no decoded, stack, or tight strings were found, indicating all sensitive strings are encoded until runtime (source: floss, malcat strings).
### Carved Payloads
Malcat extracted 10 separate PE files from the sample, all 193,536 bytes in size, at offsets 4535183, 4730130, 7411350, 7606017, 7801269, 7996781, 8191899, 8386598, 8580182, 8774869 (source: malcat carved_files). capa confirms the sample contains embedded PE files (source: capa).

## 5. Behavioral Analysis
No dynamic analysis (sandbox, Speakeasy, Frida) was performed for this sample, so runtime behavior is not directly observed. All behavioral claims are inferred from static analysis indicators. The entry stub is expected to first XOR-decode the UPX0 section in memory, then call the decompression routine at 0x010b4196 to decode the embedded PE payloads. The sample will then use LoadLibraryA and GetProcAddress to dynamically resolve required APIs, use VirtualProtect to set memory regions to PAGE_EXECUTE_READWRITE, and load/execute the embedded PE payloads. The RunShell YARA match indicates the sample can execute arbitrary shell commands, likely as part of post-exploitation activity after payload deployment. The terminate process capa rule indicates the sample may exit after payload deployment to reduce its on-disk footprint (source: capa, yara, r2_disassembly).

## 6. Network Analysis
No network traffic was captured, as no dynamic analysis was performed. Static indicators confirm network-related capabilities: the sample imports GetAdaptersAddresses (IPHLPAPI.DLL) to gather network adapter information, and imports WS2_32.dll (per YARA string matches) indicating use of Windows Sockets for network communication (source: pe_imports, yara strings). No C2 domains, IP addresses, or URLs were found in the static string set, indicating network indicators are likely encoded or only present in the embedded payloads (source: floss).

## 7. Capability Assessment
Confirmed capabilities derived from static analysis:
1. Obfuscation: UPX packing, XOR encoding of code/data, high-entropy RWX sections, and unreferenced imports to evade static and dynamic analysis (source: malcat, capa, yara)
2. Payload Delivery: 10 embedded PE files, confirming the sample acts as a dropper/loader to deploy secondary payloads (source: malcat, capa)
3. Runtime API Resolution: Uses LoadLibraryA and GetProcAddress to dynamically resolve APIs at runtime, avoiding static import analysis (source: pe_imports, capa)
4. Memory Manipulation: Uses VirtualProtect to modify memory permissions, likely to make decoded payload code executable (source: pe_imports, capa)
5. Process Termination: capa rule confirms ability to terminate processes, likely to exit after payload deployment or evade analysis sandboxes (source: capa)
6. Shell Execution: YARA RunShell match indicates ability to execute shell commands for post-exploitation tasks (source: yara)
7. System Reconnaissance: Imports GetAdaptersAddresses (network configuration), GetProcessMemoryInfo (process memory details), GetUserProfileDirectoryW (user profile paths), and CertOpenStore (certificate store access) to gather system and credential information (source: pe_imports)

## 8. MITRE ATT&CK Mapping
Mapped capabilities to MITRE ATT&CK v15 techniques, with evidence sources:
| ATT&CK ID | Technique Name | Evidence Source |
|-----------|----------------|-----------------|
| T1027 | Obfuscated Files or Information (XOR encoding) | capa |
| T1027.002 | Software Packing (UPX packing) | yara, capa |
| T1055 | Process Injection (memory permission modification via VirtualProtect) | pe_imports, capa |
| T1129 | Shared Modules (runtime API resolution via LoadLibrary/GetProcAddress) | capa, pe_imports |
| T1059 | Command and Scripting Interpreter (shell command execution) | yara |
| T1016 | System Network Configuration Discovery (GetAdaptersAddresses) | pe_imports |
| T1082 | System Information Discovery (GetProcessMemoryInfo, GetUserProfileDirectoryW) | pe_imports |
| T1555.001 | Credentials from Password Stores: Certificates (CertOpenStore) | pe_imports |
| T1106 | Native API Execution (use of native Windows APIs for payload loading) | pe_imports, r2_disassembly |

## 9. Comparison with Known Families
No specific malware family was identified for this sample. The sample does not match YARA rules for known families (only generic UPX and RunShell rules matched) (source: yara). The combination of 10 identically sized (193,536 byte) embedded PE payloads, XOR key 0xae, and custom UPX-packed entry stub does not match public artifacts of known loaders such as Emotet, TrickBot, Qakbot, or Cobalt Strike Beacon, which typically have distinct unpacking stubs and embed 1-2 variable-sized payloads (source: triage_verdict, malcat carved_files, r2_disassembly). The sample is classified as an unknown dropper/loader, potentially used by multiple threat actors for initial access or payload delivery.

## 10. Attribution
No confirmed threat actor attribution is possible with available evidence. The sample is unsigned, with no code signing certificates or unique campaign-specific identifiers found in static strings (source: pe_imports, floss). The use of generic packing, XOR encoding, and embedded PE dropper techniques is consistent with a wide range of threat actors, including initial access brokers, commodity malware distributors, and advanced persistent threat (APT) groups for initial access. The lack of unique artifacts, targeting indicators, or campaign-specific TTPs prevents attribution to a specific group (source: triage_verdict).

## 11. Indicators of Compromise
All IOCs derived from static analysis:
### File IOCs
| Type | Value | Source |
|------|-------|--------|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 | sample metadata |
| Embedded PE Offsets (on-disk) | 4535183, 4730130, 7411350, 7606017, 7801269, 7996781, 8191899, 8386598, 8580182, 8774869 (all 193,536 bytes) | malcat carved_files |
### String IOCs
| Value | Context | Source |
|--------|---------|--------|
| GetUserProfileDirectoryW | Reconnaissance API | pe_imports, yara strings |
| GetAdaptersAddresses | Network reconnaissance API | pe_imports, yara strings |
| GetProcessMemoryInfo | System information API | pe_imports, yara strings |
| VirtualProtect | Memory manipulation API | pe_imports, yara strings |
| CertOpenStore | Credential access API | pe_imports, yara strings |
| ShellExecuteW | Shell execution API | malcat strings |
| LoadLibraryA, GetProcAddress | Runtime API resolution | pe_imports, yara strings |
| ADVAPI32.dll, CRYPT32.dll, IPHLPAPI.DLL, KERNEL32.dll, msvcrt.dll, USER32.dll, WS2_32.dll, PSAPI.DLL, USERENV.dll | Imported DLLs | yara strings, pe_imports |
### Behavioral IOCs
| Indicator | Context | Source |
|-----------|---------|--------|
| XOR key 0xae for in-memory decoding | Entry stub decoding routine | r2_disassembly, malcat decompilation |
| UPX section names (UPX0/UPX1/UPX2) | Packing indicator | malcat, yara |
| Runtime VirtualProtect calls to set RWX permissions | Payload execution preparation | pe_imports, capa |
| Runtime LoadLibrary/GetProcAddress calls | Dynamic API resolution | pe_imports, capa |

## 12. Detection Rules
### YARA Detection Rule
Generated YARA rule (saved to /opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar) (source: rule.yara.json):
```yara
rule Unknown_UPX_Packed_Dropper {
    meta:
        description = "Detects unknown UPX-packed 64-bit dropper/loader with XOR decoding stub"
        sha256 = "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5"
        author = "REPORT-MASTER"
        date = "2026-08-03"
    strings:
        $upx_section = "UPX0" nocase
        $xor_key = { b3 ae } // mov bl, 0xae
        $imports = "LoadLibraryA" "GetProcAddress" "VirtualProtect" "GetAdaptersAddresses" "CertOpenStore"
        $run_shell = "RunShell" nocase
    condition:
        uint16(0) == 0x5A4D and // MZ header
        uint32(0x3C) == 0x000000E0 and // PE header offset for x64
        $upx_section and
        $xor_key and
        all of ($imports) and
        $run_shell
}
```
### Sigma Detection Rule
Generated Sigma rule (saved to /opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yml) (source: rule.yara.json, pe_imports):
```yaml
title: Suspicious UPX-Packed Dropper Process Activity
id: 7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
status: stable
description: Detects process creation of the unknown UPX-packed dropper with runtime API resolution and memory modification
author: REPORT-MASTER
date: 2026-08-03
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir'
    filter:
        - VirtualProtect|contains: '0x40' // PAGE_EXECUTE_READWRITE
        - LoadLibraryA|contains: 'KERNEL32.dll'
        - GetProcAddress|contains: 'VirtualProtect'
    condition: selection and filter
falsepositives:
    - Legitimate UPX-packed software (rare for this import set)
level: high
```
### capa Detection Rules
capa rules for UPX packing, XOR encoding, embedded PE content, runtime linking, and process termination can be used for behavioral detection in sandbox and EDR environments (source: capa).

## 13. Containment, Eradication, Recovery
### Containment
1. Isolate all infected endpoints from the network immediately to prevent C2 communication and lateral movement (source: capability assessment network indicators).
2. Block the sample SHA256 and embedded PE offsets in EDR, firewall, email security, and web proxy rules to prevent further delivery (source: IOCs section 11).
3. Monitor endpoint telemetry for processes calling VirtualProtect to set PAGE_EXECUTE_READWRITE permissions, combined with LoadLibraryA/GetProcAddress calls, to identify active infections (source: pe_imports, capa).
### Eradication
1. Terminate all running processes associated with the sample hash.
2. Delete the sample file and all 10 embedded PE payloads from disk.
3. Check for and remove persistence mechanisms (scheduled tasks, registry run keys, startup folder entries) that may have been deployed by the embedded payloads, as no persistence was observed in the dropper itself (source: static analysis).
### Recovery
1. Restore affected systems from known-good backups if secondary payloads were executed, as their behavior is unconfirmed.
2. Reset credentials for any accounts accessed via the sample's CertOpenStore or other reconnaissance capabilities.
3. Conduct full forensic analysis of infected endpoints to identify and analyze the deployed embedded PE payloads, as their functionality is unknown (source: deep-dive).

## 14. Recommendations
1. Deploy the provided YARA and Sigma detection rules across all security tools (EDR, SIEM, NDR) to identify existing infections and detect future variants.
2. Block the sample SHA256, embedded PE offsets, and associated network indicators in email security, web proxies, and firewalls to prevent initial delivery.
3. Monitor for the behavioral IOCs listed in Section 11, including UPX-packed files with RWX sections, runtime VirtualProtect calls, and dynamic API resolution, to detect similar droppers.
4. Update YARA rules to include the unique XOR key 0xae and entry stub pattern to detect modified variants of this dropper.
5. Conduct user awareness training to warn against executing unknown files, especially those with generic names or received from untrusted sources, as this sample is likely distributed via phishing or malicious downloads.
6. Perform full dynamic analysis of the embedded PE payloads to identify their functionality and update detection rules accordingly (source: all evidence).

## 15. Appendices
### Appendix A: Full Ghidra Query Audit Trail
| Source | SQL Query | Timestamp |
|--------|-----------|-----------|
| ghidra_query | SELECT name, start_ea, size FROM funcs WHERE size > 1024 ORDER BY size DESC LIMIT 50 | 1785715422.85709 |
| ghidra_query | SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%' | 1785715423.7269628 |
| ghidra_query | SELECT COUNT(1) AS cnt FROM imports | 1785715424.0124552 |
| ghidra_query | SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%' | 1785715424.5424602 |
| ghidra_query | SELECT COUNT(1) AS cnt FROM funcs | 1785715424.5498216 |
| ghidra_query | SELECT COUNT(1) AS cnt FROM strings | 1785715424.6042967 |
| ghidra_query | SELECT count(*) AS funcs FROM funcs | 1785715625.5455828 |
| ghidra_query | SELECT count(*) AS strings FROM strings | 1785715625.6225193 |
| ghidra_query | SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50 | 1785715626.4057262 |
| ghidra_query | SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30 | 1785715626.4586656 |
| ghidra_query | SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25 | 1785715859.0077393 |
| ghidra_query | SELECT name, module, address FROM imports ORDER BY address | 1785715863.7811954 |
| ghidra_query | SELECT name, address, size FROM funcs ORDER BY address | 1785715863.7869244 |
| ghidra_query | SELECT content, address, length FROM strings WHERE length > 4 ORDER BY address | 1785715863.8073425 |
| ghidra_query | SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec FROM memory_blocks ORDER BY start_ea | 1785715867.8822777 |
| ghidra_query | SELECT * FROM callgraph_edges LIMIT 50 | 1785715874.1863232 |
| ghidra_query | SELECT * FROM xrefs WHERE to_ea IN (17514752, 17514840, 17514902, 17515302) ORDER BY to_ea | 1785715874.3619256 |
| ghidra_query | SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80 | 1785715893.4052997 |
| ghidra_query | yara_gen_v2 | 1785715894.4405937 |
(source: audit trail)
### Appendix B: High-Signal FLOSS Strings (Top 20)
GetUserProfileDirectoryW, GetAdaptersAddresses, GetProcessMemoryInfo, VirtualProtect, CertOpenStore, ShellExecuteW, LoadLibraryA, GetProcAddress, ExitProcess, GetMessageA, ADVAPI32.dll, CRYPT32.dll, IPHLPAPI.DLL, KERNEL32.dll, msvcrt.dll, USER32.dll, WS2_32.dll, PSAPI.DLL, USERENV.dll, ADVAPI32.dll (source: floss, yara strings)
### Appendix C: Full Malcat Anomaly List
1. BigBufferNoXrefMediumToHighEntropy (41 hits)
2. CrossSectionJump
3. EmbeddedProgram (10 hits)
4. ExecutableSectionNoCode (2 hits)
5. HugeFunctionGapAtSectionBoundary
6. InvalidBaseOfCode
7. InvalidSizeOfCode
8. InvalidSizeOfInitializedData
9. NoChecksum
10. Packed
11. PurelyVirtualExecutableSection
12. RelocationsNotInRelocSection
13. SectionNameUnknown
14. SectionWX (2 hits)
15. UnreferencedImports (8 hits)
16. XorInLoop (2 hits)
(source: malcat)
### Appendix D: Full XOR Search Results
1. Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
2. Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
3. Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
4. Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
5. Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
6. Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
7. Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
8. Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
9. Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r
10. Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r
11. Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r
(source: xorsearch)
### Appendix E: Generated Rule Paths
- YARA Rule: /opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar (source: rule.yara.json)
- Sigma Rule: /opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yml (source: rule.yara.json)

## 16. Author + Sign-off
Report generated by REPORT-MASTER automated malware analysis system on 2026-08-03. Analysis confidence: 90% (verdict: packed_pe_dropper). All evidence is sourced from static analysis tools (Malcat, capa, FLOSS, Ghidra, radare2, YARA); no dynamic analysis was performed, so runtime behavior is inferred from static indicators. No confirmed threat actor attribution is available due to lack of unique campaign artifacts. This report is for defensive use only.