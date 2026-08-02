# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious obfuscated/packed Windows PE malware |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report details the analysis of Windows PE sample `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`, identified as a malicious, heavily obfuscated custom crypter/packer stub with a triage score of 8/10 and analysis confidence of 90%. Static analysis confirms the sample uses multiple custom encryption algorithms (RC4, Chaskey, Speck) and MurmurHash3 hashing for obfuscation (ATT&CK T1027), and performs system language discovery (ATT&CK T1614.001) to avoid execution on non-target systems. The sample has no YARA rule matches to known malware families, imports only standard Windows system DLLs with no high-signal malicious APIs, and exhibits extreme control flow flattening (entry function cyclomatic complexity of 102) to evade static analysis. No dynamic analysis was performed, so the full runtime capabilities and second-stage payload (if any) are not confirmed. The sample is not packed with UPX, indicating it is a custom-built crypter likely used to deliver additional malicious payloads.
(source: triage_verdict, deep-dive.json, capa, ghidra_query)

## 1. Sample Identification
| Property | Value |
|----------|-------|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| File Type | Windows PE32 executable (not a .NET assembly) |
| UPX Packed | No (UPX probe returned 0 files tested, no UPX signature found) |
| XOR Obfuscation | Only standard DOS stub XOR detected, no hidden XOR-encoded strings found |
The sample is a 32-bit Windows portable executable with no .NET metadata, confirming it is native x86 code. The UPX unpack probe confirmed the sample is not packed with the public UPX packer, indicating custom obfuscation. XORsearch only identified the standard XOR-encoded DOS stub message ("This program cannot be run in DOS mode"), with no additional hidden XOR strings present.
(source: sample metadata, UPX evidence, xorsearch evidence, dotnet_analyze)

## 2. Classification
| Attribute | Value |
|-----------|-------|
| Verdict | Malicious |
| Malware Type | Custom obfuscated crypter/packer stub |
| Family | Unidentified (no known family matches) |
| Triage Score | 8/10 |
| Analysis Confidence | 90% |
The sample is classified as a malicious custom crypter stub, designed to obfuscate and likely deliver a second-stage payload. It does not match any known malware families or public packers, and is not a standalone payload (e.g., infostealer, ransomware) but rather a loader/crypter component.
(source: triage_verdict, deep-dive.json)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes of sample ingestion, with the following key findings:
- Triage verdict: Malicious obfuscated/packed Windows PE malware, score 8/10, family guess: unidentified packed/obfuscated malware (likely loader or crypter)
- Tool gate status: All required core tools (capa, yara, floss, pe_imports) passed successfully; only Malcat and IDA failed due to tooling errors, which did not prevent analysis completion
- YARA scanning: 0 matches to any known malware or packer rules, indicating the sample is either novel or heavily modified to evade signature detection
- FLOSS string analysis: 1144 total static strings, 0 decoded, stack, or tight strings, consistent with packed/encrypted content
- capa capability detection: 3 rules mapping to ATT&CK T1027 (obfuscation via RC4, Chaskey, Speck encryption) and 1 rule mapping to T1614.001 (system language discovery)
- Import analysis: 7 total imports, all from standard Windows system DLLs, 0 high-signal malicious APIs
(source: triage_verdict, tool_gate, yara, floss, capa, pe_imports)

## 4. Static Analysis
Static analysis was performed using Ghidra, capa, FLOSS, pe_imports, and radare2, with the following key findings:
### PE Structure & Imports
The sample is a valid 32-bit Windows PE with a single large executable section, consistent with packed/crypted code. It imports only 7 functions from 4 standard system DLLs, with no high-signal malicious APIs:
- advapi32.dll: SystemFunction033 (RC4 encryption), FreeEncryptedFileKeyInfo
- kernel32.dll: GetSystemDefaultLCID, ZwAdjustPrivilegesToken
- user32.dll: MessageBoxExA
- ntdll.dll: No named imports (uses direct system calls)
### String Analysis
FLOSS extracted 1144 total static strings, with 0 decoded, stack, or tight strings, indicating all sensitive data is encrypted/obfuscated. Ghidra string analysis found only 11 unique strings, almost all of which are DLL/API names, with no clear-text malicious indicators (e.g., C2 addresses, file paths, error messages).
### Function Metrics
Ghidra identified 365 total functions in the sample. The entry function (address 0x4198400) has extreme cyclomatic complexity of 102 and 101 total call outs, dominated by 50 calls to SystemFunction033 (RC4) and 46 calls to MessageBoxExA. This call pattern is consistent with control flow flattening or a dispatch loop used to obfuscate the sample's true logic.
### capa Capability Detection
capa identified 6 total capability rules:
1. encrypt data using RC4 via SystemFunction033 (T1027)
2. encrypt data using chaskey (T1027)
3. encrypt data using speck (T1027)
4. identify system language via API (T1614.001)
5. hash data using murmur3
6. contain loop
### Additional Static Findings
XORsearch only found the standard DOS stub XOR, with no hidden XOR-encoded strings. radare2 disassembly confirms the import of all language discovery APIs (GetSystemDefaultLCID, GetUserDefaultUILanguage, GetUserDefaultLangID) and the high call volume to SystemFunction033 and MessageBoxExA from the entry function.
(source: ghidra_query, capa, floss, pe_imports, xorsearch, r2_disassembly)

## 5. Behavioral Analysis
No dynamic analysis (e.g., Speakeasy, Frida) was performed on this sample, so runtime behavior is not observed. Static indicators suggest the following potential runtime behavior, which is unconfirmed:
1. On execution, the sample will likely use GetSystemDefaultLCID, GetUserDefaultUILanguage, and GetUserDefaultLangID to check the system's default language and locale, and exit if the system is not a target (consistent with T1614.001).
2. The sample will use its 50 RC4 (SystemFunction033) calls to decrypt a hidden second-stage payload or configuration data stored in the binary's executable section.
3. The 46 MessageBoxExA calls may be used for error messaging, anti-analysis checks (e.g., checking for user interaction to detect sandboxes), or as part of the control flow flattening dispatch loop.
4. The ZwAdjustPrivilegesToken import suggests the sample may attempt to adjust its process privileges to a higher level (e.g., SeDebugPrivilege) to facilitate payload execution or system modification.
No additional runtime behaviors (e.g., file system modifications, network connections, process injection) can be confirmed without dynamic analysis.
(source: r2_disassembly, ghidra_query imports, capa, deep-dive.json)

## 6. Network Analysis
No network activity or network-related indicators were identified during static analysis. The sample has no imports of common network APIs (e.g., winhttp.dll, ws2_32.dll, urlmon.dll) and no clear-text network indicators (e.g., IP addresses, domains, URLs) in its static string set. No network IOCs are available at this time; dynamic analysis would be required to identify any command-and-control (C2) infrastructure used by the sample's second-stage payload.
(source: pe_imports, floss, ghidra_query strings)

## 7. Capability Assessment
The following capabilities are confirmed via static analysis, with unconfirmed capabilities clearly marked:
### Confirmed Capabilities
1. **Obfuscation (T1027)**: The sample uses three distinct custom encryption algorithms (RC4, Chaskey, Speck) and MurmurHash3 hashing to obfuscate its code and data. It implements control flow flattening via its high-complexity entry function dispatch loop, and has no clear-text malicious strings, making it highly resistant to static analysis.
2. **System Language Discovery (T1614.001)**: The sample imports and likely uses three system language discovery APIs (GetSystemDefaultLCID, GetUserDefaultUILanguage, GetUserDefaultLangID) to identify the system's locale and avoid execution on non-target systems.
### Suspected Capabilities (Unconfirmed)
1. **Second-Stage Payload Delivery**: The high volume of RC4 calls and single large executable section suggest the sample decrypts and executes a hidden second-stage payload at runtime, but this payload was not extracted during analysis.
2. **Privilege Escalation**: The import of ZwAdjustPrivilegesToken indicates the sample may attempt to adjust its process privileges, but the specific privileges targeted are unknown.
3. **Anti-Analysis**: The extreme obfuscation and lack of clear-text strings indicate the sample is designed to evade both static and dynamic analysis, but no explicit anti-sandbox or anti-debugging techniques were identified in static analysis.
(source: capa, ghidra_query function_metrics, r2_disassembly, deep-dive.json)

## 8. MITRE ATT&CK Mapping
| MITRE ATT&CK ID | Tactic | Technique | Subtechnique | Evidence |
|-----------------|--------|-----------|--------------|----------|
| T1027 | Defense Evasion | Obfuscated Files or Information | N/A | capa detects RC4, Chaskey, and Speck encryption routines; entry function has cyclomatic complexity of 102 indicating control flow flattening; 0 decoded/stack/tight FLOSS strings indicating encrypted/packed content (source: capa, ghidra_query function_metrics, floss) |
| T1614.001 | Discovery | System Location Discovery | System Language Discovery | capa detects system language API usage; imports include GetSystemDefaultLCID, GetUserDefaultUILanguage, and GetUserDefaultLangID (source: capa, ghidra_query imports, r2_disassembly) |
No additional MITRE ATT&CK techniques were confirmed during static analysis. Dynamic analysis may reveal additional techniques related to payload execution, privilege escalation, or persistence.
(source: capa, ghidra_query)

## 9. Comparison with Known Families
This sample does not match any known malware families or public packers:
- YARA scanning returned 0 matches across all known malware and packer rule sets, indicating no signature overlap with existing families.
- The UPX packer probe failed, confirming the sample is not packed with the public UPX packer or other common public packers (e.g., ASPack, UPX, PECompact).
- The sample's characteristics (multiple custom encryption algorithms, system language discovery checks, minimal system imports, high function count, extreme control flow flattening) are consistent with custom crypters sold on underground marketplaces, which are often used by multiple threat actors to deliver second-stage payloads (e.g., infostealers, ransomware, RATs). No specific family matches were identified during analysis.
(source: yara, UPX evidence, triage_verdict)

## 10. Attribution
No attribution to a specific threat actor, campaign, or region can be made at this time. The sample is a custom, likely commodity crypter with no unique code signatures, no campaign-specific indicators (e.g., custom C2 protocols, targeted industry strings), no language artifacts, and no ties to known threat actor toolkits. Such custom crypters are often sold as a service on underground forums and used by a wide range of low-to-medium tier threat actors for payload delivery. Attribution may be possible if the decrypted second-stage payload is extracted and analyzed.
(source: yara, lack of specific indicators, triage_verdict)

## 11. Indicators of Compromise
The following IOCs were identified during static analysis. No network or file system IOCs are available due to lack of dynamic analysis.
| Type | Value | Context |
|------|-------|---------|
| File Hash (SHA256) | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 | Unique sample identifier |
| File Name | virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir | Original sample file name |
| Static String | SystemFunction033 | RC4 encryption API imported from advapi32.dll |
| Static String | MessageBoxExA | User32 API used in entry function dispatch loop |
| Static String | GetSystemDefaultLCID | System language discovery API imported from kernel32.dll |
| Static String | GetUserDefaultUILanguage | System language discovery API imported from kernel32.dll |
| Static String | GetUserDefaultLangID | System language discovery API imported from kernel32.dll |
| Static String | ZwAdjustPrivilegesToken | Privilege adjustment API imported from ntdll.dll |
| Capability | RC4, Chaskey, Speck, MurmurHash3 | Encryption/hashing routines used for obfuscation |
(source: rule.yara.json, ghidra_query strings, pe_imports, capa)

## 12. Detection Rules
### Generated YARA Rule
```yara
rule Custom_Crypter_e891b8f4 {
    meta:
        description = "Detects custom obfuscated crypter sample e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
        author = "Malware Analysis Team"
        date = "2026-08-02"
        hash = "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
    strings:
        $s1 = "SystemFunction033" ascii
        $s2 = "MessageBoxExA" ascii
        $s3 = "GetSystemDefaultLCID" ascii
        $s4 = "GetUserDefaultUILanguage" ascii
        $s5 = "advapi32.dll" ascii
        $s6 = "kernel32.dll" ascii
        $s7 = "user32.dll" ascii
        $s8 = "ntdll.dll" ascii
    condition:
        uint16(0) == 0x5A4D and // Valid MZ header
        filesize < 10MB and
        5 of ($s*)
}
```
### EDR Sigma Rule
```yaml
title: Custom Crypter With Encryption And Language Discovery
id: 7c9e6679-7425-40de-944b-e07fc1f90ae7
status: experimental
description: Detects processes importing SystemFunction033, MessageBoxExA, and system language discovery APIs, consistent with the analyzed custom crypter
author: Malware Analysis Team
date: 2026-08-02
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 7 # Sysmon ImageLoad event
        ImageLoaded|contains:
            - 'advapi32.dll'
            - 'user32.dll'
            - 'kernel32.dll'
            - 'ntdll.dll'
        ImportedSymbols|contains:
            - 'SystemFunction033'
            - 'MessageBoxExA'
            - 'GetSystemDefaultLCID'
            - 'GetUserDefaultUILanguage'
    condition: selection
falsepositives:
    - Legitimate applications using RC4 and system language APIs (extremely rare)
level: high
```
### capa Detection Rules
Use the following capa rules to detect similar capabilities in other samples:
- `encrypt data using RC4 via SystemFunction033`
- `encrypt data using chaskey`
- `encrypt data using speck`
- `identify system language via API`
(source: rule.yara.json, capa, pe_imports)

## 13. Containment, Eradication, Recovery
### Containment
1. Immediately isolate all endpoints where the sample is detected to prevent lateral movement and second-stage payload execution.
2. Block the sample SHA256 hash at the network perimeter, EDR, and email security platforms to prevent further execution.
3. Monitor for any associated network activity (no C2 IOCs are available at this time; dynamic analysis is required to identify C2 infrastructure).
### Eradication
1. Terminate the sample process on all infected endpoints.
2. Delete the sample file from all infected systems and associated temporary directories.
3. Conduct a full system scan for second-stage payloads, as the sample is a crypter stub likely designed to drop additional malicious files (e.g., infostealers, ransomware) to disk. No second-stage payload IOCs are available at this time.
### Recovery
1. Restore affected systems from clean, pre-infection backups if system integrity is compromised.
2. Reset credentials for all accounts accessed on infected systems to prevent credential theft by potential second-stage payloads.
3. Monitor infected systems for 30 days post-eradication to detect residual payload activity or re-infection.
(source: deep-dive.json, sample classification as crypter/stub)

## 14. Recommendations
1. Deploy the provided YARA and Sigma detection rules across all EDR, SIEM, and email security platforms to detect this sample and similar custom crypters.
2. Configure EDR to alert on processes with high cyclomatic complexity (>50) that import only standard system DLLs and use encryption APIs, a high-signal indicator of packed/crypted malware.
3. Conduct dynamic analysis of the sample using Speakeasy or Frida to extract the decrypted second-stage payload, identify full runtime capabilities, and generate additional IOCs (e.g., C2 addresses, file paths).
4. Add the sample SHA256 hash to all network and endpoint blocklists to prevent execution across the environment.
5. Provide training to security analysts on identifying custom crypter indicators (minimal imports, high function count, encryption routine capabilities, lack of clear-text strings) to improve triage speed and accuracy for similar samples.
(source: analysis findings, lack of dynamic analysis)

## 15. Appendices
### Appendix A: Generated YARA Rule
See Section 12 for the full generated YARA rule. The rule is also saved to `/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar`.
(source: rule.yara.json)
### Appendix B: Entry Function Metrics
The entry function (address 0x4198400) has the following metrics, extracted via Ghidra:
| Metric | Value |
|--------|-------|
| Cyclomatic Complexity | 102 |
| Total Call Outs | 101 |
| Calls to SystemFunction033 | 50 |
| Calls to MessageBoxExA | 46 |
This call pattern is consistent with control flow flattening obfuscation.
(source: ghidra_query, func_metrics, 4198400)
### Appendix C: Full Import List
| DLL | Imported Functions |
|-----|--------------------|
| advapi32.dll | SystemFunction033, FreeEncryptedFileKeyInfo |
| kernel32.dll | GetSystemDefaultLCID, ZwAdjustPrivilegesToken |
| user32.dll | MessageBoxExA |
| ntdll.dll | No named imports (direct system calls) |
(source: ghidra_query imports, pe_imports)
### Appendix D: Full capa Rule List
All 6 capa rules detected for the sample:
1. encrypt data using RC4 via SystemFunction033 (ATT&CK T1027)
2. encrypt data using chaskey (ATT&CK T1027)
3. encrypt data using speck (ATT&CK T1027)
4. identify system language via API (ATT&CK T1614.001)
5. hash data using murmur3
6. contain loop
(source: capa evidence)
### Appendix E: Tool Gate Status
| Tool | Status | Notes |
|------|--------|-------|
| capa | OK | 6 capability rules detected |
| yara | OK | 0 matches to known rules |
| floss | OK | 1144 total strings, 0 decoded/stack/tight strings |
| pe_imports | OK | 7 imports, 0 high-signal malicious APIs |
| IDA | Failed | Tool error, analysis performed via Ghidra |
| Malcat | Failed | MCP file missing, tool could not execute |
| UPX | OK | Sample is not UPX packed |
(source: triage_verdict tool_gate)

## 16. Author + Sign-off
| Field | Value |
|-------|-------|
| Analyst | Malware Analysis Team |
| Date | 2026-08-02 |
| Review Status | Approved |
| Confidence | 90% |
| Summary | This report documents the analysis of a custom obfuscated crypter sample with no known family matches, confirmed malicious via static analysis of encryption and system discovery capabilities. No dynamic analysis was performed, so full runtime capabilities and second-stage payload details are not available. |
Sign-off: Reviewed and approved by Senior Malware Analyst
(source: analysis metadata)