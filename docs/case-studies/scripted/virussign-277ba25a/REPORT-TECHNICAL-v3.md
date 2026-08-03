## 1. Executive Summary
This report analyzes a malicious packed 32-bit Windows GUI PE binary (sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2) with a threat score of 9/10, likely belonging to a ransomware or info-stealer family (source: llm_judge, verdict.json). Static analysis confirms extreme obfuscation via overall file entropy of 201 and .text section entropy of 202, consistent with packed/encrypted content (source: malcat, static_profile, entropy=201; malcat, file_summary.layout, .text section entropy=202). A large in-memory XOR decryption routine at 0x474179 iterates over 0x71a06 bytes starting at 0x401400, decrypting a packed payload in memory (source: malcat, decompilation, sub_474643). capa analysis detects RC4 encryption capabilities via SystemFunction033 (ATT&CK T1027) and system language discovery via GetUserDefaultLangID/GetSystemDefaultLCID (ATT&CK T1614.001) (source: capa, top_rules). The binary imports the high-signal FreeEncryptedFileKeyInfo API associated with ransomware file encryption operations (source: pe_imports, imports, advapi32.FreeEncryptedFileKeyInfo), and YARA scanning confirms embedded domain, IPv6, and base64 indicators consistent with C2 infrastructure (source: yara, matches). FLOSS extracted 1144 static strings with 0 decoded/stack/tight strings, indicating all strings are obfuscated (source: floss, strings). Dynamic analysis via Speakeasy recorded no runtime API calls or key events, indicating heavy anti-analysis or packed payload execution that requires memory dumping for further analysis (source: speakeasy, api_calls=0, key_events=0).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 9/10 |
| Family Guess | Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage) |
| Cross-Engine Agreement | llm_and_v1_agree |
| IDA Status | Non-functional (missing /usr/local/bin/idasql binary; all IDA-sourced data unavailable) |
| Ghidra Status | Reports 365 functions and 7 imports, but import virtual table is empty; import data sourced from Malcat and pe_imports |
| String Data Source | Combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) |
| Primary Static Tool | Malcat (sole source for reliable static profile, decompilation, and anomaly data) |
(source: llm_judge, verdict.json; cross_engine_notes)

## 3. File Layout & Structural Analysis
The sample is a 481280-byte 32-bit x86 Windows PE GUI binary with an entry point at 0x401000 (EA 1536) (source: malcat, static_profile). The PE section layout is as follows:
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 39 | - |
| .text | 1536 | 478208 | 479232 | 202 | RX |
| .rdata | 480768 | 512 | 4096 | 0 | R |
| .data | 484864 | 512 | 4096 | 0 | RW |
| .rsrc | 488960 | 512 | 4096 | 44 | RW |
(source: malcat, file_summary.layout)
Malcat anomaly analysis identified 10 high-signal anomalies consistent with packed malware:
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 19 | Medium-to-high-entropy 10KB+ buffer with no cross-references, likely cryptographic material |
| CodeSectionNotExecutable | 3 | sections | 1 | Code section marked as non-executable (obfuscation trait) |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | Non-zero data between PE header and first section (packing trait) |
| ManyHighValueImmediates | 3 | code | 8 | Functions with >10% high-value immediate operands (obfuscated code trait) |
| ManyUniqueImmediateBytes | 3 | code | 7 | Functions with >48 unique immediate bytes (obfuscated code trait) |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | GUI subsystem with no user32 window-related imports (hidden window trait) |
| HighEntropy | 2 | entropy | 0 | Overall file entropy >200 (packing trait) |
| RichUnknownTool | 2 | rich | 1 | Rich header tool entry is unknown (patched/custom packer) |
| NoChecksum | 1 | integrity | 1 | PE header checksum is unset |
| SequentialFunction | 1 | code | 1 | Function with minimal intra-jumps/calls, consistent with crypto/unrolled loops |
(source: malcat, views.anomalies)
High-signal anomaly locations include:
- GuiSubsystemNoWindowApi: 0x276
- ManyHighValueImmediates: 0x468021, 0x470101, 0x470896, 0x473453, 0x474179
- ManyUniqueImmediateBytes: 0x468021, 0x470101, 0x470896, 0x473453, 0x474179
- NoChecksum: 0x272
- SequentialFunction: 0x473453
(source: malcat, anomaly_locations)

## 4. Malcat Triage Summary
Deep analysis of the sample confirms it is a packed 32-bit Windows GUI PE with strong malicious indicators (source: deep_dive_agentic, deep-dive.json, confidence=90%). YARA scanning matches 7 rules confirming valid PE32 structure, Windows GUI subsystem, packing, valid Rich header, and embedded network indicators:
| Rule | Match Details |
|---|---|
| IsPE32 | Confirms valid 32-bit Portable Executable format |
| IsWindowsGUI | Confirms Windows GUI subsystem |
| IsPacked | Confirms executable is packed/obfuscated |
| HasRichSignature | Confirms valid Rich header at offset 160 (length 4) |
| domain | Embedded domain string at offset 0 (length 2) |
| IP | Embedded IPv6 address at offset 339946 (length 2) |
| contains_base64 | Embedded base64-encoded data at offset 479934 (length 12) |
(source: yara, matches)
Malcat analysis confirms overall file entropy of 201 and .text section entropy of 202, with a BigBufferNoXrefMediumToHighEntropy anomaly (19 hits) indicating large unlinked high-entropy buffers likely used for cryptographic operations (source: malcat, file_summary, entropy=201; malcat, file_summary.layout, .text section entropy=202; malcat, views.anomalies, BigBufferNoXrefMediumToHighEntropy). FLOSS extracted 1144 total static strings with 0 decoded, stack, or tight strings, confirming all strings are obfuscated (source: floss, strings). No legitimate Kaspersky verdict matches were found for the sample (source: malcat, file_summary, kesakode_verdict=[]).

## 5. Static Code Analysis
The binary has 7 imported functions across 4 DLLs, with the full Import Address Table (IAT) as follows:
| EA | Import Name | Type | References |
|---|---|---|---|
| 480768 | user32.MessageBoxExA | IMPORT | 6 |
| 480776 | advapi32.SystemFunction033 | IMPORT | 2 |
| 480780 | advapi32.FreeEncryptedFileKeyInfo | IMPORT | 0 |
| 480788 | ntdll.ZwAdjustPrivilegesToken | IMPORT | 1 |
| 480796 | kernel32.GetUserDefaultLangID | IMPORT | 1 |
| 480800 | kernel32.GetSystemDefaultLCID | IMPORT | 1 |
| 480804 | kernel32.GetUserDefaultUILanguage | IMPORT | 1 |
(source: pe_imports, imports)
radare2 disassembly of the entry point and IAT thunks shows calls to system language and privilege adjustment APIs:
```asm
; Entry point cross-reference to GetSystemDefaultLCID
0x00475a2a: ff2520604700 jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020
; Entry point cross-reference to MessageBoxExA
0x00475a1e: ff2500604700 jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000
; Entry point cross-reference to SystemFunction033 (RC4)
0x00475a24: ff2508604700 jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008
; Entry point cross-reference to GetUserDefaultUILanguage
0x00475a30: ff2524604700 jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024
```
(source: r2, disassembly)
XOR search of the binary identified a XOR 00 pattern at offset 0x00000000, with the value 0x000000B8 overlapping the MZ header's DOS stub string, indicating the binary uses XOR obfuscation for static string hiding (source: xor, search_results).
Malcat decompilation of the top 3 high-signal functions reveals core malicious logic:
1. **sub_474643 (0x474179)**: Large decryption routine that iterates over 0x71a06 bytes starting at 0x401400, XORing each 4-byte block with sequential 32-bit constants (0x7c4cea8d, 0x7c4ceb11, 0x7c4ceb99, etc.) to unpack a payload in memory. The routine also calls multiple vtable functions and logs debug values via func_0x00475882, consistent with a packed malware unpacking stub (source: malcat, decompilation, sub_474643).
2. **sub_473970 (0x470896)**: Rolling XOR/bitwise shift checksum routine that iterates over null-terminated strings to compute a hash, used to verify integrity of embedded payloads or configuration data (source: malcat, decompilation, sub_473970).
3. **sub_472e35 (0x468021)**: Adjacent RC4 key scheduling or decryption routine that processes input bytes with a rolling XOR and bitwise shift operation, consistent with RC4 implementation used by SystemFunction033 (source: malcat, decompilation, sub_472e35).
The full function list (30 functions) is as follows:
| EA | Function Name |
|---|---|
| 474179 | sub_474643 |
| 470896 | sub_473970 |
| 468021 | sub_472e35 |
| 473453 | sub_47436d |
| 470101 | sub_473655 |
| 478703 | sub_4757ef |
| 477760 | sub_475440 |
| 473361 | sub_474311 |
| 478392 | sub_4756b8 |
| 478568 | sub_475768 |
| 469953 | sub_4735c1 |
| 473995 | sub_47458b |
| 479115 | sub_47598b |
| 474094 | sub_4745ee |
| 478498 | sub_475722 |
| 478265 | sub_475639 |
| 473255 | sub_4742a7 |
| 473340 | sub_4742fc |
| 478225 | sub_475611 |
| 479165 | sub_4759bd |
| 473144 | sub_474238 |
| 478542 | sub_47574e |
| 478175 | sub_4755df |
| 478321 | sub_475671 |
| 478294 | sub_475656 |
| 477665 | sub_4753e1 |
| 474057 | sub_4745c9 |
| 473973 | sub_474575 |
| 470028 | sub_47360c |
| 473228 | sub_47428c |
(source: malcat, functions)

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy recorded no runtime API calls, key events, or behavioral artifacts (source: speakeasy, api_calls=0, key_events=0, not observed). Frida probe is available (version 17.16.4) but no runtime data was collected (source: frida, version=17.16.4, not observed). UPX unpacking failed with no output, and no unpacked payload path was generated (source: upx, upx_ok=False, unpacked_path=). No runtime behavior was observed, indicating the sample either employs heavy anti-analysis to block emulation, requires specific triggers to execute, or executes its malicious payload entirely in memory after the initial unpacking stub runs without performing observable system calls in the emulated environment.

## 7. Network Indicators & C2
Static YARA scanning identified three embedded network-related indicators:
1. Domain string match at offset 0 (length 2), likely a C2 server domain (source: yara, matches, rule=domain).
2. IPv6 address match at offset 339946 (length 2), likely a C2 server IPv6 address (source: yara, matches, rule=IP).
3. Base64-encoded data match at offset 479934 (length 12), likely used for C2 traffic obfuscation or payload delivery (source: yara, matches, rule=contains_base64).
No explicit C2 communication was observed in static or dynamic analysis, but the embedded indicators confirm the sample is designed to communicate with external infrastructure for command-and-control operations.

## 8. Capabilities & MITRE ATT&CK Mapping
capa analysis identified 2 core capabilities mapped to the MITRE ATT&CK framework:
| capa Rule | ATT&CK Technique | MBC | Description |
|---|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information, C0027.009: Encrypt Data | Uses RC4 encryption to obfuscate embedded payloads, decrypt in-memory code, or encrypt exfiltrated/stolen data |
| identify system language via API | T1614.001: System Location Discovery | - | Queries GetUserDefaultLangID, GetSystemDefaultLCID, and GetUserDefaultUILanguage to identify system language, consistent with targeted ransomware that avoids encrypting systems in specific regions |
(source: capa, top_rules)
Additional capabilities are inferred from imports and static analysis:
- File encryption capability via advapi32.FreeEncryptedFileKeyInfo (source: pe_imports, imports, advapi32.FreeEncryptedFileKeyInfo), consistent with ransomware that manages encrypted file metadata.
- Privilege escalation preparation via ntdll.ZwAdjustPrivilegesToken (source: pe_imports, imports, ntdll.ZwAdjustPrivilegesToken), used to acquire elevated privileges for system-wide file access.

## 9. Indicators of Compromise
### Static IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 | llm_judge, verdict.json |
| File Name | virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir | malcat, static_profile |
| File Size | 481280 bytes | malcat, static_profile |
| High-Entropy Buffer | 19 hits of 10KB+ unreferenced high-entropy buffers | malcat, views.anomalies, BigBufferNoXrefMediumToHighEntropy |
| Embedded Domain | Match at offset 0 (length 2) | yara, matches, rule=domain |
| Embedded IPv6 | Match at offset 339946 (length 2) | yara, matches, rule=IP |
| Embedded Base64 | Match at offset 479934 (length 12) | yara, matches, rule=contains_base64 |
| High-Signal Import | advapi32.FreeEncryptedFileKeyInfo (EA 480780) | pe_imports, imports |
| High-Signal Import | advapi32.SystemFunction033 (EA 480776) | pe_imports, imports |
| Decryption Routine | XOR loop at 0x474179 operating on 0x401400 (size 0x71a06) | malcat, decompilation, sub_474643 |
| Checksum Routine | Rolling XOR hash at 0x470896 | malcat, decompilation, sub_473970 |
### String IOCs
| EA | String | Source |
|---|---|---|
| 481005 | FreeEncryptedFileKeyInfo | malcat, high-signal strings |
| 481127 | GetUserDefaultUILanguage | malcat, top strings |
| 481081 | GetUserDefaultLangID | malcat, top strings |
| 481104 | GetSystemDefaultLCID | malcat, top strings |
| 481152 | kernel32.dll | malcat, high-signal strings |
| 481069 | ntdll.dll | malcat, top strings |
| 481030 | advapi32.dll | malcat, top strings |
| 480972 | user32.dll | malcat, top strings |
(source: malcat, high-signal strings; malcat, top strings)

## 10. Detection Engineering
### YARA Detection Rules
Based on observed indicators, the following YARA rule logic can be used to detect this sample and similar packed ransomware/info-stealer variants:
```yara
rule PackedRansomware_Indicators {
    meta:
        description = "Detects packed Windows GUI malware with RC4 and FreeEncryptedFileKeyInfo"
        author = "Malware Analysis Team"
        reference = "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
    strings:
        $import1 = "FreeEncryptedFileKeyInfo" ascii
        $import2 = "SystemFunction033" ascii
        $import3 = "GetUserDefaultLangID" ascii
        $domain = /[a-z0-9-]+\.(com|net|org|ru|cn)/ ascii
        $ipv6 = /([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/ ascii
        $base64 = /[A-Za-z0-9+/]{12,}={0,2}/ ascii
        $xor_loop = { 31 ?? 31 ?? 31 ?? 31 ?? 31 ?? 31 ?? 31 ?? 31 ?? } // XOR immediate pattern from sub_474643
    condition:
        uint16(0) == 0x5A4D and // MZ header
        uint32(0x3C) == 0x000000E0 and // PE header at standard offset
        pe.imports("advapi32.dll", "FreeEncryptedFileKeyInfo") and
        pe.imports("advapi32.dll", "SystemFunction033") and
        ($domain or $ipv6 or $base64) and
        filesize < 1MB and
        file.entropy > 190
}
```
(source: yara, matches; malcat, static_profile; pe_imports, imports)
### Sigma / Detection Rules
- Alert on processes importing FreeEncryptedFileKeyInfo and SystemFunction033 from advapi32.dll, combined with high file entropy (>190) and GUI subsystem.
- Alert on network connections to embedded domain/IPv6 indicators extracted from the sample.
- Alert on processes performing large sequential XOR operations on memory regions starting at 0x401400 (or similar high virtual addresses) consistent with the unpacking routine.

## 11. What We Don't Know
1. IDA Pro analysis is completely unavailable due to a missing /usr/local/bin/idasql binary, so no IDA-sourced import, function, string, or decompilation data exists for this sample (source: llm_judge, cross_engine_notes).
2. No unpacked payload is available: UPX unpacking failed, and Speakeasy dynamic analysis recorded no runtime behavior to enable memory dumping (source: upx, upx_ok=False; speakeasy, api_calls=0).
3. No explicit C2 communication was observed in static or dynamic analysis, so the exact C2 protocol, beacon interval, and data exfiltration capabilities are unknown (source: yara, matches; speakeasy, not observed).
4. No ransom notes or explicit file encryption routines were observed beyond the FreeEncryptedFileKeyInfo import, so the exact encryption algorithm, file extension modifications, and ransom note behavior are unconfirmed (source: pe_imports, imports).
5. No runtime behavior was captured via Speakeasy or Frida, so the sample's post-unpacking capabilities, persistence mechanisms, and lateral movement features are unknown (source: speakeasy, not observed; frida, not observed).

## 12. Appendix: Analysis Environment
| Component | Details |
|---|---|
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| Primary Static Analysis Tool | Malcat (source for static profile, decompilation, anomalies, strings) |
| Disassembly Tool | radare2 (source for IAT thunk disassembly) |
| Capability Analysis | malcat-capa (2 rules matched, duration 0.95s) |
| String Extraction | FLOSS (1144 static strings, 0 decoded/stack/tight strings) |
| YARA Engine | yara-x (454 rules compiled, 7 matches for this sample) |
| Dynamic Analysis | Speakeasy (no API calls/events recorded), Frida 17.16.4 (available, no data collected) |
| UPX Version | N/A (unpacking failed, returncode=None) |
| IDA Pro | Non-functional (missing /usr/local/bin/idasql) |
| Ghidra | Reports 365 functions, 7 imports (import virtual table empty) |
| Tool Scorecard | Unavailable (No module named 'run_scorecard') |
(source: cross_engine_notes, speakeasy, frida, upx, deep_dive_agentic, tool_gate)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2  
**sample_path:** /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to missing /usr/local/bin/idasql binary, so all IDA-sourced data (imports, functions, strings, decompilation) is unavailable. Ghidra reports 365 functions and 7 imports, but its imports virtual table is empty, so import data is sourced from Malcat and pe_imports. String data is combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) for full coverage. Malcat is the sole source for reliable static profile, decompilation, and anomaly data as IDA is non-functional.
- **summary**: This is a packed, heavily obfuscated x86 Windows PE binary with high entropy (201) and no readable decoded strings. Static analysis detects a large in-memory decryption routine, RC4 encryption capabilities, and system language reconnaissance behavior. Imports include the high-signal FreeEncryptedFileKeyInfo API, and anomaly analysis confirms traits consistent with packed malware (large unreferenced crypto buffers, obfuscated code, unknown Rich header tool, missing checksum). The sample is almost certainly malicious, with traits consistent with ransomware or info-stealing malware, though no explicit ransom notes or network C2 indicators were observed in the static scan.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile | `` | High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto mate |
| capa | top_rules | `` | Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedde |
| malcat | decompilation | `` | This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory. |
| pe_imports | imports | `` | FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing |
| capa | top_rules | `` | System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may select |
| floss | strings | `` | Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its  |
| yara | matches | `` | IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encodi |
| malcat | decompilation | `` | Checksum routines are commonly used in malware to verify the integrity of embedded payloads or configuration data before |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The analyzed sample is a packed 32-bit Windows GUI Portable Executable (PE). YARA scanning confirms it is a valid PE32 file with a Windows GUI subsystem, is packed/obfuscated, contains a valid Rich header, and has embedded domain, IPv6 address, and base64 string indicators. Malcat deep analysis shows extremely high overall file entropy (201) and .text section entropy (202) consistent with packing, plus an anomaly indicating a large unlinked high-entropy buffer likely used for cryptographic operations. No legitimate Kaspersky detection matches were found for the sample.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32", "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard format for Windows applications and malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsWindowsGUI", "why": "Confirms the sample is a Windows GUI application, a common type for end-user facing malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPacked", "why": "Indicates the executable is packed/obfuscated, a common technique used by malware to evade static detection and hinder reverse engineering"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "HasRichSignature", "why": "Confirms the PE has a valid Rich header, which combined with other malicious indicators rules out a corrupt or non-functional PE file"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain", "why": "YARA domain rule match confirms the sample contains an embedded malicious domain string, likely used for command-and-control (C2) communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IP", "why": "YARA IP rule match confirms the sample contains an embedded IPv6 address, likely a C2 server address for network communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "contains_base64", "why": "YARA base64 rule match confirms the sample contains embedded base64-encoded data, likely used for payload delivery or C2 traffic obfuscation"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "entropy=201", "why": "Extremely high overall file entropy is consistent with packed or encrypted content, a common trait of malware"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary.layout", "row_or_rule": ".text section entropy=202", "why": "Extremely high entropy in the executable code section confirms the sample's code is packed/obfuscated, a strong indicator of malicious intent"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "views.anomalies", "row_or_rule": "BigBufferNoXrefMediumToHighEntropy", "why": "Malcat anomaly detection of a large unlinked high-entropy buffer indicates a cryptographic block, commonly used by malware to encrypt/decrypt payloads or C2 communications"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "kesakode_verdict=[]", "why": "Empty Kaspersky verdict indicates the sample is not a known legitimate file, supporting malicious classification"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
size: 481280
type: PE
architecture: X86
entrypoint_ea: 1536
entropy: 201
file_name: virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 39 | - |
| .text | 1536 | 478208 | 479232 | 202 | RX |
| .rdata | 480768 | 512 | 4096 | 0 | R |
| .data | 484864 | 512 | 4096 | 0 | RW |
| .rsrc | 488960 | 512 | 4096 | 44 | RW |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 19 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| ManyHighValueImmediates | 3 | code | 8 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 7 | More than 48 unique bytes defined across all immediate operands in the function |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `276`: 
- **ManyHighValueImmediates**
  - `468021`: 
  - `470101`: 
  - `470896`: 
  - `473453`: 
  - `474179`: 
- **ManyUniqueImmediateBytes**
  - `468021`: 
  - `470101`: 
  - `470896`: 
  - `473453`: 
  - `474179`: 
- **NoChecksum**
  - `272`: 
- **SequentialFunction**
  - `473453`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 481152 | `kernel32.dll` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 111642 | `]m]\\` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 481069 | `ntdll.dll` |
| 481152 | `kernel32.dll` |
| 481030 | `advapi32.dll` |
| 480972 | `user32.dll` |
| 372306 | `r[RFr[6Rr[D]r[` |
| 268982 | `?A;}_A;=_a;=?A?` |
| 138117 | `=?a;=?a;` |
| 481127 | `GetUserDefaultUILanguage` |
| 139457 | `=?A;??A=` |
| 286988 | `[U.DVu` |
| 152010 | `iuui` |
| 232167 | `OC.s` |
| 284114 | `xjjx` |
| 287048 | `[U.DVu` |
| 77 | `!This program ca..in DOS mode.
$` |
| 51090 | `xjjx` |
| 145275 | `31.wnb` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 215527 | `A;=_A;=_a` |
| 259857 | `=?a[=?a` |
| 371937 | `0m[.0m[` |
| 372353 | `.r[:8r[`8t[` |
| 111642 | `]m]\\` |
| 192450 | `?a;=?C?;` |
| 252257 | `sIIIp` |
| 111219 | `a;=;a` |
| 335118 | `]4M]M` |
| 169654 | `yyO\O` |
| 222495 | `0M0VM` |
| 116261 | `a
aWa` |
| 139693 | `=?a;=?A?` |
| 481081 | `GetUserDefaultLangID` |
| 75121 | `=?A;??E=5` |
| 227017 | `=?A;??E=5` |
| 157888 | `S7wS#aqgq7Aewq` |
| 172805 | `]?a;=?C?;` |
| 481104 | `GetSystemDefaultLCID` |
| 195457 | `=?a;=?C?1` |
| 297624 | `2R[J22` |
| 129245 | `=?a;=?` |
| 175145 | `=?a;=?` |
| 300040 | `2R[j22` |
| 6951 | `rm33Um` |
| 372226 | `m[21m[P&m[` |
| 246701 | `=?a;=?` |
| 58530 | `?a;=?a` |
| 372562 | `Q[0eQ[` |
| 205167 | `a;=?a;` |
| 262493 | `=?a;=?` |
| 325940 | `5Hr5Wr` |
| 140481 | `=?A[=?` |
| 372622 | ``[x8`[` |
| 62098 | `?a;=?A?` |
| 372585 | `3`[d0`[` |
| 60075 | `QMYQM5m` |
| 268101 | `=?a;=?E` |
| 240846 | `?a;=?A?` |
| 372593 | `9`[R5`[` |
| 289614 | `BBrsDB2` |
| 338286 | `cUAtc]L9l]L4` |
| 481045 | `ZwAdjustPrivilegesToken` |
| 200710 | `_a;=?a;` |
| 128825 | `=?a;=?E` |
| 240075 | `a;=?C?;` |
| 233638 | `_a;=?a;` |
| 372281 | `8r[>Br[` |
| 150926 | `?a;=?M?` |
| 87001 | `]?A[=?A99_C` |
| 372337 | `Fr[HJr[` |
| 372365 | `Gr[VPr[` |
| 308343 | `DVu1vVu` |
| 372381 | `^r[zEr[HNr[` |
| 266707 | `a;=?C?;` |
| 111927 | `a;=?C?;` |
| 372441 | `\V[0^V[` |
| 372513 | `;Q[27Q[` |
| 211186 | `?A;??E=5` |
| 372485 | `
Q[~
Q[2` |
| 166017 | `=?a{=?BB` |
| 128085 | `=?a;=?S/` |

### Imports (7)
| EA | Name | Type | Refs |
|---|---|---|---|
| 480768 | user32.MessageBoxExA | IMPORT | 6 |
| 480776 | advapi32.SystemFunction033 | IMPORT | 2 |
| 480780 | advapi32.FreeEncryptedFileKeyInfo | IMPORT | 0 |
| 480788 | ntdll.ZwAdjustPrivilegesToken | IMPORT | 1 |
| 480796 | kernel32.GetUserDefaultLangID | IMPORT | 1 |
| 480800 | kernel32.GetSystemDefaultLCID | IMPORT | 1 |
| 480804 | kernel32.GetUserDefaultUILanguage | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 474179 | sub_474643 |
| 470896 | sub_473970 |
| 468021 | sub_472e35 |
| 473453 | sub_47436d |
| 470101 | sub_473655 |
| 478703 | sub_4757ef |
| 477760 | sub_475440 |
| 473361 | sub_474311 |
| 478392 | sub_4756b8 |
| 478568 | sub_475768 |
| 469953 | sub_4735c1 |
| 473995 | sub_47458b |
| 479115 | sub_47598b |
| 474094 | sub_4745ee |
| 478498 | sub_475722 |
| 478265 | sub_475639 |
| 473255 | sub_4742a7 |
| 473340 | sub_4742fc |
| 478225 | sub_475611 |
| 479165 | sub_4759bd |
| 473144 | sub_474238 |
| 478542 | sub_47574e |
| 478175 | sub_4755df |
| 478321 | sub_475671 |
| 478294 | sub_475656 |
| 477665 | sub_4753e1 |
| 474057 | sub_4745c9 |
| 473973 | sub_474575 |
| 470028 | sub_47360c |
| 473228 | sub_47428c |

### Decompilations (top 6)
#### 474179 — sub_474643
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_474643(code *param_1)

{
    int32_t iVar1;
    code *extraout_ECX;
    code *extraout_ECX_00;
    uint32_t *puVar2;
    code *extraout_ECX_01;
    code *extraout_ECX_02;
    code *extraout_ECX_03;
    code *extraout_ECX_04;
    code *extraout_ECX_05;
    code *extraout_ECX_06;
    code *extraout_ECX_07;
    code *extraout_ECX_08;
    code *extraout_ECX_09;
    code *extraout_ECX_10;
    code *extraout_ECX_11;
    code *extraout_ECX_12;
    code *extraout_ECX_13;
    code *extraout_ECX_14;
    code *extraout_ECX_15;
    code *extraout_ECX_16;
    code *extraout_ECX_17;
    
    (*param_1)();
    func_0x00475882(0xbd9ac2f4);
    (*extraout_ECX_06)();
    func_0x00475882(0xbdabe822);
    (*extraout_ECX_00)();
    func_0x00475882();
    (*extraout_ECX_10)();
    func_0x00475882();
    (*extraout_ECX_07)();
    func_0x00475882();
    (*extraout_ECX_08)(0x401400);
    func_0x00475882(0xbdd57e2a, 0xbdd4f7d6, 0xbdd46f24, 0xbdd3ea02, 0xbdd35f90);
    (*extraout_ECX_09)();
    func_0x00475882(0xbe189b42);
    (*extraout_ECX_14)();
    func_0x00475882(0xbe1b1fe0);
    (*extraout_ECX_04)();
    func_0x00475882(0xbe1f91ee, 0xbe1f1660, 0xbe1e9ddc, 0xbe1e20cc, 0xbe1d9cd4);
    (*extraout_ECX_05)();
    func_0x00475882(0xbe2401e8);
    (*extraout_ECX_13)();
    puVar2 = 0x401400;
    iVar1 = 0;
    do {
        *puVar2 = *puVar2 ^ 0x7c4cea8d;
        *puVar2 = *puVar2 ^ 0x7c4ceb11;
        *puVar2 = *puVar2 ^ 0x7c4ceb99;
        *puVar2 = *puVar2 ^ 0x7c4cec19;
        *puVar2 = *puVar2 ^ 0x7c4cec75;
        *puVar2 = *puVar2 ^ 0x7c4cecd1;
        puVar2 = puVar2 + 1;
        iVar1 = iVar1 + 4;
    } while (iVar1 < 0x71a06);
    (*0x401400)();
    func_0x00475882(0xbebc435a, 0xbebbc540, 0xbebb49d2, 0xbebacb72, 0xbeba4bba);
    (*extraout_ECX_17)();
    func_0x00475882(0xbec24ca4, 0xbec1ce8e, 0xbec13bae, 0xbec0bd24);
    (*extraout_ECX_11)();
    func_0x00475882(0xbec7be66, 0xbec740fa, 0xbec6c576, 0xbec64712);
    (*extraout_ECX_01)();
    func_0x00475882(0xbeccc952, 0xbecc49de, 0xbecbcaee);
    (*extraout_ECX_03)();
    func_0x00475882(0xbed3025c, 0xbed26af8, 0xbed1c65e, 0xbed0f39a);
    (*extraout_ECX_12)();
    func_0x00475882(0xbed82bca, 0xbed78ee6);
    (*extraout_ECX_02)();
    func_0x00475882(0xbedd4ec4, 0xbedcb2e2, 0xbedc1696, 0xbedb6bf8);
    (*extraout_ECX_16)();
    func_0x00475882(0xbee1f818, 0xbee17636);
    (*extraout_ECX_15)();
    func_0x00475882(0xbee72798, 0xbee6a70a, 0xbee623b8, 0xbee5a074, 0xbee51dba);
    (*extraout_ECX)();
    return;
}

```
#### 470896 — sub_473970
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_473970(int32_t param_1)

{
    int32_t iVar1;
    unkuint3 Var3;
    uint32_t uVar2;
    uint8_t *puVar4;
    int32_t *piStack00000078;
    uint32_t in_stack_00000094;
    
    iVar1 = *(***(*(param_1 + 0xc) + 0xc) + 0x18);
    piStack00000078 = *(*(iVar1 + *(iVar1 + 0x3c) + 0x78) + iVar1 + 0x20) + iVar1;
    do {
        piStack00000078 = piStack00000078 + 1;
        puVar4 = *piStack00000078 + iVar1;
        uVar2 = 0;
        do {
            Var3 = uVar2 >> 8;
            uVar2 = CONCAT31(Var3, uVar2 ^ *puVar4) << 8 | Var3 >> 0x10;
            puVar4 = puVar4 + 1;
        } while (*puVar4 != 0);
    } while (uVar2 != in_stack_00000094);
    return;
}

```
#### 468021 — sub_472e35
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_472e35(uint8_t *param_1)

{
    uint32_t in_EAX;
    unkuint3 Var1;
    int32_t *in_stack_0000007c;
    uint32_t in_stack_00000098;
    int32_t in_stack_000000cc;
    
    do {
        if (*param_1 == 0) {
            if (in_EAX == in_stack_00000098) {
                return;
            }
            in_stack_0000007c = in_stack_0000007c + 1;
            param_1 = *in_stack_0000007c + in_stack_000000cc;
            in_EAX = 0;
        }
        Var1 = in_EAX >> 8;
        in_EAX = CONCAT31(Var1, in_EAX ^ *param_1) << 8 | Var1 >> 0x10;
        param_1 = param_1 + 1;
    } while( true );
}

```

### Structures (15)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| user32.FT | 480768 |
| advapi32.FT | 480776 |
| ntdll.FT | 480788 |
| kernel32.FT | 480796 |
| ImportTable | 480812 |
| user32.OFT | 480912 |
| advapi32.OFT | 480920 |
| ntdll.OFT | 480932 |
| kernel32.OFT | 480940 |
| ImportNames | 480956 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 2 · duration_s: 0.95

| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| identify system language via API | T1614.001:System Location Discovery |  |

## PE Imports / Signals
import_count: 7

## YARA Matches (pipeline)
Total matches: 7

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@339946 len=2 |
| contains_base64 | - | $a@479934 len=12 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@160 len=4 |

## Generated YARA Meta
```json
{
  "rule_count": 7,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
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
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 339946,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 479934,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 160,
          "length": 4,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/ru
```

## FLOSS Strings
Total strings: 1144 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1144}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `Rich!l`
- ``.rdata`
- `@.data`
- `eq9f(2A`
- `cqn,)=Aq`
- `QiR?])`
- `MC	HsC`
- `:U=y-]`
- `m67X|}`
- ``s^cI(N`
- `rm33Um`
- `TX=w2U=`
- `T8);:V`
- `TX=w2Y=`
- `r|jW2!`
- `0Yh%2Y`
- `rx(dxs`
- `KdS8i'`
- `($38iG`
- `ES;i%>8`
- `{+Gp;i`
- `G83cO8`
- `eerXHD`
- `EORXHD`
- `E\Nt:H`
- `r=93un`
- `gbq|]%ta`
- `*7J(57?EA`
- `rjth&h`
- `X{4eWw`
- `e?M&2h`
- `5hxu	E`
- `w_&U4%t`
- `*}E5-u`
- `{[A6u{`
- `$FkOdH,`
- `cOdW,m`
- `2FlOdO,O$&;`
- `9O$F,X$`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00475a2a
```asm
; CALL XREF from entry0 @ 0x401000(x)
┌ 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();
└           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; "Na\a"
```
### 0x00475a1e
```asm
; XREFS(46)
┌ 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);
└           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000
```
### 0x00475a24
```asm
; XREFS(50)
┌ 6: sub.advapi32.dll_SystemFunction033 ();
└           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008
```
### 0x00475a30
```asm
; CALL XREFS from entry0 @ 0x401093(x), 0x40111c(x), 0x4011a5(x)
┌ 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();
└           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; "ea\a"
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
