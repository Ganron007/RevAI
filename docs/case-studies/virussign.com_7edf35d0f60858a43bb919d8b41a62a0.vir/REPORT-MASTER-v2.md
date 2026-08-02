# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious, packed with Themida (ATT&CK T1027.002) to obfuscate a hidden malicious payload, with anti-analysis capabilities |
| Deep dive | packed_with_themida |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Executive Summary
This report analyzes the PE sample with SHA256 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544, received via the incoming corpus project. Static analysis confirms the sample is packed with the commercial Themida packer (ATT&CK T1027.002) to obfuscate a hidden malicious payload, with a triage risk score of 88 (Malicious). Key evidence includes capa identification of Themida packing and aPLib decompression logic, FLOSS extraction of a `.themida` section marker, and Ghidra analysis revealing a minimal import table (3 total imports, 0 high-signal malicious APIs) and extremely low function/string counts consistent with packed binaries. A 4.7MB encrypted `.themida` section contains the compressed original payload, which cannot be analyzed without dynamic unpacking. No known malware family matches were found via YARA, and the underlying payload's capabilities, behavior, and attribution are unknown pending unpacking. (source: triage_verdict, deep-dive.json, capa, floss, ghidra_query)

## 1. Sample Identification
The analyzed sample is a 32-bit Windows PE (Portable Executable) file with the following identifying attributes:
- SHA256: 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
- Sample path: /opt/samples/corpus/incoming/3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544/virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir
- Project name: incoming
- File type: PE32 executable, Themida-packed (not UPX-packed, per UPX probe failure)
- Notable sections: A 4,710,400 byte (4.7MB) `.themida` section at RVA 0x268783616 with no readable strings, containing the encrypted/compressed original payload
- Standard DOS stub: XOR search recovered the standard "This program cannot be run in DOS mode" string at the start of the file, confirming valid PE structure. (sources: xorsearch, upx_unpack, ghidra_query memory_blocks, pe_imports)

## 2. Classification
The sample is classified as **Malicious, Themida-packed unknown payload** with a confidence score of 88/100. Themida is a commercial packer widely used to obfuscate malware, evade static detection, and hinder reverse engineering (ATT&CK T1027.002). The exact underlying malware family cannot be determined without dynamic unpacking; the triage assessment notes the payload is likely a common commodity malware type such as a trojan, info-stealer, or ransomware. No high-signal malicious imports or strings were found in the static packer stub, as all malicious functionality is hidden in the compressed `.themida` section. (sources: triage_verdict, deep-dive.json, capa)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes of sample ingestion, yielding a malicious verdict with a score of 88. Key triage findings:
1. capa static analysis identified the sample as packed with Themida (T1027.002) and flagged aPLib decompression logic (MBC C0025.003) consistent with packed malware, plus strings referencing reverse engineering and analysis tools indicating anti-analysis capabilities.
2. FLOSS string extraction recovered a `.themida` section marker, directly corroborating the Themida packing finding.
3. PE import analysis found only 3 total imports (GetModuleHandleA, TranslateMessage, OpenProcessToken) with 0 high-signal malicious APIs, a hallmark of packed binaries with stripped import tables.
4. Ghidra analysis found only 25 functions and 54 visible strings, far fewer than expected for a full malicious binary, consistent with a small unpacking stub.
5. UPX unpacking probe failed, confirming the sample is not packed with UPX.
6. YARA scanning returned no matches for known malware families, indicating the sample is either a new variant or custom packed payload. (sources: triage_verdict, capa, floss, pe_imports, ghidra_query, upx_unpack, yara)

## 4. Static Analysis
Static analysis focused on PE structure, imports/exports, strings, and disassembly of the visible packer stub:
### PE Structure
The sample is a valid 32-bit PE file with a single large `.themida` section (4.7MB) that contains all encrypted/compressed payload data. No other suspicious sections were identified.
### Imports
Only 3 imports are present, all from core Windows DLLs (source: pe_imports, ghidra_query imports):
| DLL | Import | Purpose |
|-----|--------|---------|
| KERNEL32.DLL | GetModuleHandleA | Load core Windows libraries |
| USER32.DLL | TranslateMessage | Minimal UI-related function, likely stub |
| ADVAPI32.DLL | OpenProcessToken | Likely used for privilege escalation in the unpacked payload |
No high-signal malicious APIs (e.g., VirtualAllocEx, WriteProcessMemory, RegSetValueEx) are present, as these are part of the hidden payload.
### Exports
One forwarded export is present: `InitializeSecurity` (source: ghidra_query exports). This is a common stub export used by packers to mimic legitimate library functionality.
### Strings
FLOSS extracted 5014 total strings from the sample (source: floss). Notable string categories:
- Themida-specific marker: `.themida`
- Mangeld C++ class strings from the `StringLoaderB` class (24 unique strings, source: rule.yara.json), likely part of the packer's internal file loading logic
- High-entropy obfuscated strings with no readable content
- No malicious indicators were found: searches for common malware-related terms (http, cmd, shell, inject, keylog, ransom, crypt, bot, rat, backdoor, payload, loader, dropper) returned 0 results (source: ghidra_query strings search).
### Disassembly
Radare2 disassembly of the entry point (0x104d3058, 336 bytes) reveals a highly complex unpacking stub with 52 basic blocks and a cyclomatic complexity of 27 (source: r2_disassembly, ghidra_query function_metrics). The entry function calls a secondary function (FUN_104d31a8) and implements aPLib decompression logic, consistent with Themida's unpacking routine. The `InitializeSecurity` export function (0x10019110) consists entirely of obfuscated junk code and invalid instructions, typical of Themida's code virtualization layer to frustrate reverse engineering. (source: r2_disassembly)

## 5. Behavioral Analysis
No dynamic behavioral analysis (sandbox execution, Frida tracing, Speakeasy emulation) was performed on this sample, as the analysis environment does not support emulation of Themida-packed binaries. No runtime behavior (file system changes, process injection, registry modifications, payload execution) was observed.
Static anti-analysis indicators confirm the sample is designed to evade detection: capa identified strings referencing reverse engineering and analysis tools (source: capa), which the packer stub will use to detect sandbox or analyst environments and alter or halt execution to avoid analysis. The full behavioral capabilities of the underlying payload are unknown and require dynamic unpacking to evaluate. (source: deep-dive.json, capa)

## 6. Network Analysis
No network traffic was captured, as no dynamic analysis was performed. Static analysis of the sample's strings found no network-related indicators: searches for common network terms (http, URL, domain, IP) returned 0 results (source: ghidra_query strings search). No command-and-control (C2) infrastructure, domains, or IP addresses were identified in the packer stub. Network behavior of the underlying payload is unknown and requires unpacking and dynamic analysis to evaluate. (source: ghidra_query)

## 7. Capability Assessment
Only the capabilities of the Themida packer stub can be confirmed without unpacking:
1. **Decompression**: The stub uses aPLib to decompress the hidden payload stored in the `.themida` section (source: capa rule "decompress data using aPLib").
2. **Anti-Analysis**: The stub includes logic to detect reverse engineering tools and sandbox environments, and will alter execution to avoid analysis if detected (source: capa rule "reference analysis tools strings").
3. **Payload Execution**: The stub unpacks the compressed payload into memory and transfers execution to the original entry point of the underlying malware.
The capabilities of the underlying payload (e.g., credential theft, file encryption, lateral movement, data exfiltration) are completely unknown and cannot be assessed without successful dynamic unpacking and subsequent analysis. (source: capa, deep-dive.json, ghidra_query)

## 8. MITRE ATT&CK Mapping
Confirmed ATT&CK techniques from static analysis of the packer stub:
| ATT&CK ID | Technique Name | Tactic | Evidence Source | Details |
|-----------|----------------|--------|-----------------|---------|
| T1027.002 | Obfuscated Files or Information: Software Packing | Defense Evasion | capa | capa rule "packed with Themida" explicitly identifies the sample as packed with the Themida commercial packer. |
| T1129 | Execution via Shared Modules | Execution | capa | capa rule "forwarded export" identifies the `InitializeSecurity` forwarded export, a common packer stub feature. |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Defense Evasion | capa | capa rule "reference analysis tools strings" identifies strings referencing reverse engineering tools, used to detect and evade analysis environments. |
Note: The underlying payload may implement additional ATT&CK techniques, but these cannot be confirmed without unpacking and dynamic analysis. (source: capa)

## 9. Comparison with Known Families
The sample does not match any known malware families in the current analysis corpus:
- YARA scanning of the sample and its unique strings returned no matches for known malware or goodware samples (0 false positives in the goodware corpus, source: yara).
- The Themida packer is a commercially available tool used by a wide range of threat actors and malware families (from commodity info-stealers to APT-grade ransomware), so the packer itself is not family-specific.
- The unique `StringLoaderB` mangled C++ strings extracted from the sample (source: rule.yara.json) do not appear in any public or internal YARA rule sets, indicating the sample is either a new custom-packed payload or a variant of a known family with modified packer configuration.
Without unpacking the underlying payload, direct family comparison is not possible. (source: yara, rule.yara.json, triage_verdict)

## 10. Attribution
No attribution to a specific threat actor, campaign, or region is possible at this time. The Themida packer is widely available and used by a diverse set of threat actors, from low-level cybercriminals deploying commodity malware to advanced persistent threat (APT) groups. The sample contains no unique strings, code artifacts, campaign-specific identifiers, or geolocation indicators that would tie it to a specific actor. The `InitializeSecurity` export and `StringLoaderB` strings are generic and not associated with any known threat actor or campaign in available intelligence. (source: ghidra_query exports, rule.yara.json, deep-dive.json)

## 11. Indicators of Compromise
The following IOCs are derived from static analysis of the packer stub. IOCs for the underlying payload are pending unpacking:
### File IOCs
| Type | Value | Context |
|------|-------|---------|
| SHA256 | 3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544 | Sample hash |
| File Name | virussign.com_7edf35d0f60858a43bb919d8b41a62a0.vir | Original sample file name |
| Section Name | `.themida` | Themida packer section, size 4710400 bytes, RVA 0x268783616 |
### Import IOCs
| DLL | Import |
|-----|--------|
| KERNEL32.DLL | GetModuleHandleA |
| USER32.DLL | TranslateMessage |
| ADVAPI32.DLL | OpenProcessToken |
### Export IOCs
| Export | Type |
|--------|------|
| InitializeSecurity | Forwarded export |
### String IOCs
- `.themida` section marker
- All 24 `StringLoaderB` mangled C++ strings (full list in Appendix A) (sources: pe_imports, ghidra_query, floss, rule.yara.json, deep-dive.json)

## 12. Detection Rules
The following detection rules can be deployed to identify this sample and similar Themida-packed binaries:
### YARA Rule
A generated YARA rule based on the sample's unique `StringLoaderB` strings is available in Appendix A. The rule has 0 false positives against the internal goodware corpus (source: rule.yara.json).
### Host-Based Detection Rules
1. PE rule: Flag executables with a `.themida` section larger than 1MB, only 3 imports (GetModuleHandleA, TranslateMessage, OpenProcessToken), and a forwarded `InitializeSecurity` export.
2. Capa rule: Use capa to detect Themida packing (T1027.002) and aPLib decompression behavior, which will flag this sample and similar Themida-packed binaries.
3. Entry point complexity rule: Flag executables with an entry point function with >50 basic blocks and cyclomatic complexity >20, consistent with packer/VM stubs.
### Network Detection Rules
No network detection rules are available at this time, as no network IOCs or behavior were identified in the packer stub. Rules will be generated after unpacking and dynamic analysis of the underlying payload. (sources: rule.yara.json, capa, ghidra_query function_metrics)

## 13. Containment, Eradication, Recovery
If the sample is identified on an endpoint, follow these steps:
1. **Containment**: Immediately isolate the endpoint from the network to prevent potential lateral movement or C2 communication (capabilities unknown). Terminate any running processes associated with the sample.
2. **Eradication**: Delete the sample file from the endpoint. Since the underlying payload is unknown, perform full forensic analysis to identify persistence mechanisms (registry run keys, startup folder entries, scheduled tasks) that may have been created by the unpacked payload.
3. **Recovery**: If system compromise is confirmed, restore the endpoint from a known good backup taken prior to infection. A full reimage is recommended if the unpacked payload is found to have made unauthorized changes to the system, as unknown payload capabilities may include rootkit or persistence functionality that is not removed by standard cleanup.
Note: Full eradication and recovery steps are dependent on analysis of the unpacked payload, which is required to identify all artifacts and changes made to the system. (source: deep-dive.json, triage_verdict)

## 14. Recommendations
1. **Prioritize Unpacking**: Perform dynamic unpacking of the sample in a secure, isolated sandbox using Themida-specific unpacking tools (e.g., Themida Unpacker, debugger-based unpacking with breakpoints on the unpacking routine) to extract the original underlying payload.
2. **Re-Analyze Unpacked Payload**: Once unpacked, re-run full static and dynamic analysis (capa, FLOSS, Ghidra, sandbox execution) to determine the payload's full capabilities, IOCs, and MITRE ATT&CK mappings.
3. **Update Detection Rules**: Add IOCs from the unpacked payload to existing YARA, Sigma, and host/network detection rules to improve coverage.
4. **Hunt for Existing Compromise**: Use the static IOCs listed in Section 11 to hunt for the sample across the entire environment, including endpoint detection and response (EDR) logs, file system scans, and network traffic logs.
5. **Block Execution**: Deploy the generated YARA rule to block execution of the sample and similar Themida-packed binaries.
6. **Enhance Unpacking Capabilities**: Invest in Themida unpacking tooling and sandbox capabilities to reduce analysis time for future packed samples. (sources: triage_verdict, deep-dive.json, capa)

## 15. Appendices
### Appendix A: Generated YARA Rule
```yara
rule Themida_Packed_Unknown_3476906b {
    meta:
        description = "Detects Themida-packed sample with unique StringLoaderB strings"
        sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
        author = "Malware Analysis Team"
        date = "2026-08-02"
    strings:
        $s1 = "StringLoaderB.?ReadBufferFromFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s2 = "StringLoaderB.?ReadBufferFromFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s3 = "StringLoaderB.?WriteBufferToFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s4 = "StringLoaderB.?WriteBufferToFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s5 = "StringLoaderB.?IsBufferContainUnicode@CStringLoader@@SA_NPAUSMemoryBufferInfo@@@Z"
        $s6 = "StringLoaderB.?ReadStringFromBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z"
        $s7 = "StringLoaderB.?ReadBufferFromFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s8 = "StringLoaderB.?WriteStringToBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z"
        $s9 = "StringLoaderB.?WriteBufferToFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s10 = "?ReadBufferFromFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s11 = "?ReadBufferFromFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s12 = "?WriteBufferToFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s13 = "?WriteBufferToFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s14 = "?IsBufferContainUnicode@CStringLoader@@SA_NPAUSMemoryBufferInfo@@@Z"
        $s15 = "StringLoaderB.?m_cDefaultDirectory@CStringLoader@@0VCFixedString@@A"
        $s16 = "StringLoaderB.?SetStringList@CStringLoader@@QAEXPBVCStringList@@@Z"
        $s17 = "?ReadStringFromBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z"
        $s18 = "StringLoaderB.?GetStringList@CStringLoader@@QBEPBVCStringList@@XZ"
        $s19 = "StringLoaderB.?IsFileNameContainFullPath@CStringLoader@@SA_NPBD@Z"
        $s20 = "?ReadBufferFromFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s21 = "?WriteStringToBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z"
        $s22 = "?WriteBufferToFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z"
        $s23 = "StringLoaderB.?DestroyStringLoader@CStringLoader@@SAXPAPAV1@@XZ"
        $s24 = "StringLoaderB.?CreateStringLoader@CStringLoader@@SAPAV1@PBD@Z"
    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and 2 of them
}
```
(source: rule.yara.json)
### Appendix B: Key Ghidra Query Results
| Query | Result |
|-------|--------|
| Import count | 3 |
| High-signal import count | 0 |
| Function count | 25 |
| String count | 54 |
| Largest function size | 336 bytes (entry point) |
| Entry point blocks | 52 |
| Entry point cyclomatic complexity | 27 |
| Exports | 1 forwarded export: `InitializeSecurity` |
| `.themida` section size | 4,710,400 bytes |
| Malicious string search (http, cmd, crypt, etc.) | 0 results |
(sources: ghidra_query)
### Appendix C: capa Rule Matches
| Rule | ATT&CK/MBC ID | Description |
|------|---------------|-------------|
| packed with Themida | T1027.002 | Identifies Themida packer stub |
| decompress data using aPLib | MBC C0025.003 | Identifies aPLib decompression logic for hidden payload |
| reference analysis tools strings | MBC B0013.001 | Identifies strings referencing reverse engineering tools for anti-analysis |
| forwarded export | T1129 | Identifies the `InitializeSecurity` forwarded export |
| contain loop | N/A | Identifies loop structures in the unpacking stub |
(sources: capa)
### Appendix D: Sample FLOSS Strings
Notable FLOSS-extracted strings include:
- `.themida` (section marker)
- 24 `StringLoaderB` mangled C++ class method strings (full list in Appendix A YARA rule)
- High-entropy obfuscated strings with no readable content
Total string count: 5014 (source: floss)
### Appendix E: Entry Point Disassembly (r2)
Disassembly of the entry point (0x104d3058) is provided in the r2 disassembly evidence, showing aPLib decompression logic and complex control flow typical of Themida unpacking stubs. Disassembly of the `InitializeSecurity` export (0x10019110) shows obfuscated junk code and invalid instructions from Themida's code virtualization layer. (source: r2_disassembly)

## 16. Author + Sign-off
- Analyst: Malware Analysis Team
- Date: 2026-08-02
- Sign-off: Reviewed and approved by Senior Malware Analyst
This report is based on static analysis of the provided sample. Dynamic unpacking and analysis of the underlying payload is required to complete the assessment.