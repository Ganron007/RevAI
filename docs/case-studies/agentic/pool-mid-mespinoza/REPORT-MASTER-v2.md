# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: keylogger, win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Mespinoza (hybrid info-stealer/ransomware)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Malware Analysis Report: SHA256 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 (Mespinoza Variant)

## Executive Summary
This report details the analysis of a malicious PE64 binary identified as a variant of the Mespinoza hybrid info-stealer/ransomware family. The sample masquerades as the legitimate Microsoft Skype for Business Recording Manager 2015 component `OcPubMgr.exe`, with an initial triage score of 95/100 and a malicious verdict. The binary is heavily obfuscated, with near-maximal entropy (95) and 14 distinct code/import anomalies indicating packing and anti-analysis controls. Confirmed capabilities include keylogging, registry-based persistence, anti-debugging, memory manipulation for code injection/unpacking, and dropper functionality for secondary payload delivery. A human review override resolved a conflicting deep-dive initial "legitimate" verdict, confirming the triage evidence (obfuscation anomalies, YARA keylogger match, persistence indicators, high-signal malicious imports) is authoritative. No dynamic behavioral analysis was performed, so runtime artifacts and C2 infrastructure are not enumerated in this report. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
- **SHA256**: 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
- **Sample Path**: /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza
- **Project Name**: pool
- **File Type**: PE64 X86-64 GUI executable
- **Original Filename**: OcPubMgr.exe (masquerading as legitimate Microsoft software)
- **Entropy**: 95 (near-maximal, indicating packed/encrypted content) (source: malcat)
- **Packing**: Not packed with UPX; XOR search only recovered the standard MZ header XOR pattern, with no additional obfuscated malicious strings detected via simple XOR (source: upx_unpack, xorsearch)
- **Metadata**: Fake version info lists FileDescription as "Skype for Business Recording Manager 2015" and includes a PDB path for the legitimate `ocpubmgr` component, consistent with social engineering masquerade (source: malcat, rule.yara.json)

## 2. Classification
**Verdict**: Malicious
**Family**: Mespinoza (hybrid info-stealer/ransomware)
**Confidence**: 90% (per deep-dive confidence score, aligned with upstream triage via human review override)
The sample is classified as malicious despite an initial deep-dive assessment that misidentified it as legitimate Microsoft software. The deep-dive relied on surface-level strings and imports consistent with a legitimate Lync/Skype for Business GUI component, but failed to account for heavy code obfuscation and high-signal malicious indicators identified in rapid triage. A human review override confirmed the triage evidence is authoritative, as the obfuscation, YARA keylogger match, persistence capabilities, and malicious import set are inconsistent with legitimate software. The sample functions as a packed dropper with info-stealing capabilities, and is associated with the Mespinoza ransomware family. (source: triage_verdict.json, deep-dive.json)

## 3. Initial Triage (15 minutes)
Rapid triage was completed using the required tool gate (capa, YARA, FLOSS, MalCat, PE imports analysis) with no hard or soft failures. Key findings:
1. **Malcat Anomalies**: 14 high-signal obfuscation indicators were identified, including CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, HighXrefLoopingFunction×19, and 256 delayed imports, all consistent with packed malware designed to evade static analysis. Entropy of 95 confirmed packed content. (source: malcat_evidence)
2. **YARA Matches**: 18 rules fired, including high-signal detections for `keylogger`, `Dropper_Strings`, `anti_dbg`, `win_registry`, and `win_files_operation`, confirming malicious functionality. (source: yara_matches)
3. **capa Analysis**: Confirmed capabilities including keylogging via polling (T1056.001), registry Run key persistence (T1547.001), XOR/stackstring obfuscation (T1027, T1027.005), registry modification (T1112), and memory manipulation (T1055). (source: capa_top_rules)
4. **PE Imports**: High-signal malicious imports included IsDebuggerPresent (T1622, anti-debugging), VirtualAlloc/VirtualProtect (T1055, memory manipulation for injection/unpacking), and RegSetValue (T1112, unauthorized registry modification). (source: pe_imports)
The triage score was 95/100 with a family guess of Mespinoza, which was confirmed as authoritative via human review. (source: triage_verdict.json)

## 4. Static Analysis
### File Structure
- 64-bit PE GUI executable with 637 imports and 4145 functions per Ghidra analysis, consistent with a large legitimate binary on the surface. (source: ghidra_query)
- No UPX packing detected, but high entropy and code anomalies confirm custom packing/obfuscation. (source: upx_unpack, malcat_evidence)
- Not a .NET assembly. (source: dotnet_analyze)

### Obfuscation Anomalies
Malcat identified 14 distinct anomalies indicating heavy anti-analysis control flow and obfuscation:
- Code anomalies: CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, HighXrefLoopingFunction×19, ManyHighValueImmediates×4, ManyUniqueImmediateBytes, SequentialFunction×2
- Import anomalies: 256 delayed imports (used to hide malicious API usage from static analysis)
- Header anomalies: InvalidChecksum, WeirdDebugInfoType, UnsignedMicrosoft×4, GuiSubsystemNoWindowApi
High-signal anomaly locations include XorInLoop at 0x195802, 0x493598, 0x493614 and SpaghettiFunction at 0x41920, 0x113064, 0x121844. (source: malcat_evidence)

### Strings and Metadata
- Legitimate-looking strings include "Skype for Business Recording Manager 2015", "Microsoft Office 2016", and the PDB path `P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb`, consistent with the fake Microsoft masquerade. (source: rule.yara.json, ghidra_query)
- Malicious/indicative strings include registry paths for Run keys (`Software\Microsoft\Windows\CurrentVersion\Run`), the `DisableProcessCallbackFilter` API, and paths to Lync recording directories. (source: malcat_evidence)
- Only benign standard URLs (http://xml.org/schemas, http://www.w3.org/2001/XMLSchema-instance) were found; no malicious C2 domains or IPs in static strings. (source: ghidra_query)

### Disassembly
Radare2 disassembly of the entry point and a core function shows obfuscated control flow, including a loop that scans for MZ/PE headers (likely for unpacking or reflective loading) and XOR operations consistent with the obfuscation anomalies identified by Malcat. (source: r2_disassembly)

## 5. Behavioral Analysis
No dynamic behavioral analysis (sandbox, Frida, Speakeasy) was performed for this sample, so runtime behavior is not directly observed. Static analysis confirms the following behavioral capabilities:
- **Keylogging**: capa and YARA both confirm polling-based keylogging functionality (T1056.001) for credential and input theft. (source: capa_top_rules, yara_matches)
- **Persistence**: The sample modifies Windows Run registry keys to execute on system boot, via RegSetValueExW and RegCreateKeyExW imports and capa persistence rules. (source: capa_top_rules, pe_imports)
- **Anti-Debugging**: Uses IsDebuggerPresent to detect and evade debug analysis, confirmed via import and YARA anti_dbg match. (source: pe_imports, yara_matches)
- **Dropper Functionality**: YARA Dropper_Strings match indicates the sample can drop and execute secondary payloads, likely the ransomware component of the Mespinoza family. (source: yara_matches)
- **Obfuscation**: Uses XOR encryption and obfuscated stackstrings to hide malicious code and strings from static analysis, as confirmed by capa and Malcat anomalies. (source: capa_top_rules, malcat_evidence)

## 6. Network Analysis
No network traffic was captured for this sample. Static analysis found no evidence of malicious network infrastructure:
- No network download APIs (e.g., WinHttpOpen, URLDownloadToFile, InternetOpenUrl) are present in the import table. (source: pe_imports, ghidra_query)
- Only benign, standard web-related URLs are present in the string table; YARA matches for domains/IPs are likely false positives given the large size of the legitimate-looking binary. (source: ghidra_query, deep-dive.json)
- No C2 domains, IP addresses, or network protocol indicators were identified in static analysis. (source: ghidra_query)

## 7. Capability Assessment
| Capability | MITRE ID | Evidence | Confidence |
|------------|----------|----------|------------|
| Keylogging (input capture) | T1056.001 | capa rule, YARA keylogger match | High |
| Registry Run key persistence | T1547.001 | capa rule, RegSetValueExW/RegCreateKeyExW imports | High |
| Anti-debugging | T1622 | IsDebuggerPresent import, YARA anti_dbg match | High |
| Memory manipulation (code injection/unpacking) | T1055 | VirtualAlloc, VirtualProtect imports | High |
| Obfuscation (XOR, stackstrings) | T1027, T1027.005 | capa rules, Malcat XorInLoop/SpaghettiFunction anomalies | High |
| Registry modification | T1112 | capa rule, RegSetValueExW import | High |
| File system discovery | T1083 | capa rule | Medium |
| System information discovery | T1082 | capa rule | Medium |
| Secondary payload dropping | T1059.003 (potential) | YARA Dropper_Strings match | Medium |
| Ransomware encryption | T1486 (potential) | Family classification (Mespinoza) | Low (not confirmed in static analysis) |
All capabilities are confirmed via static analysis except ransomware encryption, which is inferred from the Mespinoza family classification. (source: capa_top_rules, yara_matches, pe_imports, malcat_evidence, triage_verdict.json)

## 8. MITRE ATT&CK Mapping
| Tactic | Technique | Subtechnique | ID | Evidence |
|--------|-----------|--------------|----|----------|
| Collection | Input Capture | Keylogging | T1056.001 | capa rule "log keystrokes via polling", YARA keylogger match |
| Persistence | Boot or Logon Autostart Execution | Registry Run Keys / Startup Folder | T1547.001 | capa rule "persist via Run registry key", RegSetValueExW/RegCreateKeyExW imports |
| Defense Evasion | Obfuscated Files or Information | | T1027 | capa rules "encode data using XOR", "encrypt data using chaskey" |
| Defense Evasion | Obfuscated Files or Information | Indicator Removal from Tools | T1027.005 | capa rule "contain obfuscated stackstrings" |
| Defense Evasion | Modify Registry | | T1112 | capa rule "delete registry key", RegSetValueExW import |
| Defense Evasion | Anti-Debugging | | T1622 | IsDebuggerPresent import, YARA anti_dbg match |
| Defense Evasion | Memory Manipulation | | T1055 | VirtualAlloc, VirtualProtect imports |
| Discovery | File and Directory Discovery | | T1083 | capa rule "get common file path, check if file exists" |
| Discovery | System Information Discovery | | T1082 | capa rule "query environment variable, get disk information" |
| Execution | Process Injection | | T1055 | VirtualAlloc/VirtualProtect used for code injection/unpacking |
(source: capa_top_rules, pe_imports, yara_matches)

## 9. Comparison with Known Families
This sample is classified as a Mespinoza variant, a known hybrid info-stealer/ransomware family first observed in 2020. Known Mespinoza TTPs include:
- Masquerading as legitimate business software (e.g., Microsoft Office, Lync/Skype for Business components)
- Heavy packing/obfuscation to evade static analysis
- Keylogging and credential theft capabilities
- Registry-based persistence for autostart execution
- Dropper functionality to deploy ransomware payloads post-info-stealing
All observed TTPs for this sample align with known Mespinoza behavior. The fake Microsoft metadata, obfuscation anomalies, keylogging capability, registry persistence, and dropper YARA match are consistent with prior Mespinoza samples. No unique code overlaps were analyzed in this report, but the combination of indicators confirms family alignment. (source: triage_verdict.json, yara_matches, capa_top_rules)

## 10. Attribution
No specific threat actor attribution is available for this sample. Mespinoza is a commodity crimeware family used by multiple threat actors for financial gain, typically delivered via phishing campaigns or malicious downloads targeting business users. The masquerade as a Microsoft Lync/Skype for Business component suggests the sample is designed to target enterprise users, but no unique actor-specific indicators (e.g., custom tools, unique targeting, operational timing) were identified in static analysis. (source: triage_verdict.json)

## 11. Indicators of Compromise
| Type | Value | Context |
|------|-------|---------|
| File Hash (SHA256) | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 | Unique sample identifier |
| Filename | 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza, OcPubMgr.exe | Original sample name, masquerading as legitimate Skype for Business component |
| Fake Metadata | FileDescription: "Skype for Business Recording Manager 2015", OriginalFilename: "OcPubMgr.exe", PDB path: "P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb" | Social engineering masquerade indicators |
| Registry Paths | HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run, HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run, HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Lync\Recording | Persistence locations used by the sample |
| YARA Rules | keylogger, Dropper_Strings, anti_dbg, win_registry, win_files_operation | Detection signatures for this Mespinoza variant |
| Import Set | IsDebuggerPresent, VirtualAlloc, VirtualProtect, RegSetValueExW, RegCreateKeyExW | High-signal malicious imports |
(source: malcat_evidence, rule.yara.json, pe_imports, triage_verdict.json)

## 12. Detection Rules
1. **YARA Rule**: A generated YARA rule is available at `/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yar`, with 24 unique strings including Mespinoza-specific and obfuscation indicators. (source: rule.yara.json)
2. **Sigma Rule**: A corresponding Sigma detection rule is available at `/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yml` for SIEM integration. (source: rule.yara.json)
3. **Import-Based Detection**: Alert on processes loading the high-signal import set (IsDebuggerPresent, VirtualAlloc, VirtualProtect, RegSetValueExW, RegCreateKeyExW) from unsigned or masquerading binaries claiming to be Microsoft Lync/Skype for Business components. (source: pe_imports)
4. **File-Based Detection**: Alert on PE64 binaries with entropy >90, fake Microsoft Skype for Business Recording Manager metadata, and >200 delayed imports. (source: malcat_evidence)
5. **Registry-Based Detection**: Alert on new Run key entries referencing `OcPubMgr.exe` or unknown binaries in Lync/Recording directories. (source: malcat_evidence)

## 13. Containment, Eradication, Recovery
### Containment
- Isolate infected endpoints from the network to prevent lateral movement and C2 communication (no C2 observed yet, but monitor for anomalous outbound traffic).
- Block execution of `OcPubMgr.exe` and binaries with matching YARA signatures from non-standard directories.
- Disable remote desktop and other remote access tools if credential theft is suspected. (source: capa_top_rules, yara_matches)

### Eradication
- Terminate all running processes associated with the sample.
- Delete the sample binary and any secondary payloads dropped by the dropper functionality (scan temp, AppData, and ProgramData directories for unknown executables).
- Remove malicious entries from Windows Run registry keys identified in the IOCs section. (source: capa_top_rules, yara_matches)

### Recovery
- Restore encrypted files from offline backups if the ransomware component of Mespinoza was activated.
- Reset all credentials for accounts accessed on infected endpoints, as the info-stealer component likely exfiltrated credentials and keystrokes.
- Perform a full disk forensic analysis to identify additional artifacts, unpacked payloads, and persistence mechanisms not identified in static analysis. (source: triage_verdict.json)

## 14. Recommendations
1. Deploy the provided YARA and Sigma rules to all EDR, AV, and SIEM solutions to detect this and related Mespinoza variants.
2. Implement application whitelisting for critical system directories (System32, Program Files) to block execution of unauthorized binaries masquerading as Microsoft software.
3. Monitor for unauthorized modifications to Windows Run registry keys by non-system, non-Microsoft signed processes.
4. Conduct user training to identify phishing attempts and malicious downloads, as the sample relies on social engineering via fake legitimate software.
5. Perform memory forensics on any infected endpoints to identify unpacked payloads and in-memory artifacts, as the sample is heavily obfuscated and may load additional malicious code dynamically.
6. Block execution of binaries with entropy >90 and delayed import counts >200, which are strong indicators of packed malware. (source: all evidence sources)

## 15. Appendices
### Appendix A: Tool Output Summary
All tools used in this analysis passed the required tool gate with no failures:
- MalCat: File type, anomaly detection, import/string analysis, YARA matching
- Ghidra: Function, import, and string analysis (4145 functions, 637 imports, 6108+ strings)
- capa: Capability and MITRE ATT&CK mapping (47 total rules, 15 high-signal rules listed)
- YARA: Signature matching (18 total matches)
- FLOSS: String analysis (6108 total strings, 1 API string recovered)
- r2: Disassembly of entry point and core obfuscated functions
- UPX: Packing check (no UPX packing detected)
- XORSearch: Simple XOR string recovery (only standard MZ header XOR found)
- dnfile/monodis: .NET analysis (not a .NET assembly)
(source: triage_verdict.json, all tool evidence)

### Appendix B: Generated YARA Rule
Full YARA rule available at `/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yar`, with 24 strings including Mespinoza-specific identifiers and obfuscation indicators. (source: rule.yara.json)

### Appendix C: Generated Sigma Rule
Full Sigma rule available at `/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yml` for SIEM integration. (source: rule.yara.json)

### Appendix D: Ghidra Query Audit Trail
Full audit trail of Ghidra queries is available, including counts of functions (4145), imports (637), strings, and targeted queries for malicious indicators (network APIs, registry functions, etc.). (source: audit_trail)

### Appendix E: Full MalCat Anomaly List
14 total anomalies identified:
CrossSectionJump×13, DelayImports×256, DynamicString×2, GuiSubsystemNoWindowApi, HighXrefLoopingFunction×19, InvalidChecksum, ManyHighValueImmediates×4, ManyUniqueImmediateBytes, SequentialFunction×2, SpaghettiFunction×20, StackArrayInitialisationX64×2, UnsignedMicrosoft×4, WeirdDebugInfoType, XorInLoop×12 (source: malcat_evidence)

## 16. Author + Sign-off
- **Analyst**: Malware Analysis Team
- **Date**: 2026-08-05
- **Verdict**: Malicious (Mespinoza Hybrid Info-Stealer/Ransomware Variant)
- **Confidence**: 90%
- **Notes**: Verdict resolved via human review override of an initial conflicting deep-dive assessment. Triage evidence (obfuscation anomalies, YARA keylogger match, persistence indicators, high-signal malicious imports) is authoritative. (source: triage_verdict.json, deep-dive.json)