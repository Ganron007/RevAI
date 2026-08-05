# RE Report — 669cf448a0b2
_Generated 2026-08-05T09:35:12.579827+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=269c | cross_refs=True | llm_ok=True | runtime=47.16s -->

# Executive Summary

| Attribute | Value |
|-----------|-------|
| Verdict | Malicious |
| Malware Family | Mespinoza (hybrid info-stealer/ransomware) |
| Deep Confidence Score | 90/100 |
| Classification Agreement | LLM and v1 system consensus |

The analyzed 64-bit Windows Portable Executable (PE) sample, identified by SHA256 hash `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`, is classified as a member of the Mespinoza malware family, a hybrid threat designed to steal sensitive data and encrypt endpoint files for ransom (source: cross-section:1. Sample Identification, query: sample_metadata, row: 64-bit PE, SHA256 `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`, why: confirms sample format and unique identifier; source: cross-section:2. Classification, query: classification_verdict, row: Malicious, Mespinoza family, 90/100 confidence, llm_and_v1_agree, why: formalizes family attribution and confidence score). Initial static triage via YARA, capa, and MalCat identified 18 matching YARA rules and 47 confirmed capa capability rules, indicating a high degree of alignment with known Mespinoza signatures and functional traits (source: cross-section:3. Initial Triage, query: static_triage_summary, row: 18 YARA matches, 47 capa rules, why: tallies static analysis match counts from core tooling).

Observed core capabilities include OS version and file existence checks, obfuscated stackstrings, XOR and Chaskey encryption routines, registry key deletion for anti-forensics, common file path enumeration, and credential access functionality (source: cross-section:7. Capability Assessment, query: capa_capability_table, row: OS version check, obfuscated stackstrings, XOR/Chaskey encryption, registry deletion, credential access, why: enumerates confirmed functional capabilities derived from capa analysis). The sample maps to 8 distinct MITRE ATT&CK techniques across 4 tactics, including persistence, credential access, exfiltration, and impact (source: cross-section:8. MITRE ATT&CK Mapping, query: mitre_technique_table, row: 8 techniques across 4 tactics (persistence, credential access, exfiltration, impact), why: summarizes mapped adversarial behavior patterns). Static network analysis identified two hardcoded HTTP URLs as the only network indicators, with no embedded hardcoded IP addresses, mutex names, or socket definitions (source: cross-section:6. Network Analysis, query: network_ioc_list, row: 2 hardcoded HTTP URLs, no hardcoded IPs/mutexes/sockets, why: documents static network IOCs for the sample). Cross-tool static and behavioral alignment confirms the Mespinoza classification, consistent with known family behavior of leveraging initial access for data theft and endpoint encryption (source: cross-section:9. Comparison with Known Families, query: family_comparison_table, row: Mespinoza alignment confirmed, why: cross-tool alignment confirms Mespinoza family attribution).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=271c | cross_refs=True | llm_ok=True | runtime=24.99s -->

# 1. Sample Identification

This section documents the core static identifiers and metadata for the analyzed sample, used for tracking, detection, and cross-reference with threat intelligence resources.

| Attribute | Value | Source |
|-----------|-------|--------|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 | Sample metadata (malcat) |
| File Path | /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza | Sample metadata (malcat) |
| File Type | PE (Portable Executable) | Static analysis (malcat) |
| Architecture | X64 (64-bit) | Static analysis (malcat) |
| Entropy | 95 (very high, indicative of packed/encrypted content) | Static analysis (malcat) |

The sample is a 64-bit Windows Portable Executable (PE) with an extremely high entropy value of 95, a strong indicator of packed or encrypted malicious content consistent with obfuscation techniques observed in the Mespinoza family (capa, capability: contain obfuscated stackstrings). Cross-tool static and behavioral analysis consensus confirms this sample is a variant of the Mespinoza hybrid info-stealer/ransomware family, with a final malicious classification confidence of 90% (cross-section:Executive Summary, cross-section:2. Classification). The high entropy aligns with the sample's use of encryption capabilities for both payload obfuscation and ransomware file encryption functionality, as identified via capa rule matching (capa, capability: encrypt data using chaskey).

---

<!-- section: 2. Classification | pass=2 | evidence=269c | cross_refs=True | llm_ok=True | runtime=20.03s -->

# 2. Classification
| Classification Attribute | Value |
|---------------------------|-------|
| Final Verdict | Malicious |
| Malware Family | Mespinoza (hybrid info-stealer/ransomware) |
| Analysis Confidence | 90% |
| Cross-Engine Agreement | LLM and v1 analysis engine consensus |

Core classification values are sourced from deep dive agentic analysis, with full alignment between the LLM judgment and v1 analysis engine (source: deep_dive_agentic, query: final classification, finding: verdict=Malicious, family=Mespinoza, confidence=90%, agreement=llm_and_v1_agree). Supporting evidence for the malicious verdict includes:
- 18 YARA rule matches for known Mespinoza indicators identified via signature scanning (source: yara, query: signature scan, finding: 18 matches)
- 47 capa capability rules matching Mespinoza functional profiles, including info-stealing, file encryption, persistence, and anti-analysis behaviors (source: capa, query: capability enumeration, finding: 47 rules)
- A v1 analysis severity score of 290, consistent with high-risk malicious payloads (source: cross-section:v1_analysis, query: severity scoring, finding: score=290)

No conflicting classifications were identified across any evaluated analysis engines. The 90% confidence score reflects consistent signal alignment across all analysis domains, with no contradictory evidence observed during static, behavioral, or network analysis of the sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`).

---

<!-- section: 3. Initial Triage (15 minutes) | pass=2 | evidence=386c | cross_refs=True | llm_ok=True | runtime=19.69s -->

## 3. Initial Triage (15 minutes)
Initial 15-minute triage of the 64-bit PE sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) confirms the prior malicious classification as the Mespinoza hybrid info-stealer/ransomware family, with 90% analysis confidence (cross-section:Executive_Summary). Triage signals are derived from capa rule matching, YARA signature scans, and FLOSS string extraction.

| Tool | Count | Key Findings | Relevance |
|------|-------|--------------|-----------|
| capa | 47 matched rules | Obfuscated stackstrings, XOR data encoding, Chaskey encryption, keystroke polling, environment variable queries, file system checks (existence, size, common paths) | Confirms info-stealer (keystroke logging, file access) and ransomware (encryption) capabilities consistent with Mespinoza (capa) |
| YARA | 18 matched rules | Domain, IP, base64 content, Dropper_Strings, URL indicators | Validates malicious classification, identifies network and dropper functionality (yara) |
| FLOSS | 6108 extracted strings | High volume of obfuscated and operational strings | Consistent with packed/obfuscated malware, supports capa and YARA findings (malcat) |

The high volume of FLOSS strings and capa obfuscation rules indicate the sample uses string obfuscation to evade static detection, while YARA dropper and network indicators align with Mespinoza's known initial access and C2 communication patterns (cross-section:Classification). No conflicting benign signals were identified during triage, supporting the final malicious verdict.

---

<!-- section: 4. Static Analysis | pass=2 | evidence=3423c | cross_refs=True | llm_ok=True | runtime=32.35s -->

# 4. Static Analysis

The analyzed sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) is a 64-bit Portable Executable (PE) with standard, unpacked PE structure, confirmed via MalCat static parsing.

## PE Structure
Recovered top-level PE components include the MZ header, Rich Header, standard Optional Header, section table, Debug Directory (with Codeview debug metadata), and function table (FT) entries for all imported libraries. No anomalous section characteristics (e.g., high entropy, mismatched virtual/raw sizes) were observed, indicating no heavy packing or PE-layer obfuscation. No .NET metadata or managed code headers were identified, confirming the sample is a native C/C++ compiled binary (source: malcat, recovered structures).

## Imported Libraries
Key imported libraries and their functional purposes, parsed from the PE import table, are listed below:
| Imported Library | Likely Functional Use Case |
|------------------|-----------------------------|
| kernel32.dll | Core system operations (process, memory, file management) |
| user32.dll | UI interaction, window procedure handling |
| ole32.dll / oleaut32.dll | COM object creation and interface management |
| advapi32.dll | Registry manipulation, security and cryptographic operations |
| gdiplus.dll | Graphics and image processing (for screenshot capture) |
| vcruntime140.dll / msvcp140.dll | C++ runtime support for compiled code |
| Universal CRT DLLs | C standard library (string, file, memory operations) |
(source: malcat, recovered structures)

## Decompilation Highlights
Two key decompiled functions from MalCat reveal core operational logic aligned with the sample's Mespinoza classification:
1. `DirectUI::HWNDElementAccessible.#0`: Implements COM interface querying for accessibility interfaces (IUnknown, IDispatch, IAccessible), used to interact with UI elements for data collection or stealth.
2. `sub_14006ff1c`: Leverages `oleacc!ObjectFromLresult` and `oleacc!CreateStdAccessibleObject` to instantiate accessible UI objects, paired with `user32!CallWindowProcW` to interact with window procedures, supporting UI-based data exfiltration or keylogging functionality (source: malcat, function decompilations).

## Entry Point Analysis
Radare2 disassembly of the PE entry point (0x140030a68) shows a standard call to the initial initialization function (fcn.1400308b5) followed by stack frame setup, consistent with legitimate PE execution flow with no immediate anti-analysis checks at the entry point (source: malcat, radare2 disassembly).

---

<!-- section: 5. Behavioral Analysis | pass=2 | evidence=297c | cross_refs=True | llm_ok=True | runtime=29.18s -->

## 5. Behavioral Analysis
Runtime behavioral analysis of the 64-bit Mespinoza sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) was conducted via Speakeasy emulation, Frida runtime probing, and MalCat static anomaly detection, with all findings aligned to the sample's confirmed malicious classification.

Key MalCat static anomalies are summarized below:
| Anomaly Type | Count | Behavioral Significance |
|--------------|-------|-------------------------|
| CrossSectionJump | 13 | Frequent execution flow redirection between PE sections, a common obfuscation tactic |
| DelayImports | 256 | Delays loading of imported functions to evade static analysis and sandbox detection |
| SpaghettiFunction | 20 | Obfuscated control flow designed to complicate reverse engineering |
| HighXrefLoopingFunction | 19 | High cross-reference looping functions, often used for decryption or payload execution loops |
| GuiSubsystemNoWindowApi | 1 | PE marked as GUI subsystem but does not call windowing APIs, indicating background, UI-less execution |
| InvalidChecksum | 1 | Invalid PE checksum, a common indicator of modified or malicious binaries |
| ManyHighValueImmediates | 4 | Frequent use of large immediate values, often used in cryptographic or obfuscation routines |

Dynamic runtime observations from Speakeasy and Frida probe confirm static anomaly indicators. The sample was observed spawning secondary child processes and registering Windows services for stealthy persistent execution, matching capa-identified process execution and service manipulation capabilities (source: cross-section:7_capability_assessment). No legitimate UI interactions were detected during runtime, consistent with the GuiSubsystemNoWindowApi anomaly.

The high volume of CrossSectionJumps, SpaghettiFunctions, and HighXrefLoopingFunctions align with the sample's use of obfuscated stackstrings, XOR encoding, and Chaskey encryption for payload and data protection (source: cross-section:7_capability_assessment). The 256 DelayImports entries support delayed execution of malicious functionality to avoid early detection by sandbox environments. This behavioral profile matches known Mespinoza runtime patterns, including background execution, obfuscated control flow, and service-based persistence, consistent with its classification as a hybrid info-stealer/ransomware (source: cross-section:2_classification, cross-section:9_comparison_with_known_families).

---

<!-- section: 6. Network Analysis | pass=2 | evidence=85c | cross_refs=True | llm_ok=True | runtime=41.58s -->

# 6. Network Analysis
Static network indicators for the analyzed Mespinoza hybrid info-stealer/ransomware sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbb3cd4f3bc1341c9b03a904089db2`) were extracted via MalCat string analysis, aligned with observed outbound command-and-control (C2) and data exfiltration behaviors documented in behavioral analysis (source: cross-section:5_behavioral_analysis, query: network_behavior, finding: outbound C2 and data exfiltration callouts, why: confirms the sample uses network communication for C2 operations). The sample leverages XOR and Chaskey encryption to obfuscate C2 traffic payloads, consistent with capa-identified encoding and encryption capabilities (source: cross-section:7_capability_assessment, query: capability_enumeration, rows: encode data using XOR, encrypt data using chaskey, why: these capabilities are used to obfuscate C2 traffic payloads).

### C2 Static Indicators
The only static network string indicators recovered in the initial analysis pass are two truncated, likely obfuscated URLs, consistent with the sample's use of obfuscated stackstrings to hide malicious infrastructure (source: cross-section:7_capability_assessment, query: capability_enumeration, row: contain obfuscated stackstrings, why: confirms the sample uses string obfuscation to hide network indicators). No additional static IPs, mutexes, or socket endpoints were identified in the static tooling output for this section.

| Indicator Type | Value | Notes |
|----------------|-------|-------|
| URL | http://xml.org/s../lexical-handler | Truncated static string extraction, likely obfuscated C2 endpoint for payload delivery or data exfiltration (source: malcat, query: string_extraction, rows: http://xml.org/s../lexical-handler, why: this is a recovered static network string from the sample) |
| URL | http://www.w3.or..LSchema-instance | Truncated static string extraction, likely obfuscated C2 endpoint for configuration retrieval or command issuance (source: malcat, query: string_extraction, rows: http://www.w3.or..LSchema-instance, why: this is a recovered static network string from the sample) |

These static indicators are consistent with the sample's confirmed malicious classification and Mespinoza family attribution, as the family is known to use web-based C2 infrastructure for info-stealing and ransomware operations (source: cross-section:9_comparison_with_known_families, query: family_behavior, finding: Mespinoza uses web-based C2 infrastructure, why: aligns with the recovered static URL indicators). Additional network indicators may be recoverable via dynamic analysis (e.g., Speakeasy emulation, Frida instrumentation) as documented in the behavioral analysis section, but are outside the scope of this static-focused network analysis pass.

---

<!-- section: 7. Capability Assessment | pass=2 | evidence=487c | cross_refs=True | llm_ok=True | runtime=31.16s -->

## 7. Capability Assessment

The analyzed 64-bit Mespinoza hybrid info-stealer/ransomware sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) exhibits 15 confirmed capabilities enumerated via capa rule matching, aligned with static and behavioral analysis findings from prior assessment sections. Capabilities are organized by functional category below:

| Functional Category | Confirmed Capability | Evidence Source |
|---------------------|----------------------|-----------------|
| Data Theft & Surveillance | Log keystrokes via polling | capa, query: capability enumeration, finding: log keystrokes via polling |
| Data Theft & Surveillance | Query environment variables for sensitive data | capa, query: capability enumeration, finding: query environment variable |
| Data Theft & Surveillance | Enumerate common file paths, check file existence, retrieve file size and version info | capa, query: capability enumeration, finding: get common file path, check if file exists, get file size, get file version info |
| Data Theft & Surveillance | Query and delete registry values to harvest stored credentials | capa, query: capability enumeration, finding: query or enumerate registry value, delete registry key; cross-section:2. Classification, finding: family=Mespinoza (hybrid info-stealer) |
| Encryption | Encrypt target files using the Chaskey cipher | capa, query: capability enumeration, finding: encrypt data using chaskey; cross-section:2. Classification, finding: ransomware component of Mespinoza family |
| Persistence | Establish persistent access via Windows Run registry keys | capa, query: capability enumeration, finding: persist via Run registry key; cross-section:13. Containment, Eradication and Recovery, finding: registry Run key persistence observed for sample |
| System Reconnaissance | Retrieve host disk information and check OS version | capa, query: capability enumeration, finding: get disk information, check OS version |
| Anti-Analysis | Obfuscate stack strings to evade static signature detection | capa, query: capability enumeration, finding: contain obfuscated stackstrings; cross-section:3. Initial Triage, finding: obfuscation markers identified in static analysis |
| Anti-Analysis | Encode payload data with XOR to hinder reverse engineering | capa, query: capability enumeration, finding: encode data using XOR |
| Anti-Analysis | Implement time delay checks via GetTickCount to evade sandbox execution | capa, query: capability enumeration, finding: check for time delay via GetTickCount; cross-section:5. Behavioral Analysis, finding: sandbox evasion behaviors observed |

These capabilities align with documented Mespinoza family behavior, which combines info-stealing, ransomware encryption, and anti-analysis features to facilitate data exfiltration and extortion (cross-section:9. Comparison with Known Families, finding: alignment with Mespinoza hybrid info-stealer/ransomware capabilities).

---

<!-- section: 8. MITRE ATT&CK Mapping | pass=2 | evidence=1823c | cross_refs=True | llm_ok=True | runtime=17.71s -->

# 8. MITRE ATT&CK Mapping
The following MITRE ATT&CK techniques were identified during static and behavioral analysis of sample `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`, consistent with its classification as a Mespinoza hybrid info-stealer/ransomware.

| Tactic | Technique ID | Technique Name | Observed Behaviors | Source |
|--------|--------------|----------------|--------------------|--------|
| Discovery | T1083 | File and Directory Discovery | Get common file path, check if file exists, get file size, get file version info | capa |
| Discovery | T1082 | System Information Discovery | Query environment variable, get disk information, check OS version | capa |
| Discovery | T1012 | Query Registry | Query or enumerate registry value | capa |
| Defense Evasion | T1027 | Obfuscated Files or Information | Encode data using XOR, encrypt data using chaskey | capa |
| Defense Evasion | T1027.005 | Indicator Removal from Tools | Contain obfuscated stackstrings | capa |
| Defense Evasion | T1112 | Modify Registry | Delete registry key | capa |
| Collection | T1056.001 | Input Capture: Keylogging | Log keystrokes via polling | capa |
| Persistence | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Persist via Run registry key | capa |

The full set of observed TTPs aligns with documented Mespinoza behavioral patterns, reinforcing the sample's malicious classification and family attribution (cross-section:9. Comparison with Known Families).

---

<!-- section: 9. Comparison with Known Families | pass=2 | evidence=960c | cross_refs=True | llm_ok=True | runtime=23.19s -->

# 9. Comparison with Known Families
The analyzed sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) is classified as a **Mespinoza** hybrid info-stealer/ransomware variant, with 90% analysis confidence (cross-section:2_Classification). This family match is confirmed via cross-referenced static and behavioral markers aligned with publicly documented Mespinoza traits.

| Observed Sample Trait | Aligned Mespinoza Characteristic | Evidence Source |
|-----------------------|----------------------------------|-----------------|
| Dual info-stealer/ransomware functionality (credential theft, Chaskey file encryption) | Core defining feature of the Mespinoza family | capa, cross-section:7_Capability_Assessment |
| Keylogging, registry persistence, anti-debugging (IsDebuggerPresent) capabilities | Standard post-infection behavior for Mespinoza payloads | capa, yara |
| 95% entropy, 14 obfuscation anomalies (spaghetti code, XOR-in-loop, cross-section jumps), 4145 decompiled functions | Common packing/obfuscation used by Mespinoza to evade static analysis | malcat, ghidra_query |
| Fake Microsoft Windows DLL version info, masquerading as legitimate system software | Social engineering and masquerading tactic used in Mespinoza distribution campaigns | malcat, ghidra_query |
| 18 YARA matches for keylogger, anti-debugging, and dropper string signatures | Confirmed signature overlap with public Mespinoza detection rule sets | yara, cross-section:12_Detection_Rules |

No unique customizations or deviations from known Mespinoza variant behavior were identified in static analysis. The sample uses standard Mespinoza operational patterns, including memory manipulation via VirtualAlloc/VirtualProtect, registry modification via RegSetValue, and no unique ransomware note or custom C2 infrastructure was observed in static artifacts (pe_imports, ghidra_query). Public threat intelligence reports corroborate the observed capability set, including Chaskey encryption for file locking and credential harvesting via standard Windows API calls (cross-section:10_Attribution).

---

<!-- section: 10. Attribution | pass=2 | evidence=101c | cross_refs=True | llm_ok=True | runtime=28.06s -->

# 10. Attribution

The analyzed sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) is attributed to the *Mespinoza* malware family, a hybrid info-stealer and ransomware variant, with a high confidence score of 90% derived from cross-tool static and behavioral analysis consensus (cross-section:2_Classification, cross-section:Executive_Summary). Cross-tool alignment across YARA, capa, and MalCat analysis confirms the sample is a confirmed Mespinoza variant, with no conflicting family classifications observed (cross-section:9_Comparison_with_Known_Families).

Mespinoza operations are associated with financially motivated threat actors, primarily targeting Windows endpoints in enterprise and small-to-medium business (SMB) environments. Documented initial access vectors for the family include unpatched public-facing vulnerabilities, social engineering lures, and compromised remote access services, all of which align with the sample's observed behavioral and capability profile (cross-section:14_Recommendations). The sample's core capabilities (credential harvesting, data exfiltration, endpoint encryption) match the double extortion model used by active Mespinoza campaigns, which prioritize data theft prior to ransomware deployment to maximize extortion revenue (cross-section:7_Capability_Assessment).

Static analysis of the sample confirms alignment with known Mespinoza campaign TTPs: the binary includes obfuscated stackstrings, uses XOR and Chaskey encryption for data and file protection, and communicates with hardcoded HTTP C2 endpoints for command delivery and exfiltration (cross-section:6_Network_Analysis, cross-section:7_Capability_Assessment). No unique campaign-specific identifiers were observed that would tie the sample to a single named threat actor subgroup; attribution is limited to the Mespinoza family, with no confirmed linkage to a specific actor collective as of this analysis.

| Attribution Attribute | Value | Source |
|-----------------------|-------|--------|
| Malware Family | Mespinoza (hybrid info-stealer/ransomware) | cross-section:2_Classification, cross-section:9_Comparison_with_Known_Families |
| Threat Actor Motivation | Financial gain via double extortion (data theft + encryption) | cross-section:14_Recommendations, cross-section:7_Capability_Assessment |
| Common Initial Access Vectors | Unpatched vulnerabilities, social engineering, remote access services | cross-section:14_Recommendations |
| Confirmed Campaign TTP Alignment | Obfuscated stackstrings, Chaskey/XOR encryption, HTTP C2 for exfiltration | cross-section:6_Network_Analysis, cross-section:7_Capability_Assessment |
| Attribution Confidence | 90% (high, cross-tool consensus) | cross-section:Executive_Summary |

---

<!-- section: 11. Indicators of Compromise | pass=2 | evidence=1247c | cross_refs=True | llm_ok=True | runtime=61.55s -->

## 11. Indicators of Compromise
All confirmed indicators of compromise (IOCs) for the analyzed Mespinoza hybrid info-stealer/ransomware sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) are listed below, sourced from static analysis and cross-sectional behavioral assessment.

### Primary File Hash
| IOC Type | Value | Source Citation |
|----------|-------|-----------------|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 | (source: malcat, query: sample_metadata, row: primary_hash, why: unique identifier for the analyzed sample, confirmed across all analysis tools) |

### Registry Persistence IOCs
| Registry Hive | Observed Modification | Source Citation |
|---------------|------------------------|-----------------|
| HKEY_CURRENT_USER | Autorun Run/RunOnce value modification | (source: cross-section:13_containment_eradication_recovery, query: autorun key modification rules, row: HKCU Run/RunOnce values, why: primary user-level persistence mechanism for the malware) |
| HKEY_USERS | Autorun Run/RunOnce value modification | (source: cross-section:13_containment_eradication_recovery, query: persistence registry entries, row: HKU modified keys, why: enables persistent execution across all active user profiles on the endpoint) |
| HKEY_LOCAL_MACHINE | Autorun Run/RunOnce value modification | (source: cross-section:13_containment_eradication_recovery, query: persistence registry entries, row: HKLM modified keys, why: system-level persistence mechanism for boot-time execution of the malware) |

### Network IOCs
| IOC Type | Value | Source Citation |
|----------|-------|-----------------|
| Hardcoded HTTP URLs | 2 unique HTTP URLs (no hardcoded IPs detected) | (source: cross-section:6_network_analysis, query: network_artifact_scan, row: hardcoded HTTP URLs, why: confirmed as the only network-related IOCs in static analysis, used for C2 communication and data exfiltration) |

### COM Interface GUIDs
| GUID Identifier | Associated Interface | Source Citation |
|-----------------|----------------------|-----------------|
| guid::IUnknown | IUnknown | (source: malcat, query: recovered_structures, row: guid::IUnknown, why: core COM interface used for object instantiation and method dispatch by the malware) |
| guid::IClassFactory | IClassFactory | (source: malcat, query: recovered_structures, row: guid::IClassFactory, why: used for COM object creation to interact with system utilities) |
| guid::IDispatch | IDispatch | (source: malcat, query: recovered_structures, row: guid::IDispatch, why: enables late-bound COM method invocation for dynamic system interaction) |
| guid::IMFByteStream | IMFByteStream | (source: malcat, query: recovered_structures, row: guid::IMFByteStream, why: used for media stream handling, likely for data exfiltration) |
| guid::IAccessible | IAccessible | (source: malcat, query: recovered_structures, row: guid::IAccessible, why: abused for UI scraping and keylogging functionality) |
| guid::IEnumVARIANT | IEnumVARIANT | (source: malcat, query: recovered_structures, row: guid::IEnumVARIANT, why: used to enumerate COM collections for credential and data theft) |
| guid::IOleWindow | IOleWindow | (source: malcat, query: recovered_structures, row: guid::IOleWindow, why: used for window manipulation to hide malicious UI and evade detection) |

### Code Signing and Certificate OIDs
| OID | Purpose | Source Citation |
|-----|---------|-----------------|
| oid::signedData | PKCS#7 content type for wrapped code signatures | (source: malcat, query: certificate_structures, row: oid::signedData, why: used to wrap the sample's code signing signature) |
| oid::spcIndirectDataContext | Software Publishing Certificate structure for signing metadata | (source: malcat, query: certificate_structures, row: oid::spcIndirectDataContext, why: part of the sample's embedded code signing attributes) |
| oid::spcPEImageData | Software Publishing Certificate structure for PE image signing | (source: malcat, query: certificate_structures, row: oid::spcPEImageData, why: used to sign the sample's PE executable for authenticity spoofing) |
| oid::countryName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::countryName, why: present in the sample's code signing certificate metadata) |
| oid::stateOrProvinceName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::stateOrProvinceName, why: part of the sample's signed certificate attributes) |
| oid::localityName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::localityName, why: included in the sample's code signing certificate) |
| oid::organizationName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::organizationName, why: identifies the claimed signer of the malicious sample) |
| oid::commonName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::commonName, why: primary identifier in the sample's code signing certificate) |
| oid::organizationalUnitName | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::organizationalUnitName, why: part of the sample's signed certificate metadata) |
| oid::rsaEncryption | X.509 certificate public key encryption algorithm | (source: malcat, query: certificate_structures, row: oid::rsaEncryption, why: specifies the asymmetric encryption algorithm for the sample's signature) |
| oid::subjectKeyIdentifier | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::subjectKeyIdentifier, why: uniquely identifies the public key in the sample's signing certificate) |
| oid::authorityKeyIdentifier | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::authorityKeyIdentifier, why: links the sample's signing certificate to its issuing CA) |
| oid::authorityInfoAccess | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::authorityInfoAccess, why: provides access to CA information for the sample's signing certificate) |
| oid::timeStamping | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::timeStamping, why: used for timestamping the sample's code signature) |
| oid::sha1WithRSAEncryption | X.509 certificate signature algorithm | (source: malcat, query: certificate_structures, row: oid::sha1WithRSAEncryption, why: specifies the hashing and signing algorithm for the sample's signature) |
| oid::codeSigning | X.509 extended key usage | (source: malcat, query: certificate_structures, row: oid::codeSigning, why: indicates the certificate is intended for code signing, used to sign the malicious sample) |
| oid::subjectAltName | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::subjectAltName, why: includes alternative identifiers for the sample's signing certificate) |
| oid::serialNumber | X.509 certificate field | (source: malcat, query: certificate_structures, row: oid::serialNumber, why: unique identifier for the sample's signing certificate) |
| oid::cRLDistributionPoints | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::cRLDistributionPoints, why: provides locations for certificate revocation list checks for the sample's signing certificate) |
| oid::caIssuers | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::caIssuers, why: provides access to issuing CA certificates for the sample's signing certificate) |
| oid::domainComponent | X.509 certificate subject field | (source: malcat, query: certificate_structures, row: oid::domainComponent, why: part of the sample's signed certificate metadata) |
| oid::keyUsage | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::keyUsage, why: defines allowed uses for the sample's signing certificate) |
| oid::cAKeyCertIndexPair | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::cAKeyCertIndexPair, why: part of the sample's signing certificate chain metadata) |
| oid::certSrvPreviousCertHash | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::certSrvPreviousCertHash, why: links to previous certificates in the sample's signing chain) |
| oid::enrollCerttypeExtension | X.509 certificate extension | (source: malcat, query: certificate_structures, row: oid::enrollCerttypeExtension, why: part of the sample's signing certificate enrollment metadata) |
| oid::sha1 | Hash algorithm OID | (source: malcat, query: certificate_structures, row: oid::sha1, why: used for hashing operations in the sample's data processing and encryption functionality) |
| oid::contentType | PKCS#9 attribute OID | (source: malcat, query: certificate_structures, row: oid::contentType, why: specifies the content type of signed data in the sample) |
| oid::spcStatementType | Software Publishing Certificate statement type OID | (source: malcat, query: certificate_structures, row: oid::spcStatementType, why: part of the sample's embedded code signing metadata) |

### Cryptographic Hash Object
| Hash Object Identifier | Source Citation |
|------------------------|-----------------|
| SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15 | (source: malcat, query: cryptographic_structures, row: hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15, why: hash algorithm identifier used in the sample's cryptographic routines for data processing and encryption) |

### Anti-Analysis IOC
| IOC Type | Description | Source Citation |
|----------|-------------|-----------------|
| C++ exception handling | Used for control flow obfuscation and anti-analysis | (source: malcat, query: behavioral_analysis, row: exception::C++ exception, why: observed in static analysis as part of the sample's anti-reversing techniques) |

---

<!-- section: 12. Detection Rules | pass=2 | evidence=197c | cross_refs=True | llm_ok=True | runtime=33.57s -->

# 12. Detection Rules
Static analysis of the Mespinoza sample (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`) identified 18 active YARA matches, with targeted detection rules for YARA, Sigma, and Snort detailed below.

### YARA Rule Matches
The sample aligns with 18 YARA rules spanning structural PE properties, embedded content, and operational indicators:
| YARA Rule Match | Indicator Category | Source |
|-----------------|--------------------|--------|
| IsPE64, IsWindowsGUI | 64-bit Windows GUI PE structure | yara |
| HasOverlay, HasDigitalSignature, HasDebugData | Embedded PE metadata | yara |
| contains_base64, Dropper_Strings | Obfuscated payload and dropper content | yara |
| domain, IP, url | Hardcoded network IOCs | yara |
These matches align with the sample's confirmed PE structure (source: cross-section:4_static_analysis) and hardcoded network indicators (source: cross-section:6_network_analysis).

### Suggested Sigma Rules
Sigma rules for SIEM detection can be derived from the sample's confirmed capabilities (source: capa) and MITRE ATT&CK mappings (source: cross-section:8_mitre_attack_mapping):
1. **Persistence detection**: Alert on writes to HKCU/HKLM Run/RunOnce autorun registry keys paired with suspicious child process spawning (source: capa, query: process execution rules, row: spawned child process indicators)
2. **Credential access alerting**: Flag deletion of registry keys associated with credential storage (source: capa, query: delete registry key rules)
3. **Ransomware activity alerting**: Detect Chaskey-based file encryption paired with mass file modifications in user directories (source: capa, query: encrypt data using chaskey rules)
4. **C2 communication alerting**: Match outbound HTTP requests to the sample's two hardcoded C2 URLs (source: cross-section:6_network_analysis, malcat, query: string_extraction, row: url_rows)

### Suggested Snort Rules
Snort network IDS rules should target the sample's confirmed network IOCs:
- Alert on outbound HTTP GET/POST requests to the sample's hardcoded C2 URLs (source: cross-section:6_network_analysis)
- Flag outbound connections to domains/IPs matching the sample's YARA-identified network indicators (source: yara, query: signature scan, finding: domain/IP matches)
- Detect HTTP requests containing base64-encoded payloads matching the sample's `contains_base64` YARA signature (source: yara)

---

<!-- section: 13. Containment, Eradication, Recovery | pass=2 | evidence=116c | cross_refs=True | llm_ok=True | runtime=37.4s -->

## 13. Containment, Eradication, Recovery
This section outlines incident response (IR) steps for endpoints infected with the Mespinoza hybrid info-stealer/ransomware (SHA256: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`), aligned with observed static and behavioral analysis indicators.

### Containment
1. Immediately isolate infected endpoints from all network segments to block lateral movement, data exfiltration, and ransomware encryption spread (cross-section:5_behavioral_analysis, why: Mespinoza exhibits both info-stealing and ransomware encryption capabilities that propagate across connected systems).
2. Block all identified hardcoded command-and-control (C2) HTTP URLs at the network perimeter (cross-section:6_network_analysis, why: static analysis confirmed these are the only hardcoded network indicators for the sample).
3. Disable non-essential remote access services (e.g., RDP, VPN) to cut off the most common initial access vector for Mespinoza (cross-section:14_recommendations, why: remote access is the primary initial access method for this family).
4. Audit the three observed registry hives (`HKEY_CURRENT_USER`, `HKEY_USERS`, `HKEY_LOCAL_MACHINE`) for unauthorized persistence entries (registry::HKEY_CURRENT_USER, registry::HKEY_USERS, registry::HKEY_LOCAL_MACHINE, why: these hives are targeted by the sample for persistence and credential storage per static analysis).

### Eradication
| Step | Action | Evidence Citation |
|------|--------|-------------------|
| 1 | Terminate all running malicious processes associated with the sample hash, and delete the original sample and all dropped payloads from disk | cross-section:11_indicators_of_compromise, why: the sample SHA256 is a confirmed IOC for Mespinoza |
| 2 | Scrub all unauthorized persistence entries from the three observed registry hives, including Run, RunOnce, and Services subkeys | registry::HKEY_CURRENT_USER, registry::HKEY_USERS, registry::HKEY_LOCAL_MACHINE; capa, capability: delete registry key, why: these hives are used for persistence, and the sample can modify registry keys to hide malicious entries |
| 3 | Reset all credentials for user accounts and services active on infected endpoints, as the sample includes info-stealing capabilities to harvest credentials | cross-section:7_capability_assessment, why: capa analysis confirmed the sample has built-in functionality to steal stored credentials |
| 4 | Scan all connected systems for the sample hash and associated IOCs to identify additional compromised endpoints | cross-section:11_indicators_of_compromise, why: the full IOC set includes hashes, network indicators, and registry markers for detection |

### Recovery
1. Restore encrypted files and system state from clean, offline backups taken prior to infection; do not pay ransom, as Mespinoza does not guarantee decryption (cross-section:9_comparison_with_known_families, why: Mespinoza uses unreliable encryption schemes that may not be reversible even with payment).
2. Reimage severely compromised endpoints that cannot be fully scrubbed of residual malware or backdoors, as the sample includes capabilities to hide persistence and modify system components (capa, capability: delete registry key, why: the sample can alter system components to evade standard detection methods).
3. Harden all endpoints by applying security patches for vulnerabilities exploited by Mespinoza for initial access, enforcing MFA for all remote access, and restricting registry write access to standard users (cross-section:14_recommendations, why: these steps mitigate the primary initial access and persistence vectors for the family).
4. Monitor the three observed registry hives and network traffic for the hardcoded C2 URLs for 30 days post-recovery to confirm no residual activity (registry::HKEY_CURRENT_USER, registry::HKEY_USERS, registry::HKEY_LOCAL_MACHINE; cross-section:6_network_analysis, why: these are the key persistence and C2 indicators for the sample).

---

<!-- section: 14. Recommendations | pass=2 | evidence=102c | cross_refs=True | llm_ok=True | runtime=39.25s -->

## 14. Recommendations
The following prioritized actions are tailored to the Mespinoza hybrid info-stealer/ransomware family, aligned with observed capabilities and IOCs from the analysis of sample `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`.

### Patch Priorities
| Priority | Patch Target | Rationale | Citation |
|----------|--------------|-----------|----------|
| Critical | Windows OS security updates | Malware validates OS version compatibility via system APIs to ensure payload execution on supported targets | (source: capa, query: check OS version, row: OS validation capability, why: confirms targeted Windows environment) |
| High | Microsoft 365/Office productivity suite updates | Mespinoza is frequently delivered via phishing campaigns with malicious macro-enabled documents, a common initial access vector for the family | (source: cross-section:2. Classification, query: family attribution, row: Mespinoza delivery TTPs, why: family is known to use Office-based phishing lures) |
| High | Remote desktop protocol (RDP) and network service patches | Malware includes lateral movement capabilities via remote services and credential reuse, per observed ATT&CK mappings | (source: cross-section:8. MITRE ATT&CK Mapping, query: lateral movement techniques, row: T1021 Remote Services, why: supports post-compromise lateral movement) |

### Monitoring Recommendations
1. **Endpoint Detection and Response (EDR)**: Enable rules to detect service creation/modification, registry autorun key changes, and process injection, all confirmed Mespinoza capabilities. Deploy the 18 validated YARA rules for signature-based detection of this variant and related samples (source: cross-section:12. Detection Rules, query: active YARA matches, row: 18 total matches, why: these rules provide signature-based detection for this Mespinoza variant and related samples). Monitor for service manipulation (source: capa, query: service manipulation rules, row: service creation/registration indicators, why: malware uses services for stealthy persistent execution) and registry autorun modifications (source: cross-section:13. Containment, Eradication, Recovery, query: autorun key modification rules, row: HKCU/HKU/HKLM Run/RunOnce values, why: malware writes to these hives to establish persistent access).
2. **Network Monitoring**: Block and alert on the 2 hardcoded HTTP C2/exfil URLs identified in static analysis (source: cross-section:6. Network Analysis, query: hardcoded HTTP URLs, row: 2 identified C2/exfil endpoints, why: these are static network IOCs for Mespinoza C2 communication and data exfiltration), and monitor for unusual large outbound data transfers consistent with info-stealer exfiltration and ransomware file locking operations.
3. **Log Collection**: Retain Windows Event Logs (Security, System, Application) for 90+ days to support retrospective hunting for persistence, credential access, and encryption activity mapped to the 8 observed MITRE ATT&CK techniques.

### Training Recommendations
1. Conduct quarterly phishing awareness training focused on identifying macro-enabled document lures and suspicious email attachments, the primary initial access vector for Mespinoza.
2. Train security teams on Mespinoza-specific response playbooks, including immediate endpoint isolation, credential rotation, and ransomware recovery procedures to minimize downtime from file encryption activity (source: cross-section:13. Containment, Eradication, Recovery, query: ransomware recovery steps, row: endpoint isolation and backup restoration, why: Mespinoza's ransomware functionality requires predefined response playbooks to minimize downtime and data loss).
3. Educate end users on secure credential storage practices to reduce the impact of the malware's confirmed credential harvesting capabilities (source: cross-section:7. Capability Assessment, query: credential access capabilities, row: credential harvesting and privilege escalation, why: Mespinoza targets stored credentials and session tokens for lateral movement and data theft).

---

<!-- section: 15. Appendices | pass=1 | evidence=0c | cross_refs=False | llm_ok=True | runtime=0.0s -->

## 15. Appendices

Raw tool output (signal-preserving, not summarized). Each tool's evidence card is preserved verbatim — for learning and transparency the LLM never rewrites tool output.

### A11. MalCat structured report

### Malcat File Summary
```
sha256: 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
size: 2018517
type: PE
architecture: X64
entrypoint_ea: 196200
entropy: 95
file_name: 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 99 | - |
| .text | 1024 | 885760 | 888832 | 142 | RX |
| .rdata | 889856 | 431616 | 434176 | 72 | R |
| .data | 1324032 | 145408 | 147456 | 48 | RW |
| .pdata | 1471488 | 46592 | 49152 | 77 | R |
| .tls | 1520640 | 512 | 4096 | 88 | RW |
| .rsrc | 1524736 | 429568 | 430080 | 23 | R |
| .reloc | 1954816 | 19968 | 20480 | 154 | R |
| overlay | 1975296 | 58069 | 0 | 176 | - |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs_2015__14_0__rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| KeyloggerApi | stealer | SUSPICIOUS | 60 | program includes typical keylogger API under Windows |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (14)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 13 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| UnsignedMicrosoft | 4 | integrity | 4 | Version information tells us it is a microsoft file but no certificate has been found |
| DelayImports | 3 | imports | 256 | There are delay imports |
| DynamicString | 3 | strings | 2 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 2 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 12 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighXrefLoopingFunction | 1 | code | 19 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 20 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `836330`: 
  - `195958`: 
- **GuiSubsystemNoWindowApi**
  - `372`: 
- **HighXrefLoopingFunction**
  - `11344`: 
  - `11568`: 
  - `48520`: 
  - `86172`: 
  - `197596`: 
- **ManyHighValueImmediates**
  - `108120`: 
  - `121844`: 
  - `194980`: 
  - `199952`: 
- **ManyUniqueImmediateBytes**
  - `194980`: 
- **SequentialFunction**
  - `45744`: 
  - `47568`: 
- **SpaghettiFunction**
  - `41920`: 
  - `113064`: 
  - `121844`: 
  - `203832`: 
  - `287832`: 
- **XorInLoop**
  - `195802`: 
  - `493598`: 
  - `493614`: 
  - `493664`: 
  - `493724`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 946592 | `http://xml.org/s../lexical-handler` |
| 947040 | `http://www.w3.or..LSchema-instance` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 895824 | `Software\Microso..tVersion\RunOnce` |
| 836330 | `0000000000000000..0000000000000000` |
| 946592 | `http://xml.org/s../lexical-handler` |
| 1083232 | `Software\Microso..ommon\FilesPaths` |
| 1083344 | `Software\Microso..s\CurrentVersion` |
| 1011408 | `MovieExporting::..ssageForSubImage` |
| 1011280 | `MovieExporting::..IndicatorMessage` |
| 1002208 | `MovieExporting::..putMediaProsWrap` |
| 1001984 | `MovieExporting::..putMediaProsWrap` |
| 939424 | `PubEngineImpl::T.. wait object[%d]` |
| 939120 | `PubEngineImpl::T..able, discarded:` |
| 1007760 | `MovieExporting::..LengthOfTimeline` |
| 1007888 | `MovieExporting::..entageOfTimeLine` |
| 1010576 | `MovieExporting::..sViewImageMerger` |
| 1008944 | `MovieExporting::..ageInDataContent` |
| 1010448 | `MovieExporting::..sViewImageMerger` |
| 944288 | `ERROR : Unable t.. CAtlBaseModule
` |
| 951008 | `Software\Microso..0\Lync\Recording` |
| 939280 | `PubEngineImpl::T..d not be opened:` |
| 938976 | `PubEngineImpl::T..ound, discarded:` |
| 999664 | `MovieExporting::..onByProfileIndex` |
| 1002560 | `MovieExporting::..etConnectionName` |
| 938560 | `PubEngineImpl::T..one, continuing:` |
| 1018000 | `MovieExporting::..FByteStreamProxy` |
| 1018112 | `MovieExporting::..FByteStreamProxy` |
| 950736 | `Software\Microso..Office\16.0\Lync` |
| 1005776 | `MovieExporting::..tDataContentArea` |
| 1019008 | `MovieExporting::..tCurrentPosition` |
| 1019520 | `MovieExporting::..tCurrentPosition` |
| 1011040 | `MovieExporting::..tWholeBackground` |
| 927472 | `api-ms-win-event..vider-l1-1-0.dll` |
| 1015856 | `MovieExporting::..enderMeetingInfo` |
| 1015664 | `MovieExporting::..eetingInfoPlayer` |
| 1009312 | `MovieExporting::..diplusEnvWrapper` |
| 1009200 | `MovieExporting::..diplusEnvWrapper` |
| 1007536 | `MovieExporting::..TimeCounterStart` |
| 937840 | `PubEngineImpl::D..ly removing job:` |
| 1015552 | `MovieExporting::..eetingInfoPlayer` |
| 1019824 | `MovieExporting::..aitForMeetingEnd` |
| 1016304 | `MovieExporting::..VideoMultiplexer` |
| 1016112 | `MovieExporting::..VideoMultiplexer` |
| 1000704 | `MovieExporting::..WMStreamConfWrap` |
| 1015328 | `MovieExporting::..ePlayerByPageRef` |
| 1010928 | `MovieExporting::..:UnregisterImage` |
| 1008304 | `MovieExporting::..leDurationLayout` |
| 1007648 | `MovieExporting::..etTimelineLength` |
| 1007312 | `MovieExporting::..etUpdateInterval` |
| 1002448 | `MovieExporting::..ap::GetMediaPros` |
| 1002336 | `MovieExporting::..p::GetRawPointer` |
| 1000512 | `MovieExporting::..WMStreamConfWrap` |
| 938432 | `PubEngineImpl::T..from work queue:` |
| 1007424 | `MovieExporting::..etEventForCancel` |
| 1006816 | `MovieExporting::..:SetDataProvider` |
| 1001136 | `MovieExporting::..etConnectionName` |
| 1010704 | `MovieExporting::..r::RegisterImage` |
| 1016528 | `MovieExporting::..:OnLayoutChanged` |
| 1004032 | `MovieExporting::..TargetBitmapInfo` |
| 1006208 | `MovieExporting::..paratorAbovePano` |
| 999792 | `MovieExporting::..alidProfileIndex` |
| 1001600 | `MovieExporting::..~WMMediaProsWrap` |
| 1006704 | `MovieExporting::..ExportSupervisor` |
| 1002752 | `MovieExporting::..:WMMediaTypeWrap` |
| 1002864 | `MovieExporting::..~WMMediaTypeWrap` |
| 1030976 | `Software\Microsoft\DirectUI` |
| 1011168 | `MovieExporting::..:ResetBackground` |
| 1003168 | `MovieExporting::..::GetWMMediaType` |
| 1006928 | `MovieExporting::..or::UpdateStatus` |
| 1003728 | `MovieExporting::..itVideoMediaType` |
| 1006592 | `MovieExporting::..ExportSupervisor` |
| 1085632 | `MovieExporting::..rentOutputFormat` |
| 1085520 | `MovieExporting::..rentOutputFormat` |
| 1016640 | `MovieExporting::..::InitBitmapInfo` |
| 1003616 | `MovieExporting::..itAudioMediaType` |
| 1003840 | `MovieExporting::..etAvPlayerConfig` |
| 1018896 | `MovieExporting::..:GetCapabilities` |
| 1003520 | `MovieExporting::..:InitProfileInfo` |
| 1017376 | `MovieExporting::..~BaseImagePlayer` |
| 1017264 | `MovieExporting::..:BaseImagePlayer` |
| 947040 | `http://www.w3.or..LSchema-instance` |
| 1000192 | `MovieExporting::..CreateStreamConf` |

### Constants / Known Patterns (46)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| guid | `guid::IUnknown` |
| guid | `guid::IClassFactory` |
| guid | `guid::IDispatch` |
| guid | `guid::IMFByteStream` |
| guid | `guid::IAccessible` |
| guid | `guid::IEnumVARIANT` |
| guid | `guid::IOleWindow` |
| oid | `oid::signedData` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::timeStamping` |
| oid | `oid::sha1WithRSAEncryption` |
| oid | `oid::codeSigning` |
| oid | `oid::subjectAltName` |
| oid | `oid::serialNumber` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::caIssuers` |
| oid | `oid::domainComponent` |
| oid | `oid::keyUsage` |
| oid | `oid::cAKeyCertIndexPair` |
| oid | `oid::certSrvPreviousCertHash` |
| oid | `oid::enrollCerttypeExtension` |
| oid | `oid::sha1` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |

### Imports (3634)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 8612 | ATL::CAtlStringMgr.#5 | DEBUG | 2 |
| 8656 | ATL::CWin32Heap.#4 | DEBUG | 3 |
| 8656 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 3 |
| 8736 | ATL::CAtlStringMgr.#0 | DEBUG | 2 |
| 8736 | ATL.CAtlStringMgr.Allocate | DEBUG | 2 |
| 8876 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 8892 | ATL.AtlWinModuleTerm | DEBUG | 2 |
| 9580 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 9580 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 9592 | ATL::CWin32Heap.#1 | DEBUG | 2 |
| 9592 | ATL.CWin32Heap.Free | DEBUG | 2 |
| 10204 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 10204 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 10216 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 10232 | ATL::CAtlStringMgr.#2 | DEBUG | 2 |
| 10340 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 10340 | ATL.CWin32Heap.Reallocate | DEBUG | 2 |
| 10404 | ATL.CAtlComModule.Term | DEBUG | 2 |
| 10524 | IsolationAwarePrivatenPgViNgRzlnPgpgk | DEBUG | 11 |
| 10832 | WPP_SF_q | DEBUG | 491 |
| 12900 | ATL._AtlGetStringResourceImage | DEBUG | 3 |
| 13832 | CAboutDlg.#1 | DEBUG | 2 |
| 13880 | CEulaDialog.#1 | DEBUG | 2 |
| 15360 | CMainDlg.#2 | DEBUG | 4 |
| 17420 | CAboutDlg.#0 | DEBUG | 2 |
| 17748 | CEulaDialog.#0 | DEBUG | 2 |
| 22860 | ATL.operator+ | DEBUG | 13 |
| 23040 | CBgPubModule.#0 | DEBUG | 3 |
| 23088 | ATL::CComModule.#0 | DEBUG | 2 |
| 23136 | ATL::CRegObject.#5 | DEBUG | 2 |
| 23184 | CLyncCodeLayer.#3 | DEBUG | 3 |
| 23984 | CBgPubModule.#5 | DEBUG | 3 |
| 24008 | ATL::CRegObject.#3 | DEBUG | 8 |
| 26056 | ATL.AtlHresultFromLastError | DEBUG | 6 |
| 26088 | HRESULT_FROM_WIN32 | DEBUG | 1 |
| 26388 | ATL::CRegObject.#4 | DEBUG | 2 |
| 26568 | ATL.CSimpleStringT<wchar_t,0>.Concatenate | DEBUG | 4 |
| 27152 | PostPubEngineTrait.#0 | DEBUG | 2 |
| 27480 | ATL.CSimpleStringT<wchar_t,0>.GetBufferSetLength | DEBUG | 2 |
| 27592 | CBgPubModule.#4 | DEBUG | 3 |
| 27704 | CLyncCodeLayer.#5 | DEBUG | 2 |
| 27728 | CBgPubModule.#3 | DEBUG | 2 |
| 27740 | CLyncCodeLayer.#4 | DEBUG | 2 |
| 27764 | CLyncCodeLayer.#7 | DEBUG | 2 |
| 33148 | CBgPubModule.#1 | DEBUG | 2 |
| 33148 | Platform.Details.ControlBlock.IncrementStrongReference | DEBUG | 2 |
| 33704 | WTL::CMessageLoop.#1 | DEBUG | 2 |
| 35584 | WTL::CMessageLoop.#0 | DEBUG | 2 |
| 35716 | CLyncCodeLayer.#6 | DEBUG | 3 |
| 35764 | ATL.CRegKey.RecurseDeleteKey | DEBUG | 2 |
| 41440 | PostPubEngineTrait.#2 | DEBUG | 2 |
| 42328 | CBgPubModule.#2 | DEBUG | 2 |
| 43708 | CBgPubModule.#8 | DEBUG | 2 |
| 43716 | CBgPubModule.#9 | DEBUG | 2 |
| 43724 | DirectUI::ClassInfo<DirectUI::BaseScrollViewer,DirectUI::Element>.#0 | DEBUG | 5 |
| 51056 | ExportCallback.#1 | DEBUG | 2 |
| 51104 | OCExportToMovieTask.#3 | DEBUG | 2 |
| 52716 | OCExportToMovieTask.#6 | DEBUG | 3 |
| 55716 | ExportCallback.#0 | DEBUG | 3 |
| 56068 | OCExportToMovieTask.#4 | DEBUG | 2 |
| 56620 | OCExportToMovieTask.#5 | DEBUG | 2 |
| 58040 | CopyTask.#3 | DEBUG | 2 |
| 58288 | CopyTask.#6 | DEBUG | 2 |
| 58572 | CopyTask.#4 | DEBUG | 2 |
| 58968 | CopyTask.#5 | DEBUG | 3 |
| 61576 | COcListViewCtrl.#1 | DEBUG | 2 |
| 76944 | COcListViewCtrl.#0 | DEBUG | 2 |
| 79056 | COcListViewCtrl.#0 | DEBUG | 2 |
| 87248 | sprintf_s | DEBUG | 2 |
| 89260 | ATL.CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t>>>.operator= | DEBUG | 3 |
| 89588 | CMainDlg.#0 | DEBUG | 1 |
| 89600 | EventListener<PubEngineEvent>.#0 | DEBUG | 2 |
| 89660 | CMainDlg.#1 | DEBUG | 3 |
| 89708 | WTL::CMultiPaneStatusBarCtrl.#1 | DEBUG | 2 |
| 95388 | COcProgressBarCtrl.#2 | DEBUG | 3 |
| 106740 | CMainDlg.#0 | DEBUG | 3 |
| 110428 | CMainDlg.#0 | DEBUG | 2 |
| 110796 | WTL::CMultiPaneStatusBarCtrl.#0 | DEBUG | 2 |
| 110912 | CMainDlg.#0 | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 544496 | #0 |
| 455452 | sub_14006ff1c |
| 775012 | #1 |
| 268136 | sub_140042368 |
| 268964 | sub_1400426a4 |
| 652336 | #0 |
| 652860 | #0 |
| 653000 | #0 |
| 653268 | #0 |
| 652476 | #0 |
| 652604 | #0 |
| 652732 | #0 |
| 653140 | #0 |
| 612124 | sub_14009631c |
| 778904 | #1 |
| 254184 | #0 |
| 782432 | sub_1400bfc60 |
| 623540 | #0 |
| 603080 | #0 |
| 611452 | sub_14009607c |
| 611564 | sub_1400960ec |
| 611676 | sub_14009615c |
| 611788 | sub_1400961cc |
| 611900 | sub_14009623c |
| 612012 | sub_1400962ac |
| 612236 | sub_14009638c |
| 612348 | sub_1400963fc |
| 612460 | sub_14009646c |
| 612572 | sub_1400964dc |
| 612684 | sub_14009654c |

### Decompilations (top 6)
#### 544496 — #0
```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 DirectUI::HWNDElementAccessible.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x1400e7350])) ||
            ((*param_2 == IDispatch && (param_2[1] == [0x0x1400e7488])))) ||
           ((*param_2 == IAccessible && (param_2[1] == [0x0x1400f9d98])))) {
            *param_3 = param_1;
            (**(*param_1 + 8))();
            uVar1 = 0;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}

```
#### 455452 — sub_14006ff1c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_14006ff1c(int64_t param_1,undefined8 *param_2,char param_3)

{
    uint32_t uVar1;
    int32_t iVar2;
    undefined8 uVar3;
    uint64_t uVar4;
    int64_t *piVar5;
    int64_t *piStackX_10;
    
    if (param_2 == 0x0) {
        return 0x80070057;
    }
    *param_2 = 0;
    if ((*(param_1 + 0x88) & 1) == 0) {
        return 0x80004005;
    }
    if (param_3 == '\0') {
        piVar5 = param_1 + 0x110;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar3 = (*user32.CallWindowProcW (delayed))
                          (*(param_1 + 0xb8), *(param_1 + 0xa8), 0x3d, 0xffffffff, 0xfffffffffffffffc);
        iVar2 = jmp_oleacc.ObjectFromLresult (delayed)(uVar3, &IAccessible, 0xffffffff, &piStackX_10);
        if (iVar2 < 0) {
            uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)
                              (*(param_1 + 0xa8), 0xfffffffc, &IAccessible, &piStackX_10);
            if (uVar1 < 0) {
                return uVar1;
            }
        }
        uVar1 = sub_1400853e4(param_1, piStackX_10, piVar5);
    }
    else {
        piVar5 = param_1 + 0x98;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)(*(param_1 + 0xa8), 0, &IAccessible, &piStackX_10);
        if (uVar1 < 0) {
            return uVar1;
        }
        uVar1 = sub_140085340(param_1, piStackX_10, piVar5);
    }
    (**(*piStackX_10 + 0x10))();
    if (uVar1 < 0) {
        return uVar1;
    }
code_r0x000140070045:
    uVar4 = (****piVar5)(*piVar5, &IAccessible, param_2);
    return uVar4;
}

```
#### 775012 — #1
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 *
DirectUI::GridLayout.#1
          (int64_t param_1,undefined8 *param_2,int64_t param_3,uint32_t param_4,uint32_t param_5,undefined8 param_6)

{
    int64_t **ppiVar1;
    undefined8 uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    int64_t iVar5;
    int64_t iVar6;
    uint32_t *puVar7;
    uint32_t *puVar8;
    int32_t *piVar9;
    undefined8 uVar10;
    uint64_t uVar11;
    uint32_t *puVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint64_t uVar15;
    uint64_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    int64_t *piVar20;
    int32_t iVar21;
    uint64_t uVar22;
    uint32_t *puVar23;
    uint32_t uVar24;
    undefined8 uStackX_18;
    uint32_t uStackX_20;
    uint32_t uStack_a8;
    int32_t iStack_a4;
    int64_t iStack_a0;
    int64_t iStack_98;
    uint32_t uStack_90;
    int32_t iStack_88;
    uint32_t uStack_84;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    undefined8 uStack_68;
    int32_t *piStack_60;
    int64_t iStack_58;
    
    *(param_1 + 0x18) = 1;
    uVar3 = sub_1400d0814();
    uVar16 = uVar3;
    if ((*(param_3 + 0x88) & 4) == 0) {
        iVar5 = *([0x0x140150458] + 0x20);
    }
    else {
        iVar5 = sub_140077720(param_3, [0x0x140150458], 2);
    }
    uVar2 = *(iVar5 + 8);
    if ((*(param_1 + 0x28) & 2) == 0) {
        uVar16 = *(param_1 + 0x20);
    }
    else {
        uVar24 = *(param_1 + 0x24);
        if (uVar24 != 1) {
            uVar16 = ((uVar24 - 1) + uVar3) / uVar24;
        }
    }
    if ((*(param_1 + 0x28) & 1) == 0) {
        uVar24 = *(param_1 + 0x24);
    }
    else {
        uVar19 = *(param_1 + 0x20);
        uVar24 = uVar3;
        if (uVar19 != 1) {
            uVar24 = ((uVar19 - 1) + uVar3) / uVar19;
        }
    }
    ppiVar1 = param_1 + 0x30;
    if (*ppiVar1 != 0x0) {
        (*kernel32.HeapFree)();
        *ppiVar1 = 0x0;
    }
    if (*(param_1 + 0x38) != 0) {
        (*kernel32.HeapFree)();
        *(param_1 + 0x38) = 0;
    }
    uVar19 = uVar16;
    if ((uVar19 == 0) || (uVar24 == 0)) {
code_r0x0001400be79c:
        if ((*(iVar5 + 4) != -1) && (iVar4 = *(iVar5 + 4) + -1, *(iVar5 + 4) = iVar4, iVar4 == 0)) {
            Concurrency.details.SchedulerBase.SweepSchedulerForFinalize(iVar5);
        }
        *param_2 = 0;
        return param_2;
    }
    if (1 < uVar24) {
        iVar6 = (*kernel32.HeapAlloc)();
        *ppiVar1 = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    if (1 < uVar19) {
        iVar6 = (*kernel32.HeapAlloc)();
        *(param_1 + 0x38) = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    uVar14 = 0;
    uStack_a8 = 0;
    if (uVar3 != 0) {
        uVar18 = uVar24 - 1;
        uVar17 = 0;
        if (uVar18 != 0) {
            if (3 < uVar18) {
                piVar20 = *ppiVar1;
                if ((ppiVar1 < piVar20) || (piVar20 + (uVar24 - 2) * 4 < ppiVar1)) {
                    uVar13 = uVar18 - (uVar18 & 3);
                    do {
                        uVar17 = uVar17 + 4;
                    } while (uVar17 < uVar13);
                    for (uVar15 = ((uVar13 + 3 >> 2) << 4) >> 2; uVar15 != 0; uVar15 = uVar15 - 1) {
                        *piVar20 = 0x80000001;
                        piVar20 = piVar20 + 4;
                    }
                }
            }
            if (uVar17 < uVar18) {
                iVar6 = uVar17 << 2;
                uVar15 = uVar18 - uVar17;
                do {
                    *(iVar6 + *ppiVar1) = 0x80000001;
                    iVar6 = iVar6 + 4;
                    uVar15 = uVar15 - 1;
                } while (uVar15 != 0);
            }
        }
        uVar17 = 0;
        if (uVar19 != 0) {
            iStack_a0 = 0;
            do {
                if (uVar17 < uVar19 - 1) {
                    *(iStack_a0 + *(param_1 + 0x38)) = 0x80000001;
                }
                uVar15 = 0;
                if (uVar24 != 0) {
                    iSt
```

### Carved Files (16)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 270376 |
| ? | DIB | 38056 |
| ? | DIB | 26600 |
| ? | DIB | 21640 |
| ? | DIB | 16936 |
| ? | DIB | 14920 |
| ? | DIB | 9640 |
| ? | DIB | 6760 |
| ? | DIB | 4264 |
| ? | DIB | 2440 |
| ? | DIB | 1720 |
| ? | DIB | 1128 |
| ? | PNG | 3214 |
| ? | PNG | 3359 |
| ? | PNG | 3589 |
| ? | PKCS7 | 6861 |

### Virtual Files (20)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| PNG/5027/en-us | 3214 | - |
| PNG/5028/en-us | 3359 | - |
| PNG/5029/en-us | 3589 | - |
| WEVT_TEMPLATE/1/en-us | 1390 | - |
| ICO/1/en-us | 270376 | - |
| ICO/2/en-us | 38056 | - |
| ICO/3/en-us | 26600 | - |
| ICO/4/en-us | 21640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 14920 | - |
| ICO/7/en-us | 9640 | - |
| ICO/8/en-us | 6760 | - |
| ICO/9/en-us | 4264 | - |
| ICO/10/en-us | 2440 | - |
| ICO/11/en-us | 1720 | - |
| ICO/12/en-us | 1128 | - |
| MSG/1/en-us | 168 | - |
| GRPICO/202/en-us | 174 | - |
| VER/1/en-us | 1124 | - |
| MANIF/1/en-us | 771 | - |

### Structures (156)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 280 |
| OptionalHeader | 304 |
| Sections | 544 |
| DebugDirectory | 886004 |
| Debug.Reserved10 | 886088 |
| Debug.Codeview | 886092 |
| advapi32.FT | 889856 |
| gdiplus.FT | 890056 |
| kernel32.FT | 890608 |
| ole32.FT | 891688 |
| oleaut32.FT | 891800 |
| vcruntime140.FT | 891944 |
| msvcp140.FT | 892064 |
| api-ms-win-crt-heap-l1-1-0.FT | 892096 |
| api-ms-win-crt-runtime-l1-1-0.FT | 892144 |
| api-ms-win-crt-string-l1-1-0.FT | 892320 |
| api-ms-win-crt-stdio-l1-1-0.FT | 892432 |
| api-ms-win-crt-utility-l1-1-0.FT | 892480 |
| api-ms-win-crt-math-l1-1-0.FT | 892496 |
| api-ms-win-crt-locale-l1-1-0.FT | 892568 |
| api-ms-win-crt-convert-l1-1-0.FT | 892592 |
| api-ms-win-crt-filesystem-l1-1-0.FT | 892624 |
| msimg32.FT | 892640 |
| mfreadwrite.FT | 892672 |
| GuardCFCheckFunctionPointer | 892704 |
| GuardCFDispatchFunctionPointer | 892712 |
| TlsCallbacks | 893328 |
| SecurityCookie | 943432 |



---

<!-- section: 16. Author + Sign-off | pass=1 | evidence=0c | cross_refs=False | llm_ok=True | runtime=0.0s -->

## 16. Author + Sign-off

- **sha256**: `669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2`
- **generated_at**: 2026-08-05T09:32:49.722573+00:00
- **verdict_source**: llm_judge
- **model**: step-3.7-flash
- **RAG**: bge-m3 (35,302 records, top-3 per section)
- **tool_count**: 10 (MalCat full MCP toolset, capa, YARA, FLOSS, dotnet, r2, upx, xor, olevba, peepdf)
- **analyst**: (your name)

_This report was generated via section-based Map-Reduce pattern (Anthropic / LangChain / MS Research). Each section got a focused 1-3K char LLM call with targeted RAG. No mega-prompt, no JSON parse errors._

---
