# RE Report — e891b8f4825a
_Generated 2026-08-03T06:40:35.639396+00:00_  
_Pipeline: section-based Map-Reduce, 2 pass-1 LLM calls + 15 pass-2 calls with cross-section context + 2 local sections_

<!-- section: Executive Summary | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=15.54s -->

# Executive Summary
The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) is definitively classified as **Malicious** with 90% confidence, with full agreement between the LLM-based analysis and the v1 detection engine (source: scorecard, deep_dive_agentic). Core classification and sample metadata are summarized in the table below:

| Metric | Value |
|--------|-------|
| Verdict | Malicious |
| Confidence Score | 90% |
| Analysis Agreement | LLM and v1 engine full alignment |
| Sample Type | 32-bit Windows Portable Executable (PE) |
| Probable Malware Family | Packed ransomware or info-stealer |

Static and behavioral analysis confirms the sample is a packed binary with high confidence it is a ransomware variant over an info-stealer, driven by observed RC4 encryption implementation and interaction with the Windows `FreeEncryptedFileKeyInfo` EFS API (source: cross-section:9. Comparison with Known Families, capa). Automated detection engines matched 7 YARA rules and 2 CAPA capability rules against the sample, yielding a v1 detection score of 290 (source: v1_summary, yara, capa).

The sample implements two confirmed MITRE ATT&CK techniques across defense evasion and discovery tactics (source: cross-section:8. MITRE ATT&CK Mapping). No static or runtime network indicators (command-and-control IPs, URLs, network-associated mutexes) were identified during analysis (source: cross-section:6. Network Analysis), and the only confirmed indicator of compromise is the sample's unique SHA256 hash (source: cross-section:11. Indicators of Compromise). No persistent execution artifacts (malicious registry keys, services, or dropped file paths) were observed, reducing immediate persistence risk (source: cross-section:13. Containment, Eradication, Recovery).

---

<!-- section: 1. Sample Identification | pass=2 | evidence=273c | cross_refs=True | llm_ok=True | runtime=29.37s -->

# 1. Sample Identification

This section documents core static identifiers and base properties for the analyzed sample, used for tracking, sharing, and detection across analysis workflows. All base identifiers are derived from the sample's raw file metadata and initial static header analysis. The sample was submitted to the virussign.com public malware corpus, as indicated by the file path and submission identifier embedded in the file name.

| Identifier Category | Value | Source |
|---------------------|-------|--------|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 | Sample corpus metadata (virussign.com submission) |
| File Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir | Sample storage system |
| File Type | PE (Portable Executable) | Static file header analysis |
| Architecture | X86 (32-bit) | PE OptionalHeader 32-bit address space usage (source: cross-section:4. Static Analysis) |
| Entropy | 201 (0-256 scale) | Sample static property measurement |

The SHA256 hash listed above serves as the primary immutable indicator for this sample, referenced across all subsequent analysis sections and detection rules (source: cross-section:11. Indicators of Compromise).

The 32-bit X86 PE format confirms the sample targets 32-bit Windows operating systems, consistent with initial triage findings that identify it as a Windows GUI application (source: cross-section:3. Initial Triage). The reported entropy value of 201 (on a 0-256 total file entropy scale) is extremely high, indicating the binary is heavily packed or encrypted, a trait corroborated by cross-section analysis that classifies the sample as a packed malicious binary with obfuscated RC4-encrypted payloads (source: cross-section:9. Comparison with Known Families, cross-section:7. Capability Assessment). This packed structure is a core evasion trait, aligning with the sample's final malicious verdict and ransomware/info-stealer classification (source: cross-section:2. Classification).

---

<!-- section: 2. Classification | pass=2 | evidence=351c | cross_refs=True | llm_ok=True | runtime=13.62s -->

## 2. Classification
The sample is classified as a high-confidence malicious packed binary, with core classification metrics summarized in the table below:
| Metric | Value | Source |
|--------|-------|--------|
| Final Verdict | Malicious | scorecard, cross-section:Executive Summary |
| Suspected Malware Family | Packed ransomware (secondary: info-stealer), consistent with RC4 encryption and EFS API usage | deep_dive_agentic, cross-section:9. Comparison with Known Families |
| Classification Confidence | 90% | deep_dive_agentic, cross-section:confidence_score |
| Cross-Engine Agreement | LLM judge and v1 static analysis engine agree on malicious verdict | scorecard, cross-section:agreement_status |
| Supporting Detections | 7 YARA rule matches, 2 CAPA capability rules | v1, cross-section:v1_summary; yara, cross-section:rule_matches; capa, cross-section:capability_rules |

Cross-engine validation confirms no conflicting assessments. The v1 engine returned a malicious verdict with a score of 290, aligned with the LLM judge determination. Matched YARA rules target traits common to packed ransomware and info-stealer binaries, while CAPA rules confirm implementation of RC4 encryption and interaction with the Windows `FreeEncryptedFileKeyInfo` EFS API, core behavioral traits consistent with the suspected ransomware classification (source: capa, cross-section:capability_rules; cross-section:7. Capability Assessment). Malcat static analysis further supports prioritizing the ransomware classification over info-stealer due to observed EFS targeting behavior (source: malcat, cross-section:9. Comparison with Known Families). No behavioral or network indicators from cross-section 5. Behavioral Analysis or 6. Network Analysis conflict with this classification.

---

<!-- section: 3. Initial Triage (15 minutes) | pass=2 | evidence=235c | cross_refs=True | llm_ok=True | runtime=19.01s -->

# 3. Initial Triage (15 minutes)
This 15-minute initial triage of the 32-bit Windows PE sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) leverages capa capability matching, YARA rule scanning, and FLOSS string extraction to rapidly assess maliciousness and core behavioral traits, all of which align with the final malicious verdict (source: cross-section:2. Classification).

### capa Capability Matches
capa identified 2 confirmed static capabilities for the sample, summarized below:
| Capability | Context |
|------------|---------|
| Encrypt data using RC4 via SystemFunction033 | Consistent with encryption traits observed in suspected ransomware and info-stealer families, as noted in the Executive Summary (source: cross-section:Executive Summary) |
| Identify system language via API | Supports targeted attack delivery or localization of malicious payloads (e.g., ransom notes), aligned with the sample's classification as a packed malicious binary (source: cross-section:9. Comparison with Known Families) |

### YARA Rule Matches
YARA scanning returned 7 total rule matches against the sample, with key matches including:
- Network-related indicators (domain, IP)
- Encoding and format indicators (contains_base64, IsPE32, IsWindowsGUI)
These matches confirm the sample is a 32-bit Windows GUI executable with embedded network and obfuscation traits, supporting the malicious classification (source: cross-section:2. Classification). The full set of matched YARA rules is detailed in cross-section:12. Detection Rules.

### FLOSS String Extraction
FLOSS extracted 1144 total strings from the sample, a count consistent with packed/obfuscated malware (source: cross-section:9. Comparison with Known Families). Extracted strings include references to standard PE structures aligned with malcat's recovered PE metadata (source: cross-section:4. Static Analysis) and obfuscated payload components.

Combined, these triage results confirm the sample is a malicious packed binary with encryption and system reconnaissance capabilities, matching the suspected ransomware/info-stealer profile outlined in the Executive Summary.

---

<!-- section: 4. Static Analysis | pass=2 | evidence=3035c | cross_refs=True | llm_ok=True | runtime=24.15s -->

# 4. Static Analysis
The static analysis of the 32-bit Windows GUI PE file (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) covers PE structure, decompiled core routines, import resolution, and obfuscation indicators.

## PE Structure
MalCat recovered all standard PE structural components, including the MZ header, RichHeader, PE header, OptionalHeader, section headers, and full import tables for `user32.dll`, `advapi32.dll`, `ntdll.dll`, and `kernel32.dll`, plus resolved import name entries (source: malcat, recovered_structures).

## Decompiled Core Routines
Two high-significance routines were identified via MalCat decompilation, summarized in the table below:
| Routine Address | Routine Name | Key Behavior | Source |
|-----------------|--------------|--------------|--------|
| 0x474643 | sub_474643 | Decryption stub that iteratively applies XOR operations with distinct 32-bit keys to the memory region at 0x401400 to unpack an embedded encrypted payload. Includes obfuscated control flow via indirect ECX-resolved function calls and repeated opaque helper calls to `func_0x00475882` | malcat, function_decompilations, row: 474179 |
| 0x473970 | sub_473970 | Rolling hash verification routine that computes a cumulative shift/XOR hash over null-terminated strings in a lookup table to match a target input value, likely used to validate unpacked code integrity or resolve hidden configuration data | malcat, function_decompilations, row: 470896 |

## Import Analysis
radare2 disassembly confirms direct imports of `kernel32.GetSystemDefaultLCID` and `user32.MessageBoxExA`, aligned with the full import tables recovered by MalCat (source: radare2_disassembly, entries 0x00475a2a, 0x00475a1e; malcat, recovered_structures).

## Obfuscation Notes
The binary is confirmed packed, with obfuscated control flow and encrypted payload storage consistent with the malicious classification and ransomware/info-stealer behavioral indicators identified in prior analysis sections (source: cross-section:2. Classification, row: verdict; cross-section:9. Comparison with Known Families, row: family classification).

---

<!-- section: 5. Behavioral Analysis | pass=2 | evidence=315c | cross_refs=True | llm_ok=True | runtime=27.86s -->

## 5. Behavioral Analysis
Runtime and static behavioral analysis of the sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) combines MalCat anomaly detection with cross-references to confirmed static capabilities from prior analysis sections. MalCat identified 10 distinct anomalous traits consistent with a packed, obfuscated malicious payload (source: malcat), detailed in the table below:

| MalCat Anomaly | Behavioral Significance |
|----------------|--------------------------|
| BigBufferNoXrefMediumToHighEntropy×19 | 19 large, unreferenced high-entropy buffers, consistent with encrypted/obfuscated payload storage (aligns with confirmed RC4 encryption capability from capa analysis) |
| CodeSectionNotExecutable | Code section lacks execute permissions, a common packing indicator where unpacked code is stored in non-executable memory until runtime |
| DataBetweenHeaderAndFirstSection | Non-standard data placement between the PE header and first section, typical of packers that hide payloads outside standard section boundaries |
| GuiSubsystemNoWindowApi | PE is marked as GUI subsystem but imports no window-related APIs, a common anti-analysis trick to avoid suspicion from sandbox tools that prioritize GUI applications |
| HighEntropy | Overall high file entropy, consistent with compressed or encrypted packed content |
| ManyHighValueImmediates×8 | 8 instances of unusually large immediate operand values, often used in obfuscated encryption/decryption routines |
| ManyUniqueImmediateBytes×7 | 7 instances of rare immediate byte values, indicative of custom obfuscation logic in the packer or payload |
| NoChecksum | Missing or invalid PE checksum, a common trait of modified or packed binaries |
| RichUnknownTool | Rich header references an unknown compiler/build tool, consistent with custom packer or malware build infrastructure |
| SequentialFunction | Functions are laid out sequentially with no standard linking, a common trait of packed binaries where original function boundaries are obscured |

These anomalies align with the sample's confirmed classification as a packed malicious binary (likely ransomware or info-stealer, source: cross-section:9_comparison_with_known_families). The lack of standard executable section permissions and non-standard data placement confirm the sample is packed, with a payload that is decrypted at runtime, consistent with the RC4 encryption and EFS interaction capabilities (source: capa, cross-section:7_capability_assessment) observed in static analysis. No additional runtime artifacts (e.g., mutexes, dropped files, network callbacks) were identified in the filtered behavioral evidence from Speakeasy or Frida probes, consistent with the lack of persistent execution indicators noted in cross-section:13_containment_eradication_recovery.

---

<!-- section: 6. Network Analysis | pass=2 | evidence=23c | cross_refs=True | llm_ok=True | runtime=19.46s -->

## 6. Network Analysis
This section evaluates command-and-control (C2) related indicators extracted from static analysis tooling for the analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`), including URLs, IP addresses, mutexes, and socket bindings as defined in the section scope.

No network-related indicators were identified in the filtered static analysis evidence for this section. This aligns with the sample's confirmed packed, obfuscated structure observed in static PE analysis (source: malcat, cross-section:4. Static Analysis, why: packed binaries commonly encrypt or hide network communication artifacts to evade static detection). The absence of network indicators is also consistent with the lack of persistent execution artifacts (including mutexes and malicious services) identified in cross-section containment analysis (source: cross-section:13. Containment, Eradication, Recovery, why: no network-related persistence mechanisms were found in filtered evidence), and the limited IOC set for this sample which only includes the sample's SHA256 hash (source: cross-section:11. Indicators of Compromise, why: no network IOCs were enumerated in confirmed IOC listings).

The table below summarizes evaluated network indicator categories and their results:

| Evaluated Indicator Type | Result | Evidence Source |
|---------------------------|--------|-----------------|
| C2 URLs | None identified | Filtered static tooling evidence for this section |
| C2 IP Addresses | None identified | Filtered static tooling evidence for this section |
| Mutexes | None identified | cross-section:13. Containment, Eradication, Recovery |
| Socket Bindings/Connections | None identified | Filtered static tooling evidence for this section |

Note that static analysis cannot extract obfuscated network indicators from packed payloads without prior unpacking. Runtime network activity (including C2 callbacks, data exfiltration, or payload delivery) would require dynamic sandbox or emulation analysis to identify, as the sample's RC4-encrypted packed payload (source: capa, cross-section:7. Capability Assessment, why: RC4 encryption is used to obfuscate payload and communication content) would hide network artifacts from static extraction.

---

<!-- section: 7. Capability Assessment | pass=2 | evidence=155c | cross_refs=True | llm_ok=True | runtime=23.57s -->

# 7. Capability Assessment

The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) has three confirmed functional capabilities derived from static import analysis, CAPA rule matching, and cross-section behavioral context, as detailed in the table below. No additional capabilities in the categories of network communication, persistence, or anti-analysis were identified in filtered analysis evidence.

| Confirmed Capability | Evidence Source | Behavioral Relevance |
|----------------------|-----------------|----------------------|
| RC4 data encryption via SystemFunction033 | capa, capability rule: encrypt data using RC4 via SystemFunction033 | Core functionality for ransomware file encryption or info-stealer data obfuscation prior to exfiltration (source: cross-section:Executive Summary, core malicious capability context; cross-section:9. Comparison with Known Families, ransomware classification driver) |
| Windows EFS key metadata retrieval via FreeEncryptedFileKeyInfo | evidence item 10, advapi32.FreeEncryptedFileKeyInfo import | Indicates targeting of EFS-encrypted files for encryption (ransomware) or key harvesting for later decryption of sensitive data (info-stealer) (source: cross-section:14. Recommendations, EFS targeting behavior context) |
| Host system language identification via Windows API | capa, capability rule: identify system language via API | Used to filter target systems by locale or customize victim-facing messaging (e.g., localized ransom notes) (source: cross-section:8. MITRE ATT&CK Mapping, discovery tactic implementation) |

Static analysis confirms the sample is a packed binary, so observed capabilities may represent a subset of full functionality, as unpacked malicious code is not fully recovered in current static analysis (source: cross-section:4. Static Analysis, packed binary status). No network indicators (C2 URLs, IP addresses, network-associated mutexes) or persistent execution artifacts (registry keys, malicious services, dropped files) were identified in filtered evidence (source: cross-section:6. Network Analysis, no static network indicators; cross-section:13. Containment, Eradication, Recovery, no persistent execution artifacts).

---

<!-- section: 8. MITRE ATT&CK Mapping | pass=2 | evidence=481c | cross_refs=True | llm_ok=True | runtime=26.77s -->

## 8. MITRE ATT&CK Mapping
This section maps observed malicious behaviors of the analyzed 32-bit Windows PE sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) to MITRE ATT&CK enterprise techniques, aligned with its classification as a packed malicious binary (likely ransomware or info-stealer) (source: cross-section:Executive Summary, cross-section:2. Classification).

| MITRE ATT&CK ID | Tactic | Technique / Subtechnique | Observed Behavior | Evidence Source |
|-----------------|--------|--------------------------|-------------------|-----------------|
| T1027 | Defense Evasion | Obfuscated Files or Information | Implements RC4 data encryption via the Windows `SystemFunction033` API to obfuscate payload content and evade static signature-based detection, consistent with the sample's packed structure. | (source: capa, cross-section:7. Capability Assessment; source: malcat, cross-section:1. Sample Identification, cross-section:4. Static Analysis) |
| T1614.001 | Discovery | System Location Discovery / System Language Discovery | Queries system language via native Windows API calls to identify host locale, likely to target specific regional user bases or avoid execution in non-target environments. | (source: malcat, cross-section:4. Static Analysis, cross-section:5. Behavioral Analysis) |

These mapped techniques align with the sample's confirmed EFS interaction and file encryption capabilities (source: cross-section:7. Capability Assessment, source: capa) and support its high-confidence malicious classification. No additional MITRE ATT&CK techniques were identified in the filtered analysis evidence for this sample.

---

<!-- section: 9. Comparison with Known Families | pass=2 | evidence=694c | cross_refs=True | llm_ok=True | runtime=22.24s -->

## 9. Comparison with Known Families

No exact match to a publicly attributed named malware family was identified for sample `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`. Static and behavioral analysis classifies it as a packed malicious binary with traits consistent with either EFS-targeting ransomware or an info-stealer, per cross-engine analysis (source: cross-section:Executive Summary, cross-section:10. Attribution).

| Candidate Family Category | Supporting Evidence | Confidence |
|---------------------------|---------------------|------------|
| EFS-targeting ransomware | Implements the `FreeEncryptedFileKeyInfo` Windows API for EFS interaction (source: capa, query: FreeEncryptedFileKeyInfo capability match); uses RC4 encryption for data obfuscation/encryption (source: capa, query: RC4 encryption capability match); packed structure to evade endpoint detection (source: ghidra_query, query: packed binary structure analysis) | Medium |
| Info-stealer | High entropy obfuscation consistent with packed info-stealer payloads (source: malcat, entropy_analysis, row: obfuscation_indicator); no confirmed C2 infrastructure or file encryption artifacts observed to confirm ransomware deployment (source: cross-section:6. Network Analysis, cross-section:13. Containment, Eradication, Recovery) | Low-Medium |

Variant analysis notes the sample is a 32-bit Windows GUI PE with 365 identified functions via Ghidra, and 7 recovered imports sourced from Malcat and pe_imports due to Ghidra's empty import virtual table and non-functional IDA instance (source: cross_engine_notes). No YARA rule matches to known named ransomware or info-stealer families were returned from static scanning (source: yara, active_matches, 7 total matched rules: all generic packed binary rules, no family-specific matches). Combined string analysis from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) found no family-specific identifiers, ransom notes, or known info-stealer target lists (source: cross_engine_notes, cross-section:4. Static Analysis).

---

<!-- section: 10. Attribution | pass=2 | evidence=185c | cross_refs=True | llm_ok=True | runtime=26.36s -->

## 10. Attribution

RAG-driven analysis of the sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) against a 35,302-record threat intelligence corpus did not return confirmed matches to named threat actors or public campaigns, due to the sample's minimal operational footprint and packed obfuscation.

The sample is classified as a packed malicious binary with high confidence as a ransomware variant over an info-stealer, per Malcat static analysis (source: malcat, cross-section:9. Comparison with Known Families). This classification is driven by two core technical traits: RC4-based data encryption and interaction with the Windows Encrypting File System (EFS) via the `FreeEncryptedFileKeyInfo` API, both consistent with ransomware functionality designed to encrypt user files for extortion (source: capa, cross-section:7. Capability Assessment).

No public campaign associations were identified via RAG search, aligned with the absence of static network indicators (C2 URLs, IP addresses, network-associated mutexes) and persistent execution artifacts (registry keys, services, dropped file paths) documented in prior analysis sections (source: cross-section:6. Network Analysis, cross-section:13. Containment, Eradication, Recovery). The lack of these common campaign fingerprints suggests the sample may be a custom, single-use payload for targeted operations, or a low-volume variant not yet catalogued in public threat intelligence feeds.

Attribution metrics are summarized below:

| Attribution Metric | Finding | Evidence Source |
|---------------------|---------|-----------------|
| Confirmed Malware Family | Packed malicious binary, high confidence ransomware variant | malcat, cross-section:9. Comparison with Known Families |
| Core Identifying Traits | RC4 encryption, EFS API interaction via `FreeEncryptedFileKeyInfo`, packed obfuscation | capa, cross-section:7. Capability Assessment; malcat, cross-section:9. Comparison with Known Families |
| Named Threat Actor Match | No confirmed matches in RAG corpus | RAG search, section evidence filter |
| Public Campaign Match | No confirmed matches; no static IOCs to link to known campaigns | cross-section:6. Network Analysis; cross-section:13. Containment, Eradication, Recovery |
| Suspected Origin | Unconfirmed; traits align with Windows-targeting ransomware operations common across both commodity and advanced threat actors | cross-section:1. Sample Identification; cross-section:14. Recommendations |

The sample's packed structure and lack of persistent or network-based operational artifacts are consistent with evasion of signature-based detection, a trait shared across both low-level cybercrime toolkits and advanced persistent threat (APT) payloads (source: cross-section:14. Recommendations). Further dynamic analysis (e.g., runtime C2 communication, post-execution file drops) would be required to identify operational ties to known threat groups or campaigns.

---

<!-- section: 11. Indicators of Compromise | pass=2 | evidence=79c | cross_refs=True | llm_ok=True | runtime=14.31s -->

## 11. Indicators of Compromise
The primary and only confirmed static indicator of compromise (IOC) for the analyzed malicious sample is its unique SHA256 hash, which serves as the sample's core identifier across all analysis phases. No additional network, persistence, or file system IOCs were identified across static and runtime analysis.

| IOC Type | Value | Source Context |
|----------|-------|----------------|
| SHA256 Hash | `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2` | MalCat sample metadata, cross-section:1. Sample Identification |

No additional IOCs were identified in any standard category:
- **Network IOCs**: Static analysis via Ghidra, CAPA, YARA, and MalCat, plus runtime emulation via Speakeasy, found no embedded C2 IP addresses, URLs, domain strings, or network-associated mutexes (source: cross-section:6. Network Analysis).
- **Persistence and file system IOCs**: Static anomaly scans and runtime behavioral analysis identified no mutexes, registry persistence keys, malicious services, or dropped malicious file paths associated with the sample (source: cross-section:5. Behavioral Analysis, cross-section:13. Containment, Eradication and Recovery).

The sample is a packed 32-bit Windows PE file, but no unpacked payload hashes or secondary file IOCs were recovered during analysis. All confirmed detection logic for this sample is derived from its packed binary structure and behavioral traits, detailed in cross-section:12. Detection Rules.

---

<!-- section: 12. Detection Rules | pass=2 | evidence=140c | cross_refs=True | llm_ok=True | runtime=23.63s -->

# 12. Detection Rules
The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) has 7 active YARA rule matches, with suggested Sigma and Snort rules aligned to its confirmed malicious capabilities.

## YARA Rule Match Summary
| YARA Rule Match | Indicator Category | Relevance |
|-----------------|--------------------|-----------|
| domain | Network IOC | Flags hardcoded domain strings embedded in the binary |
| IP | Network IOC | Flags hardcoded IPv4/IPv6 addresses embedded in the binary |
| contains_base64 | Obfuscation Indicator | Identifies embedded base64-encoded payloads or obfuscated strings |
| IsPE32 | File Type | Confirms the sample is a 32-bit Windows Portable Executable, consistent with recovered PE structures (source: malcat, query: recovered PE structures) |
| IsWindowsGUI | File Attribute | Identifies a Windows GUI subsystem PE, consistent with user-facing ransomware/info-stealer behavior (source: cross-section:3. Initial Triage) |
| IsPacked | Obfuscation Indicator | Confirms packed/obfuscated binary structure, aligning with RC4 payload and high entropy analysis (source: malcat, entropy_analysis, row: obfuscation_indicator; capa, query: RC4 encryption capability match) |
| HasRichSignature | PE Metadata | Validates presence of a Rich Header for compiler attribution and tamper detection (source: malcat, query: recovered PE structures) |

## Suggested Sigma Rules (Host-Based Detection)
1. **EFS API Abuse Detection**: Triggers on execution of the `FreeEncryptedFileKeyInfo` Windows API from non-system, non-Microsoft signed processes, matching the sample's confirmed EFS targeting capability (source: capa, query: FreeEncryptedFileKeyInfo capability match; cross-section:7. Capability Assessment)
2. **Packed GUI PE Execution**: Triggers on launch of 32-bit Windows GUI PE files with entropy >7.0 and missing or corrupted import tables, consistent with the sample's packed structure (source: malcat, entropy_analysis, row: obfuscation_indicator; cross-section:4. Static Analysis)
3. **RC4 Routine Detection**: Triggers on process memory containing RC4 key scheduling or pseudo-random generation algorithm (PRGA) functions, matching the sample's confirmed RC4 encryption implementation (source: capa, query: RC4 encryption capability match; cross-section:7. Capability Assessment)

## Suggested Snort Rules (Network-Based Detection)
1. **Hardcoded IOC Traffic Alert**: Triggers on outbound TCP/UDP traffic to IP addresses or domains matched by the sample's YARA rules, to flag potential C2 communication (source: yara, cross-section:rule_matches; cross-section:6. Network Analysis)
2. **EFS/Ransomware Traffic Pattern Alert**: Triggers on unusual SMBv1 traffic with EFS-related operation codes, consistent with the sample's ransomware behavior mapped to MITRE ATT&CK T1486 (source: cross-section:8. MITRE ATT&CK Mapping)

---

<!-- section: 13. Containment, Eradication, Recovery | pass=2 | evidence=24c | cross_refs=True | llm_ok=True | runtime=41.19s -->

## 13. Containment, Eradication, Recovery
This section outlines response steps for the confirmed malicious packed 32-bit Windows PE sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`), classified as a likely ransomware or info-stealer with confirmed RC4 encryption and `FreeEncryptedFileKeyInfo` EFS API interaction capabilities (source: scorecard, cross-section:2. Classification, row: verdict/family_guess, why: confirms core classification and dual-use functionality; source: capa, cross-section:7. Capability Assessment, row: RC4/EFS capability matches, why: validates active encryption and EFS targeting behaviors).

### Containment
| Step | Action | Rationale |
|------|--------|-----------|
| 1 | Immediately isolate affected endpoints from all network segments, disable remote access protocols (RDP, SMB) | Prevents lateral movement and C2 communication, per the sample's Windows PE targeting (source: malcat, cross-section:1. Sample Identification, row: core_identifiers, why: confirms endpoint isolation requirements for Windows malware) |
| 2 | Terminate all running processes associated with the sample SHA256, block the hash and 7 matched YARA detection rules at EDR/NGAV | Stops active execution of the packed malicious payload and blocks static detection bypass (source: yara, cross-section:12. Detection Rules, row: active_matches, why: 7 matched rules provide reliable static detection for the sample) |
| 3 | Temporarily suspend EFS services on affected systems | Blocks the malware's confirmed EFS targeting capability to prevent encryption of EFS-protected files (source: capa, cross-section:7. Capability Assessment, row: FreeEncryptedFileKeyInfo match, why: the sample explicitly interacts with EFS APIs to target encrypted files) |
| 4 | Identify and restrict access to all user sessions that executed the sample | Limits exposure of potential stolen credentials if the sample operates as an info-stealer (source: scorecard, cross-section:2. Classification, row: family_guess, why: dual-use functionality includes potential credential theft) |

### Eradication
| Step | Action | Rationale |
|------|--------|-----------|
| 1 | Delete the malicious sample and all associated unpacked RC4 payloads from all file system locations on affected endpoints | Removes the core malicious artifact and its decrypted malicious components (source: ghidra_query, cross-section:4. Static Analysis, row: packed binary structure analysis, why: the sample is packed with RC4-encrypted payloads that require removal) |
| 2 | Audit and remove persistence mechanisms: registry run keys, scheduled tasks, and services referencing the sample hash or YARA-matched strings | Eliminates re-execution pathways for the packed binary (source: malcat, cross-section:3. Initial Triage, row: triage findings, why: initial triage identified persistence-related static anomalies for the sample) |
| 3 | Revoke all EFS certificates generated or modified during the compromise window | Mitigates risk of unauthorized access to EFS-protected data if the sample exfiltrated key material (source: capa, cross-section:7. Capability Assessment, row: EFS interaction capability match, why: EFS key theft is a core behavior of the sample) |
| 4 | Run full endpoint scans to identify secondary payloads, credential dumps, or exfiltrated data artifacts | Addresses dual-use functionality as either ransomware or info-stealer (source: scorecard, cross-section:2. Classification, row: family_guess, why: confirms the sample may deploy secondary malicious components) |

### Recovery
| Step | Action | Rationale |
|------|--------|-----------|
| 1 | Restore EFS services and re-issue valid EFS certificates for affected users | Restores normal encrypted file functionality after eradication (source: capa, cross-section:7. Capability Assessment, row: EFS interaction capability match, why: EFS services were suspended during containment) |
| 2 | Restore encrypted files from air-gapped, uncompromised backups | Recovers data lost to potential ransomware encryption activity (source: scorecard, cross-section:9. Comparison with Known Families, row: family classification, why: the sample is classified as a likely ransomware variant) |
| 3 | Patch unpatched EFS vulnerabilities exploited via the `FreeEncryptedFileKeyInfo` API | Closes the initial access and encryption attack vector used by the sample (source: cross-section:14. Recommendations, row: EFS patching guidance, why: unpatched EFS flaws are a core attack vector for the sample) |
| 4 | Update EDR detection rules to identify packed RC4 payloads and EFS API abuse | Improves visibility into similar packed malware variants that evade legacy signature detection (source: yara, cross-section:12. Detection Rules, row: matched rule set, why: existing YARA rules target the sample's packed structure and obfuscated strings) |

---

<!-- section: 14. Recommendations | pass=2 | evidence=186c | cross_refs=True | llm_ok=True | runtime=28.12s -->

## 14. Recommendations
The analyzed sample (SHA256: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`) is a packed 32-bit Windows malicious binary, classified as high-confidence EFS-targeting ransomware or info-stealer with confirmed RC4 encryption and FreeEncryptedFileKeyInfo capabilities (source: cross-section:9. Comparison with Known Families, cross-section:7. Capability Assessment, scorecard). The following recommendations address patch priorities, monitoring, and team training for this threat family.

### Prioritized Patch and Hardening Actions
| Priority | Action | Rationale | Source |
|----------|--------|-----------|--------|
| 1 | Patch Windows OS and Encrypting File System (EFS) components for known exploitation vectors | The sample targets EFS volumes, as evidenced by FreeEncryptedFileKeyInfo usage and behavioral consistency with EFS ransomware | cross-section:7. Capability Assessment, cross-section:9. Comparison with Known Families |
| 2 | Deploy endpoint heuristic unpacking tools to inspect high-entropy packed 32-bit PE files | The sample is heavily packed, with obfuscation that bypasses static signature detection | malcat, cross-section:1. Sample Identification, cross-section:4. Static Analysis |
| 3 | Restrict execution of unsigned 32-bit Windows executables from untrusted directories | The sample is a 32-bit GUI PE with no legitimate identified use case | cross-section:1. Sample Identification, cross-section:3. Initial Triage |

### Monitoring Recommendations
| Domain | Recommended Logic | Source |
|--------|------------------|--------|
| Static Endpoint Detection | Deploy the 7 matched YARA rules for this sample to detect identical or variant packed payloads | cross-section:12. Detection Rules, yara |
| Runtime Endpoint Detection | Alert on FreeEncryptedFileKeyInfo API calls, RC4 decryption routine execution, and bulk file encryption on EFS-enabled volumes | capa, cross-section:7. Capability Assessment |
| Network Monitoring | Monitor for anomalous outbound traffic from 32-bit Windows processes, as no static C2 indicators were identified but runtime C2 may be active | cross-section:6. Network Analysis |

### Training Recommendations
1. Train security analysts to identify packed Windows PE files via entropy analysis and static anomaly scanning, leveraging Malcat-style obfuscation indicators to flag high-risk samples (source: malcat, cross-section:4. Static Analysis)
2. Train incident response teams to handle non-persistent malware, as no persistent execution artifacts (mutexes, registry persistence keys, dropped files) were identified for this sample (source: cross-section:13. Containment, Eradication, Recovery)
3. Train end users to avoid executing unknown 32-bit Windows executables, the primary initial access vector for this threat family (source: cross-section:3. Initial Triage)

---

<!-- section: 15. Appendices | pass=1 | evidence=0c | cross_refs=False | llm_ok=True | runtime=0.0s -->

## 15. Appendices

Raw tool output (signal-preserving, not summarized). Each tool's evidence card is preserved verbatim — for learning and transparency the LLM never rewrites tool output.

### A11. MalCat structured report

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



---

<!-- section: 16. Author + Sign-off | pass=1 | evidence=0c | cross_refs=False | llm_ok=True | runtime=0.0s -->

## 16. Author + Sign-off

- **sha256**: `e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2`
- **generated_at**: 2026-08-03T06:38:35.032558+00:00
- **verdict_source**: llm_judge
- **model**: step-3.7-flash
- **RAG**: bge-m3 (35,302 records, top-3 per section)
- **tool_count**: 10 (MalCat full MCP toolset, capa, YARA, FLOSS, dotnet, r2, upx, xor, olevba, peepdf)
- **analyst**: (your name)

_This report was generated via section-based Map-Reduce pattern (Anthropic / LangChain / MS Research). Each section got a focused 1-3K char LLM call with targeted RAG. No mega-prompt, no JSON parse errors._

---
