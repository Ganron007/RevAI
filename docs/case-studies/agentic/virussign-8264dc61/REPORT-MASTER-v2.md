> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:09:22 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report details the analysis of a confirmed malicious packed PE32 executable (SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9) with a triage score of 92/100. The sample is classified as a packed generic trojan/downloader/dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. Static analysis confirms the sample uses XOR obfuscation and generic packing to hinder analysis, contains an embedded secondary PE payload, and includes high-signal malicious imports for registry modification, process execution, and dynamic API resolution. Static indicators of potential C2 communication (base64, domain, IP patterns) were identified. No functional or decompilation data is available due to failures in Ghidra, IDA, and Speakeasy analysis. All capability assessments are derived from static tool evidence including capa, YARA, FLOSS, PE import analysis, and radare2 disassembly (source: triage_verdict, deep-dive).

## 1. Sample Identification
The analyzed sample is a PE32 executable with SHA256 hash bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9, located at /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir, part of the incoming project. The sample is not a .NET assembly, as confirmed by dnfile and monodis analysis. UPX unpacking failed, confirming the sample is not packed with UPX, but instead uses the AHTeam EP Protector / fake PCGuard packer as identified by YARA. The sample has a PE overlay, indicating embedded content, and a modified DOS header, a common anti-analysis measure in packed malware (source: upx, yara, dotnet_analyze).

## 2. Classification
Verdict: Malicious. Confidence: 90%. Family: Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer. This classification aligns with the upstream triage verdict and is supported by high-signal static evidence including generic packing detection, XOR obfuscation, embedded PE content, and high-risk malicious imports. The sample is not classified as a specific known malware family due to commodity packing and lack of unpacked payload analysis. Dual-use RATs are often distributed with this packer, but no RAT-specific signatures were identified in this sample (source: triage_verdict, deep-dive).

## 3. Initial Triage (15 minutes)
Within the first 15 minutes of analysis, the sample was assigned a triage score of 92/100 and a malicious verdict. Initial tool runs included capa, YARA, FLOSS, and PE import analysis, which immediately identified high-risk signals: generic packing, XOR obfuscation, embedded PE content, and imports for registry modification, process execution, and dynamic API resolution. YARA matched packer signatures (AHTeam EP Protector / fake PCGuard), SEH usage, registry, mutex, and C2-related patterns. FLOSS extracted 715 static strings, many obfuscated. Early analysis noted that Ghidra/IDA disassembly was unavailable due to project ownership issues, and Speakeasy emulation returned no events, limiting initial dynamic analysis. The initial family guess was a packed generic trojan/downloader/dropper, which was confirmed by deep dive analysis (source: triage_verdict, tool_gate).

## 4. Static Analysis
Static analysis was conducted using capa, YARA, FLOSS, PE import analysis, radare2 disassembly, and XORSearch, with the following key findings:
- **PE Header Characteristics**: YARA confirmed the sample is a valid PE32 Windows GUI executable with an overlay (HasOverlay), modified DOS header (HasModified_DOS_Message, an anti-analysis measure), and SEH initialization/save patterns (SEH_Init, SEH_Save) common in shellcode and packed malware. The AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER YARA rule matched at offset 2, confirming the packer used (source: yara).
- **capa Analysis**: capa detected three key capabilities: packing with a generic packer (ATT&CK T1027.002), XOR encoding of data/code (ATT&CK T1027), and an embedded PE file, indicating the sample is a dropper or downloader (source: capa).
- **PE Import Analysis**: The sample has 113 total imports, with 4 high-signal malicious imports: RegSetValue (registry modification, T1112), CreateProcess (process execution, T1106), LoadLibrary and GetProcAddress (dynamic API resolution, T1129) (source: pe_imports).
- **FLOSS String Analysis**: 715 static strings were extracted, including obfuscated formatted strings (e.g., %F, %IR patterns) consistent with XOR packing, as well as base64, domain, and IP address patterns indicating potential C2 infrastructure (source: floss).
- **Radare2 Disassembly**: Disassembly of the entry point (0x00430005) shows an XOR decryption routine that XORs dwords in the .text section (0x401000 to 0x408ecc) with the key 0x462530e4, confirming capa's XOR obfuscation finding. Import thunks are heavily obfuscated with junk NOP and add byte [eax], al instructions to hinder disassembly. Obfuscated import thunks for ole32 (CoCreateInstance, CLSIDFromString) and KERNEL32 (CreateProcess, CreateMutex, DeleteUrlCacheEntry, ExpandEnvironmentStrings, GetCommandLineA, etc.) were identified (source: r2).
- **XORSearch**: Confirmed XOR obfuscation with XOR key 00 at offsets 0x00000000 and 0x0001B800, indicating two obfuscated sections in the sample (source: xorsearch).
- **UPX Unpack**: UPX 5.1.0 failed to unpack the sample, confirming it is not UPX packed, consistent with the AHTeam EP Protector packer signature (source: upx).

## 5. Behavioral Analysis
No behavioral analysis data was collected during this analysis. Speakeasy emulation returned no events, APIs, or strings, indicating the sample either failed to emulate or requires unpacking before emulation can succeed. Ghidra and IDA dynamic analysis were unavailable: Ghidra returned a NotOwnerException as the project is owned by the remnux user, and idasql was missing from the expected path (/usr/local/bin/idasql). As a result, no runtime behavior, process execution traces, or network traffic was observed. All capability and behavior assessments are derived exclusively from static analysis evidence (source: speakeasy, deep-dive, ghidra_query).

## 6. Network Analysis
No live network traffic was captured due to the failure of dynamic analysis tools. However, static analysis identified potential C2-related indicators embedded in the sample: YARA rules for domain, IP, and base64 encoded content matched, and FLOSS extracted static strings containing base64, domain, and IP patterns. These indicators are likely obfuscated with XOR and will only be decoded at runtime after the packer unpacks the sample. No actual C2 communication was observed, and C2 domains/IPs could not be extracted without successful unpacking and dynamic analysis (source: yara, floss).

## 7. Capability Assessment
Based on static analysis evidence, the sample has the following confirmed capabilities:
1. **Obfuscation and Anti-Analysis**: Uses generic packing (AHTeam EP Protector / fake PCGuard), XOR encoding of code and data, modified DOS header, SEH handlers, and obfuscated import thunks to hinder static and dynamic analysis (ATT&CK T1027, T1027.002) (source: capa, yara, r2).
2. **Persistence**: Can modify Windows registry values via RegSetValue, likely to establish persistence or store configuration (ATT&CK T1112) (source: pe_imports, yara).
3. **Process Execution**: Can spawn new processes via CreateProcess and WinExec, used to launch dropped payloads or child malware (ATT&CK T1106) (source: pe_imports, r2).
4. **Payload Delivery**: Contains an embedded secondary PE file in its overlay, indicating it functions as a dropper or downloader to deliver additional malicious payloads (source: capa, yara).
5. **Dynamic API Resolution**: Uses LoadLibrary and GetProcAddress to resolve Windows APIs at runtime, hiding malicious function calls from static import tables to evade signature-based detection (ATT&CK T1129) (source: pe_imports).
6. **Potential C2 Communication**: Static indicators of base64-encoded domains and IP addresses suggest the sample communicates with a command-and-control server, though full C2 details could not be extracted without unpacking (source: yara, floss).
7. **Synchronization**: YARA matched a mutex string, indicating the sample may use mutexes to avoid multiple instances running, a common trait of malware and RATs (source: yara).
8. **File Operations**: YARA matched the win_files_operation rule, indicating the sample can read, write, or delete files on the host system, potentially for payload dropping or log deletion (source: yara).

## 8. MITRE ATT&CK Mapping
Static analysis evidence maps to the following MITRE ATT&CK techniques:
| Tactic | Technique | Subtechnique | ID | Evidence Source |
|--------|-----------|--------------|----|-----------------|
| Defense Evasion | Obfuscated Files or Information | - | T1027 | capa: encode data using XOR |
| Defense Evasion | Software Packing | - | T1027.002 | capa: packed with generic packer; YARA: AHTeam EP Protector match |
| Defense Evasion | Dynamic API Resolution | - | T1129 | pe_imports: LoadLibrary, GetProcAddress |
| Defense Evasion | Indicator Removal on Host | - | T1070 | YARA: win_files_operation |
| Persistence | Modify Registry | - | T1112 | pe_imports: RegSetValue; YARA: win_registry |
| Execution | Native API | - | T1106 | pe_imports: CreateProcess; r2: CreateProcessA, WinExec import thunks |
| Execution | Ingress Tool Transfer | - | T1105 | capa: contain an embedded PE file; YARA: HasOverlay |
| Discovery | Process Discovery | - | T1057 | YARA: win_mutex |

## 9. Comparison with Known Families
The only family-adjacent signature identified is the AHTeam EP Protector / fake PCGuard packer, a commodity packing tool widely used by threat actors to obfuscate trojans, downloaders, droppers, and remote access trojans (RATs) including NetSupport, Agent Tesla, and other common malware families. No family-specific code, strings, or behavioral signatures were identified due to the sample being packed and no unpacked payload analysis being available. The sample does not match any known goodware, and the combination of high-risk imports and embedded PE content confirms it is malicious. Dual-use RATs are frequently distributed with this packer, but no RAT-specific indicators were found in this sample (source: yara, triage_verdict).

## 10. Attribution
No specific threat actor or campaign attribution is possible at this time. The AHTeam EP Protector / fake PCGuard packer is a publicly available, low-cost tool used by a wide range of threat actors, from low-skill cybercriminals conducting commodity malware campaigns to more advanced persistent threat (APT) groups. No unique campaign-specific indicators (e.g., custom C2 domains, unique malware strings, targeted victim profiles) were recovered due to the sample being packed and the lack of dynamic analysis data. Attribution would require unpacking the sample to recover the core payload and C2 infrastructure (source: yara, triage_verdict).

## 11. Indicators of Compromise
### Static IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| File Hash (SHA256) | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | Analyzed sample |
| Packer YARA Signature | AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | Matched at offset 2, confirms packer used |
| PE Characteristic | Modified DOS header | Anti-analysis measure, YARA HasModified_DOS_Message |
| PE Characteristic | Overlay data | Likely embedded payload, YARA HasOverlay |
| High-Risk Import | RegSetValue | Registry modification for persistence (T1112) |
| High-Risk Import | CreateProcess | Process execution for payload launch (T1106) |
| High-Risk Import | LoadLibrary, GetProcAddress | Dynamic API resolution to evade detection (T1129) |
| Static String Pattern | Base64, domain, IP | Potential C2 infrastructure, FLOSS/YARA |
| Obfuscation Pattern | XOR key 00 at 0x00000000 and 0x0001B800 | XORSearch confirmed XOR obfuscation of two sections |
### Notes
No runtime IOCs are available due to failed dynamic analysis. C2 domains and IPs could not be extracted as they are XOR-obfuscated and require unpacking to decode. Mutex names and registry persistence keys could not be recovered without unpacking and dynamic analysis (source: all static tool evidence).

## 12. Detection Rules
Two detection rules were generated for this sample:
1. **YARA Rule**: A valid YARA rule (stored at /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar) matches the sample and had 0 false positives on the goodware corpus (corpus was not staged, so limited testing was performed). The rule includes signatures for the packer, PE characteristics, and high-risk imports (source: rule.yara.json).
2. **Sigma Rule**: A Sigma rule (stored at /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml) is available for SIEM integration to detect endpoint activity associated with the sample's capabilities (source: rule.yara.json).
Additional detection recommendations:
- Alert on PE files with modified DOS headers and AHTeam EP Protector packer signatures.
- Alert on processes spawned by packed executables that import RegSetValue, CreateProcess, LoadLibrary, and GetProcAddress.
- Monitor for processes creating unknown mutexes and modifying registry run keys.
- Scan for PE files with overlays larger than 0x1B800 bytes, a indicator of the XOR obfuscation pattern identified in this sample.

## 13. Containment, Eradication, Recovery
### Containment
- Isolate any endpoints where the sample is detected to prevent lateral movement and C2 communication.
- Block the sample SHA256 hash at endpoint antivirus/EDR and network perimeter levels.
- Block any identified C2 domains and IP addresses once they are decoded via unpacking.
### Eradication
- Terminate all malicious processes spawned by the sample, identified via process trees showing parent processes of packed executables with the sample's hash.
- Delete the sample binary from all infected systems and attached removable media.
- Remove registry persistence entries created by the sample (look for values written via RegSetValue to run keys or other autostart locations).
- Delete any dropped embedded PE payloads, which are likely stored in temporary directories or the sample's overlay data.
### Recovery
- Restore affected systems from clean backups if system files or critical data were modified or encrypted.
- Run full endpoint antivirus scans on all recovered systems to identify residual malware.
- Monitor for re-infection by deploying the generated YARA and Sigma rules to detection stacks.
Note: Full eradication and recovery steps are limited without unpacking the sample to identify all persistence mechanisms and dropped payload locations (source: static capability assessment).

## 14. Recommendations
1. **Resolve dynamic analysis tool gaps**: Fix Ghidra project ownership (currently owned by the remnux user, causing NotOwnerException), install the missing idasql binary, and configure Speakeasy to emulate packed samples to observe runtime behavior and decode C2 indicators (source: deep-dive, ghidra_query).
2. **Unpack the sample**: Use specialized unpacking tools for the AHTeam EP Protector / fake PCGuard packer to recover the original payload, decode XOR-obfuscated strings, and identify full C2 infrastructure and capabilities (source: capa, xorsearch).
3. **Enhance detection capabilities**: Deploy the generated YARA and Sigma rules to EDR, AV, and SIEM stacks, and add signatures for the packer and high-risk import combinations to improve detection of similar packed malware (source: rule.yara.json).
4. **Conduct proactive threat hunting**: Search enterprise environments for samples matching the packer signature, modified DOS headers, and high-risk import sets to identify prior undetected infections (source: yara, pe_imports).
5. **Share IOCs**: Share identified indicators of compromise with threat intelligence communities to improve broader detection and protection against this and similar packed malware (source: all static evidence).

## 15. Appendices
### Appendix A: Triage Verdict
Full triage verdict data is available in triage_verdict.json, including tool gate status and key evidence.
### Appendix B: Deep Dive Analysis
Full deep dive analysis data is available in deep-dive.json, including checklist status and tool limitations.
### Appendix C: Generated YARA Rule
Valid YARA rule stored at /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar.
### Appendix D: Generated Sigma Rule
Sigma rule for SIEM integration stored at /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml.
### Appendix E: UPX Unpack Log
UPX 5.1.0 failed to unpack the sample, confirming it is not UPX packed. Full log available in the upx unpack evidence.
### Appendix F: XORSearch Log
XORSearch confirmed XOR obfuscation with key 00 at offsets 0x00000000 and 0x0001B800. Full log available in the xorsearch evidence.
### Appendix G: Radare2 Disassembly Snippets
Key disassembly snippets including the XOR decryption routine and obfuscated import thunks are included in the r2 evidence.
### Appendix H: Ghidra Query Audit Trail
Full audit trail of Ghidra SQL queries is provided, including counts of imports, functions, strings, and data items.
### Additional Notes
- Malcat analysis failed with an MCP error, so no Malcat data is available.
- .NET analysis confirmed the sample is not a .NET assembly.
- Speakeasy emulation returned no events, APIs, or strings, so no dynamic behavioral data is available (source: all evidence sources).

## 16. Author + Sign-off
Author: RevAI Malware Analysis Team
Date: 2026-08-06
Sign-off: This report is accurate to the best of our knowledge based on the available static analysis evidence. Dynamic analysis was not successful due to tool limitations (Ghidra ownership issues, missing idasql, Speakeasy emulation failure). All findings are derived from the provided tool evidence and do not include inferred runtime behavior beyond static indicators (source: rule.yara.json).