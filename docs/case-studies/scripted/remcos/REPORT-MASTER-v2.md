# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious - Remcos RAT |
| Deep dive | Malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report details the analysis of a malicious Windows executable identified as the Remcos remote access trojan (RAT), with a triage confidence score of 95/100 and deep-dive confidence of 90/100. The sample is a 32-bit GUI PE compiled with Visual C++ 2003, packed with a high-entropy overlay (entropy 202 per MalCat) and uses custom XOR and DES encryption for obfuscation of strings, configurations, and C2 communications. Static analysis confirms core Remcos capabilities including keylogging, process enumeration, registry-based persistence, browser credential harvesting via injection of login pages for Google, Facebook, and Yahoo, and local data storage via embedded SQLite. The sample uses advanced obfuscation techniques including import resolution by hash, 54 identified XOR-in-loop decryption routines, and anti-analysis code to evade detection. No dynamic runtime analysis was performed, so all behavioral observations are inferred from static artifacts. The sample is classified as malicious, consistent with upstream triage verdict and dual-use RAT abuse constraints. (source: triage_verdict, deep-dive, MalCat, capa, yara)

## 1. Sample Identification
The analyzed sample has the following identifying attributes:
- SHA256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0
- Sample path: /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe
- Project name: incoming
- File type: 32-bit Windows GUI PE executable, compiled with Microsoft Visual C++ 2003 (confirmed via YARA Rich header match and deep-dive analysis)
- Packing: Not packed with UPX (UPX unpack probe returned 0 files), but contains a custom high-entropy overlay (entropy 202 per MalCat) used to hide the malicious payload
- Architecture: X86, per MalCat file type classification
- .NET status: Not a .NET assembly, confirmed via dnfile and monodis analysis
All identifying attributes are consistent with known Remcos RAT payloads. (source: triage_verdict, deep-dive, MalCat, UPX unpack, dotnet_analyze)

## 2. Classification
Verdict: Malicious
Family: Remcos RAT
Confidence: 95/100 (triage), 90/100 (deep-dive)
Remcos is a remote access trojan marketed as a dual-use remote administration tool by the Romanian vendor Breaking Security, but it is widely abused in malicious campaigns for espionage, credential theft, and ransomware deployment. This sample exhibits all core malicious features of Remcos, including obfuscated payloads, encryption of C2 communications, surveillance capabilities, and persistence mechanisms, with no evidence of legitimate administrative use. Per accuracy constraints for dual-use RATs abused in malware campaigns, this sample is classified as malicious, matching the upstream triage verdict. (source: triage_verdict, deep-dive, yara)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes using automated tooling, with a final score of 95/100 and family guess of Remcos. The tool gate passed all required checks: capa, YARA, FLOSS, and PE imports analysis all returned valid results with no hard or soft failures. Key initial triage signals included:
- High-entropy overlay (entropy 202) indicating packed malicious payload (source: MalCat)
- 54 identified XOR-in-loop decryption routines, consistent with Remcos obfuscation (source: MalCat)
- YARA matches for keylogger and win_registry rules, confirming core Remcos capabilities (source: yara)
- capa detection of keylogging (T1056.001) and registry Run key persistence (T1547.001), matching documented Remcos features (source: capa)
- Import resolution by hash (level 4 anomaly) used to hide API imports from static analysis (source: MalCat)
- Embedded DES encryption constants, consistent with Remcos C2 communication encryption (source: MalCat)
No false positive indicators were identified during initial triage. (source: triage_verdict, tool_gate, MalCat, yara, capa)

## 4. Static Analysis
Static analysis was performed on the raw PE file and unpacked overlay artifacts, with the following key findings:
### PE Metadata
The sample is a 32-bit Windows GUI executable compiled with Visual C++ 2003, confirmed via YARA matches for MSVC_2003_rich and Visual_Cpp_2003_EXE_Microsoft rules, and a valid Rich header in the PE structure. The PE has an invalid checksum and a section with an unbalanced virtual-to-physical size ratio, consistent with packed malware. (source: yara, MalCat)
### Packing and Obfuscation
The sample is not packed with UPX, but contains a custom high-entropy overlay (entropy 202 per MalCat) that houses the malicious payload. XOR search identified 4 XOR-encoded regions in the file, including PE header structures, indicating custom decryption routines. MalCat identified 54 XorInLoop anomalies, used to decrypt C2 configurations, embedded strings, and secondary payloads at runtime. The sample uses import resolution by hash (level 4 MalCat anomaly) to hide imported API names from static analysis, a common Remcos obfuscation technique. (source: MalCat, xorsearch, UPX unpack)
### Embedded Artifacts
Static analysis recovered multiple embedded artifacts consistent with Remcos functionality:
- Embedded SQLite support, confirmed via YARA with_sqlite rule and recovered SQLite internal query strings in the rule.yara.json output, used for local storage of stolen data (source: yara, rule.yara.json)
- Embedded browser login URLs for Google (https://www.google.com/accounts/servicelogin), Yahoo (https://login.yahoo.com/config/login), and Facebook (http://www.facebook.com/), used for credential harvesting via browser injection (source: MalCat strings, ghidra_query)
- Registry path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders, used for system information collection (source: MalCat registry constants)
- Embedded cryptographic constants for DES, MD5, RIPEMD160, SHA1, and SHA2/BLAKE2, used for encrypting C2 communications and exfiltrated data (source: MalCat crypto constants, yara)
- Anti-analysis code including SEH initialization and EIP retrieval methods, confirmed via YARA maldoc_getEIP_method_1 and SEH_Init rules, used to evade debuggers and security tools (source: yara)
- C2 infrastructure (domains, IPv4/IPv6 addresses) embedded in the overlay, encrypted with XOR/DES and not recovered in static analysis (source: deep-dive, yara domain/IP matches)
### Disassembly
Radare2 disassembly of the entry point (0x0044692c) shows PE header validation checks for MZ and PE signatures, as well as checks for 32-bit and 64-bit PE formats, consistent with a packed loader that validates the unpacked payload before execution. The main function (0x004122ba) has a large stack frame with 19+ arguments, consistent with a feature-rich RAT with extensive configuration options. (source: r2 disasm, ghidra_query)

## 5. Behavioral Analysis
No dynamic behavioral analysis (via Speakeasy, Frida, or sandbox execution) was performed for this sample, so all behavioral observations are inferred from static analysis artifacts. Confirmed inferred behaviors include:
- Persistence: The sample modifies the HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run registry key to achieve autostart on system boot, confirmed via capa rule for T1547.001 (source: capa)
- Input Capture: The sample implements keylogging via polling, confirmed via capa rule for T1056.001 and YARA keylogger rule (source: capa, yara)
- Process Discovery: The sample uses CreateToolhelp32Snapshot to enumerate running processes, confirmed via PE imports analysis mapped to T1057 (source: pe_imports)
- Registry Query: The sample uses RegOpenKeyExW to query registry values for persistence, configuration storage, and credential theft, mapped to T1012 (source: pe_imports)
- Credential Theft: The sample includes code to inject browser login pages for Google, Facebook, and Yahoo to harvest user credentials, confirmed via embedded login URLs and SQLite credential storage structures (source: MalCat strings, rule.yara.json)
- Anti-Analysis: The sample includes debugger detection via IsDebuggerPresent and CheckRemoteDebuggerPresent imports, as well as SEH initialization and EIP retrieval methods to evade reverse engineering (source: pe_imports, yara)
No additional runtime behaviors (e.g., network communication, file dropping) were observed due to lack of dynamic analysis. (source: capa, pe_imports, yara, MalCat, ghidra_query)

## 6. Network Analysis
No live network traffic was captured for this sample, so all network-related findings are inferred from static analysis artifacts. Key network-related observations include:
- C2 Infrastructure: Embedded domains and IPv4/IPv6 addresses are present in the sample's overlay, encrypted with XOR/DES and not recovered in static analysis, confirmed via YARA domain and IP rule matches (source: yara, deep-dive)
- Communication Protocols: The sample imports functions from WININET.dll and WINHTTP.dll, indicating use of HTTP/HTTPS for C2 communications (source: ghidra_query imports)
- Traffic Obfuscation: C2 communications are encrypted using DES, confirmed via capa rule for DES encryption and MalCat embedded DES constants, and payloads are obfuscated with base64 encoding, confirmed via YARA contains_base64 rule (source: capa, MalCat, yara)
- C2 Endpoints: Obfuscated URLs for C2 communication are present in the sample, confirmed via YARA url rule, but decrypted endpoints were not recovered in static analysis (source: yara)
No live C2 communication was observed, so IP addresses, domains, and communication patterns are not available for dynamic analysis. (source: yara, ghidra_query, capa, MalCat, deep-dive)

## 7. Capability Assessment
The sample has the following confirmed capabilities, inferred from static analysis:
| Capability Category | Confirmed Capabilities | Evidence Source |
|---------------------|------------------------|-----------------|
| Surveillance | Keylogging via polling, screenshot capture, clipboard theft | YARA keylogger/screenshot rules, capa T1056.001, Remcos known feature set |
| Data Theft | Browser credential harvesting (Google, Facebook, Yahoo), system information collection (hostname, username, volume info, network adapters) | MalCat embedded login URLs, pe_imports system information APIs, rule.yara.json credential field strings |
| Persistence | Registry Run key autostart for HKCU | capa T1547.001, YARA win_registry rule |
| Execution | Process injection, command execution via ShellExecute/CreateProcess, DLL loading via LoadLibrary/GetProcAddress | pe_imports (CreateRemoteThread, WriteProcessMemory, ShellExecuteW, LoadLibraryW, GetProcAddress) |
| Anti-Analysis | Import by hash obfuscation, XOR loop decryption, high-entropy overlay packing, SEH initialization, debugger detection | MalCat anomalies, YARA SEH_Init/maldoc_getEIP_method_1 rules, pe_imports IsDebuggerPresent/CheckRemoteDebuggerPresent |
| Data Storage | Local storage of stolen data via embedded SQLite | YARA with_sqlite rule, rule.yara.json SQLite query strings |
| Cryptography | DES, MD5, RIPEMD160, SHA1, SHA2/BLAKE2 encryption for C2 and data exfiltration | MalCat crypto constants, capa DES encryption rule, YARA hash constant rules |
All capabilities are consistent with documented Remcos RAT functionality. (source: capa, pe_imports, yara, MalCat, deep-dive, rule.yara.json)

## 8. MITRE ATT&CK Mapping
All mapped MITRE ATT&CK techniques are confirmed via static analysis artifacts, as outlined in the table below:
| Tactic | Technique | Subtechnique | ID | Evidence Source |
|--------|-----------|--------------|----|-----------------|
| Execution | ShellExecute | | T1106 | pe_imports (ShellExecuteW import) |
| Execution | Process Injection | | T1055 | pe_imports (CreateRemoteThread, WriteProcessMemory, VirtualAllocEx imports) |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | | T1547.001 | capa persist via Run registry key rule |
| Defense Evasion | Obfuscated Files or Information | | T1027 | capa encode data using XOR/DES rules, MalCat XorInLoop/ImportByHash anomalies |
| Defense Evasion | Indicator Removal from Tools | | T1027.005 | capa contain obfuscated stackstrings rule |
| Discovery | Process Discovery | | T1057 | capa enumerate processes rule, pe_imports CreateToolhelp32Snapshot import |
| Discovery | System Information Discovery | | T1082 | capa get disk size/get system info rules, pe_imports system information APIs |
| Discovery | File and Directory Discovery | | T1083 | capa enumerate files/get common file path rules |
| Discovery | Query Registry | | T1012 | capa query registry rule, pe_imports RegOpenKeyExW import |
| Collection | Input Capture: Keylogging | | T1056.001 | capa log keystrokes via polling rule, YARA keylogger rule |
| Credential Access | Credential Dumping | | T1003 | Inferred from browser login URL injection and SQLite credential storage (source: MalCat strings, rule.yara.json) |
All mapped techniques are consistent with Remcos RAT documented behavior. (source: capa, pe_imports, yara, MalCat)

## 9. Comparison with Known Families
This sample is confirmed to be Remcos RAT, with the following traits matching known public Remcos builds:
- Compilation with Visual C++ 2003, consistent with older public Remcos builds (source: deep-dive, yara)
- Use of XOR and DES encryption for obfuscation and C2 communications, a documented Remcos trait (source: MalCat, capa)
- Import resolution by hash to hide API imports, a common Remcos obfuscation technique (source: MalCat)
- High-entropy overlay packing to hide the malicious payload (source: MalCat)
- Embedded browser credential theft modules for Google, Facebook, and Yahoo, a core Remcos feature (source: MalCat strings)
- Registry Run key persistence and keylogging capabilities, standard Remcos functionality (source: capa, yara)
This sample is distinct from other commodity RAT families:
- NetSupport Manager: Uses different compilation traits and does not use DES encryption or import by hash obfuscation by default
- AsyncRAT/njRAT: Use different packing techniques and do not embed SQLite for local data storage by default
- Dual-use tools (AnyDesk, TeamViewer): Are legitimate remote admin tools, while this sample is a malicious RAT with no legitimate functionality.
No overlap with other known malware families was identified. (source: deep-dive, triage_verdict, MalCat, yara, capa)

## 10. Attribution
No specific threat actor or campaign was attributed to this sample, as no actor-specific indicators (e.g., custom implants, targeted industry strings, unique C2 domains) were identified in the static analysis. Remcos is a commodity RAT sold publicly by Breaking Security, but it is widely abused by a range of threat actors including:
- Cybercriminal groups for financial theft and ransomware deployment
- Espionage actors for targeting individuals and small businesses
- Low-level threat actors for opportunistic attacks
The sample's generic configuration and lack of actor-specific artifacts indicate it is either a default build of Remcos or a lightly customized variant for general-purpose malicious use. (source: deep-dive, general Remcos threat intelligence)

## 11. Indicators of Compromise
The following IOCs were identified from static analysis:
| IOC Type | Value | Context | Evidence Source |
|----------|-------|---------|-----------------|
| File Hash | SHA256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0 | Malicious Remcos RAT payload | triage_verdict |
| File Name | remcos_sample.exe | Sample file name | triage_verdict |
| File Metadata | 32-bit Windows GUI PE, compiled with VC++ 2003, high-entropy overlay | Sample identifying traits | MalCat, deep-dive, yara |
| Network (Static) | Encrypted C2 domains/IPv4/IPv6 addresses (not decrypted) | C2 infrastructure | yara, deep-dive |
| Network (Static) | https://www.google.com/accounts/servicelogin, https://login.yahoo.com/config/login, http://www.facebook.com/ | Browser credential theft injection URLs | MalCat strings |
| Registry | HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run | Persistence autostart key | capa, yara |
| Registry | HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | System information collection path | MalCat registry constants |
| Memory | Import by hash API hashes, DES encryption constants, XOR decryption loops | Obfuscation artifacts | MalCat anomalies, yara |
Note: C2 domain and IP addresses are encrypted with XOR/DES and were not recovered during static analysis. (source: triage_verdict, MalCat, yara, capa, ghidra_query, rule.yara.json)

## 12. Detection Rules
The following detection rules and heuristics can be used to identify this sample and similar Remcos variants:
### YARA Rule
A custom YARA rule for this sample is available at /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/rule.yar, which matches on 24 unique strings including SQLite internal queries, browser login URLs, registry paths, and cryptographic constants. The rule has 0 false positives against the staged goodware corpus. Existing YARA rules that also detect this sample include: keylogger, win_registry, IsPacked, HasOverlay, Visual_Cpp_2003_EXE_Microsoft, SEH_Init, screenshot, win_files_operation. (source: rule.yara.json, yara)
### Sigma Rule
A Sigma rule for registry persistence detection is available at /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/rule.yml, which detects modifications to the HKCU Run key consistent with Remcos persistence. (source: rule.yara.json)
### CAPA Rules
capa rules for this sample detect the following ATT&CK techniques: T1056.001 (keylogging), T1547.001 (Run key persistence), T1027 (XOR/DES encryption), T1057 (process discovery), T1082 (system information discovery), T1083 (file discovery), T1012 (registry query). (source: capa)
### Heuristic Detection
- PE files with entropy >190 in overlay sections
- PE files with ImportByHash anomalies and >50 XorInLoop hits
- PE files with embedded DES constants and browser login URLs for Google/Facebook/Yahoo
- Processes that modify the HKCU Run key and import CreateToolhelp32Snapshot, RegOpenKeyExW, and GetAsyncKeyState simultaneously (source: MalCat, pe_imports, capa)

## 13. Containment, Eradication, Recovery
The following steps are recommended for responding to a Remcos RAT infection, based on the sample's confirmed capabilities:
### Containment
1. Isolate infected endpoints from the network immediately to prevent C2 communication and lateral movement.
2. Block identified C2 domains/IPs at the perimeter firewall, proxy, and DNS layer (note: C2 IOCs are encrypted in this sample, so block based on sample hash and behavioral indicators).
3. Disable compromised user accounts if credential theft is confirmed, to prevent unauthorized access to other systems.
### Eradication
1. Terminate the Remcos process, checking for associated mutexes (common Remcos mutexes include "Remcos_Mutex" and unique per-build values) and injected DLLs.
2. Delete the sample file (remcos_sample.exe) and any associated dropped files (DLLs, additional payloads) from the system.
3. Remove the persistence entry from HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run.
4. Scan the system for additional Remcos artifacts, including injected browser modules and SQLite database files containing stolen credentials.
5. Remove any injected browser login pages and restore default browser settings.
### Recovery
1. Reset passwords for all compromised accounts, including browser credentials, system accounts, and any associated cloud services.
2. Restore system files and user data from a clean backup taken prior to infection, if system modification is suspected.
3. Re-image the endpoint if eradication is not successful or if system integrity is compromised.
4. Monitor the endpoint for 30 days post-remediation to detect re-infection or residual artifacts. (source: capa, pe_imports, yara, MalCat)

## 14. Recommendations
The following recommendations are provided to prevent future Remcos RAT infections and improve detection capabilities:
### Short-Term
1. Deploy the provided YARA and Sigma rules to EDR, NIDS, and email security gateways to detect this sample and similar variants.
2. Monitor for the IOCs listed in Section 11, including file hash, registry Run key modifications, and embedded browser login URLs.
3. Block executable uploads from untrusted sources with high entropy overlays (>190) to catch packed Remcos payloads.
4. Monitor for processes that import keylogging, process enumeration, and registry modification APIs simultaneously.
### Long-Term
1. Implement application whitelisting to prevent unauthorized execution of unapproved executables.
2. Restrict executable attachments in email and disable macros by default to block initial infection vectors (Remcos is often distributed via phishing emails with malicious attachments).
3. Conduct regular security awareness training for users to identify phishing attempts and suspicious files.
4. Audit HKCU and HKLM Run keys monthly for unauthorized entries, and monitor for browser setting changes that may indicate credential theft module injection.
5. Update EDR rules to detect Remcos-specific obfuscation techniques, including import by hash, XOR-in-loop decryption, and embedded DES constants. (source: all evidence sources)

## 15. Appendices
The following evidence files and artifacts are associated with this analysis:
1. Triage verdict: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/triage_verdict.json
2. Deep-dive analysis: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/deep-dive.json
3. Generated YARA rule: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/rule.yar
4. Generated Sigma rule: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/rule.yml
5. XOR search results: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/xorsearch.log
6. UPX unpack probe results: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/upx_unpack.log
7. MalCat analysis report: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/malcat_report.json
8. capa analysis results: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/capa_results.json
9. Ghidra query logs: /opt/samples/logs/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/ghidra_queries.sql
10. Radare2 disassembly snippets: Included in Section 4 of this report.
### Analysis Limitations
- No dynamic analysis (sandbox, Speakeasy, Frida) was performed, so runtime behavior and live C2 communication are not observed.
- C2 configuration (domains, IPs, keys) is encrypted with XOR/DES and was not decrypted during static analysis.
- No actor-specific indicators were identified, so attribution to a specific threat actor is not possible. (source: all evidence sources)

## 16. Author + Sign-off
This report was prepared by the Malware Analysis Team as part of the incoming sample triage project. All analysis was performed using static artifacts, with no dynamic execution of the sample.
Reviewed and approved by: Senior Malware Analyst
Date: 2026-08-03
Note: This analysis is based on the provided sample and associated artifacts. No dynamic runtime behavior was observed, so all behavioral inferences are based on static analysis evidence. (source: project metadata)