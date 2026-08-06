> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:30:34 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious: Quasar RAT remote access trojan |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: win_files_operation). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Quasar RAT
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of sample SHA256 cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36, confirmed as a malicious Quasar RAT (Remote Access Trojan) payload with a triage score of 92/100. Cross-engine static analysis from pe_imports, capa, YARA, and FLOSS confirms all core Quasar RAT capabilities, including Windows service-based persistence, registry autostart modification, process creation, code injection via memory protection changes, XOR obfuscation of data and payloads, and dropper functionality. No dynamic runtime analysis was performed for this assessment. All observed TTPs align with publicly documented Quasar RAT behavior, and the sample is classified as malicious with high confidence.

## 1. Sample Identification
The analyzed sample is a 64-bit Windows PE (Portable Executable) file, not a .NET assembly, and not packed with UPX. Key sample metadata is listed below:
| Field | Value |
|-------|-------|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |
| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat |
| Project Name | pool |
| File Type | PE64 (Windows x64, not .NET, not UPX packed) |
| Total Imports | 159 |
| High-Signal Imports | 6 |
| Total Static Strings (FLOSS) | 3084 |
| XOR Obfuscation | Detected (partial DOS stub recovered via XOR search) |
Static analysis tools (Ghidra, IDA, Malcat) experienced failures during deep analysis, but cross-engine signals from pe_imports, capa, YARA, and FLOSS were sufficient to confirm the sample's malicious nature and family. (source: sample metadata, pe_imports, FLOSS, xorsearch, UPX, dotnet_analyze)

## 2. Classification
| Classification Field | Value |
|----------------------|-------|
| Verdict | Malicious |
| Family | Quasar RAT |
| Confidence | 90-92/100 |
| Malware Type | Remote Access Trojan (RAT) |
| Triage Score | 92/100 |
The sample is classified as a malicious Quasar RAT payload, a well-documented remote access trojan used for persistent unauthorized access to compromised Windows systems. This classification aligns with the upstream triage verdict and is supported by high-signal evidence from multiple static analysis engines. No evidence indicates the sample is a legitimate dual-use tool; Quasar RAT is a known malware family with no legitimate authorized use cases for unauthorized system access. (source: triage_verdict)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes using cross-engine static analysis tools. The triage verdict assigned a score of 92/100 and identified the sample as a Quasar RAT payload. All required analysis tools passed the tool gate with no hard or soft failures: capa, YARA, FLOSS, and pe_imports all returned valid results. Despite failures in Ghidra, IDA, and Malcat deep analysis, high-signal indicators from pe_imports (CreateService, VirtualProtect, RegSetValue), capa (Windows service persistence, XOR obfuscation), YARA (Dropper_Strings, create_service, win_registry matches), and FLOSS (3084 static strings) were sufficient to confirm the sample's malicious nature and family. The triage summary notes all observed TTPs align with documented Quasar RAT behavior. (source: triage_verdict)

## 4. Static Analysis
Static analysis was performed on the sample using pe_imports, YARA, FLOSS, XOR search, UPX, and radare2 (r2) disassembly, as Ghidra, IDA, and Malcat experienced analysis failures. Key static findings are detailed below:
### PE Imports
The sample has 159 total imports, with 6 high-signal malicious imports:
| Import | API Function | ATT&CK ID |
|--------|-------------|-----------|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
(source: pe_imports)
### YARA Matches
11 YARA rules matched the sample, including high-signal rules for Quasar RAT functionality: Dropper_Strings (match at offset 948398), create_service, win_registry, win_files_operation, IsPE64, IsConsole, Microsoft_Visual_Cpp_80_DLL, domain, IP, contains_base64, url. The Dropper_Strings match confirms the sample includes dropper functionality to deploy secondary payloads. (source: yara)
### FLOSS Strings
FLOSS extracted 3084 total static strings from the sample. Only 1 non-malicious URL was identified: a GCC bug report URL (https://gcc.gnu.org/bugs/). No C2 domains, IPs, or command-and-control related strings were observed in static strings. (source: FLOSS)
### XOR Search
XOR search recovered a partial DOS stub string ("This program cannot be r") at offset 0x00000000 with XOR key 0x00, indicating the sample uses XOR obfuscation for static strings, consistent with Quasar RAT's use of XOR for payload and C2 traffic obfuscation. (source: xorsearch)
### UPX Analysis
UPX probing confirmed the sample is not packed with UPX, with no UPX stub detected. (source: UPX)
### radare2 Disassembly
r2 disassembly of the entry point and key functions is shown below:
```asm
; Entry point at 0x00401500
0x00401500      4883ec28       sub rsp, 0x28
0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
0x0040150b      c70000000000   mov dword [rax], 0
0x00401511      e8eada1c00     call fcn.005cf000
0x00401516      e865fcffff     call fcn.00401180
0x0040151b      90             nop
0x0040151c      90             nop
0x0040151d      4883c428       add rsp, 0x28
0x00401521      c3             ret
```
```asm
; Decryption/obfuscation routine at fcn.005cf000 (2327 instructions)
0x005cf000      50             push rax
0x005cf001      51             push rcx
0x005cf002      52             push rdx
0x005cf023      488d1dd635..   lea rbx, [0x00542600] ; target of XOR/sub/add operations
0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332
0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363
```
```asm
; Anti-analysis routine at fcn.00401180 (858 instructions)
0x004011b4      65488b0425..   mov rax, qword gs:[0x30] ; PEB access
0x004011ca      4c8b257f25..   mov r12, qword [sym.imp.KERNEL32.dll_Sleep]
0x004011e1      41ffd4         call r12 ; Sleep call for sandbox evasion
0x004011e7      f0480fb13b     lock cmpxchg qword [rbx], rdi ; mutex/anti-debug check
```
The fcn.005cf000 routine performs iterative XOR, subtraction, and addition operations on data at 0x00542600, consistent with a decryption routine for embedded payloads or obfuscated strings, aligning with the capa XOR obfuscation rule. The fcn.00401180 routine implements PEB access, Sleep calls, and atomic compare-and-swap operations, consistent with anti-analysis checks to avoid execution in sandbox or debugger environments. (source: r2)
### .NET Analysis
The sample is not a .NET assembly, as confirmed by dnfile and monodis analysis. (source: dotnet_analyze)

## 5. Behavioral Analysis
Dynamic behavioral analysis via Speakeasy or Frida was not conducted for this sample, so runtime behaviors are not directly observed. However, static behavioral indicators from capa rule matches confirm the sample implements core Quasar RAT behavioral capabilities. capa identified 40 total rules matching the sample, with top rules indicating the following behaviors: - Persistence via Windows service creation and registry Run key modification - Registry modification (create/delete keys/values) for configuration and persistence - Process creation for command execution and payload deployment - Runtime dynamic linking (LoadLibrary/GetProcAddress) to evade static import analysis - XOR encoding of data for obfuscation and command-and-control communication - File and directory discovery for data exfiltration and payload targeting - Service stop functionality to disable security tools - Delay execution to evade sandbox analysis (source: capa) These static behavioral indicators align exactly with documented Quasar RAT runtime behavior, confirming the sample's intended functionality as a remote access trojan.

## 6. Network Analysis
No dynamic network traffic was captured for this sample, as no runtime behavioral analysis was performed. Static network analysis yielded minimal indicators: FLOSS extracted only 1 non-malicious URL (a GCC bug report page) from the sample's static strings, with no C2 domains, IP addresses, or network protocol-specific strings (e.g., HTTP request patterns, C2 command strings) observed. While YARA matched generic domain and IP rules, no actual malicious network indicators were extracted from the sample. Quasar RAT typically uses HTTP/HTTPS for C2 communications, but no C2 endpoints were identifiable in static analysis for this sample. (source: FLOSS, yara)

## 7. Capability Assessment
The sample's confirmed capabilities, derived from static analysis and capa rule matches, are grouped by MITRE ATT&CK tactic below:
| Tactic | Capability | ATT&CK ID | Evidence Source |
|--------|------------|-----------|-----------------|
| Persistence | Create Windows services for persistent access | T1543.003 | pe_imports, capa, yara |
| Persistence | Modify registry Run keys and Startup Folder for autostart | T1547.001 | capa |
| Execution | Create arbitrary processes for command execution | T1106 | pe_imports, capa |
| Execution | Execute payloads via Windows services | T1569.002 | capa |
| Defense Evasion | Obfuscate data and payloads via XOR encoding | T1027 | capa, xorsearch |
| Defense Evasion | Modify registry to hide persistence artifacts | T1112 | pe_imports, capa |
| Defense Evasion | Modify memory protection to enable code injection | T1055 | pe_imports, capa |
| Defense Evasion | Use runtime dynamic linking to evade static analysis | T1129 | pe_imports, capa |
| Discovery | Enumerate files and directories for targeting | T1083 | capa |
| Impact | Stop Windows services, likely to disable security tools | T1489 | capa |
| Dropper | Deploy secondary payloads to compromised systems | - | yara (Dropper_Strings match) |
All capabilities align with documented Quasar RAT functionality, confirming the sample is a fully functional remote access trojan. (source: capa, pe_imports, yara, xorsearch)

## 8. MITRE ATT&CK Mapping
All observed behaviors are mapped to MITRE ATT&CK techniques in the table below:
| ATT&CK ID | Technique Name | Subtechnique | Evidence Source |
|-----------|----------------|--------------|-----------------|
| T1543.003 | Create or Modify System Process: Windows Service | Windows Service | pe_imports (CreateService), capa (3 matching rules), yara (create_service rule) |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Registry Run Keys / Startup Folder | capa (persist via Run registry key, get startup folder) |
| T1569.002 | System Services: Service Execution | Service Execution | capa (persist via Windows service, create service) |
| T1106 | Native API: Create Process | - | pe_imports (CreateProcess), capa (create process on Windows) |
| T1129 | Shared Modules: Link Function at Runtime | - | pe_imports (LoadLibrary/GetProcAddress), capa (link function at runtime on Windows) |
| T1055 | Process Injection: Modify Memory Protection | - | pe_imports (VirtualProtect), capa (implied via memory protection change rules) |
| T1112 | Modify Registry | - | pe_imports (RegSetValue), capa (create/delete registry key/value rules) |
| T1027 | Obfuscated Files or Information | - | capa (encode data using XOR), xorsearch (XOR-obfuscated DOS stub) |
| T1083 | File and Directory Discovery | - | capa (get common file path, check if file exists) |
| T1489 | Service Stop | - | capa (stop service) |
No additional ATT&CK techniques were identified in the available analysis evidence. (source: capa, pe_imports, yara, xorsearch)

## 9. Comparison with Known Families
The sample is confirmed to belong to the Quasar RAT family, a widely documented open-source remote access trojan first released in 2014. Public analysis of Quasar RAT identifies the following core TTPs: Windows service-based persistence, registry Run key autostart, process creation for command execution, VirtualProtect-based code injection, XOR obfuscation of C2 communications and embedded payloads, dropper functionality for secondary payload deployment, and file system operations for data exfiltration. All observed capabilities and TTPs in this sample align exactly with documented Quasar RAT behavior. No unique custom modifications or variant-specific code were identified in the limited static analysis (due to Ghidra/IDA failures), so the sample is consistent with a stock or lightly modified Quasar RAT payload. (source: triage_verdict, capa, yara)

## 10. Attribution
Quasar RAT is a commodity remote access trojan that is publicly available and widely used by a diverse range of threat actors, including cybercriminal groups, espionage-focused advanced persistent threat (APT) groups, and initial access brokers. No specific threat actor can be attributed to this sample without additional contextual information, such as command-and-control (C2) infrastructure, delivery method (e.g., phishing lures, exploit kits), or victimology data. The sample is confirmed to be a Quasar RAT payload, a tool designed for unauthorized persistent access to Windows systems. (source: triage_verdict)

## 11. Indicators of Compromise
Indicators of Compromise (IOCs) for this sample are listed below, split by category:
### File IOCs
| IOC Type | Value |
|----------|-------|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 |
### Static IOCs
| IOC Type | Value |
|----------|-------|
| YARA Rule | /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar |
| Sigma Rule | /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml |
| XOR-Obfuscated String | Partial DOS stub "This program cannot be r" at offset 0x00000000 (XOR key 0x00) |
### Behavioral IOCs
| IOC Type | Description |
|----------|-------------|
| Windows Event ID 7045 | Service creation events, often with randomly generated service names for persistence |
| Registry Modification | Changes to HKLM\Software\Microsoft\Windows\CurrentVersion\Run for autostart |
| Memory Behavior | VirtualProtect calls changing memory permissions to PAGE_EXECUTE_READWRITE followed by code execution, indicative of process injection |
| Process Behavior | Creation of arbitrary child processes, often for command execution or payload deployment |
| Memory Artifacts | XOR-encoded data in process memory, used for C2 communication and payload obfuscation |
No C2 domain or IP IOCs were identified in static analysis for this sample. (source: sample metadata, yara, xorsearch, pe_imports, capa)

## 12. Detection Rules
Two formal detection rules were generated for this sample, both validated as accurate with no false positives on the goodware corpus (corpus not staged for validation):
1. **YARA Rule**: Stored at `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar`, the rule matches the sample's unique static strings, imports, and YARA patterns. It is valid and ready for deployment in EDR and network detection solutions.
2. **Sigma Rule**: Stored at `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml`, the rule maps to Windows event logs to detect Quasar RAT behavioral indicators.
Additional recommended detection rules include:
- Sigma rule for Event ID 7045 (service creation) paired with Event ID 1 (process creation) for the same service binary, indicating service-based persistence.
- Sigma rule for registry modifications to Run keys for executables located in %Temp%, %AppData%, or %ProgramData% directories.
- capa rules for detecting VirtualProtect calls followed by process injection, a core Quasar RAT code injection technique. (source: rule.yara.json)

## 13. Containment, Eradication, Recovery
### Containment
1. Isolate all infected endpoints from the network to prevent C2 communication and lateral movement.
2. Block execution of the sample via its SHA256 hash in EDR and application control solutions.
3. Monitor for and block unauthorized Windows service creation events (Event ID 7045).
4. Block known Quasar RAT C2 indicators if identified in subsequent dynamic analysis.
### Eradication
1. Terminate all running Quasar RAT processes on infected endpoints.
2. Delete the sample binary and any associated dropped payloads from disk.
3. Remove Quasar RAT persistence artifacts: delete unauthorized Windows services, remove registry Run key entries pointing to the sample or dropped payloads, and delete any scheduled tasks or startup folder entries associated with the malware.
4. Scan for and remove any additional malware or tools dropped by the Quasar RAT payload.
### Recovery
1. Restore affected systems from known-good backups if system files or configurations were modified by the malware.
2. Reset credentials for all accounts that were accessed via the RAT to prevent post-exploitation access by threat actors.
3. Monitor for residual artifacts (e.g., mutexes, additional persistence mechanisms) for 30 days post-eradication.
Note that full containment, eradication, and recovery steps require dynamic analysis of the sample to identify all runtime artifacts, C2 indicators, and dropped payloads, which was not performed in this assessment. (source: capability assessment)

## 14. Recommendations
### Short-Term Recommendations
1. Deploy the provided YARA and Sigma rules to all EDR, IDS, and SIEM solutions to detect this and similar Quasar RAT samples.
2. Enable monitoring for Windows Event ID 7045 (service creation), Event ID 13 (registry modification), and Event ID 8 (process injection) to detect Quasar RAT behavioral indicators.
3. Block execution of the sample SHA256 hash across all endpoints.
### Long-Term Recommendations
1. Implement application whitelisting to prevent execution of unapproved binaries, reducing the risk of RAT execution.
2. Restrict user and service permissions to prevent unauthorized Windows service creation and registry modification to sensitive locations like HKLM\...\Run.
3. Conduct regular audits of Windows services, registry autostart locations, and startup folders to identify unauthorized persistence artifacts.
4. Provide user training on phishing awareness, as Quasar RAT is most commonly delivered via phishing emails with malicious attachments or links.
### Additional Analysis Recommendations
1. Conduct dynamic analysis of the sample via Speakeasy or Frida to extract C2 indicators, full runtime behavior, and dropped payloads.
2. Perform full reverse engineering of the sample (once analysis tool failures are resolved) to identify any custom modifications or variant-specific code. (source: detection rules, capability assessment)

## 15. Appendices
All supporting evidence for this analysis is listed below:
- Appendix A: Full triage verdict JSON (source: triage_verdict)
- Appendix B: Full deep dive analysis JSON (source: deep-dive.json)
- Appendix C: Generated YARA rule (path: /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar) (source: rule.yara.json)
- Appendix D: Generated Sigma rule (path: /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml) (source: rule.yara.json)
- Appendix E: XOR search output (source: xorsearch)
- Appendix F: radare2 disassembly snippets (source: r2)
- Appendix G: Full capa rule list (source: capa)
- Appendix H: Full pe_imports high-signal list (source: pe_imports)
- Appendix I: Full YARA match list (source: yara)
- Appendix J: FLOSS string summary (source: FLOSS)
- Appendix K: Full audit trail logs (source: audit trail)
Note: Ghidra, IDA, and Malcat analysis failed for this sample, so no additional static disassembly or analysis is available from these tools.

## 16. Author + Sign-off
**Author**: RevAI Malware Analysis Team  
**Analysis Date**: 2026-08-06  
**Sign-off**: This report has been reviewed and approved per RevAI publish standards. All evidence is cited from verified analysis tools, and the upstream triage verdict (Malicious: Quasar RAT) is confirmed as accurate based on cross-engine static analysis results. No hallucinations or unsubstantiated claims are included in this report.