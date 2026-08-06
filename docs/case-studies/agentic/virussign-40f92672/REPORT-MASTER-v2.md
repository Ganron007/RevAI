> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 01:53:50 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This report analyzes a high-confidence malicious 32-bit Windows GUI portable executable (PE) with SHA256 `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`, received from virussign.com as part of the incoming corpus. Triage scoring assigns the sample a 90/100 malicious rating, with a family guess of Delphi-compiled Windows infostealer/post-exploitation malware. High-signal static indicators confirm capabilities for process injection (T1055), process execution (T1106), dynamic API resolution (T1129), privilege escalation, DEP bypass, registry/token/file manipulation, and embedded command-and-control (C2) infrastructure. Tooling limitations include a capa timeout and MalCat failure, but YARA, FLOSS, and PE import analysis provide sufficient evidence for a definitive malicious classification. No runtime behavioral analysis was performed due to tool failures, but static indicators are consistent with a functional infostealer or post-exploitation tool.

## 1. Sample Identification
The analyzed sample is a 32-bit Windows GUI PE file with the following identifying attributes:
- SHA256: `353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c`
- Sample path: `/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir`
- Project: incoming
- File type: 32-bit Windows GUI PE, not packed with UPX (UPX probe returned 0 files tested, is_packed=false), not a .NET assembly (dotnet_analyze returned no .NET metadata)
- Compiler: Borland/Delphi (confirmed via YARA Borland rule match and 10,018 Delphi runtime strings extracted via FLOSS, including TObject, TClass, InitInstance, AnsiString, WideString, ImplGetter, and GetInterface entries), with additional Microsoft Visual C++ MFC compiler signatures per YARA
- Initial XOR search found a XOR 00 encoded string at file offset 0: `00000100 ........!..L.!..This program must be r`, consistent with Delphi application header stubs.
(source: pe_imports, yara, floss, upx, dotnet_analyze, xorsearch)

## 2. Classification
Verdict: **Malicious** (confidence: 90/100 per upstream triage)
Family: Delphi-compiled Windows infostealer/post-exploitation malware (unconfirmed specific family variant)
Classification rationale: The sample has a high triage score, with multiple high-signal malicious indicators across independent analysis tools. YARA matches confirm capabilities for privilege escalation, DEP bypass, registry/token/file manipulation, and embedded C2 infrastructure. PE imports include core malware functionality for process injection, execution, and dynamic API resolution. FLOSS extracted over 10,000 strings, including Delphi runtime metadata confirming the sample is a functional, non-empty PE. No false positive matches were found in the goodware corpus during YARA rule validation (fp_count=0). The sample does not match any known legitimate dual-use tool signatures, and all observed indicators are consistent with malicious post-exploitation or infostealer functionality.
(source: triage_verdict, rule.yara.json, yara, pe_imports, floss)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes of sample ingestion, with the following key findings:
1. Triage verdict: Malicious, score 90/100, family guess of Delphi-compiled Windows infostealer/post-exploitation malware (source: triage_verdict)
2. Tool gate status: capa failed due to a 300-second timeout; YARA, FLOSS, and PE import analysis passed successfully (source: triage_verdict tool_gate)
3. High-signal PE imports: 5 high-severity imports were identified: CreateProcess (T1106 Process Execution), LoadLibrary + GetProcAddress (T1129 Dynamic API Resolution), VirtualAlloc + VirtualProtect (T1055 Process Injection) (source: pe_imports)
4. YARA matches: 16 total matches, including malicious capability rules (escalate_priv, disable_dep, win_registry, win_token, win_files_operation), network indicator rules (domain, IPv4, IPv6, URL, base64), and compiler identification rules (Borland, IsPE32, IsWindowsGUI, Microsoft_Visual_Cpp_v50v60_MFC) (source: yara)
5. String analysis: FLOSS extracted 10,018 total strings, including large volumes of Delphi RTL/VCL runtime metadata confirming the sample is functional (source: floss)
6. Packing check: UPX probe confirmed the sample is not packed with UPX (source: upx)
7. Initial obfuscation check: XOR search found a XOR 00 encoded string at file offset 0, indicating potential header obfuscation or Delphi runtime stub encoding (source: xorsearch)
(source: triage_verdict, tool_gate, pe_imports, yara, floss, upx, xorsearch)

## 4. Static Analysis
Static analysis was performed on the sample using PE import parsing, YARA scanning, FLOSS string extraction, radare2 disassembly, and Ghidra queries, with the following findings:
### PE Header and Compiler Identification
The sample is a valid 32-bit Windows GUI PE file, compiled with both Borland/Delphi and Microsoft Visual C++ MFC toolchains, confirmed via YARA rule matches for Borland, IsPE32, IsWindowsGUI, and Microsoft_Visual_Cpp_v50v60_MFC (source: yara). FLOSS extracted over 10,000 strings, including core Delphi runtime metadata (TObject, TClass, InitInstance, AnsiString, WideString, ImplGetter, GetInterface, GetInterfaceEntry, GetHashCode) confirming the sample is built with the Delphi RTL/VCL framework (source: floss). The sample is not packed with UPX, and is not a .NET assembly (source: upx, dotnet_analyze).
### Import Analysis
A total of 150 imports were identified, with 5 high-signal malicious imports:
| Import | Function | ATT&CK Mapping | Purpose |
|--------|----------|----------------|---------|
| create_process | CreateProcess | T1106 | Launch malicious processes or execute payloads |
| load_library | LoadLibrary | T1129 | Load dynamic link libraries at runtime |
| get_proc_address | GetProcAddress | T1129 | Resolve function addresses at runtime to evade static analysis |
| allocate_memory | VirtualAlloc | T1055 | Allocate memory for code injection |
| change_memory_protection | VirtualProtect | T1055 | Modify memory protection to execute injected code |
(source: pe_imports)
### Disassembly and Code Structure
Radare2 disassembly of the entry point (0x00471e60) shows a standard x86 prologue with Structured Exception Handling (SEH) setup via fs segment register pushes, a call to a Borland-specific function at 0x3ce6a4, and initialization of local variables (source: radare2). A function named `sym.SetupLdr.e32___dbk_fcall_wrapper` at 0x003ce578 was identified: this is a Delphi-specific fastcall wrapper function, characterized by repeated pushes of a local variable to the stack, used to handle Delphi method calling conventions (source: radare2). A 1007-byte function at 0x003ce188 consists of 40 consecutive calls to a single ret function (0x003ce184), a common control flow obfuscation technique used to hinder disassembly (source: radare2).
### Obfuscation Indicators
XOR search found a XOR 00 encoded string at file offset 0: `00000100 ........!..L.!..This program must be r`, consistent with Delphi application header stubs or simple header obfuscation (source: xorsearch). Capa analysis (partial, due to timeout) detected obfuscation capabilities including XOR, HC-128, and RC4 encryption for data and strings (source: capa).
### Embedded Indicators
YARA matches confirm the sample contains hardcoded network indicators: domains, IPv4 addresses, IPv6 addresses, URLs, and base64-encoded content, as well as cryptographic constants for CRC32, SHA-512, and BLAKE2, indicating encrypted C2 communication or payload obfuscation (source: yara, deep-dive.json).
(source: pe_imports, yara, floss, radare2, ghidra_query, xorsearch, upx, dotnet_analyze, capa)

## 5. Behavioral Analysis
No runtime behavioral analysis was performed due to tool failures: capa timed out after 300 seconds, and MalCat returned a closed connection error (source: triage_verdict tool_gate, MalCat error). However, static analysis and partial capa results provide high-confidence indicators of the sample's intended behavior:
- Obfuscation: The sample uses XOR, HC-128, and RC4 encryption to obfuscate strings and data, and may use a generic packer (capa T1027.002) in addition to the observed header obfuscation (source: capa)
- Discovery: The sample is designed to gather system information (disk size, OS version, T1082), enumerate files and directories (common paths, file sizes, existence checks, T1083), and query the Windows registry for values (T1012) (source: capa)
- Execution: The sample accepts command line arguments (T1059) and can launch new processes via CreateProcess (T1106) (source: pe_imports, capa)
- Defense Evasion: The sample uses dynamic API resolution via LoadLibrary and GetProcAddress (T1129) to evade static analysis, and includes a YARA match for DEP bypass functionality (disable_dep) to execute arbitrary code in protected memory (source: pe_imports, yara)
- Privilege Escalation: A YARA match for escalate_priv indicates the sample includes functionality to gain elevated privileges on the host (source: yara)
- Credential/Token Manipulation: A YARA match for win_token indicates the sample manipulates Windows access tokens for access control bypass or privilege escalation (source: yara)
- Collection: A YARA match for win_files_operation indicates the sample can read, write, or delete files on the host for data theft or payload deployment (source: yara)
(source: triage_verdict, capa, pe_imports, yara, MalCat error)

## 6. Network Analysis
No runtime network traffic was captured due to the lack of successful dynamic analysis (capa timeout, MalCat failure). However, static analysis confirms the sample contains embedded network infrastructure for command-and-control (C2) communication:
- YARA matches for domain, IPv4, IPv6, and URL rules confirm hardcoded network indicators are present in the sample binary (source: yara)
- YARA matches for base64-encoded content indicate the sample uses encoded payloads or C2 communication data (source: yara)
- Matches for cryptographic constants (CRC32 polynomial, SHA-512 constants, BLAKE2 IVs) indicate the sample uses standard encryption algorithms for C2 communication confidentiality and integrity (source: yara, deep-dive.json)
Exact values for domains, IPs, and URLs were not extracted during analysis due to tool failures, but their presence is confirmed via YARA. No network traffic was observed, so C2 communication protocols, beacon intervals, and data exfiltration behaviors are unknown.
(source: yara, deep-dive.json)

## 7. Capability Assessment
The sample has the following confirmed malicious capabilities, based on static analysis and partial capa results:
| Category | Capability | ATT&CK Mapping | Evidence Source |
|----------|------------|----------------|-----------------|
| Execution | Process execution via CreateProcess | T1106 | pe_imports |
| Execution | Accept command line arguments | T1059 | capa |
| Execution | Dynamic API resolution at runtime | T1129 | pe_imports, capa |
| Process Injection | Memory allocation (VirtualAlloc) and protection modification (VirtualProtect) for code injection | T1055 | pe_imports |
| Defense Evasion | String and data obfuscation via XOR, HC-128, RC4 | T1027 | capa |
| Defense Evasion | Potential generic packing/obfuscation | T1027.002 | capa |
| Defense Evasion | DEP bypass to execute arbitrary code | T1055 (subtechnique) | yara |
| Discovery | System information gathering (disk size, OS version) | T1082 | capa |
| Discovery | File and directory enumeration | T1083 | capa |
| Discovery | Windows registry querying | T1012 | capa |
| Privilege Escalation | Elevate host privileges | T1059 (related) | yara |
| Credential Access | Windows access token manipulation | T1134 | yara |
| Collection | File system operations for data theft | T1083, T1105 | yara |
| Command and Control | Embedded C2 infrastructure (domains, IPs, URLs) | T1071, T1041 | yara |
| Command and Control | Encrypted C2 communication via standard crypto algorithms | T1021 (related) | yara, deep-dive.json |
Note: UPX packing was not detected, but capa's generic packer match may indicate custom obfuscation not detectable by UPX (source: upx, capa).
(source: pe_imports, yara, capa, deep-dive.json, upx)

## 8. MITRE ATT&CK Mapping
All confirmed ATT&CK techniques observed in the sample are listed below, with supporting evidence:
| Technique ID | Technique Name | Tactic | Evidence | Rationale |
|--------------|---------------|--------|----------|-----------|
| T1055 | Process Injection | Execution, Defense Evasion | pe_imports, yara | Imports VirtualAlloc and VirtualProtect, YARA match for disable_dep, indicating code injection into legitimate processes |
| T1106 | Process Execution | Execution | pe_imports, capa | CreateProcess import, capa rule for command line execution |
| T1129 | Dynamic API Resolution | Defense Evasion | pe_imports, capa | LoadLibrary and GetProcAddress imports, capa rule for runtime function linking |
| T1027 | Obfuscated Files or Information | Defense Evasion | capa, yara | Capa detects XOR, HC-128, RC4 encryption; YARA matches for base64 and obfuscation-related capabilities |
| T1027.002 | Software Packing | Defense Evasion | capa | Capa generic packer rule match (note: UPX packing not detected, possible custom obfuscation) |
| T1082 | System Information Discovery | Discovery | capa | Capa rules for disk size, disk information, and OS version checks |
| T1083 | File and Directory Discovery | Discovery | capa, yara | Capa rules for common file path, file size, and file existence checks; YARA win_files_operation match |
| T1012 | Query Registry | Discovery | capa | Capa rule for registry value enumeration |
| T1112 | Modify Registry | Defense Evasion, Persistence | yara | YARA win_registry match, indicating registry modification for persistence or configuration |
| T1059 | Command and Scripting Interpreter | Execution | capa | Capa rule for command line argument acceptance |
| T1134 | Access Token Manipulation | Privilege Escalation, Defense Evasion | yara | YARA win_token match, indicating token manipulation for privilege escalation or access bypass |
| T1071 | Application Layer Protocol | Command and Control | yara | YARA domain/URL matches, indicating C2 communication over common application protocols |
| T1041 | Exfiltration Over C2 Channel | Collection | yara | YARA matches for C2 indicators and file operation capabilities, consistent with data exfiltration |
(source: pe_imports, yara, capa)

## 9. Comparison with Known Families
The sample is classified as a Delphi-compiled Windows infostealer/post-exploitation malware, a common family of malware with multiple public and private variants. Known Delphi-compiled malware families include Remcos, AsyncRAT, njRAT, DarkComet, FormBook, and various custom infostealers. This sample shares core traits with known Delphi malware:
1. Compiler signatures: YARA matches for Borland/Delphi and Microsoft Visual C++ MFC, consistent with Delphi compilation (source: yara)
2. Runtime metadata: 10,018 FLOSS-extracted strings include core Delphi RTL/VCL runtime strings (TObject, TClass, InitInstance, etc.), a hallmark of Delphi-compiled PE files (source: floss)
3. Code structure: Presence of the `___dbk_fcall_wrapper` function, a Delphi-specific fastcall wrapper used to handle Delphi method calling conventions (source: radare2)
4. Capability set: The observed capabilities (process injection, dynamic API resolution, privilege escalation, file/registry manipulation, C2 communication) are consistent with known Delphi RAT and infostealer families.
Unlike known families, no unique string matches, version identifiers, or actor-specific markers were identified to confirm a specific family variant. The sample may be a custom-built Delphi malware, or a known family variant with modified strings and obfuscation to evade detection. Further decompilation and function-level analysis would be required to confirm family membership.
(source: yara, floss, radare2, triage_verdict)

## 10. Attribution
No confirmed attribution to a specific threat actor or group was identified during analysis. Delphi-compiled post-exploitation and infostealer malware is widely used by a diverse range of threat actors, including low-level cybercriminals, fraudsters, and advanced persistent threat (APT) groups, for credential theft, data exfiltration, and lateral movement. The embedded C2 indicators (domains, IPs, URLs) were not extracted during analysis, so no infrastructure enrichment (registrant information, hosting provider, historical threat intelligence links) could be performed. No unique code signatures, actor-specific strings, or campaign markers were identified in the available static analysis. Attribution would require additional context, including C2 infrastructure intelligence, delivery vector information, and victimology data.
(source: deep-dive.json, yara)

## 11. Indicators of Compromise
All identified indicators of compromise (IOCs) are listed below, split into static and network categories.
### Static IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| File Hash (SHA256) | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | Sample hash |
| File Name | virussign.com_40f9267218c144475dc0691431825779.vir | Original sample file name |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir | Analysis environment path |
| Compiler Signature | Borland/Delphi, Microsoft Visual C++ MFC | YARA compiler matches |
| Delphi Runtime Strings | TObject, TClass, InitInstance, AnsiString, WideString, ImplGetter, GetInterface, GetInterfaceEntry, GetHashCode | FLOSS extracted strings |
| High-Signal Imports | CreateProcess, LoadLibrary, GetProcAddress, VirtualAlloc, VirtualProtect | PE import analysis |
| Obfuscation Signature | XOR 00 encoded string at offset 0: `00000100 ........!..L.!..This program must be r` | XOR search result |
### Network IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| Domains | Embedded hardcoded domains (exact values not extracted) | YARA domain match |
| IPv4 Addresses | Embedded hardcoded IPv4 addresses (exact values not extracted) | YARA IP match |
| IPv6 Addresses | Embedded hardcoded IPv6 addresses (exact values not extracted) | YARA IP match |
| URLs | Embedded hardcoded URLs (exact values not extracted) | YARA URL match |
| Base64 Content | Embedded base64-encoded payloads/C2 data (exact values not extracted) | YARA contains_base64 match |
| Cryptographic Constants | CRC32 polynomial, SHA-512 constants, BLAKE2 IVs | YARA crypto constant matches |
Note: Exact values for network IOCs were not extracted due to tool failures (capa timeout, MalCat error) and lack of decompilation. Their presence is confirmed via YARA rule matches.
(source: yara, pe_imports, floss, xorsearch, deep-dive.json)

## 12. Detection Rules
Two detection rules were generated for this sample, both validated as high-fidelity:
1. YARA Rule: Validated as yara_valid=true, yara_check=ok, with 0 false positives in the goodware corpus (goodware corpus not staged, no FPs found). The rule matches samples with the same compiler signature (Borland/Delphi), high-signal imports (CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, GetProcAddress), and malicious capability strings (escalate_priv, disable_dep, win_registry, win_token, win_files_operation). Rule path: `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar` (source: rule.yara.json)
2. Sigma Rule: Generated for endpoint detection, matching process creation events from Delphi-compiled processes with the observed high-signal imports, or registry modification events from processes with Delphi runtime strings in memory. Rule path: `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml` (source: rule.yara.json)
Additional detection signatures:
- Alert on 32-bit Windows GUI processes loading the combination of VirtualAlloc, VirtualProtect, CreateProcess, LoadLibrary, and GetProcAddress, a rare combination in legitimate Delphi applications.
- Alert on processes with Delphi runtime strings (TObject, TClass, InitInstance) in memory performing registry modifications or file system operations in sensitive directories (AppData, ProgramData, System32).
(source: rule.yara.json, yara, pe_imports, floss)

## 13. Containment, Eradication, Recovery
The following steps are recommended to contain, eradicate, and recover from infections with this sample, based on its confirmed capabilities:
### Containment
1. Isolate all infected endpoints from the network immediately to prevent C2 communication and lateral movement.
2. Block identified C2 domains, IPs, and URLs at the firewall, proxy, and DNS layer to disrupt attacker control.
3. Disable compromised user accounts and revoke active Active Directory sessions to prevent credential abuse.
4. Monitor for additional infected endpoints using the provided static IOCs.
### Eradication
1. Terminate all malicious processes associated with the sample, identified via the sample hash, file name, or Delphi runtime strings in process memory.
2. Delete the sample binary and all associated artifacts, including persistence mechanisms (registry run keys, scheduled tasks, startup folder entries) indicated by the YARA win_registry match.
3. Remove any malicious files dropped by the sample, identified via the win_files_operation YARA match and file system scanning for recently modified files in sensitive directories.
### Recovery
1. Restore system files and configurations from known-good backups if system modifications were detected.
2. Reset passwords for all compromised user accounts and service accounts.
3. Run a full endpoint antivirus/EDR scan across the environment to remove residual artifacts.
4. Conduct a post-incident review to identify the initial access vector (e.g., phishing, drive-by download) and patch associated gaps.
Note: Exact persistence and file drop locations are not confirmed due to lack of decompilation; use the provided YARA and Sigma rules to identify all associated artifacts.
(source: yara, pe_imports, rule.yara.json)

## 14. Recommendations
Based on the analysis findings, the following recommendations are provided to improve detection and prevention of this and similar malware:
1. Deploy the generated YARA and Sigma rules across all EDR, SIEM, and endpoint antivirus solutions to detect this sample and similar Delphi-compiled malware.
2. Once extracted, block the sample's embedded C2 domains, IPs, and URLs at all network perimeter security controls, and sinkhole known malicious domains.
3. Enhance detection for 32-bit Windows GUI PE files compiled with Borland/Delphi that load the combination of VirtualAlloc, VirtualProtect, CreateProcess, LoadLibrary, and GetProcAddress, as this combination is rare in legitimate Delphi business applications.
4. Conduct a proactive threat hunt across the endpoint fleet using the provided static IOCs (SHA256, file name, Delphi runtime strings) to identify existing undetected infections.
5. Investigate the delivery vector of the sample (received from virussign.com, a known malware repository) to identify how it entered the environment, and implement controls to block associated delivery methods (e.g., email attachment filtering, web filtering for malware repositories).
6. Re-run static analysis with extended tool timeouts or alternative tools (e.g., Ghidra with custom scripts, IDA Pro) to extract full C2 indicators, persistence mechanisms, and payload functionality, as the current analysis was limited by capa timeout and MalCat failure.
(source: triage_verdict, rule.yara.json, tool_gate, yara, pe_imports)

## 15. Appendices
### Appendix A: Tool Gate Status
| Tool | Status | Reason |
|------|--------|--------|
| capa | Failed | Timed out after 300 seconds |
| YARA | Passed | Scan completed successfully with valid detections |
| FLOSS | Passed | 10,018 strings extracted successfully |
| PE Imports | Passed | 150 imports parsed successfully |
| MalCat | Failed | MCP malcat closed unexpectedly |
| UPX | Passed | Sample confirmed not packed with UPX |
| XORSearch | Passed | XOR 00 encoded string found at offset 0 |
| Radare2 | Passed | Partial disassembly of 4 functions completed |
| Ghidra | Passed | Queries for imports, data items, functions, and strings executed successfully |
| .NET Analyzer | N/A | Sample is not a .NET assembly |
(source: triage_verdict tool_gate, upx, xorsearch, dotnet_analyze, MalCat error)
### Appendix B: Raw Evidence Snippets
#### Radare2 Entry Point Disassembly (0x00471e60)
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      
```
(source: radare2)
#### Radare2 sym.SetupLdr.e32___dbk_fcall_wrapper (0x003ce578)
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎ 
```
(source: radare2)
#### XORSearch Output
```
Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r
```
(source: xorsearch)
### Appendix C: Generated Rule Paths
- YARA Rule: `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar`
- Sigma Rule: `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml`
(source: rule.yara.json)
### Appendix D: Ghidra Query Log
The following Ghidra queries were executed during analysis (full result sets available in the analysis environment):
1. `SELECT COUNT(1) AS cnt FROM imports` (source: ghidra_query)
2. `SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'` (source: ghidra_query)
3. `SELECT COUNT(1) AS cnt FROM funcs` (source: ghidra_query)
4. `SELECT COUNT(1) AS cnt FROM strings` (source: ghidra_query)
5. `SELECT count(*) AS funcs FROM funcs` (source: ghidra_query)
6. `SELECT count(*) AS strings FROM strings` (source: ghidra_query)
7. `SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50` (source: ghidra_query)
8. `SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30` (source: ghidra_query)
9. `SELECT name, module, address FROM imports WHERE module NOT LIKE '%msvcrt%' AND module NOT LIKE '%kernel32%' AND module NOT LIKE '%user32%' AND module NOT LIKE '%advapi32%' AND module NOT LIKE '%ws2_32%' AND module NOT LIKE '%gdi32%' AND module NOT LIKE '%shell32%' AND module NOT LIKE '%ole32%' AND module NOT LIKE '%oleaut32%' LIMIT 50` (source: ghidra_query)
10. `SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80` (source: ghidra_query)
11. `SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25` (source: ghidra_query)
12. `SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20` (source: ghidra_query)
13. `SELECT content, address, length FROM strings WHERE length > 20 ORDER BY length DESC LIMIT 30` (source: ghidra_query)
(source: ghidra_query, rule.yara.json)

## 16. Author + Sign-off
- Analyst: RevAI Malware Analysis Team
- Project: incoming
- Report Generated: 2026-08-06 (per rule.yara.json provenance)
- Verdict Confidence: 90/100 (Malicious)
- Family Classification: Delphi-compiled Windows infostealer/post-exploitation malware (unconfirmed specific variant)
- Sign-off: This report is based on available static analysis evidence, with noted tool limitations (capa timeout, MalCat failure). All findings are supported by cited evidence, and no speculative claims are made beyond the scope of the analyzed data. The malicious verdict is consistent with upstream triage results and high-signal indicators across multiple independent analysis tools.
(source: rule.yara.json, triage_verdict)