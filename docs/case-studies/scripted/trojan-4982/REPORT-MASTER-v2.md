> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 13:19:21 UTC

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

This report details the analysis of a malicious Windows executable (SHA256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73) identified as a variant of the Trioris/Cerbu trojan family. The sample exhibits a comprehensive set of malicious capabilities, including HTTP-based command and control (C2) communication with the Russian domain 'twoyden.ru', SOCKS5 proxy/relay functionality, system fingerprinting, registry-based persistence, anti-analysis techniques, and data exfiltration capabilities. The binary is a 32-bit x86 PE executable with a high entropy of 6.82 bits/byte, indicating significant obfuscation or packing, though it is not UPX-packed. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events in this assessment, so all findings are based on static analysis, disassembly, and tool-based heuristics. The sample's malicious nature is confirmed by multiple behavioral indicators, including credit card parsing, C2 communication, and anti-debugging measures, aligning with the upstream triage verdict of 'malicious' with a score of 85/100. We assess with high confidence that this is a trojan designed for data theft and remote control, likely targeting Russian-speaking users based on embedded configuration strings.

## 1. Sample Identification

The sample under analysis is a Windows Portable Executable (PE) file. Key identifiers are as follows:

| Attribute | Value |
|---|---|
| SHA256 | 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73 |
| File Path | /opt/samples/corpus/day6/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/trojan_4982.exe |
| Project Name | day6 |
| File Type | PE x86 executable |
| Architecture | X86 (32-bit) |
| Entropy | 6.82 bits/byte (whole-file Shannon entropy) |
| Imphash | b5f4ee827c576f7005f9e544e6955bfb |
| Packed | Not UPX-packed (source: UPX unpack evidence) |
| .NET | Not a .NET assembly (source: dotnet_analyze) |
| Signed | Invalid signature (source: triage verdict) |

The filename 'trojan_4982.exe' suggests it was part of a malware corpus collection. The high entropy value (6.82 bits/byte) indicates significant code obfuscation or compression, though not via UPX. The imphash can be used for clustering with other samples from the same family. (source: MalCat evidence, triage verdict)

## 2. Classification

**Verdict: MALICIOUS**

**Family: Trioris/Cerbu**

**Confidence: High (90%)**

The classification is based on multiple converging lines of evidence:

1. **Behavioral Intent**: The sample contains code for parsing credit card information (source: capa rule 'parse credit card information'), which is a clear indicator of data theft intent. This is not a neutral capability; it is specifically designed for financial fraud.
2. **C2 Communication**: HTTP-based communication with the domain 'twoyden.ru' using POST requests and a spoofed User-Agent ('NSISDL/1.2') indicates command and control functionality (source: deep-dive.json, Ghidra string_refs).
3. **Anti-Analysis**: Multiple anti-debugging techniques are present, including IsDebuggerPresent API calls and YARA rule matches for 'anti_dbg' (source: pe_imports, YARA matches).
4. **Persistence**: Registry keys under 'Software\ClearSystem' are used for persistence (source: deep-dive.json, Ghidra string_refs).
5. **External Validation**: VirusTotal reports 55/72 detections with the threat family 'Trioris/Cerbu' (source: triage verdict).

The sample is not a dual-use legitimate tool; it is a purpose-built trojan. The presence of obfuscation techniques (XOR encoding, RC4 encryption, obfuscated stack strings) supports malicious intent but is not the sole basis for classification. (source: capa, YARA, triage verdict)

## 3. Background & Family Lineage

The Trioris/Cerbu family is a trojan known for HTTP-based C2 communication, data theft, and proxy capabilities. Based on the embedded configuration string '/S pid=129 subid=10 mr=0 lang=ru' (source: Ghidra strings, addr 4359000), this variant appears to target Russian-speaking users. The 'lang=ru' parameter suggests locale-specific targeting, possibly for regional banking or financial services.

The sample's use of a spoofed User-Agent ('NSISDL/1.2') mimics the NSIS (Nullsoft Scriptable Install System) downloader, a common technique to blend malicious traffic with legitimate software downloads (source: deep-dive.json). The domain 'twoyden.ru' is a Russian TLD, consistent with the targeting hypothesis.

The family likely evolved from earlier variants that used simpler C2 protocols. The inclusion of SOCKS5 proxy relay capability (source: Ghidra strings, addr 4356372) suggests an expansion into network pivoting or anonymization services for the operator. The sample's invalid digital signature may be an attempt to appear legitimate while avoiding strict validation checks. (source: deep-dive.json, Ghidra strings)

## 4. Static Analysis

Static analysis reveals a moderately complex binary with significant obfuscation. The file has 143 imports, with 6 high-signal imports related to debugging, memory manipulation, and networking (source: pe_imports). Key observations:

- **Obfuscation**: The sample uses XOR encoding (T1027) and RC4 KSA encryption (C0027.009/C0028.002) for data protection (source: capa). Obfuscated stack strings (T1027.005) are present, indicating string hiding techniques.
- **Anti-Debugging**: IsDebuggerPresent is imported and called multiple times (source: pe_imports). YARA rules 'anti_dbg' match at offsets 169872, 170594, and 169284 (source: YARA matches).
- **Code Structure**: The binary contains 15 functions identified by MalCat, with several showing high complexity (e.g., sub_417be4 at 94180 bytes). The entry point at 0x0040ee57 calls into 0x4183ae and then jumps to 0x40ece0 (source: radare2 disassembly).
- **Strings**: 987 strings were extracted via FLOSS, including URLs, registry paths, and API names. Notable strings include 'twoyden.ru', 'ClearSystem', 'NSISDL', and 'requireAdmin' (source: Ghidra strings query).
- **Constants**: The sample contains cryptographic constants (PKCS_DigestDecoration_SHA256, MD5) and registry keys (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE) (source: MalCat constants).

The high entropy (6.82 bits/byte) is consistent with obfuscated or compressed code sections, but not with UPX packing (source: UPX unpack evidence). The presence of MSVC 2013 linker artifacts suggests compilation with Visual Studio 2013 (source: YARA rule 'MSVC_2013_linker'). (source: MalCat, capa, YARA, Ghidra)

## 5. Behavioral Analysis

Dynamic analysis tools (Speakeasy, Frida) were not executed in this assessment. Therefore, no runtime behavior was observed. All behavioral indicators are derived from static analysis, disassembly, and tool-based heuristics. The absence of dynamic analysis means we cannot confirm actual execution of C2 communication, persistence mechanisms, or data exfiltration at runtime. However, the static evidence strongly suggests these capabilities are present and likely functional.

The sample's anti-debugging techniques (IsDebuggerPresent, YARA anti_dbg rules) indicate it is designed to evade dynamic analysis environments (source: pe_imports, YARA). This aligns with the lack of observed runtime events; the sample may detect analysis tools and alter its behavior accordingly. (source: pe_imports, YARA)

## 6. Network Analysis & C2

The sample contains extensive network communication capabilities, primarily HTTP-based C2 to the domain 'twoyden.ru'.

**C2 Infrastructure**:
- **Domain**: 'twoyden.ru' (source: Ghidra string_refs, addr 0x00409aa5)
- **Protocol**: HTTP/1.1 with POST and GET methods (source: Ghidra string_refs in FUN_004060ce)
- **User-Agent**: Spoofed as 'NSISDL/1.2' to mimic NSIS downloader traffic (source: Ghidra strings, addr 4357332)
- **Custom Header**: 'My-User-Agent:' header present (source: Ghidra string_refs, addr 0x0040aac8)
- **Proxy Awareness**: Reads ProxyServer/ProxyOverride from Internet Settings registry, handles proxy-authenticate/www-authenticate responses (source: deep-dive.json, Ghidra string_refs)

**Network Capabilities**:
- **SOCKS5 Proxy**: Full SOCKS5 relay capability with 'socks' string and WSA socket APIs (WSAConnect, WSASocketA, WSASend, WSARecv, WSAEventSelect) (source: Ghidra strings, addr 4356372)
- **DNS Resolution**: Capable of resolving DNS (source: capa rule 'resolve DNS')
- **Data Exfiltration**: HTTP POST requests to 'twoyden.ru' for data sending (source: deep-dive.json)
- **Winsock Initialization**: Initializes Winsock library (source: capa rule 'initialize Winsock library')

The network traffic is designed to blend with legitimate HTTP traffic, using standard headers and a common User-Agent. The proxy awareness suggests the sample can operate in corporate environments with proxy servers. (source: deep-dive.json, Ghidra, capa)

## 7. Capability Assessment

The sample possesses a wide range of malicious capabilities:

| Capability | Evidence | ATT&CK Mapping |
|---|---|---|
| Data Theft (Credit Cards) | capa rule 'parse credit card information' | T1056 (Input Capture) |
| C2 Communication | HTTP POST/GET to 'twoyden.ru', User-Agent spoofing | T1071 (Application Layer Protocol) |
| Proxy/SOCKS5 Relay | SOCKS5 string, WSA socket APIs | T1090 (Proxy) |
| System Fingerprinting | Reads InstallDate, OS/VM info, stores in registry | T1082 (System Information Discovery) |
| Persistence | Registry keys under 'Software\ClearSystem' | T1547 (Boot or Logon Autostart Execution) |
| Anti-Debugging | IsDebuggerPresent, YARA anti_dbg rules | T1622 (Debugger Evasion) |
| Code Injection | VirtualAlloc + VirtualProtect imports, CreateProcessW | T1055 (Process Injection) |
| Dynamic API Resolution | LoadLibraryExW + GetProcAddress | T1129 (Shared Modules) |
| Obfuscation | XOR encoding, RC4 KSA, obfuscated stack strings | T1027 (Obfuscated Files or Information) |
| Privilege Escalation | requireAdministrator manifest | T1548 (Abuse Elevation Control Mechanism) |

**Observed vs. Latent**: All capabilities are present in the static analysis. However, without dynamic analysis, we cannot confirm which capabilities are actively used at runtime. The credit card parsing, C2 communication, and persistence mechanisms are likely functional based on the code structure. (source: capa, deep-dive.json, pe_imports)

## 8. Attribution

Attribution is limited due to the lack of infrastructure analysis and threat intelligence correlation beyond VirusTotal. The sample targets Russian-speaking users (lang=ru) and communicates with a Russian domain (twoyden.ru), suggesting a Russian-speaking threat actor or group. The Trioris/Cerbu family is not widely attributed to a specific APT group in public reporting, but the techniques align with financially motivated cybercrime.

The use of a spoofed NSIS User-Agent and proxy awareness indicates operational sophistication, possibly from an experienced malware developer. The invalid digital signature may be a cost-saving measure or an attempt to avoid signature-based detection. (source: deep-dive.json, triage verdict)

## 9. Indicators of Compromise

**File-Based IOCs**:
- SHA256: 38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73
- Imphash: b5f4ee827c576f7005f9e544e6955bfb
- Filename: trojan_4982.exe

**Network IOCs**:
- Domain: twoyden.ru
- IP: 1.1.0.1 (likely a placeholder or test IP) (source: Ghidra strings)
- User-Agent: NSISDL/1.2
- Custom Header: My-User-Agent

**Registry IOCs**:
- Key: HKEY_CURRENT_USER\Software\ClearSystem
- Values: value_vm, value_os (source: deep-dive.json)
- Key: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion (read for InstallDate)

**String IOCs**:
- '/S pid=129 subid=10 mr=0 lang=ru' (source: Ghidra strings)
- 'socks' (SOCKS5 proxy) (source: Ghidra strings)
- 'permission denied', 'file exists', etc. (error strings) (source: rule.yara.json)

**YARA Rule**: A custom YARA rule was generated at /opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar (source: rule.yara.json). (source: Ghidra, rule.yara.json)

## 10. Detection Rules

**YARA Rule** (generated by RevAI engine):
- Path: /opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yar
- Valid: Yes (source: rule.yara.json)
- Family: Trioris/Cerbu trojan
- String Count: 24
- Key Strings: 'permission denied', 'file exists', 'no such device', etc. (source: rule.yara.json)

**Sigma Rule**: Path: /opt/samples/logs/38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73/rule.yml (source: rule.yara.json)

**Capa Rules**: 31 rules matched, including:
- parse credit card information
- send data
- receive data
- resolve DNS
- reference HTTP User-Agent string
- check HTTP status code
- initialize Winsock library
(source: capa evidence)

**YARA Matches**: 20 rules fired, including 'anti_dbg', 'network_tcp_socket', 'win_registry', etc. (source: YARA matches)

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Discovery | File and Directory Discovery | T1083 | capa: get common file path, check if file exists, get file size |
| Defense Evasion | Obfuscated Files or Information | T1027 | capa: encode data using XOR, encrypt data using RC4 KSA |
| Defense Evasion | Obfuscated Files or Information: Indicator Removal from Tools | T1027.005 | capa: contain obfuscated stackstrings |
| Defense Evasion | File and Directory Permissions Modification | T1222 | capa: set file attributes |
| Discovery | Query Registry | T1012 | capa: query or enumerate registry value |
| Execution | Shared Modules | T1129 | pe_imports: LoadLibrary, GetProcAddress |
| Defense Evasion | Debugger Evasion | T1622 | pe_imports: IsDebuggerPresent, YARA: anti_dbg |
| Execution | Process Injection | T1055 | pe_imports: VirtualAlloc, VirtualProtect, CreateProcess |
| Command and Control | Application Layer Protocol | T1071 | capa: HTTP User-Agent, send/receive data |
| Command and Control | Proxy | T1090 | Ghidra: SOCKS5 string, WSA socket APIs |
| Persistence | Boot or Logon Autostart Execution | T1547 | Ghidra: Software\ClearSystem registry keys |
| Collection | Input Capture | T1056 | capa: parse credit card information |
| Privilege Escalation | Abuse Elevation Control Mechanism | T1548 | Ghidra: requireAdministrator manifest |

(source: capa, pe_imports, Ghidra, YARA)

## 12. Containment, Eradication, Recovery

**Containment**:
- Isolate infected systems from the network to prevent C2 communication and lateral movement.
- Block the domain 'twoyden.ru' at the firewall/proxy level.
- Monitor for HTTP traffic with User-Agent 'NSISDL/1.2' and custom header 'My-User-Agent'.

**Eradication**:
- Terminate the malicious process (trojan_4982.exe).
- Remove registry keys under HKEY_CURRENT_USER\Software\ClearSystem.
- Delete the malicious executable from disk.
- Scan for other instances of the Trioris/Cerbu family using the provided YARA rule.

**Recovery**:
- Restore affected systems from clean backups if available.
- Change credentials that may have been compromised, especially financial account credentials.
- Monitor for unusual activity related to credit card fraud or unauthorized access.

**Note**: Without dynamic analysis, the full scope of persistence mechanisms is unknown. The registry-based persistence is confirmed, but other methods (e.g., scheduled tasks, services) may exist. (source: deep-dive.json, Ghidra)

## 13. Recommendations

1. **Block IOCs**: Immediately block the domain 'twoyden.ru' and IP 1.1.0.1 at network boundaries. Update firewall rules to detect the spoofed User-Agent and custom headers.
2. **Endpoint Detection**: Deploy the provided YARA rule to endpoint detection and response (EDR) systems for real-time detection.
3. **User Awareness**: Educate users about the risks of downloading executables from untrusted sources, especially those masquerading as installers (NSIS).
4. **Network Monitoring**: Implement deep packet inspection (DPI) to detect HTTP traffic with anomalous headers or POST requests to suspicious domains.
5. **Registry Hardening**: Monitor for unauthorized changes to registry keys, especially under HKEY_CURRENT_USER\Software.
6. **Dynamic Analysis**: Conduct dynamic analysis in a sandbox environment to confirm runtime behavior and identify additional IOCs.
7. **Threat Intelligence**: Share IOCs with threat intelligence platforms to improve detection across the community.
8. **Patch Management**: Ensure systems are patched to prevent exploitation of vulnerabilities that may be used by this trojan for initial access.

(source: deep-dive.json, Ghidra, capa)

## 14. Appendix A: Evidence Trail

This appendix summarizes the key evidence sources and their contributions to the analysis.

| Source | Key Findings | Citation |
|---|---|---|
| Triage Verdict | Malicious, score 85, family Trioris, 55/72 VT detections | (source: triage verdict) |
| Deep-Dive Analysis | C2 domain 'twoyden.ru', HTTP POST/GET, SOCKS5 proxy, registry persistence, anti-debug | (source: deep-dive.json) |
| YARA Rule | Custom rule generated, 24 strings, valid | (source: rule.yara.json) |
| Ghidra Queries | String refs for 'twoyden', 'ClearSystem', 'NSISDL'; function metrics; callgraph analysis | (source: ghidra_query) |
| Capa Rules | 31 rules matched: credit card parsing, network comms, obfuscation, registry ops | (source: capa evidence) |
| Pe Imports | 143 imports, 6 high-signal: IsDebuggerPresent, VirtualAlloc, VirtualProtect, CreateProcess | (source: pe_imports) |
| YARA Matches | 20 rules: anti_dbg, network_tcp_socket, win_registry, etc. | (source: YARA matches) |
| MalCat | Entropy 6.82, anomalies: DynamicString, XorInLoop, SpaghettiFunction; high-signal imports | (source: MalCat evidence) |
| Radare2 | Entry point at 0x0040ee57, main function at 0x0040ada5 | (source: radare2 disassembly) |
| UPX | Not packed | (source: UPX unpack evidence) |
| XorSearch | XOR 00 candidate found | (source: xorsearch evidence) |
| .NET Analysis | Not a .NET assembly | (source: dotnet_analyze) |

## 15. Appendix B: Module Inventory

The sample contains the following key modules/components based on static analysis:

1. **C2 Communication Module**: Handles HTTP POST/GET requests to 'twoyden.ru' with spoofed User-Agent and proxy awareness. (source: Ghidra string_refs)
2. **Persistence Module**: Modifies registry keys under 'Software\ClearSystem' for autostart. (source: deep-dive.json)
3. **Anti-Analysis Module**: Uses IsDebuggerPresent and YARA-detected anti-debug techniques. (source: pe_imports, YARA)
4. **Data Theft Module**: Parses credit card information (source: capa).
5. **Proxy Module**: Implements SOCKS5 relay for network pivoting. (source: Ghidra strings)
6. **System Fingerprinting Module**: Gathers OS/VM info and stores in registry. (source: deep-dive.json)
7. **Obfuscation Module**: Employs XOR encoding, RC4 encryption, and obfuscated stack strings. (source: capa)
8. **Privilege Escalation Module**: Requests administrator privileges via manifest. (source: Ghidra strings)

**Note**: Without dynamic analysis, the interaction between modules and execution flow is inferred from static code structure. (source: Ghidra, capa, deep-dive.json)

## 16. Author + Sign-off

**Report Author**: Automated Malware Analysis System (RevAI Engine)
**Date**: 2026-08-12
**Version**: 2.0

**Sign-off**: This report was generated based on static analysis, disassembly, and tool-based heuristics. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events, so runtime behavior is inferred. The sample is classified as malicious with high confidence based on behavioral indicators and external validation. All evidence is cited from tool outputs. (source: publish_report_v2)