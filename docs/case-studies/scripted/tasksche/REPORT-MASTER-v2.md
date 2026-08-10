> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:29:21 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# WannaCry Ransomware Analysis Report

## Executive Summary

This report details the analysis of a 32-bit Windows executable (`tasksche.exe`) identified as a component of the WannaCry ransomware family. The sample exhibits core ransomware behaviors including AES-based file encryption, service-based persistence, and registry manipulation for configuration storage. Analysis confirms the presence of WannaCry-specific artifacts such as the 'WanaCrypt0r' mutex, 'WNcry@2ol7' contact email, and multiple Bitcoin wallet addresses for ransom payment. The malware leverages Microsoft's cryptographic APIs for file encryption and uses command-line execution for payload delivery. No anti-analysis or evasion techniques were observed beyond basic obfuscation. The sample is definitively malicious and poses a high risk of data loss through file encryption.

## 1. Sample Identification

| Attribute | Value |
|-----------|-------|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda |
| File Path | /opt/samples/corpus/710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Compiler | Microsoft Visual C++ 6.0 |
| Packed | No (UPX probe negative) |
| .NET | Not a .NET assembly |
| Project | 710 |

The sample is a native Win32 executable compiled with Visual C++ 6.0, consistent with WannaCry's known build environment. The filename 'tasksche.exe' aligns with WannaCry's task scheduler component naming convention (source: deep-dive.json).

## 2. Classification

| Field | Value |
|-------|-------|
| Verdict | **Malicious** |
| Confidence | 100% |
| Family | WannaCry / WanaCrypt0r / WCry |
| Type | Ransomware |
| Threat Level | Critical |

The classification is based on multiple converging evidence streams. The upstream triage verdict is 'malicious' with a score of 100 (source: verdict.json). YARA rules matched WannaCry-specific indicators including 'Wanna_Cry_Ransomware_Generic', 'WannaCry_Ransomware', and 'WannaCry_Ransomware_Dropper' (source: yara). The deep-dive analysis identified the 'WANACRY!' magic marker, 'WanaCrypt0r' mutex, and ransom contact email 'WNcry@2ol7' (source: deep-dive.json). CAPA confirmed encryption capabilities via AES and service creation for persistence (source: capa).

## 3. Background & Family Lineage

WannaCry (also known as WannaCrypt, WCry, or WanaCrypt0r) is a ransomware worm that emerged in May 2017, causing a global pandemic affecting over 200,000 systems across 150 countries. It exploited the EternalBlue vulnerability (MS17-010) in Windows SMBv1 for propagation. The malware encrypts user files using AES-128-CBC and demands ransom payment in Bitcoin.

This sample exhibits characteristics consistent with the early WannaCry variants:
- **Mutex**: 'WanaCrypt0r' used for single-instance enforcement (source: deep-dive.json)
- **Contact Email**: 'WNcry@2ol7' for ransom communication (source: deep-dive.json)
- **Bitcoin Wallets**: Three addresses (115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn, 12t9YDPgwWZUNt1FbnwQ98BHsz9f9S7JtB, 13AM4VW2dhxYgXeQepoH7HSQuz6THspMmH) for payment (source: deep-dive.json)
- **File Extension**: '.wnry' for encrypted files (source: deep-dive.json)
- **Config Files**: 'c.wnry' (configuration) and 't.wnry' (Tor component) (source: deep-dive.json)

The sample appears to be the propagation/encryption component rather than the initial dropper, based on its self-referencing as 'tasksche.exe' and presence of Tor-related files (source: deep-dive.json).

## 4. Static Analysis

### 4.1 File Structure

The PE file has standard sections with no packing detected. MalCat analysis identified 8 anomalies including BigResourceHighEntropy (resources section), CryptoApiUsage (imports), and XorInLoop (code patterns) (source: malcat). The high-entropy resource section at offset 65776 likely contains embedded data or encrypted payloads (source: malcat).

### 4.2 String Analysis

Critical strings recovered from the binary:

| String | Address | Significance |
|--------|---------|--------------|
| WANACRY! | 0x40FC3C | Magic marker unique to WannaCry |
| WanaCrypt0r | 0x40F474 | Ransomware mutex/family identifier |
| WNcry@2ol7 | 0x411A9C | Ransom contact email |
| Microsoft Enhanced RSA and AES Cryptographic Provider | Referenced by FUN_0040182c | AES encryption provider |
| cmd.exe /c "%s" | Referenced by FUN_00401ce8 | Command execution template |
| icacls . /grant Everyone:F /T /C /Q | - | File permission escalation |
| attrib +h . | - | Directory hiding |
| c.wnry | Referenced by FUN_00401000 | Configuration file |
| t.wnry | 0x411A04 | Tor data component |
| .msg | 0x40FD34 | Ransom message file extension |

(source: deep-dive.json, ghidra_query)

### 4.3 Import Analysis

High-signal imports indicate ransomware functionality:

| Import | Category | ATT&CK |
|--------|----------|--------|
| CreateServiceA | Persistence | T1543.003 |
| RegSetValueExA | Configuration | T1112 |
| CryptGenKey, CryptEncrypt, CryptImportKey | Encryption | T1027 |
| CreateProcessA | Execution | T1106 |
| VirtualAlloc, VirtualProtect | Memory | T1055 |
| LoadLibraryA, GetProcAddress | Dynamic Resolution | T1129 |

(source: pe_imports, capa)

### 4.4 Cryptographic Constants

The binary contains embedded AES S-box constants (Rijndael_Te0 through Te3, Td0 through Td3) and CRC32 tables, confirming cryptographic capabilities (source: malcat). The recovered function `aes_key_schedule` at address 4205174 initializes AES encryption contexts with key lengths of 16, 24, or 32 bytes (source: recovered_functions).

## 5. Behavioral Analysis

### 5.1 Observed Behaviors

Based on static analysis and string evidence, the sample exhibits these behaviors:

1. **File Encryption**: Uses Microsoft Enhanced RSA and AES Cryptographic Provider for AES-based file encryption (source: deep-dive.json)
2. **Persistence**: Creates Windows services via CreateServiceA/OpenSCManagerA (source: deep-dive.json, capa)
3. **Registry Manipulation**: Stores configuration in 'Software\WanaCrypt0r' registry key (source: recovered_functions)
4. **Command Execution**: Executes commands via 'cmd.exe /c "%s"' template (source: deep-dive.json)
5. **Permission Escalation**: Uses 'icacls' to grant Everyone full access (source: deep-dive.json)
6. **File Hiding**: Uses 'attrib +h .' to hide working directory (source: deep-dive.json)

### 5.2 Runtime Analysis

No runtime behavioral data was available from Speakeasy or Frida analysis. The behaviors described are inferred from static artifacts and string references.

## 6. Network Analysis & C2

### 6.1 Command and Control

The sample contains a Tor component file 't.wnry' at address 0x411A04, indicating Tor-based command and control communications (source: deep-dive.json). This is consistent with WannaCry's known use of Tor for C2 infrastructure to evade takedown.

### 6.2 Network Indicators

No direct network indicators (IP addresses, domains) were recovered from the binary. The ransom contact email 'WNcry@2ol7' serves as the primary communication channel for ransom instructions (source: deep-dive.json).

## 7. Capability Assessment

| Capability | Status | Evidence |
|------------|--------|----------|
| File Encryption | **Observed** | AES constants, CryptEncrypt imports, .wnry extension |
| Persistence | **Observed** | CreateServiceA, registry keys |
| Command Execution | **Observed** | cmd.exe template string |
| Permission Escalation | **Observed** | icacls command string |
| File Hiding | **Observed** | attrib command string |
| Tor C2 | **Latent** | t.wnry file present |
| Network Propagation | **Not Observed** | No EternalBlue/exploit strings found |
| Data Exfiltration | **Not Observed** | No exfiltration APIs or strings |
| Anti-Analysis | **Not Observed** | No anti-debug/VM strings |

The sample focuses on local file encryption and persistence. Network propagation capabilities (EternalBlue) were not observed in this component, suggesting it may be the encryption payload rather than the worm module (source: analysis).

## 8. Attribution

The sample is attributed to the WannaCry ransomware campaign based on:
- Unique 'WANACRY!' magic marker (source: deep-dive.json)
- 'WanaCrypt0r' mutex name (source: deep-dive.json)
- 'WNcry@2ol7' contact email (source: deep-dive.json)
- Bitcoin wallet addresses matching known WannaCry wallets (source: deep-dive.json)
- YARA rule matches for WannaCry family (source: yara)

The WannaCry attack was attributed to the Lazarus Group (North Korea) by multiple security vendors and government agencies. This sample exhibits characteristics consistent with the original WannaCry variants from May 2017.

## 9. Indicators of Compromise

### 9.1 File-Based IOCs

| Type | Value |
|------|-------|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda |
| Filename | tasksche.exe |
| Mutex | Global\WanaCrypt0r |
| Registry Key | Software\WanaCrypt0r |
| File Extension | .wnry |
| Config File | c.wnry |
| Tor File | t.wnry |
| Ransom Note | @Please_Read_Me@.txt |

### 9.2 String-Based IOCs

| Type | Value |
|------|-------|
| Magic Marker | WANACRY! |
| Contact Email | WNcry@2ol7 |
| Bitcoin Wallet 1 | 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn |
| Bitcoin Wallet 2 | 12t9YDPgwWZUNt1FbnwQ98BHsz9f9S7JtB |
| Bitcoin Wallet 3 | 13AM4VW2dhxYgXeQepoH7HSQuz6THspMmH |

### 9.3 Command Strings

| Command | Purpose |
|---------|---------|
| icacls . /grant Everyone:F /T /C /Q | Permission escalation |
| attrib +h . | Hide directory |
| cmd.exe /c "%s" | Command execution |

## 10. Detection Rules

### 10.1 YARA Rules

Multiple YARA rules matched this sample:

| Rule | Matches |
|------|---------|
| Wanna_Cry_Ransomware_Generic | WANACRY!, WanaCrypt0r, tasksche.exe |
| WannaCry_Ransomware | WanaCrypt0r, WNcry@2ol7 |
| WannaCry_Ransomware_Dropper | tasksche.exe, taskse, taskdl |
| WannaDecryptor | 7 string indicators |
| Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 | taskdl, taskse |

(source: yara)

### 10.2 Sigma Rules

A Sigma rule was generated at `/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/rule.yml` (source: rule.yara.json).

### 10.3 CAPA Rules

| Rule | ATT&CK |
|------|--------|
| encrypt data using AES | T1027 |
| create service | T1543.003 |
| persist via Windows service | T1543.003 |
| contain obfuscated stackstrings | T1027.005 |
| set file attributes | T1222 |

(source: capa)

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|-----|----------|
| Defense Evasion | Obfuscated Files or Information | T1027 | AES encryption, XOR encoding |
| Defense Evasion | Indicator Removal from Tools | T1027.005 | Obfuscated stackstrings |
| Defense Evasion | File and Directory Permissions Modification | T1222 | icacls command |
| Discovery | File and Directory Discovery | T1083 | File path operations |
| Discovery | System Information Discovery | T1082 | GetHostName |
| Discovery | Query Registry | T1012 | Registry queries |
| Persistence | Create or Modify System Process: Windows Service | T1543.003 | CreateServiceA |
| Execution | System Services: Service Execution | T1569.002 | Service creation |
| Impact | Data Encrypted for Impact | T1486 | AES file encryption |

(source: capa, pe_imports)

## 12. Containment, Eradication, Recovery

### 12.1 Containment

1. **Isolate infected systems** immediately from the network to prevent lateral movement
2. **Disable SMBv1** on all systems to prevent EternalBlue exploitation
3. **Block Bitcoin wallet addresses** at network perimeter
4. **Monitor for .wnry file creation** as an indicator of active encryption

### 12.2 Eradication

1. **Terminate malicious processes**: Kill tasksche.exe and related processes
2. **Remove persistence**: Delete the WannaCry service and registry keys
3. **Delete malicious files**: Remove tasksche.exe, c.wnry, t.wnry, and ransom notes
4. **Patch systems**: Apply MS17-010 to prevent re-infection

### 12.3 Recovery

1. **Restore from backups**: Recover encrypted files from clean backups
2. **Do not pay ransom**: Payment does not guarantee decryption and funds criminal activity
3. **Scan for remnants**: Use updated antivirus to detect any remaining components
4. **Monitor for reinfection**: Implement enhanced logging and monitoring

## 13. Recommendations

### 13.1 Immediate Actions

1. **Patch Management**: Ensure all systems have MS17-010 applied
2. **Network Segmentation**: Isolate critical systems and limit SMB access
3. **Backup Strategy**: Implement offline, immutable backups tested regularly
4. **Endpoint Protection**: Deploy EDR solutions with ransomware detection capabilities

### 13.2 Long-Term Improvements

1. **Disable Legacy Protocols**: Disable SMBv1 across the enterprise
2. **User Training**: Educate users on phishing and ransomware risks
3. **Incident Response Plan**: Develop and test ransomware-specific IR procedures
4. **Threat Intelligence**: Subscribe to feeds for emerging ransomware threats

## 14. Appendix A: Evidence Trail

### 14.1 Tool Evidence Summary

| Tool | Status | Key Findings |
|------|--------|--------------|
| Ghidra | Success | WANACRY! marker, WanaCrypt0r mutex, encryption APIs |
| IDA | Success | Confirmed WannaCry strings |
| YARA | Success | 28 rule matches including WannaCry-specific |
| CAPA | Success | 32 capabilities including AES encryption, service creation |
| MalCat | Success | 8 anomalies, crypto constants, high-entropy resources |
| FLOSS | Success | 6240 strings including API names |
| PE Imports | Success | 114 imports, 7 high-signal |
| Radare2 | Success | Disassembly of entry point and main function |
| UPX | Negative | Not packed |
| .NET | Negative | Not a .NET assembly |

### 14.2 Recovered Functions

| Address | Name | Confidence | Purpose |
|---------|------|------------|---------|
| 4218126 | handle_file_seek | 0.7 | File seeking operations |
| 4198653 | wannacry_registry_directory_manager | 0.9 | Registry persistence |
| 4213785 | huffman_build_code_table | 0.7 | Huffman coding |
| 4205174 | aes_key_schedule | 0.9 | AES key expansion |
| 4200202 | resolve_kernel32_file_apis | 0.9 | Dynamic API resolution |
| 4202471 | wannacry_launcher | 0.85 | Main payload launcher |
| 4216892 | inflate | 0.9 | Zlib decompression |
| 4220282 | parse_zip_local_header | 0.85 | ZIP parsing |
| 4223088 | create_directory_recursive | 0.9 | Directory creation |

(source: recovered_functions)

## 15. Appendix B: Module Inventory

### 15.1 Embedded Components

| Component | File | Purpose |
|-----------|------|---------|
| Configuration | c.wnry | Ransomware settings |
| Tor Client | t.wnry | Anonymous C2 communications |
| Ransom Note | @Please_Read_Me@.txt | Victim instructions |
| Language Files | .msg | Multi-language ransom messages |

### 15.2 Cryptographic Modules

| Module | Function | Address |
|--------|----------|---------|
| AES Encryption | aes_key_schedule | 4205174 |
| AES Encrypt | sub_402e7e | 11902 |
| AES Decrypt | sub_4031bc | 12732 |
| Huffman Coding | huffman_build_code_table | 4213785 |
| Inflate | inflate | 4216892 |

### 15.3 File Operations

| Module | Function | Address |
|--------|----------|---------|
| File Seeking | handle_file_seek | 4218126 |
| ZIP Parsing | parse_zip_local_header | 4220282 |
| Directory Creation | create_directory_recursive | 4223088 |
| File Data Inflation | inflate_file_data | 4221056 |

## 16. Author + Sign-off

**Analyst**: Automated Malware Analysis System
**Date**: 2026-08-09
**Classification**: CONFIDENTIAL
**Distribution**: Incident Response Team

This report was generated through automated analysis of static artifacts, string recovery, and tool-based evidence correlation. All findings are traceable to specific tool outputs as cited. Runtime behavioral analysis was not available for this assessment.

**Sign-off**: The analysis confirms this sample is a WannaCry ransomware component with high confidence based on multiple converging evidence streams. Immediate containment and eradication procedures are recommended.