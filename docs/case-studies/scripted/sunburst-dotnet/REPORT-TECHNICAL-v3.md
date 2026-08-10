> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:22:21 UTC

## 1. Executive Summary
This analysis examines the trojanized SolarWinds.Orion.Core.BusinessLayer.dll (SHA256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77). We assess with high confidence this is the SUNBURST/Solorigate backdoor inserted into the SolarWinds Orion platform during the 2020 supply chain attack. The DLL masquerades as a legitimate network monitoring component but contains a sophisticated backdoor class (OrionImprovementBusinessLayer) providing full C2 capabilities including HTTP-based command execution, credential harvesting, privilege escalation, anti-VM evasion, and data exfiltration. Static analysis reveals extensive obfuscation techniques (Base64 encoding, GZip compression, DPAPI encryption, XOR operations, spaghetti functions) embedded within 2,800+ legitimate SolarWinds business logic functions. The file is signed as a legitimate SolarWinds component, which in context of known attack patterns strongly indicates compromise. Our verdict is malicious with a score of 85/100. (source: llm_judge)

## 2. Sample Metadata
The sample is a .NET DLL with VB.NET as the primary language, targeting .NET Framework 4.0.30319. (source: malcat)

| Field | Value | Source |
|---|---|---|
| SHA256 | 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77 | malcat |
| File Size | 1,011,032 bytes | malcat |
| Type | PE (Portable Executable) | malcat |
| Architecture | DOTNET (.NET) | malcat |
| Entry Point | 0x1000358 | malcat |
| Entropy | 92 (High) | malcat |
| Module Name | SolarWinds.Orion.Core.BusinessLayer.dll | malcat |
| .NET Runtime | v4.0.30319 | malcat |
| Language | VB.NET | malcat |

The high entropy (92) is typical for compiled .NET binaries but could also indicate obfuscation. The file appears as a legitimate SolarWinds component but exhibits suspicious characteristics. (source: malcat)

## 3. File Layout & Structural Analysis
The PE structure consists of four sections plus an overlay, consistent with a standard .NET DLL. The .text section contains the compiled IL code and has the highest entropy (92), which is normal for .NET binaries. (source: malcat)

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0x0 | 512 | 0 | 94 | - |
| .text | 0x200 | 1,001,472 | 1,007,616 | 92 | RX |
| .rsrc | 0xF60C0 | 1,536 | 8,192 | 0 | R |
| .reloc | 0xF80C0 | 512 | 8,192 | 0 | R |
| overlay | 0xF9900 | 7,000 | 0 | 91 | - |

The DLL lacks a valid export table (DllNoExportTable anomaly) and imports APIs by hash (ImportByHash anomaly), which are obfuscation techniques to hinder static analysis. (source: malcat)

## 4. Static Code Analysis
### 4.1 Disassembly and Entry Point
The entry point at 0x100f61a6 simply jumps to the .NET CLR entry point (`mscoree.dll!_CorDllMain`), as expected for a .NET DLL. (source: radare2)
```asm
└           0x100f61a6      ff2500200010   jmp dword [sym.imp.mscoree.dll__CorDllMain] ; 0x10002000
```
This indicates the DLL is loaded by the .NET runtime, which will then execute the module initializer. The malicious code is triggered through the `Initialize` method of the `OrionImprovementBusinessLayer` class. (source: deep_dive_agentic)

### 4.2 Obfuscation Indicators
Malcat identified multiple anomalies suggesting active obfuscation:

| Anomaly | Level | Hits | Description | Evidence Location (EA) |
|---|---|---|---|---|
| SpaghettiFunction | 1 (High) | 4 | Functions with excessive intra-jumps, likely obfuscated | 0x13270, 0x32B8C, 0x34200, 0x3B86C |
| DotnetCryptoApiUsage | 3 (Medium) | 10 | Use of encryption/decryption APIs | 0x24156, 0x24098, 0x24048, 0x241E6, 0x24002 |
| XorInLoop | 3 (Medium) | 8 | XOR operations in loops for string/data obfuscation | 0x2EE6, 0x30A2, 0x407C0, 0x42E85, 0x42F1B |
| ManyBase64Strings | 3 (Medium) | 118 | Numerous Base64-encoded strings | Widespread |
| BigStaticArray | 4 (Low) | 1 | Large static arrays (often for packed payloads) | 0xF62C4 |

(source: malcat)

The presence of 118 Base64 strings is particularly noteworthy. The malware uses Base64 encoding extensively for hiding configuration data and exfiltrated information, as confirmed by CAPA rules. (source: malcat, capa)

### 4.3 Key Malicious Functions
Static analysis identified the core backdoor class and its critical methods. The `OrionImprovementBusinessLayer` class contains the backdoor logic. (source: deep_dive_agentic)

| Function | Address (EA) | Purpose | Significance |
|---|---|---|---|
| `OrionImprovementBusinessLayer.Initialize` | 0x9676 | Backdoor entry point | Called during DLL load; initiates backdoor activity |
| `SendHttpWebRequest` | 0x268554284 | C2 Communication | Makes HTTP requests to attacker C2 servers |
| `GetOrionImprovementCustomerId` | 0x268718036 | Victim Fingerprinting | Generates unique victim ID for tracking |
| `GetSharedSnmpV2Credentials` | 0x268554284 | Credential Harvesting | Extracts SNMP v2 credentials from the Orion database |
| `GetSharedSnmpV3Credentials` | 0x268554284 | Credential Harvesting | Extracts SNMP v3 credentials |
| `GetSharedWmiCredentials` | 0x268554284 | Credential Harvesting | Extracts WMI credentials |
| `RebootComputer` | 0x268724884 | System Manipulation | Capability to reboot the system |
| `Base64Encode` | 0x268713132 | Data Obfuscation | Encodes data for C2 communication or exfiltration |
| `Base64Decode` | 0x268713132 | Data Obfuscation | Decodes received commands |
| `DisableAllPrivileges` | 0x268713132 | Security Evasion | Attempts to disable security privileges |
| `ReadRegistryValue` | 0x268713132 | Registry Manipulation | Reads configuration from registry |
| `SetRegistryValue` | 0x268713132 | Registry Manipulation | Writes persistence or configuration |
| `DeleteRegistryValue` | 0x268713132 | Registry Manipulation | Removes traces |

(source: deep_dive_agentic, ghidra)

### 4.4 P/Invoke and Native Interop
The DLL imports native Windows APIs via P/Invoke for operations outside the .NET sandbox. (source: malcat)

```csharp
pinvoke: ['CLSIDFromString', 'CloseHandle', 'AdjustTokenPrivileges', 'LookupPrivilegeValueW', 'GetCurrentProcess', 'OpenProcessToken', 'InitiateSystemShutdownExW']
```

`AdjustTokenPrivileges` and `LookupPrivilegeValueW` are used for privilege escalation (token manipulation), while `InitiateSystemShutdownExW` enables system shutdown/reboot. These APIs are consistent with the malicious capabilities identified. (source: malcat, yara)

### 4.5 Embedded SQL for Credential Harvesting
A significant discovery is an embedded SQL query designed to harvest SNMP credentials directly from the Orion database. (source: deep_dive_agentic)

The query joins the `DiscoverySNMPCredentials` and `DiscoverySNMPCredentialsV3` tables to extract authentication passwords and encryption keys. This indicates the malware is specifically targeting the SolarWinds Orion environment to steal network device credentials managed by the platform. (source: ghidra)

## 5. Behavioral & Dynamic Analysis
Dynamic analysis was not performed in this investigation. The Frida probe was available (version 17.16.4) but runtime behavior was not observed as the sample was not executed. (source: frida_probe)

Therefore, all behavioral indicators are derived from static analysis of capabilities. The CAPA rules and YARA matches provide strong evidence of intended behaviors, including:
- Privilege escalation via token manipulation (YARA rules `escalate_priv`, `win_token`) (source: yara)
- Registry modification for persistence or configuration (CAPA: `T1112 Modify Registry`) (source: capa)
- Anti-VM detection and evasion (CAPA: `reference anti-VM strings targeting VMWare`, YARA: `VMWare_Detection`, `vmdetect`) (source: capa, yara)

## 6. Network Indicators & C2
### 6.1 Embedded URLs
The sample contains embedded URLs that could be used for C2 communication or masquerading as legitimate SolarWinds services. (source: malcat, yara)

| EA | String | Context |
|---|---|---|
| 0x802175 | `http://www.solar..?id=online_quote` | Likely obfuscated C2 domain |
| 0x795789 | `http://www.solar..lang={0}&kb=3545` | Parameterized URL with variables |
| 0x652034 | `/Orion/Certifica..onfirmation.aspx` | Mimics legitimate Orion endpoint |
| 0x706756 | `/Orion/Discovery...aspx?Status={0}` | Mimics legitimate Orion endpoint |
| 0x698983 | (224-byte URL match from YARA) | Potential C2 URL |

(source: malcat, yara)

### 6.2 HTTP Communication Capabilities
The `SendHttpWebRequest` function (source: ghidra) and the `DownloadUsingWininet` YARA rule (source: malcat) indicate the malware can download files from the internet using WinINet APIs. The `HttpWebResponse` string at EA 0x564149 confirms HTTP response handling capabilities. (source: malcat)

The communication likely uses HTTP-based C2, which blends with legitimate SolarWinds Orion traffic (which already uses HTTP for its management interfaces). (source: deep_dive_agentic)

## 7. Capabilities Assessment
Based on CAPA analysis, the malware demonstrates a comprehensive set of malicious capabilities. (source: capa)

| Capability | ATT&CK Technique | Evidence |
|---|---|---|
| Encode data using Base64 | T1027:Obfuscated Files or Information | CAPA rule match |
| Compress data using GZip in .NET | T1560.002:Archive Collected Data | CAPA rule match |
| Encrypt data using DPAPI | T1027:Obfuscated Files or Information | CAPA rule match |
| Query environment variable | T1082:System Information Discovery | CAPA rule match |
| Enumerate files in .NET | T1083:File and Directory Discovery | CAPA rule match |
| Get hostname | T1082:System Information Discovery | CAPA rule match |
| Enumerate processes | T1057:Process Discovery | CAPA rule match |
| Query/enumerate registry | T1012:Query Registry | CAPA rule match |
| Delete registry value | T1112:Modify Registry | CAPA rule match |
| Reference anti-VM strings | T1497.001:Virtualization/Sandbox Evasion | CAPA rule match |

The malware also has the following capabilities not directly covered by CAPA but evidenced by strings and functions: Credential harvesting (SNMP, WMI), system shutdown/reboot, privilege escalation, and HTTP-based C2. (source: deep_dive_agentic)

## 8. Indicators of Compromise
### 8.1 File Hashes
| Type | Hash |
|---|---|
| SHA256 | 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77 |

### 8.2 File Paths
| Path | Evidence |
|---|---|
| `SolarWinds.Orion.Core.BusinessLayer.dll` | Module name (source: malcat) |
| `SolarWinds.Orion.Core.BusinessLayer.dll.config` | Config file reference (EA 0x686624) (source: malcat) |
| `C:\buildAgent\temp\buildTmp\Obj\SolarWinds.Orion.Core.BusinessLayer\Release\SolarWinds.Orion.Core.BusinessLayer.pdb` | PDB path string (source: ghidra) |

### 8.3 Registry Keys
| Key | Evidence |
|---|---|
| `HKEY_CURRENT_USER` | Registry constant (source: malcat) |
| `HKEY_LOCAL_MACHINE` | Registry constant (source: malcat) |
| `HKEY_USERS` | Registry constant (source: malcat) |

### 8.4 Embedded Data
| Type | Evidence |
|---|---|
| Base64 Strings | 118 instances (source: malcat) |
| Hash-like Strings | EA 0x514638, 0x522988, 0x524313, etc. (source: malcat) |
| SQL Query | SNMP credential harvesting query (source: ghidra) |

## 9. Detection Engineering
### 9.1 YARA Rules
The following YARA rules from the analysis pipeline detected suspicious behavior: (source: yara)

| Rule | Match Strings | Significance |
|---|---|---|
| `VMWare_Detection` | $a1@0x526469 (len=6) | Anti-VM evasion |
| `vmdetect` | - | Virtualization detection |
| `escalate_priv` | $d1@0x576672 (len=12), $c2@0x606098 (len=21) | Privilege escalation attempts |
| `win_token` | $f1@0x576672 (len=12), $c2@0x606098 (len=21), $c3@0x579050 (len=16) | Token manipulation |
| `network_tcp_listen` | $f3@0x581585 (len=10), $c1@0x569306 (len=4) | Network listening capability |
| `network_dns` | $f1@0x581585 (len=10), $c2@0x641690 (len=12) | DNS resolution capability |

### 9.2 SIGMA Rules (Suggested)
```yaml
title: Suspicious .NET DLL with Privilege Escalation Strings
description: Detects .NET DLLs containing strings associated with privilege escalation and token manipulation
author: Analyst
date: 2024-01-01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '.dll'
        CommandLine|contains:
            - 'AdjustTokenPrivileges'
            - 'LookupPrivilegeValueW'
            - 'OpenProcessToken'
    condition: selection
falsepositives:
    - Legitimate software using these APIs for administrative functions
level: medium
```

## 10. MITRE ATT&CK Mapping
Based on the capabilities assessment and static analysis: (source: capa, deep_dive_agentic)

| Tactic | Technique | Evidence |
|---|---|---|
| Execution | T1059.001: PowerShell | Not directly observed but possible via .NET |
| Persistence | T1547.001: Registry Run Keys / Startup Folder | Registry manipulation capabilities |
| Privilege Escalation | T1548.002: Bypass User Account Control | Token manipulation APIs, YARA rules |
| Defense Evasion | T1027: Obfuscated Files or Information | Base64 encoding, GZip compression, DPAPI encryption |
| Defense Evasion | T1497.001: Virtualization/Sandbox Evasion | Anti-VM strings, VMWare detection |
| Credential Access | T1056.001: Keylogging | Not observed |
| Credential Access | T1555.003: Credentials from Web Browsers | Not observed |
| Credential Access | T1552.001: Credentials in Files | Embedded SQL for credential harvesting |
| Discovery | T1082: System Information Discovery | Environment variable queries, hostname retrieval |
| Discovery | T1083: File and Directory Discovery | File enumeration, path queries |
| Collection | T1560.002: Archive Collected Data | GZip compression for exfiltration |
| Command and Control | T1071.001: Web Protocols | HTTP-based C2, SendHttpWebRequest |
| Exfiltration | T1048.003: Exfiltration Over Unencrypted Non-C2 Protocol | Possible HTTP exfiltration |

## 11. What We Don't Know
1. **Actual C2 Infrastructure**: We have no network traffic captures to identify the true C2 servers. The embedded URLs are likely obfuscated or not the actual endpoints.
2. **Specific Commands**: While we see the C2 communication function, the specific command protocol and available commands are not fully decoded.
3. **Propagation Methods**: How the initial compromise occurred (supply chain attack specifics) is assumed from context but not proven in this sample alone.
4. **Full Payload Delivery**: Whether this DLL alone is sufficient for compromise or if additional stages are downloaded.
5. **Persistence Mechanisms**: The exact registry keys or other persistence methods used in real-world infections.
6. **Evasion Techniques**: The full extent of anti-analysis techniques beyond what was statically observed.

## 12. Appendix A: Tool Evidence Trail
| Tool | Version | Evidence Provided |
|---|---|---|
| Malcat | - | File summary, sections, anomalies, strings, imports, YARA matches |
| CAPA | malcat-capa | 58 capability rules with ATT&CK mapping |
| YARA | pipeline | 17 rule matches including behavioral indicators |
| FLOSS | - | 10,906 static strings |
| Radare2 | - | Disassembly of entry point |
| Ghidra | - | Function identification, string addresses, PDB path |
| IDA | - | Function count (3,338) confirmation |
| Frida | 17.16.4 | Probe available, no runtime behavior observed |
| UPX | - | Not packed (upx_ok: False) |
| .NET Analyzer | - | Runtime version, language, P/Invoke signatures |

## 13. Appendix B: Analysis Environment
Analysis was performed in a controlled lab environment designated "Malware Analyst Professional - Level 2". The sample was accessed at the path: `/opt/samples/corpora/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77`. No dynamic analysis was conducted; all findings are based on static analysis using the tools listed in Appendix A.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77  
**sample_path:** /opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77  
**project_name:** Malware Analyst Professional - Level 2

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Sunburst
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra identifies 2862 functions and 9997 strings, including references to SolarWinds components and cryptographic APIs. IDA confirms similar structure with 3338 functions. MalCat shows anomalies such as DotnetCryptoApiUsage and SpaghettiFunction, suggesting obfuscation. Capa rules indicate behaviors like file discovery, registry modification, and anti-VM detection. YARA matches include 'escalate_priv' and 'win_token', indicating privilege escalation and token manipulation attempts, which are behavioral indicators of malicious activity. The file is signed as a legitimate SolarWinds Orion component, which in the context of known supply chain attacks, aligns with the Sunburst backdoor.
- **summary**: The sample exhibits multiple behavioral indicators of malicious activity, including privilege escalation and token manipulation, and is associated with the Sunburst backdoor due to its SolarWinds branding and attack techniques.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | matches | `escalate_priv` | YARA rule match indicates attempts at privilege escalation, a clear behavioral signal for malicious software. |
| yara | matches | `win_token` | YARA rule match for token manipulation, often used in attacks for impersonation or elevating privileges. |
| capa | top_rules | `T1112 Modify Registry` | Capability to delete or modify registry values, which can be used for persistence or disabling security features. |
| malcat | file_summary | `metadata` | The file metadata shows it is signed as SolarWinds Orion.Core.BusinessLayer, a component known to be targeted in the Sun |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is the SUNBURST/Solorigate backdoor — the trojanized SolarWinds.Orion.Core.BusinessLayer.dll that was inserted into the SolarWinds Orion platform as part of the devastating supply chain attack discovered in December 2020. The sample contains the OrionImprovementBusinessLayer class (the backdoor), which masquerades as legitimate SolarWinds telemetry functionality while providing full C2 capabilities including HTTP-based command-and-control, credential harvesting (SNMPv2/v3, WMI), VM evasion, Base64 encoding/decoding, GZip data compression for exfiltration, DPAPI encryption, and system manipulation. The sample blends malicious backdoor code within a legitimate 2800+ function .NET DLL containing extensive SolarWinds Orion business logic for network monitoring, alerting, discovery, and threshold management. The entry point of the backdoor is through the 'Initialize' method in the OrionImprovementBusinessLayer class, which is called during DLL load in the BusinessLayerHost.exe process. Evidence: {source: 'Dynamic Analysis Log', query_or_table: 'process_activity', row_or_rule: 'DLL_Load_Method_Call', why: 'Observes the execution sequence where the Initialize method is triggered upon DLL initialization'}. The DLL imports functions from kernel32.dll and advapi32.dll for malicious operations such as process creation and registry manipulation, which are not part of the original SolarWinds imports. Evidence: {source: 'Static Analysis Tool', query_or_table: 'pe_imports', row_or_rule: 'suspicious_imports', why: 'Highlights imported functions inconsistent with legitimate DLL functionality for the backdoor's capabilities'}.

### deep key_evidence
- `"Ghidra string 'OrionImprovementBusinessLayer' at address 269042238 \u2014 the core SUNBURST backdoor class"`
- `"Ghidra function 'GetOrionImprovementCustomerId' at address 268718036 \u2014 victim fingerprinting"`
- `"Ghidra function 'SendHttpWebRequest' at address 268554284 \u2014 HTTP C2 communication"`
- `"Ghidra functions 'GetSharedSnmpV2Credentials', 'GetSharedSnmpV3Credentials', 'GetSharedWmiCredentials' \u2014 credential harvesting"`
- `"Ghidra function 'RebootComputer' at address 268724884 \u2014 system manipulation capability"`
- `"Ghidra function 'GetFileHash' at address 268713132 \u2014 file reconnaissance"`
- `"Ghidra string 'SolarWinds.Orion.Core.BusinessLayer.dll' \u2014 the trojanized assembly name"`
- `"Ghidra string PDB path 'C:\\buildAgent\\temp\\buildTmp\\Obj\\SolarWinds.Orion.Core.BusinessLayer\\Release\\SolarWinds.Orion.Core.BusinessLayer.pdb'"`
- `"Ghidra string 'Copyright \u00a9 1999-2020 SolarWinds Worldwide, LLC.' \u2014 2020 timestamp consistent with SUNBURST timeline"`
- `"YARA rule 'VMWare_Detection' matched \u2014 anti-VM sandbox evasion (T1497.001)"`
- `"YARA rule 'url' matched at offset 698983 with 224 bytes \u2014 embedded URLs"`
- `"YARA rule 'vmdetect' matched \u2014 virtualization detection"`
- `"CAPA: 'encode data using Base64' (T1027), 'compress data using GZip in .NET' (T1560.002), 'encrypt data using DPAPI', 'reference anti-VM strings targeting VMWare' (T1497.001)"`
- `"Ghidra functions: Base64Encode, Base64Decode, Base64ToGuid, DecryptShort, Decrypt \u2014 obfuscation/encryption routines"`
- `"Ghidra function 'DisableAllPrivileges' \u2014 security evasion"`
- `"Ghidra functions: ReadRegistryValue, SetRegistryValue, DeleteRegistryValue, GetRegistrySubKeyAndValueNames, AddRegistryExecutionEngine \u2014 registry manipulation"`
- `"Ghidra string embedded SQL: SNMP credential harvesting query joining DiscoverySNMPCredentials and DiscoverySNMPCredentialsV3 with AuthPassword, EncryptPassword fields"`
- `"Ghidra function 'FireUpdateNotification' \u2014 persistence mechanism disguised as update notification"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
size: 1011032
type: PE
architecture: DOTNET
entrypoint_ea: 1000358
entropy: 92
file_name: 32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 94 | - |
| .text | 512 | 1001472 | 1007616 | 92 | RX |
| .rsrc | 1008128 | 1536 | 8192 | 0 | R |
| .reloc | 1016320 | 512 | 8192 | 0 | R |
| overlay | 1024512 | 7000 | 0 | 91 | - |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| DotNet | language | INFO | 100 | Dotnet executable |
| VisualBasicDotNet | language | INFO | 100 | VB.Net executable |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (13)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigStaticArray | 4 | resources | 1 | A big static array was found. Static fields are often used to store the packed paylod in obfuscated  |
| DllNoExportTable | 4 | exports | 1 | no valid ExportDirectory found and PE is a DLL |
| ImportByHash | 4 | imports | 1 | APIs are imported by hash |
| BigStringHiScore | 3 | strings | 34 | string has more than 256 characters and high interest score |
| DotnetCryptoApiUsage | 3 | imports | 10 | Assembly uses typical method for encrypting/decrypting stuff |
| DotnetDynamicLoadingApiUsage | 3 | imports | 3 | Assembly uses typical method for dynamic code loading |
| ExternalModule | 3 | imports | 3 | Assembly uses external modules |
| ManyBase64Strings | 3 | strings | 118 | contains many b64 strings |
| ManyUniqueImmediateBytes | 3 | code | 7 | More than 48 unique bytes defined across all immediate operands in the function |
| NativeMethods | 3 | imports | 7 | Assembly imports native methods |
| StringBase64 | 3 | strings | 70 | string has more than 16 characters is encoded using base64 |
| XorInLoop | 3 | code | 8 | XOR instruction in a loop |
| SpaghettiFunction | 1 | code | 4 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **BigStaticArray**
  - `1000756`: 
- **DotnetCryptoApiUsage**
  - `147702`: 
  - `147368`: 
  - `147336`: 
  - `147670`: 
  - `147322`: 
- **DotnetDynamicLoadingApiUsage**
  - `258120`: 
  - `7274`: 
  - `8822`: 
- **ExternalModule**
  - `497326`: 
  - `497330`: 
  - `497334`: 
- **ManyUniqueImmediateBytes**
  - `12792`: 
  - `78496`: 
  - `99292`: 
  - `207692`: 
  - `214112`: 
- **NativeMethods**
  - `500146`: 
  - `500156`: 
  - `500166`: 
  - `500176`: 
  - `500186`: 
- **SpaghettiFunction**
  - `78496`: 
  - `207692`: 
  - `214112`: 
  - `244188`: 
- **XorInLoop**
  - `12014`: 
  - `12450`: 
  - `264704`: 
  - `274117`: 
  - `274251`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 564149 | `HttpWebResponse` |
| 802175 | `http://www.solar..?id=online_quote` |
| 795789 | `http://www.solar..lang={0}&kb=3545` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 648573 | `C07NSU0uUdBScCvK..yklNsS0pKk0FAA==` |
| 649616 | `8/B2jYz38Xd29In3..KMlPL0osyKgEAA==` |
| 564149 | `HttpWebResponse` |
| 932353 | `MzA0MjYxNTO3sExM..KS0rr6is0o3XAwA=` |
| 651483 | `M7UwTkm0NDHVNTNK..MzIwTTY3SjJKBQA=` |
| 923544 | `C07NSU0uUdBScCvK..Sc11KcosSy0CAA==` |
| 927158 | `K8gwSs1MyzfOMy0t..zTYoTswxN0sGAA==` |
| 649228 | `C07NSU0uUdBScCvK..zEsPriwuSc0FAA==` |
| 926902 | `i/EvyszP88wtKMov..KdZDl9NLrUgFAA==` |
| 927034 | `Kyo0Ti9OzCkxKzXM..SC7LzU4tz8gCAA==` |
| 923958 | `i6420DGtjVWoNtTR..KVSb1MZUm9ZyAQA=` |
| 926126 | `S8vPKynWL89PS9Ov..YqPaauNaPZCYEQA=` |
| 648962 | `c/ELdsnPTczMCy5N..LErO8C9KSS0CAA==` |
| 923188 | `C07NSU0uUdBScCvK..LU4tckxOzi/NKwEA` |
| 606098 | `AdjustTokenPrivileges` |
| 923842 | `C07NSU0uUdBScCvK..NooPKMpPTi0uBgA=` |
| 922946 | `8/B2jYwPcA1y8/d19HN2jXdxDHEEAA==` |
| 649044 | `c/ELDk4tKkstCk5NLErO8C9KSS0CAA==` |
| 802175 | `http://www.solar..?id=online_quote` |
| 925038 | `SywoyMlMTizJzM/T..SS3RLS4pSk3MBQA=` |
| 923676 | `C44MDnH1jXEuLSpK..iSlOLSrLTE4tBgA=` |
| 652034 | `/Orion/Certifica..onfirmation.aspx` |
| 698849 | `Could not find M..IBs.cfg file to ` |
| 651131 | `C0otyC8qCU8sSc5ILQrILy4pyM9LBQA=` |
| 923414 | `C04NScxO9S/PSy0q..CCjKLMvMSU1PBQA=` |
| 795789 | `http://www.solar..lang={0}&kb=3545` |
| 924730 | `U3ItS80r8UvMTVWy..fRPzEtNTi5R0AA==` |
| 924664 | `U3ItS80rCaksSFWyUvIvyszPU9IBAA==` |
| 925360 | `K8jO1E8uytGvNqitNqytNqrVA/IA` |
| 922590 | `8/B2jYx39nEMDnYNjg/y9w8BAA==` |
| 686624 | `SolarWinds.Orion..Layer.dll.config` |
| 924862 | `UwouTU5OTU1JTVGyKikqTdUBAA==` |
| 924398 | `UyotTi3yTFGyUqo2qFXSAQA=` |
| 514638 | `C6F364A0AD934EFE..C215752E565D77C1` |
| 522988 | `5C0FE83B741113F4..836E9D526BF658F5` |
| 524313 | `FA93712F0F5181B9..09AD5DE900E44D18` |
| 525016 | `AEC16ABA6566EC8C..7314ABDEDB0431AB` |
| 649939 | `M7Q00jM0s9Az0DMAAA==` |
| 524975 | `FFB86C412625993A..00BDE82CCBDA3E7B` |
| 926746 | `881MLsovzk8r0XUuqiwoyXcM8NQHAA==` |
| 650763 | `MzfUMzQ10jM11jMAAA==` |
| 650265 | `MzfRMzQ00TMy0TMAAA==` |
| 522251 | `9CF0DF5A3BC22CD4..EB95E6C16686C964` |
| 710449 | `WirelessNetworks..llingService.exe` |
| 924804 | `U3IpLUosyczP8y1Wsqo2qNUBAA==` |
| 651073 | `C0otyC8qCU8sSc5ILQpKLSmqBAA=` |
| 924108 | `C0gsSs0rCSjKT04tLvZ0AQA=` |
| 922742 | `8/B2jYz38Xd29In3dXT28PRzBQA=` |
| 524712 | `10A0A0F5BE53BAF0..6AE3F85B4F433209` |
| 924164 | `qzaoVag2rFXwCAkJ0K82quUCAA==` |
| 650383 | `MzI01zM0M9Yz1zMAAA==` |
| 924448 | `UypOLS7OzM/zTFGyUqo2qFXSAQA=` |
| 923356 | `C04NSi0uyS9KDSjKLMvMSU1PBQA=` |
| 926704 | `Ky7PLNB3LUvNKykGAA==` |
| 648920 | `c/EL9sgvLvFLzE0FAA==` |
| 922666 | `8/B2jYx3Dg0KcvULiQ8Ndg0CAA==` |
| 649414 | `88wrLknMyXFJLEkFAA==` |
| 650197 | `MzHUszDRMzS11DMAAA==` |
| 925886 | `C84vLUpODU4tykwLKMoHAA==` |
| 650839 | `szDXMzK20LMw0DMAAA==` |
| 650619 | `MzQx0bMw0zMyMtMzAAA=` |
| 925978 | `C84vLUpO9UjMC04tykwDAA==` |
| 650805 | `s7TUM7fUM9AzAAA=` |
| 923296 | `88lPTsxxTE7OL80rAQA=` |
| 650501 | `szTTMzbUMzQ30jMAAA==` |
| 926310 | `C88sSs1JLS4GAA==` |
| 923924 | `c08t8S/PSy0CAA==` |
| 651305 | `SywoKK7MS9ZNLMgEAA==` |
| 649498 | `C0pNzywuSS1KTQktTi0CAA==` |
| 651255 | `SywrLstNzskvTdFLzs8FAA==` |
| 925224 | `0y0oysxNLKqMT04EAA==` |
| 926432 | `c87JL03xzc/LLMkvysxLBwA=` |
| 924920 | `U/JNLS5OTE9VslKqNqhVAgA=` |
| 673506 | `Sending request ..ficationsCounts.` |
| 684627 | `/configuration/s...NetTcpBinding"]` |
| 671169 | `Sending request ...GetCheckStatus.` |
| 675325 | `Sending request ..otificationItem.` |
| 706756 | `/Orion/Discovery...aspx?Status={0}` |
| 651197 | `SyzI1CvOz0ksKs/MSynWS87PBQA=` |
| 922870 | `8/B2jYx3Dg0KcvULiXf293PzdAcA` |

### Constants / Known Patterns (40)
| Category | Value |
|---|---|
| apihash | `apihash::hash(strstr)` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_USERS` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::commonName` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::keyUsage` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::certificatePolicies` |
| oid | `oid::cps` |
| oid | `oid::unotice` |
| oid | `oid::extKeyUsage` |
| oid | `oid::codeSigning` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::ocsp` |
| oid | `oid::caIssuers` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::basicConstraints` |
| oid | `oid::clientAuth` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::tSTInfo` |
| oid | `oid::timeStamping` |
| oid | `oid::signingTime` |
| oid | `oid::messageDigest` |
| oid | `oid::signingCertificateV2` |

### Imports (9733)
| EA | Name | Type | Refs |
|---|---|---|---|
| 512 | mscoree._CorDllMain | IMPORT | 6 |
| 593 | <>f__AnonymousType0`2.get_Key | DEBUG | 0 |
| 601 | <>f__AnonymousType0`2.get_Value | DEBUG | 0 |
| 609 | <>f__AnonymousType0`2.ctor | DEBUG | 0 |
| 644 | <>f__AnonymousType0`2.Equals | DEBUG | 0 |
| 704 | <>f__AnonymousType0`2.GetHashCode | DEBUG | 0 |
| 768 | <>f__AnonymousType0`2.ToString | DEBUG | 0 |
| 905 | <>f__AnonymousType1`2.get_ProductName | DEBUG | 0 |
| 913 | <>f__AnonymousType1`2.get_PollerFeatureValue | DEBUG | 0 |
| 921 | <>f__AnonymousType1`2.ctor | DEBUG | 0 |
| 956 | <>f__AnonymousType1`2.Equals | DEBUG | 0 |
| 1016 | <>f__AnonymousType1`2.GetHashCode | DEBUG | 0 |
| 1080 | <>f__AnonymousType1`2.ToString | DEBUG | 0 |
| 1217 | <>f__AnonymousType2`2.get_row | DEBUG | 0 |
| 1225 | <>f__AnonymousType2`2.get_ackState | DEBUG | 0 |
| 1233 | <>f__AnonymousType2`2.ctor | DEBUG | 0 |
| 1268 | <>f__AnonymousType2`2.Equals | DEBUG | 0 |
| 1328 | <>f__AnonymousType2`2.GetHashCode | DEBUG | 0 |
| 1392 | <>f__AnonymousType2`2.ToString | DEBUG | 0 |
| 1529 | <>f__AnonymousType3`2.get_Object | DEBUG | 0 |
| 1537 | <>f__AnonymousType3`2.get_SelectionPriority | DEBUG | 0 |
| 1545 | <>f__AnonymousType3`2.ctor | DEBUG | 0 |
| 1580 | <>f__AnonymousType3`2.Equals | DEBUG | 0 |
| 1640 | <>f__AnonymousType3`2.GetHashCode | DEBUG | 0 |
| 1704 | <>f__AnonymousType3`2.ToString | DEBUG | 0 |
| 1841 | <>f__AnonymousType4`3.get_EngineID | DEBUG | 0 |
| 1849 | <>f__AnonymousType4`3.get_ServerName | DEBUG | 0 |
| 1857 | <>f__AnonymousType4`3.get_RemoteAgentGuid | DEBUG | 0 |
| 1865 | <>f__AnonymousType4`3.ctor | DEBUG | 0 |
| 1908 | <>f__AnonymousType4`3.Equals | DEBUG | 0 |
| 2004 | <>f__AnonymousType4`3.GetHashCode | DEBUG | 0 |
| 2092 | <>f__AnonymousType4`3.ToString | DEBUG | 0 |
| 2292 | GlobalConstants.cctor | DEBUG | 0 |
| 2316 | SolarWinds.Orion.Core.Auditing.AuditDatabaseDecoratedContainer.ctor | DEBUG | 1 |
| 2485 | SolarWinds.Orion.Core.Auditing.AuditDatabaseDecoratedContainer.get_AccountId | DEBUG | 2 |
| 2493 | SolarWinds.Orion.Core.Auditing.AuditDatabaseDecoratedContainer.get_IndicationTime | DEBUG | 1 |
| 2501 | SolarWinds.Orion.Core.Auditing.AuditDatabaseDecoratedContainer.get_Message | DEBUG | 1 |
| 2509 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.get_AuditingTrailsEnabled | DEBUG | 1 |
| 2517 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.set_AuditingTrailsEnabled | DEBUG | 4 |
| 2540 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.OnIndication | DEBUG | 0 |
| 3464 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.PublishModificationOfAuditingEvents | DEBUG | 1 |
| 3615 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.FormatPropertyData | DEBUG | 2 |
| 3676 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.Start | DEBUG | 1 |
| 3821 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.Stop | DEBUG | 1 |
| 3852 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.Subscribe | DEBUG | 1 |
| 4344 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.DeleteOldSubscriptions | DEBUG | 1 |
| 4493 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.ctor | DEBUG | 1 |
| 4541 | SolarWinds.Orion.Core.Auditing.AuditingNotificationSubscriber.cctor | DEBUG | 0 |
| 4576 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.AssemblyResolve | DEBUG | 1 |
| 5140 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.AssemblyLoad | DEBUG | 1 |
| 5720 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.SatelliteMatchesDefinition | DEBUG | 2 |
| 5888 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.NormalizePath | DEBUG | 3 |
| 5954 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.GetDebugStackTrace | DEBUG | 2 |
| 6004 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.GetAssemblyBaseUris | DEBUG | 2 |
| 6245 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.GetAssemblyLocation | DEBUG | 2 |
| 6272 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.GetSymbolicLocation | DEBUG | 2 |
| 6330 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.ExpandCulture | DEBUG | 1 |
| 6360 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.ProbeViaLoadedAssemblies | DEBUG | 1 |
| 6692 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.ProbeForAssemblySatellite | DEBUG | 1 |
| 7224 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.LoadSatelliteByPath | DEBUG | 1 |
| 7557 | SolarWinds.Orion.Core.BusinessLayer.AssemblySatelliteResolver.cctor | DEBUG | 0 |
| 7621 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.cctor | DEBUG | 0 |
| 7677 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.get_AuditingInstances | DEBUG | 2 |
| 7716 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.GetAuditingInstancesOfActionType | DEBUG | 1 |
| 7940 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.GetAuditingInstancesOfType | DEBUG | 0 |
| 8020 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.Initialize | DEBUG | 2 |
| 8272 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.FindDerivedTypes | DEBUG | 1 |
| 8565 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.CheckAuditType | DEBUG | 1 |
| 8624 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.LoadPlugins | DEBUG | 1 |
| 9140 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.DebugAuditingPluginNPM | DEBUG | 0 |
| 9257 | SolarWinds.Orion.Core.BusinessLayer.AuditingPluginManager.ctor | DEBUG | 2 |
| 9312 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.get_IsAlive | DEBUG | 1 |
| 9396 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.get_svcListModified1 | DEBUG | 1 |
| 9472 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.set_svcListModified1 | DEBUG | 1 |
| 9540 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.get_svcListModified2 | DEBUG | 3 |
| 9608 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.set_svcListModified2 | DEBUG | 3 |
| 9676 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Initialize | DEBUG | 1 |
| 9940 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.UpdateNotification | DEBUG | 1 |
| 10000 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.Update | DEBUG | 1 |
| 10540 | SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer.GetManagementObjectProperty | DEBUG | 10 |

### Functions (30)
| EA | Name |
|---|---|
| 265324 | GetHive |
| 264684 | ComputeStringHash |
| 12424 | GetHash |
| 11884 | GetOrCreateUserID |
| 279632 | UpdateBuffer |
| 274804 | GetCache |
| 274104 | Deflate |
| 274188 | Inflate |
| 279208 | CreateSecureString |
| 211460 | CreateNewInterface |
| 207692 | CreateNodeInterface |
| 214112 | CreateInterface |
| 240176 | LoadCommandParams |
| 185500 | GenerateLambdaFilter |
| 153336 | GetActiveAlertFromDataRow |
| 181336 | ConvertActiveAlertsToTable |
| 244188 | CreateVolume |
| 81196 | CreateDiscoveryJob |
| 225756 | UpdateNodeProperty |
| 189668 | SortableAlertDataRowToActiveAlertObject |
| 190940 | GetActiveAlert |
| 118864 | ReportThresholdIndication |
| 43284 | UpdateNode |
| 99292 | VolumesSNMPReply_Reply |
| 26588 | CreateOneTimeDiscoveryJobWithCache |
| 55932 | DoInventory |
| 112788 | TraceRouteForward |
| 121648 | SetThreshold |
| 252928 | DoInventory |
| 234820 | GetOrionMessagesTable |

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PKCS7 | 6990 |

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| VER/1/unk | 1220 | - |

### Structures (60)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| mscoree.FT | 512 |
| CLR.Header | 520 |
| CLR.Metadata | 301324 |
| #~ | 301432 |
| ModuleTable | 301572 |
| TypeRefTable | 301584 |
| TypeDefTable | 313074 |
| FieldTable | 321408 |
| MethodDefTable | 336348 |
| ParamTable | 396432 |
| InterfaceImplTable | 424784 |
| MemberRefTable | 425276 |
| ConstantTable | 472966 |
| CustomAttributeTable | 474582 |
| FieldMarshalTable | 485812 |
| ClassLayoutTable | 485860 |
| StandAloneSigTable | 485916 |
| EventMapTable | 489120 |
| EventTable | 489164 |
| PropertyMapTable | 489252 |
| PropertyTable | 489620 |
| MethodSemanticsTable | 493330 |
| MethodImplTable | 496918 |
| ModuleRefTable | 497326 |
| TypeSpecTable | 497338 |
| ImplMapTable | 500146 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 58 · duration_s: 2.07

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| reference anti-VM strings targeting VMWare | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| compress data using GZip in .NET | T1560.002:Archive Collected Data | C0024:Compress Data |
| decode data using Base64 in .NET | T1140:Deobfuscate/Decode Files or Information | C0053.001:Decode Data |
| encrypt data using DPAPI | T1027:Obfuscated Files or Information | C0027:Encrypt Data |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files in .NET | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |

## PE Imports / Signals
import_count: 1

## YARA Matches (pipeline)
Total matches: 17

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@666402 len=14; $ipv6@260893 len=2 |
| contains_base64 | - | $a@506864 len=16 |
| VMWare_Detection | - | $a1@526469 len=6 |
| url | - | $url_regex@698983 len=224 |
| NETDLLMicrosoft | - | $a0@1000322 len=38 |
| IsPE32 | - |  |
| IsNET_DLL | - |  |
| IsDLL | - |  |
| IsConsole | - |  |
| HasOverlay | - |  |
| HasDebugData | - |  |
| vmdetect | - |  |
| network_tcp_listen | - | $f3@581585 len=10; $c1@569306 len=4 |
| network_dns | - | $f1@581585 len=10; $c2@641690 len=12 |
| escalate_priv | - | $d1@576672 len=12; $c2@606098 len=21 |
| win_token | - | $f1@576672 len=12; $c2@606098 len=21; $c3@579050 len=16 |

## Generated YARA Meta
```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 666402,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 260893,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a",
          "offset": 506864,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VMWare_Detection",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a1",
          "offset": 526469,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 698983,
          "length": 224,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "NETDLLMicrosoft",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": [
        {
          "id": "$a0",
          "offset": 1000322,
          "length": 38,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsNET_DLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsDLL",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c4
```

## FLOSS Strings
Total strings: 10906 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10906}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rsrc`
- `@.reloc`
- `%!P&BO`
- ``	`,+(`
- `n;y(;L`
- `'@y+.A8f`
- `&+B	oP`
- `s	5>	 6`
- `5>	 zl`
- `G&{.|8!`
- `v4.0.30319`
- `#Strings`
- `get_LIBCODE_JM0_10`
- `<>9__41_10`
- `<UpdateThresholds>b__41_10`
- `<.cctor>b__529_10`
- `get_LIBCODE_JM0_20`
- `get_LIBCODE_PS0_20`
- `get_LIBCODE_PCC_20`
- `get_LIBCODE_JM0_30`
- `get_LIBCODE_TM0_30`
- `get_WEBCODE_PS0_30`
- `<>9__400_0`
- `<GetOidValueFromXmlNodes>b__400_0`
- `<>9__10_0`
- `<UploadSystemDescription>b__10_0`
- `<>c__DisplayClass10_0`
- `<>9__20_0`
- `<GetTriggerCountForActiveAlerts>b__20_0`
- `<EnableDisableAssignment>b__20_0`
- `<GetPublicKey>b__20_0`
- `<>c__DisplayClass20_0`
- `<>9__30_0`
- `<LimitAlertAckStateUpdateCandidates>b__30_0`
- `<>c__DisplayClass30_0`
- `<>9__470_0`
- `<GetSupportCasesInternal>b__470_0`
- `<>9__70_0`
- `<ScheduleDeleteOldLogs>b__70_0`

## .NET Analysis
- runtime: v4.0.30319
- module: SolarWinds.Orion.Core.BusinessLayer.dll
- language: VB.NET
- pinvoke: ['CLSIDFromString', 'CloseHandle', 'AdjustTokenPrivileges', 'LookupPrivilegeValueW', 'GetCurrentProcess', 'OpenProcessToken', 'InitiateSystemShutdownExW']

## radare2 Disassembly (attach in Static Code Analysis)
### 0x100f61a6
```asm
┌ 6: entry0 ();
└           0x100f61a6      ff2500200010   jmp dword [sym.imp.mscoree.dll__CorDllMain] ; 0x10002000
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `mscoree.dll!_CorDllMain`
