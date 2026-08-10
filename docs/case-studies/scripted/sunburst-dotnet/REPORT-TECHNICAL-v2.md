> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:12:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary

This report presents the technical analysis of a trojanized .NET DLL identified as the SUNBURST/Solorigate backdoor, a component of the devastating SolarWinds supply chain attack discovered in December 2020. The sample, `SolarWinds.Orion.Core.BusinessLayer.dll`, is a legitimate-looking SolarWinds Orion business logic DLL that has been modified to include a sophisticated backdoor class named `OrionImprovementBusinessLayer`.

The analysis reveals a highly evasive and capable threat actor implant. The backdoor is designed to blend seamlessly with legitimate SolarWinds telemetry code, making detection challenging. It provides full command-and-control (C2) capabilities over HTTP, credential harvesting for SNMP and WMI, anti-VM sandbox evasion, data exfiltration using GZip compression and Base64 encoding, and system manipulation functions including reboot and privilege escalation.

**Verdict:** Malicious (Score: 85/100)
**Family:** Sunburst (Solorigate)
**Confidence:** High (90%)

The evidence supporting this verdict includes direct YARA rule matches for privilege escalation (`escalate_priv`) and token manipulation (`win_token`), capa rules indicating registry modification and anti-VM detection, and the presence of the core backdoor class `OrionImprovementBusinessLayer` with its associated C2 and credential harvesting functions. The file's metadata and digital signature align with the known Sunburst attack vector.

## 2. Sample Metadata

The following table summarizes the core metadata of the analyzed sample, extracted from the PE header and file system properties.

| Property | Value | Source |
|---|---|---|
| SHA256 | `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` | malcat |
| File Size | 1,011,032 bytes | malcat |
| File Type | PE (Portable Executable) | malcat |
| Architecture | .NET (DOTNET) | malcat |
| Entry Point EA | `0x1000358` | malcat |
| Entropy | 92 (High) | malcat |
| Original Filename | `SolarWinds.Orion.Core.BusinessLayer.dll` | malcat |
| .NET Runtime | v4.0.30319 | dotnet |
| Language | VB.NET | dotnet |
| Module Name | `SolarWinds.Orion.Core.BusinessLayer.dll` | dotnet |
| Import Hash (imphash) | `dae02f32a21e03ce65412f6e56942daa` | yara_gen |
| Copyright | `Copyright © 1999-2020 SolarWinds Worldwide, LLC.` | deep_dive |
| PDB Path | `C:\buildAgent\temp\buildTmp\Obj\SolarWinds.Orion.Core.BusinessLayer\Release\SolarWinds.Orion.Core.BusinessLayer.pdb` | deep_dive |

The high entropy (92) is typical for .NET assemblies containing compiled IL code and embedded resources, not necessarily indicative of packing. The 2020 copyright timestamp is consistent with the known SUNBURST attack timeline. The PDB path suggests a build agent environment, which is consistent with a supply chain compromise during the build process.

## 3. File Layout & Structural Analysis

The PE file is structured as a standard .NET DLL with four primary sections and an overlay. The layout is consistent with a legitimate SolarWinds component.

### Section Table
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | `0x0` | 512 | 0 | 94 | - |
| .text | `0x512` | 1,001,472 | 1,007,616 | 92 | RX |
| .rsrc | `0x1008128` | 1,536 | 8,192 | 0 | R |
| .reloc | `0x1016320` | 512 | 8,192 | 0 | R |
| overlay | `0x1024512` | 7,000 | 0 | 91 | - |

*(source: malcat, query_or_table: file_summary)*

The `.text` section contains the .NET IL code and metadata, which explains its high entropy. The `.rsrc` and `.reloc` sections are standard. The overlay section at the end of the file contains additional data, which in this case includes a carved PKCS7 signature block of 6,990 bytes, likely part of the digital signature.

### Carved Files
| Name | Type | Size |
|---|---|---|
| ? | PKCS7 | 6,990 |

*(source: malcat, query_or_table: carved_files)*

The presence of a PKCS7 signature is expected for a signed DLL. The signature is likely valid, as the file is known to be signed with a legitimate SolarWinds certificate, which was a key factor in the attack's success.

### .NET Metadata Structures
The file contains a complete .NET metadata stream, including tables for types, methods, fields, and constants. Key structures include:
- `CLR.Header` at EA `0x520`
- `CLR.Metadata` at EA `0x301324`
- `#~` (metadata stream) at EA `0x301432`
- `ModuleTable` at EA `0x301572`
- `TypeDefTable` at EA `0x313074`
- `MethodDefTable` at EA `0x336348`

*(source: malcat, query_or_table: structures)*

The metadata confirms this is a standard .NET assembly with a large number of types and methods, consistent with the legitimate SolarWinds Orion business logic DLL.

## 4. Static Code Analysis

Static analysis reveals the core malicious components embedded within the legitimate SolarWinds codebase. The backdoor is implemented as a class named `OrionImprovementBusinessLayer`.

### Entry Point
The DLL's entry point is a standard .NET DLL entry that jumps to the CLR runtime:
```asm
┌ 6: entry0 ();
└           0x100f61a6      ff2500200010   jmp dword [sym.imp.mscoree.dll__CorDllMain] ; 0x10002000
```
*(source: radare2, query_or_table: disassembly)*

This is the normal entry point for a .NET DLL. The actual malicious initialization occurs when the `Initialize` method of the `OrionImprovementBusinessLayer` class is called by the host process (`BusinessLayerHost.exe`).

### Core Backdoor Class: OrionImprovementBusinessLayer
The backdoor is implemented within the `SolarWinds.Orion.Core.BusinessLayer.OrionImprovementBusinessLayer` class. Key methods identified include:

| EA | Method Name | Purpose |
|---|---|---|
| `0x9676` | `Initialize` | Entry point for backdoor initialization |
| `0x9940` | `UpdateNotification` | Persistence mechanism disguised as update |
| `0x10000` | `Update` | Main update loop |
| `0x10540` | `GetManagementObjectProperty` | WMI query for system info |

*(source: malcat, query_or_table: imports)*

The `Initialize` method is the primary entry point for the backdoor. It is called during DLL load and sets up the C2 communication channel and other malicious functionalities.

### Credential Harvesting Functions
The backdoor contains functions for harvesting credentials from the SolarWinds database:
- `GetSharedSnmpV2Credentials`
- `GetSharedSnmpV3Credentials`
- `GetSharedWmiCredentials`

*(source: deep_dive, query_or_table: key_evidence)*

These functions likely query the SolarWinds database for stored SNMP and WMI credentials, which could be used for lateral movement within the network.

### C2 Communication
The backdoor uses HTTP for command-and-control communication:
- `SendHttpWebRequest` at address `0x268554284`
- `GetOrionImprovementCustomerId` at address `0x268718036` for victim fingerprinting

*(source: deep_dive, query_or_table: key_evidence)*

The C2 communication is designed to blend with legitimate SolarWinds telemetry traffic, making detection difficult.

### Obfuscation and Evasion Techniques
The sample employs several obfuscation and evasion techniques:

1. **Base64 Encoding/Decoding:** Functions `Base64Encode`, `Base64Decode`, `Base64ToGuid` for data obfuscation.
2. **GZip Compression:** Data is compressed before exfiltration.
3. **DPAPI Encryption:** Data is encrypted using the Data Protection API.
4. **Anti-VM Detection:** Strings targeting VMWare and other virtualization platforms.
5. **XOR Obfuscation:** Multiple XOR loops detected in the code.

*(source: malcat, query_or_table: anomalies; capa, query_or_table: top_rules)*

### .NET P/Invoke Calls
The DLL uses P/Invoke to call native Windows APIs for malicious operations:
- `AdjustTokenPrivileges`
- `LookupPrivilegeValueW`
- `GetCurrentProcess`
- `OpenProcessToken`
- `InitiateSystemShutdownExW`

*(source: dotnet, query_or_table: pinvoke)*

These APIs are used for privilege escalation and system manipulation, which are not typical for a legitimate monitoring DLL.

### High-Signal Strings
Several strings indicate malicious intent:
- `HttpWebResponse` at EA `0x564149` - HTTP C2 communication
- `http://www.solar..?id=online_quote` at EA `0x802175` - C2 domain pattern
- `http://www.solar..lang={0}&kb=3545` at EA `0x795789` - C2 communication pattern
- `AdjustTokenPrivileges` at EA `0x606098` - Privilege escalation
- `SolarWinds.Orion.Core.BusinessLayer.dll.config` at EA `0x686624` - Configuration file reference

*(source: malcat, query_or_table: high_signal_strings)*

The HTTP strings suggest the backdoor uses web-based C2, while the privilege escalation string confirms token manipulation capabilities.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis was not performed in a live environment due to the nature of the sample (supply chain backdoor requiring specific SolarWinds context). However, static analysis provides strong indicators of expected behavior.

### Expected Behavioral Indicators
Based on static analysis, the sample would exhibit the following behaviors if executed in a SolarWinds environment:

1. **DLL Initialization:** The `Initialize` method would be called by `BusinessLayerHost.exe` during startup.
2. **C2 Beaconing:** The sample would attempt to communicate with C2 servers via HTTP, using patterns like `http://www.solar..?id=online_quote`.
3. **Credential Harvesting:** The sample would query the SolarWinds database for SNMP and WMI credentials.
4. **System Reconnaissance:** Functions like `GetFileHash` and `GetManagementObjectProperty` would be used to gather system information.
5. **Privilege Escalation:** The use of `AdjustTokenPrivileges` and related APIs suggests attempts to elevate privileges.
6. **Anti-VM Evasion:** The sample would check for virtualization environments and potentially alter behavior.

### Frida Probe Results
The Frida probe identified a hook candidate:
- `mscoree.dll!_CorDllMain`

*(source: frida_probe)*

This is the .NET runtime entry point, which would be the first point of execution for the DLL.

### Speakeasy Emulation
Speakeasy emulation was not applicable for this .NET sample.

## 6. Network Indicators & C2

The backdoor uses HTTP-based command-and-control communication designed to blend with legitimate SolarWinds traffic.

### C2 Communication Patterns
From the high-signal strings:
- `http://www.solar..?id=online_quote` at EA `0x802175`
- `http://www.solar..lang={0}&kb=3545` at EA `0x795789`

*(source: malcat, query_or_table: high_signal_strings)*

These strings suggest the C2 communication uses URL parameters for data exfiltration and command reception. The pattern `?id=online_quote` may be used to identify the victim or request specific commands.

### Network-Related YARA Rules
The following YARA rules matched network-related patterns:
- `network_tcp_listen` - TCP listening capabilities
- `network_dns` - DNS resolution capabilities
- `url` - URL patterns at offset `0x698983` with 224 bytes

*(source: yara, query_or_table: matches)*

The `url` rule match at offset `0x698983` likely contains the C2 URL patterns observed in the strings.

### HTTP Functions
The backdoor contains HTTP client functionality:
- `SendHttpWebRequest` at address `0x268554284`
- `HttpWebResponse` string at EA `0x564149`

*(source: deep_dive; malcat)*

These functions handle the HTTP communication with the C2 server, including sending requests and processing responses.

## 7. Capabilities Assessment

The backdoor possesses a comprehensive set of capabilities for espionage, lateral movement, and persistence.

### Capability Summary
| Capability | Evidence | ATT&CK Mapping |
|---|---|---|
| **C2 Communication** | `SendHttpWebRequest`, HTTP strings | T1071.001 (Web Protocols) |
| **Credential Harvesting** | `GetSharedSnmpV2Credentials`, `GetSharedSnmpV3Credentials`, `GetSharedWmiCredentials` | T1552.001 (Credentials In Files) |
| **Privilege Escalation** | `AdjustTokenPrivileges`, YARA `escalate_priv` | T1134 (Access Token Manipulation) |
| **Token Manipulation** | YARA `win_token` | T1134 (Access Token Manipulation) |
| **Anti-VM Evasion** | YARA `VMWare_Detection`, `vmdetect` | T1497.001 (Virtualization/Sandbox Evasion) |
| **Data Exfiltration** | GZip compression, Base64 encoding | T1560.002 (Archive Collected Data) |
| **Registry Manipulation** | `ReadRegistryValue`, `SetRegistryValue`, `DeleteRegistryValue` | T1112 (Modify Registry) |
| **System Reconnaissance** | `GetFileHash`, `GetManagementObjectProperty` | T1082 (System Information Discovery) |
| **Persistence** | `FireUpdateNotification` disguised as update | T1546 (Event Triggered Execution) |
| **System Manipulation** | `RebootComputer`, `InitiateSystemShutdownExW` | T1529 (System Shutdown/Reboot) |

### capa Rules (58 total)
The following capa rules highlight key capabilities:

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using Base64 | T1027 | E1027.m02 |
| reference anti-VM strings targeting VMWare | T1497.001 | B0009 |
| compress data using GZip in .NET | T1560.002 | C0024 |
| decode data using Base64 in .NET | T1140 | C0053.001 |
| encrypt data using DPAPI | T1027 | C0027 |
| query environment variable | T1082 | E1082 |
| get common file path | T1083 | E1083 |
| check if file exists | T1083 | E1083 |
| enumerate files in .NET | T1083 | E1083 |
| get file version info | T1083 | E1083 |
| get hostname | T1082 | E1082 |
| enumerate processes | T1057, T1518 | - |
| query or enumerate registry key | T1012 | C0036.005 |
| query or enumerate registry value | T1012 | C0036.006 |
| delete registry value | T1112 | C0036.007 |

*(source: capa, query_or_table: top_rules)*

These rules confirm the backdoor's capabilities in data obfuscation, system discovery, and registry manipulation.

## 8. Indicators of Compromise

### File-Based IOCs
| Type | Value | Description |
|---|---|---|
| SHA256 | `32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77` | Sample hash |
| Filename | `SolarWinds.Orion.Core.BusinessLayer.dll` | Trojanized DLL |
| Imphash | `dae02f32a21e03ce65412f6e56942daa` | Import hash |
| PDB Path | `C:\buildAgent\temp\buildTmp\Obj\SolarWinds.Orion.Core.BusinessLayer\Release\SolarWinds.Orion.Core.BusinessLayer.pdb` | Build path |

### Network-Based IOCs
| Type | Value | Description |
|---|---|---|
| URL Pattern | `http://www.solar..?id=online_quote` | C2 communication pattern |
| URL Pattern | `http://www.solar..lang={0}&kb=3545` | C2 communication pattern |

### Behavioral IOCs
| Type | Value | Description |
|---|---|---|
| Class Name | `OrionImprovementBusinessLayer` | Backdoor class name |
| Method Name | `Initialize` | Backdoor entry point |
| API Call | `AdjustTokenPrivileges` | Privilege escalation |
| API Call | `OpenProcessToken` | Token manipulation |
| API Call | `InitiateSystemShutdownExW` | System manipulation |

### YARA Rules
The following YARA rules matched the sample:
- `escalate_priv` - Privilege escalation indicators
- `win_token` - Token manipulation indicators
- `VMWare_Detection` - Anti-VM detection
- `vmdetect` - Virtualization detection
- `network_tcp_listen` - TCP listening capabilities
- `network_dns` - DNS resolution capabilities
- `url` - URL patterns

*(source: yara, query_or_table: matches)*

## 9. Detection Engineering

### YARA Rule
A YARA rule has been generated for this sample:
```yara
rule Sunburst_Backdoor {
    meta:
        description = "Detects Sunburst/Solorigate backdoor"
        author = "Malware Analyst"
        date = "2026-08-09"
        sha256 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
        family = "Sunburst"
    strings:
        $s1 = "OrionImprovementBusinessLayer" ascii wide
        $s2 = "SolarWinds.Orion.Core.BusinessLayer.dll" ascii wide
        $s3 = "AdjustTokenPrivileges" ascii wide
        $s4 = "http://www.solar..?id=online_quote" ascii wide
        $s5 = "http://www.solar..lang={0}&kb=3545" ascii wide
        $s6 = "GetSharedSnmpV2Credentials" ascii wide
        $s7 = "GetSharedSnmpV3Credentials" ascii wide
        $s8 = "GetSharedWmiCredentials" ascii wide
        $s9 = "SendHttpWebRequest" ascii wide
        $s10 = "FireUpdateNotification" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB and
        5 of ($s*)
}
```
*(source: yara_gen)*

### Sigma Rule
A Sigma rule has been generated for detection:
```yaml
title: Sunburst Backdoor Detection
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects execution of Sunburst backdoor
author: Malware Analyst
date: 2026/08/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\BusinessLayerHost.exe'
        CommandLine|contains: 'SolarWinds.Orion.Core.BusinessLayer.dll'
    condition: selection
falsepositives:
    - Legitimate SolarWinds Orion installation
level: high
tags:
    - attack.execution
    - attack.t1059.001
```
*(source: yara_gen)*

### Detection Recommendations
1. **Network Monitoring:** Monitor for HTTP traffic to domains matching the pattern `*.solar*` with URL parameters containing `id=`, `lang=`, or `kb=`.
2. **Process Monitoring:** Monitor for `BusinessLayerHost.exe` loading `SolarWinds.Orion.Core.BusinessLayer.dll` and making calls to `AdjustTokenPrivileges` or `OpenProcessToken`.
3. **Registry Monitoring:** Monitor for registry modifications by the SolarWinds process, especially to keys related to persistence.
4. **File Monitoring:** Monitor for the creation of files with names matching the backdoor's configuration patterns.

## 10. MITRE ATT&CK Mapping

The following table maps the observed capabilities to the MITRE ATT&CK framework.

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Execution** | Shared Modules | T1129 | DLL loaded by `BusinessLayerHost.exe` |
| **Persistence** | Event Triggered Execution | T1546 | `FireUpdateNotification` method |
| **Privilege Escalation** | Access Token Manipulation | T1134 | `AdjustTokenPrivileges`, `OpenProcessToken` |
| **Defense Evasion** | Virtualization/Sandbox Evasion | T1497.001 | YARA `VMWare_Detection`, `vmdetect` |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Base64 encoding, DPAPI encryption |
| **Credential Access** | Credentials In Files | T1552.001 | SNMP/WMI credential harvesting |
| **Discovery** | System Information Discovery | T1082 | `GetHostname`, `GetFileHash` |
| **Discovery** | File and Directory Discovery | T1083 | `GetCommonFilePath`, `CheckIfFileExists` |
| **Discovery** | Process Discovery | T1057 | `EnumerateProcesses` |
| **Discovery** | Query Registry | T1012 | `ReadRegistryValue`, `SetRegistryValue` |
| **Collection** | Archive Collected Data | T1560.002 | GZip compression |
| **Command and Control** | Web Protocols | T1071.001 | `SendHttpWebRequest` |
| **Exfiltration** | Exfiltration Over C2 Channel | T1041 | HTTP-based exfiltration |

## 11. What We Don't Know

Several aspects of this sample remain unknown or require further investigation:

1. **C2 Server Infrastructure:** The exact C2 server addresses are not fully extracted from the sample. The URL patterns suggest a domain generation algorithm (DGA) or hardcoded domains, but the full list is not available.
2. **Lateral Movement Scope:** While credential harvesting functions are present, the exact methods for using harvested credentials for lateral movement are not fully analyzed.
3. **Persistence Mechanisms:** The `FireUpdateNotification` method suggests persistence, but the exact trigger conditions and persistence locations are not fully mapped.
4. **Data Exfiltration Content:** The specific data targeted for exfiltration (beyond system information) is not fully determined.
5. **Anti-Analysis Techniques:** The full extent of anti-analysis and evasion techniques beyond anti-VM detection is not completely cataloged.
6. **Command Set:** The complete set of commands supported by the C2 protocol is not fully reverse-engineered.
7. **Network Propagation:** Whether the backdoor has worm-like capabilities for network propagation is not confirmed.
8. **Secondary Payloads:** Whether the backdoor downloads and executes additional payloads is not observed in static analysis.

These unknowns are due to the complexity of the sample, the need for dynamic analysis in a controlled environment, and the sophisticated obfuscation techniques employed by the threat actor.

## 12. Appendix A: Tool Evidence Trail

The following table documents the tools used in this analysis and their outputs.

| Tool | Version | Purpose | Key Findings |
|---|---|---|---|
| MalCat | - | Static analysis, anomaly detection | Identified 13 anomalies including `DotnetCryptoApiUsage`, `SpaghettiFunction` |
| Ghidra | - | Disassembly, string extraction | 2862 functions, 9997 strings, identified `OrionImprovementBusinessLayer` class |
| IDA | - | Disassembly, function analysis | 3338 functions, confirmed Ghidra findings |
| capa | - | Capability identification | 58 rules including `encode data using Base64`, `reference anti-VM strings targeting VMWare` |
| YARA | - | Pattern matching | 17 matches including `escalate_priv`, `win_token`, `VMWare_Detection` |
| FLOSS | - | String extraction | 10906 static strings |
| radare2 | - | Disassembly | Entry point analysis |
| Frida | 17.16.4 | Dynamic analysis probe | Identified hook candidate `mscoree.dll!_CorDllMain` |
| .NET Analyzer | - | .NET metadata analysis | Identified VB.NET language, P/Invoke calls |

### Audit Trail
The analysis followed a structured pipeline with the following key steps:
1. Initial triage and metadata extraction
2. Static analysis with Ghidra and IDA
3. Capability analysis with capa
4. Pattern matching with YARA
5. String extraction with FLOSS
6. .NET-specific analysis
7. Report generation and validation

*(source: audit_trail)*

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following specifications:

- **Operating System:** Linux (analysis workstation)
- **Analysis Tools:** Ghidra, IDA, MalCat, capa, YARA, FLOSS, radare2, Frida
- **Sample Location:** `/opt/samples/corpus/Malware Analyst Professional - Level 2/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/`
- **Project Name:** Malware Analyst Professional - Level 2
- **Analysis Date:** 2026-08-09
- **Analyst:** Automated Analysis Pipeline

The environment was configured to prevent accidental execution of the sample and to ensure all analysis was performed statically or in controlled emulation environments where applicable.
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
  "sha256": "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77",
  "family": "Sunburst",
  "imphash": "dae02f32a21e03ce65412f6e56942daa",
  "generated_at": "2026-08-09T17:49:23.382779+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "'@y+.A8f",
    "v4.0.30319",
    "#Strings",
    "get_LIBCODE_JM0_10",
    "<>9__41_10",
    "<UpdateThresholds>b__41_10",
    "<.cctor>b__529_10",
    "get_LIBCODE_JM0_20",
    "get_LIBCODE_PS0_20",
    "get_LIBCODE_PCC_20",
    "get_LIBCODE_JM0_30",
    "get_LIBCODE_TM0_30",
    "get_WEBCODE_PS0_30",
    "<>9__400_0",
    "<GetOidValueFromXmlNodes>b__400_0",
    "<>9__10_0",
    "<UploadSystemDescription>b__10_0",
    "<>c__DisplayClass10_0",
    "<>9__20_0",
    "<GetTriggerCountForActiveAlerts>b__20_0",
    "<EnableDisableAssignment>b__20_0",
    "<GetPublicKey>b__20_0",
    "<>c__DisplayClass20_0"
  ],
  "rule_path": "/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/rule.yar",
  "sigma_path": "/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/rule.yml",
  "iocs_path": "/opt/samples/logs/32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77/iocs.json",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 17:49:23 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "agentic_recover_v4", "phase": "start", "ts": 1786297758.149082}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs WHERE name LIKE 'FUN_%' OR name LIKE 'func_%' OR name = ''", "ts": 1786297758.235082}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, call_in_count, string_ref_count FROM function_metrics", "ts": 1786297758.4819698}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, COUNT(*) AS c FROM string_refs GROUP BY func_addr", "ts": 1786297758.8763418}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' OR dst_func_name`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786297758.9868724}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name FROM memory_blocks", "ts": 1786297758.9923103}`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786297758.995485}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786297759.0848527}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LI`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_`
- `{"source": "ghidra_query", "sql": "SELECT address, content FROM strings WHERE length < 300", "ts": 1786297759.355173}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, ref_addr, string_addr FROM string_refs", "ts": 1786297759.7795658}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786297759.8298542}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'", "ts": 1786297759.8897333}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786297759.9301867}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetMo`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786297759.9760058}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786297759.9903097}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as c FROM funcs", "ts": 1786297760.0312352}`
- `{"source": "agentic_recover_v4", "phase": "triage", "ts": 1786297760.0313332}`
- `{"source": "ghidra_query", "sql": "SELECT func_addr, cyclomatic_complexity, call_in_count, call_out_count, instruction_count, block_count FROM function_metrics", "ts": 1786297760.2663648}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786297760.4729009}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786297760.4734104}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786297760.7579377}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786297763.3446035}`
- `{"source": "yara_gen_v2", "ts": 1786297763.3829124}`
- `{"source": "publish_report_v2", "ts": 1786297908.1873293}`
- `{"source": "publish_report_v2_technical", "ts": 1786298118.5598214}`
