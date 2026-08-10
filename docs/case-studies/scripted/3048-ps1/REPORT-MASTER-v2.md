> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:22:26 UTC

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

This report details the analysis of a PowerShell script (SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2) identified as malicious. The script functions as a dropper/loader, employing architecture-aware execution, hidden window launch, and a double-encoded (Base64 + GZip) payload delivered via dynamic code execution. The payload is consistent with techniques used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. Key behavioral indicators include YARA rule matches for shell execution, PowerShell abuse, Base64 obfuscation, and process control APIs. The script's high entropy and obfuscation are neutral signals, but the combination of hidden execution, dynamic code creation, and process manipulation constitutes clear behavioral intent for malicious activity, likely for lateral movement, payload delivery, or command-and-control operations. The sample is classified as malicious with high confidence.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 |
| File Path | /opt/samples/corpus/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1 |
| Project | day6 |
| File Type | text/utf8 (PowerShell script) |
| Size | 2800 bytes |
| Entropy | 148 (high for a text file, indicating encoded/obfuscated content) |
| Architecture | NONE (script, not a native binary) |
| .NET Analysis | Not a .NET assembly |

The sample is a UTF-8 encoded PowerShell script. The high entropy value of 148 for a 2800-byte text file is a strong indicator of encoded or obfuscated content, which is a common evasion technique in malicious scripts (source: malcat, file_summary.entropy).

## 2. Classification

| Field | Value |
|---|---|
| Verdict | Malicious |
| Confidence | 90 |
| Family | PowerShell-based malware |
| Score | 40.0 (Triage) / 90 (Deep-dive) |
| Key Behavioral Signals | Hidden execution, dynamic code creation, process control APIs, Base64/GZip encoding |

The classification is based on behavioral intent evidence, not obfuscation alone. The script exhibits multiple hostile behaviors: it launches a hidden PowerShell window (`-nop -w hidden`), performs architecture checks for 32/64-bit compatibility, and dynamically creates and executes a double-encoded payload using `[scriptblock]::create()` (source: deep-dive.json). These are classic techniques for evading detection and executing arbitrary code, which are hallmarks of malicious droppers and loaders. The upstream triage verdict of "malicious" is confirmed and calibrated with high confidence.

## 3. Background & Family Lineage

The script's techniques are consistent with several well-known PowerShell-based attack frameworks:

- **PowerShell Empire**: Uses similar Base64/GZip encoding for stagers and payloads.
- **Cobalt Strike**: Employs PowerShell-based stagers for initial access and lateral movement.
- **Document-Embedded Macros**: Often use similar encoding and hidden execution to deliver payloads from Office documents.

The specific combination of architecture-aware execution (`[IntPtr]::Size -eq 4` with sysnative path workaround) and dynamic code creation via `[scriptblock]::create()` is a pattern seen in advanced PowerShell stagers designed for cross-architecture compatibility (source: deep-dive.json). While no specific family name is definitively identified, the techniques align with the broader category of "PowerShell-based malware" used for initial access, lateral movement, and payload delivery.

## 4. Static Analysis

### File Properties
- **Type**: text/utf8 PowerShell script (source: malcat, file type)
- **Entropy**: 148 (source: malcat, file_summary.entropy) - High entropy for a text file indicates encoded or obfuscated content.
- **Size**: 2800 bytes (source: malcat, file_summary)

### String Analysis
The script contains numerous strings indicative of malicious functionality:

| String/Pattern | Interpretation | Evidence Source |
|---|---|---|
| `-nop -w hidden -c` | Hidden PowerShell execution with no profile, a common evasion technique. | deep-dive.json (IDA strings) |
| `[IntPtr]::Size -eq 4` | Architecture check for 32-bit vs 64-bit, enabling cross-platform payload delivery. | deep-dive.json (IDA strings) |
| `[scriptblock]::create()` | Dynamic code execution, allowing the script to create and run code from a string. | deep-dive.json (IDA strings) |
| `H4sI` (GZip magic header) | Indicates a GZip-compressed payload, which is then Base64-encoded. | deep-dive.json (IDA strings) |
| `ProcessStartInfo`, `RedirectStandardOutput` | APIs for launching and controlling external processes. | malcat, strings/apis |
| `UseShellExecute`, `CreateNoWindow`, `WindowStyle` | APIs for process execution with hidden windows. | malcat, strings/apis |
| `StreamReader`, `ReadToEnd`, `MemoryStream` | APIs for reading data streams, likely used for payload decoding. | malcat, strings/apis |
| `WindowsPowerShell` | Reference to the PowerShell executable. | malcat, strings/apis |

### YARA Matches
Multiple YARA rules fired, confirming the script's nature and capabilities:

| Rule | Category | Reliability | Interpretation | Evidence Source |
|---|---|---|---|---|
| RunShell | Lateral Movement | 70 | Indicates the script starts a shell, a behavioral signal for command execution. | malcat, views.yara_hits |
| Powershell | Lateral Movement | 30 | Confirms the script is PowerShell-based. | malcat, views.yara_hits |
| contains_base64 | Obfuscation | N/A | Base64 strings suggest obfuscation. | yara, yara matches |
| domain_regex | Network | N/A | Contains patterns resembling domain names. | yara, yara matches |
| IP | Network | N/A | Contains patterns resembling IP addresses. | yara, yara matches |
| Antivirus | Defense Evasion | N/A | May contain strings related to antivirus evasion. | yara, yara matches |

The `RunShell` and `Powershell` rules are high-signal behavioral indicators. The `contains_base64` rule corroborates the obfuscation technique (source: yara, yara matches).

### Disassembly (Radare2)
The Radare2 disassembly of the script's raw bytes is largely nonsensical for a text file, as it attempts to interpret UTF-8 text as x86-64 instructions. The disassembly shows references to strings like `ell\\` and `ell.`, which are fragments of the PowerShell script content (e.g., `shell.exe`). This is not meaningful native code analysis but confirms the file is not a native binary (source: radare2, pdf (disasm)).

## 5. Behavioral Analysis

No runtime behavioral analysis (e.g., via Speakeasy or Frida) was performed on this sample. The behavioral assessment is derived entirely from static analysis of the script's code and capabilities.

**Observed Capabilities (from static analysis):**
1. **Hidden Execution**: The script uses `-nop -w hidden -c` to launch PowerShell with no profile and a hidden window, a technique to avoid user detection (source: deep-dive.json).
2. **Architecture Awareness**: It checks `[IntPtr]::Size -eq 4` and uses the `sysnative` path to ensure compatibility across 32-bit and 64-bit systems (source: deep-dive.json).
3. **Dynamic Code Execution**: The payload is decoded (Base64 + GZip) and executed via `[scriptblock]::create()`, allowing arbitrary code execution (source: deep-dive.json).
4. **Process Control**: APIs like `ProcessStartInfo`, `UseShellExecute`, and `CreateNoWindow` indicate the ability to launch and control external processes (source: malcat, strings/apis).

**Implication**: These capabilities are consistent with a dropper/loader designed to execute a secondary payload while evading detection. The lack of runtime data means we cannot observe the final payload's actions (e.g., C2 communication, lateral movement, data exfiltration).

## 6. Network Analysis & C2

No network activity was observed during analysis. However, static indicators suggest potential network capabilities:

- **YARA Matches**: The `domain_regex` and `IP` rules fired, indicating the script contains patterns resembling domain names and IP addresses (source: yara, yara matches). These could be hardcoded C2 addresses, callback URLs, or decoy strings.
- **Payload Delivery**: The script's primary function is to deliver and execute an encoded payload. This payload could contain network communication code for C2, beaconing, or data exfiltration.

**Assessment**: The script itself does not perform network communication, but it is a vehicle for delivering a payload that likely does. The presence of domain/IP patterns is suspicious and warrants further investigation of the decoded payload.

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| Hidden Execution | Observed (static) | `-nop -w hidden -c` flags (source: deep-dive.json) |
| Architecture Evasion | Observed (static) | `[IntPtr]::Size -eq 4` check (source: deep-dive.json) |
| Dynamic Code Execution | Observed (static) | `[scriptblock]::create()` with decoded payload (source: deep-dive.json) |
| Process Control | Observed (static) | `ProcessStartInfo`, `UseShellExecute` APIs (source: malcat, strings/apis) |
| Obfuscation | Observed (static) | Base64 + GZip encoding, high entropy (source: yara, malcat) |
| Network Communication | Latent (not observed) | Domain/IP patterns in YARA matches (source: yara) |
| Lateral Movement | Latent (not observed) | `RunShell` YARA rule (source: malcat) |
| Credential Theft | Not Observed | No evidence found |
| Persistence | Not Observed | No evidence found |
| Defense Evasion | Observed (static) | Hidden window, no profile, obfuscation (source: deep-dive.json) |

The script's observed capabilities are focused on evasion and payload delivery. The latent capabilities (network, lateral movement) are inferred from YARA rules and the script's role as a dropper, but are not directly observed in the static code.

## 8. Attribution

No specific threat actor or campaign attribution is possible based on the available evidence. The techniques used are common across multiple threat actors and frameworks (PowerShell Empire, Cobalt Strike, etc.). The script's simplicity and lack of unique identifiers (e.g., custom encryption keys, unique strings) make attribution difficult.

## 9. Indicators of Compromise

### File-Based IOCs
| Type | Value | Context |
|---|---|---|
| SHA256 | 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 | Malicious PowerShell script |
| File Name | 3048.ps1 | Original sample name |

### String-Based IOCs (from static analysis)
| String | Context |
|---|---|
| `-nop -w hidden -c` | Hidden PowerShell execution command line |
| `[IntPtr]::Size -eq 4` | Architecture check string |
| `[scriptblock]::create()` | Dynamic code execution method |
| `H4sI` | GZip magic header (start of compressed payload) |
| `ProcessStartInfo` | .NET API for process creation |
| `UseShellExecute` | .NET API for shell execution |
| `CreateNoWindow` | .NET API to hide process window |
| `WindowsPowerShell` | PowerShell executable reference |

### YARA Rule-Based IOCs
The following YARA rules matched and can be used for detection:
- `RunShell` (category: lateral movement)
- `Powershell` (category: lateral movement)
- `contains_base64` (category: obfuscation)
- `domain_regex` (category: network)
- `IP` (category: network)
- `Antivirus` (category: defense evasion)

## 10. Detection Rules

### YARA Rule
A custom YARA rule was generated for this sample. The rule file is located at:
`/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/rule.yar`

The rule is based on the key strings and patterns identified during analysis, including the hidden execution flags, architecture check, and dynamic code execution method (source: rule.yara.json).

### Sigma Rule
A Sigma rule for detection was generated and is located at:
`/opt/samples/logs/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/rule.yml`

### Behavioral Detection (Conceptual)
- **Process Creation**: Detect PowerShell processes launched with `-w hidden` and `-nop` flags.
- **Script Block Logging**: Monitor for `[scriptblock]::create()` calls with Base64-encoded arguments.
- **Network Connections**: Look for connections to domains/IPs matching patterns found in the script.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Script is PowerShell (source: malcat, yara) |
| Execution | Shared Modules | T1129 | Dynamic code execution via `[scriptblock]::create()` (source: deep-dive.json) |
| Defense Evasion | Obfuscated Files or Information | T1027 | Base64 + GZip encoding, high entropy (source: yara, malcat) |
| Defense Evasion | Hidden Window | T1564.003 | `-w hidden` flag (source: deep-dive.json) |
| Defense Evasion | Process Injection | T1055 | Potential via `ProcessStartInfo` APIs (source: malcat) |
| Discovery | System Information Discovery | T1082 | Architecture check (`[IntPtr]::Size`) (source: deep-dive.json) |
| Lateral Movement | Remote Services | T1021 | `RunShell` YARA rule suggests shell execution (source: malcat) |

## 12. Containment, Eradication, Recovery

### Containment
1. **Isolate Affected Systems**: Immediately isolate any system where this script was executed to prevent lateral movement.
2. **Block IOCs**: Add the file hash and any identified network indicators to blocklists at the network perimeter and endpoint protection.
3. **Disable PowerShell**: If not required for business operations, consider disabling PowerShell on critical systems via Group Policy.

### Eradication
1. **Remove Malicious Files**: Delete the script file (`3048.ps1`) and any payloads it may have dropped.
2. **Terminate Malicious Processes**: Identify and terminate any processes spawned by the script (e.g., hidden PowerShell instances).
3. **Scan for Persistence**: Check common persistence locations (registry run keys, scheduled tasks, startup folders) for any artifacts left by the payload.

### Recovery
1. **Restore from Backup**: If the payload caused damage (e.g., file encryption, data deletion), restore affected files from a known-good backup.
2. **Patch and Harden**: Ensure all systems are patched and hardened against the initial access vector (e.g., phishing, vulnerable services).
3. **Monitor for Recurrence**: Increase monitoring for similar PowerShell-based attacks and review logs for any signs of compromise.

## 13. Recommendations

1. **Implement PowerShell Logging**: Enable PowerShell Script Block Logging and Module Logging to capture executed scripts for forensic analysis.
2. **Restrict PowerShell Execution**: Use AppLocker or Windows Defender Application Control (WDAC) to restrict PowerShell execution to signed scripts or specific users.
3. **Enhance Endpoint Detection**: Deploy endpoint detection and response (EDR) solutions with behavioral detection for hidden PowerShell execution and dynamic code creation.
4. **User Training**: Educate users on the risks of executing unknown scripts and phishing emails that may deliver such payloads.
5. **Network Segmentation**: Implement network segmentation to limit lateral movement opportunities for attackers.
6. **Regular IOC Updates**: Continuously update blocklists with new IOCs from threat intelligence feeds.

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|---|---|---|---|
| malcat | views.yara_hits | RunShell | YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution. |
| malcat | views.yara_hits | Powershell | YARA rule confirms the script is PowerShell-based. |
| yara | yara matches | powershell | YARA rule matched for PowerShell content. |
| yara | yara matches | contains_base64 | Base64 strings suggest obfuscation. |
| malcat | strings/apis | ProcessStartInfo, RedirectStandardOutput, etc. | APIs related to process execution indicate the script can launch and control processes. |
| malcat | file_summary.entropy | 148 | High entropy for a text file may indicate encoded or obfuscated content. |
| deep-dive.json | IDA strings | `-nop -w hidden -c` | Hidden execution with no PowerShell profile. |
| deep-dive.json | IDA strings | `[IntPtr]::Size -eq 4` | Architecture check for 32/64-bit compatibility. |
| deep-dive.json | IDA strings | `[scriptblock]::create()` | Dynamic code execution with GZip+Base64 decoded payload. |
| rule.yara.json | rule_path | /opt/samples/logs/.../rule.yar | Generated YARA rule for detection. |
| rule.yara.json | sigma_path | /opt/samples/logs/.../rule.yml | Generated Sigma rule for detection. |

## 15. Appendix B: Module Inventory

This sample is a single PowerShell script. There are no separate modules or components. The script itself contains all functionality, including the encoded payload.

| Component | Description | Evidence |
|---|---|---|
| Main Script | PowerShell dropper/loader with evasion techniques. | SHA256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2 |
| Encoded Payload | Double-encoded (Base64 + GZip) payload embedded in the script. | Identified by `H4sI` GZip header and Base64 strings (source: deep-dive.json). |

## 16. Author + Sign-off

**Report Author**: Automated Malware Analysis System (RevAI)
**Date**: 2026-08-09
**Version**: 2.0

**Sign-off**: This report was generated by an automated analysis pipeline. All findings are based on the provided evidence and tool outputs. The verdict of "malicious" is supported by behavioral intent evidence, including hidden execution, dynamic code creation, and process control APIs. The analysis is limited to static techniques due to the absence of runtime data.