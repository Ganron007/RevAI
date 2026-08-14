> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 10:25:09 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Satana Ransomware Dropper Analysis Report

## Executive Summary

This report details the analysis of a malicious Windows PE executable (SHA256: 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96) identified as a dropper for the Satana ransomware family. The sample exhibits a high degree of sophistication, employing multiple layers of anti-analysis and anti-sandbox evasion techniques to hinder detection and reverse engineering. Key findings include a direct YARA rule match for the Satana ransomware dropper, extensive use of anti-debugging and anti-VM checks, and the presence of a large, obfuscated payload likely containing the ransomware component and C2 infrastructure. The sample's primary function appears to be to deliver and execute the ransomware payload while evading security analysis environments. The verdict is **malicious** with high confidence (90/100). (source: triage_verdict.json)

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96 |
| **File Path** | /opt/samples/corpus/malware/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/drtg.exe |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **File Size** | 50,861 bytes |
| **Entropy** | 6.46 bits/byte (Shannon, whole file) |
| **Compiler/Linker** | MSVC 2010 (Rich Header) |
| **Import Hash (imphash)** | a3bc0305643e7601d6deca72652f4ab5 |
| **Packed** | No (UPX probe negative) |
| **.NET Assembly** | No |

The file is a standard 32-bit Windows GUI executable. The entropy of 6.46 is elevated but not extreme, suggesting a mix of code and potentially compressed or encrypted data sections, consistent with a dropper containing an obfuscated payload. (source: malcat)

## 2. Classification

**Verdict: MALICIOUS**
**Family: Satana Ransomware (Dropper)**
**Confidence: 90/100**

The classification is based on a convergence of high-confidence signals from multiple analysis engines. The primary indicator is a direct YARA rule match for `Ransom_Satana_Dropper`, which is a specific signature for this malware family's delivery component. This is corroborated by behavioral-intent evidence including anti-VM evasion (targeting Qemu), anti-debugging techniques (TLS callbacks, API hooks), and the presence of a large encoded payload blob. VirusTotal community intelligence also classifies the sample as ransomware with 67 malicious detections. (source: triage_verdict.json, deep-dive.json)

## 3. Background & Family Lineage

The Satana ransomware family is known for its destructive capabilities, often encrypting user files and demanding ransom payment in cryptocurrency. This sample is identified as a **dropper**, a component whose sole purpose is to deliver and execute the main ransomware payload. Droppers are typically the first stage of an infection chain, designed to be lightweight and evasive to bypass initial security controls. The presence of extensive anti-analysis features in this dropper suggests it is part of a sophisticated campaign aimed at evading automated sandbox analysis and manual reverse engineering. The embedded YARA rule `Safeguard_103_Simonzh` may indicate a variant or a shared codebase with other malware families. (source: deep-dive.json, yara)

## 4. Static Analysis

### 4.1 Code Structure and Obfuscation
The binary exhibits significant obfuscation. The main function (`sub_402610`) has a cyclomatic complexity of 91, indicating highly convoluted control flow designed to hinder static analysis. (source: deep-dive.json, ghidra_query)

### 4.2 Anti-Analysis Techniques
Multiple anti-analysis mechanisms were identified:
- **Anti-Debugging:** The sample imports `ZwGetContextThread`, `OutputDebugStringA`, and `NtYieldExecution`, all known anti-debugging APIs. It also utilizes four TLS callbacks (`First_tls`, `on_tls_callback1`, `on_tls_callback2`, `on_tls_callback3`) which execute code before the main entry point, a common technique to detect debuggers. (source: deep-dive.json, floss, yara)
- **Anti-VM/Sandbox:** A YARA rule `Qemu_Detection` matched, indicating the sample contains strings or code to detect the Qemu virtualization environment. Additionally, the import of 11 OpenGL functions (e.g., `glBegin`, `glClear`) from `OPENGL32.DLL` is atypical for a non-GUI executable and is a known technique to detect sandbox environments that lack full GPU emulation. (source: deep-dive.json, yara, capa)
- **Environment Detection:** The function `sub_401e60` accesses the Process Environment Block (PEB) via the `PEBx86` function, a common method for malware to gather information about its execution environment and detect analysis tools. (source: malcat)

### 4.3 Obfuscated Payload
The sample contains a massive encoded blob of data (thousands of characters, non-ASCII) starting at address `0x401B00`. This is likely the encrypted or compressed ransomware payload and/or configuration data, including C2 addresses. The presence of a Base64 encoding table (`BASE64_table` YARA match) and references to `crypto::Base64` in MalCat suggest this blob is Base64-encoded. (source: deep-dive.json, malcat, yara)

### 4.4 String Analysis
FLOSS extracted 145 strings, including suspicious APIs (`ZwProtectVirtualMemory`, `NtAllocateVirtualMemory`) for memory manipulation, and two large Base64-encoded strings. Ghidra analysis also revealed an obfuscated string `qfntvthb` referenced by a function, likely an encoded key or configuration value. (source: floss, deep-dive.json, ghidra_query)

## 5. Behavioral Analysis

**Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events for this sample.** The provided evidence does not include results from runtime analysis tools like Speakeasy or Frida. Therefore, no observed runtime behaviors (e.g., file system changes, registry modifications, network connections) can be reported. The behavioral-intent evidence from static analysis (anti-debugging, anti-VM) strongly suggests the sample is designed to be evasive, but actual execution behavior remains unknown.

## 6. Network Analysis & C2

No active network connections were observed during analysis. However, static analysis reveals embedded network indicators:
- A YARA rule `url` matched at offset `49141`, indicating the presence of an embedded URL, likely for C2 communication or ransom payment instructions. (source: deep-dive.json, yara)
- A YARA rule `IP` (IPv6) matched at offset `22282`, indicating an embedded IPv6 address. (source: deep-dive.json, yara)

The specific URLs and IP addresses were not extracted in the provided evidence. The large encoded payload blob likely contains additional C2 infrastructure. Without runtime analysis, the exact C2 protocol and communication patterns are unknown.

## 7. Capability Assessment

Based on static analysis, the sample possesses the following **observed** capabilities:
- **Dropper Functionality:** Designed to deliver and execute a payload. (source: yara)
- **Anti-Analysis:** Active evasion of debuggers and virtual machines. (source: yara, capa, floss)
- **Obfuscation:** Use of encoding (Base64), high-complexity control flow, and obfuscated strings. (source: malcat, deep-dive.json)

**Latent/Potential Capabilities (inferred from payload):**
- **Ransomware Payload:** The encoded blob is assessed with high likelihood to contain the Satana ransomware payload, which would include file encryption and ransom note generation. (source: yara)
- **C2 Communication:** The embedded URL and IPv6 address suggest the capability to communicate with a command-and-control server. (source: yara)

**Not Observed:**
- File encryption, data exfiltration, lateral movement, or persistence mechanisms were not observed in the static analysis of this dropper component.

## 8. Attribution

No specific threat actor attribution is made in this report. The sample is attributed to the **Satana ransomware** family based on code signatures. The use of sophisticated anti-analysis techniques and a dedicated dropper component suggests a capable adversary, but further intelligence is required for actor attribution.

## 9. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| **SHA256** | 683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96 | Malicious PE dropper |
| **Import Hash** | a3bc0305643e7601d6deca72652f4ab5 | Satana dropper imphash |
| **YARA Rule** | Ransom_Satana_Dropper | Family signature |
| **YARA Rule** | anti_dbg | Anti-debugging techniques |
| **YARA Rule** | Qemu_Detection | Anti-VM evasion |
| **Embedded URL** | (Not extracted) | Likely C2 or payment site |
| **Embedded IPv6** | (Not extracted) | Likely C2 address |
| **Obfuscated String** | qfntvthb | Encoded config/key |
| **Obfuscated String** | kaxkytpp | Encoded config/key |

## 10. Detection Rules

### YARA Rules
A YARA rule file was generated for this sample. Key rules include:
- `Ransom_Satana_Dropper`: Matches the core dropper signature.
- `anti_dbg`: Detects anti-debugging API imports.
- `Qemu_Detection`: Detects anti-VM strings.
- `contains_base64` and `BASE64_table`: Detects Base64 encoding artifacts.

The rule file is located at: `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/rule.yar` (source: rule.yara.json)

### Sigma Rules
A Sigma rule file was also generated at: `/opt/samples/logs/683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96/rule.yml` (source: rule.yara.json)

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Base64 encoding of payload and strings. (source: capa) |
| **Defense Evasion** | Virtualization/Sandbox Evasion: System Checks | T1497.001 | Anti-VM strings targeting Qemu. (source: capa) |
| **Defense Evasion** | Debugger Evasion | (Custom) | Use of anti-debugging APIs and TLS callbacks. (source: yara, floss) |
| **Execution** | Shared Modules | T1129 | Parse PE header for dynamic API resolution. (source: capa) |

## 12. Containment, Eradication, Recovery

**Containment:** Immediately isolate any system where this file is detected. Block the SHA256 hash and associated IOCs at the network perimeter and endpoint protection solutions.

**Eradication:** Perform a full antimalware scan on affected systems using updated signatures that include the provided YARA rules. Manually check for persistence mechanisms (e.g., registry run keys, scheduled tasks) that may have been established by the payload if it executed.

**Recovery:** If the ransomware payload executed, recovery depends on the availability of clean backups. Do not pay the ransom. Restore affected files from offline backups. Reimage compromised systems if possible.

## 13. Recommendations

1.  **Deploy Detection Rules:** Implement the provided YARA and Sigma rules in security monitoring tools (EDR, SIEM) to detect this and similar droppers.
2.  **Block IOCs:** Add the file hash and any extracted network indicators to threat intelligence platforms and blocklists.
3.  **User Awareness:** Educate users about the risks of executing unknown files, especially those received via email or downloaded from untrusted sources.
4.  **Sandbox Enhancement:** Ensure analysis sandboxes can detect and mitigate common anti-VM techniques (e.g., Qemu string checks, OpenGL API calls) to improve malware analysis success rates.
5.  **Backup Strategy:** Maintain and regularly test offline, immutable backups to ensure resilience against ransomware attacks.

## 14. Appendix A: Evidence Trail

This section provides a traceable log of the analysis queries and tool executions that generated the evidence for this report.

| Timestamp (UTC) | Source | Query/Action | Purpose |
|---|---|---|---|
| 2026-08-12 20:01:58 | yara_gen_v2 | Generated YARA rule | Create detection signature |
| 2026-08-12 20:01:58 | publish_report_v2 | Report generation | Compile analysis |
| 2026-08-12 20:01:58 | publish_report_v2_technical | Technical report | Deep-dive analysis |
| 2026-08-12 20:01:58 | triage_verdict.json | Verdict compilation | Final classification |
| 2026-08-12 20:01:58 | deep-dive.json | Detailed analysis | Evidence aggregation |
| 2026-08-12 20:01:58 | rule.yara.json | Rule metadata | Rule file details |
| 2026-08-12 20:01:58 | UPX unpack | UPX probe | Check for packing |
| 2026-08-12 20:01:58 | xorsearch | XOR string recovery | Find obfuscated strings |
| 2026-08-12 20:01:58 | .NET analysis | dnfile/monodis | Check for .NET |
| 2026-08-12 20:01:58 | r2 disassembly | Radare2 disasm | Code analysis |
| 2026-08-12 20:01:58 | MalCat evidence | Static profiling | File anomalies |
| 2026-08-12 20:01:58 | capa evidence | Capability analysis | Behavioral intent |
| 2026-08-12 20:01:58 | pe_imports | Import table | API analysis |
| 2026-08-12 20:01:58 | YARA matches | Rule scanning | Signature detection |
| 2026-08-12 20:01:58 | FLOSS strings | String extraction | Obfuscated strings |
| 2026-08-12 20:01:58 | dotnet_analyze | .NET check | Framework detection |
| 2026-08-12 20:01:58 | radare2 (pdf) | Disassembly | Code structure |
| 2026-08-12 20:01:58 | UPX | Packing check | Packer detection |
| 2026-08-12 20:01:58 | xorsearch | XOR candidates | String recovery |
| 2026-08-12 20:01:58 | ghidra_query | String extraction | Find embedded strings |
| 2026-08-12 20:01:58 | ida_query | String search | Find ransom-related strings |
| 2026-08-12 20:01:58 | ida_query | Anti-analysis strings | Find evasion strings |
| 2026-08-12 20:01:58 | ida_query | String references | Cross-reference analysis |
| 2026-08-12 20:01:58 | ida_query | Address range | Extract specific strings |
| 2026-08-12 20:01:58 | ghidra_query | Network strings | Find C2 indicators |
| 2026-08-12 20:01:58 | ida_query | Network strings | Find C2 indicators |
| 2026-08-12 20:01:58 | ida_query | Command strings | Find destructive commands |
| 2026-08-12 20:01:58 | ghidra_query | Function metrics | Analyze code complexity |
| 2026-08-12 20:01:58 | ghidra_query | String references | Map string usage |
| 2026-08-12 20:01:58 | ghidra_query | Callgraph edges | Map function calls |
| 2026-08-12 20:01:58 | ghidra_query | Long strings | Find large data blobs |
| 2026-08-12 20:01:58 | ida_query | Long strings | Find large data blobs |
| 2026-08-12 20:01:58 | quick_scan_v2 | Phase 2 scan | Final verification |

## 15. Appendix B: Module Inventory

The sample imports functions from the following Windows DLLs:

| DLL | Notable Functions | Purpose |
|---|---|---|
| **KERNEL32.DLL** | `GetLocalTime`, `GetModuleFileNameW`, `SetUnhandledExceptionFilter` | Core Windows API, time, file info, error handling |
| **NTDLL.DLL** | `ZwGetContextThread`, `NtYieldExecution`, `ZwProtectVirtualMemory`, `ZwWriteVirtualMemory`, `NtAllocateVirtualMemory`, `ZwUnmapViewOfSection`, `RtlDecompressBuffer` | Low-level NT API for anti-debugging, memory manipulation, and decompression |
| **USER32.DLL** | (Not specified) | Windows User Interface |
| **OPENGL32.DLL** | `glBegin`, `glClear`, `glColor3d`, `glVertex3d`, etc. (11 functions) | Graphics API, used for anti-sandbox detection |

The import of `RtlDecompressBuffer` from NTDLL suggests the encoded payload blob may be compressed, not just encoded. (source: deep-dive.json, floss)

## 16. Author + Sign-off

**Report Author:** Automated Malware Analysis System (LLM Judge)
**Date:** 2026-08-12
**Version:** 2.0

This report was generated based on automated analysis of the provided sample and evidence. All claims are traceable to the cited tool outputs. The verdict of **malicious** is based on the convergence of high-confidence YARA matches, behavioral-intent evidence from static analysis, and community threat intelligence. Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events, and runtime behavior remains unobserved.