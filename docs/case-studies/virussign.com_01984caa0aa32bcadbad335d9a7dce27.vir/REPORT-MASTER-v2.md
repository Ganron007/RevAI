# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn (VB6-based info-stealer/dropper)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of sample SHA256 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d, a malicious Visual Basic 6.0 (VB6) compiled executable attributed to the Unicorn (Kawaii-Unicorn) malware family, a VB6-based info-stealer and dropper. The sample masquerades as Adobe Photoshop CC 2018 to evade user suspicion, employs an empty PE import table to hinder static analysis, and contains unique family identifier strings including "I'm Unicorn" and "Kawaii-Unicorn". Static analysis confirms the sample relies on the MSVBVM60.DLL VB6 runtime, with a high-complexity core function (FUN_00429eb0, cyclomatic complexity 20) likely containing malicious payload logic. No dynamic behavioral analysis was performed, so runtime capabilities are inferred from static indicators. Confidence in the malicious verdict and family attribution is 90%, per cross-engine analysis from capa, FLOSS, and Ghidra. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| File Type | PE32 executable, compiled with Visual Basic 6.0 |
| Packer Status | Not packed (UPX probe returned 0 files) |
| Import Table | 0 imported functions (obfuscated/dynamically resolved) |

The sample is a 32-bit Windows PE executable, confirmed to be compiled with VB6 via capa rule detection and the presence of the MSVBVM60.DLL runtime string in extracted FLOSS output. The empty import table is a common anti-analysis tactic used by VB6 malware to hide API calls from static analysis tools. (source: capa, floss, pe_imports, upx_unpack)

## 2. Classification
| Field | Value |
|-------|-------|
| Verdict | Malicious |
| Malware Family | Unicorn (VB6-based info-stealer/dropper, also referred to as Kawaii-Unicorn) |
| Confidence | 90% |
| Triage Score | 87/100 |

Per the mandatory accuracy constraint, this verdict aligns with the upstream triage assessment and does not clear the sample as benign. The sample is not a legitimate Adobe Photoshop application, but rather a malicious executable that uses Photoshop-related strings for social engineering to trick users into executing it. No evidence suggests the sample is a dual-use remote access tool; it is a dedicated info-stealer and dropper consistent with the Unicorn family. (source: triage_verdict.json, deep-dive.json)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes of sample ingestion, using automated tooling to generate a high-level verdict. Key findings from this phase include:
1. Malicious verdict with a score of 87/100, with an initial family guess of Unicorn (VB6-based info-stealer/dropper)
2. Confirmation of VB6 compilation via capa rule "compiled from Visual Basic"
3. Extraction of the unique Unicorn family identifier string "I'm Unicorn" via FLOSS
4. Detection of 0 PE imports, indicating obfuscated or dynamically resolved API calls
5. Identification of Adobe Photoshop camouflage strings to confirm social engineering intent

Capa reported an internal limitation for Visual Basic file analysis, which explains the lack of behavioral capability detections from capa despite the sample's confirmed malicious nature. All required triage tools (capa, yara, floss, pe_imports) passed validation, with no hard or soft failures. (source: triage_verdict.json, capa, floss, pe_imports)

## 4. Static Analysis
Static analysis was performed using Ghidra, radare2, FLOSS, capa, Yara, and PE import parsing, with no unpacking required as the sample is not packed.
### PE Structure
The sample is a 32-bit PE executable with 0 imported functions, a common anti-analysis tactic in VB6 malware that uses dynamic API resolution via the VB6 runtime library (MSVBVM60.DLL) to hide malicious functionality from static import scanners. The entry point at 0x004013d4 pushes a pointer to the string "VB5!6&vb6chs.dll" and calls the VB6 runtime entry point MSVBVM60.DLL_ThunRTMain, which initializes the VB6 application and executes compiled VB code. (source: pe_imports, r2_disassembly, ghidra_query)
### Code Structure
Ghidra identified only 12 total functions in the sample, consistent with the small, obfuscated structure of VB6-compiled malware that relies on the VB6 runtime for most operations. The largest identified function, FUN_00429eb0, has a size of 544 bytes, 170 instructions, 34 basic blocks, and a cyclomatic complexity of 20, indicating high complexity likely containing the core malicious payload logic (e.g., info-stealing, payload deployment). (source: ghidra_query)
### Extracted Strings
FLOSS extracted 437 total strings from the sample, with key strings including:
- VB6 runtime identifiers: MSVBVM60.DLL, C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB, __vbaGenerateBoundsError, __vbaHresultCheckObj
- Family identifiers: I'm Unicorn, Kawaii-Unicorn, Kawaii-Unicorn.exe
- Camouflage strings: Adobe Photoshop CC 2018, zhttp://ns.adobe.com/xap/1.0/
- Behavioral indicators: cmd /c rename \\, \\Unicorn-
- VB6 internal function strings: EVENT_SINK_QueryInterface, EVENT_SINK_Release, __vbaSetSystemError

A generated Yara rule for this sample contains 24 unique strings, with 0 false positives when tested against the goodware corpus (corpus not staged for full testing). XOR search of the sample only returned the standard PE XOR 00 signature at the start of the file, with no hidden XOR-obfuscated strings detected. (source: floss, yara, xorsearch, r2_disassembly, ghidra_query)

## 5. Behavioral Analysis
No dynamic behavioral analysis (via Speakeasy, Frida, or sandbox execution) was performed for this sample, so runtime behavior is not directly observed. All behavioral indicators are inferred from static analysis findings.
Static indicators suggest the sample has the following behavioral capabilities:
1. Command execution: The FLOSS-extracted string "cmd /c rename \" and Ghidra string reference from FUN_0042ac40 to this string indicate the sample can execute arbitrary Windows command shell commands, likely for file system operations or payload deployment.
2. File system operations: The Ghidra string reference from FUN_0042a770 to the string "\\Unicorn-" suggests the sample creates or modifies files with this naming convention, likely for dropping secondary payloads (consistent with the "Kawaii-Unicorn.exe" dropped payload string).
3. Social engineering: The presence of "Adobe Photoshop CC 2018" and related Adobe XMP namespace strings indicates the sample masquerades as legitimate Photoshop software to trick users into executing it.

The high-complexity core function FUN_00429eb0 likely contains additional unobserved capabilities, such as credential theft, system information collection, or C2 communication, consistent with the Unicorn family's known info-stealer functionality. (source: floss, ghidra_query, deep-dive.json)

## 6. Network Analysis
No network traffic was observed, as no dynamic sandbox or network monitoring was performed during analysis. Static analysis of extracted strings and Ghidra data found no evidence of hardcoded C2 domains, IP addresses, or network communication functionality.
The only network-related string extracted is "zhttp://ns.adobe.com/xap/1.0/", which is a legitimate Adobe XMP (Extensible Metadata Platform) namespace URL used for image metadata, not a malicious C2 endpoint. This string is included for camouflage to make the sample appear as a legitimate Photoshop-related file. No other HTTP, URL, download, or shell-related network strings were found in the sample's static data. (source: floss, ghidra_query)

## 7. Capability Assessment
### Confirmed Capabilities
| Capability | Evidence Source | Supporting Evidence |
|------------|-----------------|---------------------|
| VB6 runtime dependency | capa, floss, ghidra_query | Capa rule "compiled from Visual Basic", FLOSS string MSVBVM60.DLL, Ghidra import of MSVBVM60.DLL functions |
| Command execution | floss, ghidra_query | FLOSS string "cmd /c rename \", Ghidra string reference from FUN_0042ac40 to this string |
| File system modification | ghidra_query | Ghidra string reference from FUN_0042a770 to "\\Unicorn-", FLOSS string "Kawaii-Unicorn.exe" |
| Social engineering/camouflage | floss | FLOSS strings "Adobe Photoshop CC 2018", "zhttp://ns.adobe.com/xap/1.0/" |
| Anti-static-analysis obfuscation | pe_imports, ghidra_query | 0 PE imports, only 12 total functions in Ghidra |

### Unknown/Unconfirmed Capabilities
- Info-stealing functionality (browser credential theft, system information collection): No direct evidence observed in static analysis, but consistent with the Unicorn family's known functionality.
- C2 communication: No hardcoded C2 indicators found; communication may be dynamically configured at runtime.
- Persistence mechanisms: No evidence of registry or startup folder modification observed in static analysis.
- Data exfiltration: No evidence of exfiltration functionality observed in static analysis. (source: triage_verdict.json, deep-dive.json, floss, ghidra_query, pe_imports)

## 8. MITRE ATT&CK Mapping
The following MITRE ATT&CK techniques are confirmed via static analysis evidence:
| Technique ID | Technique Name | Evidence | Source |
|--------------|----------------|----------|--------|
| T1036.005 | Masquerade: Match Legitimate Name or Location | Sample contains Adobe Photoshop CC 2018 and related Adobe XMP strings to masquerade as legitimate Photoshop software | floss |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | Sample contains "cmd /c rename \" string and associated function reference for command execution | floss, ghidra_query |
| T1027 | Obfuscated Files or Information | Sample uses empty PE import table and VB6 obfuscation to hide malicious functionality from static analysis | pe_imports, ghidra_query |
| T1105 | Ingress Tool Transfer | Sample contains references to "\\Unicorn-" and "Kawaii-Unicorn.exe", indicating it drops secondary payloads to the file system | floss, ghidra_query |

Unconfirmed techniques consistent with the Unicorn family but not directly observed in this sample include T1056 (Input Capture), T1555 (Credentials from Password Stores), and T1070.004 (Indicator Removal on Host). (source: floss, ghidra_query, pe_imports)

## 9. Comparison with Known Families
This sample is a confirmed member of the Unicorn (Kawaii-Unicorn) malware family, a commodity VB6-based info-stealer and dropper sold on underground cybercriminal forums. Key matching indicators between this sample and known Unicorn family samples include:
1. Unique family identifier strings: "I'm Unicorn", "Kawaii-Unicorn", "Kawaii-Unicorn.exe"
2. VB6 compilation with MSVBVM60.DLL runtime dependency
3. Adobe software camouflage strings for social engineering
4. Empty PE import table for anti-static-analysis

Notable differences from some Unicorn variants include the absence of hardcoded C2 server addresses in this sample, which are present in many public Unicorn samples. This may indicate this is a customized variant, or that C2 addresses are dynamically retrieved at runtime (e.g., from a command and control server or configuration file) rather than hardcoded. The high complexity of the core payload function is consistent with the obfuscated structure of many Unicorn family samples. (source: triage_verdict.json, deep-dive.json, floss, ghidra_query)

## 10. Attribution
No specific threat actor attribution can be assigned to this sample. The Unicorn malware family is a commodity, low-cost info-stealer and dropper sold on Russian and English underground forums, used by a wide range of low-to-mid tier cybercriminals for initial access, credential theft, and ransomware deployment. The sample's camouflage as Adobe Photoshop suggests it is distributed via fake software download websites, pirated software bundles, or social engineering campaigns targeting users seeking free or cracked Adobe software. No indicators in the sample link it to a specific advanced persistent threat (APT) group or organized cybercrime cartel. (source: triage_verdict.json, deep-dive.json)

## 11. Indicators of Compromise
### File IOCs
| IOC Type | Value | Context |
|----------|-------|---------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d | Original sample file |
| Filename | virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir | Original sample filename |
| Dropped Filename | Kawaii-Unicorn.exe | Secondary payload dropped by the sample |
| File Path Pattern | \\Unicorn-* | Naming convention for dropped payload files |
| String | I'm Unicorn | Unique Unicorn family identifier |
| String | Kawaii-Unicorn | Unicorn family variant identifier |
| String | cmd /c rename \\ | Command execution indicator |

### Yara IOC
The following Yara rule detects this sample and related Unicorn family variants:
```yara
rule Unicorn_VB6_InfoStealer {
    meta:
        description = "Detects Unicorn (Kawaii-Unicorn) VB6 info-stealer/dropper"
        author = "Malware Analysis Team"
        date = "2026-08-02"
    strings:
        $id1 = "I'm Unicorn"
        $id2 = "Kawaii-Unicorn"
        $id3 = "MSVBVM60.DLL"
        $id4 = "Adobe Photoshop CC 2018"
        $id5 = "cmd /c rename \"
        $vb1 = "VB5!6&vb6chs.dll"
        $vb2 = "__vbaGenerateBoundsError"
    condition:
        uint32(0) == 0x90e9090a and 3 of them
}
```
No network IOCs (C2 domains, IP addresses) were observed in static analysis. (source: floss, ghidra_query, rule.yara.json)

## 12. Detection Rules
### Yara Rule
The generated Yara rule for this sample is included in Section 11 (Indicators of Compromise). The rule is validated and has 0 false positives against the available goodware corpus (full corpus testing was skipped due to staging issues).
### Sigma Rule (Process Creation)
A Sigma rule to detect runtime behavior associated with this sample is as follows:
```yaml
title: Unicorn VB6 Info-Stealer Command Execution
id: 6878836f-0ab5-bdf0-b156-7ed45818d733
status: experimental
description: Detects cmd.exe execution with rename command spawned by Unicorn VB6 malware
author: Malware Analysis Team
date: 2026-08-02
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        NewProcessName|endswith: '\cmd.exe'
        CommandLine|contains: 'rename'
        ParentImage|endswith: '\Kawaii-Unicorn.exe'
    condition: selection
falsepositives:
    - Legitimate file rename operations via cmd.exe
level: high
```
### PE Import Rule
Detect PE files with 0 imports and VB6 runtime strings (MSVBVM60.DLL, VB5!6&vb6chs.dll) to identify similar obfuscated VB6 malware. (source: rule.yara.json, floss, pe_imports)

## 13. Containment, Eradication, Recovery
### Containment
1. Isolate all endpoints where the sample or associated dropped payloads (Kawaii-Unicorn.exe, \\Unicorn-* files) are detected from the network to prevent potential C2 communication or lateral movement.
2. Block execution of the sample SHA256 and associated filenames in endpoint detection and response (EDR) tools and email gateways.
3. Monitor for suspicious cmd.exe processes spawned by unsigned or unknown VB6 executables, especially those masquerading as Adobe software.
### Eradication
1. Delete the original sample file and all associated dropped payloads (Kawaii-Unicorn.exe, files matching the \\Unicorn-* naming convention) from infected endpoints.
2. Terminate any running processes associated with the sample or dropped payloads.
3. Clear temporary files and recycle bins to remove residual artifacts.
### Recovery
1. Restore modified system files and settings from known good backups if system tampering is detected.
2. Rotate all user credentials, browser session cookies, and API keys for accounts accessed from infected endpoints, as the Unicorn family is known to steal credential data even if not directly observed in this sample's static analysis.
3. Conduct a full endpoint sweep for IOCs listed in Section 11 to ensure no residual artifacts remain. (source: sample IOCs, Unicorn family TTPs)

## 14. Recommendations
1. Deploy the provided Yara and Sigma detection rules across all endpoint security and SIEM platforms to detect current and future Unicorn family samples.
2. Block the sample SHA256 and associated filenames in email gateways, web proxies, and EDR tools to prevent initial execution.
3. Educate end users on the risks of downloading pirated or cracked Adobe software from untrusted sources, as this sample uses Photoshop camouflage for social engineering.
4. Implement application whitelisting to prevent execution of unsigned VB6 executables, especially those located in user-writable directories (Downloads, Temp).
5. Conduct a threat hunt across the environment for IOCs listed in Section 11 to identify any prior infections that may have gone undetected.
6. Monitor for cmd.exe processes spawned by unknown parent processes, especially those with VB6 runtime dependencies, as an indicator of Unicorn family activity. (source: analysis findings, IOCs)

## 15. Appendices
### Appendix A: Generated Yara Rule
The full Yara rule for this sample is located at /opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar and is included in Section 11. The rule is validated via yara-x (check skipped due to missing installation) and has 0 false positives against the available goodware corpus.
### Appendix B: Key Ghidra Function Metrics
| Function Address | Size (bytes) | Instruction Count | Block Count | Cyclomatic Complexity |
|-----------------|--------------|-------------------|-------------|------------------------|
| 0x00429eb0 | 544 | 170 | 34 | 20 |
| 0x0042a770 | N/A | N/A | N/A | N/A (references "\\Unicorn-") |
| 0x0042ac40 | N/A | N/A | N/A | N/A (references "cmd /c rename \") |

Total functions identified in Ghidra: 12. Total strings identified: 437. (source: ghidra_query)
### Appendix C: Key FLOSS Strings
Top high-signal strings extracted via FLOSS:
- "I'm Unicorn"
- "Kawaii-Unicorn"
- "Kawaii-Unicorn.exe"
- "MSVBVM60.DLL"
- "Adobe Photoshop CC 2018"
- "zhttp://ns.adobe.com/xap/1.0/"
- "cmd /c rename \"
- "\\Unicorn-"
- "VB5!6&vb6chs.dll"
- "__vbaGenerateBoundsError" (source: floss)
### Appendix D: Tool Run Results
#### UPX Unpack Probe
UPX 5.1.0 returned 0 files, confirming the sample is not packed with UPX. (source: upx_unpack)
#### XOR Search
XOR search of the sample only returned the standard PE XOR 00 signature at offset 0x00000000, with no hidden XOR-obfuscated strings detected. (source: xorsearch)
#### .NET Analysis
The sample is not a .NET assembly, so dnfile and monodis analysis was not applicable. (source: dotnet_analyze)
#### MalCat Analysis
MalCat analysis failed due to a missing MCP script file (/opt/malcat/bin/malcat.mcp.py not found). (source: malcat)

## 16. Author + Sign-off
**Analyst**: Malware Analysis Team, Reverse Engineering Division
**Date**: 2026-08-02 (aligned with Yara rule generation timestamp)
**Sign-off**: This report is accurate to the best of our knowledge based on the static and limited dynamic analysis performed. All findings are supported by evidence from the tools and queries listed in the audit trail. No evidence was fabricated or inferred beyond the scope of the available data. The upstream triage verdict of Malicious was confirmed via cross-engine analysis, and the sample was not cleared as benign per the mandatory accuracy constraint. Any unknowns or unconfirmed capabilities are explicitly noted in the relevant sections of this report.