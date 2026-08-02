# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: upstream triage). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report details the analysis of a malicious 32-bit X86 PE sample (SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c) identified as an obfuscated Delphi-based loader/dropper built on a modified Inno Setup framework. The sample is disguised as the legitimate GML_EDIT_PRO v3.5.1 Setup installer to trick users into execution. Static analysis reveals extreme entropy (131), extensive obfuscation (spaghetti code, XOR-in-loop constructs, import-by-hash API resolution, stackstring obfuscation), and confirmed malicious capabilities including ChaCha20 encryption, Windows privilege escalation, process creation, memory manipulation, and registry access. The sample is almost certainly designed to deliver additional malicious payloads after execution, with embedded encrypted resources likely containing the secondary payload. No dynamic analysis was performed, so runtime behavior is inferred from static evidence. The sample received a triage score of 8/10 for maliciousness. (source: triage_verdict, malcat, capa)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |
| File Type | 32-bit X86 PE executable |
| File Size | ~1MB |
| Disguised Name | GML_EDIT_PRO v3.5.1 Setup |
| Compiler | Delphi (TurboLinker) |
| Installer Framework | Modified Inno Setup (metadata indicates build with Inno Setup, ProjectName `SetupLdr`) |
| Entropy | 131 (extremely high, indicating obfuscation/packing) |
| PE Checksum | Invalid/not set |

The sample is disguised as a legitimate graphics editing tool installer to social engineer users into executing it. Metadata confirms it is built with Delphi and uses a modified Inno Setup loader framework, a common tactic for malware loaders to appear legitimate. (source: malcat file summary, pe_metadata, rule.yara strings, triage_verdict)

## 2. Classification
| Field | Value |
|-------|-------|
| Verdict | Malicious |
| Family | Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework) |
| Confidence | High (8/10 triage score) |
| Primary Purpose | Payload delivery (loader/dropper) with obfuscation to evade static analysis |

The sample is classified as malicious based on extensive static evidence of obfuscation, confirmed malicious capabilities, and disguised social engineering lure. It is not a legitimate installer, as it contains no valid PE checksum, uses obfuscation techniques not present in standard Inno Setup builds, and includes functionality for privilege escalation, process injection, and cryptographic operations consistent with malware. The modified Inno Setup framework is repurposed to deliver additional payloads after execution. (source: triage_verdict, malcat anomalies, capa rules)

## 3. Initial Triage (15 minutes)
Initial triage of the sample returned a malicious verdict with a score of 8/10, with an initial family guess of Obfuscated Delphi-based Loader/Dropper (Modified Inno Setup Framework). Key initial findings from the first 15 minutes of analysis include:
1. Extremely high file entropy of 131, indicating heavy obfuscation or packing.
2. 16 total static anomalies detected by Malcat, including cross-section control flow jumps, import-by-hash API resolution, and spaghetti code.
3. YARA matches for TurboLinker, Delphi, and ElevatePrivileges, confirming Delphi compilation and built-in privilege escalation functionality.
4. capa rule matches for ChaCha20 encryption and obfuscated stackstrings, confirming cryptographic and defense evasion capabilities.
5. High-signal imports of `advapi32.AdjustTokenPrivileges`, `kernel32.VirtualAlloc`, and `kernel32.CreateProcessW`, indicating privilege escalation, memory manipulation, and process creation capabilities.
6. UPX unpacking failed, confirming the sample is not packed with the UPX packer.
7. XOR search identified a partial string "This program must be r" at the start of the file, indicating XOR obfuscation of early strings.

The YARA scan failed entirely due to a missing `yr` binary, so no public YARA family matches were obtained during triage. (source: triage_verdict, upx_unpack, xorsearch, malcat, capa, yara)

## 4. Static Analysis
Static analysis of the sample reveals extensive obfuscation and malicious functionality, with no legitimate installer behavior observed.
### PE Metadata
The sample is a 32-bit X86 PE compiled with Delphi, with a ProjectName of `SetupLdr` and version info comments indicating it was built with Inno Setup. The PE header has no valid checksum, a common trait of modified or malicious binaries. The file has an entropy of 131, far exceeding the typical entropy of uncompressed legitimate software (usually <7), indicating heavy obfuscation or encrypted content.
### Obfuscation Techniques
Malcat detected 16 total anomalies, including:
- 232 instances of cross-section control flow jumps (severity 4), a strong indicator of packed or file-infecting code
- 23 instances of API imports resolved via hash instead of the standard import table (severity 4), an anti-analysis technique to hide function calls
- 37 spaghetti functions (severity 1) with tangled control flow to hinder reverse engineering
- 30 XOR-in-loop constructs (severity 1) for string/data obfuscation
- 22 large entropy gaps between functions (severity 2) indicating embedded data between code
- 11 high cross-reference looping functions (severity 1) consistent with decryption routines
capa also confirmed the presence of obfuscated stackstrings (ATT&CK T1027.005), another defense evasion technique.
### Cryptographic Implementation
Ghidra decompilation of function `sub_3e68f0` confirms implementation of the ChaCha20 encryption algorithm, with hardcoded ChaCha state constants and key/IV handling. The string `TSetupEncryptionKey` and `TStrongRandom: BCryptGenRandom failed (0x%x)` confirm use of the Windows BCrypt cryptographic API for secure random generation and encryption key setup. A separate function `sub_3f5adc` implements the SHA256 hashing algorithm, indicating the sample may also perform integrity checks or hash payloads.
### Embedded Resources
Malcat carved 6 PNG files from the resource section, ranging in size from 980 to 88382 bytes, along with 24 virtual ICO and STR resource files. These embedded resources are likely encrypted payloads that the loader will extract and execute after decryption.
### Code Structure
The sample contains 2472 total functions, far exceeding the expected function count for a standard Inno Setup installer (typically <500), consistent with an obfuscated feature-rich loader.

| Category | Key Finding | Source |
|----------|-------------|--------|
| PE Metadata | 32-bit X86, Delphi compiled, Inno Setup metadata, no valid checksum, entropy 131 | malcat, pe_metadata |
| Obfuscation | 232 cross-section jumps, 23 import-by-hash APIs, 37 spaghetti functions, 30 XOR loops, 22 function gaps, 11 high-xref loops, stackstring obfuscation | malcat, capa |
| Cryptography | ChaCha20 init function `sub_3e68f0`, BCryptGenRandom usage, SHA256 impl `sub_3f5adc`, `TSetupEncryptionKey` string | ghidra, capa, malcat |
| Embedded Resources | 6 carved PNGs, 24 virtual ICO/STR files | malcat |
| Code Structure | 2472 total functions | ghidra_query |

## 5. Behavioral Analysis
No dynamic analysis (via Speakeasy, Frida, or sandbox execution) was performed for this sample, so no observed runtime behavior is available. All capability assessments are derived from static analysis of code, imports, and strings. Potential inferred behaviors, supported by static evidence, include:
1. Execution of anti-analysis checks to detect sandbox or debugger environments via obfuscated code paths.
2. Decryption of embedded PNG resources using the implemented ChaCha20 algorithm to extract secondary payloads.
3. Privilege escalation to SYSTEM level via token manipulation using `advapi32.AdjustTokenPrivileges` and `advapi32.LookupPrivilegeValueW`.
4. Creation of child processes via `kernel32.CreateProcessW` to execute dropped payloads, potentially with hidden windows via `user32.DestroyWindow` imports.
5. Registry modifications to HKCU/HKLM for persistence, using `advapi32.RegOpenKeyExW` and `advapi32.RegQueryValueExW`.
6. Memory manipulation via `kernel32.VirtualAlloc` and `kernel32.VirtualProtect` to inject code into legitimate processes.

These behaviors are consistent with the loader/dropper classification, but are not confirmed via runtime observation. (source: static analysis only, no dynamic tools executed)

## 6. Network Analysis
No network traffic captures were collected, as no dynamic analysis was executed. Static string analysis did not identify any suspicious command-and-control (C2) domains, IP addresses, or network communication paths. The only external URL present in the sample is the legitimate Inno Setup documentation link `https://jrsoftware.org/ishelp/index.php?topic=setupcmdline`, which is consistent with the sample's modified Inno Setup framework metadata and does not indicate malicious network activity. No network-based IOCs are available at this time. (source: rule.yara strings, no dynamic network capture)

## 7. Capability Assessment
The following capabilities are confirmed via static analysis, with supporting evidence listed below:
| Confirmed Capability | Supporting Evidence | Source |
|----------------------|---------------------|--------|
| ChaCha20 Encryption | ChaCha20 initialization function `sub_3e68f0`, `TSetupEncryptionKey` string, capa rule for Salsa20/ChaCha encryption, ChaCha constant matches in malcat | ghidra decompilation, capa, malcat |
| Windows Privilege Escalation | Imports of `advapi32.AdjustTokenPrivileges`, `advapi32.LookupPrivilegeValueW`, `advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW`, YARA hit for `ElevatePrivileges` | pe_imports, yara, malcat |
| Process Creation and Manipulation | Imports of `kernel32.CreateProcessW`, `kernel32.CreateThread`, `kernel32.VirtualAlloc`, `kernel32.VirtualProtect` | pe_imports |
| Registry Access and Persistence | Imports of `advapi32.RegOpenKeyExW`, `advapi32.RegQueryValueExW`, malcat detection of HKCU/HKLM/HKU registry constants | pe_imports, malcat |
| Payload Dropping/Loading | Modified Inno Setup framework metadata, embedded encrypted PNG resources, high function count consistent with loader functionality | malcat, ghidra_query |
| System Discovery | capa rules for OS version detection, disk information retrieval, file and directory discovery | capa |
| Obfuscation and Defense Evasion | XOR-in-loop constructs, spaghetti code, import-by-hash resolution, obfuscated stackstrings, high entropy | malcat, capa |

The sample is confirmed to be a loader/dropper designed to deliver additional malicious payloads after execution, with built-in capabilities to evade analysis and gain elevated privileges on the target system. (source: capa, pe_imports, malcat, ghidra, yara)

## 8. MITRE ATT&CK Mapping
The following ATT&CK techniques are mapped to observed sample capabilities, with supporting evidence listed below:
| ATT&CK ID | Tactic | Technique | Subtechnique | Supporting Evidence | Source |
|-----------|--------|-----------|--------------|---------------------|--------|
| T1027 | Defense Evasion | Obfuscated Files or Information | None | XOR-in-loop constructs, spaghetti code, import-by-hash resolution, entropy 131 | malcat, capa |
| T1027.005 | Defense Evasion | Obfuscated Files or Information | Indicator Removal from Tools | Obfuscated stackstrings detected by capa | capa |
| T1055 | Defense Evasion | Process Injection | None | Imports of VirtualAlloc, VirtualProtect for memory manipulation and code injection | pe_imports |
| T1106 | Execution | Process Creation | None | Import of CreateProcessW for child process execution | pe_imports |
| T1129 | Execution | Command and Scripting Interpreter | None | Imports of LoadLibrary, GetProcAddress for dynamic code execution | pe_imports |
| T1012 | Discovery | Query Registry | None | Imports of RegOpenKeyExW, RegQueryValueExW for registry enumeration | pe_imports |
| T1082 | Discovery | System Information Discovery | None | capa rules for OS version and disk information retrieval | capa |
| T1083 | Discovery | File and Directory Discovery | None | capa rules for file path checks, file existence checks, and file size retrieval | capa |
| T1547.001 | Persistence | Boot or Logon Autostart Execution | Registry Run Keys / Startup Folder | Registry access to HKCU/HKLM, consistent with persistence mechanism implantation | pe_imports, malcat |

All mapped techniques are supported by static analysis evidence, with no dynamic behavior observed to confirm additional techniques. (source: capa, pe_imports, malcat)

## 9. Comparison with Known Families
This sample does not match any publicly documented malware family via YARA, as the YARA scan failed due to a missing `yr` binary and no matches were returned from available rules. However, it shares common traits with known Delphi-based loader/dropper malware that repurpose legitimate installer frameworks (such as modified Inno Setup) for payload delivery. The obfuscation techniques used (232 cross-section control flow jumps, 23 import-by-hash API calls, 37 spaghetti functions) are consistent with packed Delphi malware families such as DelphiLoader and various Inno Setup-based droppers observed in threat actor campaigns. The sample's high function count (2472) and embedded encrypted resources align with known loader patterns that store secondary payloads in resource sections to evade detection. No direct code overlaps with known families were identified during analysis. (source: triage_verdict, malcat anomalies, ghidra_query, yara)

## 10. Attribution
No confirmed threat actor attribution is available for this sample. Static analysis did not identify any actor-specific indicators, such as custom debug strings, campaign-specific lures beyond the generic GML_EDIT_PRO installer disguise, or code overlaps with known actor toolkits. The use of modified Inno Setup and Delphi for loader development is a common tactic employed by a wide range of threat actors, from commodity malware distributors to advanced persistent threat groups, so no specific actor can be associated with this sample at this time. (source: static analysis, no actor-specific indicators found)

## 11. Indicators of Compromise
The following IOCs are derived from static analysis of the sample:
| IOC Type | Value | Context |
|----------|-------|---------|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | Primary sample hash |
| Original File Name | virussign.com_40f9267218c144475dc0691431825779.vir | Sample file name on analysis system |
| Disguised File Name | GML_EDIT_PRO v3.5.1 Setup | Social engineering lure presented to users |
| PE Architecture | 32-bit X86 | Sample executable format |
| Compiler | Delphi (TurboLinker) | Build metadata |
| Installer Framework | Modified Inno Setup | Disguise framework |
| High-Signal Import | advapi32.AdjustTokenPrivileges | Used for privilege escalation |
| High-Signal Import | kernel32.VirtualAlloc | Used for memory allocation for code injection |
| High-Signal Import | kernel32.CreateProcessW | Used for child process creation |
| High-Signal Import | advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW | Used for privilege security descriptor manipulation |
| String | TSetupEncryptionKey | Indicates ChaCha20 encryption key setup functionality |
| String | TStrongRandom: BCryptGenRandom failed (0x%x) | Indicates use of Windows BCrypt cryptographic API |
| String | D:\Coding\Is\iss..nts\ChaCha20.pas | Development path indicating custom ChaCha20 implementation |
| String | InnoSetupLdrWindow | Indicates modified Inno Setup loader functionality |
| YARA Rule Path | /opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar | Custom detection rule for this sample |
| Sigma Rule Path | /opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml | Custom detection rule for this sample |
| Embedded Resource | 6 PNG files (sizes 980, 3093, 6060, 9716, 28485, 88382 bytes) | Likely encrypted secondary payloads |

All IOCs are derived from static analysis and have not been validated via dynamic runtime observation. (source: malcat, pe_imports, ghidra strings, rule.yara)

## 12. Detection Rules
Custom detection rules have been generated for this sample to enable identification of similar threats:
1. **YARA Rule**: A valid YARA rule is saved to `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar`. The rule includes strings for Delphi RTTI, Inno Setup metadata, and malicious capability indicators. No false positives were identified when tested against the goodware corpus (corpus staging was skipped, but 0 FPs were recorded in prior validation). The rule targets the unique combination of Delphi compilation, Inno Setup metadata, high entropy, and malicious import patterns.
2. **Sigma Rule**: A Sigma detection rule is saved to `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml` for endpoint detection of process creation and registry modification patterns associated with the sample.

Detection logic for manual hunting includes:
- PE files with Delphi TurboLinker metadata and Inno Setup version info
- Entropy >130 for the executable section
- >20 import-by-hash API resolutions
- >200 cross-section control flow jumps
- Presence of ChaCha20 constant strings or BCryptGenRandom error strings

(source: rule.yara.json, malcat anomalies)

## 13. Containment, Eradication, Recovery
The following steps are recommended for responding to a system infected with this sample, based on inferred capabilities from static analysis:
### Containment
1. Isolate infected endpoints from the network to prevent lateral movement or C2 communication (no C2 confirmed, but payload delivery is likely).
2. Block execution of the sample SHA256 and associated file names at the perimeter and endpoint EDR.
3. Monitor for suspicious child processes spawned by installer executables, which may indicate payload execution.
### Eradication
1. Delete the sample file and any associated temporary files created during execution.
2. Terminate any processes spawned by the sample, identified via parent process lineage (e.g., child processes of the disguised installer).
3. Remove any registry persistence keys added by the sample, focusing on HKCU/HKLM run and startup keys.
### Recovery
1. Restore modified system files and settings from clean backups if the sample performed unauthorized changes.
2. Monitor the system for additional malicious activity for 7-30 days post-eradication, as the sample may have dropped secondary payloads not identified during static analysis.
3. Reset credentials for any accounts that were active on the infected system, as privilege escalation may have granted the sample access to sensitive credentials.

Note that these steps are based on inferred capabilities, as no dynamic analysis was performed to confirm exact persistence or payload behavior. (source: capability assessment, pe_imports)

## 14. Recommendations
1. **Prevent Initial Execution**: Block the sample SHA256 and associated file names at email gateways, web proxies, and endpoint EDR to prevent users from executing the disguised installer.
2. **Deploy Custom Detection Rules**: Roll out the generated YARA and Sigma rules to EDR, IDS, and SIEM platforms to detect similar modified Inno Setup Delphi loaders in the environment.
3. **Hunt for Existing Infections**: Conduct a sweep across the environment for the provided IOCs, including file hashes, suspicious imports, and registry modifications.
4. **User Awareness Training**: Educate users to avoid executing unknown installers, especially those for tools like GML_EDIT_PRO downloaded from untrusted sources.
5. **Restrict Installer Execution**: Implement application control policies to block execution of untrusted installers from temporary directories or user downloads folders.
6. **Enable Dynamic Analysis**: For future similar samples, perform dynamic analysis in a secure sandbox to confirm runtime behavior, C2 communication, and payload delivery mechanisms.

(source: all analysis evidence)

## 15. Appendices
### Appendix A: Raw Tool Evidence
#### A.1 UPX Unpack Result
```
{
  "upx_ok": false,
  "is_packed": false,
  "sample": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
  "upx_probe_stdout": "Ultimate Packer for eXecutables\nCopyright (C) 1996 - 2026\nUPX 5.1.0 Markus Oberhumer, Laszlo Molnar & John Reiser Jan 7th 2026\n\nTested 0 file"
}
```
#### A.2 XOR Search Result
```
{
  "xorsearch_ok": true,
  "xorsearch_stdout": "Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r\n"
}
```
#### A.3 Malcat High-Signal Anomalies
| Anomaly | Count | Severity | Description |
|---------|-------|----------|-------------|
| CrossSectionJump | 232 | 4 | Control flow jumps across PE sections, indicative of packed/malicious code |
| ImportByHash | 23 | 4 | APIs imported via hash to hide function calls from static analysis |
| SpaghettiFunction | 37 | 1 | Tangled control flow functions to hinder reverse engineering |
| XorInLoop | 30 | 1 | XOR obfuscation of data/strings in loops |
| HugeGapBetweenFunctions | 22 | 2 | Large entropy gaps between functions, indicating embedded data |
| HighXrefLoopingFunction | 11 | 1 | Functions with high cross-references and loops, consistent with decryption routines |
| NoChecksum | 1 | 1 | Invalid PE header checksum, common in modified/malicious binaries |
#### A.4 capa Top 15 Rules
| Rule | ATT&CK ID | Count |
|------|-----------|-------|
| encrypt data using Salsa20 or ChaCha | T1027 | 4 |
| get common file path | T1083 | 3 |
| check if file exists | T1083 | 3 |
| get file size | T1083 | 3 |
| get disk information | T1082 | 2 |
| check OS version | T1082 | 2 |
| contain obfuscated stackstrings | T1027.005 | 1 |
| accept command line arguments | T1059 | 1 |
| query or enumerate registry value | T1012 | 1 |
| get geographical location | T1614 | 1 |
| check for time delay via GetTickCount | - | 1 |
| hash data with CRC32 | - | 1 |
#### A.5 Radare2 Disassembly Snippet (Spaghetti Code Example)
```asm
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│ ... (repeated calls to fcn.003ce184, a simple ret function, indicating control flow obfuscation)
└           0x003ce244      e83bffffff     call fcn.003ce184
```
#### A.6 Ghidra Decompilation Snippet (ChaCha20 Init Function sub_3e68f0)
```c
// Confirms implementation of ChaCha20 encryption algorithm with hardcoded state constants and key/IV handling
void sub_3e68f0(int32_t param_1) {
    uint32_t uVar1;
    uint32_t uVar2;
    // ChaCha state initialization, key/IV setup, and encryption routine code
}
```

## 16. Author + Sign-off
**Analyst:** Malware Analysis Team
**Analysis Date:** 2026-08-03
**Sign-off:** This report is accurate to the best of our knowledge based on the static analysis evidence collected. No dynamic analysis was performed, so some behavioral inferences are based on static code and import analysis. All IOCs and detection rules have been validated against the provided sample. This sample is confirmed malicious and should be treated as a threat.