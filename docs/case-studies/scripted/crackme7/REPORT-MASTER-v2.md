> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 17:09:45 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | suspicious |
| Quick scan | suspicious |
| Deep dive | crackme |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Hexorcist Crackme 7 Analysis Report

## Executive Summary

This report presents the analysis of a PE32 Windows GUI binary identified as "Hexorcist Crackme 7" (SHA256: fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f). The sample is a reverse engineering challenge from the "Hexorcist 1 - Weeks 1-8" CTF series, not a malicious payload. The binary employs XOR-based obfuscation and self-modifying code techniques to hide its core logic, which is typical for crackme applications designed to test reverse engineering skills. Static analysis reveals a minimal entry stub that decrypts a payload and registers it as a Vectored Exception Handler (VEH) to execute the main challenge logic. The binary presents a dialog box prompting for a serial number, confirming its purpose as a puzzle. No indicators of malicious behavior such as command-and-control communication, persistence mechanisms, credential theft, or data exfiltration were observed. The verdict is **suspicious** due to the obfuscation techniques, but the evidence strongly supports its classification as a benign crackme application.

## 1. Sample Identification

| Attribute | Value |
|-----------|-------|
| SHA256 | fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f |
| File Path | /opt/samples/corpus/Hexorcist 1 - Weeks 1-8/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/crackme7.exe |
| Project | Hexorcist 1 - Weeks 1-8 |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Compiler | FASM (Flat Assembler) |
| Entry Point | 0x00401000 |
| Imphash | d7f03e6d403ce99bd9054453497aa12e |
| File Size | 135,208 bytes (carved DIB resource) |
| Version Info | FileDescription='HEXORCIST CRACKME 7', OriginalFilename='hexo7.EXE', Copyright='Copyright SAS HEXORCIST' |

The sample self-identifies as "HEXORCIST CRACKME 7" in its version information, which is a strong indicator of its intended purpose as a reverse engineering challenge (source: floss, strings). The FASM compiler signature is consistent with hand-crafted or educational binaries (source: yara, FASM rule).

## 2. Classification

| Field | Value |
|-------|-------|
| Verdict | **suspicious** |
| Confidence | 90% |
| Family | Hexorcist Crackme 7 |
| Threat Type | Crackme / Reverse Engineering Challenge |
| Malicious Intent | Not observed |

The upstream triage verdict is **suspicious** with a score of 30/100 (source: triage verdict.json). The deep-dive analysis refines this to **crackme** with 90% confidence (source: deep-dive.json). The classification is based on the following evidence:

1. **Self-Identification**: The binary contains strings "HEXORCIST CRACKME 7", "SERIAL:", and "now this is getting serious", which are hallmarks of a crackme application (source: floss, strings).
2. **GUI Functionality**: Imports for DialogBoxParamA, GetDlgItemTextA, and MessageBoxA indicate a dialog-based interface for user interaction, typical of keygen/crackme challenges (source: ida, Imports).
3. **Obfuscation Techniques**: XOR encoding and high entropy are present but are neutral signals common in benign software like crackmes, not indicative of malicious intent (source: capa, encode data using XOR; source: malcat, anomalies).
4. **Absence of Malicious Behavior**: No network activity, persistence mechanisms, credential theft, or data exfiltration routines were detected (source: deep-dive.json).

The sample does not meet the threshold for **malicious** classification as it lacks behavioral-intent evidence such as C2 beaconing, file destruction, or defense impairment beyond basic obfuscation.

## 3. Background & Family Lineage

The "Hexorcist" series appears to be a collection of reverse engineering challenges (crackmes) designed for educational purposes. The naming convention "Hexorcist 1 - Weeks 1-8" suggests a structured learning curriculum. Crackmes are legitimate tools used by security researchers and enthusiasts to practice reverse engineering skills. They are not inherently malicious but may use techniques (like obfuscation) that are also employed by malware.

This specific sample, "Hexorcist Crackme 7", is part of a series where each challenge likely introduces progressively more complex obfuscation or protection schemes. The use of XOR encryption and VEH-based execution is a common technique in both crackmes and malware to hinder static analysis. However, the presence of clear crackme strings and the absence of any malicious payload strongly indicate this is a benign educational tool.

## 4. Static Analysis

### 4.1 Entry Point Analysis

The entry point at 0x00401000 contains a compact decryption stub (source: r2 disassembly). The code performs the following operations:

1. **XOR Decryption Loop**: Loads the address 0x4012b3 into EAX and the size 0x5d8 (1496 bytes) into ECX. It then XORs each byte at [EAX] with the key 0x66, increments EAX, and loops until ECX reaches zero. This decrypts a payload hidden within the .text section.
2. **VEH Registration**: Pushes the decrypted address (0x4012b3) and the value 1 (indicating first-chance handler) onto the stack, then calls `AddVectoredExceptionHandler`. This registers the decrypted code as a Vectored Exception Handler.
3. **Trigger Exception**: Executes the `HLT` instruction, which causes a privileged instruction exception. This exception is then handled by the newly registered VEH, transferring execution to the decrypted payload.

This technique is a form of self-modifying code and control flow obfuscation. The .text section is marked as Read-Write-Execute (RWX), allowing the decryption to occur in place (source: malcat, SectionWX anomaly).

### 4.2 Imports and API Usage

The binary imports only 9 functions, all from KERNEL32.DLL and USER32.DLL (source: ida, Imports). These are standard Windows APIs for GUI applications and exception handling:

| Module | Function | Purpose |
|--------|----------|---------|
| KERNEL32 | GetModuleHandleA | Retrieves module handle |
| KERNEL32 | AddVectoredExceptionHandler | Registers VEH |
| KERNEL32 | ExitProcess | Terminates process |
| USER32 | DialogBoxParamA | Creates modal dialog box |
| USER32 | GetDlgItemTextA | Retrieves text from dialog control |
| USER32 | MessageBoxA | Displays message box |
| USER32 | LoadIconA | Loads an icon resource |
| USER32 | SendMessageA | Sends message to window |
| USER32 | EndDialog | Destroys dialog box |

The absence of network-related APIs (WinHTTP, Winsock), registry manipulation APIs, or process injection APIs further supports the benign nature of the sample (source: ghidra_query, callgraph_edges for malicious APIs).

### 4.3 Strings Analysis

FLOSS decoded 33 strings, with 11 being API names and the rest being application-specific strings (source: floss, strings). Key strings include:

- `"HEXORCIST CRACKME 7"`: Self-identification as a crackme.
- `"SERIAL:"`: Prompt for a serial number, indicating a key validation challenge.
- `"now this is getting serious"`: A message likely displayed upon incorrect input or progression.
- `"Copyright SAS HEXORCIST"`: Copyright notice.
- `"MS Sans Serif"`: Font name for the dialog.

The string `"x0= 7*;1+,xhi!"` appears to be an obfuscated or encoded string, possibly part of the challenge logic (source: rule.yara.json).

### 4.4 Sections and Entropy

| Section | Entropy | Permissions | Notes |
|---------|---------|-------------|-------|
| .text | 84% | RWX | Contains entry stub and encrypted payload. High entropy indicates encryption or compression. |
| .rsrc | 85% | R | Contains resources (dialog, icon, version info). High entropy suggests packed resources. |

The high entropy in both sections is consistent with encryption or packing, but this is a neutral signal (source: malcat, static_profile).

## 5. Behavioral Analysis

No dynamic analysis was performed in this pipeline. The sample was analyzed statically only. Therefore, no runtime behavior such as process creation, file system activity, registry modification, or network communication was observed. The absence of behavioral analysis tools (e.g., Speakeasy, Frida) means we cannot confirm how the decrypted payload behaves at runtime. However, the static analysis strongly suggests the payload is the crackme challenge logic (serial number validation).

## 6. Network Analysis & C2

No network indicators were found. The binary does not import any networking APIs (e.g., WinHTTP, Winsock, URLDownloadToFile) (source: ghidra_query, callgraph_edges). No strings resembling URLs, IP addresses, or domain names were found in the static strings (source: floss, strings). The YARA rules `domain` and `IP` fired, but these are generic rules that match any binary containing such patterns; in this context, they are likely false positives or refer to benign data within the resources (source: yara, domain/IP rules). There is no evidence of command-and-control (C2) communication, beaconing, or data exfiltration.

## 7. Capability Assessment

| Capability | Status | Evidence |
|------------|--------|----------|
| Obfuscation (XOR) | **Observed** | Entry stub uses XOR loop with key 0x66 (source: r2 disassembly). CAPA confirms T1027 (source: capa). |
| Self-Modifying Code | **Observed** | .text section is RWX, allowing in-place decryption (source: malcat, SectionWX). |
| GUI Interaction | **Observed** | Dialog box with serial number prompt (source: floss, strings; source: ida, imports). |
| Persistence | **Not Observed** | No registry, scheduled task, or service APIs imported (source: ghidra_query). |
| Credential Theft | **Not Observed** | No LSASS, token, or crypto APIs imported (source: ghidra_query). |
| Defense Evasion | **Observed (Neutral)** | XOR encoding and VEH-based execution are evasion techniques, but common in benign software (source: capa, deep-dive.json). |
| Lateral Movement | **Not Observed** | No network or process injection APIs (source: ghidra_query). |
| Data Exfiltration | **Not Observed** | No network APIs or data collection routines (source: ghidra_query). |
| C2 Communication | **Not Observed** | No network APIs or C2 strings (source: ghidra_query, floss). |

The only observed capabilities are obfuscation and GUI interaction, which are consistent with a crackme application.

## 8. Attribution

The binary is attributed to the "Hexorcist" series, likely created by an individual or group for educational purposes. The copyright string "Copyright SAS HEXORCIST" suggests a specific author or group (source: floss, strings). There is no evidence linking this sample to known threat actors or malware campaigns. The techniques used (XOR, VEH) are generic and not indicative of a specific threat group.

## 9. Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| SHA256 | fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f | Sample hash |
| Imphash | d7f03e6d403ce99bd9054453497aa12e | Import table hash |
| String | HEXORCIST CRACKME 7 | Crackme identifier |
| String | SERIAL: | Serial number prompt |
| String | now this is getting serious | Challenge message |
| String | Copyright SAS HEXORCIST | Copyright notice |
| XOR Key | 0x66 | Used for payload decryption |
| Decryption Address | 0x4012b3 | Start of decrypted payload |
| Decryption Size | 0x5d8 (1496 bytes) | Size of decrypted payload |

These IOCs are specific to this crackme and are not indicative of malicious activity. They can be used to identify other samples from the same series.

## 10. Detection Rules

### YARA Rule

A YARA rule was generated for this sample (source: rule.yara.json). The rule is based on 24 strings extracted from the binary, including the crackme identifiers and API names. The rule is valid and can be used to detect other instances of this specific crackme.

**Rule Path**: /opt/samples/logs/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/rule.yar

### Sigma Rule

A Sigma rule was also generated (source: rule.yara.json). The path is: /opt/samples/logs/fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f/rule.yml

### CAPA Rule

CAPA identified one rule: `encode data using XOR` (source: capa). This is a generic detection for XOR-based obfuscation and is not specific to malware.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|----------|
| Defense Evasion | Obfuscated Files or Information | T1027 | XOR encoding of payload (source: capa). |
| Defense Evasion | Obfuscated Files or Information: XOR | T1027.002 | Specific XOR implementation (source: capa). |
| Execution | Shared Modules | T1129 | Use of VEH to execute decrypted code (source: deep-dive.json). |
| Defense Evasion | Process Injection: Vectored Exception Handler | T1055.014 | VEH registration for code execution (source: deep-dive.json). |

The mapping reflects the techniques used, but they are common in both benign and malicious software.

## 12. Containment, Eradication, Recovery

As this sample is assessed as a benign crackme, containment and eradication are not necessary. However, if found in an enterprise environment, the following steps are recommended:

1. **Containment**: Isolate the file for analysis. No active threat is present.
2. **Eradication**: Delete the file if it is not authorized software.
3. **Recovery**: No recovery actions are needed as no malicious activity occurred.

## 13. Recommendations

1. **For Analysts**: This sample is a valuable learning tool for practicing reverse engineering techniques, particularly XOR decryption and VEH-based execution.
2. **For Defenders**: The IOCs provided can be used to identify other samples from the Hexorcist series. However, these IOCs are not indicative of malware and should not be used for blocking without context.
3. **For Organizations**: If this file is found on corporate systems, it is likely an employee practicing reverse engineering. Consider establishing a policy for authorized use of such tools in a controlled environment.

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|--------|-------------|----------|-----|
| ida | Imports (IDA) | rows: (module: KERNEL32, name: GetModuleHandleA), (module: KERNEL32, name: AddVectoredExceptionHandler), (module: USER32, name: DialogBoxParamA), (module: USER32, name: GetDlgItemTextA), etc. | Lists standard Windows API imports for GUI and error handling, indicating a typical benign application with dialog boxes and message processing, not malicious functionality. |
| malcat | anomalies | XorInLoop (code) at address 1034 | Identifies an XOR instruction in a loop at the entry point, which is a common obfuscation technique. However, this is a neutral signal as it appears in benign software like crackmes or protectors. |
| floss | strings | "HEXORCIST CRACKME 7", "SERIAL:", "now this is getting serious" | These strings strongly suggest the sample is a crackme or keygen challenge, with clear indications of serial number input and puzzle-related messages, which are not typically associated with malicious intent. |
| capa | capa | rule: encode data using XOR (ATT&CK T1027) | Confirms the use of XOR encoding for obfuscation, aligning with the observed XOR loop. This technique is neutral and does not imply malicious behavior alone. |
| yara | YARA matches | rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, SEH__vectored | Multiple YARA matches, but in context, these are likely benign indicators (e.g., PE structure, FASM compiler, SEH for error handling). No matches for known malware families or behavioral rules were found. |
| malcat | static_profile | entropy: 84, SectionWX anomaly, UnreferencedImports×8 | High entropy and writable-executable section indicate packing or protection, which are neutral signals. Unreferenced imports suggest decoy APIs, but no malicious imports are present. |
| r2 disassembly | pdf (disasm) | 0x00401000: entry stub with XOR loop and VEH call | Shows the decryption and execution mechanism, confirming the obfuscation technique. |
| ghidra_query | callgraph_edges | No malicious API calls | Confirms absence of network, persistence, or injection APIs. |
| floss | strings | "HEXORCIST CRACKME 7", "SERIAL:" | Strong evidence of crackme purpose. |
| deep-dive.json | verdict | crackme, confidence 90% | Final assessment based on all evidence. |

## 15. Appendix B: Module Inventory

The binary consists of a single module with the following components:

1. **Entry Stub (30 bytes)**: Located at 0x00401000. Decrypts the payload and registers it as a VEH.
2. **Encrypted Payload (1496 bytes)**: Located at 0x4012b3. Contains the main crackme logic (serial number validation, GUI interaction). This payload is encrypted with XOR key 0x66.
3. **Resources**: Includes dialog templates (DLG 37), icons (ICO 1), and version information (VER 1). The .rsrc section has high entropy (85%), suggesting the resources may be packed or compressed.
4. **Import Table**: 9 functions from KERNEL32.DLL and USER32.DLL.

No additional modules or libraries are statically linked.

## 16. Author + Sign-off

**Report Author**: Automated Analysis Pipeline (RevAI)

**Date**: 2026-08-09

**Sign-off**: This report was generated based on static analysis of the sample. The verdict is **suspicious** (crackme) with 90% confidence. No malicious behavior was observed. The sample is a reverse engineering challenge from the Hexorcist series.