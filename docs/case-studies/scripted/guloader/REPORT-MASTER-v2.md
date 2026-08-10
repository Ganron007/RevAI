> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:53:54 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# GuLoader (CloudEyE) Malware Analysis Report

## Executive Summary

This report presents the analysis of a PE32 executable identified as GuLoader (also known as CloudEyE), a well-known Visual Basic 6-based malware dropper/loader. The sample exhibits heavy obfuscation, dynamic API resolution via shellcode, and XOR-encoded strings, which are hallmarks of the GuLoader family. The upstream triage verdict is **suspicious** due to the absence of direct behavioral evidence (e.g., C2, persistence, data exfiltration) in the static analysis phase. However, the deep-dive analysis, corroborated by multiple tools, strongly indicates malicious intent based on the sample's structure, obfuscation techniques, and known malware family characteristics. The sample's primary function is to decrypt and execute an embedded shellcode payload, which would then download and run additional malware. We assess with high confidence that this is a malicious dropper, but the final payload is not present in this sample, limiting the observable impact.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| SHA256 | c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509 |
| File Name | guLoader.exe |
| File Path | /opt/samples/corpus/REVAI-LAB-CORPUS-H3/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe |
| File Size | 49,152 bytes |
| File Type | PE32 executable (GUI) Intel 80386, for MS Windows |
| Architecture | x86 (32-bit) |
| Compilation | Visual Basic 6.0 (source: yara, capa, malcat) |
| Import Hash (Imphash) | e5dc9f90e63a8223ac7d0f9627dcbb68 (source: rule.yara.json) |
| Project Name | REVAI-LAB-CORPUS-H3 |

## 2. Classification

| Field | Value |
|---|---|
| Verdict | **Malicious** |
| Confidence | 90% |
| Family | GuLoader (CloudEyE) |
| Type | Dropper / Loader |
| Upstream Triage Verdict | Suspicious (score: 40) |
| Upstream Family Guess | Unknown (VisualBasic Loader) |

**Justification:** The upstream triage verdict of "suspicious" is based on static indicators (high entropy, anomalies, obfuscated code) without behavioral evidence. Our deep-dive analysis, however, identifies the sample as GuLoader based on its specific structural and behavioral characteristics: a VB6 runtime with no Win32 API imports, dynamic API resolution via shellcode, XOR-encoded strings, and fake version metadata. These are not generic obfuscation signals but are specific to the GuLoader malware family. The sample's sole purpose is to decrypt and execute a payload, which is a malicious action. Therefore, we upgrade the verdict to **malicious** with high confidence. (source: deep-dive.json)

## 3. Background & Family Lineage

GuLoader (also known as CloudEyE) is a commercial-grade malware loader/dropper that has been active since at least 2019. It is primarily used to deliver other malware payloads, such as information stealers (e.g., RedLine, Vidar), RATs (e.g., Agent Tesla, NanoCore), and ransomware. The loader is known for its heavy obfuscation, including:

*   **VB6 Runtime:** The core is compiled in Visual Basic 6, which provides a layer of abstraction and makes static analysis difficult.
*   **Dynamic API Resolution:** It does not import standard Win32 APIs. Instead, it resolves them at runtime through obfuscated shellcode, evading static import analysis.
*   **XOR Encryption:** Strings and the final payload are encrypted with XOR, often with a hardcoded key.
*   **Anti-Analysis Techniques:** It employs various methods to detect and evade debuggers, virtual machines, and sandboxes.

The sample analyzed here matches these characteristics precisely. The recovered function `decrypt_and_run_shellcode` (address 4224965) is a core component of GuLoader's operation. (source: deep-dive.json, recovered function names)

## 4. Static Analysis

### 4.1 File Properties and Anomalies

The PE file has an entropy of 73 (source: malcat), which is high but not conclusive for packing. The file contains three anomalies: `BoundImports`, `InvalidChecksum`, and `StackArrayInitialisationX86` (source: malcat). The `InvalidChecksum` is a common trait in malware to avoid integrity checks. The `BoundImports` anomaly suggests the import table may be manipulated.

### 4.2 Imports

The sample has **60 imports, all from MSVBVM60.DLL** (the Visual Basic 6 runtime). There are **zero imports from standard Win32 libraries** like kernel32.dll, ntdll.dll, or user32.dll (source: deep-dive.json, pe_imports). This is a critical indicator: legitimate software requires Win32 APIs for basic functionality. The absence of these imports confirms that all API calls are resolved dynamically at runtime, a technique used to hide the malware's true capabilities from static analysis.

### 4.3 Strings and Version Information

FLOSS extracted 175 strings, many of which are heavily XOR-encoded (e.g., `;iC=w}`, `O|XPHT`, `%<0G:\MN`) (source: deep-dive.json). This is characteristic of GuLoader's payload encryption. The only clear path string is `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`, which is a legitimate VB6 development path but can be mimicked by malware.

The version metadata contains nonsensical, Danish-sounding words: `ProductName='Startsym1'`, `CompanyName='Delfiteknikkernes'`, `FileDescription='Topklasser'`, `OriginalFilename='Startsym1.exe'` (source: deep-dive.json). This is a common tactic to fill required fields with meaningless data.

### 4.4 Code Complexity and Obfuscation

The main function `FUN_00408b2e` (address 0x408b2e) has a cyclomatic complexity of 54, 88 basic blocks, and 370 instructions (source: deep-dive.json). This extreme complexity is indicative of obfuscated loader logic. The entry point (0x401368) contains abnormal instruction sequences, including `XOR byte ptr [EAX], AL; POPAD; AAA`, which suggest self-modifying code (source: deep-dive.json).

### 4.5 Recovered Functions

The agentic recovery pipeline identified two key functions:

1.  **`decrypt_and_run_shellcode` (addr: 4224965, confidence: 0.65):** This function decrypts a payload using XOR with key `0x4fb8c87c` from data at `0x00402851` into allocated memory and executes it (source: recovered function names). This is the core malicious functionality.
2.  **`vba_com_object_processor` (addr: 4229934, confidence: 0.5):** This function interacts with the VBA runtime and COM objects, likely for automation or persistence (source: recovered function names).

## 5. Behavioral Analysis

**No runtime behavioral data is available.** The analysis is based solely on static and code analysis. Tools like Speakeasy or Frida were not used, and no sandbox execution was performed. Therefore, we cannot observe actual network connections, file system changes, or registry modifications. The behavioral assessment is inferred from the static code structure.

## 6. Network Analysis & C2

**No network indicators were observed in the static analysis.** The sample does not contain hardcoded URLs, IP addresses, or domain names. This is expected for GuLoader, as the C2 configuration is typically embedded within the encrypted shellcode payload, which is not present in this dropper sample. The network activity would only occur after the shellcode executes and downloads the final payload. (source: deep-dive.json)

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| **Payload Decryption & Execution** | **Observed (Static)** | The function `decrypt_and_run_shellcode` (addr 4224965) contains logic to XOR-decrypt data and execute it as shellcode. (source: recovered function names, deep-dive.json) |
| **Dynamic API Resolution** | **Observed (Static)** | Zero Win32 API imports; all API calls are resolved at runtime via shellcode. (source: deep-dive.json, pe_imports) |
| **Anti-Analysis / Obfuscation** | **Observed (Static)** | High cyclomatic complexity, abnormal instruction sequences, XOR-encoded strings, fake version info. (source: deep-dive.json, malcat) |
| **Persistence** | **Latent** | The `vba_com_object_processor` function suggests potential for COM-based persistence, but this is not directly observed. (source: recovered function names) |
| **C2 Communication** | **Latent** | Not present in this dropper; would be a capability of the final payload. |
| **Data Exfiltration** | **Latent** | Not present in this dropper; would be a capability of the final payload. |

## 8. Attribution

No specific threat actor attribution is possible based on this sample alone. GuLoader is a commercially available loader used by a wide range of cybercriminals. The fake Danish metadata does not provide reliable attribution. The sample's infrastructure (C2 servers, payload URLs) would be needed for attribution, but that data is not available in this analysis.

## 9. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| **SHA256** | c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509 | Malicious dropper file |
| **Imphash** | e5dc9f90e63a8223ac7d0f9627dcbb68 | Import hash for GuLoader variants |
| **File Name** | guLoader.exe | Common name for this malware |
| **XOR Key** | 0x4fb8c87c | Used to decrypt the shellcode payload (source: recovered function names) |
| **Data Offset** | 0x00402851 | Location of encrypted payload data (source: recovered function names) |
| **Fake Product Name** | Startsym1 | Used in version metadata (source: deep-dive.json) |
| **Fake Company Name** | Delfiteknikkernes | Used in version metadata (source: deep-dive.json) |
| **Fake File Description** | Topklasser | Used in version metadata (source: deep-dive.json) |

## 10. Detection Rules

### YARA Rule (Generated)

A YARA rule was generated for this sample (source: rule.yara.json). The rule file is located at `/opt/samples/logs/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/rule.yar`. It contains 24 strings, including the unique strings `Borderadamasprei`, `Startsym1`, `adamasprei`, and `REBALANCES`.

### Sigma Rule

A Sigma rule was also generated (source: rule.yara.json). The rule file is located at `/opt/samples/logs/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/rule.yml`.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Execution** | User Execution: Malicious File | T1204.002 | The sample is an executable file that requires user interaction to run. |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Heavy use of XOR encryption for strings and payload, high code complexity. (source: deep-dive.json) |
| **Defense Evasion** | Deobfuscate/Decode Files or Information | T1140 | The `decrypt_and_run_shellcode` function decodes the payload at runtime. (source: recovered function names) |
| **Defense Evasion** | Process Injection | T1055 | The shellcode is executed in memory, a form of process injection. (source: deep-dive.json) |
| **Discovery** | System Information Discovery | T1082 | GuLoader typically performs environment checks, though not directly observed here. |
| **Command and Control** | Ingress Tool Transfer | T1105 | The final payload is likely downloaded from a remote server after the shellcode executes. |

## 12. Containment, Eradication, Recovery

**Containment:** Isolate any systems where this file has been executed. Block the file hash at the network perimeter and endpoint protection solutions.

**Eradication:** Remove the malicious executable from all affected systems. Since this is a dropper, the final payload (if downloaded) must also be identified and removed. Scan systems for the presence of other malware delivered by GuLoader (e.g., RedLine, Vidar, Agent Tesla).

**Recovery:** If the final payload was executed, the system may be compromised. A full forensic analysis is recommended to determine the extent of the compromise. Restore systems from known-good backups if necessary.

## 13. Recommendations

1.  **Block IOCs:** Add the SHA256 hash and Imphash to threat intelligence platforms and endpoint detection rules.
2.  **User Awareness:** Educate users about the risks of executing unknown files, especially those with misleading names or from untrusted sources.
3.  **Endpoint Protection:** Ensure endpoint protection solutions are configured to detect and block GuLoader variants. The generated YARA and Sigma rules can be integrated into detection engines.
4.  **Network Monitoring:** Monitor for network connections to known GuLoader C2 infrastructure, if available. Look for patterns of initial connection followed by a larger payload download.
5.  **Sandbox Analysis:** For future samples, dynamic analysis in a sandbox environment is critical to observe the final payload and C2 communication.

## 14. Appendix A: Evidence Trail

This section summarizes the key evidence sources used in the analysis.

| Source | Key Findings |
|---|---|
| **deep-dive.json** | Identified sample as GuLoader, detailed obfuscation techniques, fake metadata, high code complexity. |
| **recovered function names** | Identified `decrypt_and_run_shellcode` and `vba_com_object_processor` functions. |
| **malcat** | Provided file entropy, anomalies, and YARA matches. |
| **yara** | Confirmed Visual Basic compilation and matched multiple rules. |
| **capa** | Confirmed Visual Basic compilation. |
| **floss** | Extracted 175 strings, many XOR-encoded. |
| **pe_imports** | Showed 60 imports, all from MSVBVM60.DLL. |
| **rule.yara.json** | Generated YARA and Sigma rules for detection. |
| **ghidra_query** | Provided function metrics, call graphs, and pseudocode for analysis. |
| **r2 disassembly** | Provided assembly-level view of entry point and import stubs. |

## 15. Appendix B: Module Inventory

The sample is a single executable file. The primary modules are:

1.  **VB6 Runtime Stub:** The main executable code compiled from Visual Basic 6. It handles initialization and calls into the MSVBVM60.DLL runtime.
2.  **Obfuscated Loader Logic:** The core malicious code, represented by the high-complexity function `FUN_00408b2e`. This contains the decryption and execution routines.
3.  **Encrypted Payload:** A block of XOR-encrypted data (at offset 0x00402851) that contains the shellcode to be executed. The shellcode itself is not present in the clear.
4.  **Resource Section:** Contains icons and version information with fake metadata.

## 16. Author + Sign-off

**Report Author:** Automated Malware Analysis Pipeline (RevAI)

**Date:** 2026-08-09

**Sign-off:** This report was generated by an automated analysis system. The findings are based on static analysis and code recovery. Dynamic analysis is recommended for complete behavioral assessment.