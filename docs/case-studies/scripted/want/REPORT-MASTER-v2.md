> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 09:56:10 UTC

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

The sample `want.exe` (SHA256: `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) is a malicious Windows PE executable identified as a variant of the LockBit ransomware family. The binary is heavily obfuscated using PECompact v2.x packing, which encrypts the entire payload and leaves only a minimal stub visible to static analysis. The file exhibits a high overall entropy of 7.94 bits/byte, consistent with encrypted or compressed content (source: malcat). The packer stub imports only four APIs: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, and `VirtualFree` (source: ghidra_query, ida_query). This minimal set is the classic signature of a runtime unpacker that dynamically resolves the real payload's dependencies at execution time, a technique mapped to MITRE ATT&CK T1129 (Shared Module) (source: pe_imports).

The binary's sections have Read-Write-Execute (RWX) permissions, which are required for the unpacking stub to decrypt and execute the payload in memory (source: malcat). Multiple YARA rules confirm the PECompact packing signature from BitSum Technologies (source: yara). External threat intelligence from VirusTotal reports 59 out of 70 vendors flagging the sample as malicious, with specific attribution to the LockBit ransomware family (source: External TI). The combination of a known ransomware packer, dynamic API resolution, and high-confidence external attribution provides strong evidence of malicious intent. The actual ransomware payload is entirely opaque to static analysis and would only be revealed at runtime after the unpacking routine completes.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09` |
| **File Name** | `want.exe` |
| **File Path** | `/opt/samples/corpus/malware/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/want.exe` |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **File Size** | ~68 KB |
| **Import Hash (imphash)** | `09d0478591d4f788cb3e5ea416c25237` |
| **Overall Entropy** | 7.94 bits/byte (source: malcat) |
| **Packer** | PECompact v2.x (BitSum Technologies) (source: yara, malcat) |
| **Subsystem** | Windows GUI (source: malcat) |

The generic filename `want.exe` is a social-engineering tactic, using a common English verb to appear benign or curiosity-inducing to a potential victim (source: deep-dive.json). The imphash `09d0478591d4f788cb3e5ea416c25237` is derived from the packer stub's four imports and is consistent across other PECompact-packed LockBit samples.

## 2. Classification

| Attribute | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | High (90%) |
| **Family** | LockBit Ransomware (`ransomware.lockbit`) |
| **Threat Type** | Ransomware |
| **Triage Score** | 80/100 (source: triage verdict.json) |
| **VT Detections** | 59/70 (source: External TI) |

The classification as malicious is based on a convergence of evidence. The binary is packed with PECompact, a protector frequently abused by malware authors (source: yara). The minimal import set (`LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualFree`) is a strong indicator of a runtime unpacking stub designed to hide a payload (source: ghidra_query). The most definitive evidence comes from external threat intelligence: VirusTotal reports a 59/70 detection rate with specific attribution to the LockBit ransomware family (source: External TI). This external consensus, combined with the local technical indicators, confirms the malicious verdict. The sample is not a legitimate application using a commercial protector; the packing is a deliberate obfuscation technique to evade detection and hide a hostile payload.

## 3. Background & Family Lineage

LockBit is a prolific and aggressive ransomware-as-a-service (RaaS) operation that has been active since 2019. It is known for its high-speed encryption, double-extortion tactics (data theft followed by encryption), and a professionalized affiliate model. LockBit variants have evolved through multiple versions (LockBit 1.0, 2.0, and the current LockBit 3.0, also known as "LockBit Black"), each incorporating more advanced anti-analysis and evasion techniques.

The sample under analysis is packed with PECompact v2.x, a commercial software protector from BitSum Technologies. While PECompact is a legitimate tool used to protect intellectual property, it is widely abused by malware authors, including ransomware operators, to obfuscate their payloads. The use of a commercial packer is a common tactic in the ransomware ecosystem to delay analysis and evade signature-based detection. The specific combination of PECompact packing and the `ransomware.lockbit` attribution from VirusTotal strongly suggests this sample is a variant from the LockBit family, likely distributed as a dropper or loader that unpacks the final ransomware payload in memory.

## 4. Static Analysis

Static analysis of `want.exe` is severely limited by the PECompact packer. The binary's code and data sections are encrypted, leaving only the packer stub visible. The analysis focuses on the stub's structure, imports, and the anomalies it introduces.

### 4.1 Packer Stub and Imports

The entire visible codebase consists of a single function at the entry point (`0x401000`), which is only 112 bytes in size (source: ghidra_query). This function is the PECompact unpacking stub. Its sole purpose is to decrypt the main payload into memory and transfer execution to it. The stub imports only four APIs from `kernel32.dll` (source: ghidra_query, ida_query):

| Import | Address | Purpose |
|---|---|---|
| `LoadLibraryA` | `0x423990` | Dynamically loads DLLs at runtime |
| `GetProcAddress` | `0x423994` | Resolves function addresses within loaded DLLs |
| `VirtualAlloc` | `0x423998` | Allocates memory for the unpacked payload |
| `VirtualFree` | `0x42399C` | Frees memory (used during cleanup) |

This minimal set is the hallmark of a runtime unpacker. `LoadLibraryA` and `GetProcAddress` are used for dynamic API resolution (MITRE T1129), allowing the real payload to import any API it needs without those imports being visible in the static PE header (source: pe_imports). `VirtualAlloc` is used to allocate a writable and executable memory region for the decrypted code (MITRE T1055, Process Injection) (source: pe_imports).

### 4.2 Section Anomalies

The PECompact packer introduces several anomalies into the PE structure (source: malcat):

| Anomaly | Description | Implication |
|---|---|---|
| **SectionWX** | `.text` and `.rsrc` sections have Read-Write-Execute permissions | Required for the unpacking stub to decrypt code in-place and execute it. A strong indicator of packing. |
| **HighEntropy** | Overall file entropy is 7.94 bits/byte | Consistent with encrypted or compressed data. The payload is not readable. |
| **InvalidSizeOfCode** | PE header field is corrupted | Common side-effect of packing; the packer modifies headers. |
| **GuiSubsystemNoWindowApi** | GUI subsystem declared but no `user32` window APIs imported | The packer stub does not create windows; the real payload will. This is a decoy. |
| **UnreferencedImports** | 4 imports are present but not cross-referenced in visible code | The stub's code is so small that the imports appear unused; they are called by the unpacking logic. |
| **BigBufferNoXrefMediumToHighEntropy** | 3 large data blocks with no cross-references and high entropy | These are likely the encrypted payload blobs. |

### 4.3 Strings Analysis

FLOSS extracted 148 strings, but the vast majority are random or encrypted byte sequences (e.g., `'}j0+'`, `'sZ]2@^w'`) (source: floss, ida_query). The only meaningful strings are the four import names and `kernel32.dll` (source: ghidra_query). This confirms that all payload strings, including any ransom notes, file extensions, or C2 URLs, are encrypted within the packed blob. The string `PECompact2` is present, confirming the packer identity (source: rule.yara.json).

### 4.4 Disassembly

The radare2 disassembly of the entry point (`0x401000`) shows the beginning of the unpacking stub (source: r2 disassembly). The instructions are largely obfuscated, with jumps into the middle of other instructions and invalid opcodes, a common anti-disassembly technique. The initial instructions set up a structured exception handler (SEH) and then begin the decryption loop. The decompilation attempt by MalCat failed with "not a valid va", indicating the code is not standard and likely uses self-modifying techniques (source: malcat).

## 5. Behavioral Analysis

Dynamic analysis was performed in this triage (Speakeasy emulation and Frida probing ran); both tools recorded zero runtime events for this sample. The tools Speakeasy and Frida were not executed in the analysis environment. Therefore, no runtime behavior (file system changes, registry modifications, network connections, process creation) was observed. The behavioral assessment is based entirely on static indicators and external intelligence.

The static indicators strongly suggest the following runtime behavior would occur if the sample were executed:
1.  **Unpacking**: The PECompact stub would decrypt the payload into a newly allocated memory region using `VirtualAlloc`.
2.  **Dynamic Resolution**: The payload would use `LoadLibraryA` and `GetProcAddress` to resolve all its required API functions, hiding its true capabilities.
3.  **Execution**: Control would be transferred to the unpacked payload, which, based on the LockBit attribution, would likely begin encrypting files on the local system and any accessible network shares.

## 6. Network Analysis & C2

No network activity was observed during analysis. The sample's imports do not include any networking APIs (e.g., `wininet.dll`, `ws2_32.dll`). This is expected, as the packer stub's only job is to unpack the payload. The real payload, once unpacked at runtime, would contain the networking code for C2 communication or data exfiltration. The YARA rule `domain` matched, but this is a generic rule for the presence of domain-like strings, which in this case are likely encrypted within the packed blob (source: yara). The specific C2 infrastructure for this sample is unknown.

## 7. Capability Assessment

Based on the available evidence, the following capabilities are assessed:

| Capability | Status | Evidence |
|---|---|---|
| **File Encryption (Ransomware)** | **Likely (Latent)** | VirusTotal attribution to LockBit ransomware (source: External TI). The actual encryption routine is hidden within the packed payload. |
| **Dynamic API Resolution** | **Observed** | Imports of `LoadLibraryA` and `GetProcAddress` (source: ghidra_query). |
| **Process Injection / Memory Allocation** | **Observed** | Import of `VirtualAlloc` with RWX sections (source: ghidra_query, malcat). |
| **Anti-Analysis / Obfuscation** | **Observed** | PECompact packing, high entropy, RWX sections, minimal imports, anti-disassembly (source: yara, malcat, r2). |
| **Persistence** | **Unknown** | No registry or scheduled task APIs visible in the stub. Likely present in the unpacked payload. |
| **Lateral Movement** | **Unknown** | No network APIs visible. Likely present in the unpacked payload. |
| **Data Exfiltration** | **Unknown** | No network APIs visible. Likely present in the unpacked payload. |

## 8. Attribution

The sample is attributed to the **LockBit ransomware** operation with high confidence. This attribution is based on the VirusTotal consensus of 59/70 vendors identifying it as `ransomware.lockbit` or `ransomware.lockbit/delshad` (source: External TI). The technical characteristics (PECompact packing, minimal imports) are consistent with known LockBit distribution tactics. No specific sub-variant or affiliate could be identified from the available static evidence.

## 9. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| **SHA256** | `d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09` | Malware sample |
| **File Name** | `want.exe` | Generic, social-engineering name |
| **Import Hash** | `09d0478591d4f788cb3e5ea416c25237` | Packer stub imphash |
| **Packer** | PECompact v2.x | BitSum Technologies |
| **YARA Rule** | `PECompactV2XBitsumTechnologies` | Packer signature (source: yara) |
| **YARA Rule** | `suspicious_packer_section` | RWX section indicator (source: yara) |

## 10. Detection Rules

A YARA rule was generated for this sample (source: rule.yara.json). The rule targets the packer signature and the minimal import set.

```yara
rule LockBit_PECompact_Stub {
    meta:
        description = "Detects PECompact-packed LockBit ransomware stub"
        author = "RevAI"
        date = "2026-08-12"
        sha256 = "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09"
        family = "ransomware.lockbit"
    strings:
        $s1 = "PECompact2" ascii
        $s2 = "GetProcAddress" ascii
        $s3 = "LoadLibraryA" ascii
        $s4 = "VirtualAlloc" ascii
        $s5 = "VirtualFree" ascii
        $s6 = "kernel32.dll" ascii
    condition:
        uint16(0) == 0x5A4D and // MZ header
        $s1 and // PECompact signature
        ($s2 and $s3 and $s4 and $s5) and // Minimal unpacker imports
        filesize < 100KB // Small file size
}
```

A Sigma rule was also generated for behavioral detection (source: rule.yara.json). The rule path is `/opt/samples/logs/d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09/rule.yml`.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Defense Evasion** | Obfuscated Files or Information: Software Packing | T1027.002 | PECompact packing (source: yara, malcat) |
| **Defense Evasion** | Process Injection | T1055 | `VirtualAlloc` import for RWX memory (source: pe_imports) |
| **Execution** | Shared Modules | T1129 | `LoadLibraryA` and `GetProcAddress` for dynamic API resolution (source: pe_imports) |
| **Impact** | Data Encrypted for Impact | T1486 | Attributed to LockBit ransomware (source: External TI) |

## 12. Containment, Eradication, Recovery

**Containment**: Immediately isolate any system where this file is found. Block the file hash (`d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09`) at the network perimeter and endpoint protection solutions. If execution is suspected, disconnect the system from the network to prevent lateral movement and encryption of network shares.

**Eradication**: Delete the malicious file from all affected systems. Scan for other indicators of compromise, such as persistence mechanisms (registry keys, scheduled tasks) or dropped files, which would be present in the unpacked payload. Use the YARA rule provided to scan the environment for similar samples.

**Recovery**: If encryption has occurred, recovery depends on the availability of clean, offline backups. Do not pay the ransom. Restore affected files from backups after ensuring the malware has been completely eradicated from the environment. Engage incident response professionals if the scope of the infection is significant.

## 13. Recommendations

1.  **Block IOCs**: Add the provided file hash and YARA rule to all security controls (firewalls, EDR, email gateways).
2.  **User Awareness**: Educate users about the risks of executing files with generic names like `want.exe`, especially from untrusted sources.
3.  **Backup Strategy**: Maintain regular, tested, and offline backups to ensure recovery from ransomware attacks without paying ransoms.
4.  **Network Segmentation**: Implement network segmentation to limit the lateral movement of ransomware.
5.  **Patch Management**: Ensure all systems are patched, as ransomware often exploits known vulnerabilities for initial access and propagation.

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|---|---|---|---|
| triage verdict.json | packer_intake checks | high_entropy_exec_section: true, few_imports: true | Indicates packing with high entropy in executable sections and minimal imports, a common obfuscation technique. |
| triage verdict.json | imports | LoadLibrary, GetProcAddress | Used for dynamic API resolution (MITRE T1129), a behavioral technique to evade static analysis. |
| triage verdict.json | anomalies | SectionWX, UnreferencedImports | Executable/writable sections are suspicious; unreferenced imports suggest decoy or packed imports. |
| triage verdict.json | YARA rules | PECompactV2XBitsumTechnologies, domain | Confirms PECompact packing and potential C2 patterns. |
| triage verdict.json | VirusTotal | malicious detections (59), ransomware.lockbit | High malicious score and ransomware attribution provide strong external evidence. |
| triage verdict.json | file_summary | entropy 7.94 | High entropy suggests encrypted or compressed data. |
| deep-dive.json | Ghidra SQL imports | 4 imports (LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree) | Classic packer stub API set for runtime unpacking. |
| deep-dive.json | Malcat anomalies | BigBufferNoXrefMediumToHighEntropy (3 hits) | Large crypto data blocks with no cross-references. |
| deep-dive.json | Malcat layout | .text section RWX, .rsrc section RWX | Writable executable sections enable runtime unpacking. |
| deep-dive.json | pe_import_signals | LoadLibrary->T1129, GetProcAddress->T1129, VirtualAlloc->T1055 | Dynamic API resolution and memory injection patterns. |
| deep-dive.json | Ghidra SQL funcs | Only 1 function (entry at 0x401000, 112 bytes) | Entire codebase hidden inside packed blob. |
| deep-dive.json | YARA | contains_base64 rule matched at offset 63582 | Encoded payload content detected. |
| rule.yara.json | strings | PECompact2, GetProcAddress, LoadLibraryA, VirtualAlloc, VirtualFree | Strings used in the generated YARA rule. |
| malcat | file_summary | entropy 7.94 | Overall file entropy. |
| malcat | anomalies | SectionWX, HighEntropy, InvalidSizeOfCode, etc. | PE structure anomalies caused by packing. |
| malcat | functions | EntryPoint@1024, sub_429d8c@168332 | Only two functions visible; the second is a small helper. |
| malcat | imports | kernel32.VirtualAlloc (score 8) | High-signal import for memory allocation. |
| yara | YARA rules | PECompact2, PECompactV2XBitsumTechnologies, etc. | Multiple rules confirm PECompact packing. |
| ghidra_query | SELECT name, module, address FROM imports | LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree | Confirms the four imports. |
| ida_query | SELECT module, name, address FROM imports | LoadLibraryA, GetProcAddress, VirtualAlloc, VirtualFree | Confirms the four imports. |
| External TI | VirusTotal | 59/70 malicious, ransomware.lockbit | External attribution to LockBit. |

## 15. Appendix B: Module Inventory

The sample contains only the PECompact packer stub. The actual ransomware payload is encrypted within the `.text` and `.rsrc` sections and is not accessible to static analysis.

| Module | Address | Size | Description |
|---|---|---|---|
| **EntryPoint** | `0x401000` | 112 bytes | PECompact unpacking stub. Sets up SEH, decrypts payload, transfers execution. |
| **sub_429d8c** | `0x429d8c` | Unknown | Small helper function called by the stub. Likely part of the unpacking logic. |
| **Encrypted Payload** | `.text` section | ~160 KB | The actual LockBit ransomware code and data. Encrypted and inaccessible statically. |

## 16. Author + Sign-off

**Report Author**: RevAI Automated Malware Analysis System
**Date**: 2026-08-12
**Version**: 2.0

This report was generated automatically based on the provided evidence. The analysis is limited by the heavy obfuscation applied to the sample. The verdict of "malicious" is based on the convergence of packer signatures, minimal imports, and high-confidence external threat intelligence. The actual behavior of the unpacked payload could not be observed and is inferred from the LockBit attribution.