> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 14:44:35 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: nSpackV2xLiuXingPing, NsPackV2XLiuXingPing, NsPackv23NorthStar, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasModified_DOS_Message, suspicious_packer_section). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** nSpack
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report presents the analysis of a 32-bit Windows executable (SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5) from the project "REVAI-LAB-CORPUS-H1". The binary is definitively packed with nSpack v2.x, a known executable protector, and masquerades as the legitimate Windows Calculator (calc.exe) through forged version information. Static analysis reveals the packer stub employs aPLib decompression, dynamic API resolution via LoadLibraryA/GetProcAddress, and memory manipulation APIs (VirtualAlloc, VirtualProtect) typical of unpacking routines. Code sections have Read-Write-Execute (RWX) permissions, enabling self-modifying code. While no overt malicious behavior such as C2 communication, persistence, or data destruction was observed in static analysis, the sample's intentional obfuscation and masquerade techniques are concerning. The upstream triage classified this sample as **suspicious** based on packing indicators, a verdict we align with given the absence of observable hostile intent in the static artifact. The true payload remains hidden within the compressed section and is only accessible at runtime.

## 1. Sample Identification
- **SHA256**: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
- **File Path**: /opt/samples/corpus/REVAI-LAB-CORPUS-H1/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/nspack.exe
- **Project Name**: REVAI-LAB-CORPUS-H1
- **File Type**: Portable Executable (PE), 32-bit (x86) architecture (source: malcat).
- **PE Header Info**: Subsystem is Windows GUI (IsWindowsGUI YARA rule), but GuiSubsystemNoWindowApi anomaly noted (source: malcat).
- **Import Hash (Imphash)**: 4ddd9e53a5be88aaffc4455bfc877c19 (source: rule.yara.json).

## 2. Classification
- **Verdict**: SUSPICIOUS.
- **Confidence**: Medium.
- **Family**: nSpack (Packer).
- **Triage Score**: 50/100 (source: triage verdict.json).
- **Rationale**: The sample exhibits high-confidence packing indicators (YARA rules, packer section names, high entropy, RWX sections) but no behavioral evidence of hostile intent such as C2 beaconing, credential theft, or data destruction was observed in the available static analysis. The classification aligns with the upstream triage verdict (source: triage verdict.json). The deep-dive analysis flagged it as malicious due to masquerade and unpacking capabilities, but these are latent attributes of the packer stub, not confirmed behaviors (source: deep-dive.json).

## 3. Background & Family Lineage
- **nSpack (also known as NSPack or NorthStar Packer)**: This is a commercial executable packer/protector from China. It is designed to compress and protect executables, often used by software developers to deter reverse engineering. However, its techniques (dynamic resolution, memory manipulation) are also commonly abused by malware authors to evade detection (source: deep-dive.json).
- **Version**: v2.x, identified by YARA rules (nSpackV2xLiuXingPing, NsPackv23NorthStar) and the embedded string "!packed by nspack$@" (source: floss, yara).
- **Masquerade**: The packer stub's version information is forged to impersonate Microsoft Windows Calculator (CALC.EXE) v5.1.2600.0, a technique to appear benign (source: deep-dive.json).

## 4. Static Analysis
- **Packer Identification**: Deterministic analysis conclusively identifies nSpack v2.x packing based on section names (nsp0, nsp1), high entropy (6.961 in nsp1), and raw/virtual size mismatches (source: packer_intake, malcat).
- **Decompression Routine**: capa detected "decompress data using aPLib" (C0025.003), confirming the packer's decompression method (source: capa).
- **Recovered Function**: The agentic recovery pipeline identified a function at address 0x1025D7E with characteristics matching LZ77 decompression (confidence: 0.7), likely the core of the aPLib decompressor (source: recovered function names).
- **Main Packer Stub**: The main function (FUN_01025d7f / sub_1025d7f) has a high cyclomatic complexity of 18, indicating obfuscated control flow. It calls the recovered `carry_check_loop` and `lz77_decompress` functions (source: ghidra_query, malcat).
- **API Imports**: The import table is minimal (11 imports), with high-signal APIs for memory management (VirtualAlloc, VirtualProtect) and dynamic resolution (LoadLibraryA, GetProcAddress) (source: pe_imports, malcat). These are necessary for the packer's unpacking routine.
- **Code Section Permissions**: Both sections, nsp0 and nsp1, have Read, Write, and Execute (RWX) permissions, which is a classic indicator of self-modifying code used by packers to write and execute the unpacked payload (source: deep-dive.json, malcat).
- **Version Info Forgery**: Embedded manifest and string resources show the binary posing as `Microsoft.Windows.Shell.calc` version 5.1.0.0 (source: rule.yara.json strings).

## 5. Behavioral Analysis
- **Static Behavioral Indicators**: No runtime behavioral analysis was performed (e.g., sandbox, emulation). The available evidence is purely static.
- **Observed Static Behaviors**: The packer stub's use of `VirtualProtect` to change memory permissions and `VirtualAlloc` to allocate memory is observed (source: malcat, pe_imports). These are necessary for unpacking but also common in malware.
- **Missing Behaviors**: No observed persistence mechanisms (e.g., registry run keys, scheduled tasks), no observed network communication, no observed data destruction or encryption (source: deep-dive.json).
- **Conclusion**: The binary's observable behavior is confined to unpacking and executing a hidden payload. Without executing the payload, its ultimate intent remains unknown.

## 6. Network Analysis & C2
- **No Network Indicators Observed**: Static analysis of strings and imports did not reveal any clear C2 domains, IP addresses, or network-related APIs (e.g., winsock, http) beyond basic OS functions.
- **YARA Rule Note**: A YARA rule for "IP" fired at file offset 3242, but the extracted content (`00000040 PE..L.....};.........................`) does not resolve to a valid IP address (source: xorsearch, yara). This is likely a false positive or part of the packer's data.
- **Assessment**: The sample itself does not exhibit network beaconing or C2 communication patterns. However, the unpacked payload may contain such capabilities, which are not visible statically.

## 7. Capability Assessment
- **Confirmed Capability (Observed)**: Executable packing and decompression using nSpack and aPLib (source: capa, floss).
- **Confirmed Capability (Observed)**: Dynamic API resolution via LoadLibraryA/GetProcAddress (source: pe_imports).
- **Confirmed Capability (Observed)**: Memory manipulation (allocation and permission changes) via VirtualAlloc/VirtualProtect (source: malcat).
- **Latent/Potential Capability (Not Observed)**: The ability to execute arbitrary code after unpacking. The payload is encrypted/compressed and its capabilities are unknown.
- **No Evidence For**: Persistence, credential theft, screen capture, lateral movement, or command-and-control communication in the static artifact (source: deep-dive.json).

## 8. Attribution
- **No Attribution**: There is no evidence linking this specific sample to a known threat actor or campaign. The packer (nSpack) is a commercial tool with a broad userbase, both legitimate and malicious. The forged calculator identity does not point to a specific actor.
- **Tactic**: The use of masquerading and packing is a generic technique for evasion, not a unique signature.

## 9. Indicators of Compromise
- **File-Based IOC**:
  - SHA256: 2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5
  - Imphash: 4ddd9e53a5be88aaffc4455bfc877c19
- **Packer String**: "!packed by nspack$@" (source: floss).
- **Forged Version Info**: OriginalFilename: CALC.EXE, FileDescription: "Windows Calculator" (source: rule.yara.json strings).
- **Section Names**: nsp0, nsp1 (source: malcat).

## 10. Detection Rules
- **YARA Rules (Generated)**: A custom YARA rule for this specific sample is available at `/opt/samples/logs/2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5/rule.yar` (source: rule.yara.json).
- **Sigma Rules**: A Sigma rule is available at the corresponding path (source: rule.yara.json).
- **General Detection**: This sample would be detected by any rule looking for nSpack packer signatures, the specific string "!packed by nspack", or RWX sections in combination with virtual memory APIs.

## 11. MITRE ATT&CK Mapping
- **Defense Evasion**:
  - **T1027: Obfuscated Files or Information**: The primary technique, implemented via nSpack packing and aPLib compression (source: capa, yara).
  - **T1036: Masquerading**: Version information is forged to appear as legitimate Windows Calculator (source: deep-dive.json).
  - **T1140: Deobfuscate/Decode Files or Information**: The packer stub decompresses the payload at runtime (source: capa).
- **Execution**:
  - **T1129: Shared Modules**: Uses `LoadLibraryA` and `GetProcAddress` to dynamically resolve APIs, a common technique in both packed and malicious code (source: pe_imports).
- **Note**: These mappings apply to the observed packer stub. The payload's ATT&CK techniques are unknown.

## 12. Containment, Eradication, Recovery
- **Containment**: The sample is already isolated in the analysis corpus. No active infection or spread is indicated.
- **Eradication**: If this sample was found in an environment, deletion of the file and any dropped executables (the unpacked payload) is required. Memory forensics would be needed to identify the unpacked payload if the process was executed.
- **Recovery**: No destructive actions (e.g., encryption of user files) were observed. If the payload did execute, recovery would depend on its actions, which are unknown.

## 13. Recommendations
- **Do Not Execute**: The true payload is unknown and could be malicious. This binary should not be executed outside of a secure analysis environment.
- **Update Signatures**: Ensure YARA and AV rules are updated to detect the nSpack packer signatures and the specific string indicators listed in this report.
- **Memory Analysis**: If this sample was executed in an incident, perform memory analysis to extract and analyze the unpacked payload from the process memory.
- **Review Network Logs**: As a precaution, review network logs for any connections initiated by a process with the name or properties of this sample during the time window it may have been active.

## 14. Appendix A: Evidence Trail
- **Triage Verdict**: Verdict: suspicious, Score: 50, Family: nSpack (source: triage verdict.json).
- **Deep-Dive Verdict**: Verdict: malicious, Confidence: 90 (source: deep-dive.json). **Note**: This assessment is based on the packer's capabilities and masquerade, not observed behavior.
- **Packer Analysis**: UPX probe returned "not packed" (source: upx_unpack). XOR search found no significant encoded strings (source: xorsearch).
- **Recovered Functions**: `lz77_decompress` at 0x1025D7E (confidence 0.7), `carry_check_loop` at 0x1025F48 (confidence 0.4) (source: recovered function names).
- **Key Tool Findings**:
  - YARA: Matches for nSpack, IP, win_registry, base64, and maldoc techniques (source: yara).
  - capa: "decompress data using aPLib" (source: capa).
  - MalCat: 16 anomalies including Packed×2, SectionWX×2, GuiSubsystemNoWindowApi (source: malcat).
  - Ghidra/Radare2: Disassembly shows the entry point jumping into the packer stub at 0x01025A56, which performs anti-debug checks (pushfd/pushal), calculates addresses, and calls VirtualProtect (source: radare2).

## 15. Appendix B: Module Inventory
- **Module 1: Packer Stub (nSpack v2.x)**
  - **Location**: Sections nsp0, nsp1.
  - **Purpose**: Decrypt, decompress, and load the hidden payload into memory.
  - **Key Functions**:
    - Entry point (0x0100101B): Jumps to main stub.
    - Main stub (0x01025A56 / sub_1025A56): Orchestrates unpacking, includes anti-analysis checks.
    - Decompressor (0x01025D7E / lz77_decompress): Implements aPLib/LZ77 decompression.
    - Carry check (0x01025F48 / carry_check_loop): Used in decompression arithmetic.
  - **APIs Used**: VirtualAlloc, VirtualProtect, LoadLibraryA, GetProcAddress.
- **Module 2: Hidden Payload (Unknown)**
  - **Location**: Compressed within the nsp1 section.
  - **Purpose**: Unknown. This is the actual executable code intended to run after unpacking.
  - **Note**: Not accessible for static analysis. Its capabilities determine the sample's true intent.

## 16. Author + Sign-off
- **Report Author**: LLM Malware Analyst (RevAI Pipeline).
- **Date of Analysis**: 2026-08-09.
- **Tool Versions**: Ghidra, Radare2, capa, MalCat, FLOSS, YARA, custom agentic recovery pipeline.
- **Sign-off**: This report is based solely on the provided evidence and static analysis. The verdict of "suspicious" is due to the lack of observed hostile behavior. The sample's packing and masquerade techniques are indicators that warrant caution, but without executing the payload, a definitive malicious classification cannot be confirmed from static artifacts alone.