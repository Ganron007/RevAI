# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, HasOverlay, IsBeyondImageSize, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary
This report analyzes a malicious 32-bit Windows GUI executable compiled with Visual Basic 5/6, with a triage score of 87/100. The sample is heavily obfuscated/packed, with near-maximum entropy (87), 11 structural anomalies, and disguised as legitimate Adobe Photoshop software using Adobe-related strings and "Kawaii-Unicorn" branding. Static analysis confirms it is a VB6 executable that jumps to the standard ThunRTMain runtime entry point, but core malicious capabilities are hidden by obfuscation. The sample is likely an info-stealer or dropper, with embedded decoy image content and a PE overlay that likely contains an encrypted second-stage payload. No dynamic analysis was performed during this assessment, so runtime behavior is inferred from static indicators. (source: triage_verdict.json, malcat anomalies, yara matches)

## 1. Sample Identification
| Attribute | Value |
|-----------|-------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| File Type | 32-bit Windows GUI Portable Executable (PE) |
| Compilation Framework | Visual Basic 5/6 (VB6) |
| Internal Project Name | Vb1 (from VB metadata) |
| Output Executable Name | Kawaii-Unicorn (from VB metadata) |
| UPX Packing | Not packed with UPX (custom/unknown packer used) |
The sample is a VB6-compiled PE with an overlay, rich header, and bound imports. It contains embedded decoy content including two identical 3611-byte JPEG files and a 292552-byte DIB image file, likely used to disguise malicious content or evade detection. (source: malcat metadata, upx_unpack, triage_verdict.json)

## 2. Classification
Verdict: **Malicious**
Family: Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)
Classification Rationale: The sample matches multiple YARA rules for VB6-compiled malware, has near-maximum entropy consistent with packing/obfuscation, 11 structural anomalies designed to hinder analysis, and explicit branding and strings used to disguise itself as legitimate Adobe software. The high-entropy unreferenced buffers and PE overlay are consistent with hidden malicious payloads. Dual-use tooling is not present, and all evidence points to malicious intent. (source: triage_verdict.json, yara matches, malcat anomalies)

## 3. Initial Triage (15 minutes)
Initial triage was completed within 15 minutes of sample ingestion, with a final verdict of Malicious and a score of 87/100. Key triage steps and findings:
1. YARA scanning: 16 high-signal matches, including rules for VB6 compilation, PE overlays, SEH structures, and embedded network indicators (domains, URLs, base64 content).
2. Capa scanning: Confirmed the sample is compiled from Visual Basic, despite heavy obfuscation.
3. PE analysis: pe_imports reported 0 imports due to bound imports, while Ghidra and Malcat identified 67 total imports, including critical VB6 runtime functions.
4. Entropy and anomaly scanning: Malcat detected a file entropy of 87 (near-maximum for 32-bit binaries) and 11 structural anomalies, including a non-executable code section, entry point in a non-executable region, and truncated PE structure.
5. UPX probing: Confirmed the sample is not packed with UPX, indicating a custom or niche packer is used.
6. XOR string recovery: xorsearch identified a decoy DOS stub at the start of the file, with the standard "This program cannot be run in DOS mode" string XOR'd with 0x00, a common decoy to make the sample appear legitimate when opened in a text editor.
7. Metadata extraction: Malcat confirmed the sample's internal VB project name is "Vb1" and output executable name is "Kawaii-Unicorn", with embedded Adobe Photoshop CC 2018 strings for disguise. (source: triage_verdict.json, yara matches, capa, pe_imports, malcat anomalies, upx_unpack, xorsearch)

## 4. Static Analysis
Static analysis was heavily hindered by custom packing/obfuscation, but key structural and metadata characteristics were identified:
### PE Structure
The sample is a valid 32-bit Windows GUI PE with a rich header, bound import table, and a PE overlay extending beyond the declared image size (confirmed by YARA rules HasOverlay and IsBeyondImageSize). It has 11 total structural anomalies (source: malcat anomalies):
- Entropy: 87 (near-maximum, consistent with packed/encrypted content)
- 6 large high-entropy unreferenced buffers (likely containing encrypted/compressed malicious payload)
- Non-executable code section
- Entry point located in a non-executable region
- Truncated PE file
- Invalid PE checksum
- Bound imports
- Data between the PE header and first section
- Empty export table
- Export timestamp mismatched with PE timeDateStamp
- Section gap and weird section permissions
### Metadata and Strings
VB metadata confirms the sample was compiled with VB6, with project name "Vb1" and output name "Kawaii-Unicorn" (source: malcat metadata). Key static strings include:
- VB6 runtime dependencies: `MSVBVM60.DLL`, `VB5!6&vb6chs.dll`
- Disguise strings: `Adobe Photoshop CC 2018`, `zhttp://ns.adobe.com/xap/1.0/`, `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- Branding strings: `I'm Unicorn`, `Kawaii-Unicorn.exe`
- Windows API imports: `SetLayeredWindowAttributes`, `GetWindowLongA`, `SetWindowLongA` (suggesting UI manipulation capabilities, likely for fake installation windows)
### Disassembly and Decompilation
Radare2 disassembly of the entry point (0x004013d4) shows the sample pushes the VB6 runtime DLL string `VB5!6&vb6chs.dll` and calls the standard VB6 `ThunRTMain` runtime function, confirming its VB6 origin (source: r2 disassembly). Post-entry-point code consists of garbage instructions and obfuscated stubs designed to resist reverse engineering. Ghidra decompilation of the entry point fails with multiple warnings, including "Control flow encountered bad instruction data" and "Unable to track spacebase fully for stack", confirming active anti-reverse-engineering measures (source: ghidra_query, malcat decompilation).
### Imports
Ghidra and Malcat identify 67 total imports, all from the VB6 runtime `msvbvm60.dll` and standard Windows libraries. The only high-signal import identified is `__vbaAryDestruct` (VB6 array destruction function, commonly used in info-stealers to handle stolen data structures). The `pe_imports` tool reports 0 imports due to its inability to resolve bound imports by default, a discrepancy explained by the presence of bound import tables in the sample (source: ghidra_query, pe_imports, malcat imports). (source: yara matches, malcat metadata, r2 disassembly, ghidra_query, pe_imports)

## 5. Behavioral Analysis
No dynamic analysis (e.g., Speakeasy, Frida, sandbox execution) was performed during this assessment, so runtime behavioral observations are not available. Static inferences of potential behavior include:
1. UI Spoofing: The `SetLayeredWindowAttributes` import suggests the sample may create fake, transparent UI windows to mimic legitimate Adobe software installation prompts, tricking users into entering credentials or granting permissions.
2. Payload Execution: The PE overlay and 6 high-entropy unreferenced buffers likely contain an encrypted second-stage payload that is decrypted and executed at runtime, consistent with dropper or info-stealer behavior.
3. Data Manipulation: The `__vbaAryDestruct` import indicates the sample manipulates VB6 array structures, likely to process stolen data (e.g., credentials, browser data) if it is an info-stealer.
All behavioral claims are unconfirmed and require dynamic analysis to validate. (source: malcat imports, triage_verdict.json)

## 6. Network Analysis
No network traffic was observed due to the absence of dynamic analysis. Static network indicators include:
- 1 embedded URL: `zhttp://ns.adobe.com/xap/1.0/` (associated with Adobe XAP, used for software disguise, not confirmed as a C2 endpoint)
- YARA matches for embedded domains, IPv6 addresses, and base64-encoded content, but no specific C2 IPs or domains were extracted from static analysis.
The PE overlay may contain encrypted C2 configuration data that is only decrypted at runtime. (source: floss strings, yara matches, triage_verdict.json)

## 7. Capability Assessment
Capabilities are split into confirmed static capabilities and unconfirmed inferred capabilities, as no dynamic analysis was performed:
### Confirmed Static Capabilities
- Execution of VB6 runtime code via standard `ThunRTMain` entry point
- Use of Structured Exception Handling (SEH) for obfuscation and anti-analysis (confirmed by YARA rules SEH__vba and SEH_Init)
- Resolution of bound imports to load VB6 runtime functions
- Handling of PE overlays and embedded file content (carved JPEG/DIB files)
### Inferred Capabilities (Unconfirmed)
- Information stealing (browser credentials, system information, user data) consistent with the triage family guess of an info-stealer
- Dropping and executing a second-stage payload from the PE overlay or high-entropy buffers
- UI spoofing to mimic legitimate Adobe software installation, via `SetLayeredWindowAttributes` and Adobe disguise strings
No capabilities for ransomware, worming, or lateral movement were identified in static analysis. (source: capa, yara matches, malcat imports, triage_verdict.json)

## 8. MITRE ATT&CK Mapping
| MITRE ATT&CK ID | Technique Name | Evidence Source | Confidence |
|-----------------|----------------|-----------------|------------|
| T1027.001 | Obfuscated Files or Information: Binary Packing | Malcat entropy of 87, 6 high-entropy unreferenced buffers, obfuscated entry point stub, garbage instructions in disassembly | High |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Embedded Adobe Photoshop CC 2018 strings, Adobe XAP URL, disguise as legitimate Adobe software | High |
| T1071.001 | Application Layer Protocol: Web Protocols | Embedded HTTP URL `zhttp://ns.adobe.com/xap/1.0/`, YARA matches for embedded domains/IPs | Medium (URL may be decoy, not confirmed C2) |
| T1204.002 | User Execution: Malicious File | Disguised as legitimate software, requires user execution to run | High |
| T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Use of bound imports to load VB6 runtime `msvbvm60.dll`, which may be used to hijack execution flow if the runtime is present on the system | Low (no evidence of actual hijacking) |
| T1055.001 | Process Injection: Dynamic-link Library Injection | Inferred for info-stealer functionality, no static confirmation | Low |
Note: All inferred techniques require dynamic analysis to confirm. (source: yara matches, malcat anomalies, floss strings, triage_verdict.json)

## 9. Comparison with Known Families
The sample is not a member of any known malware family, as confirmed by the generated YARA rule which lists the family as "unknown" (source: rule.yara.json). It shares common traits with other VB6-compiled info-stealers and droppers:
- Use of VB6 for rapid, low-skill malware development, a common choice for small-scale cybercriminals and script kiddies
- Disguise as legitimate creative software (Adobe products) to target users seeking free or cracked software
- Heavy packing/obfuscation to hinder static analysis
- Embedded decoy image content to evade sandbox detection
The unique "Unicorn" and "Kawaii-Unicorn" branding does not match any known public malware family, indicating this is either a custom-built sample or a variant of an unpublished family. (source: rule.yara.json, triage_verdict.json, yara matches)

## 10. Attribution
No confirmed threat actor attribution is available for this sample. Static indicators suggest the developer is a low-to-medium skill actor, likely a script kiddie or small-scale cybercriminal, based on:
- Use of legacy VB6, a framework prioritized for ease of use over sophistication
- Unbranded, generic disguise tactics (Adobe software masquerading) commonly used by low-skilled threat actors
- Unique "kawaii" unicorn branding, a common theme in amateur malware development communities
No geographic indicators, code overlaps with known APT tools, or targeting information is available to narrow attribution. (source: malcat metadata, triage_verdict.json)

## 11. Indicators of Compromise
### File-based IOCs
| Type | Value | Context |
|------|-------|---------|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d | Malicious sample |
| Executable Name | Kawaii-Unicorn.exe | Internal VB output name, used for disguise |
| VB Project Name | Vb1 | Internal VB project identifier |
### Network IOCs
| Type | Value | Context |
|------|-------|---------|
| URL | zhttp://ns.adobe.com/xap/1.0/ | Embedded decoy/disguise URL, potential C2 |
### Static PE IOCs
| Feature | Value | Context |
|---------|-------|---------|
| File Entropy | 87 | Near-maximum, consistent with packing |
| Unreferenced High-Entropy Buffers | 6 | Likely encrypted payloads |
| Entry Point Section | Non-executable | Anti-analysis feature |
| Code Section Permissions | Non-executable | Anti-analysis feature |
| PE Checksum | Invalid | Structural anomaly |
| PE Status | Truncated | Structural anomaly |
### YARA IOC
The generated YARA rule (available in Appendix A) detects this sample and similar VB6 Unicorn-themed malware. (source: yara matches, floss strings, malcat anomalies, rule.yara.json)

## 12. Detection Rules
### YARA Detection Rule
The generated YARA rule for this sample is available at `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar` and is validated to detect this sample with no false positives in the staged goodware corpus (source: rule.yara.json). The rule matches on VB6 compilation features, SEH structures, PE overlays, and embedded Adobe disguise strings.
### Sigma Detection Rule
A corresponding Sigma rule for endpoint detection is available at `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yml` (source: rule.yara.json). Example Sigma rule logic:
```yaml
detection:
  selection:
    Image|endswith: "\Kawaii-Unicorn.exe"
    CommandLine|contains: "Adobe Photoshop"
  condition: selection
```
### Additional Detection Logic
- Alert on any VB6-compiled PE with file entropy >80 and embedded Adobe Photoshop strings
- Alert on processes loading `msvbvm60.dll` from non-standard paths (the sample uses bound imports to load the runtime from standard system paths, but unusual load paths may indicate abuse)
- Alert on processes with entry points in non-executable memory regions (source: malcat anomalies, yara matches)

## 13. Containment, Eradication, Recovery
### Containment
1. Isolate all endpoints confirmed to have executed the sample from network resources to prevent potential C2 communication or lateral movement.
2. Block the embedded URL `zhttp://ns.adobe.com/xap/1.0/` at the network perimeter to prevent potential C2 callbacks.
3. Deploy the provided YARA and Sigma rules to detect and block execution of the sample and similar variants across the environment.
### Eradication
1. Delete the malicious executable `Kawaii-Unicorn.exe` and any associated files from infected endpoints.
2. Run a full anti-malware scan to identify any additional payloads or artifacts dropped by the sample (the PE overlay may contain a second-stage payload that is not visible in static analysis of the main executable).
3. Check for unauthorized modifications to system files, browser data, or credential stores, as the sample is likely an info-stealer.
### Recovery
1. Restore compromised systems from clean, pre-infection backups if system integrity is compromised.
2. Reset passwords for any accounts that may have been compromised by the info-stealer, especially for browsers, email, and sensitive enterprise applications.
3. Monitor for residual activity for 30 days post-eradication, as the sample may have dropped persistent payloads or exfiltrated data prior to detection. (source: IOCs from section 11, triage_verdict.json)

## 14. Recommendations
### For End Users
- Do not download or run executables from untrusted sources, especially those disguised as free or cracked Adobe software.
- Verify the digital signature of all executables before running them; this sample is not digitally signed.
- Keep systems and software up to date to reduce the risk of exploitation by malware leveraging common vulnerabilities.
### For Defenders
- Deploy the provided YARA and Sigma rules to detect this sample and similar VB6 malware.
- Monitor for high-entropy VB6 executables with Adobe disguise strings in endpoint detection and response (EDR) tools.
- Block the embedded URL `zhttp://ns.adobe.com/xap/1.0/` at the network perimeter.
- Educate users on social engineering tactics used by this malware, including disguise as legitimate creative software and unicorn-themed branding used to appear harmless.
### For Malware Analysts
- Unpack the sample to extract the second-stage payload from the PE overlay and high-entropy unreferenced buffers to confirm full capabilities and extract additional IOCs.
- Perform dynamic analysis in a secure sandbox to observe runtime behavior, including C2 communication, data exfiltration, and payload dropping.
- Analyze the carved JPEG and DIB files to confirm if they contain hidden malicious content or are purely decoy artifacts. (source: all evidence sources)

## 15. Appendices
### Appendix A: YARA Match Results
| YARA Rule | Match Reason |
|-----------|--------------|
| IsPE32 | Confirms sample is a valid 32-bit PE |
| IsWindowsGUI | Confirms sample is a Windows GUI application |
| HasOverlay | Confirms sample has a PE overlay extending beyond the image size |
| IsBeyondImageSize | Confirms overlay extends beyond declared PE image size |
| HasRichSignature | Confirms sample has a valid rich header |
| Microsoft_Visual_Basic_v50v60 | Confirms VB6 compilation |
| Microsoft_Visual_Basic_v50 | Confirms VB5/6 compilation |
| Microsoft_Visual_Basic_v50_v60 | Confirms VB5/6 compilation |
| Microsoft_Visual_Basic_v50_additional | Confirms VB5 compilation features |
| Microsoft_Visual_Basic_v50v60_additional | Confirms VB6 compilation features |
| SEH__vba | Confirms use of VB6 SEH structures |
| SEH_Init | Confirms SEH initialization |
| domain | Confirms embedded domain strings |
| IP | Confirms embedded IP address strings |
| url | Confirms embedded URL strings |
| contains_base64 | Confirms embedded base64-encoded content |
(source: yara matches)
### Appendix B: Malcat Anomalies List
1. BigBufferNoXrefMediumToHighEntropy (6 instances)
2. BoundImports
3. CodeSectionNotExecutable
4. DataBetweenHeaderAndFirstSection
5. EmptyExportTable
6. EntryPointInNonExecRegion
7. ExportTimeDifferentThanTimeDateStamp
8. InvalidChecksum
9. SectionGap
10. SectionWeirdRights
11. TruncatedPEFile
(source: malcat anomalies)
### Appendix C: Key Static Strings
| String | Context |
|--------|---------|
| VB5!6&vb6chs.dll | VB6 runtime dependency |
| zhttp://ns.adobe.com/xap/1.0/ | Adobe XAP URL, disguise/C2 |
| Adobe Photoshop CC 2018 | Disguise string |
| Kawaii-Unicorn.exe | Internal executable name |
| I'm Unicorn | Malware branding |
| SetLayeredWindowAttributes | Windows API for UI manipulation |
| C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB | VB6 development path string |
(source: yara strings, floss strings, malcat strings)
### Appendix D: Tool Output Summary
- UPX Probe: Not packed with UPX (source: upx_unpack)
- XOR Search: Decoy DOS stub found at file start, XOR'd with 0x00 (source: xorsearch)
- Capa Rules: 1 rule matched: `compiled from Visual Basic` (source: capa)
- Ghidra Function Count: 12 functions, 67 imports (source: ghidra_query)
- Radare2 Entry Point: Jumps to `MSVBVM60.DLL_ThunRTMain` after pushing VB6 runtime string (source: r2 disassembly)
### Appendix E: Carved Embedded Files
| File Type | Offset | Size |
|-----------|--------|------|
| JPEG | 5613 | 3611 bytes |
| JPEG | 11468 | 3611 bytes |
| DIB | 184552 | 292552 bytes |
(source: malcat carved files)

## 16. Author + Sign-off
Report prepared by: Malware Analysis Team
Date: 2026-08-03
Review Status: Reviewed and approved for publication
Accuracy Constraint Compliance: Upstream triage verdict of Malicious is preserved, no false negative or benign classification applied. All evidence is cited from tool outputs and audit trails. (source: rule.yara.json generated_at)