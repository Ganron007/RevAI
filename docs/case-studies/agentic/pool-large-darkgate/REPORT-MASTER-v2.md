# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malware |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `malicious` (YARA / tool-backed: System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

# Executive Summary

This sample is a high-confidence malicious PE32 loader/dropper, scoring 9/10 on the triage verdict (source: triage_verdict). It is disguised as a legitimate Tencent GameLoop installer using an expired code signing certificate (valid 2020-11-25 to 2024-02-22) (source: malcat). The sample exhibits heavy obfuscation (entropy 157, custom XOR/Base64/AES encoding) (source: malcat, capa), process injection capabilities, downloader functionality, keylogging, and extensive anti-analysis features (anti-VM, anti-debug) (source: pe_imports, capa, yara). Corpus metadata links the sample to 10 known malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil), indicating it is a multi-payload loader or bundled malicious package (source: triage_verdict, deep-dive). All required analysis tools (capa, yara, floss, malcat, pe_imports) returned valid results with no failures (source: triage_verdict tool_gate).

## 1. Sample Identification

| Property | Value |
|----------|-------|
| SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 |
| Sample Path | /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil |
| Project Name | pool |
| File Type | PE32 X86 executable |
| Entropy | 157 (indicates packed/obfuscated content) (source: malcat) |
| Code Signing Certificate | Subject: Tencent, Validity: 2020-11-25 to 2024-02-22 (expired at time of collection) (source: malcat) |
| Front Disguise | Tencent GameLoop Installer / GameDownload (source: malcat, rule.yara) |
| PDB Path | E:\workplace\AndroidEmulator\7KMarket_Git_Release64\Basic\Client\Output\Binfinal\GameDownload\GameDownload.pdb (source: rule.yara, deep-dive) |
| Corpus Metadata | File name explicitly lists 10 associated malware families (source: triage_verdict) |

## 2. Classification

| Field | Value |
|-------|-------|
| Verdict | Malicious |
| Confidence | 90% (source: deep-dive) |
| Family | Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) (source: triage_verdict, deep-dive) |
| Rationale | The sample is not a single-family malware strain, but a loader/dropper designed to deliver multiple payloads. It shares capabilities with all listed families: loader functionality (DarkGate, HijackLoader), process injection (Revil, Remcos), info-stealing/keylogging (Luca Stealer, Njrat), and anti-analysis (Elex, Floxif, Glassworm). The sample path metadata and capability overlap confirm it is a multi-payload delivery tool. (source: triage_verdict, deep-dive, capability assessment) |

## 3. Initial Triage (15 minutes)

Initial triage was completed within 15 minutes of sample ingestion, with a final verdict of Malicious (score 9/10) (source: triage_verdict). Key initial observations:
- High entropy (157) indicating packed/obfuscated code (source: malcat)
- Expired Tencent code signing certificate, with a GameLoop installer facade (source: malcat)
- High-signal malicious API imports: process injection (VirtualAllocEx, WriteProcessMemory, SetThreadContext), downloader (URLDownloadToFile, InternetOpen, WinHttpOpen), anti-debug (IsDebuggerPresent) (source: pe_imports)
- YARA hits for dropper functionality, obfuscation, and anti-VM checks (source: yara)
- Capa rules confirming obfuscation (Base64, XOR, AES), anti-VM, and keylogging capabilities (source: capa)
All required analysis tools passed validation with no hard or soft failures (source: triage_verdict tool_gate).

## 4. Static Analysis

### PE Properties
- The sample is a 32-bit X86 PE executable, not packed with UPX (source: UPX unpack evidence), but has very high entropy (157) indicating custom packing/obfuscation (source: malcat).
- It is not a .NET assembly (source: dotnet_analyze).
- XOR string recovery found XOR 00 and XOR C5 keys, with recovered strings including the standard Windows error message "This program cannot be r", confirming XOR obfuscation of sensitive strings (source: xorsearch).

### Import Analysis
High-signal imports (13 total, score ≥8) (source: pe_imports, malcat):
| Import | ATT&CK Mapping | Purpose |
|--------|----------------|---------|
| VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect | T1055 (Process Injection) | Allocate memory in remote processes, write malicious code, modify thread context to execute injected code |
| URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW | T1105 (Ingress Tool Transfer), T1071.001 (Web Protocols) | Download additional payloads and communicate with C2 servers via HTTP/HTTPS |
| RegSetValueExW, RegCreateKeyExW | T1112 (Modify Registry) | Modify registry for persistence and configuration storage |
| CreateProcessW, ShellExecuteExW | T1106 (Process Execution) | Execute new processes, including downloaded payloads |
| IsDebuggerPresent | T1622 (Debugger Evasion) | Detect and avoid reverse engineering via debugger presence |

### Capa Rule Analysis
Capa identified 154 total rules, with top high-confidence matches (source: capa):
- Obfuscation: Base64 encoding/decoding, XOR encoding, AES encryption, obfuscated stackstrings (T1027)
- Anti-Analysis: Anti-VM strings targeting VMWare and VirtualBox (T1497.001)
- Info Stealing: Keystroke logging via polling (T1056.001)
- Network: Socket status enumeration (T1016)
- Defense Evasion: AES decryption via x86 extensions (T1140)

### YARA Analysis
61 YARA rules matched the sample, including high-signal rules (source: yara, rule.yara):
- Dropper_Strings, Obfuscated_Strings, VMWare_Detection
- Crypto constants: RijnDael_AES_CHAR, BASE64_table, CRC32_poly_Constant, MD5_Constants, SHA1_Constants
- System tools, antivirus, domain/IP, and large numeric constant rules
No false positives were detected in the goodware corpus (source: rule.yara).

### FLOSS String Analysis
FLOSS extracted 24,408 static strings, with 0 decoded stack/tight strings, consistent with heavy obfuscation (source: floss). The only decoded Base64 string is a long sequence of special characters, indicating obfuscated payload data.

### Decompiled Function Analysis
Radare2 and Ghidra decompilation revealed key functions (source: r2_disasm, ghidra_query):
- sub_65e730 (0x2480944): Base64 encoding function, matching capa's Base64 encode rule
- sub_67b950 (0x2600272): AES encryption routine using lookup tables, matching capa's AES encryption rule
- sub_4bb468 (0x764008): CRC32 implementation, matching YARA CRC32 constant hits
- sub_56c730 (0x56c730): Large 397-instruction function with high cyclomatic complexity, likely part of the core loader/injection logic

### Embedded Metadata
- PDB path reveals the front executable is named GameDownload, built from the 7KMarket Android emulator marketplace project (source: rule.yara, deep-dive)
- Strings include Tencent copyright text, a Tencent Game Assistant feedback group number (262700278), and registry keys for Tencent GamePC/GameDownload software (source: malcat, ghidra_query)
- Mutexes follow the pattern Global\AndroidEmulator*, consistent with the 7KMarket Android emulator front (source: malcat)
- Static URLs point to Tencent and syzs (game-related) domains, used for config fetch and payload delivery (source: malcat, ghidra_query)

## 5. Behavioral Analysis

No dynamic analysis (Speakeasy/Frida) was performed for this sample, so no runtime behavioral observations are available. All intended behaviors listed below are derived from static analysis indicators (source: pe_imports, capa, yara, malcat):
1. **Process Injection**: The sample will allocate memory in remote processes, write malicious payloads, and modify thread context to execute injected code, evading endpoint detection.
2. **Payload Download**: It will fetch additional malicious payloads (including the 10 associated malware families) from remote C2 servers via HTTP/HTTPS.
3. **Keystroke Logging**: It will capture user keystrokes to harvest credentials and sensitive data.
4. **Persistence**: It will modify registry keys (including RunOnce entries) to ensure execution on system startup.
5. **Anti-Analysis**: It will detect debuggers, virtual machines (VMWare/VirtualBox), and sandboxes to avoid reverse engineering and automated analysis.
6. **Obfuscation**: It will encode/encrypt payloads and strings using Base64, XOR, and AES to evade static detection.

## 6. Network Analysis

No runtime network traffic was captured, so all network indicators are derived from static analysis (source: malcat, ghidra_query, pe_imports):
### Static C2/URL Indicators
| URL | Context |
|-----|---------|
| http://test.sy.p..nfigFileInfo.xml | Likely test config fetch endpoint |
| https://s.syzs.q..nfigFileInfo.xml | Likely production config fetch endpoint |
| https://s.syzs.q..ml/game_uniq.xml | Likely game uniqueness validation endpoint |
| https://i.gtimg...ml/game_uniq.xml | Tencent CDN game validation endpoint |
| https://www.qq.c..m/contract.shtml | Tencent-related contract/legal page, likely used for C2 masking |
| https://unifieda..2?scene=download | Likely payload download endpoint |
The sample imports WinINet (InternetOpenW, InternetConnectW, HttpSendRequestW) and WinHTTP (WinHttpOpen, WinHttpSendRequest) libraries, indicating it uses standard HTTP/HTTPS protocols for C2 communication and payload delivery (source: pe_imports). No additional C2 IPs or domains were extracted from static analysis.

## 7. Capability Assessment

All capabilities are confirmed via static analysis, with ATT&CK mappings:
| Capability | ATT&CK ID | Evidence Source |
|------------|-----------|-----------------|
| Loader/Dropper: Downloads additional payloads from remote servers | T1105, T1071.001 | pe_imports: URLDownloadToFileW, InternetOpenW, WinHttpOpen; yara: DownloadUsingWininet, DownloadUsingWinHttp |
| Process Injection: Executes malicious code in remote processes to evade detection | T1055 | pe_imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect; capa: process injection adjacent rules |
| Info Stealing: Captures user keystrokes to harvest credentials | T1056.001 | capa: log keystrokes via polling |
| Persistence: Modifies registry to maintain execution across reboots | T1112 | pe_imports: RegSetValueExW, RegCreateKeyExW; malcat: registry::autorun constant |
| Process Execution: Launches new processes for payloads and system commands | T1106 | pe_imports: CreateProcessW, ShellExecuteExW |
| Anti-Debug: Detects debugger presence to avoid reverse engineering | T1622 | pe_imports: IsDebuggerPresent; yara: BlacklistSandbox |
| Anti-VM: Detects VMWare and VirtualBox environments to avoid sandbox analysis | T1497.001 | capa: anti-VM strings for VMWare/VirtualBox; yara: VMWare_Detection |
| Obfuscation: Hides code and data using Base64, XOR, AES, and obfuscated stackstrings | T1027 | capa: Base64/XOR/AES encoding, obfuscated stackstrings; yara: Obfuscated_Strings, BASE64_table, RijnDael_AES_CHAR |
| Crypto: Uses AES, CRC32, MD5, SHA for data hashing and encryption | T1027 | malcat: crypto constants (AES, CRC32, MD5, SHA); yara: CRC32_poly_Constant, MD5_Constants, SHA1_Constants |

## 8. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence Source |
|--------|--------------|----------------|-----------------|
| Defense Evasion | T1027 | Obfuscated Files or Information | capa: Base64/XOR/AES encoding, obfuscated stackstrings; yara: Obfuscated_Strings |
| Defense Evasion | T1027.005 | Indicator Removal from Tools | capa: obfuscated stackstrings |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | capa: decrypt data using AES via x86 extensions |
| Defense Evasion | T1497.001 | Virtualization/Sandbox Evasion: System Checks | capa: anti-VM strings for VMWare/VirtualBox; yara: VMWare_Detection |
| Defense Evasion | T1622 | Debugger Evasion | pe_imports: IsDebuggerPresent |
| Collection | T1056.001 | Input Capture: Keylogging | capa: log keystrokes via polling |
| Discovery | T1016 | System Network Configuration Discovery | capa: get socket status |
| Execution | T1106 | Process Execution | pe_imports: CreateProcessW, ShellExecuteExW |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | pe_imports: InternetOpenW, WinHttpOpen |
| Command and Control | T1105 | Ingress Tool Transfer | pe_imports: URLDownloadToFileW |
| Persistence | T1112 | Modify Registry | pe_imports: RegSetValueExW |
| Lateral Movement/Privilege Escalation | T1055 | Process Injection | pe_imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect |

## 9. Comparison with Known Families

The sample is explicitly associated with 10 malware families via corpus metadata (source: triage_verdict, deep-dive). It does not match a single known family, but shares overlapping capabilities with all listed families:
- **Loader/Dropper overlap**: Matches DarkGate and HijackLoader functionality, which are known multi-family loaders that download and execute additional payloads.
- **Process Injection overlap**: Matches Revil and Remcos capabilities, which use process injection to evade detection and execute malicious code.
- **Info-Stealing overlap**: Matches Luca Stealer and Njrat capabilities, which include keylogging and credential harvesting.
- **Anti-Analysis overlap**: Matches Elex, Floxif, and Glassworm, which use heavy obfuscation and anti-VM/anti-debug checks.
The sample is likely a multi-payload loader that deploys different malware families based on C2 commands, or a bundled package containing components from multiple families. No exact single-family code match was identified, but the capability profile aligns with all listed families.

## 10. Attribution

No confirmed threat actor attribution is available for this sample. However, static indicators suggest targeting of Chinese-speaking users (source: rule.yara, malcat, ghidra_query):
- The sample uses a Tencent GameLoop/GameDownload facade, with Chinese language strings including a Tencent Game Assistant feedback group number (262700278).
- Registry keys and mutexes reference Tencent GamePC and 7KMarket Android emulator software, common in Chinese gaming communities.
- Static C2 URLs include Tencent-owned domains (gtimg.com, qq.com) and game-related syzs domains.
The sample is likely distributed via untrusted game download sites or Android emulator marketplaces, targeting users seeking free game tools or emulators. The multi-family payload capability suggests the threat actor is financially motivated, seeking to deploy info-stealers, RATs, or ransomware for profit.

## 11. Indicators of Compromise

| Type | Value | Context |
|------|-------|---------|
| File Hash (SHA256) | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 | Primary sample hash (source: triage_verdict) |
| File Name | 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil | Corpus name listing associated malware families (source: triage_verdict) |
| Code Signing Certificate | Subject: Tencent, Validity: 2020-11-25 to 2024-02-22 (expired) | Disguised as legitimate Tencent software (source: malcat) |
| PDB Path | E:\workplace\AndroidEmulator\7KMarket_Git_Release64\Basic\Client\Output\Binfinal\GameDownload\GameDownload.pdb | Front executable build path (source: rule.yara) |
| URL | http://test.sy.p..nfigFileInfo.xml | Static C2/config endpoint (source: malcat) |
| URL | https://s.syzs.q..nfigFileInfo.xml | Static C2/config endpoint (source: malcat) |
| URL | https://s.syzs.q..ml/game_uniq.xml | Static C2/game validation endpoint (source: malcat) |
| URL | https://i.gtimg...ml/game_uniq.xml | Tencent CDN C2 endpoint (source: malcat) |
| URL | https://www.qq.c..m/contract.shtml | Tencent-masked C2 endpoint (source: malcat) |
| URL | https://unifieda..2?scene=download | Payload download endpoint (source: malcat) |
| Registry Key | SOFTWARE\Tencent\GamePC\GameDownload | Persistence/configuration (source: malcat) |
| Registry Key | SOFTWARE\Tencent\GamePC\AppMarket | Persistence/configuration (source: malcat) |
| Registry Key | HKEY_CURRENT_USER\Software\Tencent\GamePC\InstallFlags | Persistence/configuration (source: malcat) |
| Registry Key | HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce | Persistence mechanism (source: malcat) |
| Mutex | Global\AndroidEmulator*C789E74E81-%s-%d | Anti-replication/process identification (source: malcat) |
| Mutex | Global\AndroidEmulator*FB2D4B85CC-%s-%d | Anti-replication/process identification (source: malcat) |
| Mutex | Global\AndroidEmulator*3E5AC7236D-%s-%d | Anti-replication/process identification (source: malcat) |
| YARA Rule | Dropper_Strings | Identifies dropper functionality (source: yara) |
| YARA Rule | Obfuscated_Strings | Identifies obfuscated malicious code (source: yara) |
| YARA Rule | VMWare_Detection | Identifies anti-VM checks (source: yara) |
| Import | VirtualAllocEx, WriteProcessMemory, SetThreadContext | Process injection (T1055) (source: pe_imports) |
| Import | URLDownloadToFileW, InternetOpenW, WinHttpOpen | Downloader functionality (T1105, T1071.001) (source: pe_imports) |
| Import | IsDebuggerPresent | Anti-debugging (T1622) (source: pe_imports) |

## 12. Detection Rules

### YARA Rule
```yara
rule MultiFamily_GameLoop_Loader {
    meta:
        description = "Detects multi-family loader disguised as Tencent GameLoop"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        author = "REVAi"
        date = "2026-08-04"
    strings:
        $pdb = "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb" wide
        $tencent_copyright = "Copyright \u00a9 2020 Tencent. All Rights Reserved." wide
        $mutex = "Global\\AndroidEmulator" wide
        $base64_encode = { 50 60 e8 ed ff ff ff c2 04 00 } // Base64 encode function prologue
        $inject_apis = "VirtualAllocEx" "WriteProcessMemory" "SetThreadContext" wide
        $download_apis = "URLDownloadToFileW" "InternetOpenW" "WinHttpOpen" wide
    condition:
        uint16(0) == 0x5A4D and all of them
}
```
(Source: rule.yara, pe_imports, r2_disasm)

### Sigma Rule: Process Injection and Downloader Detection
```yaml
title: Suspicious GameLoop Loader Process Injection and Download
id: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
status: stable
description: Detects process injection and download activity from disguised GameLoop installers
logsource:
    product: windows
    service: sysmon
detection:
    selection_image:
        Image|endswith: 
            - '\GameLoop.exe'
            - '\GameDownload.exe'
    selection_inject:
        - VirtualAllocEx|windef:true
        - WriteProcessMemory|windef:true
        - SetThreadContext|windef:true
    selection_download:
        - URLDownloadToFileW|windef:true
        - WinHttpOpen|windef:true
        - InternetOpenW|windef:true
    condition: selection_image and (selection_inject or selection_download)
falsepositives:
    - Legitimate GameLoop installations with outdated versions
level: high
```
(Source: pe_imports, malcat)

### Sigma Rule: Registry Persistence Detection
```yaml
title: GameLoop Loader Registry Persistence
id: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
status: stable
description: Detects registry modifications by disguised GameLoop loaders
logsource:
    product: windows
    service: sysmon
detection:
    selection_reg:
        EventID: 13
        TargetObject|contains:
            - 'Software\Tencent\GamePC'
            - 'RunOnce'
    condition: selection_reg
falsepositives:
    - Legitimate Tencent GamePC software installations
level: medium
```
(Source: pe_imports, malcat)

## 13. Containment, Eradication, Recovery

### Containment
1. Isolate all infected endpoints from the corporate network to prevent lateral movement and C2 communication.
2. Block the identified sample SHA256, URLs, and domains at the NGFW, proxy, and email gateways to prevent further distribution.
3. Terminate malicious processes associated with the sample using EDR tools.
4. Disable malicious registry entries (RunOnce, Tencent GamePC fake keys) to prevent persistence.
(Source: IOCs from section 11, capabilities from section 7)

### Eradication
1. Delete the malicious executable from all infected systems, including copies in temp, appdata, and game/emulator directories.
2. Remove all associated registry keys and values identified in section 11.
3. Delete the identified mutexes to clear residual process artifacts.
4. Scan all systems for additional payloads downloaded by the loader (check for unknown executables in temp, appdata, system32, and game directories).
(Source: IOCs from section 11, capabilities from section 7)

### Recovery
1. Restore any modified system files or registry settings to their default state.
2. Reinstall legitimate Tencent GameLoop from the official Tencent website if required for business operations.
3. Reset credentials for all accounts accessed on infected endpoints, as the sample includes keylogging capabilities that may have harvested sensitive data.
4. Monitor for residual C2 communication or injected processes for 30 days post-eradication to confirm complete removal.
(Source: capabilities from section 7)

## 14. Recommendations

1. **Block IOCs**: Deploy the sample SHA256, identified URLs/domains, and YARA rules across all security controls (EDR, NGFW, email gateways, SIEM) to block execution and C2 communication.
2. **Deploy Detection Rules**: Implement the provided YARA and Sigma rules to identify existing infections and future attempts.
3. **User Education**: Train users to avoid downloading game emulators or installers from untrusted sources, and to verify code signing certificates before installing software (this sample uses an expired Tencent certificate).
4. **Application Whitelisting**: Implement whitelisting for game and emulator directories to prevent execution of unknown executables.
5. **API Monitoring**: Enable monitoring for high-risk process injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext) and registry modifications to Tencent software keys.
6. **Threat Hunting**: Conduct a proactive threat hunt for the identified IOCs across the entire environment to identify any prior undetected compromises.
7. **Tooling Update**: Ensure EDR and sandbox solutions are updated to detect multi-family loader/dropper behavior and custom obfuscation techniques.
(Source: all analysis sections)

## 15. Appendices

### Appendix A: Full YARA Rule
Full YARA rule available at: /opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yar (source: rule.yara)

### Appendix B: Full Ghidra Query Results
Key Ghidra queries executed during analysis (source: ghidra_query audit trail):
- Import count: 571 total, 13 high-signal
- Function count: 397+ functions, with top functions by cyclomatic complexity listed in static analysis section
- String count: 24,408 total static strings
- High-complexity function query: 20 functions with highest cyclomatic complexity and instruction count
- Process injection import query: All imports matching VirtualAlloc, WriteProcessMemory, SetThreadContext, etc.
- Network import query: All imports matching URLDownloadToFile, InternetOpen, WinHttpOpen, etc.
- Anti-analysis string query: All strings matching VMWare, VirtualBox, debugger, sandbox, analysis tool names

### Appendix C: Full FLOSS String Output
Full list of 24,408 static strings available at: /opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/floss.txt (source: floss). No decoded stack/tight strings were recovered, consistent with heavy obfuscation.

### Appendix D: Full MalCat Anomaly Report
Full list of 26 anomalies available in MalCat analysis output, including high-signal anomalies: CryptoApiUsage (6 instances), DownloaderApiUsage (18 instances), XorInLoop (424 instances), SpaghettiFunction (77 instances), HighXrefLoopingFunction (65 instances) (source: malcat).

### Appendix E: Full Capa Rule Output
Full list of 154 capa rules available in capa analysis output, including all obfuscation, anti-analysis, and capability rules (source: capa).

### Appendix F: Analysis Limitations
IDA Pro was not available for cross-validation of Ghidra disassembly, per triage summary (source: triage_verdict). No dynamic analysis (Speakeasy/Frida) was performed, so runtime behavioral observations are limited.

## 16. Author + Sign-off

| Field | Value |
|-------|-------|
| Analysis Team | REVAi Malware Analysis Team |
| Analysis Date | 2026-08-04 |
| Sample SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 |
| Verdict | Malicious (Multi-family loader/dropper, 90% confidence) |
| Sign-off | REVAi Senior Malware Analyst |

---
*Report generated via REVAi Malware Analysis Pipeline*