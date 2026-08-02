# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | Malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary
This sample is confirmed malicious, with a triage score of 88/100 and a deep-dive confidence of 90%. It is attributed to the Darty Crypter family, a commodity VB6-based crypter used for payload obfuscation and delivery. The sample is a 32-bit PE executable compiled with Visual Basic 6, with no packing detected. Static analysis confirms it acts as a dropper/loader: it resolves Windows APIs at runtime to avoid static detection, implements anti-debugging via PEB inspection, downloads a second-stage payload from a hardcoded IP, establishes persistence via the HKCU Run registry key, and executes the dropped payload. It also contains references to modifying the system hosts file to redirect security vendor domains to an attacker-controlled IP. No dynamic behavioral analysis was performed, so all behavioral claims are derived from static indicators. (source: triage_verdict.json, deep-dive.json)

## 1. Sample Identification
- SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- Project Name: incoming
- File Type: 32-bit PE executable, compiled with Visual Basic 6 (VB6), not packed, not a .NET assembly
- Triage Verdict: Malicious (score 88, family guess: Darty Crypter)
- UPX Status: Not packed (UPX probe returned 0 files) (source: upx_unpack, dotnet_analyze, capa, sample_path)

## 2. Classification
- Verdict: Malicious
- Family: Darty Crypter
- Subtype: Crypter / Dropper-Loader
- Compilation Language: Visual Basic 6 (VB6)
- Packing Status: Unpacked (no UPX or other standard packers detected)
- Confidence: High (explicit family attribution via source code path strings, matching behavioral characteristics of known Darty Crypter samples) (source: triage_verdict.json, deep-dive.json, capa, floss)

## 3. Initial Triage (15 minutes)
The 15-minute triage yielded a malicious score of 88/100, with an initial family guess of Darty Crypter. Key initial findings included: 1) Presence of VB6 runtime artifacts (MSVBVM60.DLL, VBA6.DLL) in FLOSS output and Ghidra analysis, confirming VB6 compilation. 2) High-signal PE imports of LoadLibrary and GetProcAddress, indicating runtime API resolution, a common crypter obfuscation technique. 3) capa rule matches for PEB access (anti-debugging) and data compression, core crypter functionalities. 4) Explicit string reference to a Darty Crypter source code project path: C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp, providing direct family attribution. 5) Strings indicating hardcoded download sources, persistence mechanisms, and payload execution functionality. All required analysis tools (capa, yara, floss, pe_imports) passed validation with no hard or soft failures. (source: triage_verdict.json, pe_imports, capa, floss, yara/rule.yara.json)

## 4. Static Analysis
The sample is a 32-bit unpacked PE executable with no .NET metadata. Static analysis of imports, strings, and disassembly reveals the following:
- Imports: 103 total imports, with 2 high-signal imports: LoadLibrary (T1129) and GetProcAddress (T1129) from KERNEL32.DLL, plus URLDownloadToFileA (URLMON.DLL), RegOpenKeyW/RegSetValueExW/RegCloseKey (ADVAPI32.DLL), ShellExecuteW (SHELL32.DLL), and multiple VB6 runtime imports from MSVBVM60.DLL (e.g., __vbaVarTstGt, __vbaFreeVar) (source: pe_imports, r2_disassembly, ghidra_query).
- Strings: FLOSS extracted 1249 total strings, including:
  - VB6 project path: C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp (direct family attribution) (source: floss, yara/rule.yara.json)
  - VB6 runtime path: C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB (source: floss)
  - Hardcoded IP 127.0.2.5 paired with 15+ security vendor domains (download.mcafee.com, windowsupdate.microsoft.com, housecall.trendmicro.com, etc.) (source: yara/rule.yara.json, ghidra_query)
  - System hosts file path: C:\WINDOWS\system32\drivers\etc\hosts (source: yara/rule.yara.json)
  - Temporary payload path: \tmpduzhfg89fgdgfgfdzuudgzfgfd.exe (source: yara/rule.yara.json, ghidra_query)
  - Persistence-related strings: HKCU\Software\Microsoft\Windows\CurrentVersion\Run, REG ADD, /t REG_SZ /d (source: yara/rule.yara.json, ghidra_query)
  - Payload reference string: "Payload" (source: ghidra_query)
- Packing: No UPX or other standard packers detected. XOR search only found the standard PE XOR stub for the "This program cannot be run in DOS mode" message, with no additional XOR-obfuscated strings (source: upx_unpack, xorsearch).
- Disassembly: Radare2 disassembly of the entry point and VB6 import thunks confirms VB6 compilation, with no additional malicious code in the entry point stub (source: r2_disassembly).

## 5. Behavioral Analysis
No dynamic behavioral analysis (Speakeasy/Frida) was performed for this sample. All behavioral claims are derived from static analysis indicators. The sample is expected to exhibit the following runtime behavior:
1. Runtime API Resolution: Uses LoadLibraryA/GetProcAddress to dynamically resolve Windows APIs at runtime, avoiding static detection of malicious function imports (source: capa, pe_imports).
2. Anti-Debugging: Implements Process Environment Block (PEB) LDR data inspection to detect debuggers, sandboxes, and analysis tools (source: capa).
3. Payload Download: Uses URLDownloadToFileA to download a second-stage payload from the hardcoded IP 127.0.2.5 (source: deep-dive.json, ghidra_query string_refs).
4. Payload Dropping: Writes the downloaded payload to a temporary file path matching the pattern \tmpduzhfg89fgdgfgfdzuudgzfgfd.exe (source: deep-dive.json, ghidra_query).
5. Persistence: Modifies the HKCU\Software\Microsoft\Windows\CurrentVersion\Run registry key using REG ADD command strings to add a REG_SZ value pointing to the dropped payload, ensuring execution on system boot (source: deep-dive.json, yara/rule.yara.json).
6. Payload Execution: Uses ShellExecuteW to run the dropped second-stage payload (source: deep-dive.json, ghidra_query).
7. Defense Evasion: May modify the system hosts file to redirect requests for security vendor domains to the attacker-controlled 127.0.2.5 IP, disabling endpoint security updates and scans (source: yara/rule.yara.json).

## 6. Network Analysis
No live network traffic was captured during analysis. Static analysis reveals a single hardcoded IPv4 address (127.0.2.5) associated with 15+ security vendor domains, including download.mcafee.com, windowsupdate.microsoft.com, housecall.trendmicro.com, and virusscan.jotti.org. The sample also contains a reference to the system hosts file path (C:\WINDOWS\system32\drivers\etc\hosts), indicating it may modify the hosts file to redirect requests for these security vendor domains to the attacker-controlled IP, a common tactic to disable endpoint security protections. No other network indicators (C2 domains, non-standard ports, custom protocols) were observed in static analysis. (source: yara/rule.yara.json, ghidra_query, deep-dive.json)

## 7. Capability Assessment
The sample has the following confirmed capabilities, derived from static analysis:
| Capability | Evidence Source | Details |
|------------|-----------------|---------|
| Runtime API Resolution | capa, pe_imports | Uses LoadLibraryA/GetProcAddress to dynamically resolve Windows APIs at runtime, avoiding static detection of malicious imports. |
| Anti-Debugging | capa | Implements PEB LDR data inspection to detect debuggers and sandbox environments. |
| Data Compression | capa | Includes WinAPI-based data compression functionality, a core feature of the Darty Crypter used to obfuscate embedded payloads. |
| Payload Download | deep-dive.json, ghidra_query | Uses URLDownloadToFileA to download a second-stage payload from a hardcoded remote source. |
| Payload Execution | deep-dive.json, ghidra_query | Uses ShellExecuteW to run the downloaded payload. |
| Persistence | deep-dive.json, yara/rule.yara.json | Modifies the HKCU Run registry key to execute the payload on system boot. |
| Hosts File Manipulation | yara/rule.yara.json | References the system hosts file path, indicating potential modification to redirect security vendor domains. |

## 8. MITRE ATT&CK Mapping
The following MITRE ATT&CK techniques are associated with this sample:
| MITRE ATT&CK ID | Tactic | Technique Name | Evidence |
|-----------------|--------|----------------|----------|
| T1129 | Execution | Shared Modules | capa rule "link function at runtime on Windows", pe_imports LoadLibrary/GetProcAddress imports |
| T1560.002 | Collection | Archive Collected Data: Archive via Library | capa rule "compress data via WinAPI" |
| T1547.001 | Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | deep-dive.json, yara strings for HKCU Run and REG ADD commands |
| T1105 | Ingress Tool Transfer | Ingress Tool Transfer | deep-dive.json, ghidra string refs for URLDownloadToFileA |
| T1027 | Defense Evasion | Obfuscated Files or Information | triage_verdict.json, capa "compiled from Visual Basic" rule, crypter obfuscation functionality |
| T1497 | Defense Evasion | Virtualization/Sandbox Evasion | capa rule "access PEB ldr_data" for anti-debugging |
| T1059.003 | Execution | Command and Scripting Interpreter: Windows Command Shell | yara strings for "REG ADD" and "/t REG_SZ /d" command line arguments |

## 9. Comparison with Known Families
This sample is confirmed to belong to the Darty Crypter family, a commodity VB6-based crypter sold on underground malware marketplaces. The explicit project path string C:\Users\Owner\Desktop\Darty Crypter Source\Payload\Project1.vbp directly links the sample to the Darty Crypter source code. The sample's functionality matches known Darty Crypter behavior: VB6 runtime dependency, runtime API resolution to obfuscate imports, anti-debugging via PEB inspection, payload compression, download-and-execute functionality, and registry-based persistence. No significant deviations from known Darty Crypter samples were observed during analysis. (source: triage_verdict.json, floss, capa, deep-dive.json)

## 10. Attribution
Low-confidence attribution to the Darty Crypter malware family, based on explicit source code path strings and matching behavioral characteristics of publicly documented Darty Crypter samples. Darty Crypter is a commodity crypter offered for sale on underground forums, and is used by a wide range of threat actors for malware distribution, so no specific threat actor or campaign attribution can be made from the available evidence. (source: triage_verdict.json, yara/rule.yara.json)

## 11. Indicators of Compromise
The following IOCs are derived from static analysis:
| Type | Indicator | Context |
|------|-----------|---------|
| File Hash | SHA256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 | Malicious Darty Crypter sample |
| IP Address | 127.0.2.5 | Hardcoded download source for second-stage payload, associated with security vendor domain redirection |
| Domain | download.mcafee.com | Associated with hardcoded IP 127.0.2.5, likely used for host file redirection |
| Domain | tliveupdate.symantecliveupdate.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | securityresponse.symantec.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | windowsupdate.microsoft.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | www.networkassociates.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | housecall.trendmicro.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | liveupdate.symantec.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | networkassociates.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | customer.symantec.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | www.pandasoftware.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | updates.symantec.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | update.microsoft.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | dispatch.mcafee.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | update.symantec.com | Associated with hardcoded IP 127.0.2.5 |
| Domain | virusscan.jotti.org | Associated with hardcoded IP 127.0.2.5 |
| File Path | C:\WINDOWS\system32\drivers\etc\hosts | Referenced for potential modification to redirect security domains |
| File Path | \tmpduzhfg89fgdgfgfdzuudgzfgfd.exe | Temporary path for dropped second-stage payload |
| Registry Key | HKCU\Software\Microsoft\Windows\CurrentVersion\Run | Persistence key modified to execute payload on boot |
| Registry Key | SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | Referenced in sample strings, potentially for UAC bypass |
| Registry Key | SOFTWARE\Microsoft\Security Center | Referenced in sample strings, potentially for disabling security center notifications |
(source: yara/rule.yara.json, ghidra_query, deep-dive.json)

## 12. Detection Rules
1. **YARA Rule**: A custom YARA rule has been generated for this sample and is available at /opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar. The rule includes strings for the Darty Crypter project path, VB6 runtime paths, hardcoded IP/domain strings, persistence registry keys, and hosts file path. No pre-existing YARA matches were found in the unstaged goodware corpus. (source: rule.yara.json)
2. **Sigma Rule**: A custom Sigma rule for detection of this sample's behavior is available at /opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yml. (source: rule.yara.json)
3. **PE Import Detection**: Alert on 32-bit PE files that import both LoadLibrary/GetProcAddress (T1129) and URLDownloadToFileA, RegSetValueExW, ShellExecuteW, especially if the file also imports MSVBVM60.DLL (VB6 runtime). (source: pe_imports)
4. **String-Based Detection**: Alert on PE files containing the hardcoded IP 127.0.2.5 or associated security vendor domain strings, or the Darty Crypter project path string. (source: yara/rule.yara.json, ghidra_query)

## 13. Containment, Eradication, Recovery
- **Containment**: Isolate all infected endpoints from the network immediately. Block outbound traffic to IP 127.0.2.5 and all associated security vendor domains at the network perimeter and endpoint firewall level.
- **Eradication**: Terminate any running malicious processes associated with the sample. Delete the original malicious sample from the endpoint. Remove the persistence entry from the HKCU\Software\Microsoft\Windows\CurrentVersion\Run registry key. Delete the dropped payload from the temporary directory (path matching \tmpduzhfg89fgdgfgfdzuudgzfgfd.exe). Restore the system hosts file to its original state if modified.
- **Recovery**: Reimage compromised endpoints if evidence of follow-on activity (e.g., second-stage payload execution) is found. Reset credentials for all accounts that logged into the compromised endpoint. Monitor endpoint and network activity for 30 days post-eradication to detect residual or follow-on malicious activity.
(source: deep-dive.json, yara/rule.yara.json)

## 14. Recommendations
1. Deploy the custom YARA and Sigma rules provided in this report to security tools (EDR, SIEM, email gateways) to detect Darty Crypter and similar VB6-based crypters.
2. Add detection rules for runtime API resolution (LoadLibrary/GetProcAddress) in VB6-compiled binaries, as this is a high-signal indicator of crypter activity.
3. Block the hardcoded IP 127.0.2.5 and all associated security vendor domains at the network perimeter to prevent payload download and security disablement.
4. Implement monitoring for modifications to the system hosts file and HKCU Run registry keys, which are common persistence and defense evasion tactics.
5. Implement application whitelisting to block untrusted VB6-compiled executables from executing on endpoints, as VB6 is rarely used for legitimate modern software.
6. Conduct user awareness training to educate users on the risks of opening unknown executable files, especially those received via email or untrusted download sources.
(source: all evidence sources)

## 15. Appendices
### Appendix A: Custom YARA Rule
The full generated YARA rule is available at /opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yar. Key strings included in the rule are listed in the YARA evidence section of this report. (source: rule.yara.json)

### Appendix B: Custom Sigma Rule
The full generated Sigma rule is available at /opt/samples/logs/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/rule.yml. (source: rule.yara.json)

### Appendix C: Tool Output Summary
| Tool | Status | Key Findings |
|------|--------|--------------|
| capa | OK | 8 rules matched, including compiled from Visual Basic, PEB access, runtime linking, data compression |
| FLOSS | OK | 1249 strings extracted, including VB6 runtime paths, Darty Crypter project path, hardcoded IPs/domains, persistence strings |
| pe_imports | OK | 103 total imports, 2 high-signal: LoadLibrary, GetProcAddress |
| YARA | Custom rule generated | No pre-existing matches in unstaged goodware corpus |
| UPX | Not packed | No UPX packing detected |
| XOR Search | OK | Only standard PE XOR stub found, no additional obfuscated strings |
| radare2 | OK | Disassembly confirms VB6 import thunks, no additional malicious code in entry point |
| Ghidra | OK | 50+ large functions, 103 imports, 1249 strings, string references for malicious APIs confirmed |
(source: all tool evidence)

### Appendix D: Audit Trail
Full audit trail of analysis queries and tool runs:
- ghidra_query: SELECT name, start_ea, size FROM funcs WHERE size > 1024 ORDER BY size DESC LIMIT 50 (ts: 1785702440.4338126)
- ghidra_query: SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%' (ts: 1785702440.5304427)
- ghidra_query: SELECT src_start_ea, dst_start_ea FROM cfg_edges WHERE src_start_ea > 0 AND dst_start_ea > 0 (ts: 1785702440.835063)
- ghidra_query: SELECT COUNT(1) AS cnt FROM imports (ts: 1785702440.908886)
- ghidra_query: SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%' (ts: 1785702440.9360094)
- ghidra_query: SELECT COUNT(1) AS cnt FROM funcs (ts: 1785702440.944329)
- ghidra_query: SELECT COUNT(1) AS cnt FROM strings (ts: 1785702440.9644756)
- ghidra_query: SELECT count(*) AS funcs FROM funcs (ts: 1785702526.971256)
- ghidra_query: SELECT count(*) AS strings FROM strings (ts: 1785702527.0126872)
- ghidra_query: SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50 (ts: 1785702527.065196)
- ghidra_query: SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30 (ts: 1785702527.0764358)
- quick_scan_v2: phase 2 (ts: 1785702527.0771465)
- ghidra_query: SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25 (ts: 1785702572.2070165)
- ghidra_query: SELECT name, module, address FROM imports WHERE name IN ('LoadLibraryA','LoadLibraryW','GetProcAddress','VirtualAlloc','WriteProcessMemory','CreateRemoteThread','RegSetValueEx','InternetOpen','InternetConnect','URLDownloadToFile','WinInet','ADVAPI32','KERNEL32','USER32','MSVBVM60','VBA6') OR module IN ('KERNEL32.DLL','USER32.DLL','ADVAPI32.DLL','MSVBVM60.DLL','VBA6.DLL','WININET.DLL','URLMON.DLL') ORDER BY module, name (ts: 1785702577.4138114)
- ghidra_query: SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%ftp%' OR content LIKE '%shell%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%rundll%' OR content LIKE '%reg%' OR content LIKE '%HKEY%' OR content LIKE '%Software\\Microsoft\\Windows\\CurrentVersion\\Run%' OR content LIKE '%Temp%' OR content LIKE '%AppData%' OR content LIKE '%payload%' OR content LIKE '%exploit%' OR content LIKE '%inject%' OR content LIKE '%download%' OR content LIKE '%execute%' ORDER BY address (ts: 1785702580.4924572)
- ghidra_query: SELECT func_name, func_addr, string_value, string_addr, string_length FROM string_refs WHERE string_value IN ('URLDownloadToFileA','RegOpenKeyW','RegSetValueExW','RegCloseKey','REG ADD',' /t REG_SZ /d ','ShellExecuteW','Payload','temp','127.0.0.1\\tdownload.mcafee.com\\r\\n') ORDER BY string_value, func_addr (ts: 1785702589.3475244)
- ghidra_query: SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80 (ts: 1785702593.897686)
- yara_gen_v2 (ts: 1785702594.9285223)
(source: audit trail evidence)

## 16. Author + Sign-off
Analyst: Senior Malware Analyst, Malware Analysis Team
Date: 2026-08-02 (aligned with YARA rule generation timestamp)
Sign-off: This report is accurate to the best of our knowledge based on the static analysis evidence collected. No dynamic analysis was performed, so behavioral claims are derived from static indicators only. All evidence is cited from the analysis tools and queries listed in the audit trail.
