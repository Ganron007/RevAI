> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 18:31:35 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## 1. Executive Summary
This analysis examines the PE file `tasksche.exe` (SHA256: ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda), which is conclusively identified as the WannaCry ransomware (WanaCrypt0r/WCry). The sample is malicious with a confidence score of 100/100, based on converging evidence from multiple static and dynamic analysis engines. Key indicators include the presence of the `WanaCrypt0r` string (source: ghidra, ida), multiple YARA rule matches for WannaCry families (source: yara), capabilities for AES file encryption and Windows service creation (source: capa), and high-signal imports for cryptographic and service APIs (source: pe_imports, malcat). The sample implements a full ransomware attack chain: it encrypts user files using AES via the Microsoft Enhanced RSA and AES Cryptographic Provider, establishes persistence via Windows services, executes shell commands for permission escalation (`icacls`) and file hiding (`attrib`), and references Tor for potential command and control via the `t.wnry` file. No runtime behavior was captured in dynamic analysis, but static artifacts provide clear behavioral intent. We assess this sample with high confidence as a WannaCry propagation component.

## 2. Sample Metadata
The file metadata from Malcat analysis is as follows:

| Field | Value | Source |
|---|---|---|
| SHA256 | ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda | malcat |
| Size | 3514368 bytes (3.35 MB) | malcat |
| Type | PE (Portable Executable) | malcat |
| Architecture | X86 | malcat |
| Entry Point EA | 30650 (0x77BA) | malcat |
| Entropy | 224 (high, indicative of compression or encryption) | malcat |
| File Name | tasksche.exe | malcat |
| Project Name | 710 | system |

The high entropy value of 224 is noted, but this alone is a neutral signal. The file name `tasksche.exe` aligns with known WannaCry component naming (source: deep_dive_agentic).

## 3. File Layout & Structural Analysis
The PE file contains five sections, as reported by Malcat. The `.rsrc` section is notably large and has high entropy, which is a common characteristic of embedded resources in ransomware.

**Section Layout Table (source: malcat)**

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 75 | - |
| .text | 4096 | 28672 | 28672 | 117 | RX |
| .rdata | 32768 | 24576 | 24576 | 153 | R |
| .data | 57344 | 8192 | 8192 | 76 | RW |
| .rsrc | 65536 | 3448832 | 3448832 | 226 | R |

The `.rsrc` section's physical size of ~3.35 MB constitutes over 98% of the file, which aligns with the Malcat anomaly `BigResourceHighEntropy` (source: malcat, anomaly `BigResourceHighEntropy` at EA 65776). This high-entropy resource likely contains encrypted or compressed data, such as the ransomware payload, configuration, or Tor component (`t.wnry`). Additionally, the sample contains carved and virtual files, including a ZIP archive and paths like `XIA/2058/en-us` (source: malcat, carved_files and virtual_files tables).

## 4. Static Code Analysis
Static code analysis reveals cryptographic operations, command execution, and ransomware-specific logic. We present key disassembly and decompilation excerpts to illustrate these behaviors.

**Entry Point Disassembly (source: radare2, EA 0x004077ba)**
The entry point initializes the application, sets up exception handling, and calls the main function. This is standard MSVC runtime startup code, confirming the sample is a compiled C/C++ binary.
```asm
┌ 338: entry0 ();
│           0x004077ba      55             push ebp
│           0x004077bb      8bec           mov ebp, esp
│           0x004077bd      6aff           push 0xffffffffffffffff
│           0x004077bf      6888d44000     push 0x40d488
│           ; ... (SEH setup)
│           0x00407824      e816010000     call 0x40793f  ; Likely CRT init
│           0x00407829      391d70f84000   cmp dword [0x40f870], ebx
│       ┌─< 0x0040782f      750c           jne 0x40783d
```
This indicates the sample uses Microsoft Visual C++ v6.0 runtime (source: yara, rule `Microsoft_Visual_Cpp_v60`).

**Main Function Disassembly (source: radare2, EA 0x00401fe7)**
The main function appears to handle command-line arguments and launch the payload. A critical observation is the call to `GetModuleFileNameA` and a comparison of argument count to 2, followed by a string comparison with `/i` and a call to function `sub_401b5f`. This suggests a conditional launch mechanism, likely for installation or execution mode.
```asm
┌ 391: int main (int argc, char **argv, char **envp);
│           0x0040201f      ff158c804000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA]
│           0x00402025      68acf84000     push 0x40f8ac
│           0x0040202a      e8f6f1ffff     call 0x401225
│           0x00402030      ff156c814000   call dword [sym.imp.MSVCRT.dll___p___argc]
│           0x00402036      833802         cmp dword [eax], 2
│       ┌─< 0x00402039      7553           jne 0x40208e
│       │   0x0040203b      6838f54000     push 0x40f538               ; "/i"
│       │   ; ... (string comparison)
│      ││   0x00402056      53             push ebx
│      ││   0x00402057      e803fbffff     call 0x401b5f  ; Possibly wannacry_launcher
```
The recovered function name for `sub_401b5f` is `wannacry_launcher` (source: recovered_function_names, addr 4202471, confidence 0.85), which is described as the main initialization and payload launcher for WannaCry.

**AES Encryption Implementation (source: malcat, decompilation 11902 — sub_402e7e)**
The decompilation of function `sub_402e7e` shows direct usage of Rijndael S-box constants (`Rijndael_Te0__0xc66363a5U___32_lil_1024`, etc.) and operations characteristic of AES encryption. This function appears to encrypt a 16-byte block, as evidenced by the round key additions and SubBytes/ShiftRows/MixColumns operations. This confirms the embedded AES encryption capability used for file encryption.
```c
void __thiscall sub_402e7e(int32_t param_1, uint32_t *param_2, uint8_t *param_3) {
    // ... initialization
    uStack_14 = (*param_2 << 0x18 | ...) ^ *(param_1 + 8);
    // ... round operations using Rijndael_Te0, Rijndael_Te1, etc.
    uVar5 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^ ...;
    // ... final output to param_3
}
```
This aligns with the capa rule `encrypt data using AES` (source: capa) and the Malcat anomaly `CryptoApiUsage` (source: malcat).

**Decompilation of Command Execution (referenced by deep_dive_agentic)**
The Ghidra string `cmd.exe /c "%s"` is referenced by function `FUN_00401ce8` (source: deep_dive_agentic, Ghidra string_ref), indicating the sample can spawn a command shell to execute arbitrary commands. This is used for running utilities like `icacls` and `attrib`.

## 5. Behavioral & Dynamic Analysis
Dynamic analysis was attempted using Speakeasy and Frida Probe, but no API calls or runtime events were recorded (source: speakeasy, frida_probe). This is expected as WannaCry often requires specific system conditions or user interaction to trigger its payload. The Frida Probe identified hook candidates such as `KERNEL32.dll!CreateFileA`, `ADVAPI32.dll!CreateServiceA`, and `MSVCRT.dll!fopen` (source: frida_probe), but no actual invocations were observed. Therefore, no runtime behavior can be reported; all analysis is based on static artifacts.

## 6. Network Indicators & C2
Network indicators are present in static strings but no active C2 communication was observed in dynamic analysis. The deep-dive summary identifies the file `t.wnry` as a Tor data component for potential C2 (source: deep_dive_agentic, Ghidra string `t.wnry` at 0x411A04). Additionally, the ransom contact email `WNcry@2ol7` and Bitcoin wallet addresses are embedded for ransom payment. However, without runtime triggers, the exact C2 protocol remains latent. We assess that Tor-based C2 is a likely capability based on string references.

## 7. Capabilities Assessment
The sample's capabilities are systematically identified by capa and YARA engines. We list the confirmed capabilities with evidence.

**capa Capability Rules (source: capa, malcat-capa)**

| Rule | ATT&CK | MBC | Evidence Interpretation |
|---|---|---|---|
| encrypt data using AES | T1027:Obfuscated Files or Information | E1027.m05, C0027.001 | Core ransomware behavior for file encryption. |
| create service | T1543.003, T1569.002 | - | Enables persistence via Windows services. |
| persist via Windows service | T1543.003, T1569.002 | - | Confirms service-based persistence mechanism. |
| contain obfuscated stackstrings | T1027.005 | B0032.020, B0032.017 | Indicates string obfuscation, common in malware. |
| get common file path | T1083 | E1083 | Used for file discovery and targeting. |
| query or enumerate registry value | T1012 | C0036.006 | For configuration or persistence via registry. |
| hash data with CRC32 | - | C0032.001 | Used for checksums in file operations. |

**YARA Rule Matches (source: yara, pipeline)**
Key YARA matches confirm WannaCry identity:
- `WannaCry_Ransomware`: Matches 5 strings including `icacls . /grant Everyone:F /T /C /Q` and `tasksche.exe` (source: yara, row_or_rule `WannaCry_Ransomware`).
- `WannaDecryptor`: Matches 7 indicators like `WANACRY!` and `WanaCrypt0r` (source: yara, row_or_rule `WannaDecryptor`).
- `RijnDael_AES`: Confirms embedded AES constants (source: yara, row_or_rule `RijnDael_AES`).
These rules provide strong behavioral intent evidence for ransomware activity.

## 8. Indicators of Compromise
The following IOCs are extracted from static analysis and can be used for detection.

**High-Signal Strings (source: malcat, deep_dive_agentic)**

| EA | String | Interpretation |
|---|---|---|
| 57396 | `WanaCrypt0r` | Ransomware family mutex/identifier. |
| 62508 | `cmd.exe /c "%s"` | Command execution template. |
| 62716 | `icacls . /grant Everyone:F /T /C /Q` | File permission escalation command. |
| 62680 | `tasksche.exe` | Self-referencing filename. |
| 62644 | `Global\MsWinZo ne..cheCounterMutexA` | Global mutex for instance control. |
| 62528 | `115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn` | Bitcoin wallet address 1. |
| 62564 | `12t9YDPgwueZ9NyM..519p7AA8isjr6SMw` | Bitcoin wallet address 2. |
| 62600 | `13AM4VW2dhxYgXeQ..oHkHSQuy6NgaEb94` | Bitcoin wallet address 3. |
| 61580 | `Microsoft Enhanc..graphic Provider` | Cryptographic provider string. |
| 58232-60272 | Various `.docx`, `.xlsx`, `.pdf`, etc. | Targeted file extensions for encryption. |

**Additional Artifacts**
- File `c.wnry`: Configuration file (source: deep_dive_agentic, Ghidra string `c.wnry`).
- File `t.wnry`: Tor data component (source: deep_dive_agentic).
- Import `CreateServiceA` from ADVAPI32.DLL (source: malcat, imports table).

## 9. Detection Engineering
Based on the analysis, detection rules can be crafted using the indicators above. The generated YARA rule from the analysis pipeline is provided in the evidence (source: rule.yara.json). It contains 24 strings, including obfuscated patterns and key identifiers. For example, a simplified detection rule could target:
```yara
rule WannaCry_Ransomware_Indicator {
    strings:
        $s1 = "WanaCrypt0r" ascii wide
        $s2 = "tasksche.exe" ascii wide
        $s3 = "icacls . /grant Everyone:F /T /C /Q" ascii wide
        $s4 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn" ascii wide
        $mutex = "Global\\MsWinZone" ascii wide
    condition:
        uint16(0) == 0x5A4D and 3 of ($s*) or $mutex
}
```
Additionally, sigma rules for file extension monitoring and service creation anomalies should be considered.

## 10. MITRE ATT&CK Mapping
The sample's capabilities map to several MITRE ATT&CK techniques, as derived from capa and PE imports.

**ATT&CK Techniques from capa (source: capa)**

| Technique ID | Name | Evidence from capa rule |
|---|---|---|
| T1027 | Obfuscated Files or Information | `encrypt data using AES`, `contain obfuscated stackstrings` |
| T1083 | File and Directory Discovery | `get common file path`, `check if file exists`, `get file size` |
| T1082 | System Information Discovery | `get hostname` |
| T1012 | Query Registry | `query or enumerate registry value` |
| T1543.003 | Create or Modify System Process: Windows Service | `create service`, `persist via Windows service` |
| T1569.002 | System Services: Service Execution | `create service` |
| T1222 | File and Directory Permissions Modification | `set file attributes` |

**ATT&CK Techniques from PE Imports (source: pe_imports)**

| Label | API Match | ATT&CK Technique |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

These mappings indicate the sample is equipped for execution, persistence, and discovery.

## 11. What We Don't Know
Several aspects remain unknown due to limitations in analysis:
1. **Evasion Techniques**: No specific anti-debugging or obfuscation mechanisms were observed in static analysis beyond string obfuscation. This could be because the sample is unpacked or the techniques are not triggered statically (source: deep_dive_agentic, evasion_anti_analysis noted as not observed).
2. **Exfiltration Capabilities**: No evidence of data exfiltration was found; the sample focuses solely on encryption for ransom (source: deep_dive_agentic, exfiltration noted as not observed).
3. **Defense Impairment**: No explicit defense impairment (e.g., AV disabling) was detected in the static artifacts (source: deep_dive_agentic, defense_impairment noted as not observed).
4. **Dynamic Behavior**: Runtime behavior was not captured, so the exact encryption workflow, C2 communication protocol, and trigger conditions remain unobserved. This is due to the sample not executing in the analysis environment (source: speakeasy, frida_probe).
5. **Embedded Payload Details**: The high-entropy `.rsrc` section likely contains additional code or data, but its exact contents were not extracted or analyzed (source: malcat, BigResourceHighEntropy anomaly).
We assess these unknowns as limitations of the dynamic analysis environment rather than deficiencies in the sample's malicious intent.

## 12. Appendix A: Tool Evidence Trail
The analysis was performed using a multi-engine pipeline with the following evidence trail (selected timestamps from audit trail):
- **agentic_recover_v4**: LLM analysis phase for function recovery (source: agentic_recover_v4, ts 1786299879.3204746).
- **ghidra_query**: SQL queries to Ghidra database for function analysis, cross-references, and string extraction (source: ghidra_query, various sql statements).
- **ida_query**: String extraction from IDA database (source: ida_query, ts 1786300016.3436127).
- **yara_gen_v2**: YARA rule generation (source: yara_gen_v2, ts 1786300016.43092).
- **malcat**: File layout, anomalies, and decompilations.
- **capa**: Capability rule extraction.
- **yara**: Pattern matching.
- **floss**: String extraction (6240 strings total, source: floss).
- **radare2**: Disassembly at entry point and main function.
- **speakeasy** and **frida_probe**: Dynamic analysis attempts (no events recorded).
All tools converged on the malicious verdict without contradictions.

## 13. Appendix B: Analysis Environment
The analysis was conducted in a controlled environment with the following tools and versions (inferred from evidence):
- **Static Analysis**: Ghidra, IDA Pro, Malcat (with capa integration), radare2, FLOSS.
- **Dynamic Analysis**: Speakeasy (for emulation), Frida Probe v17.16.4 (for API hooking).
- **Detection Tools**: YARA (with pipeline matches), capa rules (malcat-capa engine).
- **File Metadata**: PE header analysis via Malcat.
- **Environment Details**: The sample was located at `/opt/samples/corpus/revai-lab-710/...`, suggesting a Linux-based analysis host. No network emulation was configured, which explains the lack of C2 activity. The analysis focused on static indicators due to the sample's inert state in the dynamic environment.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda  
**sample_path:** /opt/samples/corpus/revai-lab-710/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/tasksche.exe  
**project_name:** 710

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 100
- **family_guess**: WannaCry
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both report the 'WanaCrypt0r' string, YARA matches WannaCry ransomware rules, Capa detects AES encryption and service creation, MalCat highlights crypto API usage and high-entropy resources, and PE imports include service and registry APIs. All engines converge on WannaCry ransomware behavior.
- **summary**: The sample is WannaCry ransomware, identified by the 'WanaCrypt0r' string, YARA rule matches, AES encryption capabilities, and service-based persistence. All analyzed tools show consistent malicious behavior.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | Suspicious strings (Ghidra) | `WanaCrypt0r` | String 'WanaCrypt0r' is a direct identifier for WannaCry ransomware, indicating malicious intent. |
| ida | Suspicious strings (IDA) | `WanaCrypt0r` | Confirms the presence of the WannaCry ransomware string, reinforcing the malicious identity. |
| yara | YARA matches | `WannaCry_Ransomware` | YARA rule match for WannaCry ransomware provides strong behavioral evidence. |
| capa | capa evidence | `encrypt data using AES` | Capability to encrypt data using AES is a core ransomware behavior for file encryption. |
| capa | capa evidence | `create service` | Ability to create Windows services for persistence, typical of ransomware installation. |
| pe_imports | pe_imports | `create_service` | High-signal import of CreateService API indicates persistence via Windows services. |
| malcat | MalCat evidence | `CryptoApiUsage` | Anomaly indicating cryptographic API usage, supporting encryption for ransomware. |
| malcat | MalCat evidence | `BigResourceHighEntropy` | High-entropy resource section suggests embedded payload or encrypted data, common in ransomware. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This sample (tasksche.exe) is the WannaCry/WanaCrypt0r/WCry ransomware. It contains the WANACRY! magic marker, WanaCrypt0r mutex, the WNcry@2ol7 ransom contact email, three Bitcoin wallet addresses for ransom payment, AES/CryptEncrypt-based file encryption via Microsoft Enhanced RSA and AES Cryptographic Provider, .wnry file extension handling, icacls permission escalation, attrib file hiding, cmd.exe command execution, and service-based persistence via CreateServiceA/OpenSCManagerA. YARA confirms WannaDecryptor family (7 string matches), Wanna_Sample, and ransom_telefonica rules. The presence of 'c.wnry' and 't.wnry' config/tor data files and 'tasksche.exe' self-name aligns with known WannaCry propagation component behavior. For c2_network, the 't.wnry' file indicates Tor-based command and control communications, citing {analysis, summary, 't.wnry', used for Tor C2 in WannaCry}. For evasion_anti_analysis, no specific evasion techniques were observed in the provided evidence, citing {analysis, summary, none, no anti-debugging or obfuscation mentioned}. For exfiltration, no data exfiltration capabilities were observed, as the malware focuses on file encryption for ransom, citing {analysis, summary, none, no evidence of data theft}. For defense_impairment, no explicit defense impairment mechanisms were observed, citing {analysis, summary, none, no disabling of security tools or services noted}.

### deep key_evidence
- `"Ghidra string 'WANACRY!' at 0x40FC3C (4254588) \u2014 magic marker unique to WannaCry ransomware"`
- `"Ghidra string 'WanaCrypt0r' at 0x40F474 (4251700) \u2014 ransomware mutex/family identifier"`
- `"Ghidra string 'WNcry@2ol7' at 0x411A9C (4257068) \u2014 WannaCry ransom contact email"`
- `"Ghidra string_ref: FUN_00401e9e references Bitcoin address '115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn' \u2014 WannaCry ransom payment wallet"`
- `"Ghidra strings: three Bitcoin addresses (115p7UMM..., 12t9YDPg..., 13AM4VW2...) at consecutive addresses \u2014 multiple ransom payment wallets"`
- `"Ghidra string 'Microsoft Enhanced RSA and AES Cryptographic Provider' referenced by FUN_0040182c \u2014 AES file encryption provider"`
- `"Ghidra string_ref: FUN_00401a45 references CryptGenKey, CryptEncrypt, CryptImportKey, CryptDecrypt \u2014 full ransomware encryption API chain"`
- `"Ghidra string 'cmd.exe /c \"%s\"' referenced by FUN_00401ce8 \u2014 command shell execution for payload delivery"`
- `"Ghidra string 'icacls . /grant Everyone:F /T /C /Q' \u2014 file permission escalation to ensure encryption access"`
- `"Ghidra string 'attrib +h .' \u2014 hiding working directory from user"`
- `"Ghidra string 'c.wnry' referenced by FUN_00401000 and FUN_00401dab \u2014 WannaCry config file"`
- `"Ghidra string 't.wnry' at 0x411A04 \u2014 WannaCry Tor data component"`
- `"Ghidra string 'tasksche.exe' \u2014 self-referencing as WannaCry task scheduler component"`
- `"Ghidra imports: CreateServiceA, OpenSCManagerA, StartServiceA from ADVAPI32.DLL \u2014 service-based persistence mechanism"`
- `"Ghidra imports: RegSetValueExA, RegCreateKeyW \u2014 registry modification for persistence/configuration"`
- `"YARA rule 'WannaDecryptor' matched 7 string indicators including WANACRY!, WanaCrypt0r, tasksche.exe, taskse, taskdl"`
- `"YARA rule 'Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549' matched with taskdl and taskse indicators"`
- `"YARA RijnDael_AES and CRC32_table matches confirm embedded AES S-box and CRC32 constants for encryption"`
- `"Ghidra string '.msg' at 0x40FD34 \u2014 WannaCry multi-language ransom message file extension"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda
size: 3514368
type: PE
architecture: X86
entrypoint_ea: 30650
entropy: 224
file_name: tasksche.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 75 | - |
| .text | 4096 | 28672 | 28672 | 117 | RX |
| .rdata | 32768 | 24576 | 24576 | 153 | R |
| .data | 57344 | 8192 | 8192 | 76 | RW |
| .rsrc | 65536 | 3448832 | 3448832 | 226 | R |

### Malcat YARA / Signatures (8)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| Zlib | library | INFO | 80 | Uses zlib algortihm |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| CreateService | lateral movement | SUSPICIOUS | 70 | creates a service |
| msvc_uv_55 | compiler | INFO | 50 |  |
| msvc_60_07 | compiler | INFO | 50 | Visual Studio 6.0 |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| XorInLoop | 3 | code | 20 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| CryptoApiUsage | 2 | imports | 1 | Crypto-related apis are used |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `65776`: 
- **CryptoApiUsage**
  - `6378`: 
- **DynamicString**
  - `26650`: 
- **GuiSubsystemNoWindowApi**
  - `340`: 
- **NoChecksum**
  - `336`: 
- **SequentialFunction**
  - `11902`: 
  - `12732`: 
- **XorInLoop**
  - `11445`: 
  - `11557`: 
  - `11579`: 
  - `11590`: 
  - `11676`: 

### High-Signal Strings (11 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 62508 | `cmd.exe /c "%s"` |
| 62644 | `Global\MsWinZone..cheCounterMutexA` |
| 60392 | `kernel32.dll` |
| 57396 | `WanaCrypt0r` |
| 61680 | `CryptDestroyKey` |
| 61712 | `CryptAcquireContextA` |
| 61648 | `CryptDecrypt` |
| 61664 | `CryptEncrypt` |
| 61696 | `CryptImportKey` |
| 61636 | `CryptGenKey` |
| 56234 | `KERNEL32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 26650 | `89674523907856340000000000` |
| 62508 | `cmd.exe /c "%s"` |
| 60068 | `.ppt` |
| 59504 | `.rar` |
| 60056 | `.pptx` |
| 60176 | `.xlsx` |
| 58588 | `.sqlitedb` |
| 58568 | `.sqlite3` |
| 59476 | `.backup` |
| 59652 | `.vmdk` |
| 60236 | `.docm` |
| 60260 | `.docx` |
| 60164 | `.xlsm` |
| 59440 | `.jpeg` |
| 59156 | `.avi` |
| 60188 | `.xls` |
| 59168 | `.mov` |
| 59180 | `.mp4` |
| 59404 | `.png` |
| 59428 | `.jpg` |
| 60272 | `.doc` |
| 59544 | `.tar` |
| 59792 | `.pdf` |
| 59840 | `.rtf` |
| 59852 | `.csv` |
| 59048 | `.mp3` |
| 58608 | `.sql` |
| 58232 | `.pem` |
| 58196 | `.crt` |
| 58160 | `.der` |
| 58304 | `.3ds` |
| 58692 | `.myd` |
| 58340 | `.ods` |
| 58424 | `.odp` |
| 58868 | `.ps1` |
| 59492 | `.zip` |
| 59532 | `.tgz` |
| 52796 | ` inflate 1.1.3 C..1998 Mark Adler ` |
| 61580 | `Microsoft Enhanc..graphic Provider` |
| 57376 | `advapi32.dll` |
| 63204 | `oversubscribed d..bit lengths tree` |
| 63276 | `oversubscribed l..eral/length tree` |
| 63244 | `incomplete literal/length tree` |
| 62644 | `Global\MsWinZone..cheCounterMutexA` |
| 63080 | `too many length ..distance symbols` |
| 63168 | `incomplete dynam..bit lengths tree` |
| 63376 | `oversubscribed distance tree` |
| 56364 | `CreateServiceA` |
| 60392 | `kernel32.dll` |
| 62680 | `tasksche.exe` |
| 63312 | `empty distance tree with lengths` |
| 62528 | `115p7UMMngoj1pMv..HijcRdfJNXj6LrLn` |
| 3513008 | `<assembly xmlns=..PADDINGXXPADDING` |
| 62476 | `%s\ProgramData` |
| 63544 | `\..\` |
| 63528 | `/../` |
| 57396 | `WanaCrypt0r` |
| 63440 | `incorrect header check` |
| 63116 | `invalid stored block lengths` |
| 63052 | `invalid bit length repeat` |
| 63348 | `incomplete distance tree` |
| 62564 | `12t9YDPgwueZ9NyM..519p7AA8isjr6SMw` |
| 63484 | `unknown compression method` |
| 62716 | `icacls . /grant ..ryone:F /T /C /Q` |
| 61680 | `CryptDestroyKey` |
| 61712 | `CryptAcquireContextA` |
| 60320 | `DeleteFileW` |
| 63416 | `incorrect data check` |
| 61648 | `CryptDecrypt` |
| 61664 | `CryptEncrypt` |
| 62600 | `13AM4VW2dhxYgXeQ..oHkHSQuy6NgaEb94` |
| 61696 | `CryptImportKey` |
| 63024 | `invalid literal/length code` |
| 57420 | `Software\` |
| 62812 | `GetNativeSystemInfo` |
| 63464 | `invalid window size` |
| 63536 | `\../` |
| 62696 | `TaskStart` |
| 60368 | `WriteFile` |
| 63000 | `invalid distance code` |

### Constants / Known Patterns (19)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| registry | `registry::HKEY_CURRENT_USER` |
| crypto | `crypto::AES` |
| crypto | `crypto::Rijndael_Te0__0xc66363a5U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te1__0xa5c66363U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te2__0x63a5c663U___32_lil_1024` |
| crypto | `crypto::Rijndael_Te3__0x6363a5c6U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td0__0x51f4a750U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td1__0x5051f4a7U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td2__0xa75051f4U___32_lil_1024` |
| crypto | `crypto::Rijndael_Td3__0xf4a75051U___32_lil_1024` |
| crypto | `crypto::Noekeon_Nessie_round__8_byt_17` |
| compress | `compress::unlzx_table_three__32_lil_64` |
| compress | `compress::zinflate_lengthStarts__32_lil_116` |
| compress | `compress::zinflate_lengthExtraBits__32_lil_116` |
| compress | `compress::zinflate_distanceStarts__32_lil_120` |
| compress | `compress::zinflate_distanceExtraBits__32_lil_120` |
| hash | `hash::CRC32` |
| crypto | `crypto::crypto_provider` |

### Imports (119)
| EA | Name | Type | Refs |
|---|---|---|---|
| 30540 | type_info.#0 | DEBUG | 1 |
| 32768 | advapi32.CreateServiceA | IMPORT | 6 |
| 32772 | advapi32.OpenServiceA | IMPORT | 1 |
| 32776 | advapi32.StartServiceA | IMPORT | 2 |
| 32780 | advapi32.CloseServiceHandle | IMPORT | 3 |
| 32784 | advapi32.CryptReleaseContext | IMPORT | 1 |
| 32788 | advapi32.RegCreateKeyW | IMPORT | 1 |
| 32792 | advapi32.RegSetValueExA | IMPORT | 1 |
| 32796 | advapi32.RegQueryValueExA | IMPORT | 1 |
| 32800 | advapi32.RegCloseKey | IMPORT | 1 |
| 32804 | advapi32.OpenSCManagerA | IMPORT | 1 |
| 32812 | kernel32.GetFileAttributesW | IMPORT | 3 |
| 32816 | kernel32.GetFileSizeEx | IMPORT | 1 |
| 32820 | kernel32.CreateFileA | IMPORT | 4 |
| 32824 | kernel32.InitializeCriticalSection | IMPORT | 1 |
| 32828 | kernel32.DeleteCriticalSection | IMPORT | 1 |
| 32832 | kernel32.ReadFile | IMPORT | 2 |
| 32836 | kernel32.GetFileSize | IMPORT | 1 |
| 32840 | kernel32.WriteFile | IMPORT | 1 |
| 32844 | kernel32.LeaveCriticalSection | IMPORT | 2 |
| 32848 | kernel32.EnterCriticalSection | IMPORT | 1 |
| 32852 | kernel32.SetFileAttributesW | IMPORT | 1 |
| 32856 | kernel32.SetCurrentDirectoryW | IMPORT | 1 |
| 32860 | kernel32.CreateDirectoryW | IMPORT | 1 |
| 32864 | kernel32.GetTempPathW | IMPORT | 1 |
| 32868 | kernel32.GetWindowsDirectoryW | IMPORT | 1 |
| 32872 | kernel32.GetFileAttributesA | IMPORT | 4 |
| 32876 | kernel32.SizeofResource | IMPORT | 1 |
| 32880 | kernel32.LockResource | IMPORT | 1 |
| 32884 | kernel32.LoadResource | IMPORT | 1 |
| 32888 | kernel32.MultiByteToWideChar | IMPORT | 1 |
| 32892 | kernel32.Sleep | IMPORT | 1 |
| 32896 | kernel32.OpenMutexA | IMPORT | 1 |
| 32900 | kernel32.GetFullPathNameA | IMPORT | 1 |
| 32904 | kernel32.CopyFileA | IMPORT | 1 |
| 32908 | kernel32.GetModuleFileNameA | IMPORT | 1 |
| 32912 | kernel32.VirtualAlloc | IMPORT | 1 |
| 32916 | kernel32.VirtualFree | IMPORT | 1 |
| 32920 | kernel32.FreeLibrary | IMPORT | 1 |
| 32924 | kernel32.HeapAlloc | IMPORT | 1 |
| 32928 | kernel32.GetProcessHeap | IMPORT | 2 |
| 32932 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 32936 | kernel32.SetLastError | IMPORT | 6 |
| 32940 | kernel32.VirtualProtect | IMPORT | 1 |
| 32944 | kernel32.IsBadReadPtr | IMPORT | 2 |
| 32948 | kernel32.HeapFree | IMPORT | 1 |
| 32952 | kernel32.SystemTimeToFileTime | IMPORT | 1 |
| 32956 | kernel32.LocalFileTimeToFileTime | IMPORT | 1 |
| 32960 | kernel32.CreateDirectoryA | IMPORT | 2 |
| 32964 | kernel32.GetStartupInfoA | IMPORT | 1 |
| 32968 | kernel32.SetFilePointer | IMPORT | 5 |
| 32972 | kernel32.SetFileTime | IMPORT | 1 |
| 32976 | kernel32.GetComputerNameW | IMPORT | 1 |
| 32980 | kernel32.GetCurrentDirectoryA | IMPORT | 2 |
| 32984 | kernel32.SetCurrentDirectoryA | IMPORT | 2 |
| 32988 | kernel32.GlobalAlloc | IMPORT | 3 |
| 32992 | kernel32.LoadLibraryA | IMPORT | 3 |
| 32996 | kernel32.GetProcAddress | IMPORT | 3 |
| 33000 | kernel32.GlobalFree | IMPORT | 2 |
| 33004 | kernel32.CreateProcessA | IMPORT | 1 |
| 33008 | kernel32.CloseHandle | IMPORT | 5 |
| 33012 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 33016 | kernel32.TerminateProcess | IMPORT | 1 |
| 33020 | kernel32.GetExitCodeProcess | IMPORT | 1 |
| 33024 | kernel32.FindResourceA | IMPORT | 1 |
| 33032 | msvcrt.realloc | IMPORT | 2 |
| 33036 | msvcrt.fclose | IMPORT | 1 |
| 33040 | msvcrt.fwrite | IMPORT | 1 |
| 33044 | msvcrt.fread | IMPORT | 1 |
| 33048 | msvcrt.fopen | IMPORT | 1 |
| 33052 | msvcrt.sprintf | IMPORT | 2 |
| 33056 | msvcrt.rand | IMPORT | 2 |
| 33060 | msvcrt.srand | IMPORT | 1 |
| 33064 | msvcrt.strcpy | IMPORT | 1 |
| 33068 | msvcrt.memset | IMPORT | 1 |
| 33072 | msvcrt.strlen | IMPORT | 1 |
| 33076 | msvcrt.wcscat | IMPORT | 1 |
| 33080 | msvcrt.wcslen | IMPORT | 1 |
| 33084 | msvcrt.__CxxFrameHandler | IMPORT | 1 |
| 33088 | msvcrt.operator delete | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 20813 | sub_40514d |
| 11902 | sub_402e7e |
| 12732 | sub_4031bc |
| 21535 | sub_40541f |
| 10870 | sub_402a76 |
| 13583 | sub_40350f |
| 14231 | sub_403797 |
| 20511 | sub_40501f |
| 15612 | sub_403cfc |
| 21813 | sub_405535 |
| 17334 | sub_4043b6 |
| 4349 | sub_4010fd |
| 6188 | sub_40182c |
| 19481 | sub_404c19 |
| 14888 | sub_403a28 |
| 21896 | sub_405588 |
| 21923 | sub_4055a3 |
| 7400 | sub_401ce8 |
| 30650 | EntryPoint |
| 8167 | sub_401fe7 |
| 28982 | sub_407136 |
| 8681 | sub_4021e9 |
| 7595 | sub_401dab |
| 10207 | sub_4027df |
| 7007 | sub_401b5f |
| 7935 | sub_401eff |
| 4096 | sub_401000 |
| 28784 | sub_407070 |
| 4196 | sub_401064 |
| 6393 | sub_4018f9 |

### Decompilations (top 6)
#### 20813 — sub_40514d
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_40514d(int32_t param_1,int32_t param_2,int32_t param_3,int32_t param_4,int32_t param_5,uint8_t **param_6)

{
    uint8_t uVar1;
    uint32_t uVar2;
    uint8_t **ppuVar3;
    int32_t iVar4;
    uint8_t *puVar5;
    uint32_t uVar6;
    int32_t iVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint8_t *puVar12;
    undefined4 uStack_2c;
    uint8_t *puStack_14;
    uint8_t *puStack_10;
    uint8_t *puStack_c;
    uint8_t *puStack_8;
    
    ppuVar3 = param_6;
    puStack_10 = *(param_5 + 0x34);
    uVar9 = *(param_5 + 0x1c);
    puStack_c = *param_6;
    puStack_8 = param_6[1];
    param_6 = *(param_5 + 0x20);
    if (puStack_10 < *(param_5 + 0x30)) {
        puStack_14 = *(param_5 + 0x30) + (-1 - puStack_10);
    }
    else {
        puStack_14 = *(param_5 + 0x2c) - puStack_10;
    }
    uVar8 = *(&unlzx_table_three__32_lil_64 + param_1 * 4);
    uVar2 = *(&unlzx_table_three__32_lil_64 + param_2 * 4);
    do {
        for (; uVar9 < 0x14; uVar9 = uVar9 + 8) {
            puStack_8 = puStack_8 + -1;
            param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
            puStack_c = puStack_c + 1;
        }
        puVar12 = param_3 + (uVar8 & param_6) * 8;
        uVar1 = *puVar12;
code_r0x004051d5:
        uVar6 = uVar1;
        if (uVar6 != 0) {
            param_6 = param_6 >> (puVar12[1] & 0x1f);
            uVar9 = uVar9 - puVar12[1];
            if ((uVar1 & 0x10) != 0) {
                uVar6 = uVar6 & 0xf;
                uVar10 = *(&unlzx_table_three__32_lil_64 + uVar6 * 4) & param_6;
                param_6 = param_6 >> uVar6;
                uVar10 = uVar10 + *(puVar12 + 4);
                for (uVar9 = uVar9 - uVar6; uVar9 < 0xf; uVar9 = uVar9 + 8) {
                    puStack_8 = puStack_8 + -1;
                    param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
                    puStack_c = puStack_c + 1;
                }
                uVar6 = uVar2 & param_6;
                iVar4 = param_4 + uVar6 * 8;
                param_6 = param_6 >> (*(iVar4 + 1) & 0x1f);
                uVar9 = uVar9 - *(iVar4 + 1);
                uVar1 = *(param_4 + uVar6 * 8);
                while ((uVar1 & 0x10) == 0) {
                    if ((uVar1 & 0x40) != 0) {
                        ppuVar3[6] = "invalid distance code";
                        uVar8 = ppuVar3[1] - puStack_8;
                        if (uVar9 >> 3 < ppuVar3[1] - puStack_8) {
                            uVar8 = uVar9 >> 3;
                        }
                        uStack_2c = 0xfffffffd;
                        goto code_r0x004053ed;
                    }
                    iVar7 = (*(&unlzx_table_three__32_lil_64 + uVar1 * 4) & param_6) + *(iVar4 + 4);
                    puVar12 = iVar4 + iVar7 * 8;
                    iVar4 = iVar4 + iVar7 * 8;
                    param_6 = param_6 >> (*(iVar4 + 1) & 0x1f);
                    uVar9 = uVar9 - *(iVar4 + 1);
                    uVar1 = *puVar12;
                }
                uVar6 = uVar1 & 0xf;
                for (; uVar9 < uVar6; uVar9 = uVar9 + 8) {
                    puStack_8 = puStack_8 + -1;
                    param_6 = param_6 | *puStack_c << (uVar9 & 0x1f);
                    puStack_c = puStack_c + 1;
                }
                uVar11 = *(&unlzx_table_three__32_lil_64 + uVar6 * 4) & param_6;
                uVar9 = uVar9 - uVar6;
                param_6 = param_6 >> uVar6;
                puStack_14 = puStack_14 + -uVar10;
                puVar5 = puStack_10 + -(uVar11 + *(iVar4 + 4));
                puVar12 = *(param_5 + 0x28);
                if (puVar5 < puVar12) {
                    do {
                        puVar5 = puVar5 + (*(param_5 + 0x2c) - puVar12);
                    } while (puVar5 < puVar12);
                    uVar6 = *(param_5 + 0x2c) - puVar5;
                    if (uVar6 < uVar10) {
                        param_1 = uVar10 - uVa
```
#### 11902 — sub_402e7e
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_402e7e(int32_t param_1,uint32_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined auStack_2c [12];
    int32_t iStack_20;
    uint32_t uStack_18;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_2c, 0x40d570);
    }
    uStack_14 = (*param_2 << 0x18 | *(param_2 + 1) << 0x10 | *(param_2 + 2) << 8 | *(param_2 + 3)) ^ *(param_1 + 8);
    uStack_10 = (*(param_2 + 4) << 0x18 | *(param_2 + 5) << 0x10 | *(param_2 + 6) << 8 | *(param_2 + 7)) ^
                *(param_1 + 0xc);
    uVar4 = (*(param_2 + 8) << 0x18 | *(param_2 + 9) << 0x10 | *(param_2 + 10) << 8 | *(param_2 + 0xb)) ^
            *(param_1 + 0x10);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(*(param_2 + 0xe), *(param_2 + 0xf)) | *(param_2 + 0xc) << 0x18 | *(param_2 + 0xd) << 0x10) ^
               *(param_1 + 0x14);
    if (1 < iVar1) {
        iStack_8 = iVar1 + -1;
        param_2 = param_1 + 0x30;
        uStack_18 = uVar4;
        do {
            uVar5 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_18 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ param_2[-1];
            uVar4 = *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_c >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_18 >> 0x18) * 4) ^
                    *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_14 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ *param_2;
            uVar3 = *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_c >> 0x18) * 4) ^
                    *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_10 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_14 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_18 & 0xff) * 4) ^ param_2[1];
            uStack_14 = *(&Rijndael_Te2__0x63a5c663U___32_lil_1024 + (uStack_18 >> 8 & 0xff) * 4) ^
                        *(&Rijndael_Te1__0xa5c66363U___32_lil_1024 + (uStack_10 >> 0x10 & 0xff) * 4) ^
                        *(&Rijndael_Te0__0xc66363a5U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
                        *(&Rijndael_Te3__0x6363a5c6U___32_lil_1024 + (uStack_c & 0xff) * 4) ^ param_2[-2];
            iStack_8 = iStack_8 + -1;
            param_1 = iStack_20;
            param_2 = param_2 + 8;
            uStack_18 = uVar4;
            uStack_10 = uVar5;
            uStack_c = uVar3;
        } while (iStack_8 != 0);
    }
    uVar2 = *(iVar1 * 0x20 + 8 + param_1);
    param_1 = iVar1 * 0x20 + 8 + param_1;
    *param_3 = (&AES)[uStack_14 >> 0x18] ^ uVar2 >> 0x18;
    param_3[1] = (&AES)[uStack_10 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[2] = (&AES)[uVar4 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[3] = (&AES)[uStack_c & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 4);
    param_3[4] = (&AES)[uStack_10 >> 0x18] ^ uVar2 >> 0x18;
    param_3[5] = (&AES)[uVar4 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[6] = (&AES)[uStack_c >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[7] = (&AES)[uStack_14 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 8);
    param_3[8] = (&AES)[uVar4 >> 0x18] ^ uVar2 >> 0x18;
    param_3[9] = (&AES)[uStack_c >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[10] = (&AES)[uStack_14 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[0
```
#### 12732 — sub_4031bc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_4031bc(int32_t param_1,uint8_t *param_2,uint8_t *param_3)

{
    int32_t iVar1;
    undefined4 uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t *puVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    undefined auStack_30 [16];
    int32_t iStack_20;
    uint32_t uStack_14;
    uint32_t uStack_10;
    uint32_t uStack_c;
    int32_t iStack_8;
    
    iStack_20 = param_1;
    if (*(param_1 + 4) == '\0') {
        (*msvcrt.exception.exception)(0x40f570);
        jmp_msvcrt._CxxThrowException(auStack_30, 0x40d570);
    }
    uVar4 = (*param_2 << 0x18 | param_2[1] << 0x10 | param_2[2] << 8 | param_2[3]) ^ *(param_1 + 0x1e8);
    uStack_14 = (param_2[4] << 0x18 | param_2[5] << 0x10 | param_2[6] << 8 | param_2[7]) ^ *(param_1 + 0x1ec);
    uStack_10 = (param_2[8] << 0x18 | param_2[9] << 0x10 | param_2[10] << 8 | param_2[0xb]) ^ *(param_1 + 0x1f0);
    iVar1 = *(param_1 + 0x410);
    uStack_c = (CONCAT11(param_2[0xe], param_2[0xf]) | param_2[0xc] << 0x18 | param_2[0xd] << 0x10) ^ *(param_1 + 500);
    if (1 < iVar1) {
        puVar5 = param_1 + 0x210;
        iStack_8 = iVar1 + -1;
        do {
            uVar7 = *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_c >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_14 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uVar4 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_10 & 0xff) * 4) ^ puVar5[-1];
            uVar3 = *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_10 >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_14 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uVar4 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_c & 0xff) * 4) ^ *puVar5;
            uVar6 = *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uStack_c >> 0x18) * 4) ^
                    *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_10 >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_14 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uVar4 & 0xff) * 4) ^ puVar5[1];
            uVar4 = *(&Rijndael_Td1__0x5051f4a7U___32_lil_1024 + (uStack_c >> 0x10 & 0xff) * 4) ^
                    *(&Rijndael_Td2__0xa75051f4U___32_lil_1024 + (uStack_10 >> 8 & 0xff) * 4) ^
                    *(&Rijndael_Td0__0x51f4a750U___32_lil_1024 + (uVar4 >> 0x18) * 4) ^
                    *(&Rijndael_Td3__0xf4a75051U___32_lil_1024 + (uStack_14 & 0xff) * 4) ^ puVar5[-2];
            puVar5 = puVar5 + 8;
            iStack_8 = iStack_8 + -1;
            param_1 = iStack_20;
            uStack_14 = uVar7;
            uStack_10 = uVar3;
            uStack_c = uVar6;
        } while (iStack_8 != 0);
    }
    uVar2 = *(iVar1 * 0x20 + 0x1e8 + param_1);
    param_1 = iVar1 * 0x20 + 0x1e8 + param_1;
    *param_3 = (&AES)[uVar4 >> 0x18] ^ uVar2 >> 0x18;
    param_3[1] = (&AES)[uStack_c >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[2] = (&AES)[uStack_10 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[3] = (&AES)[uStack_14 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 4);
    param_3[4] = (&AES)[uStack_14 >> 0x18] ^ uVar2 >> 0x18;
    param_3[5] = (&AES)[uVar4 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[6] = (&AES)[uStack_c >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[7] = (&AES)[uStack_10 & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 8);
    param_3[8] = (&AES)[uStack_10 >> 0x18] ^ uVar2 >> 0x18;
    param_3[9] = (&AES)[uStack_14 >> 0x10 & 0xff] ^ uVar2 >> 0x10;
    param_3[10] = (&AES)[uVar4 >> 8 & 0xff] ^ uVar2 >> 8;
    iStack_8._0_1_ = uVar2;
    param_3[0xb] = (&AES)[uStack_c & 0xff] ^ iStack_8;
    uVar2 = *(param_1 + 0xc);
    param_3[0xc] = (&AES)[uStack_c >> 0x18] ^ uVar2 >> 0x18;
   
```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | ZIP | 3486039 |

### Virtual Files (3)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| XIA/2058/en-us | 3446325 | - |
| VER/1/en-us | 904 | - |
| MANIF/1/en-us | 1263 | - |

### Structures (32)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 248 |
| OptionalHeader | 272 |
| Sections | 496 |
| advapi32.FT | 32768 |
| kernel32.FT | 32812 |
| msvcrt.FT | 33032 |
| user32.FT | 33232 |
| ImportTable | 54696 |
| advapi32.OFT | 54796 |
| kernel32.OFT | 54840 |
| msvcrt.OFT | 55060 |
| user32.OFT | 55260 |
| ImportNames | 55268 |
| ImportNames | 56504 |
| ImportNames | 57182 |
| Resources | 65536 |
| Resources.XIA | 65576 |
| Resources.VER | 65600 |
| Resources.MANIF | 65624 |
| Resources.XIA.2058 | 65648 |
| Resources.VER.1 | 65672 |
| Resources.MANIF.1 | 65696 |
| Resources.XIA.2058.en-us | 65720 |
| Resources.VER.1.en-us | 65736 |
| Resources.MANIF.1.en-us | 65752 |
| ResourceName | 65768 |
| Resources.XIA.2058.en-us.Data | 65776 |
| VersionInfo | 3512104 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 32 · duration_s: 1.13

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| hash data with CRC32 |  | C0032.001:Checksum |
| reference AES constants | T1027:Obfuscated Files or Information |  |
| generate random numbers using the Delphi LCG |  | C0021:Generate Pseudo-random Sequence |

## PE Imports / Signals
import_count: 114

| label | api_match | ATT&CK |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 28

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3513471 len=7; $ipv6@36485 len=2 |
| contains_base64 | - | $a@55284 len=16 |
| Misc_Suspicious_Strings | - | $a4@62508 len=7 |
| CRC32_poly_Constant | - | $c0@53844 len=4 |
| CRC32_table | - | $c0@53332 len=20 |
| RijnDael_AES | - | $c0@35836 len=8 |
| RijnDael_AES_CHAR | - | $c0@35324 len=32 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@216 len=4 |
| WannaDecryptor | - | $id1@3419457 len=10; $id2@3422954 len=10; $id3@343662 len=6; $id4@344182 len=6; $id5@62708 len=6; $id6@3425549 len=6; $id7@80219 len=6 |
| Wanna_Sample_84c82835a5d21bbcf75a61706d8ab549 | - | $taskdl@3419456 len=7; $taskse@3422953 len=7 |
| ransom_telefonica | - | $a@56326 len=13; $b@62508 len=10; $c@62528 len=34; $d@62564 len=34; $e@62600 len=34; $f@62680 len=12 |
| Wanna_Cry_Ransomware_Generic | - | $s3@61580 len=44 |
| WannaCry_Ransomware | - | $x1@62716 len=35; $x2@3419457 len=10; $x3@62680 len=12; $x4@62644 len=35; $x5@62764 len=10 |
| WannaCry_Ransomware_Dropper | - | $s1@62508 len=15; $s2@62680 len=12; $s3@62716 len=35; $s4@62644 len=35 |
| wannacry_static_ransom | - | $mutex01@62644 len=35; $lang01@80223 len=15; $lang02@332391 len=17; $startarg02@62696 len=9; $wcry01@57396 len=22; $wcry02@60284 len=7 |
| Microsoft_Visual_Cpp_v60 | - | $a@4871 len=1; $b@49813 len=79; $c@6393 len=35 |
| Microsoft_Visual_Cpp_v50v60_MFC_additional | - | $a@5286 len=22 |
| Microsoft_Visual_Cpp_50 | - | $a@5286 len=22 |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@4196 len=4; $b@5286 len=22 |
| Microsoft_Visual_Cpp | - | $b@5286 len=29 |
| SEH_Init | - | $b@5308 len=7 |
| win_registry | - | $f1@56452 len=12; $c1@56288 len=16; $c3@56274 len=11; $c4@56308 len=14; $c6@56274 len=11 |
| win_files_operation | - | $f1@56234 len=12; $c1@55680 len=9; $c2@55510 len=14; $c3@55680 len=9; $c4@55654 len=8; $c6@55588 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@56492 len=10 |

## Generated YARA Meta
```json
{
  "sha256": "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda",
  "family": "WannaCry",
  "imphash": "68f013d7437aa653a8a98a05807afeb1",
  "generated_at": "2026-08-09T18:26:56.430779+00:00",
  "string_count": 24,
  "strings": [
    "oftware\\",
    "!This program cannot be run in DOS mode.",
    "=j&&LZ66lA??~",
    "f\"\"D~**T",
    "V22dN::t",
    "o%%Jr..\\$",
    "&&Lj66lZ??~A",
    "\"\"Df**T~",
    ";22dV::tN",
    "%%Jo..\\r",
    "&Lj&6lZ6?~A?",
    "\"Df\"*T~*",
    "2dV2:tN:",
    "x%Jo%.\\r.",
    "Lj&&lZ66~A??",
    "Df\"\"T~**;",
    "dV22tN::",
    "xxJo%%\\r..8$",
    ",4$8'9-6:.6$1#?*XhHpSeA~NrZlE",
    "QeFbF~TiKwZ",
    "4$8,9-6'.6$:#?*1hHpXeA~SrZlN",
    "SbE\\lHtQeF",
    "F~TbKwZi",
    "$8,4-6'96$:.?*1#HpXhA~SeZlNrSbE"
  ],
  "rule_path": "/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/rule.yar",
  "sigma_path": "/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/rule.yml",
  "iocs_path": "/opt/samples/logs/ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda/iocs.json",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "provenance": {
    "project": "RevAI",
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 18:26:56 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 6240 · per_category: `{"decoded_strings": 0, "stack_strings": 1, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 6239}`

### High-signal FLOSS
- `$$Hl\\`
- `UUPx((`
- `GetProcAddress`

### FLOSS sample
- `oftware\`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `SVWjcf`
- `WWWWWPj`
- `@4+G4t`
- `q89p8t`
- `V,YYG;~`
- `tlHt Ht`
- `~(9~$u`
- `FP;FTt`
- `k|_^][Y`
- `=j&&LZ66lA??~`
- `}{))R>`
- `f""D~**T`
- `V22dN::t`
- `o%%Jr..\$`
- `&&Lj66lZ??~A`
- `99rKJJ`
- `==zGdd`
- `""Df**T~`
- `;22dV::tN`
- `$$Hl\\`
- `C77nYmm`
- `%%Jo..\r`
- `55j_WW`
- `&Lj&6lZ6?~A?`
- `~=zG=d`
- `"Df"*T~*`
- `2dV2:tN:`
- `x%Jo%.\r.`
- `a5j_5W`
- `ggV}++`
- `Lj&&lZ66~A??`
- `bS11*?`
- `Xt,,4.`
- `RRvM;;`
- `MMfU33`
- `PPxD<<%`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004077ba
```asm
┌ 338: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_5ch @ ebp-0x5c
│           ; var int32_t var_60h @ ebp-0x60
│           ; var int32_t var_64h @ ebp-0x64
│           ; var int32_t var_68h @ ebp-0x68
│           ; var int32_t var_6ch @ ebp-0x6c
│           ; var int32_t var_70h @ ebp-0x70
│           ; var int32_t var_74h @ ebp-0x74
│           ; var int32_t var_78h @ ebp-0x78
│           0x004077ba      55             push ebp
│           0x004077bb      8bec           mov ebp, esp
│           0x004077bd      6aff           push 0xffffffffffffffff
│           0x004077bf      6888d44000     push 0x40d488
│           0x004077c4      68f4764000     push 0x4076f4
│           0x004077c9      64a100000000   mov eax, dword fs:[0]
│           0x004077cf      50             push eax
│           0x004077d0      6489250000..   mov dword fs:[0], esp
│           0x004077d7      83ec68         sub esp, 0x68
│           0x004077da      53             push ebx
│           0x004077db      56             push esi
│           0x004077dc      57             push edi
│           0x004077dd      8965e8         mov dword [var_18h], esp
│           0x004077e0      33db           xor ebx, ebx
│           0x004077e2      895dfc         mov dword [var_4h], ebx
│           0x004077e5      6a02           push 2                      ; 2
│           0x004077e7      ff15c4814000   call dword [sym.imp.MSVCRT.dll___set_app_type] ; 0x4081c4 ; "2\xdf"
│           0x004077ed      59             pop ecx
│           0x004077ee      830d4cf940..   or dword [0x40f94c], 0xffffffff ; [0x40f94c:4]=0
│           0x004077f5      830d50f940..   or dword [0x40f950], 0xffffffff ; [0x40f950:4]=0
│           0x004077fc      ff15c0814000   call dword [sym.imp.MSVCRT.dll___p__fmode] ; 0x4081c0 ; "$\xdf"
│           0x00407802      8b0d48f94000   mov ecx, dword [0x40f948]   ; [0x40f948:4]=0
│           0x00407808      8908           mov dword [eax], ecx
│           0x0040780a      ff15bc814000   call dword [sym.imp.MSVCRT.dll___p__commode] ; 0x4081bc
│           0x00407810      8b0d44f94000   mov ecx, dword [0x40f944]   ; [0x40f944:4]=0
│           0x00407816      8908           mov dword [eax], ecx
│           0x00407818      a1b8814000     mov eax, dword [sym.imp.MSVCRT.dll__adjust_fdiv] ; [0x4081b8:4]=0xdf04 reloc.MSVCRT.dll__adjust_fdiv
│           0x0040781d      8b00           mov eax, dword [eax]
│           0x0040781f      a354f94000     mov dword [0x40f954], eax   ; [0x40f954:4]=0
│           0x00407824      e816010000     call 0x40793f
│           0x00407829      391d70f84000   cmp dword [0x40f870], ebx   ; [0x40f870:4]=1
│       ┌─< 0x0040782f      750c           jne 0x40783d
│       │   0x00407831      683c794000     push 0x40793c               ; '<y@' ; "3\xc0\xc3\xc3\
```
### 0x00401fe7
```asm
; CALL XREF from entry0 @ 0x4078e9(x)
┌ 391: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_20bh @ ebp-0x20b
│           ; var int32_t var_20ch @ ebp-0x20c
│           ; var int32_t var_6e4h @ ebp-0x6e4
│           0x00401fe7      55             push ebp
│           0x00401fe8      8bec           mov ebp, esp
│           0x00401fea      81ece4060000   sub esp, 0x6e4
│           0x00401ff0      a010f94000     mov al, byte [0x40f910]     ; [0x40f910:1]=0
│           0x00401ff5      53             push ebx
│           0x00401ff6      56             push esi
│           0x00401ff7      57             push edi
│           0x00401ff8      8885f4fdffff   mov byte [var_20ch], al
│           0x00401ffe      b981000000     mov ecx, 0x81               ; 129
│           0x00402003      33c0           xor eax, eax
│           0x00402005      8dbdf5fdffff   lea edi, [var_20bh]
│           0x0040200b      f3ab           rep stosd dword es:[edi], eax
│           0x0040200d      66ab           stosw word es:[edi], ax
│           0x0040200f      aa             stosb byte es:[edi], al
│           0x00402010      8d85f4fdffff   lea eax, [var_20ch]
│           0x00402016      6808020000     push 0x208                  ; 520
│           0x0040201b      33db           xor ebx, ebx
│           0x0040201d      50             push eax
│           0x0040201e      53             push ebx
│           0x0040201f      ff158c804000   call dword [sym.imp.KERNEL32.dll_GetModuleFileNameA] ; 0x40808c ; DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
│           0x00402025      68acf84000     push 0x40f8ac
│           0x0040202a      e8f6f1ffff     call 0x401225
│           0x0040202f      59             pop ecx
│           0x00402030      ff156c814000   call dword [sym.imp.MSVCRT.dll___p___argc] ; 0x40816c
│           0x00402036      833802         cmp dword [eax], 2
│       ┌─< 0x00402039      7553           jne 0x40208e
│       │   0x0040203b      6838f54000     push 0x40f538               ; "/i"
│       │   0x00402040      ff1568814000   call dword [sym.imp.MSVCRT.dll___p___argv] ; 0x408168
│       │   0x00402046      8b00           mov eax, dword [eax]
│       │   0x00402048      ff7004         push dword [eax + 4]
│       │   0x0040204b      e8f0560000     call 0x407740
│       │   0x00402050      59             pop ecx
│       │   0x00402051      85c0           test eax, eax
│       │   0x00402053      59             pop ecx
│      ┌──< 0x00402054      7538           jne 0x40208e
│      ││   0x00402056      53             push ebx
│      ││   0x00402057      e803fbffff     call 0x401b5f
│      ││   0x0040205c      85c0           test eax, eax
│      ││   0x0040205e      59             pop ecx
│     ┌───< 0x0040205f      742d           je 0x40208e
│     │││   0x00402061      bed8f44000     mov esi, str.tasksche.exe   ; 0x40f4d8 ; "tasksche.exe"
│     │││   0x00402066      53      
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `KERNEL32.dll!GetFileAttributesW`
  - `KERNEL32.dll!GetFileSizeEx`
  - `KERNEL32.dll!CreateFileA`
  - `KERNEL32.dll!InitializeCriticalSection`
  - `KERNEL32.dll!DeleteCriticalSection`
  - `USER32.dll!wsprintfA`
  - `ADVAPI32.dll!CreateServiceA`
  - `ADVAPI32.dll!OpenServiceA`
  - `ADVAPI32.dll!StartServiceA`
  - `ADVAPI32.dll!CloseServiceHandle`
  - `ADVAPI32.dll!CryptReleaseContext`
  - `MSVCRT.dll!realloc`
  - `MSVCRT.dll!fclose`
  - `MSVCRT.dll!fwrite`
  - `MSVCRT.dll!fread`
  - `MSVCRT.dll!fopen`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4220192' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4220130' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4221056' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4220701' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4212000' AND address <= '4228384'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4220192) ASC\n            LIMIT 7\n            ", "ts": 1786299820.4571378}`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4211938' AND address <= '4228322'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4220130) ASC\n            LIMIT 7\n            ", "ts": 1786299820.4598482}`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4212864' AND address <= '4229248'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4221056) ASC\n            LIMIT 7\n            ", "ts": 1786299820.4623642}`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4212509' AND address <= '4228893'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4220701) ASC\n            LIMIT 7\n            ", "ts": 1786299820.4648697}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786299855.0830064}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786299860.397504}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786299879.3204746}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786299926.3543274}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4222016' AND is_stale = '0' LIMIT 1", "ts": 1786299926.6620731}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4222016' AND x.from_ea <= '4223088'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4222016' AND x.from_ea <= '4223088'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4222016' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4222016' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4213824' AND address <= '4230208'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4222016) ASC\n            LIMIT 7\n            ", "ts": 1786299926.757576}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786299972.0494466}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4223088' AND is_stale = '0' LIMIT 1", "ts": 1786299972.3211226}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4223088' AND x.from_ea <= '4223286'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4223088' AND x.from_ea <= '4223286'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4223088' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4223088' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4214896' AND address <= '4231280'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4223088) ASC\n            LIMIT 7\n            ", "ts": 1786299972.3869839}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786300013.7270927}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786300013.733573}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786300013.8110018}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786300016.3436127}`
- `{"source": "yara_gen_v2", "ts": 1786300016.43092}`
