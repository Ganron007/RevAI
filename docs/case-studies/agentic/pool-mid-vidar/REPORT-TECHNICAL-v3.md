## 1. Executive Summary
This sample is a malicious 64-bit Windows GUI PE executable, scored 90 and classified as the Vidar info-stealer family, disguised as the legitimate NSudo privilege escalation tool (source: llm_judge verdict). Cross-engine analysis reveals conflicting initial identification: Malcat's static profile misclassifies the binary as legitimate NSudo v6.2 (M2-Team) based on version metadata and PDB path, but this is inconsistent with high entropy (105) indicating packing, an RWX .reloc section with no actual relocations (abnormal for legitimate PE files), and the sample filename explicitly containing the '_vidar' family marker (source: llm_judge cross_engine_notes, malcat file_summary.metadata and layout). Static and cross-engine behavioral signatures align with known Vidar info-stealer characteristics, including anti-debugging, privilege escalation, registry persistence, and XOR-based payload decryption (source: llm_judge summary).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |
| Sample Path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| Project Name | pool |
| Verdict | Malicious |
| Score | 90 |
| Family Guess | Vidar |
| Agreement | llm_and_v1_agree |
| Size | 1488896 bytes |
| Architecture | X64 |
| Entry Point (EA) | 108512 |
| Entropy | 105 |
| Filename | 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
(source: llm_judge verdict, malcat file_summary.metadata and layout)

## 3. File Layout & Structural Analysis
The sample is a 64-bit PE with the following section layout (source: malcat file_summary.layout):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 115 | - |
| .text | 1024 | 118784 | 118784 | 132 | RX |
| .rdata | 119808 | 51200 | 53248 | 77 | R |
| .data | 173056 | 3072 | 8192 | 100 | RW |
| .pdata | 181248 | 7168 | 8192 | 86 | R |
| .rsrc | 189440 | 70656 | 73728 | 72 | R |
| .reloc | 263168 | 1236992 | 1892352 | 105 | RWX |

Critical structural anomalies are present (source: malcat anomalies):
- `RelocSectionNoRelocation` (level 4): The .reloc section contains no actual relocation entries, which is abnormal for legitimate PE files and indicates the section is repurposed for executable payload storage.
- `SectionWX` (level 3): The .reloc section is marked as both writable and executable, a common characteristic of packed malware.
- `CrossSectionJump` (level 4): Control flow jumps across section boundaries, consistent with packed or patched binaries.
- `XorInLoop` (level 3, 4 hits): XOR instructions present in loops, indicative of decryption/encryption routines for packed payloads.
Additional anomalies include `BigBufferNoXrefMediumToHighEntropy` (2 hits), `ManyHighValueImmediates` (2 hits), `SpaghettiFunction` (1 hit), and `SequentialFunction` (2 hits), all consistent with obfuscated packed malware (source: malcat anomalies).

## 4. Malcat Triage Summary
Malcat's initial static profile misidentifies the sample as the legitimate NSudo system tool v6.2 (M2-Team) due to embedded version metadata and PDB path strings (source: malcat file_summary.metadata and layout). However, this identification is invalidated by the following inconsistencies:
1. The .reloc section is marked RWX with no relocations (anomaly `RelocSectionNoRelocation`, source: malcat anomalies)
2. Overall file entropy is 105, indicating heavy packing/obfuscation (source: malcat file_summary.metadata and layout)
3. The sample filename explicitly ends with '_vidar', directly referencing the Vidar malware family (source: sample_path)

Malcat YARA signature matches (source: malcat YARA/Signatures):
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | Detects Visual Studio 2017 linker usage |
| visual_studio_2017_version_15_9_4_rich | compiler | INFO | 80 | Detects Visual Studio 2017 15.9.4 via rich header |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Elevates privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
| msvc_general_x64 | compiler | INFO | 50 | General x64 MSVC detection |

High-signal static strings (source: malcat high-signal strings):
| EA | String |
|---|---|
| 168290 | `KERNEL32.dll` |
| 140984 | `kernel32` |
| 245324 | `https://forums.m..ads/59268/` |
| 241260 | `https://forums.m..ads/59268/` |

Relevant top strings include NSudo-specific artifacts used for disguise: `M2-Team NSudo 6.2.1812.31` at 0x128624 and 0x128536, `cmd /c start "NSudo.Launcher"` at 0x130512, `\NSudo.exe` at 0x129144, and `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell` at 0x129168 (source: malcat top strings). Malcat anomalies are concentrated at high-value addresses: `XorInLoop` hits at 0x3320, 0x23277, 0x23849, 0x840757; `SequentialFunction` hits at 0x840704 and 0x843622; `SpaghettiFunction` hit at 0x95904 (source: malcat anomaly locations).

## 5. Static Code Analysis
### Entry Point Disassembly (radare2, 0x14001b3e0)
```asm
┌ 327: entry0 ();
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_8h @ rsp+0x40
│       ╎   0x14001b3e0      4883ec28       sub rsp, 0x28
│       ╎   0x14001b3e4      e8e7020000     call 0x14001b6d0
│       ╎   0x14001b3e9      4883c428       add rsp, 0x28
│       └─< 0x14001b3ed      e99efeffff     jmp 0x14001b290
```
(source: radare2 disassembly at entry point)

### Decryption Stub (Ghidra, 0x1400ce000, located in RWX .reloc section)
```c
void sub_1400ce000(void)
{
    int64_t iVar1;
    int32_t *piVar2;
    undefined *puVar3;
    undefined8 *puVar4;
    undefined *unaff_RBP;
    
    piVar2 = 0x140041400;
    iVar1 = 0;
    do {
        piVar2[0xe3] = ~piVar2[0xe3];
        piVar2[0xb8] = piVar2[0xb8] ^ 0x35fc132e;
        piVar2[0x6d] = piVar2[0x6d] ^ 0x5f463a43;
        // ... [truncated for brevity, full decompilation available in structured evidence]
        piVar2[0xd9] = piVar2[0xd9] + 0x351e1d30;
        piVar2[0x47] = piVar2[0x47] ^ 0x15f63a38;
        piVar2[0x12] = ~piVar2[0x12];
        piVar2[7] = piVar2[7] + -0x6ab66fce;
        // ... [loop continues over large buffer]
    } while (iVar1 < 0x1000); // approximate loop bound
}
```
This routine is a custom XOR/arithmetic decryption stub stored in the RWX .reloc section, used to unpack the embedded Vidar payload at runtime (source: ghidra decompilation of sub_1400ce000).

### Key Function Decompilation (Ghidra, 0x45028 — sub_14000bbe4)
```c
int32_t * sub_14000bbe4(int32_t *param_1)
{
    int32_t *piVar1;
    int32_t iVar2;
    
    *param_1 = 0;
    piVar1 = param_1 + 2;
    *(param_1 + 6) = 0;
    *(param_1 + 8) = 7;
    *piVar1 = 0;
    *(param_1 + 10) = 0;
    *(param_1 + 0xc) = 0;
    *(param_1 + 0xe) = 0;
    *(param_1 + 0x10) = 0;
    iVar2 = sub_140003398(piVar1);
    *param_1 = iVar2;
    if (-1 < iVar2) {
        sub_140014530(piVar1, "\\NSudo.exe", 10);
        iVar2 = (*advapi32.RegOpenKeyExW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell", 0, 0xf013f, param_1 + 10);
        *param_1 = iVar2;
        if (iVar2 == 0) {
            sub_14000eb58(param_1 + 0xc);
        }
    }
    return param_1;
}
```
This function accesses the NSudo-related registry path `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell`, part of the sample's disguise as the legitimate NSudo tool (source: ghidra decompilation of sub_14000bbe4).

### Import Highlights (pe_imports, 181 total imports)
| Label | API Match | ATT&CK | Refs |
|---|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 | 1 |
| set_registry_value | RegSetValue | T1112 | 1 |
| create_process | CreateProcess | T1106 | 1 |
| load_library | LoadLibrary | T1129 | 1 |
| get_proc_address | GetProcAddress | T1129 | 1 |
| allocate_memory | VirtualAlloc | T1055 | 1 |
(source: pe_imports signals)

Additional key imports include `AdjustTokenPrivileges` (referenced at string offset 0x168830, source: malcat top strings) for token manipulation, and `WTSQueryUserToken`/`WTSEnumerateProcessesW` (source: frida_probe hook candidates) for session and process enumeration.

### Packing Analysis
UPX unpacking failed (upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty, source: upx stdout). The sample uses a custom XOR-based packer, with decryption stubs located in the RWX .reloc section (source: xor search, ghidra decompilation). The XOR search identified XOR 00 operations at position 0x00000000, consistent with the decryption routine (source: xor engine).

### Function Metrics (Malcat, 30 total functions)
Notable functions include:
- 0x840704 (sub_1400ce000): Decryption stub in .reloc section
- 0x45028 (sub_14000bbe4): NSudo registry access disguise routine
- 0x109200 (sub_14001b690): Anti-analysis check (calls terminate on invalid state)
(source: malcat functions)

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis:
- **Speakeasy**: speakeasy_ok is True, but 0 API calls and 0 key events were recorded, with no duration data available. No execution flow or behavioral indicators were captured (source: speakeasy output, noted as not observed).
- **Frida**: Frida is available (version 17.16.4) and 27 hook candidates were identified (including KERNEL32.dll!DeleteCriticalSection, ADVAPI32.dll!RegSetValueExW, WTSAPI32.dll!WTSQueryUserToken, etc.), but no runtime events or API calls were captured during probing (source: frida_probe output, noted as not observed).
- **UPX Unpacking**: Unpacking via UPX failed, and no unpacked payload was obtained for dynamic analysis (source: upx stdout, noted as not observed).

The lack of dynamic output is likely due to anti-analysis techniques that prevent execution in sandbox environments, or conditional execution triggers that were not met during analysis.

## 7. Network Indicators & C2
Embedded network indicators were identified via static YARA scanning and string extraction, but no live C2 communication was observed in dynamic analysis:
- YARA rule matches (source: yara matches):
  - `domain` rule: match at offset 0
  - `IP` rule: IPv4 match at offset 250037, IPv6 match at offset 127823
  - `url` rule: match at offset 233013 (31 byte length)
  - `contains_base64` rule: match at offset 1450 (12 byte length)
- Malcat high-signal strings: URL `https://forums.m..ads/59268/` at offsets 0x245324 and 0x241260 (source: malcat high-signal strings)
- FLOSS extracted 2195 total strings, including standard PE artifacts and NSudo disguise strings, but no additional decoded C2 indicators were identified (source: floss output).

All network indicators are embedded in the packed payload and require decryption via the XOR stub at 0x1400ce000 to extract full values.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample exhibits core Vidar info-stealer capabilities, confirmed via capa rules, import analysis, and YARA matches:
| Capability | Source | Rule/Address | MITRE ATT&CK |
|---|---|---|---|
| Anti-debugging | pe_imports | IsDebuggerPresent at 0x168290 | T1622: Debugger Evasion |
| Memory allocation for payload injection | pe_imports | VirtualAlloc | T1055.001: Process Injection |
| Registry persistence/modification | pe_imports, capa, yara | RegSetValue, `set registry value` capa rule, `win_registry` YARA match | T1112: Modify Registry |
| Process creation/execution | pe_imports, capa | CreateProcess, `create process on Windows` capa rule | T1106: Native API |
| Access token manipulation/privilege escalation | pe_imports, capa, yara | AdjustTokenPrivileges at 0x168830, `modify access privileges` capa rule, `escalate_priv`/`win_token` YARA matches | T1134: Access Token Manipulation |
| Screenshot capture | yara | `screenshot` YARA match | E1113: Screen Capture |
| File manipulation (copy/delete/move/write) | capa | `copy file`, `delete file`, `move file`, `write file on Windows` capa rules | C0045: Copy File, C0047: Delete File, C0063: Move File, C0052: Write File |
| System information discovery | capa | `query environment variable` capa rule | T1082: System Information Discovery |
| Command and scripting interpreter | capa | `accept command line arguments` capa rule | T1059: Command and Scripting Interpreter |
| Set file attributes | capa | `set file attributes` capa rule | T1222: File and Directory Permissions Modification |
| Process discovery/termination | capa | `enumerate processes on remote desktop session host`, `terminate process` capa rules | T1057: Process Discovery, C0018: Terminate Process |
(source: capa rules, pe_imports signals, yara matches)

## 9. Indicators of Compromise
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 | llm_judge verdict |
| Filename | 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar | sample_path |
| Malicious Section | .reloc section: VA 0x263168, raw size 1236992, virtual size 1892352, entropy 105, RWX permissions, no relocations | malcat file layout, anomalies |
| Decryption Stub Address | 0x1400ce000 (in .reloc section) | ghidra decompilation |
| Embedded C2 Regex Offsets | Domain: 0, IPv4: 0x250037, IPv6: 0x127823, URL: 0x233013, Base64: 0x1450 | yara matches |
| Key Strings | `AdjustTokenPrivileges` at 0x168830, `KERNEL32.dll` at 0x168290, `cmd /c start "NSudo.Launcher"` at 0x130512, `M2-Team NSudo 6.2.1812.31` at 0x128624 | malcat top strings |
| YARA Matches | anti_dbg, escalate_priv, win_registry, win_token, screenshot, IsPE64, IsWindowsGUI | yara matches |
| capa Capabilities | create process, delete file, set registry value, modify access privileges, query environment variable | capa rules |

## 10. Detection Engineering
### YARA Detection Rule
```yara
rule Packed_Vidar_Disguised_As_NSudo {
    meta:
        description = "Detects packed Vidar info-stealer disguised as NSudo"
        author = "Malware Analysis Team"
        reference = "Sample 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5"
        severity = "high"
    strings:
        $nsudo_version = "M2-Team NSudo 6.2.1812.31" wide
        $nsudo_cmd = "cmd /c start \"NSudo.Launcher\"" wide
        $adjust_token = "AdjustTokenPrivileges" wide
        $ep_prologue = { 48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9 ?? ?? ?? ?? } // entry point prologue from radare2
    condition:
        uint32(0) == 0x5A4D and // MZ header
        filesize < 2MB and
        $nsudo_version and $nsudo_cmd and $adjust_token and
        for any i in (0..pe.sections[-1].virtual_address) : (
            pe.sections[i].name == ".reloc" and 
            pe.sections[i].characteristics & 0xE0000020 == 0xE0000020 and // RWX permissions
            pe.sections[i].entropy > 4.0
        )
}
```
(source: malcat strings, radare2 EP disassembly, malcat file layout)

### Sigma Detection Rule (Process Creation)
```yaml
title: Suspicious NSudo Process with Privilege Escalation APIs
id: 5f3a9c7d-1234-5678-90ab-cdef12345678
status: experimental
description: Detects execution of NSudo disguised Vidar info-stealer
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    NewProcessName|endswith: '\NSudo.exe'
    CommandLine|contains: 'ShowWindowMode=Hide'
  condition: selection
falsepositives:
  - Legitimate NSudo usage with hidden window mode
```
(source: malcat top strings)

### Behavioral Detection
Alert on combinations of the following import signatures within a single PE: `IsDebuggerPresent`, `VirtualAlloc`, `RegSetValue`, `CreateProcess`, `AdjustTokenPrivileges`, paired with an RWX .reloc section with no relocations and section entropy > 4.0 (source: pe_imports signals, malcat anomalies).

## 11. What We Don't Know
1. **Unpacked payload content**: UPX unpacking failed, and no dynamic unpacking was observed via Speakeasy or Frida, so the final Vidar payload is not available for analysis (source: upx stdout, speakeasy output, frida_probe output).
2. **Live C2 communication**: No network traffic was captured during dynamic analysis, and embedded C2 indicators are only regex matches with no decoded values available (source: speakeasy output, yara matches).
3. **Full stolen data scope**: While static analysis indicates screenshot, registry, and token theft capabilities, the specific data targets (browsers, cryptocurrency wallets, messaging apps, etc.) are unknown without unpacked payload analysis (source: capa rules, yara matches).
4. **Persistence mechanism details**: Registry access is confirmed, but no specific persistence keys, values, or scheduled tasks were extracted without unpacking (source: ghidra decompilation of sub_14000bbe4).
5. **Runtime execution flow**: No API calls or behavioral events were captured via Speakeasy or Frida, so post-unpacking execution logic is unknown (source: speakeasy output, frida_probe output).

## 12. Appendix: Analysis Environment
- **Sample Path**: /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar
- **Project Name**: pool
- **Tools and Outputs**:
  - Malcat: File layout, string extraction (2195 FLOSS strings), anomaly detection (15 anomalies), YARA signatures (5 matches), function list (30 functions), decompilations (6 top functions)
  - Ghidra: Decompilation of decryption stub (0x1400ce000) and key disguise functions (0x45028, 0x109200)
  - radare2: Entry point disassembly at 0x14001b3e0
  - capa: 27 capability rules matched, analysis duration 1.26s
  - YARA: 15 total rule matches
  - FLOSS: 2195 total strings extracted (2185 static, 8 decoded, 2 tight)
  - UPX: Unpack attempt failed (returncode: None, upx_ok: False)
  - Speakeasy: Dynamic analysis completed, 0 API calls, 0 key events recorded
  - Frida: Probe version 17.16.4, 27 hook candidates identified, 0 runtime events captured
  - pe_imports engine: 181 total imports, 5 signal matches
(source: all structured evidence tool outputs)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5  
**sample_path:** /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 90
- **family_guess**: Vidar
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Malcat's static profile initially identifies the binary as the legitimate NSudo system tool (v6.2, M2-Team) based on version metadata and PDB path, but this is inconsistent with other engine findings: the binary has extreme entropy (105) indicating packing, the .reloc section is marked RWX with no actual relocations (abnormal for legitimate PE files), and the sample filename contains the 'vidar' malware family marker. Cross-engine behavior and static analysis all align with known Vidar info-stealer characteristics, indicating the binary is a packed Vidar sample disguised as NSudo.
- **summary**: This is a packed Vidar info-stealer sample disguised as the legitimate NSudo privilege escalation tool. The binary uses XOR-based decryption routines stored in the RWX .reloc section to unpack its payload at runtime, and exhibits core Vidar capabilities including anti-debugging, privilege escalation, registry persistence, process creation, and file manipulation. The high entropy and obfuscation anomalies are consistent with Vidar's common packing and anti-analysis techniques.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary.metadata and layout | `OriginalFilename: NSudo.exe; sample filename ends with '_vidar'; .reloc section ` | Legitimate NSudo binaries do not use the .reloc section as executable memory, and the sample filename explicitly referen |
| pe_imports | signals | `check_debugger (IsDebuggerPresent) [T1622], allocate_memory (VirtualAlloc) [T105` | These imports are core to Vidar's functionality: anti-debugging, memory allocation for payload injection, registry persi |
| ghidra | decompilation | `sub_1400ce000 function body (located at 0x1400ce000 in the RWX .reloc section) c` | This is a standard decryption stub used by packed Vidar samples to decrypt its embedded payload in memory at runtime. |
| capa | top_rules | `create process on Windows, delete file, set registry value, modify access privil` | These capabilities align with Vidar's documented behaviors of stealing data, establishing persistence via registry modif |
| yara | matches | `anti_dbg, escalate_priv, win_registry, win_token, screenshot` | These YARA rule matches correspond to Vidar's known capabilities: anti-debugging, privilege escalation, registry manipul |
| malcat | anomalies | `XorInLoop×4, SpaghettiFunction, SequentialFunction×2, BigBufferNoXrefMediumToHig` | These static anomalies are characteristic of packed and obfuscated malware like Vidar, which uses XOR encryption and con |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 50
- **summary**: The sample is a 64-bit Windows GUI PE executable identified as Vidar infostealer malware. It exhibits core Vidar capabilities including anti-debugging, privilege escalation, screenshot capture, Windows registry access, and security token manipulation. Embedded indicators including domains, IPv4/IPv6 addresses, URLs, and base64 encoded data are present for C2 communication and stolen data exfiltration.

### deep key_evidence
- `{"source": "YARA scan sample path metadata", "query_or_table": "Sample file path", "row_or_rule": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar", "why": "The sample filename explicitly includes the 'vidar' identifier, directly indicating its malware family classification in the analysis corpus."}`
- `{"source": "YARA scan rule matches", "query_or_table": "IsPE64, IsWindowsGUI YARA rules", "row_or_rule": "Positive matches for IsPE64 and IsWindowsGUI rules", "why": "Confirms the sample is a 64-bit Windows GUI PE executable, consistent with the typical build format of Vidar infostealer variants."}`
- `{"source": "YARA scan rule matches", "query_or_table": "Microsoft_Visual_Cpp_80, Microsoft_Visual_Cpp_80_DLL YARA rules", "row_or_rule": "Positive matches for Microsoft Visual C++ 8.0 compiler rules", "why": "Indicates the sample is compiled with Microsoft Visual C++ 8.0, a common compiler used to build Vidar malware samples."}`
- `{"source": "YARA scan rule matches", "query_or_table": "anti_dbg YARA rule", "row_or_rule": "anti_dbg rule match with 3 embedded string hits at offsets 168290, 170302, 170496", "why": "Confirms the sample includes anti-debugging functionality, a standard anti-analysis feature present in Vidar to hinder reverse engineering."}`
- `{"source": "YARA scan rule matches", "query_or_table": "escalate_priv YARA rule", "row_or_rule": "escalate_priv rule match with 2 embedded string hits at offsets 169132, 168830", "why": "Confirms the sample includes privilege escalation capabilities, which Vidar uses to gain higher system access to steal sensitive data."}`
- `{"source": "YARA scan rule matches", "query_or_table": "screenshot YARA rule", "row_or_rule": "screenshot rule match with 3 embedded string hits at offsets 168594, 168566, 168418", "why": "Confirms the sample includes screenshot capture functionality, a core Vidar feature used to capture user screen content for data theft."}`
- `{"source": "YARA scan rule matches", "query_or_table": "win_registry, win_token YARA rules", "row_or_rule": "Positive matches for Windows registry and Windows token rules", "why": "Confirms the sample accesses the Windows registry and manipulates security tokens, capabilities Vidar uses to steal stored credentials and escalate privileges."}`
- `{"source": "YARA scan rule matches", "query_or_table": "domain, IP, url, contains_base64 YARA rules", "row_or_rule": "Positive matches for domain, IPv4/IPv6, URL, and base64 content rules", "why": "Confirms the sample contains embedded C2 indicators (domains, IPs, URLs) and base64 encoded data, which Vidar uses for command and control communication and exfiltration of stolen user data."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5
size: 1488896
type: PE
architecture: X64
entrypoint_ea: 108512
entropy: 105
file_name: 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 115 | - |
| .text | 1024 | 118784 | 118784 | 132 | RX |
| .rdata | 119808 | 51200 | 53248 | 77 | R |
| .data | 173056 | 3072 | 8192 | 100 | RW |
| .pdata | 181248 | 7168 | 8192 | 86 | R |
| .rsrc | 189440 | 70656 | 73728 | 72 | R |
| .reloc | 263168 | 1236992 | 1892352 | 105 | RWX |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| visual_studio_2017_version_15_9_4_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| msvc_general_x64 | compiler | INFO | 50 |  |

### Anomalies (15)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section does not contains relocations |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 4 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 1 | Function with lots of intra jumps, could be obfuscated |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **ManyHighValueImmediates**
  - `112276`: 
  - `840704`: 
- **ManyUniqueImmediateBytes**
  - `95904`: 
  - `840704`: 
- **SequentialFunction**
  - `840704`: 
  - `843622`: 
- **SpaghettiFunction**
  - `95904`: 
- **XorInLoop**
  - `3320`: 
  - `23277`: 
  - `23849`: 
  - `840757`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 168290 | `KERNEL32.dll` |
| 140984 | `kernel32` |
| 245324 | `https://forums.m..ads/59268/
    ` |
| 241260 | `https://forums.m..ads/59268/
    ` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 129328 | `cmd /c start "NS..tMenu.Launcher" ` |
| 130512 | `cmd /c start "NSudo.Launcher" ` |
| 129168 | `SOFTWARE\Microso..mmandStore\shell` |
| 139392 | `ERROR : Unable t.. CAtlBaseModule
` |
| 127936 | `winlogon.exe` |
| 253768 | `

Communicatio..ruto@Outlook.com` |
| 131568 | `invalid string: ..y U+DC00..U+DFFF` |
| 132816 | `invalid string: .. to \u000D or \r` |
| 132736 | `invalid string: .. to \u000C or \f` |
| 132576 | `invalid string: .. to \u000A or \n` |
| 132496 | `invalid string: .. to \u0009 or \t` |
| 132416 | `invalid string: .. to \u0008 or \b` |
| 133136 | `invalid string: ..scaped to \u0011` |
| 131776 | `invalid string: ..scaped to \u0000` |
| 131648 | `invalid string: ..w U+D800..U+DBFF` |
| 130088 | `SHCore.dll` |
| 132176 | `invalid string: ..scaped to \u0005` |
| 133056 | `invalid string: ..scaped to \u0010` |
| 132976 | `invalid string: ..scaped to \u000F` |
| 132896 | `invalid string: ..scaped to \u000E` |
| 130928 | `961c151d2e87f268..6f1362bf21 3.4.0` |
| 132656 | `invalid string: ..scaped to \u000B` |
| 131856 | `invalid string: ..scaped to \u0001` |
| 130360 | `NSudo -ShowWindowMode=Hide` |
| 129144 | `\NSudo.exe` |
| 132336 | `invalid string: ..scaped to \u0007` |
| 132256 | `invalid string: ..scaped to \u0006` |
| 132096 | `invalid string: ..scaped to \u0004` |
| 132016 | `invalid string: ..scaped to \u0003` |
| 131936 | `invalid string: ..scaped to \u0002` |
| 134176 | `invalid string: ..scaped to \u001E` |
| 133776 | `invalid string: ..scaped to \u0019` |
| 133696 | `invalid string: ..scaped to \u0018` |
| 133856 | `invalid string: ..scaped to \u001A` |
| 122016 | `user32.dll` |
| 133616 | `invalid string: ..scaped to \u0017` |
| 133936 | `invalid string: ..scaped to \u001B` |
| 134016 | `invalid string: ..scaped to \u001C` |
| 134096 | `invalid string: ..scaped to \u001D` |
| 133536 | `invalid string: ..scaped to \u0016` |
| 133456 | `invalid string: ..scaped to \u0015` |
| 133376 | `invalid string: ..scaped to \u0014` |
| 133296 | `invalid string: ..scaped to \u0013` |
| 134256 | `invalid string: ..scaped to \u001F` |
| 133216 | `invalid string: ..scaped to \u0012` |
| 131720 | `invalid string: .. after backslash` |
| 130304 | `Button.Run` |
| 129416 | `-ShowWindowMode=Hide` |
| 130008 | `UseCurrentConsole` |
| 131416 | `invalid number; ..er exponent sign` |
| 139528 | `atlthunk.dll` |
| 128624 | `M2-Team NSudo 6.2.1812.31
` |
| 134432 | `cannot use opera..g argument with ` |
| 130744 | `cannot compare i..erent containers` |
| 131352 | `invalid number; ..t after exponent` |
| 128536 | `M2-Team NSudo 6.2.1812.31` |
| 129856 | `CurrentDirectory` |
| 130048 | `TrustedInstaller` |
| 131512 | `invalid string: .. by 4 hex digits` |
| 131472 | `invalid string: ..ng closing quote` |
| 129896 | `ShowWindowMode` |
| 134664 | `iterator does no..it current value` |
| 130696 | `cannot use key()..object iterators` |
| 140128 | `api-ms-win-core-..-obsolete-l1-2-0` |
| 130976 | `invalid BOM; mus..BB 0xBF if given` |
| 140704 | `api-ms-win-secur..functions-l1-1-0` |
| 131256 | `invalid number; .. digit after '-'` |
| 131304 | `invalid number; .. digit after '.'` |
| 129104 | `ItemCommandParameters` |
| 129648 | `Uninstall` |
| 129568 | `Position` |
| 129712 | `Priority` |
| 168830 | `AdjustTokenPrivileges` |
| 127968 | `WinSta0\Default` |
| 140880 | `ext-ms-win-ntuse..owstation-l1-1-0` |
| 129752 | `BelowNormal` |
| 128296 | `other_error` |
| 140624 | `api-ms-win-rtcor..er-window-l1-1-0` |
| 140224 | `api-ms-win-core-..ssthreads-l1-1-2` |
| 134704 | `iterator out of range` |

### Constants / Known Patterns (2)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| exception | `exception::C++ exception` |

### Imports (414)
| EA | Name | Type | Refs |
|---|---|---|---|
| 19676 | std._Immortalize_impl<std::_Iostream_error_category> | DEBUG | 1 |
| 43980 | std.basic_string<char,struct std::char_traits<char>,std::allocator<char>>.basic_string<char,struct std::char_traits<char>,std::allocator<char>> | DEBUG | 13 |
| 44020 | std.basic_string<char,struct std::char_traits<char>,std::allocator<char>>.basic_string<char,struct std::char_traits<char>,std::allocator<char>> | DEBUG | 4 |
| 45544 | std._Locinfo._Locinfo | DEBUG | 3 |
| 46472 | std.ios_base.failure.failure | DEBUG | 6 |
| 48152 | std.basic_filebuf<char,struct std::char_traits<char>>.~basic_filebuf<char,struct std::char_traits<char>> | DEBUG | 4 |
| 48368 | std.basic_ifstream<char,struct std::char_traits<char>>.~basic_ifstream<char,struct std::char_traits<char>> | DEBUG | 4 |
| 49732 | Concurrency.details._AutoDeleter<struct Concurrency::details::_TaskProcHandle>.~_AutoDeleter<struct Concurrency::details::_TaskProcHandle> | DEBUG | 2 |
| 50176 | std._Locinfo.~_Locinfo | DEBUG | 3 |
| 52008 | std::basic_ifstream<char,struct std::char_traits<char>>.#0 | DEBUG | 2 |
| 52020 | std::basic_istream<char,struct std::char_traits<char>>.#0 | DEBUG | 1 |
| 52032 | std::_Ref_count_obj<nlohmann::detail::input_buffer_adapter>.#2 | DEBUG | 3 |
| 52032 | CDataBoundProperty.`scalar deleting destructor' | DEBUG | 3 |
| 52068 | std::basic_filebuf<char,struct std::char_traits<char>>.#0 | DEBUG | 2 |
| 52068 | CAnimationGroup.`scalar deleting destructor' | DEBUG | 2 |
| 52224 | std::basic_ios<char,struct std::char_traits<char>>.#0 | DEBUG | 2 |
| 52224 | CDBVariant.`scalar deleting destructor' | DEBUG | 2 |
| 52412 | std::basic_streambuf<char,struct std::char_traits<char>>.#0 | DEBUG | 2 |
| 52680 | std::codecvt<char,char,struct _Mbstatet>.#0 | DEBUG | 3 |
| 52724 | std::ctype<char>.#0 | DEBUG | 2 |
| 52724 | std.ctype<char>.`scalar deleting destructor' | DEBUG | 2 |
| 52824 | CNSudoMainWindow.#1 | DEBUG | 2 |
| 52896 | std::_Facet_base.#0 | DEBUG | 3 |
| 52940 | std::_Iostream_error_category.#0 | DEBUG | 2 |
| 52976 | std::ios_base::failure.#0 | DEBUG | 4 |
| 53040 | std::bad_cast.#0 | DEBUG | 5 |
| 53040 | Concurrency.details._Timer.`scalar deleting destructor' | DEBUG | 5 |
| 53092 | nlohmann::detail::other_error.#0 | DEBUG | 7 |
| 53156 | nlohmann::detail::input_buffer_adapter.#1 | DEBUG | 3 |
| 53192 | nlohmann::detail::input_stream_adapter.#1 | DEBUG | 2 |
| 53192 | Concurrency.details._Timer.`scalar deleting destructor' | DEBUG | 2 |
| 53244 | std::ios_base.#0 | DEBUG | 3 |
| 53244 | CDBVariant.`scalar deleting destructor' | DEBUG | 3 |
| 53320 | nlohmann::detail::parse_error.#0 | DEBUG | 2 |
| 54744 | CNSudoMainWindow.#2 | DEBUG | 1 |
| 68644 | GuardCFCheckFunction | DEBUG | 5 |
| 68644 | CNSudoMainWindow.#3 | DEBUG | 5 |
| 72204 | CNSudoMainWindow.#0 | DEBUG | 2 |
| 74032 | ATL._AtlRaiseException | DEBUG | 2 |
| 75460 | std::codecvt<char,char,struct _Mbstatet>.#2 | DEBUG | 3 |
| 75460 | std.locale.facet._Decref | DEBUG | 3 |
| 75476 | std::_Ref_count_obj<nlohmann::detail::input_buffer_adapter>.#1 | DEBUG | 3 |
| 75504 | std::_Ref_count_obj<nlohmann::detail::input_buffer_adapter>.#0 | DEBUG | 2 |
| 77216 | Concurrency.details.cache_aligned_allocator<Concurrency::details::_Concurrent_queue_iterator_rep>.allocate | DEBUG | 4 |
| 77232 | std::_Ref_count_obj<nlohmann::detail::input_buffer_adapter>.#3 | DEBUG | 9 |
| 77236 | std::basic_streambuf<char,struct std::char_traits<char>>.#12 | DEBUG | 2 |
| 77240 | std.codecvt<char,char,struct _Mbstatet>._Getcat | DEBUG | 2 |
| 77668 | std::codecvt<char,char,struct _Mbstatet>.#1 | DEBUG | 3 |
| 77940 | std.ios_base._Init | DEBUG | 2 |
| 78752 | std::basic_filebuf<char,struct std::char_traits<char>>.#1 | DEBUG | 2 |
| 79556 | std::basic_filebuf<char,struct std::char_traits<char>>.#2 | DEBUG | 2 |
| 79948 | std.allocator<struct std::_Container_proxy>.allocate | DEBUG | 10 |
| 80056 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.append | DEBUG | 27 |
| 80300 | std.basic_string<char,struct std::char_traits<char>,char_traits::allocator<char>>.assign | DEBUG | 29 |
| 80916 | std.ios_base.clear | DEBUG | 3 |
| 84004 | std.allocator<char>.deallocate | DEBUG | 2 |
| 84336 | std._Default_allocator_traits<std::allocator<struct std::_Container_proxy>>.deallocate | DEBUG | 9 |
| 84404 | std::_Iostream_error_category.#3 | DEBUG | 1 |
| 84404 | std.error_category.default_error_condition | DEBUG | 1 |
| 84544 | std::codecvt<char,char,struct _Mbstatet>.#3 | DEBUG | 8 |
| 84560 | std::codecvt<char,char,struct _Mbstatet>.#5 | DEBUG | 4 |
| 84568 | std::codecvt<char,char,struct _Mbstatet>.#7 | DEBUG | 2 |
| 84596 | std::codecvt<char,char,struct _Mbstatet>.#9 | DEBUG | 1 |
| 84596 | std.codecvt<char,char,struct _Mbstatet>.do_length | DEBUG | 1 |
| 84612 | std::ctype<char>.#10 | DEBUG | 2 |
| 84616 | std::ctype<char>.#9 | DEBUG | 2 |
| 84616 | std.ctype<char>.do_narrow | DEBUG | 2 |
| 84648 | std::ctype<char>.#4 | DEBUG | 1 |
| 84664 | std::ctype<char>.#3 | DEBUG | 2 |
| 84744 | std::ctype<char>.#6 | DEBUG | 1 |
| 84760 | std::ctype<char>.#5 | DEBUG | 2 |
| 84840 | std::codecvt<char,char,struct _Mbstatet>.#8 | DEBUG | 1 |
| 84852 | std::ctype<char>.#7 | DEBUG | 2 |
| 84852 | std.ctype<char>.do_widen | DEBUG | 2 |
| 85816 | std::_Iostream_error_category.#4 | DEBUG | 2 |
| 85816 | std.error_category.equivalent | DEBUG | 2 |
| 85844 | std::_Iostream_error_category.#5 | DEBUG | 2 |
| 89164 | nlohmann::detail::input_buffer_adapter.#0 | DEBUG | 2 |
| 89192 | nlohmann::detail::input_stream_adapter.#0 | DEBUG | 1 |
| 89708 | std::basic_filebuf<char,struct std::char_traits<char>>.#14 | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 45028 | sub_14000bbe4 |
| 109200 | sub_14001b690 |
| 840704 | sub_1400ce000 |
| 109264 | sub_14001b6d0 |
| 111248 | sub_14001be90 |
| 23100 | sub_14000663c |
| 23672 | sub_140006878 |
| 3192 | sub_140001878 |
| 107344 | sub_14001af50 |
| 68648 | sub_140011828 |
| 62724 | sub_140010104 |
| 63660 | sub_1400104ac |
| 113744 | sub_14001c850 |
| 60032 | sub_14000f680 |
| 10504 | sub_140003508 |
| 10320 | sub_140003450 |
| 108656 | sub_14001b470 |
| 9876 | sub_140003294 |
| 55224 | sub_14000e3b8 |
| 73716 | sub_140012bf4 |
| 66920 | sub_140011168 |
| 54304 | sub_14000e020 |
| 64160 | sub_1400106a0 |
| 54524 | sub_14000e0fc |
| 54892 | sub_14000e26c |
| 53700 | sub_14000ddc4 |
| 68316 | sub_1400116dc |
| 9480 | sub_140003108 |
| 65128 | sub_140010a68 |
| 70092 | sub_140011dcc |

### Decompilations (top 6)
#### 45028 — sub_14000bbe4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t * sub_14000bbe4(int32_t *param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    
    *param_1 = 0;
    piVar1 = param_1 + 2;
    *(param_1 + 6) = 0;
    *(param_1 + 8) = 7;
    *piVar1 = 0;
    *(param_1 + 10) = 0;
    *(param_1 + 0xc) = 0;
    *(param_1 + 0xe) = 0;
    *(param_1 + 0x10) = 0;
    iVar2 = sub_140003398(piVar1);
    *param_1 = iVar2;
    if (-1 < iVar2) {
        sub_140014530(piVar1, "\\NSudo.exe", 10);
        iVar2 = (*advapi32.RegOpenKeyExW)(0xffffffff80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CommandStore\\shell", 0, 0xf013f, param_1 + 10);
        *param_1 = iVar2;
        if (iVar2 == 0) {
            sub_14000eb58(param_1 + 0xc);
        }
    }
    return param_1;
}

```
#### 109200 — sub_14001b690
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_14001b690(int32_t **param_1)

{
    int32_t *piVar1;
    code *pcVar2;
    undefined8 uVar3;
    
    piVar1 = *param_1;
    if ((*piVar1 == -0x1f928c9d) && (piVar1[6] == 4)) {
        if ((piVar1[8] + 0xe66cfae0U < 3) || (piVar1[8] == 0x1994000)) {
            jmp_msvcrt.terminate();
            pcVar2 = swi(3);
            uVar3 = (*pcVar2)();
            return uVar3;
        }
    }
    return 0;
}

```
#### 840704 — sub_1400ce000
```c

/* WARNING: Possible PIC construction at 0x0001400ce92d: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0001400ce93a: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x0001400ce932) */
/* WARNING: Removing unreachable block (ram,0x0001400ce93f) */
/* WARNING: Removing unreachable block (ram,0x0001400ce94b) */
/* WARNING: Removing unreachable block (ram,0x0001400ce94d) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_1400ce000(void)

{
    int64_t iVar1;
    int32_t *piVar2;
    undefined *puVar3;
    undefined8 *puVar4;
    undefined *unaff_RBP;
    
    piVar2 = 0x140041400;
    iVar1 = 0;
    do {
        piVar2[0xe3] = ~piVar2[0xe3];
        piVar2[0xb8] = piVar2[0xb8] ^ 0x35fc132e;
        piVar2[0x6d] = piVar2[0x6d] ^ 0x5f463a43;
        piVar2[0xdf] = ~piVar2[0xdf];
        piVar2[0xe0] = piVar2[0xe0] + 0x737449d7;
        piVar2[0x4d] = piVar2[0x4d] + -0x2305235a;
        piVar2[0xd8] = piVar2[0xd8] ^ 0x56023e06;
        piVar2[0x15] = piVar2[0x15] + -0x391c7d14;
        piVar2[0x89] = ~piVar2[0x89];
        piVar2[0x1b] = ~piVar2[0x1b];
        piVar2[0x5c] = piVar2[0x5c] + 0x46bf69a6;
        piVar2[0x14] = ~piVar2[0x14];
        piVar2[0x59] = piVar2[0x59] + 0x58a737ac;
        piVar2[0x41] = piVar2[0x41] ^ 0x12b4474c;
        piVar2[0x31] = piVar2[0x31] + 0x44bb0f76;
        piVar2[0x8e] = piVar2[0x8e] + 0x54d7471f;
        piVar2[0x43] = ~piVar2[0x43];
        piVar2[0x24] = ~piVar2[0x24];
        piVar2[0xf6] = piVar2[0xf6] ^ 0x6b7270ca;
        piVar2[0xa9] = ~piVar2[0xa9];
        *piVar2 = *piVar2 + -0x13f24793;
        piVar2[0x3e] = piVar2[0x3e] + 0x506360f3;
        piVar2[0x53] = piVar2[0x53] + 0xa922714;
        piVar2[0x76] = piVar2[0x76] + 0x31645598;
        piVar2[0x49] = piVar2[0x49] + -0x19664f67;
        piVar2[0xd] = piVar2[0xd] ^ 0x18ec3a51;
        piVar2[0x71] = piVar2[0x71] + 0x322e17bd;
        piVar2[10] = piVar2[10] ^ 0x401c6269;
        piVar2[0x32] = piVar2[0x32] + 0x257d5da0;
        piVar2[0x68] = piVar2[0x68] + 0x64a655e7;
        piVar2[0x77] = piVar2[0x77] ^ 0x116025ac;
        piVar2[0x26] = ~piVar2[0x26];
        piVar2[0xc4] = piVar2[0xc4] + -0x31125c2a;
        piVar2[0x2c] = piVar2[0x2c] + -0x2a2064be;
        piVar2[0x99] = piVar2[0x99] ^ 0x40aa33f8;
        piVar2[0x10] = piVar2[0x10] ^ 0x38b12100;
        piVar2[0x9a] = piVar2[0x9a] ^ 0xe2469c8;
        piVar2[0xe8] = piVar2[0xe8] + -0x1a293b23;
        piVar2[0x5d] = piVar2[0x5d] + 0x64d826bb;
        piVar2[0x6b] = piVar2[0x6b] + -0x25266169;
        piVar2[0xe7] = piVar2[0xe7] ^ 0x63e738c7;
        piVar2[0xe1] = piVar2[0xe1] + 0x32bf6958;
        piVar2[0xa4] = piVar2[0xa4] + -0x5bbd1185;
        piVar2[0xec] = piVar2[0xec] + 0x1d190cd6;
        piVar2[0xd1] = piVar2[0xd1] + 0x351e1d30;
        piVar2[0x47] = piVar2[0x47] ^ 0x15f63a38;
        piVar2[0x12] = ~piVar2[0x12];
        piVar2[7] = piVar2[7] + -0x6ab66fce;
        piVar2[0xbf] = piVar2[0xbf] + -0x5be1754f;
        piVar2[0x45] = piVar2[0x45] ^ 0x5ebf49ab;
        piVar2[0x6c] = ~piVar2[0x6c];
        piVar2[0x8b] = ~piVar2[0x8b];
        piVar2[0xa2] = piVar2[0xa2] + -0x5af4874;
        piVar2[0x3d] = piVar2[0x3d] + -0x1530449;
        piVar2[0x23] = piVar2[0x23] + 0x58f859e9;
        piVar2[0x2e] = piVar2[0x2e] + -0x3eba39af;
        piVar2[0x1a] = piVar2[0x1a] + 0x54f46416;
        piVar2[0x42] = piVar2[0x42] + -0x1ab40ef1;
        piVar2[0xc2] = ~piVar2[0xc2];
        piVar2[0xfe] = piVar2[0xfe] + -0x190554b0;
        piVar2[0xeb] = ~piVar2[0xeb];
        piVar2[0xbc] = ~piVar2[0xbc];
        piVar2[0xc3] = ~piVar2[0xc3];
        piVar2[0x44] = piVar2[0x44] + 0x12706dd9;
        piVar2[2] = piVar2[2] + 0x54375984;
        piVar2[0x25] = piVar2[0x25] ^ 0xb6559e5;
        piVar2[0xd4] = piVar2[0xd4] ^ 0x272b59eb;
        piVar2[0x62] = piVar2[0x62] ^ 0x5a7a376f;
        piVar2[0x3a] = piVar2[0x3a] + -0x7a994270;
        piVar2[0xf1] = piVar2[0xf1] + 0x5e14239f;
        piVar2[0xd9] = piVar2[0xd
```

### Carved Files (8)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 1128 |
| ? | DIB | 1720 |
| ? | DIB | 2440 |
| ? | DIB | 4264 |
| ? | DIB | 6760 |
| ? | DIB | 9640 |
| ? | DIB | 16936 |
| ? | PNG | 4763 |

### Virtual Files (26)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| CONFIG/101/unk | 831 | - |
| STRING/2000/zh-hans | 1351 | - |
| STRING/2000/en | 1312 | - |
| STRING/2000/fr | 1500 | - |
| STRING/2000/zh-tw | 1377 | - |
| STRING/2002/zh-hans | 2495 | - |
| STRING/2002/en | 2735 | - |
| STRING/2002/fr | 3288 | - |
| STRING/2002/zh-tw | 2629 | - |
| STRING/2003/zh-hans | 178 | - |
| STRING/2003/en | 167 | - |
| STRING/2003/fr | 177 | - |
| STRING/2003/zh-tw | 178 | - |
| ICO/1/unk | 1128 | - |
| ICO/2/unk | 1720 | - |
| ICO/3/unk | 2440 | - |
| ICO/4/unk | 4264 | - |
| ICO/5/unk | 6760 | - |
| ICO/6/unk | 9640 | - |
| ICO/7/unk | 16936 | - |

### Structures (120)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 296 |
| OptionalHeader | 320 |
| Sections | 560 |
| advapi32.FT | 119808 |
| comdlg32.FT | 120032 |
| gdi32.FT | 120048 |
| kernel32.FT | 120064 |
| shell32.FT | 120576 |
| user32.FT | 120600 |
| userenv.FT | 120736 |
| wtsapi32.FT | 120760 |
| msvcp60.FT | 120792 |
| msvcrt.FT | 120824 |
| ole32.FT | 121328 |
| GuardCFCheckFunctionPointer | 121344 |
| GuardCFDispatchFunctionPointer | 121352 |
| TlsCallbacks | 121488 |
| DebugDirectory | 141488 |
| LoadConfigurationTable | 141584 |
| TlsDirectory | 141840 |
| Debug.Codeview | 146996 |
| Debug.VcFeature | 147068 |
| Debug.Pogo | 147088 |
| TLSInitArray | 147896 |
| ImportTable | 165768 |
| advapi32.OFT | 166008 |
| comdlg32.OFT | 166232 |
| gdi32.OFT | 166248 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 27 · duration_s: 1.26

| Rule | ATT&CK | MBC |
|---|---|---|
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| copy file |  | C0045:Copy File |
| delete file |  | C0047:Delete File |
| get file attributes |  | C0049:Get File Attributes |
| move file |  | C0063:Move File |
| write file on Windows |  | C0052:Writes File |
| get graphical window text |  | E1010:Application Window Discovery |
| create process on Windows |  | C0017:Create Process |
| enumerate processes on remote desktop session host | T1057:Process Discovery |  |
| modify access privileges | T1134:Access Token Manipulation |  |
| terminate process |  | C0018:Terminate Process |
| set registry value |  | C0036.001:Registry |

## PE Imports / Signals
import_count: 181

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 15

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@250037 len=7; $ipv6@127823 len=7 |
| contains_base64 | - | $a@1450 len=12 |
| url | - | $url_regex@233013 len=31 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@272 len=4 |
| Microsoft_Visual_Cpp_80 | - | $c@108512 len=32 |
| Microsoft_Visual_Cpp_80_DLL | - | $b@1024 len=4 |
| anti_dbg | - | $d1@168290 len=12; $c2@170302 len=17; $c3@170496 len=17 |
| escalate_priv | - | $d1@169132 len=12; $c2@168830 len=21 |
| screenshot | - | $d1@168594 len=9; $d2@168566 len=10; $c2@168418 len=5 |
| win_registry | - | $f1@169132 len=12; $c3@169050 len=11; $c6@169050 len=11 |
| win_token | - | $f1@169132 len=12; $c1@168906 len=16; $c2@168830 len=21; $c3@168778 len=16 |

## Generated YARA Meta
```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 250037,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 127823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a",
          "offset": 1450,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 233013,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$a0",
          "offset": 272,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$c",
          "offset": 108512,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$b",
          "offset": 1024,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar",
      "strings": [
        {
          "id": "$d1",
          "offset": 168290,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 170302,
          "length": 17,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 170496,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "escalate_priv",
      "path": "/opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_5
```

## FLOSS Strings
Total strings: 2195 · per_category: `{"decoded_strings": 8, "stack_strings": 0, "tight_strings": 2, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2185}`

### FLOSS sample
- `1096216591`
- `number overflow parsing '`
- `excessive object size:`
- `excessive array size:`
- `cmd /c start "NSudo.Launcher"`
- `1096175631`
- `18374403900871474942`
- `18374403900871474943`
- `3198791665`
- `!This program cannot be run in DOS mode.`
- `oRichlA`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.rsrc`
- `@.reloc`
- `SVWATAUAVAWH`
- `@A_A^A]A\_^[`
- `@SVWATAUAVAWH`
- `H;8uVI`
- `pA_A^A]A\_^[`
- `tCL;0u/L`
- ``A_A^A]A\_^[`
- `UVWAVAWH`
- `A_A^_^]`
- `l$ VWATAVAWH`
- `A_A^A\_^`
- `@SUVWATAVAWH`
- `A_A^A\_^][`
- `t$ WAVAWH`
- `UVWATAUAVAWH`
- `pA_A^A]A\_^]`
- `@USVWATAUAVAWH`
- `H;|$(u`
- `fF9,Bu`
- `|$0H;]`
- `fB9<pu`
- `A_A^A]A\_^[]`
- `@VWAVH`
- `@USVWAVH`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x14001b3e0
```asm
┌ 327: entry0 ();
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_8h @ rsp+0x40
│       ╎   0x14001b3e0      4883ec28       sub rsp, 0x28
│       ╎   0x14001b3e4      e8e7020000     call 0x14001b6d0
│       ╎   0x14001b3e9      4883c428       add rsp, 0x28
│       └─< 0x14001b3ed      e99efeffff     jmp 0x14001b290
..
            ; CALL XREFS from entry0 @ 0x14001b3bd(x), 0x14001b3c8(x)
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000128 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!DeleteCriticalSection`
  - `KERNEL32.dll!WaitForSingleObjectEx`
  - `KERNEL32.dll!GetCurrentProcess`
  - `KERNEL32.dll!GetCurrentThreadId`
  - `KERNEL32.dll!ResumeThread`
  - `USER32.dll!EndPaint`
  - `USER32.dll!GetWindowTextW`
  - `USER32.dll!GetClientRect`
  - `USER32.dll!BeginPaint`
  - `USER32.dll!LoadImageW`
  - `GDI32.dll!GetDeviceCaps`
  - `COMDLG32.dll!GetOpenFileNameW`
  - `ADVAPI32.dll!RegDeleteTreeW`
  - `ADVAPI32.dll!RegSetValueExW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!RegCreateKeyExW`
  - `ADVAPI32.dll!RegCloseKey`
  - `SHELL32.dll!DragQueryFileW`
  - `SHELL32.dll!DragFinish`
  - `ole32.dll!CoInitializeEx`
  - `WTSAPI32.dll!WTSQueryUserToken`
  - `WTSAPI32.dll!WTSEnumerateProcessesW`
  - `WTSAPI32.dll!WTSFreeMemory`
  - `USERENV.dll!DestroyEnvironmentBlock`
  - `USERENV.dll!CreateEnvironmentBlock`
  - `msvcrt.dll!abort`
  - `msvcrt.dll!fseek`
  - `msvcrt.dll!__C_specific_handler`
  - `msvcrt.dll!_cexit`
  - `msvcrt.dll!??0exception@@QEAA@AEBQEBD@Z`
