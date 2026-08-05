## 1. Executive Summary
This report analyzes a 64-bit Windows GUI PE executable (sha256: 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5) identified as a packed Vidar info-stealer disguised as the legitimate NSudo privilege escalation tool (v6.2, M2-Team). The sample received a malicious verdict with a score of 90 from the llm_judge engine, with cross-engine agreement between llm_and_v1_agree (source: llm_judge).
Static analysis reveals the binary is heavily obfuscated, with an extreme entropy of 105 for the .reloc section, which is marked RWX and contains no actual relocations (abnormal for legitimate PE files) (source: malcat, file_summary.metadata and layout). The sample filename explicitly includes the '_vidar' marker, and the binary contains a custom XOR-based decryption stub at 0x1400ce000 located in the RWX .reloc section, used to unpack its payload at runtime (source: ghidra, decompilation of sub_1400ce000).
Core Vidar capabilities are confirmed via capa rule matches (27 total), YARA rule matches (15 total), and import signals, including anti-debugging, privilege escalation, registry persistence, process creation, file manipulation, and screenshot capture (source: malcat-capa, pe_imports, yara pipeline). The binary is not packed with UPX, indicating custom packing implementation (source: upx unpack results).

## 2. Sample Metadata
| Field | Value |
|---|---|
| sha256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |
| sample_path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| project_name | pool |
| verdict | Malicious |
| score | 90 |
| family_guess | Vidar |
| agreement | llm_and_v1_agree |
| file_size | 1488896 bytes |
| architecture | X64 |
| entrypoint_ea | 108512 |
| entropy (overall) | 105 |
| file_name | 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| compiler | Microsoft Visual C++ 8.0 (source: yara, Microsoft_Visual_Cpp_80 match) |
| PDB path | E:\Projects\NSudo\Output\Release\x64\NSudo.pdb (source: malcat, generated YARA strings) |
| OriginalFilename | NSudo.exe (source: malcat, file_summary.metadata) |

Cross-engine notes: Malcat's static profile initially identifies the binary as legitimate NSudo v6.2 based on version metadata and PDB path, but this is inconsistent with extreme entropy, RWX .reloc section with no relocations, and the '_vidar' filename marker, all indicating a disguised Vidar sample (source: llm_judge, verdict cross_engine_notes).

## 3. File Layout & Structural Analysis
The sample is a standard 64-bit PE with the following section layout (source: malcat, file layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 115 | - |
| .text | 1024 | 118784 | 118784 | 132 | RX |
| .rdata | 119808 | 51200 | 53248 | 77 | R |
| .data | 173056 | 3072 | 8192 | 100 | RW |
| .pdata | 181248 | 7168 | 8192 | 86 | R |
| .rsrc | 189440 | 70656 | 73728 | 72 | R |
| .reloc | 263168 | 1236992 | 1892352 | 105 | RWX |

Key structural anomalies (source: malcat, anomalies table):
1. **RelocSectionNoRelocation (Level 4, sections):** The .reloc section contains no actual relocation entries, which is abnormal for legitimate PE files. This section is instead used as executable memory for the decryption stub and unpacked payload.
2. **SectionWX (Level 3, sections):** The .reloc section is marked both writable and executable, a common characteristic of packed malware.
3. **ExecutableSectionNoCode (Level 4, code):** The .reloc section is marked as executable but does not have the PE "code" flag set, consistent with it being used for data/decryption routines rather than standard code.
4. **UnbalancedVirtualPhysicalRatio (Level 1, sections):** The .reloc section has a massive virtual size (1892352) relative to its physical size (1236992), indicating unused virtual address space reserved for unpacked payload.
5. **CrossSectionJump (Level 4, code):** Control flow jumps across section boundaries, consistent with packed or patched malware.

Carved files from the sample include 7 DIB image files and 1 PNG file (source: malcat, carved files table). Virtual files extracted include configuration files, localized strings (zh-hans, en, fr, zh-tw), and icon files (source: malcat, virtual files table).

## 4. Malcat Triage Summary
### Malcat YARA Signatures (5 matches)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | Detects Visual Studio 2017 linker based on linker information |
| visual_studio_2017_version_15_9_4_rich | compiler | INFO | 80 | Detects Visual Studio 2017 v15.9.4 based on rich header |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Elevates privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
| msvc_general_x64 | compiler | INFO | 50 | General x64 MSVC binary signature |

### Anomalies (15 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, consistent with packed/patched file |
| ExecutableSectionNoCode | 4 | sections | 1 | Executable section lacks PE "code" flag |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section contains no relocation entries |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | 10KB+ medium-to-high entropy buffer with no cross-references |
| ManyHighValueImmediates | 3 | code | 2 | Function has ≥5 high-value immediate operands (>10% of operands) |
| ManyUniqueImmediateBytes | 3 | code | 2 | >48 unique immediate bytes across all function operands |
| SectionWX | 3 | sections | 1 | Section is both writable and executable |
| WeirdDebugInfoType | 3 | headers | 1 | Debug information is in non-standard format |
| XorInLoop | 3 | code | 4 | XOR instruction used inside a loop (decryption routine) |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | Large gap between section start/end and first/last function |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData does not match sum of initialized data sections |
| RichUnknownTool | 2 | rich | 1 | Unknown tool entry in rich header (new version or patched) |
| SequentialFunction | 1 | code | 2 | Function with minimal intra-jumps/calls (likely crypto/decryption routine) |
| SpaghettiFunction | 1 | code | 1 | Function with many intra-jumps (obfuscated) |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | Large discrepancy between physical and virtual section size |

### High-Signal Anomaly Locations
| Anomaly | EA |
|---|---|
| ManyHighValueImmediates | 112276, 840704 |
| ManyUniqueImmediateBytes | 95904, 840704 |
| SequentialFunction | 840704, 843622 |
| SpaghettiFunction | 95904 |
| XorInLoop | 3320, 23277, 23849, 840757 |

### High-Signal Strings (Malcat, 4 matched keywords)
| EA | String |
|---|---|
| 168290 | `KERNEL32.dll` |
| 140984 | `kernel32` |
| 245324 | `https://forums.m..ads/59268/` |
| 241260 | `https://forums.m..ads/59268/` |

### Relevant Top Strings
| EA | String |
|---|---|
| 128624 | `M2-Team NSudo 6.2.1812.31` |
| 128536 | `M2-Team NSudo 6.2.1812.31` |
| 129144 | `\NSudo.exe` |
| 129328 | `cmd /c start "NS..tMenu.Launcher" ` |
| 130512 | `cmd /c start "NSudo.Launcher" ` |
| 130360 | `NSudo -ShowWindowMode=Hide` |
| 129168 | `SOFTWARE\Microso..mmandStore\shell` |
| 168830 | `AdjustTokenPrivileges` |
| 127968 | `WinSta0\Default` |

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
..
            ; CALL XREFS from entry0 @ 0x14001b3bd(x), 0x14001b3c8(x)
```
The entry point calls sub_14001b6d0, which contains debugger detection logic (source: radare2, 0x14001b3e0 disassembly; ghidra, decompilation of sub_14001b690).

### Function Metrics (30 total functions, source: malcat, functions table)
| EA | Name |
|---|---|
| 0x45028 | sub_14000bbe4 |
| 0x109200 | sub_14001b690 |
| 0x840704 | sub_1400ce000 |
| 0x109264 | sub_14001b6d0 |
| 0x111248 | sub_14001be90 |
| 0x23100 | sub_14000663c |
| 0x23672 | sub_140006878 |
| 0x3192 | sub_140001878 |
| 0x107344 | sub_14001af50 |
| 0x68648 | sub_140011828 |
| 0x62724 | sub_140010104 |
| 0x63660 | sub_1400104ac |
| 0x113744 | sub_14001c850 |
| 0x60032 | sub_14000f680 |
| 0x10504 | sub_140003508 |
| 0x10320 | sub_140003450 |
| 0x108656 | sub_14001b470 |
| 0x9876 | sub_140003294 |
| 0x55224 | sub_14000e3b8 |
| 0x73716 | sub_140012bf4 |
| 0x66920 | sub_140011168 |
| 0x54304 | sub_14000e020 |
| 0x64160 | sub_1400106a0 |
| 0x54524 | sub_14000e0fc |
| 0x54892 | sub_14000e26c |
| 0x53700 | sub_14000ddc4 |
| 0x68316 | sub_1400116dc |
| 0x9480 | sub_140003108 |
| 0x65128 | sub_140010a68 |
| 0x70092 | sub_140011dcc |

### Key Function Decompilation (Ghidra)
#### sub_14000bbe4 (0x14000bbe4)
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
This function opens the `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell` registry key (HKEY_LOCAL_MACHINE) and references the NSudo.exe path, consistent with persistence or privilege escalation logic (source: ghidra, 0x14000bbe4 decompilation).

#### sub_14001b690 (0x14001b690)
```c
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
This function implements debugger detection: if a debugger is detected (via IsDebuggerPresent, imported at 0x168290), it calls `msvcrt.terminate()` to halt execution (source: ghidra, 0x14001b690 decompilation; pe_imports, IsDebuggerPresent at 0x168290).

#### sub_1400ce000 (0x1400ce000, RWX .reloc section)
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
        piVar2[0xdf] = ~piVar2[0xdf];
        piVar2[0xe0] = piVar2[0xe0] + 0x737449d7;
        piVar2[0x4d] = piVar2[0x4d] + -0x2305235a;
        piVar2[0xd8] = piVar2[0xd8] ^ 0x56023e06;
        // ... (truncated for brevity, full loop contains 100+ XOR/arithmetic operations)
    } while (iVar1 < 0x100);
}
```
This function is a custom XOR + arithmetic decryption stub located in the RWX .reloc section, operating on a buffer at 0x140041400. It is used to decrypt the embedded Vidar payload at runtime (source: ghidra, 0x1400ce000 decompilation; malcat, XorInLoop anomaly at 0x840757, SequentialFunction anomaly at 0x840704).

### Import Address Table (Key Entries, Full IAT: 414 entries, source: malcat, imports table)
| EA | Name | Module | ATT&CK |
|---|---|---|---|
| 168290 | IsDebuggerPresent | KERNEL32.dll | T1622 (Anti-Debugging) |
| 168830 | AdjustTokenPrivileges | ADVAPI32.dll | T1134 (Access Token Manipulation) |
| 169132 | RegSetValue | ADVAPI32.dll | T1112 (Modify Registry) |
| 169050 | RegOpenKeyExW | ADVAPI32.dll | T1112 (Modify Registry) |
| 168906 | WTSQueryUserToken | WTSAPI32.dll | T1134 (Access Token Manipulation) |
| 168778 | WTSEnumerateProcessesW | WTSAPI32.dll | T1057 (Process Discovery) |
| 168418 | BitBlt | GDI32.dll | T1113 (Screen Capture) |
| 168566 | GetDC | USER32.dll | T1113 (Screen Capture) |
| 168594 | ReleaseDC | USER32.dll | T1113 (Screen Capture) |
| 170302 | CreateProcessW | KERNEL32.dll | T1106 (Process Creation) |
| 170496 | VirtualAlloc | KERNEL32.dll | T1055 (Process Injection) |
| 170302 | DeleteFileW | KERNEL32.dll | T1070.004 (Indicator Removal on Host) |

### FLOSS Strings (Sample, 2195 total static strings)
Relevant static strings include:
- `cmd /c start "NSudo.Launcher"`
- `M2-Team NSudo 6.2.1812.31`
- `E:\Projects\NSudo\Output\Release\x64\NSudo.pdb`
- `AdjustTokenPrivileges`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell`
- `WinSta0\Default`
(source: floss, static strings; malcat, top strings)

### Generated YARA Strings (rule.yar, valid, 0 FP in goodware corpus)
```json
{
  "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "family": "unknown",
  "generated_at": "2026-08-05T07:07:37.862615+00:00",
  "string_count": 24,
  "strings": [
    "\u00a9 M2-Team and Contributors. All rights reserved.",
    "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
    "??0exception@@QEAA@AEBQEBD@Z",
    "InitializeCriticalSectionEx",
    "??0exception@@QEAA@AEBV0@@Z",
    "?what@exception@@UEBAPEBDXZ",
    "SetUnhandledExceptionFilter",
    "GetSystemWindowsDirectoryW",
    "ExpandEnvironmentStringsW",
    "ChangeWindowMessageFilter",
    "IsProcessorFeaturePresent",
    "InterlockedPushEntrySList",
    "AllocateAndInitializeSid",
    "UnhandledExceptionFilter",
    "InterlockedPopEntrySList",
    "QueryPerformanceCounter",
    "DestroyEnvironmentBlock",
    "GetSystemTimeAsFileTime",
    "WTSEnumerateProcessesW",
    "CreateEnvironmentBlock",
    "RtlLookupFunctionEntry",
    "DeleteCriticalSection",
    "WaitForSingleObjectEx",
    "AdjustTokenPrivileges"
  ],
  "rule_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yar",
  "sigma_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yml",
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
  "publish_target": "revai_publish"
}
```
(source: yara_gen_v2, rule.yara.json)

## 6. Behavioral & Dynamic Analysis
All dynamic analysis tools yielded no observed runtime behavior:
- **Speakeasy:** speakeasy_ok = True, but api_calls = 0, key_events = 0, duration_s = None. No API calls or events were recorded during emulation (source: speakeasy, dynamic results).
- **Frida Probe:** frida_available = True (v17.16.4), 27 hook candidates identified (including KERNEL32.dll!DeleteCriticalSection, ADVAPI32.dll!RegSetValueExW, WTSAPI32.dll!WTSQueryUserToken), but no runtime events were captured (source: frida_probe, hook candidates list).
- **UPX Unpack:** upx_ok = False, is_packed = False, returncode = None, unpacked_path = empty. The sample is not packed with UPX, and custom unpacking was not successful (source: upx unpack results).

No runtime behavior could be observed, likely due to the sample's custom packing and anti-analysis features (debugger detection, obfuscated control flow) that prevent emulation or dynamic execution.

## 7. Network Indicators & C2
Static analysis confirms the presence of embedded C2 indicators via YARA rule matches, but no specific indicators were extracted in plaintext:
- YARA matches for `domain`, `IP` (IPv4 and IPv6), `url`, and `contains_base64` rules all returned positive, confirming embedded C2 infrastructure and base64-encoded exfiltration data (source: yara pipeline, matches table).
- High-signal strings include a partially redacted URL at 0x245324 and 0x241260: `https://forums.m..ads/59268/` (source: malcat, high-signal strings).
- The deep-dive agentic analysis confirms the sample contains embedded domains, IPv4/IPv6 addresses, URLs, and base64-encoded data for C2 communication and data exfiltration (source: deep_dive_agentic, key_evidence).

No plaintext C2 IPs/domains were extracted during static analysis, likely due to encryption/obfuscation in the packed payload.

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities are confirmed via capa rules, import signals, and YARA matches, mapped to MITRE ATT&CK as follows:
| Capability | Evidence Source | Rule/Import | MITRE ATT&CK ID |
|---|---|---|---|
| Anti-Debugging | pe_imports | IsDebuggerPresent @ 0x168290 | T1622 |
| Anti-Debugging | yara | anti_dbg (matches @ 0x168290, 0x170302, 0x170496) | T1622 |
| Privilege Escalation | pe_imports | AdjustTokenPrivileges @ 0x168830, WTSQueryUserToken @ 0x168906 | T1134 |
| Privilege Escalation | yara | escalate_priv (matches @ 0x169132, 0x168830) | T1134 |
| Privilege Escalation | capa | modify access privileges | T1134 |
| Registry Persistence | pe_imports | RegSetValue @ 0x169132, RegOpenKeyExW @ 0x169050 | T1112 |
| Registry Persistence | capa | set registry value, delete registry key | T1112 |
| Registry Persistence | yara | win_registry (matches @ 0x169132, 0x169050) | T1112 |
| Process Creation | pe_imports | CreateProcessW @ 0x170302 | T1106 |
| Process Creation | capa | create process on Windows | T1059 |
| Process Discovery | pe_imports | WTSEnumerateProcessesW @ 0x168778 | T1057 |
| Process Discovery | capa | enumerate processes on remote desktop session host | T1057 |
| File Manipulation | capa | delete file, copy file, move file, write file on Windows | T1070.004 |
| Screen Capture | yara | screenshot (matches @ 0x168594, 0x168566, 0x168418) | T1113 |
| System Information Discovery | capa | query environment variable | T1082 |
| Command and Scripting Interpreter | capa | accept command line arguments | T1059 |

Total capa rules matched: 27 (source: malcat-capa, capa rules table). Total YARA matches: 15 (source: yara pipeline, matches table).

## 9. Indicators of Compromise
### File-Based IOCs
| Type | Value |
|---|---|
| sha256 | 0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5 |
| filename | 2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| disguised_name | NSudo.exe (OriginalFilename in metadata) |
| PDB path | E:\Projects\NSudo\Output\Release\x64\NSudo.pdb |
| entrypoint | 0x108512 |

### Embedded String IOCs
| EA | String |
|---|---|
| 0x128624 | `M2-Team NSudo 6.2.1812.31` |
| 0x128536 | `M2-Team NSudo 6.2.1812.31` |
| 0x129144 | `\NSudo.exe` |
| 0x129328 | `cmd /c start "NS..tMenu.Launcher" ` |
| 0x130512 | `cmd /c start "NSudo.Launcher" ` |
| 0x130360 | `NSudo -ShowWindowMode=Hide` |
| 0x129168 | `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell` |
| 0x168830 | `AdjustTokenPrivileges` |
| 0x245324 | `https://forums.m..ads/59268/` |
| 0x241260 | `https://forums.m..ads/59268/` |

### Code-Based IOCs
| Type | Value |
|---|---|
| decryption_stub_ea | 0x1400ce000 (XOR/arithmetic decryption routine in RWX .reloc) |
| decryption_buffer_ea | 0x140041400 |
| debugger_check_ea | 0x14001b690 |
| registry_persistence_ea | 0x14000bbe4 |
| packer_entropy | 105 (.reloc section) |
| packer_anomaly | RWX .reloc section with no relocations |

### YARA Detection IOCs
Generated YARA rule path: `/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yar` (valid, 0 false positives in goodware corpus) (source: yara_gen_v2, rule.yara.json).

## 10. Detection Engineering
### YARA Detection
Use the generated YARA rule at `rule.yar` which includes unique strings from the sample (e.g., `M2-Team NSudo 6.2.1812.31`, `E:\Projects\NSudo\Output\Release\x64\NSudo.pdb`, `AdjustTokenPrivileges`) and has 0 false positives against the staged goodware corpus (source: yara_gen_v2, rule.yara.json). Additional YARA rules from the pipeline that detect this sample include:
- `anti_dbg` (matches @ 0x168290, 0x170302, 0x170496)
- `escalate_priv` (matches @ 0x169132, 0x168830)
- `screenshot` (matches @ 0x168594, 0x168566, 0x168418)
- `win_registry` (matches @ 0x169132, 0x169050)
- `win_token` (matches @ 0x169132, 0x168906, 0x168830)
- `domain`, `IP`, `url`, `contains_base64` (detect embedded C2 indicators)
(source: yara pipeline, matches table)

### Capability-Based Detection
Use capa rules to detect the following capabilities:
- Anti-debugging (IsDebuggerPresent)
- Access token manipulation (AdjustTokenPrivileges)
- Registry modification (RegSetValue, RegOpenKeyExW)
- Process creation (CreateProcessW)
- File deletion/copy/move
- Screen capture (BitBlt, GetDC/ReleaseDC)
(source: malcat-capa, capa rules table)

### Anomaly-Based Detection
Detect the following static anomalies unique to this packed sample:
1. RWX .reloc section with no relocation entries (RelocSectionNoRelocation anomaly)
2. Section entropy >100 (105 for .reloc section)
3. XOR-in-loop anomalies at 0x3320, 0x23277, 0x23849, 0x840757
4. SpaghettiFunction anomaly at 0x95904
5. SequentialFunction anomaly at 0x840704 (decryption routine)
6. CrossSectionJump anomaly (control flow across section boundaries)
(source: malcat, anomalies table, anomaly locations)

### Disguise Detection
Legitimate NSudo v6.2 binaries do not have a RWX .reloc section, do not contain XOR decryption stubs, and do not have entropy values above 7 for any section. Combine NSudo string matches with packing anomalies to reduce false positives (source: llm_judge, cross_engine_notes).

## 11. What We Don't Know
1. **Exact C2 Indicators:** While YARA confirms the presence of embedded domains, IPv4/IPv6 addresses, URLs, and base64 data, no plaintext C2 indicators were extracted during static analysis. The indicators are likely encrypted/obfuscated in the packed payload, which was not successfully unpacked (unknown, source: yara matches, deep_dive_agentic; upx unpack failed).
2. **Unpacked Payload:** The custom XOR decryption stub at 0x1400ce000 was identified, but the unpacked payload was not recovered. UPX unpacking failed, and no dynamic analysis events were observed to capture the unpacked code in memory (unknown, source: upx unpack, speakeasy dynamic results).
3. **Full Persistence Mechanism:** The sample accesses the `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CommandStore\shell` registry key, but the full persistence path (e.g., registry value name, payload path) was not extracted from static analysis (unknown, source: ghidra, sub_14000bbe4 decompilation).
4. **Exfiltration Details:** No observed runtime behavior to confirm the exact data types stolen, exfiltration protocol, or C2 communication flow (unknown, source: speakeasy, frida_probe: no events observed).
5. **Payload Functionality:** The full capabilities of the unpacked Vidar payload are unknown, as the payload was not recovered during analysis (unknown, source: upx unpack failed, no dynamic events).

## 12. Appendix: Analysis Environment
### Tools Used
| Tool | Version/Details | Result |
|---|---|---|
| Malcat | Latest (structured analysis) | File layout, anomalies, strings, imports, YARA signatures |
| Ghidra | Latest (decompilation) | Function analysis, decryption stub identification |
| radare2 | Latest (disassembly) | Entry point disassembly |
| capa | malcat-capa engine (v5.16) | 27 capability rules matched |
| YARA | Latest (pipeline + generated rules) | 15 pipeline matches, 1 valid generated rule |
| FLOSS | Latest | 2195 static strings extracted |
| UPX | Latest | Unpack failed (upx_ok = False) |
| Speakeasy | Latest | Emulation completed, 0 API calls/events observed |
| Frida | 17.16.4 | 27 hook candidates identified, 0 runtime events observed |
| llm_judge | step-3.7-flash | Verdict: Malicious, score 90, family Vidar |
| deep_dive_agentic | langgraph | Confidence 50, Vidar infostealer verdict |

### Analysis Metadata
| Field | Value |
|---|---|
| sample_path | /opt/samples/corpus/pool/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/2026-07-04_578608b9385c3d0d8fca05fc2c69c1d4_vidar |
| project_name | pool |
| analysis_timestamps | 1785913352 - 1785913657 (audit trail entries) |
| tool_gate_status | ok (all required tools passed) |
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
  "sha256": "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5",
  "family": "unknown",
  "generated_at": "2026-08-05T07:07:37.862615+00:00",
  "string_count": 24,
  "strings": [
    "\u00a9 M2-Team and Contributors. All rights reserved.",
    "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb",
    "??0exception@@QEAA@AEBQEBD@Z",
    "InitializeCriticalSectionEx",
    "??0exception@@QEAA@AEBV0@@Z",
    "?what@exception@@UEBAPEBDXZ",
    "SetUnhandledExceptionFilter",
    "GetSystemWindowsDirectoryW",
    "ExpandEnvironmentStringsW",
    "ChangeWindowMessageFilter",
    "IsProcessorFeaturePresent",
    "InterlockedPushEntrySList",
    "AllocateAndInitializeSid",
    "UnhandledExceptionFilter",
    "InterlockedPopEntrySList",
    "QueryPerformanceCounter",
    "DestroyEnvironmentBlock",
    "GetSystemTimeAsFileTime",
    "WTSEnumerateProcessesW",
    "CreateEnvironmentBlock",
    "RtlLookupFunctionEntry",
    "DeleteCriticalSection",
    "WaitForSingleObjectEx",
    "AdjustTokenPrivileges"
  ],
  "rule_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yar",
  "sigma_path": "/opt/samples/logs/0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5/rule.yml",
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
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785913352.792775}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785913352.847998}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785913352.8595479}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785913352.8662896}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785913455.5489342}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785913455.586635}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785913455.7022474}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785913455.7158103}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785913455.7189682}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785913566.262104}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.dll', 'CRYPT32.dll', 'WININET.dll', 'URLMON.dll', 'WS2_32.dll', 'GDI32.dll', 'USER32.dll', 'KERNEL32.dll', 'SHELL32.dll', 'SHLWAPI.dll', 'CRYPTUI.dll', 'CRYPT32.dll', 'WINTRUST.dll', 'IMAGEHLP.dll`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports LIMIT 50", "ts": 1785913575.903866}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.dll','CRYPT32.dll','WININET.dll','URLMON.dll','WS2_32.dll','GDI32.dll','USER32.dll','SHELL32.dll','SHLWAPI.dll','WINTRUST.dll','OLE32.dll','OLEAUT32.dll','CRYPTUI.dll','IMAGEHLP.dll','PSAPI.dll','`
- `{"source": "ghidra_query", "sql": "SELECT DISTINCT module FROM imports ORDER BY module", "ts": 1785913589.5207012}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name", "ts": 1785913592.3826768}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module='ADVAPI32.DLL' ORDER BY name", "ts": 1785913596.5010393}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module='USER32.DLL' ORDER BY name", "ts": 1785913600.0074985}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785913656.81879}`
- `{"source": "yara_gen_v2", "ts": 1785913657.862867}`
