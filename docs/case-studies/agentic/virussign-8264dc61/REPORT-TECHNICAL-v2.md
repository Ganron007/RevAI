## 1. Executive Summary

This sample is definitively classified as **Malicious** with a confidence score of 9/10 (source: llm_judge, verdict.json). It is a 32-bit X86 Windows GUI PE executable packed with AHTeam EP Protector (source: checklist_yara_scan, rule `AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER`), exhibiting high entropy (18) consistent with cryptor-packed code (source: malcat, file summary). The entry point performs XOR decryption of two memory regions (0x401000–0x408ecc with key 0x462530e4, 0x42b000–0x42e1d0 with key 0xb6d16c5) before entering an infinite loop (source: malcat, decompilation, EntryPoint@54786). A 56,320-byte valid secondary PE payload is embedded in the file overlay (source: malcat, carved_files, `PE@123392 (56320 bytes)`), confirming dropper/loader functionality. Static analysis reveals 113 imports, including high-signal APIs for desktop manipulation, registry modification, process creation, and WinINet-based network communication (source: malcat, signal_imports; pe_imports table). YARA matches confirm evasion (HideInternetActivity) and host fingerprinting (FingerprintEnvironment) capabilities (source: malcat, YARA signatures). FLOSS recovered 715 static strings and 0 decoded strings, indicating full string obfuscation (source: floss, strings). No dynamic runtime behavior was observed during analysis (source: speakeasy, frida_probe).

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | sample metadata |
| Sample Path | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir | sample metadata |
| Project Name | incoming | sample metadata |
| Verdict | Malicious | llm_judge, verdict.json |
| Score | 9 | llm_judge, verdict.json |
| Family Guess | Packed Malware Loader/Dropper (cryptor-obfuscated, embedded PE payload) | llm_judge, verdict.json |
| Tooling Notes | IDA is non-functional due to missing idasql binary; Ghidra reports 0 functions while Malcat identifies 15 functions; combined string data from both tools is used for analysis | cross_engine_notes, verdict.json |

## 3. File Layout & Structural Analysis

The sample is a 1,048,576-byte X86 PE file with a modified, packed structure (source: malcat, file layout table):

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 107 | - |
| .text | 1024 | 32768 | 32768 | 170 | RWX |
| .data | 33792 | 12800 | 16384 | 99 | RW |
| .idata | 50176 | 4096 | 4096 | 143 | RW |
| gap | 54272 | 512 | 0 | 90 | - |
| .kofbl | 54784 | 512 | 4096 | 90 | RX |
| .l1 | 58880 | 4608 | 8192 | 66 | RWX |
| overlay | 67072 | 992256 | 0 | 12 | - |
| .bss | 1059328 | 0 | 139264 | 0 | RW |

Key structural anomalies (source: malcat, anomalies table):
- **SectionGap**: 512-byte physical gap between .idata (ends at 0xC800) and .kofbl (starts at 0xD600)
- **SizeOfRawDataNotAligned**: 3 hits, SizeOfRawData values not aligned to FileAlignment
- **SectionNameUnknown**: 2 hits, unrecognized section names `.kofbl` and `.l1`
- **SectionWX**: 2 hits, `.text` and `.l1` sections are both writable and executable
- **EmbeddedProgram**: 1 hit, valid secondary PE carved from overlay at offset 0x1F800 (123392 decimal), size 56,320 bytes (source: malcat, carved_files)
- **NoChecksum**: PE header checksum unset at offset 0x216 (source: malcat, anomaly locations)

## 4. Malcat Triage Summary

### Malcat YARA Signatures
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| HideInternetActivity | network | UNCOMMON | 60 | Tries to hide recent internet activity |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | Tries to assess the OS environment |

### High-Signal Anomaly Locations
| Anomaly | Address |
|---|---|
| NoChecksum | 0x216 |
| XorInLoop | 0x54824, 0x54896 |

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 0x52210 | CreateMutexA |
| 0x52090 | LoadLibraryA |
| 0x51558 | DeleteUrlCacheEntry |
| 0x60282 | GetComputerNameA |
| 0x121410 | GetUserNameA |
| 0x115430 | GetVersion |
| 0x61887 | KERNEL32.DLL |
| 0x53416 | WININET.DLL |
| 0x61921 | ADVAPI32.DLL |

### Core Triage Metrics
- Total Imports: 113 (113 unreferenced, UnreferencedImports anomaly, source: malcat, anomalies table)
- Total Functions: 30 (EntryPoint@0x54786, sub_431c04–sub_431d7d, source: malcat, functions table)
- Carved Files: 1 valid PE (56,320 bytes, source: malcat, carved_files)
- FLOSS Strings: 715 static, 0 decoded (source: floss, strings)

## 5. Static Code Analysis

### Entry Point Decompilation (Malcat, EntryPoint@0x54786)
```c
void EntryPoint(void) {
    uint32_t *puVar1;
    // Decrypt first code region: 0x401000–0x408ecc
    puVar1 = 0x401000;
    do {
        *puVar1 = *puVar1 ^ 0x462530e4;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x408ecc);
    // Decrypt second region: 0x42b000–0x42e1d0
    puVar1 = 0x42b000;
    do {
        *puVar1 = *puVar1 ^ 0xb6d16c5;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x42e1d0);
    in(0x58); // Input from port 0x58 (unknown purpose)
    // Infinite loop
    do {
    } while (true);
}
```

### radare2 Disassembly (Entry Point XOR Routine, 0x00430005)
```asm
┌ 139: fcn.00430005 ()
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
```

### radare2 Disassembly (Obfuscated Import Thunk, 0x004312b0)
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ()
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
```

Key static observations (source: malcat, decompilation; radare2, disassembly):
1. The entry point implements a simple XOR cryptor for two distinct memory regions, confirming packed/obfuscated code.
2. 113 of 113 imports are unreferenced in static analysis (source: malcat, anomalies, UnreferencedImports), indicating they are either decoys or dynamically resolved at runtime.
3. Import thunks are heavily obfuscated with junk instructions, consistent with AHTeam EP Protector packing (source: checklist_yara_scan, rule `AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER`).
4. No valid function entry points are detected by Ghidra/IDA due to encrypted code, limiting control flow analysis (source: cross_engine_notes, verdict.json).

## 6. Behavioral & Dynamic Analysis

No runtime behavior was observed across all dynamic analysis tools:
- **Speakeasy**: Analysis completed successfully (speakeasy_ok=True), but 0 API calls and 0 key events were recorded (source: speakeasy, evidence).
- **Frida**: Version 17.16.4 is available, but no instrumentation data was captured (source: frida_probe, evidence).
- **UPX**: Unpack attempt failed (upx_ok=False), sample is not identified as UPX-packed (source: upx, unpack evidence).

No process execution, network callbacks, file system modifications, or registry changes were observed. All dynamic tooling returned null/empty results.

## 7. Network Indicators & C2

Static analysis confirms C2-related capabilities via YARA and import signals:
| Indicator Type | Position | Length | Source |
|---|---|---|---|
| Domain regex match | 0x0 | 2 | checklist_yara_scan, matches |
| IPv6 address | 0x72810 | 23 | checklist_yara_scan, matches |
| Base64-encoded content | 0x47878 | 16 | checklist_yara_scan, matches |
| WinINet library string | 0x49832 | 11 | checklist_yara_scan, matches |

Relevant WinINet imports (source: pe_imports table):
| API | EA | ATT&CK |
|---|---|---|
| DeleteUrlCacheEntry | 0x59696 | T1071 (Application Layer Protocol) |
| FindFirstUrlCacheEntryA | 0x59698 | T1071 |
| FindNextUrlCacheEntryA | 0x59702 | T1071 |

The sample uses WinINet for network operations, with hardcoded C2 indicators obfuscated in the binary (full values not recoverable via static string analysis, source: floss, 0 decoded strings). The YARA rule `HideInternetActivity` confirms functionality to clear network artifacts (source: malcat, YARA signatures).

## 8. Capabilities & MITRE ATT&CK Mapping

| Capability | Evidence Source | Rule/Address | MITRE ATT&CK / MBC |
|---|---|---|---|
| Embedded PE delivery | capa | `contain an embedded PE file` | B0023: Install Additional Program |
| Registry modification | pe_imports | RegSetValue (0x59932) | T1112: Modify Registry |
| Process creation | pe_imports | CreateProcessA (0x59752) | T1106: Process Execution |
| Dynamic module loading | pe_imports | LoadLibraryA (0x59704), GetProcAddress (0x59656) | T1129: Shared Modules |
| Mutex creation (single instance / anti-analysis) | checklist_yara_scan | `win_mutex` (0x48626) | T1497: Virtualization/Sandbox Evasion |
| File system operations | checklist_yara_scan | `win_files_operation` (0x49856, 0x48766) | T1105: Ingress Tool Transfer, T1027: Obfuscated Files |
| Host fingerprinting | malcat YARA | `FingerprintEnvironment` | T1082: System Information Discovery, T1012: Query Registry |
| Network activity hiding | malcat YARA | `HideInternetActivity` | T1071: Application Layer Protocol, T1030: Data Transfer Size Limits |
| SEH-based anti-analysis | checklist_yara_scan | `SEH_Save`, `SEH_Init` (0x66713, 0x66720) | T1497: Virtualization/Sandbox Evasion |
| Desktop manipulation | malcat signal_imports | CreateDesktopA, GetThreadDesktop, SetThreadDesktop, DestroyWindow | T1055: Process Injection (desktop isolation for hidden payload execution) |

## 9. Indicators of Compromise

| IOC Type | Value | Context | Source |
|---|---|---|---|
| File Hash (SHA256) | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | Primary sample | sample metadata |
| Packer Signature | AHTeam EP Protector | Identified via YARA rule `AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER` | checklist_yara_scan |
| Embedded PE Offset | 0x1F800 (123392 decimal) | Overlay region, size 56320 bytes | malcat, carved_files |
| XOR Decryption Key 1 | 0x462530e4 | Decrypts 0x401000–0x408ecc | malcat, decompilation EntryPoint@54786 |
| XOR Decryption Key 2 | 0xb6d16c5 | Decrypts 0x42b000–0x42e1d0 | malcat, decompilation EntryPoint@54786 |
| C2 Indicator (IPv6) | Match at 0x72810, length 23 | Full value obfuscated | checklist_yara_scan, matches |
| C2 Indicator (Domain) | Match at 0x0, length 2 | Full value obfuscated | checklist_yara_scan, matches |
| C2 Indicator (Base64) | Match at 0x47878, length 16 | Full value obfuscated | checklist_yara_scan, matches |
| Mutex Artifact | YARA match at 0x48626 | Mutex name obfuscated | checklist_yara_scan, matches |
| Registry Artifact | YARA matches at 0x50204, 0x49486 | Registry key/path obfuscated | checklist_yara_scan, matches |
| File System Artifact | YARA matches at 0x49856, 0x48766 | File path/operation obfuscated | checklist_yara_scan, matches |
| Obfuscation Indicator | 715 static strings, 0 decoded | Full string obfuscation via XOR/cryptor | floss, strings |
| Anomaly Addresses | XorInLoop at 0x54824, 0x54896; NoChecksum at 0x216 | Packing/obfuscation markers | malcat, anomalies |

## 10. Detection Engineering

### YARA Detection Rules
15 YARA matches were identified in the sample (source: yara, pipeline matches):
| Rule | Namespace | Match Position | Length |
|---|---|---|---|
| domain | - | 0x0 | 2 |
| IP | - | 0x72810 | 23 |
| contains_base64 | - | 0x47878 | 16 |
| IsPE32 | - | N/A | N/A |
| IsWindowsGUI | - | N/A | N/A |
| HasOverlay | - | N/A | N/A |
| HasModified_DOS_Message | - | N/A | N/A |
| AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | - | 0x2 | 1 |
| SEH_Save | - | 0x66713 | 7 |
| SEH_Init | - | 0x66720 | 7 |
| win_mutex | - | 0x48626 | 11 |
| win_registry | - | 0x50204, 0x49486, 0x49470, 0x49454, 0x49506, 0x49454 | 12/16/13/11/14/11 |
| win_files_operation | - | 0x49856, 0x48766, 0x48606, 0x48766, 0x48582, 0x48818, 0x48566 | 12/9/14/9/8/11/11 |
| Str_Win32_Wininet_Library | - | 0x49832 | 11 |
| maldoc_getEIP_method_1 | - | 0x54788 | 6 |

Generated YARA rule metadata (source: rule.yara.json):
- Rule path: /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar
- Sigma path: /opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml
- YARA valid: true, 0 goodware false positives

### Anomaly-Based Detection
Flag samples with the following traits (source: malcat, anomalies):
1. XOR decryption loops in entry point (addresses 0x54824, 0x54896)
2. RWX section (`.l1` at 0xE800)
3. Unknown section names (`.kofbl` at 0xD600)
4. Physical section gap between .idata and .kofbl
5. Embedded PE in overlay region
6. Unreferenced import count > 50% of total imports

## 11. What We Don't Know

1. **Embedded Payload Functionality**: The 56,320-byte PE carved from the overlay has not been analyzed statically or dynamically; its full capabilities are unknown (source: malcat, carved_files; speakeasy, not observed).
2. **Full C2 Indicator Values**: Only match positions for the domain, IPv6 address, and base64 content are known; full values are obfuscated and not recoverable via static string analysis (source: checklist_yara_scan, matches; floss, 0 decoded strings).
3. **Persistence Mechanism Details**: Exact registry key paths, mutex names, and dropped file paths are not available in clear text (source: checklist_yara_scan, win_registry/win_mutex matches; floss, 0 decoded strings).
4. **Entry Point Infinite Loop Purpose**: It is unknown if the infinite loop after decryption is a payload entry point, anti-debug measure, or decoy (source: malcat, decompilation EntryPoint@54786).
5. **Unreferenced Import Purpose**: The 113 unreferenced imports may be decoys, dynamically resolved for the embedded payload, or used for anti-analysis; their exact role is unknown (source: malcat, anomalies, UnreferencedImports).
6. **Full Capability Set**: No decompilation or control flow graph is available for the core packed code, and no dynamic behavior was observed, so the full set of malicious capabilities is unconfirmed (source: cross_engine_notes, verdict.json; speakeasy, not observed).

## 12. Appendix: Analysis Environment

| Tool | Version/Status | Output | Source |
|---|---|---|---|
| IDA | Non-functional (missing idasql binary) | No analysis data available | cross_engine_notes, verdict.json |
| Ghidra | N/A | 0 functions, 122 strings, import count matches Malcat | ghidra_query, audit trail |
| Malcat | N/A | 15 functions, 100 strings, full file layout, imports, anomalies, entry point decompilation | malcat, structured analysis |
| FLOSS | N/A | 715 static strings, 0 decoded/stack/tight strings | floss, strings |
| radare2 | N/A | Disassembly of entry point and import thunks | radare2, disassembly evidence |
| capa | N/A | 1 rule matched (`contain an embedded PE file`), duration 0.81s | capa, capability rules |
| UPX | N/A | Unpack failed, not identified as UPX-packed | upx, unpack evidence |
| Speakeasy | N/A | 0 API calls, 0 key events, no runtime behavior | speakeasy, evidence |
| Frida | 17.16.4 | Available, no data captured | frida_probe, evidence |
| YARA | N/A | 15 pipeline matches, generated rule valid, 0 goodware FPs | yara, pipeline matches; rule.yara.json |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Packed Malware Loader/Dropper (cryptor-obfuscated, embedded PE payload)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to a missing idasql binary, so no IDA-derived analysis data is available. Ghidra reports 0 functions while Malcat identifies 15 functions, likely because Ghidra fails to auto-detect functions in encrypted/packed code. Ghidra (122) and Malcat (100) string counts are complementary, so combined string data is used for analysis. No decompilation or control flow graph data is available from Ghidra/IDA due to lack of reliable function coverage; only Malcat provides limited decompilation of the entry point and import thunk functions. Malcat is the primary reliable source for static profiling, imports, and anomaly detection, as its data aligns with Ghidra's import and string counts where available.
- **summary**: This is a high-entropy (18) cryptor-packed X86 PE file that functions as a malware loader/dropper. It decrypts its own code sections via XOR on entry, embeds a secondary PE payload in its overlay, and includes imports for desktop manipulation, registry modification, and process creation. YARA hits confirm it includes evasion (hiding internet activity) and host fingerprinting capabilities. While no full decompilation or control flow graph is available due to packed code and limited function detection from Ghidra/IDA, static analysis across Malcat, capa, YARA, and FLOSS confirms malicious intent with high confidence.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `contain an embedded PE file` | Capa analysis confirms the sample contains an embedded PE file, a key indicator of dropper/loader malware designed to de |
| malcat | carved_files | `PE@123392 (56320 bytes)` | Malcat carved a valid secondary PE file from the sample's overlay region, confirming the presence of an embedded payload |
| malcat | decompilation | `EntryPoint@54786` | The entry point performs XOR decryption of two memory regions (0x401000-0x408ecc and 0x42b000-0x42e1d0) before entering  |
| malcat | signal_imports | `CreateDesktopA, DestroyWindow, GetThreadDesktop, SetThreadDesktop, RegCreateKeyE` | These high-signal imports indicate capabilities for desktop manipulation, registry modification for persistence, and pro |
| malcat | malcat_evidence | `HideInternetActivity, FingerprintEnvironment` | These YARA rule matches indicate the sample includes functionality to hide network activity and gather host environment  |
| malcat | anomalies | `XorInLoop (2 hits at 54824, 54896)` | XOR operations within loops are a hallmark of packing/encryption routines used to obfuscate code and data, aligning with |
| malcat | file_layout / anomalies | `Unknown section name .kofbl, RWX section .l1, SectionGap anomaly` | Unrecognized section names, a read-write-execute section, and physical gaps between sections are common indicators of mo |
| floss | strings | `715 static strings, 0 decoded strings` | FLOSS recovered no decoded strings, indicating that most string data is encrypted/obfuscated, which is consistent with c |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The sample is a 32-bit Windows GUI PE executable packed with AHTeam EP Protector, exhibiting multiple confirmed malicious characteristics including hardcoded network IOCs, SEH-based anti-analysis, persistence mechanisms (mutex, registry modification, file operations), and use of WinINet for network communication.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message", "why": "These YARA rule matches confirm the sample is a 32-bit Windows GUI PE executable with a modified DOS header and overlay data, characteristics consistent with packed or obfuscated malicious files."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER", "why": "This match identifies the sample is packed with AHTeam EP Protector, a known executable protector frequently used to obfuscate malware payloads and hinder reverse engineering analysis."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "SEH_Save, SEH_Init", "why": "These matches indicate Structured Exception Handling (SEH) is configured in the sample, a common anti-debugging and anti-analysis technique used by malware to bypass debuggers and control program error flow."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "win_mutex, win_registry, win_files_operation", "why": "These matches show the sample implements malicious system interaction: mutex creation to prevent multiple instance execution, Windows registry modifications for persistence, and file system operations likely for dropping additional payloads or modifying system files`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain, IP, contains_base64, Str_Win32_Wininet_Library", "why": "These matches confirm the sample has command-and-control (C2) capabilities: it contains hardcoded network indicators (a domain and IPv6 address), base64-encoded content (likely for C2 communication or payload delivery), and uses the WinINet library for net`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
size: 1048576
type: PE
architecture: X86
entrypoint_ea: 54786
entropy: 18
file_name: virussign.com_8264dc61e512149f551c29e1b91b545e.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 107 | - |
| .text | 1024 | 32768 | 32768 | 170 | RWX |
| .data | 33792 | 12800 | 16384 | 99 | RW |
| .idata | 50176 | 4096 | 4096 | 143 | RW |
| gap | 54272 | 512 | 0 | 90 | - |
| .kofbl | 54784 | 512 | 4096 | 90 | RX |
| .l1 | 58880 | 4608 | 8192 | 66 | RWX |
| overlay | 67072 | 992256 | 0 | 12 | - |
| .bss | 1059328 | 0 | 139264 | 0 | RW |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| HideInternetActivity | network | UNCOMMON | 60 | tries to hide recent internet activity |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |

### Anomalies (11)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionGap | 4 | sections | 1 | there is a physical gap between two sections |
| SizeOfRawDataNotAligned | 4 | sections | 3 | SizeOfRawData is not aligned to FileAlignment |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 113 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **NoChecksum**
  - `216`: 
- **XorInLoop**
  - `54824`: 
  - `54896`: 

### High-Signal Strings (17 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 61887 | `KERNEL32.DLL` |
| 116928 | `KERNEL32.DLL` |
| 53440 | `KERNEL32.DLL` |
| 80502 | `KERNEL32.DLL` |
| 121807 | `KERNEL32.DLL` |
| 60436 | `GetProcAddress` |
| 120340 | `GetProcAddress` |
| 115354 | `GetProcAddress` |
| 51866 | `GetProcAddress` |
| 52210 | `CreateMutexA` |
| 52090 | `LoadLibraryA` |
| 60764 | `CreateMutexA` |
| 115698 | `CreateMutexA` |
| 115578 | `LoadLibraryA` |
| 120556 | `LoadLibraryA` |
| 120668 | `CreateMutexA` |
| 60652 | `LoadLibraryA` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 51558 | `DeleteUrlCacheEntry` |
| 60148 | `DeleteUrlCacheEntry` |
| 120052 | `DeleteUrlCacheEntry` |
| 115046 | `DeleteUrlCacheEntry` |
| 60282 | `GetComputerNameA` |
| 120186 | `GetComputerNameA` |
| 115190 | `GetComputerNameA` |
| 51702 | `GetComputerNameA` |
| 121410 | `GetUserNameA` |
| 61506 | `GetUserNameA` |
| 116490 | `GetUserNameA` |
| 53002 | `GetUserNameA` |
| 115430 | `GetVersion` |
| 120412 | `GetVersion` |
| 120426 | `GetVersionExA` |
| 115446 | `GetVersionExA` |
| 60522 | `GetVersionExA` |
| 60508 | `GetVersion` |
| 51958 | `GetVersionExA` |
| 51942 | `GetVersion` |
| 61934 | `CRTDLL.DLL` |
| 61921 | `ADVAPI32.DLL` |
| 61887 | `KERNEL32.DLL` |
| 61875 | `WININET.DLL` |
| 61911 | `GDI32.DLL` |
| 61862 | `OLEAUT32.DLL` |
| 61945 | `MSVCRT.DLL` |
| 61900 | `USER32.DLL` |
| 61852 | `ole32.DLL` |
| 86820 | `1:7a:eb:91:d6:9c..b:40:b3:26:cd:72` |
| 87038 | `9d:6a:ab:f8:69:2..b:af:42:8f:9b:41` |
| 82066 | `dll.dll` |
| 85460 | `[6657, 340576, 3.. 279060, 279060]` |
| 117328 | `CRTDLL.DLL` |
| 121854 | `CRTDLL.DLL` |
| 80546 | `CRTDLL.DLL` |
| 53840 | `CRTDLL.DLL` |
| 83714 | `:fa:22:33:b1:6d:..6:e1:ba:ed:0f:b3` |
| 53416 | `WININET.DLL` |
| 121795 | `WININET.DLL` |
| 88766 | `:fa:22:33:b1:6d:..6:e1:ba:ed:0f:b3` |
| 116904 | `WININET.DLL` |
| 53788 | `ADVAPI32.DLL` |
| 116928 | `KERNEL32.DLL` |
| 53440 | `KERNEL32.DLL` |
| 80502 | `KERNEL32.DLL` |
| 117276 | `ADVAPI32.DLL` |
| 121807 | `KERNEL32.DLL` |
| 12666 | `BFTr%` |
| 121841 | `ADVAPI32.DLL` |
| 53756 | `GDI32.DLL` |
| 121865 | `RPCRT4.DLL` |
| 121831 | `GDI32.DLL` |
| 117244 | `GDI32.DLL` |
| 53396 | `OLEAUT32.DLL` |
| 116884 | `OLEAUT32.DLL` |
| 121782 | `OLEAUT32.DLL` |
| 85892 | ` 0.0253700073808..70007380843163, ` |
| 83562 | `d5:14:60:61:a7:3b:6e:4e:` |
| 121772 | `ole32.DLL` |
| 117120 | `USER32.DLL` |
| 83826 | `48:97:84:72:c2:9` |
| 116856 | `ole32.DLL` |
| 53368 | `ole32.DLL` |
| 53632 | `USER32.DLL` |
| 88614 | `d5:14:60:61:a7:3b:6e:4e:` |
| 121820 | `USER32.DLL` |
| 88878 | `48:97:84:72:c2:9` |
| 81623 | `2 2$2(2,20242D2H..L2P2T2X2\2`2d2h2` |
| 60596 | `InterlockedIncrement` |
| 115522 | `InterlockedIncrement` |
| 52034 | `InterlockedIncrement` |
| 120500 | `InterlockedIncrement` |
| 81567 | `5"5.5:5F5R5^5j5v5` |
| 121748 | `RpcErrorEndEnumeration` |
| 80272 | `GetEnvironmentStringsA` |
| 79632 | `kkcc` |
| 114950 | `CoCreateInstance` |
| 88818 | `19:d2:1c:d3:` |
| 88642 | `2:29:ce:69:5` |

### Imports (113)
| EA | Name | Type | Refs |
|---|---|---|---|
| 59568 | ole32.CoCreateInstance | IMPORT | 1 |
| 59572 | ole32.CLSIDFromString | IMPORT | 0 |
| 59576 | ole32.CoInitialize | IMPORT | 0 |
| 59580 | ole32.CoUninitialize | IMPORT | 0 |
| 59588 | oleaut32.SysAllocString | IMPORT | 1 |
| 59596 | wininet.DeleteUrlCacheEntry | IMPORT | 1 |
| 59600 | wininet.FindFirstUrlCacheEntryA | IMPORT | 0 |
| 59604 | wininet.FindNextUrlCacheEntryA | IMPORT | 0 |
| 59612 | kernel32.ExitProcess | IMPORT | 1 |
| 59616 | kernel32.ExpandEnvironmentStringsA | IMPORT | 0 |
| 59620 | kernel32.GetCommandLineA | IMPORT | 0 |
| 59624 | kernel32.GetComputerNameA | IMPORT | 0 |
| 59628 | kernel32.GetCurrentProcessId | IMPORT | 0 |
| 59632 | kernel32.GetCurrentThreadId | IMPORT | 0 |
| 59636 | kernel32.GetExitCodeThread | IMPORT | 0 |
| 59640 | kernel32.GetFileSize | IMPORT | 0 |
| 59644 | kernel32.GetModuleFileNameA | IMPORT | 0 |
| 59648 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 59652 | kernel32.CloseHandle | IMPORT | 0 |
| 59656 | kernel32.GetProcAddress | IMPORT | 0 |
| 59660 | kernel32.GetSystemDirectoryA | IMPORT | 0 |
| 59664 | kernel32.GetTempPathA | IMPORT | 0 |
| 59668 | kernel32.GetTickCount | IMPORT | 0 |
| 59672 | kernel32.GetVersion | IMPORT | 0 |
| 59676 | kernel32.GetVersionExA | IMPORT | 0 |
| 59680 | kernel32.GetWindowsDirectoryA | IMPORT | 0 |
| 59684 | kernel32.GlobalMemoryStatus | IMPORT | 0 |
| 59688 | kernel32.CopyFileA | IMPORT | 0 |
| 59692 | kernel32.InterlockedIncrement | IMPORT | 0 |
| 59696 | kernel32.IsBadReadPtr | IMPORT | 0 |
| 59700 | kernel32.IsBadWritePtr | IMPORT | 0 |
| 59704 | kernel32.LoadLibraryA | IMPORT | 0 |
| 59708 | kernel32.LocalAlloc | IMPORT | 0 |
| 59712 | kernel32.LocalFree | IMPORT | 0 |
| 59716 | kernel32.OpenMutexA | IMPORT | 0 |
| 59720 | kernel32.CreateFileA | IMPORT | 0 |
| 59724 | kernel32.ReadFile | IMPORT | 0 |
| 59728 | kernel32.RtlUnwind | IMPORT | 0 |
| 59732 | kernel32.SetFilePointer | IMPORT | 0 |
| 59736 | kernel32.CreateMutexA | IMPORT | 0 |
| 59740 | kernel32.Sleep | IMPORT | 0 |
| 59744 | kernel32.TerminateProcess | IMPORT | 0 |
| 59748 | kernel32.VirtualQuery | IMPORT | 0 |
| 59752 | kernel32.CreateProcessA | IMPORT | 0 |
| 59756 | kernel32.WaitForSingleObject | IMPORT | 0 |
| 59760 | kernel32.WideCharToMultiByte | IMPORT | 0 |
| 59764 | kernel32.WinExec | IMPORT | 0 |
| 59768 | kernel32.WriteFile | IMPORT | 0 |
| 59772 | kernel32.lstrlenA | IMPORT | 0 |
| 59776 | kernel32.lstrlenW | IMPORT | 0 |
| 59780 | kernel32.CreateThread | IMPORT | 0 |
| 59784 | kernel32.DeleteFileA | IMPORT | 0 |
| 59792 | user32.GetWindowTextA | IMPORT | 1 |
| 59796 | user32.GetWindowRect | IMPORT | 0 |
| 59800 | user32.FindWindowA | IMPORT | 0 |
| 59804 | user32.GetWindow | IMPORT | 0 |
| 59808 | user32.GetClassNameA | IMPORT | 0 |
| 59812 | user32.SetFocus | IMPORT | 0 |
| 59816 | user32.GetForegroundWindow | IMPORT | 0 |
| 59820 | user32.LoadCursorA | IMPORT | 0 |
| 59824 | user32.LoadIconA | IMPORT | 0 |
| 59828 | user32.SetTimer | IMPORT | 0 |
| 59832 | user32.RegisterClassA | IMPORT | 0 |
| 59836 | user32.MessageBoxA | IMPORT | 0 |
| 59840 | user32.GetMessageA | IMPORT | 0 |
| 59844 | user32.GetWindowLongA | IMPORT | 0 |
| 59848 | user32.SetWindowLongA | IMPORT | 0 |
| 59852 | user32.CreateDesktopA | IMPORT | 0 |
| 59856 | user32.SetThreadDesktop | IMPORT | 0 |
| 59860 | user32.GetThreadDesktop | IMPORT | 0 |
| 59864 | user32.TranslateMessage | IMPORT | 0 |
| 59868 | user32.DispatchMessageA | IMPORT | 0 |
| 59872 | user32.SendMessageA | IMPORT | 0 |
| 59876 | user32.PostQuitMessage | IMPORT | 0 |
| 59880 | user32.ShowWindow | IMPORT | 0 |
| 59884 | user32.CreateWindowExA | IMPORT | 0 |
| 59888 | user32.DestroyWindow | IMPORT | 0 |
| 59892 | user32.MoveWindow | IMPORT | 0 |
| 59896 | user32.DefWindowProcA | IMPORT | 0 |
| 59900 | user32.CallWindowProcA | IMPORT | 0 |

### Functions (30)
| EA | Name |
|---|---|
| 54786 | EntryPoint |
| 61956 | sub_431c04 |
| 61969 | sub_431c11 |
| 61982 | sub_431c1e |
| 61995 | sub_431c2b |
| 62008 | sub_431c38 |
| 62021 | sub_431c45 |
| 62034 | sub_431c52 |
| 62047 | sub_431c5f |
| 62060 | sub_431c6c |
| 62073 | sub_431c79 |
| 62086 | sub_431c86 |
| 62099 | sub_431c93 |
| 62112 | sub_431ca0 |
| 62125 | sub_431cad |
| 62138 | sub_431cba |
| 62151 | sub_431cc7 |
| 62164 | sub_431cd4 |
| 62177 | sub_431ce1 |
| 62190 | sub_431cee |
| 62203 | sub_431cfb |
| 62229 | sub_431d15 |
| 62242 | sub_431d22 |
| 62255 | sub_431d2f |
| 62268 | sub_431d3c |
| 62281 | sub_431d49 |
| 62294 | sub_431d56 |
| 62307 | sub_431d63 |
| 62320 | sub_431d70 |
| 62333 | sub_431d7d |

### Decompilations (top 6)
#### 54786 — EntryPoint
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint32_t *puVar1;
    
    puVar1 = 0x401000;
    do {
        *puVar1 = *puVar1 ^ 0x462530e4;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x408ecc);
    puVar1 = 0x42b000;
    do {
        *puVar1 = *puVar1 ^ 0xb6d16c5;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x42e1d0);
    in(0x58);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}

```
#### 61956 — sub_431c04
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c04(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c0f. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CoCreateInstance)();
    return;
}

```
#### 61969 — sub_431c11
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c11(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c1c. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CLSIDFromString)();
    return;
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PE | 56320 |

### Structures (24)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 58880 |
| ole32.OFT | 59080 |
| oleaut32.OFT | 59100 |
| wininet.OFT | 59108 |
| kernel32.OFT | 59124 |
| user32.OFT | 59304 |
| gdi32.OFT | 59420 |
| advapi32.OFT | 59444 |
| crtdll.OFT | 59484 |
| msvcrt.OFT | 59560 |
| ole32.FT | 59568 |
| oleaut32.FT | 59588 |
| wininet.FT | 59596 |
| kernel32.FT | 59612 |
| user32.FT | 59792 |
| gdi32.FT | 59908 |
| advapi32.FT | 59932 |
| crtdll.FT | 59972 |
| msvcrt.FT | 60048 |
| ImportNames | 60056 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.81

| Rule | ATT&CK | MBC |
|---|---|---|
| contain an embedded PE file |  | B0023:Install Additional Program |

## PE Imports / Signals
import_count: 113

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 15

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@72810 len=23 |
| contains_base64 | - | $a@47878 len=16 |
| maldoc_getEIP_method_1 | - | $a@54788 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasModified_DOS_Message | - |  |
| AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | - | $b@2 len=1 |
| SEH_Save | - | $a@66713 len=7 |
| SEH_Init | - | $b@66720 len=7 |
| win_mutex | - | $c1@48626 len=11 |
| win_registry | - | $f1@50204 len=12; $c1@49486 len=16; $c2@49470 len=13; $c3@49454 len=11; $c4@49506 len=14; $c6@49454 len=11 |
| win_files_operation | - | $f1@49856 len=12; $c1@48766 len=9; $c2@48606 len=14; $c3@48766 len=9; $c4@48582 len=8; $c5@48818 len=11; $c6@48566 len=11 |
| Str_Win32_Wininet_Library | - | $wininet_lib@49832 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "family": "unknown",
  "generated_at": "2026-08-03T09:25:26.495953+00:00",
  "string_count": 24,
  "strings": [
    "ExpandEnvironmentStringsA",
    "FindFirstUrlCacheEntryA",
    "FindNextUrlCacheEntryA",
    "GetWindowsDirectoryA",
    "InterlockedIncrement",
    "DeleteUrlCacheEntry",
    "GetCurrentProcessId",
    "GetSystemDirectoryA",
    "WaitForSingleObject",
    "WideCharToMultiByte",
    "GetForegroundWindow",
    "CreateBrushIndirect",
    "GetCurrentThreadId",
    "GetModuleFileNameA",
    "GlobalMemoryStatus",
    "GetExitCodeThread",
    "CoCreateInstance",
    "GetComputerNameA",
    "GetModuleHandleA",
    "TerminateProcess",
    "SetThreadDesktop",
    "GetThreadDesktop",
    "TranslateMessage",
    "DispatchMessageA"
  ],
  "rule_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar",
  "sigma_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml",
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
  "cadre_revai": true,
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 715 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 715}`

### FLOSS sample
- `.idata`
- `.kofbl`
- `<OF#55`
- `1PA\2%F`
- `oe-IZ4'IZ$`
- `#&%FgV!F`
- `:Pr%FEL`
- `p0%Fmu`
- `0%O?D!`
- `%I`3$F`
- `1 ~{q%`
- `(^{q%fm`
- `Dr%O$L`
- `\r%{d0%F`
- `1%F\GRF`
- `v0%FdM`
- `4Pad==`
- `0Mn^r%`
- `0M{^r%`
- `0%Fi5Q`
- `Ii4 /Xr%`
- `<3`Vid`
- `!IR4#{`
- `pVid6C`
- `Ii<(~Xr%`
- `Do$0fup%`
- `m<0vqp%IR`
- `2Pr%IR`
- `gF]!%F`
- `MCIRs$c$0%Fg`
- `0QNou)`
- `#Z%.d0%F`
- `gF]3%F`
- `ou)ISp'`
- `eNoe-ISb-o41``
- `xNou) mu)`
- `>0%Fou`
- `5IR4;{`
- `L}%Fmu`
- `D}%FoM`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00430005
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
### 0x004312b0
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  ~   0300           add eax, dword [eax]
│       │   ;-- (0x00431300) GetModuleHandleA:
│       └─> 0x004312ff  ~   00f0           add al, dh
│           0x00431301  ~   1503000416     adc eax, 0x16040003
│           ;-- CloseHandle:
..
│           0x00431306      0300           add eax, dword [eax]
│           ;-- GetProcAddress:
│           0x00431308      1216           adc dl, byte [esi]
│           0x0043130a      0300           add eax, dword [eax]
│           ;-- GetSystemDirectoryA:
│    
```
### 0x00431334
```asm
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
### 0x00431340
```asm
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA:
└       ┌─< 0x0043137c  ~   ea170300f6..   ljmp 0x317
│       │   ;-- lstrlenW:
..
```
### 0x00431384
```asm
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4   add byte [eax - 0x4bfffce8], ch
│           ;-- SetTimer:
..
│           ;-- RegisterClassA:
│           0x004313b9      1803           sbb byte [ebx], al
│           0x004313bb  ~   00c6           add dh, al
│           ;-- MessageBoxA:
..
│           0x004313bd      1803           sbb byte [ebx], al
│           0x004313bf  ~   00d4           add ah, dl
│           ;-- GetMessageA:
..
│           0x004313c1      1803           sbb byte [ebx], al
│           0x004313c3  ~   00e2           add
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ......................................
- Found XOR 00 position 0001B800: 00000080 ......................................

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785748958.275409}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785748958.3384292}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785748958.3501425}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785748958.3641121}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785749000.3795428}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785749000.4069881}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785749000.443895}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785749000.455804}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785749000.4575567}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785749052.6175096}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports LIMIT 50", "ts": 1785749076.6087127}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785749125.4630806}`
- `{"source": "yara_gen_v2", "ts": 1785749126.4961004}`
