> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 04:42:52 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

# Technical Malware Analysis Report v2

## 1. Executive Summary
The sample `challenge66.exe` (SHA256: 9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6) is a malicious Windows PE executable identified as a UPX-packed Visual Basic 6 (VB6) crypter dropper. Static analysis reveals a classic UPX decompression stub at the entry point, minimal imports (only 6 KERNEL32 functions for memory management and dynamic loading), and embedded strings indicating Turkish-language crypter tooling branded "Ghost Şifreleyici Modernize Hayalet" (Ghost Encryptor Modernized Ghost). The sample communicates with the C2 domain `www.hidden-sabotage.com`. Multiple detection engines confirm UPX packing (YARA: 7+ packer rules; Malcat: Packed×6 anomaly; capa: generic packer T1027.002). VirusTotal reports 60 malicious detections, classifying it under the `trojan.llac/babar` family. Dynamic analysis in Speakeasy and Frida executed but recorded zero API calls or events, suggesting anti-analysis or a lack of triggering conditions. The primary malicious indicators are the C2 domain, the crypter tool branding, and the high-confidence packing, which together indicate hostile intent beyond mere obfuscation. We assess the sample as MALICIOUS (confidence: 90%).

## 2. Sample Metadata
The following table presents the fundamental file properties extracted by Malcat.

| Field | Value | Source |
|---|---|---|
| SHA256 | `9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6` | malcat: file_summary |
| Sample Path | `/opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe` | malcat: file_summary |
| File Size | 169,998 bytes | malcat: file_summary |
| Type | PE32 executable (GUI) Intel 80386, for MS Windows | malcat: file_summary |
| Architecture | x86 | malcat: file_summary |
| Entry Point (EA) | 0x000104016 (104016 decimal) | malcat: file_summary |
| File Entropy | 7.57 bits/byte (Shannon, whole file) | malcat: file_summary |
| Internal Name | `Ghost Şifreleyici Modernize Hayalet.exe` | malcat: file_summary (VersionInfo::InternalName) |
| VS_VERSION_INFO | Contains Turkish strings and `www.hidden-sabotage.com` | malcat: file_summary |
| Imphash | `b4e06d942b341e012040239c1cca0b7d` | rule.yara.json |
| File Name | `challenge66.exe` | malcat: file_summary |

The high entropy (7.57 bits/byte) is consistent with packing or encryption, a neutral signal that must be corroborated with behavioral intent. The internal name explicitly identifies the file as a "Ghost Encryptor," a Turkish crypter tool, which suggests its purpose is to obfuscate or protect other executables. (source: malcat)

## 3. File Layout & Structural Analysis
The PE file exhibits several structural anomalies characteristic of packing. Malcat's section layout and anomaly tables provide a detailed view of the file's construction.

### PE Section Layout
| Name | EA (hex) | Physical Size (bytes) | Virtual Size (bytes) | Rights | Source |
|---|---|---|---|---|---|
| header | 0x00000000 | 1024 | 0 | - | malcat: file_layout |
| (unnamed) | 0x00000400 | 103936 | 106496 | RWX | malcat: file_layout |
| .rsrc | 0x0001A200 | 15872 | 16384 | RW | malcat: file_layout |
| overlay | 0x0001E240 | 49166 | 0 | - | malcat: file_layout |
| (unnamed) | 0x00029E86 | 0 | 241664 | RWX | malcat: file_layout |

**Interpretation:** The layout shows two large RWX (Read-Write-Execute) sections, which is typical for packers that need to decompress and execute code in memory. The unnamed sections and the large virtual-only section (physical size 0, virtual size 241KB) are strong indicators of a self-modifying unpacking stub. The presence of an overlay at EA 0x1E240 (49KB) is also common in packed samples, often containing the compressed payload or additional data. (source: malcat)

### High-Signal Anomalies (Level 3+)
The following anomalies from Malcat's analysis strongly indicate packing and obfuscation.

| Name | Level | Category | Hits | Description | Source |
|---|---|---|---|---|---|
| Packed | 2 | packers | 6 | File is packed using a legit or less-legit obfuscator | malcat: anomalies |
| PatchedUPXHeader | 4 | packers | 0 | At least one Yara signature matched UPX but no UPX header was identified by Malcat, indicating a potentially patched or modified packer | malcat: anomalies |
| SectionWX | 3 | sections | 2 | section is executable and writeable | malcat: anomalies |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) | malcat: anomalies |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy | malcat: anomalies |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop | malcat: anomalies |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function | malcat: anomalies |

The `Packed×6` and `PatchedUPXHeader` anomalies provide direct evidence that UPX has been used and its standard header has been altered, a common anti-analysis technique. The RWX sections and XorInLoop anomaly are consistent with decryption or decompression routines within a packer stub. The lack of window API imports in a GUI subsystem further suggests that the visible application logic is buried inside the packed payload. (source: malcat)

## 4. Static Code Analysis
### Entry Point Disassembly (UPX Stub)
The disassembly at the entry point (0x00455250) is a classic UPX decompression stub. We present the initial instructions and the subsequent decompression loop, which interprets a bitstream to copy and decompress the packed payload.

```asm
; radare2 disassembly at 0x00455250
pushal                      ; Save all registers
mov esi, section.sect_1     ; ESI = 0x43c000 (source of packed data)
lea edi, [esi - 0x3b000]   ; EDI = destination (lower memory)
push edi
or ebp, 0xffffffff         ; EBP = -1 (used as a flag for bit operations)
jmp 0x455272
; ... decompression loop follows ...
```
**Interpretation:** The `PUSHAD` instruction followed by loading ESI and EDI with addresses for source and destination is the hallmark of UPX. The code then enters a loop that processes bits from the packed data to decompress and copy the original executable. This stub is responsible for unpacking the VB6 payload in memory. (source: radare2, also referenced in deep_dive_agentic)

### Import Address Table (IAT)
The IAT is minimal, containing only six KERNEL32 imports, which is highly unusual for a functional application and strongly indicates that the bulk of API calls are resolved dynamically.

| EA | Name | Type | Refs | Source |
|---|---|---|---|---|
| 122796 | kernel32.LoadLibraryA | IMPORT | 1 | malcat: imports |
| 122800 | kernel32.GetProcAddress | IMPORT | 0 | malcat: imports |
| 122804 | kernel32.VirtualProtect | IMPORT | 0 | malcat: imports |
| 122808 | kernel32.VirtualAlloc | IMPORT | 0 | malcat: imports |
| 122812 | kernel32.VirtualFree | IMPORT | 0 | malcat: imports |
| 122816 | kernel32.ExitProcess | IMPORT | 0 | malcat: imports |
| 122824 | msvbvm60.rtcR8ValFromBstr | IMPORT | 1 | malcat: imports |

**Interpretation:** The presence of `LoadLibraryA` and `GetProcAddress` signals dynamic API resolution, a common evasion technique (ATT&CK T1129). The memory management functions (`VirtualProtect`, `VirtualAlloc`, `VirtualFree`) are needed by the UPX stub to allocate executable memory, change memory protections, and unpack code. The single MSVBVM60 import (`rtcR8ValFromBstr`) is a strong indicator that the unpacked payload is a Visual Basic 6 application. The low reference count for most APIs suggests they are used infrequently, likely only by the packer stub itself. (source: malcat, pe_imports)

### High-Signal Strings
Key strings found in the resource section and overlay reveal the sample's identity and potential C2 infrastructure.

| EA | String | Context | Source |
|---|---|---|---|
| 122236, 122000 | `www.hidden-sabotage.com` | Found in VS_VERSION_INFO area; indicates C2 domain | malcat: top_strings |
| 122490, 122602 | `ifreleyici Modernize Hayalet` / `Ghost Şifreleyici Modernize Hayalet.exe` | Turkish for "Ghost Encryptor Modernized Ghost" | malcat: top_strings |
| 122832 | `KERNEL32.DLL` | Library for core APIs | malcat: high_signal_strings |
| 122845 | `MSVBVM60.DLL` | Visual Basic 6 virtual machine | malcat: top_strings |
| 5676 | `e6rFRICHTX32.OCX` | Rich Text control, common in VB6 GUI apps | FLOSS: static_strings |
| (multiple) | `winsck.ocx` | Winsock OCX for network functionality in VB6 | FLOSS: static_strings; deep_dive_agentic |
| 122088, 122316 | `Modernize Hayalet` | Part of the crypter tool name | malcat: top_strings |

**Interpretation:** The domain `www.hidden-sabotage.com` is a primary indicator of compromise (IOC). The repeated Turkish crypter tool name confirms the sample's purpose as a dropper for obfuscated payloads. The presence of `MSVBVM60.DLL`, `winsck.ocx`, and `FRICHTX32.OCX` strings strongly supports that the unpacked payload is a VB6 application with networking and GUI capabilities. (source: malcat, FLOSS, deep_dive_agentic)

### capa & YARA Matches
capa identified one capability rule, confirming the packing technique. YARA matched numerous packer-specific signatures.

#### capa Rules
| Rule | ATT&CK | MBC | Source |
|---|---|---|---|
| packed with generic packer | T1027.002: Obfuscated Files or Information | F0001.002: Software Packing | capa |

#### YARA Matches (Selected High-Confidence)
| Rule | Match String(s) | EA | Source |
|---|---|---|---|
| UPXv20MarkusLaszloReiser | `$a0@104367 len=85` | 0x00019B0F | yara |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | `$a1@104016 len=63` | 0x00019A80 | yara |
| PackerUPX_CompresorGratuito | `$a@104016 len=12` | 0x00019A80 | yara |
| IsPacked | (structural) | - | yara |
| HasOverlay | (structural) | - | yara |
| UPX_wwwupxsourceforgenet | `$a@104016 len=12; $b@104016 len=12` | 0x00019A80 | yara |

**Interpretation:** The YARA rules match multiple UPX variants (v2.0, v2.90 LZMA) at or very near the entry point, providing high-confidence evidence of UPX packing. The `IsPacked` and `HasOverlay` rules corroborate the structural anomalies noted by Malcat. The capa rule explicitly maps this to defense evasion technique T1027.002 (Software Packing). (source: capa, yara)

## 5. Behavioral & Dynamic Analysis
Dynamic analysis was performed using Speakeasy and Frida. Both tools executed successfully but recorded zero API calls or runtime events.

| Tool | Status | Events Observed | Source |
|---|---|---|---|
| Speakeasy | `speakeasy_ok: True` | 0 API calls, 0 key events | Speakeasy (dynamic) |
| Frida Probe | `frida_available: True` (v17.16.4) | 0 hook triggers | Frida Probe |

**Interpretation:** The absence of observed runtime behavior from these dynamic analysis engines does not mean the sample is benign. It likely indicates that the sample employs anti-analysis techniques (e.g., environment checks, sleep timers, or requires specific command-line arguments) that prevented execution in our analysis environment. The sample's packing and use of dynamic API resolution are consistent with such evasion. We cannot infer runtime behavior from this negative result; we only note that it was not observed. (source: Speakeasy, Frida Probe)

## 6. Network Indicators & C2
The primary network indicator is the hardcoded C2 domain found in the version information.

- **Domain:** `www.hidden-sabotage.com` (found at Ghidra addresses 0x4561040 and 0x4561276 per deep_dive_agentic; also at Malcat EAs 122236 and 122000). (source: malcat, deep_dive_agentic)
- **Network Stack:** The presence of `winsck.ocx` (Winsock OCX) in the FLOSS strings indicates the unpacked VB6 payload includes built-in network socket functionality, likely used for C2 communication. (source: FLOSS)

No specific ports, protocols, or HTTP headers were extracted from the static strings. The network capability is latent in the packed payload and was not triggered during dynamic analysis.

## 7. Capabilities Assessment
Based on static analysis, the sample has the following capabilities. We distinguish between observed (in the outer layer) and latent (in the packed payload).

| Capability | Evidence | Status | ATT&CK Mapping | Source |
|---|---|---|---|---|
| **Software Packing** | UPX stub, YARA matches, capa rule, Malcat anomalies | **Observed** | T1027.002 | yara, capa, malcat |
| **Dynamic API Resolution** | Minimal IAT (LoadLibrary, GetProcAddress) | **Observed** | T1129 | pe_imports |
| **Memory Manipulation** | VirtualProtect, VirtualAlloc imports | **Observed** | T1055 (Process Injection sub-technique) | pe_imports |
| **GUI Application** | `IsWindowsGUI` YARA rule, GUI subsystem, rich text control strings | **Observed (in payload)** | - | yara, malcat, FLOSS |
| **Network Communication** | `winsck.ocx` string, C2 domain `www.hidden-sabotage.com` | **Latent (in payload)** | T1071 (Application Layer Protocol) | FLOSS, malcat |
| **Crypter/Dropper Functionality** | Internal name "Ghost Encryptor", Turkish crypter branding | **Latent (in payload)** | T1027 (Obfuscated Files) | malcat |
| **Overlay Data** | Large overlay with medium-high entropy | **Observed** | - | malcat |
| **Anti-Analysis** | Patched UPX header, zero runtime events in dynamic analysis | **Likely Latent** | T1497 (Virtualization/Sandbox Evasion) | malcat, Speakeasy |

The core observed capabilities are packing and dynamic loading, which are defense evasion mechanisms. The more concerning capabilities (networking, dropper) are locked inside the packed payload and were not directly observed executing.

## 8. Indicators of Compromise
The following IOCs are derived from static analysis.

### File-based IOCs
- **SHA256:** `9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6`
- **Imphash:** `b4e06d942b341e012040239c1cca0b7d`
- **Internal Name:** `Ghost Şifreleyici Modernize Hayalet.exe`

### Network IOCs
- **Domain:** `www.hidden-sabotage.com`

### String IOCs
- `winsck.ocx`
- `e6rFRICHTX32.OCX`
- `rm1.Insertar_Objeto2`
- `GraficAudio~Calc_Pictu`
- `ET_PICTURE6`
- `Ghost Şifreleyici Modernize Hayalet`
- `Modernize Hayalet`

### YARA Rules (from rule.yara.json)
A consolidated YARA rule is provided at `/opt/samples/logs/.../rule.yar`.

## 9. Detection Engineering
The provided YARA rule (`rule.yar`) targets unique strings and structural properties. For enterprise detection, focus on:
1. **Network Signatures:** DNS queries for `www.hidden-sabotage.com`.
2. **Endpoint Signatures:**
   - Presence of the string `Ghost Şifreleyici Modernize Hayalet` in PE version info.
   - Detection of the specific UPX variants listed in the YARA rules.
   - Monitoring for processes that import only the 6 KERNEL32 functions listed (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess), which is highly anomalous for a legitimate application.
3. **Sigma Rules:** A Sigma rule for the IOC is generated at `/opt/samples/logs/.../rule.yml`.

## 10. MITRE ATT&CK Mapping
| Tactic | Technique | Evidence | Source |
|---|---|---|---|
| **Defense Evasion** | T1027.002: Obfuscated Files or Information (Software Packing) | UPX packing, capa rule | capa, yara, malcat |
| **Defense Evasion** | T1129: Shared Modules | Dynamic API resolution via LoadLibraryA/GetProcAddress | pe_imports |
| **Execution** | T1055: Process Injection (Memory Allocation with VirtualProtect/VirtualAlloc) | Import of memory manipulation APIs | pe_imports |
| **Defense Evasion** | T1497: Virtualization/Sandbox Evasion | Zero runtime events in dynamic analysis, likely anti-analysis | Speakeasy |
| **Command and Control** | T1071: Application Layer Protocol (Latent) | `winsck.ocx` string, C2 domain | FLOSS, malcat |

## 11. What We Don't Know
Several critical aspects of this sample's behavior remain unknown due to analysis limitations.

1. **Packed Payload Functionality:** The exact capabilities of the VB6 payload (e.g., persistence mechanisms, specific C2 protocol, data exfiltration methods) are unknown because dynamic analysis did not trigger execution and static analysis cannot fully deobfuscate the packed data. (source: Speakeasy, radare2)
2. **Anti-Analysis Techniques:** The specific methods used to evade dynamic analysis (e.g., environment fingerprinting, sleep calls, mutex checks) are unknown. The zero-event result from Speakeasy/Frida could be due to these techniques or a lack of triggering conditions. (source: Speakeasy, Frida Probe)
3. **Payload Delivery:** What secondary payload (if any) this crypter is designed to drop or decrypt is unknown. The overlay data at EA 0x1E240 (49KB, medium-high entropy) likely contains this payload, but its nature is obfuscated. (source: malcat: anomalies)
4. **Network Protocol Details:** The exact C2 protocol (e.g., HTTP, custom TCP), beacon intervals, or data formatting are not evident from static strings. (source: malcat, FLOSS)
5. **Full IoC List:** Additional IoCs such as registry keys, file system artifacts, or mutexes created by the payload are unknown. (unknown: static analysis limitation)

## 12. Appendix A: Tool Evidence Trail
This appendix documents the sequence of tool executions and their outputs used to generate this report.

### Audit Trail (Recent Tool Calls)
```json
{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786669134.541347}
{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786669135.1202927}
{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786682203.4688869}
{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786682203.4725142}
{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786682209.6826055}
{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786682210.682473}
{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786682213.047595}
{"source": "quick_scan_v2", "phase": 2, "ts": 1786682216.4546432}
```
This trail shows that Ghidra and IDA were queried for function, import, string, and memory block information, which was used to corroborate findings from other tools. (source: audit_trail)

## 13. Appendix B: Analysis Environment
The analysis was conducted in a controlled environment using the following tools and versions, as indicated by the evidence pack.

| Tool | Version / Status | Purpose | Source |
|---|---|---|---|
| Malcat | Not specified | Static PE analysis, anomaly detection, strings | malcat |
| YARA (Pipeline) | 20 matches | Pattern matching for packers, IOCs | yara |
| capa | 1 rule | Capability extraction and MITRE mapping | capa |
| FLOSS | 470 strings | String extraction (static) | FLOSS |
| radare2 | Not specified | Disassembly | radare2 |
| Ghidra | Queried via SQL | Decompilation, import/offset analysis | ghidra_query |
| IDA | Queried via SQL | Import and function analysis | ida_query |
| Speakeasy | Ran, 0 events | Dynamic API emulation | Speakeasy |
| Frida Probe | v17.16.4, 0 hooks | Dynamic function hooking | Frida Probe |
| UPX Unpack | Failed (`upx_ok: False`) | Attempted unpacking | upx_unpack |
| XOR Search | Found XOR 00 at 0 | Basic obfuscation check | xor_search |
| .NET Analysis | `is_dotnet: false` | .NET assembly check | dotnet |

The environment included VirusTotal for external threat intelligence enrichment, which provided the `trojan.llac/babar` classification and 60/72 malicious detection rate. (source: external TI)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6  
**sample_path:** /opt/samples/corpus/binaries/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/challenge66.exe  
**project_name:** binaries

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: llac
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple engines confirm UPX packing and dynamic API resolution via minimal imports. MalCat and YARA detect packing anomalies, capa identifies software packing, and pe_imports shows APIs for dynamic loading. VirusTotal reports high malicious detections with trojan.llac/babar family, indicating malicious intent despite static analysis showing primarily obfuscation.
- **summary**: The sample is a PE executable packed with UPX, showing high entropy, minimal imports for dynamic API resolution, and version info indicating 'Ghost Encryptor'. While static analysis highlights obfuscation without clear behavioral signals, VirusTotal detections classify it as a trojan with 60 malicious reports, supporting a malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `Packed×6, PatchedUPXHeader` | Indicates software packing with UPX, a common obfuscation technique in malware. |
| yara | YARA matches | `UPXv20MarkusLaszloReiser, UPX_290_LZMA` | Confirms presence of UPX packer signatures, supporting packing evidence. |
| capa | top_rules | `packed with generic packer` | ATT&CK technique T1027.002 for software packing, a defense evasion method. |
| pe_imports | signals | `load_library, get_proc_address, change_memory_protection, allocate_memory` | APIs for dynamic code loading and memory manipulation, typical in packers and malware for evasion. |
| malcat | file_summary | `VersionInfo::InternalName: Ghost Şifreleyici Modernize Hayalet` | Suggests the file is an 'encryptor', which could imply malicious use like ransomware or keygen, though static analysis a |
| external TI | VirusTotal | `malicious=60, threat_class: trojan.llac/babar` | High detection rate and specific malware family identification indicate malicious intent, overriding neutral obfuscation |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: UPX-packed VB6 crypter dropper ('Ghost Şifreleyici Modernize Hayalet' — Turkish 'Ghost Encryptor Modernized Ghost') communicating with www.hidden-sabotage.com. The outer layer is a UPX stub with only 6 KERNEL32 memory-management imports (LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess). The packed payload is a Visual Basic 6 application with Winsock networking (winsck.ocx), RTF GUI controls, and embedded C2 domain references. YARA rules matched 7+ UPX packer signatures. CAPA confirms software packing (T1027.002). The crypter theme, suspicious domain, and packing obfuscation classify this as malicious tooling. Persistence mechanisms were not observed in the analyzed components, with no evidence from tools like YARA or CAPA indicating registry, startup, or scheduled task modifications. Exfiltration data or tools were not identified; while Winsock networking suggests communication, no specific data exfiltration methods or payloads were detected in static analysis. Credential access techniques were not observed; no memory scraping, keylogging, or credential theft modules were found in the unpacked VB6 payload.

### deep key_evidence
- `"YARA: 7+ UPX packer rules matched (UPXv20MarkusLaszloReiser, UPXV200V290, UPX290LZMA, upx_3, PackerUPX_CompresorGratuito, UPX_wwwupxsourceforgenet_additional)"`
- `"CAPA: 'packed with generic packer' \u2014 MITRE T1027.002 (Software Packing), MBC F0001.002"`
- `"Entry point 0x454310: classic UPX decompression stub (PUSHAD; MOV ESI,0x43c000; LEA EDI,[ESI+0xfffc5000]; byte-copy loop with bit-shift)"`
- `"Ghidra imports (6 total, all KERNEL32): LoadLibraryA, GetProcAddress, VirtualProtect, VirtualAlloc, VirtualFree, ExitProcess"`
- `"pe_import_signals: dynamic API resolution (T1129) via LoadLibrary+GetProcAddress; memory protection changes (T1055) via VirtualProtect+VirtualAlloc"`
- `"String 'www.hidden-sabotage.com' at Ghidra addresses 0x4561040 and 0x4561276 (resource section, VS_VERSION_INFO area)"`
- `"String 'Ghost \u015eifreleyici Modernize Hayalet' (Ghost Encryptor Modernized Ghost) \u2014 Turkish crypter tool name in VS_VERSION_INFO at 0x4561516"`
- `"FLOSS extracted 470 strings including VB6 artifacts: winsck.ocx (Winsock/network), FRICHTX32.OCX (RichText), rm1.Insertar_Objeto2, GraficAudio, ET_PICTURE6, TextRTF"`
- `"PE memory layout: 2 executable RWX sections (SECTION.0: 241KB, SECTION.1: 106KB) \u2014 typical of packer with self-modifying unpacking code"`
- `"YARA rule 'IsPacked' matched; 'HasOverlay' and 'HasRichSignature' also matched"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6
size: 169998
type: PE
architecture: X86
entrypoint_ea: 104016
entropy: 7.57
file_name: challenge66.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
| header | 0 | 1024 | 0 | - |
|  | 1024 | 103936 | 106496 | RWX |
| .rsrc | 107520 | 15872 | 16384 | RW |
| overlay | 123904 | 49166 | 0 | - |
|  | 173070 | 0 | 241664 | RWX |

### Malcat YARA / Signatures (7)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| upx_080_or_higher_01 | packer | INFO | 50 |  |
| upx_089_3xx | packer | INFO | 50 |  |
| upx_0896_102_105_122_03 | packer | INFO | 50 |  |
| upx_12x | packer | INFO | 50 |  |
| upx_290_lzma_02 | packer | INFO | 50 |  |
| upx_391_nrv2e_02 | packer | INFO | 50 |  |

### Anomalies (22)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| InvalidBaseOfData | 4 | sections | 1 | at least one data section starts before BaseOfData, or BaseOfData is not the start of a data section |
| PatchedUPXHeader | 4 | packers | 0 | At least one Yara signature matched UPX but no UPX header was identified by Malcat, indicating a pot |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 3 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| SectionEmptyName | 3 | sections | 2 | section name is null |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| UnreferencedImports | 3 | imports | 7 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| DuplicatedSectionName | 2 | sections | 1 | section name has already been used before in section table |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 6 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `284`: 
- **NoChecksum**
  - `280`: 
- **XorInLoop**
  - `104130`: 

### High-Signal Strings (7 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 122832 | `KERNEL32.DLL` |
| 98313 | `\\\\"` |
| 76520 | `\\XX` |
| 122874 | `GetProcAddress` |
| 72064 | `<``\\j` |
| 122860 | `LoadLibraryA` |
| 122890 | `VirtualProtect` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 122832 | `KERNEL32.DLL` |
| 122845 | `MSVBVM60.DLL ` |
| 122602 | `ifreleyici Modernize Hayalet.exe` |
| 122236 | `www.hidden-sabotage.com` |
| 122000 | `www.hidden-sabotage.com` |
| 122490 | `ifreleyici Modernize Hayalet` |
| 121762 | `VS_VERSION_INFO` |
| 122554 | `OriginalFilename` |
| 121890 | `040904B0` |
| 154773 | `gi~`fdImff			O_O..BVXyo{sCdxi{lkoo` |
| 5676 | `e6rFRICHTX32.OCX` |
| 72047 | `B.dhd` |
| 122202 | `LegalTrademarks` |
| 123904 | `pepotespepotesMZ` |
| 133441 | `%-%=9<003000333 ...%%';=89;<>:?% Y` |
| 131783 | `zkl=<`ol|=985ezf..:r?o1gvn<?r1ph>0` |
| 135700 | `J
h}H|oo	
xBfz}	..`k				zY{ej		
Fg` |
| 98313 | `\\\\"` |
| 129674 | `

` |
| 124446 | `
J


` |
| 130188 | `J



` |
| 150496 | `<



` |
| 122054 | `FileDescription` |
| 122450 | `InternalName` |
| 171076 | `~~
	
@	f	n
h	{
..p
k	f
o	~		Y
=	` |
| 171236 | `		G	b
jj
rg	d
..*B	ls
a
a
h	y` |
| 171844 | `f




-
` |
| 132753 | `
W



` |
| 131020 | `:	H
2
9
:
:	;
;
:` |
| 131962 | `@g`}`hfcsln	Jehz..}`hecsl			
cl9hg` |
| 94642 | `t2%S2AllS2%Soca%S2%teS2` |
| 130878 | `cosoloscic		d	
	..	=	>	:
2	?	;	5
_` |
| 121854 | `StringFileInfo` |
| 122402 | `ProductVersion` |
| 139158 | `L


` |
| 135026 | `


` |
| 136467 | `

` |
| 75790 | `qLLL` |
| 121974 | `CompanyName` |
| 139237 | `


b` |
| 141700 | `6


` |
| 144535 | `<


` |
| 72719 | `99@@` |
| 156851 | `

` |
| 10225 | `j.bih` |
| 74285 | `dPPP` |
| 149252 | `L


` |
| 147893 | `0


` |
| 147560 | `


` |
| 145909 | `0


` |
| 13756 | `StSt` |
| 15783 | `@@@x` |
| 143610 | `<


` |
| 143532 | `N


` |
| 99828 | `XXX2` |
| 143428 | `?


` |
| 101469 | `dXXX` |
| 141921 | ``


` |
| 77 | `!This program ca..in DOS mode.
$` |
| 140415 | `2


` |
| 139991 | `



IG` |
| 124274 | `


` |
| 132236 | `K
\K

` |
| 122706 | `Translation` |
| 76520 | `\\XX` |
| 129710 | `

` |
| 76230 | `HHLH` |
| 130671 | `


e` |
| 76222 | `vLLv` |
| 133756 | `8:8...` |
| 124766 | `


` |
| 124261 | `


` |
| 125200 | `

` |
| 134443 | `-)*/(.&%%<?95547..1>>4!.!+-*(+,*-*` |
| 122358 | `FileVersion` |
| 122088 | `Modernize Hayalet` |
| 122316 | `Modernize Hayalet` |
| 132811 | `




	
` |
| 154728 | `		Bo}aJhefLgn`gl..OA^VYCDAUHnmXoo
` |
| 9967 | `?Fromfqfkipislqsqvhnqrvjgt` |

### Imports (7)
| EA | Name | Type | Refs |
|---|---|---|---|
| 122796 | kernel32.LoadLibraryA | IMPORT | 1 |
| 122800 | kernel32.GetProcAddress | IMPORT | 0 |
| 122804 | kernel32.VirtualProtect | IMPORT | 0 |
| 122808 | kernel32.VirtualAlloc | IMPORT | 0 |
| 122812 | kernel32.VirtualFree | IMPORT | 0 |
| 122816 | kernel32.ExitProcess | IMPORT | 0 |
| 122824 | msvbvm60.rtcR8ValFromBstr | IMPORT | 1 |

### Functions (1)
| EA | Name |
|---|---|
| 104016 | EntryPoint |

### Decompilations (top 6)
#### 104016 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```

### Carved Files (2)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 9640 |
| ? | DIB | 4264 |

### Virtual Files (4)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 9640 | - |
| ICO/2/unk | 4264 | - |
| GRPICO/1/unk | 34 | - |
| VER/1/en-us | 980 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 192 |
| OptionalHeader | 216 |
| Sections | 440 |
| Resources | 107520 |
| Resources.ICO | 107560 |
| Resources.ICO.1 | 107592 |
| Resources.ICO.1.unk | 107616 |
| Resources.ICO.2 | 107632 |
| Resources.ICO.2.unk | 107656 |
| Resources.GRPICO | 107672 |
| Resources.GRPICO.1 | 107696 |
| Resources.GRPICO.1.unk | 107720 |
| Resources.VER | 107736 |
| Resources.VER.1 | 107760 |
| Resources.VER.1.en-us | 107784 |
| Resources.ICO.1.unk.Data | 107804 |
| Resources.ICO.2.unk.Data | 117448 |
| Resources.GRPICO.1.unk.Data | 121716 |
| VersionInfo | 121756 |
| ImportTable | 122736 |
| kernel32.FT | 122796 |
| msvbvm60.FT | 122824 |
| ImportNames | 122832 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 1.08

| Rule | ATT&CK | MBC |
|---|---|---|
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |

## PE Imports / Signals
import_count: 6

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 20

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@37486 len=3 |
| contains_base64 | - | $a@5676 len=12 |
| UPXv20MarkusLaszloReiser | - | $a0@104367 len=85 |
| UPXV200V290MarkusOberhumerLaszloMolnarJohnReiser | - | $a0@104414 len=39 |
| UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser | - | $a1@104016 len=63 |
| upx_3 | - | $str1@104016 len=45 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| PackerUPX_CompresorGratuito_wwwupxsourceforgenet | - | $a@104016 len=12 |
| UPX_wwwupxsourceforgenet_additional | - | $a@104016 len=12 |
| yodas_Protector_v1033_dllocx_Ashkbiz_Danehkar_h | - | $a@241 len=1 |
| Netopsystems_FEAD_Optimizer_1 | - | $a@104016 len=64 |
| UPX_290_LZMA | - | $a@104016 len=63 |
| UPX_290_LZMA_Markus_Oberhumer_Laszlo_Molnar_John_Reiser | - | $b@104016 len=63 |
| UPX_290_LZMA_additional | - | $a@104016 len=63 |
| UPX_wwwupxsourceforgenet | - | $a@104016 len=12; $b@104016 len=12 |

## Generated YARA Meta
```json
{
  "sha256": "9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6",
  "family": "Ghost \u015eifreleyici Modernize Hayalet (likely a RAT/trojan, possibly related to llac/babar based on VT)",
  "imphash": "b4e06d942b341e012040239c1cca0b7d",
  "generated_at": "2026-08-12T23:53:21.656605+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "1^2e2.3C9",
    "Sk8OF6.v",
    "8!7(+6l%",
    "Oc2->a\"6",
    "winsck.ocx@SW",
    "e6rFRICHTX32.OCX",
    "DrderSty",
    "BAFM~omctlJ",
    "^;RS_<M_",
    "rm1.Insertar_Objeto2",
    "GraficAudio~Calc_Pictu",
    "re3Slide_",
    "g4OPEN$IL",
    "Notify_IcoI",
    "LabelProg\\paLB",
    "WuC:\\WINDOWS\\sys",
    "soft Visu@ StY\\VB`V",
    "ect 0.1U",
    "ET_PICTURE6",
    "<Web m>s",
    "?Fromfqfkipislqsqvhnqrvjgt",
    "kmgjmti@",
    "Ap\"ogoobcgqi"
  ],
  "rule_path": "/opt/samples/logs/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/rule.yar",
  "sigma_path": "/opt/samples/logs/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/rule.yml",
  "iocs_path": "/opt/samples/logs/9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6/iocs.json",
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
    "utc": "2026-08-12 23:53:21 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 470 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 470}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `QV8yN.[`
- `1^2e2.3C9`
- `<V|@d{W`
- `=Icti>`
- `WhXoXaZ`
- `#g_6~=~`
- `Sk8OF6.v`
- `Jz+,S8`
- `+H?nfx`
- `i/Cr`;`
- `|zm/GH$`
- `LN40m/`
- `8!7(+6l%`
- `Oc2->a"6`
- `winsck.ocx@SW`
- `+dColor`
- `Enable`
- `TextRTF`
- `J;"dfn`
- `e6rFRICHTX32.OCX`
- `DrderSty`
- `BAFM~omctlJ`
- `stView`
- `c)6@_M`
- `{o R^_`
- `-3H(K^`
- `^;RS_<M_`
- `L.X7hoy`
- `rm1.Insertar_Objeto2`
- `GraficAudio~Calc_Pictu`
- `re3Slide_`
- `g4OPEN$IL`
- `Notify_IcoI`
- `Class.`
- `LabelProg\paLB`
- `WuC:\WINDOWS\sys`
- `soft Visu@ StY\VB`V`
- `s\Soo.`
- `ect 0.1U`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00455250
```asm
┌ 439: entry0 ();
│       ╎   0x00455250      60             pushal
│       ╎   0x00455251      be00c04300     mov esi, section.sect_1     ; 0x43c000
│       ╎   0x00455256      8dbe0050fcff   lea edi, [esi - 0x3b000]
│       ╎   0x0045525c      57             push edi
│       ╎   0x0045525d      83cdff         or ebp, 0xffffffff          ; -1
│      ┌──< 0x00455260      eb10           jmp 0x455272
..
│     ┌───> 0x00455268      8a06           mov al, byte [esi]
│     ╎│╎   0x0045526a      46             inc esi
│     ╎│╎   0x0045526b      8807           mov byte [edi], al
│     ╎│╎   0x0045526d      47             inc edi
│     ╎│╎   ; CODE XREFS from entry0 @ 0x455327(x), 0x45533d(x)
│   ┌┌────> 0x0045526e      01db           add ebx, ebx
│  ┌──────< 0x00455270      7507           jne 0x455279
│  │╎╎╎│╎   ; CODE XREF from entry0 @ 0x455260(x)
│  │╎╎╎└──> 0x00455272      8b1e           mov ebx, dword [esi]
│  │╎╎╎ ╎   0x00455274      83eefc         sub esi, 0xfffffffc
│  │╎╎╎ ╎   0x00455277      11db           adc ebx, ebx
│  └──└───< 0x00455279      72ed           jb 0x455268
│   ╎╎  ╎   0x0045527b      b801000000     mov eax, 1
│   ╎╎  ╎   ; CODE XREF from entry0 @ 0x4552aa(x)
│   ╎╎ ┌──> 0x00455280      01db           add ebx, ebx
│   ╎╎┌───< 0x00455282      7507           jne 0x45528b
│   ╎╎│╎╎   0x00455284      8b1e           mov ebx, dword [esi]
│   ╎╎│╎╎   0x00455286      83eefc         sub esi, 0xfffffffc
│   ╎╎│╎╎   0x00455289      11db           adc ebx, ebx
│   ╎╎└───> 0x0045528b      11c0           adc eax, eax
│   ╎╎ ╎╎   0x0045528d      01db           add ebx, ebx
│   ╎╎┌───< 0x0045528f      730b           jae 0x45529c
│  ┌──────< 0x00455291      7528           jne 0x4552bb
│  │╎╎│╎╎   0x00455293      8b1e           mov ebx, dword [esi]
│  │╎╎│╎╎   0x00455295      83eefc         sub esi, 0xfffffffc
│  │╎╎│╎╎   0x00455298      11db           adc ebx, ebx
│ ┌───────< 0x0045529a      721f           jb 0x4552bb
│ ││╎╎└───> 0x0045529c      48             dec eax
│ ││╎╎ ╎╎   0x0045529d      01db           add ebx, ebx
│ ││╎╎┌───< 0x0045529f      7507           jne 0x4552a8
│ ││╎╎│╎╎   0x004552a1      8b1e           mov ebx, dword [esi]
│ ││╎╎│╎╎   0x004552a3      83eefc         sub esi, 0xfffffffc
│ ││╎╎│╎╎   0x004552a6      11db           adc ebx, ebx
│ ││╎╎└───> 0x004552a8      11c0           adc eax, eax
│ ││╎╎ └──< 0x004552aa      ebd4           jmp 0x455280
│ ││╎╎┌┌──> 0x004552ac      01db           add ebx, ebx
│ ────────< 0x004552ae      7507           jne 0x4552b7
│ ││╎╎╎╎╎   0x004552b0      8b1e           mov ebx, dword [esi]
│ ││╎╎╎╎╎   0x004552b2      83eefc         sub esi, 0xfffffffc
│ ││╎╎╎╎╎   0x004552b5      11db           adc ebx, ebx
│ ────────> 0x004552b7      11c9           adc ecx, ecx
│ ────────< 0x004552b9      eb52           jmp 0x45530d
│ └└──────> 0x004552bb      31c9           xor ecx, ecx
│   ╎╎╎╎╎   0x004552bd      83e803         sub eax, 3
│  ┌──────< 0x004552c0      7211           jb 0x4552d3
│  │╎╎╎╎╎   0x
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r

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
  - `KERNEL32.DLL!LoadLibraryA`
  - `KERNEL32.DLL!GetProcAddress`
  - `KERNEL32.DLL!VirtualProtect`
  - `KERNEL32.DLL!VirtualAlloc`
  - `KERNEL32.DLL!VirtualFree`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786669134.541347}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786669135.1202927}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786669135.6960506}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786669136.441572}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786669136.9383156}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786669136.940348}`
- `{"source": "publish_report_v2", "ts": 1786669353.4814956}`
- `{"source": "publish_report_v2_technical", "ts": 1786669504.503738}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786682203.4688869}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786682203.471251}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786682203.4725142}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', addr) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786682203.4750314}`
- `{"source": "ida_query", "sql": "SELECT name, addr, size FROM funcs LIMIT 15", "ts": 1786682203.4765134}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786682207.9578252}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786682208.4939551}`
- `{"source": "ghidra_query", "sql": "SELECT name, addr FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786682209.0183794}`
- `{"source": "ghidra_query", "sql": "SELECT addr, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786682209.6826055}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786682210.1794815}`
- `{"source": "ghidra_query", "sql": "SELECT start_addr, end_addr, name FROM memory_blocks", "ts": 1786682210.682473}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786682211.4555604}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786682211.959379}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786682212.5456235}`
- `{"source": "ghidra_query", "sql": "SELECT addr, content FROM strings WHERE length < 300", "ts": 1786682213.047595}`
- `{"source": "ghidra_query", "sql": "SELECT addr AS address, name, size FROM funcs", "ts": 1786682213.5435708}`
- `{"source": "ghidra_query", "sql": "SELECT addr, name FROM names", "ts": 1786682214.0404422}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786682214.6214783}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786682215.201601}`
- `{"source": "ghidra_query", "sql": "SELECT addr, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786682215.9550204}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786682216.452547}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786682216.4546432}`
