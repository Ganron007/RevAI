> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:17:59 UTC

# Technical Malware Analysis Report: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9

## 1. Executive Summary
This sample is a confirmed malicious packed PE32 executable with a threat score of 92, classified as likely trojan/downloader/dropper wrapped with the AHTeam EP Protector / fake PCGuard packer (source: llm_judge). Static analysis from capa, pe_imports, YARA, and FLOSS confirms it uses generic packing and XOR obfuscation to hinder reverse engineering, contains an embedded secondary PE payload, and includes indicators of potential command-and-control (C2) communication. High-signal malicious Windows API imports for registry modification, process execution, and dynamic API resolution were identified. No functional decompilation data is available due to operational failures in Ghidra and IDA analysis, but existing tool evidence is sufficient for high-confidence malicious classification (source: llm_judge).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 |
| Sample Path | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Threat Score | 92 |
| Family Guess | Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers. |
*(source: llm_judge)*

## 3. File Layout & Structural Analysis
The sample is a valid PE32 Windows GUI executable with multiple anti-analysis and packing structural markers:
### YARA Structural Matches
| Rule | Match Offset | Length | Description |
|---|---|---|---|
| IsPE32 | N/A | N/A | Valid PE32 file format confirmed |
| IsWindowsGUI | N/A | N/A | GUI subsystem, no console window |
| HasOverlay | N/A | N/A | Overlay data present (common for packed/embedded content) |
| HasModified_DOS_Message | N/A | N/A | Modified DOS header message (anti-analysis measure) |
| AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | 2 | 1 | Packer/protector fingerprint matching fake PCGuard wrapper |
| SEH_Save | 66713 | 7 | Structured Exception Handler (SEH) save pattern, common in shellcode/packed malware |
| SEH_Init | 66720 | 7 | SEH initialization pattern |
*(source: yara)*
Additional structural observations:
- Total PE imports: 113 (source: pe_imports)
- UPX unpack attempt failed: no unpacked sample generated (upx_ok: False, returncode: None, unpacked_path: empty) (source: upx)
- XOR obfuscation detected at two positions: 0x00000000 and 0x0001B800, with 0x80-byte runs of XOR 0x00 at each location (source: xor)
- FLOSS extracted 715 total static strings, the majority obfuscated (consistent with XOR packing) (source: floss)
- Sample is not a .NET assembly (is_dotnet: false) (source: dotnet)

## 4. Malcat Triage Summary
Malcat analysis encountered a top-level error during processing (malcat_analyze MCP connection closed) (source: deep_dive_agentic). Speakeasy dynamic analysis returned no recorded events or API calls (not observed) (source: speakeasy). Frida probe is available (version 17.16.4) but no instrumentation data was collected (not observed) (source: frida_probe).

## 5. Static Code Analysis
No Ghidra or IDA disassembly/decompilation is available due to operational failures (Ghidra NotOwnerException, missing IDA idasql binary) (source: deep_dive_agentic). Radare2 disassembly of key functions is available below:
### Entry Point (0x00430005) - XOR Decoder Loop
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
This loop XOR-decodes the .text section (0x401000 to 0x408ecc) with the 4-byte key 0x462530e4, a common packing/obfuscation routine (source: r2_decomp, capa).
### Import Address Table (IAT) Stub (0x004312b0)
The IAT is obfuscated, with stubs for high-risk Windows APIs including ole32 (CoCreateInstance, CLSIDFromString), wininet (DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA), and kernel32 (GetCommandLineA, GetCurrentProcessId, GetModuleHandleA, GetProcAddress, CreateProcessA, TerminateProcess, WriteFile) (source: r2_decomp, pe_imports).
### Additional Import Stubs
| Address | Key APIs |
|---|---|
| 0x00431334 | LoadLibraryA, LocalAlloc |
| 0x00431340 | OpenMutexA, CreateFileA, ReadFile, SetFilePointer, CreateMutexA, Sleep, VirtualQuery, CreateProcessA, WaitForSingleObject, WriteFile, lstrlenA/lstrlenW |
| 0x00431384 | CreateThread, DeleteFileA, GetWindowTextA, GetWindowRect, FindWindowA, GetWindow, GetClassNameA, SetFocus, GetForegroundWindow, LoadCursorA, LoadIconA, SetTimer, RegisterClassA, MessageBoxA, GetMessageA |
*(source: r2_decomp)*

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis:
- Speakeasy emulation: not observed (0 API calls, 0 key events recorded, no execution flow captured) (source: speakeasy)
- Frida instrumentation: not observed (no data collected from the available Frida 17.16.4 probe) (source: frida_probe)
- UPX unpacking: failed, no unpacked sample available for dynamic analysis (source: upx)
The sample's packed nature and anti-analysis markers (modified DOS header, SEH usage) likely prevent successful emulation in standard sandboxes.

## 7. Network Indicators & C2
YARA rules detected multiple network-related indicators embedded in the sample:
| Rule | Match Offset | Length | Description |
|---|---|---|---|
| domain | 0 | 2 | Domain name regex pattern (potential C2 domain) |
| IP | 72810 | 23 | IPv6 address pattern (potential C2 server) |
| contains_base64 | 47878 | 16 | Base64-encoded content (potential encoded C2 payload or command) |
| maldoc_getEIP_method_1 | 54788 | 6 | GetEIP method pattern (common in shellcode/network payloads) |
| Str_Win32_Wininet_Library | 49832 | 11 | WinINET library string, indicating use of Windows internet APIs for C2 communication |
*(source: yara)*
No cleartext C2 domains or IP addresses were extracted from static strings, as all network-related content appears obfuscated.

## 8. Capabilities & MITRE ATT&CK Mapping
### capa Capability Rules
| Rule | ATT&CK Technique | MBC |
|---|---|---|
| encode data using XOR | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| packed with generic packer | T1027.002: Obfuscated Files or Information | F0001.002: Software Packing |
| contain an embedded PE file | N/A | B0023: Install Additional Program |
| contain loop | N/A | N/A |
| (internal) packer file limitation | N/A | N/A |
*(source: capa, duration: 2.63s)*
### PE Import Signals (High-Risk Capabilities)
| Label | API Match | ATT&CK Technique |
|---|---|---|
| set_registry_value | RegSetValue | T1112: Modify Registry |
| create_process | CreateProcess | T1106: Native API |
| load_library | LoadLibrary | T1129: Shared Modules |
| get_proc_address | GetProcAddress | T1129: Shared Modules |
*(source: pe_imports, total imports: 113)*
### Additional Capability Indicators (YARA)
| Rule | Match Offsets | Capability |
|---|---|---|
| win_mutex | 48626 | Mutex creation (anti-analysis, single-instance enforcement) |
| win_registry | 50204, 49486, 49470, 49454, 49506 | Registry modification (persistence, configuration storage) |
| win_files_operation | 48566, 48582, 48606, 48766, 48818, 49856 | File system operations (payload dropping, file manipulation) |
*(source: yara)*

## 9. Indicators of Compromise
### High-Signal Static Indicators
| Indicator Type | Value/Offset | Source |
|---|---|---|
| Packer Fingerprint | AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER at offset 2 | yara |
| SEH Patterns | SEH_Save at 66713, SEH_Init at 66720 | yara |
| Mutex String | win_mutex match at 48626 (11-byte string) | yara |
| Registry Strings | win_registry matches at 49454, 49470, 49486, 49506, 50204 | yara |
| File Operation Strings | win_files_operation matches at 48566, 48582, 48606, 48766, 48818, 49856 | yara |
| Base64 Content | contains_base64 match at 47878 (16-byte string) | yara |
| IPv6 Pattern | IP match at 72810 (23-byte string) | yara |
| Domain Pattern | domain match at 0 (2-byte string) | yara |
| XOR Decoder Routine | Entry point at 0x00430005, XOR key 0x462530e4 | r2_decomp, capa |
| Embedded PE | capa rule `contain an embedded PE file` matched | capa |
### Obfuscated FLOSS Strings (Sample)
```
.idata
.kofbl
<OF#55
1PA\2%F
oe-IZ4'IZ$
#&%FgV!F
:Pr%FEL
p0%Fmu
0%O?D!
%I`3$F
1 ~{q%
(^{q%fm
Dr%O$L
\r%{d0%F
1%F\GRF
v0%FdM
4Pad==
0Mn^r%
0M{^r%
0%Fi5Q
Ii4 /Xr%
<3`Vid
!IR4#{
pVid6C
Ii<(~Xr%
Do$0fup%
m<0vqp%IR
2Pr%IR
gF]!%F
MCIRs$c$0%Fg
0QNou)
#Z%.d0%F
gF]3%F
ou)ISp'
eNoe-ISb-o41`
xNou) mu)
>0%Fou
5IR4;{
L}%Fmu
D}%FoM
```
*(source: floss, total static strings: 715)*

## 10. Detection Engineering
### Static YARA Detection Rules
The following YARA rules matched the sample and can be used for detection:
- IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message (structural PE markers)
- AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER (packer fingerprint)
- SEH_Save, SEH_Init (SEH anti-analysis patterns)
- win_mutex, win_registry, win_files_operation (capability strings)
- domain, IP, contains_base64, maldoc_getEIP_method_1 (C2/payload indicators)
- Str_Win32_Wininet_Library (network library string)
*(source: yara)*
### capa Detection Rules
Matched capa rules for capability-based detection:
- `encode data using XOR` (T1027)
- `packed with generic packer` (T1027.002)
- `contain an embedded PE file` (B0023)
*(source: capa)*
### Import-Based Detection
Flag samples importing the following high-risk API combinations:
- RegSetValue + CreateProcess + LoadLibrary + GetProcAddress (registry modification, process execution, dynamic API resolution)
*(source: pe_imports)*
### Static Pattern Detection
Flag the XOR decoder loop pattern at entry point 0x00430005 (XOR of .text section with 4-byte key 0x462530e4, loop bounds 0x401000 to 0x408ecc) as a packer-specific static signature.
*(source: r2_decomp)*

## 11. What We Don't Know
The following analysis gaps exist due to tooling failures and the sample's packed nature:
1. No Ghidra disassembly or decompilation is available: Ghidra project access failed with a NotOwnerException (project owned by remnux) (source: deep_dive_agentic)
2. No IDA analysis is available: the required idasql binary is missing from /usr/local/bin/ (source: deep_dive_agentic)
3. No unpacked payload is available: UPX unpacking failed, and the sample is wrapped with a non-UPX packer (AHTeam EP Protector / fake PCGuard) (source: upx, yara)
4. No dynamic runtime behavior is observed: Speakeasy and Frida returned no execution data, likely due to packing/anti-analysis controls (source: speakeasy, frida_probe)
5. No confirmed cleartext C2 indicators: only regex matches for domains, IPs, and base64 content were found; no decrypted C2 addresses are available (source: yara)
6. No extracted embedded PE payload: capa detected an embedded PE, but it could not be extracted for analysis (source: capa)

## 12. Appendix: Analysis Environment
### Tooling & Runtime Metrics
| Tool | Version/Status | Metrics |
|---|---|---|
| capa | N/A | 5 rules matched, runtime 2.63s |
| FLOSS | N/A | 715 total static strings extracted, 0 decoded/stack/tight strings |
| radare2 | N/A | Entry point and import stub disassembly available |
| Speakeasy | ok | 0 API calls, 0 key events recorded |
| Frida | 17.16.4 | Available, no instrumentation data collected |
| UPX | N/A | Unpack attempt failed (returncode: None) |
| XOR Search | N/A | 2 XOR 0x00 positions found: 0x00000000, 0x0001B800 (0x80-byte runs each) |
| Malcat | N/A | Top-level analysis error (MCP connection closed) |
| Ghidra | N/A | Analysis failed (NotOwnerException) |
| IDA | N/A | Analysis failed (missing idasql binary) |
*(source: capa, floss, speakeasy, frida_probe, upx, xor, deep_dive_agentic)*
### Sample Context
- SHA256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
- Sample Path: /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir
- Project Name: incoming
*(source: llm_judge)*
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 92
- **family_guess**: Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers.
- **summary**: This sample is a confirmed malicious packed PE32 executable. Static analysis from capa, pe_imports, YARA, and FLOSS confirms it uses generic packing and XOR obfuscation to hinder analysis, contains an embedded secondary PE, has high-signal malicious Windows API imports for registry modification, process execution, and dynamic API resolution, and includes indicators of potential C2 communication (domain/IP/base64 patterns). The sample is likely a trojan, downloader, or dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. No functional or decompilation data is available due to Ghidra/IDA analysis failures.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with generic packer` | capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malwa |
| capa | top_rules | `encode data using XOR` | capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming a |
| capa | top_rules | `contain an embedded PE file` | capa found an embedded PE file within the sample, a common malware technique for dropping additional payloads or seconda |
| pe_imports | signals | `set_registry_value (RegSetValue) [T1112]` | High-signal import indicating the sample can modify Windows registry values, a common tactic for persistence, configurat |
| pe_imports | signals | `create_process (CreateProcess) [T1106]` | High-signal import indicating the sample can spawn new processes, used for executing payloads, running child malware, or |
| pe_imports | signals | `load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]` | High-signal imports indicating dynamic API resolution, a common technique to hide malicious function calls from static i |
| yara | matches | `IsPE32, HasOverlay, HasModified_DOS_Message, AHTeam_EP_Protector_03_fake_PCGuard` | YARA matches confirm the sample is a valid PE32 file with an overlay (common for packed/embedded content), modified DOS  |
| yara | matches | `contains_base64, domain, IP` | YARA detected base64 encoded content, domain, and IP address patterns in the sample, indicating potential C2 communicati |
| capa | strings | `715 total static strings, including obfuscated formatted strings (e.g. '%F', '%I` | FLOSS extracted 715 static strings, many of which are obfuscated (consistent with the XOR packing detected by capa), ind |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Deterministic static signals indicate a packed/protected Windows PE with anti-analysis and persistence behaviors. YARA matches include packer/protector fingerprints, SEH initialization/save patterns, and mutex/registry strings. capa reports XOR obfuscation, generic packing, and an embedded PE. PE import signals show registry modification and process creation APIs. Ghidra/IDA/SQL analysis is unavailable due to project ownership and missing idasql, but the existing tool evidence is sufficient for a high-confidence malicious classification.

### deep key_evidence
- `"YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2"`
- `"YARA rules SEH_Save and SEH_Init matched near offset 66713/66720"`
- `"YARA rule win_mutex matched at offset 48626"`
- `"YARA rule win_registry matched at offsets 50204, 49486, 49470, 49454, 49506"`
- `"YARA rules domain, IP, contains_base64, and maldoc_getEIP_method_1 matched"`
- `"capa rule encode data using XOR (T1027) matched"`
- `"capa rule packed with generic packer (T1027.002) matched"`
- `"capa rule contain an embedded PE file matched"`
- `"pe_import_signals: RegSetValue (T1112), CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129)"`
- `"Ghidra SQL unavailable: NotOwnerException on project owned by remnux"`
- `"IDA SQL unavailable: /usr/local/bin/idasql missing"`
- `"Malcat analysis error; Speakeasy returned no events/APIs/strings"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 5 · duration_s: 2.63

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 72810,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 47878,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 54788,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 2,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 66713,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 66720,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 48626,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
     
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
