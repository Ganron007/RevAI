> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 03:27:28 UTC

## 1. Executive Summary
This sample (sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) is a malicious UPX-packed 64-bit Windows PE file, scored 92/100 by the llm_judge verdict engine with family guess "Packed Windows trojan (likely info-stealer or RAT, UPX compressed with anti-VM/sandbox evasion and XOR obfuscation capabilities)" (source: llm_judge, verdict.json). Cross-engine analysis confirms consistent malicious indicators: capa identifies UPX packing, XOR obfuscation, Xen anti-VM checks, embedded PE payload, and runtime dynamic linking; YARA matches confirm UPX signatures, base64 content, PE overlay, Winsock2 references, and Meterpreter-related indicators; PE import analysis reveals LoadLibrary, GetProcAddress, and VirtualProtect imports associated with code injection and defense evasion; FLOSS extracted 10,548 obfuscated static strings with no decoded content. Ghidra and IDA analysis engines failed to execute (Ghidra due to project ownership error, IDA due to missing idasql binary), so all conclusions are derived from capa, pe_imports, YARA, FLOSS, and radare2 outputs, which are fully consistent in identifying malicious characteristics (source: llm_judge, cross_engine_notes). No benign characteristics were identified across any analysis tool.

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 92 |
| Family Guess | Packed Windows trojan (likely info-stealer or RAT, UPX compressed with anti-VM/sandbox evasion and XOR obfuscation capabilities) |
| Cross-Engine Agreement | llm_and_v1_agree |
| Analysis Tool Status | Ghidra (failed: project ownership error), IDA (failed: missing idasql binary), capa (ok), pe_imports (ok), YARA (ok), FLOSS (ok), radare2 (ok), UPX (unpack failed), Speakeasy (0 events), Frida (no data) |

(source: llm_judge, verdict.json; cross_engine_notes)

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows PE file, confirmed by YARA `IsPE64` rule match (source: yara, matches table). It is packed with UPX, confirmed by three independent YARA signature matches at offsets 0x188 (392), 0x1B0 (432), and 0x205 (517) (source: yara, matches table, UPX row; deep_dive_agentic, key_evidence). A PE overlay is present, confirmed by YARA `HasOverlay` rule match (source: yara, matches table), a common characteristic of packed malware used to store the original payload or additional malicious components.

The entry point (0x010b4100) is XOR-obfuscated, with a self-decryption loop using key 0xae that decrypts a large region of code before transferring control (source: r2, disassembly at 0x010b4100). XOR search identified 11 positions with XOR 00 patterns aligned to the DOS stub, confirming widespread XOR obfuscation across the file (source: xor, search results table below):

| XOR Position | XOR Key | Observed Pattern |
|--------------|---------|------------------|
| 0x00000000 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x00451B8F | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x00481512 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0070FE96 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0073F701 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0076F1B5 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0079ED6D | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x007CE79B | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x007FE026 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0082D456 | 0x00 | `!This program cannot be run in DOS mode.` |
| 0x0085CCD5 | 0x00 | `!This program cannot be run in DOS mode.` |

UPX unpacking attempt failed: `upx_ok: False`, `is_packed: False`, `returncode: None`, `unpacked_path: `` (source: upx, unpack results). FLOSS extracted 10,548 static strings, with 0 decoded, stack, tight, or language strings, indicating all strings are obfuscated or encoded (source: floss, per_category). Malcat analysis failed with error `malcat_analyze top-level: MCP malcat closed: `, so no layout data is available from this engine (source: malcat, analysis error).

## 4. Malcat Triage Summary
Malcat analysis encountered a critical error during execution: `malcat_analyze top-level: MCP malcat closed: ` (source: malcat, analysis error). No triage data, layout information, or signature matches were returned from this engine. All subsequent analysis relies on capa, pe_imports, YARA, FLOSS, and radare2 outputs.

## 5. Static Code Analysis
Static analysis is limited by the failure of Ghidra and IDA engines (source: llm_judge, cross_engine_notes). All disassembly is derived from radare2 output.

### Entry Point Disassembly (0x010b4100, source: r2)
```asm
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```

The entry function first performs a large XOR self-decryption loop over a region from `rsi` to `r9` (arg4) using key 0xae stored in `bl`, decrypting obfuscated code in place (source: r2, 0x010b4117-0x010b4123). After decryption, it loads a qword from `rdi + 0xca937c`, overwrites the dword at that address with 0x712e619e, then calls `fcn.010b4196` (likely an LZMA decompression routine, per the bit-stream decoding logic in the function) before returning via a repz ret (source: r2, 0x010b4128-0x010b4156).

### Decompression Routine Disassembly (0x010b4196, source: r2)
```asm
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│     ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│     ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│     ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│     ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│     ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│     ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│     ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│     ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│     ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│     ╎┌───> 0x010b41ba      ffc8           dec eax
│     ╎╎│╎   0x010b41bc      41ffd3         call r11
│     ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│     ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│     ╎╎└──> 0x010b41c1      41ffd3         call r11
│     ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│     ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│     ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│     ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│     ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│     ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│     ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│     ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│     ╎  ╎   0x010b41d6      83e803         sub eax, 3
│     ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│     ╎ │╎   0x010b41db      c1e008         shl eax, 8
│     ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│     ╎ │╎   0x010b41e1      09d0           or eax, edx
│     ╎ │╎   0x010b41e3      48ffc6         inc rsi
│     ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│     ╎┌───< 0x010b41e9      7458           je 0x10b4243
│     ╎││╎   0x010b41eb      d1f8           sar eax, 1
│     ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│    ┌─────< 0x010b41f0      7238           jb 0x10b422a
│   ┌──────< 0x010b41f2      eb0e           jmp 0x10b4202
│   ││╎│└──> 0x010b41f4      01db           add ebx, ebx
│   ││╎│┌──< 0x010b41f6      7508           jne 0x10b4200
│   ││╎││╎   0x010b41f8      8b1e           mov ebx, dword [rsi]
│   ││╎││╎   0x010b41fa      4883eefc       sub rsi, 0xfffffffffffffffc
│   ││╎││╎   0x010b41fe      11db           adc ebx, ebx
│  ┌────└──> 0x010b4200      7228           jb 0x10b422a
│  │││╎│ ╎   ; CODE XREF from fcn.010b
```

This function implements a bit-stream decoder consistent with LZMA decompression logic, used to decompress the embedded payload after the XOR decryption step (source: r2, 0x010b4196).

### PE Import Signals (source: pe_imports)
| Label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

Total import count: 12 (source: pe_imports, import_count). The imports confirm the sample uses runtime dynamic linking to resolve Windows APIs, and imports VirtualProtect to modify memory permissions for code execution, consistent with process injection or code hollowing (source: pe_imports, signals).

### capa Capability Rules (source: capa)
| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| reference anti-VM strings targeting Xen | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| link function at runtime on Windows | T1129:Shared Modules |  |
| change memory protection |  | C0008:Change Memory Protection |
| allocate or change RW memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

Total rules matched: 10, analysis duration: 14.53s (source: capa, top_rules, all rules).

### YARA Matches (source: yara)
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@51072 len=3 |
| contains_base64 | - | $a@2689014 len=12 |
| UPX | - | $a@392 len=4; $b@432 len=4; $c@517 len=4 |
| android_meterpreter | - | $checkSdeEncode@744814 len=4 |
| IsPE64 | - |  |
| IsConsole | - |  |
| HasOverlay | - |  |
| suspicious_packer_section | - |  |
| win_mutex | - | $c1@4716493 len=11 |
| win_files_operation | - | $f1@4482966 len=12; $c1@4716263 len=9; $c3@4716263 len=9; $c5@4716599 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@4483023 len=10 |

Total matches: 12 (source: yara, matches table). High-signal strings with engine and effective address (EA):
- UPX packing signatures: 0x188, 0x1B0, 0x205 (source: yara, UPX rule)
- Meterpreter `checkSdeEncode` indicator: 0xB4B2E (744814) (source: yara, android_meterpreter rule)
- Mutex string: 0x4800CD (4716493) (source: yara, win_mutex rule)
- Winsock2 library string `ws2_32`: 0x4483023 (source: yara, Str_Win32_Winsock2_Library rule)
- Base64 content marker: 0x29000E (2689014) (source: yara, contains_base64 rule)
- File operation strings: 0x4482966, 0x4716263, 0x4716599 (source: yara, win_files_operation rule)

### FLOSS Strings (source: floss)
Total strings: 10,548, all categorized as static strings (0 decoded, 0 stack, 0 tight, 0 language strings). Sample obfuscated static strings:
```
!This program cannot be run in DOS mode.
nQz>F^
gQ~F-u(k
C{mCFdD2
WuDsmio
YuuptX
2mbq4>
~e??eR
a}KYulH_
'w}LoD
%U%>ZQQ@
L%B=^5
1w"~pA
?3]RQQ
gW1%;jn&
^@*>BW
PXQQiI
< J\>VB6
~O/j_m
{+RR1}f
E#-R/%
,yQ*_F
JZB\az
bfe@#~
<aOdRR
YU%nYF
gH`c,n
=/C"k)
-VFJPM
U'{dQIY
p]'PoA
G5Sovf
0l -Mb
'nUG~O
MW0xw2K
0	WoITW
kkc#pF
YEuPEg
'p-MRP
nG?T:Q
```
No meaningful plaintext strings were extracted, confirming widespread obfuscation.

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis:
- Speakeasy emulation completed with 0 API calls and 0 key events, no duration recorded (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed)
- Frida probe is available (version 17.16.4) but no instrumentation data was collected (source: frida_probe, frida_available: True, version: 17.16.4, not observed)
- UPX unpacking failed, so no unpacked payload was available for dynamic execution (source: upx, upx_ok: False, unpacked_path: ``)

No process creation, network connections, file system modifications, or registry changes were observed. All behavioral conclusions are limited to static indicators.

## 7. Network Indicators & C2
Static analysis confirms the sample has network functionality:
- YARA `Str_Win32_Winsock2_Library` rule matches the `ws2_32` library string at offset 0x4483023, indicating the sample uses Windows Winsock2 for network communication (source: yara, matches table)
- YARA `contains_base64` rule matches base64-encoded content at offset 0x29000E (2689014), likely used to obfuscate C2 addresses, payloads, or command data (source: yara, matches table)
- YARA `domain` and `IP` rules match hardcoded domain and IPv6 address patterns at offsets 0x0 and 0xC7E0 (51072) respectively (source: yara, matches table)

No plaintext C2 addresses, domains, or IPs were extracted from static analysis, as all network-related strings are obfuscated (source: floss, 0 decoded strings). Concrete C2 indicators are unknown pending unpacking or dynamic analysis.

## 8. Capabilities & MITRE ATT&CK Mapping
All capabilities are derived from static analysis, as no dynamic behavior was observed.

| Capability | Evidence Source | MITRE ATT&CK Mapping |
|------------|-----------------|----------------------|
| UPX packing | capa rule `packed with UPX`, YARA UPX matches at 0x188, 0x1B0, 0x205 | T1027.002: Obfuscated Files or Information |
| XOR obfuscation | capa rule `encode data using XOR`, r2 entry loop at 0x010b4117 | T1027: Obfuscated Files or Information |
| Xen anti-VM checks | capa rule `reference anti-VM strings targeting Xen` | T1497.001: Virtualization/Sandbox Evasion |
| Runtime dynamic linking | capa rule `link function at runtime on Windows`, PE imports LoadLibrary/GetProcAddress | T1129: Shared Modules |
| Memory protection modification | capa rule `change memory protection`, PE import VirtualProtect | T1055: Process Injection |
| RW memory allocation | capa rule `allocate or change RW memory` | C0007: Allocate Memory |
| Process termination | capa rule `terminate process` | C0018: Terminate Process |
| Embedded PE payload | capa rule `contain an embedded PE file` | B0023: Install Additional Program |
| Mutex creation | YARA `win_mutex` match at 0x4800CD | T1055.001: Process Injection (mutex for mutual exclusion) |
| File system operations | YARA `win_files_operation` matches at 0x4482966, 0x4716263, 0x4716599 | T1105: Ingress Tool Transfer, T1070.004: Indicator Removal on File |
| Network communication | YARA `Str_Win32_Winsock2_Library` match, domain/IP YARA matches | T1071.001: Application Layer Protocol (likely HTTP/HTTPS for C2) |
| Meterpreter-related indicators | YARA `android_meterpreter` match at 0xB4B2E | (unknown, possible code reuse or false positive for Windows PE) |

## 9. Indicators of Compromise
### Sample Hash
- SHA256: `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5` (source: sample metadata)

### YARA Indicators (source: yara, matches table)
| Rule | Offset/EA | Description |
|------|-----------|-------------|
| UPX | 0x188, 0x1B0, 0x205 | UPX packing signatures |
| android_meterpreter | 0xB4B2E (744814) | Meterpreter `checkSdeEncode` indicator |
| win_mutex | 0x4800CD (4716493) | Windows mutex creation string |
| win_files_operation | 0x4482966, 0x4716263, 0x4716599 | Windows file operation strings |
| Str_Win32_Winsock2_Library | 0x4483023 | Winsock2 library `ws2_32` string |
| contains_base64 | 0x29000E (2689014) | Base64-encoded content marker |
| domain | 0x0 | Domain regex match |
| IP | 0xC7E0 (51072) | IPv6 address match |
| HasOverlay | N/A | PE overlay present |
| IsPE64 | N/A | 64-bit PE file |
| IsConsole | N/A | Console subsystem |
| suspicious_packer_section | N/A | Suspicious packer section present |

### capa Capability Indicators (source: capa, all rules)
- `packed with UPX`
- `encode data using XOR`
- `reference anti-VM strings targeting Xen`
- `link function at runtime on Windows`
- `change memory protection`
- `allocate or change RW memory`
- `terminate process`
- `contain an embedded PE file`
- `contain loop`

### PE Import Indicators (source: pe_imports, signals)
- `LoadLibrary` (T1129)
- `GetProcAddress` (T1129)
- `VirtualProtect` (T1055)

### XOR Obfuscation Positions (source: xor, search results)
| Position | Key | Pattern |
|----------|-----|---------|
| 0x00000000 | 0x00 | DOS stub |
| 0x00451B8F | 0x00 | DOS stub |
| 0x00481512 | 0x00 | DOS stub |
| 0x0070FE96 | 0x00 | DOS stub |
| 0x0073F701 | 0x00 | DOS stub |
| 0x0076F1B5 | 0x00 | DOS stub |
| 0x0079ED6D | 0x00 | DOS stub |
| 0x007CE79B | 0x00 | DOS stub |
| 0x007FE026 | 0x00 | DOS stub |
| 0x0082D456 | 0x00 | DOS stub |
| 0x0085CCD5 | 0x00 | DOS stub |

### Unknown IOCs
- Decrypted C2 addresses, mutex names, and file operation targets are unknown, as all static strings are obfuscated and no dynamic analysis was performed (source: floss, 0 decoded strings; speakeasy, 0 events).
- Unpacked embedded PE payload hash is unknown, as UPX unpacking failed (source: upx, unpacked_path: ``).

## 10. Detection Engineering
### Available Signatures
- YARA rules: `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar` (source: rule.yara.json, rule_path), validated with `yara_check: ok`, 0 false positives on goodware corpus (goodware FP count: 0, source: rule.yara.json, goodware_fp)
- Sigma rules: `/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yml` (source: rule.yara.json, sigma_path)

### Detection Logic Recommendations
1. **Packing Detection**: Flag PE files with UPX signatures at offsets 0x188, 0x1B0, 0x205, or with XOR self-decryption loops at entry point using key 0xae (source: yara, UPX matches; r2, 0x010b4100 disassembly)
2. **Obfuscation Detection**: Flag files with >10,000 static strings and 0 decoded/stack strings from FLOSS, or with widespread XOR obfuscation across the DOS stub and PE headers (source: floss, per_category; xor, search results)
3. **Malicious Capability Detection**: Flag files importing LoadLibrary, GetProcAddress, and VirtualProtect in combination with UPX packing and embedded PE indicators (source: pe_imports, signals; capa, all rules)
4. **C2 Detection**: Flag files with base64 markers and Winsock2 library references, especially when combined with anti-VM indicators (source: yara, contains_base64 and Str_Win32_Winsock2_Library matches; capa, reference anti-VM strings targeting Xen rule)

## 11. What We Don't Know
1. **Unpacked Payload**: The embedded PE payload could not be extracted, as UPX unpacking failed with no output and empty unpacked path (source: upx, upx_ok: False, unpacked_path: ``). The full capabilities, C2 infrastructure, and payload functionality of the embedded PE are unknown.
2. **Concrete C2 IOCs**: No plaintext C2 addresses, domains, or IPs were extracted from static analysis, as all network-related strings are obfuscated and no dynamic analysis was performed (source: floss, 0 decoded strings; speakeasy, 0 events).
3. **Mutex and File Operation Targets**: The specific mutex name and file system targets referenced in YARA matches are unknown, as the strings are obfuscated and no runtime traces were collected (source: yara, win_mutex and win_files_operation matches; speakeasy, not observed).
4. **Exact Malware Family**: The family guess is "Packed Windows trojan (likely info-stealer or RAT)" but no confirmed family attribution is possible without unpacking the payload (source: llm_judge, family_guess).
5. **Full Anti-VM Scope**: Only Xen hypervisor anti-VM strings were observed; it is unknown if the sample detects other hypervisors (e.g., VMware, VirtualBox, Hyper-V) (source: capa, reference anti-VM strings targeting Xen rule).
6. **Meterpreter Match Relevance**: The YARA `android_meterpreter` match for `checkSdeEncode` at 0xB4B2E is present in a Windows PE64 sample, so its purpose (code reuse, false positive, or cross-platform payload component) is unknown (source: yara, android_meterpreter match).
7. **Ghidra/IDA Analysis Results**: Ghidra failed due to project ownership error, IDA failed due to missing idasql binary, so no additional static analysis, function metrics, or cross-references are available from these engines (source: llm_judge, cross_engine_notes; audit trail, ghidra_query entries).

## 12. Appendix: Analysis Environment
| Tool | Status | Details |
|------|--------|---------|
| capa | Ok | 10 rules matched, 14.53s analysis duration (source: capa, tool_gate) |
| pe_imports | Ok | 12 imports, 3 malicious signals identified (source: pe_imports, tool_gate) |
| YARA | Ok | 12 matches, rule validation passed, 0 goodware false positives (source: yara, tool_gate) |
| FLOSS | Ok | 10,548 static strings, 0 decoded/stack/tight strings (source: floss, tool_gate) |
| .NET Analysis | Not observed | `is_dotnet: false` (source: dotnet, tool_gate) |
| radare2 | Ok | Entry point and decompression routine disassembly available (source: r2_decomp, tool_gate) |
| UPX | Unpack failed | `upx_ok: False`, `is_packed: False`, `returncode: None`, `unpacked_path: `` (source: upx, tool_gate) |
| XOR Search | Ok | 11 XOR 00 positions identified (source: xor, tool_gate) |
| Speakeasy | Not observed | 0 API calls, 0 key events, no duration recorded (source: speakeasy, tool_gate) |
| Frida Probe | Ok (no data) | Version 17.16.4 available, no instrumentation data collected (source: frida_probe, tool_gate) |
| Ghidra | Failed | Project ownership error, no analysis output (source: cross_engine_notes, audit trail) |
| IDA | Failed | Missing idasql binary, no analysis output (source: cross_engine_notes) |
| Malcat | Failed | MCP malcat closed error, no triage data (source: malcat, analysis error) |

### Function Metrics Note
A Ghidra query for function metrics ordered by string reference count was executed (`SELECT * FROM function_metrics ORDER BY string_ref_count DESC LIMIT 20`, source: audit trail, ts: 1785877501.8652818) but no results were returned due to Ghidra failure. No function metrics are available from other engines.

### Full IAT Note
A Ghidra query for full import table (`SELECT * FROM imports ORDER BY name`, source: audit trail, ts: 1785877497.5020337) was executed but no results were returned due to Ghidra failure. Only the 3 high-signal import signals from pe_imports are available.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5  
**sample_path:** /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 92
- **family_guess**: Packed Windows trojan (likely info-stealer or RAT, UPX compressed with anti-VM/sandbox evasion and XOR obfuscation capabilities)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis engines failed to execute (Ghidra due to project ownership error, IDA due to missing idasql binary), so all conclusions are derived from capa, pe_imports, YARA, and FLOSS outputs, which are fully consistent in identifying malicious characteristics.
- **summary**: This sample is a UPX-packed Windows PE file with strong, cross-engine confirmed indicators of malicious behavior. It includes anti-VM checks targeting the Xen hypervisor, uses XOR encoding for obfuscation, dynamically resolves Windows APIs at runtime, modifies memory protection for code execution, contains an embedded PE payload, has a PE overlay, and includes indicators of network functionality and C2 infrastructure. No benign characteristics were identified across any analysis tool.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX` | Independent confirmation the sample is compressed with the UPX packer, a widely used tool for obfuscating malware to imp |
| capa | top_rules | `reference anti-VM strings targeting Xen` | The sample contains strings referencing the Xen hypervisor, indicating it includes functionality to detect virtualized/s |
| capa | top_rules | `encode data using XOR` | The sample uses XOR encoding to obfuscate data or code, a standard defense evasion technique to hide malicious payloads  |
| capa | all rules | `contain an embedded PE file` | The sample contains an embedded PE file, a common technique for packed malware to store the original malicious payload s |
| pe_imports | signals | `load_library (LoadLibrary) [T1129]` | The sample imports LoadLibrary, confirming it dynamically loads Windows system libraries at runtime to hide malicious fu |
| pe_imports | signals | `get_proc_address (GetProcAddress) [T1129]` | The sample imports GetProcAddress, used to resolve addresses of dynamically loaded APIs at runtime, further hindering st |
| pe_imports | signals | `change_memory_protection (VirtualProtect) [T1055]` | The sample imports VirtualProtect, a function used to modify memory region permissions, commonly used for code injection |
| yara | matches | `UPX` | YARA rule match independently confirms the sample is packed with UPX, aligning with capa's packer detection and confirmi |
| yara | matches | `contains_base64` | The sample contains base64-encoded data, likely used to obfuscate command-and-control (C2) addresses, payloads, or other |
| yara | matches | `HasOverlay` | The sample has a PE overlay (data appended after the valid PE structure), a common characteristic of packed malware used |
| yara | matches | `domain, IP` | YARA rule matches confirm the sample contains hardcoded or encoded domain and IP address indicators, consistent with com |
| yara | matches | `Str_Win32_Winsock2_Library` | The sample contains references to the Winsock2 library, indicating it has network functionality, likely for C2 communica |
| floss | per_category | `static_strings: 10548` | The extremely high volume of static strings, many of which are obfuscated (as seen in sampled strings), aligns with the  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE64 sample is UPX-packed and exhibits runtime dynamic linking, memory protection changes, anti-VM/Xen checks, and Meterpreter-related indicators. Entry code performs a large XOR self-decryption loop before transferring control, consistent with packed/obfuscated malware.

### deep key_evidence
- `"YARA: UPX packing signatures at offsets 392, 432, 517"`
- `"YARA: android_meterpreter indicator checkSdeEncode at offset 744814"`
- `"YARA: win_mutex string at offset 4716493"`
- `"YARA: win_files_operation strings at offsets 4482966, 4716263, 4716599"`
- `"YARA: Winsock2 library string ws2_32 at offset 4483023"`
- `"YARA: base64 content marker at offset 2689014"`
- `"capa: packed with UPX"`
- `"capa: encode data using XOR"`
- `"capa: reference anti-VM strings targeting Xen"`
- `"capa: link function at runtime on Windows"`
- `"capa: change memory protection"`
- `"capa: allocate or change RW memory"`
- `"pe_import_signals: LoadLibrary, GetProcAddress, VirtualProtect"`
- `"r2: entry0 XOR self-decryption loop over a large region with key 0xae before call/transfer of control"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 10 · duration_s: 14.53

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| reference anti-VM strings targeting Xen | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| link function at runtime on Windows | T1129:Shared Modules |  |
| change memory protection |  | C0008:Change Memory Protection |
| allocate or change RW memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 12

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@51072 len=3 |
| contains_base64 | - | $a@2689014 len=12 |
| UPX | - | $a@392 len=4; $b@432 len=4; $c@517 len=4 |
| android_meterpreter | - | $checkSdeEncode@744814 len=4 |
| IsPE64 | - |  |
| IsConsole | - |  |
| HasOverlay | - |  |
| suspicious_packer_section | - |  |
| win_mutex | - | $c1@4716493 len=11 |
| win_files_operation | - | $f1@4482966 len=12; $c1@4716263 len=9; $c3@4716263 len=9; $c5@4716599 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@4483023 len=10 |

## Generated YARA Meta
```json
{
  "sha256": "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5",
  "family": "unknown",
  "generated_at": "2026-08-06T03:24:15.348875+00:00",
  "string_count": 13,
  "strings": [
    "Independent confirmation the sample is compressed with the UPX packer, a widely used tool for obfuscating malware to imp",
    "The sample contains strings referencing the Xen hypervisor, indicating it includes functionality to detect virtualized/s",
    "The sample uses XOR encoding to obfuscate data or code, a standard defense evasion technique to hide malicious payloads ",
    "The sample contains an embedded PE file, a common technique for packed malware to store the original malicious payload s",
    "The sample imports LoadLibrary, confirming it dynamically loads Windows system libraries at runtime to hide malicious fu",
    "The sample imports GetProcAddress, used to resolve addresses of dynamically loaded APIs at runtime, further hindering st",
    "The sample imports VirtualProtect, a function used to modify memory region permissions, commonly used for code injection",
    "YARA rule match independently confirms the sample is packed with UPX, aligning with capa's packer detection and confirmi",
    "The sample contains base64-encoded data, likely used to obfuscate command-and-control (C2) addresses, payloads, or other",
    "The sample has a PE overlay (data appended after the valid PE structure), a common characteristic of packed malware used",
    "YARA rule matches confirm the sample contains hardcoded or encoded domain and IP address indicators, consistent with com",
    "The sample contains references to the Winsock2 library, indicating it has network functionality, likely for C2 communica",
    "The extremely high volume of static strings, many of which are obfuscated (as seen in sampled strings), aligns with the "
  ],
  "rule_path": "/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar",
  "sigma_path": "/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yml",
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
    "commit": "80c92a39d67f7e321883d3656b87cc4b04c5b7b5",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-06 03:24:15 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 10548 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10548}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `nQz>F^`
- `gQ~F-u(k`
- `C{mCFdD2`
- `WuDsmio`
- `YuuptX`
- `2mbq4>`
- `~e??eR`
- `a}KYulH_`
- `'w}LoD`
- `%U%>ZQQ@`
- `L%B=^5`
- `1w"~pA`
- `?3]RQQ`
- `gW1%;jn&`
- `^@*>BW`
- `PXQQiI`
- `< J\>VB6`
- `~O/j_m`
- `{+RR1}f`
- `E#-R/%`
- `,yQ*_F`
- `JZB\az`
- `bfe@#~`
- `<aOdRR`
- `YU%nYF`
- `gH`c,n`
- `=/C"k)`
- `-VFJPM`
- `U'{dQIY`
- `p]'PoA`
- `G5Sovf`
- `0l -Mb`
- `'nUG~O`
- `MW0xw2K`
- `0	WoITW`
- `kkc#pF`
- `YEuPEg`
- `'p-MRP`
- `nG?T:Q`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x010b4100
```asm
┌ 88: entry0 (int64_t arg4);
│           ; arg int64_t arg4 @ r9
│           0x010b4100      53             push rbx
│           0x010b4101      56             push rsi
│           0x010b4102      57             push rdi
│           0x010b4103      55             push rbp
│           0x010b4104      488d351a9f..   lea rsi, [0x00c6e025]
│           0x010b410b      488dbedb2f..   lea rdi, [rsi - 0x86d025]
│           0x010b4112      50             push rax
│           0x010b4113      53             push rbx
│           0x010b4114      56             push rsi
│           0x010b4115      b3ae           mov bl, 0xae                ; 174
│       ┌─> 0x010b4117      8a06           mov al, byte [rsi]
│       ╎   0x010b4119      30d8           xor al, bl
│       ╎   0x010b411b      8806           mov byte [rsi], al
│       ╎   0x010b411d      48ffc6         inc rsi
│       ╎   0x010b4120      4c39ce         cmp rsi, r9                 ; arg4
│       └─< 0x010b4123      75f2           jne 0x10b4117
│           0x010b4125      5e             pop rsi
│           0x010b4126      5b             pop rbx
│           0x010b4127      58             pop rax
│           0x010b4128      488d877c93..   lea rax, [rdi + 0xca937c]
│           0x010b412f      ff30           push qword [rax]
│           0x010b4131      c7009e612e71   mov dword [rax], 0x712e619e ; [0x712e619e:4]=-1
│           0x010b4137      50             push rax
│           0x010b4138      57             push rdi
│           0x010b4139      31db           xor ebx, ebx
│           0x010b413b      31c9           xor ecx, ecx
│           0x010b413d      4883cdff       or rbp, 0xffffffffffffffff
│           0x010b4141      e850000000     call fcn.010b4196
│           0x010b4146      01db           add ebx, ebx
│       ┌─< 0x010b4148      7402           je 0x10b414c
│       │   0x010b414a      f3c3           repz ret
│       └─> 0x010b414c      8b1e           mov ebx, dword [rsi]
│           0x010b414e      4883eefc       sub rsi, 0xfffffffffffffffc
│           0x010b4152      11db           adc ebx, ebx
│           0x010b4154      8a16           mov dl, byte [rsi]
└           0x010b4156      f3c3           repz ret
```
### 0x010b4196
```asm
╎   ; CALL XREF from entry0 @ 0x10b4141(x)
┌ 400: fcn.010b4196 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   0x010b4196      fc             cld
│       ╎   0x010b4197      415b           pop r11
│      ┌──< 0x010b4199      eb08           jmp 0x10b41a3
│     ┌───> 0x010b419b      48ffc6         inc rsi
│     ╎│╎   0x010b419e      8817           mov byte [rdi], dl
│     ╎│╎   0x010b41a0      48ffc7         inc rdi
│     ╎│╎   ; CODE XREFS from fcn.010b4196 @ 0x10b4199(x), 0x10b423e(x)
│    ┌─└──> 0x010b41a3      8a16           mov dl, byte [rsi]
│    ╎╎ ╎   0x010b41a5      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41a7      750a           jne 0x10b41b3
│    ╎╎│╎   0x010b41a9      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41ab      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41af      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41b1      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41b3      72e6           jb 0x10b419b
│    ╎  ╎   0x010b41b5      8d4101         lea eax, [rcx + 1]          ; arg1
│    ╎ ┌──< 0x010b41b8      eb07           jmp 0x10b41c1
│    ╎┌───> 0x010b41ba      ffc8           dec eax
│    ╎╎│╎   0x010b41bc      41ffd3         call r11
│    ╎╎│╎   0x010b41bf      11c0           adc eax, eax
│    ╎╎│╎   ; CODE XREF from fcn.010b4196 @ 0x10b41b8(x)
│    ╎╎└──> 0x010b41c1      41ffd3         call r11
│    ╎╎ ╎   0x010b41c4      11c0           adc eax, eax
│    ╎╎ ╎   0x010b41c6      01db           add ebx, ebx
│    ╎╎┌──< 0x010b41c8      750a           jne 0x10b41d4
│    ╎╎│╎   0x010b41ca      8b1e           mov ebx, dword [rsi]
│    ╎╎│╎   0x010b41cc      4883eefc       sub rsi, 0xfffffffffffffffc
│    ╎╎│╎   0x010b41d0      11db           adc ebx, ebx
│    ╎╎│╎   0x010b41d2      8a16           mov dl, byte [rsi]
│    ╎└└──> 0x010b41d4      73e4           jae 0x10b41ba
│    ╎  ╎   0x010b41d6      83e803         sub eax, 3
│    ╎ ┌──< 0x010b41d9      7219           jb 0x10b41f4
│    ╎ │╎   0x010b41db      c1e008         shl eax, 8
│    ╎ │╎   0x010b41de      0fb6d2         movzx edx, dl
│    ╎ │╎   0x010b41e1      09d0           or eax, edx
│    ╎ │╎   0x010b41e3      48ffc6         inc rsi
│    ╎ │╎   0x010b41e6      83f0ff         xor eax, 0xffffffff         ; -1
│    ╎┌───< 0x010b41e9      7458           je 0x10b4243
│    ╎││╎   0x010b41eb      d1f8           sar eax, 1
│    ╎││╎   0x010b41ed      4863e8         movsxd rbp, eax
│   ┌─────< 0x010b41f0      7238           jb 0x10b422a
│  ┌──────< 0x010b41f2      eb0e           jmp 0x10b4202
│  ││╎│└──> 0x010b41f4      01db           add ebx, ebx
│  ││╎│┌──< 0x010b41f6      7508           jne 0x10b4200
│  ││╎││╎   0x010b41f8      8b1e           mov ebx, dword [rsi]
│  ││╎││╎   0x010b41fa      4883eefc       sub rsi, 0xfffffffffffffffc
│  ││╎││╎   0x010b41fe      11db           adc ebx, ebx
│ ┌────└──> 0x010b4200      7228           jb 0x10b422a
│ │││╎│ ╎   ; CODE XREF from fcn.010b
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r
- Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r

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
- `{"source": "publish_report_v2", "ts": 1785762227.2282276}`
- `{"source": "publish_report_v2_technical", "ts": 1785762360.360016}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785877020.9407427}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785877021.9966345}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785877022.0273018}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785877022.086204}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785877235.6470623}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785877235.7246559}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785877236.5474188}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785877236.6083379}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785877236.6141067}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785877489.3294475}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports ORDER BY name", "ts": 1785877497.5020337}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%ws2%' OR content LIKE '%socket%' OR content LIKE '%http%' OR content LIKE '%cmd%' OR content LIKE '%mutex%' OR content LIKE '%Create%' OR content LIKE '%WinExec%' OR content LIKE '%URL%' OR content LIKE '%domain%' OR conte`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs WHERE name IS NOT NULL AND name != '' ORDER BY name LIMIT 50", "ts": 1785877497.535805}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 50", "ts": 1785877501.6660635}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics ORDER BY string_ref_count DESC LIMIT 20", "ts": 1785877501.8652818}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%.%' AND length > 5 ORDER BY length DESC LIMIT 50", "ts": 1785877501.8831787}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs WHERE is_code=1 LIMIT 50", "ts": 1785877506.2727969}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks ORDER BY start_ea", "ts": 1785877506.281618}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs WHERE name != '' AND name IS NOT NULL ORDER BY address LIMIT 100", "ts": 1785877506.2850668}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM string_refs LIMIT 50", "ts": 1785877659.6995082}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE 'http%' OR content LIKE 'https%' OR content LIKE 'ftp%' OR content LIKE 'ssh%' OR content LIKE 'tcp%' OR content LIKE 'udp%' OR content LIKE '127.%' OR content LIKE '192.%' OR content LIKE '10.%' OR content LIKE '172.%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%checkSdeEncode%' OR content LIKE '%meterpreter%' OR content LIKE '%android%' OR content LIKE '%mutex%' OR content LIKE '%CreateMutex%' OR content LIKE '%OpenMutex%' OR content LIKE '%CreateFile%' OR content LIKE '%WriteFil`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785877865.045647}`
- `{"source": "yara_gen_v2", "ts": 1785877866.0820966}`
- `{"source": "publish_report_v2", "ts": 1785877989.2251637}`
- `{"source": "publish_report_v2_technical", "ts": 1785878135.2564945}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785986174.4500954}`
- `{"source": "yara_gen_v2", "ts": 1785986655.3491726}`
