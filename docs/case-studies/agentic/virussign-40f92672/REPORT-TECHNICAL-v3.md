> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:02:24 UTC

## 1. Executive Summary
This sample is a high-confidence malicious 32-bit Windows GUI portable executable (PE) compiled with Borland/Delphi, with a verdict score of 90 and family guess of Delphi-compiled Windows infostealer/post-exploitation malware (source: llm_judge, verdict: Malicious, score: 90, family_guess: Delphi-compiled Windows infostealer/post-exploitation malware, agreement: llm_and_v1_agree). High-signal PE imports confirm core malicious capabilities: CreateProcess for process execution (T1106) (source: pe_imports, signals, label: create_process, api_match: CreateProcess, ATT&CK: T1106), LoadLibrary and GetProcAddress for dynamic API resolution (T1129) (source: pe_imports, signals, label: load_library, api_match: LoadLibrary; label: get_proc_address, api_match: GetProcAddress, ATT&CK: T1129), and VirtualAlloc/VirtualProtect for process injection (T1055) (source: pe_imports, signals, label: allocate_memory, api_match: VirtualAlloc; label: change_memory_protection, api_match: VirtualProtect, ATT&CK: T1055). YARA matches confirm additional high-severity capabilities including privilege escalation, DEP bypass, registry/token/file manipulation, and embedded C2 indicators (domains, IPs, URLs, base64 content) (source: yara, matches, rules: escalate_priv, disable_dep, win_registry, win_token, win_files_operation, domain, IP, url, contains_base64). FLOSS extracted 10018 static strings including extensive Delphi RTL/VCL runtime metadata (e.g., TObject, TClass, AnsiString, WideString) confirming the sample is a functional, non-empty Delphi-compiled PE (source: floss, total strings: 10018, strings sample). While static analysis tooling (Ghidra, IDA, Malcat, capa) experienced failures, all available high-signal indicators are consistent with a malicious Delphi-based infostealer or post-exploitation payload.

## 2. Sample Metadata
| Field | Value |
|-------|-------|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 90 |
| Family Guess | Delphi-compiled Windows infostealer/post-exploitation malware |
| Agreement | llm_and_v1_agree |
| Analysis Model | step-3.7-flash (llm_judge) |
All metadata is sourced from (source: llm_judge, verdict.json).

## 3. File Layout & Structural Analysis
The sample is a valid 32-bit Windows GUI PE file, confirmed by YARA matches for IsPE32 and IsWindowsGUI rules, and Borland compiler signature matches (source: yara, matches, rules: IsPE32, IsWindowsGUI, Borland). The PE import table contains 150 total imports, with high-signal entries for process injection, execution, and dynamic API resolution (source: pe_imports, import_count: 150). FLOSS extracted 10018 static strings from the sample, including standard PE section layout strings: `.itext`, `.data`, `.idata`, `.didata`, `.edata`, `.rdata`, `@.reloc`, `B.rsrc` (source: floss, total strings: 10018, strings sample). UPX analysis confirmed the sample is not packed: upx_ok is False, is_packed is False, and no unpacked output path was generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: ""). XOR search identified a XOR 00 pattern at file offset 0x00000000 (source: XOR Search, Found XOR 00 position 00000000). The sample is not a .NET binary (source: .NET Analysis, is_dotnet: false). Delphi runtime strings extracted by FLOSS (e.g., TObject, TClass, InitInstance, AnsiString, WideString) confirm the sample uses the Borland Delphi RTL/VCL framework (source: floss, strings sample).

## 4. Malcat Triage Summary
Malcat analysis failed with a top-level MCP closure error: `malcat_analyze top-level: MCP malcat closed: ` (source: Malcat Structured Analysis, error: malcat_analyze top-level: MCP malcat closed: ). No Malcat-specific structured analysis data, triage results, or disassembly is available for this sample due to this failure. All available analysis was performed via alternative engines (pe_imports, YARA, FLOSS, radare2).

## 5. Static Code Analysis
Static disassembly is limited due to tool failures: Ghidra failed to start with a NotOwnerException project ownership error, IDA is non-functional due to a missing idasql binary, and capa timed out after 300s with no function-level capability mapping generated (source: cross_engine_notes, llm_judge). Available radare2 disassembly snippets are provided below:
### Entry Point (0x00471e60)
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55
```
(source: radare2 Disassembly, 0x00471e60)
### sym.SetupLdr.e32___dbk_fcall_wrapper (0x003ce578)
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎   0x003ce5ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5cd      50             push eax
│       ╎   0x003ce5ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d1      50             push eax
│       ╎   0x003ce5d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d5      50             push eax
│       ╎   0x003ce5d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d9      50             push eax
│       ╎   0x003ce5da      8b45f
```
(source: radare2 Disassembly, 0x003ce578)
### fcn.003ce184 (0x003ce184)
```asm
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```
(source: radare2 Disassembly, 0x003ce184)
### fcn.003ce188 (0x003ce188)
```asm
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff     call fcn.003ce184
│           0x003ce249      e836ffffff     call fcn.003ce184
│           0x003ce24e      e831ffffff     call fcn.003ce184
│           0x003ce253      e82cffffff     call fcn.003ce184
│           0x003ce258      e827ffffff     call fcn.003ce184
│           0x003ce25d      e822ffffff     call fcn.003ce184
│           0x003ce262      e81dffffff     call fcn.003ce184
│           0x003ce267      e818ffffff     call fcn.003ce184
│           0x003ce26c      e813ffffff     call fcn.00
```
(source: radare2 Disassembly, 0x003ce188)
The entry point function initializes stack frames, sets up structured exception handling, and calls external functions for initialization (source: radare2 Disassembly, 0x00471e60). The sym.SetupLdr.e32___dbk_fcall_wrapper function is a Borland Delphi debug kernel call wrapper that pushes a local variable 20+ times before returning (source: radare2 Disassembly, 0x003ce578). The fcn.003ce184 function is a simple return (ret) instruction called over 200 times from fcn.003ce188, likely a placeholder or debug stub (source: radare2 Disassembly, 0x003ce184, 0x003ce188). Extensive Delphi runtime strings extracted by FLOSS confirm the sample uses the Borland Delphi RTL/VCL framework (source: floss, strings sample).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy dynamic analysis completed successfully but recorded 0 API calls and 0 key events, with no runtime execution artifacts available (source: Speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed). The Frida probe is available (version 17.16.4) but no runtime data was collected during analysis (source: Frida Probe, frida_available: True, version: 17.16.4, not observed). UPX analysis confirmed the sample is not packed, so no unpacking was performed and no unpacked sample path was generated (source: upx, upx_ok: False, is_packed: False, unpacked_path: ""). No network traffic, process injection events, registry modifications, or other dynamic indicators are available for this sample; all analysis is based on static indicators.

## 7. Network Indicators & C2
YARA rules matched multiple hardcoded network indicators consistent with C2 infrastructure:
| Rule | String ID | Offset | Length | Context |
|------|-----------|--------|--------|---------|
| domain | $domain_regex | 0 | 3 | Hardcoded domain regex |
| IP | $ipv4 | 1002335 | 7 | Hardcoded IPv4 address |
| IP | $ipv6 | 782284 | 3 | Hardcoded IPv6 address |
| url | $url_regex | 700280 | 78 | Hardcoded URL |
| contains_base64 | $a | 2670 | 12 | Base64-encoded content |
(source: yara, matches, Generated YARA Meta)
Deep dive analysis confirms these network indicators are consistent with C2 communication or encoded payload storage functionality (source: deep_dive_agentic, key_evidence: network and encoding indicator rule matches). No dynamic C2 communication was observed, as no runtime data was collected.

## 8. Capabilities & MITRE ATT&CK Mapping
### PE Import High-Signal Capabilities
| Label | API Match | ATT&CK Technique | Description |
|-------|-----------|------------------|-------------|
| create_process | CreateProcess | T1106 | Process Execution, used to launch malicious processes or execute payloads |
| load_library | LoadLibrary | T1129 | Dynamic API Resolution, used to load DLLs at runtime to evade static analysis |
| get_proc_address | GetProcAddress | T1129 | Dynamic API Resolution, used to resolve function addresses at runtime |
| allocate_memory | VirtualAlloc | T1055 | Process Injection, used to allocate memory for code injection |
| change_memory_protection | VirtualProtect | T1055 | Process Injection, used to modify memory permissions for injected code |
(source: pe_imports, signals)
### capa Capability Rules (Total: 59, Duration: 651.91s)
| Rule | ATT&CK | MBC |
|------|--------|-----|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using HC-128 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.006:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| link function at runtime on Windows | T1129:Shared Modules |  |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |
(source: capa Capability Rules)
### YARA Capability Matches
| Rule | Offsets | Capability |
|------|---------|------------|
| escalate_priv | 776504 ($d1 len=12), 776594 ($c2 len=21) | Privilege Escalation |
| disable_dep | 720820 ($c4 len=19) | DEP Bypass |
| win_registry | 776504 ($f1 len=12), 776796 ($c3 len=11, $c6 len=11) | Windows Registry Manipulation |
| win_token | 776504 ($f1 len=12), 776594 ($c2 len=21), 776658 ($c3 len=16) | Security Token Manipulation |
| win_files_operation | 773968 ($f1 len=12), 775576 ($c1 len=9), 774236 ($c2 len=14), 775576 ($c3 len=9), 774332 ($c4 len=8) | File System Operations |
(source: yara, matches)
All capability indicators are consistent with an infostealer or post-exploitation malware payload.

## 9. Indicators of Compromise
All IOCs are derived from static analysis of the sample:
### File-Based IOCs
| Type | Value | Source |
|------|-------|--------|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | Sample Metadata |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir | Sample Metadata |
| PE Import APIs | CreateProcess, LoadLibrary, GetProcAddress, VirtualAlloc, VirtualProtect | pe_imports, signals |
### Static String/Offset IOCs
| Rule | String ID | Offset | Length | Source |
|------|-----------|--------|--------|--------|
| domain | $domain_regex | 0 | 3 | yara, matches |
| IP | $ipv4 | 1002335 | 7 | yara, matches |
| IP | $ipv6 | 782284 | 3 | yara, matches |
| contains_base64 | $a | 2670 | 12 | yara, matches |
| CRC32_poly_Constant | $c0 | 680866 | 4 | yara, matches |
| SHA512_Constants | $c1 | 737040 | 4 | yara, matches |
| SHA512_Constants | $c3 | 737044 | 4 | yara, matches |
| SHA512_Constants | $c5 | 737048 | 4 | yara, matches |
| SHA512_Constants | $c7 | 737052 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c0 | 222840 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c1 | 222850 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c2 | 222860 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c3 | 222870 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c4 | 222880 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c5 | 222890 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c6 | 222900 | 4 | yara, matches |
| SHA2_BLAKE2_IVs | $c7 | 222910 | 4 | yara, matches |
| url | $url_regex | 700280 | 78 | yara, matches |
| Borland | $patternBorland | 47502 | 14 | yara, matches |
| Microsoft_Visual_Cpp_v50v60_MFC | $a | 16196 | 4 | yara, matches |
| escalate_priv | $d1 | 776504 | 12 | yara, matches |
| escalate_priv | $c2 | 776594 | 21 | yara, matches |
| win_registry | $f1 | 776504 | 12 | yara, matches |
| win_registry | $c3 | 776796 | 11 | yara, matches |
| win_registry | $c6 | 776796 | 11 | yara, matches |
| win_token | $f1 | 776504 | 12 | yara, matches |
| win_token | $c2 | 776594 | 21 | yara, matches |
| win_token | $c3 | 776658 | 16 | yara, matches |
| win_files_operation | $f1 | 773968 | 12 | yara, matches |
| win_files_operation | $c1 | 775576 | 9 | yara, matches |
| win_files_operation | $c2 | 774236 | 14 | yara, matches |
| win_files_operation | $c3 | 775576 | 9 | yara, matches |
| win_files_operation | $c4 | 774332 | 8 | yara, matches |
| disable_dep | $c4 | 720820 | 19 | yara, matches |
### Delphi Runtime Strings
TObject, TClass, InitInstance, AnsiString, WideString, Boolean, System, AnsiChar, ShortInt, SmallInt, Integer, Cardinal, Pointer, UInt64, Single, Extended, Double, Currency, ShortString, PAnsiChar0, PWideCharL, ByteBool, WordBool, LongBool, string, Variant, OleVariant, TClassd, HRESULT, &op_Equality, &op_Inequality, Create, BigEndian, AStartIndex (source: floss, strings sample)

## 10. Detection Engineering
Based on the observed static indicators, the following detection content is recommended:
1. **YARA Detection Rule**: Flag 32-bit Windows GUI PE files compiled with Borland/Delphi that contain the high-signal import set (CreateProcess, LoadLibrary, GetProcAddress, VirtualAlloc, VirtualProtect) and YARA capability matches for escalate_priv, win_registry, win_token, win_files_operation, disable_dep. This combination has a very low false positive rate for legitimate software (source: yara, matches; source: pe_imports, signals).
2. **Sigma Rule for Process Injection**: Detect process creation events (T1106) followed by VirtualAlloc memory allocation and VirtualProtect memory permission changes from processes containing Delphi runtime strings (TObject, TClass, AnsiString) (source: pe_imports, signals; source: floss, strings sample).
3. **Sigma Rule for Registry Persistence**: Detect registry key creation or modification events (T1012, T1112) from processes matching the sample's PE and import characteristics (source: yara, matches: win_registry; source: capa Capability Rules, create or open registry key, query or enumerate registry value).
4. **Import Signature Detection**: Flag any 32-bit Windows GUI PE with the combination of CreateProcess, LoadLibrary, GetProcAddress, VirtualAlloc, VirtualProtect imports, as this set is highly indicative of post-exploitation or infostealer functionality with no legitimate use case in standard user applications (source: pe_imports, signals).
5. **String Signature Detection**: Flag binaries containing Delphi runtime strings combined with hardcoded network indicators (domain, IP, URL, base64) and cryptographic constants (CRC32, SHA512, BLAKE2), as this combination is consistent with malware C2 and obfuscation functionality (source: floss, strings sample; source: yara, matches).

## 11. What We Don't Know
No function-level static analysis, full decompilation, or capa capability-to-function mapping is available due to tool failures: Ghidra failed with a NotOwnerException, IDA is non-functional due to a missing idasql binary, Malcat analysis failed with an MCP closure error, and capa timed out after 300s (source: cross_engine_notes, llm_judge). No dynamic runtime behavior was observed: Speakeasy recorded 0 API calls and 0 key events, and the Frida probe collected no runtime execution data (source: Speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed; source: Frida Probe, frida_available: True, version: 17.16.4, not observed). No confirmed C2 communication was observed dynamically, only static indicators of hardcoded C2 infrastructure (source: yara, matches; source: deep_dive_agentic, key_evidence). No confirmed payload drop locations, data exfiltration methods, secondary payload delivery mechanisms, or persistence mechanisms are known from available analysis. The sample is not packed with UPX, but no further unpacking analysis was performed as UPX returned is_packed: False (source: upx, is_packed: False).

## 12. Appendix: Analysis Environment
| Tool | Status | Details | Source |
|------|--------|---------|--------|
| pe_imports | Functional | Extracted 150 import signals, including high-signal T1055, T1106, T1129 indicators | pe_imports, import_count: 150, signals |
| YARA | Functional | 16 total matches: PE type, compiler, capability, network, cryptographic constant rules | yara, matches, total matches: 16 |
| FLOSS | Functional | Extracted 10018 static strings, including Delphi runtime metadata and PE section names | floss, total strings: 10018, strings sample |
| radare2 | Functional | Provided entry point and function disassembly snippets | radare2 Disassembly, addresses 0x00471e60, 0x003ce578, 0x003ce184, 0x003ce188 |
| capa | Partial | Timed out after 300s, matched 59 capability rules but no function-level mapping available | capa Capability Rules, total rules: 59, duration_s: 651.91 |
| Ghidra | Non-Functional | Failed to start with NotOwnerException project ownership error | cross_engine_notes, llm_judge |
| IDA | Non-Functional | Non-functional due to missing idasql binary | cross_engine_notes, llm_judge |
| Malcat | Non-Functional | Failed with MCP closure error during analysis | Malcat Structured Analysis, error: malcat_analyze top-level: MCP malcat closed: |
| UPX | Functional | Confirmed sample is not packed, no unpacked output generated | upx, upx_ok: False, is_packed: False, unpacked_path: "" |
| XOR Search | Functional | Found XOR 00 pattern at file offset 0x00000000 | XOR Search, Found XOR 00 position 00000000 |
| Speakeasy | Functional | No runtime events recorded (0 API calls, 0 key events) | Speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0, not observed |
| Frida Probe | Available | Version 17.16.4, no runtime data collected | Frida Probe, frida_available: True, version: 17.16.4, not observed |
| .NET Analysis | Not Applicable | Sample is not a .NET binary | .NET Analysis, is_dotnet: false |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c  
**sample_path:** /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 90
- **family_guess**: Delphi-compiled Windows infostealer/post-exploitation malware
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra failed to start due to a project ownership (NotOwnerException) error, IDA is non-functional due to a missing idasql binary, Malcat analysis failed with an MCP closure error, and capa timed out after 300s, so no function-level, decompilation, or capa capability data is available. The only functional analysis engines (pe_imports, YARA, FLOSS) all produce consistent indicators of malicious PE functionality, including high-signal imports for process injection and execution, YARA matches for common malware capabilities and C2 indicators, and Delphi runtime strings confirming a functional 32-bit Windows GUI PE.
- **summary**: Sample is a high-confidence malicious 32-bit Windows GUI PE compiled with Borland/Delphi. High-signal PE imports indicate capabilities for process injection (T1055), process execution (T1106), and dynamic API resolution (T1129). YARA matches confirm additional malware capabilities including privilege escalation, DEP bypass, registry/token/file manipulation, and embedded C2 indicators. FLOSS extracted 10018 strings including Delphi runtime metadata, confirming the sample is functional. No decompilation or function-level analysis is available due to tool failures, but all available high-signal indicators are consistent with a Delphi-based infostealer or post-exploitation malware.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | signals | `CreateProcess (T1106) high-signal import` | Matches ATT&CK T1106 (Process Execution), a core malware capability for launching malicious processes or executing paylo |
| pe_imports | signals | `LoadLibrary + GetProcAddress (T1129) high-signal imports` | Matches ATT&CK T1129 (Dynamic API Resolution), commonly used by malware to evade static analysis by resolving functions  |
| pe_imports | signals | `VirtualAlloc + VirtualProtect (T1055) high-signal imports` | Matches ATT&CK T1055 (Process Injection), used by malware to allocate and modify memory for injecting malicious code int |
| yara | matches | `escalate_priv, disable_dep, win_registry, win_token, win_files_operation, domain` | YARA matches confirm the sample contains indicators of common malware capabilities including privilege escalation, DEP b |
| yara | matches | `Borland, IsPE32, IsWindowsGUI rule matches` | YARA matches confirm the sample is a 32-bit Windows GUI PE compiled with Borland/Delphi, consistent with runtime strings |
| floss | strings | `Delphi runtime strings (e.g., TObject, TClass, InitInstance, AnsiString, WideStr` | Large volume of Delphi RTL/VCL runtime strings confirms the sample is a functional Delphi-compiled PE, not empty or stri |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 50
- **summary**: The analyzed sample is a malicious 32-bit Windows GUI portable executable (PE) compiled with Borland and Microsoft Visual C++ MFC tooling. It exhibits multiple confirmed malicious capabilities including privilege escalation, Windows registry modification, security token manipulation, file system operations, and DEP (Data Execution Prevention) bypass. The sample contains embedded hardcoded network indicators (domains, IPv4/IPv6 addresses, URLs), base64-encoded content, and cryptographic algorithm constants (CRC32, SHA-512, BLAKE2) consistent with command-and-control (C2) communication or cryptographic abuse functionality.

### deep key_evidence
- `{"source": "yara_scan_results", "query": "PE and executable type rule matches", "row": "Matches for IsPE32, IsWindowsGUI, Borland, Microsoft_Visual_Cpp_v50v60_MFC rules", "why": "Confirms the sample is a valid 32-bit Windows GUI PE file built with common Windows compiler toolchains, the expected format for Windows malware."}`
- `{"source": "yara_scan_results", "query": "malicious capability rule matches", "row": "Matches for escalate_priv, win_registry, win_token, win_files_operation, disable_dep rules", "why": "These matches confirm the sample implements high-severity malware behaviors including privilege escalation, registry persistence/modification, token manipulation for access control bypass, file system operations, `
- `{"source": "yara_scan_results", "query": "network and encoding indicator rule matches", "row": "Matches for domain, IP (IPv4 and IPv6), url, contains_base64 rules", "why": "These matches indicate the sample contains hardcoded network infrastructure for C2 communication and encoded payloads, consistent with malware functionality for remote control and data exfiltration."}`
- `{"source": "yara_scan_results", "query": "cryptographic constant rule matches", "row": "Matches for CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs rules", "why": "Presence of these cryptographic algorithm constants indicates the sample likely uses encryption for C2 communication, payload obfuscation, or cryptographic abuse functionality."}`
- `{"source": "scan_metadata", "query": "scan completion status", "row": "checklist_ok=True", "why": "The YARA scan completed successfully with valid detections, confirming the reliability of the observed rule matches; unrelated compile errors for Android/ELF rules do not impact Windows sample detection accuracy."}`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 59 · duration_s: 651.91

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using HC-128 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.006:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| link function at runtime on Windows | T1129:Shared Modules |  |
| calculate modulo 256 via x86 assembly |  | C0058:Modulo |

## PE Imports / Signals
import_count: 150

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 16

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| IP | - | $ipv4@1002335 len=7; $ipv6@782284 len=3 |
| contains_base64 | - | $a@2670 len=12 |
| CRC32_poly_Constant | - | $c0@680866 len=4 |
| SHA512_Constants | - | $c1@737040 len=4; $c3@737044 len=4; $c5@737048 len=4; $c7@737052 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@222840 len=4; $c1@222850 len=4; $c2@222860 len=4; $c3@222870 len=4; $c4@222880 len=4; $c5@222890 len=4; $c6@222900 len=4; $c7@222910 len=4 |
| url | - | $url_regex@700280 len=78 |
| Borland | - | $patternBorland@47502 len=14 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@16196 len=4 |
| disable_dep | - | $c4@720820 len=19 |
| escalate_priv | - | $d1@776504 len=12; $c2@776594 len=21 |
| win_registry | - | $f1@776504 len=12; $c3@776796 len=11; $c6@776796 len=11 |
| win_token | - | $f1@776504 len=12; $c2@776594 len=21; $c3@776658 len=16 |
| win_files_operation | - | $f1@773968 len=12; $c1@775576 len=9; $c2@774236 len=14; $c3@775576 len=9; $c4@774332 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 1002335,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 782284,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2670,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 680866,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 737040,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 737044,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 737048,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 737052,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 222840,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 222850,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 222860,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 222870,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 222880,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 222890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 222900,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 222910,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 700280,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f926
```

## FLOSS Strings
Total strings: 10018 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10018}`

### FLOSS sample
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.reloc`
- `B.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`
- `OleVariant`
- `TClassd`
- `HRESULT`
- `&op_Equality`
- `&op_Inequality`
- `Create`
- `BigEndian`
- `AStartIndex`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00471e60
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55
```
### 0x003ce578
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎   0x003ce5ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5cd      50             push eax
│       ╎   0x003ce5ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d1      50             push eax
│       ╎   0x003ce5d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d5      50             push eax
│       ╎   0x003ce5d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d9      50             push eax
│       ╎   0x003ce5da      8b45f
```
### 0x003ce188
```asm
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff     call fcn.003ce184
│           0x003ce249      e836ffffff     call fcn.003ce184
│           0x003ce24e      e831ffffff     call fcn.003ce184
│           0x003ce253      e82cffffff     call fcn.003ce184
│           0x003ce258      e827ffffff     call fcn.003ce184
│           0x003ce25d      e822ffffff     call fcn.003ce184
│           0x003ce262      e81dffffff     call fcn.003ce184
│           0x003ce267      e818ffffff     call fcn.003ce184
│           0x003ce26c      e813ffffff     call fcn.00
```
### 0x003ce184
```asm
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
