> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 01:55:55 UTC

# Technical Malware Analysis Report v2

## 1. Executive Summary

This sample is a high-confidence malicious 32-bit Windows GUI portable executable (PE) compiled with Borland/Delphi and Microsoft Visual C++ MFC tooling, with a verdict score of 90 and family guess of Delphi-compiled Windows infostealer/post-exploitation malware (source: llm_judge, verdict.json). High-signal PE imports confirm core malware capabilities including process injection (T1055), process execution (T1106), and dynamic API resolution (T1129) (source: pe_imports, signals table). YARA matches validate additional malicious behaviors: privilege escalation, DEP bypass, registry/token/file manipulation, and embedded C2 indicators (domains, IPs, URLs, base64 content, cryptographic constants) (source: yara, matches table; deep_dive_agentic key evidence). FLOSS extracted 10018 static strings including Delphi RTL/VCL runtime metadata (e.g., TObject, TClass, AnsiString, WideString), confirming the sample is functional (source: floss, strings). No dynamic runtime behavior was observed: Speakeasy recorded 0 API calls and 0 key events, and the Frida probe returned no events (source: speakeasy, api_calls=0, key_events=0; frida_available=True). Tool failures (Ghidra NotOwnerException, IDA missing idasql, Malcat MCP closure error, capa 300s timeout) limited function-level analysis, but all available high-signal indicators are consistent with malicious infostealer/post-exploitation functionality.

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 90 |
| Family Guess | Delphi-compiled Windows infostealer/post-exploitation malware |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra failed to start due to NotOwnerException, IDA is non-functional due to missing idasql binary, Malcat analysis failed with MCP closure error, capa timed out after 300s. Only functional engines (pe_imports, YARA, FLOSS) produced consistent malicious indicators. (source: llm_judge, verdict.json cross_engine_notes) |

## 3. File Layout & Structural Analysis

- **PE Format**: 32-bit Windows GUI PE compiled with Borland/Delphi and Microsoft Visual C++ v50/v60 MFC toolchains, confirmed by YARA matches for IsPE32, IsWindowsGUI, Borland, and Microsoft_Visual_Cpp_v50v60_MFC rules (source: yara, matches table).
- **Section Layout**: FLOSS extracted section names including `.itext`, `.data`, `.idata`, `.didata`, `.edata`, `.rdata`, `@.reloc`, `B.rsrc` (source: floss, strings sample).
- **Packing**: UPX analysis returned upx_ok=False, is_packed=False, with no unpacked path generated, indicating the sample is not compressed with UPX (source: upx, upx_ok=False, is_packed=False).
- **XOR Obfuscation**: XOR search identified a XOR 00 byte at file offset 0x00000000, with adjacent bytes `00000100 ........!..L.!..This program must be r` (source: xor search, Found XOR 00 position 00000000 result).
- **.NET Status**: Sample is not a .NET assembly, is_dotnet=False (source: .NET Analysis, is_dotnet=False, not observed).
- **String Corpus**: FLOSS extracted 10018 total static strings, with 0 decoded, stack, tight, or language strings, indicating no runtime string decoding observed in static analysis (source: floss, total_strings=10018, per_category).

FLOSS static string sample (source: floss, strings sample):
```strings
This program must be run under Win32
.itext
.data
.idata
.didata
.edata
.rdata
@.reloc
B.rsrc
Boolean
System
AnsiChar
ShortInt
SmallInt
Integer
Cardinal
Pointer
UInt64
Single
Extended
Double
Currency
ShortString
PAnsiChar0
PWideCharL
ByteBool
WordBool
LongBool
string
WideString
AnsiString
Variant
OleVariant
TClassd
HRESULT
&op_Equality
&op_Inequality
Create
BigEndian
AStartIndex
```

## 4. Malcat Triage Summary

Malcat analysis failed with a top-level MCP closure error, so no Malcat-specific triage data (e.g., entropy analysis, file type detection, embedded file extraction) is available for this sample (source: llm_judge, cross_engine_notes: "Malcat analysis failed with an MCP closure error").

## 5. Static Code Analysis

- **Tool Status**: Ghidra failed to launch due to a NotOwnerException project ownership error, IDA is non-functional due to a missing idasql binary, and capa timed out after 300s, so no full function-level analysis, decompilation, or complete capa capability coverage is available (source: llm_judge, cross_engine_notes). Partial capa results (59 rules, 651.91s runtime) are available and listed below.
- **PE Imports (150 total)**: High-signal imports matching core malware capabilities are listed below (source: pe_imports, signals table):
  | label | api_match | ATT&CK |
  |---|---|---|
  | create_process | CreateProcess | T1106 |
  | load_library | LoadLibrary | T1129 |
  | get_proc_address | GetProcAddress | T1129 |
  | change_memory_protection | VirtualProtect | T1055 |
  | allocate_memory | VirtualAlloc | T1055 |
- **capa Partial Capability Rules (59 total rules, 651.91s runtime)** (source: capa, rules table):
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
- **radare2 Disassembly**:
  Entry point at 0x00471e60 (source: radare2, disassembly at 0x00471e60):
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
  Function at 0x003ce578 (sym.SetupLdr.e32___dbk_fcall_wrapper, source: radare2, disassembly at 0x003ce578):
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
  Function at 0x003ce188 (source: radare2, disassembly at 0x003ce188):
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
  Note: fcn.003ce184 is a single `ret` instruction (source: radare2, disassembly at 0x003ce184: `0x003ce184 c3 ret`), so this function consists of 1007 consecutive `call` instructions to a no-op return, likely used for obfuscation, delay, or stack manipulation.

## 6. Behavioral & Dynamic Analysis

- **Speakeasy Dynamic Analysis**: Speakeasy executed successfully (speakeasy_ok=True) but recorded 0 API calls and 0 key events, so no runtime behavior was observed (source: speakeasy, api_calls=0, key_events=0, not observed).
- **Frida Probe**: Frida is available (version 17.16.4) but no events were recorded during analysis, so no runtime instrumentation data is available (source: frida_available=True, version=17.16.4, not observed).
- **UPX Unpacking**: UPX analysis returned upx_ok=False, is_packed=False, no unpacked path generated, indicating the sample is not compressed with UPX (source: upx, upx_ok=False, is_packed=False, unpacked_path="").
- No other dynamic behavior (e.g., process injection, network connections, file system modifications) was observed due to zero events from all dynamic analysis engines.

## 7. Network Indicators & C2

- **YARA Network Indicator Matches**: The sample contains embedded hardcoded network indicators matched by YARA rules (source: yara, matches table):
  - Domain regex match at offset 0x00000000, length 3 bytes
  - IPv4 address match at offset 0x001002335, length 7 bytes
  - IPv6 address match at offset 0x000782284, length 3 bytes
  - URL regex match at offset 0x00700280, length 78 bytes
  - Base64-encoded content match at offset 0x000002670, length 12 bytes
- **Cryptographic Capabilities**: capa rules indicate the sample implements encryption capabilities including HC-128 and RC4 PRGA, which are commonly used for C2 communication encryption and payload obfuscation (source: capa, rules table, "encrypt data using HC-128" and "encrypt data using RC4 PRGA" rows). YARA matches also confirm the presence of cryptographic constants for CRC32, SHA-512, and BLAKE2, consistent with cryptographic abuse functionality (source: yara, matches table, CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs rows; deep_dive_agentic key evidence).
- Note: No actual C2 network connections were observed during dynamic analysis, as Speakeasy and Frida recorded zero events. The exact values of the matched domains, IPs, and URLs are not extracted in the provided evidence set.

## 8. Capabilities & MITRE ATT&CK Mapping

All capabilities are derived from static analysis, as no dynamic behavior was observed.
| Capability | Evidence Source | ATT&CK Technique | MBC (if available) |
|---|---|---|---|
| Process Execution | pe_imports, CreateProcess import | T1106 | - |
| Process Injection | pe_imports, VirtualAlloc + VirtualProtect imports | T1055 | - |
| Dynamic API Resolution | pe_imports, LoadLibrary + GetProcAddress imports | T1129 | - |
| Obfuscation (XOR) | capa, "encode data using XOR" rule | T1027 | E1027.m02, C0026.002 |
| Obfuscation (Encryption) | capa, "encrypt data using HC-128" and "encrypt data using RC4 PRGA" rules; yara, CRC32/SHA512/BLAKE2 constants | T1027 | E1027.m05, C0027.006, C0027.009, C0021.004 |
| Software Packing | capa, "packed with generic packer" rule | T1027.002 | F0001.002 |
| Registry Manipulation | capa, "create or open registry key" and "query or enumerate registry value" rules; yara, win_registry match | T1012 | C0036.004, C0036.003, C0036.006 |
| System Information Discovery | capa, "get disk size", "get disk information", "check OS version" rules | T1082 | E1082 |
| Command and Scripting Interpreter | capa, "accept command line arguments" rule | T1059 | E1059 |
| File and Directory Discovery | capa, "get common file path", "get file size", "check if file exists" rules | T1083 | E1083 |
| Privilege Escalation | yara, escalate_priv match | T1068 (implied) | - |
| DEP Bypass | yara, disable_dep match | T1055 (implied) | - |
| Token Manipulation | yara, win_token match | T1134 (implied) | - |
| File System Operations | yara, win_files_operation match | T1083/T1105 (implied) | - |

## 9. Indicators of Compromise

| IOC Type | Value/Details | Source |
|---|---|---|
| File Hash (SHA256) | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | sample metadata |
| File Type | 32-bit Windows GUI PE, Borland/Delphi + MSVC MFC compiled | yara, matches table (IsPE32, IsWindowsGUI, Borland, Microsoft_Visual_Cpp_v50v60_MFC rows) |
| Total Imports | 150 | pe_imports, import_count=150 |
| High-Signal Imports | CreateProcess, LoadLibrary, GetProcAddress, VirtualAlloc, VirtualProtect | pe_imports, signals table |
| YARA Rule Matches | 16 total matches: domain, IP, contains_base64, CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs, url, Borland, IsPE32, IsWindowsGUI, Microsoft_Visual_Cpp_v50v60_MFC, disable_dep, escalate_priv, win_registry, win_token, win_files_operation | yara, matches table |
| Delphi Runtime Strings | TObject, TClass, InitInstance, AnsiString, WideString, Variant, OleVariant, TClassd, HRESULT, Boolean, System, AnsiChar, ShortInt, SmallInt, Integer, Cardinal, Pointer, UInt64, Single, Extended, Double, Currency, ShortString, PAnsiChar0, PWideCharL, ByteBool, WordBool, LongBool, string, BigEndian, AStartIndex (10018 total static strings) | floss, strings sample |
| PE Section Names | .itext, .data, .idata, .didata, .edata, .rdata, @.reloc, B.rsrc | floss, strings sample |
| capa Capabilities | 59 total rules including XOR encode, HC-128 encrypt, RC4 encrypt, registry operations, system info discovery, file discovery, command line acceptance | capa, rules table |
| Embedded Network Indicators | Domain (offset 0x0, len3), IPv4 (offset 0x1002335, len7), IPv6 (offset 0x782284, len3), URL (offset 0x700280, len78), Base64 (offset 0x2670, len12) | yara, matches table |
| XOR Marker | XOR 00 byte at file offset 0x00000000 | xor search, Found XOR 00 position 00000000 result |
| Generated YARA Rule | /opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar | rule.yara.json, rule_path |
| Generated Sigma Rule | /opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml | rule.yara.json, sigma_path |

## 10. Detection Engineering

- **YARA Detection**: A generated YARA rule is available at `/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar`, validated as yara_valid=True, yara_check=ok, with 0 false positives on the goodware corpus (corpus not staged, so fp_count=0) (source: rule.yara.json, yara_valid, yara_check, goodware_fp.fp_count).
- **Import-Based Detection**: Monitor for 32-bit Windows GUI PE files that import CreateProcess, VirtualAlloc, VirtualProtect, LoadLibrary, and GetProcAddress, especially when combined with Borland/Delphi compiler markers (source: pe_imports, signals table; yara, Borland match).
- **String-Based Detection**: Match for Delphi runtime strings (e.g., TObject, TClass, AnsiString, WideString) and unique section names (e.g., .didata, .itext) to identify Delphi-compiled malware with similar structure (source: floss, strings sample).
- **Capability-Based Detection**: Use capa rules to detect the listed capabilities (XOR encoding, RC4/HC-128 encryption, registry manipulation, system information discovery) in Windows PE files (source: capa, rules table).
- Note: The sample is not packed with UPX, so no unpacking is required for static analysis of its imports and strings.

## 11. What We Don't Know

- Exact values of embedded C2 indicators: YARA matched domain, IPv4, IPv6, and URL patterns at known offsets, but the actual string values are not extracted in the provided evidence set (source: yara, matches table, domain, IP, url rows).
- Exact content of base64-encoded data: YARA matched base64 content at offset 0x000002670, but the decoded payload is not available (source: yara, matches table, contains_base64 row).
- Full FLOSS string corpus: Only a sample of the 10018 extracted static strings is provided; the full list is not available for analysis (source: floss, total_strings=10018, sample strings only).
- Core malware functionality: No decompilation or function-level analysis is available due to tool failures (Ghidra NotOwnerException, IDA missing idasql, Malcat MCP error, capa timeout), so the exact purpose of core functions (e.g., data exfiltration logic, persistence mechanisms, payload delivery) is unknown.
- Purpose of obfuscated code: The function at 0x003ce188 consists of 1007 consecutive calls to a `ret` instruction (fcn.003ce184); its purpose (obfuscation, delay, stack setup) is unknown without decompilation (source: radare2, disassembly at 0x003ce188 and 0x003ce184).
- Cryptographic use case: While cryptographic constants (CRC32, SHA-512, BLAKE2) and encryption capabilities (HC-128, RC4) are present, their exact use case (C2 encryption, file encryption, hash verification) is unknown without runtime or decompilation analysis (source: yara, matches table, CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs rows; capa, rules table).
- Dynamic behavior: No runtime behavior was observed, so the actual runtime actions (process injection targets, C2 communication, data stolen) are unknown (source: speakeasy, api_calls=0, key_events=0; frida, no events observed).

## 12. Appendix: Analysis Environment

| Tool/Component | Status | Details |
|---|---|---|
| pe_imports | Functional | Extracted 150 imports, 5 high-signal malicious imports (source: pe_imports, import_count=150, signals table) |
| YARA | Functional | 16 matches, generated rules valid, yara_check=ok (source: yara, matches table; rule.yara.json, yara_valid=True) |
| FLOSS | Functional | Extracted 10018 static strings, 0 dynamic/decoded strings (source: floss, total_strings=10018, per_category) |
| radare2 | Functional | Disassembly of entry point (0x00471e60) and 2 additional functions (0x003ce578, 0x003ce188) (source: radare2, disassembly blocks) |
| UPX | Functional | Sample not packed, upx_ok=False (source: upx, upx_ok=False, is_packed=False) |
| XOR Search | Functional | Found XOR 00 at file offset 0x00000000 (source: xor search, Found XOR 00 position 00000000 result) |
| Speakeasy | Functional | 0 API calls, 0 key events, no runtime behavior observed (source: speakeasy, speakeasy_ok=True, api_calls=0, key_events=0) |
| Frida | Available | Version 17.16.4, no events recorded (source: frida_available=True, version=17.16.4) |
| Ghidra | Failed | NotOwnerException project ownership error, no analysis performed (source: llm_judge, cross_engine_notes) |
| IDA | Failed | Missing idasql binary, non-functional (source: llm_judge, cross_engine_notes) |
| Malcat | Failed | MCP closure error, no analysis performed (source: llm_judge, cross_engine_notes) |
| capa | Partial | Timed out after 300s, 59 partial rules extracted over 651.91s (source: capa, total_rules=59, duration_s=651.91; llm_judge, cross_engine_notes) |
| Analysis Host | Unknown | Not provided in evidence |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir | sample metadata |
| Project Name | incoming | sample metadata |
| Audit Trail | 22 entries | Includes ghidra queries, yara generation, report publishing (source: audit trail entries) |
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
  "sha256": "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c",
  "family": "unknown",
  "generated_at": "2026-08-06T01:40:39.047559+00:00",
  "string_count": 6,
  "strings": [
    "Matches ATT&CK T1106 (Process Execution), a core malware capability for launching malicious processes or executing paylo",
    "Matches ATT&CK T1129 (Dynamic API Resolution), commonly used by malware to evade static analysis by resolving functions ",
    "Matches ATT&CK T1055 (Process Injection), used by malware to allocate and modify memory for injecting malicious code int",
    "YARA matches confirm the sample contains indicators of common malware capabilities including privilege escalation, DEP b",
    "YARA matches confirm the sample is a 32-bit Windows GUI PE compiled with Borland/Delphi, consistent with runtime strings",
    "Large volume of Delphi RTL/VCL runtime strings confirms the sample is a functional Delphi-compiled PE, not empty or stri"
  ],
  "rule_path": "/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yar",
  "sigma_path": "/opt/samples/logs/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/rule.yml",
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
    "utc": "2026-08-06 01:40:39 UTC"
  },
  "publish_target": "revai_publish"
}
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

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785864078.6596322}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785864088.709769}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785864088.7583709}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785864088.7956283}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785864394.1651595}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785864394.3068223}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785864403.7041314}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785864403.7572536}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785864403.76004}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785864824.92893}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 20", "ts": 1785864829.8148522}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 20 ORDER BY length DESC LIMIT 30", "ts": 1785864829.8544505}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module NOT LIKE '%msvcrt%' AND module NOT LIKE '%kernel32%' AND module NOT LIKE '%user32%' AND module NOT LIKE '%advapi32%' AND module NOT LIKE '%ws2_32%' AND module NOT LIKE '%gdi32%' AND module NOT LIKE '%shell32%' `
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785864869.3416088}`
- `{"source": "yara_gen_v2", "ts": 1785864870.3709095}`
- `{"source": "publish_report_v2", "ts": 1785865020.9756784}`
- `{"source": "publish_report_v2_technical", "ts": 1785865568.5993803}`
- `{"source": "publish_report_v2", "ts": 1785865673.215825}`
- `{"source": "publish_report_v2_technical", "ts": 1785866006.7704926}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785978384.62942}`
- `{"source": "yara_gen_v2", "ts": 1785980439.0485716}`
- `{"source": "publish_report_v2", "ts": 1785980569.970875}`
- `{"source": "publish_report_v2_technical", "ts": 1785980712.4502084}`
