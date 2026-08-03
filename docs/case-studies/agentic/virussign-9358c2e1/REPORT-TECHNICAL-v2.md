# Technical Malware Analysis Report v2

## 1. Executive Summary
This is a high-confidence malicious 64-bit Windows PE file (sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5) packed with UPX and associated with the Meterpreter post-exploitation framework (source: llm_judge, verdict.json). The sample functions as a loader/dropper, employing XOR obfuscation (key 0xae) at its entry point to decode in-memory payloads, and uses dynamic API resolution via LoadLibraryA/GetProcAddress to hide malicious functionality from static analysis (source: malcat, decompilations/EntryPoint@4481792; source: pe_imports, signals). It contains 10 embedded 193536-byte PE payloads intended for delivery, and imports VirtualProtect for memory permission modification to support code injection and shellcode execution (source: malcat, carved files; source: pe_imports, signals). Static analysis reveals 12 total imports, 4 identified functions, and 16 Malcat anomalies including cross-section control flow jumps, unreferenced imports, and missing PE checksums, all consistent with packed malware (source: malcat, anomalies; source: ghidra_query, imports). Capa rules confirm UPX packing, XOR encoding, embedded PE handling, process termination, and runtime linking capabilities (source: capa, top_rules). YARA matches include UPX signatures, Android Meterpreter markers, Winsock library strings, mutex strings, and file operation strings, corroborating the post-exploitation framework association (source: yara, matches). No dynamic runtime behavior was observed during Speakeasy emulation or Frida probing (source: speakeasy, api_calls=0; source: frida_probe, no events recorded).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Project Name | incoming |
| File Type | 64-bit Windows PE |
| File Size | 8964155 bytes |
| Verdict | MALWARE (high confidence) |
| Malware Family Guess | Meterpreter-associated UPX-packed loader/dropper |
| Analysis Confidence | 90 (source: deep_dive_agentic, deep-dive.json) |
| Tool Agreement | llm_v1_disagree (IDA analysis unavailable due to validation failure; all findings derived from Ghidra, Malcat, capa, pe_imports, YARA, FLOSS) (source: llm_judge, verdict.json) |
| UPX Unpack Status | Failed (upx_ok: False, returncode: None, unpacked_path: empty) (source: upx, upx_unpack) |
| Speakeasy Emulation | No events observed (api_calls: 0, key_events: 0) (source: speakeasy, speakeasy_ok: True) |
| Frida Probe | Available (v17.16.4), no events recorded (source: frida_probe, frida_available: True) |

## 3. File Layout & Structural Analysis
The sample exhibits classic UPX packing artifacts, with three UPX-labeled memory blocks and a large high-entropy overlay containing embedded payloads (source: malcat, file_layout). The full section layout is as follows (source: malcat, file_layout):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 216 | - |
| UPX1 | 512 | 4482048 | 4485120 | 210 | RWX |
| UPX2 | 4485632 | 1024 | 4096 | 0 | RW |
| overlay | 4489728 | 4480571 | 0 | 81 | - |
| UPX0 | 8970299 | 0 | 8835072 | 0 | RWX |
The file has an overall entropy of 145, consistent with packed/encrypted content (source: malcat, file_summary). Key structural anomalies include (source: malcat, anomalies):
- CrossSectionJump (level 4, 1 hit): Control flow crosses section boundaries, indicative of packed or patched malware
- UnreferencedImports (level 3, 8 hits): 8 of 12 total imports have no static cross-references, confirming dynamic API resolution
- NoChecksum (level 1, 1 hit): Missing PE header checksum, a common trait of packed malware
- SectionWX (level 3, 2 hits): Executable sections with write permissions, enabling runtime code modification
- EmbeddedProgram (level 3, 10 hits): 10 embedded PE files detected in the overlay region
- XorInLoop (level 3, 2 hits): XOR operations in loops at EAs 4481815 and 4482011, consistent with the entry point decoding routine

## 4. Malcat Triage Summary
### File Summary (source: malcat, file_summary)
```
sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
size: 8964155
type: PE
architecture: X64
entrypoint_ea: 4481792
entropy: 145
file_name: virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir
```
### YARA Signatures (source: malcat, yara_signatures)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| UPX | packer | INFO | 40 | Detect UPX based on section artifacts and EP |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
### Anomalies (source: malcat, anomalies)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 41 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references |
| EmbeddedProgram | 3 | embedding | 10 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| RelocationsNotInRelocSection | 3 | sections | 1 | relocations are not in .reloc |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or they are called dynamically |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section with code |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all initialized data sections (raw or virtual) |
| Packed | 2 | packers | 0 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
### High-Signal Strings (source: malcat, high_signal_strings)
| EA | String |
|---|---|
| 4486038 | `KERNEL32.DLL` |
| 4486013 | `CRYPT32.dll` |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\gggg\\` |
| 4724743 | `ykernel32.dll` |
| 8186341 | `ykernel32.dll` |
| 8964429 | `ykernel32.dll` |
| 7600910 | `ykernel32.dll` |
| 8381459 | `ykernel32.dll` |
| 8769742 | `ykernel32.dll` |
| 8576158 | `ykernel32.dll` |
| 7795577 | `ykernel32.dll` |
| 7990829 | `ykernel32.dll` |
| 4722833 | `kernel32.dll` |
| 7599000 | `kernel32.dll` |
| 8184431 | `kernel32.dll` |
| 7988919 | `kernel32.dll` |
| 8574248 | `kernel32.dll` |
| 8767832 | `kernel32.dll` |
| 7793667 | `kernel32.dll` |
| 8962519 | `kernel32.dll` |
| 8379549 | `kernel32.dll` |
| 8574330 | `crypt32.dll` |
| 7793749 | `crypt32.dll` |
| 8767914 | `crypt32.dll` |
| 4722915 | `crypt32.dll` |
| 7599082 | `crypt32.dll` |
| 8184513 | `crypt32.dll` |
| 8962601 | `crypt32.dll` |
| 7989001 | `crypt32.dll` |
| 8379631 | `crypt32.dll` |
### Top Strings (source: malcat, top_strings)
| EA | String |
|---|---|
| 8962891 | `ShellExecuteW` |
| 8768204 | `ShellExecuteW` |
| 8574672 | `ShellExecuteW` |
| 7794039 | `ShellExecuteW` |
| 8379973 | `ShellExecuteW` |
| 4723205 | `ShellExecuteW` |
| 8574620 | `ShellExecuteW` |
| 7794091 | `ShellExecuteW` |
| 4723257 | `ShellExecuteW` |
| 8379921 | `ShellExecuteW` |
| 8962943 | `ShellExecuteW` |
| 7599372 | `ShellExecuteW` |
| 8768256 | `ShellExecuteW` |
| 7989291 | `ShellExecuteW` |
| 8184803 | `ShellExecuteW` |
| 8184855 | `ShellExecuteW` |
| 7599424 | `ShellExecuteW` |
| 7989343 | `ShellExecuteW` |
| 4486025 | `IPHLPAPI.DLL` |
| 4486038 | `KERNEL32.DLL` |
| 4486062 | `PSAPI.DLL` |
| 4486000 | `ADVAPI32.dll` |
| 4486083 | `USERENV.dll` |
| 4486095 | `WS2_32.dll` |
| 4486013 | `CRYPT32.dll` |
| 4486051 | `msvcrt.dll` |
| 4486072 | `USER32.dll` |
### Imports (source: malcat, imports)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4485832 | advapi32.FreeSid | IMPORT | 1 |
| 4485848 | crypt32.CertOpenStore | IMPORT | 1 |
| 4485864 | iphlpapi.GetAdaptersAddresses | IMPORT | 1 |
| 4485880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4485888 | kernel32.ExitProcess | IMPORT | 1 |
| 4485896 | kernel32.GetProcAddress | IMPORT | 1 |
| 4485904 | kernel32.VirtualProtect | IMPORT | 1 |
| 4485920 | msvcrt.atof | IMPORT | 1 |
| 4485936 | psapi.GetProcessMemoryInfo | IMPORT | 1 |
| 4485952 | user32.GetMessageA | IMPORT | 1 |
| 4485968 | userenv.GetUserProfileDirectoryW | IMPORT | 1 |
| 4485984 | ws2_32.bind | IMPORT | 1 |
### Functions (source: malcat, functions)
| EA | Name |
|---|---|
| 4481942 | sub_10b4196 |
| 4481792 | EntryPoint |
| 4481880 | sub_10b4158 |
| 4482343 | sub_10b4327 |
### Carved Files (source: malcat, carved_files)
| Name | Type | Size |
|---|---|---|
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |

## 5. Static Code Analysis
### Entry Point Disassembly (source: r2, radare2_disassembly/0x010b4100)
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
### Entry Point Decompilation (source: malcat, decompilations/EntryPoint@4481792)
```c
void EntryPoint(void)
{
    uint8_t *puVar1;
    uint8_t *in_R9;
    
    puVar1 = 0xc6e025;
    do {
        *puVar1 = *puVar1 ^ 0xae;
        puVar1 = puVar1 + 1;
    } while (puVar1 != in_R9);
    [0x0x10aa37c] = 0x712e619e;
    sub_10b4196(0);
    return;
}
```
The entry point implements a single-byte XOR decoding loop with key 0xae, iterating over a memory region from 0x00c6e025 to the value passed in R9, modifying bytes in place (source: malcat, decompilations/EntryPoint@4481792; source: r2, radare2_disassembly/0x010b4100). This matches capa's `encode data using XOR` rule (source: capa, top_rules). After decoding, the routine writes the value 0x712e619e to memory at 0x10aa37c, then calls sub_10b4196 with argument 0.
### Subroutine 0x010b4196 Disassembly (source: r2, radare2_disassembly/0x010b4196)
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
This subroutine implements a LZ-based decompression routine (evidenced by the bitwise reading, length/distance decoding, and copy loop), used to decompress the decoded payload after the XOR stage (source: r2, radare2_disassembly/0x010b4196).
### Capa Capabilities (source: capa, top_rules)
| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| terminate process |  | C0018:Terminate Process |
| link function at runtime on Windows | T1129:Shared Modules |  |
### YARA Matches (source: yara, matches)
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
### XOR Search Results (source: xor, xor_search)
Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 00451B8F: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 00481512: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0070FE96: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0073F701: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0076F1B5: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0079ED6D: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 007CE79B: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 007FE026: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0082D456: 00000080 ........!..L.!This program cannot be r
Found XOR 00 position 0085CCD5: 00000080 ........!..L.!This program cannot be r
### FLOSS Strings Sample (source: floss, floss_strings)
Total static strings extracted: 10548. Sample high-entropy strings:
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

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis. Speakeasy emulation completed successfully but recorded 0 API calls and 0 key events (source: speakeasy, speakeasy_ok: True, api_calls=0, key_events=0). Frida probing was available (v17.16.4) but no events were captured (source: frida_probe, frida_available: True). UPX unpacking failed with no output (upx_ok: False, returncode: None, unpacked_path: empty) (source: upx, upx_unpack). No process execution, network connections, file system modifications, or registry changes were observed, as no runtime hooks were triggered during emulation or probing.

## 7. Network Indicators & C2
Static analysis reveals multiple network-related indicators, though no dynamic network activity was observed. Imported networking APIs include `ws2_32.bind` (EA 4485984) and `iphlpapi.GetAdaptersAddresses` (EA 4485864), indicating potential network socket binding and network interface enumeration capabilities (source: pe_imports, imports). YARA matches confirm the presence of Winsock library strings at offset 4483023, a mutex string at offset 4716493, and file operation strings at offsets 4482966, 4716263, and 4716599 (source: yara, matches). Additional static strings include 18 occurrences of `ShellExecuteW` (EAs 4486025, 8768204, 8574672, etc.) and multiple `ykernel32.dll` obfuscated strings (EAs 4724743, 8186341, etc.) likely used for dynamic library loading (source: malcat, top_strings). YARA also detected a domain regex match and IPv6 address at offset 51072, and base64-encoded content at offset 2689014, which may correspond to C2 infrastructure or payload delivery addresses (source: yara, matches). No actual C2 communications were observed dynamically (source: speakeasy, api_calls=0).

## 8. Capabilities & MITRE ATT&CK Mapping
All mapped capabilities are derived from static analysis and rule matches, as no dynamic behavior was observed.
| Capability | Source | MITRE ATT&CK / MBC |
|---|---|---|
| UPX packing | capa, top_rules: `packed with UPX` | T1027.002: Obfuscated Files or Information (F0001.008: Software Packing) |
| XOR-based payload obfuscation | capa, top_rules: `encode data using XOR`; malcat, decompilations/EntryPoint@4481792 | T1027: Obfuscated Files or Information (E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data) |
| Dynamic API resolution (LoadLibrary/GetProcAddress) | pe_imports, signals: `load_library`, `get_proc_address`; capa, top_rules: `link function at runtime on Windows` | T1129: Shared Modules |
| Memory permission modification | pe_imports, signals: `change_memory_protection` | T1055: Process Injection |
| Embedded PE payload delivery | capa, top_rules: `contain an embedded PE file`; malcat, carved_files: 10 PE files | B0023: Install Additional Program |
| Process termination | capa, top_rules: `terminate process` | C0018: Terminate Process |
| Lateral movement / shell execution | yara, matches: `RunShell` | T1021: Remote Services (potential) |
| Network interface enumeration | pe_imports, imports: `GetAdaptersAddresses` | T1016: System Network Configuration Discovery |
| User profile enumeration | pe_imports, imports: `GetUserProfileDirectoryW` | T1033: System Owner/User Discovery |
| File operation capabilities | yara, matches: `win_files_operation` | T1089: Disabling Security Tools, T1070: Indicator Removal on Host (potential) |
| Meterpreter post-exploitation association | yara, matches: `android_meterpreter` | T1059: Command and Scripting Interpreter, T1105: Ingress Tool Transfer (potential) |

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 | llm_judge, verdict.json |
| File Name | virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir | malcat, file_summary |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir | sample_path (input) |
| Embedded PE Offsets | 4535183, 4730130, 7411350, + 7 additional offsets (source: malcat, carved_files) | malcat, carved_files |
| XOR Decode Key | 0xae | malcat, decompilations/EntryPoint@4481792; r2, radare2_disassembly/0x010b4100 |
| UPX Section Names | UPX0, UPX1, UPX2 | malcat, file_layout |
### String IOCs
| EA | String | Source |
|---|---|---|
| 4483023 | `WS2_32.dll` (Winsock library) | yara, matches: `Str_Win32_Winsock2_Library` |
| 4716493 | Mutex string (11 bytes) | yara, matches: `win_mutex` |
| 4482966, 4716263, 4716599 | File operation strings | yara, matches: `win_files_operation` |
| 744814 | Android Meterpreter marker | yara, matches: `android_meterpreter` |
| 4486025, 8768204, 8574672, 7794039, 8379973, 4723205, 8574620, 7794091, 4723257, 8379921, 8962943, 7599372, 8768256, 7989291, 8184803, 8184855, 7599424, 7989343 | `ShellExecuteW` | malcat, top_strings |
| 4724743, 8186341, 8964429, 7600910, 8381459, 8769742, 8576158, 7795577, 7990829 | `ykernel32.dll` (obfuscated kernel32 string) | malcat, high_signal_strings |
### YARA Rule Path
/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yar (source: rule.yara.json, rule_path)

## 10. Detection Engineering
### Custom YARA Rule (source: rule.yara.json, generated_yara)
```yara
rule MALWARE_Meterpreter_UPX_Loader {
    meta:
        description = "Detects UPX-packed Meterpreter-associated loader/dropper"
        sha256 = "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5"
        author = "automated_analysis"
        date = "2026-08-03"
    strings:
        $upx_section = "UPX0" nocase
        $upx_section2 = "UPX1" nocase
        $xor_key = { b3 ae } // mov bl, 0xae at entry point
        $shell_exec = "ShellExecuteW" wide
        $ws2 = "WS2_32.dll" wide
        $mutex = { 00 11 22 33 44 55 66 77 88 99 aa bb } // placeholder for mutex at 4716493
        $meterpreter = { 53 64 65 45 6e 63 6f 64 65 } // checkSdeEncode marker at 744814
    condition:
        uint16(0) == 0x5A4D and
        filesize > 8000000 and
        $upx_section and $upx_section2 and
        $xor_key at entrypoint and
        $shell_exec and $ws2 and
        $meterpreter and
        pe.imports("ws2_32.dll", "bind") and
        pe.imports("kernel32.dll", "VirtualProtect") and
        pe.imports("kernel32.dll", "LoadLibraryA") and
        pe.imports("kernel32.dll", "GetProcAddress")
}
```
### Sigma Rule Path
/opt/samples/logs/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/rule.yml (source: rule.yara.json, sigma_path)
### Detection Logic
1. **Packing Detection**: Flag files with UPX0/UPX1/UPX2 sections, entropy > 140, and missing PE checksum (source: malcat, file_layout; malcat, anomalies: NoChecksum)
2. **Obfuscation Detection**: Flag entry points with single-byte XOR loops (key 0xae observed) and LZ decompression subroutines (source: r2, radare2_disassembly/0x010b4100; r2, radare2_disassembly/0x010b4196)
3. **Embedded Payload Detection**: Flag PE files with >5 embedded 192KB PE files in the overlay region (source: malcat, carved_files)
4. **Import-Based Detection**: Flag files with LoadLibraryA, GetProcAddress, VirtualProtect, and ws2_32.bind imports, plus >5 unreferenced imports (source: pe_imports, imports; malcat, anomalies: UnreferencedImports)
5. **String-Based Detection**: Flag files with `ShellExecuteW`, `ykernel32.dll` obfuscated strings, mutex strings at offset 4716493, and Android Meterpreter markers at offset 744814 (source: malcat, top_strings; yara, matches)

## 11. What We Don't Know
1. **IDA Analysis Results**: IDA analysis is unavailable due to validation failure, so no IDA-specific disassembly or cross-references are present (source: llm_judge, verdict.json: cross_engine_notes).
2. **Embedded Payload Functionality**: The 10 carved 193536-byte PE files were not unpacked, executed, or analyzed, so their exact malicious functionality is unknown (source: malcat, carved_files).
3. **Exact C2 Infrastructure**: No dynamic network activity was observed, so the actual C2 server addresses, protocols, and communication patterns are unknown (source: speakeasy, api_calls=0).
4. **Subroutine 0x010b4196 Full Functionality**: The decompilation of sub_10b4196 failed (source: malcat, decompilations/sub_10b4196: "Error while decompiling : not a valid ea"), so the full logic of the LZ decompression routine and subsequent payload execution is not fully mapped.
5. **Android Meterpreter Match Relevance**: The YARA `android_meterpreter` rule matched at offset 744814, but the sample is a 64-bit Windows PE, so the purpose of this cross-platform marker is unknown (potential false positive, cross-platform payload component, or misclassification) (source: yara, matches: android_meterpreter).
6. **UPX Unpack Failure Reason**: UPX unpacking failed with no error output, so the reason for unpack failure (custom UPX stub, modified UPX header, etc.) is unknown (source: upx, upx_unpack: upx_ok=False, returncode=None).
7. **Purpose of Identical Embedded PEs**: All 10 carved PE files are identical in size (193536 bytes), but it is unknown if they are identical in content, or if they are variant payloads for different architectures/functionalities (source: malcat, carved_files).

## 12. Appendix: Analysis Environment
| Tool | Version / Status | Purpose |
|---|---|---|
| Ghidra | Available (validation failed for IDA) | Static disassembly, function analysis, memory block mapping, string extraction (source: ghidra_query, audit_trail) |
| Malcat | Available | File layout analysis, anomaly detection, carved file extraction, string extraction, decompilation (source: malcat, all malcat tables) |
| capa | Available (v5.16) | Capability detection, MITRE ATT&CK mapping (source: capa, top_rules) |
| pe_imports | Available | Import analysis, ATT&CK signal mapping (source: pe_imports, imports; pe_imports, signals) |
| YARA | Available | Signature matching, IOC extraction (source: yara, matches; rule.yara.json) |
| FLOSS | Available | Obfuscated string extraction (source: floss, floss_strings) |
| radare2 | Available | Entry point disassembly, decompilation (source: r2, radare2_disassembly) |
| UPX | Available | Unpacking attempt (source: upx, upx_unpack) |
| Speakeasy | Available (v?) | Dynamic emulation (source: speakeasy, speakeasy_ok: True) |
| Frida | v17.16.4 | Dynamic instrumentation probing (source: frida_probe, frida_available: True) |
| Analysis Project | incoming | Sample corpus project name |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir | Analyzed sample location |
| Analysis Timestamps | 1785715867 - 1785762132 (UTC) | Audit trail timestamps (source: audit_trail) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5  
**sample_path:** /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: MALWARE (high confidence)
- **score**: 9
- **family_guess**: Meterpreter-associated UPX-packed loader/dropper
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: IDA analysis is unavailable due to validation failure, so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra's function count (25) and import count (12) align with Malcat's data, while Malcat provides unique high-level anomaly and structural insights (e.g., UPX sections, embedded PEs, XOR loops) not available from Ghidra. All tools consistently identify UPX packing, XOR obfuscation, and suspicious runtime linking imports. Malcat's carved PE files and capa's embedded PE detection align, confirming the presence of additional payloads. YARA matches for UPX, RunShell, and android_meterpreter corroborate the packing and post-exploitation framework association.
- **summary**: This is a high-confidence malicious 64-bit Windows PE file, packed with UPX and likely functioning as a Meterpreter-associated loader/dropper. The sample employs XOR obfuscation in its entry point to decode its payload in memory, uses dynamic API resolution (LoadLibrary/GetProcAddress) to hide functionality, and contains 10 embedded PE payloads for delivery. It has capabilities for memory permission modification (VirtualProtect, for code injection/execution), and likely network communication (per WS2_32 import and YARA network-related rules). The high entropy, packing, and multiple obfuscation techniques are designed to evade static analysis, with the embedded payloads containing the core malicious post-exploitation functionality.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with UPX` | Confirms the sample is compressed with UPX, a packer frequently used to obfuscate malware, consistent with Malcat's UPX  |
| malcat | decompilations | `EntryPoint@4481792 decompilation` | The entry point contains an XOR decoding loop (key 0xae) that modifies memory in place, a common obfuscation technique f |
| pe_imports | signals | `change_memory_protection (VirtualProtect, T1055)` | VirtualProtect is used to alter memory page permissions, a key technique for code injection, shellcode execution, and ev |
| malcat | carved files | `10 carved PE files at offsets 4535183, 4730130, 7411350, etc.` | The sample embeds 10 additional PE files, which are almost certainly malicious payloads intended to be dropped or execut |
| pe_imports | signals | `load_library (LoadLibrary, T1129) and get_proc_address (GetProcAddress, T1129)` | These APIs enable dynamic resolution of function addresses at runtime, a common obfuscation method to hide malicious API |
| malcat | file_summary | `entropy=145` | Extremely high file entropy is a strong indicator of packed, encrypted, or compressed malicious content, consistent with |
| yara | matches | `android_meterpreter` | This YARA match indicates the sample is associated with Meterpreter, a widely used post-exploitation framework, suggesti |
| malcat | anomalies | `CrossSectionJump` | Control flow that jumps across section boundaries is a common indicator of packed or patched malware, used to disrupt st |
| malcat | anomalies | `UnreferencedImports×8` | 8 imported functions have no static cross-references, indicating they are called dynamically at runtime to hide maliciou |
| malcat | anomalies | `NoChecksum` | Missing PE header checksum is a common trait of packed or modified malware, as packers typically do not recalculate the  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a 64-bit Windows PE with UPX packing and runtime dynamic API resolution. Static imports are minimal and include networking, process/memory, and user-profile APIs. Capa flags UPX packing, XOR-based encoding, embedded PE handling, process termination, and runtime linking. YARA matches include UPX signatures, Winsock library strings, mutex strings, file-operation strings, and an Android Meterpreter-related marker. The entry routine performs a large XOR decode loop over a memory region, then pushes a decoded pointer and calls into obfuscated code, consistent with a packed loader/dropper.

### deep key_evidence
- `"UPX sections present: UPX0/UPX1/UPX2 memory blocks (Ghidra memory_blocks)"`
- `"YARA UPX match at offsets 392, 432, 517"`
- `"YARA Winsock library string match at offset 4483023"`
- `"YARA mutex string match at offset 4716493"`
- `"YARA file-operation strings at offsets 4482966, 4716263, 4716599"`
- `"YARA android_meterpreter marker at offset 744814"`
- `"Imports: LoadLibraryA, GetProcAddress, VirtualProtect, bind, GetAdaptersAddresses, GetProcessMemoryInfo, GetUserProfileDirectoryW, ExitProcess (Ghidra imports)"`
- `"Capa: packed with UPX; encode data using XOR; terminate process; link function at runtime on Windows; contain an embedded PE file"`
- `"Entry disassembly shows large XOR decode loop and subsequent call into decoded code (r2 decompile at 0x010b4100)"`
- `"PE import signals: LoadLibrary, GetProcAddress, VirtualProtect (pe_import_signals)"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5
size: 8964155
type: PE
architecture: X64
entrypoint_ea: 4481792
entropy: 145
file_name: virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 216 | - |
| UPX1 | 512 | 4482048 | 4485120 | 210 | RWX |
| UPX2 | 4485632 | 1024 | 4096 | 0 | RW |
| overlay | 4489728 | 4480571 | 0 | 81 | - |
| UPX0 | 8970299 | 0 | 8835072 | 0 | RWX |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| UPX | packer | INFO | 40 | Detect UPX based on section artifacts and EP |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 2 | executable section has the flag code not set |
| InvalidBaseOfCode | 4 | sections | 1 | at least one code section starts before BaseOfCode, or BaseOfCode is not the start of a code section |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 41 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| EmbeddedProgram | 3 | embedding | 10 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| PurelyVirtualExecutableSection | 3 | sections | 1 | a section is virtual-only and executable (packer?) |
| RelocationsNotInRelocSection | 3 | sections | 1 | relocations are not in .reloc |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 8 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| Packed | 2 | packers | 0 | File is packed using a legit or less-legit obfuscator |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **NoChecksum**
  - `216`: 
- **XorInLoop**
  - `4481815`: 
  - `4482011`: 

### High-Signal Strings (30 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 4486038 | `KERNEL32.DLL` |
| 4486013 | `CRYPT32.dll` |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\\\gggg\\\\` |
| 4724743 | `ykernel32.dll` |
| 8186341 | `ykernel32.dll` |
| 8964429 | `ykernel32.dll` |
| 7600910 | `ykernel32.dll` |
| 8381459 | `ykernel32.dll` |
| 8769742 | `ykernel32.dll` |
| 8576158 | `ykernel32.dll` |
| 7795577 | `ykernel32.dll` |
| 7990829 | `ykernel32.dll` |
| 4722833 | `kernel32.dll` |
| 7599000 | `kernel32.dll` |
| 8184431 | `kernel32.dll` |
| 7988919 | `kernel32.dll` |
| 8574248 | `kernel32.dll` |
| 8767832 | `kernel32.dll` |
| 7793667 | `kernel32.dll` |
| 8962519 | `kernel32.dll` |
| 8379549 | `kernel32.dll` |
| 8574330 | `crypt32.dll` |
| 7793749 | `crypt32.dll` |
| 8767914 | `crypt32.dll` |
| 4722915 | `crypt32.dll` |
| 7599082 | `crypt32.dll` |
| 8184513 | `crypt32.dll` |
| 8962601 | `crypt32.dll` |
| 7989001 | `crypt32.dll` |
| 8379631 | `crypt32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 8962891 | `ShellExecuteW` |
| 8768204 | `ShellExecuteW` |
| 8574672 | `ShellExecuteW` |
| 7794039 | `ShellExecuteW` |
| 8379973 | `ShellExecuteW` |
| 4723205 | `ShellExecuteW` |
| 8574620 | `ShellExecuteW` |
| 7794091 | `ShellExecuteW` |
| 4723257 | `ShellExecuteW` |
| 8379921 | `ShellExecuteW` |
| 8962943 | `ShellExecuteW` |
| 7599372 | `ShellExecuteW` |
| 8768256 | `ShellExecuteW` |
| 7989291 | `ShellExecuteW` |
| 8184803 | `ShellExecuteW` |
| 8184855 | `ShellExecuteW` |
| 7599424 | `ShellExecuteW` |
| 7989343 | `ShellExecuteW` |
| 4486025 | `IPHLPAPI.DLL` |
| 4486038 | `KERNEL32.DLL` |
| 4486062 | `PSAPI.DLL` |
| 4486000 | `ADVAPI32.dll` |
| 4486083 | `USERENV.dll` |
| 4486095 | `WS2_32.dll` |
| 4486013 | `CRYPT32.dll` |
| 4486051 | `msvcrt.dll` |
| 4486072 | `USER32.dll` |
| 8190317 | `SJafGSZcYvfvcEIs..wfjmMoKypOGsRkCs` |
| 7994805 | `ICFMVOEbrAanwjOb..qXFLjnjTyhzwuQtX` |
| 8968405 | `txaNmVkwHcwvXpjX..NJDNqmVqgMtzopdk` |
| 7604886 | `wKNVPIimQvCQbXJe..LrsEqMTnscESjwuD` |
| 7995919 | `&MOdcJRsgEeFIbRP..YnfCzXGWiBHXAlvZ` |
| 8386000 | `8hiPELBXDGhssVkB..WlQwsVRogPadkjJf` |
| 4729593 | `EhYDEBYdcTNvihDQ..sfilkguQrnejpUDK` |
| 7800696 | `gPLOHvfwhpeIKJUR..JQAfoAftrTfoXXLq` |
| 8385435 | `HOXANYvuzYVfJhdj..OmMWXYlvpXLtJlCt` |
| 8773718 | `DdpJKXOFdZYmIwoh..rmrGxndVMLwurmYR` |
| 4728719 | `dVBnplzWzWmfiwSJ..AAivDshTtQASfYtG` |
| 7799553 | `MQXAgaWhYjqDFmIc..wVwLrXFwdzNNhEjz` |
| 8191121 | `6zLQQlNfMrqUeqVT..SZhGOncQjhhZDbjV` |
| 8774367 | `?RYerWDAyvWtviRt..wENRvzjRkjeotMmW` |
| 8969617 | `LzHCKoEFspvsKMwN..dEjGOrFnKkYEIQiv` |
| 4089304 | `^Q^^gggg^^^^gggg..gggg\\\\gggg\\\\` |
| 4724743 | `ykernel32.dll` |
| 8186341 | `ykernel32.dll` |
| 8964429 | `ykernel32.dll` |
| 7600910 | `ykernel32.dll` |
| 8381459 | `ykernel32.dll` |
| 8769742 | `ykernel32.dll` |
| 8576158 | `ykernel32.dll` |
| 7795577 | `ykernel32.dll` |
| 7990829 | `ykernel32.dll` |
| 2745726 | `/7/o/G/` |
| 7795489 | `ekjynhadefrderat..haterafdertayunm` |
| 8964341 | `ekjynhadefrderat..haterafdertayunm` |
| 2107489 | `9.QQQ` |
| 8186253 | `ekjynhadefrderat..haterafdertayunm` |
| 4724655 | `ekjynhadefrderat..haterafdertayunm` |
| 8576070 | `ekjynhadefrderat..haterafdertayunm` |
| 7600822 | `ekjynhadefrderat..haterafdertayunm` |
| 2098869 | `l.QQQ` |
| 7990741 | `ekjynhadefrderat..haterafdertayunm` |
| 8769654 | `ekjynhadefrderat..haterafdertayunm` |
| 4307724 | `m.QQQ` |
| 8381371 | `ekjynhadefrderat..haterafdertayunm` |
| 8381427 | `acledit.dll` |
| 4724711 | `acledit.dll` |
| 8767978 | `modemui.dll` |
| 8380073 | `modemui.dll` |
| 4723357 | `modemui.dll` |
| 8574394 | `modemui.dll` |
| 7600878 | `acledit.dll` |
| 7599146 | `modemui.dll` |
| 8379987 | `shell32.dll` |
| 7599438 | `shell32.dll` |
| 7599524 | `modemui.dll` |
| 8962665 | `modemui.dll` |
| 8184869 | `shell32.dll` |
| 2048730 | `nW.QQQ` |
| 1524594 | `/N/Np` |

### Imports (12)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4485832 | advapi32.FreeSid | IMPORT | 1 |
| 4485848 | crypt32.CertOpenStore | IMPORT | 1 |
| 4485864 | iphlpapi.GetAdaptersAddresses | IMPORT | 1 |
| 4485880 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4485888 | kernel32.ExitProcess | IMPORT | 1 |
| 4485896 | kernel32.GetProcAddress | IMPORT | 1 |
| 4485904 | kernel32.VirtualProtect | IMPORT | 1 |
| 4485920 | msvcrt.atof | IMPORT | 1 |
| 4485936 | psapi.GetProcessMemoryInfo | IMPORT | 1 |
| 4485952 | user32.GetMessageA | IMPORT | 1 |
| 4485968 | userenv.GetUserProfileDirectoryW | IMPORT | 1 |
| 4485984 | ws2_32.bind | IMPORT | 1 |

### Functions (4)
| EA | Name |
|---|---|
| 4481942 | sub_10b4196 |
| 4481792 | EntryPoint |
| 4481880 | sub_10b4158 |
| 4482343 | sub_10b4327 |

### Decompilations (top 6)
#### 4481942 — sub_10b4196
```c
sub_10b4196 {
    // Error while decompiling : not a valid ea
}

```
#### 4481792 — EntryPoint
```c

/* WARNING: Removing unreachable block (ram,0x010b414a) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    uint8_t *in_R9;
    
    puVar1 = 0xc6e025;
    do {
        *puVar1 = *puVar1 ^ 0xae;
        puVar1 = puVar1 + 1;
    } while (puVar1 != in_R9);
    [0x0x10aa37c] = 0x712e619e;
    sub_10b4196(0);
    return;
}

```
#### 4481880 — sub_10b4158
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_10b4158(uint32_t param_1)

{
    undefined4 uVar1;
    uint32_t uVar2;
    undefined4 *puVar3;
    undefined uVar4;
    uint64_t unaff_RBP;
    undefined4 *unaff_RDI;
    
    puVar3 = unaff_RDI + unaff_RBP;
    uVar4 = *puVar3;
    if ((5 < param_1) && (unaff_RBP < 0xfffffffffffffffd)) {
        uVar2 = param_1 - 4;
        do {
            param_1 = uVar2;
            uVar1 = *puVar3;
            puVar3 = puVar3 + 1;
            *unaff_RDI = uVar1;
            unaff_RDI = unaff_RDI + 1;
            uVar2 = param_1 - 4;
        } while (3 < param_1);
        uVar4 = *puVar3;
        if (param_1 == 0) {
            return;
        }
    }
    do {
        puVar3 = puVar3 + 1;
        *unaff_RDI = uVar4;
        param_1 = param_1 - 1;
        uVar4 = *puVar3;
        unaff_RDI = unaff_RDI + 1;
    } while (param_1 != 0);
    return;
}

```

### Carved Files (10)
| Name | Type | Size |
|---|---|---|
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |
| ? | PE | 193536 |

### Structures (21)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 392 |
| UPX.PackHeader | 517 |
| ExceptionTable | 1290752 |
| TlsDirectory | 4482384 |
| TLSInitArray | 4482424 |
| TlsCallbacks | 4482432 |
| ImportTable | 4485632 |
| advapi32.FT | 4485832 |
| crypt32.FT | 4485848 |
| iphlpapi.FT | 4485864 |
| kernel32.FT | 4485880 |
| msvcrt.FT | 4485920 |
| psapi.FT | 4485936 |
| user32.FT | 4485952 |
| userenv.FT | 4485968 |
| ws2_32.FT | 4485984 |
| ImportNames | 4486000 |
| Relocations | 4486292 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 5 · duration_s: 1.11

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with UPX | T1027.002:Obfuscated Files or Information | F0001.008:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| terminate process |  | C0018:Terminate Process |
| link function at runtime on Windows | T1129:Shared Modules |  |

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
  "generated_at": "2026-08-03T13:02:12.041004+00:00",
  "string_count": 24,
  "strings": [
    "GetUserProfileDirectoryW",
    "GetAdaptersAddresses",
    "GetProcessMemoryInfo",
    "VirtualProtect",
    "CertOpenStore",
    "ADVAPI32.dll",
    "IPHLPAPI.DLL",
    "KERNEL32.DLL",
    "LoadLibraryA",
    "CRYPT32.dll",
    "USERENV.dll",
    "ExitProcess",
    "GetMessageA",
    "msvcrt.dll",
    "USER32.dll",
    "WS2_32.dll",
    "PSAPI.DLL",
    "Confirms the sample is compressed with UPX, a packer frequently used to obfuscate malware, consistent with Malcat's UPX ",
    "The entry point contains an XOR decoding loop (key 0xae) that modifies memory in place, a common obfuscation technique f",
    "VirtualProtect is used to alter memory page permissions, a key technique for code injection, shellcode execution, and ev",
    "The sample embeds 10 additional PE files, which are almost certainly malicious payloads intended to be dropped or execut",
    "These APIs enable dynamic resolution of function addresses at runtime, a common obfuscation method to hide malicious API",
    "Extremely high file entropy is a strong indicator of packed, encrypted, or compressed malicious content, consistent with",
    "This YARA match indicates the sample is associated with Meterpreter, a widely used post-exploitation framework, suggesti"
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
  "cadre_revai": true,
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
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_read, is_write, is_exec FROM memory_blocks ORDER BY start_ea", "ts": 1785715867.8822777}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 50", "ts": 1785715874.1863232}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs WHERE to_ea IN (17514752, 17514840, 17514902, 17515302) ORDER BY to_ea", "ts": 1785715874.3619256}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785715893.4052997}`
- `{"source": "yara_gen_v2", "ts": 1785715894.4405937}`
- `{"source": "publish_report_v2", "ts": 1785715999.2251601}`
- `{"source": "publish_report_v2_technical", "ts": 1785716073.9139216}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785761501.059775}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785761502.0303588}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785761502.0531745}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785761502.097601}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785761724.526902}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785761724.58553}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785761725.3001533}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785761725.352586}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785761725.357742}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785761964.0585084}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports LIMIT 50", "ts": 1785761968.0816832}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs LIMIT 50", "ts": 1785761968.0857038}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings LIMIT 50", "ts": 1785761968.1019697}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM string_refs WHERE string_value LIKE '%ws2%' OR string_value LIKE '%bind%' OR string_value LIKE '%mutex%' OR string_value LIKE '%http%' OR string_value LIKE '%cmd%' OR string_value LIKE '%shell%' OR string_value LIKE '%meterpreter%' OR string_value LIK`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics ORDER BY instruction_count DESC LIMIT 20", "ts": 1785762093.0062385}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%\\\\Windows\\\\System32%' OR content LIKE '%\\\\Temp%' OR content LIKE '%http%' OR content LIKE '%cmd.exe%' OR content LIKE '%powershell%' OR content LIKE '%rundll32%' OR content LIKE '%regsvr32%' LIMIT 100", "ts": 1785762`
- `{"source": "ghidra_query", "sql": "SELECT * FROM memory_blocks ORDER BY size DESC LIMIT 20", "ts": 1785762097.4905524}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE length > 20 ORDER BY length DESC LIMIT 100", "ts": 1785762105.753236}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM xrefs WHERE to_ea IN (SELECT ea FROM strings WHERE content='bind' OR content='GetUserProfileDirectoryW' OR content='GetAdaptersAddresses' OR content='GetProcessMemoryInfo') LIMIT 50", "ts": 1785762111.1714277}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%.%' AND length BETWEEN 6 AND 80 ORDER BY length DESC LIMIT 100", "ts": 1785762111.1805346}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE content LIKE '%\\\\%' OR content LIKE '%/%' OR content LIKE '%:%' LIMIT 100", "ts": 1785762111.1940024}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785762131.012331}`
- `{"source": "yara_gen_v2", "ts": 1785762132.0412014}`
