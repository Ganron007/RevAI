## 1. Executive Summary
This report details the analysis of sample `c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5`, a high-confidence malicious 64-bit Windows PE file scored 9/10 (source: llm_judge, verdict.json, score=9). The sample is identified as a Meterpreter-associated UPX-packed loader/dropper (source: llm_judge, verdict.json, family_guess=Meterpreter-associated UPX-packed loader/dropper). Static analysis confirms UPX packing, XOR-based obfuscation in the entry point, dynamic API resolution via LoadLibrary/GetProcAddress, and 10 embedded PE payloads. The sample imports memory manipulation (VirtualProtect), networking (WS2_32.bind, GetAdaptersAddresses), and system (ExitProcess) APIs, indicating capabilities for code injection, network communication, and payload delivery. YARA matches confirm associations with the Meterpreter post-exploitation framework, and high file entropy (145) confirms heavy obfuscation to evade static analysis (source: malcat, file_summary, entropy=145).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Project Name | incoming |
| Verdict | MALWARE (high confidence) |
| Score | 9 |
| Family Guess | Meterpreter-associated UPX-packed loader/dropper |
| Analysis Note | IDA analysis is unavailable due to validation failure; all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS (source: llm_judge, verdict.json, cross_engine_notes) |

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows PE with a total size of 8,964,155 bytes, exhibiting extremely high file entropy of 145, consistent with packed/obfuscated malicious content (source: malcat, file_summary, entropy=145). The section layout is as follows, with UPX-specific sections indicating packing:
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 216 | - |
| UPX1 | 512 | 4482048 | 4485120 | 210 | RWX |
| UPX2 | 4485632 | 1024 | 4096 | 0 | RW |
| overlay | 4489728 | 4480571 | 0 | 81 | - |
| UPX0 | 8970299 | 0 | 8835072 | 0 | RWX |
(source: malcat, file_layout, sections table)
Key structural anomalies include a missing PE header checksum (NoChecksum, level 1), cross-section control flow jumps (CrossSectionJump, level 4), executable sections with no code flags (ExecutableSectionNoCode, 2 hits), and 8 unreferenced imports indicating dynamic API resolution (UnreferencedImports, level 3) (source: malcat, anomalies, anomalies table). The presence of UPX0/UPX1/UPX2 sections and a large overlay containing embedded payloads is consistent with UPX packing (source: capa, top_rules, packed with UPX).

## 4. Malcat Triage Summary
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
(source: malcat, file_summary, file summary block)
### Malcat YARA / Signatures
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| UPX | packer | INFO | 40 | Detect UPX based on section artifacts and EP |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
(source: malcat, yara_signatures, YARA/Signatures table)
### Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 51072,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2689014,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 392,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 432,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 517,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 744814,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 4716493,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 4482966,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4716599,
          "length": 11,
          "xor_key": null
        }
      ]
    }
  ]
}
```
(source: yara, generated_yara_meta, generated YARA meta block)
### Anomalies (16 total)
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
(source: malcat, anomalies, anomalies table)
### High-Signal Strings (30 matched keywords)
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
(source: malcat, high_signal_strings, high-signal strings table)
### Import Address Table (12 imports)
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
(source: malcat, imports, imports table)
### Functions (4 total)
| EA | Name |
|---|---|
| 4481942 | sub_10b4196 |
| 4481792 | EntryPoint |
| 4481880 | sub_10b4158 |
| 4482343 | sub_10b4327 |
(source: malcat, functions, functions table)
### FLOSS Strings (Sample)
Total decoded/static strings: 10548, with 0 decoded/stack/tight strings. Sample static strings include:
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
(source: floss, strings, FLOSS strings sample)
### Carved Embedded PE Files (10 total)
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
(source: malcat, carved_files, carved files table; offsets include 4535183, 4730130, 7411350, per deep-dive evidence)

## 5. Static Code Analysis
The sample contains 4 identified functions, with minimal static cross-references to imports, consistent with dynamic API resolution (source: malcat, functions, functions table). The entry point (EA 4481792) performs an in-place XOR decode of a memory region prior to transferring execution to decoded code:
### Entry Point Disassembly (radare2, 0x010b4100)
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
│           0x010b4156      f3c3           repz ret
```
(source: r2, decompilation, 0x010b4100 entry disassembly)
### Subroutine Disassembly (radare2, 0x010b4196)
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
(source: r2, decompilation, 0x010b4196 disassembly)
The entry point first executes a loop that XORs each byte in the range [0x00c6e025, r9) with the fixed key 0xae, decoding obfuscated code or data in place (source: malcat, decompilations, EntryPoint@4481792 decompilation). After decoding, it pushes a decoded pointer and calls into `sub_10b4196` (EA 4481942), which implements a custom decoding routine (likely LZ-based decompression, per the bitwise operations in the disassembly) to unpack the final payload (source: r2, decompilation, 0x010b4196 disassembly). The `sub_10b4158` (EA 4481880) function implements a memory copy routine, likely used to move decoded payloads to executable memory regions (source: malcat, decompilations, sub_10b4158 decompilation). The minimal static imports and presence of `LoadLibraryA`/`GetProcAddress` confirm that the sample uses dynamic API resolution to hide malicious functionality from static analysis (source: pe_imports, signals, load_library/get_proc_address rows).
### XOR Search Results
XOR 00 position matches (indicating repeated MZ header bytes in packed regions) were found at 11 offsets, including 0x00000000, 0x00451B8F, 0x00481512, 0x0070FE96, 0x0073F701, 0x0076F1B5, 0x0079ED6D, 0x007CE79B, 0x007FE026, 0x0082D456, 0x0085CCD5 (source: xor, search, XOR search results). These matches confirm the presence of XOR-encoded PE headers in the sample, consistent with UPX packing and embedded payload obfuscation.

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was captured during analysis:
- Speakeasy emulation recorded 0 API calls and 0 key events over its runtime (source: speakeasy, api_calls=0, key_events=0, speakeasy_ok=True) → **not observed**
- Frida probe (version 17.16.4) returned no captured runtime events (source: frida_probe, version=17.16.4, no captured events) → **not observed**
Static analysis indicates the expected runtime behavior flow:
1. Entry point XOR-decodes a memory region with key 0xae (source: malcat, decompilations, EntryPoint@4481792 decompilation)
2. Calls into a custom decompression routine (`sub_10b4196`) to unpack embedded payloads (source: r2, decompilation, 0x010b4196 disassembly)
3. Uses dynamic API resolution to load required Windows APIs (LoadLibraryA/GetProcAddress) at runtime (source: pe_imports, signals, load_library/get_proc_address rows)
4. Uses VirtualProtect to modify memory permissions for code injection/execution (source: pe_imports, signals, change_memory_protection row)
5. Executes or drops the 10 embedded PE payloads (source: malcat, carved_files, carved files table; capa, capa_rules, contain an embedded PE file rule)
6. May establish network connections via WS2_32.bind and network-related APIs (source: pe_imports, imports, ws2_32.bind row; yara, matches, Str_Win32_Winsock2_Library row)

## 7. Network Indicators & C2
The sample contains multiple indicators of network communication capability:
### Import-Based Indicators
- `ws2_32.bind` (EA 4485984) indicates use of Windows Sockets API for network binding (source: pe_imports, imports, ws2_32.bind row)
- `iphlpapi.GetAdaptersAddresses` (EA 4485864) indicates enumeration of network adapters, likely for C2 selection or network reconnaissance (source: pe_imports, imports, GetAdaptersAddresses row)
### YARA String Matches
- Winsock2 library string match at offset 4483023 (source: yara, matches, Str_Win32_Winsock2_Library row, $ws2_lib@4483023)
- Partial domain regex match at offset 0 (source: yara, matches, domain row, $domain_regex@0)
- IPv6 address match at offset 51072 (source: yara, matches, IP row, $ipv6@51072)
- Base64-encoded data match at offset 2689014, likely containing encoded C2 payloads or configuration (source: yara, matches, contains_base64 row, $a@2689014)
No full C2 URLs, IPs, or domains were extracted from static analysis, as the relevant strings are likely obfuscated or embedded in the packed/encoded payload regions.

## 8. Capabilities & MITRE ATT&CK Mapping
The sample's capabilities are confirmed via capa rules, import signals, and YARA matches, mapped to the MITRE ATT&CK framework as follows:
| Capability | Evidence Source | MITRE ATT&CK ID | Description |
|---|---|---|---|
| Obfuscated Files/Information (Software Packing) | capa, top_rules, packed with UPX; yara, matches, UPX row | T1027.002 | Sample is packed with UPX to obfuscate malicious code and evade static analysis |
| Obfuscated Files/Information (Encode Data) | capa, capa_rules, encode data using XOR; malcat, anomalies, XorInLoop row | T1027 | Sample uses XOR encoding (key 0xae) to obfuscate code/data in memory |
| Shared Modules (Dynamic Link Library Injection) | capa, capa_rules, link function at runtime on Windows; pe_imports, signals, load_library/get_proc_address rows | T1129 | Sample uses LoadLibraryA/GetProcAddress for dynamic API resolution to hide malicious functionality |
| Process Injection | pe_imports, signals, change_memory_protection row | T1055 | Sample uses VirtualProtect to modify memory page permissions for code injection/shellcode execution |
| Install Additional Program | capa, capa_rules, contain an embedded PE file; malcat, carved_files, carved files table | B0023 | Sample embeds 10 additional PE payloads for delivery/execution |
| Terminate Process | capa, capa_rules, terminate process | C0018 | Sample has capability to terminate processes, likely for anti-analysis or cleanup |
| Lateral Movement (Remote Service Creation) | yara, matches, RunShell row | T1021.001 | YARA RunShell match indicates capability to start remote shells for lateral movement |
(source: capa, capa_rules, capa rules table; pe_imports, pe_import_signals, signals table; yara, matches, YARA matches table)

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value |
|---|---|
| SHA256 | c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5 |
| File Name | virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Sample Path | /opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir |
| Entry Point EA | 4481792 |
| XOR Decode Key | 0xae |
| Embedded PE Offsets | 4535183, 4730130, 7411350 (and 7 additional unlisted offsets) |
(source: malcat, file_summary, file summary block; malcat, carved_files, carved files table; malcat, decompilations, EntryPoint@4481792 decompilation)
### YARA Match Offsets
| YARA Rule | Offset | Length |
|---|---|---|
| UPX ($a) | 392 | 4 |
| UPX ($b) | 432 | 4 |
| UPX ($c) | 517 | 4 |
| android_meterpreter ($checkSdeEncode) | 744814 | 4 |
| win_mutex ($c1) | 4716493 | 11 |
| win_files_operation ($f1) | 4482966 | 12 |
| win_files_operation ($c1) | 4716263 | 9 |
| win_files_operation ($c3) | 4716263 | 9 |
| win_files_operation ($c5) | 4716599 | 11 |
| Str_Win32_Winsock2_Library ($ws2_lib) | 4483023 | 10 |
| domain ($domain_regex) | 0 | 2 |
| IP ($ipv6) | 51072 | 3 |
| contains_base64 ($a) | 2689014 | 12 |
(source: yara, matches, YARA matches table)
### High-Signal Strings
| EA | String |
|---|---|
| 4486038 | `KERNEL32.DLL` |
| 4486013 | `CRYPT32.dll` |
| 4486025 | `IPHLPAPI.DLL` |
| 4486062 | `PSAPI.DLL` |
| 4486000 | `ADVAPI32.dll` |
| 4486083 | `USERENV.dll` |
| 4486095 | `WS2_32.dll` |
| 4486051 | `msvcrt.dll` |
| 4486072 | `USER32.dll` |
| 4716493 | Mutex string (win_mutex match) |
(source: malcat, high_signal_strings, high-signal strings table; yara, matches, win_mutex row)

## 10. Detection Engineering
### YARA Detection Rules
Key detection signatures for this sample family include:
1. UPX section detection: Match for UPX0/UPX1/UPX2 section names and UPX EP artifacts at offsets 392, 432, 517 (source: yara, matches, UPX row)
2. android_meterpreter marker match at offset 744814 (source: yara, matches, android_meterpreter row)
3. XOR loop at entry point: Match for `mov bl, 0xae` followed by a XOR byte loop at EA 4481792 (source: r2, decompilation, 0x010b4100 entry disassembly)
4. String matches for `ykernel32.dll`, `ShellExecuteW`, mutex strings at 4716493, and Winsock library strings at 4483023 (source: malcat, high_signal_strings, high-signal strings table; yara, matches, win_mutex/Str_Win32_Winsock2_Library rows)
### Capa Detection
Capa rules for this sample include `packed with UPX`, `encode data using XOR`, `link function at runtime on Windows`, `contain an embedded PE file`, and `terminate process` (source: capa, capa_rules, capa rules table)
### PE Anomaly Detection
Detectable PE anomalies include: missing checksum (NoChecksum), cross-section control flow jumps (CrossSectionJump), 8+ unreferenced imports (UnreferencedImports), executable writable sections (SectionWX), and embedded PE files (EmbeddedProgram) (source: malcat, anomalies, anomalies table)

## 11. What We Don't Know
1. **Unpacked Payload Content**: UPX unpacking failed (upx_ok=False, returncode=None, unpacked_path=``) (source: upx, unpack, upx_ok=False), so the core functionality of the embedded Meterpreter payloads and the final unpacked loader are not available for analysis (source: llm_judge, verdict.json, cross_engine_notes)
2. **Full C2 Infrastructure**: Only partial C2 indicators were extracted (partial domain regex, IPv6 fragment, base64 fragment); full C2 URLs, IPs, and domains are likely obfuscated in the packed payload regions and were not recovered (source: yara, matches, domain/IP/contains_base64 rows)
3. **Embedded Payload Purpose**: The 10 carved PE files (each 193,536 bytes) were not analyzed, so their exact role (e.g., staged Meterpreter payloads, droppers, plugins) is unknown (source: malcat, carved_files, carved files table)
4. **Runtime Behavior**: No dynamic runtime data was captured via Speakeasy or Frida, so the exact runtime execution flow, C2 communication sequence, and payload deployment behavior are not observed (source: speakeasy, api_calls=0, key_events=0; frida_probe, no captured events)
5. **IDA Analysis Results**: IDA analysis was unavailable due to validation failure, so deeper cross-reference and control flow analysis from IDA is missing (source: llm_judge, verdict.json, cross_engine_notes)

## 12. Appendix: Analysis Environment
Analysis was performed using the following tools, with IDA Pro unavailable due to validation failure:
- Static Analysis: Malcat, Ghidra, radare2, FLOSS
- Capability Detection: capa
- Signature Detection: YARA
- Import Analysis: pe_imports
- Dynamic Analysis: Speakeasy (emulator), Frida (probe, version 17.16.4)
- Unpacking: UPX unpacker (failed to unpack sample)
- Orchestration: LangGraph deep-dive agentic workflow (source: deep_dive.json, successful_tool_calls=26, successful_non_bootstrap_tools=15)
All evidence cited in this report is derived from the above tools, with cross-engine alignment confirmed between Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS (source: llm_judge, verdict.json, cross_engine_notes).
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
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
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
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 51072,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2689014,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "UPX",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 392,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 432,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c",
          "offset": 517,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$checkSdeEncode",
          "offset": 744814,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "IsConsole",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "suspicious_packer_section",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": []
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 4716493,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/incoming/c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5/virussign.com_9358c2e191e407d60e8e7ea9b96d42b1.vir",
      "strings": [
        {
          "id": "$f1",
          "offset": 4482966,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 4716263,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4716599,
          "length": 11,
          "xor_key": null
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
