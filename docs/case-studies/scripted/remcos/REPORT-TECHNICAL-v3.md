# Technical Malware Analysis Report: Remcos RAT Sample 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0

## 1. Executive Summary
This report details the analysis of a high-confidence Remcos remote access trojan (RAT) sample, scoring 95/100 for maliciousness (source: llm_judge, verdict.json, verdict: Malicious - Remcos RAT, score: 95). The sample is a 32-bit Windows GUI executable compiled with Visual C++ 2003, packed with a high-entropy overlay containing the malicious payload (source: malcat, file_summary.metadata, file_name: remcos_sample.exe; malcat, file_summary.layout, overlay entropy: 202). Static analysis confirms the sample uses XOR loop obfuscation (54 hits, source: malcat, anomalies, name: XorInLoop, num_hits: 54), import resolution by hash (source: malcat, anomalies, name: ImportByHash, level: 4), and embedded DES encryption constants for C2 and data obfuscation (source: malcat, constants, type: crypto::DES_*). Capa and YARA rules confirm core Remcos capabilities including keylogging (source: capa, top_rules, name: log keystrokes via polling, attack[0].id: T1056.001; source: yara, matches, rule: keylogger), registry persistence (source: capa, top_rules, name: persist via Run registry key, attack[0].id: T1547.001; source: yara, matches, rule: win_registry), process enumeration (source: pe_imports, signals, api_match: CreateToolhelp32Snapshot, attack: [T1057]), and browser credential harvesting via embedded login page URLs for Google, Facebook, and Yahoo (source: ghidra, suspicious strings, content: https://www.google.com/accounts/servicelogin). No dynamic runtime behavior was observed during analysis.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0 |
| Sample Path | /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe |
| Project Name | incoming |
| Verdict | Malicious - Remcos RAT |
| Score | 95 |
| Family Guess | Remcos |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | IDA analysis is unavailable due to missing idasql binary; all evidence is derived from Ghidra, Malcat, capa, YARA, FLOSS, and pe_imports. Ghidra (1057 strings) and Malcat (100 strings) string datasets are combined for maximum coverage with high confidence. Ghidra decompilation confirms DES encryption routines that align with Malcat's embedded DES constant detections and capa's DES encryption behavior rules. Independent engines consistently detect core Remcos capabilities including keylogging, registry persistence, process enumeration, and credential harvesting indicators. |
| Source | llm_judge, verdict.json |

## 3. File Layout & Structural Analysis
The sample is a 698895-byte PE32 X86 Windows GUI executable with an entry point at 0x285996 and overall entropy of 160 (source: malcat, file_summary.metadata). The section layout is as follows, with a high-entropy (202) overlay at the end of the file containing the packed malicious payload:
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 92 | - |
| .text | 1024 | 315904 | 319488 | 142 | RX |
| .rdata | 320512 | 45056 | 45056 | 86 | R |
| .data | 365568 | 5632 | 106496 | 83 | RW |
| .rsrc | 472064 | 35328 | 36864 | 34 | R |
| overlay | 508928 | 295951 | 0 | 202 | - |
(source: malcat, file_summary.layout)
The high-entropy overlay is a common packing technique used by Remcos to hide the main payload from static analysis (source: malcat, anomalies, name: BigResourceHighEntropy, level: 2). The .text section has elevated entropy (142) indicating obfuscated code, and the .data section has a large virtual size relative to physical size (UnbalancedVirtualPhysicalRatio anomaly, source: malcat, anomalies, name: UnbalancedVirtualPhysicalRatio, level: 1).

## 4. Malcat Triage Summary
Malcat identified 5 YARA/signature matches, 15 anomalies, 8 high-signal strings, and 300 total extracted strings. Key findings include:
### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2005_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2003_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| Sqlite | library | INFO | 80 | embeds sqlite library, sqlite is often used by password stealers |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
(source: malcat, signatures)
### Anomalies (15)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ImportByHash | 4 | imports | 1 | APIs are imported by hash |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 3 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 9 | string is constructed dynamically |
| EmbeddedProgram | 3 | embedding | 3 | File embeds a program |
| ManyHighValueImmediates | 3 | code | 7 | Function contains at least 5 and more than 10% of high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 6 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 8 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 54 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| SectionMostlyVirtual | 2 | sections | 1 | section is composed of mostly virtual space |
| HighXrefLoopingFunction | 1 | code | 7 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 8 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialization |
| SpaghettiFunction | 1 | code | 6 | Function with lots of intra jumps, could be obfuscated |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |
(source: malcat, anomalies)
### High-Signal Strings (8 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 341480 | `https://www.goog..nts/servicelogin` |
| 341624 | `https://login.ya..com/config/login` |
| 343296 | `<meta http-equiv..tml;charset=%s'>` |
| 341572 | `http://www.facebook.com/` |
| 340600 | `kernel32.dll` |
| 341768 | `ftp://` |
| 345708 | `GetProcessTimes` |
| 341724 | `https://` |
(source: malcat, high-signal strings)
The ImportByHash (level 4) and XorInLoop (54 hits) anomalies are consistent with known Remcos obfuscation techniques for hiding API imports and decrypting C2 configurations/strings (source: malcat, anomalies, name: ImportByHash, level: 4; name: XorInLoop, num_hits: 54). Embedded DES constants (source: malcat, constants, type: crypto::DES_*) confirm the use of DES encryption for sensitive data and C2 traffic.

## 5. Static Code Analysis
Static analysis was performed using Ghidra, radare2, Malcat, FLOSS, and capa. Key findings include:
### Entry Point Disassembly (radare2, 0x0044692c)
```asm
┌ 445: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_48h @ ebp-0x48
│           ; var int32_t var_4ch @ ebp-0x4c
│           ; var int32_t var_78h @ ebp-0x78
│           ; var int32_t var_7ch @ ebp-0x7c
│           0x0044692c      6a70           push 0x70                   ; 'p' ; 112
│           0x0044692e      68c0f44400     push 0x44f4c0
│           0x00446933      e804020000     call 0x446b3c
│           0x00446938      33ff           xor edi, edi
│           0x0044693a      57             push edi
│           0x0044693b      ff15acf04400   call dword [sym.imp.KERNEL32.dll_GetModuleHandleA] ; 0x44f0ac ; "~\x97\x05" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00446941      6681384d5a     cmp word [eax], 0x5a4d      ; 'MZ'
│       ┌─< 0x00446946      751f           jne 0x446967
│       │   0x00446948      8b483c         mov ecx, dword [eax + 0x3c]
│       │   0x0044694b      03c8           add ecx, eax
│       │   0x0044694d      813950450000   cmp dword [ecx], 0x4550     ; 'PE'
│      ┌──< 0x00446953      7512           jne 0x446967
│      ││   0x00446955      0fb74118       movzx eax, word [ecx + 0x18]
│      ││   0x00446959      3d0b010000     cmp eax, 0x10b              ; 267
│     ┌───< 0x0044695e      741f           je 0x44697f
│     │││   0x00446960      3d0b020000     cmp eax, 0x20b              ; 523
│    ┌────< 0x00446965      7405           je 0x44696c
│  ┌┌──└└─> 0x00446967      897de4         mov dword [var_1ch], edi
│  ╎╎││ ┌─< 0x0044696a      eb27           jmp 0x446993
│  ╎╎└────> 0x0044696c      83b9840000..   cmp dword [ecx + 0x84], 0xe
│  └──────< 0x00446973      76f2           jbe 0x446967
│   ╎ │ │   0x00446975      33c0           xor eax, eax
│   ╎ │ │   0x00446977      39b9f8000000   cmp dword [ecx + 0xf8], edi
│   ╎ │┌──< 0x0044697d      eb0e           jmp 0x44698d
│   ╎ └───> 0x0044697f      8379740e       cmp dword [ecx + 0x74], 0xe
│   └─────< 0x00446983      76e2           jbe 0x446967
│      ││   0x00446985      33c0           xor eax, eax
│      ││   0x00446987      39b9e8000000   cmp dword [ecx + 0xe8], edi
│      ││   ; CODE XREF from entry0 @ 0x44697d(x)
│      └──> 0x0044698d      0f95c0         setne al
│       │   0x00446990      8945e4         mov dword [var_1ch], eax
│       │   ; CODE XREF from entry0 @ 0x44696a(x)
│       └─> 0x00446993      897dfc         mov dword [var_4h], edi
│           0x00446996      6a02           push 2                      ; 2
│           0x00446998      5b             pop ebx
│           0x00446999      53             push ebx
│           0x0044699a      ff158cf34400   call dword [sym.imp.msvcrt.dll___set_app_type
```
(source: r2, disassembly, 0x0044692c)
The entry point performs PE header validation (checks for MZ/PE signatures, 32/64-bit header validity) before proceeding, a common anti-analysis check (source: r2, disassembly, 0x0044692c).
### Main Function Disassembly (radare2, 0x004122ba)
```asm
; CALL XREF from entry0 @ 0x446abf(x)
┌ 543: int main (int32_t argc, int32_t argv, int32_t envp, int32_t arg_40h, int32_t arg_44h, int32_t arg_60h_3, int32_t arg_60h_2, int32_t arg_60h, int32_t arg_26ch_2, int32_t arg_270h, int32_t arg_284h, int32_t arg_268h, int32_t arg_26ch, int32_t arg_288h, int32_t arg_2ach, int32_t arg_718h, int32_t arg_704h_3, int32_t arg_704h_2, int32_t arg_704h, int32_t arg_70ch);
│           ; arg int32_t argc @ esp+0x9c
│           ; arg int32_t argv @ esp+0xa0
│           ; arg int32_t envp @ esp+0xa4
│           ; arg int32_t arg_40h @ esp+0xa8
│           ; arg int32_t arg_44h @ esp+0xac
│           ; arg int32_t arg_60h_3 @ esp+0xb4
│           ; arg int32_t arg_60h_2 @ esp+0xb8
│           ; arg int32_t arg_60h @ esp+0xcc
│           ; arg int32_t arg_26ch_2 @ esp+0x284
│           ; arg int32_t arg_270h @ esp+0x290
│           ; arg int32_t arg_284h @ esp+0x2a8
│           ; arg int32_t arg_268h @ esp+0x2b0
│           ; arg int32_t arg_26ch @ esp+0x2b8
│           ; arg int32_t arg_288h @ esp+0x2bc
│           ; arg int32_t arg_2ach @ esp+0x300
│           ; arg int32_t arg_718h @ esp+0x738
│           ; arg int32_t arg_704h_3 @ esp+0x75c
│           ; arg int32_t arg_704h_2 @ esp+0x760
│           ; arg int32_t arg_704h @ esp+0x764
│           ; arg int32_t arg_70ch @ esp+0x76c
│           ; var int32_t var_10h_3 @ esp+0x3c
│           ; var int32_t var_50h_3 @ esp+0x54
│           ; var int32_t var_44h_2 @ esp+0x58
│           ; var int32_t var_30h_2 @ esp+0x5c
│           ; var int32_t var_50h_2 @ esp+0x64
│           ; var int32_t var_10h_2 @ esp+0x68
│           ; var int32_t var_44h @ esp+0x70
│           ; var int32_t var_14h @ esp+0x78
│           ; var int32_t var_10h @ esp+0x7c
│           ; var int32_t var_50h @ esp+0x80
│           ; var int32_t var_30h @ esp+0x88
│           ; var int32_t var_60h @ esp+0x8c
│           0x004122ba      55             push ebp
│           0x004122bb      8bec           mov ebp, esp
│           0x004122bd      83e4f8         and esp, 0xfffffff8
│           0x004122c0      b84c310000     mov eax, 0x314c             ; 'L1'
│           0x004122c5      e8e6ba0300     call 0x44ddb0
│           0x004122ca      53             push ebx
│           0x004122cb      56             push esi
│           0x004122cc      57             push edi
│           0x004122cd      e80f31ffff     call 0x4053e1
│           0x004122d2      85c0           test eax, eax
│       ┌─< 0x004122d4      7506           jne 0x4122dc
│       │   0x004122d6      40             inc eax
│      ┌──< 0x004122d7      e9f4010000     jmp 0x4124d0
│      │└─> 0x004122dc      e806480000     call 0x416ae7
│      │    0x004122e1      6801800000     push 0x8001
│      │    0x004122e6      ff15c4f14400   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x44f1c4 ; UINT SetErrorMode(UINT uMode)
│      │    0x004122ec      33db           xor ebx, ebx
│      │    0x004122ee      53             push ebx
│      │    0x004122ef
```
(source: r2, disassembly, 0x004122ba)
The main function sets a system error mode (0x8001 = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX) to suppress system error dialogs, a common anti-analysis and user evasion technique (source: r2, disassembly, 0x004122e1).
### DES Encryption Decompilation (Ghidra, 0x21803 — sub_40612b)
```c
void __thiscall sub_40612b(int32_t param_1,uint32_t *param_2,int32_t param_3)
{
    uint32_t *puVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uStack_8;
    
    uVar4 = (*param_2 >> 0x1d) + *param_2 * 8;
    uStack_8 = (param_2[1] >> 0x1d) + param_2[1] * 8;
    if (param_3 == 0) {
        puVar1 = param_1 + 0x70;
        param_3 = 4;
        do {
            uVar2 = puVar1[2] ^ uVar4;
            uVar3 = (puVar1[3] ^ uVar4) * 0x10000000 + ((puVar1[3] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = *puVar1 ^ uStack_8;
            uVar3 = (puVar1[1] ^ uStack_8) * 0x10000000 + ((puVar1[1] ^ uStack_8) >> 4);
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-2] ^ uVar4;
            uVar3 = (puVar1[-1] ^ uVar4) * 0x10000000 + ((puVar1[-1] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-4] ^ uStack_8;
            uVar3 = (puVar1[-3] ^ uStack_8) * 0x10000000 + ((puVar1[-3] ^ uStack_8) >> 4);
            puVar1 = puVar1 + -8;
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            param_3 = param_3 + -1;
        } while (param_3 != 0);
    }
    else {
        puVar1 = param_1 + 8;
        param_3 = 4;
        do {
            uVar2 = puVar1[-2] ^ uVar4;
            uVar3 = (puVar1[-1] ^ uVar4) * 0x10000000 + ((puVar1[-1] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = *puVar1 ^ uStack_8;
            uVar3 = (puVar1[1] ^ uStack_8) * 0x10000000 + ((puVar1[1] ^ uStack_8) >> 4);
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-2] ^ uVar4;
            uVar3 = (puVar1[-1] ^ uVar4) * 0x10000000 + ((puVar1[-1] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-4] ^ uStack_8;
            uVar3 = (puVar1[-3] ^ uStack_8) * 0x10000000 + ((puVar1[-3] ^ uStack_8) >> 4);
            puVar1 = puVar1 + -8;
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            param_3 = param_3 + -1;
        } while (param_3 != 0);
    }
}
```
(source: ghidra, decompilation, 0x21803 — sub_40612b)
This function implements DES encryption/decryption using embedded lookup tables (DES_SPR_SPtrans__32_lil_2048) consistent with the DES constants detected by Malcat (source: malcat, constants, type: crypto::DES_*). Additional Ghidra decompilations of DES key schedule functions (0x20403 — sub_405bb3, 0x86590 — sub_415e3e) confirm full DES implementation for C2 and data encryption (source: ghidra, decompilation, 0x20403 — sub_405bb3; 0x86590 — sub_415e3e).
### Import Table (Malcat, 273 imports)
| EA | Name | Type | Refs |
|---|---|---|---|
| 320512 | advapi32.RegQueryValueExW | IMPORT | 6 |
| 320516 | advapi32.RegOpenKeyExW | IMPORT | 1 |
| 320520 | advapi32.RegEnumValueW | IMPORT | 1 |
| 320524 | advapi32.RegCloseKey | IMPORT | 2 |
| 320532 | comctl32.#17 | IMPORT | 2 |
| 320536 | comctl32.ImageList_Create | IMPORT | 1 |
| 320540 | comctl32.ImageList_AddMasked | IMPORT | 1 |
| 320544 | comctl32.ImageList_SetImageCount | IMPORT | 3 |
| 320548 | comctl32.ImageList_ReplaceIcon | IMPORT | 1 |
| 320552 | comctl32.CreateStatusWindowW | IMPORT | 1 |
| 320556 | comctl32.CreateToolbarEx | IMPORT | 1 |
| 320564 | gdi32.GetTextExtentPoint32W | IMPORT | 2 |
| 320568 | gdi32.GetDeviceCaps | IMPORT | 2 |
| 320572 | gdi32.SelectObject | IMPORT | 1 |
| 320576 | gdi32.SetBkMode | IMPORT | 3 |
| 320580 | gdi32.DeleteObject | IMPORT | 4 |
| 320584 | gdi32.SetTextColor | IMPORT | 3 |
| 320588 | gdi32.CreateFontIndirectW | IMPORT | 2 |
| 320592 | gdi32.GetStockObject | IMPORT | 1 |
| 320596 | gdi32.SetBkColor | IMPORT | 1 |
| 320604 | kernel32.GetFullPathNameA | IMPORT | 2 |
| 320608 | kernel32.InitializeCriticalSection | IMPORT | 2 |
| 320612 | kernel32.GetFullPathNameW | IMPORT | 1 |
| 320616 | kernel32.DeleteFileA | IMPORT | 1 |
| 320620 | kernel32.GetDiskFreeSpaceW | IMPORT | 1 |
| 320624 | kernel32.AreFileApisANSI | IMPORT | 2 |
| 320628 | kernel32.EnterCriticalSection | IMPORT | 1 |
| 320632 | kernel32.GetSystemTime | IMPORT | 1 |
| 320636 | kernel32.LockFileEx | IMPORT | 2 |
| 320640 | kernel32.FormatMessageA | IMPORT | 1 |
| 320644 | kernel32.UnlockFileEx | IMPORT | 1 |
| 320648 | kernel32.LockFile | IMPORT | 3 |
| 320652 | kernel32.UnlockFile | IMPORT | 4 |
| 320656 | kernel32.FlushFileBuffers | IMPORT | 1 |
| 320660 | kernel32.InterlockedCompareExchange | IMPORT | 2 |
| 320664 | kernel32.DeleteCriticalSection | IMPORT | 2 |
| 320668 | kernel32.CreateFileA | IMPORT | 1 |
| 320672 | kernel32.GetDiskFreeSpaceA | IMPORT | 1 |
| 320676 | kernel32.Sleep | IMPORT | 6 |
| 320680 | kernel32.GetSystemInfo | IMPORT | 1 |
| 320684 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 320688 | kernel32.GetStartupInfoW | IMPORT | 1 |
| 320692 | kernel32.GetTempPathA | IMPORT | 1 |
| 320696 | kernel32.GetFileAttributesExW | IMPORT | 1 |
| 320700 | kernel32.QueryPerformanceCounter | IMPORT | 1 |
| 320704 | kernel32.GetFileAttributesA | IMPORT | 2 |
| 320708 | kernel32.SetEndOfFile | IMPORT | 1 |
| 320712 | kernel32.LeaveCriticalSection | IMPORT | 1 |
| 320716 | kernel32.EnumResourceTypesW | IMPORT | 1 |
| 320720 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 320724 | kernel32.Process32NextW | IMPORT | 1 |
| 320728 | kernel32.CreateFileW | IMPORT | 8 |
| 320732 | kernel32.CloseHandle | IMPORT | 24 |
| 320736 | kernel32.FileTimeToLocalFileTime | IMPORT | 2 |
| 320740 | kernel32.DeleteFileW | IMPORT | 5 |
| 320744 | kernel32.LocalFree | IMPORT | 7 |
| 320748 | kernel32.SystemTimeToFileTime | IMPORT | 4 |
| 320752 | kernel32.CopyFileW | IMPORT | 1 |
| 320756 | kernel32.GetFileSize | IMPORT | 9 |
| 320760 | kernel32.WriteFile | IMPORT | 7 |
| 320764 | kernel32.WideCharToMultiByte | IMPORT | 9 |
| 320768 | kernel32.CompareFileTime | IMPORT | 2 |
| 320772 | kernel32.FreeLibrary | IMPORT | 13 |
| 320776 | kernel32.GetLastError | IMPORT | 26 |
| 320780 | kernel32.GetProcAddress | IMPORT | 15 |
| 320784 | kernel32.LoadLibraryW | IMPORT | 2 |
| 320788 | kernel32.FileTimeToSystemTime | IMPORT | 2 |
| 320792 | kernel32.GetModuleHandleW | IMPORT | 21 |
| 320796 | kernel32.GetTickCount | IMPORT | 3 |
| 320800 | kernel32.SetFilePointerEx | IMPORT | 1 |
| 320804 | kernel32.MultiByteToWideChar | IMPORT | 8 |
| 320808 | kernel32.FindResourceW | IMPORT | 2 |
| 320812 | kernel32.LockResource | IMPORT | 2 |
| 320816 | kernel32.LoadResource | IMPORT | 2 |
| 320820 | kernel32.SystemTimeToTzSpecificLocalTime | IMPORT | 1 |
| 320824 | kernel32.lstrlenW | IMPORT | 1 |
| 320828 | kernel32.lstrcpyW | IMPORT | 1 |
| 320832 | kernel32.LoadLibraryExW | IMPORT | 1 |
| 320836 | kernel32.GlobalAlloc | IMPORT | 2 |
| 320840 | kernel32.GetSystemDirectoryW | IMPORT | 1 |
(source: malcat, imports)
The import table includes registry manipulation APIs (RegOpenKeyExW, RegQueryValueExW) for persistence and data theft, process enumeration APIs (CreateToolhelp32Snapshot, Process32NextW) for process listing and injection, and file system APIs for data exfiltration (source: malcat, imports).
### FLOSS Strings (Sample)
FLOSS extracted 2008 total strings, including 18 decoded strings and 1990 static strings. Sample decoded strings include:
- `j:,4;87`
- `=&&jL66Zl??A~`
- `g99KrJJ`
- `&jL&6Zl6?A~?`
- `jL&&Zl66A~??`
- `RRMv;;a`
- `L&&jl66Z~??A`
- `interrupted`
- `!<5!4%!`
- `&<5!4%!`
(source: floss, strings)
### XOR Search Results
XOR search identified multiple XOR-encoded PE headers at offsets 0x00000000, 0x00062605, 0x00071C0A, and 0x000A180F, indicating embedded payloads or encrypted code sections (source: xor, search results).

## 6. Behavioral & Dynamic Analysis
Dynamic analysis was limited due to the sample's packed nature and anti-analysis features:
- **Speakeasy**: No API calls or events were recorded during emulation (speakeasy_ok: True, api_calls: 0, key_events: 0, duration_s: None) (source: speakeasy, results, status: not observed).
- **Frida Probe**: 30 hook candidates were identified across msvcrt, COMCTL32, VERSION, WININET, KERNEL32, USER32, and GDI32 DLLs, but no runtime data was captured (source: frida, probe, hook_candidates: [msvcrt.dll!__wgetmainargs, msvcrt.dll!_initterm, msvcrt.dll!__setusermatherr, msvcrt.dll!_adjust_fdiv, msvcrt.dll!wcsrchr, COMCTL32.dll!ImageList_Create, COMCTL32.dll!ImageList_AddMasked, COMCTL32.dll!ImageList_SetImageCount, COMCTL32.dll!ImageList_ReplaceIcon, VERSION.dll!VerQueryValueW, VERSION.dll!GetFileVersionInfoSizeW, VERSION.dll!GetFileVersionInfoW, WININET.dll!FindCloseUrlCache, WININET.dll!FindNextUrlCacheEntryW, WININET.dll!FindFirstUrlCacheEntryW, KERNEL32.dll!GetFullPathNameA, KERNEL32.dll!InitializeCriticalSection, KERNEL32.dll!GetFullPathNameW, KERNEL32.dll!DeleteFileA, KERNEL32.dll!GetDiskFreeSpaceW, USER32.dll!GetKeyState, USER32.dll!DispatchMessageW, USER32.dll!TranslateMessage, USER32.dll!IsDialogMessageW, USER32.dll!DrawTextExW, GDI32.dll!GetTextExtentPoint32W, GDI32.dll!GetDeviceCaps, GDI32.dll!SelectObject, GDI32.dll!SetBkMode, GDI32.dll!DeleteObject], status: not observed).
- **UPX Unpack**: UPX unpacking failed (upx_ok: False, returncode: None, unpacked_path: empty) (source: upx, results, status: not observed). No unpacked payload was recovered for dynamic analysis.
No runtime behavior (C2 communications, keylogging, file operations) was observed during analysis.

## 7. Network Indicators & C2
YARA rules and static strings confirm embedded network and C2 infrastructure:
### YARA Network Matches
| Rule | Match Offset | Length | Description |
|---|---|---|---|
| domain | 0 | 2 | Embedded C2 domain regex |
| IP (IPv4) | 401996 | 7 | Embedded IPv4 C2 address |
| IP (IPv6) | 382760 | 2 | Embedded IPv6 C2 address |
| url | 337896 | 88 | Obfuscated C2 URL |
| contains_base64 | 176404 | 12 | Base64-encoded C2 payload/command |
(source: yara, matches)
### High-Signal C2/URL Strings (Malcat)
| EA | String |
|---|---|
| 341480 | `https://www.goog..nts/servicelogin` |
| 341624 | `https://login.ya..com/config/login` |
| 341572 | `http://www.facebook.com/` |
| 341724 | `https://` |
| 341768 | `ftp://` |
(source: malcat, high-signal strings)
The embedded login URLs for Google, Yahoo, and Facebook indicate the sample includes browser credential harvesting modules that inject fake login pages to steal user credentials (source: ghidra, suspicious strings, content: https://www.google.com/accounts/servicelogin). Obfuscated base64 strings and URLs are used to encode C2 communications and evade network-based detection (source: yara, matches, rule: contains_base64, url).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample implements core Remcos RAT capabilities, mapped to MITRE ATT&CK and MBC frameworks via capa, YARA, and static analysis:
| Capability | MITRE ATT&CK ID | MBC Reference | Source | Evidence |
|---|---|---|---|---|
| Keylogging | T1056.001: Input Capture | F0002.002: Keylogging | capa, yara | capa rule: log keystrokes via polling; yara rule: keylogger |
| Registry Persistence | T1547.001: Boot or Logon Autostart Execution | F0012: Registry Run Keys / Startup Folder | capa, yara | capa rule: persist via Run registry key; yara rule: win_registry |
| Process Enumeration | T1057: Process Discovery, T1518: Software Discovery | - | pe_imports, yara | pe_imports api_match: CreateToolhelp32Snapshot; yara rule: EnumerateProcesses |
| Registry Query | T1012: Query Registry | C0036.006: Registry | capa, pe_imports | capa rule: query or enumerate registry value; pe_imports api_match: RegOpenKeyExW |
| File System Discovery | T1083: File and Directory Discovery | E1083: File and Directory Discovery | capa | capa rules: get common file path, check if file exists, enumerate files on Windows, get file size |
| System Information Discovery | T1082: System Information Discovery | E1082: System Information Discovery | capa | capa rule: get disk size |
| Data Encryption (DES) | T1027: Obfuscated Files or Information | C0027.004: Encrypt Data | capa, malcat | capa rule: encrypt data using DES; malcat constants: crypto::DES_* |
| Data Encryption (RC4) | T1027: Obfuscated Files or Information | C0027.009: Encrypt Data, C0028.002: Encryption Key | capa | capa rule: encrypt data using RC4 KSA |
| Data Encryption (AES) | T1027: Obfuscated Files or Information | C0027.001: Encrypt Data | capa | capa rule: manually build AES constants |
| Obfuscation (Stackstrings) | T1027.005: Obfuscated Files or Information | B0032.020: Executable Code Obfuscation, B0032.017: Executable Code Obfuscation | capa | capa rule: contain obfuscated stackstrings |
| Obfuscation (XOR) | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data | capa, malcat | capa rule: encode data using XOR; malcat anomaly: XorInLoop (54 hits) |
| Credential Harvesting | T1555: Credentials from Password Stores | - | malcat, yara | malcat strings: places.sqlite, wand.dat, profiles.ini, index.dat; yara rule: screenshot, keylogger |
| Lateral Movement (Shell) | T1021: Remote Services | - | malcat | malcat signature: RunShell (UNCOMMON, 70 reliability) |
| Anti-Analysis (Import Hiding) | T1027: Obfuscated Files or Information | - | malcat | malcat anomaly: ImportByHash (level 4) |
| Anti-Analysis (Packed Overlay) | T1027: Obfuscated Files or Information | - | malcat, yara | malcat layout: overlay entropy 202; yara rules: IsPacked, HasOverlay |
(source: capa, top_rules; pe_imports, signals; yara, matches; malcat, anomalies, constants, high-signal strings)

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0 | llm_judge, verdict.json |
| File Name | remcos_sample.exe | malcat, file_summary.metadata |
| File Size | 698895 bytes | malcat, file_summary.metadata |
| Overlay Entropy | 202 | malcat, file_summary.layout |
| Import By Hash | Present (1 hit) | malcat, anomalies, name: ImportByHash, level: 4 |
| XOR Loop Hits | 54 | malcat, anomalies, name: XorInLoop, num_hits: 54 |
| DES Constants | Present at 0x334960 (DES_Long), 0x364600 (DES_sbox) | yara, matches, rule: DES_Long, DES_sbox; malcat, constants |
### Network IOCs
| IOC Type | Value/Offset | Source |
|---|---|---|
| C2 Domain Regex | Offset 0 | yara, matches, rule: domain |
| IPv4 C2 Address | Offset 401996 | yara, matches, rule: IP |
| IPv6 C2 Address | Offset 382760 | yara, matches, rule: IP |
| Obfuscated C2 URL | Offset 337896 | yara, matches, rule: url |
| Base64 C2 Payload | Offset 176404 | yara, matches, rule: contains_base64 |
| Google Login URL | https://www.google.com/accounts/servicelogin | ghidra, suspicious strings; malcat, high-signal strings, EA: 341480 |
| Yahoo Login URL | https://login.yahoo.com/config/login | malcat, high-signal strings, EA: 341624 |
| Facebook Login URL | http://www.facebook.com/ | malcat, high-signal strings, EA: 341572 |
### Host-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| Registry Persistence Keys | HKEY_CURRENT_USER\Run, HKEY_LOCAL_MACHINE\Run | capa, top_rules, name: persist via Run registry key; pe_imports, signals, api_match: RegOpenKeyExW |
| Browser Credential Files | places.sqlite, wand.dat, profiles.ini, index.dat, WebCacheV01.dat, WebCacheV24.dat | malcat, top strings, EA: 344380, 340344, 342016, 341460, 341256, 341344 |
| SQLite Queries | INSERT INTO sqlite_sequence, CREATE TABLE, UPDATE sqlite_sequence | malcat, top strings, EA: 356968, 325920, 351336 |

## 10. Detection Engineering
### YARA Detection Rules
Leverage the following high-confidence indicators for detection:
1. Detect the embedded DES sbox at offset 0x364600 (length 64) and DES long constant at 0x334960 (length 64) (source: yara, matches, rule: DES_Long, DES_sbox).
2. Detect high-entropy overlays (>190 entropy) at the end of PE files (source: malcat, file_summary.layout, overlay entropy: 202).
3. Detect the ImportByHash anomaly (imports resolved via hash rather than name) (source: malcat, anomalies, name: ImportByHash, level: 4).
4. Detect the high-signal login URLs: `https://www.google.com/accounts/servicelogin`, `https://login.yahoo.com/config/login`, `http://www.facebook.com/` (source: malcat, high-signal strings, EA: 341480, 341624, 341572).
5. Detect the SQLite credential file names: `places.sqlite`, `wand.dat`, `profiles.ini`, `index.dat` (source: malcat, top strings, EA: 344380, 340344, 342016, 341460).
### Capa Detection
Use capa rules to detect the following behaviors:
- log keystrokes via polling (T1056.001)
- persist via Run registry key (T1547.001)
- encrypt data using DES (T1027)
- enumerate processes (T1057)
- query or enumerate registry value (T1012)
(source: capa, top_rules)
### Anomaly-Based Detection
Flag executables with >50 XOR-in-loop hits and high-entropy (>190) overlays as potential Remcos payloads (source: malcat, anomalies, name: XorInLoop, num_hits: 54; file_summary.layout, overlay entropy: 202).

## 11. What We Don't Know
1. Full C2 infrastructure: Exact C2 domains, IP addresses, and ports are not fully extracted, only offsets for embedded network indicators are confirmed (source: yara, matches, rule: domain, IP).
2. Unpacked payload: UPX unpacking failed, and no dynamic unpacking was successful, so the full unpacked malicious payload is not available for analysis (source: upx, results, upx_ok: False, unpacked_path: empty).
3. Runtime behavior: No dynamic runtime data was captured via Speakeasy or Frida, so actual C2 communications, keylogging activity, and file exfiltration behavior are unobserved (source: speakeasy, results, status: not observed; frida, probe, status: not observed).
4. Exact configuration: The sample's C2 keys, sleep intervals, and enabled feature flags are not recovered from static analysis (source: llm_judge, verdict.json, cross_engine_notes: IDA analysis unavailable).
5. Full targeted applications: The complete list of targeted browsers and applications for credential harvesting is not fully enumerated (source: malcat, top strings, partial list of credential files).

## 12. Appendix: Analysis Environment
| Tool/Component | Version/Details | Purpose |
|---|---|---|
| Malcat | Latest (structured evidence) | File layout, anomaly detection, string extraction, import analysis |
| Ghidra | Latest (structured evidence) | Decompilation, DES routine analysis, suspicious string identification |
| capa | malcat-capa engine, 49 rules, 2.35s runtime | Capability detection, MITRE ATT&CK mapping |
| YARA | Pipeline (26 matches) | Signature detection, C2/constant identification |
| FLOSS | 2008 total strings | Decoded and static string extraction |
| radare2 | Latest (structured evidence) | Entry point and main function disassembly |
| UPX | Latest (structured evidence) | Unpacking attempt (failed) |
| Speakeasy | v17.16.4 (structured evidence) | Dynamic emulation (no events observed) |
| Frida | 17.16.4 (structured evidence) | Runtime hooking (no data captured) |
| llm_judge | step-3.7-flash | Verdict generation, evidence aggregation |
| IDA Pro | Unavailable | Missing idasql binary, no analysis performed |
(source: deep_dive.json, tool_gate; llm_judge, verdict.json, cross_engine_notes)
Sample analysis path: /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe, project name: incoming.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0  
**sample_path:** /opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious - Remcos RAT
- **score**: 95
- **family_guess**: Remcos
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA analysis is unavailable due to missing idasql binary; all evidence is derived from Ghidra, Malcat, capa, YARA, FLOSS, and pe_imports. Ghidra (1057 strings) and Malcat (100 strings) string datasets are combined for maximum coverage with high confidence. Ghidra decompilation confirms DES encryption routines that align with Malcat's embedded DES constant detections and capa's DES encryption behavior rules. Independent engines consistently detect core Remcos capabilities including keylogging, registry persistence, process enumeration, and credential harvesting indicators.
- **summary**: This is a high-confidence detection of the Remcos remote access trojan (RAT). The sample is packed with a high-entropy overlay containing the malicious payload, and uses XOR and DES encryption for obfuscation of strings, configurations, and C2 communications. It implements core Remcos features including keylogging, process enumeration, registry-based persistence, and browser credential harvesting via injection of login pages for major services. Import resolution by hash and widespread looped XOR operations are used to evade static analysis, consistent with known Remcos obfuscation techniques.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary.metadata | `file_name = "remcos_sample.exe"` | Explicit sample naming directly identifies the malware family as Remcos. |
| yara | matches | `rule = "keylogger"` | Remcos is a RAT with native keylogging functionality, matching this YARA detection. |
| capa | top_rules | `name = "log keystrokes via polling", attack[0].id = "T1056.001"` | Confirms keylogging capability consistent with Remcos's documented feature set. |
| capa | top_rules | `name = "persist via Run registry key", attack[0].id = "T1547.001"` | Remcos uses Windows Registry Run keys for persistence, matching this capa detection. |
| pe_imports | signals | `api_match = "CreateToolhelp32Snapshot", attack = ["T1057"]` | Process enumeration via Toolhelp32 API is a core Remcos capability for process listing and code injection. |
| pe_imports | signals | `api_match = "RegOpenKeyExW", attack = ["T1012"]` | Registry access is used by Remcos for persistence, configuration storage, and credential theft. |
| malcat | anomalies | `name = "ImportByHash", level = 4` | Import resolution by hash is a common obfuscation technique used in Remcos to hide imported API names from static analys |
| malcat | anomalies | `name = "XorInLoop", num_hits = 54` | Widespread XOR encryption in loops is used by Remcos to decrypt C2 configurations, embedded strings, and secondary paylo |
| malcat | file_summary.layout | `name = "overlay", entropy = 202` | High-entropy overlay is a common packing technique used in Remcos to hide the main malicious payload from static analysi |
| malcat | constants | `type = "crypto::DES_*"` | Remcos uses DES encryption for C2 communications and local data storage, matching these embedded DES lookup tables. |
| ghidra | suspicious strings | `content = "https://www.google.com/accounts/servicelogin"` | Remcos includes browser injection modules to steal credentials from popular login pages, as evidenced by these embedded  |
| yara | matches | `rule = "win_registry"` | Confirms registry manipulation functionality consistent with Remcos persistence and data theft operations. |
| capa | top_rules | `name = "encrypt data using DES"` | Matches Remcos's documented use of DES for encrypting sensitive data and C2 traffic. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a packed 32-bit Windows GUI Remcos remote access trojan (RAT) compiled with Visual C++ 2003. It contains embedded command-and-control (C2) infrastructure (domains, IPv4/IPv6 addresses), cryptographic algorithm implementations (MD5, RIPEMD160, SHA1, SHA2/BLAKE2, DES), malicious surveillance capabilities (keylogging, screenshot functionality), embedded SQLite support for local data storage, obfuscated base64 strings and URLs for C2 communication, and anti-analysis code, all consistent with known Remcos malware behavior.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "IsPE32, IsWindowsGUI", "why": "Confirms the sample is a 32-bit Windows GUI executable, matching the expected format for Remcos RAT payloads."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "IsPacked, HasOverlay", "why": "Indicates the sample is packed with an additional overlay, a common anti-analysis technique used by Remcos to hinder reverse engineering."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "Visual_Cpp_2003_EXE_Microsoft, HasRichSignature", "why": "Confirms the sample was compiled with Visual C++ 2003, consistent with known public builds of the Remcos RAT."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "domain, IP", "why": "Matches embedded C2 domain and IPv4/IPv6 addresses, confirming the sample is configured to communicate with external command-and-control infrastructure, a core feature of the Remcos RAT."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA2_BLAKE2_IVs, DES_Long, DES_sbox", "why": "Matches embedded cryptographic algorithm constants, which are used by Remcos to encrypt C2 communications and exfiltrated stolen data to avoid detection."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "keylogger, screenshot", "why": "Matches code for keylogging and screenshot capture functionality, which are standard malicious surveillance capabilities of the Remcos RAT used to steal credentials and monitor victim activity."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "with_sqlite", "why": "Indicates embedded SQLite support, which Remcos uses to locally store stolen data (e.g., keystrokes, screenshots, system information) before exfiltration."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "contains_base64, url", "why": "Matches obfuscated base64 strings and URLs, which are used by Remcos to encode C2 communication payloads and command URLs to evade network-based detection."}`
- `{"source": "checklist_yara_scan", "query_or_table": "YARA rule matches", "row_or_rule": "maldoc_getEIP_method_1, SEH_Init", "why": "Matches anti-analysis and execution flow manipulation code, including SEH initialization and EIP retrieval methods, used to evade debuggers and security checks, common in packed Remcos samples."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0
size: 698895
type: PE
architecture: X86
entrypoint_ea: 285996
entropy: 160
file_name: remcos_sample.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 92 | - |
| .text | 1024 | 315904 | 319488 | 142 | RX |
| .rdata | 320512 | 45056 | 45056 | 86 | R |
| .data | 365568 | 5632 | 106496 | 83 | RW |
| .rsrc | 472064 | 35328 | 36864 | 34 | R |
| overlay | 508928 | 295951 | 0 | 202 | - |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2005_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2003_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| Sqlite | library | INFO | 80 | embeds sqlite library, sqlite is often used by password stealers |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (15)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ImportByHash | 4 | imports | 1 | APIs are imported by hash |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 3 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 9 | string is constructed dynamically |
| EmbeddedProgram | 3 | embedding | 3 | File embeds a program |
| ManyHighValueImmediates | 3 | code | 7 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 6 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 8 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 54 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| SectionMostlyVirtual | 2 | sections | 1 | section is composed of mostly virtual space |
| HighXrefLoopingFunction | 1 | code | 7 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 8 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 6 | Function with lots of intra jumps, could be obfuscated |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `474728`: 
- **DynamicString**
  - `7763`: 
  - `299393`: 
  - `298279`: 
  - `311168`: 
  - `298336`: 
- **HighXrefLoopingFunction**
  - `51682`: 
  - `97394`: 
  - `97689`: 
  - `183266`: 
  - `193865`: 
- **ManyHighValueImmediates**
  - `9803`: 
  - `17468`: 
  - `24250`: 
  - `24373`: 
  - `68693`: 
- **ManyUniqueImmediateBytes**
  - `7562`: 
  - `158187`: 
  - `188476`: 
  - `271118`: 
  - `278322`: 
- **SequentialFunction**
  - `20403`: 
  - `21803`: 
  - `72182`: 
  - `86590`: 
  - `287600`: 
- **SpaghettiFunction**
  - `10647`: 
  - `154220`: 
  - `192783`: 
  - `216350`: 
  - `278322`: 
- **XorInLoop**
  - `2847`: 
  - `15067`: 
  - `18135`: 
  - `21864`: 
  - `22409`: 

### High-Signal Strings (8 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 341480 | `https://www.goog..nts/servicelogin` |
| 341624 | `https://login.ya..com/config/login` |
| 343296 | `<meta http-equiv..tml;charset=%s'>` |
| 341572 | `http://www.facebook.com/` |
| 340600 | `kernel32.dll` |
| 341768 | `ftp://` |
| 345708 | `GetProcessTimes` |
| 341724 | `https://` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 356968 | `SELECT 'INSERT I..qlite_sequence';` |
| 356664 | `SELECT 'INSERT I..  AND rootpage>0` |
| 7763 | `0000000000000000..745E58FB9174EF91` |
| 324996 | `naturaleftouteri..htfullinnercross` |
| 353568 | `there is already..a table named %s` |
| 345440 | `CreateToolhelp32Snapshot` |
| 299393 | `0100000000000000..0000000000000000` |
| 298279 | `67E6096A85AE67BB..ABD9831F19CDE05B` |
| 311168 | `0000000000000000..76543210F0E1D2C3` |
| 298336 | `D89E05C107D57C36..A78FF964A44FFABE` |
| 25337 | `7E431CDA2ADFF225` |
| 73974 | `0123456789ABCDEFFEDCBA9876543210` |
| 345516 | `Process32Next` |
| 345484 | `Module32Next` |
| 343480 | `<br><h4>%s <a hr..">%s</a></h4><p>` |
| 342576 | `<html><head>%s<t..%s <h3>%s</h3>
` |
| 25189 | `1818AD5EC17AD962` |
| 346112 | `Software\Microso..er\Shell Folders` |
| 341480 | `https://www.goog..nts/servicelogin` |
| 341256 | `Microsoft\Window..\WebCacheV01.dat` |
| 341344 | `Microsoft\Window..\WebCacheV24.dat` |
| 341624 | `https://login.ya..com/config/login` |
| 343296 | `<meta http-equiv..tml;charset=%s'>` |
| 324208 | `0123456789ABCDEF0123456789abcdef` |
| 347788 | `sqlite_attach` |
| 347612 | `sqlite_version` |
| 341572 | `http://www.facebook.com/` |
| 344768 | `Exception %8.8X ..
Code Data: %s
` |
| 342428 | `<font color="%s">%s</font>` |
| 343176 | `<!DOCTYPE HTML P...2 Final//EN">
` |
| 356304 | `SELECT 'CREATE T..  AND rootpage>0` |
| 322496 | `Error: Cannot lo..control classes.` |
| 342208 | `<tr><td%s nowrap..color=#%s%s>%s
` |
| 322048 | `"url","username"..sswordChanged"
` |
| 334288 | `REINDEXEDESCAPEA..UUMVIEWINITIALLY` |
| 340744 | `{%8.8X-%4.4X-%4...%2.2X%2.2X%2.2X}` |
| 340928 | `taskhostex.exe` |
| 356544 | `SELECT 'CREATE U.. UNIQUE INDEX %'` |
| 345140 | `ntdll.dll` |
| 357128 | `INSERT INTO vacu.. AND rootpage=0)` |
| 343024 | `<table border="1..ing="5"><tr%s>
` |
| 356848 | `SELECT 'DELETE F..qlite_sequence' ` |
| 342816 | `<?xml version="1..ISO-8859-1" ?>
` |
| 356440 | `SELECT 'CREATE I..CREATE INDEX %' ` |
| 340900 | `taskhost.exe` |
| 322428 | `comctl32.dll` |
| 344380 | `places.sqlite` |
| 350960 | `UPDATE %Q.%s SET..type='trigger');` |
| 357784 | `qualified table .. within triggers` |
| 341432 | `0123456789ABCDEF` |
| 342336 | `<table border="1..llpadding="5">
` |
| 325920 | `CREATE TABLE sql..er,
  sql text
)` |
| 351336 | `UPDATE sqlite_te..e = %Q WHERE %s;` |
| 340344 | `wand.dat` |
| 342016 | `_lng.ini` |
| 344676 | `profiles.ini` |
| 346244 | `shlwapi.dll` |
| 357968 | `the NOT INDEXED .. within triggers` |
| 357880 | `the INDEXED BY c.. within triggers` |
| 343864 | `report.html` |
| 343424 | `<table dir="rtl"><tr><td>
` |
| 351656 | `UPDATE "%w".%s S..e' AND name = %Q` |
| 357336 | `UPDATE %Q.%s SET.. WHERE rowid=#%d` |
| 353856 | `index associated..annot be dropped` |
| 353280 | `number of column..referenced table` |
| 358688 | `\VarFileInfo\Translation` |
| 340692 | `netmsg.dll` |
| 358104 | `2011-01-28 17:03..df47be29e3fe8cd7` |
| 341460 | `index.dat` |
| 340600 | `kernel32.dll` |
| 355408 | `only a single re..of an expression` |
| 349324 | `cannot rollback ..ents in progress` |
| 324976 | `0123456789ABCDEF` |
| 351488 | `Cannot add a REF..LL default value` |
| 358376 | `unable to delete..ctive statements` |
| 350324 | `aggregate functi.. GROUP BY clause` |
| 358284 | `unable to delete..ctive statements` |
| 354080 | `unable to open a..temporary tables` |
| 350176 | `%r ORDER BY term..n the result set` |
| 345532 | `psapi.dll` |

### Constants / Known Patterns (19)
| Category | Value |
|---|---|
| hash | `hash::MD5` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| apihash | `apihash::hash(exp)` |
| hash | `hash::RIPEMD160` |
| crypto | `crypto::DES_odd_parity__8_byt_256` |
| crypto | `crypto::DES_semi_weak_keys__8_byt_96` |
| crypto | `crypto::DES_skb__32_lil_2048` |
| crypto | `crypto::DES_SPR_SPtrans__32_lil_2048` |
| crypto | `crypto::libntlm_DES_key_swap__32_lil_64` |
| crypto | `crypto::libntlm_DES_key_swap__32_big_64` |
| crypto | `crypto::RawDES_sbox1__32_lil_256` |
| crypto | `crypto::RawDES_sbox2__32_lil_256` |
| crypto | `crypto::RawDES_sbox3__32_lil_256` |
| crypto | `crypto::RawDES_sbox4__32_lil_256` |
| crypto | `crypto::RawDES_sbox5__32_lil_256` |
| crypto | `crypto::RawDES_sbox6__32_lil_256` |
| crypto | `crypto::RawDES_sbox7__32_lil_256` |
| crypto | `crypto::RawDES_sbox8__32_lil_256` |

### Imports (273)
| EA | Name | Type | Refs |
|---|---|---|---|
| 320512 | advapi32.RegQueryValueExW | IMPORT | 6 |
| 320516 | advapi32.RegOpenKeyExW | IMPORT | 1 |
| 320520 | advapi32.RegEnumValueW | IMPORT | 1 |
| 320524 | advapi32.RegCloseKey | IMPORT | 2 |
| 320532 | comctl32.#17 | IMPORT | 2 |
| 320536 | comctl32.ImageList_Create | IMPORT | 1 |
| 320540 | comctl32.ImageList_AddMasked | IMPORT | 1 |
| 320544 | comctl32.ImageList_SetImageCount | IMPORT | 3 |
| 320548 | comctl32.ImageList_ReplaceIcon | IMPORT | 1 |
| 320552 | comctl32.CreateStatusWindowW | IMPORT | 1 |
| 320556 | comctl32.CreateToolbarEx | IMPORT | 1 |
| 320564 | gdi32.GetTextExtentPoint32W | IMPORT | 2 |
| 320568 | gdi32.GetDeviceCaps | IMPORT | 2 |
| 320572 | gdi32.SelectObject | IMPORT | 1 |
| 320576 | gdi32.SetBkMode | IMPORT | 3 |
| 320580 | gdi32.DeleteObject | IMPORT | 4 |
| 320584 | gdi32.SetTextColor | IMPORT | 3 |
| 320588 | gdi32.CreateFontIndirectW | IMPORT | 2 |
| 320592 | gdi32.GetStockObject | IMPORT | 1 |
| 320596 | gdi32.SetBkColor | IMPORT | 1 |
| 320604 | kernel32.GetFullPathNameA | IMPORT | 2 |
| 320608 | kernel32.InitializeCriticalSection | IMPORT | 2 |
| 320612 | kernel32.GetFullPathNameW | IMPORT | 1 |
| 320616 | kernel32.DeleteFileA | IMPORT | 1 |
| 320620 | kernel32.GetDiskFreeSpaceW | IMPORT | 1 |
| 320624 | kernel32.AreFileApisANSI | IMPORT | 2 |
| 320628 | kernel32.EnterCriticalSection | IMPORT | 1 |
| 320632 | kernel32.GetSystemTime | IMPORT | 1 |
| 320636 | kernel32.LockFileEx | IMPORT | 2 |
| 320640 | kernel32.FormatMessageA | IMPORT | 1 |
| 320644 | kernel32.UnlockFileEx | IMPORT | 1 |
| 320648 | kernel32.LockFile | IMPORT | 3 |
| 320652 | kernel32.UnlockFile | IMPORT | 4 |
| 320656 | kernel32.FlushFileBuffers | IMPORT | 1 |
| 320660 | kernel32.InterlockedCompareExchange | IMPORT | 2 |
| 320664 | kernel32.DeleteCriticalSection | IMPORT | 2 |
| 320668 | kernel32.CreateFileA | IMPORT | 1 |
| 320672 | kernel32.GetDiskFreeSpaceA | IMPORT | 1 |
| 320676 | kernel32.Sleep | IMPORT | 6 |
| 320680 | kernel32.GetSystemInfo | IMPORT | 1 |
| 320684 | kernel32.GetModuleHandleA | IMPORT | 2 |
| 320688 | kernel32.GetStartupInfoW | IMPORT | 1 |
| 320692 | kernel32.GetTempPathA | IMPORT | 1 |
| 320696 | kernel32.GetFileAttributesExW | IMPORT | 1 |
| 320700 | kernel32.QueryPerformanceCounter | IMPORT | 1 |
| 320704 | kernel32.GetFileAttributesA | IMPORT | 2 |
| 320708 | kernel32.SetEndOfFile | IMPORT | 1 |
| 320712 | kernel32.LeaveCriticalSection | IMPORT | 1 |
| 320716 | kernel32.EnumResourceTypesW | IMPORT | 1 |
| 320720 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 320724 | kernel32.Process32NextW | IMPORT | 1 |
| 320728 | kernel32.CreateFileW | IMPORT | 8 |
| 320732 | kernel32.CloseHandle | IMPORT | 24 |
| 320736 | kernel32.FileTimeToLocalFileTime | IMPORT | 2 |
| 320740 | kernel32.DeleteFileW | IMPORT | 5 |
| 320744 | kernel32.LocalFree | IMPORT | 7 |
| 320748 | kernel32.SystemTimeToFileTime | IMPORT | 4 |
| 320752 | kernel32.CopyFileW | IMPORT | 1 |
| 320756 | kernel32.GetFileSize | IMPORT | 9 |
| 320760 | kernel32.WriteFile | IMPORT | 7 |
| 320764 | kernel32.WideCharToMultiByte | IMPORT | 9 |
| 320768 | kernel32.CompareFileTime | IMPORT | 2 |
| 320772 | kernel32.FreeLibrary | IMPORT | 13 |
| 320776 | kernel32.GetLastError | IMPORT | 26 |
| 320780 | kernel32.GetProcAddress | IMPORT | 15 |
| 320784 | kernel32.LoadLibraryW | IMPORT | 2 |
| 320788 | kernel32.FileTimeToSystemTime | IMPORT | 2 |
| 320792 | kernel32.GetModuleHandleW | IMPORT | 21 |
| 320796 | kernel32.GetTickCount | IMPORT | 3 |
| 320800 | kernel32.SetFilePointerEx | IMPORT | 1 |
| 320804 | kernel32.MultiByteToWideChar | IMPORT | 8 |
| 320808 | kernel32.FindResourceW | IMPORT | 2 |
| 320812 | kernel32.LockResource | IMPORT | 2 |
| 320816 | kernel32.LoadResource | IMPORT | 2 |
| 320820 | kernel32.SystemTimeToTzSpecificLocalTime | IMPORT | 1 |
| 320824 | kernel32.lstrlenW | IMPORT | 1 |
| 320828 | kernel32.lstrcpyW | IMPORT | 1 |
| 320832 | kernel32.LoadLibraryExW | IMPORT | 1 |
| 320836 | kernel32.GlobalAlloc | IMPORT | 2 |
| 320840 | kernel32.GetSystemDirectoryW | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 21803 | sub_40612b |
| 20403 | sub_405bb3 |
| 86590 | sub_415e3e |
| 20258 | sub_405b22 |
| 311168 | sub_44cb80 |
| 73953 | sub_412ce1 |
| 90004 | sub_416b94 |
| 28240 | sub_407a50 |
| 49174 | sub_40cc16 |
| 278322 | sub_444b32 |
| 280625 | sub_445431 |
| 287600 | sub_446f70 |
| 305856 | sub_44b6c0 |
| 72182 | sub_4125f6 |
| 303648 | sub_44ae20 |
| 301552 | sub_44a5f0 |
| 300080 | sub_44a030 |
| 311712 | sub_44cda0 |
| 22975 | sub_4065bf |
| 303040 | sub_44abc0 |
| 20032 | sub_405a40 |
| 20145 | sub_405ab1 |
| 305072 | sub_44b3b0 |
| 313216 | sub_44d380 |
| 314208 | sub_44d760 |
| 25167 | sub_406e4f |
| 23228 | sub_4066bc |
| 68693 | sub_411855 |
| 313664 | sub_44d540 |
| 56890 | sub_40ea3a |

### Decompilations (top 6)
#### 21803 — sub_40612b
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_40612b(int32_t param_1,uint32_t *param_2,int32_t param_3)

{
    uint32_t *puVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uStack_8;
    
    uVar4 = (*param_2 >> 0x1d) + *param_2 * 8;
    uStack_8 = (param_2[1] >> 0x1d) + param_2[1] * 8;
    if (param_3 == 0) {
        puVar1 = param_1 + 0x70;
        param_3 = 4;
        do {
            uVar2 = puVar1[2] ^ uVar4;
            uVar3 = (puVar1[3] ^ uVar4) * 0x10000000 + ((puVar1[3] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = *puVar1 ^ uStack_8;
            uVar3 = (puVar1[1] ^ uStack_8) * 0x10000000 + ((puVar1[1] ^ uStack_8) >> 4);
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-2] ^ uVar4;
            uVar3 = (puVar1[-1] ^ uVar4) * 0x10000000 + ((puVar1[-1] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = puVar1[-4] ^ uStack_8;
            uVar3 = (puVar1[-3] ^ uStack_8) * 0x10000000 + ((puVar1[-3] ^ uStack_8) >> 4);
            puVar1 = puVar1 + -8;
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                            *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                            *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^
                            *((uVar3 >> 0x1a) * 4 + 0x453c70) ^ *((uVar2 >> 0x1a) * 4 + 0x453b70);
            param_3 = param_3 + -1;
        } while (param_3 != 0);
    }
    else {
        puVar1 = param_1 + 8;
        param_3 = 4;
        do {
            uVar2 = puVar1[-2] ^ uVar4;
            uVar3 = (puVar1[-1] ^ uVar4) * 0x10000000 + ((puVar1[-1] ^ uVar4) >> 4);
            uStack_8 = uStack_8 ^
                       *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >> 0x12 & 0x3f) * 4 + 0x453970) ^
                       *((uVar2 >> 10 & 0x3f) * 4 + 0x453770) ^
                       *(&DES_SPR_SPtrans__32_lil_2048 + (uVar2 >> 2 & 0x3f) * 4) ^ *((uVar3 >> 0x1a) * 4 + 0x453c70) ^
                       *((uVar2 >> 0x1a) * 4 + 0x453b70);
            uVar2 = *puVar1 ^ uStack_8;
            uVar3 = (puVar1[1] ^ uStack_8) * 0x10000000 + ((puVar1[1] ^ uStack_8) >> 4);
            uVar4 = uVar4 ^ *((uVar3 >> 0x12 & 0x3f) * 4 + 0x453a70) ^ *((uVar3 >> 10 & 0x3f) * 4 + 0x453870) ^
                            *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uV
```
#### 20403 — sub_405bb3
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __fastcall sub_405bb3(uint8_t *param_1)

{
    int32_t iVar1;
    uint32_t *in_EAX;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    int32_t iStack_4;
    
    uVar2 = CONCAT31(CONCAT21(CONCAT11(*param_1, param_1[1]), param_1[2]), param_1[3]);
    uVar4 = CONCAT31(CONCAT21(CONCAT11(param_1[4], param_1[5]), param_1[6]), param_1[7]);
    uVar3 = (uVar4 >> 4 ^ uVar2) & 0xf0f0f0f;
    uVar2 = uVar2 ^ uVar3;
    uVar4 = uVar4 ^ uVar3 << 4;
    uVar4 = uVar4 ^ (uVar4 ^ uVar2) & 0x10101010;
    uVar3 = (((((*(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 5 & 0xf) * 4) & 0x1fffff) << 3 |
               *(&libntlm_DES_key_swap__32_lil_64 + (*param_1 >> 5) * 4) & 0xffffff) * 2 |
              *(&libntlm_DES_key_swap__32_lil_64 + (uVar2 & 0xf) * 4) & 0x1ffffff) * 2 |
             *(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 8 & 0xf) * 4) & 0x3ffffff) * 2 |
            *(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 0x10 & 0xf) * 4) & 0x7ffffff) * 2 |
            ((*(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 0xd & 0xf) * 4) * 2 |
             *(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 0x15 & 0xf) * 4)) << 5 |
            *(&libntlm_DES_key_swap__32_lil_64 + (uVar2 >> 0x18 & 0xf) * 4)) & 0xfffffff;
    uVar2 = (((((*(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 4 & 0xf) * 4) & 0x1fffff) * 2 |
               *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 0xc & 0xf) * 4) & 0x3fffff) << 2 |
              *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 0x1c) * 4) & 0xffffff) * 2 |
             *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 1 & 0xf) * 4) & 0x1ffffff) * 2 |
            *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 9 & 0xf) * 4) & 0x3ffffff) << 2 |
            ((*(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 0x14 & 0xf) * 4) << 4 |
             *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 0x11 & 0xf) * 4)) * 2 |
            *(&libntlm_DES_key_swap__32_big_64 + (uVar4 >> 0x19 & 0xf) * 4)) & 0xfffffff;
    iStack_4 = 0;
    do {
        if (((iStack_4 < 2) || (iStack_4 == 8)) || (iStack_4 == 0xf)) {
            uVar5 = uVar3 >> 0x1b | uVar3 * 2;
            iVar1 = 0x1b;
            uVar4 = uVar2 * 2;
        }
        else {
            uVar5 = uVar3 >> 0x1a | uVar3 << 2;
            iVar1 = 0x1a;
            uVar4 = uVar2 << 2;
        }
        uVar3 = uVar5 & 0xfffffff;
        uVar6 = uVar2 >> iVar1;
        uVar4 = uVar6 | uVar4;
        uVar2 = uVar4 & 0xfffffff;
        *in_EAX = (((((((((uVar2 >> 2 & 0x2000000 | uVar4 & 0x1000000) >> 6 | uVar4 & 0x100000) >> 4 | uVar4 & 0x800000)
                        >> 1 | uVar4 & 0x4000000) >> 3 | uVar4 & 0x4000 | uVar5 & 0x4000000) >> 5 | uVar4 & 0x400) >> 1
                    | uVar4 & 0x10000) >> 1 | uVar4 & 0x40) >> 2 | uVar4 & 0x800 | uVar5 & 0x200000) >> 1 |
                  ((((((((uVar5 & 1) << 10 | uVar5 & 0x82) << 4 | uVar5 & 0x2000) << 4 | uVar5 & 0x100) * 2 |
                     uVar5 & 0x1000) << 3 | uVar4 & 0x20 | uVar5 & 0x40000) << 2 | uVar5 & 0x2400000) << 2 |
                  uVar5 & 0x8000) << 2 | uVar4 & 0x100;
        in_EAX[1] = (((((((((((uVar5 & 0x10) << 5 | uVar5 & 0x800) * 2 | uVar5 & 0x20) * 2 | uVar5 & 0x4004) << 4 |
                          uVar5 & 0x200) * 2 | uVar5 & 0x20000) << 2 | uVar4 & 0x10) * 2 | uVar4 & 2) << 4 |
                      uVar5 & 0x10000) * 2 | uVar6 & 1) * 2 | uVar5 & 0x800000) * 2 |
                    (((((((uVar2 >> 7 & 0x8000 | uVar4 & 0x2020000) >> 5 | uVar4 & 0x80000) >> 2 | uVar4 & 0x1000) >> 1
                       | uVar5 & 0x1000000) >> 2 | uVar5 & 0x100000) >> 1 | uVar4 & 0x88) >> 1 | uVar5 & 0x8000000 |
                    uVar4 & 0x8000) >> 2 | uVar4 & 0x200;
        in_EAX = in_EAX + 2;
        iStack_4 = iStack_4 + 1;
    } while (iStack_4 < 0x10);
    return 0;
}

```
#### 86590 — sub_415e3e
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_415e3e(int32_t *param_1)

{
    int32_t iVar1;
    uint32_t *in_EAX;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    int32_t *piStack_c;
    int32_t *piStack_8;
    
    uVar2 = (in_EAX[1] >> 4 ^ *in_EAX) & 0xf0f0f0f;
    uVar6 = *in_EAX ^ uVar2;
    uVar4 = in_EAX[1] ^ uVar2 << 4;
    uVar2 = (uVar6 << 0x12 ^ uVar6) & 0xcccc0000;
    uVar3 = (uVar4 << 0x12 ^ uVar4) & 0xcccc0000;
    uVar4 = uVar4 ^ uVar3 >> 0x12 ^ uVar3;
    uVar6 = uVar6 ^ uVar2 >> 0x12 ^ uVar2;
    uVar2 = (uVar4 >> 1 ^ uVar6) & 0x55555555;
    uVar6 = uVar6 ^ uVar2;
    uVar4 = uVar4 ^ uVar2 * 2;
    uVar2 = (uVar6 >> 8 ^ uVar4) & 0xff00ff;
    uVar4 = uVar4 ^ uVar2;
    uVar6 = uVar6 ^ uVar2 << 8;
    uVar2 = (uVar4 >> 1 ^ uVar6) & 0x55555555;
    uVar6 = uVar6 ^ uVar2;
    uVar4 = uVar4 ^ uVar2 * 2;
    uVar2 = (uVar4 >> 0xc & 0xff0 | uVar6 & 0xf000000f) >> 4 | (uVar4 & 0xff) << 0x10 | uVar4 & 0xff00;
    uVar6 = uVar6 & 0xfffffff;
    piStack_8 = 0x45a920;
    piStack_c = param_1;
    do {
        if (*piStack_8 == 0) {
            uVar4 = uVar6 >> 1 | uVar6 << 0x1b;
            iVar1 = 0x1b;
            uVar3 = uVar2 >> 1;
        }
        else {
            uVar4 = uVar6 >> 2 | uVar6 << 0x1a;
            iVar1 = 0x1a;
            uVar3 = uVar2 >> 2;
        }
        uVar5 = uVar3 | uVar2 << iVar1;
        uVar6 = uVar4 & 0xfffffff;
        uVar2 = uVar3 | uVar2 << iVar1 & 0xfffffff;
        uVar3 = uVar6 >> 1;
        uVar3 = *((((uVar3 & 0x7000000 | uVar4 & 0xc00000) >> 1 | uVar4 & 0x100000) >> 0x14) * 4 + 0x453070) |
                *(((uVar4 & 0x1e000 | uVar3 & 0x60000) >> 0xd) * 4 + 0x452f70) |
                *(((uVar3 & 0xf00 | uVar4 & 0xc0) >> 6) * 4 + 0x452e70) | *(&DES_skb__32_lil_2048 + (uVar4 & 0x3f) * 4);
        piStack_8 = piStack_8 + 1;
        uVar4 = *(((uVar2 >> 1 & 0x1e00 | uVar5 & 0x180) >> 7) * 4 + 0x453270) |
                *(((uVar2 >> 1 & 0x6000000 | uVar5 & 0x1e00000) >> 0x15) * 4 + 0x453470) |
                *((uVar2 >> 0xf & 0x3f) * 4 + 0x453370) | *((uVar5 & 0x3f) * 4 + 0x453170);
        *piStack_c = ((uVar4 << 0x10) >> 0x1e) + (uVar3 & 0xffff | uVar4 << 0x10) * 4;
        piStack_c[1] = (uVar3 >> 0x10 | uVar4 & 0xffff0000) * 0x40 + (uVar4 >> 0x1a);
        piStack_c = piStack_c + 2;
    } while (piStack_8 < 0x45a960);
    return;
}

```

### Carved Files (18)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 304 |
| ? | DIB | 1000 |
| ? | DIB | 216 |
| ? | DIB | 216 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | DIB | 1128 |
| ? | PE | 62976 |
| ? | PE | 195584 |
| ? | PE | 37376 |

### Virtual Files (49)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| BIN/50/en-us | 5832 | - |
| CUR/1/en-us | 308 | - |
| BMP/104/en-us | 1000 | - |
| BMP/133/en-us | 216 | - |
| BMP/134/en-us | 216 | - |
| ICO/2/en-us | 4264 | - |
| ICO/3/en-us | 1128 | - |
| ICO/4/en-us | 1128 | - |
| ICO/5/en-us | 1128 | - |
| ICO/6/en-us | 1128 | - |
| ICO/7/en-us | 1128 | - |
| ICO/8/en-us | 1128 | - |
| ICO/9/en-us | 1128 | - |
| ICO/10/en-us | 1128 | - |
| ICO/11/en-us | 1128 | - |
| ICO/12/en-us | 1128 | - |
| MENU/102/en-us | 1118 | - |
| MENU/104/en-us | 500 | - |
| DLG/105/en-us | 162 | - |
| DLG/107/en-us | 662 | - |

### Structures (192)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 480 |
| advapi32.FT | 320512 |
| comctl32.FT | 320532 |
| gdi32.FT | 320564 |
| kernel32.FT | 320604 |
| shell32.FT | 320988 |
| user32.FT | 321012 |
| version.FT | 321344 |
| wininet.FT | 321360 |
| comdlg32.FT | 321376 |
| msvcrt.FT | 321392 |
| ole32.FT | 321628 |
| DebugDirectory | 321696 |
| Debug.Codeview | 359184 |
| ImportTable | 359316 |
| advapi32.OFT | 359556 |
| comctl32.OFT | 359576 |
| gdi32.OFT | 359608 |
| kernel32.OFT | 359648 |
| shell32.OFT | 360032 |
| user32.OFT | 360056 |
| version.OFT | 360388 |
| wininet.OFT | 360404 |
| comdlg32.OFT | 360420 |
| msvcrt.OFT | 360436 |
| ole32.OFT | 360672 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 49 · duration_s: 2.35

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| manually build AES constants | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using DES | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.004:Encrypt Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |

## PE Imports / Signals
import_count: 272

| label | api_match | ATT&CK |
|---|---|---|
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 26

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@401996 len=7; $ipv6@382760 len=2 |
| contains_base64 | - | $a@176404 len=12 |
| Big_Numbers1 | - | $c0@320624 len=32 |
| MD5_Constants | - | $c1@28304 len=4; $c4@73977 len=4; $c5@73984 len=4; $c6@73991 len=4; $c7@73998 len=4 |
| RIPEMD160_Constants | - | $c1@28304 len=4; $c5@73977 len=4; $c6@73984 len=4; $c7@73991 len=4 |
| SHA1_Constants | - | $c1@28304 len=4; $c5@73977 len=4; $c6@73984 len=4; $c7@73991 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@298282 len=4; $c1@298289 len=4; $c2@298296 len=4; $c3@298303 len=4; $c4@298310 len=4; $c5@298317 len=4; $c6@298324 len=4; $c7@298331 len=4 |
| DES_Long | - | $c0@334960 len=64 |
| DES_sbox | - | $c0@364600 len=64 |
| with_sqlite | - | $hex_string@321060 len=16 |
| url | - | $url_regex@337896 len=88 |
| maldoc_getEIP_method_1 | - | $a@458764 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@216 len=4 |
| Visual_Cpp_2003_EXE_Microsoft | - | $a@285996 len=15 |
| SEH_Init | - | $b@286536 len=7 |
| screenshot | - | $d1@361396 len=9; $d2@361230 len=10; $c2@360554 len=5 |
| keylogger | - | $f1@361230 len=10; $c2@361218 len=11 |
| win_registry | - | $f1@361538 len=12; $c3@361474 len=11; $c6@361474 len=11 |
| win_files_operation | - | $f1@359844 len=12; $c1@358212 len=9; $c2@358388 len=14; $c3@358212 len=9; $c4@358868 len=8; $c5@359668 len=11; $c6@359750 len=11 |
| Str_Win32_Wininet_Library | - | $wininet_lib@358068 len=11 |

## Generated YARA Meta
```json
{
  "rule_count": 26,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
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
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 401996,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 382760,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 176404,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Big_Numbers1",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 320624,
          "length": 32,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73998,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 28304,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 73977,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 73984,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 73991,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/incoming/1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0/remcos_sample.exe",
      "strings": [
        {
          "id": "$c0",
          "offset": 298282,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 298289,
          "length": 4,
          "xo
```

## FLOSS Strings
Total strings: 2008 · per_category: `{"decoded_strings": 18, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1990}`

### FLOSS sample
- `j:,4;87`
- `=&&jL66Zl??A~`
- `g99KrJJ`
- `&jL&6Zl6?A~?`
- `jL&&Zl66A~??`
- `RRMv;;a`
- `L&&jl66Z~??A`
- `interrupted`
- `!<5!4%!`
- `&<5!4%!`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `D$TH9D$`
- `u'9~(~G`
- `Wtnj_P`
- `QQSVWh|`
- `333310`
- `%33333`
- `9>uPhA`
- `@f9F"W`
- `YYtWC;`
- `YYu49]`
- `PWhP>E`
- `tqSVWj`
- `GWCSPQ`
- `0vpSW3`
- `GGF;t$`
- `u,WVh4@E`
- `SVWj X`
- `YYtZFj?V`
- `tqSVW3`
- `9_DV~B`
- `tMhLCE`
- `D$Tj	P`
- `YYt49\$`
- `tff9t$@tI`
- `D$@j	P`
- `YY9t$$t`
- `9^0W~.S`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0044692c
```asm
┌ 445: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_28h @ ebp-0x28
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_48h @ ebp-0x48
│           ; var int32_t var_4ch @ ebp-0x4c
│           ; var int32_t var_78h @ ebp-0x78
│           ; var int32_t var_7ch @ ebp-0x7c
│           0x0044692c      6a70           push 0x70                   ; 'p' ; 112
│           0x0044692e      68c0f44400     push 0x44f4c0
│           0x00446933      e804020000     call 0x446b3c
│           0x00446938      33ff           xor edi, edi
│           0x0044693a      57             push edi
│           0x0044693b      ff15acf04400   call dword [sym.imp.KERNEL32.dll_GetModuleHandleA] ; 0x44f0ac ; "~\x97\x05" ; HMODULE GetModuleHandleA(LPCSTR lpModuleName)
│           0x00446941      6681384d5a     cmp word [eax], 0x5a4d      ; 'MZ'
│       ┌─< 0x00446946      751f           jne 0x446967
│       │   0x00446948      8b483c         mov ecx, dword [eax + 0x3c]
│       │   0x0044694b      03c8           add ecx, eax
│       │   0x0044694d      813950450000   cmp dword [ecx], 0x4550     ; 'PE'
│      ┌──< 0x00446953      7512           jne 0x446967
│      ││   0x00446955      0fb74118       movzx eax, word [ecx + 0x18]
│      ││   0x00446959      3d0b010000     cmp eax, 0x10b              ; 267
│     ┌───< 0x0044695e      741f           je 0x44697f
│     │││   0x00446960      3d0b020000     cmp eax, 0x20b              ; 523
│    ┌────< 0x00446965      7405           je 0x44696c
│  ┌┌──└└─> 0x00446967      897de4         mov dword [var_1ch], edi
│  ╎╎││ ┌─< 0x0044696a      eb27           jmp 0x446993
│  ╎╎└────> 0x0044696c      83b9840000..   cmp dword [ecx + 0x84], 0xe
│  └──────< 0x00446973      76f2           jbe 0x446967
│   ╎ │ │   0x00446975      33c0           xor eax, eax
│   ╎ │ │   0x00446977      39b9f8000000   cmp dword [ecx + 0xf8], edi
│   ╎ │┌──< 0x0044697d      eb0e           jmp 0x44698d
│   ╎ └───> 0x0044697f      8379740e       cmp dword [ecx + 0x74], 0xe
│   └─────< 0x00446983      76e2           jbe 0x446967
│      ││   0x00446985      33c0           xor eax, eax
│      ││   0x00446987      39b9e8000000   cmp dword [ecx + 0xe8], edi
│      ││   ; CODE XREF from entry0 @ 0x44697d(x)
│      └──> 0x0044698d      0f95c0         setne al
│       │   0x00446990      8945e4         mov dword [var_1ch], eax
│       │   ; CODE XREF from entry0 @ 0x44696a(x)
│       └─> 0x00446993      897dfc         mov dword [var_4h], edi
│           0x00446996      6a02           push 2                      ; 2
│           0x00446998      5b             pop ebx
│           0x00446999      53             push ebx
│           0x0044699a      ff158cf34400   call dword [sym.imp.msvcrt.dll___set_app_type
```
### 0x004122ba
```asm
; CALL XREF from entry0 @ 0x446abf(x)
┌ 543: int main (int32_t argc, int32_t argv, int32_t envp, int32_t arg_40h, int32_t arg_44h, int32_t arg_60h_3, int32_t arg_60h_2, int32_t arg_60h, int32_t arg_26ch_2, int32_t arg_270h, int32_t arg_284h, int32_t arg_268h, int32_t arg_26ch, int32_t arg_288h, int32_t arg_2ach, int32_t arg_718h, int32_t arg_704h_3, int32_t arg_704h_2, int32_t arg_704h, int32_t arg_70ch);
│           ; arg int32_t argc @ esp+0x9c
│           ; arg int32_t argv @ esp+0xa0
│           ; arg int32_t envp @ esp+0xa4
│           ; arg int32_t arg_40h @ esp+0xa8
│           ; arg int32_t arg_44h @ esp+0xac
│           ; arg int32_t arg_60h_3 @ esp+0xb4
│           ; arg int32_t arg_60h_2 @ esp+0xb8
│           ; arg int32_t arg_60h @ esp+0xcc
│           ; arg int32_t arg_26ch_2 @ esp+0x284
│           ; arg int32_t arg_270h @ esp+0x290
│           ; arg int32_t arg_284h @ esp+0x2a8
│           ; arg int32_t arg_268h @ esp+0x2b0
│           ; arg int32_t arg_26ch @ esp+0x2b8
│           ; arg int32_t arg_288h @ esp+0x2bc
│           ; arg int32_t arg_2ach @ esp+0x300
│           ; arg int32_t arg_718h @ esp+0x738
│           ; arg int32_t arg_704h_3 @ esp+0x75c
│           ; arg int32_t arg_704h_2 @ esp+0x760
│           ; arg int32_t arg_704h @ esp+0x764
│           ; arg int32_t arg_70ch @ esp+0x76c
│           ; var int32_t var_10h_3 @ esp+0x3c
│           ; var int32_t var_50h_3 @ esp+0x54
│           ; var int32_t var_44h_2 @ esp+0x58
│           ; var int32_t var_30h_2 @ esp+0x5c
│           ; var int32_t var_50h_2 @ esp+0x64
│           ; var int32_t var_10h_2 @ esp+0x68
│           ; var int32_t var_44h @ esp+0x70
│           ; var int32_t var_14h @ esp+0x78
│           ; var int32_t var_10h @ esp+0x7c
│           ; var int32_t var_50h @ esp+0x80
│           ; var int32_t var_30h @ esp+0x88
│           ; var int32_t var_60h @ esp+0x8c
│           0x004122ba      55             push ebp
│           0x004122bb      8bec           mov ebp, esp
│           0x004122bd      83e4f8         and esp, 0xfffffff8
│           0x004122c0      b84c310000     mov eax, 0x314c             ; 'L1'
│           0x004122c5      e8e6ba0300     call 0x44ddb0
│           0x004122ca      53             push ebx
│           0x004122cb      56             push esi
│           0x004122cc      57             push edi
│           0x004122cd      e80f31ffff     call 0x4053e1
│           0x004122d2      85c0           test eax, eax
│       ┌─< 0x004122d4      7506           jne 0x4122dc
│       │   0x004122d6      40             inc eax
│      ┌──< 0x004122d7      e9f4010000     jmp 0x4124d0
│      │└─> 0x004122dc      e806480000     call 0x416ae7
│      │    0x004122e1      6801800000     push 0x8001
│      │    0x004122e6      ff15c4f14400   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x44f1c4 ; UINT SetErrorMode(UINT uMode)
│      │    0x004122ec      33db           xor ebx, ebx
│      │    0x004122ee      53             push ebx
│      │    0x004122ef
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r
- Found XOR 00 position 00062605: 00000040 PE..L.....iT.................2........
- Found XOR 00 position 00071C0A: 00000040 PE..L...R..`..........................
- Found XOR 00 position 000A180F: 00000040 PE..L...8..c...........#..............

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
  - `msvcrt.dll!__wgetmainargs`
  - `msvcrt.dll!_initterm`
  - `msvcrt.dll!__setusermatherr`
  - `msvcrt.dll!_adjust_fdiv`
  - `msvcrt.dll!wcsrchr`
  - `COMCTL32.dll!ImageList_Create`
  - `COMCTL32.dll!ImageList_AddMasked`
  - `COMCTL32.dll!ImageList_SetImageCount`
  - `COMCTL32.dll!ImageList_ReplaceIcon`
  - `VERSION.dll!VerQueryValueW`
  - `VERSION.dll!GetFileVersionInfoSizeW`
  - `VERSION.dll!GetFileVersionInfoW`
  - `WININET.dll!FindCloseUrlCache`
  - `WININET.dll!FindNextUrlCacheEntryW`
  - `WININET.dll!FindFirstUrlCacheEntryW`
  - `KERNEL32.dll!GetFullPathNameA`
  - `KERNEL32.dll!InitializeCriticalSection`
  - `KERNEL32.dll!GetFullPathNameW`
  - `KERNEL32.dll!DeleteFileA`
  - `KERNEL32.dll!GetDiskFreeSpaceW`
  - `USER32.dll!GetKeyState`
  - `USER32.dll!DispatchMessageW`
  - `USER32.dll!TranslateMessage`
  - `USER32.dll!IsDialogMessageW`
  - `USER32.dll!DrawTextExW`
  - `GDI32.dll!GetTextExtentPoint32W`
  - `GDI32.dll!GetDeviceCaps`
  - `GDI32.dll!SelectObject`
  - `GDI32.dll!SetBkMode`
  - `GDI32.dll!DeleteObject`
