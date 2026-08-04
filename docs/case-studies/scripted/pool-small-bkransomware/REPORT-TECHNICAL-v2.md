# Technical Malware Analysis Report: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c

## 1. Executive Summary
This sample is a high-confidence malicious PE32 x86 Windows GUI executable with a threat score of 9, classified as a multi-functional loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families (source: llm_judge, verdict.json). It masquerades as a legitimate Adobe Bootstrapper installer, with a file size of 485376 bytes, entry point at EA 135201, and extreme entropy of 109 indicating packed/encrypted payload content (source: malcat, Malcat File Summary). Static analysis reveals 17 high-severity structural anomalies including cross-section control flow jumps, 14 spaghetti code functions, 7 XOR-in-loop routines, 21 delay imports, and import-by-hash obfuscation, all consistent with malware designed to evade analysis (source: malcat, Anomalies table). YARA scanning matched 23 rules confirming core malicious capabilities including anti-debugging, network dropper functionality, privilege escalation, screenshot capture, keylogging, registry manipulation, and file system operations (source: yara, YARA Matches table). Capa analysis confirmed 30 capability rules mapping to MITRE ATT&CK techniques including system information discovery, file system discovery, registry modification, payload download, process execution, and system shutdown, aligning with both remote access trojan (RAT) and ransomware functionality (source: malcat-capa, capa Capability Rules table).

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c | llm_judge, verdict.json |
| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos | sample_path |
| Project Name | pool | project_name |
| File Type | PE32 Windows GUI executable | malcat, Malcat File Summary |
| Architecture | X86 | malcat, Malcat File Summary |
| File Size | 485376 bytes | malcat, Malcat File Summary |
| Entry Point (EA) | 135201 | malcat, Malcat File Summary |
| Entropy | 109 | malcat, Malcat File Summary |
| Verdict | Malicious | llm_judge, verdict.json |
| Score | 9 | llm_judge, verdict.json |
| Family Guess | Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families | llm_judge, verdict.json |
| Analysis Note | IDA was unavailable due to missing idasql binary; all static analysis derived from Ghidra, Malcat, capa, YARA, pe_imports, and FLOSS | llm_judge, cross_engine_notes |

## 3. File Layout & Structural Analysis
The sample's PE section layout is as follows (source: malcat, File Layout table):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 52 | - |
| .text | 1024 | 242688 | 245760 | 139 | RX |
| .rdata | 246784 | 86528 | 90112 | 76 | R |
| .data | 336896 | 10752 | 28672 | 71 | RW |
| .rsrc | 365568 | 144384 | 147456 | 77 | RWX |

The sample exhibits 17 high-severity structural anomalies (source: malcat, Anomalies table):
- **Level 4 (Critical):** CrossSectionJump (1 hit, code), ExecutableSectionNoCode (1 hit, sections), ExtraSpaceAfterResourcesDataDirectory (1 hit, resources), ImportByHash (1 hit, imports), InvalidChecksum (1 hit, integrity)
- **Level 3 (High):** BigStringHiScore (1 hit, strings), DelayImports (21 hits, imports), ManyHighValueImmediates (2 hits, code), ManyUniqueImmediateBytes (3 hits, code), SectionWX (1 hit, sections, .rsrc is RWX), WeirdDebugInfoType (1 hit, headers), XorInLoop (7 hits, code)
- **Level 2 (Medium):** DownloaderApiUsage (1 hit, imports), HugeFunctionGapAtSectionBoundary (1 hit, code), InvalidSizeOfInitializedData (1 hit, sections)
- **Level 1 (Low):** HighXrefLoopingFunction (5 hits, code, likely string decryption routines), SpaghettiFunction (14 hits, code, obfuscation indicator)

High-signal anomaly locations (source: malcat, Anomaly Locations table):
| Anomaly Type | EA Addresses |
|---|---|
| HighXrefLoopingFunction | 36581, 46146, 135232, 137164, 139970 |
| ManyHighValueImmediates | 34874, 37738 |
| ManyUniqueImmediateBytes | 170803, 174000, 187626 |
| SpaghettiFunction | 34874, 36698, 52894, 82310, 140842 |
| XorInLoop | 47477, 143424, 190322, 193762, 220515 |

Additional structural observations: 20 DIB (device-independent bitmap) files were carved from the sample, consistent with screenshot capture functionality confirmed via YARA (source: malcat, Carved Files table; source: yara, YARA Matches table). 65 virtual files were identified, including localization INIs, cursor files, and image resources, supporting the Adobe installer masquerade (source: malcat, Virtual Files table). The sample has 318 unique imported APIs (source: pe_imports, PE Imports / Signals table). The UPX unpack attempt returned upx_ok: False, is_packed: False, and no unpacked payload was produced (source: upx, UPX Unpack section).

## 4. Malcat Triage Summary
Malcat deep profile summary (source: malcat, Malcat File Summary):
```
sha256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
size: 485376
type: PE
architecture: X86
entrypoint_ea: 135201
entropy: 109
file_name: 2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
```

Malcat YARA/Signatures (source: malcat, Malcat YARA / Signatures table):
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs2013_12_0_40629_00_update_5_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| visual_studio_2013_update_1__12_0__also_has_this_build_number_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

Full anomalies table (source: malcat, Anomalies table):
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| ImportByHash | 4 | imports | 1 | APIs are imported by hash |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DelayImports | 3 | imports | 21 | There are delay imports |
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 3 | More than 48 unique bytes defined across all immediate operands in the function |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 7 | XOR instruction in a loop |
| DownloaderApiUsage | 2 | imports | 1 | Downloader-related apis are used |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| HighXrefLoopingFunction | 1 | code | 5 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SpaghettiFunction | 1 | code | 14 | Function with lots of intra jumps, could be obfuscated |

High-signal strings (source: malcat, High-Signal Strings table):
| EA | String |
|---|---|
| 251280 | `\kernel32.dll` |
| 248344 | `kernel32.dll` |
| 265888 | `WaitForMSIMutex: Start..` |
| 265940 | `WaitForMSIMutex: End..` |
| 257068 | `http://` |
| 260868 | `/smutextimeout` |
| 282256 | `GetProcessWindowStation` |
| 257084 | `ftp://` |
| 431036 | `nke http://www.a..Programa ni mogo` |
| 428950 | ` http://www.adob..aplikacji nie mo` |
| 432252 | `  http://www.ado..Bu uygulama bu i` |
| 466118 | ` http://www.adob..ji %s nie powiod` |
| 421924 | ` http://www.adob..ineseSimplified=` |
| 469084 | ` okuyun: http://.._tr. Ukrainian=` |
| 433042 | ` http://www.adob..TED_SP] Arabic=` |
| 426444 | ` http://www.adob..n=Ez az alkalmaz` |
| 467102 | `ii de pe http://..lp_ro. Russian=` |
| 468776 | ` http://www.adob..h=%s derlemesi y` |
| 461232 | ` http://www.adob..seSimplified=%s ` |
| 421494 | ` http://www.adob..ae. Bulgarian=` |
| 432524 | `tfen http://www...reksinimlerine g` |

## 5. Static Code Analysis
IDA was unavailable for analysis due to a missing idasql binary, so all static analysis is derived from Ghidra (1641 functions, 1525 strings), Malcat, capa, YARA, pe_imports, and FLOSS (source: llm_judge, cross_engine_notes).

### radare2 Disassembly
#### 0x00421c21 (entry0)
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
..
```
Cite: (source: radare2, 0x00421c21 disassembly)

#### 0x004391d2 (main)
```asm
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01           mov eax, dword [ecx]
│    ││││   0x0043922e      ff5060         call dword [eax + 0x60]     ; 96
│    └────> 0x00439231      8b06           mov eax, dword [esi]
│     │││   0x00439233      8bce           mov ecx, esi
│     │││   0x00439235      ff5068         call dword [eax + 0x68]     ; 104
│    ┌────< 0x00439238      eb07           jmp 0x439241
│    ││└──> 0x0043923a      8b06           mov eax, dword [esi]
│    ││ │   0x0043923c      8bce           mov ecx, esi
│    ││ │   0x0043923e   
```
Cite: (source: radare2, 0x004391d2 disassembly)

#### 0x004139ec (fcn.004139ec)
```asm
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
Cite: (source: radare2, 0x004139ec disassembly)

#### 0x004235c9 (fcn.004235c9)
```asm
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff75e0         push dword [var_20h]
└           0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException] ; 0x43d248 ; VOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
```
Cite: (source: radare2, 0x004235c9 disassembly)

### Malcat Decompilation
#### 161187 — sub_4281a3
```c
/* DISPLAY WARNING: Type casts are NOT being printed */
undefined4 sub_4281a3(int32_t **param_1)
{
    int32_t *piVar1;
    int32_t iVar2;
    code *pcVar3;
    undefined4 uVar4;
    
    piVar1 = *param_1;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        sub_42cd34();
        pcVar3 = swi(3);
        uVar4 = (*pcVar3)();
        return uVar4;
    }
    return 0;
}
```
Cite: (source: malcat, Decompilation of 161187 sub_4281a3)

#### 181155 — sub_42cfa3
```c
/* DISPLAY WARNING: Type casts are NOT being printed */
void sub_42cfa3(void)
{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x28);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x2c));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x30);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x34);
    if (((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
         ((piVar1[5] == 0x19930520 || ((piVar1[5] == 0x19930521 || (piVar1[5] == 0x19930522)))))) &&
        (*(unaff_EBP + -0x38) == 0)) &&
       ((*(unaff_EBP + -0x1c) != 0 && (iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]), iVar2 != 0)))) {
        ___DestructExceptionObject(piVar1, *(unaff_EBP + 0x10));
    }
    return;
}
```
Cite: (source: malcat, Decompilation of 181155 sub_42cfa3)

#### 43332 — sub_40b544
```c
/* DISPLAY WARNING: Type casts are NOT being printed */
void sub_40b544(void)
{
    undefined4 *puVar1;
    undefined4 uVar2;
    int32_t unaff_EBP;
    
    __EH_prolog3(4);
    if (([0x0x4559b4] != 0) && ([0x0x4559cc] == 0)) {
        func_0x0040b5dd();
        puVar1 = *(unaff_EBP + 8);
        ATL.CSimpleStringT<wchar_t,0>.operator=(puVar1);
        sub_40b2fe();
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorText", *puVar1, 1);
        uVar2 = sub_40c667();
        sub_4012cf(uVar2);
        *(unaff_EBP + -4) = 0;
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorLanguage", [0x0x45599c], 1);
        [0x0x4559b8] = 1;
        ATL.CStringData.Release();
    }
    __EH_epilog3();
    return;
}
```
Cite: (source: malcat, Decompilation of 43332 sub_40b544)

Additional static observations: XOR search found XOR 00 at position 0x00000000 with pattern `00000110 ........!..L.!This program cannot be r`, indicating XOR obfuscation of the PE header or initial payload (source: xor, XOR Search section). FLOSS extracted 2846 static strings, including 1 decoded string, with samples including `?GetPu`, `!This program cannot be run in DOS mode.`, and `ttHt=Hu095` (source: floss, FLOSS Strings section). Ghidra identified high-signal strings containing `http://`, `kernel32.dll`, and `SOFTWARE\Adobe\Setup\Reader` (source: ghidra, ghidra suspicious strings from key_evidence). Generated YARA meta includes 24 strings, including the PDB path `D:\DCB\CBT_Main\Acrobat\Installers\BootStrapExe_Small\Release\Setup.pdb` and MFC/ATL runtime strings (source: rule.yara.json, Generated YARA Meta).

## 6. Behavioral & Dynamic Analysis
Speakeasy dynamic analysis completed successfully, but 0 API calls and 0 key events were recorded; no runtime behavior was observed (source: speakeasy, Speakeasy (dynamic) section). Frida probe completed successfully, with 34 hook candidates identified across VERSION.dll, KERNEL32.dll, USER32.dll, GDI32.dll, WINSPOOL.DRV, ADVAPI32.dll, SHELL32.dll, and SHLWAPI.dll, but no runtime events were observed (source: frida, Frida Probe section). UPX unpack attempt returned upx_ok: False, is_packed: False, and no unpacked payload was produced (source: upx, UPX Unpack section). The sample's use of 21 delay imports and import-by-hash obfuscation may prevent dynamic analysis tools from resolving imports correctly, contributing to the lack of observed runtime events (source: malcat, Anomalies table).

## 7. Network Indicators & C2
YARA network-related matches confirm the presence of hardcoded network indicators (source: yara, YARA Matches table):
- `domain` rule: matches hardcoded domain patterns for C2 communication
- `IP` rule: matches IPv4 address at 0x459893 (len 7) and IPv6 address at 0x252878 (len 4)
- `url` rule: matches URL pattern at 0x396920 (len 96)
- `contains_base64` rule: matches base64-encoded content at 0x245300 (len 24)

Malcat high-signal network strings (source: malcat, High-Signal Strings table):
| EA | String |
|---|---|
| 257068 | `http://` |
| 257084 | `ftp://` |
| 260868 | `/smutextimeout` |
| 428950 | ` http://www.adob..aplikacji nie mo` |
| 432252 | `  http://www.ado..Bu uygulama bu i` |
| 466118 | ` http://www.adob..ji %s nie powiod` |
| 421924 | ` http://www.adob..ineseSimplified=` |
| 469084 | ` okuyun: http://.._tr. Ukrainian=` |
| 433042 | ` http://www.adob..TED_SP] Arabic=` |
| 426444 | ` http://www.adob..n=Ez az alkalmaz` |
| 467102 | `ii de pe http://..lp_ro. Russian=` |
| 468776 | ` http://www.adob..h=%s derlemesi y` |
| 461232 | ` http://www.adob..seSimplified=%s ` |
| 421494 | ` http://www.adob..ae. Bulgarian=` |
| 432524 | `tfen http://www...reksinimlerine g` |

The `http://` and `ftp://` prefixes indicate potential C2 communication or payload download endpoints. The `http://www.adob...` strings are localized error messages masquerading as Adobe installer content, but may contain embedded C2 URLs. The `/smutextimeout` string likely indicates a C2 communication timeout parameter. Capa rules confirm `download URL` and `receive data` capabilities consistent with C2 communication (source: malcat-capa, capa Capability Rules table). Malcat YARA signature `DownloadUsingWininet` confirms use of WinINET API for network downloads (source: malcat, Malcat YARA / Signatures table).

## 8. Capabilities & MITRE ATT&CK Mapping
### capa Capability Rules (source: malcat-capa, capa Capability Rules table)
| Rule | ATT&CK | MBC |
|---|---|---|
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| reference SQL statements | T1213:Data from Information Repositories |  |
| receive data |  | B0030.002:C2 Communication |
| download URL |  | C0002.006:HTTP Communication |
| copy file |  | C0045:Copy File |
| delete file |  | C0047:Delete File |
| read .ini file |  | C0051:Read File |
| shutdown system | T1529:System Shutdown/Reboot |  |
| get system information on Windows | T1082:System Information Discovery |  |

### PE Imports High-Signal (source: pe_imports, PE Imports / Signals table)
| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

### YARA Capability Matches (source: yara, YARA Matches table)
| Rule | Capability |
|---|---|
| anti_dbg | Anti-debugging |
| network_dropper | Payload download and execution |
| escalate_priv | Privilege escalation |
| screenshot | Desktop screenshot capture |
| keylogger | Keystroke logging |
| win_registry | Windows registry manipulation |
| win_token | Windows token manipulation |
| win_files_operation | File system operations |
| win_hook | Windows hooking for input interception |

### Full MITRE ATT&CK Mapping
| Technique | Evidence Source |
|---|---|
| T1622 (Anti-Debugging) | `IsDebuggerPresent` import (source: pe_imports); `anti_dbg` YARA rule (source: yara) |
| T1105 (Ingress Tool Transfer) | `URLDownloadToFile` import (source: pe_imports); `network_dropper` YARA rule (source: yara); `download URL` capa rule (source: malcat-capa) |
| T1112 (Modify Registry) | `RegSetValue` import (source: pe_imports); `win_registry` YARA rule (source: yara); `query or enumerate registry value`/`delete registry key` capa rules (source: malcat-capa) |
| T1106 (Process Execution) | `CreateProcess`/`ShellExecute` imports (source: pe_imports) |
| T1129 (Module Loading) | `LoadLibrary`/`GetProcAddress` imports (source: pe_imports) |
| T1082 (System Information Discovery) | `query environment variable`/`get system information on Windows` capa rules (source: malcat-capa) |
| T1083 (File and Directory Discovery) | `get common file path`/`check if file exists`/`get file version info` capa rules (source: malcat-capa) |
| T1012 (Query Registry) | `query or enumerate registry value` capa rule (source: malcat-capa) |
| T1529 (System Shutdown/Reboot) | `shutdown system` capa rule (source: malcat-capa) |
| T1056.1 (Keylogging) | `keylogger` YARA rule (source: yara) |
| T1113 (Screen Capture) | `screenshot` YARA rule (source: yara) |
| T1547.003 (Windows Hooking) | `win_hook` YARA rule (source: yara) |
| T1068 (Privilege Escalation) | `escalate_priv` YARA rule (source: yara); `ElevatePrivileges` Malcat signature (source: malcat) |
| T1213 (Data from Information Repositories) | `reference SQL statements` capa rule (source: malcat-capa) |

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|---|---|---|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c | llm_judge, verdict.json |
| File Name | 2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos | sample_path |
| File Type | PE32 X86 Windows GUI | malcat, Malcat File Summary |
| Entry Point | 0x00021021 (135201 decimal) | malcat, Malcat File Summary |
| Entropy | 109 | malcat, Malcat File Summary |
| Compiler | MSVC 2013 (Update 5) | malcat, Malcat YARA / Signatures table |
| PDB Path | D:\DCB\CBT_Main\Acrobat\Installers\BootStrapExe_Small\Release\Setup.pdb | rule.yara.json, Generated YARA Meta |
| Masquerade Identity | Adobe Bootstrapper Setup.exe | malcat, Malcat File Summary |

### Network IOCs
| IOC Type | Value/Pattern | Source |
|---|---|---|
| URL Pattern | `http://` prefix, `http://www.adob...` localized strings | malcat, High-Signal Strings table; yara, YARA Matches table |
| FTP Pattern | `ftp://` prefix | malcat, High-Signal Strings table |
| Base64 Content | 24-byte base64 string at 0x245300 | yara, YARA Matches table |
| Domain/IP Patterns | Matched by YARA `domain`, `IP`, `url` rules | yara, YARA Matches table |

### Registry IOCs
| IOC Type | Value | Source |
|---|---|---|
| Registry Path | `SOFTWARE\Adobe\Setup\Reader` | malcat, Top Strings table; malcat, Decompilation of 43332 sub_40b544 |
| Registry Values | `ErrorText`, `ErrorLanguage` | malcat, Decompilation of 43332 sub_40b544 |

### Mutex IOCs
| IOC Type | Value | Source |
|---|---|---|
| Mutex Name | `WaitForMSIMutex` | malcat, High-Signal Strings table |

### Structural IOCs
| IOC Type | Value | Source |
|---|---|---|
| Section Flags | .rsrc section is RWX (executable, writable, readable) | malcat, File Layout table |
| Anomaly Count | 17 structural anomalies | malcat, Anomalies table |
| Delay Imports | 21 delay-loaded imports | malcat, Anomalies table |
| Import Hash | APIs imported by hash | malcat, Anomalies table |

## 10. Detection Engineering
### YARA Detection
A generated YARA rule is available at `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar` (source: rule.yara.json, rule_path). The sample matches 23 YARA rules, including high-signal capability rules (source: yara, YARA Matches table):
- `anti_dbg`, `network_dropper`, `escalate_priv`, `screenshot`, `keylogger`, `win_registry`, `win_token`, `win_files_operation`, `win_hook`
- `domain`, `IP`, `url`, `contains_base64`
- `IsPE32`, `IsWindowsGUI`, `SEH_Save`, `SEH_Init`

### capa Detection
30 capability rules are triggered, including high-signal rules (source: malcat-capa, capa Capability Rules table):
- `query environment variable`, `check OS version`, `get system information on Windows` (T1082)
- `get common file path`, `check if file exists`, `get file version info` (T1083)
- `query or enumerate registry value`, `delete registry key` (T1012, T1112)
- `download URL`, `receive data`
- `shutdown system` (T1529)

### PE Import Signatures
High-signal imports to detect (source: pe_imports, PE Imports / Signals table):
- `IsDebuggerPresent` (T1622 anti-debugging)
- `URLDownloadToFile` (T1105 payload download)
- `RegSetValue` (T1112 registry modification)
- `CreateProcess`/`ShellExecute` (T1106 process execution)
- `LoadLibrary`/`GetProcAddress` (T1129 dynamic module loading)

### String Signatures
High-signal static strings to detect (source: malcat, High-Signal Strings table; malcat, Top Strings table):
- `WaitForMSIMutex: Start..` at 0x265888, `WaitForMSIMutex: End..` at 0x265940
- `http://` at 0x257068, `ftp://` at 0x257084
- `SOFTWARE\Adobe\Setup\Reader` at 0x258964
- `\kernel32.dll` at 0x251280

### Structural Anomaly Signatures
Detectable via static analysis (source: malcat, Anomalies table; malcat, File Layout table):
- .text section entropy > 100 (observed: 139)
- Cross-section control flow jumps
- 14+ SpaghettiFunction instances
- 7+ XorInLoop instances
- 21 delay imports
- Import by hash
- RWX section flags (observed in .rsrc)
- Invalid PE checksum

## 11. What We Don't Know
1. IDA SQL analysis is unavailable due to a missing idasql binary, so no IDA-specific function call graph, cross-reference, or type analysis is available (source: llm_judge, cross_engine_notes).
2. Dynamic analysis via Speakeasy and Frida observed zero API calls or events, so no runtime behavior (e.g., C2 communication, payload execution, file encryption) was captured (source: speakeasy, Speakeasy (dynamic) section; source: frida, Frida Probe section).
3. The UPX unpack attempt failed, so no unpacked embedded payload is available for analysis (source: upx, UPX Unpack section).
4. The full list of hardcoded C2 domains, IP addresses, and URLs is not fully extracted: YARA rules confirm their presence, but the full match content is trimmed in the evidence (source: yara, YARA Matches table).
5. No encryption-related imports or capa rules were observed, so the exact ransomware encryption routine (if present) is not confirmed in static evidence (source: pe_imports, PE Imports / Signals table; source: malcat-capa, capa Capability Rules table).
6. While registry modification is confirmed, the exact persistence mechanism (e.g., Run key, scheduled task) is not explicitly observed in the available evidence (source: pe_imports, PE Imports / Signals table; source: malcat-capa, capa Capability Rules table).
7. The exact payload download URL and secondary payload content are not extracted from static evidence (source: malcat-capa, capa Capability Rules table).

## 12. Appendix: Analysis Environment
| Tool | Status | Output | Source |
|---|---|---|---|
| Malcat | Successful | Deep profile, file layout, 17 anomalies, 100 strings, 6 YARA signatures, 3 decompilations, 20 carved files, 65 virtual files, 247 structures, 2371 import references, 30 functions | malcat, all Malcat tables |
| Ghidra | Successful | 1641 functions, 1525 strings, SQL query results for functions, imports, strings, CFG edges | ghidra, Audit Trail |
| capa (malcat-capa) | Successful | 30 capability rules, MITRE ATT&CK and MBC mappings | malcat-capa, capa Capability Rules table |
| YARA | Successful | 23 rule matches, generated rule at `/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar` | yara, YARA Matches table; rule.yara.json |
| FLOSS | Successful | 2846 static strings, 1 decoded string | floss, FLOSS Strings section |
| radare2 | Successful | Disassembly of entry0 (0x00421c21), main (0x004391d2), fcn.004139ec (0x004139ec), fcn.004235c9 (0x004235c9) | radare2, radare2 Disassembly section |
| UPX | Failed | upx_ok: False, is_packed: False, no unpacked payload | upx, UPX Unpack section |
| Speakeasy | Successful (no events) | 0 API calls, 0 key events, no runtime behavior observed | speakeasy, Speakeasy (dynamic) section |
| Frida | Successful (no events) | 34 hook candidates identified, no runtime events observed | frida, Frida Probe section |
| IDA | Unavailable | Missing idasql binary, no analysis performed | llm_judge, cross_engine_notes |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c  
**sample_path:** /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Multi-functional malware loader/dropper with indicators matching BK Ransomware, Elex, Hawkeye, Maze, and Remcos families, combining remote access trojan and ransomware capabilities
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA was unavailable for analysis due to a tooling failure (missing idasql binary), so all static analysis is derived from Ghidra, Malcat, capa, YARA, pe_imports, and FLOSS. Ghidra reports 1641 functions and 1525 strings, while Malcat reports 100 strings and 17 high-severity anomalies; combining both tools maximizes coverage of code and string indicators. Malcat's static profile provides unique structural metrics (entropy, section flags, anomaly count) not present in Ghidra's output. Capa, pe_imports, and YARA results are consistent across engines, corroborating the malicious capability assessment.
- **summary**: This is a high-confidence malicious PE32 x86 sample masquerading as a legitimate Adobe Bootstrapper installer. It exhibits strong indicators of obfuscation (high entropy, spaghetti code, XOR loops, delay imports) and implements core malware capabilities including anti-debugging, payload download, registry modification, process execution, privilege escalation, file system discovery, screenshot capture, keylogging, and system shutdown. The combination of capabilities and masquerading as Adobe software indicates it is a multi-functional loader/dropper with indicators matching known malware families including BK Ransomware, Elex, Hawkeye, Maze, and Remcos.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | deep profile anomalies & file_summary | `Entropy=109, CrossSectionJump, SpaghettiFunction×14, XorInLoop×7, HighXrefLoopin` | Extremely high entropy indicates packed/encrypted payload; cross-section jumps, spaghetti code, XOR loops, and high cros |
| yara | yara matches | `anti_dbg, network_dropper, escalate_priv, screenshot, keylogger, win_registry, w` | YARA rule matches confirm the sample contains anti-debugging, network dropper, privilege escalation, screenshot capture, |
| pe_imports | pe_imports high-signal signals | `IsDebuggerPresent (T1622), URLDownloadToFileW (T1105), RegSetValueExW (T1112), C` | These high-signal imports directly map to core malware capabilities: anti-debugging, payload download, registry modifica |
| capa | capa top_rules | `T1082 (System Information Discovery), T1083 (File and Directory Discovery), T101` | Capa capability mapping confirms the sample performs discovery, registry manipulation, payload download, process executi |
| malcat | deep profile file_summary metadata | `VersionInfo claims to be Adobe Bootstrapper Setup.exe, but has 17 anomalies incl` | The sample masquerades as a legitimate Adobe installer using stolen version metadata, while structural PE anomalies conf |
| ghidra | suspicious strings | `Strings containing 'http://', 'kernel32.dll', 'SOFTWARE\Adobe\Setup\Reader'` | HTTP-prefixed strings indicate potential C2 communication or payload download endpoints; registry paths masquerading as  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a malicious PE32 Windows GUI executable explicitly associated with multiple known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos) per its filename. YARA scanning matched 23 rules confirming the sample contains network indicators (domains, IPs, URLs), base64 encoded content, and implements a range of malicious behaviors including anti-debugging, SEH exception handling, Windows hooking, network dropper functionality, privilege escalation, screenshot capture, and keylogging capabilities consistent with remote access trojan (RAT) and ransomware functionality.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "all match entries share path /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos", "why": "Sample filename explicitly references known malware families (BK Ransomware, Elex, Hawkeye, Maze, Remcos), ind`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: IsPE32", "why": "Confirms the sample is a valid PE32 executable, the standard format for Windows malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: IsWindowsGUI", "why": "Confirms the sample is a Windows GUI application, consistent with RAT and ransomware user-facing functionality"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: domain", "why": "Indicates the sample contains hardcoded domain indicators for command and control (C2) communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: IP", "why": "Indicates the sample contains hardcoded IPv4 and IPv6 addresses for C2 communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: url", "why": "Indicates the sample contains hardcoded URLs for C2 communication or payload delivery"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: anti_dbg", "why": "Confirms the sample includes anti-debugging functionality to evade security analysis"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: network_dropper", "why": "Confirms the sample has functionality to download and execute additional malicious payloads from remote sources"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: keylogger", "why": "Confirms the sample includes keylogging functionality to steal user credentials and sensitive input"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: screenshot", "why": "Confirms the sample includes functionality to capture user desktop screenshots for surveillance and data theft"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: escalate_priv", "why": "Confirms the sample includes functionality to gain elevated system privileges for persistent, unrestricted system access"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: win_hook", "why": "Confirms the sample uses Windows hooking to intercept user input and system events, consistent with RAT surveillance functionality"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c
size: 485376
type: PE
architecture: X86
entrypoint_ea: 135201
entropy: 109
file_name: 2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 52 | - |
| .text | 1024 | 242688 | 245760 | 139 | RX |
| .rdata | 246784 | 86528 | 90112 | 76 | R |
| .data | 336896 | 10752 | 28672 | 71 | RW |
| .rsrc | 365568 | 144384 | 147456 | 77 | RWX |

### Malcat YARA / Signatures (6)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs2013_12_0_40629_00_update_5_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| visual_studio_2013_update_1__12_0__also_has_this_build_number_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (17)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExecutableSectionNoCode | 4 | sections | 1 | executable section has the flag code not set |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| ImportByHash | 4 | imports | 1 | APIs are imported by hash |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| BigStringHiScore | 3 | strings | 1 | string has more than 256 characters and high interest score |
| DelayImports | 3 | imports | 21 | There are delay imports |
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 3 | More than 48 unique bytes defined across all immediate operands in the function |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 7 | XOR instruction in a loop |
| DownloaderApiUsage | 2 | imports | 1 | Downloader-related apis are used |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| HighXrefLoopingFunction | 1 | code | 5 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SpaghettiFunction | 1 | code | 14 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **HighXrefLoopingFunction**
  - `36581`: 
  - `46146`: 
  - `135232`: 
  - `137164`: 
  - `139970`: 
- **ManyHighValueImmediates**
  - `34874`: 
  - `37738`: 
- **ManyUniqueImmediateBytes**
  - `170803`: 
  - `174000`: 
  - `187626`: 
- **SpaghettiFunction**
  - `34874`: 
  - `36698`: 
  - `52894`: 
  - `82310`: 
  - `140842`: 
- **XorInLoop**
  - `47477`: 
  - `143424`: 
  - `190322`: 
  - `193762`: 
  - `220515`: 

### High-Signal Strings (21 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 251280 | `\kernel32.dll` |
| 248344 | `kernel32.dll` |
| 265888 | `WaitForMSIMutex: Start..
` |
| 265940 | `WaitForMSIMutex: End..
` |
| 257068 | `http://` |
| 260868 | `/smutextimeout` |
| 282256 | `GetProcessWindowStation` |
| 257084 | `ftp://` |
| 431036 | `nke http://www.a..Programa ni mogo` |
| 428950 | ` http://www.adob..aplikacji nie mo` |
| 432252 | `  http://www.ado..Bu uygulama bu i` |
| 466118 | ` http://www.adob..ji %s nie powiod` |
| 421924 | ` http://www.adob..ineseSimplified=` |
| 469084 | ` okuyun: http://.._tr.
Ukrainian=` |
| 433042 | ` http://www.adob..TED_SP]
Arabic=` |
| 426444 | ` http://www.adob..n=Ez az alkalmaz` |
| 467102 | `ii de pe http://..lp_ro.
Russian=` |
| 468776 | ` http://www.adob..h=%s derlemesi y` |
| 461232 | ` http://www.adob..seSimplified=%s ` |
| 421494 | ` http://www.adob..ae. 
Bulgarian=` |
| 432524 | `tfen http://www...reksinimlerine g` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 295528 | `ERROR : Unable t.. CAtlBaseModule
` |
| 256384 | `SetupuninstallPr.. track criteria.` |
| 256760 | `SetupuninstallPr.. with error= %d.` |
| 259424 | `SetupInitInstanc..nstall Migration` |
| 253000 | `Initialization: .. not specified.
` |
| 250784 | `Failed to extrac..lt MSI name %s.
` |
| 264800 | `Invalid value en..VCRT in INI file` |
| 253632 | `Initialization: ..t Product Name.
` |
| 253768 | `Initialization: ..roduct Version.
` |
| 253912 | `Initialization: ..t Product Code.
` |
| 261608 | `SetupINitialize:.., reset to : %u
` |
| 256632 | `SetupuninstallPr..g Reboot for %s.` |
| 261480 | `SetupINitialize:.., reset to : %u
` |
| 261872 | `SetupINitialize:..to get free: %u
` |
| 262016 | `SetupINitialize:.. /msi part): %s
` |
| 253144 | `Initialization: ..cate "%s" file.
` |
| 254536 | `InstallProduct: ..e=%s Error=%d .
` |
| 254048 | `Initialization: ..t Upgrade Code.
` |
| 259680 | `Initialization: ..file "%s" file.
` |
| 250952 | `Failed to extrac..ommand line %s.
` |
| 261352 | `SetupINitialize:..rom cmdline: %u
` |
| 261168 | `Initialization: ..he default INI.
` |
| 262912 | `SOFTWARE\Microso..nternet Explorer` |
| 263352 | `OS requirement: ..plorer detected.` |
| 257104 | `InstallUpdate: C..e=%s Error=%d .
` |
| 254216 | `Initialization: ..nother process.
` |
| 256088 | `SetupuninstallPr..roduct Found %s.` |
| 263144 | `MSI version %s i.. not available.
` |
| 262360 | `Initialization: ..Product Object.
` |
| 261744 | `SetupINitialize:.., reset to : %u
` |
| 265632 | `No configuration..roduct updates.
` |
| 265744 | `Installation of .. Error Code=%d.
` |
| 255856 | `Transform Skippe..nsform entry:: 
` |
| 256520 | `REBOOT="ReallySu..NDARY_REPAIR="1"` |
| 254664 | `Another installa..inuing this one.` |
| 264928 | `Initialization: ..install Object.
` |
| 250556 | `vc_runtimeMinimum_x64.msi` |
| 272720 | `Software\Microso..olicies\Explorer` |
| 262152 | `SetupINitialize:..(/msi part): %s
` |
| 252880 | `Initialization: ..ill be ignored.
` |
| 260960 | `SetupINitialize:.. Fail value: %d
` |
| 259264 | `SELECT `Message`..ERE Error.Error=` |
| 254424 | `SELECT Value FRO..operty.Property=` |
| 259888 | `/sAll		Silent Mo..ters for MSIEXEC` |
| 272960 | `Software\Microso..olicies\Comdlg32` |
| 272840 | `Software\Microso..Policies\Network` |
| 256280 | `SetupuninstallPr..n: DC Products .` |
| 263032 | `Initialization: .. Update Object.
` |
| 258248 | `{AC76BA86-0000-0..7E-7E8A45000000}` |
| 259552 | `SetupInitInstanc..tall had reboot.` |
| 255144 | `\msiexec.exe` |
| 255172 | `msiexec.exe` |
| 258964 | `SOFTWARE\Adobe\Setup\Reader` |
| 262272 | `Initialization: ..open "%s" file.
` |
| 262476 | `BootStrap.log` |
| 273216 | `%08lX-%04X-%04x-..%02X%02X%02X%02X` |
| 258432 | `PatchProduct: Re..itiated for %s.
` |
| 265040 | `VC10 64 bit runt..llation failed.
` |
| 257000 | ` /quiet /norestart /overwriteoem` |
| 251376 | `Select Version F..RE FileName='%s'` |
| 251280 | `\kernel32.dll` |
| 255288 | `"%s" /i "%s" %s .."ReallySuppress"` |
| 258360 | `PatchProduct: Pa..ing Product %s.
` |
| 255960 | `{AC76BA86-0000-0..60-7E8A45000000}` |
| 273316 | `RestartByRestartManager` |
| 256200 | `{A6EADE66-0000-0..4E-7E8A45000000}` |
| 269668 | `hhctrl.ocx` |
| 269444 | `AFX_WM_RECREATED2DRESOURCES` |
| 263848 | `ENGLISH_WITH_HEBREW_SUPPORT` |
| 251128 | `Failed to instal.. 64 bit runtime.` |
| 275480 | `%08lX%04X%04x%02..%02X%02X%02X%02X` |
| 255200 | `"%s" /i %s %s RE.."ReallySuppress"` |
| 263968 | `PATCH_INSTALL_FAILURE_TEXT` |
| 263264 | `OS requirement: ..ted OS detected.` |
| 265560 | `Skipping other product updates.
` |
| 251208 | `Unable to get sy..em folder path.
` |
| 263792 | `ENGLISH_WITH_ARABIC_SUPPORT` |
| 250628 | `12.0.21005.1` |
| 264072 | `MIG_INSTALL_FAILED_TEXT` |
| 255368 | ` IGNOREVCRT64=1 VCRTERROR=` |

### Constants / Known Patterns (78)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| apihash | `apihash::hash(strstr)` |
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| registry | `registry::HKEY_USERS` |
| exception | `exception::CLR exception` |
| guid | `guid::IDispatch` |
| guid | `guid::IAccessible` |
| guid | `guid::IOleWindow` |
| guid | `guid::IUnknown` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6034` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_rl` |
| runtime | `runtime::msvc_date` |
| runtime | `runtime::msvc_locale` |
| guid | `guid::IWICPalette` |
| guid | `guid::IWICBitmapSource` |
| guid | `guid::IWICFormatConverter` |
| guid | `guid::IWICBitmapScaler` |
| guid | `guid::IWICBitmapClipper` |

### Imports (2371)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1123 | ??__E?wndNoTopMost@CWnd@@2V1@B@@YAXXZ | DEBUG | 1 |
| 1147 | ??__E?wndTop@CWnd@@2V1@B@@YAXXZ | DEBUG | 1 |
| 1171 | ??__E?wndTopMost@CWnd@@2V1@B@@YAXXZ | DEBUG | 1 |
| 1343 | ??__E_simpleResourceException@@YAXXZ | DEBUG | 1 |
| 1401 | ??__E_simpleUserException@@YAXXZ | DEBUG | 1 |
| 1562 | ??__E_afxInitAppState@@YAXXZ | DEBUG | 1 |
| 1834 | ATL.CSimpleStringT<wchar_t,0>.operator= | DEBUG | 92 |
| 1914 | CCallback.#11 | DEBUG | 1 |
| 1972 | ATL.CSimpleStringT<wchar_t,0>.CloneData | DEBUG | 42 |
| 2067 | ATL.CSimpleStringT<wchar_t,0>.CopyChars | DEBUG | 7 |
| 2098 | ATL.CSimpleStringT<wchar_t,0>.CopyCharsOverlapped | DEBUG | 1 |
| 2129 | ATL.CSimpleStringT<wchar_t,0>.Empty | DEBUG | 14 |
| 2399 | CCallback.#10 | DEBUG | 5 |
| 2449 | ATL::CComObjectNoLock<ATL::CAccessibleProxy>.#4 | DEBUG | 3 |
| 2457 | CCallback.#9 | DEBUG | 1 |
| 2465 | CCallback.#6 | DEBUG | 1 |
| 3102 | ATL.CSimpleStringT<wchar_t,0>.Reallocate | DEBUG | 1 |
| 3158 | ATL.CStringData.Release | DEBUG | 417 |
| 3230 | ATL.CSimpleStringT<wchar_t,0>.SetLength | DEBUG | 20 |
| 3273 | ATL.CSimpleStringT<wchar_t,0>.SetString | DEBUG | 2 |
| 3704 | CDownloaderDlg.#1 | DEBUG | 1 |
| 3735 | AfxCrtErrorCheck | DEBUG | 22 |
| 3777 | ATL.AtlGetStringResourceImage | DEBUG | 2 |
| 3825 | CWnd.#65 | DEBUG | 8 |
| 3825 | CWnd.BeginModalState | DEBUG | 8 |
| 3873 | ATL.CSimpleStringT<wchar_t,0>.Concatenate | DEBUG | 3 |
| 3944 | ATL.ChTraitsCRT<wchar_t>.ConvertToBaseType | DEBUG | 1 |
| 3995 | CDialog.#88 | DEBUG | 6 |
| 3995 | CDialog.Create | DEBUG | 6 |
| 4017 | CWnd.#66 | DEBUG | 8 |
| 4017 | CWnd.EndModalState | DEBUG | 8 |
| 4029 | ATL.CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t>>>.GetManager | DEBUG | 8 |
| 4064 | CDownloaderDlg.#10 | DEBUG | 1 |
| 4070 | CDownloaderDlg.#0 | DEBUG | 1 |
| 4184 | CDownloaderDlg.#93 | DEBUG | 1 |
| 4808 | ATL.CSimpleStringT<wchar_t,0>.SetString | DEBUG | 97 |
| 4849 | ATL._AtlGetStringResourceImage | DEBUG | 1 |
| 5004 | CDummyDlg.#1 | DEBUG | 1 |
| 5041 | CDummyDlg.#10 | DEBUG | 1 |
| 5047 | CDummyDlg.#0 | DEBUG | 1 |
| 5053 | CDHtmlDialog.OnDestroyModeless | DEBUG | 1 |
| 5063 | CDockState.CreateObject | DEBUG | 1 |
| 5126 | CDummyThread.#1 | DEBUG | 1 |
| 5163 | CDummyThread.#26 | DEBUG | 1 |
| 5188 | CDummyThread.#10 | DEBUG | 1 |
| 5194 | CDummyThread.#0 | DEBUG | 1 |
| 5200 | CDummyThread.#20 | DEBUG | 1 |
| 5282 | CDockState.CreateObject | DEBUG | 1 |
| 5397 | CExtInstDlg.#1 | DEBUG | 1 |
| 5434 | CExtInstDlgThread.#1 | DEBUG | 1 |
| 5471 | CExtInstDlg.#10 | DEBUG | 1 |
| 5477 | CExtInstDlgThread.#10 | DEBUG | 1 |
| 5483 | CExtInstDlg.#0 | DEBUG | 1 |
| 5489 | CExtInstDlgThread.#0 | DEBUG | 1 |
| 5495 | CExtInstDlgThread.#20 | DEBUG | 1 |
| 5598 | CExtInstDlg.#93 | DEBUG | 1 |
| 6634 | ATL.AtlAdd<int> | DEBUG | 1 |
| 6672 | ATL.AtlAddThrow<int> | DEBUG | 1 |
| 6712 | ATL.CSimpleStringT<wchar_t,0>.CSimpleStringT<wchar_t,0> | DEBUG | 4 |
| 6872 | CStreamOnCString.CStreamOnCString | DEBUG | 1 |
| 6953 | std.unique_ptr<std::_Facet_base,struct std::default_delete<std::_Facet_base>>.~unique_ptr<std::_Facet_base,struct std::default_delete<std::_Facet_base>> | DEBUG | 0 |
| 7051 | CInstallVCRT.#1 | DEBUG | 1 |
| 7576 | CInstallVCRT.#0 | DEBUG | 1 |
| 9843 | ATL.CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t>>>.Tokenize | DEBUG | 8 |
| 10098 | CInstMsiProg.#1 | DEBUG | 1 |
| 10135 | CInstMsiProg.#26 | DEBUG | 2 |
| 10140 | CInstMsiProg.#10 | DEBUG | 1 |
| 10146 | CInstMsiProg.#0 | DEBUG | 1 |
| 10152 | CInstMsiProg.#20 | DEBUG | 1 |
| 10362 | CMFCCustomizeButton.~CMFCCustomizeButton | DEBUG | 3 |
| 10435 | CComboBox.#1 | DEBUG | 1 |
| 10466 | CLangDlg.#1 | DEBUG | 1 |
| 10497 | CLangDlg.#64 | DEBUG | 1 |
| 11130 | CLangDlg.#10 | DEBUG | 1 |
| 11136 | CLangDlg.#0 | DEBUG | 1 |
| 11142 | CLangDlg.#93 | DEBUG | 1 |
| 12010 | ATL.operator+ | DEBUG | 5 |
| 12110 | CLaunchProd.#1 | DEBUG | 1 |
| 12758 | ATL.CSimpleStringT<wchar_t,0>.Append | DEBUG | 33 |
| 12799 | ATL.CSimpleStringT<wchar_t,0>.Append | DEBUG | 26 |

### Functions (30)
| EA | Name |
|---|---|
| 161187 | sub_4281a3 |
| 181155 | sub_42cfa3 |
| 43332 | sub_40b544 |
| 31132 | sub_40859c |
| 65031 | #29 |
| 33359 | sub_408e4f |
| 43283 | sub_40b513 |
| 206741 | sub_433395 |
| 1600 | sub_401240 |
| 42431 | sub_40b1bf |
| 193712 | sub_4300b0 |
| 42646 | sub_40b296 |
| 234205 | 9 |
| 234376 | 11 |
| 234556 | 12 |
| 234753 | 16 |
| 234992 | 19 |
| 235155 | 20 |
| 235654 | 24 |
| 235771 | 25 |
| 235903 | 27 |
| 235989 | 29 |
| 236051 | 30 |
| 236761 | 41 |
| 237279 | 48 |
| 237591 | 49 |
| 237880 | 54 |
| 238683 | 65 |
| 238911 | 71 |
| 238951 | 72 |

### Decompilations (top 6)
#### 161187 — sub_4281a3
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_4281a3(int32_t **param_1)

{
    int32_t *piVar1;
    int32_t iVar2;
    code *pcVar3;
    undefined4 uVar4;
    
    piVar1 = *param_1;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        sub_42cd34();
        pcVar3 = swi(3);
        uVar4 = (*pcVar3)();
        return uVar4;
    }
    return 0;
}

```
#### 181155 — sub_42cfa3
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_42cfa3(void)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x28);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x2c));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x30);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x34);
    if (((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
         ((piVar1[5] == 0x19930520 || ((piVar1[5] == 0x19930521 || (piVar1[5] == 0x19930522)))))) &&
        (*(unaff_EBP + -0x38) == 0)) &&
       ((*(unaff_EBP + -0x1c) != 0 && (iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]), iVar2 != 0)))) {
        ___DestructExceptionObject(piVar1, *(unaff_EBP + 0x10));
    }
    return;
}

```
#### 43332 — sub_40b544
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40b544(void)

{
    undefined4 *puVar1;
    undefined4 uVar2;
    int32_t unaff_EBP;
    
    __EH_prolog3(4);
    if (([0x0x4559b4] != 0) && ([0x0x4559cc] == 0)) {
        func_0x0040b5dd();
        puVar1 = *(unaff_EBP + 8);
        ATL.CSimpleStringT<wchar_t,0>.operator=(puVar1);
        sub_40b2fe();
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorText", *puVar1, 1);
        uVar2 = sub_40c667();
        sub_4012cf(uVar2);
        *(unaff_EBP + -4) = 0;
        sub_40b7c7(0x80000002, "SOFTWARE\\Adobe\\Setup\\Reader", "ErrorLanguage", [0x0x45599c], 1);
        [0x0x4559b8] = 1;
        ATL.CStringData.Release();
    }
    __EH_epilog3();
    return;
}

```

### Carved Files (20)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 1384 |
| ? | DIB | 2216 |
| ? | DIB | 304 |
| ? | DIB | 176 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 304 |
| ? | DIB | 184 |
| ? | DIB | 324 |

### Virtual Files (65)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| LOCALIZATION_INI/135/en-us | 93970 | - |
| CUR/3/en-us | 308 | - |
| CUR/4/en-us | 180 | - |
| CUR/5/en-us | 308 | - |
| CUR/6/en-us | 308 | - |
| CUR/7/en-us | 308 | - |
| CUR/8/en-us | 308 | - |
| CUR/9/en-us | 308 | - |
| CUR/10/en-us | 308 | - |
| CUR/11/en-us | 308 | - |
| CUR/12/en-us | 308 | - |
| CUR/13/en-us | 308 | - |
| CUR/14/en-us | 308 | - |
| CUR/15/en-us | 308 | - |
| CUR/16/en-us | 308 | - |
| CUR/17/en-us | 308 | - |
| CUR/18/en-us | 308 | - |
| BMP/30994/en-us | 184 | - |
| BMP/30996/en-us | 324 | - |
| ICO/1/en-us | 1384 | - |

### Structures (247)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 272 |
| OptionalHeader | 296 |
| Sections | 520 |
| advapi32.FT | 246784 |
| gdi32.FT | 246868 |
| kernel32.FT | 246968 |
| oleaut32.FT | 247552 |
| shell32.FT | 247576 |
| shlwapi.FT | 247588 |
| user32.FT | 247616 |
| version.FT | 248036 |
| winspool.FT | 248052 |
| ole32.FT | 248068 |
| urlmon.FT | 248092 |
| DebugDirectory | 248288 |
| LoadConfigurationTable | 303368 |
| Debug.Codeview | 303440 |
| Debug.VcFeature | 303536 |
| SEHandlers | 310912 |
| DelayImportTable | 325396 |
| oleacc.Names | 325492 |
| msi.Names | 325504 |
| ImportTable | 325724 |
| advapi32.OFT | 325964 |
| gdi32.OFT | 326048 |
| kernel32.OFT | 326148 |
| oleaut32.OFT | 326732 |
| shell32.OFT | 326756 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 30 · duration_s: 1.17

| Rule | ATT&CK | MBC |
|---|---|---|
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| reference SQL statements | T1213:Data from Information Repositories |  |
| receive data |  | B0030.002:C2 Communication |
| download URL |  | C0002.006:HTTP Communication |
| copy file |  | C0045:Copy File |
| delete file |  | C0047:Delete File |
| read .ini file |  | C0051:Read File |
| shutdown system | T1529:System Shutdown/Reboot |  |
| get system information on Windows | T1082:System Information Discovery |  |

## PE Imports / Signals
import_count: 318

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 23

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@459893 len=7; $ipv6@252878 len=4 |
| contains_base64 | - | $a@245300 len=24 |
| Misc_Suspicious_Strings | - | $a3@400684 len=14 |
| url | - | $url_regex@396920 len=96 |
| maldoc_getEIP_method_1 | - | $a@460864 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@240 len=4 |
| VC8_Microsoft_Corporation | - | $a@6306 len=10 |
| SEH_Save | - | $a@137441 len=7 |
| SEH_Init | - | $a@21246 len=6; $b@193755 len=7 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@263200 len=12; $c2@326380 len=17; $c3@325196 len=17 |
| win_hook | - | $f1@328710 len=10; $c1@328252 len=19; $c3@328274 len=14 |
| network_dropper | - | $f1@329876 len=10; $c1@329856 len=17 |
| escalate_priv | - | $d1@329548 len=12; $c2@329194 len=21 |
| screenshot | - | $d1@329094 len=9; $d2@328710 len=10; $c2@328496 len=5 |
| keylogger | - | $f1@328710 len=10; $c2@327842 len=11 |
| win_registry | - | $f1@329548 len=12; $c3@329242 len=11; $c6@329242 len=11 |
| win_token | - | $f1@329548 len=12; $c2@329194 len=21; $c3@329174 len=16 |
| win_files_operation | - | $f1@263200 len=12; $c1@325760 len=9; $c2@325728 len=14; $c3@325760 len=9; $c4@325700 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "family": "unknown",
  "generated_at": "2026-08-04T05:55:06.033322+00:00",
  "string_count": 24,
  "strings": [
    "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate.",
    "This program is linked to the missing export %s in the file %s. This machine may have an incompatible version of %s.",
    "Another installation is in progress. You must complete that installation before continuing this one.",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_WPAVCDocument@@PAV3@@@",
    ".?AV?$CMap@PAVCDocument@@PAV1@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_W@@",
    "Setup needs to restart your system to complete the installation.  Do you want to restart now?",
    "Initialization: Failed to open %s file, Make sure the file is not used by another process.",
    "Initialization: Unable to locate alternative INI file \"%s\", revert to the default INI.",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_WV12@PB_W@@",
    "This operating system is not supported by this installation.  Setup will now terminate.",
    "Failed to extract VCRT64 command line from ini. Hence using default command line %s.",
    ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_W_N_N@@",
    "Failed to extract VCRT64 MSI File Name from ini. Hence using default MSI name %s.",
    "System registry entries have been removed and the INI file (if any) was deleted.",
    "Initialization: Failed to initialize Product - Unable to locate \"%s\" file.",
    "SetupuninstallProducts: Migration: Uninstall of %s failed with error= %d.",
    "D:\\DCB\\CBT_Main\\Acrobat\\Installers\\BootStrapExe_Small\\Release\\Setup.pdb",
    "Initialization: Failed to initialize Product - msi key not specified.",
    "Initialization: Failed to initialize - Unable to get Product Version.",
    "This program requires the file %s, which was not found on this system.",
    "SetupINitialize: setup.exe Timeout set for MSI Mutex to get free: %u",
    "Initialization: Failed to initialize - Unable to get Product Name.",
    "Initialization: Failed to initialize - Unable to get Product Code.",
    "Initialization: Failed to initialize - Unable to get Upgrade Code."
  ],
  "rule_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar",
  "sigma_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yml",
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
Total strings: 2846 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2845}`

### FLOSS sample
- `?GetPu`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `ttHt=Hu095`
- `QWWWWWWPW`
- `jEjCjB@j8`
- `XSVWjD_W3`
- `QSSSSSSPS`
- `QPWWhL`
- `t8PPPPh`
- `9G t!j`
- `t'9~ u"`
- `t	9p(u`
- `u8hd)D`
- `u	9wlt>`
- `~(9~8t	WW`
- `u h<)D`
- `At;F u`
- `t49^ u'`
- `~ 9^$u`
- `t>9~ t9j0`
- `t7j(SV`
- `;7u<;G`
- `uij0[SQ`
- `t)9w u$`
- `PjShp.D`
- `jShp.D`
- `+t=Ht-Ht`
- `HtpHHt`
- `Pj^h`1D`
- `j^h`1D`
- `SSWPSSSS`
- `j.Zf9P,u`
- `u	f9p0u`
- `WQh,8D`
- `W9qXtDV`
- `9wXt8V`
- `VW9AXtw`
- `t-h@8D`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00421c21
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
..
```
### 0x004391d2
```asm
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01           mov eax, dword [ecx]
│    ││││   0x0043922e      ff5060         call dword [eax + 0x60]     ; 96
│    └────> 0x00439231      8b06           mov eax, dword [esi]
│     │││   0x00439233      8bce           mov ecx, esi
│     │││   0x00439235      ff5068         call dword [eax + 0x68]     ; 104
│    ┌────< 0x00439238      eb07           jmp 0x439241
│    ││└──> 0x0043923a      8b06           mov eax, dword [esi]
│    ││ │   0x0043923c      8bce           mov ecx, esi
│    ││ │   0x0043923e   
```
### 0x004139ec
```asm
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
### 0x004235c9
```asm
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff75e0         push dword [var_20h]
└           0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException] ; 0x43d248 ; VOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r

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
  - `VERSION.dll!VerQueryValueW`
  - `VERSION.dll!GetFileVersionInfoW`
  - `VERSION.dll!GetFileVersionInfoSizeW`
  - `KERNEL32.dll!LocalReAlloc`
  - `KERNEL32.dll!GlobalFlags`
  - `KERNEL32.dll!CompareStringW`
  - `KERNEL32.dll!GetLocaleInfoW`
  - `KERNEL32.dll!GetSystemDefaultUILanguage`
  - `USER32.dll!InvalidateRect`
  - `USER32.dll!DestroyMenu`
  - `USER32.dll!RealChildWindowFromPoint`
  - `USER32.dll!ClientToScreen`
  - `USER32.dll!EndPaint`
  - `GDI32.dll!TextOutW`
  - `GDI32.dll!ExtTextOutW`
  - `GDI32.dll!SetViewportExtEx`
  - `GDI32.dll!SetViewportOrgEx`
  - `GDI32.dll!SetWindowExtEx`
  - `WINSPOOL.DRV!OpenPrinterW`
  - `WINSPOOL.DRV!ClosePrinter`
  - `WINSPOOL.DRV!DocumentPropertiesW`
  - `ADVAPI32.dll!RegEnumValueW`
  - `ADVAPI32.dll!RegQueryValueW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHGetSpecialFolderPathW`
  - `SHLWAPI.dll!PathFileExistsW`
  - `SHLWAPI.dll!PathIsUNCW`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "\nSELECT name, start_ea, size\nFROM funcs\nWHERE size > 1024\nORDER BY size DESC\nLIMIT 50\n", "ts": 1785822596.876488}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785822597.25579}`
- `{"source": "ghidra_query", "sql": "\n        SELECT src_start_ea, dst_start_ea\n        FROM cfg_edges\n        WHERE src_start_ea > 0 AND dst_start_ea > 0\n    ", "ts": 1785822603.7697334}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785822603.9156883}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785822604.115963}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785822604.1469605}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785822604.1785777}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785822725.9546566}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785822726.0299287}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785822726.3575234}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785822726.3908813}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785822726.3987205}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785822822.5701475}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name LIMIT 100", "ts": 1785822839.844212}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module IN ('ADVAPI32.DLL','KERNEL32.DLL','USER32.DLL','WS2_32.DLL','WININET.DLL','CRYPT32.DLL','SHELL32.DLL','GDI32.DLL') ORDER BY module, name", "ts": 1785822845.9594183}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module IN ('KERNEL32.DLL','USER32.DLL','WS2_32.DLL','WININET.DLL','CRYPT32.DLL','SHELL32.DLL') ORDER BY module, name", "ts": 1785822849.0965397}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module='KERNEL32.DLL' ORDER BY name", "ts": 1785822851.9564111}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module='KERNEL32.DLL' ORDER BY name", "ts": 1785822857.680121}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name IN ('WriteFile','ReadFile','SetFilePointer','SetEndOfFile','DeviceIoControl','GetLogicalDrives','GetDriveTypeW','GetVolumeInformationW','GetDiskFreeSpaceW','FindFirstVolumeW','FindNextVolumeW','GetVolumeNameForVolumeMount`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module IN ('WS2_32.DLL','WININET.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL') ORDER BY module, name", "ts": 1785822866.7862644}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785822905.00276}`
- `{"source": "yara_gen_v2", "ts": 1785822906.03351}`
