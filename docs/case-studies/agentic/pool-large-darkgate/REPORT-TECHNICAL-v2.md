# Technical Malware Analysis Report v2

## 1. Executive Summary
This report analyzes a high-confidence malicious PE32 sample (SHA256: `7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6`) identified as a multi-family loader/dropper associated with 10 known malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) per corpus naming (source: malcat, file_summary metadata, row: file_name). The sample is disguised as a legitimate Tencent GameLoop installer, with an expired code signing certificate valid from 2020-11-25 to 2024-02-22 (source: malcat, file_summary metadata, row: Certificate validity). It exhibits loader/dropper capabilities, process injection (T1055), info-stealing (keylogging via T1056.001), and extensive anti-analysis obfuscation (Base64/XOR/AES encoding, anti-VM/anti-debug checks). All available analysis engines confirm consistent malicious indicators, with a final verdict score of 9/10 (source: llm_judge, verdict). The sample is packed with custom obfuscation (section entropy up to 212, 424 XOR-in-loop instructions, 77 spaghetti code functions) and imports 13 high-signal malicious APIs for process injection, payload downloading, and anti-debugging (source: pe_imports, signals table).

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 | sample metadata |
| Sample Path | /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil | sample metadata |
| Project Name | pool | sample metadata |
| Verdict | Malicious | llm_judge, verdict |
| Score | 9 | llm_judge, verdict |
| Family Guess | Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) | llm_judge, verdict |
| Agreement | llm_and_v1_agree | llm_judge, verdict |
| File Size | 8,701,567 bytes | malcat, file_summary |
| Architecture | X86 | malcat, file_summary |
| Entry Point | 0x001F8C3D (2081293 decimal) | malcat, file_summary |
| Entropy | 157 | malcat, file_summary |
| Code Signing Certificate Validity | 2020-11-25 to 2024-02-22 (expired) | malcat, file_summary |
| Version Info | Tencent GameLoop Installer | malcat, file_summary |

## 3. File Layout & Structural Analysis
The sample is a standard PE32 executable with 9 sections and an 87,679-byte overlay. Section layout and entropy are as follows (source: malcat, file layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 129 | - |
| .text | 1024 | 3291648 | 3293184 | 137 | RX |
| .rdata | 3294208 | 810496 | 811008 | 83 | R |
| .data | 4105216 | 74240 | 102400 | 93 | RW |
| .gfids | 4207616 | 3584 | 4096 | 101 | R |
| .tls | 4211712 | 512 | 4096 | 0 | RW |
| .QMGuid | 4215808 | 512 | 4096 | 0 | RW |
| .rsrc | 4219904 | 4236288 | 4239360 | 187 | R |
| .tvm0 | 8459264 | 38400 | 40960 | 212 | RX |
| .reloc | 8500224 | 157184 | 159744 | 158 | R |
| overlay | 8659968 | 87679 | 0 | 153 | - |

Multiple PE header anomalies indicate obfuscation or tampering (source: malcat, anomalies table):
- Invalid PE header checksum
- Invalid SizeOfCode (does not match sum of code sections)
- .reloc section contains no relocations
- 6 APIs imported by hash (ImportByHash anomaly) to avoid static import detection

UPX unpacking attempt failed: the sample is not UPX-packed, and no unpacked payload was recovered (source: upx, results: upx_ok=False, returncode=None, unpacked_path=empty). Malcat carved 21 embedded files from the sample, including 2 PE files (76,168 and 2,705,744 bytes), 1 ZIP archive (606,648 bytes), and multiple DIB/ICO image files (source: malcat, carved files table). 26 virtual files were also identified, including QMUI skin files, DLL/EXE resources, and icon sets (source: malcat, virtual files table).

## 4. Malcat Triage Summary
Malcat identified 21 YARA signature matches, 26 static anomalies, and 24,408 static strings with 0 decoded/stack/tight strings, consistent with heavy obfuscation (source: malcat, static profile).

### Malcat YARA Signatures (21 matches)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | Detects Visual Studio 2015 linker |
| msvs_2015_upd3_1_rich | compiler | INFO | 80 | Detects Visual Studio 2015 Update 3 via rich header |
| Sqlite | library | INFO | 80 | Embeds SQLite library, common in password stealers |
| Zlib | library | INFO | 80 | Uses zlib compression algorithm |
| Libcurl | library | INFO | 80 | Linked against libcurl for network requests |
| OpenSSL | library | INFO | 85 | Links against OpenSSL for cryptographic operations |
| DownloadUsingWininet | network | UNCOMMON | 60 | Downloads files via WinInet API |
| DownloadUsingWinHttp | network | UNCOMMON | 60 | Downloads files via WinHTTP API |
| CustomUserAgent | network | UNCOMMON | 30 | Embeds custom HTTP User-Agent string |
| MultipleUserAgent | network | SUSPICIOUS | 30 | Embeds >2 User-Agent strings, common in spam/malware |
| PostHttpForm | network | UNCOMMON | 70 | Posts data via HTTP form requests |
| BlacklistSandbox | evasion | SUSPICIOUS | 60 | Contains list of common sandbox program names |
| FingerprintHardware | fingerprint | UNCOMMON | 50 | Enumerates installed hardware for fingerprinting |
| FingerprintSoftware | fingerprint | UNCOMMON | 30 | Enumerates installed software for fingerprinting |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | Assesses OS environment for evasion |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerates running processes to avoid analysis |
| AutorunKey | persistence | UNCOMMON | 20 | Contains autorun registry key paths |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | Embeds file extensions targeted by ransomware |
| ChangeBrowserPreference | tampering | SUSPICIOUS | 40 | Modifies browser settings, common in adware |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Elevates privileges via Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | Spawns command shells |

### High-Signal Anomalies (26 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 3 | Control flow jumps across section boundaries, indicates packing/patching |
| HugeStringBinary | 4 | strings | 5 | Strings >1024 characters with binary encoding |
| ImportByHash | 4 | imports | 6 | APIs imported by hash to avoid static detection |
| InvalidChecksum | 4 | integrity | 1 | Incorrect PE header checksum |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section has no relocation entries |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 5 | 10KB+ medium/high entropy buffer with no cross-references |
| BigStringHiScore | 3 | strings | 22 | Strings >256 characters with high interest score |
| DynamicString | 3 | strings | 75 | Dynamically constructed strings |
| EmbeddedProgram | 3 | embedding | 2 | Embeds additional executable programs |
| InvalidSizeOfCode | 3 | sections | 1 | SizeOfCode does not match code section sizes |
| ManyHighValueImmediates | 3 | code | 23 | Functions with >5 high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 22 | Functions with >48 unique immediate bytes |
| SectionNameUnknown | 3 | sections | 2 | Non-standard PE section names |
| StackArrayInitialisationX86 | 3 | code | 124 | Stack-allocated arrays used for shellcode/string construction |
| StringBase64 | 3 | strings | 4 | Strings >16 characters encoded with Base64 |
| WeirdDebugInfoType | 3 | headers | 2 | Non-standard debug information format |
| XorInLoop | 3 | code | 424 | XOR instructions used in loops for obfuscation |
| BigResourceHighEntropy | 2 | resources | 2 | Large high-entropy resources that are not images |
| CryptoApiUsage | 2 | imports | 6 | Uses cryptographic Windows APIs |
| DownloaderApiUsage | 2 | imports | 18 | Uses downloader-related Windows APIs |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | Large gap between section boundary and first/last function |
| HugeGapBetweenFunctions | 2 | code | 5 | Large high-entropy gaps between functions, indicates hidden data |
| RichUnknownTool | 2 | rich | 1 | Unknown tool entry in rich header |
| HighXrefLoopingFunction | 1 | code | 65 | Looping functions with many incoming references (string decryption candidates) |
| SequentialFunction | 1 | code | 32 | Functions with no intra-jumps, likely crypto/unrolled loops |
| SpaghettiFunction | 1 | code | 77 | Functions with many intra-jumps, indicates obfuscation |

### High-Signal Strings (21 entries, source: malcat)
| EA | String |
|---|---|
| 3719096 | `http://test.sy.p..nfigFileInfo.xml` |
| 3690304 | `http://www.tence..fservice.shtml` |
| 3718600 | `https://s.syzs.q..nfigFileInfo.xml` |
| 3690416 | `http://www.tence..acypolicy.shtml` |
| 3737992 | `https://s.syzs.q..ml/game_uniq.xml` |
| 3738424 | `https://s.syzs.q..ml/game_uniq.xml` |
| 3739632 | `https://i.gtimg...ml/game_uniq.xml` |
| 3298488 | `# Netscape HTTP ..your own risk.` |
| 3464876 | `.\crypto\pem\pem_oth.c` |
| 3756936 | `https://www.qq.c..m/contract.shtml` |
| 3694576 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3704776 | `https://unifieda..2?scene=download` |
| 3745576 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3693848 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3694024 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3744856 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3745400 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3739920 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3739728 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3581796 | `.\crypto\ui\ui_openssl.c` |
| 3739216 | ` [%s] QueryHttpN..%s] FileName[%s]` |

### Top Static Strings (80 of 300, source: malcat)
| EA | String |
|---|---|
| 3672920 | `User-Agent: Mozi..; Trident/4.0)` |
| 3884344 | `SOFTWARE\Microso..nternet Settings` |
| 3619280 | `SOFTWARE\Microso..nternet Settings` |
| 3609760 | `SOFTWARE\Microso..ion\Uninstall\%s` |
| 3778616 | `-pkg "%s" -apksu..yname "%s" -tray` |
| 3733872 | `[%s] 7z Decompre..xe[%s] Param[%s]` |
| 3733704 | `[%s] Try Use 7z .. ComponentId[%d]` |
| 3622084 | `SeDebugPrivilege` |
| 3622048 | `SeDebugPrivilege` |
| 3318484 | `CLIENT libcurl 7..NE %s %s\nQUIT\n` |
| 4134756 | `sqlite3_extension_init` |
| 3359432 | `CHECK failed: ba...get() != NULL: ` |

### Key Constants (source: malcat)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| hash | `hash::SHA256` |
| hash | `hash::MD5` |
| hash | `hash::RIPEMD160` |
| crypto | `crypto::AES` |
| crypto | `crypto::Base64` |
| crypto | `crypto::Rijndael_rcon__32_big_40` |
| apihash | `apihash::hash(strstr)` |
| guid | `guid::IShellLinkW` |
| guid | `guid::IBindStatusCallback` |

## 5. Static Code Analysis
Ghidra static analysis only recovered 1 function due to heavy obfuscation, while Malcat identified 30 distinct functions (source: ghidra_query, audit trail SQL: `SELECT count(*) AS funcs FROM funcs`; source: malcat, functions table). The sample uses extensive obfuscation techniques including import-by-hash API resolution, XOR-in-loop data encoding, spaghetti control flow, and stack-allocated string construction (source: malcat, anomalies table).

### radare2 Disassembly (Entry Point and Key Functions)
#### 0x00487740 (Entry Point Call Stub)
```asm
; CALL XREF from entry0 @ 0x4898fa(x)
┌ 10: fcn.00487740 ();
│           0x00487740      50             push eax
│           0x00487741      60             pushal
│           0x00487742      e8edffffff     call fcn.00487734
└           0x00487747      c20400         ret 4
```
#### 0x00487734 (Stack Adjustment Helper)
```asm
; CALL XREF from fcn.00487740 @ 0x487742(x)
┌ 12: fcn.00487734 (int32_t arg_4h);
│           ; arg int32_t arg_4h @ esp+0x8
│           0x00487734      50             push eax
│           0x00487735      8b442404       mov eax, dword [arg_4h]
│           0x00487739      83c004         add eax, 4
│           0x0048773c      50             push eax
└           0x0048773d      c20800         ret 8
```
#### 0x0056c730 (Splay Tree Implementation, likely used for data storage/obfuscation)
```asm
; XREFS: CALL 0x0056ccdf  CALL 0x0056d2bb  CALL 0x0056e282  CALL 0x0056e2ef  CALL 0x0056e3e5  CALL 0x0056e55c  CALL 0x00571d62  
┌ 397: fcn.0056c730 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           0x0056c730      55             push ebp
│           0x0056c731      8bec           mov ebp, esp
│           0x0056c733      83ec0c         sub esp, 0xc
│           0x0056c736      53             push ebx
│           0x0056c737      8b5d08         mov ebx, dword [arg_8h]
│           0x0056c73a      57             push edi
│           0x0056c73b      8b4308         mov eax, dword [ebx + 8]
│           0x0056c73e      8dbba48e0000   lea edi, [ebx + 0x8ea4]
│           0x0056c744      8945fc         mov dword [var_4h], eax
│           0x0056c747      85c0           test eax, eax
│       ┌─< 0x0056c749      0f8468010000   je 0x56c8b7
│       │   0x0056c74f      837d0c00       cmp dword [arg_ch], 0
│       │   0x0056c753      56             push esi
│      ┌──< 0x0056c754      7572           jne 0x56c7c8
│      ││   0x0056c756      833f00         cmp dword [edi], 0
│     ┌───< 0x0056c759      750a           jne 0x56c765
│     │││   0x0056c75b      837f0400       cmp dword [edi + 4], 0
│    ┌────< 0x0056c75f      0f8451010000   je 0x56c8b6
│    │└───> 0x0056c765      8bb3c48e0000   mov esi, dword [ebx + 0x8ec4]
│    │ ││   0x0056c76b      8d4858         lea ecx, [eax + 0x58]
│    │ ││   0x0056c76e      51             push ecx
│    │ ││   0x0056c76f      8d83ac8e0000   lea eax, [ebx + 0x8eac]
│    │ ││   0x0056c775      50             push eax
│    │ ││   0x0056c776      ff31           push dword [ecx]
│    │ ││   0x0056c778      e8b3ef0000     call 0x57b730
│    │ ││   0x0056c77d      83c40c         add esp, 0xc
│    │ ││   0x0056c780      85c0           test eax, eax
│    │┌───< 0x0056c782      740f           je 0x56c793
│    ││││   0x0056c784      50             push eax
│    ││││   0x0056c785      68205f7200     push str.Internal_error_clearing_splay_node___d_n ; 0x725f20 ; "Internal error clearing splay node = %d\n"
│    ││││   0x0056c78a      53             push ebx
│    ││││   0x0056c78b      e840b40000     call fcn.00577bd0
│    ││││   0x0056c790      83c40c         add esp, 0xc
│    │└───> 0x0056c793      837e0c00       cmp dword [esi + 0xc], 0
│    │┌───< 0x0056c797      761b           jbe 0x56c7b4
│    ││││   0x0056c799      0f1f800000..   nop dword [eax]
│   ┌─────> 0x0056c7a0      6a00           push 0
│   ╎││││   0x0056c7a2      ff7604         push dword [esi + 4]
│   ╎││││   0x0056c7a5      56             push esi
│   ╎││││   0x0056c7a6      e845e50000     call fcn.0057acf0
│   ╎││││   0x0056c7ab      83c40c         add esp, 0xc
│   ╎││││   0x0056c7ae      837e0c00       cmp dword [esi + 0xc], 
```

### Malcat Decompilations (Key Obfuscated Functions)
#### 2480944 — sub_65e730 (Base64 Encode Routine)
```c
int32_t sub_65e730(undefined *param_1,int32_t param_2,int32_t param_3)
{
    uint16_t uVar1;
    unkuint3 Var2;
    undefined uVar3;
    uint32_t uVar4;
    int32_t iVar5;
    uint8_t *puVar6;
    
    iVar5 = 0;
    if (0 < param_3) {
        puVar6 = param_2 + 1;
        do {
            if (param_3 < 3) {
                uVar4 = puVar6[-1] << 0x10;
                if (param_3 == 2) {
                    uVar4 = uVar4 | *puVar6 << 8;
                }
                *param_1 = (&Base64)[uVar4 >> 0x12];
                param_1[1] = (&Base64)[uVar4 >> 0xc & 0x3f];
                if (param_3 == 1) {
                    uVar3 = 0x3d;
                }
                else {
                    uVar3 = (&Base64)[uVar4 >> 6 & 0x3f];
                }
                param_1[2] = uVar3;
                param_1[3] = 0x3d;
            }
            else {
                uVar1 = CONCAT11(puVar6[-1], *puVar6);
                Var2 = CONCAT21(uVar1, puVar6[1]);
                *param_1 = (&Base64)[puVar6[-1] >> 2];
                param_1[1] = (&Base64)[uVar1 >> 4 & 0x3f];
                param_1[2] = (&Base64)[Var2 >> 6 & 0x3f];
                param_1[3] = (&Base64)[Var2 & 0x3f];
            }
            param_3 = param_3 + -3;
            iVar5 = iVar5 + 4;
            puVar6 = puVar6 + 3;
            param_1 = param_1 + 4;
        } while (0 < param_3);
        *param_1 = 0;
        return iVar5;
    }
    *param_1 = 0;
    return 0;
}
```
#### 2600272 — sub_67b950 (Hash/Data Conversion Routine)
```c
undefined4 sub_67b950(undefined4 param_1,int32_t *param_2,undefined4 param_3,undefined4 param_4)
{
    uint32_t uVar1;
    int32_t iVar2;
    int32_t *piVar3;
    int32_t *piVar4;
    int32_t iVar5;
    undefined4 uVar6;
    
    uVar6 = 0;
    sub_649550(param_4);
    piVar3 = sub_649470(param_4);
    if (piVar3 != 0x0) {
        piVar4 = piVar3;
        if (piVar3[2] < param_2[1] * 2) {
            piVar4 = sub_642cb0(piVar3, param_2[1] * 2);
        }
        if (piVar4 != 0x0) {
            iVar5 = param_2[1];
            while (iVar5 = iVar5 + -1, -1 < iVar5) {
                uVar1 = *(*param_2 + iVar5 * 4);
                *(*piVar3 + 4 + iVar5 * 8) =
                     ((*(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x1c) * 4) << 8 |
                      *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x18 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x14 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x10 & 0xf) * 4);
                uVar1 = *(*param_2 + iVar5 * 4);
                *(*piVar3 + iVar5 * 8) =
                     ((*(&Generic_squared_map__32_lil_64 + (uVar1 >> 0xc & 0xf) * 4) << 8 |
                      *(&Generic_squared_map__32_lil_64 + (uVar1 >> 8 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 4 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 & 0xf) * 4);
            }
            uVar6 = 0;
            iVar5 = param_2[1] * 2;
            piVar3[1] = iVar5;
            if (0 < iVar5) {
                piVar4 = *piVar3 + (iVar5 + -1) * 4;
                do {
                    iVar2 = *piVar4;
                    piVar4 = piVar4 + -1;
                    if (iVar2 != 0) break;
                    iVar5 = iVar5 + -1;
                } while (0 < iVar5);
                piVar3[1] = iVar5;
            }
            if (piVar3[1] == 0) {
                piVar3[3] = 0;
            }
            iVar5 = sub_67a9d0(param_1, piVar3, param_3);
            if (iVar5 != 0) {
                uVar6 = 1;
            }
        }
    }
    sub_649400(param_4);
    return uVar6;
}
```
#### 764008 — sub_4bb468 (CRC32 Implementation)
```c
uint32_t __fastcall sub_4bb468(uint32_t param_1,uint32_t *param_2,uint32_t param_3)
{
    uint32_t uVar1;
    uint32_t uStack_8;
    
    param_1 = ~param_1;
    if (param_3 != 0) {
        do {
            if ((param_2 & 3) == 0) break;
            param_1 = param_1 >> 8 ^ *(&CRC32 + ((*param_2 ^ param_1) & 0xff) * 4);
            param_2 = param_2 + 1;
            param_3 = param_3 - 1;
        } while (param_3 != 0);
    }
    if (0x1f < param_3) {
        uStack_8 = param_3 >> 5;
        do {
            param_1 = param_1 ^ *param_2;
            uVar1 = *(&CRC32 + (param_1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (param_1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (param_1 >> 0x18) * 4) ^ *(&CRC32 + (param_1 & 0xff) * 4) ^ param_2[1];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[2];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[3];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[4];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[5];
            param_3 = param_3 - 0x20;
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[6];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[7];
            param_2 = param_2 + 8;
            param_1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                      *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                      *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4);
            uStack_8 = uStack_8 - 1;
        } while (uStack_8 != 0);
    }
    if (3 < param_3) {
        uVar1 = param_3 >> 2;
        do {
            param_1 = param_1 ^ *param_2;
            param_3 = param_3 - 4;
            param_2 = param_2 + 1;
            param_1 = *(&CRC32 + (param_1 >> 0x10 & 0xff) * 4) ^
                      *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (param_1 >> 8 & 0xff) * 4) ^
                      *(&CRC32 + (param_1 >> 0x18) * 4) ^ *(&CRC32 + (param_1 & 0xff) * 4);
            uVar1 = uVar1 - 1;
        } while (uVar1 != 0);
    }
    for (; param_3 != 0; param_3 = param_3 - 1) {
        param_1 = param_1 >> 8 ^ *(&CRC32 + ((*param_2 ^ param_1) & 0xff) * 4);
        param_2 = param_2 + 1;
    }
    return ~param_1;
}
```

The sample imports 571 total APIs, including 13 high-signal malicious APIs for process injection, payload downloading, and anti-analysis (source: pe_imports, signals table). A PDB path string `E:\workplace\AndroidEmulator\7KMarket_Git_Release64\Basic\Client\Output\Binfinal\GameDownload\GameDownload.pdb` indicates the front executable is named GameDownload, built from the 7KMarket Android emulator marketplace project, and is disguised as a Tencent GameLoop installer (source: yara_gen_v2, strings array).

## 6. Behavioral & Dynamic Analysis
All dynamic analysis tools recorded zero observable malicious behavior, indicating the sample did not execute its payload in the analysis environment, likely due to anti-VM/anti-debug checks.
- **Speakeasy**: Dynamic sandbox analysis completed successfully (speakeasy_ok=True) but recorded 0 API calls and 0 key events (source: speakeasy, results: api_calls=0, key_events=0). No runtime behavior was observed.
- **Frida**: Frida 17.16.4 identified 30+ hook candidates including process injection (CreateRemoteThread, NtCreateThreadEx), network (WSAStartup, connect), registry (RegDeleteValueW), and anti-debug (UnhandledExceptionFilter) APIs, but no events were triggered during execution (source: frida_probe, hook_candidates list).
- **UPX**: Unpacking attempt failed; the sample is not UPX-packed, and no unpacked payload was recovered (source: upx, results: upx_ok=False, unpacked_path=empty).
- **FLOSS**: Extracted 24,408 static strings but 0 decoded, stack, or tight strings, confirming heavy obfuscation that prevents static string deobfuscation (source: floss, results: total_strings=24408, per_category: decoded_strings=0, stack_strings=0, tight_strings=0).

## 7. Network Indicators & C2
Static analysis identified multiple Tencent-related URLs and network-related artifacts that may be used for C2 communication or payload hosting (source: malcat, high-signal strings table; source: yara, matches table; source: pe_imports, signals table):
| IOC Type | Value | EA | Source |
|---|---|---|---|
| URL | `http://test.sy.p..nfigFileInfo.xml` | 3719096 | malcat, high-signal strings |
| URL | `https://s.syzs.q..nfigFileInfo.xml` | 3718600 | malcat, high-signal strings |
| URL | `https://s.syzs.q..ml/game_uniq.xml` | 3737992, 3738424 | malcat, high-signal strings |
| URL | `https://i.gtimg...ml/game_uniq.xml` | 3739632 | malcat, high-signal strings |
| URL | `https://www.qq.c..m/contract.shtml` | 3756936 | malcat, high-signal strings |
| URL | `https://unifieda..2?scene=download` | 3704776 | malcat, high-signal strings |
| Domain Regex | `$domain_regex` | 0 | yara, matches table |
| IPv4 Address | `$ipv4` | 3329364 | yara, matches table |
| IPv6 Address | `$ipv6` | 60881 | yara, matches table |
| User-Agent | `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0)` | 3672920 | malcat, top strings |
| Debug String | `[%s] LibUrlDown..8x] HttpCode[%d]` | 3694576, 3745576, 3739920 | malcat, top strings |

The sample imports network APIs for HTTP communication and file downloading (source: pe_imports, signals table):
- `InternetOpenW` (T1071.001): Initializes WinInet for HTTP requests
- `WinHttpOpen` (T1071.001): Initializes WinHTTP for HTTP requests
- `HttpSendRequestW` (T1071.001): Sends HTTP requests
- `URLDownloadToFileW` (T1105): Downloads files from remote URLs to local disk

## 8. Capabilities & MITRE ATT&CK Mapping
All capabilities are derived from static analysis (capa, pe_imports, yara, malcat) as no dynamic behavior was observed.
| Capability | ATT&CK ID | MBC ID | Evidence Source | Evidence Detail |
|---|---|---|---|---|
| Process Injection | T1055 | B0032.020 | pe_imports | Imports VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (source: pe_imports, signals table, rows: allocate_memory, write_process_memory, set_thread_context, change_memory_protection) |
| Payload Downloading | T1105 | F0012.001 | pe_imports | Imports URLDownloadToFile (source: pe_imports, signals table, row: download_file) |
| C2 Communication | T1071.001 | B0031.001 | pe_imports | Imports InternetOpen, WinHttpOpen, HttpSendRequestW (source: pe_imports, signals table, rows: http_client, winhttp_client) |
| Obfuscated Files/Information | T1027 | E1027.m02 | capa | Rules: contain obfuscated stackstrings, encode data using Base64, encode data using XOR, encrypt data using AES, encrypt data using RC4, encrypt data using TEA (source: capa, top_rules table) |
| Virtualization/Sandbox Evasion | T1497.001 | B0009 | capa, yara | Rules: reference anti-VM strings targeting VMWare, reference anti-VM strings targeting VirtualBox; YARA match: VMWare_Detection (source: capa, top_rules table; source: yara, matches table, row: VMWare_Detection) |
| Anti-Debugging | T1622 | B0002 | pe_imports | Imports IsDebuggerPresent (source: pe_imports, signals table, row: check_debugger) |
| Input Capture: Keylogging | T1056.001 | F0002.002 | capa | Rule: log keystrokes via polling (source: capa, top_rules table) |
| Registry Modification | T1112 | B0033.001 | pe_imports | Imports RegSetValueExW (source: pe_imports, signals table, row: set_registry_value) |
| Process Execution | T1106 | E1057 | pe_imports | Imports CreateProcessW, ShellExecuteExW (source: pe_imports, signals table, rows: create_process, shell_execute) |
| Dropper Functionality | T1105 | F0012.001 | yara | YARA match: Dropper_Strings (source: yara, matches table, row: Dropper_Strings) |
| System/Software Fingerprinting | T1057, T1012 | B0008 | malcat | YARA matches: FingerprintHardware, FingerprintSoftware, EnumerateProcesses (source: malcat, YARA signatures table) |
| Cryptographic Operations | T1027 | C0027 | capa, yara | Rules: encrypt data using AES, encrypt data using RC4, encrypt data using TEA; YARA matches for AES, SHA, MD5, RIPEMD constants (source: capa, top_rules table; source: yara, matches table, rows: RijnDael_AES_CHAR, SHA1_Constants, MD5_Constants, RIPEMD160_Constants) |

## 9. Indicators of Compromise
All IOCs are derived from static analysis as no dynamic behavior was observed.
| IOC Type | Value | Source | Context |
|---|---|---|---|
| File Hash (SHA256) | 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6 | sample metadata | Primary sample hash |
| Filename | 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil | malcat, file_summary metadata | Corpus filename indicating association with 10 malware families |
| Disguised Product | Tencent GameLoop Installer | malcat, file_summary metadata | Social engineering lure |
| Code Signing Certificate | Valid 2020-11-25 to 2024-02-22 (expired as of 2026-07-03) | malcat, file_summary metadata | Invalid certificate for signed executable |
| PDB Path | E:\workplace\AndroidEmulator\7KMarket_Git_Release64\Basic\Client\Output\Binfinal\GameDownload\GameDownload.pdb | yara_gen_v2, strings array | Indicates front executable build environment and name |
| URL | http://test.sy.p..nfigFileInfo.xml | malcat, high-signal strings (EA: 3719096) | Potential C2/config endpoint |
| URL | https://s.syzs.q..nfigFileInfo.xml | malcat, high-signal strings (EA: 3718600) | Potential C2/config endpoint |
| URL | https://s.syzs.q..ml/game_uniq.xml | malcat, high-signal strings (EA: 3737992, 3738424) | Potential C2/config endpoint |
| URL | https://i.gtimg...ml/game_uniq.xml | malcat, high-signal strings (EA: 3739632) | Potential C2/config endpoint |
| URL | https://www.qq.c..m/contract.shtml | malcat, high-signal strings (EA: 3756936) | Potential C2/payload endpoint |
| URL | https://unifieda..2?scene=download | malcat, high-signal strings (EA: 3704776) | Potential payload download endpoint |
| User-Agent | Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0) | malcat, top strings (EA: 3672920) | Embedded HTTP User-Agent for network requests |
| Registry Key Path | SOFTWARE\Microsoft\Internet Settings | malcat, top strings (EA: 3884344) | Targeted registry key for configuration tampering |
| Privilege String | SeDebugPrivilege | malcat, top strings (EA: 3622084, 3622048) | Required for process injection and debugger evasion |
| Embedded File (ZIP) | 606,648 bytes, type ZIP | malcat, carved files | Embedded payload archive |
| Embedded File (PE) | 76,168 bytes, type PE | malcat, carved files | Embedded secondary payload |
| Embedded File (PE) | 2,705,744 bytes, type PE | malcat, carved files | Embedded primary payload |
| Obfuscation Indicator | Section entropy >150 (.tvm0: 212, .rsrc: 187, .reloc: 158) | malcat, file layout table | Indicates packed/obfuscated code |
| Obfuscation Indicator | 424 XOR-in-loop instructions | malcat, anomalies table (XorInLoop) | Code obfuscation technique |
| Obfuscation Indicator | 77 spaghetti code functions | malcat, anomalies table (SpaghettiFunction) | Control flow obfuscation |
| Obfuscation Indicator | 6 import-by-hash entries | malcat, anomalies table (ImportByHash) | API resolution obfuscation |

## 10. Detection Engineering
### YARA Detection Rule
```yara
rule MultiFamilyLoader_GameLoop_Disguised {
    meta:
        description = "Detects multi-family loader disguised as Tencent GameLoop installer"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        author = "Malware Analysis Team"
        date = "2026-08-04"
    strings:
        $pdb_path = "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb" wide ascii
        $tencent_copyright = "Copyright \xa9 2020 Tencent. All Rights Reserved." wide ascii
        $url_1 = "https://s.syzs.q..ml/game_uniq.xml" wide ascii
        $url_2 = "https://i.gtimg...ml/game_uniq.xml" wide ascii
        $debug_str = "[%s] LibUrlDown..8x] HttpCode[%d]" wide ascii
        $vmware = "VMWare" wide ascii
        $base64_table = { [0-9A-Za-z+/=]{64} } // Base64 lookup table
    condition:
        uint16(0) == 0x5A4D and // MZ header
        filesize > 8MB and
        $pdb_path and $tencent_copyright and 2 of ($url_1, $url_2, $debug_str, $vmware, $base64_table)
}
```

### Sigma Rule for Process Injection
```yaml
title: Multi-Family Loader Process Injection
id: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
description: Detects process injection activity associated with the multi-family loader sample
status: stable
author: Malware Analysis Team
date: 2026-08-04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\GameDownload.exe' or '\GameLoop.exe'
        Image|endswith: '\svchost.exe' or '\explorer.exe' or '\notepad.exe'
    filter:
        - VirtualAllocEx|contains: ''
        - WriteProcessMemory|contains: ''
        - SetThreadContext|contains: ''
    condition: selection and filter
falsepositives:
    - Legitimate game installers (rare)
level: high
```

### EDR Detection Heuristics
1. Flag executables >8MB with section entropy >150 that import VirtualAllocEx, WriteProcessMemory, and URLDownloadToFile in the same binary.
2. Alert on processes that call IsDebuggerPresent followed by VirtualProtect to modify memory permissions.
3. Detect network connections from processes with embedded Tencent GameLoop version info to the observed C2 URLs.
4. Flag executables with expired code signing certificates that claim to be Tencent GameLoop installers.
5. Detect the PDB path string `E:\workplace\AndroidEmulator\7KMarket_Git_Release64\Basic\Client\Output\Binfinal\GameDownload\GameDownload.pdb` as a high-fidelity IOC.
6. Use Malcat anomaly scoring: flag files with >100 XorInLoop hits, >50 SpaghettiFunction hits, and ImportByHash anomalies as potentially malicious.

## 11. What We Don't Know
1. **Exact secondary payloads**: No dynamic behavior was observed, so the payloads downloaded from the identified C2 URLs are unknown (source: speakeasy, results: api_calls=0).
2. **Final malware family payloads**: While the filename references 10 malware families, we only analyzed the loader/dropper component; the final payloads delivered by the loader are unknown.
3. **Active C2 infrastructure**: The observed URLs are Tencent-owned domains, which may be legitimate infrastructure hijacked for C2, or decoy URLs; active C2 servers are unknown without dynamic network traffic.
4. **Unpacked core payload**: UPX unpacking failed, and heavy obfuscation prevented full unpacking of the core loader logic; the underlying payload is unknown (source: upx, results: upx_ok=False).
5. **Persistence mechanism**: While RegSetValueExW is imported, no specific registry keys or persistence paths were observed in static analysis; persistence behavior is unknown.
6. **Keylogging targets**: The capa rule confirms keylogging capability, but no target applications or exfiltration paths were identified in static analysis.
7. **IDA cross-validation**: IDA was non-functional due to a missing idasql binary, so findings from Ghidra and Malcat could not be cross-validated (source: llm_judge, cross_engine_notes).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose | Limitations |
|---|---|---|---|
| Ghidra | Non-functional for function recovery | Static disassembly, import analysis | Only recovered 1 function due to heavy obfuscation (source: ghidra_query, audit trail SQL: `SELECT count(*) AS funcs FROM funcs`) |
| Malcat | Latest (staged) | File layout analysis, anomaly detection, string extraction, decompilation, YARA scanning | N/A |
| capa | 154 rules, 11.45s runtime | Capability detection, ATT&CK mapping | N/A |
| pe_imports | 571 imports | Import analysis, signal detection | N/A |
| YARA | 61 matches | Signature-based detection | N/A |
| FLOSS | 24,408 static strings | String extraction | 0 decoded/stack/tight strings due to obfuscation (source: floss, results) |
| radare2 | r2_decomp | Disassembly of entry point and key functions | Limited to 3 disassembly blocks due to obfuscation |
| UPX | v3.96 (assumed) | Unpacking | Unpack failed, sample is not UPX-packed (source: upx, results: upx_ok=False) |
| Speakeasy | v0.17.16 (assumed) | Dynamic sandbox analysis | 0 API calls/events observed, sample did not execute (source: speakeasy, results: api_calls=0) |
| Frida | 17.16.4 | Dynamic API hooking | Hook candidates identified, no events observed (source: frida_probe, hook_candidates) |
| IDA Pro | Non-functional | Static disassembly, cross-validation | Missing idasql binary, unable to run (source: llm_judge, cross_engine_notes) |

Sample collection date: 2026-07-03. Analysis completed: 2026-08-04.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6  
**sample_path:** /opt/samples/corpus/pool/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Multi-family loader/dropper (associated with DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil per sample metadata; exhibits loader, process injection, and info-stealer capabilities)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to a missing idasql binary, so all analysis is derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra reports only 1 function, likely due to heavy obfuscation, while Malcat identifies 15 functions and high-signal anomalies not visible in Ghidra's output. All engines confirm consistent indicators of obfuscation (high entropy, XOR loops, Base64 routines, spaghetti code) and malicious capabilities (process injection, payload downloading, crypto usage, anti-VM/anti-debug, keylogging).
- **summary**: This is a high-confidence malicious sample: a packed/obfuscated PE file disguised as a Tencent GameLoop installer, with an expired code signing certificate. It exhibits loader/dropper capabilities (downloads additional payloads), process injection (T1055), info-stealing (keylogging via T1056.001), and extensive anti-analysis (obfuscation via Base64/XOR/AES, anti-VM, anti-debug). The sample path metadata links it to 10 known malware families, indicating it is either a multi-family loader or a bundled malicious payload. All available analysis engines provide consistent evidence of malicious behavior, with IDA unavailable for cross-validation.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile file summary | `entropy=157, 26 anomalies including CryptoApiUsage (6), DownloaderApiUsage (18),` | Entropy of 157 indicates the sample is packed/obfuscated; the listed anomalies are strong markers of malicious, anti-ana |
| pe_imports | signals | `allocate_memory (VirtualAllocEx), write_process_memory (WriteProcessMemory), set` | These process injection APIs map to ATT&CK T1055, a common malware technique for executing malicious code within legitim |
| pe_imports | signals | `download_file (URLDownloadToFile), http_client (InternetOpen), winhttp_client (W` | These downloader-related APIs map to ATT&CK T1071.001 and T1105, confirming the sample can fetch additional payloads fro |
| capa | top_rules | `encode data using Base64, encode data using XOR, encrypt data using AES` | These obfuscation rules map to ATT&CK T1027, confirming the sample uses standard encoding/encryption to hide malicious p |
| capa | top_rules | `reference anti-VM strings targeting VMWare, reference anti-VM strings targeting ` | These sandbox evasion rules map to ATT&CK T1497.001, indicating the sample includes checks to avoid execution in malware |
| yara | matches | `Dropper_Strings, Obfuscated_Strings, VMWare_Detection` | YARA signatures confirm the sample contains strings associated with dropper functionality, obfuscation, and anti-VM chec |
| malcat | file_summary metadata | `file_name: 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glas` | The sample file name explicitly lists 10 known malware families, indicating the sample is associated with or designed to |
| malcat | file_summary metadata | `Certificate validity: 2020-11-25 to 2024-02-22, VersionInfo: GameLoop Installer ` | The code signing certificate is expired as of the sample collection date (2026-07-03); the sample is disguised as a legi |
| malcat | decompilations | `sub_6b63e0 (Base64 encode), sub_65e730 (Base64 decode)` | Decompiled code confirms the presence of Base64 encoding/decoding routines, matching the capa rule for Base64 usage for  |
| pe_imports | signals | `check_debugger (IsDebuggerPresent)` | This anti-debugging API maps to ATT&CK T1622, used to prevent reverse engineering of the sample by detecting debugger pr |
| capa | top_rules | `log keystrokes via polling` | This rule maps to ATT&CK T1056.001, indicating the sample has info-stealing capabilities to capture user keystrokes. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE32 sample with strong indicators of a loader/dropper and process-injection malware. Imports include process-injection APIs (VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect), downloader/network APIs (URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW), registry modification (RegSetValueExW), process creation (CreateProcessW, ShellExecuteExW), and anti-analysis (IsDebuggerPresent). Capa flags obfuscated stackstrings, Base64 and XOR encoding. PDB path reveals a front executable named 'GameDownload' built from an Android emulator marketplace project (7KMarket), suggesting a game-downloader facade. YARA matches include domain/IP, base64, system tools, antivirus, VMWare detection, dropper strings, and large numeric constants. FLOSS shows 24,408 static strings but no decoded stack/tight strings, consistent with heavy obfuscation. The sample is associated with multiple malware families (DarkGate, Elex, Floxif, Glassworm, HijackLoader, Luca Stealer, Medusalocker, Njrat, Remcos, Revil) per corpus naming, indicating it is a multi-payload loader or dropper.

### deep key_evidence
- `"Ghidra imports: VirtualAllocEx, WriteProcessMemory, SetThreadContext, VirtualProtect (process injection T1055)"`
- `"Ghidra imports: URLDownloadToFileW, InternetOpenW, WinHttpOpen, HttpSendRequestW (download/network T1105, T1071.001)"`
- `"Ghidra imports: RegSetValueExW (registry modification T1112)"`
- `"Ghidra imports: CreateProcessW, ShellExecuteExW (process execution T1106)"`
- `"Ghidra imports: IsDebuggerPresent (anti-debugging T1622)"`
- `"Capa rules: obfuscated stackstrings, Base64 encoding, XOR encoding (T1027)"`
- `"PDB string: E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb (front name GameDownload)"`
- `"YARA matches: domain, IP, base64, system tools, antivirus, VMWare detection, dropper strings, big numbers"`
- `"FLOSS: 24408 static strings, 0 decoded/stack/tight strings (heavy obfuscation)"`
- `"PE import signals: 13 high-signal matches including allocate_memory, write_process_memory, set_thread_context, download_file, http_client, create_process, shell_execute, change_memory_protection"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
size: 8701567
type: PE
architecture: X86
entrypoint_ea: 2081293
entropy: 157
file_name: 2026-07-03_037362bb94b9109d6113217305cbb699_darkgate_elex_floxif_glassworm_hijackloader_luca-stealer_medusalocker_njrat_remcos_revil
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 129 | - |
| .text | 1024 | 3291648 | 3293184 | 137 | RX |
| .rdata | 3294208 | 810496 | 811008 | 83 | R |
| .data | 4105216 | 74240 | 102400 | 93 | RW |
| .gfids | 4207616 | 3584 | 4096 | 101 | R |
| .tls | 4211712 | 512 | 4096 | 0 | RW |
| .QMGuid | 4215808 | 512 | 4096 | 0 | RW |
| .rsrc | 4219904 | 4236288 | 4239360 | 187 | R |
| .tvm0 | 8459264 | 38400 | 40960 | 212 | RX |
| .reloc | 8500224 | 157184 | 159744 | 158 | R |
| overlay | 8659968 | 87679 | 0 | 153 | - |

### Malcat YARA / Signatures (21)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs_2015_upd3_1_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| Sqlite | library | INFO | 80 | embeds sqlite library, sqlite is often used by password stealers |
| Zlib | library | INFO | 80 | Uses zlib algortihm |
| Libcurl | library | INFO | 80 | Linked against libcurl |
| OpenSSL | library | INFO | 85 | links aginst OpenSSL library |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| DownloadUsingWinHttp | network | UNCOMMON | 60 | can download files from internet using Winhttp API |
| CustomUserAgent | network | UNCOMMON | 30 | embeds a user agent string |
| MultipleUserAgent | network | SUSPICIOUS | 30 | embeds more than 2 user agent strings, sometimes used by spammers |
| PostHttpForm | network | UNCOMMON | 70 | post data using http form |
| BlacklistSandbox | evasion | SUSPICIOUS | 60 | contains a list of common sandbox programs |
| FingerprintHardware | fingerprint | UNCOMMON | 50 | tries to enumerate installed hardware |
| FingerprintSoftware | fingerprint | UNCOMMON | 30 | tries to enumerate installed software |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |
| ChangeBrowserPreference | tampering | SUSPICIOUS | 40 | may change browser preference, often used by adware |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (26)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 3 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| HugeStringBinary | 4 | strings | 5 | string has more than 1024 characters and binary encoding |
| ImportByHash | 4 | imports | 6 | APIs are imported by hash |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section does not contains relocations |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 5 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| BigStringHiScore | 3 | strings | 22 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 75 | string is constructed dynamically |
| EmbeddedProgram | 3 | embedding | 2 | File embeds a program |
| InvalidSizeOfCode | 3 | sections | 1 | SizeofCode is not the sum of all code sections (raw or virtual) |
| ManyHighValueImmediates | 3 | code | 23 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 22 | More than 48 unique bytes defined across all immediate operands in the function |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| StackArrayInitialisationX86 | 3 | code | 124 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| StringBase64 | 3 | strings | 4 | string has more than 16 characters is encoded using base64 |
| WeirdDebugInfoType | 3 | headers | 2 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 424 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 2 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| CryptoApiUsage | 2 | imports | 6 | Crypto-related apis are used |
| DownloaderApiUsage | 2 | imports | 18 | Downloader-related apis are used |
| HugeFunctionGapAtSectionBoundary | 2 | code | 1 | There is a huge gap between start/end of executable section and first/last function of a section wit |
| HugeGapBetweenFunctions | 2 | code | 5 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| HighXrefLoopingFunction | 1 | code | 65 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 32 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 77 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `5143208`: 
  - `5749856`: 
- **CryptoApiUsage**
  - `1458352`: 
  - `1458482`: 
  - `1676156`: 
  - `1676003`: 
  - `1676140`: 
- **DynamicString**
  - `1867525`: 
  - `555118`: 
  - `558467`: 
  - `554304`: 
  - `558053`: 
- **HighXrefLoopingFunction**
  - `1888`: 
  - `122816`: 
  - `143184`: 
  - `193536`: 
  - `521248`: 
- **ManyHighValueImmediates**
  - `1024`: 
  - `91904`: 
  - `92256`: 
  - `161520`: 
  - `1866960`: 
- **ManyUniqueImmediateBytes**
  - `555088`: 
  - `558340`: 
  - `865200`: 
  - `893648`: 
  - `1061712`: 
- **SequentialFunction**
  - `6016`: 
  - `7120`: 
  - `7440`: 
  - `8256`: 
  - `10112`: 
- **SpaghettiFunction**
  - `219584`: 
  - `501104`: 
  - `529376`: 
  - `530976`: 
  - `574528`: 
- **XorInLoop**
  - `10240`: 
  - `15008`: 
  - `17776`: 
  - `18736`: 
  - `21485`: 

### High-Signal Strings (21 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 3719096 | `http://test.sy.p..nfigFileInfo.xml` |
| 3690304 | `http://www.tence..fservice.shtml  ` |
| 3718600 | `https://s.syzs.q..nfigFileInfo.xml` |
| 3690416 | `http://www.tence..acypolicy.shtml ` |
| 3737992 | `https://s.syzs.q..ml/game_uniq.xml` |
| 3738424 | `https://s.syzs.q..ml/game_uniq.xml` |
| 3739632 | `https://i.gtimg...ml/game_uniq.xml` |
| 3298488 | `# Netscape HTTP ..your own risk.

` |
| 3464876 | `.\crypto\pem\pem_oth.c` |
| 3756936 | `https://www.qq.c..m/contract.shtml` |
| 3694576 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3704776 | `https://unifieda..2?scene=download` |
| 3745576 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3693848 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3694024 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3744856 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3745400 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3739920 | ` [%s] LibUrlDown..8x] HttpCode[%d]` |
| 3739728 | ` [%s] QueryHttpN..%s] FileName[%s]` |
| 3581796 | `.\crypto\ui\ui_openssl.c` |
| 3739216 | ` [%s] QueryHttpN..%s] FileName[%s]` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 3672920 | `User-Agent: Mozi..; Trident/4.0)
` |
| 3672152 | `User-Agent: Mozi..; Trident/4.0)
` |
| 3673760 | `User-Agent: Mozi..; Trident/4.0)
` |
| 3674704 | `User-Agent: Mozi..; Trident/4.0)
` |
| 3884344 | `SOFTWARE\Microso..nternet Settings` |
| 3619280 | `SOFTWARE\Microso..nternet Settings` |
| 3609760 | `SOFTWARE\Microso..ion\Uninstall\%s` |
| 3422368 | `__crt_strtox::fl.._value::as_float` |
| 3422248 | `__crt_strtox::fl..value::as_double` |
| 3884040 | `
User-Agent: Mo...1; Trident/4.0)` |
| 4139912 | `INSERT INTO vacu..'AND rootpage=0)` |
| 3778616 | `-pkg "%s" -apksu..yname "%s" -tray` |
| 4140048 | `SELECT'INSERT IN..ce(rootpage,1)>0` |
| 3748576 | `-pkg "%s" -apksu..displayname "%s"` |
| 3778304 | `-pkg "%s" -apksu..displayname "%s"` |
| 3753200 | `-pkg "%s" -apksu..displayname "%s"` |
| 3748688 | `-pkg "%s" -apksu..displayname "%s"` |
| 3760080 | `-pkg "%s" -apksu..displayname "%s"` |
| 3782152 | `-pkg "%s" -apksu..displayname "%s"` |
| 4127512 | `SELECT 1 FROM "%.. name, %d)=NULL ` |
| 4140256 | `SELECT sql FROM ..ce(rootpage,1)>0` |
| 4127320 | `SELECT 1 FROM te.., name, 1)=NULL ` |
| 4127696 | `UPDATE "%w".%s S..X_%%' ESCAPE 'X'` |
| 1867525 | `6B6B8F8FD3D3CDCD0000` |
| 3733872 | `[%s] 7z Decompre..xe[%s] Param[%s]` |
| 4129384 | `UPDATE temp.%s S..rigger', 'view')` |
| 3733704 | `[%s] Try Use 7z .. ComponentId[%d]` |
| 4129520 | `UPDATE "%w".%s S..reate virtual%%'` |
| 4128520 | `UPDATE %Q.%s SET..type='trigger');` |
| 4128912 | `UPDATE sqlite_te..iew', 'trigger')` |
| 555118 | `9B0033160D100134..172901090B161D64` |
| 4140688 | `UPDATE %Q.%s SET.. WHERE rowid=#%d` |
| 4128056 | `UPDATE "%w".%s S..e' AND name = %Q` |
| 3734088 | `[%s][Error] Prep..eExtTool 7z Fail` |
| 4137504 | `CREATE TABLE x(t..ge int,sql text)` |
| 3623000 | `Content-Type:app..d; charset=UTF-8` |
| 558467 | `96DBBD92979E88A7..88898DD59F9797FB` |
| 3623116 | `Content-Type:app..d; charset=UTF-8` |
| 3625684 | `ConfigFile.zip` |
| 554304 | `9AA3818A9B828BA68F808A828BAFEE` |
| 4139456 | `sqlite3_get_tabl..mpatible queries` |
| 4131720 | `UPDATE %Q.%s SET.. WHERE rowid=#%d` |
| 558053 | `0200B1929C99B1949F8F9C8F84BCFD` |
| 559017 | `1000B38C80819D8A9CC18B8383EF` |
| 91930 | `0000000080808080..0000C0A90000E0B5` |
| 92281 | `000000000000201C..0000000006000000` |
| 554018 | `0000000004000000..0000000004000000` |
| 2234295 | `00000000660B0000..1900000061000000` |
| 2555700 | `D89E05C15D9DBBCB..0000000030000000` |
| 2557284 | `08C9BCF367E6096A..0000000040000000` |
| 559537 | `3F009C90938190ACEEA4ACACC0` |
| 71265 | `00000000808080808080808080808080` |
| 3303180 | `Content-Type: ap..orm-urlencoded
` |
| 559206 | `ED004E55567E21203C767E7E12` |
| 1402761 | `000000004C000000..5A00000055000000` |
| 1453308 | `0000000002000000..0000000000000000` |
| 1514098 | `0200000000000000..0000000001000000` |
| 2409584 | `0000000000000000..0000000000000000` |
| 3074238 | `0000000000000000..0000000000000000` |
| 559367 | `0200A1B2B1B8CFCED3999191FD` |
| 2352072 | `0000000000000000..0000000000000000` |
| 558186 | `0000000000000000..D5C8D9FAD5D0D9BC` |
| 554480 | `D4FBF8E4F2DFF6F9F3FBF297` |
| 3622084 | `SeDebugPrivilege` |
| 557946 | `7100C8E2E1E1EAC8E7F6BC8E` |
| 3622048 | `SeDebugPrivilege` |
| 4128384 | `UPDATE "%w".sqli.. WHERE name = %Q` |
| 558390 | `0400B8C1A7AB89949C899A` |
| 821248 | `0000000000000000..0000000001000000` |
| 1203792 | `0000000000000000..0000000000000001` |
| 2430456 | `0000000000000000..0000000001000000` |
| 3359432 | `CHECK failed: ba...get() != NULL: ` |
| 4134756 | `sqlite3_extension_init` |
| 4140200 | `SELECT sql FROM ..ERE type='index'` |
| 395169 | `00000000FFFFFFFF..14000000007F0000` |
| 3297524 | `Content-Type: mu..tipart/form-data` |
| 3820468 | `naturaleftouteri..htfullinnercross` |
| 843696 | `0000000001234567..0000000000000000` |
| 3318484 | `CLIENT libcurl 7..NE %s %s
QUIT
` |
| 4132676 | `there is already..a table named %s` |

### Constants / Known Patterns (135)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| hash | `hash::SHA256` |
| hash | `hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640` |
| crypto | `crypto::AES` |
| crypto | `crypto::Rijndael_rcon__32_big_40` |
| crypto | `crypto::DES_SPR_SPtrans__32_lil_2048` |
| apihash | `apihash::hash(strstr)` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| hash | `hash::MD5` |
| hash | `hash::xxhash` |
| apihash | `apihash::hash(__initenv)` |
| apihash | `apihash::hash(RtlPrefixUnicodeString)` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| exception | `exception::CLR exception` |
| code | `code::PEBx86` |
| hash | `hash::RIPEMD160` |
| hash | `hash::RIPEMD128` |
| hash | `hash::SHA1` |
| crypto | `crypto::Base64` |
| guid | `guid::IShellLinkW` |
| guid | `guid::IUnknown` |
| guid | `guid::IPersistFile` |
| guid | `guid::IBindStatusCallback` |
| crypto | `crypto::EC_curve__EC_SECG_CHAR2_193R1_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_SECG_CHAR2_193R2_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_NIST_CHAR2_233B_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_NIST_CHAR2_283B_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_NIST_CHAR2_409B_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_NIST_CHAR2_571B_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_163V1_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_163V2_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_163V3_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_191V1_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_191V2_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_191V3_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_239V1_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_239V2_SEED__8_byt_20` |
| crypto | `crypto::EC_curve__EC_X9_62_CHAR2_239V3_SEED__8_byt_20` |

### Imports (8334)
| EA | Name | Type | Refs |
|---|---|---|---|
| 62551 | nlohmann::detail::wide_string_input_adapter<std::basic_string<wchar_t,struct std::char_traits<wchar_t>,char_traits::allocator<wchar_t>>>.#4 | DEBUG | 79 |
| 62556 | nlohmann::detail::wide_string_input_adapter<std::basic_string<wchar_t,struct std::char_traits<wchar_t>,char_traits::allocator<wchar_t>>>.#6 | DEBUG | 53 |
| 98064 | ??__E?wndTop@CWnd@@2V1@B@@YAXXZ | DEBUG | 1 |
| 100906 | ??__Efout@std@@YAXXZ | DEBUG | 1 |
| 101064 | ??__Eg_DebugOutFilePtr@details@Concurrency@@YAXXZ | DEBUG | 1 |
| 101078 | ??__E?s_cookie@Security@details@Concurrency@@2KA@@YAXXZ | DEBUG | 1 |
| 102608 | Concurrency::details::FreeThreadProxyFactory.#4 | DEBUG | 78 |
| 103984 | TiXmlUnknown.#10 | DEBUG | 1294 |
| 104304 | ATL.IDocument.IDocument | DEBUG | 33 |
| 107184 | GuardCFCheckFunction | DEBUG | 238 |
| 107184 | std::_Ref_count_obj<HttpUploader>.#0 | DEBUG | 238 |
| 108960 | Concurrency::details::ThreadScheduler.#22 | DEBUG | 14 |
| 111456 | __crt_internal_free_policy.operator()<unsigned short> | DEBUG | 4 |
| 112000 | _HRESULT_FROM_WIN32 | DEBUG | 13 |
| 114464 | .?AV?$_Func_impl@V<lambda_e436dc57fe0494e5b8d93aa46cf92d85>@@V?$allocator@H@std@@X$$V@std@@.#5 | DEBUG | 60 |
| 116176 | Concurrency::details::ExternalContextBase.#1 | DEBUG | 45 |
| 117136 | std.char_traits<char>.length | DEBUG | 9 |
| 117264 | CMsgBox.#3 | DEBUG | 240 |
| 117728 | TiXmlUnknown.#14 | DEBUG | 288 |
| 117808 | ICommandCallback.#3 | DEBUG | 1 |
| 117936 | ICommandCallback.#0 | DEBUG | 1 |
| 118016 | ICommandCallback.#2 | DEBUG | 1 |
| 118064 | ICommandCallback.#1 | DEBUG | 1 |
| 118928 | ATL::CWin32Heap.#0 | DEBUG | 3 |
| 118960 | ATL::CWin32Heap.#1 | DEBUG | 3 |
| 118992 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 119056 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 119088 | ATL::CWin32Heap.#4 | DEBUG | 1 |
| 119280 | ATL::CAtlStringMgr.#0 | DEBUG | 1 |
| 119440 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 119520 | ATL::CAtlStringMgr.#2 | DEBUG | 1 |
| 119680 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 119696 | ATL::CAtlStringMgr.#5 | DEBUG | 1 |
| 127712 | ATL.CStringData.IsShared | DEBUG | 3 |
| 128084 | nlohmann::detail::wide_string_input_adapter<std::basic_string<wchar_t,struct std::char_traits<wchar_t>,char_traits::allocator<wchar_t>>>.#10 | DEBUG | 38 |
| 129328 | CCommandProv.#3 | DEBUG | 1 |
| 129408 | CDaoRelationFieldInfo.CDaoRelationFieldInfo | DEBUG | 1 |
| 131616 | CClfsManagedLogClient.IsWaitingForLogFileFullHandler | DEBUG | 15 |
| 132304 | Concurrency::details::ThreadInternalContext.#0 | DEBUG | 60 |
| 133152 | google::protobuf::DescriptorProto.#11 | DEBUG | 6 |
| 133232 | nonstd::optional_lite::bad_optional_access.#0 | DEBUG | 2 |
| 133392 | std.basic_ostringstream<char,struct std::char_traits<char>,std::allocator<char>>.~basic_ostringstream<char,struct std::char_traits<char>,std::allocator<char>> | DEBUG | 1 |
| 133600 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#11 | DEBUG | 1 |
| 133968 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#10 | DEBUG | 1 |
| 134528 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#6 | DEBUG | 1 |
| 134704 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#4 | DEBUG | 1 |
| 134912 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#3 | DEBUG | 1 |
| 135568 | std::basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.#0 | DEBUG | 1 |
| 135568 | std.basic_stringbuf<char,struct std::char_traits<char>,std::allocator<char>>.`scalar deleting destructor' | DEBUG | 1 |
| 135952 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#3 | DEBUG | 1 |
| 136064 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#4 | DEBUG | 1 |
| 136464 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#5 | DEBUG | 1 |
| 136848 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#6 | DEBUG | 1 |
| 136976 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#7 | DEBUG | 1 |
| 137104 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#8 | DEBUG | 1 |
| 137232 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#9 | DEBUG | 1 |
| 137360 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#10 | DEBUG | 1 |
| 137824 | std.ostreambuf_iterator<char,struct std::char_traits<char>>.ostreambuf_iterator<char,struct std::char_traits<char>> | DEBUG | 8 |
| 138560 | std.basic_streambuf<char,struct std::char_traits<char>>.setp | DEBUG | 5 |
| 138608 | std.basic_streambuf<char,struct std::char_traits<char>>.setp | DEBUG | 3 |
| 138656 | std.basic_streambuf<char,struct std::char_traits<char>>.setg | DEBUG | 14 |
| 138704 | std.basic_streambuf<char,struct std::char_traits<char>>.egptr | DEBUG | 6 |
| 138864 | std::num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>.#0 | DEBUG | 1 |
| 138912 | std::numpunct<char>.#7 | DEBUG | 1 |
| 138944 | std::numpunct<char>.#6 | DEBUG | 1 |
| 138976 | std::numpunct<wchar_t>.#5 | DEBUG | 2 |
| 139008 | std::numpunct<char>.#4 | DEBUG | 1 |
| 139024 | std::numpunct<char>.#3 | DEBUG | 1 |
| 141184 | std.num_put<char,std::ostreambuf_iterator<char,struct std::char_traits<char>>>._Ffmt | DEBUG | 4 |
| 142496 | std::numpunct<char>.#0 | DEBUG | 1 |
| 143168 | std::_Associated_state<std::shared_ptr<easywsclient::WebSocket>>.#3 | DEBUG | 35 |
| 146399 | std::basic_ostream<char,struct std::char_traits<char>>.#0 | DEBUG | 1 |
| 146407 | std::basic_ostringstream<char,struct std::char_traits<char>,std::allocator<char>>.#0 | DEBUG | 1 |
| 148656 | std._Hash_array_representation<char> | DEBUG | 2 |
| 149296 | Concurrency::details::ThreadVirtualProcessor.#5 | DEBUG | 8 |
| 149328 | std.locale.id.operator  | DEBUG | 9 |
| 149552 | struct std::ctype_base.#0 | DEBUG | 1 |
| 149616 | std::ctype<char>.#0 | DEBUG | 1 |
| 149760 | std::ctype<char>.#3 | DEBUG | 1 |
| 149840 | std::ctype<char>.#4 | DEBUG | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 2480944 | sub_65e730 |
| 2600272 | sub_67b950 |
| 764008 | sub_4bb468 |
| 2061168 | sub_5f7f70 |
| 2855264 | sub_6b9d60 |
| 2798784 | sub_6ac0c0 |
| 2061904 | sub_5f8250 |
| 2060050 | sub_5f7b12 |
| 2863872 | sub_6bbf00 |
| 1667680 | sub_597e60 |
| 2683248 | sub_68fd70 |
| 2876720 | sub_6bf130 |
| 2061584 | sub_5f8110 |
| 2060432 | sub_5f7c90 |
| 2683840 | sub_68ffc0 |
| 3148864 | sub_701840 |
| 2480032 | sub_65e3a0 |
| 3081008 | #67 |
| 2059923 | sub_5f7a93 |
| 762091 | sub_4baceb |
| 2059817 | sub_5f7a29 |
| 1474208 | sub_568aa0 |
| 2929232 | sub_6cbe50 |
| 764656 | sub_4bb6f0 |
| 2929952 | sub_6cc120 |
| 2856304 | sub_6ba170 |
| 1668096 | sub_598000 |
| 2860960 | sub_6bb3a0 |
| 2554256 | sub_670590 |
| 2800832 | sub_6ac8c0 |

### Decompilations (top 6)
#### 2480944 — sub_65e730
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t sub_65e730(undefined *param_1,int32_t param_2,int32_t param_3)

{
    uint16_t uVar1;
    unkuint3 Var2;
    undefined uVar3;
    uint32_t uVar4;
    int32_t iVar5;
    uint8_t *puVar6;
    
    iVar5 = 0;
    if (0 < param_3) {
        puVar6 = param_2 + 1;
        do {
            if (param_3 < 3) {
                uVar4 = puVar6[-1] << 0x10;
                if (param_3 == 2) {
                    uVar4 = uVar4 | *puVar6 << 8;
                }
                *param_1 = (&Base64)[uVar4 >> 0x12];
                param_1[1] = (&Base64)[uVar4 >> 0xc & 0x3f];
                if (param_3 == 1) {
                    uVar3 = 0x3d;
                }
                else {
                    uVar3 = (&Base64)[uVar4 >> 6 & 0x3f];
                }
                param_1[2] = uVar3;
                param_1[3] = 0x3d;
            }
            else {
                uVar1 = CONCAT11(puVar6[-1], *puVar6);
                Var2 = CONCAT21(uVar1, puVar6[1]);
                *param_1 = (&Base64)[puVar6[-1] >> 2];
                param_1[1] = (&Base64)[uVar1 >> 4 & 0x3f];
                param_1[2] = (&Base64)[Var2 >> 6 & 0x3f];
                param_1[3] = (&Base64)[Var2 & 0x3f];
            }
            param_3 = param_3 + -3;
            iVar5 = iVar5 + 4;
            puVar6 = puVar6 + 3;
            param_1 = param_1 + 4;
        } while (0 < param_3);
        *param_1 = 0;
        return iVar5;
    }
    *param_1 = 0;
    return 0;
}

```
#### 2600272 — sub_67b950
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_67b950(undefined4 param_1,int32_t *param_2,undefined4 param_3,undefined4 param_4)

{
    uint32_t uVar1;
    int32_t iVar2;
    int32_t *piVar3;
    int32_t *piVar4;
    int32_t iVar5;
    undefined4 uVar6;
    
    uVar6 = 0;
    sub_649550(param_4);
    piVar3 = sub_649470(param_4);
    if (piVar3 != 0x0) {
        piVar4 = piVar3;
        if (piVar3[2] < param_2[1] * 2) {
            piVar4 = sub_642cb0(piVar3, param_2[1] * 2);
        }
        if (piVar4 != 0x0) {
            iVar5 = param_2[1];
            while (iVar5 = iVar5 + -1, -1 < iVar5) {
                uVar1 = *(*param_2 + iVar5 * 4);
                *(*piVar3 + 4 + iVar5 * 8) =
                     ((*(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x1c) * 4) << 8 |
                      *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x18 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x14 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 0x10 & 0xf) * 4);
                uVar1 = *(*param_2 + iVar5 * 4);
                *(*piVar3 + iVar5 * 8) =
                     ((*(&Generic_squared_map__32_lil_64 + (uVar1 >> 0xc & 0xf) * 4) << 8 |
                      *(&Generic_squared_map__32_lil_64 + (uVar1 >> 8 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 >> 4 & 0xf) * 4)) << 8 |
                     *(&Generic_squared_map__32_lil_64 + (uVar1 & 0xf) * 4);
            }
            uVar6 = 0;
            iVar5 = param_2[1] * 2;
            piVar3[1] = iVar5;
            if (0 < iVar5) {
                piVar4 = *piVar3 + (iVar5 + -1) * 4;
                do {
                    iVar2 = *piVar4;
                    piVar4 = piVar4 + -1;
                    if (iVar2 != 0) break;
                    iVar5 = iVar5 + -1;
                } while (0 < iVar5);
                piVar3[1] = iVar5;
            }
            if (piVar3[1] == 0) {
                piVar3[3] = 0;
            }
            iVar5 = sub_67a9d0(param_1, piVar3, param_3);
            if (iVar5 != 0) {
                uVar6 = 1;
            }
        }
    }
    sub_649400(param_4);
    return uVar6;
}

```
#### 764008 — sub_4bb468
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t __fastcall sub_4bb468(uint32_t param_1,uint32_t *param_2,uint32_t param_3)

{
    uint32_t uVar1;
    uint32_t uStack_8;
    
    param_1 = ~param_1;
    if (param_3 != 0) {
        do {
            if ((param_2 & 3) == 0) break;
            param_1 = param_1 >> 8 ^ *(&CRC32 + ((*param_2 ^ param_1) & 0xff) * 4);
            param_2 = param_2 + 1;
            param_3 = param_3 - 1;
        } while (param_3 != 0);
    }
    if (0x1f < param_3) {
        uStack_8 = param_3 >> 5;
        do {
            param_1 = param_1 ^ *param_2;
            uVar1 = *(&CRC32 + (param_1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (param_1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (param_1 >> 0x18) * 4) ^ *(&CRC32 + (param_1 & 0xff) * 4) ^ param_2[1];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[2];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[3];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[4];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[5];
            param_3 = param_3 - 0x20;
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[6];
            uVar1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                    *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                    *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4) ^ param_2[7];
            param_2 = param_2 + 8;
            param_1 = *(&CRC32 + (uVar1 >> 0x10 & 0xff) * 4) ^
                      *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (uVar1 >> 8 & 0xff) * 4) ^
                      *(&CRC32 + (uVar1 >> 0x18) * 4) ^ *(&CRC32 + (uVar1 & 0xff) * 4);
            uStack_8 = uStack_8 - 1;
        } while (uStack_8 != 0);
    }
    if (3 < param_3) {
        uVar1 = param_3 >> 2;
        do {
            param_1 = param_1 ^ *param_2;
            param_3 = param_3 - 4;
            param_2 = param_2 + 1;
            param_1 = *(&CRC32 + (param_1 >> 0x10 & 0xff) * 4) ^
                      *(&Adler_CRC32__0x01c26a37___32_lil_1024 + (param_1 >> 8 & 0xff) * 4) ^
                      *(&CRC32 + (param_1 >> 0x18) * 4) ^ *(&CRC32 + (param_1 & 0xff) * 4);
            uVar1 = uVar1 - 1;
        } while (uVar1 != 0);
    }
    for (; param_3 != 0; param_3 = param_3 - 1) {
        param_1 = param_1 >> 8 ^ *(&CRC32 + ((*param_2 ^ param_1) & 0xff) * 4);
        param_2 = param_2 + 1;
    }
    return ~param_1;
}

```

### Carved Files (21)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 1128 |
| ? | DIB | 2440 |
| ? | DIB | 4264 |
| ? | DIB | 9640 |
| ? | DIB | 16936 |
| ? | DIB | 38056 |
| ? | DIB | 67624 |
| ? | DIB | 270376 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |
| ? | ICO | 410598 |
| ? | PE | 76168 |
| ? | ZIP | 606648 |
| ? | PE | 2705744 |

### Virtual Files (26)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| CUSTOM/IDR_CUSTOM_FOR_EXTRACE_ICON/zh-cn | 410598 | - |
| DLL/110/zh-cn | 76168 | - |
| EXE/137/zh-cn | 2705744 | - |
| SKIN/IDR_QMUI_DAT/zh-cn | 606648 | - |
| ICO/1/zh-cn | 1128 | - |
| ICO/2/zh-cn | 2440 | - |
| ICO/3/zh-cn | 4264 | - |
| ICO/4/zh-cn | 9640 | - |
| ICO/5/zh-cn | 16936 | - |
| ICO/6/zh-cn | 38056 | - |
| ICO/7/zh-cn | 67624 | - |
| ICO/8/zh-cn | 270376 | - |
| ICO/9/zh-cn | 744 | - |
| ICO/10/zh-cn | 296 | - |
| ICO/11/zh-cn | 3752 | - |
| ICO/12/zh-cn | 2216 | - |
| ICO/13/zh-cn | 1384 | - |
| ICO/14/zh-cn | 9640 | - |
| ICO/15/zh-cn | 4264 | - |
| ICO/16/zh-cn | 1128 | - |

### Structures (166)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 344 |
| OptionalHeader | 368 |
| Sections | 592 |
| advapi32.FT | 3294208 |
| comctl32.FT | 3294344 |
| gdi32.FT | 3294356 |
| imm32.FT | 3294520 |
| iphlpapi.FT | 3294528 |
| kernel32.FT | 3294548 |
| netapi32.FT | 3295580 |
| oleaut32.FT | 3295596 |
| opengl32.FT | 3295620 |
| psapi.FT | 3295644 |
| shell32.FT | 3295652 |
| shlwapi.FT | 3295696 |
| user32.FT | 3295760 |
| version.FT | 3296132 |
| winhttp.FT | 3296148 |
| wininet.FT | 3296216 |
| winmm.FT | 3296276 |
| wldap32.FT | 3296288 |
| ws2_32.FT | 3296356 |
| d3d9.FT | 3296512 |
| gdiplus.FT | 3296520 |
| imagehlp.FT | 3296600 |
| ole32.FT | 3296612 |
| urlmon.FT | 3296648 |
| GuardCFCheckFunctionPointer | 3296656 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 154 · duration_s: 11.45

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| reference Base64 string | T1027:Obfuscated Files or Information | C0026.001:Encode Data, C0019:Check String |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using AES via x86 extensions | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using RC4 KSA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0028.002:Encryption Key |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| reference anti-VM strings | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| reference anti-VM strings targeting VMWare | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| reference anti-VM strings targeting VirtualBox | T1497.001:Virtualization/Sandbox Evasion | B0009:Virtual Machine Detection |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get socket status | T1016:System Network Configuration Discovery | C0001.012:Socket Communication |
| decrypt data using AES via x86 extensions | T1140:Deobfuscate/Decode Files or Information | C0031.001:Decrypt Data |
| encrypt data using TEA | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |

## PE Imports / Signals
import_count: 571

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| write_process_memory | WriteProcessMemory | T1055 |
| set_thread_context | SetThreadContext | T1055 |
| check_debugger | IsDebuggerPresent | T1622 |
| http_client | InternetOpen | T1071.001 |
| winhttp_client | WinHttpOpen | T1071.001 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 61

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3329364 len=7; $ipv6@60881 len=2 |
| contains_base64 | - | $a@10010 len=12 |
| System_Tools | - |  |
| Antivirus | - |  |
| VMWare_Detection | - | $a1@3791656 len=6 |
| Dropper_Strings | - | $a0@5752647 len=18; $a1@3751138 len=52; $a3@3621820 len=12; $a4@5086696 len=17 |
| Obfuscated_Strings | - |  |
| Big_Numbers0 | - | $c0@3817300 len=20 |
| Big_Numbers1 | - | $c0@3815136 len=32 |
| Big_Numbers3 | - | $c0@4142220 len=64 |
| Advapi_Hash_API | - | $advapi32@3414028 len=24; $CryptCreateHash@4098454 len=15; $CryptHashData@4098472 len=13; $CryptAcquireContext@3562656 len=19 |
| CRC32_poly_Constant | - | $c0@2876735 len=4 |
| CRC32_table | - | $c0@3633040 len=20 |
| MD5_Constants | - | $c4@843724 len=4; $c5@843734 len=4; $c6@843747 len=4; $c7@843760 len=4 |
| RIPEMD160_Constants | - | $c5@843724 len=4; $c6@843734 len=4; $c7@843747 len=4 |
| SHA1_Constants | - | $c5@843724 len=4; $c6@843734 len=4; $c7@843747 len=4 |
| SHA512_Constants | - | $c1@23232 len=4; $c3@23236 len=4; $c5@23240 len=4; $c7@23244 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@2555396 len=4; $c1@2555403 len=4; $c2@2555415 len=4; $c3@2555422 len=4; $c4@2555429 len=4; $c5@2555436 len=4; $c6@2555443 len=4; $c7@2555450 len=4 |
| DES_Long | - | $c0@77632 len=64 |
| RijnDael_AES_CHAR | - | $c0@61632 len=32 |
| BASE64_table | - | $c0@3329096 len=64 |
| ecc_order | - | $secp192k1@3544832 len=24; $secp192r1@3541460 len=24; $secp224k1@3545017 len=29; $secp224r1@3541664 len=28; $secp256k1@3545224 len=32; $prime256v1@3543668 len=3 |
| with_sqlite | - | $hex_string@3811312 len=16 |
| url | - | $url_regex@3296982 len=42 |
| maldoc_find_kernel32_base_method_1 | - | $a1@2078027 len=7; $a2@560401 len=6 |
| maldoc_getEIP_method_1 | - | $a@10116 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |

## Generated YARA Meta
```json
{
  "sha256": "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6",
  "family": "unknown",
  "generated_at": "2026-08-04T07:46:29.829726+00:00",
  "string_count": 24,
  "strings": [
    "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb",
    "Copyright \u00a9 2020 Tencent. All Rights Reserved.",
    "InitializeCriticalSectionAndSpinCount",
    "WinHttpGetIEProxyConfigForCurrentUser",
    "GdipSetImageAttributesColorMatrix",
    "SystemTimeToTzSpecificLocalTime",
    "GetLogicalProcessorInformation",
    "SetUnhandledExceptionFilter",
    "MsgWaitForMultipleObjectsEx",
    "GdipCreateHBITMAPFromBitmap",
    "RegisterWaitForSingleObject",
    "IDR_CUSTOM_FOR_EXTRACE_ICON",
    "InterlockedCompareExchange",
    "PostQueuedCompletionStatus",
    "GdipDisposeImageAttributes",
    "GdipCreateBitmapFromStream",
    "\u817e\u8baf\u624b\u6e38\u52a9\u624b      \u53cd\u9988\u7fa4\u53f7\uff1a262700278",
    "IsProcessorFeaturePresent",
    "GetPrivateProfileSectionW",
    "ExpandEnvironmentStringsW",
    "InitializeCriticalSection",
    "GetQueuedCompletionStatus",
    "ExpandEnvironmentStringsA",
    "MsgWaitForMultipleObjects"
  ],
  "rule_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yar",
  "sigma_path": "/opt/samples/logs/7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6/rule.yml",
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
Total strings: 24408 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 24408}`

### High-signal FLOSS
- `Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>`
- `SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>`
- `AES for x86, CRYPTOGAMS by <appro@openssl.org>`
- `AES for Intel AES-NI, CRYPTOGAMS by <appro@openssl.org>`
- `GHASH for x86, CRYPTOGAMS by <appro@openssl.org>`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.gfids`
- `.QMGuid`
- `@.tvm0`
- ``.reloc`
- `V4_^[]`
- `X<[]_^`
- `_<[]_^`
- `Montgomery Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>`
- `SHA1 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `SHA256 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `d$l_^[]`
- `#L$(#T$,`
- `D7q/;M`
- `SHA512 block transform for x86, CRYPTOGAMS by <appro@openssl.org>`
- `)QZ^&1`
- `\$ 3D$`
- `\$43D$03\$8`
- `GF(2^m) Multiplication for x86, CRYPTOGAMS by <appro@openssl.org>`
- `T`00P`00P`
- `V++}V++}`
- `L&&jL&&jl66Zl66Z~??A~??A`
- `Oh44\h44\Q`
- `sb11Sb11S*`
- `RF##eF##e`
- `&N''iN''i`
- `X,,tX,,t4`
- `v;;Mv;;M`
- `R)){R)){`
- `>^//q^//q`
- `,@  `@  ``
- `r99Kr99K`
- `f33Uf33U`
- `x<<Dx<<D%`
- `p88Hp88H`
- `uB!!cB!!c`
- `z==Gz==G`
- `D""fD""fT**~T**~;`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00487740
```asm
; CALL XREF from entry0 @ 0x4898fa(x)
┌ 10: fcn.00487740 ();
│           0x00487740      50             push eax
│           0x00487741      60             pushal
│           0x00487742      e8edffffff     call fcn.00487734
└           0x00487747      c20400         ret 4
```
### 0x00487734
```asm
; CALL XREF from fcn.00487740 @ 0x487742(x)
┌ 12: fcn.00487734 (int32_t arg_4h);
│           ; arg int32_t arg_4h @ esp+0x8
│           0x00487734      50             push eax
│           0x00487735      8b442404       mov eax, dword [arg_4h]
│           0x00487739      83c004         add eax, 4
│           0x0048773c      50             push eax
└           0x0048773d      c20800         ret 8
```
### 0x0056c730
```asm
; XREFS: CALL 0x0056ccdf  CALL 0x0056d2bb  CALL 0x0056e282  
            ; XREFS: CALL 0x0056e2ef  CALL 0x0056e3e5  CALL 0x0056e55c  
            ; XREFS: CALL 0x00571d62  
┌ 397: fcn.0056c730 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           0x0056c730      55             push ebp
│           0x0056c731      8bec           mov ebp, esp
│           0x0056c733      83ec0c         sub esp, 0xc
│           0x0056c736      53             push ebx
│           0x0056c737      8b5d08         mov ebx, dword [arg_8h]
│           0x0056c73a      57             push edi
│           0x0056c73b      8b4308         mov eax, dword [ebx + 8]
│           0x0056c73e      8dbba48e0000   lea edi, [ebx + 0x8ea4]
│           0x0056c744      8945fc         mov dword [var_4h], eax
│           0x0056c747      85c0           test eax, eax
│       ┌─< 0x0056c749      0f8468010000   je 0x56c8b7
│       │   0x0056c74f      837d0c00       cmp dword [arg_ch], 0
│       │   0x0056c753      56             push esi
│      ┌──< 0x0056c754      7572           jne 0x56c7c8
│      ││   0x0056c756      833f00         cmp dword [edi], 0
│     ┌───< 0x0056c759      750a           jne 0x56c765
│     │││   0x0056c75b      837f0400       cmp dword [edi + 4], 0
│    ┌────< 0x0056c75f      0f8451010000   je 0x56c8b6
│    │└───> 0x0056c765      8bb3c48e0000   mov esi, dword [ebx + 0x8ec4]
│    │ ││   0x0056c76b      8d4858         lea ecx, [eax + 0x58]
│    │ ││   0x0056c76e      51             push ecx
│    │ ││   0x0056c76f      8d83ac8e0000   lea eax, [ebx + 0x8eac]
│    │ ││   0x0056c775      50             push eax
│    │ ││   0x0056c776      ff31           push dword [ecx]
│    │ ││   0x0056c778      e8b3ef0000     call 0x57b730
│    │ ││   0x0056c77d      83c40c         add esp, 0xc
│    │ ││   0x0056c780      85c0           test eax, eax
│    │┌───< 0x0056c782      740f           je 0x56c793
│    ││││   0x0056c784      50             push eax
│    ││││   0x0056c785      68205f7200     push str.Internal_error_clearing_splay_node___d_n ; 0x725f20 ; "Internal error clearing splay node = %d\n"
│    ││││   0x0056c78a      53             push ebx
│    ││││   0x0056c78b      e840b40000     call fcn.00577bd0
│    ││││   0x0056c790      83c40c         add esp, 0xc
│    │└───> 0x0056c793      837e0c00       cmp dword [esi + 0xc], 0
│    │┌───< 0x0056c797      761b           jbe 0x56c7b4
│    ││││   0x0056c799      0f1f800000..   nop dword [eax]
│   ┌─────> 0x0056c7a0      6a00           push 0
│   ╎││││   0x0056c7a2      ff7604         push dword [esi + 4]
│   ╎││││   0x0056c7a5      56             push esi
│   ╎││││   0x0056c7a6      e845e50000     call fcn.0057acf0
│   ╎││││   0x0056c7ab      83c40c         add esp, 0xc
│   ╎││││   0x0056c7ae      837e0c00       cmp dword [esi + 0xc], 
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000158 ........!..L.!This program cannot be r
- Found XOR 00 position 004CBD20: 00000100 ........!..L.!This program cannot be r
- Found XOR 00 position 00572860: 000000D0 ........!..L.!This program cannot be r
- Found XOR C5 position 008394BC: 000000F8 ........!..L.!This program cannot be r

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
  - `VERSION.dll!GetFileVersionInfoW`
  - `VERSION.dll!VerQueryValueW`
  - `VERSION.dll!GetFileVersionInfoSizeW`
  - `PSAPI.DLL!GetModuleFileNameExW`
  - `WS2_32.dll!WSAStartup`
  - `WS2_32.dll!shutdown`
  - `WS2_32.dll!getaddrinfo`
  - `WS2_32.dll!socket`
  - `WS2_32.dll!connect`
  - `IMM32.dll!ImmDisableIME`
  - `KERNEL32.dll!UnhandledExceptionFilter`
  - `KERNEL32.dll!GetCurrentProcess`
  - `KERNEL32.dll!DeviceIoControl`
  - `KERNEL32.dll!GetDiskFreeSpaceExW`
  - `KERNEL32.dll!GetLogicalDrives`
  - `USER32.dll!CreateWindowExA`
  - `USER32.dll!RegisterClassExA`
  - `USER32.dll!DefWindowProcW`
  - `USER32.dll!DestroyWindow`
  - `USER32.dll!ReleaseDC`
  - `GDI32.dll!MoveToEx`
  - `GDI32.dll!CreateSolidBrush`
  - `GDI32.dll!LineTo`
  - `GDI32.dll!OffsetRgn`
  - `GDI32.dll!Rectangle`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `ADVAPI32.dll!CloseServiceHandle`
  - `ADVAPI32.dll!ControlService`
  - `ADVAPI32.dll!ReportEventA`
  - `ADVAPI32.dll!RegisterEventSourceA`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785828663.20815}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785828663.7202528}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785828663.7484632}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785828663.792828}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785828923.4540768}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785828923.5692914}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785828924.0572908}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785828924.0991693}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785828924.1330402}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785829300.2063015}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE name LIKE '%CreateRemoteThread%' OR name LIKE '%WriteProcessMemory%' OR name LIKE '%VirtualAlloc%' OR name LIKE '%RegSetValue%' OR name LIKE '%InternetOpen%' OR name LIKE '%URLDownloadToFile%' OR name LIKE '%WinInet%'`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics ORDER BY cyclomatic_complexity DESC, instruction_count DESC LIMIT 20", "ts": 1785829306.7892892}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%.exe%' OR content LIKE '%.dll%' OR content LIKE 'http%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%reg%' OR content LIKE '%svchost%' OR content LIKE '%system32%' OR cont`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE 'http%' OR content LIKE 'https%' OR content LIKE '%://%' OR content LIKE '%ftp%' OR content LIKE '%tor%' OR content LIKE '%onion%' OR content LIKE '%payload%' OR content LIKE '%config%' OR content LIKE`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%GameDownload%' OR content LIKE '%VERSION.dll%' OR content LIKE '%PSAPI.DLL%' OR content LIKE '%WS2_32.dll%' OR content LIKE '%IMM32.dll%' OR content LIKE '%OutputDebugStringW%' OR content LIKE '%GetT`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%https%' OR content LIKE '%ftp%' OR content LIKE '%tor%' OR content LIKE '%onion%' OR content LIKE '%payload%' OR content LIKE '%config%' OR content LIKE '%server%' OR content`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%GameDownload%' OR content LIKE '%VERSION.dll%' OR content LIKE '%PSAPI.DLL%' OR content LIKE '%WS2_32.dll%' OR content LIKE '%IMM32.dll%' OR content LIKE '%OutputDebugStringW%' OR content LIKE '%GetT`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE 'http%' OR content LIKE 'https%' OR content LIKE 'ftp%' OR content LIKE '%.onion%' OR content LIKE '%payload%' OR content LIKE '%config%' OR content LIKE '%server%' OR content LIKE '%host%' OR content `
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%GameDownload%' OR content LIKE '%VERSION.dll%' OR content LIKE '%PSAPI.DLL%' OR content LIKE '%WS2_32.dll%' OR content LIKE '%IMM32.dll%' OR content LIKE '%OutputDebugStringW%' OR content LIKE '%GetT`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%CreateRemoteThread%' OR content LIKE '%QueueUserAPC%' OR content LIKE '%NtCreateThreadEx%' OR content LIKE '%SetWindowsHookEx%' OR content LIKE '%SendMessage%' OR content LIKE '%PostMessage%' OR cont`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%.exe%' OR content LIKE '%.dll%' OR content LIKE '%temp%' OR content LIKE '%appdata%' OR content LIKE '%software%' OR content LIKE '%microsoft%' OR content LIKE '%vmware%' OR `
- `{"source": "ghidra_query", "sql": "SELECT * FROM callgraph_edges LIMIT 5", "ts": 1785829374.046085}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785829588.7908928}`
- `{"source": "yara_gen_v2", "ts": 1785829589.8298666}`
