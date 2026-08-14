# Technical Evidence Pack

**sha256:** ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98  
**sample_path:** /opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 95
- **family_guess**: trojan.graftor/skeeyah
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA reveal HTTP-related strings (e.g., 'http://', 'WININET.DLL') and DLL imports, indicating network capabilities. Malcat identifies obfuscation anomalies like DownloaderApiUsage and XorInLoop, alongside YARA matches for keylogger and network rules. Capa confirms behavioral-intent evidence: keylogging and clipboard data theft. pe_imports highlights high-signal imports such as IsDebuggerPresent and InternetOpen for anti-debugging and C2. External TI from VirusTotal shows 56 malicious detections, classifying it as a trojan with tags like persistence and runtime-modules.
- **summary**: This PE executable, disguised as 'System Search Indexer', exhibits malicious behaviors including keylogging, clipboard data theft, network communication via WinINet APIs (e.g., InternetOpen, HttpOpenRequestA), and anti-analysis techniques (e.g., IsDebuggerPresent, obfuscation anomalies). Multiple analysis engines corroborate these findings, and external threat intelligence confirms it belongs to the graftor/skeeyah trojan family, indicating clear hostile intent beyond mere obfuscation.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | rule | `log keystrokes via application hook` | Detects keystroke capture capability via application hooks, a clear data theft behavior indicating malicious intent (ATT |
| capa | rule | `read clipboard data` | Identifies clipboard data theft, another data collection technique for credential or sensitive information theft (ATT&CK |
| pe_imports | imports | `InternetOpen` | HTTP client API import suggests capability for command-and-control communication or data exfiltration (ATT&CK T1071.001) |
| malcat | anomalies | `DownloaderApiUsage` | Indicates downloader-related API usage, often associated with malware for fetching payloads or additional components. |
| yara | matches | `keylogger` | YARA rule detects keylogging patterns, corroborating capa findings and confirming data theft functionality. |
| external_ti | VirusTotal | `malicious=56` | High detection rate by antivirus vendors, with popular threat names 'graftor' and 'skeeyah', classifying it as malicious |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This PE executable (msdsrv.exe) is a keylogger with HTTP-based C2 exfiltration capability. CAPA confirms two keylogging techniques: application hooking (SetWindowsHookExA) and polling (GetAsyncKeyState/GetKeyState), both mapped to MITRE ATT&CK T1056.001. The sample uses WININET.DLL HTTP APIs (InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile) to exfiltrate captured keystrokes to a remote server. Keystrokes are also written locally to 'temp.txt'. Base64 encoding (T1027) is used for defense evasion. The executable tracks the active foreground window (GetForegroundWindow) to associate keystrokes with specific applications. The filename 'msdsrv.exe' masquerades as a Microsoft service. YARA rules matched anti-debug strings, window hooking, HTTP networking, and IP address patterns. The function at 0x004024d0 has extremely high complexity (cyclomatic complexity 336, 148 call-outs, 9 string references) consistent with the main malware payload orchestrating keylogging and network communication.

### deep key_evidence
- `"CAPA: 'log keystrokes via application hook' (T1056.001 / F0002.001) - SetWindowsHookExA keyboard hook"`
- `"CAPA: 'log keystrokes via polling' (T1056.001 / F0002.002) - GetAsyncKeyState/GetKeyState polling"`
- `"Imports: SetWindowsHookExA (USER32.DLL), GetAsyncKeyState (USER32.DLL), GetKeyState (USER32.DLL), GetForegroundWindow (USER32.DLL)"`
- `"Imports: InternetOpenA, InternetConnectA, HttpSendRequestExA, InternetWriteFile, InternetReadFile (WININET.DLL) - full HTTP C2 stack"`
- `"String refs: 'temp.txt' referenced in FUN_00403610 (0x00403610) - local keystroke log file"`
- `"Strings: 'CHttpConnection', 'CHttpFile', 'http://', 'HTTP/1.0', 'WININET.DLL' - MFC HTTP client classes for C2"`
- `"CAPA: 'encode data using Base64' (T1027 / E1027.m02 / C0026.001) - defense evasion via encoding"`
- `"YARA: anti_dbg matched at offsets 191098 and 193100 - anti-debugging strings present"`
- `"YARA: win_hook matched at offsets 175752, 191366, 191278, 191260 - window hooking infrastructure"`
- `"YARA: network_http matched at offsets 163812, 163429, 191716, 191806, 191786, 191886 - HTTP networking strings"`
- `"YARA: contains_base64 matched at offset 162639 - Base64 encoded data present"`
- `"Ghidra funcs: FUN_004024d0 at 0x004024d0 has cyclomatic_complexity=336, call_out_count=148, string_ref_count=9 - main payload orchestrator"`
- `"Filename 'msdsrv.exe' masquerades as Microsoft service (MSD/Microsoft naming convention)"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98
size: 328704
type: PE
architecture: X86
entrypoint_ea: 74850
entropy: 5.88
file_name: msdsrv.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 49 | - |
| .text | 1024 | 160256 | 163840 | 139 | RX |
| .rdata | 164864 | 34304 | 36864 | 75 | R |
| .data | 201728 | 9216 | 28672 | 99 | RW |
| .rsrc | 230400 | 92160 | 94208 | 84 | R |
| .reloc | 324608 | 31744 | 32768 | 77 | R |

### Malcat YARA / Signatures (6)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2008_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2005_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| MSVC_2008_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| DownloadUsingWininet | network | UNCOMMON | 60 | can download files from internet using wininet API |
| FingerprintHardware | fingerprint | UNCOMMON | 50 | tries to enumerate installed hardware |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| ManyHighValueImmediates | 3 | code | 1 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 15 | XOR instruction in a loop |
| DownloaderApiUsage | 2 | imports | 6 | Downloader-related apis are used |
| HighXrefLoopingFunction | 1 | code | 3 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SpaghettiFunction | 1 | code | 14 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **HighXrefLoopingFunction**
  - `14784`: 
  - `19476`: 
  - `78064`: 
- **ManyHighValueImmediates**
  - `113106`: 
- **ManyUniqueImmediateBytes**
  - `106530`: 
  - `110114`: 
- **SpaghettiFunction**
  - `6352`: 
  - `14576`: 
  - `23451`: 
  - `60207`: 
  - `64368`: 
- **XorInLoop**
  - `71099`: 
  - `71149`: 
  - `71170`: 
  - `71197`: 
  - `71204`: 

### High-Signal Strings (9 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 172768 | `kernel32.dll` |
| 172896 | `KERNEL32.DLL` |
| 179236 | `GetProcessWindowStation` |
| 167148 | `http://` |
| 167848 | `KERNEL32` |
| 167712 | `HTTP/1.0` |
| 194682 | `KERNEL32.dll` |
| 166996 | `CHttpConnection` |
| 167052 | `CHttpFile` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 169984 | `EnumDisplayMonitors` |
| 172768 | `kernel32.dll` |
| 172848 | `mscoree.dll` |
| 172896 | `KERNEL32.DLL` |
| 167948 | `shell32.dll` |
| 167396 | `WININET.DLL` |
| 180336 | `JW98YR8EHFUIEHFUEHFUHEUIFHEUFE93` |
| 167900 | `comctl32.dll` |
| 210268 | `Pkfut]rfYXMj`not..neoqRespeooYXRvk` |
| 167924 | `comdlg32.dll` |
| 180320 | `temp.txt` |
| 179592 | `CCBFFEIIHLLKOONR..yyx|10443776::*1` |
| 179760 | `
===============..================` |
| 171140 | `hhctrl.ocx` |
| 195864 | `GetVolumeInformationA` |
| 179336 | `USER32.DLL` |
| 195390 | `InternetReadFile` |
| 171084 | `InitCommonControls` |
| 194612 | `GetComputerNameA` |
| 171104 | `InitCommonControlsEx` |
| 179704 | `"dssds";` |
| 170004 | `MonitorFromPoint` |
| 321824 | `<assembly xmlns=..INGXXPADDINGPADD` |
| 179236 | `GetProcessWindowStation` |
| 179452 | `invalid string position` |
| 179684 | `"shfjshf"` |
| 170040 | `MonitorFromWindow` |
| 194996 | `GetUserNameA` |
| 179260 | `GetUserObjectInformationA` |
| 172208 | `commctrl_DragListMsg` |
| 210396 | `palf`peemarnfosjlj/0` |
| 174344 | `
This applicati..e information.
` |
| 174680 | `<program name unknown>` |
| 170060 | `GetSystemMetrics` |
| 172808 | `HeapQueryInformation` |
| 196486 | `GetVersionExA` |
| 179724 | `--%s--` |
| 179436 | `string too long` |
| 179288 | `GetLastActivePopup` |
| 170024 | `MonitorFromRect` |
| 169968 | `GetMonitorInfoA` |
| 166864 | `Exception thrown in destructor` |
| 172708 | `Unknown exception` |
| 169948 | `EnumDisplayDevicesA` |
| 167148 | `http://` |
| 179856 | `SEESION` |
| 172940 | `FlsFree` |
| 172972 | `FlsAlloc` |
| 180396 | `A_u^?C^alrn/ill` |
| 179308 | `GetActiveWindow` |
| 172832 | `CorExitProcess` |
| 179696 | `

` |
| 171128 | `HtmlHelpA` |
| 172960 | `FlsGetValue` |
| 172948 | `FlsSetValue` |
| 179324 | `MessageBoxA` |
| 169872 | `AfxOleControl90s` |
| 169852 | `AfxFrameOrView90s` |
| 169816 | `AfxControlBar90s` |
| 175052 | `e+000` |
| 180372 | `Excep while up %s: %s` |
| 210328 | `qamq.*tyq` |
| 167848 | `KERNEL32` |
| 210372 | `tarecchttapgadfs+lhq` |
| 174704 | `Runtime Error!

Program: ` |
| 167712 | `HTTP/1.0` |
| 210192 | `Y?sv_iiuY?` |
| 210212 | `Y?sv_iiuY?` |
| 210112 | `@knubjt.Qnaopbes*Andl`iod6` |
| 179832 | `
Active Window: ` |
| 172924 | `DecodePointer` |
| 209988 | `jqluflasq+fpoi-e^pa<` |
| 172880 | `EncodePointer` |
| 209860 | `{ClipBoard Data:` |
| 210148 | `@knubjt.Aesqloiufkn;` |
| 210048 | `@knubjt.Aesqloiufkn;` |
| 169836 | `AfxMDIFrame90s` |
| 174968 | `bad exception` |
| 210012 | `@knubjt.Aesqloiufkn;` |
| 210340 | `A]tb?]clrl` |

### Constants / Known Patterns (29)
| Category | Value |
|---|---|
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| exception | `exception::C++ exception` |
| exception | `exception::FuncInfo header` |
| exception | `exception::CLR exception` |
| guid | `guid::IShellLinkA` |
| guid | `guid::IPersistFile` |
| guid | `guid::IAccessible` |
| guid | `guid::IDispatch` |
| guid | `guid::IOleWindow` |
| runtime | `runtime::msvc_r6034` |
| runtime | `runtime::msvc_r6033` |
| runtime | `runtime::msvc_r6031` |
| runtime | `runtime::msvc_r6027` |
| runtime | `runtime::msvc_r6026` |
| runtime | `runtime::msvc_r6025` |
| runtime | `runtime::msvc_r6024` |
| runtime | `runtime::msvc_r6019` |
| runtime | `runtime::msvc_r6018` |
| runtime | `runtime::msvc_r6017` |
| runtime | `runtime::msvc_r6016` |
| runtime | `runtime::msvc_r6009` |
| runtime | `runtime::msvc_r6008` |
| runtime | `runtime::msvc_r6002` |
| runtime | `runtime::msvc_runtime` |
| runtime | `runtime::msvc_date` |
| guid | `guid::IUnknown` |
| guid | `guid::IFileDialogEvents` |
| guid | `guid::IFileDialogControlEvents` |

### Imports (1573)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1040 | std::bad_alloc.#0 | DEBUG | 1 |
| 1392 | std::out_of_range.#1 | DEBUG | 3 |
| 1408 | std::logic_error.#0 | DEBUG | 1 |
| 17376 | CFileException.#1 | DEBUG | 1 |
| 17456 | CPtrArray.#2 | DEBUG | 26 |
| 18944 | ATL.CSimpleStringT<char,0>.SetLength | DEBUG | 3 |
| 19453 | AfxSetNewHandler | DEBUG | 11 |
| 19476 | operator new | DEBUG | 36 |
| 19523 | operator delete | DEBUG | 78 |
| 19534 | operator new[] | DEBUG | 1 |
| 19545 | COleException.#0 | DEBUG | 1 |
| 19551 | AfxCrtErrorCheck | DEBUG | 5 |
| 19697 | COleException.COleException | DEBUG | 1 |
| 19721 | AfxThrowOleException | DEBUG | 1 |
| 19788 | COleException.#4 | DEBUG | 1 |
| 19788 | COleException.GetErrorMessage | DEBUG | 1 |
| 19880 | COleException.#1 | DEBUG | 1 |
| 19914 | ATL.CSimpleStringT<char,0>.AppendChar | DEBUG | 2 |
| 19959 | CException.Delete | DEBUG | 6 |
| 19973 | CUserException.#3 | DEBUG | 10 |
| 19984 | CUserException.#5 | DEBUG | 10 |
| 19984 | CException.ReportError | DEBUG | 10 |
| 20100 | CSimpleException.#0 | DEBUG | 1 |
| 20106 | CMemoryException.#0 | DEBUG | 1 |
| 20112 | CNotSupportedException.#0 | DEBUG | 1 |
| 20118 | CInvalidArgException.#0 | DEBUG | 1 |
| 20124 | CSimpleException.InitString | DEBUG | 1 |
| 20251 | CThreadLocal<_AFX_THREAD_STATE>.CreateObject | DEBUG | 13 |
| 20298 | CException.CException | DEBUG | 4 |
| 20308 | CException.CException | DEBUG | 2 |
| 20325 | CUserException.#4 | DEBUG | 6 |
| 20325 | CSimpleException.GetErrorMessage | DEBUG | 6 |
| 20409 | CUserException.#1 | DEBUG | 5 |
| 20443 | _strnlen_s | DEBUG | 1 |
| 20464 | AfxLoadString | DEBUG | 1 |
| 20554 | AfxFindStringResourceHandle | DEBUG | 2 |
| 20650 | CAfxStringMgr.#0 | DEBUG | 1 |
| 20650 | CAfxStringMgr.Allocate | DEBUG | 1 |
| 20713 | CAfxStringMgr.#1 | DEBUG | 1 |
| 20731 | CAfxStringMgr.#2 | DEBUG | 1 |
| 20731 | CAfxStringMgr.Reallocate | DEBUG | 1 |
| 20781 | CAfxStringMgr.#4 | DEBUG | 1 |
| 20823 | CAfxStringMgr.CAfxStringMgr | DEBUG | 1 |
| 20858 | CAfxStringMgr.#3 | DEBUG | 1 |
| 20858 | CAfxStringMgr.GetNilString | DEBUG | 1 |
| 20872 | StringLengthWorkerA | DEBUG | 1 |
| 20950 | CStdioFile.#20 | DEBUG | 4 |
| 20955 | CFile.#0 | DEBUG | 1 |
| 21103 | StringCchLengthA | DEBUG | 1 |
| 21158 | CFile.#13 | DEBUG | 2 |
| 21158 | CFile.Read | DEBUG | 2 |
| 21224 | CFile.#14 | DEBUG | 1 |
| 21224 | CFile.Write | DEBUG | 1 |
| 21301 | CFile.#10 | DEBUG | 1 |
| 21301 | CFile.Seek | DEBUG | 1 |
| 21384 | CFile.#3 | DEBUG | 1 |
| 21384 | CFile.GetPosition | DEBUG | 1 |
| 21460 | CFile.#18 | DEBUG | 1 |
| 21460 | CFile.Flush | DEBUG | 1 |
| 21501 | CFile.#15 | DEBUG | 1 |
| 21554 | CFile.#16 | DEBUG | 1 |
| 21607 | CStdioFile.#11 | DEBUG | 2 |
| 21607 | CFile.SetLength | DEBUG | 2 |
| 21661 | CFile.#12 | DEBUG | 3 |
| 21661 | CFile.GetLength | DEBUG | 3 |
| 21726 | AfxGetFileTitle | DEBUG | 1 |
| 21836 | CFile.#19 | DEBUG | 3 |
| 21836 | CFile.Close | DEBUG | 3 |
| 21905 | CFile.#17 | DEBUG | 2 |
| 21905 | CFile.Abort | DEBUG | 2 |
| 21938 | CFile.CFile | DEBUG | 3 |
| 21969 | CFile.#9 | DEBUG | 1 |
| 21969 | CFile.Duplicate | DEBUG | 1 |
| 22157 | CFile.~CFile | DEBUG | 6 |
| 22408 | CFile.#1 | DEBUG | 1 |
| 22408 | CFile.`scalar deleting destructor' | DEBUG | 1 |
| 22488 | _AfxFullPath2 | DEBUG | 1 |
| 22935 | CStdioFile.#7 | DEBUG | 4 |
| 22961 | CFile.#8 | DEBUG | 3 |
| 22961 | CFile.Open | DEBUG | 3 |

### Functions (30)
| EA | Name |
|---|---|
| 113106 | sub_41c5d2 |
| 116700 | sub_41d3dc |
| 13744 | sub_4041b0 |
| 46572 | #29 |
| 13312 | sub_404000 |
| 116090 | sub_41d17a |
| 104532 | sub_41a454 |
| 158459 | 58 |
| 158713 | 61 |
| 158995 | 64 |
| 156233 | 5 |
| 156284 | 6 |
| 156865 | 20 |
| 157278 | 29 |
| 157375 | 31 |
| 157463 | 33 |
| 157709 | 40 |
| 157856 | 43 |
| 158912 | 63 |
| 141568 | sub_423500 |
| 141736 | sub_4235a8 |
| 6352 | sub_4024d0 |
| 11344 | sub_403850 |
| 139072 | 4 |
| 156340 | 7 |
| 156376 | 8 |
| 156411 | 9 |
| 156446 | 10 |
| 156482 | 11 |
| 156528 | 12 |

### Decompilations (top 6)
#### 113106 — sub_41c5d2
```c

/* WARNING: This function may have set the stack pointer */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 __fastcall sub_41c5d2(int32_t param_1,char param_2)

{
    int32_t *piVar1;
    int32_t iVar2;
    int32_t unaff_EBP;
    char *unaff_EDI;
    
    *(param_1 + -0x43) = *(param_1 + -0x43) + param_1 + '\x01';
    *(unaff_EBP + -0x5effbe44) = *(unaff_EBP + -0x5effbe44) + param_2;
    *unaff_EDI = *unaff_EDI + param_2;
    piVar1 = *0xbce70045;
    bce7003d = unaff_EBP;
    if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) &&
       ((iVar2 = piVar1[5], iVar2 == 0x19930520 ||
        (((iVar2 == 0x19930521 || (iVar2 == 0x19930522)) || (iVar2 == 0x1994000)))))) {
        [0x0xbce70039] = 0x41c62e;
        terminate();
    }
    return 0;
}

```
#### 116700 — sub_41d3dc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_41d3dc(void)

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
            sub_41d17a(piVar1, *(unaff_EBP + 0x10));
        }
    }
    return;
}

```
#### 13744 — sub_4041b0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_4041b0(void)

{
    int32_t iVar1;
    int32_t *unaff_EDI;
    undefined4 uStack_258;
    int32_t **ppiStack_254;
    int32_t *piStack_250;
    undefined4 *puStack_24c;
    int32_t *piStack_248;
    int32_t **ppiStack_244;
    int32_t *piStack_240;
    undefined4 *puStack_23c;
    int32_t *piStack_238;
    int32_t *piStack_234;
    undefined4 uStack_230;
    int32_t *piStack_22c;
    undefined4 uStack_228;
    undefined *puStack_224;
    undefined *puStack_220;
    undefined4 uStack_21c;
    undefined auStack_214 [528];
    uint32_t uStack_4;
    
    uStack_4 = [0x0x432be0#SecurityCookie] ^ auStack_214;
    uStack_21c = 0;
    puStack_220 = 0x4041cf;
    (*ole32.CoInitialize)();
    puStack_220 = &stack0xfffffde8;
    puStack_224 = &IShellLinkA;
    uStack_228 = 1;
    piStack_22c = 0x0;
    uStack_230 = 0x429530;
    piStack_234 = 0x4041e8;
    iVar1 = (*ole32.CoCreateInstance)();
    if (-1 < iVar1) {
        piStack_238 = piStack_22c;
        puStack_23c = 0x4041f9;
        (**(*piStack_22c + 0x50))();
        puStack_23c = 0x42c982;
        piStack_240 = piStack_234;
        ppiStack_244 = 0x40420a;
        (**(*piStack_234 + 0x1c))();
        ppiStack_244 = &piStack_238;
        piStack_248 = &IPersistFile;
        puStack_24c = puStack_23c;
        piStack_250 = 0x40421f;
        iVar1 = (***puStack_23c)();
        if (-1 < iVar1) {
            piStack_250 = 0x104;
            ppiStack_254 = &piStack_240;
            uStack_258 = 0xffffffff;
            (*kernel32.MultiByteToWideChar)(0, 0);
            (**(*unaff_EDI + 0x18))(unaff_EDI, &uStack_258);
            (**([0x0x1] + 8))(1);
        }
        piStack_250 = piStack_248;
        ppiStack_254 = 0x404269;
        (**(*piStack_248 + 8))();
    }
    uStack_230 = 0x40427a;
    sub_411faa();
    return;
}

```

### Carved Files (7)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | DIB | 67624 |
| ? | DIB | 9640 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |

### Virtual Files (10)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/id-id | 3752 | - |
| ICO/2/id-id | 2216 | - |
| ICO/3/id-id | 1384 | - |
| ICO/4/id-id | 67624 | - |
| ICO/5/id-id | 9640 | - |
| ICO/6/id-id | 4264 | - |
| ICO/7/id-id | 1128 | - |
| GRPICO/131/id-id | 104 | - |
| VER/1/id-id | 720 | - |
| MANIF/1/en-us | 346 | - |

### Structures (70)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 240 |
| OptionalHeader | 264 |
| Sections | 488 |
| advapi32.FT | 164864 |
| comdlg32.FT | 164872 |
| gdi32.FT | 164880 |
| kernel32.FT | 164976 |
| oleacc.FT | 165464 |
| oleaut32.FT | 165476 |
| shell32.FT | 165492 |
| shlwapi.FT | 165500 |
| user32.FT | 165520 |
| wininet.FT | 165884 |
| winspool.FT | 165940 |
| ole32.FT | 165956 |
| LoadConfigurationTable | 180416 |
| SEHandlers | 185712 |
| ImportTable | 193020 |
| advapi32.OFT | 193280 |
| comdlg32.OFT | 193288 |
| gdi32.OFT | 193296 |
| kernel32.OFT | 193392 |
| oleacc.OFT | 193880 |
| oleaut32.OFT | 193892 |
| shell32.OFT | 193908 |
| shlwapi.OFT | 193916 |
| user32.OFT | 193936 |
| wininet.OFT | 194300 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 22 · duration_s: 1.08

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| log keystrokes via application hook | T1056.001:Input Capture | F0002.001:Keylogging |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get hostname | T1082:System Information Discovery | E1082:System Information Discovery |
| get session user name | T1033:System Owner/User Discovery, T1087:Account Discovery |  |
| connect to HTTP server |  | C0002.009:HTTP Communication |
| create HTTP request |  | C0002.012:HTTP Communication |
| open clipboard | T1115:Clipboard Data |  |
| read clipboard data | T1115:Clipboard Data |  |
| create directory |  | C0046:Create Directory |
| delete file |  | C0047:Delete File |
| move file |  | C0063:Move File |
| get graphical window text |  | E1010:Application Window Discovery |
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 264

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| http_client | InternetOpen | T1071.001 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@295772 len=16; $ipv6@176064 len=6 |
| contains_base64 | - | $a@162639 len=12 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@216 len=4 |
| VC8_Microsoft_Corporation | - | $a@22742 len=10 |
| Microsoft_Visual_Cpp_8 | - | $a@671 len=82; $b@61476 len=10 |
| SEH_Save | - | $a@76034 len=7 |
| SEH_Init | - | $a@1244 len=6; $b@104575 len=7 |
| anti_dbg | - | $d1@191098 len=12; $c2@193100 len=17 |
| win_hook | - | $f1@175752 len=10; $c1@191366 len=19; $c2@191278 len=17; $c3@191260 len=14 |
| network_http | - | $f1@163812 len=11; $c1@163429 len=15; $c2@191716 len=12; $c4@191806 len=16; $c5@191786 len=17; $c6@191886 len=15; $c7@191844 len=15 |
| screenshot | - | $d1@195402 len=9; $d2@175752 len=10; $c2@193990 len=5 |
| keylogger | - | $f1@175752 len=10; $c1@191222 len=16; $c2@191114 len=11 |
| win_files_operation | - | $f1@191098 len=12; $c1@191794 len=9; $c2@191768 len=14; $c3@191794 len=9; $c4@191814 len=8; $c5@191048 len=11; $c6@192324 len=11; $c7@192262 len=14 |
| Str_Win32_Wininet_Library | - | $wininet_lib@163812 len=11 |
| Str_Win32_Internet_API | - | $wininet_call_closeh@191662 len=19; $wininet_call_readf@191806 len=16; $wininet_call_connect@163429 len=15; $wininet_call_open@191716 len=12 |
| Str_Win32_Http_API | - | $wininet_call_httpr@191844 len=15; $wininet_call_httpo@191886 len=15 |

## Generated YARA Meta
```json
{
  "rule_count": 19,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
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
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 295772,
          "length": 16,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 176064,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 162639,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 216,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "VC8_Microsoft_Corporation",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 22742,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Cpp_8",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 671,
          "length": 82,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 61476,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 76034,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 1244,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 104575,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$d1",
          "offset": 191098,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 193100,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_hook",
      "path": "/opt/samples/corpus/malware/ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98/msdsrv.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 175752,
          "length": 10,
          "xor_key": null
        },
        {
          "id"
```

## FLOSS Strings
Total strings: 1166 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1165}`

### FLOSS sample
- `DataABackup.lnk`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `@.reloc`
- `D$DSUVW`
- `D$@9|$Ts`
- `D$tPQPVU`
- `\$@9|$8r`
- `L$ _^3`
- `?????????????`
- `??????????????????`
- `!"#$%&?????'()*+,-./0??????????????????????????????????????????????????????112233????????????????????456789:??????????????????????????;<=>`
- `L$0QjnP`
- `SSjPSP`
- `SSOWVQ`
- `HtpHHt`
- `u6hgo@`
- `td9~<u_`
- `9~<u;h`
- `N8;N@r(`
- `8\t	j/`
- `+F(_^[;E`
- `F(@@;F,v`
- `F(;^ r`
- `F(;F0u`
- `^(_^[]`
- `<A|0<Z`
- `<A|S<Z`
- `u*h`FC`
- `S\_^[]`
- `t39w u&`
- `_ 9w$u`
- `9~Pu	P`
- `t	9p(u`
- `Ht;O u`
- `u:j0^V`
- `SVWj(3`
- `tj9~8u@j`
- `9~8ucj`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00413062
```asm
┌ 320: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_20h @ ebp-0x20
│       ╎   ; var int32_t var_38h @ ebp-0x38
│       ╎   ; var int32_t var_3ch @ ebp-0x3c
│       ╎   ; var int32_t var_68h @ ebp-0x68
│       ╎   0x00413062      e8509c0000     call 0x41ccb7
│       └─< 0x00413067      e978feffff     jmp 0x412ee4
..
```
### 0x004042e0
```asm
; CALL XREF from entry0 @ 0x412ff2(x)
┌ 343: int main (int argc, char **argv, char **envp);
│           ; var int32_t var_ch_2 @ esp+0x24
│           ; var int32_t var_10h @ esp+0x28
│           ; var int32_t var_ch @ esp+0x34
│           ; var int32_t var_20h_2 @ esp+0x38
│           ; var int32_t var_1ch @ esp+0x44
│           ; var int32_t var_20h @ esp+0x48
│           ; var int32_t var_24h @ esp+0x4c
│           ; var int32_t var_2ch_2 @ esp+0x54
│           ; var int32_t var_30h @ esp+0x58
│           ; var int32_t var_28h @ esp+0x68
│           ; var int32_t var_2ch @ esp+0x6c
│           ; var int32_t var_38h_2 @ esp+0x70
│           ; var int32_t var_3ch @ esp+0x74
│           ; var int32_t var_38h @ esp+0x78
│           ; var int32_t var_128h @ esp+0x148
│           ; var int32_t var_12ch @ esp+0x150
│           ; var int32_t var_130h @ esp+0x160
│           ; var int32_t var_22ch @ esp+0x254
│           ; var int32_t var_230h @ esp+0x270
│           ; var int32_t var_328h @ esp+0x378
│           0x004042e0      81ec2c030000   sub esp, 0x32c
│           0x004042e6      a1e02b4300     mov eax, dword [0x432be0]   ; [0x432be0:4]=0xbb40e64e
│           0x004042eb      33c4           xor eax, esp
│           0x004042ed      8984242803..   mov dword [var_328h], eax
│           0x004042f4      56             push esi
│           0x004042f5      57             push edi
│           0x004042f6      e845fdffff     call 0x404040
│           0x004042fb      e870dcffff     call 0x401f70
│           0x00404300      e87bf2ffff     call 0x403580
│           0x00404305      e806f3ffff     call 0x403610
│           0x0040430a      8b352c924200   mov esi, dword [sym.imp.KERNEL32.dll_Sleep] ; [0x42922c:4]=0x303da reloc.KERNEL32.dll_Sleep
│           0x00404310      68d0070000     push 0x7d0                  ; 2000
│           0x00404315      ffd6           call esi
│           0x00404317      e834f5ffff     call 0x403850
│           0x0040431c      8b0db0cc4200   mov ecx, dword [0x42ccb0]   ; [0x42ccb0:4]=0x615e433f ; "?C^alrn/ill"
│           0x00404322      a1accc4200     mov eax, dword [str.A_u_Calrn_ill] ; [0x42ccac:4]=0x5e755f41 ; "A_u^?C^alrn/ill"
│           0x00404327      8b15b4cc4200   mov edx, dword [0x42ccb4]   ; [0x42ccb4:4]=0x2f6e726c ; "lrn/ill"
│           0x0040432d      68f4000000     push 0xf4                   ; 244
│           0x00404332      894c242c       mov dword [var_2ch], ecx
│           0x00404336      89442428       mov dword [var_28h], eax
│           0x0040433a      a1b8cc4200     mov eax, dword [0x42ccb8]   ; [0x42ccb8:4]=0x6c6c69 ; "ill"
│           0x0040433f      8d4c2438       lea ecx, [var_38h]
│           0x00404343      6a00           push 0
│           0x00404345      51             push ecx
│           0x00404346      89542438       mov dword [var_38h_2], edx
│           0x0040434a      8944243c       mov dword [var_3ch], eax
│           0x0040434e      e89df90000     call 0x413cf0
│           0x00404353      83c40c 
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000F0 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!LoadLibraryA`
  - `KERNEL32.dll!ReadFile`
  - `KERNEL32.dll!WriteFile`
  - `KERNEL32.dll!SetFilePointer`
  - `KERNEL32.dll!FlushFileBuffers`
  - `USER32.dll!GetClientRect`
  - `USER32.dll!SetForegroundWindow`
  - `USER32.dll!SetMenu`
  - `USER32.dll!MapWindowPoints`
  - `USER32.dll!GetMessagePos`
  - `ADVAPI32.dll!GetUserNameA`
  - `SHELL32.dll!SHGetSpecialFolderPathA`
  - `ole32.dll!CoCreateInstance`
  - `ole32.dll!CoInitialize`
  - `SHLWAPI.dll!PathFindFileNameA`
  - `SHLWAPI.dll!PathIsUNCA`
  - `SHLWAPI.dll!PathStripToRootA`
  - `SHLWAPI.dll!PathAppendA`
  - `WININET.dll!HttpOpenRequestA`
  - `WININET.dll!InternetConnectA`
  - `WININET.dll!HttpSendRequestExA`
  - `WININET.dll!HttpEndRequestA`
  - `WININET.dll!InternetReadFile`
  - `OLEACC.dll!LresultFromObject`
  - `OLEACC.dll!CreateStdAccessibleObject`
  - `GDI32.dll!CreateBitmap`
  - `GDI32.dll!DeleteObject`
  - `GDI32.dll!SaveDC`
  - `GDI32.dll!RestoreDC`
  - `GDI32.dll!SetBkColor`
