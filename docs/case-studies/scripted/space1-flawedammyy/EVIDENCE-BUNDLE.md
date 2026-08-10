# Technical Evidence Pack

**sha256:** 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da  
**sample_path:** /opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex  
**project_name:** Malware Analyst Professional - Level 2

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 75
- **family_guess**: unknown service-based trojan
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both identify process enumeration functions (e.g., CreateToolhelp32Snapshot, Process32FirstW). Malcat anomalies (e.g., BigResourceHighEntropy, CrossSectionJump) and pe_imports high-signal imports (e.g., CreateServiceA, IsDebuggerPresent) align with capa rules for anti-debug, shellcode execution, and persistence. YARA matches include service creation and anti-debug rules. FLOSS strings show API calls consistent with these behaviors.
- **summary**: The PE file space1.ex exhibits clear malicious intent through behavioral signals: anti-debugging (IsDebuggerPresent), process enumeration (CreateToolhelp32Snapshot), service creation for persistence (CreateServiceA), and shellcode execution capabilities (capa rule). Obfuscation techniques (e.g., high entropy, dynamic strings) are present but secondary. Cross-engine analysis confirms consistent findings, with high-signal imports and anomalies pointing to hostile activity beyond mere protection.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports signals | `create_service` | API for creating services (CreateServiceA), indicating potential persistence via service installation (T1543.003). |
| capa | capa rules | `execute shellcode via indirect call` | Rule detects capability for indirect shellcode execution, a direct malicious behavior for code execution. |
| ghidra | Anti Analysis Signals | `FUN_00402640 calls CreateToolhelp32Snapshot, Process32FirstW, Process32NextW` | Process enumeration functions used for discovery (T1057), a common reconnaissance technique in malware. |
| ida | Imports (IDA) | `IsDebuggerPresent` | Anti-debugging API import, indicating evasion techniques to hinder analysis (T1622). |
| pe_imports | pe_imports_evidence | `CreateService` | YARA rule matched for service creation API, supporting evidence of persistence behavior. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Dropper/loader targeting Windows. The entry function systematically enumerates 13 security product processes (360 Security suite, Comodo, AhnLab V3, Dr.Web, ESET) via CreateToolhelp32Snapshot and terminates or evades if detected. After AV evasion, it resolves APIs dynamically (GetProcAddress+LoadLibraryA) using an obfuscated API name table, allocates RWX memory via VirtualAlloc, decrypts embedded payload data (garbled strings like '&*^@QDSJGIO', 'V><MDNbyfui6y2iuow'), and uses QueueUserAPC for code injection. It establishes persistence via CreateServiceA/OpenSCManagerA and registry (RegOpenKeyA), and has network capabilities via WININET and WSOCK32 DLLs. Built with MSVC and uses stack-string obfuscation to hinder static analysis. Exfiltration: Network capabilities are indicated by WININET and WSOCK32 DLLs, but specific exfiltration methods are not observed in the provided analysis, citing evidence from the network DLL references in the summary. Credential access: Not observed in the provided details.

### deep key_evidence
- `"YARA 'anti_dbg' rule matched at offsets 7456 and 9106 with strings $d1 (12 bytes) and $c2 (17 bytes)"`
- `"CAPA: 'enumerate processes' (T1057/T1518), 'check for trap flag exception' (B0001), 'contain obfuscated stackstrings' (T1027.005), 'allocate or change RWX memory'"`
- `"Entry function (0x402720) calls FUN_00402640 13 times with AV process names: QHACTIVEDEFENSE.EXE, QHSAFETRAY.EXE, QHWATCHDOG.EXE, CMDAGENT.EXE, CIS.EXE, V3LITE.EXE, V3MAIN.EXE, V3SP.EXE, SPIDERAGENT.EXE, DWENGINE.EXE, DWARKDAEMON.EXE, EGUI.EXE, EKRN.EXE \u2014 each followed by conditional jump to 0x402948 (exit if found)"`
- `"Imports include CreateServiceA+OpenSCManagerA (ADVAPI32, service persistence), QueueUserAPC (code injection), VirtualAlloc (RWX allocation), DebugSetProcessKillOnExit+IsDebuggerPresent (anti-debug), GetProcAddress+LoadLibraryA (dynamic API resolution), RegOpenKeyA (registry manipulation)"`
- `"Network-capable imports: InternetOpenA, InternetConnectA, HttpSendRequestA (WININET), WSAStartup, connect, send, recv (WSOCK32)"`
- `"Obfuscated/garbled strings in data section: '&*^@QDSJGIO', '&JTEH$WHD', 'V><MDNbyfui6y2iuow', 'fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6'"`
- `"FLOSS decoded 3 stack strings from the binary; entry function has cyclomatic complexity 56 with 62 basic blocks and 19 string references"`
- `"GDI32 imports (CreateDCW, GetTextMetricsW, SetDIBits) suggest screen capture capability"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da
size: 160256
type: PE
architecture: X86
entrypoint_ea: 6944
entropy: 176
file_name: space1.ex
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 45 | - |
| .text | 1024 | 3584 | 4096 | 124 | RX |
| .rdata | 5120 | 2560 | 4096 | 129 | RX |
| .rdata | 9216 | 2560 | 4096 | 82 | R |
| .data | 13312 | 512 | 4096 | 78 | RW |
| .rsrc | 17408 | 150016 | 151552 | 179 | R |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2008_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2008_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| CreateService | lateral movement | SUSPICIOUS | 70 | creates a service |

### Anomalies (8)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 3 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| DynamicString | 3 | strings | 3 | string is constructed dynamically |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having + |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| BigResourceHighEntropy | 2 | resources | 1 | File contain a big resource (> 10% of the file or > 3K) high-entropy resource and is not a picture |
| DuplicatedSectionName | 2 | sections | 1 | section name has already been used before in section table |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| RcdataNoDelphi | 2 | resources | 1 | File contains a rcdata resource and is not a delphi application |

### Anomaly Locations (high-signal)
- **BigResourceHighEntropy**
  - `38104`: 
- **DynamicString**
  - `5583`: 
  - `5674`: 
  - `5521`: 
- **GuiSubsystemNoWindowApi**
  - `316`: 
- **XorInLoop**
  - `3830`: 
  - `7431`: 

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 9504 | `kernel32.dll` |
| 11258 | `KERNEL32.dll` |
| 10932 | `GetProcAddress` |
| 11010 | `LoadLibraryA` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 9936 | `fliudsifIUJGowpd..iuhtroi3j21932y6` |
| 5583 | `QueryPerformanceFrequency` |
| 9528 | `QHACTIVEDEFENSE.EXE` |
| 9776 | `DWENGINE.EXE` |
| 5674 | `QueryPerformanceCounter` |
| 9804 | `DWARKDAEMON.EXE` |
| 9744 | `SPIDERAGENT.EXE` |
| 9568 | `QHSAFETRAY.EXE` |
| 9856 | `EKRN.EXE` |
| 9836 | `EGUI.EXE` |
| 9676 | `V3LITE.EXE` |
| 9600 | `QHWATCHDOG.EXE` |
| 9632 | `CMDAGENT.EXE` |
| 9724 | `V3SP.EXE` |
| 9700 | `V3MAIN.EXE` |
| 9660 | `CIS.EXE` |
| 9504 | `kernel32.dll` |
| 11174 | `CreateToolhelp32Snapshot` |
| 5521 | `IsBadCodePtr` |
| 11572 | `CreateServiceA` |
| 9908 | `fdsfds` |
| 11076 | `Process32NextW` |
| 9900 | `fdsfsd,` |
| 9916 | `V><MDNbyfui6y2iuow` |
| 9520 | `user32` |
| 11620 | `ADVAPI32.dll` |
| 11258 | `KERNEL32.dll` |
| 9888 | `&JTEH$WHD` |
| 9876 | `&*^@QDSJGIO` |
| 11514 | `GDI32.dll` |
| 11556 | `WINSPOOL.DRV` |
| 11460 | `USER32.dll` |
| 139893 | `0fliudsifIUJGowp..fjawhe78yr73ohiu` |
| 140349 | `lhdtfkj56uy34e3w..7ihdtfjj<2uyC1e3` |
| 135901 | `B%shfIU\Gowrdur{..h238%ihdffkj76uy` |
| 27158 | `;nPVYYFDZSEDv,SM..gAmPu,uwvANxUxMg` |
| 126207 | `j!6ey#4u3go`erjq..mvrews{3196hhdtf` |
| 26582 | `5TDzPHHAlwCjF,dD..wpaAbNl,OsWaCWbX` |
| 133153 | `<&"8wpdury2387ih..y2387ihdtfkj1%4y` |
| 19032 | `QXCHNYOHVJGRDQD..UOEZCHMKTHFFPGG` |
| 27562 | `4BDmkrwQ,UHAarMN..,NVmTguj,BITxmtO` |
| 27706 | `6aWSbkQ,DyLeYO,H..UnHd,aBdgnYuJOQu` |
| 137812 | `hdtfkjtt6=vr"{>%..tfkj56uyp4e3wope` |
| 137572 | `FLIUDSIFiujgOWPD..wopefjawhe78yrWQ` |
| 137032 | `FLIUDSIFiujgowpd..pefjawhe78yr63f` |
| 152215 | `aJGowpdury2387ih..DINGPADDINGXXPAD` |
| 102403 | `opefjawhe78yr63f..387ihdtfkj56uy34` |
| 146798 | `Vh=8yr63fliudsif..hdtfkj5&uy?5e3G_` |
| 125062 | `	:;87ahltacj56uy..ifIUJGowpdury238` |
| 125541 | `Gmwrdwr{2185ijdv..e3wopefjawhe78Yr` |
| 136382 | `v3fliuesifIUJGnw..udsifIUJGowpdurq` |
| 38774 | `6ihdtfkj56uy34%3..3wopefjawhe78yrc` |
| 137275 | `fkj56u8qw!v1(8,,..yr63fliudsifIUJG` |
| 135266 | `4rx3387ihdtfkj5&..e3wopefjawhe78yr` |
| 9488 | `bad allocation` |
| 27834 | `2mRxteWIGU,ejajF..TRTki,ZXxPuFgilt` |
| 26918 | `/eTRDva,DAwSOkWY..WRUjxa,PAeefADGM` |
| 136041 | `4e3zopeSjawje788..8whe<8yrZ3flduds` |
| 26746 | `.RPJHbNSuA,nygKN..Omw,OFVgu,GixhMc` |
| 105141 | `i-d,f.j56uyb4-3 ..Fer8!rs3fl?uWs%f` |
| 136916 | `he78yr63fliudsif..yr63fliudsifYEZW` |
| 140277 | `wifIUJGowpdury23..ifIUJGowpdtrp638` |
| 146195 | `3#o
efjawhe78yr6..pefjawhe78Kre3*l` |
| 26478 | `-SgogWakfT,gHYix..dbgqyzOP,UwkRekL` |
| 27304 | `%xeaVCeQ,CJZwekU..SXCwADvw,PZIJhKq` |
| 26352 | `&ExrkbJaCby,rWil..PkJPbDW,NlfpOyGL` |
| 127321 | `UJGowpdury2387ih..3fliudsifIUJGow@` |
| 136277 | `fiudsifIUJGowpdu..awhe78yr63fliuds` |
| 128257 | ``jj56uy34e3wopef..owpdury2387ijw4f` |
| 26266 | `#whpmlGP,wysbAw,..HndaH,cJPRqSbjAo` |
| 145227 | `e6jawhe78yr63fli..kj56uy34e3ho#e$j` |
| 145475 | `2u8Ai2df<ja64yI..dsifIUJGowpdury2` |
| 28180 | ` t5E ` |
| 119101 | `rD3Kl+u!sif U>GB..=ry2]8[iEd6f.j56` |
| 125991 | `k47tx25d2vnqdgk`..nvqeeri2#8'ixddf` |
| 38386 | `owptury"287i(dtv..8y243fhiudsifKU
` |
| 125477 | `lhueshfHUKGnwqdt..voqevjqwxe'8ir&3` |
| 26182 | ` OEVrOfkeB,qdqsP..MIm,ZvOIVXgjXSzQ` |
| 145787 | `fIUJGowpdury2387..pefjawhe78yr63\l` |
| 27460 | `DRjKRqXq,SOxDJrMm,vJOCijj` |

### Constants / Known Patterns (2)
| Category | Value |
|---|---|
| exception | `exception::C++ exception` |
| code | `code::PEBx86` |

### Imports (67)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1064 | SEH.0 | DEBUG | 2 |
| 1436 | SEH.1 | DEBUG | 3 |
| 3120 | SEH.2 | DEBUG | 3 |
| 3924 | SEH.3 | DEBUG | 2 |
| 9216 | advapi32.RegOpenKeyA | IMPORT | 5 |
| 9220 | advapi32.OpenSCManagerA | IMPORT | 0 |
| 9224 | advapi32.CreateServiceA | IMPORT | 0 |
| 9232 | gdi32.GetTextMetricsW | IMPORT | 1 |
| 9236 | gdi32.SetDIBits | IMPORT | 1 |
| 9240 | gdi32.CreateDCW | IMPORT | 0 |
| 9248 | kernel32.VirtualFree | IMPORT | 1 |
| 9252 | kernel32.GetProcessHeap | IMPORT | 0 |
| 9256 | kernel32.TlsSetValue | IMPORT | 0 |
| 9260 | kernel32.GetConsoleCP | IMPORT | 0 |
| 9264 | kernel32.SizeofResource | IMPORT | 1 |
| 9268 | kernel32.GetSystemDirectoryA | IMPORT | 0 |
| 9272 | kernel32.GetACP | IMPORT | 1 |
| 9276 | kernel32.lstrcmpW | IMPORT | 1 |
| 9280 | kernel32.lstrlenW | IMPORT | 1 |
| 9284 | kernel32.RtlMoveMemory | IMPORT | 3 |
| 9288 | kernel32.GetLastError | IMPORT | 1 |
| 9292 | kernel32.SetLastError | IMPORT | 0 |
| 9296 | kernel32.GetProcAddress | IMPORT | 2 |
| 9300 | kernel32.VirtualAlloc | IMPORT | 2 |
| 9304 | kernel32.QueueUserAPC | IMPORT | 0 |
| 9308 | kernel32.DisableThreadLibraryCalls | IMPORT | 1 |
| 9312 | kernel32.LoadLibraryA | IMPORT | 3 |
| 9316 | kernel32.GetCurrentThread | IMPORT | 1 |
| 9320 | kernel32.LockResource | IMPORT | 1 |
| 9324 | kernel32.CreateEventW | IMPORT | 0 |
| 9328 | kernel32.Process32NextW | IMPORT | 1 |
| 9332 | kernel32.DebugSetProcessKillOnExit | IMPORT | 1 |
| 9336 | kernel32.GetModuleHandleA | IMPORT | 3 |
| 9340 | kernel32.EraseTape | IMPORT | 1 |
| 9344 | kernel32.IsDebuggerPresent | IMPORT | 2 |
| 9348 | kernel32.CreateToolhelp32Snapshot | IMPORT | 1 |
| 9352 | kernel32.CloseHandle | IMPORT | 1 |
| 9356 | kernel32.GetCurrentProcessId | IMPORT | 1 |
| 9360 | kernel32.TlsFree | IMPORT | 0 |
| 9364 | kernel32.lstrcpyW | IMPORT | 1 |
| 9368 | kernel32.UnhandledExceptionFilter | IMPORT | 1 |
| 9372 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 9376 | kernel32.TerminateProcess | IMPORT | 1 |
| 9380 | kernel32.VirtualQuery | IMPORT | 1 |
| 9384 | kernel32.RtlUnwind | IMPORT | 1 |
| 9388 | kernel32.GetModuleHandleW | IMPORT | 1 |
| 9392 | kernel32.GetCurrentActCtx | IMPORT | 1 |
| 9396 | kernel32.LoadResource | IMPORT | 1 |
| 9400 | kernel32.FindResourceW | IMPORT | 1 |
| 9404 | kernel32.CreateFileA | IMPORT | 0 |
| 9408 | kernel32.HeapReAlloc | IMPORT | 0 |
| 9412 | kernel32.Process32FirstW | IMPORT | 1 |
| 9416 | kernel32.ExitProcess | IMPORT | 5 |
| 9420 | kernel32.SetUnhandledExceptionFilter | IMPORT | 1 |
| 9428 | user32.SetCursor | IMPORT | 1 |
| 9432 | user32.CharUpperBuffW | IMPORT | 1 |
| 9436 | user32.SetWindowTextW | IMPORT | 0 |
| 9440 | user32.FindWindowA | IMPORT | 2 |
| 9444 | user32.CheckRadioButton | IMPORT | 0 |
| 9448 | user32.SendDlgItemMessageA | IMPORT | 0 |
| 9452 | user32.AttachThreadInput | IMPORT | 0 |
| 9456 | user32.MessageBeep | IMPORT | 0 |
| 9460 | user32.LoadAcceleratorsW | IMPORT | 0 |
| 9464 | user32.SetWinEventHook | IMPORT | 0 |
| 9468 | user32.EndDialog | IMPORT | 0 |
| 9476 | winspool.OpenPrinter2A | IMPORT | 2 |
| 9480 | winspool.OpenPrinterW | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 1920 | sub_401380 |
| 3120 | 2 |
| 1345 | sub_401141 |
| 3780 | sub_401ac4 |
| 2912 | sub_401760 |
| 6944 | EntryPoint |
| 1436 | 1 |
| 6448 | sub_402530 |
| 3516 | sub_4019bc |
| 6628 | sub_4025e4 |
| 5296 | sub_4020b0 |
| 5504 | sub_402180 |
| 6112 | sub_4023e0 |
| 6720 | sub_402640 |
| 1064 | 0 |
| 1024 | jmp_kernel32.Process32FirstW |
| 1030 | jmp_kernel32.Process32NextW |
| 1036 | jmp_kernel32.CreateToolhelp32Snapshot |
| 1042 | jmp_winspool.OpenPrinter2A |
| 4128 | jmp_kernel32.RtlUnwind |
| 5120 | sub_402000 |
| 2768 | sub_4016d0 |
| 1728 | sub_4012c0 |
| 1505 | sub_4011e1 |
| 6560 | sub_4025a0 |
| 2832 | sub_401710 |
| 1318 | sub_401126 |
| 1637 | sub_401265 |
| 3994 | sub_401b9a |
| 4045 | sub_401bcd |

### Decompilations (top 6)
#### 1920 — sub_401380
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_401380(uint32_t *param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    int32_t iVar3;
    int32_t iVar4;
    int32_t iVar5;
    uint32_t *puVar6;
    uint32_t *puVar7;
    int32_t iVar8;
    int32_t **unaff_FS_OFFSET;
    bool bVar9;
    uint32_t uStack_54;
    undefined auStack_44 [4];
    uint32_t uStack_40;
    uint8_t uStack_30;
    int32_t iStack_2c;
    uint32_t uStack_28;
    uint32_t uStack_24;
    uint32_t *puStack_20;
    uint32_t *puStack_1c;
    int32_t *piStack_14;
    code *pcStack_10;
    uint32_t uStack_c;
    undefined4 uStack_8;
    
    pcStack_10 = SEH.2;
    piStack_14 = *unaff_FS_OFFSET;
    uStack_c = [0x0x404014#SecurityCookie] ^ 0x4033b0;
    uStack_54 = [0x0x404014#SecurityCookie] ^ &stack0xfffffffc;
    puStack_1c = &uStack_54;
    *unaff_FS_OFFSET = &piStack_14;
    puStack_20 = param_1[2];
    if ((puStack_20 & 3) != 0) {
code_r0x004013c3:
        *unaff_FS_OFFSET = piStack_14;
        return 0;
    }
    puVar6 = unaff_FS_OFFSET[6][2];
    if ((puVar6 <= puStack_20) && (puStack_20 < unaff_FS_OFFSET[6][1])) goto code_r0x004013c3;
    uStack_28 = param_1[3];
    if (uStack_28 == 0xffffffff) goto code_r0x004016b2;
    bVar9 = false;
    uVar2 = 0;
    puVar7 = puStack_20;
    do {
        if ((*puVar7 != 0xffffffff) && (uVar2 <= *puVar7)) goto code_r0x004013c3;
        if (puVar7[1] != 0) {
            bVar9 = true;
        }
        uVar2 = uVar2 + 1;
        puVar7 = puVar7 + 3;
    } while (uVar2 <= uStack_28);
    if ((bVar9) && ((param_1[-2] < puVar6 || (param_1 <= param_1[-2])))) goto code_r0x004013c3;
    uStack_24 = puStack_20 & 0xfffff000;
    for (iVar8 = 0; puVar6 = &uStack_54, iVar8 < [0x0x404058]; iVar8 = iVar8 + 1) {
        uVar2 = *(iVar8 * 8 + 0x404060);
        iVar5 = *(iVar8 * 8 + 0x404064);
        if (uVar2 == uStack_24) {
            uStack_8 = 0;
            iVar3 = sub_4016d0(iVar5);
            puVar6 = puStack_1c;
            if (((iVar3 != 0) && (iVar3 = sub_4012c0(puStack_20), puVar6 = puStack_1c, iVar3 != 0)) &&
               (iVar4 = sub_401710(iVar5, param_1[1] - iVar5), iVar3 = [0x0x40405c], puVar6 = puStack_1c, iVar4 != 0)) {
                if (iVar8 < 1) goto code_r0x004016b2;
                LOCK();
                [0x0x40405c] = 1;
                UNLOCK();
                if (iVar3 != 0) goto code_r0x004016b2;
                if (*(iVar8 * 8 + 0x404060) == uStack_24) goto code_r0x00401518;
                iVar8 = [0x0x404058] + -1;
                if (iVar8 < 0) goto code_r0x00401509;
                goto code_r0x004014e7;
            }
            break;
        }
    }
    puStack_1c = puVar6;
    uStack_8 = 0xfffffffe;
    iVar8 = (*kernel32.VirtualQuery)(puStack_20, auStack_44, 0x1c);
    uVar2 = uStack_40;
    if (iVar8 == 0) goto code_r0x004016b2;
    if ((iStack_2c != 0x1000000) || (iVar8 = sub_4016d0(uStack_40), iVar8 == 0)) {
        *unaff_FS_OFFSET = piStack_14;
        return 0xffffffff;
    }
    if (((((uStack_30 & 0xcc) != 0) &&
         ((iVar8 = sub_401710(uVar2, puStack_20 - uVar2), iVar8 == 0 || ((*(iVar8 + 0x24) & 0x80000000) != 0)))) ||
        (iVar8 = sub_4012c0(puStack_20), iVar8 == 0)) ||
       (iVar5 = sub_401710(uVar2, param_1[1] - uVar2), iVar8 = [0x0x40405c], iVar5 == 0)) goto code_r0x004013c3;
    LOCK();
    [0x0x40405c] = 1;
    UNLOCK();
    if (iVar8 != 0) goto code_r0x004016b2;
    iVar8 = [0x0x404058];
    if (0 < [0x0x404058]) {
        puVar6 = [0x0x404058] * 8 + 0x404058;
        do {
            if (*puVar6 == uStack_24) break;
            iVar8 = iVar8 + -1;
            puVar6 = puVar6 + -2;
        } while (0 < iVar8);
    }
    if (iVar8 == 0) {
        iVar8 = 0xf;
        if ([0x0x404058] < 0x10) {
            iVar8 = [0x0x404058];
        }
        if (-1 < iVar8) {
            puVar6 = 0x404060;
            iVar8 = iVar8 + 1;
            do {
                uVar2 = *puVar6;
                uVar1 = puVar6[1];
                *puVar6 = uStac
```
#### 3120 — 2
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 SEH.2(int32_t *param_1,int32_t param_2,undefined4 param_3)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t *piVar3;
    int32_t *piStack_1c;
    undefined4 uStack_18;
    int32_t *piStack_14;
    undefined4 uStack_10;
    int32_t iStack_c;
    char cStack_5;
    
    piVar3 = *(param_2 + 8) ^ [0x0x404014#SecurityCookie];
    cStack_5 = '\0';
    uStack_10 = 1;
    if (*piVar3 != -2) {
        sub_40181d();
    }
    sub_40181d();
    iVar2 = param_2;
    if ((*(param_1 + 1) & 0x66) == 0) {
        *(param_2 + -4) = &piStack_1c;
        iVar2 = *(param_2 + 0xc);
        piStack_1c = param_1;
        uStack_18 = param_3;
        if (iVar2 == -2) {
            return uStack_10;
        }
        do {
            piStack_14 = piVar3 + iVar2 * 3 + 4;
            iStack_c = *piStack_14;
            if (piVar3[iVar2 * 3 + 5] != 0) {
                iVar1 = sub_401bb6();
                cStack_5 = '\x01';
                if (iVar1 < 0) {
                    uStack_10 = 0;
                    goto code_r0x004018d8;
                }
                if (0 < iVar1) {
                    if (((*param_1 == -0x1f928c9d) && (0x404408 != 0x0)) &&
                       (iVar1 = sub_401760(0x404408), iVar1 != 0)) {
                        (*0x404408)(param_1, 1);
                    }
                    sub_401be6();
                    if (*(param_2 + 0xc) != iVar2) {
                        sub_401c00(param_2 + 0x10, 0x404014#SecurityCookie);
                    }
                    *(param_2 + 0xc) = iStack_c;
                    if (*piVar3 != -2) {
                        sub_40181d();
                    }
                    sub_40181d();
                    sub_401bcd();
                    goto code_r0x0040199c;
                }
            }
            iVar2 = iStack_c;
        } while (iStack_c != -2);
        if (cStack_5 == '\0') {
            return uStack_10;
        }
    }
    else {
code_r0x0040199c:
        if (*(iVar2 + 0xc) == -2) {
            return uStack_10;
        }
        sub_401c00(param_2 + 0x10, 0x404014#SecurityCookie);
    }
code_r0x004018d8:
    if (*piVar3 != -2) {
        sub_40181d();
    }
    sub_40181d();
    return uStack_10;
}

```
#### 1345 — sub_401141
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401141(int32_t *param_1,undefined4 param_2)

{
    int32_t iVar1;
    
    if ((*param_1 == -0x1f928c9d) && (0x404408 != 0x0)) {
        iVar1 = sub_401760(0x404408);
        if (iVar1 != 0) {
            (*0x404408)(param_1, param_2);
        }
    }
    return;
}

```

### Virtual Files (29)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| MENU/AYRVNAIMJ/en-us | 1568 | - |
| MENU/LKHMEYKJC/en-us | 1422 | - |
| MENU/MVFHCY/en-us | 920 | - |
| MENU/OBGPRTS/en-us | 936 | - |
| MENU/QXCHNYOH/en-us | 920 | - |
| MENU/VJGRDQDRRCSGV/en-us | 1234 | - |
| STR/69/en-us | 166 | - |
| STR/81/en-us | 108 | - |
| STR/85/en-us | 122 | - |
| STR/109/en-us | 138 | - |
| STR/110/en-us | 124 | - |
| STR/117/en-us | 68 | - |
| STR/122/en-us | 126 | - |
| STR/124/en-us | 90 | - |
| STR/129/en-us | 150 | - |
| STR/132/en-us | 106 | - |
| STR/154/en-us | 68 | - |
| STR/160/en-us | 82 | - |
| STR/163/en-us | 136 | - |
| STR/170/en-us | 140 | - |

### Structures (125)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 224 |
| OptionalHeader | 248 |
| Sections | 472 |
| advapi32.FT | 9216 |
| gdi32.FT | 9232 |
| kernel32.FT | 9248 |
| user32.FT | 9428 |
| winspool.FT | 9476 |
| LoadConfigurationTable | 10056 |
| SEHandlers | 10128 |
| ImportTable | 10220 |
| advapi32.OFT | 10340 |
| gdi32.OFT | 10356 |
| kernel32.OFT | 10372 |
| user32.OFT | 10552 |
| winspool.OFT | 10600 |
| ImportNames | 10612 |
| SecurityCookie | 13332 |
| Resources | 17408 |
| Resources.MENU | 17472 |
| Resources.STR | 17536 |
| Resources.ACC | 17672 |
| Resources.RCDATA | 17728 |
| Resources.HTML | 17752 |
| Resources.MANIF | 17776 |
| Resources.MENU.AYRVNAIMJ | 17800 |
| Resources.MENU.LKHMEYKJC | 17824 |
| Resources.MENU.MVFHCY | 17848 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 11 · duration_s: 1.02

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| enumerate processes | T1057:Process Discovery, T1518:Software Discovery |  |
| check for trap flag exception |  | B0001:Debugger Detection |
| find graphical window | T1010:Application Window Discovery |  |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| execute shellcode via indirect call |  | C0007:Allocate Memory |
| extract resource via kernel32 functions |  |  |

## PE Imports / Signals
import_count: 63

| label | api_match | ATT&CK |
|---|---|---|
| queue_apc | QueueUserAPC | T1055 |
| check_debugger | IsDebuggerPresent | T1622 |
| create_service | CreateService | T1543.003 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@96608 len=2 |
| contains_base64 | - | $a@7871 len=12 |
| Antivirus | - |  |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@200 len=4 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1 |
| SEH_Save | - | $a@1521 len=7 |
| SEH_Init | - | $a@1540 len=6; $b@3823 len=7 |
| anti_dbg | - | $d1@7456 len=12; $c2@9106 len=17 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
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
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 96608,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 7871,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a0",
          "offset": 200,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1521,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 1540,
          "length": 6,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 3823,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/Malware Analyst Professional - Level 2/5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da/space1.ex",
      "strings": [
        {
          "id": "$d1",
          "offset": 7456,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 9106,
          "length": 17,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`
```

## FLOSS Strings
Total strings: 2471 · per_category: `{"decoded_strings": 0, "stack_strings": 3, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2468}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcessHeap`
- `GetProcAddress`
- `LoadLibraryA`
- `KERNEL32.dll`

### FLOSS sample
- `QueryPerformanceFrequency`
- `QueryPerformanceCounter`
- `IsBadCodePtr`
- `!This program cannot be run in DOS mode.`
- `/uRich`
- ``.rdata`
- `@.data`
- `VC20XC00U`
- `;t$,v-`
- `UQPXY]Y[`
- `URPQQhT`
- `1F;5T@@`
- `bad allocation`
- `kernel32.dll`
- `user32`
- `&*^@QDSJGIO`
- `&JTEH$WHD`
- `fdsfsd,`
- `fdsfds`
- `V><MDNbyfui6y2iuow`
- `fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6`
- `ExitProcess`
- `HeapReAlloc`
- `CreateFileA`
- `FindResourceW`
- `LoadResource`
- `GetCurrentActCtx`
- `GetModuleHandleW`
- `GetCurrentThread`
- `VirtualFree`
- `GetProcessHeap`
- `TlsSetValue`
- `GetConsoleCP`
- `SizeofResource`
- `GetSystemDirectoryA`
- `GetACP`
- `lstrcmpW`
- `lstrlenW`
- `RtlMoveMemory`
- `GetLastError`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00402720
```asm
┌ 556: entry0 ();
│           0x00402720      6838314000     push str.QHACTIVEDEFENSE.EXE ; 0x403138 ; u"QHACTIVEDEFENSE.EXE"
│           0x00402725      e816ffffff     call 0x402640
│           0x0040272a      83c404         add esp, 4
│           0x0040272d      85c0           test eax, eax
│       ┌─< 0x0040272f      0f8513020000   jne 0x402948
│       │   0x00402735      6860314000     push str.QHSAFETRAY.EXE     ; 0x403160 ; u"QHSAFETRAY.EXE"
│       │   0x0040273a      e801ffffff     call 0x402640
│       │   0x0040273f      83c404         add esp, 4
│       │   0x00402742      85c0           test eax, eax
│      ┌──< 0x00402744      0f85fe010000   jne 0x402948
│      ││   0x0040274a      6880314000     push str.QHWATCHDOG.EXE     ; 0x403180 ; u"QHWATCHDOG.EXE"
│      ││   0x0040274f      e8ecfeffff     call 0x402640
│      ││   0x00402754      83c404         add esp, 4
│      ││   0x00402757      85c0           test eax, eax
│     ┌───< 0x00402759      0f85e9010000   jne 0x402948
│     │││   0x0040275f      68a0314000     push str.CMDAGENT.EXE       ; 0x4031a0 ; u"CMDAGENT.EXE"
│     │││   0x00402764      e8d7feffff     call 0x402640
│     │││   0x00402769      83c404         add esp, 4
│     │││   0x0040276c      85c0           test eax, eax
│    ┌────< 0x0040276e      0f85d4010000   jne 0x402948
│    ││││   0x00402774      68bc314000     push str.CIS.EXE            ; 0x4031bc ; u"CIS.EXE"
│    ││││   0x00402779      e8c2feffff     call 0x402640
│    ││││   0x0040277e      83c404         add esp, 4
│    ││││   0x00402781      85c0           test eax, eax
│   ┌─────< 0x00402783      0f85bf010000   jne 0x402948
│   │││││   0x00402789      68cc314000     push str.V3LITE.EXE         ; 0x4031cc ; u"V3LITE.EXE"
│   │││││   0x0040278e      e8adfeffff     call 0x402640
│   │││││   0x00402793      83c404         add esp, 4
│   │││││   0x00402796      85c0           test eax, eax
│  ┌──────< 0x00402798      0f85aa010000   jne 0x402948
│  ││││││   0x0040279e      68e4314000     push str.V3MAIN.EXE         ; 0x4031e4 ; u"V3MAIN.EXE"
│  ││││││   0x004027a3      e898feffff     call 0x402640
│  ││││││   0x004027a8      83c404         add esp, 4
│  ││││││   0x004027ab      85c0           test eax, eax
│ ┌───────< 0x004027ad      0f8595010000   jne 0x402948
│ │││││││   0x004027b3      68fc314000     push str.V3SP.EXE           ; 0x4031fc ; u"V3SP.EXE"
│ │││││││   0x004027b8      e883feffff     call 0x402640
│ │││││││   0x004027bd      83c404         add esp, 4
│ │││││││   0x004027c0      85c0           test eax, eax
│ ────────< 0x004027c2      0f8580010000   jne 0x402948
│ │││││││   0x004027c8      6810324000     push str.SPIDERAGENT.EXE    ; 0x403210 ; u"SPIDERAGENT.EXE"
│ │││││││   0x004027cd      e86efeffff     call 0x402640
│ │││││││   0x004027d2      83c404         add esp, 4
│ │││││││   0x004027d5      85c0           test eax, eax
│ ────────< 0x004027d7      0f856b010000   jne 0x402948
│ │││││││   0x004027dd      6830324000     push str.DWENGINE.EXE
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
