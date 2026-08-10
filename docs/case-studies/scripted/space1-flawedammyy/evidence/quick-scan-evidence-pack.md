## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=5f251ed33fb1b696 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=176, sha256=5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da
  Anomalies (8): BigResourceHighEntropy (resources), CrossSectionJump×3 (code), DuplicatedSectionName (sections), DynamicString×3 (strings), GuiSubsystemNoWindowApi (headers), RcdataNoDelphi (resources), SectionWeirdRights (sections), XorInLoop×2 (code)
  High-signal anomaly locations: BigResourceHighEntropy@38104; DynamicString@5583,5674,5521; GuiSubsystemNoWindowApi@316; XorInLoop@3830,7431
  YARA (signal): CreateService
  YARA (info, 3 total): MSVC_2008_linker, MSVC_2008_rich, EnumerateProcesses
  Functions (15): sub_401380@1920, 2@3120, sub_401141@1345, sub_401ac4@3780, sub_401760@2912, EntryPoint@6944, 1@1436, sub_402530@6448, sub_4019bc@3516, sub_4025e4@6628, sub_4020b0@5296, sub_402180@5504, sub_4023e0@6112, sub_402640@6720, 0@1064
  Top high-signal imports (score≥8, 6 of 63):
    [10] kernel32.IsDebuggerPresent ×2
    [9] advapi32.CreateServiceA
    [9] kernel32.QueueUserAPC
    [8] kernel32.VirtualAlloc ×2
    [8] kernel32.CreateToolhelp32Snapshot
    [8] advapi32.OpenSCManagerA
  Mid-signal imports: kernel32.TerminateProcess, user32.SendDlgItemMessageA, kernel32.LoadLibraryA, kernel32.GetProcAddress, advapi32.RegOpenKeyA, kernel32.GetModuleHandleA, kernel32.GetModuleHandleW, kernel32.CreateFileA
  (low-signal/noise imports: 49 omitted)
    Constants/exception (1): exception::C++ exception
    Constants/code (1): code::PEBx86
  Strings/apis (24 total): QueryPerformanceFrequency, QueryPerformanceCounter, CreateServiceA, DisableThreadLibraryCalls, SetUnhandledExceptionFilter, GetCurrentActCtx, GetCurrentProcess, GetSystemDirectoryA, GetCurrentProcessId, LoadAcceleratorsW, DebugSetProcessKillOnExit, GetCurrentThread, SendDlgItemMessageA, GetProcAddress, AttachThreadInput
  Strings (other, 276 items, omitted)
  Virtual files (29): MENU/AYRVNAIMJ/en-us, MENU/LKHMEYKJC/en-us, MENU/MVFHCY/en-us, MENU/OBGPRTS/en-us, MENU/QXCHNYOH/en-us, MENU/VJGRDQDRRCSGV/en-us, STR/69/en-us, STR/81/en-us, STR/85/en-us, STR/109/en-us
  Recovered structures (125): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, gdi32.FT, kernel32.FT, user32.FT, winspool.FT, LoadConfigurationTable, SEHandlers, ImportTable, advapi32.OFT, gdi32.OFT
  Decompilations (3 top functions):
    ### 1920 (sub_401380, score=?)
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
            if (((iVar3 !=
```
    ### 3120 (2, score=?)
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
code_r
```
    ### 1345 (sub_401141, score=?)
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

## capa evidence (11 total, showing top 11)
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (2): link function at runtime on Windows, parse PE header
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Application Window Discovery'], 'tactic': 'Discovery', 'technique': 'Application Window Discovery', 'subtechnique': '', 'id': 'T1010'} (1): find graphical window
  All rules (6): check for trap flag exception, allocate or change RWX memory, terminate process, enumerate PE sections, execute shellcode via indirect call, extract resource via kernel32 functions

## pe_imports (63 imports, 6 high-signal)
  queue_apc (QueueUserAPC) [T1055]
  check_debugger (IsDebuggerPresent) [T1622]
  create_service (CreateService) [T1543.003]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (12)
  Rules: domain, IP, contains_base64, Antivirus, IsPE32, IsWindowsGUI, IsPacked, HasRichSignature, Microsoft_Visual_Basic_v50, SEH_Save, SEH_Init, anti_dbg

## FLOSS strings (2471 total)
  base64 (1): fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6
  apis (37): QueryPerformanceFrequency, QueryPerformanceCounter, ExitProcess, HeapReAlloc, CreateFileA, FindResourceW, LoadResource, GetCurrentActCtx, GetModuleHandleW, GetCurrentThread, VirtualFree, GetProcessHeap
  (other strings, 42 items omitted)

<!-- evidence_assembler: used 8930/28000 chars across 5 tools -->