## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=1b0eb55bb50d0286 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=160, sha256=1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0
  Anomalies (15): BigResourceHighEntropy (resources), BigStringHiScore×3 (strings), DynamicString×9 (strings), EmbeddedProgram×3 (embedding), HighXrefLoopingFunction×7 (code), ImportByHash (imports), InvalidChecksum (integrity), ManyHighValueImmediates×7 (code), ManyUniqueImmediateBytes×6 (code), SectionMostlyVirtual (sections), SequentialFunction×8 (code), SpaghettiFunction×6 (code), StackArrayInitialisationX86×8 (code), UnbalancedVirtualPhysicalRatio (sections), XorInLoop×54 (code)
  High-signal anomaly locations: BigResourceHighEntropy@474728; DynamicString@7763,299393,298279; HighXrefLoopingFunction@51682,97394,97689; ManyHighValueImmediates@9803,17468,24250; ManyUniqueImmediateBytes@7562,158187,188476; SequentialFunction@20403,21803,72182; SpaghettiFunction@10647,154220,192783; XorInLoop@2847,15067,18135
  YARA (info, 5 total): MSVC_2005_linker, MSVC_2003_rich, Sqlite, EnumerateProcesses, RunShell
  Functions (15): sub_40612b@21803, sub_405bb3@20403, sub_415e3e@86590, sub_405b22@20258, sub_44cb80@311168, sub_412ce1@73953, sub_416b94@90004, sub_407a50@28240, sub_40cc16@49174, sub_444b32@278322, sub_445431@280625, sub_446f70@287600, sub_44b6c0@305856, sub_4125f6@72182, sub_44ae20@303648
  Top high-signal imports (score≥8, 4 of 273):
    [10] user32.DestroyMenu
    [10] user32.DestroyWindow
    [10] user32.GetDesktopWindow
    [8] kernel32.CreateToolhelp32Snapshot
  Mid-signal imports: user32.SendMessageW, kernel32.OpenProcess, user32.SendDlgItemMessageW, kernel32.QueryPerformanceCounter, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryW, kernel32.DeleteFileA, kernel32.LoadLibraryExW, kernel32.GetModuleHandleW, kernel32.CreateFileW, advapi32.RegQueryValueExW, kernel32.CreateFileMappingW, kernel32.DuplicateHandle, kernel32.GetModuleHandleA, advapi32.RegOpenKeyExW, kernel32.CreateFileA
  (low-signal/noise imports: 252 omitted)
  - Constants/registry (2): registry::HKEY_CURRENT_USER×3, registry::HKEY_LOCAL_MACHINE
  - Constants/crypto (14): crypto::DES_odd_parity__8_byt_256, crypto::DES_semi_weak_keys__8_byt_96, crypto::DES_skb__32_lil_2048, crypto::DES_SPR_SPtrans__32_lil_2048, crypto::libntlm_DES_key_swap__32_lil_64, crypto::libntlm_DES_key_swap__32_big_64, crypto::RawDES_sbox1__32_lil_256, crypto::RawDES_sbox2__32_lil_256, crypto::RawDES_sbox3__32_lil_256, crypto::RawDES_sbox4__32_lil_256, crypto::RawDES_sbox5__32_lil_256, crypto::RawDES_sbox6__32_lil_256
    Constants/hash (2): hash::MD5, hash::RIPEMD160
    Constants/apihash (1): apihash::hash(exp)
  Strings/urls (3 total): https://www.goog..nts/servicelogin, https://login.ya..com/config/login, http://www.facebook.com/
  Strings/registry (1 total): Software\Microso..er\Shell Folders
  Strings/apis (11 total): OriginalFileName, FileDescription, InitCommonControlsEx, FileVersion, ShellExecuteW, QueryFullProcessImageNameW, NtQuerySystemInformation, NtOpenSymbolicLinkObject, NtQuerySymbolicLinkObject, GetProcessTimes, NtResumeProcess
  Strings (other, 285 items, omitted)
  Carved files (18): DIB@480564 (304 bytes), DIB@480868 (1000 bytes), DIB@481868 (216 bytes), DIB@482084 (216 bytes), DIB@482300 (4264 bytes), DIB@486564 (1128 bytes), DIB@487692 (1128 bytes), DIB@488820 (1128 bytes), DIB@489948 (1128 bytes), DIB@491076 (1128 bytes)
  Virtual files (49): BIN/50/en-us, CUR/1/en-us, BMP/104/en-us, BMP/133/en-us, BMP/134/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us
  Recovered structures (192): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, comctl32.FT, gdi32.FT, kernel32.FT, shell32.FT, user32.FT, version.FT, wininet.FT, comdlg32.FT, msvcrt.FT
  Decompilations (3 top functions):
    ### 21803 (sub_40612b, score=?)
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
                       *((uVar3 >> 2 & 0x3f) * 4 + 0x453670) ^ *((uVar2 >>
```
    ### 20403 (sub_405bb3, score=?)
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
            *(&libntlm_DES_
```
    ### 86590 (sub_415e3e, score=?)
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
                *(((uVar2 >
```

## capa evidence (49 total, showing top 15)
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (5): get common file path, check if file exists, enumerate files on Windows, get file size, get file version info
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (4): encode data using XOR, manually build AES constants, encrypt data using DES, encrypt data using RC4 KSA
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes via polling
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get disk size
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (1): query or enumerate registry value
  ATT&CK {'parts': ['Persistence', 'Boot or Logon Autostart Execution', 'Registry Run Keys / Startup Folder'], 'tactic': 'Persistence', 'technique': 'Boot or Logon Autostart Execution', 'subtechnique': 'Registry Run Keys / Startup Folder', 'id': 'T1547.001'} (1): persist via Run registry key

## pe_imports (272 imports, 3 high-signal)
  shell_execute (ShellExecute) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]

## YARA matches (26)
  Rules: domain, IP, contains_base64, Big_Numbers1, MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA2_BLAKE2_IVs, DES_Long, DES_sbox, with_sqlite, url, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDebugData, HasRichSignature, Visual_Cpp_2003_EXE_Microsoft, SEH_Init, screenshot, keylogger, win_registry, win_files_operation

## FLOSS strings (2008 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x0044692c
```c
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
│  
```
  ### 0x004122ba
```c
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
│       ┌─< 0x004122d4      7506      
```

## UPX
  (not packed)


## xorsearch (4 candidates)
  Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r
  Found XOR 00 position 00062605: 00000040 PE..L.....iT.................2........
  Found XOR 00 position 00071C0A: 00000040 PE..L...R..`..........................
  Found XOR 00 position 000A180F: 00000040 PE..L...8..c...........#..............

<!-- evidence_assembler: used 18166/60000 chars across 9 tools -->