## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=8088f08a5636cec3 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=7.37, sha256=8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde
  Anomalies (10): BigResourceHighEntropy×4 (resources), CryptoApiUsage×3 (imports), DllNoExportTable (exports), DownloaderApiUsage×6 (imports), InvalidChecksum (integrity), ManyHighValueImmediates (code), PossiblePackerApiDynamicImport (imports), RcdataNoDelphi×7 (resources), SequentialFunction×3 (code), XorInLoop×16 (code)
  High-signal anomaly locations: BigResourceHighEntropy@153164,207780,274392; CryptoApiUsage@27506,27483,27341; ManyHighValueImmediates@40608; SequentialFunction@39648,63280,65472; XorInLoop@32256,39808,40112
  YARA (signal): PublicIP
  YARA (info, 11 total): MSVC_2010_linker, DownloadUsingWininet, CustomUserAgent, PostHttpForm, ProcessInjectionTargets, FingerprintEnvironment, EnumerateProcesses, CreateScheduledTask, AutorunKey, ElevatePrivileges…
  Functions (15): sub_1800193de@100318, sub_18000a6e0@39648, sub_180009be0@36832, sub_180008220@30240, sub_1800082d0@30416, sub_180013ed0@78544, sub_180001b20@3872, sub_180010bc0@65472, sub_180010330@63280, sub_180010050@62544, sub_180010970@64880, sub_180011660@68192, sub_180013310@75536, sub_1800072c0@26304, sub_1800089f0@32240
  Top high-signal imports (score≥8, 44 of 192):
    [10] bcrypt.BCryptOpenAlgorithmProvider ×3
    [10] advapi32.CryptGetHashParam ×2
    [10] bcrypt.BCryptCloseAlgorithmProvider ×2
    [10] bcrypt.BCryptGetProperty ×2
    [10] advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    [10] advapi32.CryptAcquireContextW
    [10] advapi32.CryptCreateHash
    [10] advapi32.CryptDestroyHash
    [10] advapi32.CryptHashData
    [10] advapi32.CryptReleaseContext
    [10] bcrypt.BCryptCreateHash
    [10] bcrypt.BCryptDestroyHash
    [10] bcrypt.BCryptDestroyKey
    [10] bcrypt.BCryptFinishHash
    [10] bcrypt.BCryptHashData
    [10] bcrypt.BCryptImportKeyPair
    [10] bcrypt.BCryptVerifySignature
    [10] kernel32.CreateRemoteThread
    [10] kernel32.HeapDestroy
    [10] userenv.DestroyEnvironmentBlock
    [9] wininet.InternetCloseHandle ×9
    [9] wininet.InternetReadFile ×5
    [9] wininet.InternetSetOptionW ×4
    [9] wininet.InternetConnectA ×2
    [9] wininet.InternetOpenA ×2
    [9] wininet.InternetQueryDataAvailable ×2
    [9] ws2_32.WSAStartup ×2
    [9] advapi32.RegCreateKeyExW
    [9] advapi32.RegSetValueExW
    [9] wininet.HttpSendRequestA
  Mid-signal imports: kernel32.CreateThread, advapi32.OpenProcessToken, kernel32.TerminateProcess, kernel32.OpenProcess, ws2_32.WSASend, user32.SendMessageW, ws2_32.WSARecv, advapi32.CreateProcessAsUserW, kernel32.QueryPerformanceCounter, ws2_32.recvfrom, ws2_32.sendto, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.CreateNamedPipeW, kernel32.CreateFileW, kernel32.GetModuleHandleW, advapi32.RegOpenKeyExW, advapi32.RegOpenKeyW, advapi32.RegQueryValueExW, kernel32.CreateFileMappingW
  (low-signal/noise imports: 128 omitted)
  * Constants/registry (3): registry::HKEY_CURRENT_USER×2, registry::HKEY_LOCAL_MACHINE×4, registry::HKEY_USERS
    Constants/hash (1): hash::SHA256
  Strings/urls (1 total): http://icanhazip.com
  Strings/ips (2 total): 0.0.0.0:0, 203.183.172.196:3478
  Strings/registry (4 total): Software\Microso..ccounts\UserList, Software\Microso..Version\Winlogon, Software\Microso..\SpecialAccounts, Software\Microso..ersion\Uninstall
  Strings/mutex (1 total): Global\
  Strings/paths (9 total): C:\windows\system32\shutdown.exe, \\.\pipe\, \\.\PhysicalDrive0, \\.\D:, \\.\C:, C:\Users\, C:\Program Files\, C:\Windows\, C:\Windows
  Strings/suspicious (1 total): Tcmd.exe
  Strings/apis (41 total): InternetReadFile, GetComputerNameW, GetComputerNameA, ShellExecuteW, RtlCreateUserThread, GetSystemInfo, GetProcAddress, GetVersionExW, RtlGetVersion, GetAdaptersAddresses, InternetGetConnectedState, InitializeCriticalSection, InternetQueryDataAvailable, DeleteCriticalSection, InternetWriteFile
  Strings (other, 241 items, omitted)
  Virtual files (8): RCDATA/3DFRM0TFI/en-us, RCDATA/4FGGN9GAK/en-us, RCDATA/5GBYB8BZ3/en-us, RCDATA/6BNUV7NZJ/en-us, RCDATA/7MCIC6HXH/en-us, RCDATA/8ZSYOX5YG/en-us, RCDATA/9P3PS4UEF/en-us, MANIF/2/en-us
  Recovered structures (67): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, iphlpapi.FT, kernel32.FT, netapi32.FT, shell32.FT, shlwapi.FT, user32.FT, userenv.FT, wininet.FT, ws2_32.FT
  Decompilations (3 top functions):
    ### 100318 (sub_1800193de, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x000180019415) */
/* WARNING: Removing unreachable block (ram,0x000180019400) */
/* WARNING: Removing unreachable block (ram,0x0001800193eb) */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_1800193de(undefined4 *param_1)

{
    undefined4 *puVar1;
    undefined4 uVar2;
    undefined4 uVar3;
    undefined4 uVar4;
    undefined8 in_RAX;
    undefined4 *puVar5;
    
    puVar1 = cpuid_brand_part1_info(0x80000002);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *param_1 = *puVar1;
    param_1[1] = uVar2;
    param_1[2] = uVar4;
    param_1[3] = uVar3;
    puVar5 = param_1 + 0x10;
    puVar1 = cpuid_brand_part2_info(0x80000003);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *puVar5 = *puVar1;
    puVar5[1] = uVar2;
    puVar5[2] = uVar4;
    puVar5[3] = uVar3;
    puVar5 = param_1 + 0x20;
    puVar1 = cpuid_brand_part3_info(0x80000004);
    uVar2 = puVar1[1];
    uVar3 = puVar1[2];
    uVar4 = puVar1[3];
    *puVar5 = *puVar1;
    puVar5[1] = uVar2;
    puVar5[2] = uVar4;
    puVar5[3] = uVar3;
    return in_RAX;
}
```
    ### 39648 (sub_18000a6e0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_18000a6e0(undefined8 *param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    int32_t *piVar4;
    int32_t iVar5;
    uint32_t uVar6;
    undefined *puVar7;
    int64_t iVar8;
    uint32_t uVar9;
    int64_t iVar10;
    undefined4 auStack_151 [2];
    undefined8 uStack_148;
    undefined8 uStack_140;
    undefined8 uStack_138;
    undefined8 uStack_130;
    int32_t aiStack_128 [64];
    
    uStack_148 = *param_1;
    uStack_140 = param_1[1];
    uStack_138 = param_1[2];
    uStack_130 = param_1[3];
    iVar8 = 0x10;
    puVar7 = param_1 + 0x29;
    do {
        iVar8 = iVar8 + -1;
        *(puVar7 + 4 + &stack0xfffffffffffffeab + -param_1) =
             CONCAT31(CONCAT21(CONCAT11(puVar7[-1], *puVar7), puVar7[1]), puVar7[2]);
        puVar7 = puVar7 + 4;
    } while (iVar8 != 0);
    piVar4 = aiStack_128;
    iVar8 = 0xc;
    do {
        uVar9 = piVar4[1];
        uVar1 = piVar4[2];
        uVar6 = piVar4[0xe];
        uVar2 = piVar4[3];
        uVar3 = piVar4[0xf];
        uVar6 = ((uVar6 << 0xf | uVar6 >> 0x11) ^ (uVar6 << 0xd | uVar6 >> 0x13) ^ uVar6 >> 10) +
                ((uVar9 << 0xe | uVar9 >> 0x12) ^ (uVar9 >> 7 | uVar9 << 0x19) ^ uVar9 >> 3) + piVar4[9] + *piVar4;
        piVar4[0x10] = uVar6;
        uVar9 = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ uVar3 >> 10) +
                ((uVar1 << 0xe | uVar1 >> 0x12) ^ (uVar1 >> 7 | uVar1 << 0x19) ^ uVar1 >> 3) + piVar4[10] + uVar9;
        piVar4[0x11] = uVar9;
        piVar4[0x12] = ((uVar6 * 0x8000 | uVar6 >> 0x11) ^ (uVar6 * 0x2000 | uVar6 >> 0x13) ^ uVar6 >> 10) +
                       ((uVar2 << 0xe | uVar2 >> 0x12) ^ (uVar2 >> 7 | uVar2 << 0x19) ^ uVar2 >> 3) + piVar4[0xb] +
                       uVar1;
        uVar1 = piVar4[4];
        piVar4[0x13] = ((uVar9 * 0x8000 | uVar9 >> 0x11) ^ (uVar9 * 0x2000 | uVar9 >> 0x13) ^ uVar9 >> 10) +
                       ((uVar1 << 0xe | uVar1 >> 0x12
```
    ### 36832 (sub_180009be0, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x000180009c40) */

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_180009be0(int64_t param_1)

{
    int32_t iVar1;
    uint32_t uVar2;
    undefined4 uVar3;
    uint64_t uVar4;
    int64_t iVar5;
    int64_t iVar6;
    undefined4 auStackX_8 [2];
    int32_t aiStackX_10 [2];
    undefined4 auStackX_18 [4];
    undefined auStack_128 [256];
    
    *(param_1 + 0x188) = 0;
    iVar1 = sub_1800095b0();
    if (iVar1 == 0) {
        uVar4 = (*kernel32.GetLastError)();
        return uVar4;
    }
    uVar2 = 0x4000000;
    if ((*(param_1 + 0x98) & 1) != 0) {
        uVar2 = 0x4803000;
    }
    uVar4 = 0;
    iVar5 = (*wininet.HttpOpenRequestA)(*(param_1 + 0x10), 0x18001ad04, *(param_1 + 0xb0), 0, 0, 0, uVar2, 0);
    if (iVar5 == 0) {
        uVar4 = (*kernel32.GetLastError)();
    }
    else {
        if ((uVar2 >> 0x17 & 1) != 0) {
            sub_180008fa0(iVar5);
        }
        sub_180009000(iVar5);
        iVar1 = (*wininet.HttpSendRequestA)(iVar5, 0, 0, 0, uVar4 & 0xffffffff00000000);
        if (iVar1 == 0) {
            uVar2 = (*kernel32.GetLastError)();
            uVar4 = uVar2;
            (*wininet.InternetCloseHandle)(iVar5);
        }
        else {
            auStackX_8[0] = 0;
            iVar1 = (*wininet.InternetQueryDataAvailable)(iVar5, auStackX_8, 0, 0);
            uVar4 = 0;
            if ((iVar1 != 0) && (iVar6 = sub_18000a210(auStackX_8[0]), uVar4 = 0, iVar6 != 0)) {
                aiStackX_10[0] = 0;
                iVar1 = (*wininet.InternetReadFile)(iVar5, iVar6, auStackX_8[0], aiStackX_10);
                while( true ) {
                    uVar4 = 0;
                    if ((iVar1 == 0) || (uVar4 = 0, aiStackX_10[0] == 0)) goto code_r0x000180009d87;
                    iVar1 = sub_180008960(param_1 + 0x170, iVar6);
                    if (iVar1 == 0) break;
                    iVar1 = (*wininet.InternetReadFile)(iVar5, iVar6, auStackX_8[0], aiStackX_10);
            
```

## capa evidence (74 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (6): encode data using Base64, encode data using XOR, manually build AES constants, encode data using ADD XOR SUB operations, create new key via CryptAcquireContext, hash data via BCrypt
  ATT&CK {'parts': ['Discovery', 'File and Directory Discovery'], 'tactic': 'Discovery', 'technique': 'File and Directory Discovery', 'subtechnique': '', 'id': 'T1083'} (3): get common file path, check if file exists, get file size
  ATT&CK {'parts': ['Discovery', 'Query Registry'], 'tactic': 'Discovery', 'technique': 'Query Registry', 'subtechnique': '', 'id': 'T1012'} (2): query or enumerate registry key, query or enumerate registry value
  ATT&CK {'parts': ['Discovery', 'System Network Configuration Discovery'], 'tactic': 'Discovery', 'technique': 'System Network Configuration Discovery', 'subtechnique': '', 'id': 'T1016'} (1): get socket status
  ATT&CK {'parts': ['Discovery', 'System Information Discovery'], 'tactic': 'Discovery', 'technique': 'System Information Discovery', 'subtechnique': '', 'id': 'T1082'} (1): get hostname
  ATT&CK {'parts': ['Discovery', 'Process Discovery'], 'tactic': 'Discovery', 'technique': 'Process Discovery', 'subtechnique': '', 'id': 'T1057'} (1): enumerate processes
  ATT&CK {'parts': ['Discovery', 'Software Discovery'], 'tactic': 'Discovery', 'technique': 'Software Discovery', 'subtechnique': '', 'id': 'T1518'} (1): enumerate processes
  ATT&CK {'parts': ['Persistence', 'Create or Modify System Process', 'Windows Service'], 'tactic': 'Persistence', 'technique': 'Create or Modify System Process', 'subtechnique': 'Windows Service', 'id': 'T1543.003'} (1): stop service
  ATT&CK {'parts': ['Impact', 'Service Stop'], 'tactic': 'Impact', 'technique': 'Service Stop', 'subtechnique': '', 'id': 'T1489'} (1): stop service

## pe_imports (192 imports, 7 high-signal)
  create_remote_thread (CreateRemoteThread) [T1055]
  http_client (InternetOpen) [T1071.001]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  shell_execute (ShellExecute) [T1106]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (26)
  Rules: domain, IP, contains_base64, Browsers, Dropper_Strings, Misc_Suspicious_Strings, Advapi_Hash_API, SHA2_BLAKE2_IVs, url, IsPE64, IsDLL, IsWindowsGUI, IsPacked, HasRichSignature, Microsoft_Visual_Cpp_80_DLL, network_http, network_tcp_socket, escalate_priv, win_mutex, win_registry, win_token, win_files_operation, Str_Win32_Winsock2_Library, Str_Win32_Wininet_Library, Str_Win32_Internet_API

## FLOSS strings (907 total)
  paths (1): C:\Windows\explorer.exe
  base64 (36): daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkC, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCo, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoT, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTA, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAn, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnx, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxo, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxof, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofd, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdd, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofdds, daYdnceMmbNJXpFBNXciGGeWmSxBePkFpNPquUkCoTAnxofddsK
  (other strings, 43 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 49
  virtualalloc @ 0x18000767b (fcn.1800075f0)
  virtualalloc @ 0x18000b195 (fcn.18000b130)
  virtualalloc @ 0x18000b2ba (fcn.18000b270)
  heapalloc @ 0x18000a21f (fcn.18000a210)
  wsprintfw @ 0x180008637 (fcn.180008570)
  wsprintfw @ 0x18000873f (?)
  wsprintfw @ 0x18000878f (?)
  wsprintfw @ 0x18000bec9 (fcn.18000beb0)
  wsprintfw @ 0x18000bf29 (fcn.18000bf10)
  wsprintfw @ 0x18000c19e (fcn.18000c0d0)
  wsprintfw @ 0x18000c370 (fcn.18000c2a0)
  wsprintfw @ 0x18000c8f5 (fcn.18000c6c0)
  wsprintfw @ 0x18000c985 (fcn.18000c6c0)
  wsprintfw @ 0x18000ca2e (fcn.18000c6c0)
  wsprintfw @ 0x18000cbea (fcn.18000cba0)

<!-- evidence_assembler: used 14363/28000 chars across 7 tools -->