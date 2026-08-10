## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=7fbde4a47c916e4e | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=157, sha256=7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6
  Anomalies (26): BigBufferNoXrefMediumToHighEntropy×5 (entropy), BigResourceHighEntropy×2 (resources), BigStringHiScore×22 (strings), CrossSectionJump×3 (code), CryptoApiUsage×6 (imports), DownloaderApiUsage×18 (imports), DynamicString×75 (strings), EmbeddedProgram×2 (embedding), HighXrefLoopingFunction×65 (code), HugeFunctionGapAtSectionBoundary (code), HugeGapBetweenFunctions×5 (code), HugeStringBinary×5 (strings), ImportByHash×6 (imports), InvalidChecksum (integrity), InvalidSizeOfCode (sections), ManyHighValueImmediates×23 (code), ManyUniqueImmediateBytes×22 (code), RelocSectionNoRelocation (sections), RichUnknownTool (rich), SectionNameUnknown×2 (sections), SequentialFunction×32 (code), SpaghettiFunction×77 (code), StackArrayInitialisationX86×124 (code), StringBase64×4 (strings), WeirdDebugInfoType×2 (headers), XorInLoop×424 (code)
  High-signal anomaly locations: BigResourceHighEntropy@5143208,5749856; CryptoApiUsage@1458352,1458482,1676156; DynamicString@1867525,555118,558467; HighXrefLoopingFunction@1888,122816,143184; ManyHighValueImmediates@1024,91904,92256; ManyUniqueImmediateBytes@555088,558340,865200; SequentialFunction@6016,7120,7440; SpaghettiFunction@219584,501104,529376; XorInLoop@10240,15008,17776
  YARA (signal): MultipleUserAgent, BlacklistSandbox, ChangeBrowserPreference
  YARA (info, 18 total): MSVC_2015_linker, msvs_2015_upd3_1_rich, Sqlite, Zlib, Libcurl, OpenSSL, DownloadUsingWininet, DownloadUsingWinHttp, CustomUserAgent, PostHttpForm…
  Functions (15): sub_6b63e0@2840544, sub_65e730@2480944, sub_4bb468@764008, sub_5f7f70@2061168, sub_6b9d60@2855264, sub_6ac0c0@2798784, sub_5f8250@2061904, sub_5f7b12@2060050, sub_6b9c60@2855008, sub_6bbf00@2863872, sub_597e60@1667680, sub_68fd70@2683248, sub_6bf130@2876720, sub_5f8110@2061584, sub_5f7c90@2060432
  Top high-signal imports (score≥8, 53 of 588):
    [10] kernel32.IsDebuggerPresent ×4
    [10] user32.GetDesktopWindow ×4
    [10] advapi32.CryptReleaseContext ×3
    [10] user32.DestroyWindow ×3
    [10] advapi32.CryptGetHashParam ×2
    [10] kernel32.HeapDestroy ×2
    [10] advapi32.CryptAcquireContextA
    [10] advapi32.CryptAcquireContextW
    [10] advapi32.CryptCreateHash
    [10] advapi32.CryptDestroyHash
    [10] advapi32.CryptGenRandom
    [10] advapi32.CryptHashData
    [10] kernel32.VirtualAllocEx
    [10] kernel32.WriteProcessMemory
    [9] wininet.InternetCloseHandle ×10
    [9] advapi32.RegSetValueExW ×9
    [9] wininet.InternetCrackUrlW ×9
    [9] ws2_32.WSAStartup ×7
    [9] winhttp.WinHttpSetOption ×6
    [9] wininet.InternetReadFile ×6
    [9] wininet.HttpSendRequestW ×5
    [9] winhttp.WinHttpQueryHeaders ×4
    [9] wininet.InternetConnectW ×4
    [9] wininet.InternetOpenW ×4
    [9] advapi32.RegCreateKeyExW ×3
    [9] winhttp.WinHttpCloseHandle ×3
    [9] urlmon.URLDownloadToFileW ×2
    [9] winhttp.WinHttpAddRequestHeaders ×2
    [9] winhttp.WinHttpReadData ×2
    [9] winhttp.WinHttpSendRequest ×2
  Mid-signal imports: user32.SendMessageW, ws2_32.send, ws2_32.sendto, kernel32.TerminateProcess, kernel32.CreateProcessW, user32.SendMessageTimeoutW, ws2_32.recv, ws2_32.recvfrom, kernel32.QueryPerformanceCounter, advapi32.OpenProcessToken, kernel32.OpenProcess, kernel32.CreateThread, iphlpapi.IcmpSendEcho, kernel32.CreateProcessA, kernel32.GetProcAddress, kernel32.DeleteFileW, kernel32.LoadLibraryW, kernel32.LoadLibraryA, kernel32.LoadLibraryExW, kernel32.CreatePipe, kernel32.DeleteFileA, kernel32.LoadLibraryExA, opengl32.wglGetProcAddress, kernel32.CreateFileW, kernel32.GetModuleHandleW…
  (low-signal/noise imports: 499 omitted)
  - Constants/registry (4): registry::HKEY_CURRENT_USER×55, registry::HKEY_USERS×10, registry::HKEY_LOCAL_MACHINE×77, registry::autorun
  - Constants/crypto (48): crypto::AES×10, crypto::Rijndael_rcon__32_big_40, crypto::DES_SPR_SPtrans__32_lil_2048, crypto::Base64×5, crypto::EC_curve__EC_SECG_CHAR2_193R1_SEED__8_byt_20, crypto::EC_curve__EC_SECG_CHAR2_193R2_SEED__8_byt_20, crypto::EC_curve__EC_NIST_CHAR2_233B_SEED__8_byt_20, crypto::EC_curve__EC_NIST_CHAR2_283B_SEED__8_byt_20, crypto::EC_curve__EC_NIST_CHAR2_409B_SEED__8_byt_20, crypto::EC_curve__EC_NIST_CHAR2_571B_SEED__8_byt_20, crypto::EC_curve__EC_X9_62_CHAR2_163V1_SEED__8_byt_20, crypto::EC_curve__EC_X9_62_CHAR2_163V2_SEED__8_byt_20
    Constants/hash (10): hash::SHA256, hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640, hash::MD5, hash::xxhash, hash::RIPEMD160, hash::RIPEMD128, hash::SHA1, hash::CRC32
    Constants/apihash (3): apihash::hash(strstr), apihash::hash(__initenv), apihash::hash(RtlPrefixUnicodeString)
    Constants/exception (3): exception::C++ exception, exception::FuncInfo header, exception::CLR exception
    Constants/code (1): code::PEBx86
    Constants/guid (6): guid::IShellLinkW, guid::IUnknown, guid::IPersistFile, guid::IBindStatusCallback, guid::IPicture, guid::INetFwMgr
    Constants/compress (10): compress::zinflate_distanceStarts__32_lil_120, compress::zinflate_lengthExtraBits__32_lil_116, compress::zinflate_lengthStarts__32_lil_116, compress::unlzx_table_three__32_lil_64, compress::zinflate_distanceExtraBits__32_lil_120, compress::Zlib_dist_code__8_byt_512, compress::Zlib_base_dist__32_lil_120, compress::Zlib_base_length__32_lil_116
    Constants/oid (49): oid::signedData, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha1WithRSAEncryption, oid::stateOrProvinceName, oid::localityName, oid::organizationName, oid::organizationalUnitName
  Strings/urls (9 total): http://test.sy.p..nfigFileInfo.xml, http://www.tence..fservice.shtml, https://s.syzs.q..nfigFileInfo.xml, http://www.tence..acypolicy.shtml, https://s.syzs.q..ml/game_uniq.xml, https://i.gtimg...ml/game_uniq.xml, https://www.qq.c..m/contract.shtml, https://unifieda..2?scene=download
  Strings/registry (21 total): SOFTWARE\Microso..nternet Settings, SOFTWARE\Microso..ion\Uninstall\%s, Software\Classes..00-000000000046}, Software\Tencent..\LoginStatusInfo, Software\Tencent..ePC\InstallFlags, SOFTWARE\Tencent..ePC\GameDownload, Software\Tencent..GamePC\AppMarket, Software\Microso..tVersion\RunOnce, Software\Tencent\TrojanScanLog, SOFTWARE\Tencent..GamePC\AppMarket
  Strings/mutex (3 total): Global\AndroidEm..C789E74E81-%s-%d, Global\AndroidEm..FB2D4B85CC-%s-%d, Global\AndroidEm..3E5AC7236D-%s-%d
  Strings (other, 267 items, omitted)
  Carved files (21): DIB@4222312 (1128 bytes), DIB@4223440 (2440 bytes), DIB@4225880 (4264 bytes), DIB@4230144 (9640 bytes), DIB@4239784 (16936 bytes), DIB@4256720 (38056 bytes), DIB@4294776 (67624 bytes), DIB@4362400 (270376 bytes), DIB@4632896 (744 bytes), DIB@4633640 (296 bytes)
  Virtual files (26): CUSTOM/IDR_CUSTOM_FOR_EXTRACE_ICON/zh-cn, DLL/110/zh-cn, EXE/137/zh-cn, SKIN/IDR_QMUI_DAT/zh-cn, ICO/1/zh-cn, ICO/2/zh-cn, ICO/3/zh-cn, ICO/4/zh-cn, ICO/5/zh-cn, ICO/6/zh-cn
  Recovered structures (166): MZ, RichHeader, PE, OptionalHeader, Sections, advapi32.FT, comctl32.FT, gdi32.FT, imm32.FT, iphlpapi.FT, kernel32.FT, netapi32.FT, oleaut32.FT, opengl32.FT, psapi.FT
  Decompilations (3 top functions):
    ### 2840544 (sub_6b63e0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined * __fastcall sub_6b63e0(uint8_t *param_1,uint32_t param_2)

{
    uint8_t *puVar1;
    uint8_t uVar2;
    uint8_t uVar3;
    uint16_t uVar4;
    undefined *puVar5;
    undefined *puVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    
    if (param_2 == 0) {
        return 0x0;
    }
    uVar8 = param_2 / 3;
    param_2 = param_2 % 3;
    puVar5 = _malloc(((param_2 != 0) + uVar8) * 4 + 1);
    puVar6 = puVar5;
    if (puVar5 != 0x0) {
        for (; uVar8 != 0; uVar8 = uVar8 - 1) {
            uVar2 = *param_1;
            puVar1 = param_1 + 1;
            uVar3 = param_1[2];
            param_1 = param_1 + 3;
            uVar7 = uVar2 << 0x10 | *puVar1 << 8;
            *puVar6 = (&Base64)[(uVar2 << 0x10) >> 0x12];
            puVar6[1] = (&Base64)[(uVar7 & 0x3f000) >> 0xc];
            puVar6[2] = (&Base64)[(uVar3 | uVar7) >> 6 & 0x3f];
            puVar6[3] = (&Base64)[uVar3 & 0x3f];
            puVar6 = puVar6 + 4;
        }
        if (param_2 != 1) {
            if (param_2 == 2) {
                uVar4 = CONCAT11(*param_1, param_1[1]);
                *puVar6 = (&Base64)[*param_1 >> 2];
                puVar6[1] = (&Base64)[uVar4 >> 4 & 0x3f];
                puVar6[2] = (&Base64)[(uVar4 & 0xf) * 4];
                puVar6[3] = 0x3d;
                puVar6 = puVar6 + 4;
            }
            *puVar6 = 0;
            return puVar5;
        }
        uVar2 = *param_1;
        *puVar6 = (&Base64)[uVar2 >> 2];
        puVar6[1] = (&Base64)[(uVar2 & 3) * 0x10];
        *(puVar6 + 2) = 0x3d3d;
        puVar6[4] = 0;
        return puVar5;
    }
    return 0x0;
}
```
    ### 2480944 (sub_65e730, score=?)
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
    ### 764008 (sub_4bb468, score=?)
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
                    *(&Adler_CRC32__0x01c
```

## capa evidence (154 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (8): encode data using Base64, reference Base64 string, encode data using XOR, encrypt data using AES, encrypt data using AES via x86 extensions, encrypt data using RC4 KSA
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (3): reference anti-VM strings, reference anti-VM strings targeting VMWare, reference anti-VM strings targeting VirtualBox
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Collection', 'Input Capture', 'Keylogging'], 'tactic': 'Collection', 'technique': 'Input Capture', 'subtechnique': 'Keylogging', 'id': 'T1056.001'} (1): log keystrokes via polling
  ATT&CK {'parts': ['Discovery', 'System Network Configuration Discovery'], 'tactic': 'Discovery', 'technique': 'System Network Configuration Discovery', 'subtechnique': '', 'id': 'T1016'} (1): get socket status
  ATT&CK {'parts': ['Defense Evasion', 'Deobfuscate/Decode Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Deobfuscate/Decode Files or Information', 'subtechnique': '', 'id': 'T1140'} (1): decrypt data using AES via x86 extensions

## pe_imports (571 imports, 13 high-signal)
  allocate_memory (VirtualAllocEx) [T1055]
  write_process_memory (WriteProcessMemory) [T1055]
  set_thread_context (SetThreadContext) [T1055]
  check_debugger (IsDebuggerPresent) [T1622]
  http_client (InternetOpen) [T1071.001]
  winhttp_client (WinHttpOpen) [T1071.001]
  download_file (URLDownloadToFile) [T1105]
  set_registry_value (RegSetValue) [T1112]
  create_process (CreateProcess) [T1106]
  shell_execute (ShellExecute) [T1106]
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (61)
  Rules: domain, IP, contains_base64, System_Tools, Antivirus, VMWare_Detection, Dropper_Strings, Obfuscated_Strings, Big_Numbers0, Big_Numbers1, Big_Numbers3, Advapi_Hash_API, CRC32_poly_Constant, CRC32_table, MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA512_Constants, SHA2_BLAKE2_IVs, DES_Long, RijnDael_AES_CHAR, BASE64_table, ecc_order, with_sqlite, url

## FLOSS strings (24408 total)
  base64 (1): !!"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$%&&&&&&&
  (other strings, 79 items omitted)

<!-- evidence_assembler: used 15463/28000 chars across 5 tools -->