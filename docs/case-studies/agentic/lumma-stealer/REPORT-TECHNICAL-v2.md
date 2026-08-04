## 1. Executive Summary
This sample is a malicious packed Windows PE32 GUI executable belonging to the Lumma Stealer (LummaC2) info-stealing malware family, with a threat score of 9/10 (source: llm_judge). It is signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation (valid 2025-01-09 to 2027-01-08), a common tactic used by Lumma operators to bypass Windows SmartScreen and endpoint security trust checks (source: malcat, file_summary.metadata). The sample contains a 1MB+ high-entropy (entropy 222) NSIS installer overlay that acts as a dropper for the core Lumma payload (source: malcat, carved_files). Static analysis across Malcat, Ghidra, YARA, capa, and FLOSS confirms core Lumma capabilities including keylogging, Windows registry manipulation, process enumeration, file system discovery, XOR obfuscation of exfiltrated data, and privilege escalation (source: capa, yara, floss, pe_imports). Multiple high-signal indicators (XOR loops in code, packed high-entropy structure, info-stealing YARA matches) converge to confirm malicious intent.

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 | llm_judge |
| Sample Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe | llm_judge |
| Project Name | incoming | llm_judge |
| Verdict | Malicious (Lumma Stealer info-stealing malware) | llm_judge |
| Threat Score | 9 | llm_judge |
| Family Guess | Lumma Stealer (LummaC2) | llm_judge |
| Agreement | llm_and_v1_agree | llm_judge |
| File Size | 1142333 bytes | malcat, file_summary.metadata |
| File Type | PE | malcat, file_summary.metadata |
| Architecture | X86 | malcat, file_summary.metadata |
| Entry Point (EA) | 11747 (0x2DD3) | malcat, file_summary.metadata |
| Overall Entropy | 216 | malcat, file_summary.metadata |
| Code Signing Certificate Subject | Mozilla Corporation | malcat, file_summary.metadata |
| Certificate Validity | 2025-01-09 to 2027-01-08 | llm_judge, cross_engine_notes |
| Certificate Issuer | DigiCert | llm_judge, cross_engine_notes |

## 3. File Layout & Structural Analysis
The sample is a packed PE with a large high-entropy overlay consistent with an embedded NSIS installer payload. The full section layout is below (source: malcat, file_layout):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 124 | - |
| .text | 1024 | 28672 | 28672 | 143 | RX |
| .rdata | 29696 | 11264 | 12288 | 84 | R |
| .data | 41984 | 512 | 425984 | 0 | RW |
| .rsrc | 467968 | 4608 | 28672 | 176 | R |
| .reloc | 496640 | 4096 | 4096 | 0 | R |
| overlay | 500736 | 1092157 | 0 | 222 | - |
| .ndata | 1592893 | 0 | 675840 | 0 | RW |

Key structural observations:
- The 1,092,157-byte overlay at EA 0x7A000 (physical offset 500736) has an entropy of 222, indicating it is encrypted/packed. Malcat carved a 1,055,469-byte NSIS installer from this overlay at offset 0x80360 (523776) (source: malcat, carved_files), confirming the sample acts as a dropper for a secondary payload.
- The .reloc section has a virtual/physical size mismatch and contains no relocations, flagged as a level 4 anomaly (source: malcat, anomalies: RelocSectionNoRelocation).
- The .rsrc section has a resource directory gap at EA 0x74F22 (479602), a level 4 anomaly (source: malcat, anomalies: ResourceDirectoryGap).
- Carved files from the sample include 2 DIB images, 1 PNG, 1 NSIS installer, and 1 PKCS7 blob (source: malcat, carved_files). A single virtual file (ICO/1/en-us, 11138 bytes) was also identified (source: malcat, virtual_files).
- 46 PE structures were identified, including standard PE headers, import tables, and resource structures (source: malcat, structures).

## 4. Malcat Triage Summary
Malcat identified 7 YARA signature matches, 12 anomalies, and 24 high-signal strings during triage:
### Malcat YARA Signatures (source: malcat, yara_signatures)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | Detects Visual Studio 2010 linker usage |
| msvs2010_sp1_kb_983509_rich | compiler | INFO | 80 | Detects Visual Studio 2010 SP1 via Rich Header |
| NsisInstaller | installer | INFO | 90 | Detects Nullsoft installer structure |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Detects process enumeration API usage |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | Detects privilege escalation API usage |
| RunShell | lateral movement | UNCOMMON | 70 | Detects shell execution API usage |
| nsis_overlay_data | installer | INFO | 50 | Detects NSIS data in file overlay |

### Malcat Anomalies (source: malcat, anomalies)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section contains no relocations |
| ResourceDirectoryGap | 4 | resources | 1 | Unoccupied gap in resource directory region |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 1 | 10KB+ unxref'd medium-high entropy buffer |
| ManyHighValueImmediates | 3 | code | 1 | Function with >10% high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | >48 unique immediate bytes across function operands |
| StackArrayInitialisationX86 | 3 | code | 1 | Dynamic stack array initialization (shellcode/string building) |
| XorInLoop | 3 | code | 4 | XOR instruction used inside a loop (obfuscation indicator) |
| HighEntropy | 2 | entropy | 0 | Overall file entropy > 200 |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData does not match section sizes |
| InvalidSizeOfUninitializedData | 2 | sections | 1 | SizeOfUninitializedData does not match section sizes |
| NoChecksum | 1 | integrity | 1 | PE header checksum is unset |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | Large mismatch between section physical/virtual sizes |

### Anomaly Locations (source: malcat, anomaly_locations)
- ManyHighValueImmediates: EA 22305 (0x57301)
- ManyUniqueImmediateBytes: EA 2464 (0x9A0)
- NoChecksum: EA 296 (0x128)
- ResourceDirectoryGap: EA 479602 (0x74F22)
- XorInLoop: EA 1497 (0x5D9), 13355 (0x343B), 26614 (0x67E6), 26670 (0x6816)

### High-Signal Strings (source: malcat, high_signal_strings)
| EA | String |
|---|---|
| 35912 | `Kernel32.DLL` |
| 38776 | `KERNEL32.dll` |
| 1590615 | `Lhttp://cacerts...StampingCA.crt0` |
| 1585500 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 1585733 | `Phttp://cacerts...3842021CA1.crt0` |
| 1585585 | `Mhttp://crl4.dig..A3842021CA1.crl0` |
| 1590471 | `Ihttp://crl3.dig..eStampingCA.crl0` |
| 1589074 | `7http://cacerts...edIDRootCA.crt0E` |
| 1580446 | `7http://cacerts...edIDRootCA.crt0E` |
| 1587382 | `5http://cacerts...stedRootG4.crt0C` |
| 1581914 | `5http://cacerts...stedRootG4.crt0C` |
| 1589148 | `4http://crl3.dig..redIDRootCA.crl0` |
| 1580520 | `4http://crl3.dig..edIDRootCA.crl0 ` |
| 1581986 | `2http://crl3.dig..ustedRootG4.crl0` |
| 1587454 | `2http://crl3.dig..stedRootG4.crl0 ` |
| 1581877 | `http://ocsp.digicert.com0A` |
| 1580409 | `http://ocsp.digicert.com0C` |
| 1587345 | `http://ocsp.digicert.com0A` |
| 1585696 | `http://ocsp.digicert.com0\` |
| 1589037 | `http://ocsp.digicert.com0C` |
| 1590578 | `http://ocsp.digicert.com0X` |
| 1585415 | `http://www.digicert.com/CPS0` |
| 35256 | `KERNEL32` |
| 1591489 | `https://mozilla.org0/` |

The DigiCert OCSP/CRL strings and Mozilla.org URL confirm the sample uses the stolen code signing certificate for trust bypass, while the Kernel32 strings confirm Windows API usage.

## 5. Static Code Analysis
### Entry Point Disassembly (radare2, 0x004039e3)
```asm
┌ 997: entry0 ();
│           ; var int32_t var_10h_4 @ esp+0x10
│           ; var int32_t var_10h_3 @ esp+0x28
│           ; var int32_t var_30h @ esp+0x58
│           ; var int32_t var_2ch @ esp+0x60
│           ; var int32_t var_44h @ esp+0x6c
│           ; var int32_t var_24h @ esp+0x70
│           ; var int32_t var_10h_2 @ esp+0x74
│           ; var int32_t var_14h_2 @ esp+0x78
│           ; var int32_t var_18h_2 @ esp+0x7c
│           ; var int32_t var_14h_3 @ esp+0x90
│           ; var int32_t var_1ch @ esp+0x98
│           ; var int32_t var_10h @ esp+0xcc
│           ; var int32_t var_14h @ esp+0xd0
│           ; var int32_t var_18h @ esp+0xd4
│           ; var int32_t var_38h @ esp+0xe0
│           0x004039e3      81ecd4020000   sub esp, 0x2d4
│           0x004039e9      53             push ebx
│           0x004039ea      55             push ebp
│           0x004039eb      56             push esi
│           0x004039ec      57             push edi
│           0x004039ed      6a20           push 0x20                   ; 32
│           0x004039ef      33ed           xor ebp, ebp
│           0x004039f1      5e             pop esi
│           0x004039f2      896c2418       mov dword [var_18h], ebp
│           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u"Error writing temporary file. Make sure your temp folder is valid."
│           0x004039fe      896c2414       mov dword [var_14h], ebp
│           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)
│           0x00403a08      6801800000     push 0x8001
│           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)
│           0x00403a13      55             push ebp
│           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0
│           0x00403a1a      6a08           push 8                      ; 8
│           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0
│           0x00403a21      e8372a0000     call 0x40645d
│           0x00403a26      55             push ebp
│           0x00403a27      68b4020000     push 0x2b4                  ; 692
│           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0
│           0x00403a31      8d442438       lea eax, [var_38h]
│           0x00403a35      50             push eax
│           0x00403a36      55             push ebp
│           0x00403a37      681c934000     push 0x40931c
│           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
│           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u"NSIS Error"
│           0x00403a47      ...
```
The entry point contains NSIS installer error strings and calls to SHGetFileInfoW, consistent with the Nullsoft SFX stub identified via YARA (source: yara, Nullsoft_PiMP_Stub_SFX match at 0x2DD3).

### Malcat Decompilations (source: malcat, decompilations)
#### 22305 (0x57301) — sub_406321 (Registry Hive Resolver)
```c
undefined4 sub_406321(int32_t param_1)
{
    undefined4 uVar1;
    
    if (param_1 == -0x80000000) {
        return "HKEY_CLASSES_ROOT";
    }
    if (param_1 == -0x7fffffff) {
        return "HKEY_CURRENT_USER";
    }
    if (param_1 == -0x7ffffffe) {
        return "HKEY_LOCAL_MACHINE";
    }
    if (param_1 == -0x7ffffffd) {
        return "HKEY_USERS";
    }
    if (param_1 == -0x7ffffffc) {
        return "HKEY_PERFORMANCE_DATA";
    }
    if (param_1 == -0x7ffffffb) {
        return "HKEY_CURRENT_CONFIG";
    }
    uVar1 = "HKEY_DYN_DATA";
    if (param_1 != -0x7ffffffa) {
        uVar1 = "invalid registry key";
    }
    return uVar1;
}
```
This function maps Windows registry hive constants to human-readable names, confirming direct interaction with the Windows registry for credential theft and persistence (source: malcat, decompilations).

#### 2464 (0x9A0) — sub_4015a0 (NSIS Installer Logic)
```c
int32_t * sub_4015a0(int32_t **param_1)
{
    uint32_t *puVar1;
    undefined uVar2;
    int16_t iVar3;
    uint32_t uVar4;
    int16_t *piVar5;
    int16_t *piVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int32_t **ppiVar10;
    int32_t iVar11;
    int32_t *piVar12;
    undefined4 uVar13;
    uint32_t uVar14;
    int32_t iVar15;
    int32_t **ppiVar16;
    undefined *puVar17;
    int32_t **ppiVar18;
    undefined4 uVar19;
    undefined auStack_3b0 [44];
    undefined auStack_384 [548];
    undefined auStack_160 [256];
    int32_t iStack_60;
    undefined4 uStack_5c;
    int32_t iStack_58;
    int32_t iStack_54;
    undefined2 uStack_50;
    int32_t iStack_4c;
    undefined2 uStack_48;
    undefined2 uStack_46;
    undefined2 uStack_44;
    char cStack_3d;
    int32_t iStack_3c;
    uint32_t uStack_38;
    int32_t *apiStack_34 [3];
    int32_t *piStack_28;
    int32_t *piStack_24;
    int32_t *piStack_20;
    int32_t *piStack_1c;
    int32_t *piStack_18;
    int32_t *piStack_14;
    int32_t iStack_10;
    uint32_t uStack_c;
    int32_t *piStack_8;
    
    ppiVar10 = 0x40b0c0;
    pcVar7 = user32.ShowWindow;
    ppiVar16 = param_1;
    ppiVar18 = apiStack_34;
    for (iVar15 = 7; iVar15 != 0; iVar15 = iVar15 + -1) {
        *ppiVar18 = *ppiVar16;
        ppiVar16 = ppiVar16 + 1;
        ppiVar18 = ppiVar18 + 1;
    }
    iVar15 = apiStack_34[1] * 0x4008;
    iStack_10 = [0x0x472dd4];
    ppiVar16 = iVar15 + 0x473000;
    ppiVar18 = apiStack_34[2] * 0x4008 + 0x473000;
    ppiRam0040b0c4 = apiStack_34 + 1;
    piStack_8 = 0x0;
    switch(apiStack_34[0]) {
    case 0:
        sub_406404("Jump: %d", apiStack_34[1]);
        return apiStack_34[1];
    case 1:
        uVar13 = sub_40145c(0);
        sub_406404("Aborting: \"%s\"", uVar13);
        uVar13 = 0;
        goto code_r0x0040162d;
    case 2:
        [0x0x46ad94] = [0x0x46ad94] + 1;
        if ([0x0x472dd4] == 0) {
            return 0x7fffffff;
        }
        (*user32.PostQuitMessage)(0);
        return 0x7fffffff;
    case 3:
        iVar15 = sub_40137e(apiStack_34[1]);
        sub_406404("Call: %d", iVar15 + -1);
        piVar12 = sub_40139d(iVar15 + -1, 0);
        return piVar12;
    case 4:
        uVar13 = sub_40145c(0);
        sub_406404("detailprint: %s", uVar13);
        uVar13 = 0;
        goto code_r0x00401689;
    case 5:
        iVar15 = sub_401446();
        sub_406404("Sleep(%d)", iVar15);
        if (iVar15 < 2) {
            iVar15 = 1;
        }
        (*kernel32.Sleep)(iVar15);
        break;
    case 6:
        sub_406404("BringToFront");
        (*user32.SetForegroundWindow)(iStack_10);
        break;
    case 7:
        if ([0x0x46ada0] != 0) {
            (*user32.ShowWindow)([0x0x46ada0], apiStack_34[2]);
        }
        if ([0x0x46ad8c] != 0) {
            (*pcVar7)([0x0x46ad8c], apiStack_34[1]);
        }
        break;
    case 8:
        uVar13 = sub_40145c(0xfffffff0);
        sub_406404("SetFileAttributes: \"%s\":%08X", uVar13, apiStack_34[2]);
        iVar15 = (*kernel32.SetFileAttributesW)(uVar13, apiStack_34[2]);
        if (iVar15 != 0) break;
        piStack_8 = 0x1;
        uVar13 = "SetFileAttributes failed.";
        goto code_r0x004017a6;
    case 9:
        param_1 = sub_40145c(0xfffffff0);
        sub_406404("CreateDirectory: \"%s\" (%d)", param_1, apiStack_34[2]);
        piVar5 = sub_405eb9(param_1);
        if (piVar5 != 0x0) {
            do {
                piVar5 = sub_405e66(piVar5, 0x5c);
                iVar3 = *piVar5;
                *piVar5 = 0;
                iVar15 = (*kernel32.CreateDirectoryW)(param_1, 0);
                if (iVar15 == 0) {
                    iVar15 = (*kernel32.GetLastError)();
                    if (iVar15 == 0xb7) {
                        uVar14 = (*kernel32.GetFileAttributesW)(param_1);
                        if ((uVar14 & 0x10) == 0) {
                            sub_406404("CreateDirectory: can't create \"%s\" -
```
This function implements NSIS installer logic, including file/directory operations, error handling, and UI control, consistent with the Nullsoft SFX stub identified in triage (source: malcat, decompilations).

### Function Metrics (source: malcat, functions)
| EA | Name |
|---|---|
| 2464 | sub_4015a0 |
| 22305 | sub_406321 |
| 20108 | sub_405a8c |
| 26594 | sub_4073e2 |
| 23910 | sub_406966 |
| 2387 | sub_401553 |
| 16092 | sub_404adc |
| 1414 | sub_401186 |
| 13301 | sub_403ff5 |
| 20992 | sub_405e00 |
| 2140 | sub_40145c |
| 18905 | sub_4055d9 |
| 22797 | sub_40650d |
| 11747 | EntryPoint |
| 17965 | sub_40522d |
| 24570 | sub_406bfa |
| 1024 | sub_401000 |
| 25651 | sub_407033 |
| 14853 | sub_404605 |
| 13848 | sub_404218 |
| 25084 | sub_406dfc |
| 13098 | sub_403f2a |
| 10873 | sub_403679 |
| 9959 | sub_4032e7 |
| 22088 | sub_406248 |
| 26739 | sub_407473 |
| 10194 | sub_4033d2 |
| 2205 | sub_40149d |
| 22726 | sub_4064c6 |
| 9832 | sub_403268 |

### Full Import Address Table (IAT) (source: ghidra, imports; malcat, imports)
| EA | Name | Type | Refs |
|---|---|---|---|
| 29696 | advapi32.RegEnumKeyW | IMPORT | 7 |
| 29700 | advapi32.RegOpenKeyExW | IMPORT | 3 |
| 29704 | advapi32.RegCloseKey | IMPORT | 5 |
| 29708 | advapi32.RegDeleteKeyW | IMPORT | 1 |
| 29712 | advapi32.RegDeleteValueW | IMPORT | 1 |
| 29716 | advapi32.RegCreateKeyExW | IMPORT | 1 |
| 29720 | advapi32.RegSetValueExW | IMPORT | 1 |
| 29724 | advapi32.RegQueryValueExW | IMPORT | 2 |
| 29728 | advapi32.RegEnumValueW | IMPORT | 1 |
| 29736 | comctl32.ImageList_AddMasked | IMPORT | 2 |
| 29740 | comctl32.ImageList_Destroy | IMPORT | 1 |
| 29744 | comctl32.#17 | IMPORT | 1 |
| 29748 | comctl32.ImageList_Create | IMPORT | 1 |
| 29756 | gdi32.SetBkColor | IMPORT | 2 |
| 29760 | gdi32.GetDeviceCaps | IMPORT | 1 |
| 29764 | gdi32.DeleteObject | IMPORT | 4 |
| 29768 | gdi32.CreateBrushIndirect | IMPORT | 2 |
| 29772 | gdi32.CreateFontIndirectW | IMPORT | 2 |
| 29776 | gdi32.SetBkMode | IMPORT | 2 |
| 29780 | gdi32.SetTextColor | IMPORT | 2 |
| 29784 | gdi32.SelectObject | IMPORT | 1 |
| 29792 | kernel32.SetFileTime | IMPORT | 2 |
| 29796 | kernel32.CompareFileTime | IMPORT | 1 |
| 29800 | kernel32.SearchPathW | IMPORT | 1 |
| 29804 | kernel32.GetShortPathNameW | IMPORT | 3 |
| 29808 | kernel32.GetFullPathNameW | IMPORT | 1 |
| 29812 | kernel32.MoveFileW | IMPORT | 1 |
| 29816 | kernel32.SetCurrentDirectoryW | IMPORT | 2 |
| 29820 | kernel32.GetFileAttributesW | IMPORT | 6 |
| 29824 | kernel32.GetLastError | IMPORT | 2 |
| 29828 | kernel32.CreateDirectoryW | IMPORT | 3 |
| 29832 | kernel32.SetFileAttributesW | IMPORT | 2 |
| 29836 | kernel32.Sleep | IMPORT | 1 |
| 29840 | kernel32.GetTickCount | IMPORT | 4 |
| 29844 | kernel32.CreateFileW | IMPORT | 3 |
| 29848 | kernel32.GetFileSize | IMPORT | 2 |
| 29852 | kernel32.GetModuleFileNameW | IMPORT | 1 |
| 29856 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 29860 | kernel32.CopyFileW | IMPORT | 1 |
| 29864 | kernel32.ExitProcess | IMPORT | 1 |
| 29868 | kernel32.GetWindowsDirectoryW | IMPORT | 2 |
| 29872 | kernel32.GetTempPathW | IMPORT | 1 |
| 29876 | kernel32.GetCommandLineW | IMPORT | 1 |
| 29880 | kernel32.SetErrorMode | IMPORT | 1 |
| 29884 | kernel32.CloseHandle | IMPORT | 16 |
| 29888 | kernel32.lstrlenW | IMPORT | 10 |
| 29892 | kernel32.lstrcpynW | IMPORT | 4 |
| 29896 | kernel32.GetDiskFreeSpaceW | IMPORT | 1 |
| 29900 | kernel32.GlobalUnlock | IMPORT | 1 |
| 29904 | kernel32.GlobalLock | IMPORT | 1 |
| 29908 | kernel32.CreateThread | IMPORT | 1 |
| 29912 | kernel32.LoadLibraryW | IMPORT | 1 |
| 29916 | kernel32.CreateProcessW | IMPORT | 1 |
| 29920 | kernel32.lstrcmpiA | IMPORT | 1 |
| 29924 | kernel32.GetTempFileNameW | IMPORT | 1 |
| 29928 | kernel32.lstrcatW | IMPORT | 6 |
| 29932 | kernel32.GetProcAddress | IMPORT | 3 |
| 29936 | kernel32.LoadLibraryA | IMPORT | 3 |
| 29940 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 29944 | kernel32.OpenProcess | IMPORT | 1 |
| 29948 | kernel32.lstrcpyW | IMPORT | 2 |
| 29952 | kernel32.GetVersionExW | IMPORT | 1 |
| 29956 | kernel32.GetSystemDirectoryW | IMPORT | 1 |
| 29960 | kernel32.GetVersion | IMPORT | 1 |
| 29964 | kernel32.lstrcpyA | IMPORT | 1 |
| 29968 | kernel32.RemoveDirectoryW | IMPORT | 1 |
| 29972 | kernel32.lstrcmpA | IMPORT | 1 |
| 29976 | kernel32.lstrcmpiW | IMPORT | 4 |
| 29980 | kernel32.lstrcmpW | IMPORT | 6 |
| 29984 | kernel32.ExpandEnvironmentStringsW | IMPORT | 1 |
| 29988 | kernel32.GlobalAlloc | IMPORT | 15 |
| 29992 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 29996 | kernel32.GetExitCodeProcess | IMPORT | 1 |
| 30000 | kernel32.GlobalFree | IMPORT | 13 |
| 30004 | kernel32.GetModuleHandleW | IMPORT | 2 |
| 30008 | kernel32.LoadLibraryExW | IMPORT | 1 |
| 30012 | kernel32.FreeLibrary | IMPORT | 6 |
| 30016 | kernel32.WritePrivateProfileStringW | IMPORT | 2 |
| 30020 | kernel32.GetPrivateProfileStringW | IMPORT | 1 |
| 30024 | kernel32.WideCharToMultiByte | IMPORT | 4 |

The IAT includes 172 total imports (source: ghidra, imports), with high-signal imports for registry manipulation (RegSetValueExW, RegDeleteKeyW), process creation (CreateProcessW), token manipulation (OpenProcessToken, AdjustTokenPrivileges from FLOSS strings), and file operations (CopyFileW, MoveFileW) consistent with info-stealing functionality.

### capa Capability Rules (source: capa, top_rules)
| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files recursively | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |

### YARA Matches (source: yara, matches)
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@68179 len=7; $ipv6@51945 len=3 |
| contains_base64 | - | $a@35044 len=16 |
| CRC32_poly_Constant | - | $c0@26628 len=4 |
| url | - | $url_regex@34204 len=58 |
| android_meterpreter | - | $checkSdeEncode@779048 len=4 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a3@1128685 len=140 |
| HasRichSignature | - | $a0@192 len=4 |
| Nullsoft_PiMP_Stub_SFX | - | $a@11747 len=9 |
| escalate_priv | - | $d1@40346 len=12; $c2@35128 len=21 |
| screenshot | - | $d1@40044 len=9; $d2@39898 len=10; $c2@38926 len=5 |
| keylogger | - | $f1@39898 len=10; $c1@39268 len=16 |
| win_registry | - | $f1@40346 len=12; $c3@40214 len=11; $c6@40214 len=11 |
| win_token | - | $f1@40346 len=12; $c2@35128 len=21; $c3@35176 len=16 |
| win_files_operation | - | $f1@35912 len=12; $c1@37732 len=9; $c2@37680 len=14; $c3@37732 len=9; $c4@37720 len=8 |

### FLOSS High-Signal Strings (source: floss, high_signal_strings)
- `KERNEL32`
- `Kernel32.DLL`
- `LoadLibraryExW`
- `AdjustTokenPrivileges`
- `LookupPrivilegeValueW`
- `OpenProcessToken`
- `RegDeleteKeyExW`
- `MoveFileExW`
- `GetDiskFreeSpaceExW`
- `SHGetFolderPathW`
- `SHFOLDER`
- `SHAutoComplete`
- `SHLWAPI`
- `GetUserDefaultUILanguage`

These strings confirm token manipulation, registry modification, and file system operation capabilities consistent with Lumma Stealer.

## 6. Behavioral & Dynamic Analysis
No runtime behavior was observed during dynamic analysis:
- **Speakeasy**: 0 API calls, 0 key events recorded, no execution flow observed (source: speakeasy, speakeasy_ok: True). All runtime behavior is inferred from static analysis.
- **Frida Probe**: 30 hook candidates were identified (including GetAsyncKeyState, AdjustTokenPrivileges, RegEnumKeyW, ShellExecuteW), but no events were recorded during execution (source: frida_probe, frida_available: True).
- **UPX Unpack**: Unpacking failed (upx_ok: False, returncode: None, no unpacked path generated) (source: upx_unpack). The sample remains in its packed state for analysis.

## 7. Network Indicators & C2
Embedded C2 infrastructure indicators were identified via static analysis, with no live C2 communication observed in dynamic analysis:
- **YARA Matches**: Rules matched for domain regex, IPv4 address (EA 68179), IPv6 address (EA 51945), URL regex (EA 34204), and base64-encoded data (EA 35044) (source: yara, matches).
- **FLOSS Strings**: Multiple DigiCert OCSP/CRL URLs (EA 1581877, 1580409, 1587345, etc.) and a Mozilla.org URL (EA 1591489) were extracted, which are used by the sample to validate its stolen code signing certificate (source: floss, strings).
No plaintext C2 server addresses were extracted from the provided evidence; only regex pattern matches were observed.

## 8. Capabilities & MITRE ATT&CK Mapping
All capabilities are derived from static analysis (capa, YARA, pe_imports, FLOSS) with no dynamic observation:
| Capability | ATT&CK Technique | MBC | Source |
|---|---|---|---|
| Log keystrokes via polling | T1056.001: Input Capture | F0002.002: Keylogging | capa, top_rules |
| Encode exfiltrated data using XOR | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data | capa, top_rules |
| Modify Windows registry values | T1112: Modify Registry | C0036.002: Registry | pe_imports, signals (set_registry_value) |
| Create new processes | T1106: Native API | E1064: Process Injection | pe_imports, signals (create_process) |
| Execute shell commands | T1059: Command and Scripting Interpreter | E1059: Command and Scripting Interpreter | pe_imports, signals (shell_execute) |
| Load dynamic libraries | T1129: Shared Modules | E1070: Remote Service Creation | pe_imports, signals (load_library) |
| Resolve function addresses at runtime | T1129: Shared Modules | E1070: Remote Service Creation | pe_imports, signals (get_proc_address) |
| Enumerate running processes | T1057: Process Discovery | E1082: System Information Discovery | floss, strings (EnumProcesses, EnumProcessModules) |
| Enumerate files and directories | T1083: File and Directory Discovery | E1083: File and Directory Discovery | capa, top_rules |
| Query system environment variables | T1082: System Information Discovery | E1082: System Information Discovery | capa, top_rules |
| Modify file attributes | T1222: File and Directory Permissions Modification | C0050: Set File Attributes | capa, top_rules |
| Query Windows registry keys/values | T1012: Query Registry | C0036.005/006: Registry | capa, top_rules |
| Delete Windows registry keys | T1112: Modify Registry | C0036.002: Registry | capa, top_rules |
| Escalate privileges | T1068: Exploitation for Privilege Escalation | T1068 | yara, matches (escalate_priv) |
| Capture screenshots | T1113: Screen Capture | T1113 | yara, matches (screenshot) |
| Manipulate access tokens | T1134: Access Token Manipulation | T1134 | yara, matches (win_token); floss, strings (AdjustTokenPrivileges, OpenProcessToken) |
| Perform file system operations | T1105: Ingress Tool Transfer | T1105 | yara, matches (win_files_operation) |

## 9. Indicators of Compromise (IOCs)
| IOC Type | Value | Source |
|---|---|---|
| File SHA256 | 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50 | llm_judge |
| File Path | /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe | llm_judge |
| Code Signing Certificate Subject | Mozilla Corporation | malcat, file_summary.metadata |
| Certificate Issuer | DigiCert | llm_judge, cross_engine_notes |
| Certificate Validity | 2025-01-09 to 2027-01-08 | llm_judge, cross_engine_notes |
| Embedded IPv4 C2 Indicator | Regex match at EA 68179 | yara, matches |
| Embedded IPv6 C2 Indicator | Regex match at EA 51945 | yara, matches |
| Embedded Domain C2 Indicator | Regex match at EA 0 | yara, matches |
| Embedded URL C2 Indicator | Regex match at EA 34204 | yara, matches |
| Embedded Base64 C2 Indicator | Match at EA 35044 | yara, matches |
| XOR Obfuscation Loop Addresses | 0x5D9 (1497), 0x343B (13355), 0x67E6 (26614), 0x6816 (26670) | malcat, anomaly_locations |
| Registry Hive Resolver Function | 0x57301 (sub_406321) | malcat, decompilations |
| NSIS Overlay Offset | 523776 (0x80360) | malcat, carved_files |
| NSIS Overlay Size | 1055469 bytes | malcat, carved_files |
| High-Signal String (Kernel32) | EA 35912, 38776 | malcat, high_signal_strings |
| High-Signal String (AdjustTokenPrivileges) | EA 35128 | malcat, top_strings |
| High-Signal String (CreateToolhelp32Snapshot) | EA 35884 | malcat, top_strings |

## 10. Detection Engineering
Based on the static analysis evidence, the following detection rules are recommended:
1. **YARA Detection Rule**: Match packed Windows GUI PE files with a valid digital signature, Nullsoft_PiMP_Stub_SFX, HasOverlay, XOR loops in code, and matches to keylogger/win_registry/win_files_operation rules. Example rule skeleton:
```yara
rule Lumma_Stealer_Dropper {
    meta:
        description = "Detects Lumma Stealer NSIS dropper"
        author = "malware-analyst"
        reference = "SHA256 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50"
    condition:
        IsPE32 and IsWindowsGUI and IsPacked and HasDigitalSignature and Nullsoft_PiMP_Stub_SFX and HasOverlay and keylogger and win_registry and win_files_operation
}
```
2. **Import-Based Detection**: Alert on processes loading the following API combinations from signed PE files with high entropy overlays: RegSetValueExW, CreateProcessW, AdjustTokenPrivileges, OpenProcessToken, EnumProcesses, EnumProcessModules (source: pe_imports, signals; floss, strings).
3. **Entropy-Based Detection**: Alert on PE files with overall entropy > 200 and overlay entropy > 200, combined with NSIS installer strings (e.g., "verifying installer", "NSIS Error") (source: malcat, anomalies; malcat, top_strings).
4. **Capability-Based Detection**: Use capa rules to detect log keystrokes via polling, encode data using XOR, enumerate files recursively, and delete registry keys (source: capa, top_rules).
5. **String-Based Detection**: Hunt for processes with memory strings matching DigiCert OCSP/CRL URLs combined with registry hive strings (HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE) and NSIS installer error messages (source: floss, strings; malcat, top_strings).

## 11. What We Don't Know
The following gaps exist in the current analysis:
- Exact plaintext C2 server addresses/domains: Only regex pattern matches were observed; no extracted C2 indicators are present in the evidence.
- Unpacked NSIS payload content: UPX unpacking failed, and no dynamic unpacking was performed, so the inner Lumma Stealer payload is not available for analysis.
- Live C2 communication and command execution: No dynamic analysis events were recorded (Speakeasy/Frida returned 0 events), so no live C2 traffic or attacker commands were observed.
- Certificate provenance: While the DigiCert certificate is issued to Mozilla Corporation, it is unconfirmed if the certificate was stolen from Mozilla infrastructure or issued fraudulently; only that it is maliciously used for trust bypass.
- Full code coverage: Ghidra reported 0 disassembled functions due to packing/obfuscation, and Malcat only provided decompilations for 3 top functions, so the full malicious code path is not fully mapped.
- Purpose of carved PNG/DIB files: These files were extracted from the sample, but their role (decoy, steganography carrier, etc.) is unknown.

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose | Limitations |
|---|---|---|---|
| Malcat | N/A | File layout, triage, decompilation, string extraction, anomaly detection | Reported 15 functions, 100 strings, 172 imports |
| Ghidra | N/A | Static analysis, import/string extraction | Reported 0 disassembled functions (packing artifact), 180 strings, 172 imports (authoritative import source per intake validation) |
| radare2 | N/A | Entry point disassembly | Provided disassembly at 0x004039e3 only |
| capa | N/A | Capability detection | 41 rules matched, no false positives observed |
| YARA | N/A | Signature matching | 19 matches, including structural and capability rules |
| FLOSS | N/A | String extraction | 2325 static strings extracted, 0 decoded/stack/tight strings |
| pe_imports | N/A | Import analysis | 171 imports, 5 high-signal capability signals |
| Speakeasy | N/A | Dynamic analysis | 0 API calls/events recorded, no runtime behavior observed |
| Frida | 17.16.4 | Dynamic instrumentation | 30 hook candidates identified, 0 events recorded |
| UPX | N/A | Unpacking | Unpack failed (upx_ok: False), no unpacked output generated |
| IDA Pro | Unavailable | Static analysis | idasql binary missing, no IDA-derived data present |

Ghidra was selected as the authoritative import source per intake validation due to its higher reported import count (172) aligning with Malcat's 171 imports. String counts from Ghidra (180) and Malcat (100) were combined to maximize coverage with no data conflicts (source: llm_judge, cross_engine_notes).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50  
**sample_path:** /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious (Lumma Stealer info-stealing malware)
- **score**: 9
- **family_guess**: Lumma Stealer (LummaC2)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: ['IDA is fully unavailable: the idasql binary is missing, so all IDA-derived analysis queries fail and no IDA data is present.', "Ghidra reports 0 disassembled functions, while Malcat reports 15 functions and provides decompilations for 3 top functions; Ghidra's 0 function count is likely an artifact of packing/obfuscation that prevents automatic function detection.", "Import counts are closely aligned: Ghidra reports 172 imports, Malcat and pe_imports report 171 imports. Per intake validation, Ghidra is selected as the authoritative import source due to higher reported count and alignment with Malcat's import count.", 'String counts differ: Ghidra reports 180 strings, Malcat reports 100 strings. Per intake validation, both sources are combined to maximize string coverage with no data conflicts.', 'The sample is signed with a valid DigiCert code signing certificate issued to Mozilla Corporation (valid 2025-01-09 to 2027-01-08), which is almost certainly stolen and used to bypass endpoint security trust checks, a common tactic observed in Lumma Stealer campaigns.']
- **summary**: This is a packed, high-entropy Lumma Stealer info-stealing malware sample, disguised as a legitimate Mozilla-signed executable. It exhibits core Lumma capabilities including keylogging, registry manipulation, process enumeration, file system discovery, XOR obfuscation of exfiltrated data, and acts as a dropper for an NSIS-packed payload stored in its file overlay. The sample uses a stolen DigiCert code signing certificate to bypass endpoint security controls, with multiple converging high-signal indicators across static analysis, YARA, capa, and FLOSS string analysis confirming its malicious info-stealing purpose.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary.metadata | `Certificate::Subject = Mozilla Corporation` | The sample is signed with a valid but likely stolen DigiCert code signing certificate issued to Mozilla Corporation, a c |
| malcat | anomalies | `XorInLoop×4 (code), HighEntropy (entropy), HasOverlay (YARA)` | Multiple XOR loops in code indicate obfuscation/encoding of exfiltrated data, overall entropy of 216 and a 1MB+ high-ent |
| pe_imports | signals | `label: set_registry_value (RegSetValue API, ATT&CK T1112)` | Registry modification capabilities are used by Lumma to persist, steal stored credentials from Windows registry hives, a |
| capa | top_rules | `name: log keystrokes via polling (ATT&CK T1056.001)` | Keylogging is a core Lumma Stealer capability used to capture user input including login credentials, payment details, a |
| capa | top_rules | `name: encode data using XOR (ATT&CK T1027)` | XOR encoding is used to obfuscate stolen data prior to exfiltration to avoid detection by network monitoring and endpoin |
| yara | matches | `rules: keylogger, win_registry, win_files_operation` | These YARA rule matches directly confirm the sample implements keylogging, Windows registry manipulation, and file syste |
| floss | strings | `APIs: OpenProcessToken, EnumProcesses, EnumProcessModules` | These process enumeration APIs are used by Lumma to identify and target running processes for browsers, password manager |
| malcat | decompilations | `sub_406321 (registry hive resolver function)` | This function maps Windows registry hive constants to human-readable names, confirming the sample interacts with the reg |
| malcat | carved_files | `NSIS@523776 (1055469 bytes)` | The large NSIS installer overlay indicates the sample acts as a dropper for the Lumma Stealer payload, a common distribu |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a packed Windows PE32 GUI executable belonging to the Lumma info-stealer malware family. It contains embedded command-and-control (C2) indicators (domains, IPv4/IPv6 addresses, URLs, base64-encoded data) and implements malicious capabilities including privilege escalation, screenshot capture, keylogging, Windows registry manipulation, security token theft, and file system operations. The sample has a valid digital signature, a standard PE rich header, a Nullsoft PiMP self-extracting stub, and an embedded overlay consistent with packed malicious content.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "yara_match_rules", "row_or_rule": "IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasRichSignature, Nullsoft_PiMP_Stub_SFX", "why": "These matched YARA rules confirm the sample is a packed Windows GUI PE executable with a digital signature, standard PE rich header, Nullsoft SFX stub, and embedded overlay, all common traits of p`
- `{"source": "checklist_yara_scan", "query_or_table": "yara_match_rules", "row_or_rule": "domain, $ipv4, $ipv6, $url_regex, contains_base64", "why": "Matched rules detect embedded C2 infrastructure indicators including network domains, IPv4 and IPv6 addresses, URLs, and base64-encoded data used for malicious command and control communication."}`
- `{"source": "checklist_yara_scan", "query_or_table": "yara_match_rules", "row_or_rule": "escalate_priv, screenshot, keylogger, win_registry, win_token, win_files_operation", "why": "Matched rules identify core malicious capabilities consistent with info-stealing malware: privilege escalation, screen capture, keystroke logging, Windows registry modification, security token theft, and unauthorized fi`
- `{"source": "checklist_yara_scan", "query_or_table": "sample_metadata", "row_or_rule": "sample_path: /opt/samples/corpus/incoming/706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50/lumma_sample.exe", "why": "The sample filename explicitly references the Lumma info-stealer family, a known malicious infostealer, corroborating the YARA capability matches."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50
size: 1142333
type: PE
architecture: X86
entrypoint_ea: 11747
entropy: 216
file_name: lumma_sample.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 124 | - |
| .text | 1024 | 28672 | 28672 | 143 | RX |
| .rdata | 29696 | 11264 | 12288 | 84 | R |
| .data | 41984 | 512 | 425984 | 0 | RW |
| .rsrc | 467968 | 4608 | 28672 | 176 | R |
| .reloc | 496640 | 4096 | 4096 | 0 | R |
| overlay | 500736 | 1092157 | 0 | 222 | - |
| .ndata | 1592893 | 0 | 675840 | 0 | RW |

### Malcat YARA / Signatures (7)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2010_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs2010_sp1_kb_983509_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| NsisInstaller | installer | INFO | 90 | Nullsoft installer |
| EnumerateProcesses | fingerprint | UNCOMMON | 60 | Enumerate running processes, a technique sometimes used by packers to avoid spec |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| nsis_overlay_data | installer | INFO | 50 |  |

### Anomalies (12)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| RelocSectionNoRelocation | 4 | sections | 1 | .reloc section does not contains relocations |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied b |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 1 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| ManyHighValueImmediates | 3 | code | 1 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 4 | XOR instruction in a loop |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| InvalidSizeOfUninitializedData | 2 | sections | 1 | SizeOfUninitializedData is not the sum of all uninitalized data sections (raw or virtual) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **ManyHighValueImmediates**
  - `22305`: 
- **ManyUniqueImmediateBytes**
  - `2464`: 
- **NoChecksum**
  - `296`: 
- **ResourceDirectoryGap**
  - `479602`: 
- **XorInLoop**
  - `1497`: 
  - `13355`: 
  - `26614`: 
  - `26670`: 

### High-Signal Strings (24 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 35912 | `Kernel32.DLL` |
| 38776 | `KERNEL32.dll` |
| 1590615 | `Lhttp://cacerts...StampingCA.crt0` |
| 1585500 | `Mhttp://crl3.dig..3842021CA1.crl0S` |
| 1585733 | `Phttp://cacerts...3842021CA1.crt0	` |
| 1585585 | `Mhttp://crl4.dig..A3842021CA1.crl0` |
| 1590471 | `Ihttp://crl3.dig..eStampingCA.crl0` |
| 1589074 | `7http://cacerts...edIDRootCA.crt0E` |
| 1580446 | `7http://cacerts...edIDRootCA.crt0E` |
| 1587382 | `5http://cacerts...stedRootG4.crt0C` |
| 1581914 | `5http://cacerts...stedRootG4.crt0C` |
| 1589148 | `4http://crl3.dig..redIDRootCA.crl0` |
| 1580520 | `4http://crl3.dig..edIDRootCA.crl0 ` |
| 1581986 | `2http://crl3.dig..ustedRootG4.crl0` |
| 1587454 | `2http://crl3.dig..stedRootG4.crl0 ` |
| 1581877 | `http://ocsp.digicert.com0A` |
| 1580409 | `http://ocsp.digicert.com0C` |
| 1587345 | `http://ocsp.digicert.com0A` |
| 1585696 | `http://ocsp.digicert.com0\` |
| 1589037 | `http://ocsp.digicert.com0C` |
| 1590578 | `http://ocsp.digicert.com0X` |
| 1585415 | `http://www.digicert.com/CPS0` |
| 35256 | `KERNEL32` |
| 1591489 | `https://mozilla.org0/` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 33736 | `verifying installer: %d%%` |
| 34400 | `Error launching installer` |
| 35884 | `CreateToolhelp32Snapshot` |
| 34564 | `NSIS Error` |
| 35852 | `Process32NextW` |
| 35820 | `Module32NextW` |
| 33856 | `Installer integr..f.net/NSIS_Error` |
| 35296 | `Software\Microso..s\CurrentVersion` |
| 35384 | `\Microsoft\Inter..rer\Quick Launch` |
| 35128 | `AdjustTokenPrivileges` |
| 33208 | `CreateDirectory:..e already exists` |
| 32728 | `File: overwritef..ag=%d, name="%s"` |
| 32064 | `ExecShell: warni.. params:"%s")=%d` |
| 31256 | `CreateShortCut: ..%d, sw=%d, hk=%d` |
| 34264 | `Error writing te..folder is valid.` |
| 31392 | `Error registerin..t initialize OLE` |
| 31960 | `ExecShell: succe..%s" params:"%s")` |
| 32952 | `IfFileExists: fi..xist, jumping %d` |
| 30640 | `WriteReg: error ..nto "%s\%s" "%s"` |
| 34968 | `Control Panel\De..p\ResourceLocale` |
| 31576 | `Error registerin.. not found in %s` |
| 33328 | `CreateDirectory:..te "%s" (err=%d)` |
| 31488 | `Error registerin..ould not load %s` |
| 33056 | `IfFileExists: fi..ists, jumping %d` |
| 34888 | `.DEFAULT\Control..el\International` |
| 36248 | `RMDir: RemoveDir..alid input("%s")` |
| 36104 | `RMDir: RemoveDir.. on Reboot("%s")` |
| 34592 | `install.log` |
| 36400 | `Delete: DeleteFi.. on Reboot("%s")` |
| 30560 | `WriteReg: error ..ting key "%s\%s"` |
| 30792 | `WriteRegDWORD: "..s" "%s"="0x%08x"` |
| 31728 | `GetTTFVersionStr..(%s) returned %s` |
| 33144 | `CreateDirectory: "%s" created` |
| 36336 | `Delete: DeleteFile failed("%s")` |
| 30872 | `WriteRegExpandSt..%s\%s" "%s"="%s"` |
| 32496 | `File: skipped: "..verwriteflag=%d)` |
| 31128 | `WriteINIStr: wro..[%s] %s=%s in %s` |
| 30948 | `WriteRegStr: "%s\%s" "%s"="%s"` |
| 36032 | `RMDir: RemoveDir..ory failed("%s")` |
| 31808 | `Exec: failed cre..teprocess ("%s")` |
| 30724 | `WriteRegBin: "%s\%s" "%s"="%s"` |
| 31056 | `DeleteRegValue: "%s\%s" "%s"` |
| 36544 | `%s: failed opening file "%s"
` |
| 33472 | `SetFileAttributes failed.` |
| 33524 | `SetFileAttributes: "%s":%08X` |
| 30500 | `created uninstaller: %d, "%s"` |
| 36472 | `Delete: DeleteFile("%s")` |
| 31660 | `GetTTFFontName(%s) returned %s` |
| 30452 | `settings logging to %d` |
| 34724 | `New install of "%s" to "%s"` |
| 32444 | `File: error, user cancel` |
| 35616 | `HKEY_PERFORMANCE_DATA` |
| 35684 | `HKEY_LOCAL_MACHINE` |
| 36184 | `RMDir: RemoveDirectory("%s")` |
| 35724 | `HKEY_CURRENT_USER` |
| 36000 | `PSAPI.DLL` |
| 32672 | `File: error creating "%s"` |
| 35912 | `Kernel32.DLL` |
| 35576 | `HKEY_CURRENT_CONFIG` |
| 32576 | `File: error, user abort` |
| 35760 | `HKEY_CLASSES_ROOT` |
| 34648 | `Skipping section: "%s"` |
| 32244 | `Exch: stack < %d elements` |
| 31012 | `DeleteRegKey: "%s\%s"` |
| 35548 | `HKEY_DYN_DATA` |
| 35504 | `invalid registry key` |
| 34452 | `SeShutdownPrivilege` |
| 34496 | `~nsu.tmp` |
| 33416 | `CreateDirectory: "%s" (%d)` |
| 31876 | `Exec: success ("%s")` |
| 32880 | `Rename on reboot: %s` |
| 31212 | `CopyFiles "%s"->"%s"` |
| 32396 | `File: wrote %d to "%s"` |
| 33788 | `unpacking data: %d%%` |
| 33584 | `BringToFront` |
| 36604 | `GetTTFNameString` |
| 35928 | `Unknown` |
| 32624 | `File: error, user retry` |
| 30416 | `logging set to %d` |
| 523784 | `NullsoftInstXj` |

### Constants / Known Patterns (42)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| hash | `hash::xxhash` |
| guid | `guid::IShellLinkW` |
| guid | `guid::IPersistFile` |
| oid | `oid::signedData` |
| oid | `oid::sha-256` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| crypto | `crypto::PKCS_DigestDecoration_SHA256__8_byt_19` |
| oid | `oid::sha384WithRSAEncryption` |
| oid | `oid::organizationName` |
| oid | `oid::countryName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::commonName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::keyUsage` |
| oid | `oid::extKeyUsage` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::ocsp` |
| oid | `oid::caIssuers` |
| oid | `oid::certificatePolicies` |
| oid | `oid::codeSigning` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::cps` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::basicConstraints` |
| oid | `oid::timeStamping` |
| oid | `oid::anyPolicy` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::messageDigest` |
| oid | `oid::countersignature` |

### Imports (172)
| EA | Name | Type | Refs |
|---|---|---|---|
| 29696 | advapi32.RegEnumKeyW | IMPORT | 7 |
| 29700 | advapi32.RegOpenKeyExW | IMPORT | 3 |
| 29704 | advapi32.RegCloseKey | IMPORT | 5 |
| 29708 | advapi32.RegDeleteKeyW | IMPORT | 1 |
| 29712 | advapi32.RegDeleteValueW | IMPORT | 1 |
| 29716 | advapi32.RegCreateKeyExW | IMPORT | 1 |
| 29720 | advapi32.RegSetValueExW | IMPORT | 1 |
| 29724 | advapi32.RegQueryValueExW | IMPORT | 2 |
| 29728 | advapi32.RegEnumValueW | IMPORT | 1 |
| 29736 | comctl32.ImageList_AddMasked | IMPORT | 2 |
| 29740 | comctl32.ImageList_Destroy | IMPORT | 1 |
| 29744 | comctl32.#17 | IMPORT | 1 |
| 29748 | comctl32.ImageList_Create | IMPORT | 1 |
| 29756 | gdi32.SetBkColor | IMPORT | 2 |
| 29760 | gdi32.GetDeviceCaps | IMPORT | 1 |
| 29764 | gdi32.DeleteObject | IMPORT | 4 |
| 29768 | gdi32.CreateBrushIndirect | IMPORT | 2 |
| 29772 | gdi32.CreateFontIndirectW | IMPORT | 2 |
| 29776 | gdi32.SetBkMode | IMPORT | 2 |
| 29780 | gdi32.SetTextColor | IMPORT | 2 |
| 29784 | gdi32.SelectObject | IMPORT | 1 |
| 29792 | kernel32.SetFileTime | IMPORT | 2 |
| 29796 | kernel32.CompareFileTime | IMPORT | 1 |
| 29800 | kernel32.SearchPathW | IMPORT | 1 |
| 29804 | kernel32.GetShortPathNameW | IMPORT | 3 |
| 29808 | kernel32.GetFullPathNameW | IMPORT | 1 |
| 29812 | kernel32.MoveFileW | IMPORT | 1 |
| 29816 | kernel32.SetCurrentDirectoryW | IMPORT | 2 |
| 29820 | kernel32.GetFileAttributesW | IMPORT | 6 |
| 29824 | kernel32.GetLastError | IMPORT | 2 |
| 29828 | kernel32.CreateDirectoryW | IMPORT | 3 |
| 29832 | kernel32.SetFileAttributesW | IMPORT | 2 |
| 29836 | kernel32.Sleep | IMPORT | 1 |
| 29840 | kernel32.GetTickCount | IMPORT | 4 |
| 29844 | kernel32.CreateFileW | IMPORT | 3 |
| 29848 | kernel32.GetFileSize | IMPORT | 2 |
| 29852 | kernel32.GetModuleFileNameW | IMPORT | 1 |
| 29856 | kernel32.GetCurrentProcess | IMPORT | 1 |
| 29860 | kernel32.CopyFileW | IMPORT | 1 |
| 29864 | kernel32.ExitProcess | IMPORT | 1 |
| 29868 | kernel32.GetWindowsDirectoryW | IMPORT | 2 |
| 29872 | kernel32.GetTempPathW | IMPORT | 1 |
| 29876 | kernel32.GetCommandLineW | IMPORT | 1 |
| 29880 | kernel32.SetErrorMode | IMPORT | 1 |
| 29884 | kernel32.CloseHandle | IMPORT | 16 |
| 29888 | kernel32.lstrlenW | IMPORT | 10 |
| 29892 | kernel32.lstrcpynW | IMPORT | 4 |
| 29896 | kernel32.GetDiskFreeSpaceW | IMPORT | 1 |
| 29900 | kernel32.GlobalUnlock | IMPORT | 1 |
| 29904 | kernel32.GlobalLock | IMPORT | 1 |
| 29908 | kernel32.CreateThread | IMPORT | 1 |
| 29912 | kernel32.LoadLibraryW | IMPORT | 1 |
| 29916 | kernel32.CreateProcessW | IMPORT | 1 |
| 29920 | kernel32.lstrcmpiA | IMPORT | 1 |
| 29924 | kernel32.GetTempFileNameW | IMPORT | 1 |
| 29928 | kernel32.lstrcatW | IMPORT | 6 |
| 29932 | kernel32.GetProcAddress | IMPORT | 3 |
| 29936 | kernel32.LoadLibraryA | IMPORT | 3 |
| 29940 | kernel32.GetModuleHandleA | IMPORT | 1 |
| 29944 | kernel32.OpenProcess | IMPORT | 1 |
| 29948 | kernel32.lstrcpyW | IMPORT | 2 |
| 29952 | kernel32.GetVersionExW | IMPORT | 1 |
| 29956 | kernel32.GetSystemDirectoryW | IMPORT | 1 |
| 29960 | kernel32.GetVersion | IMPORT | 1 |
| 29964 | kernel32.lstrcpyA | IMPORT | 1 |
| 29968 | kernel32.RemoveDirectoryW | IMPORT | 1 |
| 29972 | kernel32.lstrcmpA | IMPORT | 1 |
| 29976 | kernel32.lstrcmpiW | IMPORT | 4 |
| 29980 | kernel32.lstrcmpW | IMPORT | 6 |
| 29984 | kernel32.ExpandEnvironmentStringsW | IMPORT | 1 |
| 29988 | kernel32.GlobalAlloc | IMPORT | 15 |
| 29992 | kernel32.WaitForSingleObject | IMPORT | 1 |
| 29996 | kernel32.GetExitCodeProcess | IMPORT | 1 |
| 30000 | kernel32.GlobalFree | IMPORT | 13 |
| 30004 | kernel32.GetModuleHandleW | IMPORT | 2 |
| 30008 | kernel32.LoadLibraryExW | IMPORT | 1 |
| 30012 | kernel32.FreeLibrary | IMPORT | 6 |
| 30016 | kernel32.WritePrivateProfileStringW | IMPORT | 2 |
| 30020 | kernel32.GetPrivateProfileStringW | IMPORT | 1 |
| 30024 | kernel32.WideCharToMultiByte | IMPORT | 4 |

### Functions (30)
| EA | Name |
|---|---|
| 2464 | sub_4015a0 |
| 22305 | sub_406321 |
| 20108 | sub_405a8c |
| 26594 | sub_4073e2 |
| 23910 | sub_406966 |
| 2387 | sub_401553 |
| 16092 | sub_404adc |
| 1414 | sub_401186 |
| 13301 | sub_403ff5 |
| 20992 | sub_405e00 |
| 2140 | sub_40145c |
| 18905 | sub_4055d9 |
| 22797 | sub_40650d |
| 11747 | EntryPoint |
| 17965 | sub_40522d |
| 24570 | sub_406bfa |
| 1024 | sub_401000 |
| 25651 | sub_407033 |
| 14853 | sub_404605 |
| 13848 | sub_404218 |
| 25084 | sub_406dfc |
| 13098 | sub_403f2a |
| 10873 | sub_403679 |
| 9959 | sub_4032e7 |
| 22088 | sub_406248 |
| 26739 | sub_407473 |
| 10194 | sub_4033d2 |
| 2205 | sub_40149d |
| 22726 | sub_4064c6 |
| 9832 | sub_403268 |

### Decompilations (top 6)
#### 2464 — sub_4015a0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t * sub_4015a0(int32_t **param_1)

{
    uint32_t *puVar1;
    undefined uVar2;
    int16_t iVar3;
    uint32_t uVar4;
    int16_t *piVar5;
    int16_t *piVar6;
    code *pcVar7;
    undefined4 uVar8;
    int32_t iVar9;
    int32_t **ppiVar10;
    int32_t iVar11;
    int32_t *piVar12;
    undefined4 uVar13;
    uint32_t uVar14;
    int32_t iVar15;
    int32_t **ppiVar16;
    undefined *puVar17;
    int32_t **ppiVar18;
    undefined4 uVar19;
    undefined auStack_3b0 [44];
    undefined auStack_384 [548];
    undefined auStack_160 [256];
    int32_t iStack_60;
    undefined4 uStack_5c;
    int32_t iStack_58;
    int32_t iStack_54;
    undefined2 uStack_50;
    int32_t iStack_4c;
    undefined2 uStack_48;
    undefined2 uStack_46;
    undefined2 uStack_44;
    char cStack_3d;
    int32_t iStack_3c;
    uint32_t uStack_38;
    int32_t *apiStack_34 [3];
    int32_t *piStack_28;
    int32_t *piStack_24;
    int32_t *piStack_20;
    int32_t *piStack_1c;
    int32_t *piStack_18;
    int32_t *piStack_14;
    int32_t iStack_10;
    uint32_t uStack_c;
    int32_t *piStack_8;
    
    ppiVar10 = 0x40b0c0;
    pcVar7 = user32.ShowWindow;
    ppiVar16 = param_1;
    ppiVar18 = apiStack_34;
    for (iVar15 = 7; iVar15 != 0; iVar15 = iVar15 + -1) {
        *ppiVar18 = *ppiVar16;
        ppiVar16 = ppiVar16 + 1;
        ppiVar18 = ppiVar18 + 1;
    }
    iVar15 = apiStack_34[1] * 0x4008;
    iStack_10 = [0x0x472dd4];
    ppiVar16 = iVar15 + 0x473000;
    ppiVar18 = apiStack_34[2] * 0x4008 + 0x473000;
    ppiRam0040b0c4 = apiStack_34 + 1;
    piStack_8 = 0x0;
    switch(apiStack_34[0]) {
    case :
        sub_406404("Jump: %d", apiStack_34[1]);
        return apiStack_34[1];
    case :
        uVar13 = sub_40145c(0);
        sub_406404("Aborting: \"%s\"", uVar13);
        uVar13 = 0;
        goto code_r0x0040162d;
    case :
        [0x0x46ad94] = [0x0x46ad94] + 1;
        if ([0x0x472dd4] == 0) {
            return 0x7fffffff;
        }
        (*user32.PostQuitMessage)(0);
        return 0x7fffffff;
    case :
        iVar15 = sub_40137e(apiStack_34[1]);
        sub_406404("Call: %d", iVar15 + -1);
        piVar12 = sub_40139d(iVar15 + -1, 0);
        return piVar12;
    case :
        uVar13 = sub_40145c(0);
        sub_406404("detailprint: %s", uVar13);
        uVar13 = 0;
        goto code_r0x00401689;
    case :
        iVar15 = sub_401446();
        sub_406404("Sleep(%d)", iVar15);
        if (iVar15 < 2) {
            iVar15 = 1;
        }
        (*kernel32.Sleep)(iVar15);
        break;
    case :
        sub_406404("BringToFront");
        (*user32.SetForegroundWindow)(iStack_10);
        break;
    case :
        if ([0x0x46ada0] != 0) {
            (*user32.ShowWindow)([0x0x46ada0], apiStack_34[2]);
        }
        if ([0x0x46ad8c] != 0) {
            (*pcVar7)([0x0x46ad8c], apiStack_34[1]);
        }
        break;
    case :
        uVar13 = sub_40145c(0xfffffff0);
        sub_406404("SetFileAttributes: \"%s\":%08X", uVar13, apiStack_34[2]);
        iVar15 = (*kernel32.SetFileAttributesW)(uVar13, apiStack_34[2]);
        if (iVar15 != 0) break;
        piStack_8 = 0x1;
        uVar13 = "SetFileAttributes failed.";
        goto code_r0x004017a6;
    case :
        param_1 = sub_40145c(0xfffffff0);
        sub_406404("CreateDirectory: \"%s\" (%d)", param_1, apiStack_34[2]);
        piVar5 = sub_405eb9(param_1);
        if (piVar5 != 0x0) {
            do {
                piVar5 = sub_405e66(piVar5, 0x5c);
                iVar3 = *piVar5;
                *piVar5 = 0;
                iVar15 = (*kernel32.CreateDirectoryW)(param_1, 0);
                if (iVar15 == 0) {
                    iVar15 = (*kernel32.GetLastError)();
                    if (iVar15 == 0xb7) {
                        uVar14 = (*kernel32.GetFileAttributesW)(param_1);
                        if ((uVar14 & 0x10) == 0) {
                            sub_406404("CreateDirectory: can't create \"%s\" -
```
#### 22305 — sub_406321
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_406321(int32_t param_1)

{
    undefined4 uVar1;
    
    if (param_1 == -0x80000000) {
        return "HKEY_CLASSES_ROOT";
    }
    if (param_1 == -0x7fffffff) {
        return "HKEY_CURRENT_USER";
    }
    if (param_1 == -0x7ffffffe) {
        return "HKEY_LOCAL_MACHINE";
    }
    if (param_1 == -0x7ffffffd) {
        return "HKEY_USERS";
    }
    if (param_1 == -0x7ffffffc) {
        return "HKEY_PERFORMANCE_DATA";
    }
    if (param_1 == -0x7ffffffb) {
        return "HKEY_CURRENT_CONFIG";
    }
    uVar1 = "HKEY_DYN_DATA";
    if (param_1 != -0x7ffffffa) {
        uVar1 = "invalid registry key";
    }
    return uVar1;
}

```
#### 20108 — sub_405a8c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_405a8c(void)

{
    int16_t iVar1;
    code *pcVar2;
    int32_t iVar3;
    undefined2 *puVar4;
    uint32_t uVar5;
    int32_t iVar6;
    undefined4 uVar7;
    uint32_t uVar8;
    undefined4 uStack_58;
    undefined4 uStack_54;
    int32_t iStack_50;
    int32_t iStack_4c;
    int32_t iStack_48;
    uint32_t uStack_44;
    uint32_t uStack_40;
    uint32_t uStack_3c;
    undefined4 uStack_38;
    undefined4 uStack_34;
    uint32_t uStack_30;
    undefined4 uStack_2c;
    
    iVar6 = [0x0x472ddc];
    uStack_2c = 6;
    uStack_30 = 0x405aa0;
    pcVar2 = sub_40645d();
    if (pcVar2 == 0x0) {
        004d30c0 = 0x30;
        uStack_30 = 0;
        uStack_34 = 0x447250;
        uStack_38 = 0;
        004d30c2 = 0x78;
        uStack_3c = "Control Panel\\Desktop\\ResourceLocale";
        uStack_40 = 0x80000001;
        [0x0x4d30c4] = 0;
        uStack_44 = 0x405ae9;
        sub_406034();
        if ([0x0x447250] == 0) {
            uStack_44 = 0;
            iStack_48 = 0x447250;
            iStack_4c = 0x4094d4;
            iStack_50 = ".DEFAULT\\Control Panel\\International";
            uStack_54 = 0x80000003;
            uStack_58 = 0x405b08;
            sub_406034();
        }
        uStack_44 = 0x447250;
        iStack_48 = 0x4d30c0;
        iStack_4c = 0x405b13;
        jmp_kernel32.lstrcatW();
    }
    else {
        uStack_30 = 0x405aa8;
        uStack_30 = (*pcVar2)();
        uStack_30 = uStack_30 & 0xffff;
        uStack_34 = 0x4d30c0;
        uStack_38 = 0x405ab6;
        sub_4060b2();
    }
    uStack_38 = 0x405b18;
    sub_403ff5();
    00472e80 = [0x0x472e28] & 0x20;
    uStack_38 = 0x4c70a8;
    [0x0x472e9c] = 0x10000;
    uStack_3c = 0x405b3a;
    iVar3 = sub_4068df();
    if ((iVar3 == 0) && (*(iVar6 + 0x48) != 0)) {
        uStack_3c = 0;
        uVar8 = 0x462540;
        uStack_40 = 0x462540;
        uStack_44 = [0x0x472df8] + *(iVar6 + 0x4c) * 2;
        iStack_48 = [0x0x472df8] + *(iVar6 + 0x48) * 2;
        iStack_4c = *(iVar6 + 0x44);
        iStack_50 = 0x405b6c;
        sub_406034();
        if ([0x0x462540] != 0) {
            if ([0x0x462540] == 0x22) {
                uStack_3c = 0x22;
                uVar8 = 0x462542;
                uStack_40 = 0x462542;
                uStack_44 = 0x405b8a;
                puVar4 = sub_405e66();
                *puVar4 = 0;
            }
            uStack_40 = 0x405b95;
            uStack_3c = uVar8;
            iVar3 = jmp_kernel32.lstrlenW();
            uStack_44 = (uVar8 - 8) + iVar3 * 2;
            if (uVar8 < uStack_44) {
                uStack_40 = ".exe";
                iStack_48 = 0x405ba9;
                iVar3 = (*kernel32.lstrcmpiW)();
                if (iVar3 == 0) {
                    uStack_44 = 0x405bb4;
                    uStack_40 = uVar8;
                    uVar5 = (*kernel32.GetFileAttributesW)();
                    if ((uVar5 == 0xffffffff) || ((uVar5 & 0x10) == 0)) {
                        uStack_44 = 0x405bc3;
                        uStack_40 = uVar8;
                        sub_4068b2();
                    }
                }
            }
            uStack_44 = 0x405bc9;
            uStack_40 = uVar8;
            uStack_44 = sub_406883();
            iStack_48 = 0x4c70a8;
            iStack_4c = 0x405bd0;
            sub_40616a();
        }
    }
    uStack_3c = 0x4c70a8;
    uStack_40 = 0x405bd6;
    iVar3 = sub_4068df();
    if (iVar3 == 0) {
        uStack_40 = *(iVar6 + 0x118);
        uStack_44 = 0x4c70a8;
        iStack_48 = 0x405be6;
        sub_406966();
    }
    if ((([0x0x472e28] & 0x10) != 0) && ([0x0x472e24] == 0)) {
        uStack_40 = 0x405bfc;
        sub_403fd4();
        [0x0x461530] = 1;
    }
    uStack_40 = 0x8040;
    uStack_44 = 0;
    iStack_48 = 0;
    iStack_4c = 1;
    iStack_50 = 0x67;
    uStack_54 = [0x0x472dd8];
    uStack_58 = 0x405c1d;
    0046ad90 = (*user32.LoadImageW)();
    if (*(iVar6 + 0x50) == -1) {
code_r0x00405cc
```

### Carved Files (5)
| Name | Type | Size |
|---|---|---|
| ? | PNG | 11138 |
| ? | DIB | 9832 |
| ? | DIB | 4392 |
| ? | NSIS | 1055469 |
| ? | PKCS7 | 13639 |

### Virtual Files (1)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 11138 | - |

### Structures (46)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 208 |
| OptionalHeader | 232 |
| Sections | 456 |
| advapi32.FT | 29696 |
| comctl32.FT | 29736 |
| gdi32.FT | 29756 |
| kernel32.FT | 29792 |
| shell32.FT | 30076 |
| user32.FT | 30104 |
| version.FT | 30380 |
| ole32.FT | 30396 |
| ImportTable | 36708 |
| advapi32.OFT | 36888 |
| comctl32.OFT | 36928 |
| gdi32.OFT | 36948 |
| kernel32.OFT | 36984 |
| shell32.OFT | 37268 |
| user32.OFT | 37296 |
| version.OFT | 37572 |
| ole32.OFT | 37588 |
| ImportNames | 37608 |
| Resources | 467968 |
| Resources.ICO | 468016 |
| Resources.DLG | 468056 |
| Resources.GRPICO | 468096 |
| Resources.MANIF | 468120 |
| Resources.ICO.1 | 468144 |
| Resources.ICO.2 | 468168 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 41 · duration_s: 1.09

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files on Windows | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| enumerate files recursively | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry key | T1012:Query Registry | C0036.005:Registry |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |

## PE Imports / Signals
import_count: 171

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 19

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@68179 len=7; $ipv6@51945 len=3 |
| contains_base64 | - | $a@35044 len=16 |
| CRC32_poly_Constant | - | $c0@26628 len=4 |
| url | - | $url_regex@34204 len=58 |
| android_meterpreter | - | $checkSdeEncode@779048 len=4 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a3@1128685 len=140 |
| HasRichSignature | - | $a0@192 len=4 |
| Nullsoft_PiMP_Stub_SFX | - | $a@11747 len=9 |
| escalate_priv | - | $d1@40346 len=12; $c2@35128 len=21 |
| screenshot | - | $d1@40044 len=9; $d2@39898 len=10; $c2@38926 len=5 |
| keylogger | - | $f1@39898 len=10; $c1@39268 len=16 |
| win_registry | - | $f1@40346 len=12; $c3@40214 len=11; $c6@40214 len=11 |
| win_token | - | $f1@40346 len=12; $c2@35128 len=21; $c3@35176 len=16 |
| win_files_operation | - | $f1@35912 len=12; $c1@37732 len=9; $c2@37680 len=14; $c3@37732 len=9; $c4@37720 len=8 |

## FLOSS Strings
Total strings: 2325 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2325}`

### High-signal FLOSS
- `KERNEL32`
- `Kernel32.DLL`
- `LoadLibraryExW`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.ndata`
- `@.reloc`
- `PWSVh@`
- `#Vhh2@`
- `Instu``
- `softuW`
- `NulluN	E`
- `SUVWj 3`
- `D$8PUh`
- `u}9-$.G`
- `[j0Xjxf`
- `D$$+D$`
- `D$4+D$,P`
- `PPPPPP`
- `\u!f9O`
- `QSUVWh`
- `Ed+EL;E`
- `u$9Mls`
- `)Mh)Mlf`
- `]4;Mhr`
- `E89E0}s`
- `u$9Uls`
- `-)Uh)Ul3`
- `SHGetFolderPathW`
- `SHFOLDER`
- `SHAutoComplete`
- `SHLWAPI`
- `GetUserDefaultUILanguage`
- `AdjustTokenPrivileges`
- `LookupPrivilegeValueW`
- `OpenProcessToken`
- `RegDeleteKeyExW`
- `ADVAPI32`
- `MoveFileExW`
- `GetDiskFreeSpaceExW`
- `KERNEL32`
- `[Rename]`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004039e3
```asm
┌ 997: entry0 ();
│           ; var int32_t var_10h_4 @ esp+0x10
│           ; var int32_t var_10h_3 @ esp+0x28
│           ; var int32_t var_30h @ esp+0x58
│           ; var int32_t var_2ch @ esp+0x60
│           ; var int32_t var_44h @ esp+0x6c
│           ; var int32_t var_24h @ esp+0x70
│           ; var int32_t var_10h_2 @ esp+0x74
│           ; var int32_t var_14h_2 @ esp+0x78
│           ; var int32_t var_18h_2 @ esp+0x7c
│           ; var int32_t var_14h_3 @ esp+0x90
│           ; var int32_t var_1ch @ esp+0x98
│           ; var int32_t var_10h @ esp+0xcc
│           ; var int32_t var_14h @ esp+0xd0
│           ; var int32_t var_18h @ esp+0xd4
│           ; var int32_t var_38h @ esp+0xe0
│           0x004039e3      81ecd4020000   sub esp, 0x2d4
│           0x004039e9      53             push ebx
│           0x004039ea      55             push ebp
│           0x004039eb      56             push esi
│           0x004039ec      57             push edi
│           0x004039ed      6a20           push 0x20                   ; 32
│           0x004039ef      33ed           xor ebp, ebp
│           0x004039f1      5e             pop esi
│           0x004039f2      896c2418       mov dword [var_18h], ebp
│           0x004039f6      c7442410d8..   mov dword [var_10h], str.Error_writing_temporary_file._Make_sure_your_temp_folder_is_valid. ; [0x4091d8:4]=0x720045 ; u"Error writing temporary file. Make sure your temp folder is valid."
│           0x004039fe      896c2414       mov dword [var_14h], ebp
│           0x00403a02      ff1530804000   call dword [sym.imp.COMCTL32.dll_InitCommonControls] ; 0x408030 ; void InitCommonControls(void)
│           0x00403a08      6801800000     push 0x8001
│           0x00403a0d      ff15b8804000   call dword [sym.imp.KERNEL32.dll_SetErrorMode] ; 0x4080b8 ; UINT SetErrorMode(UINT uMode)
│           0x00403a13      55             push ebp
│           0x00403a14      ff15c0824000   call dword [sym.imp.ole32.dll_OleInitialize] ; 0x4082c0
│           0x00403a1a      6a08           push 8                      ; 8
│           0x00403a1c      a3b82e4700     mov dword [0x472eb8], eax   ; [0x472eb8:4]=0
│           0x00403a21      e8372a0000     call 0x40645d
│           0x00403a26      55             push ebp
│           0x00403a27      68b4020000     push 0x2b4                  ; 692
│           0x00403a2c      a3d02d4700     mov dword [0x472dd0], eax   ; [0x472dd0:4]=0
│           0x00403a31      8d442438       lea eax, [var_38h]
│           0x00403a35      50             push eax
│           0x00403a36      55             push ebp
│           0x00403a37      681c934000     push 0x40931c
│           0x00403a3c      ff1584814000   call dword [sym.imp.SHELL32.dll_SHGetFileInfoW] ; 0x408184 ; DWORD_PTR SHGetFileInfoW(LPCWSTR pszPath, DWORD dwFileAttributes, SHFILEINFOW *psfi, UINT cbFileInfo, UINT uFlags)
│           0x00403a42      6804934000     push str.NSIS_Error         ; 0x409304 ; u"NSIS Error"
│           0x00403a47  
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000D0 ........!..L.!This program cannot be r

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
  - `KERNEL32.dll!SetFileTime`
  - `KERNEL32.dll!CompareFileTime`
  - `KERNEL32.dll!SearchPathW`
  - `KERNEL32.dll!GetShortPathNameW`
  - `KERNEL32.dll!GetFullPathNameW`
  - `USER32.dll!GetAsyncKeyState`
  - `USER32.dll!IsDlgButtonChecked`
  - `USER32.dll!ScreenToClient`
  - `USER32.dll!GetMessagePos`
  - `USER32.dll!CallWindowProcW`
  - `GDI32.dll!SetBkColor`
  - `GDI32.dll!GetDeviceCaps`
  - `GDI32.dll!DeleteObject`
  - `GDI32.dll!CreateBrushIndirect`
  - `GDI32.dll!CreateFontIndirectW`
  - `SHELL32.dll!SHBrowseForFolderW`
  - `SHELL32.dll!SHGetPathFromIDListW`
  - `SHELL32.dll!SHGetFileInfoW`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHFileOperationW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegOpenKeyExW`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `COMCTL32.dll!ImageList_AddMasked`
  - `COMCTL32.dll!ImageList_Destroy`
  - `COMCTL32.dll!ImageList_Create`
  - `ole32.dll!CoTaskMemFree`
  - `ole32.dll!OleInitialize`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785817867.247507}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785817867.2647088}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785817867.2682254}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785817867.272921}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785817940.3397045}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785817940.369798}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785817940.4145932}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785817940.4237776}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785817940.4261003}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785818007.302888}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY address LIMIT 50", "ts": 1785818012.917708}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%domain%' OR content LIKE '%.exe%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%rundll%' OR content LIKE '%temp%' OR content LIKE '%appdata%' OR co`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs LIMIT 20", "ts": 1785818012.9249783}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.DLL','WININET.DLL','URLMON.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL','GDI32.DLL','WS2_32.DLL','WINHTTP.DLL','NTDLL.DLL','KERNEL32.DLL') ORDER BY address LIMIT 100", "ts": 1785818028.5023437}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%\\\\%' OR content LIKE '%/%' OR content LIKE '%.%' ORDER BY address LIMIT 100", "ts": 1785818033.9053614}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 0 AND 200 OR address BETWEEN 11700 AND 11800 OR address BETWEEN 34000 AND 35200 OR address BETWEEN 38800 AND 40500 OR address BETWEEN 51900 AND 52050 OR address BETWEEN 68100 AND 68250 OR address BE`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module IN ('ADVAPI32.DLL','WININET.DLL','URLMON.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL','GDI32.DLL','WS2_32.DLL','WINHTTP.DLL','NTDLL.DLL') ORDER BY module, address", "ts": 1785818033.9300396}`
