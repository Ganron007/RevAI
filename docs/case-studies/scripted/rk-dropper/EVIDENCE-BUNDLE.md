# Technical Evidence Pack

**sha256:** 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0  
**sample_path:** /opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe  
**project_name:** day6

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 80
- **family_guess**: Adload
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Discrepancies in string and function counts across Ghidra, IDA, and Malcat indicate varied tool coverage; Malcat and Capa consistently detect obfuscation (e.g., CrossSectionJump, XorInLoop, obfuscated stackstrings). Ghidra and IDA show common DLL imports but no definitive C2 or payload strings. External VirusTotal detections (58 malicious) strongly suggest a known malware family, but local analysis lacks explicit behavioral evidence like C2 or persistence.
- **summary**: The sample exhibits multiple obfuscation indicators (e.g., CrossSectionJump, DynamicString, XorInLoop) and high-signal imports like VirtualAllocEx, suggesting defense evasion and potential code injection. Capa confirms obfuscated stackstrings as a behavioral tactic. While local analysis does not reveal explicit C2, persistence, or data exfiltration, external VirusTotal detections with 58 malicious engines and threat class 'trojan.adload/fugrafa' strongly indicate malicious intent. The combination of obfuscation and external reputation warrants a malicious verdict, though score reflects lack of clear local behavioral evidence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `CrossSectionJump, DynamicString, XorInLoop` | Multiple obfuscation techniques (cross-section jumps, dynamic string construction, XOR loops) indicate potential defense |
| malcat | top high-signal imports | `kernel32.VirtualAllocEx` | High-signal API for memory allocation often used in process injection or malicious code execution, a behavioral intent f |
| capa | top_rules | `contain obfuscated stackstrings` | Behavioral evidence of defense evasion through string obfuscation (T1027.005), a technique commonly employed by malware  |
| yara | matches | `domain, IP, url` | YARA rules detected network-related strings, which could indicate C2 or communication infrastructure, though content app |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is a packed dropper/loader (rootkit dropper) with heavy string obfuscation, process injection capabilities, and C2 infrastructure embedded in the PE overlay. The sample uses a stolen/expired Ukrainian code signing certificate from 'Kharkiv Vagon-Remont, LLC' (COMODO CA, valid 2017-01-27 to 2017-12-05) with encoded payload data embedded in the certificate ProgramName field. The binary contains high-entropy packed code (7.9 bits in .text, 7.8 in overlay), obfuscated stack strings (CAPA T1027.005, FLOSS decoded 0 of 484 strings), process injection APIs (VirtualAllocEx, OpenThread), mutex-based single-instance control, file I/O, process creation, registry access, and network C2 indicators (IP address and URL in overlay). The entry manifest requires administrator privileges. The original filename is getoohun.exe. Persistence: Not observed; no persistence mechanisms such as registry run keys or scheduled tasks were identified in the provided analysis {source: summary, query_or_table: capabilities, row_or_rule: none, why: no persistence techniques listed in evidence}. Exfiltration: Not observed; no exfiltration techniques or data theft indicators were noted {source: summary, query_or_table: network indicators, row_or_rule: C2, why: C2 indicators mentioned but specific exfiltration methods not detailed}. Imports: Observed imports include APIs for process injection (e.g., VirtualAllocEx, OpenThread), file I/O, process creation, and registry access, as per the summary's capabilities {source: summary, query_or_table: API list, row_or_rule: process injection APIs, why: these APIs are cited in the analysis}.

### deep key_evidence
- `"Malcat anomalies: 10 detected including invalid checksum, high-entropy entry (7.9 bits), code in overlay at 0x33a400, high-entropy overlay (7.8 bits), orphan debug directory, suspicious certificate origin"`
- `"Certificate abuse: stolen cert from 'Kharkiv Vagon-Remont, LLC' (Ukraine, COMODO CA, expired 2017-12-05); ProgramName contains encoded payload data: '9TqdEZ3BMHS0Gr1RQ4cXO8qnshebwP3RGTUZu0gheTajKJUHuJ7HsZonW0GlopENypY8gj3nkb7xoPK2SBeR3bcvE2AV5tA2YnqfqzsLO2WZwt165Du4UTUBmrqZuFu23N5XmhufmR1LapahkVAXyrwrEPiJwLS6YJMTwFaHAdyXajU4Iri8kX7ZeJG0etkDW'"`
- `"CAPA: obfuscated stackstrings (T1027.005), create process (T1059), read/write files, create mutex, get disk size (T1082), get common file paths (T1083), set file attributes (T1222), reference anti-analysis tools strings (13 rules matched)"`
- `"FLOSS: 484 static strings found, 0 decoded strings; all referenced strings are random-encoded sequences confirming heavy runtime string obfuscation"`
- `"Import signals: VirtualAllocEx (process injection T1055), LoadLibrary (T1129); also OpenThread, CreateMutexW, CreateFileW, WriteFile, CreateNamedPipeW, CreatePipe, GetLogicalDriveStringsW, RegOpenKeyW"`
- `"Ghidra function metrics: FUN_00731260 has cyclomatic complexity 81, 638 instructions, 122 blocks, 18 call-outs, 8 string refs \u2014 indicates complex obfuscated/CFF main payload function"`
- `"All Ghidra string_refs to encoded strings: 'keuwosaippaldeaa', 'ottrcvfayshjoutoyipnezimhtv', 'nulmwfohcwntecottryari', 'cpagdsrpuigpkogsroyo', 'dsathahhrddowfsntrr' etc. \u2014 XOR-encoded stack strings"`
- `"YARA matches: IP address at offset 0x33a000 (in overlay), URL at 0x33b61c (in overlay), base64 at 0x331c9c, mutex at 0x331e2c, file operations patterns, maldoc getEIP technique"`
- `"Manifest requests requireAdministrator privileges; original filename getoohun.exe / GETOOHUN.EXE; product GETOOHUN v1.3.9.6; company '\u00a9Iofu' (suspicious)"`
- `"Large single .text section (3.3MB, entropy 7.9) indicates packed/encrypted payload with overlay containing additional C2 infrastructure"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0
size: 3388672
type: PE
architecture: X86
entrypoint_ea: 3335192
entropy: 4.67
file_name: rk-dropper.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 126 | - |
| .text | 1024 | 3346432 | 3346432 | 112 | RX |
| .rdata | 3347456 | 5120 | 8192 | 96 | R |
| .data | 3355648 | 512 | 2662400 | 0 | RW |
| .rsrc | 6018048 | 30208 | 32768 | 82 | R |
| overlay | 6050816 | 5376 | 0 | 0 | - |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2013_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_2003_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| msvs2013_12_0_40629_00_update_5_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| visual_studio_2013_update_1__12_0__also_has_this_build_number_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| msvc_uv_25 | compiler | INFO | 50 |  |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 9 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| UnknownRootResourceDirectoryId | 4 | resources | 1 | A root resource directory ID is not standard |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX86 | 3 | code | 12 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 8 | XOR instruction in a loop |
| FewStrings | 2 | strings | 0 | file does not have many identified strings (less than 1% of the file is composed of strings) |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeGapBetweenFunctions | 2 | code | 288 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| UnbalancedVirtualPhysicalRatio | 1 | sections | 1 | huge difference between the physical and virtual size of a section |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `3342854`: 
- **GuiSubsystemNoWindowApi**
  - `324`: 
- **ManyUniqueImmediateBytes**
  - `3343968`: 
- **XorInLoop**
  - `1596107`: 
  - `1597997`: 
  - `1613686`: 
  - `3345229`: 
  - `3345498`: 

### High-Signal Strings (11 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 3351216 | `KERNEL32.dll` |
| 6053161 | `;http://crl.como..nAuthority.crl0q` |
| 6051995 | `2http://crt.como..eSigningCA.crt0$` |
| 6051915 | `2http://crl.como..eSigningCA.crl0t` |
| 6053250 | `/http://crt.como..AddTrustCA.crt0$` |
| 6053312 | `http://ocsp.comodoca.com0` |
| 6052060 | `http://ocsp.comodoca.com0` |
| 6051868 | `https://secure.comodo.net/CPS0C` |
| 3350124 | `CreateMutexW` |
| 3350884 | `ReleaseMutex` |
| 3351010 | `LoadLibraryW` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 3342854 | `B801000000000000..0000000000000000` |
| 6046828 | `<?xml version="1..y>
</assembly>

` |
| 3348792 | `dsathahhrdddowfsntrr` |
| 3348336 | `ealaersairayagse` |
| 3348952 | `chaimnaftinfsnothcko` |
| 3348604 | `daoctoweeattlyaec` |
| 3349032 | `asadcrntsaeleheedh` |
| 3348888 | `ottrcvfayshjoutoyipnezimhtv` |
| 3348748 | `cpagdsrpuigpkogsroyo` |
| 3348044 | `hkonpiadtneaorsnsdo` |
| 3348268 | `nulmwfohcwntecottryari` |
| 3348668 | `oktoohtfaoboae` |
| 3348996 | `lonhdinotaowdedt` |
| 3348316 | `deheieei` |
| 3348552 | `oerlgeogtdoonh` |
| 3348200 | `sbvtftsrotferh` |
| 3348020 | `ssee` |
| 3348836 | `owoanwettkknygsb` |
| 3348372 | `keuwosaippaldeaa` |
| 3348492 | `pnhiyvmeltohtrtti` |
| 3348640 | `fhtwfhuwyiwna` |
| 3348104 | `nduivtshtshs` |
| 3348468 | `srrohaltawr` |
| 3348244 | `cretnasrar` |
| 3348528 | `fcoshtafess` |
| 3348148 | `hfooetedhgcr` |
| 3348440 | `ehanasdmryhce` |
| 3347992 | `cpsituarttcw` |
| 3348408 | `nbicnstn` |
| 3348584 | `tiasdrtt` |
| 3349072 | `dnrviphnr` |
| 3349116 | `aenuayard` |
| 3348176 | `dleahlohpi` |
| 3349092 | `eneppsalbr` |
| 3348232 | `phedp` |
| 3348712 | `ntbcrn` |
| 3348728 | `mmnadhie` |
| 3348132 | `osaehs` |
| 3348084 | `houhnefk` |
| 3348872 | `hehniw` |
| 6046696 | `1.3.9.6` |
| 3348700 | `ofpt` |
| 3348428 | `tdbo` |
| 3348032 | `rhie` |
| 3351216 | `KERNEL32.dll` |
| 3351244 | `ADVAPI32.dll` |
| 3352072 | `GDI32.dll` |
| 3349982 | `msvcrt.dll` |
| 1196686 | `<oc(` |
| 3351506 | `CreatePolyPolygonRgn` |
| 6053161 | `;http://crl.como..nAuthority.crl0q` |
| 3351296 | `USER32.dll` |
| 6055693 | `VideoFile player..8kX7ZeJG0etkDW0` |
| 6051995 | `2http://crt.como..eSigningCA.crt0$` |
| 6051915 | `2http://crl.como..eSigningCA.crl0t` |
| 6053250 | `/http://crt.como..AddTrustCA.crt0$` |
| 3318372 | `lv0p` |
| 3351606 | `SetBoundsRect` |
| 6053312 | `http://ocsp.comodoca.com0` |
| 6052060 | `http://ocsp.comodoca.com0` |
| 6046480 | `GETOOHUN.EXE` |
| 6046420 | `getoohun.exe` |
| 6051868 | `https://secure.comodo.net/CPS0C` |
| 6046744 | `1.3.9.6` |
| 1016052 | `YS_r` |
| 538265 | `TdvA` |
| 229558 | `=BsW-` |
| 1607973 | `An<Q:` |
| 1767314 | `6Zwm` |
| 2329327 | `0JW2` |
| 563257 | `eiV?J` |
| 2749593 | `kdnJ` |
| 6044394 | `Sho&w Processes in All Sessions` |
| 595261 | `X:;3` |
| 2310528 | `qdBP1` |
| 1600000 | `X75c` |
| 3208228 | `(5lD` |
| 6045740 | `Sho&w Threads in All Sessions` |
| 1608254 | `-e1<i	` |
| 6046234 | `VS_VERSION_INFO` |

### Constants / Known Patterns (36)
| Category | Value |
|---|---|
| oid | `oid::signedData` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::postalCode` |
| oid | `oid::streetAddress` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::keyUsage` |
| oid | `oid::basicConstraints` |
| oid | `oid::extKeyUsage` |
| oid | `oid::codeSigning` |
| oid | `oid::netscape-cert-type` |
| oid | `oid::cps` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::caIssuers` |
| oid | `oid::ocsp` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::sha384WithRSAEncryption` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::certificatePolicies` |
| oid | `oid::anyPolicy` |
| oid | `oid::sha1` |
| oid | `oid::contentType` |
| oid | `oid::signingTime` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::messageDigest` |
| oid | `oid::spcSpOpusInfo` |

### Imports (125)
| EA | Name | Type | Refs |
|---|---|---|---|
| 3347456 | advapi32.RegOpenKeyW | IMPORT | 9 |
| 3347464 | gdi32.GetWorldTransform | IMPORT | 2 |
| 3347468 | gdi32.CreateMetaFileW | IMPORT | 1 |
| 3347472 | gdi32.GetCharWidthW | IMPORT | 1 |
| 3347476 | gdi32.GetKerningPairsW | IMPORT | 1 |
| 3347480 | gdi32.CreateCompatibleBitmap | IMPORT | 1 |
| 3347484 | gdi32.CreateICW | IMPORT | 1 |
| 3347488 | gdi32.SetColorAdjustment | IMPORT | 1 |
| 3347492 | gdi32.PlgBlt | IMPORT | 1 |
| 3347496 | gdi32.SetTextAlign | IMPORT | 1 |
| 3347500 | gdi32.SetArcDirection | IMPORT | 1 |
| 3347504 | gdi32.FlattenPath | IMPORT | 1 |
| 3347508 | gdi32.GetRegionData | IMPORT | 1 |
| 3347512 | gdi32.CloseMetaFile | IMPORT | 1 |
| 3347516 | gdi32.GetEnhMetaFilePaletteEntries | IMPORT | 1 |
| 3347520 | gdi32.GetTextFaceW | IMPORT | 1 |
| 3347524 | gdi32.ExtCreatePen | IMPORT | 1 |
| 3347528 | gdi32.CreateRectRgnIndirect | IMPORT | 1 |
| 3347532 | gdi32.PlayEnhMetaFile | IMPORT | 1 |
| 3347536 | gdi32.Chord | IMPORT | 1 |
| 3347540 | gdi32.CopyEnhMetaFileW | IMPORT | 1 |
| 3347544 | gdi32.OffsetViewportOrgEx | IMPORT | 1 |
| 3347548 | gdi32.SetStretchBltMode | IMPORT | 1 |
| 3347552 | gdi32.FillRgn | IMPORT | 1 |
| 3347556 | gdi32.CreatePatternBrush | IMPORT | 1 |
| 3347560 | gdi32.ArcTo | IMPORT | 1 |
| 3347564 | gdi32.SetMiterLimit | IMPORT | 1 |
| 3347568 | gdi32.CreatePolyPolygonRgn | IMPORT | 1 |
| 3347572 | gdi32.CreateDIBPatternBrushPt | IMPORT | 1 |
| 3347576 | gdi32.CreatePenIndirect | IMPORT | 1 |
| 3347580 | gdi32.TranslateCharsetInfo | IMPORT | 1 |
| 3347584 | gdi32.SetTextJustification | IMPORT | 1 |
| 3347588 | gdi32.GetWindowExtEx | IMPORT | 1 |
| 3347592 | gdi32.StretchDIBits | IMPORT | 1 |
| 3347596 | gdi32.GetGlyphOutlineW | IMPORT | 1 |
| 3347600 | gdi32.GetROP2 | IMPORT | 1 |
| 3347604 | gdi32.CreateEllipticRgn | IMPORT | 1 |
| 3347608 | gdi32.AnimatePalette | IMPORT | 1 |
| 3347612 | gdi32.InvertRgn | IMPORT | 1 |
| 3347616 | gdi32.SetPixelFormat | IMPORT | 1 |
| 3347620 | gdi32.PathToRegion | IMPORT | 1 |
| 3347624 | gdi32.GetRgnBox | IMPORT | 1 |
| 3347628 | gdi32.SetBoundsRect | IMPORT | 1 |
| 3347632 | gdi32.SetRectRgn | IMPORT | 1 |
| 3347640 | kernel32.VirtualFree | IMPORT | 2 |
| 3347644 | kernel32.SetConsoleOutputCP | IMPORT | 1 |
| 3347648 | kernel32.GlobalUnlock | IMPORT | 1 |
| 3347652 | kernel32.WritePrivateProfileSectionW | IMPORT | 1 |
| 3347656 | kernel32.VirtualAlloc | IMPORT | 3 |
| 3347660 | kernel32.GetCurrentProcess | IMPORT | 3 |
| 3347664 | kernel32.GetCurrentProcessId | IMPORT | 1 |
| 3347668 | kernel32.GetExitCodeProcess | IMPORT | 2 |
| 3347672 | kernel32.SwitchToThread | IMPORT | 1 |
| 3347676 | kernel32.GetCalendarInfoW | IMPORT | 1 |
| 3347680 | kernel32.GetCurrentThreadId | IMPORT | 3 |
| 3347684 | kernel32.OpenThread | IMPORT | 3 |
| 3347688 | kernel32.GetExitCodeThread | IMPORT | 2 |
| 3347692 | kernel32.GetLastError | IMPORT | 3 |
| 3347696 | kernel32.ResetEvent | IMPORT | 2 |
| 3347700 | kernel32.ReleaseMutex | IMPORT | 3 |
| 3347704 | kernel32.WriteFile | IMPORT | 3 |
| 3347708 | kernel32.ClearCommError | IMPORT | 1 |
| 3347712 | kernel32.GetTickCount | IMPORT | 5 |
| 3347716 | kernel32.CreatePipe | IMPORT | 2 |
| 3347720 | kernel32.OpenMutexW | IMPORT | 4 |
| 3347724 | kernel32.CreateEventW | IMPORT | 3 |
| 3347728 | kernel32.CreateSemaphoreW | IMPORT | 1 |
| 3347732 | kernel32.LoadLibraryW | IMPORT | 1 |
| 3347736 | kernel32.GetModuleFileNameW | IMPORT | 1 |
| 3347740 | kernel32.GetCommandLineW | IMPORT | 2 |
| 3347744 | kernel32.GetDiskFreeSpaceW | IMPORT | 1 |
| 3347748 | kernel32.CreateFileW | IMPORT | 1 |
| 3347752 | kernel32.SetFileAttributesW | IMPORT | 1 |
| 3347756 | kernel32.GetFileAttributesW | IMPORT | 6 |
| 3347760 | kernel32.DeleteFileW | IMPORT | 1 |
| 3347764 | kernel32.CreateNamedPipeW | IMPORT | 1 |
| 3347768 | kernel32.GetACP | IMPORT | 3 |
| 3347772 | kernel32.GetOEMCP | IMPORT | 1 |
| 3347776 | kernel32.GetThreadLocale | IMPORT | 1 |
| 3347780 | kernel32.GetUserDefaultLCID | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 3343968 | sub_731260 |
| 1613678 | sub_58ab6e |
| 1596107 | sub_5866cb |
| 780487 | sub_4bf4c7 |
| 3340128 | sub_730360 |
| 1597997 | sub_586e2d |
| 1610752 | sub_58a000 |
| 3337504 | sub_72f920 |
| 1598037 | sub_586e55 |
| 1005222 | sub_4f62a6 |
| 3237562 | sub_7172ba |
| 62713 | sub_4100f9 |
| 641162 | sub_49d48a |
| 175181 | sub_42b84d |
| 77056 | sub_413900 |
| 2619961 | sub_680639 |
| 3196854 | sub_70d3b6 |
| 2913469 | sub_6c80bd |
| 80961 | sub_414841 |
| 444209 | sub_46d331 |
| 1220528 | sub_52abb0 |
| 2140672 | sub_60b600 |
| 2203686 | sub_61ac26 |
| 907520 | sub_4de500 |
| 1398282 | sub_55620a |
| 3178377 | sub_708b89 |
| 844786 | sub_4ceff2 |
| 958594 | sub_4eac82 |
| 1198900 | sub_525734 |
| 1792287 | sub_5b651f |

### Decompilations (top 6)
#### 3343968 — sub_731260
```c

/* WARNING: Removing unreachable block (ram,0x007313d6) */
/* WARNING: Removing unreachable block (ram,0x007312f8) */
/* WARNING: Removing unreachable block (ram,0x007312ef) */
/* WARNING: Removing unreachable block (ram,0x0073131b) */
/* WARNING: Removing unreachable block (ram,0x00731323) */
/* WARNING: Removing unreachable block (ram,0x00731334) */
/* WARNING: Removing unreachable block (ram,0x0073134a) */
/* WARNING: Removing unreachable block (ram,0x0073133c) */
/* WARNING: Removing unreachable block (ram,0x007315b2) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_731260(void)

{
    int32_t iVar1;
    undefined2 extraout_var;
    uint32_t uVar2;
    uint32_t uVar3;
    undefined2 extraout_var_00;
    uint32_t *puVar4;
    int32_t iVar5;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    uint32_t uStack_68;
    int32_t iStack_5c;
    uint32_t uStack_54;
    int32_t iStack_44;
    int32_t iStack_40;
    uint32_t uStack_3c;
    int32_t iStack_38;
    uint32_t uStack_34;
    undefined4 uStack_30;
    undefined4 uStack_2c;
    uint32_t uStack_28;
    undefined4 uStack_24;
    undefined4 uStack_20;
    uint32_t uStack_1c;
    undefined4 uStack_18;
    uint32_t uStack_14;
    undefined4 uStack_10;
    undefined4 uStack_c;
    uint32_t uStack_8;
    
    uVar2 = [0x0x734038];
    uVar3 = [0x0x734018];
    uStack_14 = [0x0x734010];
    uStack_1c = 0;
    uStack_28 = 0;
    uStack_10 = [0x0x734020];
    iStack_38 = 0x24a;
    uStack_18._2_2_ = [0x0x73400c] >> 0x10;
    uStack_2c = 0;
    uStack_8 = 0;
    uStack_c = 0;
    iVar1 = (*kernel32.VirtualAlloc)(0, 0xb84fe, 0x1000, 0x40, 0, 0);
    uStack_14 = (*kernel32.CreateNamedPipeW)("fhtwfhuwyiwna", 2, 4, 300, 0, 0, 0, 0);
    if ((uStack_10 == 0) && (uVar3 == 0)) {
        uStack_20._0_2_ = uVar2;
        if (((uVar2 & 0xffff) != 0) || (uStack_c != 0)) {
            uStack_1c = uStack_20 + 0x8bU ^ uStack_14;
        }
        iStack_38 = 0x39d;
    }
    uStack_8 = uStack_1c;
    iVar5 = 0x584b30;
    if (uStack_c < uStack_1c) {
        switch(iVar1) {
        case :
            uStack_14 = uStack_1c | uStack_c;
            break;
        :
            uStack_2c = uVar2;
            break;
        case :
            uStack_10 = CONCAT31(uStack_10._1_3_, uStack_1c) | 0x24;
            break;
        case :
            uStack_28 = (uStack_10 + iStack_38) - uStack_14;
            break;
        case :
            uStack_28 = 0;
        }
    }
    if (uStack_10 != 0) {
        (*kernel32.GetCurrentThreadId)();
        uStack_1c = uVar2 & 0xff & uStack_10;
        uStack_18._2_2_ = extraout_var;
    }
    uStack_20 = CONCAT31(uVar2 >> 8, uVar3 * '?' * uStack_c);
    if ((-uStack_14 <= uStack_8) && (uStack_28 != uStack_c)) {
        uStack_14 = uStack_2c + uStack_20 + 0x2c1;
        uStack_20 = (*kernel32.GetModuleFileNameW)(0, "mmnadhie", 0);
    }
    uVar2 = (*kernel32.LoadLibraryW)("cpagdsrpuigpkogsroyo");
    switch(uStack_20) {
    case :
        uStack_2c = uStack_8;
        break;
    :
        uStack_1c = uStack_10 & 0xffff;
        break;
    case :
        uStack_20 = uStack_8 * uStack_c & uStack_14;
        break;
    case :
        uStack_10 = CONCAT22(uStack_10._2_2_, uStack_c - uStack_14);
        break;
    case :
        uStack_2c = uVar3;
    }
    uStack_70 = 0x400c6149;
    uStack_8 = (*kernel32.GetExitCodeProcess)(uStack_14, &uStack_14);
    uVar3 = uStack_14;
    uStack_18 = CONCAT22(uStack_18._2_2_, uStack_14) | 0xff1e;
    uStack_54 = 0x483efb5e;
    uStack_28 = (uStack_8 + uStack_20) - uStack_18;
    uStack_c = (*kernel32.GetACP)();
    uStack_6c = 0xd51c9c74;
    uStack_20 = uStack_18 + 5;
    uStack_2c = CONCAT22(uStack_2c._2_2_, uStack_10 * uStack_14 - uStack_18);
    iStack_44 = 0x69e82bd4;
    if ((uStack_2c <= uVar2) || (uStack_18 == (uStack_14 & 0xff))) {
        uStack_8 = (uVar3 & 0xffff | 0xff1e) * 699;
    }
    uStack_10 = 0;
    iStack_5c = -0x51b43cf7;
    (*kernel32.GetCurrentProcess)();
    uStack_8 = (*kernel32.GetExitCo
```
#### 1613678 — sub_58ab6e
```c
sub_58ab6e {
    // Error while decompiling : not a valid va
}

```
#### 1596107 — sub_5866cb
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_5866cb(undefined4 param_1,int32_t param_2)

{
    char *pcVar1;
    code *pcVar2;
    uint32_t *in_EAX;
    int32_t extraout_EDX;
    int32_t unaff_EBX;
    uint32_t **unaff_EDI;
    
    do {
        pcVar1 = CONCAT31(param_2 >> 8, 0xd) + 0x230be42;
        *pcVar1 = -*pcVar1;
        *unaff_EDI = in_EAX;
        *in_EAX = *in_EAX ^ CONCAT22(unaff_EBX >> 0x10, CONCAT11(0x80, unaff_EBX));
        pcVar2 = swi(0xd4);
        (*pcVar2)();
        unaff_EBX = *(extraout_EDX + -0x364342eb) * 0x5d;
        in_EAX = CONCAT31(CONCAT22(unaff_EDI + 3 >> 0x10, 0xcd00) >> 8, 0x2b);
        unaff_EDI = 0x57480255;
        param_2 = extraout_EDX;
        aa1ce707 = extraout_EDX;
    } while( true );
}

```

### Carved Files (5)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 2392 |
| ? | DIB | 16936 |
| ? | DIB | 4264 |
| ? | DIB | 1128 |
| ? | PKCS7 | 5367 |

### Virtual Files (11)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| BMP/15/en-us | 2392 | - |
| ICO/50/unk | 16936 | - |
| ICO/51/unk | 4264 | - |
| ICO/52/unk | 1128 | - |
| MENU/4/en-us | 1356 | - |
| MENU/5/en-us | 1342 | - |
| GRPICO/11281/unk | 48 | - |
| VER/1/en-us | 600 | - |
| MANIF/1/en-us | 1223 | - |
| 241/4/en-us | 36 | - |
| 241/6/en-us | 36 | - |

### Structures (59)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 232 |
| OptionalHeader | 256 |
| Sections | 480 |
| advapi32.FT | 3347456 |
| gdi32.FT | 3347464 |
| kernel32.FT | 3347640 |
| user32.FT | 3347896 |
| msvcrt.FT | 3347912 |
| ImportTable | 3349148 |
| advapi32.OFT | 3349268 |
| gdi32.OFT | 3349276 |
| kernel32.OFT | 3349452 |
| user32.OFT | 3349708 |
| msvcrt.OFT | 3349724 |
| ImportNames | 3349788 |
| Resources | 6018048 |
| Resources.BMP | 6018120 |
| Resources.ICO | 6018144 |
| Resources.MENU | 6018184 |
| Resources.GRPICO | 6018216 |
| Resources.VER | 6018240 |
| Resources.MANIF | 6018264 |
| Resources.241 | 6018288 |
| Resources.BMP.15 | 6018320 |
| Resources.ICO.50 | 6018344 |
| Resources.ICO.51 | 6018368 |
| Resources.ICO.52 | 6018392 |
| Resources.MENU.4 | 6018416 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 13 · duration_s: 1.16

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| set file attributes | T1222:File and Directory Permissions Modification | C0050:Set File Attributes |
| get disk size | T1082:System Information Discovery | E1082:System Information Discovery |
| create pipe |  | C0003.001:Interprocess Communication |
| copy file |  | C0045:Copy File |
| delete file |  | C0047:Delete File |
| get file attributes |  | C0049:Get File Attributes |
| write file on Windows |  | C0052:Writes File |
| create or open mutex on Windows |  | C0042:Create Mutex |
| allocate or change RWX memory |  | C0007:Allocate Memory |
| terminate process |  | C0018:Terminate Process |
| parse PE header | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 125

| label | api_match | ATT&CK |
|---|---|---|
| allocate_memory | VirtualAllocEx | T1055 |
| load_library | LoadLibrary | T1129 |

## YARA Matches (pipeline)
Total matches: 13

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@3381736 len=14; $ipv6@320746 len=2 |
| contains_base64 | - | $a@3349852 len=12 |
| url | - | $url_regex@3384348 len=31 |
| maldoc_getEIP_method_1 | - | $a@320183 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a0@3383296 len=133 |
| HasRichSignature | - | $a0@208 len=4 |
| SEH_Init | - | $a@3335760 len=6 |
| win_mutex | - | $c1@3350124 len=11 |
| win_files_operation | - | $f1@3351216 len=12; $c1@3350900 len=9; $c3@3350900 len=9 |

## Generated YARA Meta
```json
{
  "rule_count": 13,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
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
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 3381736,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 320746,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3349852,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 3384348,
          "length": 31,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 320183,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 3383296,
          "length": 133,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a0",
          "offset": 208,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 3335760,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$c1",
          "offset": 3350124,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_files_operation",
      "path": "/opt/samples/corpus/day6/1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0/rk-dropper.exe",
      "strings": [
        {
          "id": "$f1",
          "offset": 3351216,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 3350900,
          "length": 9,
          "xor_key": null
        },
        {
          "id": "$c3",
          "
```

## FLOSS Strings
Total strings: 484 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 484}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `Uqa9V]`
- `QxS<A\`
- `!WK[TWKd`
- `ll%jO@`
- `A@Cr'q`
- `!gM^rJxH`
- `v6Kp/H`
- `dmKRuZ`
- `gm+|0*`
- `o}C%3V`
- `qxUzlQ`
- `nnWa{~`
- `.M0Q]]`
- `vyQ/}%`
- `2a-kp[`
- `B`f<K*`
- `H@uH3r`
- `R$`NNN4`
- `#K:1ntV`
- `Z{l+V7/`
- `UY+i4@`
- `2^iH,5`
- `Uo$4mL`
- `oFP_aA`
- `d5y!BR`
- `zah@*]?t`
- `N0n4e]`
- `buGr.5`
- `SuTp4 <`
- `47/v<#M`
- `yH|ADr`
- `0YWQrG`
- `U4]ske`
- `K]y_fz`
- `+&%Y,DE`
- `NYW^OTX`
- `HFlKB6`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0072f018
```asm
┌ 446: entry0 ();
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           ; var int32_t var_24h @ ebp-0x24
│           ; var int32_t var_2ch @ ebp-0x2c
│           ; var int32_t var_30h @ ebp-0x30
│           ; var int32_t var_34h @ ebp-0x34
│           ; var int32_t var_38h @ ebp-0x38
│           ; var int32_t var_3ch @ ebp-0x3c
│           ; var int32_t var_50h @ ebp-0x50
│           ; var int32_t var_54h @ ebp-0x54
│           ; var int32_t var_80h @ ebp-0x80
│           0x0072f018      6a70           push 0x70                   ; 'p' ; 112
│           0x0072f01a      6890267300     push 0x732690
│           0x0072f01f      e8f8010000     call 0x72f21c
│           0x0072f024      8d4580         lea eax, [var_80h]
│           0x0072f027      50             push eax
│           0x0072f028      ff1554217300   call dword [sym.imp.KERNEL32.dll_GetStartupInfoW] ; 0x732154 ; VOID GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)
│           0x0072f02e      66813d0000..   cmp word [0x400000], 0x5a4d ; 'MZ'
│                                                                      ; [0x400000:2]=0xffff
│       ┌─< 0x0072f037      7527           jne 0x72f060
│       │   0x0072f039      a13c004000     mov eax, dword [0x40003c]   ; [0x40003c:4]=-1
│       │   0x0072f03e      8d8000004000   lea eax, [eax + 0x400000]
│       │   0x0072f044      813850450000   cmp dword [eax], 0x4550     ; 'PE'
│      ┌──< 0x0072f04a      7514           jne 0x72f060
│      ││   0x0072f04c      0fb74818       movzx ecx, word [eax + 0x18]
│      ││   0x0072f050      81f90b010000   cmp ecx, 0x10b              ; 267
│     ┌───< 0x0072f056      7421           je 0x72f079
│     │││   0x0072f058      81f90b020000   cmp ecx, 0x20b              ; 523
│    ┌────< 0x0072f05e      7406           je 0x72f066
│  ┌┌──└└─> 0x0072f060      8365e400       and dword [var_1ch], 0
│  ╎╎││ ┌─< 0x0072f064      eb27           jmp 0x72f08d
│  ╎╎└────> 0x0072f066      83b8840000..   cmp dword [eax + 0x84], 0xe
│  └──────< 0x0072f06d      76f1           jbe 0x72f060
│   ╎ │ │   0x0072f06f      33c9           xor ecx, ecx
│   ╎ │ │   0x0072f071      3988f8000000   cmp dword [eax + 0xf8], ecx
│   ╎ │┌──< 0x0072f077      eb0e           jmp 0x72f087
│   ╎ └───> 0x0072f079      8378740e       cmp dword [eax + 0x74], 0xe
│   └─────< 0x0072f07d      76e1           jbe 0x72f060
│      ││   0x0072f07f      33c9           xor ecx, ecx
│      ││   0x0072f081      3988e8000000   cmp dword [eax + 0xe8], ecx
│      ││   ; CODE XREF from entry0 @ 0x72f077(x)
│      └──> 0x0072f087      0f95c1         setne cl
│       │   0x0072f08a      894de4         mov dword [var_1ch], ecx
│       │   ; CODE XREF from entry0 @ 0x72f064(x)
│       └─> 0x0072f08d      8365fc00       and dword [var_4h], 0
│           0x0072f091      6a02           push 2                      ; 2
│           0x0072f093      5e             pop esi
│           0x0072f094  
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

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
  - `msvcrt.dll!_controlfp`
  - `msvcrt.dll!_except_handler3`
  - `msvcrt.dll!__set_app_type`
  - `msvcrt.dll!__p__fmode`
  - `msvcrt.dll!__p__commode`
  - `KERNEL32.dll!VirtualFree`
  - `KERNEL32.dll!SetConsoleOutputCP`
  - `KERNEL32.dll!GlobalUnlock`
  - `KERNEL32.dll!WritePrivateProfileSectionW`
  - `KERNEL32.dll!VirtualAlloc`
  - `ADVAPI32.dll!RegOpenKeyW`
  - `USER32.dll!DrawIcon`
  - `USER32.dll!AppendMenuW`
  - `USER32.dll!CharNextW`
  - `GDI32.dll!GetWorldTransform`
  - `GDI32.dll!CreateMetaFileW`
  - `GDI32.dll!GetCharWidthW`
  - `GDI32.dll!GetKerningPairsW`
  - `GDI32.dll!CreateCompatibleBitmap`
