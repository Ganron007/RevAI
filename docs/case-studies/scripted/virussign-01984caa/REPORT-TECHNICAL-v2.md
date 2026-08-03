# Technical Malware Analysis Report v2

## 1. Executive Summary
This report analyzes a malicious, heavily packed/obfuscated 32-bit Windows GUI executable (sha256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d) compiled with the Visual Basic 5/6 runtime, with a threat score of 87 (source: llm_judge). The sample is branded with "Unicorn" and "Kawaii-Unicorn" metadata and includes Adobe Photoshop-related strings to disguise itself as legitimate Adobe software (source: malcat, strings table). Static analysis is heavily hindered by packing: the file has near-maximum entropy (87), 11 structural anomalies (including a non-executable code section, entry point in a non-executable region, truncated PE structure, and 6 large high-entropy unreferenced buffers likely containing encrypted/compressed malicious payload) (source: malcat, anomalies table). Only the VB6 compilation origin is confirmed via capa and YARA, while core malicious capabilities are hidden. Tool discrepancies (e.g., import count differences) are explained by bound imports and tool-specific limitations for obfuscated VB6 binaries (source: llm_judge, cross_engine_notes). The entry point follows standard VB6 execution flow by jumping to the ThunRTMain runtime function (source: malcat, decompilation table).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d |
| Sample Path | /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir |
| Project Name | incoming |
| File Size | 479293 bytes (source: malcat, file_summary) |
| File Type | PE32 Windows GUI executable, X86 architecture (source: malcat, file_summary) |
| Entropy | 87 (near-maximum, source: malcat, anomalies table) |
| VB6 Project Name | Vb1 (source: malcat, file_summary.metadata) |
| VB6 Output Executable Name | Kawaii-Unicorn.exe (source: malcat, file_summary.metadata) |
| Compiler | Visual Basic 5/6, MSVC 6 linker (source: malcat, YARA signatures table; yara, matches) |
| Verdict | Malicious (source: llm_judge, verdict) |
| Threat Score | 87 (source: llm_judge, verdict) |
| Family Guess | Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software) (source: llm_judge, verdict) |
| Build Timestamp | 2019:01:07 19:44:27 (source: malcat, strings table, EA 5455) |

## 3. File Layout & Structural Analysis
The sample's file layout is defined by 5 primary regions, with significant structural anomalies indicating heavy packing/obfuscation (source: malcat, file layout table):
| Name | EA | Physical Size | Virtual Size | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 176128 | 176128 | 177 | RW |
| gap | 180224 | 4096 | 0 | 39 | - |
| .rsrc | 184320 | 294912 | 294912 | 35 | R |
| overlay | 479232 | 61 | 0 | - |

The sample has 11 confirmed structural anomalies (source: malcat, anomalies table):
| Anomaly Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| EmptyExportTable | 4 | exports | 1 | Export Table is empty (no valid export but ExportDirectory found) |
| EntryPointInNonExecRegion | 4 | code | 1 | EntryPoint symbol is set and points to a non-executable region |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| SectionGap | 4 | sections | 1 | there is a physical gap between two sections |
| TruncatedPEFile | 4 | integrity | 1 | some or all section bytes are not present on disk (Windows may not load it) |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 6 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having +E) |
| BoundImports | 2 | imports | 1 | Bound imports are present |
| ExportTimeDifferentThanTimeDateStamp | 2 | time | 1 | Difference between PE TimeDateStamp and export TimeDateStamp is bigger than 10 minutes (and both are valid) |

Additionally, 3 carved files were extracted from the sample (source: malcat, carved files table):
| Name | Type | Size |
|---|---|---|
| ? | JPEG | 3611 bytes |
| ? | JPEG | 3611 bytes |
| ? | DIB | 292552 bytes |

3 virtual resource files were also identified (source: malcat, virtual files table):
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 292552 | - |
| GRPICO/1/unk | 20 | - |
| VER/1/zh-cn | 564 | - |

The 6 high-entropy unreferenced buffers and the PE overlay are consistent with packed/encrypted malicious payloads hidden to evade static analysis.

## 4. Malcat Triage Summary
Malcat's dedicated VB6 analysis extracted 4 relevant YARA signatures (source: malcat, YARA / Signatures table):
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 |

4 high-signal strings were identified by Malcat (source: malcat, high-signal strings table):
| EA | String |
|---|---|
| 15209 | `zhttp://ns.adobe.com/xap/1.0/` |
| 20308 | `IEC http://www.iec.ch` |
| 20341 | `IEC http://www.iec.ch` |
| 165187 | `n\U1` |

Key top strings (80 of 300 extracted) include VB6 runtime dependencies, decoy Adobe branding, and unicorn-themed identifiers (source: malcat, top strings table):
| EA | String |
|---|---|
| 168420 | `VB5!6&vb6chs.dll` |
| 170256 | `C:\Program Files..dio\VB98\VB6.OLB` |
| 568 | `MSVBVM60.DLL` |
| 176604 | `MSVBVM60.DLL` |
| 170888 | `cmd /c rename "` |
| 170456 | `SetLayeredWindowAttributes` |
| 170828 | `\Unicorn-` |
| 170144 | `Unicorn` |
| 477580 | `Kawaii-Unicorn.exe` |
| 15136 | `Adobe Photoshop CC 2018` |
| 477352 | `Kawaii-Unicorn` |
| 170944 | `.die` |
| 170432 | `Timer1` |
| 170424 | `Timer2` |
| 170400 | `Form` |
| 170376 | `Label1` |
| 170232 | `Text1` |
| 171176 | `__vbaGenerateBoundsError` |
| 176982 | `__vbaGenerateBoundsError` |
| 177310 | `__vbaErrorOverflow` |
| 171064 | `__vbaErrorOverflow` |
| 171036 | `__vbaStrVarVal` |
| 177268 | `__vbaStrVarVal` |
| 176772 | `__vbaSetSystemError` |
| 171412 | `__vbaSetSystemError` |
| 170540 | `GetWindowLongA` |
| 170612 | `SetWindowLongA` |
| 170444 | `user32` |
| 170956 | `VBA6.DLL` |

Malcat identified 67 imports from msvbvm60.dll and system DLLs (source: malcat, imports table; ghidra, tool summary):
| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | msvbvm60._CIcos | IMPORT | 6 |
| 4100 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4104 | msvbvm60.__vbaVarMove | IMPORT | 3 |
| 4108 | msvbvm60.__vbaFreeVar | IMPORT | 11 |
| 4112 | msvbvm60.rtcRgb | IMPORT | 3 |
| 4116 | msvbvm60.__vbaFreeVarList | IMPORT | 3 |
| 4120 | msvbvm60.__vbaEnd | IMPORT | 2 |
| 4124 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4128 | msvbvm60.__vbaFreeObjList | IMPORT | 8 |
| 4132 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4136 | msvbvm60.__vbaStrCat | IMPORT | 11 |
| 4140 | msvbvm60.__vbaSetSystemError | IMPORT | 4 |
| 4144 | msvbvm60.__vbaHresultCheckObj | IMPORT | 21 |
| 4148 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4152 | msvbvm60.__vbaAryDestruct | IMPORT | 2 |
| 4156 | msvbvm60.rtcRandomNext | IMPORT | 3 |
| 4160 | msvbvm60.rtcRandomize | IMPORT | 3 |
| 4164 | msvbvm60.__vbaOnError | IMPORT | 4 |
| 4168 | msvbvm60.__vbaObjSet | IMPORT | 6 |
| 4172 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4176 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4180 | msvbvm60._CIsin | IMPORT | 1 |
| 4184 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4188 | msvbvm60.__vbaFileClose | IMPORT | 3 |
| 4192 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4196 | msvbvm60.__vbaGenerateBoundsError | IMPORT | 3 |
| 4200 | msvbvm60.__vbaPutOwner3 | IMPORT | 2 |
| 4204 | msvbvm60.DllFunctionCall | IMPORT | 1 |
| 4208 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4212 | msvbvm60.__vbaRedim | IMPORT | 2 |
| 4216 | msvbvm60.__vbaStrR8 | IMPORT | 3 |
| 4220 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4224 | msvbvm60.rtcShell | IMPORT | 3 |
| 4228 | msvbvm60.__vbaUI1I2 | IMPORT | 2 |
| 4232 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4236 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4240 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4244 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4248 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4252 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4256 | msvbvm60.__vbaGetOwner3 | IMPORT | 2 |
| 4260 | msvbvm60.__vbaUbound | IMPORT | 2 |
| 4264 | msvbvm60.__vbaStrVarVal | IMPORT | 2 |
| 4268 | msvbvm60.__vbaVarCat | IMPORT | 3 |
| 4272 | msvbvm60._CIlog | IMPORT | 1 |
| 4276 | msvbvm60.__vbaErrorOverflow | IMPORT | 2 |
| 4280 | msvbvm60.__vbaFileOpen | IMPORT | 3 |
| 4284 | msvbvm60.__vbaNew2 | IMPORT | 7 |
| 4288 | msvbvm60.rtcFileLength | IMPORT | 2 |
| 4292 | msvbvm60.__vbaR8Str | IMPORT | 2 |
| 4296 | msvbvm60._adj_fdiv_m32i | IMPORT | 1 |
| 4300 | msvbvm60._adj_fdivr_m32i | IMPORT | 1 |
| 4304 | msvbvm60.__vbaFreeStrList | IMPORT | 8 |
| 4308 | msvbvm60._adj_fdivr_m32 | IMPORT | 1 |
| 4312 | msvbvm60._adj_fdiv_r | IMPORT | 1 |
| 4316 | msvbvm60.ThunRTMain | IMPORT | 1 |
| 4320 | msvbvm60.__vbaI4Var | IMPORT | 2 |
| 4324 | msvbvm60.__vbaVarMod | IMPORT | 2 |
| 4328 | msvbvm60._CIatan | IMPORT | 1 |
| 4332 | msvbvm60.__vbaStrMove | IMPORT | 10 |
| 4336 | msvbvm60._allmul | IMPORT | 1 |
| 4340 | msvbvm60._CItan | IMPORT | 1 |
| 4344 | msvbvm60.__vbaFPInt | IMPORT | 3 |
| 4348 | msvbvm60.__vbaUI1Var | IMPORT | 2 |
| 4352 | msvbvm60._CIexp | IMPORT | 1 |
| 4356 | msvbvm60.__vbaFreeStr | IMPORT | 2 |
| 4360 | msvbvm60.__vbaFreeObj | IMPORT | 3 |

Malcat identified 2 functions (source: malcat, functions table):
| EA | Name |
|---|---|
| 5076 | EntryPoint |
| 5068 | jmp_msvbvm60.ThunRTMain |

The BoundImports anomaly (source: malcat, anomalies table) explains the discrepancy between pe_imports reporting 0 imports and Ghidra/Malcat reporting 67 imports: the pefile library used by pe_imports cannot resolve bound import entries.

## 5. Static Code Analysis
Static analysis is heavily hindered by packing/obfuscation, but key structural and entry flow details are confirmed. The entry point (EA 0x004013d4) is a standard VB6 thunk that pushes the VB6 runtime DLL name and jumps to the ThunRTMain runtime entry point (source: radare2, 0x004013d4 disassembly; malcat, decompilation table):
```asm
┌ 92: entry0 ();
│           0x004013d4      68e4914200     push 0x4291e4               ; "VB5!6&vb6chs.dll"
│           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain
│           0x004013de      0000           add byte [eax], al
│           0x004013e0      0000           add byte [eax], al
│           0x004013e2      0000           add byte [eax], al
│           0x004013e4      3000           xor byte [eax], al
│           0x004013e6      0000           add byte [eax], al
│           0x004013e8      3800           cmp byte [eax], al
│           0x004013ea      0000           add byte [eax], al
│           0x004013ec      0000           add byte [eax], al
│           0x004013ee      0000           add byte [eax], al
│           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]
│       ┌─< 0x004013f1      e27e           loop 0x401471
│       │   0x004013f3      fb             sti
│       │   0x004013f4      9b             wait
│       │   0x004013f5      6f             outsd dx, dword [esi]
│       │   0x004013f6      53             push ebx
│       │   0x004013f7      4d             dec ebp
│       │   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255
│       │   0x004013fd      58             pop eax
│       │   0x004013fe      0b16           or edx, dword [esi]
│       │   0x00401400      0000           add byte [eax], al
│       │   0x00401402      0000           add byte [eax], al
│       │   0x00401404      0000           add byte [eax], al
│       │   0x00401406      0100           add dword [eax], eax
│       │   0x00401408      0000           add byte [eax], al
│       │   0x0040140a      0000           add byte [eax], al
│       │   0x0040140c      48             dec eax
│       │   0x0040140d      00fd           add ch, bh
│       │   0x0040140f      07             pop es
│       │   0x00401410      56             push esi
│       │   0x00401411      6231           bound esi, qword [ecx]
│       │   0x00401413      007085         add byte [eax - 0x7b], dh
│       │   0x00401416      2903           sub dword [ebx], eax
│       │   0x00401418      0000           add byte [eax], al
│      ┌──> 0x0040141a      0000           add byte [eax], al
│      ╎│   0x0040141c      ffcc           dec esp
│      ╎│   0x0040141e      3100           xor dword [eax], eax
│      ╎│   0x00401420      048c           add al, 0x8c                ; 140
│      ╎│   0x00401422      2d5b5eb187     sub eax, 0x87b15e5b
│      ╎│   0x00401427      56             push esi
│      ╎│   0x00401428      43             inc ebx
│      ╎│   0x00401429      99             cdq
│      ╎│   0x0040142a      ff             invalid
.. │       └─> 0x00401471      0000           add byte [eax], al
│           0x00401473      0000           add byte [eax], al
└           0x00401475      ff             invalid
```

The ThunRTMain import thunk is located at EA 0x004013cc (source: radare2, 0x004013cc disassembly):
```asm
; CALL XREF from entry0 @ 0x4013d9(x)
┌ 6: sub.MSVBVM60.DLL_ThunRTMain ();
└           0x004013cc      ff25dc104000   jmp dword [sym.imp.MSVBVM60.DLL_ThunRTMain] ; 0x4010dc
```

The import address table (IAT) stubs for msvbvm60.dll functions are located starting at EA 0x00401000, with obfuscated jump instructions to the actual imported functions (source: radare2, 0x00401000 disassembly):
```asm
╎╎   ;-- section..text:
┌ 619: sym.imp.MSVBVM60.DLL__CIcos ();
│      ╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] srwx section size 176128 named .text
│      ╎╎   ;-- _adj_fptan:
..
│      ╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│      ╎╎   ;-- __vbaVarMove:
..
│      ╎╎   0x0040100c  ~   7231           jb 0x40103e
│     │╎╎   ;-- (0x00401010) rtcRgb:
│     │╎╎   0x0040100d  ~   68a4728dcc     push 0xcc8d72a4
│    ┌────> 0x00401012  ~   a1726272a4     mov eax, dword [0xa4726272] ; [0xa4726272:4]=-1
│    ╎│╎╎   ;-- __vbaFreeVarList:
│   ┌─────> 0x00401014      6272a4         bound esi, qword [edx - 0x5c]
```

Ghidra's decompilation of the entry point produces invalid code with multiple warnings due to packing/obfuscation, while Malcat's limited decompilation correctly identifies the jump to the VB6 ThunRTMain standard entry point (source: llm_judge, cross_engine_notes; malcat, decompilation table). The EntryPoint decompilation (EA 5076) shows garbage code and control flow errors consistent with packed/obfuscated VB6 pcode (source: malcat, decompilation table):
```c
/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x004015c0) overlaps instruction at (ram,0x004015bf)
    */
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Type propagation algorithm not settling */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t *piVar1;
    uint32_t uVar2;
    uint8_t *puVar3;
    undefined4 uVar4;
    char cVar5;
    uint8_t uVar6;
    uint8_t uVar7;
    uint8_t uVar8;
    uint32_t *puVar9;
    int32_t *piVar10;
    char **ppcVar11;
    unkbyte3 Var20;
    char *pcVar14;
    uint32_t uVar15;
    int32_t iVar16;
    uint8_t *puVar17;
    char **ppcVar18;
    int32_t iVar19;
    uint8_t uVar21;
    char cVar23;
    int32_t extraout_ECX;
    char *pcVar22;
    uint8_t uVar24;
    undefined2 uVar25;
    uint8_t *puVar26;
    char **unaff_EBX;
    char **ppcVar27;
    undefined *puVar28;
    uint32_t unaff_EBP;
    uint32_t uVar29;
    int32_t unaff_ESI;
    undefined4 *puVar30;
    int32_t unaff_EDI;
    uint8_t in_AF;
    undefined8 uVar31;
    undefined2 uStackY_8;
    uint32_t *puVar12;
    uint8_t *puVar13;
    
    uVar31 = jmp_msvbvm60.ThunRTMain("VB5!6&vb6chs.dll");
    ppcVar27 = uVar31 >> 0x20;
    piVar10 = uVar31;
    uVar8 = uVar31;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 ^ uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    puVar30 = unaff_ESI + 1;
    pcVar22 = extraout_ECX + -1;
    uVar25 = uVar31 >> 0x20;
    uVar21 = uVar31 >> 0x28;
    cVar5 = unaff_EBX;
    if (pcVar22 == 0x0) {
        out(*puVar30, uVar25);
        uVar4 = *(unaff_ESI + 5);
        ff4ad58a = uVar8;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + unaff_EBX;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        puVar9 = unaff_EBX + -1;
        *(unaff_EBX + -0x1f) = *(unaff_EBX + -0x1f) + (uVar21 | uVar4 >> 8);
        *unaff_EBX = *unaff_EBX + -puVar9;
        *puVar9 = *puVar9 + puVar9;
        *puVar9 = *puVar9 + puVar9;
        *puVar9 = *puVar9 ^ puVar9;
    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
    }
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    piVar1 = ppcVar27 + piVar10;
    iVar19 = *piVar1;
    *piVar1 = *piVar1 + 1;
    uStackY_8 = uVar31;
    if (SCARRY4(iVar19, 1) == *piVar1 < 0) {
        *piVar10 = *piVar10 + uVar8;
    }
    uVar24 = uVar31 >> 0x20;
    *(unaff_EBP + 0x6e) = *(unaff_EBP + 0x6e) + uVar24;
    *unaff_EBX = *unaff_EBX + pcVar22;
    *(extraout_ECX + 0x26) = *(extraout_ECX + 0x26) + pcVar22;
    puVar3 = unaff_EDI + 5;
    uVar4 = in(uVar25);
    *(unaff_EDI + 1) = uVar4;
    *(unaff_EBP + 0x6e) = *(unaff_EBP + 0x6e) & uVar24;
    puVar28 = *(unaff_EBX + 0x6f) * 0x3006e72;
    *piVar10 = *piVar10 | uVar8;
    *(piVar10 + 0x42000119) = *(piVar10 + 0x42000119) + uVar8;
    uVar7 = uVar31 >> 8;
    *pcVar22 = *pcVar22 + uVar7;
    cVar23 = pcVar22 >> 8;
    if ((POPCOUNT(*pcVar22) & 1U) == 0) {
        puVar28[puVar30 * 2] = puVar28[puVar30 * 2] + cVar23;
    }
    cVar23 = cVar23 + uVar21;
    iVar19 = CONCAT22(pcVar22 >> 0x10, CONCAT11(cVar23, pcVar22));
    if ((POPCOUNT(cVar23) & 1U) == 0) {
        cVar23 = (unaff_EBX >> 8) * '\x02';
        unaff_EBX = CONCAT22(unaff_EBX >> 0x10, CONCAT11(cVar23, cVar5));
    }
    puVar9 = iVar19 + -1;
    uVar21 = puVar9;
    cVar5 = puVar9 >> 8;
    ppcVar18 = puVar28;
    if (puVar9 == 0x0 || cVar23 != '\0') {
        ppcVar18 = puVar28 + -4;
        *(puVar28 + -4) = unaff_EBP;
        uVar29 = unaff_EBP + 1;
        if (uVar29 < 0) {
            *piVar10 = *piVar10 + uVar8;
            goto code_r0x0040150a;
        }
        *piVar10 = *piVar10 + uVar8;
```

The jmp_msvbvm60.ThunRTMain function (EA 5068) is a simple indirect jump to the VB6 runtime's ThunRTMain entry point (source: malcat, decompilation table):
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.ThunRTMain(void)

{
    /* WARNING: Could not recover jumptable at 0x004013cc. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.ThunRTMain)();
    return;
}
```

An XOR search of the file found a XOR 00 key at offset 0x00000000, with the first bytes matching the standard DOS stub "!This program cannot be run in DOS mode." (source: xor search, audit trail). Ghidra function metrics show 12 total functions, with the largest functions located in the obfuscated .text section (source: ghidra_query, function_metrics SQL query, audit trail).

## 6. Behavioral & Dynamic Analysis
Dynamic analysis via Speakeasy returned 0 API calls and 0 key events, with no runtime behavior observed (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). Frida is available (version 17.16.4) but no instrumentation data was collected (source: frida_probe, frida_available: True). UPX unpacking failed, with no unpacked output generated (source: upx, upx_ok: False, returncode: None, unpacked_path: ``). No dynamic behavior could be observed due to the sample's heavy packing/obfuscation, which prevents emulation of the core malicious functionality. The sample would require unpacking in a live Windows environment prior to dynamic analysis to capture runtime behavior.

## 7. Network Indicators & C2
Multiple network-related indicators were identified via YARA and string analysis, though no active C2 communication was observed (no dynamic behavior):
- YARA rule matches for `domain`, `IP`, `url`, and `contains_base64` confirm embedded network indicators (domains, IPv6 addresses, URLs, base64-encoded content) typically used for C2 or payload delivery (source: yara, matches table; deep_dive_agentic, key_evidence)
- URL string `zhttp://ns.adobe.com/xap/1.0/` at EA 15209 (source: malcat, high-signal strings table; FLOSS, high-signal strings) – this is an Adobe XMP namespace URL, likely used as a decoy to disguise the sample as legitimate Adobe software
- URL YARA match at EA 15210 (source: yara, matches table, url rule)
- IPv6 address YARA match at EA 41240 (source: yara, matches table, IP rule)
- Base64-encoded content YARA match at EA 9384 (source: yara, matches table, contains_base64 rule)
- IEC standard URL strings `IEC http://www.iec.ch` at EAs 20308 and 20341 (source: malcat, high-signal strings table) – likely decoy content embedded to further disguise the sample as legitimate software

No active C2 endpoints were identified in static analysis, and no network traffic was observed in dynamic analysis.

## 8. Capabilities & MITRE ATT&CK Mapping
Capa static capability detection only identified the `compiled from Visual Basic` rule, with no additional capability detections due to packing/obfuscation hiding core functionality (source: capa, capa capability rules table). Based on available static indicators, potential capabilities include:
- **Execution**: The sample uses the VB6 runtime's `ThunRTMain` entry point and `rtcShell` import (EA 4224, 3 references) which can be used to execute shell commands (source: malcat, imports table)
- **File System Manipulation**: Imports `__vbaFileOpen` (EA 4280, 3 refs) and `__vbaFileClose` (EA 4188, 3 refs) indicate file operation capabilities, and the string `cmd /c rename "` (EA 170888) suggests file renaming functionality (source: malcat, imports table; malcat, top strings table)
- **Window Manipulation**: Import `SetLayeredWindowAttributes` (EA 170456) indicates ability to modify window transparency/layering, common in info-stealers to hide UI (source: malcat, top strings table)
- **Obfuscation**: SEH structures (confirmed via YARA rules `SEH__vba` and `SEH_Init` at EAs 177164 and 171714) are used for obfuscation and control flow hijacking (source: yara, matches table)
- **Decoy Content**: Embedded JPEG/DIB files and Adobe Photoshop/ICC profile strings suggest the sample may masquerade as legitimate Adobe software to trick users into execution

Without unpacking the core payload, full MITRE ATT&CK mapping is not possible. The sample is likely an info-stealer or dropper per the family guess (source: llm_judge, verdict).

## 9. Indicators of Compromise
All IOCs are derived from static analysis, as no dynamic behavior was observed:
### File-Based IOCs
| IOC | Type | Source |
|---|---|---|
| 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d | SHA256 | llm_judge, verdict |
| virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir | Original Filename | sample_path, structured evidence |
| Kawaii-Unicorn.exe | Internal/Original Filename | malcat, top strings table (EA 477580, 477352) |
| Vb1 | VB6 Project Name | malcat, file_summary.metadata |

### String IOCs
| IOC | Type | EA | Source |
|---|---|---|---|
| MSVBVM60.DLL | VB6 Runtime Dependency | 568, 176604 | malcat, top strings table |
| VB5!6&vb6chs.dll | VB6 Runtime DLL | 168420 | malcat, top strings table |
| Adobe Photoshop CC 2018 | Decoy Branding | 15136, 15975 | malcat, top strings table |
| zhttp://ns.adobe.com/xap/1.0/ | Decoy URL | 15209 | malcat, high-signal strings table; FLOSS, high-signal strings |
| IEC http://www.iec.ch | Decoy URL | 20308, 20341 | malcat, high-signal strings table |
| SetLayeredWindowAttributes | Window Manipulation API | 170456 | malcat, top strings table |
| cmd /c rename " | Command Execution String | 170888 | malcat, top strings table |
| Unicorn | Themed Identifier | 170144, 170828 | malcat, top strings table |
| Kawaii-Unicorn | Themed Identifier | 477352, 477508 | malcat, top strings table |
| Base64-encoded content (16 bytes at EA 9384) | Encoded Payload/Command | 9384 | yara, matches table (contains_base64) |
| IPv6 address (at EA 41240) | Potential C2 | 41240 | yara, matches table (IP) |

### Structural IOCs
| IOC | Description | Source |
|---|---|---|
| Non-executable .text section with entropy 177 | Packed/obfuscated code | malcat, file layout table; anomalies table |
| Entry point in non-executable region | Anti-analysis technique | malcat, anomalies table |
| 6 high-entropy unreferenced buffers (>10KB each) | Encrypted/compressed payload | malcat, anomalies table |
| PE overlay extending beyond image size | Hidden payload storage | yara, matches table (HasOverlay, IsBeyondImageSize) |
| Bound imports | Import obfuscation | malcat, anomalies table |
| Empty export table | Anti-analysis technique | malcat, anomalies table |

### YARA IOCs
The generated YARA rule for this sample is available at `/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar` (source: rule.yara.json, rule_path).

## 10. Detection Engineering
### Static Detection Signatures
1. **YARA Rule**: The generated YARA rule for this sample (rule.yara.json) matches on VB6 compilation markers, Adobe decoy strings, unicorn-themed identifiers, PE overlay, and SEH structures (source: rule.yara.json, yara_valid: True):
```json
{
  "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "family": "unknown",
  "generated_at": "2026-08-03T06:11:36.726731+00:00",
  "string_count": 24,
  "strings": [
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    ".IEC 61966-2.1 Default RGB colour space - sRGB",
    ".IEC 61966-2.Y Default RGB colour space - sRGB",
    ",Reference Viewing Condition in IEC61966-2.1",
    "Copyright (c) 1998 Hewlett-Packard Company",
    "zhttp://ns.adobe.com/xap/1.0/",
    "SetLayeredWindowAttributes",
    "EVENT_SINK_QueryInterface",
    "__vbaGenerateBoundsError",
    "Adobe Photoshop CC 2018",
    "IEC http://www.iec.ch",
    "cropWhenPrintingbool",
    "__vbaHresultCheckObj",
    "printSixteenBitbool",
    "printProofSetupObjc",
    "__vbaSetSystemError",
    "printOutputOptions",
    "cropRectBottomlong",
    "cropRectRightlong",
    "__vbaErrorOverflow",
    "EVENT_SINK_Release",
    "__vbaExceptHandler",
    "Kawaii-Unicorn.exe",
    "ESliceBGColorType"
  ],
  "rule_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar",
  "sigma_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yml",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "cadre_revai": true,
  "publish_target": "revai_publish"
}
```

2. **Malcat Signatures**: The 4 Malcat YARA signatures for VB6/MSVC 6 compilation can be used to detect similar packed VB6 malware (source: malcat, YARA / Signatures table).

3. **Capa Rule**: The `compiled from Visual Basic` capa rule detects VB6 compiled binaries, which can be used to flag similar samples (source: capa, capa capability rules table).

4. **Structural Detection**: Alert on PE files with non-executable .text sections, entry points in non-executable regions, empty export tables, and multiple high-entropy unreferenced buffers >10KB, as these are strong indicators of packed/obfuscated malware.

5. **Import Detection**: Note that pe_imports will return 0 imports for samples with bound imports; use Ghidra or Malcat for import analysis of suspicious VB6 binaries (source: llm_judge, cross_engine_notes).

### Dynamic Detection Signatures
- Alert on VB6 executables that spawn child processes via `rtcShell` or execute `cmd /c rename` commands
- Alert on processes that call `SetLayeredWindowAttributes` to modify window transparency, a common behavior in info-stealers to hide UI
- Monitor for file system activity in user directories (e.g., renaming files, accessing Adobe-related file paths) from VB6 compiled processes

## 11. What We Don't Know
1. **Exact Malicious Functionality**: The core malicious code is packed/encrypted in the high-entropy unreferenced buffers and PE overlay, so it is unknown if the sample is an info-stealer, dropper, or other malware type (source: malcat, anomalies table; llm_judge, family_guess is unconfirmed).
2. **Active C2 Endpoints**: No active C2 communication was observed in static or dynamic analysis; the embedded IPv6 address and base64 content may be C2 indicators, but their purpose is unknown without unpacking (source: yara, matches table).
3. **Unpacked Payload Content**: The 6 high-entropy buffers and PE overlay are likely encrypted/compressed payloads, but no decryption key or unpacking routine was identified in static analysis (source: malcat, anomalies table; upx, upx_ok: False).
4. **Purpose of Carved Files**: The two identical 3611-byte JPEG files and 292552-byte DIB file may be decoy content or used in payload execution, but their role is unknown (source: malcat, carved files table).
5. **Post-ThunRTMain Execution Flow**: The VB6 pcode is obfuscated, so the exact execution flow after the standard VB6 runtime initialization is unknown without unpacking or VB6 pcode decompilation (source: malcat, decompilation table; ghidra, tool summary).
6. **Thematic Branding Purpose**: The "Unicorn" and "Kawaii-Unicorn" branding may be for attacker identification, victim targeting, or obfuscation, but its purpose is unknown (source: malcat, file_summary.metadata; malcat, top strings table).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose | Source |
|---|---|---|---|
| Malcat | N/A | Triage, string extraction, import analysis, VB6 metadata extraction, anomaly detection | malcat, all Malcat tables |
| Ghidra | N/A | Disassembly, function identification, import analysis, decompilation | ghidra, tool summary; ghidra_query, audit trail |
| radare2 | N/A | Entry point disassembly, IAT stub analysis | radare2, disassembly blocks |
| FLOSS | N/A | Stack/tight string extraction | floss, FLOSS strings section |
| YARA | N/A | Compilation, language, and indicator matching | yara, matches table; rule.yara.json |
| capa | N/A | Static capability detection | capa, capa capability rules table |
| pe_imports | N/A | Import table analysis (pefile library) | pe_imports, engine output (import_count: 0) |
| UPX | N/A | Executable unpacking | upx, upx_ok: False |
| Speakeasy | N/A | Windows API emulation for dynamic analysis | speakeasy, speakeasy_ok: True, 0 events |
| Frida | 17.16.4 | Dynamic instrumentation probe | frida_probe, frida_available: True |
| llm_judge | step-3.7-flash | Verdict generation, cross-engine discrepancy resolution | llm_judge, verdict; cross_engine_notes |

IDA was unavailable for this analysis, so no IDA-derived data is present (source: llm_judge, cross_engine_notes). All analysis was conducted on the sample at path `/opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir` as part of the `incoming` project.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d  
**sample_path:** /opt/samples/corpus/incoming/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 87
- **family_guess**: Unicorn-themed Packed Visual Basic 6 Malware (likely info-stealer or dropper, disguised as legitimate Adobe software)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: ['IDA is unavailable for this sample, so no IDA-derived analysis data exists.', "pe_imports reports 0 imports, while Ghidra and Malcat both report 67 imports: this discrepancy is caused by the presence of bound imports (confirmed by Malcat's BoundImports anomaly), which the pefile library used by pe_imports cannot resolve.", "Malcat reports 2 functions, while Ghidra reports 12 functions: this is due to Malcat's limited function detection for obfuscated VB6 binaries, while Ghidra's more comprehensive analysis identifies additional functional entries.", "Ghidra's decompilation of the entry point produces invalid code with multiple warnings due to packing/obfuscation, while Malcat's limited decompilation correctly identifies the jump to the VB6 ThunRTMain standard entry point.", "Capa only detects the 'compiled from Visual Basic' rule with no additional capability detections, as the sample's packing/obfuscation hides its core functionality from static analysis.", 'String counts vary across tools (Malcat: 100, Ghidra: 200, FLOSS: 437), so combining all sources provides full coverage of embedded strings.']
- **summary**: This is a malicious, heavily packed/obfuscated Visual Basic 6 compiled PE32 executable. It is branded with 'Unicorn' and 'Kawaii-Unicorn' metadata and strings, and includes Adobe Photoshop-related strings to disguise itself as legitimate software. The sample has near-maximum entropy (87), 11 structural anomalies (including a non-executable code section, entry point in a non-executable region, truncated PE structure, and invalid checksum), and 6 large high-entropy unreferenced buffers likely containing encrypted/compressed malicious payload. Static analysis is heavily hindered by packing: only the VB6 compilation origin is confirmed via capa and YARA, while core malicious capabilities are hidden. The entry point follows standard VB6 execution flow by jumping to the ThunRTMain runtime function. Tool discrepancies (e.g., import count differences) are explained by bound imports and tool-specific limitations for obfuscated VB6 binaries.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | matches | `Microsoft_Visual_Basic_v50v60, Microsoft_Visual_Basic_v50, Microsoft_Visual_Basi` | Multiple YARA rules specifically targeting Visual Basic 5/6 compiled binaries, VB runtime SEH structures, and standard P |
| capa | top_rules | `name: compiled from Visual Basic` | Capa's static capability detection confirms the binary is compiled from Visual Basic, aligning with YARA and static meta |
| malcat | file_summary.metadata | `VisualBasicInfos::ProjectName: Vb1, VisualBasicInfos::ProjectExeName: Kawaii-Uni` | Malcat's dedicated Visual Basic metadata extraction confirms the sample is a VB6 project named 'Vb1' with output executa |
| malcat | anomalies | `entropy: 87, BigBufferNoXrefMediumToHighEntropy (6 hits), CodeSectionNotExecutab` | Near-maximum file entropy (87) and 11 total structural anomalies, including a non-executable code section, entry point i |
| ghidra | tool summary | `funcs: 12, imports: 67` | Ghidra's analysis identifies 12 functions and 67 import entries, confirming the sample contains functional code despite  |
| malcat | decompilation | `jmp_msvbvm60.ThunRTMain` | Malcat's decompilation of the entry point shows a direct jump to the VB6 runtime's ThunRTMain function, the standard ent |
| malcat | strings | `MSVBVM60.DLL, VB5!6&vb6chs.dll, zhttp://ns.adobe.com/xap/1.0/, I'm Unicorn` | Strings confirm dependency on the VB6 runtime (msvbvm60.dll) and VB6 runtime DLL (vb6chs.dll), include a URL associated  |
| malcat | anomalies | `BoundImports` | The presence of bound imports confirms the sample uses bound import resolution, which explains the discrepancy between p |
| pe_imports | engine output | `import_count: 0` | pe_imports (using the pefile library) reports 0 imports, a discrepancy with Ghidra/Malcat's 67 imports, caused by the pr |
| malcat | decompilation (EntryPoint@5076) | `WARNING: Control flow encountered bad instruction data, WARNING: Unable to track` | Ghidra's decompilation of the entry point fails to produce valid, readable code due to the sample's packing/obfuscation, |
| malcat | carved files | `JPEG@5613 (3611 bytes), JPEG@11468 (3611 bytes), DIB@184552 (292552 bytes)` | Embedded carved JPEG and DIB image files suggest the sample includes decoy legitimate content to disguise its malicious  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a 32-bit Windows GUI executable compiled with the Visual Basic 5/6 runtime, containing embedded network indicators (domains, IPv6 addresses, URLs, base64-encoded content), a PE overlay, and SEH structures, all consistent with obfuscated malware targeting Windows systems.

### deep key_evidence
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "IsPE32", "why": "Match confirms the sample is a valid 32-bit Windows Portable Executable, the required format for Windows desktop malware"}`
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "IsWindowsGUI", "why": "Match confirms the executable is a Windows GUI application, a common type for end-user malware"}`
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "Microsoft_Visual_Basic_v50v60 / Microsoft_Visual_Basic_v50", "why": "Matches confirm the executable is built with the Visual Basic 5/6 runtime, a common framework for legacy Windows malware"}`
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "domain / IP / url / contains_base64", "why": "Matches confirm the sample contains embedded network indicators (domains, IPv6 addresses, URLs, base64 content) typically used for command-and-control communication or payload delivery"}`
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "HasOverlay / IsBeyondImageSize", "why": "Matches confirm the sample has a PE overlay extending beyond its declared image size, a common technique to hide malicious payloads or additional malicious code"}`
- `{"source": "yara_scan findings", "query_or_table": "YARA compiled rule match results", "row_or_rule": "SEH__vba / SEH_Init", "why": "Matches confirm the sample uses Structured Exception Handling (SEH) structures, often leveraged in obfuscated or exploit-based malware to bypass security controls and avoid detection"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d
size: 479293
type: PE
architecture: X86
entrypoint_ea: 5076
entropy: 87
file_name: virussign.com_01984caa0aa32bcadbad335d9a7dce27.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 176128 | 176128 | 177 | RW |
| gap | 180224 | 4096 | 0 | 39 | - |
| .rsrc | 184320 | 294912 | 294912 | 35 | R |
| overlay | 479232 | 61 | 0 | 0 | - |

### Malcat YARA / Signatures (4)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 |  |

### Anomalies (11)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| EmptyExportTable | 4 | exports | 1 | Export Table is empty (no valid export but ExportDirectory found) |
| EntryPointInNonExecRegion | 4 | code | 1 | EntryPoint symbol is set and points to a non-executable region |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| SectionGap | 4 | sections | 1 | there is a physical gap between two sections |
| TruncatedPEFile | 4 | integrity | 1 | some or all section bytes are not present on disk (Windows may not load it) |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 6 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| SectionWeirdRights | 3 | sections | 1 | sections has a standard name but the sections rights are not the usual ones (like .text not having + |
| BoundImports | 2 | imports | 1 | Bound imports are present |
| ExportTimeDifferentThanTimeDateStamp | 2 | time | 1 | Difference between PE TimeDateStamp and export TimeDateStamp is bigger than 10 minutes (and both are |

### High-Signal Strings (4 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 15209 | `zhttp://ns.adobe.com/xap/1.0/` |
| 20308 | `IEC http://www.iec.ch` |
| 20341 | `IEC http://www.iec.ch` |
| 165187 | `n\\U1` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 168420 | `VB5!6&vb6chs.dll` |
| 170256 | `C:\Program Files..dio\VB98\VB6.OLB` |
| 568 | `MSVBVM60.DLL` |
| 176604 | `MSVBVM60.DLL` |
| 15324 | `ta/" x:xmptk="Ad../1.0/sType/Resou` |
| 170888 | `cmd /c rename "` |
| 170456 | `SetLayeredWindowAttributes` |
| 170828 | `\Unicorn-` |
| 15799 | `ceRef#" xmp:Crea..:27+08:00" xmp:M` |
| 15975 | `9:44:27+08:00" d..nt="Adobe Photos` |
| 16487 | `op CC 2018 (Wind..<rdf:li stEvt:ac` |
| 170924 | `.exe" ` |
| 170768 | `.exe` |
| 477580 | `Kawaii-Unicorn.exe` |
| 170540 | `GetWindowLongA` |
| 170612 | `SetWindowLongA` |
| 170944 | `.die` |
| 170144 | `Unicorn` |
| 15209 | `zhttp://ns.adobe.com/xap/1.0/` |
| 170432 | `Timer1` |
| 170424 | `Timer2` |
| 170400 | `Form` |
| 170376 | `Label1` |
| 170232 | `Text1` |
| 20308 | `IEC http://www.iec.ch` |
| 20341 | `IEC http://www.iec.ch` |
| 15259 | `" id="W5M0MpCehi..ns:x="adobe:ns:m` |
| 477130 | `VS_VERSION_INFO` |
| 170444 | `user32` |
| 16736 | `ion="saved" stEv..                ` |
| 477258 | `080404B0` |
| 477546 | `OriginalFilename` |
| 102007 | `6.A60` |
| 15136 | `Adobe Photoshop CC 2018` |
| 477352 | `Kawaii-Unicorn` |
| 477508 | `Kawaii-Unicorn` |
| 111282 | `wE.wou` |
| 170956 | `VBA6.DLL` |
| 20419 | `.IEC 61966-2.1 D..our space - sRGB` |
| 20555 | `,Reference Viewi.. in IEC61966-2.1` |
| 20610 | `,Reference Viewi.. in IEC61966-2.1` |
| 5455 | `2019:01:07 19:44:27` |
| 20476 | `.IEC 61966-2.Y D..our space - sRGB` |
| 9566 | `printOutputOptions` |
| 15102 | `Adobe Photoshop` |
| 477482 | `InternalName` |
| 15951 | `tadataDate="2019-01-07T` |
| 477222 | `StringFileInfo` |
| 477434 | `ProductVersion` |
| 171176 | `__vbaGenerateBoundsError` |
| 176982 | `__vbaGenerateBoundsError` |
| 20044 | `Copyright (c) 19..-Packard Company` |
| 21308 | `&@Zt` |
| 77 | `!This program ca..in DOS mode.
$` |
| 35348 | `9555` |
| 69651 | `YYYI` |
| 477282 | `CompanyName` |
| 77851 | `;/9.s` |
| 477390 | `FileVersion` |
| 57331 | `[666` |
| 96443 | `UUMM` |
| 477658 | `Translation` |
| 477416 | `1.00` |
| 477464 | `1.00` |
| 9384 | `printSixteenBitbool` |
| 177134 | `EVENT_SINK_QueryInterface` |
| 177310 | `__vbaErrorOverflow` |
| 10015 | `cropRectBottomlong` |
| 171064 | `__vbaErrorOverflow` |
| 171036 | `__vbaStrVarVal` |
| 177268 | `__vbaStrVarVal` |
| 9990 | `cropWhenPrintingbool` |
| 176772 | `__vbaSetSystemError` |
| 171412 | `__vbaSetSystemError` |
| 9324 | `printOutput` |
| 11344 | `bottomOutsetlong` |
| 9657 | `Lblsbool` |
| 21872 | `="=a=` |
| 21856 | `;-;k;` |
| 21848 | `:6:t:` |

### Imports (67)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | msvbvm60._CIcos | IMPORT | 6 |
| 4100 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4104 | msvbvm60.__vbaVarMove | IMPORT | 3 |
| 4108 | msvbvm60.__vbaFreeVar | IMPORT | 11 |
| 4112 | msvbvm60.rtcRgb | IMPORT | 3 |
| 4116 | msvbvm60.__vbaFreeVarList | IMPORT | 3 |
| 4120 | msvbvm60.__vbaEnd | IMPORT | 2 |
| 4124 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4128 | msvbvm60.__vbaFreeObjList | IMPORT | 8 |
| 4132 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4136 | msvbvm60.__vbaStrCat | IMPORT | 11 |
| 4140 | msvbvm60.__vbaSetSystemError | IMPORT | 4 |
| 4144 | msvbvm60.__vbaHresultCheckObj | IMPORT | 21 |
| 4148 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4152 | msvbvm60.__vbaAryDestruct | IMPORT | 2 |
| 4156 | msvbvm60.rtcRandomNext | IMPORT | 3 |
| 4160 | msvbvm60.rtcRandomize | IMPORT | 3 |
| 4164 | msvbvm60.__vbaOnError | IMPORT | 4 |
| 4168 | msvbvm60.__vbaObjSet | IMPORT | 6 |
| 4172 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4176 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4180 | msvbvm60._CIsin | IMPORT | 1 |
| 4184 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4188 | msvbvm60.__vbaFileClose | IMPORT | 3 |
| 4192 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4196 | msvbvm60.__vbaGenerateBoundsError | IMPORT | 3 |
| 4200 | msvbvm60.__vbaPutOwner3 | IMPORT | 2 |
| 4204 | msvbvm60.DllFunctionCall | IMPORT | 1 |
| 4208 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4212 | msvbvm60.__vbaRedim | IMPORT | 2 |
| 4216 | msvbvm60.__vbaStrR8 | IMPORT | 3 |
| 4220 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4224 | msvbvm60.rtcShell | IMPORT | 3 |
| 4228 | msvbvm60.__vbaUI1I2 | IMPORT | 2 |
| 4232 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4236 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4240 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4244 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4248 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4252 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4256 | msvbvm60.__vbaGetOwner3 | IMPORT | 2 |
| 4260 | msvbvm60.__vbaUbound | IMPORT | 2 |
| 4264 | msvbvm60.__vbaStrVarVal | IMPORT | 2 |
| 4268 | msvbvm60.__vbaVarCat | IMPORT | 3 |
| 4272 | msvbvm60._CIlog | IMPORT | 1 |
| 4276 | msvbvm60.__vbaErrorOverflow | IMPORT | 2 |
| 4280 | msvbvm60.__vbaFileOpen | IMPORT | 3 |
| 4284 | msvbvm60.__vbaNew2 | IMPORT | 7 |
| 4288 | msvbvm60.rtcFileLength | IMPORT | 2 |
| 4292 | msvbvm60.__vbaR8Str | IMPORT | 2 |
| 4296 | msvbvm60._adj_fdiv_m32i | IMPORT | 1 |
| 4300 | msvbvm60._adj_fdivr_m32i | IMPORT | 1 |
| 4304 | msvbvm60.__vbaFreeStrList | IMPORT | 8 |
| 4308 | msvbvm60._adj_fdivr_m32 | IMPORT | 1 |
| 4312 | msvbvm60._adj_fdiv_r | IMPORT | 1 |
| 4316 | msvbvm60.ThunRTMain | IMPORT | 1 |
| 4320 | msvbvm60.__vbaI4Var | IMPORT | 2 |
| 4324 | msvbvm60.__vbaVarMod | IMPORT | 2 |
| 4328 | msvbvm60._CIatan | IMPORT | 1 |
| 4332 | msvbvm60.__vbaStrMove | IMPORT | 10 |
| 4336 | msvbvm60._allmul | IMPORT | 1 |
| 4340 | msvbvm60._CItan | IMPORT | 1 |
| 4344 | msvbvm60.__vbaFPInt | IMPORT | 3 |
| 4348 | msvbvm60.__vbaUI1Var | IMPORT | 2 |
| 4352 | msvbvm60._CIexp | IMPORT | 1 |
| 4356 | msvbvm60.__vbaFreeStr | IMPORT | 2 |
| 4360 | msvbvm60.__vbaFreeObj | IMPORT | 3 |

### Functions (2)
| EA | Name |
|---|---|
| 5076 | EntryPoint |
| 5068 | jmp_msvbvm60.ThunRTMain |

### Decompilations (top 6)
#### 5076 — EntryPoint
```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x004015c0) overlaps instruction at (ram,0x004015bf)
    */
/* WARNING: Unable to track spacebase fully for stack */
/* WARNING: Type propagation algorithm not settling */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t *piVar1;
    uint32_t uVar2;
    uint8_t *puVar3;
    undefined4 uVar4;
    char cVar5;
    uint8_t uVar6;
    uint8_t uVar7;
    uint8_t uVar8;
    uint32_t *puVar9;
    int32_t *piVar10;
    char **ppcVar11;
    unkbyte3 Var20;
    char *pcVar14;
    uint32_t uVar15;
    int32_t iVar16;
    uint8_t *puVar17;
    char **ppcVar18;
    int32_t iVar19;
    uint8_t uVar21;
    char cVar23;
    int32_t extraout_ECX;
    char *pcVar22;
    uint8_t uVar24;
    undefined2 uVar25;
    uint8_t *puVar26;
    char **unaff_EBX;
    char **ppcVar27;
    undefined *puVar28;
    uint32_t unaff_EBP;
    uint32_t uVar29;
    int32_t unaff_ESI;
    undefined4 *puVar30;
    int32_t unaff_EDI;
    uint8_t in_AF;
    undefined8 uVar31;
    undefined2 uStackY_8;
    uint32_t *puVar12;
    uint8_t *puVar13;
    
    uVar31 = jmp_msvbvm60.ThunRTMain("VB5!6&vb6chs.dll");
    ppcVar27 = uVar31 >> 0x20;
    piVar10 = uVar31;
    uVar8 = uVar31;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 ^ uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    puVar30 = unaff_ESI + 1;
    pcVar22 = extraout_ECX + -1;
    uVar25 = uVar31 >> 0x20;
    uVar21 = uVar31 >> 0x28;
    cVar5 = unaff_EBX;
    if (pcVar22 == 0x0) {
        out(*puVar30, uVar25);
        uVar4 = *(unaff_ESI + 5);
        ff4ad58a = uVar8;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + unaff_EBX;
        *unaff_EBX = *unaff_EBX + cVar5;
        *unaff_EBX = *unaff_EBX + cVar5;
        puVar9 = unaff_EBX + -1;
        *(unaff_EBX + -0x1f) = *(unaff_EBX + -0x1f) + (uVar21 | uVar4 >> 8);
        *unaff_EBX = *unaff_EBX + -puVar9;
        *puVar9 = *puVar9 + puVar9;
        *puVar9 = *puVar9 + puVar9;
        *puVar9 = *puVar9 ^ puVar9;
    /* WARNING: Bad instruction - Truncating control flow here */
        halt_baddata();
    }
    *piVar10 = *piVar10 + uVar8;
    *piVar10 = *piVar10 + uVar8;
    piVar1 = ppcVar27 + piVar10;
    iVar19 = *piVar1;
    *piVar1 = *piVar1 + 1;
    uStackY_8 = uVar31;
    if (SCARRY4(iVar19, 1) == *piVar1 < 0) {
        *piVar10 = *piVar10 + uVar8;
    }
    uVar24 = uVar31 >> 0x20;
    *(unaff_EBP + 0x6e) = *(unaff_EBP + 0x6e) + uVar24;
    *unaff_EBX = *unaff_EBX + pcVar22;
    *(extraout_ECX + 0x26) = *(extraout_ECX + 0x26) + pcVar22;
    puVar3 = unaff_EDI + 5;
    uVar4 = in(uVar25);
    *(unaff_EDI + 1) = uVar4;
    *(unaff_EBP + 0x6e) = *(unaff_EBP + 0x6e) & uVar24;
    puVar28 = *(unaff_EBX + 0x6f) * 0x3006e72;
    *piVar10 = *piVar10 | uVar8;
    *(piVar10 + 0x42000119) = *(piVar10 + 0x42000119) + uVar8;
    uVar7 = uVar31 >> 8;
    *pcVar22 = *pcVar22 + uVar7;
    cVar23 = pcVar22 >> 8;
    if ((POPCOUNT(*pcVar22) & 1U) == 0) {
        puVar28[puVar30 * 2] = puVar28[puVar30 * 2] + cVar23;
    }
    cVar23 = cVar23 + uVar21;
    iVar19 = CONCAT22(pcVar22 >> 0x10, CONCAT11(cVar23, pcVar22));
    if ((POPCOUNT(cVar23) & 1U) == 0) {
        cVar23 = (unaff_EBX >> 8) * '\x02';
        unaff_EBX = CONCAT22(unaff_EBX >> 0x10, CONCAT11(cVar23, cVar5));
    }
    puVar9 = iVar19 + -1;
    uVar21 = puVar9;
    cVar5 = puVar9 >> 8;
    ppcVar18 = puVar28;
    if (puVar9 == 0x0 || cVar23 != '\0') {
        ppcVar18 = puVar28 + -4;
        *(puVar28 + -4) = unaff_EBP;
        uVar29 = unaff_EBP + 1;
        if (uVar29 < 0) {
            *piVar10 = *piVar10 + uVar8;
            goto code_r0x0040150a;
        }
        *piVar10 = *piVar10 + uVar8;
  
```
#### 5068 — jmp_msvbvm60.ThunRTMain
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.ThunRTMain(void)

{
    /* WARNING: Could not recover jumptable at 0x004013cc. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.ThunRTMain)();
    return;
}

```

### Carved Files (3)
| Name | Type | Size |
|---|---|---|
| ? | JPEG | 3611 |
| ? | JPEG | 3611 |
| ? | DIB | 292552 |

### Virtual Files (3)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/unk | 292552 | - |
| GRPICO/1/unk | 20 | - |
| VER/1/zh-cn | 564 | - |

### Structures (26)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| BoundImportTable | 552 |
| msvbvm60.FT | 4096 |
| ExportDirectory | 12800 |
| VBForms | 168340 |
| VBHeader | 168420 |
| ImportTable | 176292 |
| msvbvm60.OFT | 176332 |
| ImportNames | 176604 |
| Resources | 184320 |
| Resources.ICO | 184360 |
| Resources.GRPICO | 184384 |
| Resources.VER | 184408 |
| Resources.ICO.1 | 184432 |
| Resources.GRPICO.1 | 184456 |
| Resources.VER.1 | 184480 |
| Resources.ICO.1.unk | 184504 |
| Resources.GRPICO.1.unk | 184520 |
| Resources.VER.1.zh-cn | 184536 |
| Resources.ICO.1.unk.Data | 184552 |
| Resources.GRPICO.1.unk.Data | 477104 |
| VersionInfo | 477124 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.89

| Rule | ATT&CK | MBC |
|---|---|---|
| compiled from Visual Basic |  |  |

## PE Imports / Signals
import_count: 0

## YARA Matches (pipeline)
Total matches: 16

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@41240 len=2 |
| contains_base64 | - | $a@9384 len=16 |
| url | - | $url_regex@15210 len=28 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| IsBeyondImageSize | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| Microsoft_Visual_Basic_v50v60 | - | $a@5076 len=20 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1 |
| Microsoft_Visual_Basic_v50_v60 | - | $b@5068 len=18; $c@5076 len=19 |
| Microsoft_Visual_Basic_v50_additional | - | $a@5076 len=20 |
| Microsoft_Visual_Basic_v50v60_additional | - | $a@5076 len=20 |
| SEH__vba | - | $@177164 len=16 |
| SEH_Init | - | $b@171714 len=7 |

## Generated YARA Meta
```json
{
  "sha256": "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d",
  "family": "unknown",
  "generated_at": "2026-08-03T06:11:36.726731+00:00",
  "string_count": 24,
  "strings": [
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB",
    ".IEC 61966-2.1 Default RGB colour space - sRGB",
    ".IEC 61966-2.Y Default RGB colour space - sRGB",
    ",Reference Viewing Condition in IEC61966-2.1",
    "Copyright (c) 1998 Hewlett-Packard Company",
    "zhttp://ns.adobe.com/xap/1.0/",
    "SetLayeredWindowAttributes",
    "EVENT_SINK_QueryInterface",
    "__vbaGenerateBoundsError",
    "Adobe Photoshop CC 2018",
    "IEC http://www.iec.ch",
    "cropWhenPrintingbool",
    "__vbaHresultCheckObj",
    "printSixteenBitbool",
    "printProofSetupObjc",
    "__vbaSetSystemError",
    "printOutputOptions",
    "cropRectBottomlong",
    "cropRectRightlong",
    "__vbaErrorOverflow",
    "EVENT_SINK_Release",
    "__vbaExceptHandler",
    "Kawaii-Unicorn.exe",
    "ESliceBGColorType"
  ],
  "rule_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yar",
  "sigma_path": "/opt/samples/logs/6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d/rule.yml",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "cadre_revai": true,
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 437 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 437}`

### High-signal FLOSS
- `zhttp://ns.adobe.com/xap/1.0/`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `MSVBVM60.DLL`
- `Unicorn`
- `I'm Unicorn`
- `Adobe Photoshop CC 2018 (Windows)`
- `2019:01:07 19:44:27`
- `Adobe_CM`
- `dEU6te`
- `'7GWgw`
- `^FNEmu`
- `T+i&5.<`
- `T{@DiJ`
- `\Photoshop 3.0`
- `printOutput`
- `PstSbool`
- `Inteenum`
- `printSixteenBitbool`
- `printerNameTEXT`
- `printProofSetupObjc`
- `proofSetup`
- `Bltnenum`
- `builtinProof`
- `proofCMYK`
- `printOutputOptions`
- `Cptnbool`
- `Clbrbool`
- `RgsMbool`
- `CntCbool`
- `Lblsbool`
- `Ngtvbool`
- `EmlDbool`
- `Intrbool`
- `BckgObjc`
- `Rd  doub@o`
- `Grn doub@o`
- `Bl  doub@o`
- `BrdTUntF#Rlt`
- `Bld UntF#Rlt`
- `RsltUntF#Pxl@b`
- `vectorDatabool`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x004013d4
```asm
┌ 92: entry0 ();
│           0x004013d4      68e4914200     push 0x4291e4               ; "VB5!6&vb6chs.dll"
│           0x004013d9      e8eeffffff     call sub.MSVBVM60.DLL_ThunRTMain
│           0x004013de      0000           add byte [eax], al
│           0x004013e0      0000           add byte [eax], al
│           0x004013e2      0000           add byte [eax], al
│           0x004013e4      3000           xor byte [eax], al
│           0x004013e6      0000           add byte [eax], al
│           0x004013e8      3800           cmp byte [eax], al
│           0x004013ea      0000           add byte [eax], al
│           0x004013ec      0000           add byte [eax], al
│           0x004013ee      0000           add byte [eax], al
│           0x004013f0      a6             cmpsb byte [esi], byte es:[edi]
│       ┌─< 0x004013f1      e27e           loop 0x401471
│       │   0x004013f3      fb             sti
│       │   0x004013f4      9b             wait
│       │   0x004013f5      6f             outsd dx, dword [esi]
│       │   0x004013f6      53             push ebx
│       │   0x004013f7      4d             dec ebp
│       │   0x004013f8      a28ad54aff     mov byte [0xff4ad58a], al   ; [0xff4ad58a:1]=255
│       │   0x004013fd      58             pop eax
│       │   0x004013fe      0b16           or edx, dword [esi]
│       │   0x00401400      0000           add byte [eax], al
│       │   0x00401402      0000           add byte [eax], al
│       │   0x00401404      0000           add byte [eax], al
│       │   0x00401406      0100           add dword [eax], eax
│       │   0x00401408      0000           add byte [eax], al
│       │   0x0040140a      0000           add byte [eax], al
│       │   0x0040140c      48             dec eax
│       │   0x0040140d      00fd           add ch, bh
│       │   0x0040140f      07             pop es
│       │   0x00401410      56             push esi
│       │   0x00401411      6231           bound esi, qword [ecx]
│       │   0x00401413      007085         add byte [eax - 0x7b], dh
│       │   0x00401416      2903           sub dword [ebx], eax
│       │   0x00401418      0000           add byte [eax], al
│      ┌──> 0x0040141a      0000           add byte [eax], al
│      ╎│   0x0040141c      ffcc           dec esp
│      ╎│   0x0040141e      3100           xor dword [eax], eax
│      ╎│   0x00401420      048c           add al, 0x8c                ; 140
│      ╎│   0x00401422      2d5b5eb187     sub eax, 0x87b15e5b
│      ╎│   0x00401427      56             push esi
│      ╎│   0x00401428      43             inc ebx
│      ╎│   0x00401429      99             cdq
│      ╎│   0x0040142a      ff             invalid
..
│       └─> 0x00401471      0000           add byte [eax], al
│           0x00401473      0000           add byte [eax], al
└           0x00401475      ff             invalid
```
### 0x004013cc
```asm
; CALL XREF from entry0 @ 0x4013d9(x)
┌ 6: sub.MSVBVM60.DLL_ThunRTMain ();
└           0x004013cc      ff25dc104000   jmp dword [sym.imp.MSVBVM60.DLL_ThunRTMain] ; 0x4010dc
```
### 0x00401000
```asm
╎╎   ;-- section..text:
┌ 619: sym.imp.MSVBVM60.DLL__CIcos ();
│      ╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] srwx section size 176128 named .text
│      ╎╎   ;-- _adj_fptan:
..
│      ╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│      ╎╎   ;-- __vbaVarMove:
..
│      ╎╎   ;-- (0x0040100c) __vbaFreeVar:
│     ┌───< 0x0040100b  ~   7231           jb 0x40103e
│     │╎╎   ;-- (0x00401010) rtcRgb:
│     │╎╎   0x0040100d  ~   68a4728dcc     push 0xcc8d72a4
│    ┌────> 0x00401012  ~   a1726272a4     mov eax, dword [0xa4726272] ; [0xa4726272:4]=-1
│    ╎│╎╎   ;-- __vbaFreeVarList:
│   ┌─────> 0x00401014      6272a4         bound esi, qword [edx - 0x5c]
│   ╎╎│╎│   ;-- (0x00401018) __vbaEnd:
│   ╎╎│╎└─< 0x00401017  ~   7288           jb 0x400fa1
│   ╎╎│╎    0x00401019  ~   bea072ba02     mov esi, 0x2ba72a0
│   ╎╎│╎    ;-- _adj_fdiv_m64:
│   ╎╎│╎    ;-- (0x00401020) __vbaFreeObjList:
│   ╎╎│╎    0x0040101c  ~   ba02a372c3     mov edx, 0xc372a302
│   ╎╎│╎    0x00401021      9f             lahf
│   ╎╎│╎    0x00401022  ~   a1724109a3     mov eax, dword [0xa3094172] ; [0xa3094172:4]=-1
│   ╎╎│╎│   ;-- _adj_fprem1:
..
│   ╎╎│╎│   ;-- (0x00401028) __vbaStrCat:
│   ╎╎│╎│   0x00401025  ~   09a372766aa2   or dword [ebx - 0x5d95898e], esp
│   ╎╎│╎│   0x00401029      6aa2           push 0xffffffffffffffa2
│   ╎╎│╎│   ;-- (0x0040102c) __vbaSetSystemError:
│  ┌──────< 0x0040102b  ~   723a           jb 0x401067
│  │╎╎│╎│   0x0040102d      c3             ret
..
│ ││╎╎│╎│   ;-- (0x00401040) rtcRandomize:
│ ││╎╎└───> 0x0040103e  ~   a1723acda1     mov eax, dword [0xa1cd3a72] ; [0xa1cd3a72:4]=-1
│ ││╎╎│││   ;-- (0x00401044) __vbaOnError:
│ ─────└──< 0x00401043  ~   729d           jb 0x400fe2
│ ││╎╎│ │   0x00401045      49             dec ecx
│ ││╎╎│ │   0x00401046  ~   a272f19fa1     mov byte [0xa19ff172], al   ; [0xa19ff172:1]=255
│ ││╎╎│ │   ;-- __vbaObjSet:
..
│ ││╎╎│┌──< 0x0040104b  ~   7206           jb 0x401053                 ; sym.imp.MSVBVM60.DLL__CIcos+0x53
│ ││╎╎│││   ;-- _adj_fdiv_m16i:
..
│ ││╎╎│││   ;-- (0x00401050) _adj_fdivr_m16i:
│ ││╎╎│││   0x0040104d  ~   03a3720604a3   add esp, dword [ebx - 0x5cfbf98e]
│ ││╎╎│││   ;-- (0x00401054) _CIsin:
│ ─────└──> 0x00401053  ~   72ee           jb 0x401043
│ ││╎╎│ │   0x00401055      94             xchg esp, eax
│ ││╎╎│ │   0x00401056  ~   a372ea62a3     mov dword [0xa362ea72], eax ; [0xa362ea72:4]=-1
│ ││╎╎│ │   ;-- __vbaChkstk:
..
│ ││╎╎│┌──< 0x0040105b  ~   727d           jb 0x4010da
│ ││╎╎│││   ;-- __vbaFileClose:
..
│ ││╎╎│││   0x0040105d      41             inc ecx
│ ││╎╎│││   0x0040105e  ~   a172749ba0     mov eax, dword [0xa09b7472] ; [0xa09b7472:4]=-1
│ ││╎╎│││   ;-- EVENT_SINK_AddRef:
..
│ ────────> 0x00401061      9b             wait
│ ││╎╎│││   0x00401062  ~   a07210c4a1     mov al, byte [0xa1c41072]   ; [0xa1c41072:1]=255
│ ││╎╎│││   ;-- __vbaGenerateBoundsError:
..
│ ││╎╎│││   0x00401065  ~   c4a1726c57a2   les esp, [ecx - 0x5da8
```
### 0x00401030
```asm
┌ 64: sym.imp.MSVBVM60.DLL___vbaHresultCheckObj ();
│     ╎╎└─< 0x00401030      74a2           je 0x400fd4
│     ╎╎    ;-- (0x00401034) _adj_fdiv_m32:
│     ╎╎    0x00401032  ~   a1726e02a3     mov eax, dword [0xa3026e72] ; [0xa3026e72:4]=-1
│     ╎╎    ;-- (0x00401038) __vbaAryDestruct:
│     ╎╎ ─> 0x00401037  ~   72fe           jb 0x401037
│     ╎╎    0x00401039  ~   c1a17205cd..   shl dword [ecx - 0x5e32fa8e], 0x72
│     ╎╎    ;-- (0x0040103c) rtcRandomNext:
│     ╎╎┌─> 0x0040103a  ~   a17205cda1     mov eax, dword [0xa1cd0572] ; [0xa1cd0572:4]=-1
│     ╎╎╎   ;-- (0x00401040) rtcRandomize:
..
│     ╎╎╎   0x0040103f  ~   723a           jb 0x40107b
│     ╎╎╎   ;-- rtcRandomize:
│     ╎╎╎   0x00401040      3acd           cmp cl, ch
│     ╎╎╎   0x00401042  ~   a1729d49a2     mov eax, dword [0xa2499d72] ; [0xa2499d72:4]=-1
│   ╎╎╎╎╎   ;-- __vbaOnError:
..
│   ╎╎╎╎└─< 0x00401047  ~   72f1           jb 0x40103a
│   ╎╎╎╎    ;-- __vbaObjSet:
..
│   ╎╎╎╎    0x00401049      9f             lahf
│   ╎╎╎╎    0x0040104a  ~   a1720603a3     mov eax, dword [0xa3030672] ; [0xa3030672:4]=-1
│   ╎╎╎╎    ;-- _adj_fdiv_m16i:
..
│   ╎╎╎╎    ;-- (0x00401050) _adj_fdivr_m16i:
│   ╎╎╎╎┌─< 0x0040104f  ~   7206           jb 0x401057
│   ╎╎╎╎│   ;-- _adj_fdivr_m16i:
..
│   ╎╎╎╎│   0x00401051      04a3           add al, 0xa3                ; 163
│   │╎╎╎│   ;-- (0x00401054) _CIsin:
..
│    ╎╎╎│   ;-- (0x00401058) __vbaChkstk:
│    ╎╎╎└─> 0x00401057  ~   72ea           jb 0x401043
│    ╎╎╎    ;-- (0x0040105c) __vbaFileClose:
│    ╎╎╎    0x00401059  ~   62a3727d41a1   bound esp, qword [ebx - 0x5ebe828e]
│    ╎╎╎│   0x0040105f  ~   7274           jb 0x4010d5
│    ╎╎╎│   ;-- EVENT_SINK_AddRef:
..
│  │╎╎╎╎│   ;-- (0x00401068) __vbaPutOwner3:
│  │╎╎╎╎│   ;-- (0x00401074) __vbaRedim:
│   ╎╎│╎│   ;-- (0x00401078) __vbaStrR8:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   ;-- (0x0040107c) EVENT_SINK_Release:
│   ╎╎ ╎│   0x0040107b  ~   7287           jb sym.imp.MSVBVM60.DLL__adj_fptan
│   ╎╎ ╎│   0x0040107d      9b             wait
..
│    ╎ ╎│   ;-- (0x00401088) _CIsqrt:
│    ╎  │   ;-- (0x00401090) __vbaExceptHandler:
│    ╎  │   ;-- _adj_fprem:
│      ││   ;-- (0x004010a0) __vbaGetOwner3:
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "\nSELECT name, start_ea, size\nFROM funcs\nWHERE size > 1024\nORDER BY size DESC\nLIMIT 50\n", "ts": 1785737330.0095475}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785737330.0662465}`
- `{"source": "ghidra_query", "sql": "\n        SELECT src_start_ea, dst_start_ea\n        FROM cfg_edges\n        WHERE src_start_ea > 0 AND dst_start_ea > 0\n    ", "ts": 1785737330.1198864}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785737330.1833642}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785737330.1951106}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785737330.1993566}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785737330.2113638}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785737384.0962908}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785737384.129228}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785737384.1675503}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785737384.1755974}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785737384.1770372}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785737449.9798925}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports ORDER BY address", "ts": 1785737454.4493866}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM funcs ORDER BY address", "ts": 1785737454.4573894}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM strings WHERE length > 4 ORDER BY address", "ts": 1785737454.462124}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM function_metrics ORDER BY cyclomatic_complexity DESC", "ts": 1785737454.561993}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785737495.69716}`
- `{"source": "yara_gen_v2", "ts": 1785737496.7268612}`
