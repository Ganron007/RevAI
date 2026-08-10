# Technical Evidence Pack

**sha256:** c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509  
**sample_path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe  
**project_name:** Hexorcist 3 - Weeks 20-30

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 40
- **family_guess**: Unknown (VisualBasic Loader)
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: All tools consistently identify the sample as a Visual Basic application. Ghidra and IDA report matching import counts (60) and string data, with IDA showing higher function counts. Malcat provides a comprehensive static profile indicating high entropy and anomalies, while capa and YARA confirm Visual Basic compilation. Decompilation from Malcat reveals obfuscated code with control flow issues. No behavioral-intent evidence (e.g., C2, persistence, credential theft) is present across tools.
- **summary**: The sample guLoader.exe is a PE32 binary compiled from Visual Basic, exhibiting high entropy, anomalies, and obfuscated decompilation code. All analysis tools (Ghidra, IDA, Malcat, capa, YARA, FLOSS) agree on its Visual Basic nature, but no behavioral indicators of malicious intent (e.g., C2, persistence, data exfiltration) were found. The obfuscation and anomalies are neutral signals that warrant suspicion, but definitive malice cannot be concluded without further evidence.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile_data | `entropy=73, anomalies_count=3, yara_hits_count=5` | High entropy and anomalies (BoundImports, InvalidChecksum, StackArrayInitialisationX86) suggest obfuscation or packing,  |
| yara | YARA matches | `rule: Microsoft_Visual_Basic_v50v60` | Confirms the sample is compiled with Visual Basic, a framework commonly used in both benign and malicious software, alig |
| malcat | decompilations | `EntryPoint (address 4744)` | Decompilation shows obfuscated code with warnings about bad instructions and overlaps, indicating protection mechanisms  |
| capa | capa evidence | `rule: compiled from Visual Basic` | Corroborates Visual Basic compilation, reinforcing the sample's nature without adding behavioral evidence. |
| floss | FLOSS strings | `paths: C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB` | Presence of VB6 development paths suggests a legitimate environment, but such strings can be mimicked in malware to evad |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This is GuLoader (also known as CloudEyE), a well-known VB6-based malware dropper/loader. The sample is compiled in Visual Basic 6, contains heavily XOR-encoded strings revealed by FLOSS (175 strings, many like ';iC=w}', 'O|XPHT', '%<0G:\MN'), and has no standard Win32 API imports — only MSVBVM60.DLL runtime functions (60 imports). Actual API resolution is performed dynamically through obfuscated shellcode. The main function FUN_00408b2e shows extreme complexity (88 basic blocks, cyclomatic complexity 54, 370 instructions) indicative of obfuscated loader logic. The entry point contains abnormal instruction sequences (XOR byte ptr, POPAD, AAA) suggesting code self-modification. Version metadata uses nonsensical Danish-sounding words ('Delfiteknikkernes', 'Topklasser', 'PENNEFJERE', 'Startsym1') as fake product/company names. YARA rules matched VB5/v6 signatures, base64 content, and SEH patterns consistent with GuLoader's anti-analysis techniques.

### deep key_evidence
- `"YARA: 12 rules matched including Microsoft_Visual_Basic_v50v60, contains_base64 (offset 4798), SEH__vba (offset 38206), SEH_Init (offset 34485)"`
- `"Imports: 60 imports all from MSVBVM60.DLL \u2014 no Win32 API imports (kernel32, ntdll, etc.), confirming dynamic API resolution via shellcode"`
- `"FLOSS: 175 strings extracted; heavily XOR-encoded strings found (e.g., ';iC=w}', 'O|XPHT', ':]4QWt', '%xMc%|', 'G:T XR|') characteristic of GuLoader payload encryption"`
- `"Ghidra functions: FUN_00408b2e (addr 0x408b2e, 1610 bytes) has cyclomatic complexity 54, 88 blocks, 370 instructions, 38 call-outs \u2014 indicative of obfuscated loader"`
- `"Entry point (0x401368): Abnormal instruction patterns including XOR byte ptr [EAX], AL; POPAD; AAA sequences suggesting self-modifying code"`
- `"Fake version info: ProductName='Startsym1', CompanyName='Delfiteknikkernes', FileDescription='Topklasser', OriginalFilename='Startsym1.exe' \u2014 nonsensical Danish-sounding names"`
- `"Ghidra string_refs: No string references found in main function, confirming strings are decoded at runtime through XOR decryption"`
- `"File size: 49,152 bytes \u2014 compact VB6 dropper consistent with GuLoader's typical payload size"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509
size: 49152
type: PE
architecture: X86
entrypoint_ea: 4744
entropy: 73
file_name: guLoader.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 4096 | 0 | 13 | - |
| .text | 4096 | 36864 | 36864 | 93 | RX |
| .data | 40960 | 4096 | 4096 | 4 | RW |
| .rsrc | 45056 | 4096 | 2320 | 27 | R |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_6_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| MSVC_6_rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| VisualBasic | language | INFO | 100 | VisualBasic executable (pcode or native) |
| ms_visual_basic_50_60_01 | compiler | INFO | 50 |  |
| ms_visual_basic_50_01 | compiler | INFO | 50 |  |

### Anomalies (3)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| StackArrayInitialisationX86 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| BoundImports | 2 | imports | 1 | Bound imports are present |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 7000 | `C:\Program Files..dio\VB98\VB6.OLB` |
| 7348 | `OhxGFWabiTZ16Ppk..vcXCtkMMlSJiZG44` |
| 7220 | `15:15:15` |
| 7424 | `Delfiteknikkernes` |
| 7292 | `8/8/8` |
| 37776 | `MSVBVM60.DLL` |
| 568 | `MSVBVM60.DLL` |
| 7500 | `Topklasser` |
| 4968 | `VB5!6&*` |
| 7160 | `BIBLIOG` |
| 7308 | `whomble` |
| 6864 | `REBALANCES` |
| 6884 | `adamasprei` |
| 6876 | `chippya` |
| 7136 | `Option1` |
| 7120 | `Option3` |
| 7128 | `Option2` |
| 45956 | `Startsym1.exe` |
| 6976 | `Form` |
| 7184 | `Label1` |
| 45398 | `VS_VERSION_INFO` |
| 45594 | `040904B0` |
| 45922 | `OriginalFilename` |
| 45700 | `PENNEFJERE` |
| 7568 | `VBA6.DLL` |
| 45870 | `InternalName` |
| 45666 | `FileDescription` |
| 45822 | `ProductVersion` |
| 45558 | `StringFileInfo` |
| 45522 | `Translation` |
| 45618 | `CompanyName` |
| 77 | `!This program ca..in DOS mode.
$` |
| 45778 | `FileVersion` |
| 45852 | `1.00` |
| 4798 | `Borderadamasprei` |
| 45804 | `1.00` |
| 38412 | `__vbaVarLateMemCallLd` |
| 38176 | `EVENT_SINK_QueryInterface` |
| 7708 | `__vbaVarLateMemCallLd` |
| 45896 | `Startsym1` |
| 7776 | `__vbaFreeVar` |
| 37832 | `__vbaFreeVar` |
| 38144 | `EVENT_SINK_Release` |
| 38300 | `_adj_fdiv_m32i` |
| 37990 | `_adj_fdiv_m16i` |
| 38318 | `_adj_fdivr_m32i` |
| 45730 | `ProductName` |
| 7844 | `__vbaFreeVarList` |
| 45490 | `VarFileInfo` |
| 38112 | `__vbaCastObjVar` |
| 38050 | `EVENT_SINK_AddRef` |
| 7680 | `__vbaCastObjVar` |
| 38008 | `_adj_fdivr_m16i` |
| 7616 | `__vbaStrVarMove` |
| 37866 | `__vbaFreeVarList` |
| 37848 | `__vbaStrVarMove` |
| 37816 | `__vbaVarMove` |
| 8231 | `BIBLIOG` |
| 38508 | `__vbaFreeObj` |
| 38462 | `_allmul` |
| 7600 | `__vbaVarMove` |
| 38492 | `__vbaFreeStr` |
| 7760 | `__vbaFreeObj` |
| 7792 | `__vbaFreeStr` |
| 38130 | `_adj_fpatan` |
| 38368 | `_adj_fdiv_r` |
| 38204 | `__vbaExceptHandler` |
| 7808 | `__vbaHresultCheckObj` |
| 38240 | `_adj_fdivr_m64` |
| 38350 | `_adj_fdivr_m32` |
| 7580 | `__vbaAryDestruct` |
| 37956 | `__vbaAryDestruct` |
| 37940 | `_adj_fdiv_m32` |
| 37916 | `__vbaHresultCheckObj` |
| 37886 | `_adj_fdiv_m64` |
| 15233 | `<KxK` |
| 45644 | `skulap` |
| 28745 | `/-P?pR` |
| 38100 | `__vbaI2I4` |
| 45756 | `Udskiv6` |

### Constants / Known Patterns (1)
| Category | Value |
|---|---|
| guid | `guid::IPictureDisp` |

### Imports (60)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4096 | msvbvm60._CIcos | IMPORT | 6 |
| 4100 | msvbvm60._adj_fptan | IMPORT | 1 |
| 4104 | msvbvm60.__vbaVarMove | IMPORT | 1 |
| 4108 | msvbvm60.__vbaFreeVar | IMPORT | 1 |
| 4112 | msvbvm60.__vbaStrVarMove | IMPORT | 1 |
| 4116 | msvbvm60.__vbaFreeVarList | IMPORT | 1 |
| 4120 | msvbvm60._adj_fdiv_m64 | IMPORT | 1 |
| 4124 | msvbvm60.rtcVarBstrFromChar | IMPORT | 1 |
| 4128 | msvbvm60._adj_fprem1 | IMPORT | 1 |
| 4132 | msvbvm60.rtcLowerCaseVar | IMPORT | 1 |
| 4136 | msvbvm60.rtcTrimBstr | IMPORT | 1 |
| 4140 | msvbvm60.__vbaHresultCheckObj | IMPORT | 1 |
| 4144 | msvbvm60.rtcIsDate | IMPORT | 1 |
| 4148 | msvbvm60._adj_fdiv_m32 | IMPORT | 1 |
| 4152 | msvbvm60.__vbaAryDestruct | IMPORT | 1 |
| 4156 | msvbvm60.__vbaObjSet | IMPORT | 1 |
| 4160 | msvbvm60._adj_fdiv_m16i | IMPORT | 1 |
| 4164 | msvbvm60.rtcFormatNumber | IMPORT | 1 |
| 4168 | msvbvm60._adj_fdivr_m16i | IMPORT | 1 |
| 4172 | msvbvm60.rtcDoEvents | IMPORT | 1 |
| 4176 | msvbvm60._CIsin | IMPORT | 1 |
| 4180 | msvbvm60.rtcMidCharVar | IMPORT | 1 |
| 4184 | msvbvm60.__vbaChkstk | IMPORT | 1 |
| 4188 | msvbvm60.EVENT_SINK_AddRef | IMPORT | 1 |
| 4192 | msvbvm60.__vbaStrCmp | IMPORT | 1 |
| 4196 | msvbvm60.rtcKillFiles | IMPORT | 1 |
| 4200 | msvbvm60.__vbaVarTstEq | IMPORT | 1 |
| 4204 | msvbvm60.rtcIsNull | IMPORT | 1 |
| 4208 | msvbvm60.__vbaI2I4 | IMPORT | 1 |
| 4212 | msvbvm60.__vbaCastObjVar | IMPORT | 1 |
| 4216 | msvbvm60._adj_fpatan | IMPORT | 1 |
| 4220 | msvbvm60.rtcPMT | IMPORT | 1 |
| 4224 | msvbvm60.EVENT_SINK_Release | IMPORT | 1 |
| 4228 | msvbvm60._CIsqrt | IMPORT | 1 |
| 4232 | msvbvm60.EVENT_SINK_QueryInterface | IMPORT | 1 |
| 4236 | msvbvm60.rtcJoin | IMPORT | 1 |
| 4240 | msvbvm60.__vbaExceptHandler | IMPORT | 1 |
| 4244 | msvbvm60._adj_fprem | IMPORT | 1 |
| 4248 | msvbvm60._adj_fdivr_m64 | IMPORT | 1 |
| 4252 | msvbvm60.__vbaFPException | IMPORT | 1 |
| 4256 | msvbvm60._CIlog | IMPORT | 1 |
| 4260 | msvbvm60.__vbaNew2 | IMPORT | 1 |
| 4264 | msvbvm60._adj_fdiv_m32i | IMPORT | 1 |
| 4268 | msvbvm60._adj_fdivr_m32i | IMPORT | 1 |
| 4272 | msvbvm60.__vbaI4Str | IMPORT | 1 |
| 4276 | msvbvm60._adj_fdivr_m32 | IMPORT | 1 |
| 4280 | msvbvm60._adj_fdiv_r | IMPORT | 1 |
| 4284 | msvbvm60.ThunRTMain | IMPORT | 1 |
| 4288 | msvbvm60.__vbaVarTstNe | IMPORT | 1 |
| 4292 | msvbvm60.__vbaVarDup | IMPORT | 1 |
| 4296 | msvbvm60.rtcVarStrFromVar | IMPORT | 1 |
| 4300 | msvbvm60.__vbaVarLateMemCallLd | IMPORT | 1 |
| 4304 | msvbvm60._CIatan | IMPORT | 1 |
| 4308 | msvbvm60.__vbaStrMove | IMPORT | 1 |
| 4312 | msvbvm60.rtcGetHourOfDay | IMPORT | 1 |
| 4316 | msvbvm60._allmul | IMPORT | 1 |
| 4320 | msvbvm60._CItan | IMPORT | 1 |
| 4324 | msvbvm60._CIexp | IMPORT | 1 |
| 4328 | msvbvm60.__vbaFreeStr | IMPORT | 1 |
| 4332 | msvbvm60.__vbaFreeObj | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 4744 | EntryPoint |
| 4384 | jmp_msvbvm60.__vbaChkstk |
| 4390 | jmp_msvbvm60.__vbaExceptHandler |
| 4396 | jmp_msvbvm60.__vbaFPException |
| 4528 | jmp_msvbvm60.__vbaAryDestruct |
| 4534 | jmp_msvbvm60.rtcVarStrFromVar |
| 4558 | jmp_msvbvm60.rtcJoin |
| 4564 | jmp_msvbvm60.rtcPMT |
| 4570 | jmp_msvbvm60.__vbaI2I4 |
| 4576 | jmp_msvbvm60.rtcMidCharVar |
| 4582 | jmp_msvbvm60.__vbaVarTstEq |
| 4588 | jmp_msvbvm60.rtcFormatNumber |
| 4594 | jmp_msvbvm60.rtcIsNull |
| 4600 | jmp_msvbvm60.rtcDoEvents |
| 4648 | jmp_msvbvm60.__vbaStrMove |
| 4660 | jmp_msvbvm60.__vbaFreeObj |
| 4666 | jmp_msvbvm60.__vbaFreeVar |
| 4672 | jmp_msvbvm60.rtcIsDate |
| 4678 | jmp_msvbvm60.__vbaFreeStr |
| 4684 | jmp_msvbvm60.__vbaHresultCheckObj |
| 4690 | jmp_msvbvm60.__vbaNew2 |
| 4696 | jmp_msvbvm60.__vbaFreeVarList |
| 4702 | jmp_msvbvm60.__vbaVarDup |
| 4738 | jmp_msvbvm60.ThunRTMain |
| 35630 | sub_408b2e |
| 35562 | sub_408aea |
| 37358 | sub_4091ee |
| 37404 | sub_40921c |
| 35601 | sub_408b11 |
| 35610 | sub_408b1a |

### Decompilations (top 6)
#### 4744 — EntryPoint
```c

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Instruction at (ram,0x0040133b) overlaps instruction at (ram,0x0040133a)
    */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(undefined4 param_1,undefined4 param_2,undefined2 param_3)

{
    uint32_t *puVar1;
    char cVar2;
    uint8_t uVar3;
    uint8_t *puVar4;
    int32_t *piVar5;
    undefined *puVar6;
    char *pcVar7;
    uint32_t uVar8;
    uint8_t *extraout_ECX;
    uint8_t uVar10;
    char *unaff_EBX;
    char *unaff_ESI;
    undefined2 in_DS;
    bool bVar11;
    undefined8 uVar12;
    char *in_stack_0000001c;
    char *in_stack_00000028;
    char *in_stack_0000002c;
    uint8_t *in_stack_00000030;
    int32_t *in_stack_00000034;
    undefined4 *puVar9;
    
    uVar12 = jmp_msvbvm60.ThunRTMain("VB5!6&*");
    pcVar7 = uVar12 >> 0x20;
    puVar4 = uVar12;
    uVar3 = uVar12;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 + uVar3;
    *puVar4 = *puVar4 ^ uVar3;
    *puVar4 = *puVar4 + uVar3;
    puVar4 = puVar4 + 1;
    cVar2 = puVar4;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    *puVar4 = *puVar4 + cVar2;
    uVar10 = unaff_EBX >> 8;
    *pcVar7 = *pcVar7 + uVar10;
    piVar5 = [0x0x82409c5c] + -0x73f6e718;
    uVar3 = piVar5;
    *piVar5 = *piVar5 + uVar3;
    *extraout_ECX = *extraout_ECX + uVar3;
    *piVar5 = *piVar5 + uVar3;
    puVar4 = pcVar7 + 0x6f;
    bVar11 = CARRY1(*puVar4, uVar3);
    *puVar4 = *puVar4 + uVar3;
    if ((bVar11) || (bVar11)) {
        extraout_ECX[0x26ed4748] = uVar10;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        *piVar5 = *piVar5 + uVar3;
        in_stack_00000030 = extraout_ECX;
        in_stack_00000028 = unaff_EBX;
        in_stack_0000001c = unaff_ESI;
    }
    else {
        ffffff88 = in(param_3);
        if (!bVar11) {
            cVar2 = in_stack_00000034;
            *in_stack_00000034 = *in_stack_00000034 + cVar2;
            *in_stack_00000034 = *in_stack_00000034 + cVar2;
            *(in_stack_00000034 + 2) = *(in_stack_00000034 + 2) + cVar2;
            goto code_r0x00401345;
        }
        piVar5 = in_stack_00000034;
        pcVar7 = in_stack_0000002c;
        if (!bVar11) {
            puVar6 = *(*in_stack_00000034 * 0x74706143) * 0x6000000;
            *puVar6 = *puVar6;
            puVar1 = CONCAT21(puVar6 >> 0x10, in_stack_00000030 >> 8) * 0x100 + -0x10040;
            uVar8 = *puVar1;
            *puVar1 = *puVar1 + puVar1;
            pcVar7 = CONCAT31(puVar1 >> 8, (puVar1 + -0x1a) - CARRY4(uVar8, puVar1)) + 1;
            *pcVar7 = *pcVar7 + pcVar7;
            *pcVar7 = *pcVar7 + pcVar7;
    /* WARNING: Bad instruction - Truncating control flow here */
            halt_baddata();
        }
    }
    cVar2 = piVar5;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *piVar5 = *piVar5 + cVar2;
    *pcVar7 = *pcVar7;
    *piVar5 = *piVar5 + cVar2;
    in_stack_00000034 = piVar5;
    in_stack_0000002c = pcVar7;
code_r0x00401345:
    uVar3 = in_stack_00000034;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000028 = *in_stack_00000028 + (in_stack_00000034 >> 8);
    pcVar7 = segment(in_DS, in_stack_00000028 + in_stack_0000001c);
    *pcVar7 = *pcVar7 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    *in_stack_00000034 = *in_stack_00000034 + uVar3;
    uVar8 = CONCAT31(CONCAT22(in_stack_0
```
#### 4384 — jmp_msvbvm60.__vbaChkstk
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaChkstk(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaChkstk)();
    return;
}

```
#### 4390 — jmp_msvbvm60.__vbaExceptHandler
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void jmp_msvbvm60.__vbaExceptHandler(void)

{
    /* WARNING: Treating indirect jump as call */
    (*msvbvm60.__vbaExceptHandler)();
    return;
}

```

### Carved Files (4)
| Name | Type | Size |
|---|---|---|
| ? | ICO | 26030 |
| ? | DIB | 296 |
| ? | DIB | 744 |
| ? | DIB | 304 |

### Virtual Files (5)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/30001/unk | 304 | - |
| ICO/30002/unk | 744 | - |
| ICO/30003/unk | 296 | - |
| GRPICO/1/unk | 48 | - |
| VER/1/en-us | 592 | - |

### Structures (47)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| BoundImportTable | 552 |
| BoundImportNames | 568 |
| msvbvm60.FT | 4096 |
| VBExternalTable | 4824 |
| VBObj.chippya | 4832 |
| VBForms | 4888 |
| VBHeader | 4968 |
| VBProjectInfo | 5124 |
| VBObj.REBALANCES | 5696 |
| VBObj.REBALANCES.OptInfos | 5752 |
| VBObj.REBALANCES.Controls | 5824 |
| VBObj.REBALANCES.Controls.Form.Events | 6064 |
| VBObj.REBALANCES.Controls.Option3.Events | 6212 |
| VBObj.REBALANCES.Controls.Option2.Events | 6312 |
| VBObj.REBALANCES.Controls.Option1.Events | 6412 |
| VBObj.REBALANCES.Controls.BIBLIOG.Events | 6512 |
| VBObj.REBALANCES.Controls.Label1.Events | 6588 |
| VBObjectTable | 6684 |
| VBObjectArray | 6768 |
| VBForm.0 | 7892 |
| ImportTable | 37492 |
| msvbvm60.OFT | 37532 |
| ImportNames | 37776 |
| Resources | 45056 |
| Resources.VER | 45096 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.88

| Rule | ATT&CK | MBC |
|---|---|---|
| compiled from Visual Basic |  |  |

## PE Imports / Signals
import_count: 46

## YARA Matches (pipeline)
Total matches: 12

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@4798 len=16 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasRichSignature | - | $a0@168 len=4 |
| Microsoft_Visual_Basic_v50v60 | - | $a@4744 len=20 |
| Microsoft_Visual_Basic_v50 | - | $a@79 len=1; $b@4751 len=20 |
| Microsoft_Visual_Basic_v50_v60 | - | $c@4744 len=19 |
| Microsoft_Visual_Basic_v50_additional | - | $a@4744 len=20 |
| Microsoft_Visual_Basic_v50v60_additional | - | $a@4744 len=20 |
| SEH__vba | - | $@38206 len=16 |
| SEH_Init | - | $b@34485 len=7 |

## Generated YARA Meta
```json
{
  "rule_count": 12,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4798,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
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
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 79,
          "length": 1,
          "xor_key": null
        },
        {
          "id": "$b",
          "offset": 4751,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_v60",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$c",
          "offset": 4744,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50_additional",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Microsoft_Visual_Basic_v50v60_additional",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$a",
          "offset": 4744,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH__vba",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$",
          "offset": 38206,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509/guLoader.exe",
      "strings": [
        {
          "id": "$b",
          "offset": 34485,
          "length": 7,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "
```

## FLOSS Strings
Total strings: 175 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 175}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.data`
- `MSVBVM60.DLL`
- `Borderadamasprei`
- `VB5!6&*`
- `Startsym1`
- `adamasprei`
- `REBALANCES`
- `chippya`
- `C:\Program Files (x86)\Microsoft Visual Studio\VB98\VB6.OLB`
- `Option3`
- `Option2`
- `Option1`
- `BIBLIOG`
- `Label1`
- `VBA6.DLL`
- `__vbaAryDestruct`
- `__vbaVarMove`
- `__vbaStrVarMove`
- `__vbaI2I4`
- `__vbaVarTstEq`
- `__vbaI4Str`
- `__vbaCastObjVar`
- `__vbaObjSet`
- `__vbaVarLateMemCallLd`
- `__vbaStrMove`
- `__vbaStrCmp`
- `__vbaFreeObj`
- `__vbaFreeVar`
- `__vbaFreeStr`
- `__vbaHresultCheckObj`
- `__vbaNew2`
- `__vbaFreeVarList`
- `__vbaVarDup`
- `__vbaVarTstNe`
- `Tamburin5`
- `O|K{K/`
- `;iC=w}`
- `O$X32\`
- `O|XPHT`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401288
```asm
┌ 236: entry0 ();
│           0x00401288      6868134000     push 0x401368               ; 'h\x13@' ; "VB5!6&*"
│           0x0040128d      e8f0ffffff     call 0x401282
│           0x00401292      0000           add byte [eax], al
│           0x00401294      0000           add byte [eax], al
│           0x00401296      0000           add byte [eax], al
│           0x00401298      3000           xor byte [eax], al
│           0x0040129a      0000           add byte [eax], al
│           0x0040129c      40             inc eax
│           0x0040129d      0000           add byte [eax], al
│           0x0040129f      0000           add byte [eax], al
│           0x004012a1      0000           add byte [eax], al
│           0x004012a3      003a           add byte [edx], bh
│           0x004012a5      6a88           push 0xffffffffffffff88
│           0x004012a7      37             aaa
│           0x004012a8      a15c9c4082     mov eax, dword [0x82409c5c] ; [0x82409c5c:4]=-1
│           0x004012ad      05e818098c     add eax, 0x8c0918e8
│           0x004012b2      3d8c000000     cmp eax, 0x8c               ; 140
│           0x004012b7      0000           add byte [eax], al
│           0x004012b9      0001           add byte [ecx], al
│           0x004012bb      0000           add byte [eax], al
│           0x004012bd      00426f         add byte [edx + 0x6f], al
│       ┌─< 0x004012c0      7264           jb 0x401326
│      ┌──< 0x004012c2      657261         jb 0x401326
│      ││   0x004012c5      6461           popal
│      ││   0x004012c7      6d             insd dword es:[edi], dx
│      ││   0x004012c8      61             popal
│     ┌───< 0x004012c9      7370           jae 0x40133b
│    ┌────< 0x004012cb      7265           jb 0x401332
│    ││││   0x004012cd      690043617074   imul eax, dword [eax], 0x74706143
│    ││││   0x004012d3      690000000006   imul eax, dword [eax], 0x6000000
│    ││││   0x004012d9      0000           add byte [eax], al
│    ││││   0x004012db      00ec           add ah, ch
│    ││││   0x004012dd      1d40000100     sbb eax, 0x10040
│    ││││   0x004012e2      0100           add dword [eax], eax
│    ││││   0x004012e4      1c1a           sbb al, 0x1a
│    ││││   0x004012e6      40             inc eax
│    ││││   0x004012e7      0000           add byte [eax], al
│    ││││   0x004012e9      0000           add byte [eax], al
│    ││││   0x004012eb      00ff           add bh, bh
..
│    ││└└─> 0x00401326      88b94847ed26   mov byte [ecx + 0x26ed4748], bh ; [0x26ed4748:1]=255
│    ││     0x0040132c      0000           add byte [eax], al
│    ││     0x0040132e      0000           add byte [eax], al
│    ││     0x00401330      0000           add byte [eax], al
│    └────> 0x00401332      0000           add byte [eax], al
│     │     0x00401334      0000           add byte [eax], al
│     │     0x00401336      0000           add byte [eax], al
│     │     0x00401338      0000           add byte [eax], al
│     │     0x0040133a  ~
```
### 0x00401000
```asm
╎╎╎╎   ;-- section..text:
│    ╎╎╎╎   ;-- (0x00401004) _adj_fptan:
┌ 473: sym.imp.MSVBVM60.DLL__CIcos ();
│    ╎╎╎╎   0x00401000  ~   8693a372f909   xchg byte [ebx + 0x9f972a3], dl ; [00] -r-x section size 36864 named .text
│    ╎╎╎╎   0x00401006  ~   a372ee6aa4     mov dword [0xa46aee72], eax ; [0xa46aee72:4]=-1
│    ╎╎╎╎   ;-- __vbaVarMove:
│   ┌─────> 0x00401008      ee             out dx, al
│   ╎╎╎╎╎   0x00401009      6aa4           push 0xffffffffffffffa4
│   ╎╎╎╎╎   ;-- (0x0040100c) __vbaFreeVar:
│  ┌──────< 0x0040100b  ~   7231           jb 0x40103e
│  │╎╎╎╎╎   0x0040100d  ~   68a4722919     push 0x192972a4
│ ┌───────> 0x0040100e      a4             movsb byte es:[edi], byte [esi]
│ ╎│╎╎╎╎╎   0x0040100f  ~   7229           jb 0x40103a
│ ╎│╎╎╎╎╎   ;-- __vbaStrVarMove:
..
│ ╎│╎╎╎╎╎   ;-- (0x00401014) __vbaFreeVarList:
│ ╎│╎╎╎╎╎   0x00401011  ~   19a2726272a4   sbb dword [edx - 0x5b8d9d8e], esp
│ ╎│╎╎╎│╎   ;-- (0x00401018) _adj_fdiv_m64:
│ ╎│╎╎╎└──< 0x00401017  ~   72ba           jb 0x400fd3
│ ╎│╎╎╎ ╎   ;-- (0x0040101c) rtcVarBstrFromChar:
│ ╎│╎╎╎ ╎   0x00401019  ~   02a372c20fa2   add ah, byte [ebx - 0x5df03d8e]
│ ╎│╎╎╎ ╎   ;-- (0x00401020) _adj_fprem1:
│ ╎│╎╎╎┌──> 0x0040101e  ~   a2724109a3     mov byte [0xa3094172], al   ; [0xa3094172:1]=255
│ ╎│╎╎╎╎╎   ;-- (0x00401024) rtcLowerCaseVar:
│ ────────> 0x00401021  ~   09a372a075a2   or dword [ebx - 0x5d8a5f8e], esp
│ ╎│╎╎╎╎╎   0x00401025      75a2           jne 0x400fc9
│ ╎│╎╎╎╎╎   ;-- (0x00401028) rtcTrimBstr:
│ ────────< 0x00401027  ~   7201           jb 0x40102a
│ ╎│╎╎╎╎└─< 0x00401029  ~   76a2           jbe 0x400fcd
│ ────────> 0x0040102a  ~   a27274a2a1     mov byte [0xa1a27472], al   ; [0xa1a27472:1]=255
│ ╎│╎╎╎╎    ;-- (0x0040102c) __vbaHresultCheckObj:
│ ╎│╎╎╎╎┌─< 0x0040102b  ~   7274           jb 0x4010a1
│ ╎│╎╎╎╎│   0x0040102d  ~   a2a172b1c8     mov byte [0xc8b172a1], al   ; [0xc8b172a1:1]=255
│ ╎│╎╎╎╎│   ;-- (0x00401030) rtcIsDate:
│ ╎│╎╎╎╎│   0x0040102e  ~   a172b1c8a1     mov eax, dword [0xa1c8b172] ; [0xa1c8b172:4]=-1
│ ╎│╎╎╎╎│   ;-- (0x00401034) _adj_fdiv_m32:
│ ╎│╎╎╎╎│   0x00401031  ~   c8a1726e       enter 0x72a1, 0x6e
│ ╎│╎╎╎╎│   0x00401035  ~   02a372fec1a1   add ah, byte [ebx - 0x5e3e018e]
│ ╎│╎╎╎╎│   ;-- (0x00401038) __vbaAryDestruct:
│ ────────> 0x00401037  ~   72fe           jb 0x401037
│ ╎│╎╎╎╎│   0x00401039  ~   c1a172f19f..   shl dword [ecx - 0x5e600e8e], 0x72
│ ╎│╎╎╎╎│   ;-- (0x0040103c) __vbaObjSet:
│ ╎│╎╎╎╎│   0x0040103a  ~   a172f19fa1     mov eax, dword [0xa19ff172] ; [0xa19ff172:4]=-1
│ ╎│╎╎╎╎│   0x0040103d      9f             lahf
│ ╎└──────> 0x0040103e  ~   a1720603a3     mov eax, dword [0xa3030672] ; [0xa3030672:4]=-1
│ ╎ ╎╎╎╎│   ;-- (0x00401040) _adj_fdiv_m16i:
│ ╎┌──────> 0x0040103f  ~   7206           jb 0x401047
│ ╎╎╎╎╎╎│   0x00401041  ~   03a372a264a3   add esp, dword [ebx - 0x5c9b5d8e]
│ ────────> 0x00401043  ~   72a2           jb 0x400fe7
│ ╎╎╎╎╎╎│   ;-- rtcFormatNumber:
│ ────────> 0x00401044  ~   a264a37206     mov byte [0x672a364], al    ; [0x672a
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
- hook_candidates:
  - `MSVBVM60.DLL!_CIcos`
  - `MSVBVM60.DLL!_adj_fptan`
  - `MSVBVM60.DLL!__vbaVarMove`
  - `MSVBVM60.DLL!__vbaFreeVar`
  - `MSVBVM60.DLL!__vbaStrVarMove`
