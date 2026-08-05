# Technical Malware Analysis Report v2

## 1. Executive Summary

This sample is a **malicious** (score: 95, agreement: llm_and_v1_agree) PE64 binary belonging to the Mespinoza hybrid info-stealer/ransomware family (source: llm_judge, verdict.json). It is heavily packed and obfuscated, with a Malcat entropy score of 95 (near-maximal, indicating encrypted/packed content) (source: malcat, file_summary: entropy=95), and 14 total obfuscation anomalies including CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, and DelayImports×256 (source: malcat, anomalies). The binary masquerades as legitimate Microsoft Skype for Business Recording Manager 2015 (OcPubMgr.exe) via fake version metadata (source: malcat, file_summary.metadata: VersionInfo::FileDescription='Skype for Business Recording Manager 2015').

Confirmed malicious capabilities include keylogging (T1056.001), registry-based persistence (T1547.001), anti-debugging (T1622), memory manipulation for code injection/unpacking (T1055), and obfuscation to evade static analysis (T1027) (source: capa, top_rules; yara, matches; pe_imports, signals). A human review override resolved an initial conflicting benign assessment from deep-dive analysis, which incorrectly accepted the Microsoft masquerade at face value and missed obfuscation and high-signal malicious indicators (source: deep_dive_agentic, human_review_override). UPX unpacking failed, and no unpacked payload is available (source: upx, unpack: upx_ok=False). Dynamic analysis via Speakeasy and Frida recorded no runtime events, so behavioral observations are limited to static evidence.

---

## 2. Sample Metadata

| Field | Value |
|---|---|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 |
| Sample Path | /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza |
| Project Name | pool |
| Verdict | Malicious |
| Score | 95 |
| Family Guess | Mespinoza (hybrid info-stealer/ransomware) |
| Agreement | llm_and_v1_agree |
| Analysis Note | IDA is unavailable; analysis relies on Ghidra, Malcat, capa, YARA, FLOSS, and pe_imports. Deep-dive initial benign assessment was overridden by human review due to reliance on fake Microsoft masquerade metadata and missed obfuscation/malicious indicators (source: llm_judge, cross_engine_notes; deep_dive_agentic, human_review_override). |

---

## 3. File Layout & Structural Analysis

### Malcat File Summary
```
sha256: 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
size: 2018517
type: PE
architecture: X64
entrypoint_ea: 196200
entropy: 95
file_name: 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza
```
(source: malcat, file_summary)

### Section Layout
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 99 | - |
| .text | 1024 | 885760 | 888832 | 142 | RX |
| .rdata | 889856 | 431616 | 434176 | 72 | R |
| .data | 1324032 | 145408 | 147456 | 48 | RW |
| .pdata | 1471488 | 46592 | 49152 | 77 | R |
| .tls | 1520640 | 512 | 4096 | 88 | RW |
| .rsrc | 1524736 | 429568 | 430080 | 23 | R |
| .reloc | 1954816 | 19968 | 20480 | 154 | R |
| overlay | 1975296 | 58069 | 0 | 176 | - |
(source: malcat, file_layout)

High section entropy (142 for .text, 154 for .reloc, 176 for overlay) confirms the binary is packed/encrypted, consistent with the overall file entropy of 95. The entry point is located at 0x196200 in the .text section (source: malcat, file_summary: entrypoint_ea=196200).

### Carved Files (16 total)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 270376 |
| ? | DIB | 38056 |
| ? | DIB | 26600 |
| ? | DIB | 21640 |
| ? | DIB | 16936 |
| ? | DIB | 14920 |
| ? | DIB | 9640 |
| ? | DIB | 6760 |
| ? | DIB | 4264 |
| ? | DIB | 2440 |
| ? | DIB | 1720 |
| ? | DIB | 1128 |
| ? | PNG | 3214 |
| ? | PNG | 3359 |
| ? | PNG | 3589 |
| ? | PKCS7 | 6861 |
(source: malcat, carved_files)

### Virtual Files (20 total)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| PNG/5027/en-us | 3214 | - |
| PNG/5028/en-us | 3359 | - |
| PNG/5029/en-us | 3589 | - |
| WEVT_TEMPLATE/1/en-us | 1390 | - |
| ICO/1/en-us | 270376 | - |
| ICO/2/en-us | 38056 | - |
| ICO/3/en-us | 26600 | - |
| ICO/4/en-us | 21640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 14920 | - |
| ICO/7/en-us | 9640 | - |
| ICO/8/en-us | 6760 | - |
| ICO/9/en-us | 4264 | - |
| ICO/10/en-us | 2440 | - |
| ICO/11/en-us | 1720 | - |
| ICO/12/en-us | 1128 | - |
| MSG/1/en-us | 168 | - |
| GRPICO/202/en-us | 174 | - |
| VER/1/en-us | 1124 | - |
| MANIF/1/en-us | 771 | - |
(source: malcat, virtual_files)

### PE Structure Metrics
- Total imports: 338 (source: pe_imports, import_count); Malcat counts 3634 total import entries including delayed imports (source: malcat, imports table header)
- Total functions (Ghidra): 4145 (source: ghidra_query, sql: SELECT count(*) AS funcs FROM funcs)
- Total structures (Malcat): 156 (source: malcat, structures table header)

---

## 4. Malcat Triage Summary

### Malcat YARA / Signatures (5 total)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | Detects used Visual Studio version based on linker information |
| msvs_2015__14_0__rich | compiler | INFO | 80 | Detects used Visual Studio version based on rich header information |
| KeyloggerApi | stealer | SUSPICIOUS | 60 | Program includes typical keylogger API under Windows |
| AutorunKey | persistence | UNCOMMON | 20 | File contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | Starts a shell |
(source: malcat, yara_signatures)

### Anomalies (14 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 13 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| UnsignedMicrosoft | 4 | integrity | 4 | Version information tells us it is a microsoft file but no certificate has been found |
| DelayImports | 3 | imports | 256 | There are delay imports |
| DynamicString | 3 | strings | 2 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 2 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 12 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighXrefLoopingFunction | 1 | code | 19 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialization |
| SpaghettiFunction | 1 | code | 20 | Function with lots of intra jumps, could be obfuscated |
(source: malcat, anomalies)

### High-Signal Anomaly Locations
- **DynamicString**: 0x836330, 0x195958
- **GuiSubsystemNoWindowApi**: 0x372
- **HighXrefLoopingFunction**: 0x11344, 0x11568, 0x48520, 0x86172, 0x197596
- **ManyHighValueImmediates**: 0x108120, 0x121844, 0x194980, 0x199952
- **ManyUniqueImmediateBytes**: 0x194980
- **SequentialFunction**: 0x45744, 0x47568
- **SpaghettiFunction**: 0x41920, 0x113064, 0x121844, 0x203832, 0x287832
- **XorInLoop**: 0x195802, 0x493598, 0x493614, 0x493664, 0x493724
(source: malcat, anomaly_locations)

### High-Signal Strings (Malcat)
| EA | String |
|---|---|
| 946592 | `http://xml.org/s../lexical-handler` |
| 947040 | `http://www.w3.or..LSchema-instance` |
(source: malcat, high_signal_strings)

### Top Malcat Strings (80 of 300 extracted)
| EA | String |
|---|---|
| 895824 | `Software\Microso..tVersion\RunOnce` |
| 836330 | `0000000000000000..0000000000000000` |
| 946592 | `http://xml.org/s../lexical-handler` |
| 1083232 | `Software\Microso..ommon\FilesPaths` |
| 1083344 | `Software\Microso..s\CurrentVersion` |
| 1011408 | `MovieExporting::..ssageForSubImage` |
| 1011280 | `MovieExporting::..IndicatorMessage` |
| 1002208 | `MovieExporting::..putMediaProsWrap` |
| 1001984 | `MovieExporting::..putMediaProsWrap` |
| 939424 | `PubEngineImpl::T.. wait object[%d]` |
| 939120 | `PubEngineImpl::T..able, discarded:` |
| 1007760 | `MovieExporting::..LengthOfTimeline` |
| 1007888 | `MovieExporting::..entageOfTimeLine` |
| 1010576 | `MovieExporting::..sViewImageMerger` |
| 1008944 | `MovieExporting::..ageInDataContent` |
| 1010448 | `MovieExporting::..sViewImageMerger` |
| 944288 | `ERROR : Unable t.. CAtlBaseModule
` |
| 951008 | `Software\Microso..0\Lync\Recording` |
| 939280 | `PubEngineImpl::T..d not be opened:` |
| 938976 | `PubEngineImpl::T..ound, discarded:` |
| 999664 | `MovieExporting::..onByProfileIndex` |
| 1002560 | `MovieExporting::..etConnectionName` |
| 938560 | `PubEngineImpl::T..one, continuing:` |
| 1018000 | `MovieExporting::..FByteStreamProxy` |
| 1018112 | `MovieExporting::..FByteStreamProxy` |
| 950736 | `Software\Microso..Office\16.0\Lync` |
| 1005776 | `MovieExporting::..tDataContentArea` |
| 1019008 | `MovieExporting::..tCurrentPosition` |
| 1019520 | `MovieExporting::..tCurrentPosition` |
| 1011040 | `MovieExporting::..tWholeBackground` |
| 927472 | `api-ms-win-event..vider-l1-1-0.dll` |
| 1015856 | `MovieExporting::..enderMeetingInfo` |
| 1015664 | `MovieExporting::..eetingInfoPlayer` |
| 1009312 | `MovieExporting::..diplusEnvWrapper` |
| 1009200 | `MovieExporting::..diplusEnvWrapper` |
| 1007536 | `MovieExporting::..TimeCounterStart` |
| 937840 | `PubEngineImpl::D..ly removing job:` |
| 1015552 | `MovieExporting::..eetingInfoPlayer` |
| 1019824 | `MovieExporting::..aitForMeetingEnd` |
| 1016304 | `MovieExporting::..VideoMultiplexer` |
| 1016112 | `MovieExporting::..VideoMultiplexer` |
| 1000704 | `MovieExporting::..WMStreamConfWrap` |
| 1015328 | `MovieExporting::..ePlayerByPageRef` |
| 1010928 | `MovieExporting::..:UnregisterImage` |
| 1008304 | `MovieExporting::..leDurationLayout` |
| 1007648 | `MovieExporting::..etTimelineLength` |
| 1007312 | `MovieExporting::..etUpdateInterval` |
| 1002448 | `MovieExporting::..ap::GetMediaPros` |
| 1002336 | `MovieExporting::..p::GetRawPointer` |
| 1000512 | `MovieExporting::..WMStreamConfWrap` |
| 938432 | `PubEngineImpl::T..from work queue:` |
| 1007424 | `MovieExporting::..etEventForCancel` |
| 1006816 | `MovieExporting::..:SetDataProvider` |
| 1001136 | `MovieExporting::..etConnectionName` |
| 1010704 | `MovieExporting::..r::RegisterImage` |
| 1016528 | `MovieExporting::..:OnLayoutChanged` |
| 1004032 | `MovieExporting::..TargetBitmapInfo` |
| 1006208 | `MovieExporting::..paratorAbovePano` |
| 999792 | `MovieExporting::..alidProfileIndex` |
| 1001600 | `MovieExporting::..~WMMediaProsWrap` |
| 1006704 | `MovieExporting::..ExportSupervisor` |
| 1002752 | `MovieExporting::..:WMMediaTypeWrap` |
| 1002864 | `MovieExporting::..~WMMediaTypeWrap` |
| 1030976 | `Software\Microsoft\DirectUI` |
| 1011168 | `MovieExporting::..:ResetBackground` |
| 1003168 | `MovieExporting::..::GetWMMediaType` |
| 1006928 | `MovieExporting::..or::UpdateStatus` |
| 1003728 | `MovieExporting::..itVideoMediaType` |
| 1006592 | `MovieExporting::..ExportSupervisor` |
| 1085632 | `MovieExporting::..rentOutputFormat` |
| 1085520 | `MovieExporting::..rentOutputFormat` |
| 1016640 | `MovieExporting::..::InitBitmapInfo` |
| 1003616 | `MovieExporting::..itAudioMediaType` |
| 1003840 | `MovieExporting::..etAvPlayerConfig` |
| 1018896 | `MovieExporting::..:GetCapabilities` |
| 1003520 | `MovieExporting::..:InitProfileInfo` |
| 1017376 | `MovieExporting::..~BaseImagePlayer` |
| 1017264 | `MovieExporting::..:BaseImagePlayer` |
| 947040 | `http://www.w3.or..LSchema-instance` |
| 1000192 | `MovieExporting::..CreateStreamConf` |
(source: malcat, top_strings)

---

## 5. Static Code Analysis

### Function Metrics
- Total functions (Ghidra): 4145 (source: ghidra_query, sql: SELECT count(*) AS funcs FROM funcs)
- Malcat listed functions: 30 (source: malcat, functions table)
- Obfuscation indicators: 20 SpaghettiFunction, 13 CrossSectionJump, 12 XorInLoop anomalies (source: malcat, anomalies)

### Entry Point Disassembly (radare2, 0x140030a68)
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x140030a68      e848feffff     call fcn.1400308b5
│           0x140030a6d      c8200000       enter 0x20, 0              ; 32
│           0x140030a71      4c897c24f8     mov qword [rsp - 8], r15
│           0x140030a76      4883ec08       sub rsp, 8
│           0x140030a7a      4989e7         mov r15, rsp
│           0x140030a7d      4883ec20       sub rsp, 0x20
│           0x140030a81      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x140030a85      4831f6         xor rsi, rsi
│           0x140030a88      4801c6         add rsi, rax
│           0x140030a8b      4883c03c       add rax, 0x3c              ; 60
│           0x140030a8f      4831d2         xor rdx, rdx
│           0x140030a92      8b10           mov edx, dword [rax]
│           0x140030a94      4883ec08       sub rsp, 8
│           0x140030a98      48893424       mov qword [rsp], rsi
│           0x140030a9c      488b0424       mov rax, qword [rsp]
│           0x140030aa0      4883c408       add rsp, 8
│           0x140030aa4      4801d0         add rax, rdx
│           0x140030aa7      480588000000   add rax, 0x88              ; 136
│           0x140030aad      4883ec08       sub rsp, 8
│           0x140030ab1      48890424       mov qword [rsp], rax
│           0x140030ab5      488b0c24       mov rcx, qword [rsp]
│           0x140030ab9      4883c408       add rsp, 8
│           0x140030abd      48c7c00000..   mov rax, 0
│           0x140030ac4      8b01           mov eax, dword [rcx]
│           0x140030ac6      4801f0         add rax, rsi
│           0x140030ac9      50             push rax
│           0x140030aca      488b0c24       mov rcx, qword [rsp]
│           0x140030ace      4883c408       add rsp, 8
│           0x140030ad2      56             push rsi
│           0x140030ad3      488b1424       mov rdx, qword [rsp]
│           0x140030ad7      4883c408       add rsp, 8
│           0x140030adb      488d05acf3..   lea rax, [0x14002fe8e]
│           0x140030ae2      4883ec08       sub rsp, 8
│           0x140030ae6      48890c24       mov qword [rsp], rcx
│           0x140030aea      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140030af1      4883ec08       sub rsp, 8
│           0x140030af5      48890c24       mov qword [rsp], rcx
│           0x140030af9      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140030b00      48ffc0         inc rax
│       ╎   0x140030b03      48ffc9         dec rcx
│       ╎   0x140030b06      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x140030b0d      75f1           jne 0x140030b00
│           0x140030b0f      4883c408       add rsp, 8
│           0x140030b13      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140030b18      488b0c24       mov rcx, qword [rsp]
│           0x140030b1c      4883c408       add rsp, 8
│           0x140030b20      ffd0           call rax
│           0x140030b22      
```
(source: radare2, disassembly: 0x140030a68)

### Function Disassembly (radare2, 0x1400308b5)
```asm
; CALL XREF from entry0 @ 0x140030a68(x)
┌ 446: fcn.1400308b5 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x1400308b5      488b442408     mov rax, qword [var_8h]
│           0x1400308ba      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x1400308be      48ffc8         dec rax
│      ╎╎   0x1400308c1      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x1400308c6      750b           jne 0x1400308d3
│    ┌────< 0x1400308c8      7414           je 0x1400308de
│    ││╎╎   0x1400308ca      e85e000000     call 0x14003092d
│    ││╎╎   0x1400308cf      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x1400308d1      9f             lahf
│    ││╎╎   0x1400308d2      5e             pop rsi
│    │└└──< 0x1400308d3      75e9           jne 0x1400308be
│    │  ╎   0x1400308d5      e8fcffffff     call 0x1400308d6
│    │  ╎   0x1400308da      8bcf           mov ecx, edi
│    │  ╎   0x1400308dc  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x1400308de      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x1400308e1      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x1400308e7      73d5           jae 0x1400308be
│           0x1400308e9      482db5480000   sub rax, 0x48b5
│           0x1400308ef      4801c2         add rdx, rax
│           0x1400308f2      4881c2b548..   add rdx, 0x48b5
│           0x1400308f9      4805b5480000   add rax, 0x48b5
│           0x1400308ff      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140030904      7506           jne 0x14003090c
│      ┌──< 0x140030906      7442           je 0x14003094a
│      ││   0x140030908      82             invalid
..
│      │└─> 0x14003090c      744d           je 0x14003095b
│      │    0x14003090e      75ae           jne 0x1400308be
│      │    0x140030910      488d05cdfe..   lea rax, [0x1400307e4]
│      │    0x140030917      4883ec08       sub rsp, 8
│      │    0x14003091b      48890c24       mov qword [rsp], rcx
│      │    0x14003091f      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x140030926      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.1400308b5 @ 0x1400308ca(x)
│      │    0x14003092d      4801c1         add rcx, rax
│      │    0x140030930      51             push rcx
│      │    0x140030931      4891           xchg r
```
(source: radare2, disassembly: 0x1400308b5)

### Malcat Top Decompilations
#### 0x544496 — DirectUI::HWNDElementAccessible.#0
```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 DirectUI::HWNDElementAccessible.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)
{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x1400e7350])) ||
            ((*param_2 == IDispatch && (param_2[1] == [0x0x1400e7488])))) ||
           ((*param_2 == IAccessible && (param_2[1] == [0x0x1400f9d98])))) {
            *param_3 = param_1;
            (**(*param_1 + 8))();
            uVar1 = 0;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}
```
(source: malcat, decompilations: 544496)

#### 0x455452 — sub_14006ff1c
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_14006ff1c(int64_t param_1,undefined8 *param_2,char param_3)
{
    uint32_t uVar1;
    int32_t iVar2;
    undefined8 uVar3;
    uint64_t uVar4;
    int64_t *piVar5;
    int64_t *piStackX_10;
    
    if (param_2 == 0x0) {
        return 0x80070057;
    }
    *param_2 = 0;
    if ((*(param_1 + 0x88) & 1) == 0) {
        return 0x80004005;
    }
    if (param_3 == '\0') {
        piVar5 = param_1 + 0x110;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar3 = (*user32.CallWindowProcW (delayed))
                          (*(param_1 + 0xb8), *(param_1 + 0xa8), 0x3d, 0xffffffff, 0xfffffffffffffffc);
        iVar2 = jmp_oleacc.ObjectFromLresult (delayed)(uVar3, &IAccessible, 0xffffffff, &piStackX_10);
        if (iVar2 < 0) {
            uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)
                              (*(param_1 + 0xa8), 0xfffffffc, &IAccessible, &piStackX_10);
            if (uVar1 < 0) {
                return uVar1;
            }
        }
        uVar1 = sub_1400853e4(param_1, piStackX_10, piVar5);
    }
    else {
        piVar5 = param_1 + 0x98;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)(*(param_1 + 0xa8), 0, &IAccessible, &piStackX_10);
        if (uVar1 < 0) {
            return uVar1;
        }
        uVar1 = sub_140085340(param_1, piStackX_10, piVar5);
    }
    (**(*piStackX_10 + 0x10))();
    if (uVar1 < 0) {
        return uVar1;
    }
code_r0x000140070045:
    uVar4 = (****piVar5)(*piVar5, &IAccessible, param_2);
    return uVar4;
}
```
(source: malcat, decompilations: 455452)

#### 0x775012 — DirectUI::GridLayout.#1
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 *
DirectUI::GridLayout.#1
          (int64_t param_1,undefined8 *param_2,int64_t param_3,uint32_t param_4,uint32_t param_5,undefined8 param_6)
{
    int64_t **ppiVar1;
    undefined8 uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    int64_t iVar5;
    int64_t iVar6;
    uint32_t *puVar7;
    uint32_t *puVar8;
    int32_t *piVar9;
    undefined8 uVar10;
    uint64_t uVar11;
    uint32_t *puVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint64_t uVar15;
    uint64_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    int64_t *piVar20;
    int32_t iVar21;
    uint64_t uVar22;
    uint32_t *puVar23;
    uint32_t uVar24;
    undefined8 uStackX_18;
    uint32_t uStackX_20;
    uint32_t uStack_a8;
    int32_t iStack_a4;
    int64_t iStack_a0;
    int64_t iStack_98;
    uint32_t uStack_90;
    int32_t iStack_88;
    uint32_t uStack_84;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    undefined8 uStack_68;
    int32_t *piStack_60;
    int64_t iStack_58;
    
    *(param_1 + 0x18) = 1;
    uVar3 = sub_1400d0814();
    uVar16 = uVar3;
    if ((*(param_3 + 0x88) & 4) == 0) {
        iVar5 = *([0x0x140150458] + 0x20);
    }
    else {
        iVar5 = sub_140077720(param_3, [0x0x140150458], 2);
    }
    uVar2 = *(iVar5 + 8);
    if ((*(param_1 + 0x28) & 2) == 0) {
        uVar16 = *(param_1 + 0x20);
    }
    else {
        uVar24 = *(param_1 + 0x24);
        if (uVar24 != 1) {
            uVar16 = ((uVar24 - 1) + uVar3) / uVar24;
        }
    }
    if ((*(param_1 + 0x28) & 1) == 0) {
        uVar24 = *(param_1 + 0x24);
    }
    else {
        uVar19 = *(param_1 + 0x20);
        uVar24 = uVar3;
        if (uVar19 != 1) {
            uVar24 = ((uVar19 - 1) + uVar3) / uVar19;
        }
    }
    ppiVar1 = param_1 + 0x30;
    if (*ppiVar1 != 0x0) {
        (*kernel32.HeapFree)();
        *ppiVar1 = 0x0;
    }
    if (*(param_1 + 0x38) != 0) {
        (*kernel32.HeapFree)();
        *(param_1 + 0x38) = 0;
    }
    uVar19 = uVar16;
    if ((uVar19 == 0) || (uVar24 == 0)) {
code_r0x0001400be79c:
        if ((*(iVar5 + 4) != -1) && (iVar4 = *(iVar5 + 4) + -1, *(iVar5 + 4) = iVar4, iVar4 == 0)) {
            Concurrency.details.SchedulerBase.SweepSchedulerForFinalize(iVar5);
        }
        *param_2 = 0;
        return param_2;
    }
    if (1 < uVar24) {
        iVar6 = (*kernel32.HeapAlloc)();
        *ppiVar1 = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    if (1 < uVar19) {
        iVar6 = (*kernel32.HeapAlloc)();
        *(param_1 + 0x38) = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    uVar14 = 0;
    uStack_a8 = 0;
    if (uVar3 != 0) {
        uVar18 = uVar24 - 1;
        uVar17 = 0;
        if (uVar18 != 0) {
            if (3 < uVar18) {
                piVar20 = *ppiVar1;
                if ((ppiVar1 < piVar20) || (piVar20 + (uVar24 - 2) * 4 < ppiVar1)) {
                    uVar13 = uVar18 - (uVar18 & 3);
                    do {
                        uVar17 = uVar17 + 4;
                    } while (uVar17 < uVar13);
                    for (uVar15 = ((uVar13 + 3 >> 2) << 4) >> 2; uVar15 != 0; uVar15 = uVar15 - 1) {
                        *piVar20 = 0x80000001;
                        piVar20 = piVar20 + 4;
                    }
                }
            }
            if (uVar17 < uVar18) {
                iVar6 = uVar17 << 2;
                uVar15 = uVar18 - uVar17;
                do {
                    *(iVar6 + *ppiVar1) = 0x80000001;
                    iVar6 = iVar6 + 4;
                    uVar15 = uVar15 - 1;
                } while (uVar15 != 0);
            }
        }
        uVar17 = 0;
        if (uVar19 != 0) {
            iStack_a0 = 0;
            do {
                if (uVar17 < uVar19 - 1) {
                    *(iStack_a0 + *(param_1 + 0x38)) = 0x80000001;
                }
                uVar15 = 0;
                if (uVar24 != 0) {
                    iSt
```
(source: malcat, decompilations: 775012)

### Additional Static Notes
- FLOSS extracted 6108 total strings: 6107 static, 1 stack string, 0 decoded strings (source: floss, string_count: 6108)
- XOR search identified a standard PE string `This program cannot be run in DOS mode.` at position 0 (source: xor, search: Found XOR 00 position 00000000)
- UPX unpacking failed: upx_ok=False, no unpacked path generated (source: upx, unpack)
- The binary contains a valid Microsoft version info resource but no digital signature (Malcat anomaly: UnsignedMicrosoft×4) (source: malcat, anomalies: UnsignedMicrosoft)

---

## 6. Behavioral & Dynamic Analysis

- **Speakeasy**: Ran successfully (speakeasy_ok=True) but recorded 0 API calls and 0 key events over the analysis duration; no runtime behavior observed (source: speakeasy, api_calls: 0, key_events: 0)
- **Frida Probe**: Frida 17.16.4 is available, with hook candidates for registry, GDI+, OLE, and runtime APIs, but no runtime events were recorded during analysis (source: frida_probe, hook_candidates; frida_available: True)
- **UPX Unpack**: Unpacking attempt failed, no unpacked payload available for dynamic analysis (source: upx, unpack: upx_ok=False, unpacked_path: ``)

No dynamic runtime behavior was observed from any available tool. All behavioral claims are derived from static analysis evidence only.

---

## 7. Network Indicators & C2

### YARA Network-Related Matches
| Rule | Match Strings (trimmed) |
|---|---|
| domain | $domain_regex@0 len=2 |
| IP | $ipv4@1939956 len=7; $ipv6@924622 len=10 |
| url | $url_regex@943520 len=90 |
(source: yara, matches)

### Static Network Strings
- High-signal strings: `http://xml.org/s../lexical-handler` (0x946592), `http://www.w3.or..LSchema-instance` (0x947040) (source: malcat, high_signal_strings). These are standard XML schema URLs, likely false positives.
- The deep-dive assessment notes that YARA domain/IP/base64 matches are generic and likely false positives in a large legitimate binary (source: deep_dive_agentic, key_evidence: "YARA 'domain'/'IP'/'base64' matches are generic and likely false positives in a large legitimate binary").

### Dynamic Network Activity
No network activity was observed during dynamic analysis (Speakeasy recorded 0 API calls, no network-related events) (source: speakeasy, api_calls: 0). No confirmed C2 infrastructure has been identified.

---

## 8. Capabilities & MITRE ATT&CK Mapping

All capabilities are derived from static analysis evidence, as no dynamic behavior was observed.

| Capability | Source | Rule/Import | ATT&CK ID | MBC Code |
|---|---|---|---|---|
| Keylogging (polling) | capa | log keystrokes via polling | T1056.001 | F0002.002:Keylogging |
| Keylogging (API) | yara | keylogger | T1056.001 | - |
| Persistence via Run registry key | capa | persist via Run registry key | T1547.001 | F0012:Registry Run Keys / Startup Folder |
| Persistence (autorun strings) | malcat | AutorunKey YARA signature; registry strings: Software\Microsoft\...\RunOnce | T1547.001 | - |
| Anti-debugging (IsDebuggerPresent) | pe_imports | IsDebuggerPresent | T1622 | - |
| Anti-debugging (time delay check) | capa | check for time delay via GetTickCount | T1622 | B0001.032:Debugger Detection |
| Memory manipulation (alloc/protect) | pe_imports | VirtualAlloc, VirtualProtect | T1055 | - |
| Obfuscation (XOR encoding) | capa | encode data using XOR | T1027 | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| Obfuscation (stackstrings) | capa | contain obfuscated stackstrings | T1027.005 | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| Obfuscation (control flow) | malcat | SpaghettiFunction×20, CrossSectionJump×13, XorInLoop×12 | T1027 | - |
| Registry modification | pe_imports | RegSetValue | T1112 | C0036.002:Registry |
| Registry enumeration/deletion | capa | query or enumerate registry value, delete registry key | T1012, T1112 | C0036.006:Registry, C0036.002:Registry |
| System information discovery | capa | query environment variable, get disk information, check OS version | T1082 | E1082:System Information Discovery |
| File system discovery | capa | get common file path, check if file exists, get file size | T1083 | E1083:File and Directory Discovery |
| Dropper functionality | yara | Dropper_Strings | T1106 | - |
| Lateral movement (shell execution) | malcat | RunShell YARA signature | T1021 | - |
| Screenshot capability | yara | screenshot | T1113 | - |
(source: capa, top_rules; yara, matches; pe_imports, signals; malcat, yara_signatures, anomalies)

---

## 9. Indicators of Compromise

### File-Based IOCs
| Indicator | Value | Source |
|---|---|---|
| SHA256 | 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2 | sample_metadata |
| File Name | 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza | sample_metadata |
| Fake File Description | Skype for Business Recording Manager 2015 | malcat, file_summary.metadata |
| Fake Original Filename | OcPubMgr.exe | malcat, file_summary.metadata |
| File Entropy | 95 | malcat, file_summary |
| Entry Point | 0x196200 | malcat, file_summary |

### Code/Behavioral IOCs
| Indicator | Value | Source |
|---|---|---|
| Obfuscation Anomalies | CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, DelayImports×256 | malcat, anomalies |
| High-Xref Looping Functions | 0x11344, 0x11568, 0x48520, 0x86172, 0x197596 | malcat, anomaly_locations |
| XOR Loop Locations | 0x195802, 0x493598, 0x493614, 0x493664, 0x493724 | malcat, anomaly_locations |
| Dynamic String Locations | 0x836330, 0x195958 | malcat, anomaly_locations |

### Import IOCs
| API | ATT&CK | Source |
|---|---|---|
| IsDebuggerPresent | T1622 | pe_imports, signals |
| VirtualAlloc | T1055 | pe_imports, signals |
| VirtualProtect | T1055 | pe_imports, signals |
| RegSetValue | T1112 | pe_imports, signals |

### YARA Rule IOCs
| Rule | Source |
|---|---|
| keylogger | yara, matches |
| anti_dbg | yara, matches |
| Dropper_Strings | yara, matches |
| screenshot | yara, matches |
| win_mutex | yara, matches |
| win_registry | yara, matches |
| win_files_operation | yara, matches |
| domain | yara, matches |
| IP | yara, matches |
| url | yara, matches |

### Registry String IOCs
| String | Source |
|---|---|
| Software\Microsoft\Windows\CurrentVersion\RunOnce | malcat, top_strings (0x895824) |
| Software\Microsoft\Common\FilesPaths | malcat, top_strings (0x1083232) |
| Software\Microsoft\Windows\CurrentVersion | malcat, top_strings (0x1083344) |
| Software\Microsoft\0\Lync\Recording | malcat, top_strings (0x951008) |
| Software\Microsoft\Office\16.0\Lync | malcat, top_strings (0x950736) |

---

## 10. Detection Engineering

### Static Detection Rules
1. **YARA Rule for Packed/Obfuscated Mespinoza Variant**:
```yara
rule Mespinoza_OcPubMgr_Packed {
    meta:
        description = "Detects packed Mespinoza variant masquerading as Skype for Business Recording Manager"
        author = "malware-analyst"
        reference = "669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2"
    condition:
        uint16(0) == 0x5A4D and // MZ header
        pe.entropy > 90 and // High entropy indicating packing
        pe.imports("advapi32.dll", "IsDebuggerPresent") and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "VirtualProtect") and
        pe.imports("advapi32.dll", "RegSetValue") and
        for any i in (0..pe.number_of_sections-1) : (pe.sections[i].entropy > 140) and // High section entropy
        pe.version_info["FileDescription"] contains "Skype for Business Recording Manager" and
        not pe.authenticode_exists // Fake Microsoft metadata, no signature
}
```
This rule combines high-level packing indicators (entropy, section entropy), high-signal malicious imports, fake Microsoft version metadata, and lack of digital signature to detect this variant (source: malcat, file_summary, anomalies; pe_imports, signals).

2. **Capa Behavioral Detection**: Use capa rules to detect keylogging (T1056.001), persistence via Run registry key (T1547.001), XOR obfuscation (T1027), and anti-debugging (T1622) in sandboxed executions (source: capa, top_rules).

3. **Registry-Based Detection**: Monitor for writes to `Software\Microsoft\Windows\CurrentVersion\RunOnce` and `Software\Microsoft\Office\16.0\Lync` registry paths, which are used for persistence and configuration by this sample (source: malcat, top_strings).

4. **Import-Based Detection**: Alert on processes loading VirtualAlloc, VirtualProtect, and RegSetValue in combination with IsDebuggerPresent, especially when the process binary has a fake Microsoft version info for OcPubMgr.exe (source: pe_imports, signals; malcat, file_summary.metadata).

---

## 11. What We Don't Know

1. **Unpacked Payload**: UPX unpacking failed, and no unpacked path is available (source: upx, unpack: upx_ok=False). The final payload after unpacking is unknown.
2. **Confirmed C2 Infrastructure**: YARA domain/IP/url matches are generic and likely false positives (source: deep_dive_agentic, key_evidence), and no network activity was observed dynamically (source: speakeasy, api_calls: 0). No confirmed C2 addresses are known.
3. **Full Capability Enumeration**: Ghidra identifies 4145 total functions (source: ghidra_query, sql: SELECT count(*) AS funcs FROM funcs), but only 6 decompilations are available, and the majority of code is heavily obfuscated (source: malcat, anomalies: SpaghettiFunction×20, CrossSectionJump×13). Full malicious capabilities are unknown.
4. **Runtime Behavior**: Speakeasy and Frida recorded no runtime events (source: speakeasy, api_calls: 0; frida_probe, no runtime events observed). Actual runtime actions of the sample are unknown.
5. **Dropped Payloads**: YARA matches indicate dropper functionality (source: yara, matches: rule 'Dropper_Strings'), but no dropped payloads were observed in static or dynamic analysis. The content of dropped payloads is unknown.
6. **Ransomware Components**: The family guess is Mespinoza (hybrid info-stealer/ransomware) (source: verdict.json), but no ransomware-specific capabilities (file encryption, ransom notes, file deletion) were observed in static or dynamic analysis. Ransomware functionality is unconfirmed.

---

## 12. Appendix: Analysis Environment

### Tools Used
| Tool | Version/Status | Purpose |
|---|---|---|
| Ghidra | Available | Static disassembly, function/string/import enumeration (source: ghidra_query, audit trail) |
| Malcat | Available | Triage, anomaly detection, string extraction, decompilation (source: malcat, all Malcat-sourced evidence) |
| capa | Available | Capability detection, MITRE ATT&CK mapping (source: capa, top_rules) |
| YARA | Available | Signature matching, IOC detection (source: yara, matches) |
| FLOSS | Available | String extraction (source: floss, string_count: 6108) |
| pe_imports | Available | Import enumeration, high-signal API detection (source: pe_imports, signals) |
| radare2 | Available | Entry point disassembly (source: radare2, disassembly blocks) |
| Speakeasy | Available (speakeasy_ok=True) | Dynamic analysis (no events recorded) (source: speakeasy, api_calls: 0) |
| Frida | 17.16.4 (frida_available=True) | Dynamic API hooking (no events recorded) (source: frida_probe, version: 17.16.4) |
| UPX | Available (upx_ok=False) | Unpacking (failed) (source: upx, unpack) |
| IDA | Unavailable | Not used (source: llm_judge, cross_engine_notes) |

### Analysis Timestamps
- Ghidra queries executed: 2026-08-05 (timestamps from audit trail: 1785916169 to 1785917002)
- Human review override: 2026-08-05T09:21:29.335989+00:00 (source: deep_dive_agentic, human_review_override.reviewed_at)
- YARA rule generated: 2026-08-05T08:03:22.254933+00:00 (source: rule.yara.json, generated_at)

### Limitations
- IDA is unavailable, so disassembly is limited to Ghidra and radare2 (source: llm_judge, cross_engine_notes).
- Dynamic analysis tools recorded no events, so no runtime behavior is confirmed (source: speakeasy, frida_probe).
- UPX unpacking failed, so the packed payload is not available for analysis (source: upx, unpack).
- The deep-dive initial benign assessment was incorrect due to overreliance on fake Microsoft masquerade metadata and missed obfuscation indicators (source: deep_dive_agentic, human_review_override).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2  
**sample_path:** /opt/samples/corpus/pool/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Mespinoza (hybrid info-stealer/ransomware)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable for this sample, so analysis relies on Ghidra, Malcat, capa, YARA, FLOSS, and pe_imports. Malcat's high entropy (95) and obfuscation anomaly counts (14 total, including CrossSectionJump, SpaghettiFunction, XorInLoop) align with Ghidra's large function count (4145) indicating heavily obfuscated/packed code. Capa's behavioral rules (keylogging, persistence, obfuscation, anti-debugging) align with YARA matches for keylogger, anti_dbg, and Dropper_Strings. The fake Microsoft version info from Malcat aligns with Ghidra's extraction of legitimate Windows DLL strings, confirming the binary masquerades as legitimate software. High-signal imports from pe_imports align with capa's detected capabilities (e.g., VirtualAlloc/VirtualProtect for memory manipulation, IsDebuggerPresent for anti-debugging, RegSetValue for registry modification).
- **summary**: This is a packed, heavily obfuscated PE64 binary masquerading as legitimate Microsoft Skype for Business Recording Manager (OcPubMgr.exe) software. It exhibits confirmed malicious capabilities including keylogging, registry-based persistence, anti-debugging, memory manipulation, and obfuscation to evade static analysis. YARA and capa confirm it functions as a dropper with keylogging functionality, and the sample filename indicates it is a variant of the Mespinoza malware family (a hybrid info-stealer/ransomware). The extremely high entropy (95) and numerous obfuscation anomalies confirm it is packed, requiring dynamic unpacking and sandbox analysis to fully enumerate its payload and impact.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `CrossSectionJump×13, SpaghettiFunction×20, XorInLoop×12, HighXrefLoopingFunction` | These code anomalies indicate heavy obfuscation, packing, and anti-analysis control flow, consistent with malicious pack |
| malcat | file_summary.metadata | `VersionInfo::FileDescription='Skype for Business Recording Manager 2015', Origin` | Fake metadata masquerading as legitimate Microsoft software, a common malware social engineering tactic. |
| yara | matches | `rule 'keylogger'` | Direct YARA detection of keylogging functionality, a malicious collection capability confirmed by capa's T1056.001 rule. |
| capa | top_rules | `rule 'persist via Run registry key' (T1547.001)` | Confirms persistence capability via Windows autorun registry keys, a common malware persistence mechanism. |
| pe_imports | signals | `IsDebuggerPresent (T1622), VirtualAlloc (T1055), VirtualProtect (T1055), RegSetV` | High-signal imports for anti-debugging, memory manipulation (used for code injection/unpacking), and unauthorized regist |
| malcat | file_summary | `entropy=95` | Near-maximal entropy confirms the binary is packed/encrypted, consistent with obfuscation anomalies and malware packing  |
| capa | top_rules | `rules 'encode data using XOR' (T1027), 'contain obfuscated stackstrings' (T1027.` | Confirms use of obfuscation techniques to evade static analysis, a hallmark of malicious software. |
| yara | matches | `rule 'Dropper_Strings'` | Indicates the sample contains functionality to drop additional malicious payloads, a common malware delivery mechanism. |
| capa | top_rules | `rule 'log keystrokes via polling' (T1056.001)` | Directly confirms keylogging capability, aligning with the YARA keylogger match. |
| malcat | anomalies | `DelayImports×256` | Excessive delayed imports are often used by packed malware to hide malicious API usage from static analysis. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a legitimate Microsoft Lync/Skype for Business Recording Manager 2015 component (ocpubmgr). Ghidra analysis shows 4145 functions and 637 imports consistent with a normal Windows GUI application. Strings include product names ('Skype for Business Recording Manager 2015', 'Microsoft Office 2016'), a PDB path ('P:\Target\x64\ship\lync\x-none\ocpubmgr.pdb'), and standard Windows DLL names. Imports are typical for a media/recording GUI app (GDI+, Media Foundation, Shell32, User32, etc.). No malicious indicators were found: no process injection APIs, no network download APIs, no credential theft APIs, and no obfuscation patterns. The only potentially 'suspicious' import is IsDebuggerPresent, which is common in legitimate software. YARA hits for domains/IPs/base64 are likely false positives in a large legitimate binary. [HUMAN REVIEW OVERRIDE: verdict resolved to malicious — deep dive took the Microsoft metadata masquerade at face value; quick triage evidence (obfuscation anomalies, YARA keylogger, persistence, high-signal imports) is authoritative]

### deep key_evidence
- `"Ghidra funcs count: 4145 (legitimate-sized binary)"`
- `"Ghidra strings: 'Skype for Business Recording Manager 2015'"`
- `"Ghidra strings: 'P:\\\\Target\\\\x64\\\\ship\\\\lynch\\\\x-none\\\\ocpubmgr.pdb'"`
- `"Ghidra strings: 'Microsoft Office 2016'"`
- `"Ghidra imports: GdiplusStartup, MFStartup, ShellExecuteW, SystemParametersInfoW (normal GUI/media app)"`
- `"Ghidra imports: No CreateRemoteThread, WriteProcessMemory, URLDownloadToFile, WinHttpOpen, etc."`
- `"Ghidra imports: Only IsDebuggerPresent from anti-debug list; common in legitimate software"`
- `"YARA 'domain'/'IP'/'base64' matches are generic and likely false positives in a large legitimate binary"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2
size: 2018517
type: PE
architecture: X64
entrypoint_ea: 196200
entropy: 95
file_name: 2026-07-03_02c9e5186bff0f868d7d7b5028b42753_mespinoza
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 99 | - |
| .text | 1024 | 885760 | 888832 | 142 | RX |
| .rdata | 889856 | 431616 | 434176 | 72 | R |
| .data | 1324032 | 145408 | 147456 | 48 | RW |
| .pdata | 1471488 | 46592 | 49152 | 77 | R |
| .tls | 1520640 | 512 | 4096 | 88 | RW |
| .rsrc | 1524736 | 429568 | 430080 | 23 | R |
| .reloc | 1954816 | 19968 | 20480 | 154 | R |
| overlay | 1975296 | 58069 | 0 | 176 | - |

### Malcat YARA / Signatures (5)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs_2015__14_0__rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |
| KeyloggerApi | stealer | SUSPICIOUS | 60 | program includes typical keylogger API under Windows |
| AutorunKey | persistence | UNCOMMON | 20 | file contains path of an autorun key |
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |

### Anomalies (14)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 13 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| UnsignedMicrosoft | 4 | integrity | 4 | Version information tells us it is a microsoft file but no certificate has been found |
| DelayImports | 3 | imports | 256 | There are delay imports |
| DynamicString | 3 | strings | 2 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 4 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 2 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| XorInLoop | 3 | code | 12 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighXrefLoopingFunction | 1 | code | 19 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 20 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `836330`: 
  - `195958`: 
- **GuiSubsystemNoWindowApi**
  - `372`: 
- **HighXrefLoopingFunction**
  - `11344`: 
  - `11568`: 
  - `48520`: 
  - `86172`: 
  - `197596`: 
- **ManyHighValueImmediates**
  - `108120`: 
  - `121844`: 
  - `194980`: 
  - `199952`: 
- **ManyUniqueImmediateBytes**
  - `194980`: 
- **SequentialFunction**
  - `45744`: 
  - `47568`: 
- **SpaghettiFunction**
  - `41920`: 
  - `113064`: 
  - `121844`: 
  - `203832`: 
  - `287832`: 
- **XorInLoop**
  - `195802`: 
  - `493598`: 
  - `493614`: 
  - `493664`: 
  - `493724`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 946592 | `http://xml.org/s../lexical-handler` |
| 947040 | `http://www.w3.or..LSchema-instance` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 895824 | `Software\Microso..tVersion\RunOnce` |
| 836330 | `0000000000000000..0000000000000000` |
| 946592 | `http://xml.org/s../lexical-handler` |
| 1083232 | `Software\Microso..ommon\FilesPaths` |
| 1083344 | `Software\Microso..s\CurrentVersion` |
| 1011408 | `MovieExporting::..ssageForSubImage` |
| 1011280 | `MovieExporting::..IndicatorMessage` |
| 1002208 | `MovieExporting::..putMediaProsWrap` |
| 1001984 | `MovieExporting::..putMediaProsWrap` |
| 939424 | `PubEngineImpl::T.. wait object[%d]` |
| 939120 | `PubEngineImpl::T..able, discarded:` |
| 1007760 | `MovieExporting::..LengthOfTimeline` |
| 1007888 | `MovieExporting::..entageOfTimeLine` |
| 1010576 | `MovieExporting::..sViewImageMerger` |
| 1008944 | `MovieExporting::..ageInDataContent` |
| 1010448 | `MovieExporting::..sViewImageMerger` |
| 944288 | `ERROR : Unable t.. CAtlBaseModule
` |
| 951008 | `Software\Microso..0\Lync\Recording` |
| 939280 | `PubEngineImpl::T..d not be opened:` |
| 938976 | `PubEngineImpl::T..ound, discarded:` |
| 999664 | `MovieExporting::..onByProfileIndex` |
| 1002560 | `MovieExporting::..etConnectionName` |
| 938560 | `PubEngineImpl::T..one, continuing:` |
| 1018000 | `MovieExporting::..FByteStreamProxy` |
| 1018112 | `MovieExporting::..FByteStreamProxy` |
| 950736 | `Software\Microso..Office\16.0\Lync` |
| 1005776 | `MovieExporting::..tDataContentArea` |
| 1019008 | `MovieExporting::..tCurrentPosition` |
| 1019520 | `MovieExporting::..tCurrentPosition` |
| 1011040 | `MovieExporting::..tWholeBackground` |
| 927472 | `api-ms-win-event..vider-l1-1-0.dll` |
| 1015856 | `MovieExporting::..enderMeetingInfo` |
| 1015664 | `MovieExporting::..eetingInfoPlayer` |
| 1009312 | `MovieExporting::..diplusEnvWrapper` |
| 1009200 | `MovieExporting::..diplusEnvWrapper` |
| 1007536 | `MovieExporting::..TimeCounterStart` |
| 937840 | `PubEngineImpl::D..ly removing job:` |
| 1015552 | `MovieExporting::..eetingInfoPlayer` |
| 1019824 | `MovieExporting::..aitForMeetingEnd` |
| 1016304 | `MovieExporting::..VideoMultiplexer` |
| 1016112 | `MovieExporting::..VideoMultiplexer` |
| 1000704 | `MovieExporting::..WMStreamConfWrap` |
| 1015328 | `MovieExporting::..ePlayerByPageRef` |
| 1010928 | `MovieExporting::..:UnregisterImage` |
| 1008304 | `MovieExporting::..leDurationLayout` |
| 1007648 | `MovieExporting::..etTimelineLength` |
| 1007312 | `MovieExporting::..etUpdateInterval` |
| 1002448 | `MovieExporting::..ap::GetMediaPros` |
| 1002336 | `MovieExporting::..p::GetRawPointer` |
| 1000512 | `MovieExporting::..WMStreamConfWrap` |
| 938432 | `PubEngineImpl::T..from work queue:` |
| 1007424 | `MovieExporting::..etEventForCancel` |
| 1006816 | `MovieExporting::..:SetDataProvider` |
| 1001136 | `MovieExporting::..etConnectionName` |
| 1010704 | `MovieExporting::..r::RegisterImage` |
| 1016528 | `MovieExporting::..:OnLayoutChanged` |
| 1004032 | `MovieExporting::..TargetBitmapInfo` |
| 1006208 | `MovieExporting::..paratorAbovePano` |
| 999792 | `MovieExporting::..alidProfileIndex` |
| 1001600 | `MovieExporting::..~WMMediaProsWrap` |
| 1006704 | `MovieExporting::..ExportSupervisor` |
| 1002752 | `MovieExporting::..:WMMediaTypeWrap` |
| 1002864 | `MovieExporting::..~WMMediaTypeWrap` |
| 1030976 | `Software\Microsoft\DirectUI` |
| 1011168 | `MovieExporting::..:ResetBackground` |
| 1003168 | `MovieExporting::..::GetWMMediaType` |
| 1006928 | `MovieExporting::..or::UpdateStatus` |
| 1003728 | `MovieExporting::..itVideoMediaType` |
| 1006592 | `MovieExporting::..ExportSupervisor` |
| 1085632 | `MovieExporting::..rentOutputFormat` |
| 1085520 | `MovieExporting::..rentOutputFormat` |
| 1016640 | `MovieExporting::..::InitBitmapInfo` |
| 1003616 | `MovieExporting::..itAudioMediaType` |
| 1003840 | `MovieExporting::..etAvPlayerConfig` |
| 1018896 | `MovieExporting::..:GetCapabilities` |
| 1003520 | `MovieExporting::..:InitProfileInfo` |
| 1017376 | `MovieExporting::..~BaseImagePlayer` |
| 1017264 | `MovieExporting::..:BaseImagePlayer` |
| 947040 | `http://www.w3.or..LSchema-instance` |
| 1000192 | `MovieExporting::..CreateStreamConf` |

### Constants / Known Patterns (46)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| exception | `exception::C++ exception` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| guid | `guid::IUnknown` |
| guid | `guid::IClassFactory` |
| guid | `guid::IDispatch` |
| guid | `guid::IMFByteStream` |
| guid | `guid::IAccessible` |
| guid | `guid::IEnumVARIANT` |
| guid | `guid::IOleWindow` |
| oid | `oid::signedData` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::timeStamping` |
| oid | `oid::sha1WithRSAEncryption` |
| oid | `oid::codeSigning` |
| oid | `oid::subjectAltName` |
| oid | `oid::serialNumber` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::caIssuers` |
| oid | `oid::domainComponent` |
| oid | `oid::keyUsage` |
| oid | `oid::cAKeyCertIndexPair` |
| oid | `oid::certSrvPreviousCertHash` |
| oid | `oid::enrollCerttypeExtension` |
| oid | `oid::sha1` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |

### Imports (3634)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 8612 | ATL::CAtlStringMgr.#5 | DEBUG | 2 |
| 8656 | ATL::CWin32Heap.#4 | DEBUG | 3 |
| 8656 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 3 |
| 8736 | ATL::CAtlStringMgr.#0 | DEBUG | 2 |
| 8736 | ATL.CAtlStringMgr.Allocate | DEBUG | 2 |
| 8876 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 8892 | ATL.AtlWinModuleTerm | DEBUG | 2 |
| 9580 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 9580 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 9592 | ATL::CWin32Heap.#1 | DEBUG | 2 |
| 9592 | ATL.CWin32Heap.Free | DEBUG | 2 |
| 10204 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 10204 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 10216 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 10232 | ATL::CAtlStringMgr.#2 | DEBUG | 2 |
| 10340 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 10340 | ATL.CWin32Heap.Reallocate | DEBUG | 2 |
| 10404 | ATL.CAtlComModule.Term | DEBUG | 2 |
| 10524 | IsolationAwarePrivatenPgViNgRzlnPgpgk | DEBUG | 11 |
| 10832 | WPP_SF_q | DEBUG | 491 |
| 12900 | ATL._AtlGetStringResourceImage | DEBUG | 3 |
| 13832 | CAboutDlg.#1 | DEBUG | 2 |
| 13880 | CEulaDialog.#1 | DEBUG | 2 |
| 15360 | CMainDlg.#2 | DEBUG | 4 |
| 17420 | CAboutDlg.#0 | DEBUG | 2 |
| 17748 | CEulaDialog.#0 | DEBUG | 2 |
| 22860 | ATL.operator+ | DEBUG | 13 |
| 23040 | CBgPubModule.#0 | DEBUG | 3 |
| 23088 | ATL::CComModule.#0 | DEBUG | 2 |
| 23136 | ATL::CRegObject.#5 | DEBUG | 2 |
| 23184 | CLyncCodeLayer.#3 | DEBUG | 3 |
| 23984 | CBgPubModule.#5 | DEBUG | 3 |
| 24008 | ATL::CRegObject.#3 | DEBUG | 8 |
| 26056 | ATL.AtlHresultFromLastError | DEBUG | 6 |
| 26088 | HRESULT_FROM_WIN32 | DEBUG | 1 |
| 26388 | ATL::CRegObject.#4 | DEBUG | 2 |
| 26568 | ATL.CSimpleStringT<wchar_t,0>.Concatenate | DEBUG | 4 |
| 27152 | PostPubEngineTrait.#0 | DEBUG | 2 |
| 27480 | ATL.CSimpleStringT<wchar_t,0>.GetBufferSetLength | DEBUG | 2 |
| 27592 | CBgPubModule.#4 | DEBUG | 3 |
| 27704 | CLyncCodeLayer.#5 | DEBUG | 2 |
| 27728 | CBgPubModule.#3 | DEBUG | 2 |
| 27740 | CLyncCodeLayer.#4 | DEBUG | 2 |
| 27764 | CLyncCodeLayer.#7 | DEBUG | 2 |
| 33148 | CBgPubModule.#1 | DEBUG | 2 |
| 33148 | Platform.Details.ControlBlock.IncrementStrongReference | DEBUG | 2 |
| 33704 | WTL::CMessageLoop.#1 | DEBUG | 2 |
| 35584 | WTL::CMessageLoop.#0 | DEBUG | 2 |
| 35716 | CLyncCodeLayer.#6 | DEBUG | 3 |
| 35764 | ATL.CRegKey.RecurseDeleteKey | DEBUG | 2 |
| 41440 | PostPubEngineTrait.#2 | DEBUG | 2 |
| 42328 | CBgPubModule.#2 | DEBUG | 2 |
| 43708 | CBgPubModule.#8 | DEBUG | 2 |
| 43716 | CBgPubModule.#9 | DEBUG | 2 |
| 43724 | DirectUI::ClassInfo<DirectUI::BaseScrollViewer,DirectUI::Element>.#0 | DEBUG | 5 |
| 51056 | ExportCallback.#1 | DEBUG | 2 |
| 51104 | OCExportToMovieTask.#3 | DEBUG | 2 |
| 52716 | OCExportToMovieTask.#6 | DEBUG | 3 |
| 55716 | ExportCallback.#0 | DEBUG | 3 |
| 56068 | OCExportToMovieTask.#4 | DEBUG | 2 |
| 56620 | OCExportToMovieTask.#5 | DEBUG | 2 |
| 58040 | CopyTask.#3 | DEBUG | 2 |
| 58288 | CopyTask.#6 | DEBUG | 2 |
| 58572 | CopyTask.#4 | DEBUG | 2 |
| 58968 | CopyTask.#5 | DEBUG | 3 |
| 61576 | COcListViewCtrl.#1 | DEBUG | 2 |
| 76944 | COcListViewCtrl.#0 | DEBUG | 2 |
| 79056 | COcListViewCtrl.#0 | DEBUG | 2 |
| 87248 | sprintf_s | DEBUG | 2 |
| 89260 | ATL.CStringT<wchar_t,StrTraitMFC<wchar_t,ATL::ChTraitsCRT<wchar_t>>>.operator= | DEBUG | 3 |
| 89588 | CMainDlg.#0 | DEBUG | 1 |
| 89600 | EventListener<PubEngineEvent>.#0 | DEBUG | 2 |
| 89660 | CMainDlg.#1 | DEBUG | 3 |
| 89708 | WTL::CMultiPaneStatusBarCtrl.#1 | DEBUG | 2 |
| 95388 | COcProgressBarCtrl.#2 | DEBUG | 3 |
| 106740 | CMainDlg.#0 | DEBUG | 3 |
| 110428 | CMainDlg.#0 | DEBUG | 2 |
| 110796 | WTL::CMultiPaneStatusBarCtrl.#0 | DEBUG | 2 |
| 110912 | CMainDlg.#0 | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 544496 | #0 |
| 455452 | sub_14006ff1c |
| 775012 | #1 |
| 268136 | sub_140042368 |
| 268964 | sub_1400426a4 |
| 652336 | #0 |
| 652860 | #0 |
| 653000 | #0 |
| 653268 | #0 |
| 652476 | #0 |
| 652604 | #0 |
| 652732 | #0 |
| 653140 | #0 |
| 612124 | sub_14009631c |
| 778904 | #1 |
| 254184 | #0 |
| 782432 | sub_1400bfc60 |
| 623540 | #0 |
| 603080 | #0 |
| 611452 | sub_14009607c |
| 611564 | sub_1400960ec |
| 611676 | sub_14009615c |
| 611788 | sub_1400961cc |
| 611900 | sub_14009623c |
| 612012 | sub_1400962ac |
| 612236 | sub_14009638c |
| 612348 | sub_1400963fc |
| 612460 | sub_14009646c |
| 612572 | sub_1400964dc |
| 612684 | sub_14009654c |

### Decompilations (top 6)
#### 544496 — #0
```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 DirectUI::HWNDElementAccessible.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x1400e7350])) ||
            ((*param_2 == IDispatch && (param_2[1] == [0x0x1400e7488])))) ||
           ((*param_2 == IAccessible && (param_2[1] == [0x0x1400f9d98])))) {
            *param_3 = param_1;
            (**(*param_1 + 8))();
            uVar1 = 0;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}

```
#### 455452 — sub_14006ff1c
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

uint64_t sub_14006ff1c(int64_t param_1,undefined8 *param_2,char param_3)

{
    uint32_t uVar1;
    int32_t iVar2;
    undefined8 uVar3;
    uint64_t uVar4;
    int64_t *piVar5;
    int64_t *piStackX_10;
    
    if (param_2 == 0x0) {
        return 0x80070057;
    }
    *param_2 = 0;
    if ((*(param_1 + 0x88) & 1) == 0) {
        return 0x80004005;
    }
    if (param_3 == '\0') {
        piVar5 = param_1 + 0x110;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar3 = (*user32.CallWindowProcW (delayed))
                          (*(param_1 + 0xb8), *(param_1 + 0xa8), 0x3d, 0xffffffff, 0xfffffffffffffffc);
        iVar2 = jmp_oleacc.ObjectFromLresult (delayed)(uVar3, &IAccessible, 0xffffffff, &piStackX_10);
        if (iVar2 < 0) {
            uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)
                              (*(param_1 + 0xa8), 0xfffffffc, &IAccessible, &piStackX_10);
            if (uVar1 < 0) {
                return uVar1;
            }
        }
        uVar1 = sub_1400853e4(param_1, piStackX_10, piVar5);
    }
    else {
        piVar5 = param_1 + 0x98;
        if (*piVar5 != 0) goto code_r0x000140070045;
        uVar1 = jmp_oleacc.CreateStdAccessibleObject (delayed)(*(param_1 + 0xa8), 0, &IAccessible, &piStackX_10);
        if (uVar1 < 0) {
            return uVar1;
        }
        uVar1 = sub_140085340(param_1, piStackX_10, piVar5);
    }
    (**(*piStackX_10 + 0x10))();
    if (uVar1 < 0) {
        return uVar1;
    }
code_r0x000140070045:
    uVar4 = (****piVar5)(*piVar5, &IAccessible, param_2);
    return uVar4;
}

```
#### 775012 — #1
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 *
DirectUI::GridLayout.#1
          (int64_t param_1,undefined8 *param_2,int64_t param_3,uint32_t param_4,uint32_t param_5,undefined8 param_6)

{
    int64_t **ppiVar1;
    undefined8 uVar2;
    uint32_t uVar3;
    int32_t iVar4;
    int64_t iVar5;
    int64_t iVar6;
    uint32_t *puVar7;
    uint32_t *puVar8;
    int32_t *piVar9;
    undefined8 uVar10;
    uint64_t uVar11;
    uint32_t *puVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint64_t uVar15;
    uint64_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    int64_t *piVar20;
    int32_t iVar21;
    uint64_t uVar22;
    uint32_t *puVar23;
    uint32_t uVar24;
    undefined8 uStackX_18;
    uint32_t uStackX_20;
    uint32_t uStack_a8;
    int32_t iStack_a4;
    int64_t iStack_a0;
    int64_t iStack_98;
    uint32_t uStack_90;
    int32_t iStack_88;
    uint32_t uStack_84;
    uint32_t uStack_70;
    uint32_t uStack_6c;
    undefined8 uStack_68;
    int32_t *piStack_60;
    int64_t iStack_58;
    
    *(param_1 + 0x18) = 1;
    uVar3 = sub_1400d0814();
    uVar16 = uVar3;
    if ((*(param_3 + 0x88) & 4) == 0) {
        iVar5 = *([0x0x140150458] + 0x20);
    }
    else {
        iVar5 = sub_140077720(param_3, [0x0x140150458], 2);
    }
    uVar2 = *(iVar5 + 8);
    if ((*(param_1 + 0x28) & 2) == 0) {
        uVar16 = *(param_1 + 0x20);
    }
    else {
        uVar24 = *(param_1 + 0x24);
        if (uVar24 != 1) {
            uVar16 = ((uVar24 - 1) + uVar3) / uVar24;
        }
    }
    if ((*(param_1 + 0x28) & 1) == 0) {
        uVar24 = *(param_1 + 0x24);
    }
    else {
        uVar19 = *(param_1 + 0x20);
        uVar24 = uVar3;
        if (uVar19 != 1) {
            uVar24 = ((uVar19 - 1) + uVar3) / uVar19;
        }
    }
    ppiVar1 = param_1 + 0x30;
    if (*ppiVar1 != 0x0) {
        (*kernel32.HeapFree)();
        *ppiVar1 = 0x0;
    }
    if (*(param_1 + 0x38) != 0) {
        (*kernel32.HeapFree)();
        *(param_1 + 0x38) = 0;
    }
    uVar19 = uVar16;
    if ((uVar19 == 0) || (uVar24 == 0)) {
code_r0x0001400be79c:
        if ((*(iVar5 + 4) != -1) && (iVar4 = *(iVar5 + 4) + -1, *(iVar5 + 4) = iVar4, iVar4 == 0)) {
            Concurrency.details.SchedulerBase.SweepSchedulerForFinalize(iVar5);
        }
        *param_2 = 0;
        return param_2;
    }
    if (1 < uVar24) {
        iVar6 = (*kernel32.HeapAlloc)();
        *ppiVar1 = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    if (1 < uVar19) {
        iVar6 = (*kernel32.HeapAlloc)();
        *(param_1 + 0x38) = iVar6;
        if (iVar6 == 0) goto code_r0x0001400be79c;
    }
    uVar14 = 0;
    uStack_a8 = 0;
    if (uVar3 != 0) {
        uVar18 = uVar24 - 1;
        uVar17 = 0;
        if (uVar18 != 0) {
            if (3 < uVar18) {
                piVar20 = *ppiVar1;
                if ((ppiVar1 < piVar20) || (piVar20 + (uVar24 - 2) * 4 < ppiVar1)) {
                    uVar13 = uVar18 - (uVar18 & 3);
                    do {
                        uVar17 = uVar17 + 4;
                    } while (uVar17 < uVar13);
                    for (uVar15 = ((uVar13 + 3 >> 2) << 4) >> 2; uVar15 != 0; uVar15 = uVar15 - 1) {
                        *piVar20 = 0x80000001;
                        piVar20 = piVar20 + 4;
                    }
                }
            }
            if (uVar17 < uVar18) {
                iVar6 = uVar17 << 2;
                uVar15 = uVar18 - uVar17;
                do {
                    *(iVar6 + *ppiVar1) = 0x80000001;
                    iVar6 = iVar6 + 4;
                    uVar15 = uVar15 - 1;
                } while (uVar15 != 0);
            }
        }
        uVar17 = 0;
        if (uVar19 != 0) {
            iStack_a0 = 0;
            do {
                if (uVar17 < uVar19 - 1) {
                    *(iStack_a0 + *(param_1 + 0x38)) = 0x80000001;
                }
                uVar15 = 0;
                if (uVar24 != 0) {
                    iSt
```

### Carved Files (16)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 270376 |
| ? | DIB | 38056 |
| ? | DIB | 26600 |
| ? | DIB | 21640 |
| ? | DIB | 16936 |
| ? | DIB | 14920 |
| ? | DIB | 9640 |
| ? | DIB | 6760 |
| ? | DIB | 4264 |
| ? | DIB | 2440 |
| ? | DIB | 1720 |
| ? | DIB | 1128 |
| ? | PNG | 3214 |
| ? | PNG | 3359 |
| ? | PNG | 3589 |
| ? | PKCS7 | 6861 |

### Virtual Files (20)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| PNG/5027/en-us | 3214 | - |
| PNG/5028/en-us | 3359 | - |
| PNG/5029/en-us | 3589 | - |
| WEVT_TEMPLATE/1/en-us | 1390 | - |
| ICO/1/en-us | 270376 | - |
| ICO/2/en-us | 38056 | - |
| ICO/3/en-us | 26600 | - |
| ICO/4/en-us | 21640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 14920 | - |
| ICO/7/en-us | 9640 | - |
| ICO/8/en-us | 6760 | - |
| ICO/9/en-us | 4264 | - |
| ICO/10/en-us | 2440 | - |
| ICO/11/en-us | 1720 | - |
| ICO/12/en-us | 1128 | - |
| MSG/1/en-us | 168 | - |
| GRPICO/202/en-us | 174 | - |
| VER/1/en-us | 1124 | - |
| MANIF/1/en-us | 771 | - |

### Structures (156)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 280 |
| OptionalHeader | 304 |
| Sections | 544 |
| DebugDirectory | 886004 |
| Debug.Reserved10 | 886088 |
| Debug.Codeview | 886092 |
| advapi32.FT | 889856 |
| gdiplus.FT | 890056 |
| kernel32.FT | 890608 |
| ole32.FT | 891688 |
| oleaut32.FT | 891800 |
| vcruntime140.FT | 891944 |
| msvcp140.FT | 892064 |
| api-ms-win-crt-heap-l1-1-0.FT | 892096 |
| api-ms-win-crt-runtime-l1-1-0.FT | 892144 |
| api-ms-win-crt-string-l1-1-0.FT | 892320 |
| api-ms-win-crt-stdio-l1-1-0.FT | 892432 |
| api-ms-win-crt-utility-l1-1-0.FT | 892480 |
| api-ms-win-crt-math-l1-1-0.FT | 892496 |
| api-ms-win-crt-locale-l1-1-0.FT | 892568 |
| api-ms-win-crt-convert-l1-1-0.FT | 892592 |
| api-ms-win-crt-filesystem-l1-1-0.FT | 892624 |
| msimg32.FT | 892640 |
| mfreadwrite.FT | 892672 |
| GuardCFCheckFunctionPointer | 892704 |
| GuardCFDispatchFunctionPointer | 892712 |
| TlsCallbacks | 893328 |
| SecurityCookie | 943432 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 47 · duration_s: 4.6

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| encrypt data using chaskey | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| check for time delay via GetTickCount |  | B0001.032:Debugger Detection |

## PE Imports / Signals
import_count: 338

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 18

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@1939956 len=7; $ipv6@924622 len=10 |
| contains_base64 | - | $a@23547 len=12 |
| Dropper_Strings | - | $a0@892806 len=36 |
| url | - | $url_regex@943520 len=90 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@1960448 len=105 |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@264 len=4 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@1177844 len=12; $c2@1184736 len=17; $c3@1184674 len=17 |
| screenshot | - | $d1@1169600 len=9; $d2@1169760 len=10; $c1@1173352 len=6; $c2@1174814 len=5 |
| keylogger | - | $f1@1169760 len=10; $c2@1176500 len=11; $c3@1175332 len=13 |
| win_mutex | - | $c1@1183286 len=11 |
| win_registry | - | $f1@1177872 len=12; $c3@1180754 len=11; $c6@1180754 len=11 |
| win_files_operation | - | $f1@1177844 len=12; $c1@1183574 len=9; $c3@1183574 len=9; $c4@1183146 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2",
  "family": "unknown",
  "generated_at": "2026-08-05T08:03:22.254933+00:00",
  "string_count": 24,
  "strings": [
    "?OCREC_GetPostPublishJobDirectoryManager@@YAJAEAV?$CRefCountedPtr@UITaskDirectoryManager@@@@@Z",
    "Microsoft\u00ae is a registered trademark of Microsoft Corporation.",
    "Windows\u00ae is a registered trademark of Microsoft Corporation.",
    "P:\\Target\\x64\\ship\\lync\\x-none\\ocpubmgr.pdb",
    "_register_thread_local_exe_atexit_callback",
    "Skype for Business Recording Manager 2015",
    "InitializeCriticalSectionAndSpinCount",
    "CreateXmlReaderInputWithEncodingName",
    "api-ms-win-crt-filesystem-l1-1-0.dll",
    "GdipSetStringFormatDigitSubstitution",
    "__initialize_lconv_for_unsigned_char",
    "__vcrt_InitializeCriticalSectionEx",
    "_invalid_parameter_noinfo_noreturn",
    "MFCreateSourceReaderFromByteStream",
    "api-ms-win-crt-convert-l1-1-0.dll",
    "api-ms-win-crt-utility-l1-1-0.dll",
    "api-ms-win-crt-runtime-l1-1-0.dll",
    "GdipSetImageAttributesColorMatrix",
    "GdipGetGenericFontFamilySansSerif",
    "api-ms-win-crt-locale-l1-1-0.dll",
    "api-ms-win-crt-string-l1-1-0.dll",
    "GdipGetFontCollectionFamilyCount",
    "api-ms-win-crt-stdio-l1-1-0.dll",
    "GdipSetStringFormatHotkeyPrefix"
  ],
  "rule_path": "/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yar",
  "sigma_path": "/opt/samples/logs/669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2/rule.yml",
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
  "revai": true,
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 6108 · per_category: `{"decoded_strings": 0, "stack_strings": 1, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 6107}`

### FLOSS sample
- `VirtualAlloc`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.reloc`
- `9y@~'3`
- `x`;{@}[H`
- `WAVAWH`
- `fA9<@u`
- `0A_A^_`
- `t$ UWAVH`
- `x ATAVAWH`
- `0A_A^A\`
- `AUAVAWH`
- `A_A^A]`
- `K SUVWAVAWH`
- `8A_A^_^][`
- `SVWAVAWH`
- `0A_A^_^[`
- `SUVWATAVAWH`
- `A_A^A\_^][`
- `UVWATAUAVAWH`
- `fA94Gu`
- `@A_A^A]A\_^]`
- `SVWATAUAVAW`
- `D$xH9D$ptQH`
- `A_A^A]A\_^[`
- `A_A^A\`
- `WATAUAVAWH`
- `Hcl$pE3`
- `A_A^A]A\_`
- `Y@H9;u$L`
- `VWAUAVAW`
- `t0L93t`
- `fD9s*v%`
- `A_A^A]_^`
- `!\$ E3`
- `fD;0tsH`
- `fD;8u^H`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x140030a68
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x140030a68      e848feffff     call fcn.1400308b5
│           0x140030a6d      c8200000       enter 0x20, 0              ; 32
│           0x140030a71      4c897c24f8     mov qword [rsp - 8], r15
│           0x140030a76      4883ec08       sub rsp, 8
│           0x140030a7a      4989e7         mov r15, rsp
│           0x140030a7d      4883ec20       sub rsp, 0x20
│           0x140030a81      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x140030a85      4831f6         xor rsi, rsi
│           0x140030a88      4801c6         add rsi, rax
│           0x140030a8b      4883c03c       add rax, 0x3c              ; 60
│           0x140030a8f      4831d2         xor rdx, rdx
│           0x140030a92      8b10           mov edx, dword [rax]
│           0x140030a94      4883ec08       sub rsp, 8
│           0x140030a98      48893424       mov qword [rsp], rsi
│           0x140030a9c      488b0424       mov rax, qword [rsp]
│           0x140030aa0      4883c408       add rsp, 8
│           0x140030aa4      4801d0         add rax, rdx
│           0x140030aa7      480588000000   add rax, 0x88              ; 136
│           0x140030aad      4883ec08       sub rsp, 8
│           0x140030ab1      48890424       mov qword [rsp], rax
│           0x140030ab5      488b0c24       mov rcx, qword [rsp]
│           0x140030ab9      4883c408       add rsp, 8
│           0x140030abd      48c7c00000..   mov rax, 0
│           0x140030ac4      8b01           mov eax, dword [rcx]
│           0x140030ac6      4801f0         add rax, rsi
│           0x140030ac9      50             push rax
│           0x140030aca      488b0c24       mov rcx, qword [rsp]
│           0x140030ace      4883c408       add rsp, 8
│           0x140030ad2      56             push rsi
│           0x140030ad3      488b1424       mov rdx, qword [rsp]
│           0x140030ad7      4883c408       add rsp, 8
│           0x140030adb      488d05acf3..   lea rax, [0x14002fe8e]
│           0x140030ae2      4883ec08       sub rsp, 8
│           0x140030ae6      48890c24       mov qword [rsp], rcx
│           0x140030aea      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140030af1      4883ec08       sub rsp, 8
│           0x140030af5      48890c24       mov qword [rsp], rcx
│           0x140030af9      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140030b00      48ffc0         inc rax
│       ╎   0x140030b03      48ffc9         dec rcx
│       ╎   0x140030b06      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x140030b0d      75f1           jne 0x140030b00
│           0x140030b0f      4883c408       add rsp, 8
│           0x140030b13      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140030b18      488b0c24       mov rcx, qword [rsp]
│           0x140030b1c      4883c408       add rsp, 8
│           0x140030b20      ffd0           call rax
│           0x140030b22      
```
### 0x1400308b5
```asm
; CALL XREF from entry0 @ 0x140030a68(x)
┌ 446: fcn.1400308b5 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x1400308b5      488b442408     mov rax, qword [var_8h]
│           0x1400308ba      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x1400308be      48ffc8         dec rax
│      ╎╎   0x1400308c1      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x1400308c6      750b           jne 0x1400308d3
│    ┌────< 0x1400308c8      7414           je 0x1400308de
│    ││╎╎   0x1400308ca      e85e000000     call 0x14003092d
│    ││╎╎   0x1400308cf      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x1400308d1      9f             lahf
│    ││╎╎   0x1400308d2      5e             pop rsi
│    │└└──< 0x1400308d3      75e9           jne 0x1400308be
│    │  ╎   0x1400308d5      e8fcffffff     call 0x1400308d6
│    │  ╎   0x1400308da      8bcf           mov ecx, edi
│    │  ╎   0x1400308dc  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x1400308de      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x1400308e1      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x1400308e7      73d5           jae 0x1400308be
│           0x1400308e9      482db5480000   sub rax, 0x48b5
│           0x1400308ef      4801c2         add rdx, rax
│           0x1400308f2      4881c2b548..   add rdx, 0x48b5
│           0x1400308f9      4805b5480000   add rax, 0x48b5
│           0x1400308ff      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140030904      7506           jne 0x14003090c
│      ┌──< 0x140030906      7442           je 0x14003094a
│      ││   0x140030908      82             invalid
..
│      │└─> 0x14003090c      744d           je 0x14003095b
│      │    0x14003090e      75ae           jne 0x1400308be
│      │    0x140030910      488d05cdfe..   lea rax, [0x1400307e4]
│      │    0x140030917      4883ec08       sub rsp, 8
│      │    0x14003091b      48890c24       mov qword [rsp], rcx
│      │    0x14003091f      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x140030926      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.1400308b5 @ 0x1400308ca(x)
│      │    0x14003092d      4801c1         add rcx, rax
│      │    0x140030930      51             push rcx
│      │    0x140030931      4891           xchg r
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000118 ........!..L.!This program cannot be r

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
  - `ADVAPI32.dll!TraceMessage`
  - `ADVAPI32.dll!RegCloseKey`
  - `ADVAPI32.dll!RegCreateKeyExW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `gdiplus.dll!GdipDrawRectangleI`
  - `gdiplus.dll!GdipCreateLineBrushFromRect`
  - `gdiplus.dll!GdipCreateTexture`
  - `gdiplus.dll!GdipBitmapGetPixel`
  - `gdiplus.dll!GdipCloneBitmapAreaI`
  - `KERNEL32.dll!GetModuleHandleW`
  - `KERNEL32.dll!GetModuleHandleExW`
  - `KERNEL32.dll!GetProcAddress`
  - `KERNEL32.dll!LoadLibraryW`
  - `KERNEL32.dll!CreateActCtxW`
  - `ole32.dll!CreateStreamOnHGlobal`
  - `ole32.dll!CoDisconnectObject`
  - `ole32.dll!CLSIDFromProgID`
  - `ole32.dll!ProgIDFromCLSID`
  - `ole32.dll!CLSIDFromString`
  - `OLEAUT32.dll!SysAllocStringByteLen`
  - `OLEAUT32.dll!SysStringByteLen`
  - `OLEAUT32.dll!SysStringLen`
  - `OLEAUT32.dll!SysAllocString`
  - `OLEAUT32.dll!VarUI4FromStr`
  - `VCRUNTIME140.dll!memcmp`
  - `VCRUNTIME140.dll!__vcrt_InitializeCriticalSectionEx`
  - `VCRUNTIME140.dll!__std_terminate`
  - `VCRUNTIME140.dll!__C_specific_handler`
  - `VCRUNTIME140.dll!__CxxFrameHandler3`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785916169.5715353}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785916172.2345746}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785916172.3670523}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785916172.4355962}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785916448.9995265}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785916449.158988}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785916453.3061986}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785916453.3816085}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785916453.4031084}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785916964.9945407}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE size > 100 ORDER BY size DESC LIMIT 20", "ts": 1785916970.4377937}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 20 ORDER BY length DESC LIMIT 30", "ts": 1785916970.4841967}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE module NOT LIKE '%msvc%' AND module NOT LIKE '%kernel32%' AND module NOT LIKE '%user32%' AND module NOT LIKE '%advapi32%' AND module NOT LIKE '%ws2_32%' AND module NOT LIKE '%wininet%' AND module NOT LIKE '%shell32%' `
- `{"source": "ghidra_query", "sql": "SELECT COUNT(*) as func_count FROM funcs", "ts": 1785916976.315795}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%ftp%' OR content LIKE '%cmd%' OR content LIKE '%powershell%' OR content LIKE '%shell%' OR content LIKE '%exec%' OR content LIKE '%CreateProcess%' OR content LIKE '%WinExec%' `
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%.exe%' OR content LIKE '%.dll%' OR content LIKE '%.sys%' OR content LIKE '%temp%' OR content LIKE '%tmp%' OR content LIKE '%AppData%' OR content LIKE '%ProgramData%' OR content LIKE '%Startup%' OR co`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE name IN ('CreateRemoteThread','WriteProcessMemory','ReadProcessMemory','VirtualAllocEx','SetWindowsHookEx','GetAsyncKeyState','RegSetValueEx','InternetOpenUrl','URLDownloadToFile','WinHttpOpen','CryptEncrypt','CryptDe`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module IN ('WININET.DLL','URLMON.DLL','WINHTTP.DLL','CRYPT32.DLL','ADVAPI32.DLL','WS2_32.DLL') LIMIT 50", "ts": 1785916983.0306938}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785917001.1814423}`
- `{"source": "yara_gen_v2", "ts": 1785917002.2553382}`
