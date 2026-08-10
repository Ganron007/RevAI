## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=3476906b2c724a60 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=224, sha256=3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544
  Anomalies (15): BigBufferNoXrefMediumToHighEntropy×2 (entropy), CrossSectionJump (code), DllNoRelocation (sections), DuplicatedSectionName×4 (sections), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary×2 (code), HugeGapBetweenFunctions×83 (code), InvalidSizeOfCode (sections), ManyHighValueImmediates×4 (code), PurelyVirtualExecutableSection (sections), SectionMostlyVirtual (sections), SectionNameUnknown×7 (sections), SectionWX (sections), UnbalancedVirtualPhysicalRatio (sections), UnreferencedImports×3 (imports)
  High-signal anomaly locations: ManyHighValueImmediates@51727,1286388,1518970
  YARA (info, 1 total): MSVC_2022_linker
  Functions (15): sub_105f197a@1518970, sub_104fdc27@520231, sub_106410b2@1844402, sub_1050d604@584196, sub_1000d60f@51727, sub_106bc784@2349956, sub_105b8cf4@1286388, sub_10617c8e@1675406, sub_1057665c@1014364, sub_10538a66@761446, sub_10016f71@90993, sub_1073d878@2878584, sub_104e67d2@424914, sub_10626734@1735476, sub_1000c596@47510
  Mid-signal imports: advapi32.OpenProcessToken, kernel32.GetModuleHandleA
  (low-signal/noise imports: 1 omitted)
  Strings/apis (3 total): InitializeSecurity, OpenProcessToken, GetModuleHandleA
  Strings (other, 297 items, omitted)
  Recovered structures (16): MZ, RichHeader, PE, OptionalHeader, Sections, ExportDirectory, ExportNames, OrdinalNameTable, ExportNames, ExportAddressTable, ExportNameTable, ImportNames, ImportTable, kernel32.FT, user32.FT
  Decompilations (3 top functions):
    ### 1518970 (sub_105f197a, score=?)
```c
sub_105f197a {
    // Error while decompiling : not a valid va
}
```
    ### 520231 (sub_104fdc27, score=?)
```c
/* WARNING: Control flow encountered bad instruction data */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_104fdc27(void)

{
    char cVar1;
    undefined4 *puVar2;
    undefined4 *unaff_EBP;
    undefined4 uStack_8;
    
    puVar2 = &stack0xfffffffc;
    cVar1 = '\b';
    do {
        unaff_EBP = unaff_EBP + -1;
        puVar2 = puVar2 + -1;
        *puVar2 = *unaff_EBP;
        cVar1 = cVar1 + -1;
    } while ('\0' < cVar1);
    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}
```
    ### 1844402 (sub_106410b2, score=?)
```c
sub_106410b2 {
    // Error while decompiling : not a valid va
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with Themida
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): forwarded export
  All rules (1): decompress data using aPLib

## pe_imports (3 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (10)
  Rules: domain, IP, contains_base64, CRC32_poly_Constant, IsPE32, IsDLL, IsWindowsGUI, IsPacked, HasRichSignature, win_token

## FLOSS strings (5014 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x104d3058
```c
┌ 336: entry0 ();
│           0x104d3058      e84b010000     call 0x104d31a8
│           0x104d305d      53             push ebx
│           0x104d305e      89e3           mov ebx, esp
│           0x104d3060      53             push ebx
│           0x104d3061      8b7308         mov esi, dword [ebx + 8]
│           0x104d3064      8b7b10         mov edi, dword [ebx + 0x10]
│           0x104d3067      fc             cld
│           0x104d3068      b280           mov dl, 0x80                ; 128
│       ┌─> 0x104d306a      8a06           mov al, byte [esi]
│       ╎   0x104d306c      46             inc esi
│       ╎   0x104d306d      8807           mov byte [edi], al
│       ╎   0x104d306f      47             inc edi
│       ╎   0x104d3070      bb02000000     mov ebx, 2
│       ╎   ; CODE XREFS from entry0 @ 0x104d30da(x), 0x104d3123(x), 0x104d3163(x), 0x104d3178(x), 0x104d3199(x)
│  ┌┌┌┌┌──> 0x104d3075      00d2           add dl, dl
│ ┌───────< 0x104d3077      7505           jne 0x104d307e
│ │╎╎╎╎╎╎   0x104d3079      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎╎   0x104d307b      46             inc esi
│ │╎╎╎╎╎╎   0x104d307c      10d2           adc dl, dl
│ └─────└─< 0x104d307e      73ea           jae 0x104d306a
│  ╎╎╎╎╎    0x104d3080      00d2           add dl, dl
│  ╎╎╎╎╎┌─< 0x104d3082      7505           jne 0x104d3089
│  ╎╎╎╎╎│   0x104d3084      8a16           mov dl, byte [esi]
│  ╎╎╎╎╎│   0x104d3086      46             inc esi
│  ╎╎╎╎╎│   0x104d3087      10d2           adc dl, dl
│ ┌─────└─> 0x104d3089      7351           jae 0x104d30dc
│ │╎╎╎╎╎    0x104d308b      31c0           xor eax, eax
│ │╎╎╎╎╎    0x104d308d      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d308f      7505           jne 0x104d3096
│ │╎╎╎╎╎│   0x104d3091      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d3093      46             inc esi
│ │╎╎╎╎╎│   0x104d3094      10d2           adc dl, dl
│ ──────└─> 0x104d3096      0f83e1000000   jae 0x104d317d
│ │╎╎╎╎╎    0x104d309c      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d309e      7505           jne 0x104d30a5
│ │╎╎╎╎╎│   0x104d30a0      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30a2      46             inc esi
│ │╎╎╎╎╎│   0x104d30a3      10d2           adc dl, dl
│ │╎╎╎╎╎└─> 0x104d30a5      11c0           adc eax, eax
│ │╎╎╎╎╎    0x104d30a7      00d2           add dl, dl
│ │╎╎╎╎╎┌─< 0x104d30a9      7505           jne 0x104d30b0
│ │╎╎╎╎╎│   0x104d30ab      8a16           mov dl, byte [esi]
│ │╎╎╎╎╎│   0x104d30ad      46 
```
  ### 0x10019110
```c
┌ 110: sym.StringLoaderA.dll_InitializeSecurity (int32_t arg_65h);
│      ╎╎   ; arg int32_t arg_65h @ ebp+0x65
│      ╎╎   ; var int32_t var_3eh @ ebp-0x3e
│      ╎╎   0x10019110      2c52           sub al, 0x52                ; 82
│      ╎╎   0x10019112      54             push esp
│      ╎╎   0x10019113      50             push eax
│      ╎╎   0x10019114  ~   3ed09f6b59..   rcr byte ds:[edi - 0x43b3a695], 1
│     ┌───> 0x1001911a      bce63478ed     mov esp, 0xed7834e6
│     ╎ ╎   0x1001911f      b103           mov cl, 3
│     ╎ ╎   0x10019121      92             xchg edx, eax
│     ╎ ╎   0x10019122      baa6f7e81a     mov edx, 0x1ae8f7a6
│     ╎ ╎   0x10019127      6a03           push 3                      ; 3
│     ╎ ╎   0x10019129      3ea7           cmpsd dword ds:[esi], dword es:[edi]
│     ╎ ╎   0x1001912b      4c             dec esp
│     ╎ ╎   0x1001912c      1490           adc al, 0x90
│     ╎ ╎   0x1001912e      ff01           inc dword [ecx]
│     ╎ ╎   0x10019130      dabbd42fca48   fidivr dword [ebx + 0x48ca2fd4]
│     ╎ ╎   0x10019136      44             inc esp
│     └───< 0x10019137      7de1           jge 0x1001911a
│       ╎   0x10019139      a5             movsd dword es:[edi], dword [esi]
│       ╎   0x1001913a      bcfbb49fcd     mov esp, 0xcd9fb4fb
│      ┌──< 0x1001913f      787c           js 0x100191bd
│      │╎   0x10019141      62952f766976   bound edx, qword [ebp + 0x7669762f]
│      │╎   0x10019147      6d             insd dword es:[edi], dx
│      │╎   0x10019148      ed             in eax, dx
│      │╎   0x10019149      0cc4           or al, 0xc4                 ; 196
│      │╎   0x1001914b      5a             pop edx
│      │╎   0x1001914c      c165c2ff       shl dword [var_3eh], 0xff
│      │╎   0x10019150      94             xchg esp, eax
│      │╎   0x10019151      e7c5           out 0xc5, eax
│      │╎   0x10019153      9a12903ce8..   lcall 0xce34, 0xe83c9012
│      │╎   0x1001915a      b076           mov al, 0x76                ; 'v' ; 118
│      │╎   0x1001915c      0296ab586a57   add dl, byte [esi + 0x576a58ab]
│      │╎   0x10019162      9d             popfd
│      │╎   0x10019163      bd0776dc75     mov ebp, 0x75dc7607
│      │╎   0x10019168      57             push edi
│      │╎   0x10019169      2127           and dword [edi], esp
│      │╎   0x1001916b      df             invalid
..
│      └──> 0x100191bd      8e4565         mov es, word [arg_65h]
│       │   0x100191c0      ed             in eax, dx
│       │
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000F8 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 8486/60000 chars across 9 tools -->