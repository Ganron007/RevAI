## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=4660766415cdc4a6 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X64, entropy=226, sha256=4660766415cdc4a6ff3bffb20f35c6f3a7ccfd494816b1a135de8c11e7151860
  Anomalies (16): BigBufferNoXrefMediumToHighEntropy×33 (entropy), CrossSectionJump (code), ExecutableSectionNoCode×2 (sections), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), HugeFunctionGapAtSectionBoundary (code), InvalidBaseOfCode (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), NoChecksum (integrity), Packed (packers), PatchedUPXHeader (packers), PurelyVirtualExecutableSection (sections), SectionNameUnknown (sections), SectionWX×2 (sections), TimeDateStampZero (time)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@220; NoChecksum@216
  YARA (info, 2 total): UPX, upx_39x_lzma_x64
  Functions (1): EntryPoint@4311376
  Top high-signal imports (score≥8, 1 of 4):
    [8] kernel32.VirtualProtect
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 1 omitted)
  Strings/apis (3 total): GetProcAddress, LoadLibraryA, VirtualProtect
  Strings (other, 297 items, omitted)
  Recovered structures (8): MZ, PE, OptionalHeader, Sections, ExceptionTable, ImportTable, kernel32.FT, ImportNames
  Decompilations (1 top functions):
    ### 4311376 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Software Packing'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Software Packing', 'id': 'T1027.002'} (1): packed with UPX
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): link function at runtime on Windows
  All rules (1): terminate process

## pe_imports (4 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  change_memory_protection (VirtualProtect) [T1055]

## YARA matches (7)
  Rules: domain, IP, contains_base64, IsPE64, IsWindowsGUI, IsPacked, suspicious_packer_section

## FLOSS strings (7237 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x142efd750
```c
┌ 2952: entry0 (int64_t arg_ch, int64_t arg_10h, int64_t arg_20h);
│       ╎   ; var int64_t var_1h @ rbp+0x1
│       ╎   ; arg int64_t arg_ch @ rsp+0x104
│       ╎   ; arg int64_t arg_10h @ rsp+0x108
│       ╎   ; arg int64_t arg_20h @ rsp+0x118
│       ╎   ; var int64_t var_4h @ rsp+0x4
│       ╎   ; var int64_t var_8h @ rsp+0x8
│       ╎   ; var int64_t var_ch @ rsp+0xc
│       ╎   ; var int64_t var_10h @ rsp+0x10
│       ╎   ; var int64_t var_14h @ rsp+0x14
│       ╎   ; var int64_t var_18h @ rsp+0x18
│       ╎   ; var int64_t var_1ch @ rsp+0x1c
│       ╎   ; var int64_t var_20h @ rsp+0x20
│       ╎   ; var int64_t var_2ch @ rsp+0x2c
│       ╎   ; var int64_t var_30h @ rsp+0x30
│       ╎   ; var int64_t var_38h @ rsp+0x38
│       ╎   ; var int64_t var_40h @ rsp+0x40
│       ╎   ; var int64_t var_80h @ rsp+0x80
│       ╎   ; var int64_t var_20h_2 @ rsp+0x88
│       ╎   0x142efd750      53             push rbx
│       ╎   0x142efd751      56             push rsi
│       ╎   0x142efd752      57             push rdi
│       ╎   0x142efd753      55             push rbp
│       ╎   0x142efd754      488d35ca38..   lea rsi, [0x142ae1025]
│       ╎   0x142efd75b      488dbedbff..   lea rdi, [rsi - 0x2ae0025]
│       ╎   0x142efd762      57             push rdi
│       ╎   0x142efd763      b8a1b0ef02     mov eax, 0x2efb0a1
│       ╎   0x142efd768      50             push rax
│       ╎   0x142efd769      4889e1         mov rcx, rsp
│       ╎   0x142efd76c      4889fa         mov rdx, rdi
│       ╎   0x142efd76f      4889f7         mov rdi, rsi
│       ╎   0x142efd772      be26c74100     mov esi, 0x41c726
│       ╎   0x142efd777      55             push rbp
│       ╎   0x142efd778      4889e5         mov rbp, rsp
│       ╎   0x142efd77b      448b09         mov r9d, dword [rcx]
│       ╎   0x142efd77e      4989d0         mov r8, rdx
│       ╎   0x142efd781      4889f2         mov rdx, rsi
│       ╎   0x142efd784      488d7702       lea rsi, [rdi + 2]
│       ╎   0x142efd788      56             push rsi
│       ╎   0x142efd789      8a07           mov al, byte [rdi]
│       ╎   0x142efd78b      ffca           dec edx
│       ╎   0x142efd78d      88c1           mov cl, al
│       ╎   0x142efd78f      2407           and al, 7
│       ╎   0x142efd791      c0e903         shr cl, 3
│       ╎   0x142efd794      48c7c300fd..   mov rbx, 0xfffffffffffffd00
│       ╎   0x142efd79b      48d3e3         shl rbx, cl
│       ╎   0x142efd79e      88c1           mov cl, al
│       ╎ 
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 4982/60000 chars across 9 tools -->