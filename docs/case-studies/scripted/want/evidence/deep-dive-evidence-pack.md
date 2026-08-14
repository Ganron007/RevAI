## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=d52f0647e519edce | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=223, sha256=d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09
  Anomalies (10): BigBufferNoXrefMediumToHighEntropy×3 (entropy), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), MultiplePackers (packers), Packed (packers), SectionWX×2 (sections), UnbalancedVirtualPhysicalRatio (sections), UnreferencedImports×4 (imports)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@324
  YARA (info, 4 total): MSVC_2017_linker, visual_studio_2017_version_15_0_rich, PECompact2, pecompact_2xx
  Functions (2): EntryPoint@1024, sub_429d8c@168332
  Top high-signal imports (score≥8, 1 of 4):
    [8] kernel32.VirtualAlloc
  Mid-signal imports: kernel32.LoadLibraryA, kernel32.GetProcAddress
  (low-signal/noise imports: 1 omitted)
  Strings/apis (4 total): GetProcAddress, LoadLibraryA, VirtualAlloc, VirtualFree
  Strings (other, 296 items, omitted)
  Recovered structures (9): MZ, RichHeader, PE, OptionalHeader, Sections, kernel32.OFT, ImportTable, ImportNames, Relocations
  Decompilations (2 top functions):
    ### 1024 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid va
}
```
    ### 168332 (sub_429d8c, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 sub_429d8c(int32_t param_1)

{
    undefined *puVar1;
    
    [0x0x429db0] = 0xf0428b11;
    puVar1 = *(param_1 + 0xc);
    *puVar1 = 0xe9;
    *(puVar1 + 1) = 0x429daf - (puVar1 + 5);
    return 0;
}
```

## capa
  incomplete: capa returned empty rules


## pe_imports (4 imports, 3 high-signal)
  load_library (LoadLibrary) [T1129]
  get_proc_address (GetProcAddress) [T1129]
  allocate_memory (VirtualAlloc) [T1055]

## YARA matches (26)
  Rules: domain, contains_base64, PECompactV2XBitsumTechnologies, PECompact2xxBitSumTechnologies, PECompactv2xx, pecompact2, IsPE32, IsWindowsGUI, IsPacked, HasRichSignature, PeCompact_v208_Bitsum_Technologiessignature_by_loveboom, PECompact_2x_Jeremy_Collake, PECompact_20x_Heuristic_Mode_Jeremy_Collake, PECompact_2xx_BitSum_Technologies, PECompact_v2xx, PECompact_V2X_Bitsum_Technologies_additional, PECompact_V2X_Bitsum_Technologies, PECompact_v20_additional, PeCompact_2xx_BitSum_Technologies, PeCompact_253_DLL_BitSum_Technologies_additional, PECompact_v20, PeCompact_253_DLL_BitSum_Technologies, PECompact_v2xx_additional, suspicious_packer_section, SEH_Save

## FLOSS strings (148 total)
  (other strings, 80 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00401000
```c
;-- section..text:
┌ 114: entry0 ();
│           0x00401000      b88c9d4200     mov eax, 0x429d8c           ; [00] -rwx section size 163840 named .text
│           0x00401005      50             push eax
│           0x00401006      64ff350000..   push dword fs:[0]
│           0x0040100d      6489250000..   mov dword fs:[0], esp
│           0x00401014      33c0           xor eax, eax
│           0x00401016      8908           mov dword [eax], ecx
│           0x00401018      50             push eax
│           0x00401019      45             inc ebp
│           0x0040101a      43             inc ebx
│           0x0040101b      6f             outsd dx, dword [esi]
│           0x0040101c      6d             insd dword es:[edi], dx
│       ┌─< 0x0040101d      7061           jo 0x401080
│       │   0x0040101f      63743200       arpl word [edx + esi], si
│     ╎╎│   0x00401023      bc794e9e74     mov esp, 0x749e4e79
│     ╎╎│   0x00401028      47             inc edi
│     ╎╎│   0x00401029      0300           add eax, dword [eax]
│     ╎╎│   0x0040102b      81903c9304..   adc dword [eax + 0xd04933c], 0xd8418213
│     ╎╎│   0x00401035      3eaf           scasd eax, dword es:[edi]
│     ╎╎│   0x00401037      0e             push cs
│    ┌────< 0x00401038      ea8deb171c..   ljmp 0x2ff
..
│  │ │  └─> 0x00401080      646c           insb byte es:[edi], dx
│  │ │      0x00401082      e23e           loop 0x4010c2
│  │ │      0x00401084      f5             cmc
│  │ │      0x00401085      d28ac6e262e4   ror byte [edx - 0x1b9d1d3a], cl
│  │ │      0x0040108b      68b75856e3     push 0xe35658b7
│  │ │      0x00401090      2c67           sub al, 0x67                ; 103
│  │ │      0x00401092      f9             stc
│  │ │      0x00401093      3c55           cmp al, 0x55                ; 'U' ; 85
│  │ │      0x00401095      16             push ss
│  │ │      0x00401096      2dabf2e4cb     sub eax, 0xcbe4f2ab
│  │ │      0x0040109b      b153           mov cl, 0x53                ; 'S' ; 83
│  │ │      0x0040109d      bf1e381a34     mov edi, 0x341a381e         ; '\x1e8\x1a4'
│  │ │      0x004010a2      98             cwde
│  │ │      0x004010a3      c226d7         ret 0xd726
..
│  │ │      0x004010ae      ac             lodsb al, byte [esi]
│  └──────> 0x004010af      0284fd79c1..   add al, byte [ebp + edi*8 + 0x2faec179]
│    │      0x004010b6      ff             invalid
..
│    │      0x004010c2      e3ea           jecxz 0x4010ae
│    │      0x004010c4      58             pop
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 000000E8 ........!..L.!This program cannot be r

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: present — Data Execution Prevention flag set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 0

## revai_tools_audit (pe, revai_tools_audit)

<!-- evidence_assembler: used 5930/60000 chars across 12 tools -->