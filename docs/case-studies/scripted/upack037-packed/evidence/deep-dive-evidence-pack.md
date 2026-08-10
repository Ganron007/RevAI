## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=36137a22c973fdb6 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=156, sha256=36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9
  Anomalies (17): DataBetweenHeaderAndFirstSection (headers), ExtraSpaceAfterResourcesDataDirectory (resources), GuiSubsystemNoWindowApi (headers), InvalidBaseOfCode (sections), InvalidSizeOfCode (sections), InvalidSizeOfInitializedData (sections), InvalidSizeOfUninitializedData (sections), NoChecksum (integrity), NoImportTable (imports), Packed×2 (packers), PointerToRawDataNotAligned×2 (sections), SectionEmptyName (sections), SectionNameUnknown×3 (sections), SectionWX×3 (sections), SizeOfRawDataNotAligned×2 (sections), UnbalancedVirtualPhysicalRatio (sections), WrongSizeOfOptionalHeader (headers)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@108; NoChecksum@104
  YARA (info, 2 total): upack_037_03, upack_039f_03
  Strings/apis (7 total): LoadLibraryA, OriginalFilename, FileDescription, StringFileInfo, FileVersion, GetProcAddress, VarFileInfo
  Strings (other, 293 items, omitted)
  Carved files (8): DIB@7251 (744 bytes), DIB@7995 (296 bytes), DIB@8291 (3752 bytes), DIB@12043 (2216 bytes), DIB@14259 (1384 bytes), DIB@15643 (9640 bytes), DIB@25283 (4264 bytes), DIB@29547 (1128 bytes)
  Virtual files (11): ICO/1/en-us, ICO/2/en-us, ICO/3/en-us, ICO/4/en-us, ICO/5/en-us, ICO/6/en-us, ICO/7/en-us, ICO/8/en-us, GRPICO/SC/en-us, VER/1/en-us
  Recovered structures (77): PE, OptionalHeader, Sections, Resources, Resources.ICO, Resources.ICO.1, Resources.ICO.1.en-us, Resources.ICO.2, Resources.ICO.2.en-us, Resources.ICO.3, Resources.ICO.3.en-us, Resources.ICO.4, Resources.ICO.4.en-us, Resources.ICO.5, Resources.ICO.5.en-us

## capa
  incomplete: capa rc=13


## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (21)
  Rules: domain, IP, contains_base64, WinUpackv039finalByDwingc2005h1, Upackv039finalDwing, UpackV037Dwing, IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, WinUpack_v039_final_By_Dwing_c2005_additional, Upack_v0399_Dwing_additional, Upack_V037_V039_Dwing, Upack_v039_final, Upack_v039_final_Sign_by_hot_UNP_additional, WinUpack_v039_final_By_Dwing_c2005_h1, Upack_v039_final_Dwing_h, Upack_v039_final_Sign_by_hot_UNP, Upack_V037_Dwing, WinUpack_v039_final_By_Dwing_c2005_h1_additional, WinUpack_v039_final_By_Dwing_c2005

## FLOSS strings (52 total)
  ips (2): version="5.1.0.0", version="6.0.0.0"
  apis (2): LoadLibraryA, GetProcAddress
  (other strings, 48 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 4 functions (asm)
  ### 0x01001018
```c
┌ 64: entry0 ();
│           0x01001018      beb0110001     mov esi, 0x10011b0
│           0x0100101d      ad             lodsd eax, dword [esi]
│           0x0100101e      50             push eax
│           0x0100101f      ff7634         push dword [esi + 0x34]
│       ┌─< 0x01001022      eb7c           jmp 0x10010a0
..
│       │   ; CODE XREF from entry0 @ 0x1001022(x)
│       └─> 0x010010a0      ff7638         push dword [esi + 0x38]
│       │   0x010010a3      ad             lodsd eax, dword [esi]
│       │   0x010010a4      50             push eax
│       │   0x010010a5      8b3e           mov edi, dword [esi]
│       │   0x010010a7      bef0400301     mov esi, 0x10340f0
│       │   0x010010ac      6a27           push 0x27                   ; '\'' ; 39
│       │   0x010010ae      59             pop ecx
│       │   0x010010af      f3a5           rep movsd dword es:[edi], dword [esi]
│       │   0x010010b1      ff7604         push dword [esi + 4]
│       │   0x010010b4      83c8ff         or eax, 0xffffffff          ; -1
│       │   0x010010b7      8bdf           mov ebx, edi
│       │   0x010010b9      ab             stosd dword es:[edi], eax
│      ┌──< 0x010010ba      eb1c           jmp 0x10010d8
..
│  ││││││   ; CODE XREF from entry0 @ 0x10010ba(x)
│  ││││└──> 0x010010d8      40             inc eax
│  ││││ │   0x010010d9      ab             stosd dword es:[edi], eax
│  ││││ │   0x010010da      40             inc eax
│  ││││ └─> 0x010010db      b104           mov cl, 4
│  ││││     0x010010dd      f3ab           rep stosd dword es:[edi], eax
│  ││││     0x010010df      c1e00a         shl eax, 0xa
│  ││││     0x010010e2      b51c           mov ch, 0x1c                ; 28
│  ││││     0x010010e4      f3ab           rep stosd dword es:[edi], eax
│  ││││     0x010010e6      8b7e0c         mov edi, dword [esi + 0xc]
│  ││││     0x010010e9      57             push edi
│  ││││     0x010010ea      51             push ecx
└  ││││ ┌─< 0x010010eb      e9fbb70200     jmp loc.0102c8eb
```
  ### 0x0102c8eb
```c
; CODE XREF from entry0 @ 0x10010eb(x)
├ 30521: loc.0102c8eb ();
│ 0x0102c8eb      58             pop eax
│ 0x0102c8ec      8d548358       lea edx, [ebx + eax*4 + 0x58]
│ 0x0102c8f0      ff16           call dword [esi]
│ 0x0102c8f2      724f           jb 0x102c943
│ 0x0102c8f4      04fd           add al, 0xfd                          ; 253
│ 0x0102c8f6      1ad2           sbb dl, dl
│ 0x0102c8f8      22c2           and al, dl
│ 0x0102c8fa      3c07           cmp al, 7                             ; 7
│ 0x0102c8fc      73f6           jae 0x102c8f4
│ 0x0102c8fe      50             push eax
│ 0x0102c8ff      0fb66fff       movzx ebp, byte [edi - 1]
│ 0x0102c903      c1ed05         shr ebp, 5
│ 0x0102c906      6669ed0003     imul bp, bp, 0x300
│ 0x0102c90b      8dacab0810..   lea ebp, [ebx + ebp*4 + 0x1008]
│ 0x0102c912      57             push edi
│ 0x0102c913      b001           mov al, 1
│ 0x0102c915      e31f           jecxz 0x102c936
│ 0x0102c917      2b7b08         sub edi, dword [ebx + 8]
│ 0x0102c91a      840f           test byte [edi], cl
│ 0x0102c91c      0f95c4         setne ah
│ 0x0102c91f      fec4           inc ah
│ 0x0102c921      8d548500       lea edx, [ebp + eax*4]
│ 0x0102c925      ff16           call dword [esi]
│ 0x0102c927      12c0           adc al, al
│ 0x0102c929      d0e9           shr cl, 1
│ 0x0102c92b      740e           je 0x102c93b
│ 0x0102c92d      2ae0           sub ah, al
│ 0x0102c92f      80e401         and ah, 1
│ 0x0102c932      75e6           jne 0x102c91a
│ 0x0102c934      33c9           xor ecx, ecx
│ 0x0102c936      b501           mov ch, 1
│ 0x0102c938      ff5650         call dword [esi + 0x50]               ; 80
│ 0x0102c93b      33c9           xor ecx, ecx
│ 0x0102c93d      5f             pop edi
│ ; CODE XREF from loc.0102c8eb @ 0x102c96e(x)
│ 0x0102c93e      e9f2000000     jmp 0x102ca35
│ 0x0102c943      04f9           add al, 0xf9                          ; 249
│ 0x0102c945      1ac0           sbb al, al
│ 0x0102c947      b130           mov cl, 0x30                          ; '0' ; 48
│ 0x0102c949      2403           and al, 3
│ 0x0102c94b      8b6b08         mov ebp, dword [ebx + 8]
│ 0x0102c94e      0408           add al, 8
│ 0x0102c950      03d1           add edx, ecx
│ 0x0102c952      ff16           call dword [esi]
│ 0x0102c954      7342           jae 0x102c998
│ 0x0102c956      03d1           add edx, ecx
│ 0x0102c958      ff16           call dword [esi]
│ 0x0102c95a      7214           jb 0x102c970
│ 0x0102
```
  ### 0x010340a0
```c
; CODE XREF from loc.0102c8eb @ 0x1034022(x)
├ 52: loc.010340a0 ();
│           0x010340a0      ff7638         push dword [esi + 0x38]
│           0x010340a3      ad             lodsd eax, dword [esi]
│           0x010340a4      50             push eax
│           0x010340a5      8b3e           mov edi, dword [esi]
│           0x010340a7      bef0400301     mov esi, 0x10340f0
│           0x010340ac      6a27           push 0x27                   ; '\'' ; 39
│           0x010340ae      59             pop ecx
│           0x010340af      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x010340b1      ff7604         push dword [esi + 4]
│           0x010340b4      83c8ff         or eax, 0xffffffff          ; -1
│           0x010340b7      8bdf           mov ebx, edi
│           0x010340b9      ab             stosd dword es:[edi], eax
│       ┌─< 0x010340ba      eb1c           jmp 0x10340d8
..
│   │││││   ; CODE XREF from loc.010340a0 @ 0x10340ba(x)
│   ││││└─> 0x010340d8      40             inc eax
│   ││││    0x010340d9      ab             stosd dword es:[edi], eax
│   ││││    0x010340da      40             inc eax
│   ││││    0x010340db      b104           mov cl, 4
│   ││││    0x010340dd      f3ab           rep stosd dword es:[edi], eax
│   ││││    0x010340df      c1e00a         shl eax, 0xa
│   ││││    0x010340e2      b51c           mov ch, 0x1c                ; 28
│   ││││    0x010340e4      f3ab           rep stosd dword es:[edi], eax
│   ││││    0x010340e6      8b7e0c         mov edi, dword [esi + 0xc]
│   ││││    0x010340e9      57             push edi
│   ││││    0x010340ea      51             push ecx
└   ││││┌─< 0x010340eb      e9fbb70200     jmp 0x105f8eb
```
  ### 0x010011e8
```c
┌ 98309: sym.imp.KERNEL32.DLL_LoadLibraryA ();
│ 0x010011e8      2800           sub byte [eax], al
│ 0x010011ea      0000           add byte [eax], al
│ ;-- GetProcAddress:
│ 0x010011ec      be00000000     mov esi, 0
│ 0x010011f1      0000           add byte [eax], al
│ 0x010011f3      0000           add byte [eax], al
│ 0x010011f5      0000           add byte [eax], al
│ 0x010011f7      0000           add byte [eax], al
│ 0x010011f9      0002           add byte [edx], al
│ 0x010011fb      0000           add byte [eax], al
│ 0x010011fd      00e8           add al, ch
│ 0x010011ff      1100           adc dword [eax], eax
│ 0x01001201      0000           add byte [eax], al
│ 0x01001203      0000           add byte [eax], al
│ 0x01001205      0000           add byte [eax], al
│ 0x01001207      0000           add byte [eax], al
│ 0x01001209      0000           add byte [eax], al
│ 0x0100120b      0000           add byte [eax], al
│ 0x0100120d      0000           add byte [eax], al
│ 0x0100120f      0000           add byte [eax], al
│ 0x01001211      0000           add byte [eax], al
│ 0x01001213      0000           add byte [eax], al
│ 0x01001215      0000           add byte [eax], al
│ 0x01001217      0000           add byte [eax], al
│ 0x01001219      0000           add byte [eax], al
│ 0x0100121b      0000           add byte [eax], al
│ 0x0100121d      0000           add byte [eax], al
│ 0x0100121f      0000           add byte [eax], al
│ 0x01001221      0000           add byte [eax], al
│ 0x01001223      0000           add byte [eax], al
│ 0x01001225      0000           add byte [eax], al
│ 0x01001227      0000           add byte [eax], al
│ 0x01001229      0000           add byte [eax], al
│ 0x0100122b      0000           add byte [eax], al
│ 0x0100122d      0000           add byte [eax], al
│ 0x0100122f      0000           add byte [eax], al
│ 0x01001231      0000           add byte [eax], al
│ 0x01001233      0000           add byte [eax], al
│ 0x01001235      0000           add byte [eax], al
│ 0x01001237      0000           add byte [eax], al
│ 0x01001239      0000           add byte [eax], al
│ 0x0100123b      0000           add byte [eax], al
│ 0x0100123d      0000           add byte [eax], al
│ 0x0100123f      0000           add byte [eax], al
│ 0x01001241      0000           add byte [eax], al
│ 0x01001243      0000           add byte [eax], al
│ 0x01001245      0000           add byte [eax], al
│ 0x01001247      0000           add byte [eax], al
│
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000010 .@....................9..........P....

<!-- evidence_assembler: used 11542/60000 chars across 9 tools -->