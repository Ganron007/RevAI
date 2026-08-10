## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=fc5a215c0f6d3bdb | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=84, sha256=fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f
  Anomalies (4): FewStrings (strings), SectionWX (sections), UnreferencedImports×8 (imports), XorInLoop (code)
  High-signal anomaly locations: XorInLoop@1034
  YARA (info, 1 total): FASM
  Functions (1): EntryPoint@1024
  Mid-signal imports: user32.SendMessageA, kernel32.GetModuleHandleA
  (low-signal/noise imports: 7 omitted)
  Strings/apis (11 total): OriginalFilename, AddVectoredExceptionHandler, FileDescription, StringFileInfo, FileVersion, GetDlgItemTextA, GetModuleHandleA, VarFileInfo, SendMessageA, LoadIconA, ExitProcess
  Strings (other, 128 items, omitted)
  Carved files (1): DIB@17912 (135208 bytes)
  Virtual files (4): ICO/1/unk, DLG/37/en-us, GRPICO/17/unk, VER/1/unk
  Recovered structures (29): MZ, PE, OptionalHeader, Sections, ImportTable, ImportNames, kernel32.OFT, kernel32.FT, ImportNames, user32.OFT, user32.FT, ImportNames, Resources, Resources.DLG, Resources.DLG.37
  Decompilations (1 top functions):
    ### 1024 (EntryPoint, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint8_t *puVar1;
    int32_t iVar2;
    
    puVar1 = 0x4012b3;
    iVar2 = 0x5d8;
    do {
        *puVar1 = *puVar1 ^ 0x66;
        puVar1 = puVar1 + 1;
        iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    (*kernel32.AddVectoredExceptionHandler)(1, 0x4012b3);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```

## capa evidence (1 total, showing top 1)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR

## pe_imports (9 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (7)
  Rules: domain, IP, contains_base64, IsPE32, IsWindowsGUI, FASM, SEH__vectored

## FLOSS strings (33 total)
  apis (11): GetModuleHandleA, AddVectoredExceptionHandler, ExitProcess, GetDlgItemTextA, LoadIconA, SendMessageA, StringFileInfo, FileDescription, FileVersion, OriginalFilename, VarFileInfo
  (other strings, 21 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00401000
```c
;-- section..text:
┌ 30: entry0 ();
│           0x00401000      b8b3124000     mov eax, 0x4012b3           ; [00] -rwx section size 4096 named .text
│           0x00401005      b9d8050000     mov ecx, 0x5d8              ; 1496
│       ┌─> 0x0040100a      803066         xor byte [eax], 0x66        ; [0x66:1]=255 ; 102
│       ╎   0x0040100d      40             inc eax
│       └─< 0x0040100e      e2fa           loop 0x40100a
│           0x00401010      68b3124000     push 0x4012b3
│           0x00401015      6a01           push 1                      ; 1
│           0x00401017      ff156c304000   call dword [sym.imp.KERNEL32.DLL_AddVectoredExceptionHandler] ; 0x40306c ; PVOID AddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
└           0x0040101d      f4             hlt
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 3286/60000 chars across 9 tools -->