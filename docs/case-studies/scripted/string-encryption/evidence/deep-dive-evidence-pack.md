## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=263db990612712d7 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=44, sha256=263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca
  Anomalies (1): XorInLoop (code)
  High-signal anomaly locations: XorInLoop@686
  YARA (info, 1 total): FASM
  Functions (2): sub_4010a8@680, EntryPoint@512
  (low-signal/noise imports: 2 omitted)
  Strings/apis (1 total): ExitProcess
  Strings (other, 7 items, omitted)
  Recovered structures (12): MZ, PE, OptionalHeader, Sections, ImportTable, ImportNames, kernel32.OFT, kernel32.FT, ImportNames, user32.OFT, user32.FT, ImportNames
  Decompilations (2 top functions):
    ### 680 (sub_4010a8, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_4010a8(int32_t param_1)

{
    uint8_t *in_EAX;
    uint8_t unaff_BL;
    uint8_t *puVar1;
    
    puVar1 = in_EAX;
    do {
        *puVar1 = *in_EAX ^ unaff_BL;
        param_1 = param_1 + -1;
        in_EAX = in_EAX + 1;
        puVar1 = puVar1 + 1;
    } while (param_1 != 0);
    return;
}
```
    ### 512 (EntryPoint, score=?)
```c
/* WARNING: Possible PIC construction at 0x0040100f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401037: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0040105f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401087: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00401064) */
/* WARNING: Removing unreachable block (ram,0x0040103c) */
/* WARNING: Removing unreachable block (ram,0x00401014) */
/* WARNING: Removing unreachable block (ram,0x0040108c) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t iVar1;
    uint8_t *puVar2;
    uint8_t *puVar3;
    
    iVar1 = 0x12;
    puVar2 = 0x403000;
    puVar3 = 0x403000;
    do {
        *puVar3 = *puVar2 ^ 0x90;
        iVar1 = iVar1 + -1;
        puVar2 = puVar2 + 1;
        puVar3 = puVar3 + 1;
    } while (iVar1 != 0);
    return;
}
```

## capa evidence (2 total, showing top 2)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  All rules (1): terminate process

## pe_imports (2 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (4)
  Rules: domain, IsPE32, IsWindowsGUI, FASM

## FLOSS strings (6 total)
  apis (1): ExitProcess
  (other strings, 5 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 2 functions (asm)
  ### 0x00401000
```c
;-- section..text:
┌ 168: entry0 ();
│           0x00401000      bb90000000     mov ebx, 0x90               ; 144 ; [00] -r-x section size 4096 named .text
│           0x00401005      b800304000     mov eax, section..data      ; 0x403000
│           0x0040100a      b912000000     mov ecx, 0x12               ; 18
│           0x0040100f      e894000000     call fcn.004010a8
│           0x00401014      6a00           push 0
│           0x00401016      6800304000     push section..data          ; 0x403000
│           0x0040101b      6800304000     push section..data          ; 0x403000
│           0x00401020      6a00           push 0
│           0x00401022      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401028      bbeb000000     mov ebx, 0xeb               ; 235
│           0x0040102d      b813304000     mov eax, 0x403013           ; '\x130@'
│           0x00401032      b90f000000     mov ecx, 0xf                ; 15
│           0x00401037      e86c000000     call fcn.004010a8
│           0x0040103c      6a00           push 0
│           0x0040103e      6813304000     push 0x403013               ; '\x130@'
│           0x00401043      6813304000     push 0x403013               ; '\x130@'
│           0x00401048      6a00           push 0
│           0x0040104a      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401050      bbfe000000     mov ebx, 0xfe               ; 254
│           0x00401055      b823304000     mov eax, 0x403023           ; '#0@'
│           0x0040105a      b959000000     mov ecx, 0x59               ; 'Y' ; 89
│           0x0040105f      e844000000     call fcn.004010a8
│           0x00401064      6a00           push 0
│           0x00401066      6823304000     push 0x403023               ; '#0@'
│           0x0040106b      6823304000     push 0x403023               ; '#0@'
│           0x00401070      6a00           push 0
│           0x00401072      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401078      bbc3000000     mov ebx, 0xc3               ; 195
│           0x0040107d      b87d304000     mov eax, 0x40307d           ; '}0@'
│           0x00401082      b921000000     mov ecx, 0x21               ;
```
  ### 0x004010a8
```c
; CALL XREFS from entry0 @ 0x40100f(x), 0x401037(x), 0x40105f(x), 0x401087(x)
┌ 14: fcn.004010a8 ();
│           0x004010a8      89c6           mov esi, eax
│           0x004010aa      89f7           mov edi, esi
│           0x004010ac      31c0           xor eax, eax
│       ┌─> 0x004010ae      ac             lodsb al, byte [esi]
│       ╎   0x004010af      30d8           xor al, bl
│       ╎   0x004010b1      aa             stosb byte es:[edi], al
│       ╎   0x004010b2      49             dec ecx
│       └─< 0x004010b3      75f9           jne 0x4010ae
└           0x004010b5      c3             ret
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 5895/60000 chars across 9 tools -->