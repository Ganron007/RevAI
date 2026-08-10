## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=1d4c0b32aea68056 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=216, sha256=1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a
  Anomalies (9): BigBufferNoXrefMediumToHighEntropy×2 (entropy), CrossSectionJump (code), GuiSubsystemNoWindowApi (headers), HighEntropy (entropy), InvalidChecksum (integrity), ResourceDirectoryGap (resources), SectionNameUnknown (sections), SectionWX (sections), XorInLoop (code)
  High-signal anomaly locations: GuiSubsystemNoWindowApi@220; ResourceDirectoryGap@62480; XorInLoop@38141
  YARA (info, 1 total): MSVC_2017_linker
  Functions (8): sub_40a288@38536, sub_40a0d5@38101, EntryPoint@38671, sub_40a135@38197, sub_40a047@37959, sub_40a000@37888, sub_40a2de@38622, sub_40a2b5@38581
  (low-signal/noise imports: 1 omitted)
    Constants/code (1): code::PEBx86
    Constants/oid (39): oid::signedData, oid::sha1, oid::spcIndirectDataContext, oid::spcPEImageData, oid::sha256WithRSAEncryption, oid::countryName, oid::stateOrProvinceName, oid::localityName
    Constants/hash (1): hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15
  Strings/urls (14 total): ?http://crl.user..nAuthority.crl0v, 3http://crl.sect..StampingCA.crl0t, 3http://crt.user..AddTrustCA.crt0%, 2http://crt.sect..eSigningCA.crt0#, 2http://crl.sect..eSigningCA.crl0s, 3http://crt.sect..StampingCA.crt0#, http://ocsp.usertrust.com0, http://ocsp.sectigo.com0, http://ocsp.sectigo.com0%, https://sectigo.com/CPS0, https://sectigo.com/CPS0D
  Strings/apis (2 total): FindNextFileW, ExitProcess
  Strings (other, 284 items, omitted)
  Carved files (1): PKCS7@66568 (8014 bytes)
  Recovered structures (12): MZ, PE, OptionalHeader, Sections, kernel32.FT, DebugDirectory, Debug.Pogo, ImportTable, kernel32.OFT, ImportNames, Resources, Certificate
  Decompilations (3 top functions):
    ### 38536 (sub_40a288, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40a288(void)

{
    int32_t iVar1;
    int32_t unaff_FS_OFFSET;
    
    iVar1 = *(unaff_FS_OFFSET + 0x30);
    [0x0x40f5d6] = *(iVar1 + 0x18);
    [0x0x40f5da] = *(iVar1 + 8);
    [0x0x40f5de] = *(iVar1 + 100);
    [0x0x40f5e2] = *(*(iVar1 + 0x10) + 0x44);
    return;
}
```
    ### 38101 (sub_40a0d5, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40a0d5(int32_t param_1,char param_2)

{
    char cVar1;
    char cVar2;
    int32_t iVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined4 *puVar6;
    undefined4 *puVar7;
    uint8_t *puVar8;
    
    puVar6 = 0x40f270;
    puVar7 = 0x40f370;
    for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar7 = *puVar6;
        puVar6 = puVar6 + 1;
        puVar7 = puVar7 + 1;
    }
    uVar4 = 0;
    uVar5 = 0;
    puVar8 = param_1 + -1;
    do {
        uVar5 = uVar5 + *(uVar4 + 0x40f371);
        cVar1 = *(uVar4 + 0x40f371);
        cVar2 = *(uVar5 + 0x40f370);
        *(uVar5 + 0x40f370) = cVar1;
        *(uVar4 + 0x40f371) = cVar2;
        puVar8 = puVar8 + 1;
        uVar4 = uVar4 + 1;
        *puVar8 = *puVar8 ^ *((cVar1 + cVar2) + 0x40f370);
        param_2 = param_2 + -1;
    } while (param_2 != '\0');
    return;
}
```
    ### 38671 (EntryPoint, score=?)
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}
```

## capa evidence (3 total, showing top 3)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): encode data using XOR
  All rules (2): decompress data using aPLib, terminate process

## pe_imports (1 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (11)
  Rules: domain, IP, contains_base64, url, maldoc_find_kernel32_base_method_1, IsPE32, IsWindowsGUI, IsPacked, HasOverlay, HasDigitalSignature, HasDebugData

## FLOSS strings (191 total)
  apis (2): ExitProcess, FindNextFileW
  (other strings, 78 items omitted)

## dotnet_analyze
  (not a .NET assembly)


## radare2 (pdf (disasm)) — 5 functions (asm)
  ### 0x0040a30f
```c
┌ 45: entry0 ();
│           0x0040a30f      6a10           push 0x10                   ; 16
│           0x0040a311      6820004100     push 0x410020               ; ' '
│           0x0040a316      6810004100     push 0x410010               ; '\x10'
│           0x0040a31b      e827fdffff     call fcn.0040a047
│           0x0040a320      e863ffffff     call fcn.0040a288
│           0x0040a325      e88bffffff     call fcn.0040a2b5
│           0x0040a32a      e8afffffff     call fcn.0040a2de
│           0x0040a32f      e8e9edffff     call fcn.0040911d
│           0x0040a334      6a00           push 0
└           0x0040a336      ff1500b04000   call dword [sym.imp.KERNEL32.dll_ExitProcess] ; 0x40b000 ; "<\xb1" ; VOID ExitProcess(UINT uExitCode)
```
  ### 0x0040a047
```c
; CALL XREF from entry0 @ 0x40a31b(x)
┌ 142: fcn.0040a047 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; arg int32_t arg_10h @ ebp+0x10
│           0x0040a047      55             push ebp
│           0x0040a048      8bec           mov ebp, esp
│           0x0040a04a      53             push ebx
│           0x0040a04b      51             push ecx
│           0x0040a04c      52             push edx
│           0x0040a04d      56             push esi
│           0x0040a04e      57             push edi
│           0x0040a04f      b9f0000000     mov ecx, 0xf0               ; 240
│           0x0040a054      be70f24000     mov esi, 0x40f270
│           0x0040a059      8b4508         mov eax, dword [arg_8h]
│           0x0040a05c      8b10           mov edx, dword [eax]
│           0x0040a05e      8b5804         mov ebx, dword [eax + 4]
│           0x0040a061      8b7808         mov edi, dword [eax + 8]
│           0x0040a064      8b400c         mov eax, dword [eax + 0xc]
│       ┌─> 0x0040a067      89540e0c       mov dword [esi + ecx + 0xc], edx
│       ╎   0x0040a06b      89440e08       mov dword [esi + ecx + 8], eax
│       ╎   0x0040a06f      895c0e04       mov dword [esi + ecx + 4], ebx
│       ╎   0x0040a073      893c0e         mov dword [esi + ecx], edi
│       ╎   0x0040a076      81ea10101010   sub edx, 0x10101010
│       ╎   0x0040a07c      2d10101010     sub eax, 0x10101010
│       ╎   0x0040a081      81eb10101010   sub ebx, 0x10101010
│       ╎   0x0040a087      81ef10101010   sub edi, 0x10101010
│       ╎   0x0040a08d      83e910         sub ecx, 0x10               ; 16
│       └─< 0x0040a090      79d5           jns 0x40a067
│           0x0040a092      33d2           xor edx, edx
│           0x0040a094      33c9           xor ecx, ecx
│           0x0040a096      8b750c         mov esi, dword [arg_ch]
│           0x0040a099      33db           xor ebx, ebx
│           0x0040a09b      8b7d10         mov edi, dword [arg_10h]
│      ┌┌─> 0x0040a09e      8a8170f24000   mov al, byte [ecx + 0x40f270]
│      ╎╎   0x0040a0a4      02141e         add dl, byte [esi + ebx]
│      ╎╎   0x0040a0a7      02d0           add dl, al
│      ╎╎   0x0040a0a9      8aa270f24000   mov ah, byte [edx + 0x40f270]
│      ╎╎   0x0040a0af      43             inc ebx
│      ╎╎   0x0040a0b0      888270f24000   mov byte [edx + 0x40f270], al ; [0x40f270:1]=0
│      ╎╎   0x0040a0b6     
```
  ### 0x0040a288
```c
; CALL XREF from entry0 @ 0x40a320(x)
┌ 45: fcn.0040a288 ();
│           0x0040a288      51             push ecx
│           0x0040a289      648b0d3000..   mov ecx, dword fs:[0x30]
│           0x0040a290      8b4118         mov eax, dword [ecx + 0x18]
│           0x0040a293      a3d6f54000     mov dword [0x40f5d6], eax   ; [0x40f5d6:4]=0
│           0x0040a298      8b4108         mov eax, dword [ecx + 8]
│           0x0040a29b      a3daf54000     mov dword [0x40f5da], eax   ; [0x40f5da:4]=0
│           0x0040a2a0      8b4164         mov eax, dword [ecx + 0x64]
│           0x0040a2a3      a3def54000     mov dword [0x40f5de], eax   ; [0x40f5de:4]=0
│           0x0040a2a8      8b4910         mov ecx, dword [ecx + 0x10]
│           0x0040a2ab      8b4144         mov eax, dword [ecx + 0x44]
│           0x0040a2ae      a3e2f54000     mov dword [0x40f5e2], eax   ; [0x40f5e2:4]=0
│           0x0040a2b3      59             pop ecx
└           0x0040a2b4      c3             ret
```
  ### 0x0040a2b5
```c
; CALL XREF from entry0 @ 0x40a325(x)
┌ 41: fcn.0040a2b5 ();
│           0x0040a2b5      53             push ebx
│           0x0040a2b6      56             push esi
│           0x0040a2b7      57             push edi
│           0x0040a2b8      8b1ddaf54000   mov ebx, dword [0x40f5da]   ; [0x40f5da:4]=0
│           0x0040a2be      8b733c         mov esi, dword [ebx + 0x3c]
│           0x0040a2c1      8d341e         lea esi, [esi + ebx]
│           0x0040a2c4      8db6f8000000   lea esi, [esi + 0xf8]
│           0x0040a2ca      8b7e0c         mov edi, dword [esi + 0xc]
│           0x0040a2cd      8d3c1f         lea edi, [edi + ebx]
│           0x0040a2d0      8b7610         mov esi, dword [esi + 0x10]
│           0x0040a2d3      56             push esi
│           0x0040a2d4      57             push edi
│           0x0040a2d5      e826fdffff     call fcn.0040a000
│           0x0040a2da      5f             pop edi
│           0x0040a2db      5e             pop esi
│           0x0040a2dc      5b             pop ebx
└           0x0040a2dd      c3             ret
```
  ### 0x0040a000
```c
;-- section..text1:
            ; CALL XREF from fcn.0040a2b5 @ 0x40a2d5(x)
            ; CALL XREF from fcn.0040a2de @ 0x40a303(x)
┌ 71: fcn.0040a000 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x0040a000      55             push ebp                    ; [01] -r-x section size 4096 named .text1
│           0x0040a001      8bec           mov ebp, esp
│           0x0040a003      53             push ebx
│           0x0040a004      51             push ecx
│           0x0040a005      52             push edx
│           0x0040a006      56             push esi
│           0x0040a007      57             push edi
│           0x0040a008      8b7d08         mov edi, dword [arg_8h]
│           0x0040a00b      8b450c         mov eax, dword [arg_ch]
│           0x0040a00e      b9ff000000     mov ecx, 0xff               ; 255
│           0x0040a013      33d2           xor edx, edx
│           0x0040a015      f7f1           div ecx
│           0x0040a017      85c0           test eax, eax
│       ┌─< 0x0040a019      7418           je 0x40a033
│       │   0x0040a01b      8bd8           mov ebx, eax
│      ┌──> 0x0040a01d      68ff000000     push 0xff                   ; 255
│      ╎│   0x0040a022      57             push edi
│      ╎│   0x0040a023      e8ad000000     call 0x40a0d5
│      ╎│   0x0040a028      81c7ff000000   add edi, 0xff               ; 255
│      ╎│   0x0040a02e      4b             dec ebx
│      ╎│   0x0040a02f      85db           test ebx, ebx
│      └──< 0x0040a031      75ea           jne 0x40a01d
│       └─> 0x0040a033      85d2           test edx, edx
│       ┌─< 0x0040a035      7407           je 0x40a03e
│       │   0x0040a037      52             push edx
│       │   0x0040a038      57             push edi
│       │   0x0040a039      e897000000     call 0x40a0d5
│       └─> 0x0040a03e      5f             pop edi
│           0x0040a03f      5e             pop esi
│           0x0040a040      5a             pop edx
│           0x0040a041      59             pop ecx
│           0x0040a042      5b             pop ebx
│           0x0040a043      5d             pop ebp
└           0x0040a044      c20800         ret 8
```

## UPX
  (not packed)


## xorsearch (1 candidates)
  Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

<!-- evidence_assembler: used 11833/60000 chars across 9 tools -->