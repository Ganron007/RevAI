## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=683a09da21991825 | packaging=v6.1 -->

## MalCat evidence
  File: type=PE, architecture=X86, entropy=6.46, sha256=683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96
  Anomalies (7): BigBufferNoXrefMediumToHighEntropy×2 (entropy), BoundImports (imports), ManyUniqueImmediateBytes (code), RichMultipleLinkers (rich), StringBase64 (strings), WeirdDebugInfoType (headers), XorInLoop×11 (code)
  High-signal anomaly locations: ManyUniqueImmediateBytes@4176; XorInLoop@4361,4422,4454
  YARA (info, 1 total): MSVC_2010_linker
  Functions (15): sub_401e60@4704, sub_402010@5136, PEBx86@1712, sub_401c50@4176, sub_402610@6672, sub_402030@5168, sub_402e70@8816, sub_402ca0@8352, sub_402b10@7952, sub_401280@1664, sub_402c20@8224, sub_4012c0@1728, sub_401310@1808, sub_402940@7488, sub_4012d0@1744
  (low-signal/noise imports: 21 omitted)
  * Constants/crypto (1): crypto::Base64
    Constants/code (1): code::PEBx86
  Strings/apis (3 total): ZwGetContextThread, NtYieldExecution, GetLocalTime
  Strings (other, 138 items, omitted)
  Virtual files (1): MANIF/1/en-us
  Recovered structures (25): MZ, RichHeader, PE, OptionalHeader, Sections, BoundImportTable, BoundImportNames, kernel32.FT, opengl32.FT, user32.FT, ntdll.FT, DebugDirectory, Debug.Fixup, ImportTable, kernel32.OFT
  Decompilations (3 top functions):
    ### 4704 (sub_401e60, score=?)
```c
/* WARNING: Removing unreachable block (ram,0x00401fb1) */
/* WARNING: Removing unreachable block (ram,0x00401ef3) */
/* WARNING: Removing unreachable block (ram,0x00401ef5) */
/* WARNING: Removing unreachable block (ram,0x00401ee4) */
/* WARNING: Removing unreachable block (ram,0x00401ee6) */
/* WARNING: Removing unreachable block (ram,0x00401ebf) */
/* WARNING: Removing unreachable block (ram,0x00401f10) */
/* WARNING: Removing unreachable block (ram,0x00401fbb) */
/* WARNING: Removing unreachable block (ram,0x00401ec4) */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_401e60(void)

{
    uint32_t uVar1;
    uint32_t uStack_8;
    
    sub_4012d0(0x40110c, "First_tls");
    uVar1 = [0x0x401064];
    [0x0x40d594] = 0;
    if (([0x0x40d41c] == 0) && ([0x0x401064] != 0)) {
        uStack_8 = 0;
        do {
            uStack_8 = uStack_8 + 1;
        } while (uStack_8 < 0xfaa7c);
        0040d668 = PEBx86();
        if (0040d668 != 0) {
            0040d41c = *(0040d668 + 0x30);
            uStack_8 = 0;
            if ((uVar1 >> 0x10) + ([0x0x401064] & 0xffff) * 2 != 0) {
                do {
                    uStack_8 = uStack_8 + 1;
                } while (uStack_8 < (uVar1 >> 0x10) + ([0x0x401064] & 0xffff) * 2);
            }
            if (0040d41c != 0) {
                sub_402520();
                return;
            }
            func_0x0040103c();
        }
    }
    return;
}
```
    ### 5136 (sub_402010, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_402010(void)

{
    int32_t iVar1;
    
    iVar1 = 0;
    do {
        *((&Base64)[iVar1] + 0x40d6a8) = iVar1;
        iVar1 = iVar1 + 1;
    } while (iVar1 < 0x40);
    return;
}
```
    ### 1712 (PEBx86, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

undefined4 PEBx86(void)

{
    int32_t unaff_FS_OFFSET;
    
    return *(unaff_FS_OFFSET + 0x18);
}
```

## capa evidence (7 total, showing top 7)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (1): reference Base64 string
  ATT&CK {'parts': ['Defense Evasion', 'Virtualization/Sandbox Evasion', 'System Checks'], 'tactic': 'Defense Evasion', 'technique': 'Virtualization/Sandbox Evasion', 'subtechnique': 'System Checks', 'id': 'T1497.001'} (1): reference anti-VM strings targeting Qemu
  ATT&CK {'parts': ['Execution', 'Shared Modules'], 'tactic': 'Execution', 'technique': 'Shared Modules', 'subtechnique': '', 'id': 'T1129'} (1): parse PE header
  All rules (4): inspect section memory permissions, contains PDB path, print debug messages, resolve function by parsing PE exports

## pe_imports (21 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (15)
  Rules: domain, IP, contains_base64, Qemu_Detection, BASE64_table, url, IsPE32, IsWindowsGUI, HasOverlay, HasDebugData, HasRichSignature, Safeguard_103_Simonzh, Check_OutputDebugStringA_iat, anti_dbg, Ransom_Satana_Dropper

## FLOSS strings (145 total)
  base64 (2): 4siPKFd;`U7v`U0VcPGjirHv`fWPIVuSGQ2TISePjPGf[1KP30Lv0UQeVLWP`AEeVFiD@@6PVP2dCemdFCCPVS6OCuOAEW2PFujLJzeFVSSPC22rKh7LCCIPASjF[E@lQPUZ, 5rhQJGe:aT6waT1WbQFkhsIwagVQHWtRFP3UHRdQkQFgZ0JQ21Mw1TPdWMVQa@DdWGhEAA7QWQ3eBdleGBBQWR7NBtN@DV3QGtkMK{dGWRRQB33sJi6MBBHQ@RkGZDAmPQT[FQTV3SsQ:a5sVARPTJ3wrU3QEi7A5qrsV{NTwHoRBAFT3vntF{YQ:a;UrP3QEruTs5oP
  apis (8): ZwProtectVirtualMemory, ZwWriteVirtualMemory, GetModuleFileNameW, NtAllocateVirtualMemory, SetUnhandledExceptionFilter, ZwGetContextThread, NtYieldExecution, GetLocalTime
  (other strings, 70 items omitted)

## revai_tools_sec (pe, revai_tools_sec)
  Address Space Layout Randomization: missing — no DYNAMIC_BASE flag
  64-bit high-entropy ASLR: missing — 64-bit high-entropy ASLR flag not set
  Data Execution Prevention: missing — Data Execution Prevention flag not set
  Control Flow Guard: missing — no GUARD_CF flag
  Structured Exception Handling: present — no NO_SEH flag — SEH handlers may exist
  Signed-image enforcement: missing — Signed-image enforcement flag not set
  Stack cookie (/GS): missing — no __security_cookie reference found

## revai_tools_sinks (pe, revai_tools_sinks)
  sink_count: 2
  vsprintf @ 0x4012ea (fcn.004012d0)
  memmove @ 0x401e50 (fcn.00401c50)

<!-- evidence_assembler: used 5723/28000 chars across 7 tools -->