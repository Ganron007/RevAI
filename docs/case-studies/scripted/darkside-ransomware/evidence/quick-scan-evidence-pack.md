## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=1d4c0b32aea68056 | packaging=v6.1 -->

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

<!-- evidence_assembler: used 3934/28000 chars across 5 tools -->