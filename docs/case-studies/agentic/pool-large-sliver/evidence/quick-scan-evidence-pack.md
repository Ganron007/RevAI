## Tool evidence (stage=quick_scan, signal-prioritized)
<!-- stage: quick_scan | sha=eceb8e06657564c1 | packaging=v6.1 -->

## MalCat evidence
  File: type=ELF, architecture=X64, entropy=108, sha256=eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f
  Anomalies (13): BigBufferNoXrefMediumToHighEntropy×7 (entropy), BigStringHiScore×256 (strings), DynamicString×256 (strings), HighXrefLoopingFunction×131 (code), HugeGapBetweenFunctions (code), HugeStringBinary×16 (strings), ManyHighValueImmediates×755 (code), ManyUniqueImmediateBytes×1032 (code), SequentialFunction×611 (code), SpaghettiFunction×19 (code), StackArrayInitialisationX64×3 (code), TruncatedELFFile×2 (integrity), XorInLoop×5271 (code)
  High-signal anomaly locations: DynamicString@23277960,25482088,19712360; HighXrefLoopingFunction@17440154,17445018,17447834; ManyHighValueImmediates@17812026,17816666,17819578; ManyUniqueImmediateBytes@17812026,17812762,17816666; SequentialFunction@17694170,17798266,17798650; SpaghettiFunction@17435194,17453370,17692602; XorInLoop@17433717,17433978,17434006
  Functions (15): sub_7f32e0@21563162, sub_8c7240@22431354, sub_9462c0@22951674, sub_8c7a40@22433402, sub_946ac0@22953722, sub_909f00@22704954, sub_4015c0@17426938, sub_607840@19549306, sub_5b8080@19223738, sub_b4f500@25086266, sub_c460e0@26096922, sub_b4fe20@25088602, sub_906be0@22691866, sub_a77f60@24204186, sub_86fb40@22073210
  - Constants/registry (1): registry::HKEY_CURRENT_USER×5
  - Constants/crypto (1): crypto::ChaCha×16
    Constants/hash (3): hash::xxhash, hash::SHA256, hash::RIPEMD160
  Strings (other, 300 items, omitted)
  Recovered structures (3): ELF, Segments, Sections
  Decompilations (3 top functions):
    ### 21563162 (sub_7f32e0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_7f32e0(void)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined auVar6 [16];
    undefined auVar7 [16];
    undefined auVar8 [16];
    undefined auVar9 [16];
    undefined *puVar10;
    uint32_t uVar11;
    int32_t iVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint32_t uVar15;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    uint32_t uVar22;
    uint32_t uVar23;
    uint32_t uVar24;
    uint32_t uVar25;
    uint32_t uVar26;
    uint32_t uVar27;
    uint32_t uVar28;
    uint32_t uVar29;
    uint32_t uVar30;
    uint32_t uVar31;
    uint64_t uVar32;
    uint32_t uVar33;
    uint32_t uVar34;
    uint32_t uVar35;
    uint32_t uVar36;
    uint32_t uVar37;
    uint32_t uVar38;
    uint32_t uVar39;
    uint32_t uVar40;
    uint32_t uVar41;
    uint32_t uVar42;
    uint32_t uVar43;
    uint32_t uVar44;
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint32_t uVar49;
    uint32_t uVar50;
    uint32_t uVar51;
    uint32_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    uint32_t uVar55;
    uint32_t uVar56;
    uint32_t uVar57;
    uint32_t uVar58;
    uint32_t uVar59;
    uint32_t uVar60;
    uint32_t uVar61;
    int32_t iVar62;
    int64_t in_FS_OFFSET;
    undefined auVar63 [32];
    undefined auVar64 [32];
    undefined auVar65 [32];
    undefined auVar66 [32];
    undefined auVar67 [32];
    undefined auVar68 [32];
    undefined auVar69 [32];
    undefined auVar70 [16];
    undefined auVar71 [32];
    uint32_t *in_stack_00000008;
    undefined (*in_stack_00000010) [32];
    uint64_t in_stack_00000018;
    int32_t aiStack_220 [8];
    int32_t aiStack_200 [8];
    int32_t aiStack_1e0 [8];
    int32_t aiStack_1c0 [8];
    undefined auStack_1a0 [384];
    undefined (*pauStack_20) [32];
    undefined (*pauStack_18)
```
    ### 22431354 (sub_8c7240, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_8c7240(undefined8 param_1,int64_t param_2,undefined8 param_3,uint64_t param_4,uint64_t param_5,
               undefined8 param_6)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t iVar3;
    int32_t iVar4;
    uint32_t *puVar5;
    uint32_t *puVar6;
    int64_t iVar7;
    undefined4 *in_RAX;
    int64_t iVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    int64_t unaff_RBX;
    undefined *puVar15;
    undefined *unaff_RBP;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    int64_t unaff_R14;
    uint32_t uVar22;
    uint32_t uVar23;
    
    do {
        puVar15 = register0x00000020;
        if (*(unaff_R14 + 0x10) < register0x00000020 + -0x68) {
            puVar15 = register0x00000020 + -0xe8;
            *(register0x00000020 + -8) = unaff_RBP;
            unaff_RBP = register0x00000020 + -8;
            *(register0x00000020 + 0x10) = unaff_RBX;
            *(register0x00000020 + 0x28) = param_2;
            if ((param_4 == param_5) && ((param_4 & 0x3f) == 0)) {
                *(register0x00000020 + 0x18) = param_4;
                *(register0x00000020 + -0xb0) = *in_RAX;
                uVar10 = in_RAX[1];
                uVar9 = in_RAX[2];
                *(register0x00000020 + -0xc0) = in_RAX[3];
                *(register0x00000020 + -0x8c) = in_RAX[4];
                iVar1 = in_RAX[5];
                *(register0x00000020 + -0x74) = iVar1;
                iVar2 = in_RAX[6];
                *(register0x00000020 + -0xa8) = in_RAX[7];
                uVar12 = in_RAX[9];
                *(register0x00000020 + -0x88) = uVar12;
                uVar11 = in_RAX[10];
                *(register0x00000020 + -0x94) = uVar11;
                uVar14 = in_RAX[0xb];
                *(register0x00000020 + -0xac) = uVar14;
                if (*(in
```
    ### 22951674 (sub_9462c0, score=?)
```c
/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_9462c0(undefined8 param_1,int64_t param_2,undefined8 param_3,uint64_t param_4,uint64_t param_5,
               undefined8 param_6)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t iVar3;
    int32_t iVar4;
    uint32_t *puVar5;
    uint32_t *puVar6;
    int64_t iVar7;
    undefined4 *in_RAX;
    int64_t iVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    int64_t unaff_RBX;
    undefined *puVar15;
    undefined *unaff_RBP;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    int64_t unaff_R14;
    uint32_t uVar22;
    uint32_t uVar23;
    
    do {
        puVar15 = register0x00000020;
        if (*(unaff_R14 + 0x10) < register0x00000020 + -0x68) {
            puVar15 = register0x00000020 + -0xe8;
            *(register0x00000020 + -8) = unaff_RBP;
            unaff_RBP = register0x00000020 + -8;
            *(register0x00000020 + 0x10) = unaff_RBX;
            *(register0x00000020 + 0x28) = param_2;
            if ((param_4 == param_5) && ((param_4 & 0x3f) == 0)) {
                *(register0x00000020 + 0x18) = param_4;
                *(register0x00000020 + -0xac) = *in_RAX;
                uVar10 = in_RAX[1];
                uVar9 = in_RAX[2];
                *(register0x00000020 + -0xcc) = in_RAX[3];
                *(register0x00000020 + -0x98) = in_RAX[4];
                iVar1 = in_RAX[5];
                *(register0x00000020 + -200) = iVar1;
                iVar2 = in_RAX[6];
                *(register0x00000020 + -0xa8) = in_RAX[7];
                uVar12 = in_RAX[9];
                *(register0x00000020 + -0xd0) = uVar12;
                uVar11 = in_RAX[10];
                *(register0x00000020 + -100) = uVar11;
                uVar14 = in_RAX[0xb];
                *(register0x00000020 + -0x90) = uVar14;
                if (*(in_R
```

## capa evidence (16 total, showing top 15)
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': '', 'id': 'T1027'} (5): encode data using Base64, encode data using XOR, encrypt data using AES via x86 extensions, encrypt data using RC4 PRGA, encrypt data using Salsa20 or ChaCha
  ATT&CK {'parts': ['Defense Evasion', 'Obfuscated Files or Information', 'Indicator Removal from Tools'], 'tactic': 'Defense Evasion', 'technique': 'Obfuscated Files or Information', 'subtechnique': 'Indicator Removal from Tools', 'id': 'T1027.005'} (1): contain obfuscated stackstrings
  ATT&CK {'parts': ['Defense Evasion', 'Deobfuscate/Decode Files or Information'], 'tactic': 'Defense Evasion', 'technique': 'Deobfuscate/Decode Files or Information', 'subtechnique': '', 'id': 'T1140'} (1): decrypt data using AES via x86 extensions
  All rules (8): check for software breakpoints, parse credit card information, hash data using fnv, hash data using SHA1, hash data using SHA256, authenticate HMAC, execute syscall, hash data using SHA384

## pe_imports (0 imports, 0 high-signal)
  (no high-signal APIs matched)

## YARA matches (11)
  Rules: domain, IP, contains_base64, Misc_Suspicious_Strings, CRC32_poly_Constant, MD5_Constants, RIPEMD160_Constants, SHA1_Constants, SHA512_Constants, SHA2_BLAKE2_IVs, Chacha_256_constant

## floss
  error: FLOSS supports PE only (got elf)


<!-- evidence_assembler: used 9199/28000 chars across 5 tools -->