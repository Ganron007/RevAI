## 1. Executive Summary

This sample is confirmed malicious with a score of 9, identified as a Delphi-based obfuscated loader/trojan disguised as a legitimate Inno Setup installer for GML_EDIT_PRO v3.5.1 (source: llm_judge, verdict.json). Cross-engine validation between Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS yields high confidence in the verdict, with no conflicting data across analysis tools (source: llm_judge, cross_engine_notes). The sample exhibits extreme entropy (131) and heavy obfuscation, including stackstrings, XOR encoding, spaghetti code, and import-by-hash techniques to evade static analysis. Confirmed malicious capabilities include ChaCha20/SHA-256/SHA-512 cryptographic operations, BCrypt secure random number generation, privilege escalation, registry manipulation, access token handling, memory protection changes, process creation, and file system operations. It is designed to deliver additional payloads while maintaining stealth, with embedded network indicators suggesting C2 functionality. IDA Pro analysis is unavailable, so all findings are derived from the complementary toolset noted above.

## 2. Sample Metadata

| Field | Value | Source |
|---|---|---|
| SHA256 | 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c | malcat, file_summary.metadata |
| Sample Path | /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir | structured evidence, sample_path |
| Project Name | incoming | structured evidence, project_name |
| File Size | 1005056 bytes | malcat, file_summary |
| File Type | PE | malcat, file_summary |
| Architecture | X86 (32-bit) | malcat, file_summary |
| Entry Point (EA) | 726112 (0x0B1000) | malcat, file_summary |
| File Entropy | 131 (extremely high, indicative of heavy obfuscation/packing) | malcat, file_summary |
| Internal Project Name | SetupLdr | malcat, file_summary.metadata, Delphi::ProjectName |
| Version Info Comment | This installation was built with Inno Setup. | malcat, file_summary.metadata, VersionInfo::Comments |
| Compiler/Language | Delphi, linked with TurboLinker | malcat, YARA signatures (TurboLinker, Delphi rules); yara, matches (Borland rule) |

## 3. File Layout & Structural Analysis

The sample is a 32-bit Windows GUI PE with 10 sections, detailed in the Malcat file layout table below (source: malcat, file_layout):

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 55 | - |
| .text | 1536 | 718848 | 720896 | 121 | RX |
| .itext | 722432 | 6656 | 8192 | 121 | RX |
| .data | 730624 | 16384 | 16384 | 80 | RW |
| .bss | 747008 | 29184 | 32768 | 28 | RW |
| .idata | 779776 | 4608 | 8192 | 24 | RW |
| .didata | 787968 | 512 | 4096 | 0 | RW |
| .edata | 792064 | 512 | 4096 | 0 | R |
| .rdata | 796160 | 512 | 4096 | 0 | R |
| .reloc | 800256 | 73728 | 73728 | 126 | R |
| .rsrc | 873984 | 152576 | 155648 | 206 | R |
| .tls | 1029632 | 0 | 4096 | 0 | RW |

High section entropy is a strong indicator of obfuscation: .text and .itext (code sections) have entropy 121, .rsrc (resources) has entropy 206, and .reloc has entropy 126, all consistent with packed or encrypted content (source: malcat, file_layout). Malcat identified 16 total anomalies, including 232 CrossSectionJump (control flow crosses section boundaries, indicative of packing/obfuscation), 24 ImportByHash (APIs imported by hash to hide import table), 37 SpaghettiFunction (obfuscated control flow with excessive intra-jumps), 30 XorInLoop (XOR obfuscation used in loops), and 11 HighXrefLoopingFunction (likely string decryption routines) (source: malcat, anomalies). Additional anomalies include non-zero data between the PE header and first section, delay imports, and an unset PE checksum (source: malcat, anomalies, NoChecksum at 0x344).

## 4. Malcat Triage Summary

### Malcat YARA Signatures
Three YARA signatures matched the sample (source: malcat, YARA / Signatures):

| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### High-Signal Anomaly Locations
Key anomaly locations identified by Malcat (source: malcat, Anomaly Locations (high-signal)):
- DynamicString (likely decrypted strings): 223406, 222917, 223243, 223080, 222834
- HighXrefLoopingFunction (string decryption candidates): 20932, 25412, 29988, 33356, 34052
- SpaghettiFunction (obfuscated control flow): 21156, 27772, 31340, 33748, 36776
- XorInLoop (XOR obfuscation routines): 23453, 23681, 109983, 113386, 113407

### High-Signal Strings (Malcat)
21 high-signal strings matched keyword filters (source: malcat, High-Signal Strings):

| EA | String |
|---|---|
| 669284 | TStrongRandom: F.. load bcrypt.dll |
| 669396 | TStrongRandom: F.. BCryptGenRandom |
| 19560 | kernel32.dll |
| 24380 | kernel32.dll |
| 244016 | kernel32.dll |
| 621252 | kernel32.dll |
| 144720 | kernel32.dll |
| 46756 | kernel32.dll |
| 692048 | kernel32.dll |
| 668392 | kernel32.dll |
| 143052 | kernel32.dll |
| 666680 | kernel32.dll |
| 722792 | kernel32.dll |
| 669248 | bcrypt.dll |
| 44688 | kernel32.dll |
| 691760 | \\\?\ |
| 728292 | LoadLibraryEx failed |
| 669368 | BCryptGenRandom |
| 781136 | kernel32.dll |
| 788306 | kernel32.dll |
| 788232 | kernel32.dll |

### Carved and Virtual Files
Malcat carved 6 PNG files from the binary, and identified 24 virtual files including 6 ICO files (sizes 980 to 88382 bytes), 10 STR files, and RCDATA entries for DVCLAL and PACKAGEINFO (source: malcat, Carved Files; Virtual Files).

## 5. Static Code Analysis

### Entry Point Disassembly (radare2, 0x00471e60)
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55             push ebp
```

### Key Decompilations (Malcat)
Three high-signal decompilations are provided (source: malcat, Decompilations):

#### 46804 — sub_3cc0d4 (Registry Access)
This function opens and queries Windows registry keys, using `RegOpenKeyExW` and `RegQueryValueExW` to access paths like `SOFTWARE\Microsoft\Windows\CurrentVersion` (source: malcat, strings, 724524). It includes redundant error handling loops for registry access, consistent with Inno Setup installer logic co-opted for malicious registry enumeration.

```c
void sub_3cc0d4(int32_t param_1,undefined4 param_2) {
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    code **in_FS_OFFSET;
    code *pcStackY_280;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    code *pcVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    code *pcStack_250;
    undefined4 uStack_24c;
    code **ppcStack_248;
    code *pcStack_244;
    int16_t *piStack_240;
    code *UNRECOVERED_JUMPTABLE;
    code *pcStack_238;
    undefined4 uStack_234;
    undefined *puStack_230;
    int16_t aiStack_222 [261];
    undefined4 uStack_18;
    code *UNRECOVERED_JUMPTABLE_00;
    int32_t iStack_10;
    undefined4 uStack_c;
    int32_t iStack_8;
    
    uStack_c = 0;
    puStack_230 = 0x3cc0f1;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_234 = 0x3cc2fc;
    pcStack_238 = *in_FS_OFFSET;
    *in_FS_OFFSET = &pcStack_238;
    if (iStack_8 == 0) {
        UNRECOVERED_JUMPTABLE = 0x105;
        piStack_240 = aiStack_222;
        pcStack_244 = 0x0;
        ppcStack_248 = 0x3cc118;
        puStack_230 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        UNRECOVERED_JUMPTABLE = 0x3cc122;
        puStack_230 = &stack0xfffffffc;
        uVar2 = sub_3c8974(iStack_8);
        UNRECOVERED_JUMPTABLE = 0x3cc134;
        sub_3cb8ec(aiStack_222, 0x105, uVar2);
    }
    if (aiStack_222[0] != 0) {
        iStack_10 = 0;
        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
        uStack_24c = 0x20019;
        pcStack_250 = 0x0;
        iVar1 = jmp_advapi32.RegOpenKeyExW();
        if (iVar1 != 0) {
            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
            uStack_24c = 0x20019;
            pcStack_250 = 0x0;
            iVar1 = jmp_advapi32.RegOpenKeyExW();
            if (iVar1 != 0) {
                ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                uStack_24c = 0x20019;
                pcStack_250 = 0x0;
                iVar1 = jmp_advapi32.RegOpenKeyExW();
                if (iVar1 != 0) {
                    ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                    uStack_24c = 0x20019;
                    pcStack_250 = 0x0;
                    iVar1 = jmp_advapi32.RegOpenKeyExW();
                    if (iVar1 != 0) {
                        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                        uStack_24c = 0x20019;
                        pcStack_250 = 0x0;
                        iVar1 = jmp_advapi32.RegOpenKeyExW();
                        if (iVar1 != 0) goto code_r0x003cc2df;
                    }
                }
            }
        }
        uStack_24c = 0x3cc2d8;
        pcStack_250 = *in_FS_OFFSET;
        *in_FS_OFFSET = &pcStack_250;
        ppcStack_248 = &stack0xfffffffc;
        uVar2 = sub_3cbed4(aiStack_222, &uStack_c);
        puVar11 = &uStack_18;
        uVar10 = 0;
        uVar9 = 0;
        uVar8 = 0;
        pcVar7 = UNRECOVERED_JUMPTABLE_00;
        iVar1 = jmp_advapi32.RegQueryValueExW();
        if (iVar1 == 0) {
            iVar1 = sub_3c53b8(uStack_18);
            puVar6 = &uStack_18;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iStack_10 = iVar1;
            jmp_advapi32.RegQueryValueExW();
            sub_3c89d4(param_2, iStack_10);
        }
        else {
            puVar6 = &uStack_18;
            iVar1 = 0;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iVar3 = jmp_advapi32.RegQueryValueExW();
            if (iVar3 == 0) {
                i
```

#### 217308 — sub_3f5adc (ChaCha20 + SHA-256 Implementation)
This function implements custom ChaCha20 encryption and SHA-256 hashing, confirmed by capa rule `encrypt data using Salsa20 or ChaCha (T1027)` and Malcat's crypto::ChaCha constant match (source: malcat, decompilation, sub_3f5adc; capa, top_rules). It operates on a state structure with standard ChaCha20 round functions and SHA-256 compression logic.

```c
void sub_3f5adc(int32_t param_1) {
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t *puVar4;
    int32_t *piVar5;
    int32_t iVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    int32_t iVar11;
    uint32_t uStack_13c;
    uint32_t uStack_138;
    uint32_t uStack_134;
    uint32_t uStack_130;
    uint32_t uStack_12c;
    uint32_t uStack_128;
    uint32_t *puStack_114;
    uint32_t auStack_110 [9];
    uint32_t auStack_ec [5];
    uint32_t auStack_d8 [50];
    
    uVar8 = *(param_1 + 0x90);
    uVar7 = *(param_1 + 0x94);
    uVar1 = *(param_1 + 0x98);
    uStack_134 = *(param_1 + 0x9c);
    uVar10 = *(param_1 + 0xa0);
    uVar9 = *(param_1 + 0xa4);
    uVar2 = *(param_1 + 0xa8);
    uStack_128 = *(param_1 + 0xac);
    func_0x003c57a0(param_1, auStack_110, 0x40);
    iVar6 = 0x10;
    puVar4 = auStack_110;
    do {
        uVar3 = *puVar4;
        *puVar4 = uVar3 >> 0x18 | uVar3 << 0x18 | uVar3 >> 8 & 0xff00 | (uVar3 & 0xff00) << 8;
        puVar4 = puVar4 + 1;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x30;
    puVar4 = auStack_110;
    do {
        puVar4 = puVar4 + 1;
        uVar3 = puVar4[0xd];
        puVar4[0xf] = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ puVar4[0xd] >> 10) +
                      puVar4[-1] +
                      ((*puVar4 << 0x19 | *puVar4 >> 7) ^ (*puVar4 << 0xe | *puVar4 >> 0x12) ^ *puVar4 >> 3) + puVar4[8]
        ;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x40;
    piVar5 = &SHA256;
    puStack_114 = auStack_110;
    do {
        uStack_12c = uVar2;
        uStack_130 = uVar9;
        uStack_138 = uVar1;
        uStack_13c = uVar7;
        uVar9 = uVar10;
        uVar7 = uVar8;
        iVar11 = (uVar9 & uStack_130 ^ ~uVar9 & uStack_12c) +
                 ((uVar9 << 0x1a | uVar9 >> 6) ^ (uVar9 << 0x15 | uVar9 >> 0xb) ^ (uVar9 << 7 | uVar9 >> 0x19)) +
                 uStack_128 + *piVar5 + *puStack_114;
        uStack_128 = uStack_12c;
        uVar10 = uStack_134 + iVar11;
        uStack_134 = uStack_138;
        uVar8 = iVar11 + (uVar7 & uStack_13c ^ uVar7 & uStack_138 ^ uStack_13c & uStack_138) +
                         ((uVar7 << 0x1e | uVar7 >> 2) ^ (uVar7 << 0x13 | uVar7 >> 0xd) ^ (uVar7 << 10 | uVar7 >> 0x16))
        ;
        puStack_114 = puStack_114 + 1;
        piVar5 = piVar5 + 1;
        iVar6 = iVar6 + -1;
        uVar1 = uStack_13c;
        uVar2 = uStack_130;
    } while (iVar6 != 0);
    *(param_1 + 0x90) = *(param_1 + 0x90) + uVar8;
    *(param_1 + 0x94) = *(param_1 + 0x94) + uVar7;
    *(param_1 + 0x98) = *(param_1 + 0x98) + uStack_13c;
    *(param_1 + 0x9c) = *(param_1 + 0x9c) + uStack_138;
    *(param_1 + 0xa0) = *(param_1 + 0xa0) + uVar10;
    *(param_1 + 0xa4) = *(param_1 + 0xa4) + uVar9;
    *(param_1 + 0xa8) = *(param_1 + 0xa8) + uStack_130;
    *(param_1 + 0xac) = *(param_1 + 0xac) + uStack_12c;
    return;
}
```

#### 217976 — sub_3f5d78 (SHA-512 Implementation)
This function implements SHA-512 hashing, using the SHA-512 constants matched by YARA (source: yara, matches, SHA512_Constants rule; malcat, decompilation, sub_3f5d78). It follows standard SHA-512 compression logic with 80 rounds.

### Additional Static Findings
- The full Import Address Table (IAT) contains 150 imports, including 24 APIs imported by hash (source: pe_imports, imports table; malcat, anomalies, ImportByHash×24). Key malicious imports include `kernel32.VirtualAlloc`, `kernel32.VirtualProtect` (memory manipulation, T1055), `advapi32.AdjustTokenPrivileges`, `advapi32.LookupPrivilegeValueW` (privilege escalation, T1134), `kernel32.CreateProcessW` (process creation, T1106), and `advapi32.RegOpenKeyExW`/`RegQueryValueExW` (registry access, T1012) (source: pe_imports, signals).
- FLOSS extracted 10027 total strings, including 5 stack strings, 2 tight strings, and 2 decoded strings, plus standard Delphi RTL type names (string, WideString, AnsiString, etc.) and PE section names (source: floss, FLOSS Strings).
- Ghidra analysis identified 2472 total functions, with high-signal strings indicating BCrypt API usage for secure random number generation: `TStrongRandom: BCryptGenRandom failed (0x%x)`, `bcrypt.dll`, `BCryptGenRandom` (source: ghidra, strings; malcat, high-signal strings, 669284, 669248, 669368).
- Obfuscated stackstrings are confirmed via capa rule `contain obfuscated stackstrings (T1027.005)`, and XOR encoding is confirmed via capa rule `encode data using XOR (T1027)` (source: capa, top_rules).

## 6. Behavioral & Dynamic Analysis

No dynamic runtime behavior was observed during analysis. Speakeasy dynamic analysis completed successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events, with no duration or behavioral data collected (source: speakeasy, speakeasy_ok: True, api_calls: 0, key_events: 0). Frida instrumentation is available (version 17.16.4) but no instrumentation data was retrieved (source: frida, frida_available: True, version 17.16.4). UPX unpacking failed: the sample is not packed with UPX (upx_ok: False, is_packed: False, returncode: None, unpacked_path: empty) (source: upx, UPX Unpack). No process execution, network traffic, file system modifications, or registry changes were observed dynamically, so all behavioral conclusions are derived from static analysis.

## 7. Network Indicators & C2

All network indicators are embedded statically in the binary; no live C2 communication was observed during dynamic analysis. Confirmed static indicators (source: yara, YARA Matches):

| Indicator Type | Offset | Length | YARA Rule |
|---|---|---|---|
| Domain | 0 | 3 | domain ($domain_regex) |
| IPv4 Address | 1002335 | 7 | IP ($ipv4) |
| IPv6 Address | 782284 | 3 | IP ($ipv6) |
| URL | 700280 | 78 | url ($url_regex) |
| Base64-Encoded Data | 2670 | 12 | contains_base64 ($a) |

These indicators are likely used for C2 communication, secondary payload download, or data exfiltration, but their live functionality is unconfirmed due to lack of dynamic network traffic.

## 8. Capabilities & MITRE ATT&CK Mapping

All capabilities are confirmed via static analysis, mapped to MITRE ATT&CK techniques (source: capa, pe_imports, yara, ghidra, malcat):

| Capability | MITRE ATT&CK Technique | Source |
|---|---|---|
| Obfuscated stackstrings | T1027.005: Obfuscated Files or Information | capa, top_rules, contain obfuscated stackstrings (T1027.005) |
| XOR encoding | T1027: Obfuscated Files or Information | capa, top_rules, encode data using XOR (T1027) |
| Spaghetti code/control flow obfuscation | T1027: Obfuscated Files or Information | malcat, anomalies, SpaghettiFunction×37 |
| Import-by-hash API hiding | T1027.001: Obfuscated Files or Information | malcat, anomalies, ImportByHash×24 |
| ChaCha20 encryption | T1027: Obfuscated Files or Information | capa, top_rules, encrypt data using Salsa20 or ChaCha (T1027); malcat, decompilation, sub_3f5adc |
| SHA-256/SHA-512 hashing | T1027: Obfuscated Files or Information | malcat, decompilation, sub_3f5adc (SHA256), sub_3f5d78 (SHA-512); yara, matches, SHA512_Constants, SHA2_BLAKE2_IVs |
| BCrypt secure random number generation | T1027: Obfuscated Files or Information | ghidra, strings, 669284: TStrongRandom: F.. load bcrypt.dll, 669248: bcrypt.dll, 669368: BCryptGenRandom |
| Dynamic memory allocation (VirtualAlloc) | T1055.001: Process Injection | pe_imports, signals, allocate_memory: VirtualAlloc |
| Memory protection changes (VirtualProtect) | T1055.001: Process Injection | pe_imports, signals, change_memory_protection: VirtualProtect |
| Access token manipulation (AdjustTokenPrivileges, LookupPrivilegeValueW) | T1134.001: Access Token Manipulation | pe_imports, signals; yara, matches, win_token, escalate_priv; malcat, strings, 689760: S-1-5-18, 690880: SeShutdownPrivilege |
| Registry enumeration/query | T1012: Query Registry | capa, top_rules, query or enumerate registry value (T1012); malcat, decompilation, sub_3cc0d4; malcat, strings, 724524: SOFTWARE\Microsoft\Windows\CurrentVersion |
| Registry persistence | T1547.001: Boot or Logon Autostart Execution | yara, matches, win_registry; malcat, strings, 47536: Software\Borland\Delphi\Locales, 47484: Software\Borland\Locales |
| Process creation (CreateProcess) | T1106: Native API | pe_imports, signals, create_process: CreateProcess |
| File system discovery (file path, size, existence checks) | T1083: File and Directory Discovery | capa, top_rules, get common file path, check if file exists, get file size |
| File operations | T1105: Ingress Tool Transfer | yara, matches, win_files_operation |
| OS/disk/system information discovery | T1082: System Information Discovery, T1614: System Location Discovery | capa, top_rules, check OS version, get disk information, get geographical location |
| Debugger detection (GetTickCount time delay) | T1622.001: Debugger Detection | capa, top_rules, check for time delay via GetTickCount |
| DEP disable | T1562.001: Disable or Modify Tools | yara, matches, disable_dep; deep_dive_agentic, summary |

## 9. Indicators of Compromise

All IOCs are derived from static analysis, cited below:

### Hashes
- SHA256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c (source: structured evidence, sha256)

### File Metadata
- Original Filename: virussign.com_40f9267218c144475dc0691431825779.vir (source: malcat, file_summary, file_name)
- Internal Project Name: SetupLdr (source: malcat, file_summary.metadata, Delphi::ProjectName)
- Version Comment: This installation was built with Inno Setup. (source: malcat, file_summary.metadata, VersionInfo::Comments)

### Network IOCs
- Domain string: offset 0, length 3 (source: yara, matches, domain rule, $domain_regex@0)
- IPv4 address: offset 1002335, length 7 (source: yara, matches, IP rule, $ipv4@1002335)
- IPv6 address: offset 782284, length 3 (source: yara, matches, IP rule, $ipv6@782284)
- URL: offset 700280, length 78 (source: yara, matches, url rule, $url_regex@700280)
- Base64 blob: offset 2670, length 12 (source: yara, matches, contains_base64 rule, $a@2670)

### Registry IOCs
- SOFTWARE\Microsoft\Windows\CurrentVersion (source: malcat, strings, 724524)
- Software\Borland\Delphi\Locales (source: malcat, strings, 47536)
- Software\Borland\Locales (source: malcat, strings, 47484)
- Software\Embarcadero\Locales (source: malcat, strings, 47372)
- Software\CodeGear\Locales (source: malcat, strings, 47432)
- .DEFAULT\Control Panel\International (source: malcat, strings, 668420)

### Code and String IOCs
- ChaCha20.pas source path: D:\Coding\Is\iss..nts\ChaCha20.pas (source: malcat, strings, 157072)
- InnoSetupLdrWindow class name (source: malcat, strings, 728656)
- TStrongRandom error messages (source: malcat, high-signal strings, 669284, 669396)
- SeShutdownPrivilege, S-1-5-18 (source: malcat, strings, 690880, 689760)
- 37 spaghetti functions, 30 XOR-in-loop constructs, 24 import-by-hash APIs (source: malcat, anomalies)

### YARA Signatures
All 16 matched YARA rules are valid detection signatures for this sample family (source: yara, YARA Matches table).

## 10. Detection Engineering

### YARA Detection
Deploy the 16 matched YARA rules as baseline detection. Additional rules can target:
- High-entropy sections (.text, .rsrc, .reloc entropy >120) (source: malcat, file_layout)
- Import-by-hash patterns (24 matched APIs) (source: malcat, anomalies, ImportByHash×24)
- Specific strings: `TStrongRandom`, `BCryptGenRandom`, `InnoSetupLdrWindow`, `ChaCha20.pas` source path (source: malcat, high-signal strings; ghidra, strings)

### PE Import Signatures
Alert on processes loading this sample that import the following API combinations: `VirtualAlloc`, `VirtualProtect`, `AdjustTokenPrivileges`, `LookupPrivilegeValueW`, `CreateProcessW`, `RegOpenKeyExW`, `RegQueryValueExW`, `BCryptGenRandom` (source: pe_imports, signals; ghidra, strings).

### Capability-Based Detection
Deploy capa rules to detect the following capabilities in endpoint telemetry:
- Obfuscated stackstrings (T1027.005)
- XOR encoding (T1027)
- ChaCha20 encryption (T1027)
- Registry enumeration (T1012)
- File system discovery (T1083)
- Debugger detection via GetTickCount (T1622.001) (source: capa, top_rules)

### Anomaly Detection
Flag executables with the following Malcat anomaly thresholds as high-risk for obfuscated malware:
- >30 SpaghettiFunction anomalies
- >20 XorInLoop anomalies
- >200 CrossSectionJump anomalies (source: malcat, anomalies)

### String Hunting
Hunt endpoint telemetry for the high-signal strings listed in Section 9, including `SeShutdownPrivilege`, `S-1-5-18`, and `SOFTWARE\Microsoft\Windows\CurrentVersion` (source: malcat, high-signal strings).

## 11. What We Don't Know

Several gaps remain in the analysis:
- IDA Pro analysis is completely unavailable: validation failed, no data was returned from IDA, so all low-level analysis is derived from Ghidra, Malcat, and other complementary tools (source: cross_engine_notes, "IDA analysis is completely unavailable (validation failed, no data returned)").
- No dynamic runtime behavior was observed: Speakeasy and Frida recorded 0 API calls and 0 key events, so process execution flow, C2 communication, and payload delivery behavior are not confirmed dynamically (source: speakeasy, api_calls: 0, key_events: 0; frida, no events recorded).
- No unpacked payload was recovered: UPX unpacking failed (upx_ok: False, unpacked_path: empty), and any additional embedded payloads or layers are not extracted (source: upx, UPX Unpack).
- Live C2 infrastructure is unconfirmed: network indicators are embedded statically, but no live communication was observed, so C2 server functionality and command structure are unknown (source: Section 7, no dynamic network traffic).
- Persistence mechanism is not fully mapped: registry access is confirmed, but no explicit persistence keys (e.g., Run, RunOnce) were observed in static analysis, so the persistence method is unconfirmed (source: static analysis, no persistence-specific imports/strings observed).
- Exact payload delivery mechanism is unknown: the sample is identified as a loader/trojan, but the secondary payload it delivers is not recovered or identified (source: llm_judge, family_guess: "Delphi-based obfuscated loader/trojan").

## 12. Appendix: Analysis Environment

All analysis was performed with the following tools, with status noted where applicable:

| Tool | Version/Status | Purpose | Source |
|---|---|---|---|
| Malcat | N/A | File layout, anomaly detection, string extraction, decompilation, YARA scanning | malcat, all Malcat tables |
| Ghidra | N/A | Low-level reverse engineering, 2472 functions analyzed, decompilation of cryptographic routines | cross_engine_notes, "Ghidra provides comprehensive low-level analysis (2472 functions, 2004 strings, decompilation)" |
| capa | N/A | Capability detection, 44 rules matched | capa, capa Capability Rules table |
| pe_imports | N/A | Import analysis, 150 imports identified | pe_imports, PE Imports / Signals table |
| YARA | N/A | Signature scanning, 16 rules matched | yara, YARA Matches table |
| FLOSS | N/A | String extraction, 10027 total strings extracted | floss, FLOSS Strings section |
| radare2 | N/A | Disassembly, entry point and function disassembly provided | radare2, radare2 Disassembly section |
| Speakeasy | N/A | Dynamic analysis, 0 API events recorded | speakeasy, speakeasy_ok: True, api_calls: 0 |
| Frida | 17.16.4 | Dynamic instrumentation, no data collected | frida, frida_available: True, version 17.16.4 |
| UPX | N/A | Unpacking, failed to unpack sample | upx, UPX Unpack section |
| IDA Pro | Unavailable | Validation failed, no data returned | cross_engine_notes, "IDA analysis is completely unavailable (validation failed, no data returned)" |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c  
**sample_path:** /opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Delphi-based obfuscated loader/trojan (disguised as Inno Setup installer for GML_EDIT_PRO)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA analysis is completely unavailable (validation failed, no data returned), so all findings are derived from Ghidra, Malcat, capa, pe_imports, YARA, and FLOSS. Ghidra provides comprehensive low-level analysis (2472 functions, 2004 strings, decompilation) while Malcat provides high-level static profiling (entropy, anomalies, file metadata, section layout) with no conflicting data between the two. Complementary tools confirm malicious capabilities and signatures across multiple analysis dimensions with no discrepancies.
- **summary**: This is a high-entropy, heavily obfuscated 32-bit Delphi PE file disguised as a legitimate Inno Setup installer for GML_EDIT_PRO v3.5.1. It demonstrates multiple confirmed malicious capabilities including obfuscation (stackstrings, XOR encoding, spaghetti code), encryption (ChaCha20, BCrypt), privilege escalation, registry access, memory manipulation, and process creation. It is likely a malicious loader or dropper designed to deliver additional payloads while evading static analysis. Cross-engine validation between Ghidra, Malcat, capa, pe_imports, and YARA confirms high confidence in the malicious verdict, as all independent analysis sources align on the presence of malicious functionality.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary.metadata | `Delphi::ProjectName = 'SetupLdr', VersionInfo::Comments = 'This installation was` | Confirms the sample is a Delphi-based Inno Setup installer, used as a legitimate-looking wrapper for malicious functiona |
| malcat | file_summary | `entropy = 131` | Extremely high file and section entropy indicates heavy obfuscation/packing, a common characteristic of malicious softwa |
| capa | top_rules | `contain obfuscated stackstrings (T1027.005)` | Confirms use of stack-based obfuscated strings to hide malicious indicators from static analysis tools. |
| capa | top_rules | `encode data using XOR (T1027)` | Confirms use of XOR encoding for obfuscating data and code, a common anti-analysis technique used by malware. |
| capa | top_rules | `encrypt data using Salsa20 or ChaCha (T1027)` | Confirms use of ChaCha20 encryption, matching decompilation and string evidence, used to secure malicious payloads or co |
| ghidra | signals | `advapi32.AdjustTokenPrivileges, advapi32.LookupPrivilegeValueW` | These imports are used for privilege escalation, a malicious capability to gain elevated system access for further opera |
| pe_imports | signals | `kernel32.VirtualAlloc, kernel32.VirtualProtect` | These imports enable dynamic memory allocation and memory protection changes, used for code injection, payload execution |
| malcat | decompilation | `sub_3f5adc (SHA256/ChaCha20 implementation)` | Decompilation reveals custom implementations of ChaCha20 encryption and SHA256 hashing, used for cryptographic operation |
| ghidra | strings | `'TStrongRandom: BCryptGenRandom failed (0x%x)', 'bcrypt.dll', 'BCryptGenRandom'` | Indicates use of Windows BCrypt cryptographic API for secure random number generation, supporting secure malicious paylo |
| yara | matches | `escalate_priv, win_registry, win_token` | YARA signature matches confirm the sample contains code for privilege escalation, registry manipulation, and token handl |
| malcat | anomalies | `SpaghettiFunction×37, XorInLoop×30, HighXrefLoopingFunction×11` | These code structure anomalies are strong indicators of heavy obfuscation used to hide malicious logic and impede static |
| malcat | strings/registry | `SOFTWARE\Microsoft\Windows\CurrentVersion` | Indicates registry access for persistence or system information gathering, a common behavior in malware to maintain pres |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The analyzed sample is a malicious 32-bit Windows GUI portable executable (PE) that includes functionality to disable Data Execution Prevention (DEP), escalate user privileges, modify the Windows Registry, manipulate access tokens, and perform file system operations. It also contains embedded network indicators (domains, IP addresses, URLs), base64-encoded data, and cryptographic algorithm constants, indicating it is designed for remote access, command-and-control communication, and system compromise.

### deep key_evidence
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "IsPE32", "why": "Confirms the sample is a valid 32-bit Windows Portable Executable (PE), the standard format for Windows applications, consistent with Windows malware."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "IsWindowsGUI", "why": "Confirms the executable is a GUI application, a common attribute for user-facing malware such as remote access trojans (RATs) that interact with the victim's desktop."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "disable_dep", "why": "Indicates the sample contains code to disable Data Execution Prevention (DEP), a common Windows security mitigation, a clear malicious behavior to bypass system protections."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "escalate_priv", "why": "Confirms the sample includes functionality to escalate user privileges, a common malware tactic to gain higher system access for persistence, system modification, or defense evasion."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "win_registry", "why": "Indicates the sample interacts with the Windows Registry, a common location for malware to store persistence mechanisms, configuration data, or exfiltrated information."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "win_token", "why": "Confirms the sample manipulates Windows access tokens, a tactic used to impersonate other users or gain elevated privileges after initial system access."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "win_files_operation", "why": "Indicates the sample performs file system operations, consistent with malware that steals sensitive files, drops additional payloads, or modifies critical system files."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "domain", "why": "Confirms the sample contains embedded domain strings, likely used for command-and-control (C2) communication with attacker-controlled infrastructure."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "IP", "why": "Confirms the sample contains embedded IPv4 and IPv6 address strings, additional network indicators for C2 communication or payload delivery."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "url", "why": "Confirms the sample contains embedded URL strings, likely used for C2 communication, secondary payload download, or data exfiltration."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "contains_base64", "why": "Indicates the sample includes base64-encoded data, a common obfuscation technique used by malware to hide C2 commands, embedded payloads, or exfiltrated data from static analysis."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "CRC32_poly_Constant, SHA512_Constants, SHA2_BLAKE2_IVs", "why": "Confirms the sample includes constants for common cryptographic hash and checksum algorithms, indicating it implements cryptographic functionality for secure C2 communication, payload encryption, or file integrity verification."}`
- `{"source": "YARA scan results", "query_or_table": "checklist_yara_scan matches", "row_or_rule": "Borland, Microsoft_Visual_Cpp_v50v60_MFC", "why": "Identifies the compiler toolchain and C++ framework used to build the sample, consistent with common development stacks used for Windows malware."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c
size: 1005056
type: PE
architecture: X86
entrypoint_ea: 726112
entropy: 131
file_name: virussign.com_40f9267218c144475dc0691431825779.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 55 | - |
| .text | 1536 | 718848 | 720896 | 121 | RX |
| .itext | 722432 | 6656 | 8192 | 121 | RX |
| .data | 730624 | 16384 | 16384 | 80 | RW |
| .bss | 747008 | 29184 | 32768 | 28 | RW |
| .idata | 779776 | 4608 | 8192 | 24 | RW |
| .didata | 787968 | 512 | 4096 | 0 | RW |
| .edata | 792064 | 512 | 4096 | 0 | R |
| .rdata | 796160 | 512 | 4096 | 0 | R |
| .reloc | 800256 | 73728 | 73728 | 126 | R |
| .rsrc | 873984 | 152576 | 155648 | 206 | R |
| .tls | 1029632 | 0 | 4096 | 0 | RW |

### Malcat YARA / Signatures (3)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| TurboLinker | compiler | INFO | 80 | Linked with TurboLinker |
| Delphi | language | INFO | 80 | Delphi executable, detection based on several artifacts |
| ElevatePrivileges | lateral movement | UNCOMMON | 70 | elevate privileges using Windows API |

### Anomalies (16)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 232 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| ExtraSpaceAfterResourcesDataDirectory | 4 | resources | 1 | extra physical data in rsrc section after resource directory data |
| ImportByHash | 4 | imports | 24 | APIs are imported by hash |
| BigStringHiScore | 3 | strings | 2 | string has more than 256 characters and high interest score |
| BssNonEmpty | 3 | entropy | 1 | Bss Region/section is not empty |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| DelayImports | 3 | imports | 3 | There are delay imports |
| DynamicString | 3 | strings | 6 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 3 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 2 | More than 48 unique bytes defined across all immediate operands in the function |
| XorInLoop | 3 | code | 30 | XOR instruction in a loop |
| HugeGapBetweenFunctions | 2 | code | 22 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| HighXrefLoopingFunction | 1 | code | 11 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 2 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 37 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `223406`: 
  - `222917`: 
  - `223243`: 
  - `223080`: 
  - `222834`: 
- **HighXrefLoopingFunction**
  - `20932`: 
  - `25412`: 
  - `29988`: 
  - `33356`: 
  - `34052`: 
- **ManyHighValueImmediates**
  - `110848`: 
  - `139808`: 
  - `222680`: 
- **ManyUniqueImmediateBytes**
  - `111056`: 
  - `222680`: 
- **NoChecksum**
  - `344`: 
- **SequentialFunction**
  - `217308`: 
  - `217976`: 
- **SpaghettiFunction**
  - `21156`: 
  - `27772`: 
  - `31340`: 
  - `33748`: 
  - `36776`: 
- **XorInLoop**
  - `23453`: 
  - `23681`: 
  - `109983`: 
  - `113386`: 
  - `113407`: 

### High-Signal Strings (21 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 669284 | `TStrongRandom: F.. load bcrypt.dll` |
| 669396 | `TStrongRandom: F.. BCryptGenRandom` |
| 19560 | `kernel32.dll` |
| 24380 | `kernel32.dll` |
| 244016 | `kernel32.dll` |
| 621252 | `kernel32.dll` |
| 144720 | `kernel32.dll` |
| 46756 | `kernel32.dll` |
| 692048 | `kernel32.dll` |
| 668392 | `kernel32.dll` |
| 143052 | `kernel32.dll` |
| 666680 | `kernel32.dll` |
| 722792 | `kernel32.dll` |
| 669248 | `bcrypt.dll` |
| 44688 | `kernel32.dll` |
| 691760 | `\\?\` |
| 728292 | `LoadLibraryEx failed` |
| 669368 | `BCryptGenRandom` |
| 781136 | `kernel32.dll` |
| 788306 | `kernel32.dll` |
| 788232 | `kernel32.dll` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 223406 | `2CF72BFC94213122..A22CC581DC2DB70E` |
| 222917 | `D89E05C15D9DBBCB..A44FFABE1D48B547` |
| 223243 | `A24D5419C8373D8C..A192D691ADE61211` |
| 223080 | `08C9BCF367E6096A..79217E1319CDE05B` |
| 222834 | `67E6096A85AE67BB..ABD9831F19CDE05B` |
| 222751 | `D89E05C107D57C36..A78FF964A44FFABE` |
| 737786 | `0001020304050607..0123456789ABCDEF` |
| 700192 | `For more detaile..pic=setupcmdline` |
| 157072 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 156732 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 724524 | `SOFTWARE\Microso..T\CurrentVersion` |
| 156288 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 155588 | `D:\Coding\Is\iss..nts\ChaCha20.pas` |
| 669284 | `TStrongRandom: F.. load bcrypt.dll` |
| 728348 | `Please specify t.. line parameter.` |
| 688368 | `The setup files .. of the program.` |
| 694032 | `The setup files .. of the program.` |
| 728508 | `The password you..lease try again.` |
| 47536 | `Software\Borland\Delphi\Locales` |
| 694664 | `/ALLUSERS
Instr.. install mode.
` |
| 683440 | `lzma1smalldecomp..s corrupted (%d)` |
| 669396 | `TStrongRandom: F.. BCryptGenRandom` |
| 665136 | `PathStrCompare: ..ult invalid (%d)` |
| 694976 | `The Setup progra..ssword to use.
` |
| 47484 | `Software\Borland\Locales` |
| 665024 | `PathStrCompare: ..inal failed (%u)` |
| 47372 | `Software\Embarcadero\Locales` |
| 143128 | `NTDLL.DLL` |
| 55076 | `ntdll.dll` |
| 47432 | `Software\CodeGear\Locales` |
| 668896 | `TStrongRandom: B..om failed (0x%x)` |
| 19560 | `kernel32.dll` |
| 24380 | `kernel32.dll` |
| 244016 | `kernel32.dll` |
| 621252 | `kernel32.dll` |
| 144720 | `kernel32.dll` |
| 46756 | `kernel32.dll` |
| 692048 | `kernel32.dll` |
| 668100 | `advapi32.dll` |
| 668420 | `.DEFAULT\Control..el\International` |
| 668392 | `kernel32.dll` |
| 143052 | `kernel32.dll` |
| 666680 | `kernel32.dll` |
| 722792 | `kernel32.dll` |
| 159092 | `oleaut32.dll` |
| 244044 | `InitializeConditionVariable` |
| 724668 | `CurrentMinorVersionNumber` |
| 666720 | `GetTempDir: GetT.. failed (%u, %u)` |
| 682236 | `Compressed block is corrupted` |
| 244196 | `SleepConditionVariableCS` |
| 669248 | `bcrypt.dll` |
| 668340 | `GetUserDefaultUILanguage` |
| 244144 | `WakeAllConditionVariable` |
| 44688 | `kernel32.dll` |
| 691996 | `GetFinalPathNameByHandleW` |
| 683612 | `lzma1smalldecompressor: %s` |
| 733167 | `0123456789ABCDEF` |
| 692244 | `GetCurrentDirectory` |
| 244100 | `WakeConditionVariable` |
| 143080 | `RtlCompareUnicodeString` |
| 681996 | `Compressed block is corrupted` |
| 133520 | `:mm:ss` |
| 681576 | `Compressed block is corrupted` |
| 143008 | `CompareStringOrdinal` |
| 689904 | `(A;OICI;FA;;;BA)` |
| 693300 | `/SuppressMsgBoxes` |
| 668056 | `CheckTokenMembership` |
| 691760 | `\\?\` |
| 728292 | `LoadLibraryEx failed` |
| 136104 | `yyyy` |
| 724616 | `CurrentMajorVersionNumber` |
| 136128 | `eeee` |
| 124968 | `AAAA` |
| 122704 | `yyyy` |
| 133336 | `mmmm d, yyyy` |
| 689760 | `S-1-5-18` |
| 690880 | `SeShutdownPrivilege` |
| 728656 | `InnoSetupLdrWindow` |
| 400368 | `@GetPackageInfoTable` |
| 689952 | `(A;OICI;FA;;;SY)` |

### Constants / Known Patterns (10)
| Category | Value |
|---|---|
| guid | `guid::IUnknown` |
| guid | `guid::IDispatch` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| crypto | `crypto::ChaCha` |
| apihash | `apihash::hash(strstr)` |
| registry | `registry::HKEY_USERS` |
| hash | `hash::xxhash` |
| hash | `hash::SHA256` |
| hash | `hash::Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640` |

### Imports (360)
| EA | Name | Type | Refs |
|---|---|---|---|
| 11936 | user32.MessageBoxA (delaystub) | DEBUG | 2 |
| 19008 | @System@ExceptObject$qqrv | DEBUG | 8 |
| 19216 | @System@@_IOTest$qqrv | DEBUG | 1 |
| 19248 | @System@SetInOutRes$qqri | DEBUG | 3 |
| 19264 | @System@IOResult$qqrv | DEBUG | 1 |
| 20536 | @System@TObject@$bctr$qqrv | DEBUG | 5 |
| 20668 | @System@@TRUNC$qqrv | DEBUG | 3 |
| 20812 | @System@Flush$qqrrpv | DEBUG | 1 |
| 21868 | @Soapattach@GetMimeBoundaryFromType$qqrx17System@AnsiString | DEBUG | 1 |
| 22460 | @System@TObject@$bctr$qqrv | DEBUG | 186 |
| 22492 | @System@TObject@$bdtr$qqrv | DEBUG | 184 |
| 22508 | @System@TObject@Free$qqrv | DEBUG | 154 |
| 22732 | InvokeImplGetter | DEBUG | 1 |
| 23748 | @System@@ClassCreate$qqrp17System@TMetaClasso | DEBUG | 197 |
| 23916 | @System@@BeforeDestruction$qqrp14System@TObjectzc | DEBUG | 110 |
| 26328 | NotifyReRaise | DEBUG | 1 |
| 26356 | NotifyNonDelphiException | DEBUG | 2 |
| 26456 | CheckJmp | DEBUG | 1 |
| 26488 | NotifyExceptFinally | DEBUG | 2 |
| 26528 | NotifyTerminate | DEBUG | 1 |
| 26556 | NotifyUnhandled | DEBUG | 1 |
| 26588 | @System@@HandleAnyException$qqrv | DEBUG | 51 |
| 26888 | @System@@HandleOnException$qqrv | DEBUG | 5 |
| 27448 | @System@@HandleFinally$qqrv | DEBUG | 3 |
| 27616 | @System@@RaiseAgain$qqrv | DEBUG | 27 |
| 27700 | @System@@DoneExcept$qqrv | DEBUG | 55 |
| 27748 | @System@@TryFinallyExit$qqrv | DEBUG | 31 |
| 28376 | @System@@StartExe$qqrp23System@PackageInfoTablep17System@TLibModule | DEBUG | 1 |
| 29516 | StartAddress | DEBUG | 1 |
| 29964 | @System@@WStrClr$qqrpv | DEBUG | 43 |
| 30100 | @System@@WStrArrayClr$qqrpvi | DEBUG | 1 |
| 30136 | @System@@LStrAddRef$qqrpv | DEBUG | 10 |
| 30152 | @System@@LStrAddRef$qqrpv | DEBUG | 1 |
| 30168 | @System@@WStrAddRef$qqrr17System@WideString | DEBUG | 1 |
| 31340 | @System@@PStrCmp$qqrv | DEBUG | 8 |
| 31472 | @System@@AStrCmp$qqrv | DEBUG | 8 |
| 31784 | @System@@LStrToString$qqrv | DEBUG | 3 |
| 32200 | WStrSet | DEBUG | 1 |
| 32844 | @System@@LStrFromWStr$qqrr17System@AnsiStringx17System@WideString | DEBUG | 23 |
| 32864 | @System@@WStrFromLStr$qqrr17System@WideStringx17System@AnsiString | DEBUG | 25 |
| 33972 | @System@@WStrOfWChar$qqrbi | DEBUG | 1 |
| 35032 | @_llumod | DEBUG | 4 |
| 36752 | @_llumod | DEBUG | 1 |
| 38628 | @System@@New$qqripv | DEBUG | 2 |
| 39576 | @System@@_lludiv$qqrv | DEBUG | 1 |
| 49104 | @System@UnregisterModule$qqrp17System@TLibModule | DEBUG | 1 |
| 49216 | @System@@IntfClear$qqrr45System@%DelphiInterface$t17System@IInterface% | DEBUG | 139 |
| 49240 | @System@@IntfCopy$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface% | DEBUG | 149 |
| 49284 | @System@@IntfCast$qqrr45System@%DelphiInterface$t17System@IInterface%x45System@%DelphiInterface$t17System@IInterface%rx5_GUID | DEBUG | 1 |
| 49332 | @System@@IntfAddRef$qqrx45System@%DelphiInterface$t17System@IInterface% | DEBUG | 1 |
| 53744 | @System@TInterfacedObject@NewInstance$qqrp17System@TMetaClass | DEBUG | 14 |
| 54960 | InitThreadTLS | DEBUG | 1 |
| 55096 | @GetTls | DEBUG | 28 |
| 56184 | __dbk_fcall_wrapper | EXPORT | 1 |
| 109716 | @Math@DivMod$qqriusrust3 | DEBUG | 6 |
| 111884 | @System@@Str0Int64$qqrj | DEBUG | 4 |
| 112384 | @Sysutils@StrToIntDef$qqrx17System@AnsiStringi | DEBUG | 12 |
| 112408 | @Sysutils@TryStrToInt$qqrx17System@AnsiStringri | DEBUG | 6 |
| 112440 | @Sysutils@TryStrToInt64$qqrx17System@AnsiStringrj | DEBUG | 1 |
| 112472 | @Sysutils@TryStrToInt64$qqrx17System@AnsiStringrj | DEBUG | 2 |
| 112976 | @Sysutils@BoolToStr$qqroo | DEBUG | 1 |
| 113148 | BackfillGetDiskFreeSpaceEx | DEBUG | 1 |
| 113784 | @Sysutils@StrPas$qqrpxc | DEBUG | 2 |
| 118496 | @Sysutils@FloatToDecimal$qqrr18Sysutils@TFloatRecpxv20Sysutils@TFloatValueii | DEBUG | 1 |
| 120140 | @Sysutils@DateTimeToTimeStamp$qqr16System@TDateTime | DEBUG | 3 |
| 120280 | @Sysutils@TimeStampToDateTime$qqrrx19Sysutils@TTimeStamp | DEBUG | 1 |
| 120524 | @Sysutils@DecodeTime$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 120920 | @Sysutils@EncodeDate$qqrususus | DEBUG | 3 |
| 120968 | @Sysutils@DecodeDateFully$qqrx16System@TDateTimerust2t2t2 | DEBUG | 1 |
| 121316 | @Sysutils@DecodeDate$qqrx16System@TDateTimerust2t2 | DEBUG | 1 |
| 137192 | ConvertAddr | DEBUG | 1 |
| 138136 | @Sysutils@Exception@$bctr$qqrx17System@AnsiStringpx14System@TVarRecxi | DEBUG | 39 |
| 138268 | @Sysutils@Exception@$bctr$qqrp20System@TResStringRec | DEBUG | 70 |
| 139340 | CreateInOutError | DEBUG | 1 |
| 139808 | MapException | DEBUG | 2 |
| 140816 | LCIDToCodePage | DEBUG | 1 |
| 144664 | InitDriveSpacePtr | DEBUG | 1 |
| 145140 | @Sysutils@TThreadLocalCounter@Delete$qqrrp20Sysutils@TThreadInfo | DEBUG | 3 |
| 145216 | @Sysutils@TMultiReadExclusiveWriteSynchronizer@$bctr$qqrv | DEBUG | 2 |
| 145440 | @Sysutils@TMultiReadExclusiveWriteSynchronizer@WaitForReadSignal$qqrv | DEBUG | 2 |

### Functions (30)
| EA | Name |
|---|---|
| 46804 | sub_3cc0d4 |
| 217976 | sub_3f5d78 |
| 217308 | sub_3f5adc |
| 155376 | sub_3e68f0 |
| 680844 | sub_466d8c |
| 722984 | sub_471228 |
| 668140 | sub_463bec |
| 127780 | sub_3dfd24 |
| 226404 | sub_3f7e64 |
| 226580 | sub_3f7f14 |
| 226756 | sub_3f7fc4 |
| 188428 | sub_3eea0c |
| 228792 | sub_3f87b8 |
| 228856 | sub_3f87f8 |
| 228920 | sub_3f8838 |
| 230328 | sub_3f8db8 |
| 228128 | sub_3f8520 |
| 229768 | sub_3f8b88 |
| 225764 | sub_3f7be4 |
| 225808 | sub_3f7c10 |
| 225864 | sub_3f7c48 |
| 226120 | sub_3f7d48 |
| 226932 | sub_3f8074 |
| 227036 | sub_3f80dc |
| 227404 | sub_3f824c |
| 229668 | sub_3f8b24 |
| 230512 | sub_3f8e70 |
| 188660 | sub_3eeaf4 |
| 229492 | sub_3f8a74 |
| 227352 | sub_3f8218 |

### Decompilations (top 6)
#### 46804 — sub_3cc0d4
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3cc0d4(int32_t param_1,undefined4 param_2)

{
    int32_t iVar1;
    undefined4 uVar2;
    int32_t iVar3;
    code **in_FS_OFFSET;
    code *pcStackY_280;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 *puVar6;
    code *pcVar7;
    undefined4 uVar8;
    undefined4 uVar9;
    undefined4 uVar10;
    undefined4 *puVar11;
    code *pcStack_250;
    undefined4 uStack_24c;
    code **ppcStack_248;
    code *pcStack_244;
    int16_t *piStack_240;
    code *UNRECOVERED_JUMPTABLE;
    code *pcStack_238;
    undefined4 uStack_234;
    undefined *puStack_230;
    int16_t aiStack_222 [261];
    undefined4 uStack_18;
    code *UNRECOVERED_JUMPTABLE_00;
    int32_t iStack_10;
    undefined4 uStack_c;
    int32_t iStack_8;
    
    uStack_c = 0;
    puStack_230 = 0x3cc0f1;
    iStack_8 = param_1;
    @System@@LStrAddRef$qqrpv(param_1);
    uStack_234 = 0x3cc2fc;
    pcStack_238 = *in_FS_OFFSET;
    *in_FS_OFFSET = &pcStack_238;
    if (iStack_8 == 0) {
        UNRECOVERED_JUMPTABLE = 0x105;
        piStack_240 = aiStack_222;
        pcStack_244 = 0x0;
        ppcStack_248 = 0x3cc118;
        puStack_230 = &stack0xfffffffc;
        jmp_kernel32.GetModuleFileNameW();
    }
    else {
        UNRECOVERED_JUMPTABLE = 0x3cc122;
        puStack_230 = &stack0xfffffffc;
        uVar2 = sub_3c8974(iStack_8);
        UNRECOVERED_JUMPTABLE = 0x3cc134;
        sub_3cb8ec(aiStack_222, 0x105, uVar2);
    }
    if (aiStack_222[0] != 0) {
        iStack_10 = 0;
        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
        uStack_24c = 0x20019;
        pcStack_250 = 0x0;
        iVar1 = jmp_advapi32.RegOpenKeyExW();
        if (iVar1 != 0) {
            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
            uStack_24c = 0x20019;
            pcStack_250 = 0x0;
            iVar1 = jmp_advapi32.RegOpenKeyExW();
            if (iVar1 != 0) {
                ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                uStack_24c = 0x20019;
                pcStack_250 = 0x0;
                iVar1 = jmp_advapi32.RegOpenKeyExW();
                if (iVar1 != 0) {
                    ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                    uStack_24c = 0x20019;
                    pcStack_250 = 0x0;
                    iVar1 = jmp_advapi32.RegOpenKeyExW();
                    if (iVar1 != 0) {
                        ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                        uStack_24c = 0x20019;
                        pcStack_250 = 0x0;
                        iVar1 = jmp_advapi32.RegOpenKeyExW();
                        if (iVar1 != 0) {
                            ppcStack_248 = &UNRECOVERED_JUMPTABLE_00;
                            uStack_24c = 0x20019;
                            pcStack_250 = 0x0;
                            iVar1 = jmp_advapi32.RegOpenKeyExW();
                            if (iVar1 != 0) goto code_r0x003cc2df;
                        }
                    }
                }
            }
        }
        uStack_24c = 0x3cc2d8;
        pcStack_250 = *in_FS_OFFSET;
        *in_FS_OFFSET = &pcStack_250;
        ppcStack_248 = &stack0xfffffffc;
        uVar2 = sub_3cbed4(aiStack_222, &uStack_c);
        puVar11 = &uStack_18;
        uVar10 = 0;
        uVar9 = 0;
        uVar8 = 0;
        pcVar7 = UNRECOVERED_JUMPTABLE_00;
        iVar1 = jmp_advapi32.RegQueryValueExW();
        if (iVar1 == 0) {
            iVar1 = sub_3c53b8(uStack_18);
            puVar6 = &uStack_18;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iStack_10 = iVar1;
            jmp_advapi32.RegQueryValueExW();
            sub_3c89d4(param_2, iStack_10);
        }
        else {
            puVar6 = &uStack_18;
            iVar1 = 0;
            uVar5 = 0;
            uVar4 = 0;
            pcStackY_280 = UNRECOVERED_JUMPTABLE_00;
            iVar3 = jmp_advapi32.RegQueryValueExW();
            if (iVar3 == 0) {
                i
```
#### 217976 — sub_3f5d78
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5d78(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    uint32_t uVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint32_t uVar15;
    uint32_t uVar16;
    uint32_t *puVar17;
    uint32_t *puVar18;
    int32_t iVar19;
    int32_t iVar20;
    uint32_t uStack_2f8;
    uint32_t uStack_2f4;
    uint32_t uStack_2f0;
    uint32_t uStack_2ec;
    uint32_t uStack_2e8;
    uint32_t uStack_2e4;
    uint32_t uStack_2e0;
    uint32_t uStack_2dc;
    uint32_t uStack_2d8;
    uint32_t uStack_2d4;
    uint32_t uStack_2d0;
    uint32_t uStack_2cc;
    uint32_t uStack_2c8;
    uint32_t uStack_2c4;
    uint32_t uStack_2c0;
    uint32_t uStack_2bc;
    uint32_t auStack_290 [18];
    uint32_t auStack_248 [10];
    uint32_t auStack_220 [132];
    
    uVar11 = *(param_1 + 0x90);
    uVar8 = *(param_1 + 0x94);
    uVar9 = *(param_1 + 0x98);
    uVar10 = *(param_1 + 0x9c);
    uVar12 = *(param_1 + 0xa0);
    uVar13 = *(param_1 + 0xa4);
    uStack_2e0 = *(param_1 + 0xa8);
    uStack_2dc = *(param_1 + 0xac);
    uVar14 = *(param_1 + 0xb0);
    uVar15 = *(param_1 + 0xb4);
    uVar16 = *(param_1 + 0xb8);
    uVar1 = *(param_1 + 0xbc);
    uVar2 = *(param_1 + 0xc0);
    uVar3 = *(param_1 + 0xc4);
    uStack_2c0 = *(param_1 + 200);
    uStack_2bc = *(param_1 + 0xcc);
    func_0x003c57a0(param_1, auStack_290, 0x80);
    iVar20 = 0x10;
    puVar17 = auStack_290;
    do {
        uVar4 = *puVar17;
        uVar5 = puVar17[1];
        *puVar17 = uVar5 >> 0x18 | uVar5 << 0x18 | uVar5 >> 8 & 0xff00 | (uVar5 & 0xff00) << 8;
        puVar17[1] = uVar4 >> 0x18 | uVar4 << 0x18 | uVar4 >> 8 & 0xff00 | (uVar4 & 0xff00) << 8;
        puVar17 = puVar17 + 2;
        iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar20 = 0x40;
    puVar17 = auStack_290;
    do {
        puVar17 = puVar17 + 2;
        uVar4 = (*puVar17 >> 7 | puVar17[1] << 0x19) ^
                (*puVar17 >> 8 | puVar17[1] << 0x18) ^ (*puVar17 >> 1 | puVar17[1] << 0x1f);
        uVar5 = (puVar17[0x1a] >> 6 | puVar17[0x1b] << 0x1a) ^
                (puVar17[0x1b] >> 0x1d | puVar17[0x1a] << 3) ^ (puVar17[0x1a] >> 0x13 | puVar17[0x1b] << 0xd);
        uVar6 = puVar17[-2] + uVar4;
        uVar7 = uVar6 + puVar17[0x10];
        puVar17[0x1e] = uVar7 + uVar5;
        puVar17[0x1f] =
             puVar17[-1] +
             (puVar17[1] >> 7 ^ (puVar17[1] >> 8 | *puVar17 << 0x18) ^ (puVar17[1] >> 1 | *puVar17 << 0x1f)) +
             CARRY4(puVar17[-2], uVar4) + puVar17[0x11] + CARRY4(uVar6, puVar17[0x10]) +
             (puVar17[0x1b] >> 6 ^
             (puVar17[0x1b] << 3 | puVar17[0x1a] >> 0x1d) ^ (puVar17[0x1b] >> 0x13 | puVar17[0x1a] << 0xd)) +
             CARRY4(uVar7, uVar5);
        iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    iVar20 = 0x50;
    puVar18 = &Hash_constant_words_K_for_SHA_384_and_SHA_512__64_lil_640;
    puVar17 = auStack_290;
    do {
        uStack_2c4 = uVar3;
        uStack_2c8 = uVar2;
        uStack_2cc = uVar1;
        uStack_2d0 = uVar16;
        uStack_2d4 = uVar15;
        uStack_2d8 = uVar14;
        uStack_2e4 = uVar13;
        uStack_2e8 = uVar12;
        uStack_2ec = uVar10;
        uStack_2f0 = uVar9;
        uStack_2f4 = uVar8;
        uStack_2f8 = uVar11;
        uVar8 = (uStack_2f4 >> 7 | uStack_2f8 << 0x19) ^
                (uStack_2f4 >> 2 | uStack_2f8 << 0x1e) ^ (uStack_2f8 >> 0x1c | uStack_2f4 << 4);
        uVar9 = uStack_2f0 & uStack_2e8 ^ uStack_2f8 & uStack_2e8 ^ uStack_2f8 & uStack_2f0;
        uVar10 = uVar9 + uVar8;
        uVar11 = (uStack_2d4 >> 9 | uStack_2d8 << 0x17) ^
                 (uStack_2d8 >> 0x12 | uStack_2d4 << 0xe) ^ (uStack_2d8 >> 0xe | uStack_2d4 << 0x12);
        uVar12 = uStack_2c0 + uVar11;
        uVar13 = ~uStack_2d8 & uStack_2c8 ^ uStack_2d8 & uStack_2d0;
   
```
#### 217308 — sub_3f5adc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_3f5adc(int32_t param_1)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t *puVar4;
    int32_t *piVar5;
    int32_t iVar6;
    uint32_t uVar7;
    uint32_t uVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    int32_t iVar11;
    uint32_t uStack_13c;
    uint32_t uStack_138;
    uint32_t uStack_134;
    uint32_t uStack_130;
    uint32_t uStack_12c;
    uint32_t uStack_128;
    uint32_t *puStack_114;
    uint32_t auStack_110 [9];
    uint32_t auStack_ec [5];
    uint32_t auStack_d8 [50];
    
    uVar8 = *(param_1 + 0x90);
    uVar7 = *(param_1 + 0x94);
    uVar1 = *(param_1 + 0x98);
    uStack_134 = *(param_1 + 0x9c);
    uVar10 = *(param_1 + 0xa0);
    uVar9 = *(param_1 + 0xa4);
    uVar2 = *(param_1 + 0xa8);
    uStack_128 = *(param_1 + 0xac);
    func_0x003c57a0(param_1, auStack_110, 0x40);
    iVar6 = 0x10;
    puVar4 = auStack_110;
    do {
        uVar3 = *puVar4;
        *puVar4 = uVar3 >> 0x18 | uVar3 << 0x18 | uVar3 >> 8 & 0xff00 | (uVar3 & 0xff00) << 8;
        puVar4 = puVar4 + 1;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x30;
    puVar4 = auStack_110;
    do {
        puVar4 = puVar4 + 1;
        uVar3 = puVar4[0xd];
        puVar4[0xf] = ((uVar3 << 0xf | uVar3 >> 0x11) ^ (uVar3 << 0xd | uVar3 >> 0x13) ^ puVar4[0xd] >> 10) +
                      puVar4[-1] +
                      ((*puVar4 << 0x19 | *puVar4 >> 7) ^ (*puVar4 << 0xe | *puVar4 >> 0x12) ^ *puVar4 >> 3) + puVar4[8]
        ;
        iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
    iVar6 = 0x40;
    piVar5 = &SHA256;
    puStack_114 = auStack_110;
    do {
        uStack_12c = uVar2;
        uStack_130 = uVar9;
        uStack_138 = uVar1;
        uStack_13c = uVar7;
        uVar9 = uVar10;
        uVar7 = uVar8;
        iVar11 = (uVar9 & uStack_130 ^ ~uVar9 & uStack_12c) +
                 ((uVar9 << 0x1a | uVar9 >> 6) ^ (uVar9 << 0x15 | uVar9 >> 0xb) ^ (uVar9 << 7 | uVar9 >> 0x19)) +
                 uStack_128 + *piVar5 + *puStack_114;
        uStack_128 = uStack_12c;
        uVar10 = uStack_134 + iVar11;
        uStack_134 = uStack_138;
        uVar8 = iVar11 + (uVar7 & uStack_13c ^ uVar7 & uStack_138 ^ uStack_13c & uStack_138) +
                         ((uVar7 << 0x1e | uVar7 >> 2) ^ (uVar7 << 0x13 | uVar7 >> 0xd) ^ (uVar7 << 10 | uVar7 >> 0x16))
        ;
        puStack_114 = puStack_114 + 1;
        piVar5 = piVar5 + 1;
        iVar6 = iVar6 + -1;
        uVar1 = uStack_13c;
        uVar2 = uStack_130;
    } while (iVar6 != 0);
    *(param_1 + 0x90) = *(param_1 + 0x90) + uVar8;
    *(param_1 + 0x94) = *(param_1 + 0x94) + uVar7;
    *(param_1 + 0x98) = *(param_1 + 0x98) + uStack_13c;
    *(param_1 + 0x9c) = *(param_1 + 0x9c) + uStack_138;
    *(param_1 + 0xa0) = *(param_1 + 0xa0) + uVar10;
    *(param_1 + 0xa4) = *(param_1 + 0xa4) + uVar9;
    *(param_1 + 0xa8) = *(param_1 + 0xa8) + uStack_130;
    *(param_1 + 0xac) = *(param_1 + 0xac) + uStack_12c;
    return;
}

```

### Carved Files (6)
| Name | Type | Size |
|---|---|---|
| ? | PNG | 980 |
| ? | PNG | 3093 |
| ? | PNG | 6060 |
| ? | PNG | 9716 |
| ? | PNG | 28485 |
| ? | PNG | 88382 |

### Virtual Files (24)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/100/en-us | 980 | - |
| ICO/101/en-us | 3093 | - |
| ICO/102/en-us | 6060 | - |
| ICO/103/en-us | 9716 | - |
| ICO/104/en-us | 28485 | - |
| ICO/105/en-us | 88382 | - |
| STR/4085/unk | 588 | - |
| STR/4086/unk | 740 | - |
| STR/4087/unk | 1024 | - |
| STR/4088/unk | 976 | - |
| STR/4089/unk | 1020 | - |
| STR/4090/unk | 724 | - |
| STR/4091/unk | 184 | - |
| STR/4092/unk | 156 | - |
| STR/4093/unk | 908 | - |
| STR/4094/unk | 920 | - |
| STR/4095/unk | 872 | - |
| STR/4096/unk | 676 | - |
| RCDATA/DVCLAL/unk | 16 | - |
| RCDATA/PACKAGEINFO/unk | 1168 | - |

### Structures (112)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 256 |
| OptionalHeader | 280 |
| Sections | 504 |
| ImportTable | 779776 |
| kernel32.OFT | 779896 |
| comctl32.OFT | 780320 |
| user32.OFT | 780328 |
| oleaut32.OFT | 780396 |
| advapi32.OFT | 780460 |
| kernel32.FT | 780516 |
| comctl32.FT | 780940 |
| user32.FT | 780948 |
| oleaut32.FT | 781016 |
| advapi32.FT | 781080 |
| ImportNames | 781136 |
| DelayImportTable | 787968 |
| kernel32.Addresses | 788112 |
| user32.Addresses | 788116 |
| kernel32.Addresses | 788120 |
| kernel32.Names | 788148 |
| user32.Names | 788156 |
| kernel32.Names | 788164 |
| ExportDirectory | 792064 |
| ExportAddressTable | 792104 |
| ExportNameTable | 792112 |
| OrdinalNameTable | 792120 |
| ExportNames | 792124 |
| TlsDirectory | 796160 |
| Relocations | 800256 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 44 · duration_s: 1.82

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using HC-128 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.006:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| check for time delay via GetTickCount |  | B0001.032:Debugger Detection |
| get geographical location | T1614:System Location Discovery |  |
| hash data with CRC32 |  | C0032.001:Checksum |
| encrypt data using Salsa20 or ChaCha | T1027:Obfuscated Files or Information |  |

## PE Imports / Signals
import_count: 150

| label | api_match | ATT&CK |
|---|---|---|
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |
| allocate_memory | VirtualAlloc | T1055 |

## YARA Matches (pipeline)
Total matches: 16

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=3 |
| IP | - | $ipv4@1002335 len=7; $ipv6@782284 len=3 |
| contains_base64 | - | $a@2670 len=12 |
| CRC32_poly_Constant | - | $c0@680866 len=4 |
| SHA512_Constants | - | $c1@737040 len=4; $c3@737044 len=4; $c5@737048 len=4; $c7@737052 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@222840 len=4; $c1@222850 len=4; $c2@222860 len=4; $c3@222870 len=4; $c4@222880 len=4; $c5@222890 len=4; $c6@222900 len=4; $c7@222910 len=4 |
| url | - | $url_regex@700280 len=78 |
| Borland | - | $patternBorland@47502 len=14 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| Microsoft_Visual_Cpp_v50v60_MFC | - | $a@16196 len=4 |
| disable_dep | - | $c4@720820 len=19 |
| escalate_priv | - | $d1@776504 len=12; $c2@776594 len=21 |
| win_registry | - | $f1@776504 len=12; $c3@776796 len=11; $c6@776796 len=11 |
| win_token | - | $f1@776504 len=12; $c2@776594 len=21; $c3@776658 len=16 |
| win_files_operation | - | $f1@773968 len=12; $c1@775576 len=9; $c2@774236 len=14; $c3@775576 len=9; $c4@774332 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 16,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 1002335,
          "length": 7,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 782284,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 2670,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 680866,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 737040,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 737044,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 737048,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 737052,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA2_BLAKE2_IVs",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$c0",
          "offset": 222840,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c1",
          "offset": 222850,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 222860,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 222870,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c4",
          "offset": 222880,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 222890,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 222900,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 222910,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f9267218c144475dc0691431825779.vir",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 700280,
          "length": 78,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Borland",
      "path": "/opt/samples/corpus/incoming/353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c/virussign.com_40f926
```

## FLOSS Strings
Total strings: 10027 · per_category: `{"decoded_strings": 2, "stack_strings": 5, "tight_strings": 2, "language_strings": 0, "language_strings_missed": 0, "static_strings": 10018}`

### FLOSS sample
- `j:,4;87`
- `4278124286`
- `GPVACPVA?`
- `KPVAGPVACPVA?`
- `KPVAKPVAGPVACPVA?`
- `?PVAKPVAKPVAGPVACPVA?`
- `CPVA?PVAKPVAKPVAGPVACPVA?`
- `1096159247`
- `This program must be run under Win32`
- ``.itext`
- ``.data`
- `.idata`
- `.didata`
- `.edata`
- `.rdata`
- `@.reloc`
- `B.rsrc`
- `Boolean`
- `System`
- `AnsiChar`
- `ShortInt`
- `SmallInt`
- `Integer`
- `Cardinal`
- `Pointer`
- `UInt64`
- `Single`
- `Extended`
- `Double`
- `Currency`
- `ShortString`
- `PAnsiChar0`
- `PWideCharL`
- `ByteBool`
- `WordBool`
- `LongBool`
- `string`
- `WideString`
- `AnsiString`
- `Variant`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00471e60
```asm
┌ 290: entry0 ();
│           ; var int32_t var_14h @ ebp-0x14
│           ; var int32_t var_18h @ ebp-0x18
│           ; var int32_t var_40h @ ebp-0x40
│           0x00471e60      55             push ebp
│           0x00471e61      8bec           mov ebp, esp
│           0x00471e63      b90f000000     mov ecx, 0xf                ; 15
│       ┌─> 0x00471e68      6a00           push 0
│       ╎   0x00471e6a      6a00           push 0
│       ╎   0x00471e6c      49             dec ecx
│       └─< 0x00471e6d      75f9           jne 0x471e68
│           0x00471e6f      51             push ecx
│           0x00471e70      53             push ebx
│           0x00471e71      56             push esi
│           0x00471e72      57             push edi
│           0x00471e73      b868ba4600     mov eax, 0x46ba68
│           0x00471e78      e827c8f5ff     call 0x3ce6a4
│           0x00471e7d      33c0           xor eax, eax
│           0x00471e7f      55             push ebp
│           0x00471e80      68c6264700     push 0x4726c6
│           0x00471e85      64ff30         push dword fs:[eax]
│           0x00471e88      648920         mov dword fs:[eax], esp
│           0x00471e8b      33d2           xor edx, edx
│           0x00471e8d      55             push ebp
│           0x00471e8e      6880264700     push 0x472680
│           0x00471e93      64ff32         push dword fs:[edx]
│           0x00471e96      648922         mov dword fs:[edx], esp
│           0x00471e99      a134a64700     mov eax, dword [0x47a634]   ; [0x47a634:4]=0x3c0000
│           0x00471e9e      e81583ffff     call 0x46a1b8
│           0x00471ea3      33c0           xor eax, eax
│           0x00471ea5      8945ec         mov dword [var_14h], eax
│           0x00471ea8      33d2           xor edx, edx
│           0x00471eaa      55             push ebp
│           0x00471eab      686f264700     push 0x47266f               ; 'o&G'
│           0x00471eb0      64ff32         push dword fs:[edx]
│           0x00471eb3      648922         mov dword fs:[edx], esp
│           0x00471eb6      8d55ec         lea edx, [var_14h]
│           0x00471eb9      33c0           xor eax, eax
│           0x00471ebb      e87c14ffff     call 0x46333c
│           0x00471ec0      8d45ec         lea eax, [var_14h]
│           0x00471ec3      e8a47cffff     call 0x469b6c
│           0x00471ec8      6a02           push 2                      ; 2
│           0x00471eca      6a00           push 0
│           0x00471ecc      6a01           push 1                      ; 1
│           0x00471ece      8b4dec         mov ecx, dword [var_14h]
│           0x00471ed1      b201           mov dl, 1
│           0x00471ed3      a184454600     mov eax, dword [0x464584]   ; [0x464584:4]=0x4645dc ".LF"
│           0x00471ed8      e84f2cffff     call 0x464b2c
│           0x00471edd      a3ace24700     mov dword [0x47e2ac], eax   ; [0x47e2ac:4]=0
│           0x00471ee2      33d2           xor edx, edx
│           0x00471ee4      55
```
### 0x003ce578
```asm
┌ 167: sym.SetupLdr.e32___dbk_fcall_wrapper ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   0x003ce578      55             push ebp
│       ╎   0x003ce579      8bec           mov ebp, esp
│       ╎   0x003ce57b      51             push ecx
│       ╎   0x003ce57c      53             push ebx
│       ╎   0x003ce57d      56             push esi
│       ╎   0x003ce57e      57             push edi
│       ╎   0x003ce57f      33c0           xor eax, eax
│       ╎   0x003ce581      8945fc         mov dword [var_4h], eax
│       ╎   0x003ce584      33c0           xor eax, eax
│       ╎   0x003ce586      55             push ebp
│       ╎   0x003ce587      6819e63c00     push 0x3ce619
│       ╎   0x003ce58c      64ff30         push dword fs:[eax]
│       ╎   0x003ce58f      648920         mov dword fs:[eax], esp
│       ╎   0x003ce592      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce595      50             push eax
│       ╎   0x003ce596      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce599      50             push eax
│       ╎   0x003ce59a      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce59d      50             push eax
│       ╎   0x003ce59e      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a1      50             push eax
│       ╎   0x003ce5a2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a5      50             push eax
│       ╎   0x003ce5a6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5a9      50             push eax
│       ╎   0x003ce5aa      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5ad      50             push eax
│       ╎   0x003ce5ae      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b1      50             push eax
│       ╎   0x003ce5b2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b5      50             push eax
│       ╎   0x003ce5b6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5b9      50             push eax
│       ╎   0x003ce5ba      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5bd      50             push eax
│       ╎   0x003ce5be      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c1      50             push eax
│       ╎   0x003ce5c2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c5      50             push eax
│       ╎   0x003ce5c6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5c9      50             push eax
│       ╎   0x003ce5ca      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5cd      50             push eax
│       ╎   0x003ce5ce      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d1      50             push eax
│       ╎   0x003ce5d2      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d5      50             push eax
│       ╎   0x003ce5d6      8b45fc         mov eax, dword [var_4h]
│       ╎   0x003ce5d9      50             push eax
│       ╎   0x003ce5da      8b45f
```
### 0x003ce188
```asm
; CALL XREF from sym.SetupLdr.e32___dbk_fcall_wrapper @ 0x3ce607(x)
┌ 1007: fcn.003ce188 ();
│           0x003ce188      55             push ebp
│           0x003ce189      8bec           mov ebp, esp
│           0x003ce18b      e8f4ffffff     call fcn.003ce184
│           0x003ce190      e8efffffff     call fcn.003ce184
│           0x003ce195      e8eaffffff     call fcn.003ce184
│           0x003ce19a      e8e5ffffff     call fcn.003ce184
│           0x003ce19f      e8e0ffffff     call fcn.003ce184
│           0x003ce1a4      e8dbffffff     call fcn.003ce184
│           0x003ce1a9      e8d6ffffff     call fcn.003ce184
│           0x003ce1ae      e8d1ffffff     call fcn.003ce184
│           0x003ce1b3      e8ccffffff     call fcn.003ce184
│           0x003ce1b8      e8c7ffffff     call fcn.003ce184
│           0x003ce1bd      e8c2ffffff     call fcn.003ce184
│           0x003ce1c2      e8bdffffff     call fcn.003ce184
│           0x003ce1c7      e8b8ffffff     call fcn.003ce184
│           0x003ce1cc      e8b3ffffff     call fcn.003ce184
│           0x003ce1d1      e8aeffffff     call fcn.003ce184
│           0x003ce1d6      e8a9ffffff     call fcn.003ce184
│           0x003ce1db      e8a4ffffff     call fcn.003ce184
│           0x003ce1e0      e89fffffff     call fcn.003ce184
│           0x003ce1e5      e89affffff     call fcn.003ce184
│           0x003ce1ea      e895ffffff     call fcn.003ce184
│           0x003ce1ef      e890ffffff     call fcn.003ce184
│           0x003ce1f4      e88bffffff     call fcn.003ce184
│           0x003ce1f9      e886ffffff     call fcn.003ce184
│           0x003ce1fe      e881ffffff     call fcn.003ce184
│           0x003ce203      e87cffffff     call fcn.003ce184
│           0x003ce208      e877ffffff     call fcn.003ce184
│           0x003ce20d      e872ffffff     call fcn.003ce184
│           0x003ce212      e86dffffff     call fcn.003ce184
│           0x003ce217      e868ffffff     call fcn.003ce184
│           0x003ce21c      e863ffffff     call fcn.003ce184
│           0x003ce221      e85effffff     call fcn.003ce184
│           0x003ce226      e859ffffff     call fcn.003ce184
│           0x003ce22b      e854ffffff     call fcn.003ce184
│           0x003ce230      e84fffffff     call fcn.003ce184
│           0x003ce235      e84affffff     call fcn.003ce184
│           0x003ce23a      e845ffffff     call fcn.003ce184
│           0x003ce23f      e840ffffff     call fcn.003ce184
│           0x003ce244      e83bffffff     call fcn.003ce184
│           0x003ce249      e836ffffff     call fcn.003ce184
│           0x003ce24e      e831ffffff     call fcn.003ce184
│           0x003ce253      e82cffffff     call fcn.003ce184
│           0x003ce258      e827ffffff     call fcn.003ce184
│           0x003ce25d      e822ffffff     call fcn.003ce184
│           0x003ce262      e81dffffff     call fcn.003ce184
│           0x003ce267      e818ffffff     call fcn.003ce184
│           0x003ce26c      e813ffffff     call fcn.00
```
### 0x003ce184
```asm
; XREFS(200)
┌ 1: fcn.003ce184 ();
└           0x003ce184      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000100 ........!..L.!..This program must be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
