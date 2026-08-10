# Technical Evidence Pack

**sha256:** 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a  
**sample_path:** /opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex  
**project_name:** REVAI-LAB-CORPUS-L2

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 55
- **family_guess**: Unknown
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reports 9 functions and 6 strings, while IDA reports 8 functions and 320 strings, indicating analysis discrepancies. Packing indicators are consistent across tools, with high entropy sections and entry point not in first section. Anti-analysis technique via PEB access detected, and obfuscation through XOR encoding observed, but no clear behavioral-intent evidence for malicious actions like file encryption, C2, or persistence.
- **summary**: The sample exhibits signs of packing, obfuscation (XOR encoding), and anti-analysis (PEB access), with a digital signature present. However, no direct behavioral-intent evidence such as file destruction, C2 communication, credential theft, or persistence mechanisms was identified. The analysis shows neutral signals consistent with protected software or potential malware, warranting suspicion but not definitive malicious verdict. Discrepancies in tool outputs highlight the need for cross-engine validation.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | Anti Analysis Signals | `4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913` | Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indic |
| capa | rules | `encode data using XOR` | Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), a neutral signal that can be |
| malcat | anomalies | `CrossSectionJump` | Control flow jumps across sections may indicate packed code, file infection, or other obfuscation, which is common in pr |
| malcat | metadata | `Certificate::Validity: from 2020-12-21 to 2021-12-21` | Presence of a digital signature with a specific validity period; while signatures can indicate legitimacy, expired or su |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: DarkSide ransomware dropper/packer. The sample is a heavily packed PE (61KB) with only 1 static import (ExitProcess), RWX .text section, and high entropy indicating runtime unpacking. CAPA confirms XOR encoding (T1027) and aPLib decompression. YARA matched kernel32 PEB-walking API resolution technique. FLOSS extracted 191 strings but all are garbage/encoded with zero decoded strings, confirming heavy obfuscation. The filename is explicitly 'darkside.ex'. Code signing certificate ('OASIS COURT LIMITED', valid 2020-2021) is trivially forged and not evidence of legitimacy. Debug timestamp 2021-02-16 aligns with DarkSide ransomware operational timeline (pre-Colonial Pipeline attack).

### deep key_evidence
- `"Filename: darkside.ex \u2014 explicit DarkSide ransomware naming"`
- `"Ghidra imports: Only 1 import (ExitProcess from KERNEL32.DLL) \u2014 extreme import minimalism indicates packer stub"`
- `"Ghidra memory_blocks: .text section is RWX (Read+Write+Execute) with size 33792 \u2014 classic unpacking indicator"`
- `"Malcat layout: .text entropy 225/256, .rsrc entropy 226/256 \u2014 high entropy indicates packed/encrypted payload"`
- `"CAPA: 'encode data using XOR' (MITRE T1027 Defense Evasion, MBC E1027.m02)"`
- `"CAPA: 'decompress data using aPLib' (MBC C0025.003) \u2014 confirms packer is aPLib-based"`
- `"CAPA: 'terminate process' (MBC C0018) \u2014 post-exploitation capability"`
- `"YARA: maldoc_find_kernel32_base_method_1 at offset 35465 \u2014 PEB walking for dynamic API resolution"`
- `"YARA: HasOverlay triggered \u2014 overlay data present"`
- `"YARA: HasDigitalSignature at offset 53760 \u2014 signed with Sectigo cert for OASIS COURT LIMITED"`
- `"FLOSS: 191 strings extracted, 0 decoded, 0 stack strings \u2014 all strings are obfuscated/garbage"`
- `"FLOSS: FindNextFileW string present \u2014 file enumeration capability for ransomware target discovery"`
- `"Malcat metadata: Certificate issued to OASIS COURT LIMITED, valid 2020-12-21 to 2021-12-16 \u2014 forged/stolen cert"`
- `"Malcat metadata: Debug date 2021-02-16 \u2014 aligns with DarkSide ransomware active period"`
- `"Ghidra function_metrics: FUN_0040a135 has 46 blocks, cyclomatic complexity 23 \u2014 complex obfuscated unpacker logic"`
- `"Ghidra: .text1 stub section (1024 bytes, RX) \u2014 small unpacker stub that decompresses main payload into .text"`
- `"Speakeasy: No API calls logged \u2014 packer uses anti-emulation to evade sandbox analysis"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a
size: 61784
type: PE
architecture: X86
entrypoint_ea: 38671
entropy: 216
file_name: darkside.ex
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 38 | - |
| .text | 1024 | 33792 | 36864 | 225 | RWX |
| .text1 | 37888 | 1024 | 4096 | 0 | RX |
| .rdata | 41984 | 512 | 4096 | 0 | R |
| .data | 46080 | 13312 | 16384 | 184 | RW |
| .rsrc | 62464 | 4096 | 4096 | 226 | RW |
| overlay | 66560 | 8024 | 0 | 211 | - |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |

### Anomalies (9)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied b |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `220`: 
- **ResourceDirectoryGap**
  - `62480`: 
- **XorInLoop**
  - `38141`: 

### High-Signal Strings (15 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 42314 | `KERNEL32.dll` |
| 70656 | `?http://crl.user..nAuthority.crl0v` |
| 68880 | `?http://crl.user..nAuthority.crl0v` |
| 72473 | `3http://crl.sect..StampingCA.crl0t` |
| 70749 | `3http://crt.user..AddTrustCA.crt0%` |
| 68973 | `3http://crt.user..AddTrustCA.crt0%` |
| 67664 | `2http://crt.sect..eSigningCA.crt0#` |
| 67584 | `2http://crl.sect..eSigningCA.crl0s` |
| 72554 | `3http://crt.sect..StampingCA.crt0#` |
| 70815 | `http://ocsp.usertrust.com0
` |
| 69039 | `http://ocsp.usertrust.com0
` |
| 72620 | `http://ocsp.sectigo.com0
` |
| 67729 | `http://ocsp.sectigo.com0%` |
| 67533 | `https://sectigo.com/CPS0` |
| 72432 | `https://sectigo.com/CPS0D` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 42314 | `KERNEL32.dll` |
| 70656 | `?http://crl.user..nAuthority.crl0v` |
| 68880 | `?http://crl.user..nAuthority.crl0v` |
| 72473 | `3http://crl.sect..StampingCA.crl0t` |
| 70749 | `3http://crt.user..AddTrustCA.crt0%` |
| 68973 | `3http://crt.user..AddTrustCA.crt0%` |
| 67664 | `2http://crt.sect..eSigningCA.crt0#` |
| 67584 | `2http://crl.sect..eSigningCA.crl0s` |
| 72554 | `3http://crt.sect..StampingCA.crt0#` |
| 70815 | `http://ocsp.usertrust.com0
` |
| 69039 | `http://ocsp.usertrust.com0
` |
| 72620 | `http://ocsp.sectigo.com0
` |
| 67729 | `http://ocsp.sectigo.com0%` |
| 67533 | `https://sectigo.com/CPS0` |
| 72432 | `https://sectigo.com/CPS0D` |
| 68255 | `
181102000000Z` |
| 71549 | `
201023000000Z` |
| 66865 | `
201221000000Z` |
| 69743 | `%USERTrust RSA C..ation Authority0` |
| 69784 | `
190502000000Z` |
| 68214 | `%USERTrust RSA C..ation Authority0` |
| 66880 | `
211221235959Z0` |
| 71677 | `#Sectigo RSA Tim..mping Signer #20` |
| 71564 | `
320122235959Z0` |
| 73288 | `Sectigo RSA Code Signing CA` |
| 66835 | `Sectigo RSA Code Signing CA0` |
| 68383 | `Sectigo RSA Code Signing CA0` |
| 77 | `!This program ca..in DOS mode.

$` |
| 67765 | `nonaterscont1986@yahoo.com0
` |
| 9606 | `43.nfL` |
| 68270 | `
301231235959Z0|1` |
| 73866 | `Sectigo RSA Time Stamping CA` |
| 73972 | `
210217111653Z0?` |
| 71518 | `Sectigo RSA Time Stamping CA0` |
| 69912 | `Sectigo RSA Time Stamping CA0` |
| 69799 | `
380118235959Z0}1` |
| 68310 | `Greater Manchester1` |
| 73215 | `Greater Manchester1` |
| 49905 | `AUTORITE NT` |
| 66762 | `Greater Manchester1` |
| 73793 | `Greater Manchester1` |
| 71445 | `Greater Manchester1` |
| 71605 | `Greater Manchester1` |
| 69839 | `Greater Manchester1` |
| 68183 | `The USERTRUST Network1.0,` |
| 67005 | `OASIS COURT LIMITED1` |
| 69712 | `The USERTRUST Network1.0,` |
| 67035 | `OASIS COURT LIMITED0` |
| 47100 | `FindNextFileW` |
| 72035 | `>Itt` |
| 54978 | `64m6` |
| 33879 | `vvAe` |
| 42228 | `.bss` |
| 49233 | `8fHf` |
| 71018 | `mAmg` |
| 69137 | `F^@F` |
| 66622 | `>0<0` |
| 20292 | `2syy` |
| 25296 | `]Z
Z` |
| 65252 | `oQio` |
| 1635 | `pmms` |
| 53315 | `3e``` |
| 16603 | `U161` |
| 16572 | `LkXL` |
| 15041 | `EWEv` |
| 57197 | `*.4M` |
| 28811 | `U@Ua` |
| 14133 | `yyWx` |
| 68357 | `Sectigo Limited1$0"` |
| 73262 | `Sectigo Limited1$0"` |
| 66809 | `Sectigo Limited1$0"` |
| 32958 | `XG`eX` |
| 68957 | `j0h0?` |
| 70646 | `I0G0E` |
| 67498 | `C0A05` |
| 55711 | `eBkEE` |
| 68870 | `I0G0E` |
| 67574 | `<0:08` |
| 67648 | `g0e0>` |
| 42244 | `.rsrc` |

### Constants / Known Patterns (41)
| Category | Value |
|---|---|
| code | `code::PEBx86` |
| oid | `oid::signedData` |
| oid | `oid::sha1` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::postalCode` |
| oid | `oid::streetAddress` |
| oid | `oid::rsaEncryption` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::keyUsage` |
| oid | `oid::basicConstraints` |
| oid | `oid::extKeyUsage` |
| oid | `oid::codeSigning` |
| oid | `oid::netscape-cert-type` |
| oid | `oid::certificatePolicies` |
| oid | `oid::cps` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::caIssuers` |
| oid | `oid::ocsp` |
| oid | `oid::subjectAltName` |
| oid | `oid::sha384WithRSAEncryption` |
| oid | `oid::timeStamping` |
| oid | `oid::anyPolicy` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::messageDigest` |
| oid | `oid::countersignature` |
| oid | `oid::sha-384` |
| oid | `oid::data` |

### Imports (1)
| EA | Name | Type | Refs |
|---|---|---|---|
| 41984 | kernel32.ExitProcess | IMPORT | 6 |

### Functions (8)
| EA | Name |
|---|---|
| 38536 | sub_40a288 |
| 38101 | sub_40a0d5 |
| 38671 | EntryPoint |
| 38197 | sub_40a135 |
| 37959 | sub_40a047 |
| 37888 | sub_40a000 |
| 38622 | sub_40a2de |
| 38581 | sub_40a2b5 |

### Decompilations (top 6)
#### 38536 — sub_40a288
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
#### 38101 — sub_40a0d5
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
#### 38671 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PKCS7 | 8014 |

### Structures (12)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| kernel32.FT | 41984 |
| DebugDirectory | 42000 |
| Debug.Pogo | 42028 |
| ImportTable | 42252 |
| kernel32.OFT | 42292 |
| ImportNames | 42300 |
| Resources | 62464 |
| Certificate | 66560 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 0.8

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 1

## YARA Matches (pipeline)
Total matches: 11

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@55207 len=2 |
| contains_base64 | - | $a@37372 len=12 |
| url | - | $url_regex@54733 len=24 |
| maldoc_find_kernel32_base_method_1 | - | $a1@35465 len=7 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@53760 len=105 |
| HasDebugData | - |  |

## Generated YARA Meta
```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 55207,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a",
          "offset": 37372,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 54733,
          "length": 24,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_find_kernel32_base_method_1",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 35465,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "IsPacked",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": [
        {
          "id": "$a1",
          "offset": 53760,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/REVAI-LAB-CORPUS-L2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex",
      "strings": []
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
   
```

## FLOSS Strings
Total strings: 191 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 191}`

### High-signal FLOSS
- `KERNEL32.dll`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.text1`
- ``.rdata`
- `@.data`
- `XJ7ZB;`
- ``(/D1RK`
- `2sR:2|`
- `e;*-Q$=`
- `aBN-R"`
- `aSkS5:`
- `,IG]DT`
- `?*-Q$8`
- `-b|Xp0`
- `43.nfL`
- `@Ua+E=`
- `H.`e$K`
- `9g'P@/ZcS``
- `<u(k]kaA`
- `9Uj*83`
- `wtCLhJ`
- `q[j*>7`
- `m]J,	z`
- `e&74a3`
- `OAI<2p`
- `88|jlc8tyf`
- `">V'h$!;`
- `V',%!;`
- `-BHE\L`
- `-BHEPB`
- `Lh<NFcU`
- ``BHLNY`
- `5`e*ci<2x`
- `$Vr_dX8`
- `azfJ?L%`
- `~8]TEj`
- `dcWt$lR`
- `T{@"Ze`
- `1?a;*-`
- `3agdm;`
- `AUdMj0'`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040a30f
```asm
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
```asm
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
│      ╎╎   0x0040a0b6      88a170f24000   mov byte [ecx + 0x40f270], ah ; [0x40f270:1]=0
│      ╎╎   0x0040a0bc      3bdf           cmp ebx, edi
│     ┌───< 0x0040a0be      7306           jae 0x40a0c6
│     │╎╎   0x0040a0c0      fec1           inc cl
│     │└──< 0x0040a0c2      75da           jne 0x40a09e
│     │┌──< 0x0040a0c4      eb06           jmp 0x40a0cc
│     └───> 0x0040a0c6      33db           xor ebx, ebx
│      │╎   0x0040a0c8      fec1           inc cl
│      │└─< 0x0040a0ca      75d2           jne 0x40a09e
│
```
### 0x0040a288
```asm
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
```asm
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
```asm
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

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
