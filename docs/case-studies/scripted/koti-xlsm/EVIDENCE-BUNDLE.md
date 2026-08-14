# Technical Evidence Pack

**sha256:** 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e  
**sample_path:** /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: XAgent
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis failed due to session errors; MalCat identified the file as a ZIP/OOXML with high entropy (7.56) and macro content (xl/macrosheets/sheet1.xml); YARA rules matched for base64-encoded strings; VirusTotal reported 34 malicious detections with tags like 'calls-wmi' and threat label 'trojan.msexcel/x97m'. No direct behavioral evidence from static analysis tools, but external TI strongly indicates malicious activity.
- **summary**: The sample is an Excel macro-enabled workbook (OOXML format) with high entropy and base64-encoded content. External threat intelligence from VirusTotal indicates it is a trojan downloader associated with the XAgent family, as evidenced by multiple AV detections and behavioral tags. While static analysis tools like Ghidra and IDA failed, MalCat confirmed the macro presence and high entropy, and YARA rules detected suspicious strings. These factors collectively point to malicious intent.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | matches | `contains_base64` | YARA rule 'contains_base64' matched at offset 1859, length 12, indicating base64-encoded content which is often used in  |
| virustotal | hash_lookup | `detections: 34 malicious, 0 suspicious, 0 harmless, 30 undetected` | VirusTotal analysis shows high number of AV detections (34/64) with tags including 'calls-wmi', 'xlsx', and 'malware', a |
| malcat | file_summary | `entropy: 7.56, type: ZIP, virtual_files: includes xl/macrosheets/sheet1.xml` | MalCat analysis reveals high entropy (7.56) indicating possible encryption or compression, and the presence of macro she |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: The XLSM file triggered YARA rules for domain regex and base64 content, suggesting potential malicious payloads or obfuscation, but specific behaviors like downloading APIs are not confirmed in the evidence.

### deep key_evidence
- `"YARA rule 'domain' matched with string $domain_regex at offset 0 in file /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm."`
- `"YARA rule 'contains_base64' matched with string $a at offset 1859 in the same file, indicating the presence of base64 encoded data."`
- `"File type is XLSM (Excel macro-enabled workbook), which can contain macros, but no macro code or API calls are shown in the provided evidence."`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e
size: 26363
type: ZIP
architecture: NONE
entropy: 7.56
file_name: koti.xlsm
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| [Content_Types].xml | 0 | 1019 | 1019 | 111 | R |
| .rels | 1019 | 806 | 806 | 84 | R |
| workbook.xml.rels | 1825 | 626 | 626 | 125 | R |
| workbook.xml | 2451 | 473 | 473 | 215 | R |
| theme1.xml | 2924 | 1764 | 1764 | 222 | R |
| sheet1.xml | 4688 | 1609 | 1609 | 216 | R |
| sheet1.xml.rels | 6297 | 284 | 284 | 198 | R |
| sheet1.xml.rels | 6581 | 260 | 260 | 204 | R |
| sheet2.xml.rels | 6841 | 259 | 259 | 209 | R |
| drawing1.xml.rels | 7100 | 272 | 272 | 210 | R |
| sheet2.xml | 7372 | 1039 | 1039 | 209 | R |
| sheet1.xml | 8411 | 579 | 579 | 214 | R |
| styles.xml | 8990 | 787 | 787 | 218 | R |
| sharedStrings.xml | 9777 | 396 | 396 | 217 | R |
| drawing1.xml | 10173 | 2553 | 2553 | 221 | R |
| image1.png | 12726 | 8350 | 8350 | 221 | R |
| image3.png | 21076 | 897 | 897 | 204 | R |
| image2.png | 21973 | 606 | 606 | 202 | R |
| core.xml | 22579 | 631 | 631 | 132 | R |
| printerSettings2.bin | 23210 | 137 | 137 | 170 | R |
| printerSettings3.bin | 23347 | 137 | 137 | 169 | R |
| printerSettings1.bin | 23484 | 175 | 175 | 172 | R |
| calcChain.xml | 23659 | 241 | 241 | 200 | R |
| app.xml | 23900 | 753 | 753 | 146 | R |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 2954 | `xl/theme/theme1.xml` |
| 4718 | `xl/macrosheets/sheet1.xml` |
| 10203 | `xl/drawings/drawing1.xml` |
| 8441 | `xl/worksheets/sheet1.xml` |
| 7402 | `xl/worksheets/sheet2.xml` |
| 22003 | `xl/media/image2.png` |
| 21106 | `xl/media/image3.png` |
| 12756 | `xl/media/image1.png` |
| 2481 | `xl/workbook.xml` |
| 9020 | `xl/styles.xml` |
| 23514 | `xl/printerSettin..erSettings1.binb` |
| 23377 | `xl/printerSettin..erSettings3.binb` |
| 26178 | `xl/printerSettin..rSettings1.binPK` |
| 23240 | `xl/printerSettin..erSettings2.binb` |
| 26093 | `xl/printerSettin..rSettings3.binPK` |
| 26008 | `xl/printerSettin..rSettings2.binPK` |
| 6611 | `xl/macrosheets/_../sheet1.xml.rels` |
| 25253 | `xl/worksheets/_r..heet2.xml.relsPK` |
| 25171 | `xl/macrosheets/_..heet1.xml.relsPK` |
| 25090 | `xl/worksheets/_r..heet1.xml.relsPK` |
| 6871 | `xl/worksheets/_r../sheet2.xml.rels` |
| 6327 | `xl/worksheets/_r../sheet1.xml.rels` |
| 25334 | `xl/drawings/_rel..wing1.xml.relsPK` |
| 7130 | `xl/drawings/_rel..rawing1.xml.rels` |
| 24821 | `xl/_rels/workbook.xml.relsPK` |
| 24954 | `xl/theme/theme1.xmlPK` |
| 1855 | `xl/_rels/workbook.xml.rels ` |
| 25019 | `xl/macrosheets/sheet1.xmlPK` |
| 25680 | `xl/drawings/drawing1.xmlPK` |
| 25415 | `xl/worksheets/sheet2.xmlPK` |
| 25485 | `xl/worksheets/sheet1.xmlPK` |
| 14471 | `\9///ooo` |
| 13265 | `111t` |
| 13201 | `Mnnn` |
| 9094 | `W>>>` |
| 25750 | `xl/media/image1.pngPK` |
| 25815 | `xl/media/image3.pngPK` |
| 25880 | `xl/media/image2.pngPK` |
| 23689 | `xl/calcChain.xmld` |
| 24893 | `xl/workbook.xmlPK` |
| 26263 | `xl/calcChain.xmlPK` |
| 25945 | `docProps/core.xmlPK` |
| 9807 | `xl/sharedStrings.xmld` |
| 24764 | `_rels/.relsPK` |
| 25555 | `xl/styles.xmlPK` |
| 8972 | `=q99L=` |
| 26325 | `docProps/app.xmlPK` |
| 1049 | `_rels/.rels ` |
| 25614 | `xl/sharedStrings.xmlPK` |
| 24699 | `[Content_Types].xmlPK` |
| 2896 | `IDd5W5--` |
| 22221 | `211o` |
| 10815 | `VjMM` |
| 22609 | `docProps/core.xml ` |
| 14949 | `bH4b` |
| 24518 | `?5?i` |
| 13020 | `EEE	` |
| 30 | `[Content_Types].xml ` |
| 13004 | `SRR.\` |
| 17448 | `YrTdd` |
| 10717 | `q8K>8` |
| 22123 | ``ddbc` |
| 18319 | `6lhjj` |
| 13406 | `6lxjj` |
| 11196 | `GdAA` |
| 14674 | `I-mll` |
| 23930 | `docProps/app.xml ` |
| 12631 | `GWiki` |
| 14084 | `T]\RZt\` |
| 19205 | `2C21/^` |
| 14048 | `blTrvv` |
| 5505 | `rtjr9:` |
| 16612 | `SSRyF3` |
| 14581 | `d@DXdb` |
| 10245 | ``j`*c`` |
| 18172 | `EkEpg\` |
| 8296 | `23VBJe3w` |
| 16454 | `=1Hi`eeI` |
| 13169 | `'''[[[` |
| 8317 | `DaW[xc`0` |

### Virtual Files (24)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| [Content_Types].xml | 1799 | - |
| _rels/.rels | 588 | - |
| xl/_rels/workbook.xml.rels | 1104 | - |
| xl/workbook.xml | 763 | - |
| xl/theme/theme1.xml | 7130 | - |
| xl/macrosheets/sheet1.xml | 5500 | - |
| xl/worksheets/_rels/sheet1.xml.rels | 464 | - |
| xl/macrosheets/_rels/sheet1.xml.rels | 322 | - |
| xl/worksheets/_rels/sheet2.xml.rels | 322 | - |
| xl/drawings/_rels/drawing1.xml.rels | 562 | - |
| xl/worksheets/sheet2.xml | 3371 | - |
| xl/worksheets/sheet1.xml | 946 | - |
| xl/styles.xml | 2026 | - |
| xl/sharedStrings.xml | 771 | - |
| xl/drawings/drawing1.xml | 18678 | - |
| xl/media/image1.png | 8301 | - |
| xl/media/image3.png | 848 | - |
| xl/media/image2.png | 557 | - |
| docProps/core.xml | 593 | - |
| xl/printerSettings/printerSettings2.bin | 220 | - |

### Structures (49)
| Name | EA |
|---|---|
| LocalFile | 0 |
| LocalFile | 1019 |
| LocalFile | 1825 |
| LocalFile | 2451 |
| LocalFile | 2924 |
| LocalFile | 4688 |
| LocalFile | 6297 |
| LocalFile | 6581 |
| LocalFile | 6841 |
| LocalFile | 7100 |
| LocalFile | 7372 |
| LocalFile | 8411 |
| LocalFile | 8990 |
| LocalFile | 9777 |
| LocalFile | 10173 |
| LocalFile | 12726 |
| LocalFile | 21076 |
| LocalFile | 21973 |
| LocalFile | 22579 |
| LocalFile | 23210 |
| LocalFile | 23347 |
| LocalFile | 23484 |
| LocalFile | 23659 |
| LocalFile | 23900 |
| CentralDirectory | 24653 |
| CentralDirectory | 24718 |
| CentralDirectory | 24775 |
| CentralDirectory | 24847 |
| CentralDirectory | 24908 |
| CentralDirectory | 24973 |


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 2

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@1859 len=12 |

## Generated YARA Meta
```json
{
  "rule_count": 2,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
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
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
      "strings": [
        {
          "id": "$a",
          "offset": 1859,
          "length": 12,
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
    "/opt/samples/rules/flat/Android_Spywaller.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_Spywaller.yar:10:1\n   |\n10 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_OmniRat.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_OmniRat.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Wshell_ChineseSpam.yar: error[E014]: invalid regular expression\n  --> /opt/samples/rules/flat/Wshell_ChineseSpam.yar:17:42\n   |\n17 |         $c = /if ?\\(\\$_POST\\[Submit\\]\\) ?{/\n   |                                          ^ unclosed counted repetition\n   |\n   = note: did you mean `\\{` instead of `{`?",
    "/opt/samples/rules/flat/Android_FakeBank_Fanta.yar: error[E010]: unknown module `androguard`\n --> /opt/samples/rules/flat/Android_FakeBank_Fanta.yar:6:1\n  |\n6 | import \"androguard\"\n  | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found",
    "/opt/samples/rules/flat/Android_AliPay_smsStealer.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_AliPay_smsStealer.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^^^^^^^^^^^^^^^^^^ module `androguard` not found"
  ],
  "incomplete": true
}
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 24: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0006           add byte [rsi], al          ; arg2
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      00888fbe01c2   add byte [rax - 0x3dfe4171], cl
│           0x00000013      0100           add dword [rax], eax
│           0x00000015      0007           add byte [rdi], al          ; arg1
└           0x00000017      07             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
