# Technical Evidence Pack

**sha256:** 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f  
**sample_path:** /opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin  
**project_name:** 7 - Malware Lab Samples

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: Cobalt Strike
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed due to startup errors, providing no data. IDA and Malcat both indicate no functions or imports, consistent with raw shellcode. YARA rules detect Cobalt Strike-related patterns, providing behavioral evidence of malicious intent. Malcat's high entropy (100) is neutral but common in encrypted or packed code.
- **summary**: This 509-byte shellcode binary exhibits high entropy and no imports or functions, but YARA rules identify signatures for Cobalt Strike functions, strongly indicating malicious use for command and control or payload execution. The lack of structural features from IDA and Malcat supports its nature as raw shellcode, while the YARA match provides critical behavioral evidence of threat actor tooling.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `Cobalt_functions` | Rule matches strings at offsets 163 and 420 associated with Cobalt Strike, a known malicious tool used for command and c |
| malcat | file_summary | `entropy 100` | Extremely high entropy indicates possible encryption, compression, or obfuscation, which is a neutral signal but common  |
| ida | IDA database summary | `funcs_count 0` | No functions detected, which is typical for position-independent shellcode or raw binary without structured code, aligni |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Cobalt Strike x86-64 staged shellcode beacon. The 509-byte payload contains an embedded beacon configuration with C2 server tunnelcs.fax-email.us, Cobalt Strike watermark 15914547, and the 'stage' marker typical of Cobalt Strike's staged payload delivery. YARA rules Cobalt_functions and contains_base64 triggered on known shellcode patterns. The file has zero imports (position-independent shellcode resolves APIs dynamically via PEB walking), high entropy (100), and a single CODE segment — all hallmarks of shellcode. The base64-encoded data and domain pattern further confirm C2 communication setup.

### deep key_evidence
- `"IDA string at addr 330: '.aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.' \u2014 Cobalt Strike beacon config with watermark 15914547 and C2 domain tunnelcs.fax-email.us"`
- `"YARA rule 'Cobalt_functions' matched at offsets 163 and 420 \u2014 known Cobalt Strike shellcode hash patterns"`
- `"YARA rule 'contains_base64' matched at offset 372 \u2014 base64-encoded payload data"`
- `"YARA rule 'domain' matched at offset 2 \u2014 domain regex pattern in raw shellcode"`
- `"File is 509 bytes, x86-64 (metapc), single CODE segment, entropy 100 \u2014 position-independent shellcode"`
- `"Zero imports (imports_count=0) \u2014 shellcode resolves Windows APIs dynamically via PEB walking"`
- `"Zero functions detected (functions_count=0) \u2014 no standard function prologues, raw shellcode execution flow"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f
size: 509
type: ?
architecture: NONE
entropy: 100
file_name: shellcode.bin
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
|  | 0 | 509 | 509 | 100 | - |

### Top Strings (37 extracted; showing 37)
| EA | String |
|---|---|
| 287 | `.Sj.Sj.hH...j.Phj` |
| 330 | `.aaa.stage.15914..XXXXXXXXXXXXXX..` |
| 264 | `a.....HH` |
| 396 | `H..A...` |
| 246 | `a.....@..C...` |
| 228 | `a.....@..C...` |
| 11 | `d.R0.R..R..r(.` |
| 2 | `....`.` |
| 110 | `f..K.X..` |
| 450 | `..?.` |
| 149 | `.h....h` |
| 196 | `a...` |
| 210 | `@...` |
| 317 | `...@.0` |
| 273 | `a......` |
| 46 | `RW.R..B<.` |
| 119 | `....` |
| 495 | `...|.` |
| 479 | `...Rh` |
| 467 | `WWWC.` |
| 439 | `_.G..` |
| 416 | `...hD` |
| 75 | `<I.4..` |
| 158 | `..j.hX` |
| 65 | `P.H..X .` |
| 56 | `.@x.` |
| 445 | `.u9.` |
| 136 | `X_Z..` |
| 104 | `X.X$.` |
| 180 | `iPhdnsaThLw&.` |
| 124 | `.D$$[[aYZQ` |
| 473 | `RWS.` |
| 490 | `[_Z=` |
| 457 | `.|$.1` |
| 404 | `_~.h` |
| 33 | `<a|., ` |
| 99 | `;}$u` |


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 3

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@2 len=4 |
| contains_base64 | - | $a@372 len=20 |
| Cobalt_functions | - | $h1@163 len=4; $h4@420 len=4 |

## Generated YARA Meta
```json
{
  "rule_count": 3,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 2,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$a",
          "offset": 372,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Cobalt_functions",
      "path": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
      "strings": [
        {
          "id": "$h1",
          "offset": 163,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$h4",
          "offset": 420,
          "length": 4,
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
┌ 7: fcn.00000000 ();
│           0x00000000      fc             cld
│           0x00000001      e82e2e2e2e     call 0x2e2e2e34
└           0x00000006      60             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/7 - Malware Lab Samples/9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f/shellcode.bin",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
