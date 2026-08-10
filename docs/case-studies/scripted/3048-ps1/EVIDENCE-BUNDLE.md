# Technical Evidence Pack

**sha256:** 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2  
**sample_path:** /opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1  
**project_name:** day6

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 40.0
- **family_guess**: PowerShell-based malware
- **confidence**: 40
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed due to server errors; IDA provided minimal data with zero functions and one string; MalCat and YARA supplied comprehensive evidence of behavioral signals and obfuscation, indicating malicious intent.
- **summary**: A PowerShell script with high entropy and base64 obfuscation, exhibiting behavioral signals such as YARA rules for shell execution and process control APIs. These findings strongly suggest malicious intent, likely used for lateral movement, payload delivery, or command-and-control operations.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | views.yara_hits | `RunShell` | YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is c |
| malcat | views.yara_hits | `Powershell` | YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload deliver |
| yara | yara matches | `powershell` | YARA rule matched for PowerShell content, corroborating the script's nature and potential for malicious use. |
| yara | yara matches | `contains_base64` | Base64 strings suggest obfuscation, a neutral but suspicious technique often used in malicious scripts to evade detectio |
| malcat | strings/apis | `ProcessStartInfo, RedirectStandardOutput, etc.` | APIs related to process execution (e.g., ProcessStartInfo, RedirectStandardOutput) indicate the script can launch and co |
| malcat | file_summary.entropy | `148` | High entropy for a text file (2800 bytes) may indicate encoded or obfuscated content, supporting suspicion of malicious  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PowerShell dropper/loader script that uses architecture-aware execution, hidden window launch (-nop -w hidden), and a double-encoded (Base64 + GZip) payload delivered via [scriptblock]::create(). The encoded payload (2800 bytes of dense Base64) is a classic technique used by PowerShell Empire, Cobalt Strike stagers, and document-embedded macro payloads. YARA rules matched for RunShell (lateral movement), Powershell execution, Base64 encoding, domain regex, and IPv6 patterns.

### deep key_evidence
- `"Malcat YARA hit: 'RunShell' rule (category: lateral movement, reliability 70) \u2014 starts a shell"`
- `"Malcat YARA hit: 'Powershell' rule (category: lateral movement, reliability 30) \u2014 runs a powershell script"`
- `"YARA checklist: contains_base64 rule matched (16 pattern hits at offset 52)"`
- `"YARA checklist: domain_regex matched, powershell matched at offset 59, ipv6 matched at offset 11"`
- `"IDA strings: full script reveals '-nop -w hidden -c' flags for hidden execution with no PowerShell profile"`
- `"IDA strings: architecture check '[IntPtr]::Size -eq 4' with sysnative path workaround for 32/64-bit compatibility"`
- `"IDA strings: dynamic code execution via [scriptblock]::create() with GZip+Base64 decoded payload (H4sI GZip magic header)"`
- `"Malcat strings: 12+ long Base64-encoded strings identified, indicating heavily obfuscated payload"`
- `"Malcat: file type text/utf8, 2800 bytes, entropy 148 \u2014 consistent with encoded PowerShell payload"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2
size: 2800
type: text/utf8
architecture: NONE
entropy: 148
file_name: 3048.ps1
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
|  | 0 | 2800 | 2800 | 148 | - |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| RunShell | lateral movement | UNCOMMON | 70 | starts a shell |
| Powershell | lateral movement | SUSPICIOUS | 30 | runs a powershell script |

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 75 | `powershell` |
| 100 | `powershell` |
| 52 | `WindowsPowerShell` |

### Top Strings (109 extracted; showing 80)
| EA | String |
|---|---|
| 75 | `powershell` |
| 100 | `powershell` |
| 1575 | `o7pr3d3E1k5jz02X..GAV521nIJ17x5ls7` |
| 1846 | `Gpbr0XQ3VYSTpa6N..K7RjgOTuuIzjddpQ` |
| 922 | `T3JylvqFE5qcDlZQ..8BxX0ldul5V1Ngah` |
| 1173 | `2hkmcF9neg5RB7Ja..gNN9JfmZNyjAfv3v` |
| 775 | `P3VqrGPCxLhlhYXO..vUr8SyWQmhdZowlJ` |
| 2159 | `7F96i2Gg0GWOMwld..QKGJS8cXU5oqmLUV` |
| 2364 | `sX3hKXG549OGzo9r..I49gUI8fvDGiZpyZ` |
| 1436 | `JIzORjuBW1XFNGUr..9XwoM3DpQaGhpNAC` |
| 1379 | `WYuJycRmqIaC0cyb..HFpK8G8ENJPljUam` |
| 1500 | `AraaEnCWshkAR1OD..yqRk6mZ4sh9tvdsR` |
| 1973 | `WZ4ZLhY3guI7s7G0..k2HoVJV9N3SWvZUI` |
| 1777 | `2RwaVKLc7mCSsNxE..HH6NuKI6Oev8Z3at` |
| 2027 | `Eo2s3vBUtuLYploi..fAfYge4eCdAvfIwo` |
| 1327 | `JoEvjoV91JZMDbXv..IXc2SSEI5HvQvpYH` |
| 607 | `611R5MNolexcoi8E..PEQ8yVlplSUvD1X3` |
| 2679 | `RedirectStandardOutput` |
| 409 | `ayBL9nEj5D9YKCaN..yGnURa6drYHkwwDz` |
| 2320 | `VXTTL1eqvOE8I0eJ..wy8c6oqJlKaeOxGh` |
| 1279 | `lU0vnCWIVFB8MI7S..VDfCvzH9olicnRhm` |
| 696 | `JkW7RcEve6LTvO0R..MiTPy83oAY4JfhYp` |
| 511 | `2aOMhRxfK28a3K18..rjhpv3sB8jQ64Xzj` |
| 483 | `1HVVXXqdHVv97FXkCTmQoNyv797` |
| 1741 | `UHz3R3ZHxwY5Hh0k..JU96hldxPZFqKB04` |
| 881 | `4CWlvQHtOPaD257u..795uK5oQ7SVLoPfm` |
| 1129 | `JmRhR7Dc5Mc7JdUncF8m5W` |
| 652 | `7fdx5ayuc9ojlfN8..Lp7Te4P5sMINWmWK` |
| 2074 | `IDsion4QRXMVBygw..hhaEOO1Cli8oxT7A` |
| 260 | `StreamReader` |
| 558 | `fhzuswzHxWXcusOFmOc42lCCc77B` |
| 2553 | `hPfju7f8AKrkmBB0MAAA` |
| 2529 | `KjBcPP5YRyPv22tirfbYv3k` |
| 150 | `ProcessStartInfo` |
| 2603 | `CompressionMode` |
| 2653 | `UseShellExecute` |
| 52 | `WindowsPowerShell` |
| 2129 | `bH1z1MLK3pr6ViKTDmYgGxlzs9MVK` |
| 339 | `MemoryStream` |
| 1153 | `irr6nBfFQXlTbPTQqHK` |
| 390 | `H4sIAAKbYF0CA7VWa4` |
| 2262 | `LU1Xn65QIK0ZBrcTlzhPbecnVh` |
| 2289 | `gQNQ` |
| 2503 | `CFAfzRuF5ECBE24Yii` |
| 91 | `else` |
| 1728 | `XHxWnyqBynZr` |
| 2250 | `Mo7IwddEbwZ` |
| 294 | `Compression` |
| 2447 | `4xLtTc9791g9bIWfph` |
| 2591 | `Compression` |
| 138 | `Diagnostics` |
| 2621 | `Decompress` |
| 2735 | `CreateNoWindow` |
| 2767 | `Diagnostics` |
| 1552 | `n3R8ujJU71sRiqM1` |
| 2789 | `Start` |
| 4 | `IntPtr` |
| 231 | `create` |
| 2779 | `Process` |
| 2296 | `YMX5z7b93TOsryEFGoB3AFV` |
| 33 | `windir` |
| 2724 | `Hidden` |
| 204 | `hidden` |
| 587 | `cG5Ic7w` |
| 2469 | `idS3SIXz8f8bry9w` |
| 217 | `scriptblock` |
| 170 | `FileName` |
| 2117 | `5Gx9vtUIKw5` |
| 2635 | `ReadToEnd` |
| 371 | `FromBase64String` |
| 42 | `sysnative` |
| 546 | `XkxTOYkQiR8` |
| 595 | `9nmEXsF9ztX` |
| 867 | `CpKPfH3FF` |
| 757 | `PcJ7Xm9w92` |
| 2486 | `rH4XhkLzEu9X03` |
| 445 | `B2dGqsRu7h` |
| 464 | `vfbzXgyexmskpWui2Q` |
| 185 | `Arguments` |
| 2711 | `WindowStyle` |


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 5

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| powershell | - | $a@59 len=10 |
| IP | - | $ipv6@11 len=2 |
| contains_base64 | - | $a@52 len=16 |
| Antivirus | - |  |

## Generated YARA Meta
```json
{
  "rule_count": 5,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
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
      "rule": "powershell",
      "path": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 59,
          "length": 10,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 11,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": [
        {
          "id": "$a",
          "offset": 52,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Antivirus",
      "path": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
      "strings": []
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
    "/opt/samples/rules/flat/Android_AliPay_smsStealer.yar: error[E010]: unknown module `androguard`\n  --> /opt/samples/rules/flat/Android_AliPay_smsStealer.yar:11:1\n   |\n11 | import \"androguard\"\n   | ^^
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 1906: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_31h, int64_t arg_32h, int64_t arg_36h, int64_t arg_41h, int64_t arg_49h, int64_t arg_4ah, int64_t arg_56h, int64_t arg_63h, int64_t arg_6ah, int64_t arg_79h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_31h @ rbp+0x31
│           ; arg int64_t arg_32h @ rbp+0x32
│           ; arg int64_t arg_36h @ rbp+0x36
│           ; arg int64_t arg_41h @ rbp+0x41
│           ; arg int64_t arg_49h @ rbp+0x49
│           ; arg int64_t arg_4ah @ rbp+0x4a
│           ; arg int64_t arg_56h @ rbp+0x56
│           ; arg int64_t arg_63h @ rbp+0x63
│           ; arg int64_t arg_6ah @ rbp+0x6a
│           ; arg int64_t arg_79h @ rbp+0x79
│           0x00000000      6966285b49..   imul esp, dword [rsi + 0x28], 0x746e495b
│           0x00000007      50             push rax
│       ┌─< 0x00000008      7472           je 0x7c
│       │   0x0000000a      5d             pop rbp
│       │   0x0000000b      3a3a           cmp bh, byte [arg_49h]      ; arg3
│       │   0x0000000d      53             push rbx
│       │   0x0000000e      697a65202d..   imul edi, dword [rdx + 0x65], 0x71652d20
│       │   0x00000015      203429         and byte [rcx + rbp], dh    ; arg4
│      ┌──< 0x00000018      7b24           jnp 0x3e
│      ││   0x0000001a      62             invalid
..
    │││││   ; DATA XREF from fcn.00000000 @ 0x1a0(w)
│  ││││└──> 0x0000003e      657253         jb 0x94
│  ││││││   ; DATA XREF from fcn.00000000 @ 0x70e(w)
│  ││││││   0x00000041      68656c6c5c     push 0x5c6c6c65             ; 'ell\\'
│ ┌───────< 0x00000046      7631           jbe 0x79
│ │││││││   0x00000048      2e305c706f     xor byte cs:[rax + rsi*2 + 0x6f], bl
│ │││││││   ; DATA XREF from fcn.00000000 @ 0x6aa(r)
│ ────────< 0x0000004d      7765           ja 0xb4
│ ────────< 0x0000004f      7273           jb 0xc4
│ │││││││   0x00000051      68656c6c2e     push 0x2e6c6c65             ; 'ell.'
│ ────────< 0x00000056      657865         js 0xbe
│ │││││││   0x00000059      27             invalid
  │││││││   ; DATA XREFS from fcn.00000000 @ 0x72c(r), 0x7b7(r)
..
  │││││││   ; DATA XREF from fcn.00000000 @ 0xb3(r)
  │││││││   ; DATA XREF from fcn.00000000 @ 0x3e4(w)
  │││││││   ; DATA XREF from fcn.00000000 @ 0x805(w)
  │││││││   ; DATA XREFS from fcn.00000000 @ 0x606(r), 0xa5a(r)
  │││││││   ; DATA XREFS from fcn.00000000 @ 0x5a1(w), 0x9fb(w)
  │││││││   ; DATA XREFS from fcn.00000000 @ 0x43e(r), 0x440(w)
│ │││││││   ; DATA XREF from fcn.00000000 @ 0x954(w)
│ └───────> 0x00000079      65772d         ja 0xa9
│  │││││└─> 0x0000007c      4f             invalid
..
│ │││││└──> 0x00000094      732e           jae 0xc4
│ │││││ │   0x00000096      50             push rax
│ │││││ │   0x00000097      726
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/revai-lab-610/day6/14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2/3048.ps1",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
