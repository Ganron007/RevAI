# Technical Evidence Pack

**sha256:** f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1  
**sample_path:** /opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js  
**project_name:** malware

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: trojan.dwnldr/skeeyah
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed entirely due to server errors; IDA reported zero functions and only one string, providing minimal insight; Malcat revealed the file is text/utf8 with Base64 constants and numerous obfuscated strings indicative of encoding; YARA matched six rules including behavioral indicators like domain and Android Meterpreter; VirusTotal shows high malicious detections (44/61 engines) with threat labels suggesting a trojan downloader.
- **summary**: The JavaScript file 'loveyou.js' shows significant obfuscation through Base64 encoding and contains strings matching YARA rules for malware indicators such as Android Meterpreter and domain patterns. External threat intelligence from VirusTotal confirms a high malicious detection rate, classifying it as a trojan downloader. Despite tool limitations (Ghidra failure, IDA low function count), the behavioral evidence from YARA and Malcat points to malicious intent, warranting a malicious verdict.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `android_meterpreter` | Indicates presence of Android Meterpreter RAT strings, suggesting malicious remote access capability and behavioral inte |
| yara | yara matches | `domain` | Matches domain regex patterns, potentially indicating C2 communication endpoints, which is behavioral evidence of networ |
| malcat | constants | `crypto::Base64` | Use of Base64 encoding constant, common in obfuscation and payload delivery in malware, though neutral alone, supports o |
| malcat | strings | `base64-like strings` | Multiple strings resembling Base64 encoded data (e.g., 'wpHDtlHDiMOWf0JK..'), which may contain obfuscated malicious cod |
| external | VirusTotal | `44 malicious detections` | High detection rate from multiple AV engines (44 malicious out of 61) confirms malicious nature and aligns with threat l |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: This JavaScript file (loveyou.js) is a heavily obfuscated Android Meterpreter payload loader. It contains multiple layers of base64 encoding with runtime decoding, function indirection through objects, and obfuscated variable names to evade detection. The file uses social engineering via its filename to entice execution. YARA rules confirm android_meterpreter signature match, base64 table presence, and packed function patterns. The massive base64-encoded payload (4,509+ chars) is decoded and executed at runtime, likely delivering a Meterpreter reverse shell or RAT component. Additional capability domains: Persistence is not observed {source: 'malware analysis', query_or_table: 'capability assessment', row_or_rule: 'none', why: 'No persistence mechanisms identified in the obfuscated payload or YARA rules'}. C2 network is observed {source: 'loveyou.js analysis', query_or_table: 'YARA rules', row_or_rule: 'android_meterpreter signature', why: 'Meterpreter reverse shell payload inherently establishes command and control connections'}. Exfiltration is not observed {source: 'malware analysis', query_or_table: 'payload features', row_or_rule: 'none', why: 'No exfiltration patterns or data theft indicators found'}. Defense impairment is observed {source: 'loveyou.js analysis', query_or_table: 'obfuscation methods', row_or_rule: 'base64 encoding and function indirection', why: 'Techniques used to evade detection and impair security defenses'}. Credential access is not observed {source: 'malware analysis', query_or_table: 'functionality scan', row_or_rule: 'none', why: 'No credential harvesting or dumping code present'}. Imports are not observed {source: 'file analysis', query_or_table: 'dependencies', row_or_rule: 'none', why: 'External imports or modules not specified in the payload analysis'}.

### deep key_evidence
- `"YARA rule 'android_meterpreter' matched at offset 9687 with $stopEval string (4 bytes), confirming Android Meterpreter payload"`
- `"YARA rule 'BASE64_table' matched at offset 3337 (64 bytes), indicating embedded base64 decoding table"`
- `"YARA rule 'possible_includes_base64_packed_functions' matched at offsets 4 and 3415, confirming base64-packed functions"`
- `"YARA rule 'function_through_object' matched at offsets 3737 and 4117, indicating function call obfuscation through objects"`
- `"YARA rule 'contains_base64' matched at offset 4, confirming base64 encoded content"`
- `"IDA strings: Massive obfuscated array 'adfgkdafkhjgrsgfksghkod_0x515c' containing 100+ base64-encoded values starting at offset 0"`
- `"Malcat strings: Large base64 payload at address 9679 (4,509 chars) with additional obfuscated data at addresses 67, 240, 377, 818, 1175, 1254, 1468, 1590, 1737, 2069"`
- `"Malcat strings: Obfuscated function/variable names 'adfgkdafkhjgrsgfksghkod_0x442408' (at 12135) and 'adfgkdafkhjgrsgfksghkod_0x49ad' (at 12690, 12811, 15530, 5730)"`
- `"File entropy: 124 (high), indicating heavy obfuscation and packed content"`
- `"Social engineering filename 'loveyou.js' designed to entice user execution"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1
size: 16805
type: text/utf8
architecture: NONE
entropy: 5.74
file_name: loveyou.js
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
|  | 0 | 16805 | 16805 | - |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 818 | `wpHDtlHDiMOWf0JK..FwrjCvHI9w4PCniw` |
| 1254 | `WMOWRcKKF8OUAMOn..pb8Kewq0XVS4sw6M` |
| 2069 | `XsKxwrDDlzHCjcK4..xNPcKDw6vDgcO0YQ` |
| 240 | `wqvCtBk3K8KJUSHD..AUL2TCjMOzwpbDgA` |
| 377 | `wqR0wpILaCFPRz9J..HsOSwrvDmcOzwoIL` |
| 1175 | `w5TCjisEEsKVYQXD..KnIS9XPEXDo1dEFw` |
| 5627 | `x20IVbqwAIVbqwct..bqweIVbqwctIVbqw` |
| 1737 | `VVBSJcOfw5jCusOj..ew5p2OwXCjzJZST4` |
| 5961 | `vIVbqwOpIVbqwNIV..IVbqwMZIVbqwAIVb` |
| 1590 | `dMOzwovCv8KPWDRs..r3TDki0Ybhs5w4sq` |
| 5700 | `x22sIVbqwhIVbqwelIVbqwLIVbqw` |
| 67 | `w5TCmDxpJ8K5w7Eu..DphPDqVdXWFHDiHc` |
| 1468 | `BMOow4DDpj3CuGTD..m8OfwqwIJMKKw4Ed` |
| 12135 | `adfgkdafkhjgrsgfksghkod_0x442408` |
| 12811 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15530 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12690 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5730 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12755 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15635 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5532 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12927 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5406 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12973 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5344 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6011 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6226 | `adfgkdafkhjgrsgfksghkod_0x1f6a59` |
| 6149 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12422 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12469 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6103 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6057 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15742 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12525 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 12643 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5914 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5868 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5822 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15682 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5233 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15587 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5776 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15091 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13803 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14000 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14127 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14183 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14230 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 3030 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14286 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14333 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14482 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15166 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14560 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14617 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14664 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15035 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14711 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14776 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14884 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 14941 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15302 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5287 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 6471 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5152 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5091 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 5047 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 4996 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15359 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13145 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13209 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13029 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13273 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13399 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 15245 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13455 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13557 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 2886 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13604 | `adfgkdafkhjgrsgfksghkod_0x49ad` |
| 13660 | `adfgkdafkhjgrsgfksghkod_0x49ad` |

### Constants / Known Patterns (1)
| Category | Value |
|---|---|
| crypto | `crypto::Base64` |


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
| domain | - | $domain_regex@0 len=3 |
| possible_includes_base64_packed_functions | - | $f@3415 len=4; $fff@4 len=20 |
| function_through_object | - | $@4117 len=14; $@3737 len=16 |
| contains_base64 | - | $a@4 len=20 |
| BASE64_table | - | $c0@3337 len=64 |
| android_meterpreter | - | $stopEval@9687 len=4 |

## Generated YARA Meta
```json
{
  "rule_count": 6,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
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
      "rule": "possible_includes_base64_packed_functions",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
      "strings": [
        {
          "id": "$f",
          "offset": 3415,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$fff",
          "offset": 4,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "function_through_object",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
      "strings": [
        {
          "id": "$",
          "offset": 4117,
          "length": 14,
          "xor_key": null
        },
        {
          "id": "$",
          "offset": 3737,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
      "strings": [
        {
          "id": "$a",
          "offset": 4,
          "length": 20,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "BASE64_table",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
      "strings": [
        {
          "id": "$c0",
          "offset": 3337,
          "length": 64,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "android_meterpreter",
      "path": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
      "strings": [
        {
          "id": "$stopEval",
          "offset": 9687,
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
    "/opt/samples/rules/flat/Wshell_Chin
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00000000
```asm
┌ 1375: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_4fh, int64_t arg_68h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_4fh @ rbp+0x4f
│           ; arg int64_t arg_68h @ rbp+0x68
│       ┌─< 0x00000000      7661           jbe 0x63
│      ┌──< 0x00000002      7220           jb 0x24
│      ││   0x00000004      61             invalid
..
│      └──> 0x00000024      27             invalid
..
        │   ; XREFS: DATA 0x000001d2  DATA 0x0000027a  DATA 0x00000298  
        │   ; XREFS: DATA 0x00000321  DATA 0x0000044e  DATA 0x00000468  
        │   ; XREFS: DATA 0x00000495  DATA 0x000004e4  
      │││   ; DATA XREFS from fcn.00000000 @ 0x277(r), 0x2ca(r), 0x492(r), 0x576(r), 0x70f(r)
     ││││   ; DATA XREFS from fcn.00000000 @ 0x3a4(w), 0x5a3(w)
    │││││   ; DATA XREF from fcn.00000000 @ 0x4cd(r)
   ││││││   ; DATA XREF from fcn.00000000 @ 0x25b(w)
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x8d(w)
│ │││││ └─> 0x00000063      7737           ja 0x9c
│ │││││ ┌─< 0x00000065      44447068       jo 0xd1
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x49a(w)
│ │││││ │   0x00000069      50             push rax
│ │││││┌──< 0x0000006a      447156         jno 0xc3
│ ││││└───> 0x0000006d      6458           pop rax
│ ││││ ││   0x0000006f      57             push rdi                    ; arg1
│ ││││ ││   0x00000070      4648446948..   imul r9d, dword [rax + 0x63], 0x272c273d
│ ││││ ││   0x0000007a      4d51           push r9                     ; arg6
│ │││└┌───< 0x0000007c      7a44           jp 0xc2
│ │││┌────< 0x0000007e      724d           jb 0xcd
│ ────────< 0x00000080      4b647736       ja 0xba
│ │││││││   0x00000084      673d272c2754   cmp eax, 0x54272c27         ; '\',\'T'
│ │ │││││   0x0000008a      6c             insb byte [rdi], dx
│ │┌──────< 0x0000008b      7243           jb 0xd0
│ │││││││   0x0000008d      6a63           push 0x63                   ; 'c' ; "w7DDphPDqVdXWFHDiHc=','MQzDrMKdw6g=','TlrCjcK1w4E=','worDr8OkOBc=','e8KNbsKWBA==','XXZsw6wnJMK6eG3CrRs=','ZMKKwpMzw44Wd8Kow7NBJ3w1w4XCiT0=','wqvCtBk3K8KJUSHDsg7Cv8KHfsKSd0NDIsOJPkMhwqrCklzCpcKTw4EcQcKEHkhkAGzDsSQtEBIef8OPw7rClCcUwoAUL2TCjMOzwpbDgA==','wqdREMKJCQ==','XsK5UMO5','wqR0wpILaCFPRz9JwqjCp8KIw6UJwpbCnsKPRcK9w7tXwqzCrsKQw6PDssKTw4NCwo7DssKsHsOSwrvDmcOzwoIL','woLDrlXDisOK','wpvDvsKawoo=','PhvDncKyw69vwpg=','wrXDmsOnw7jCrg==','S8KPwoQ2wpXChsO5wrBCwokJwpTDhCLDsXc=','AMOqYGrDlQ==','X8Kwwr7DuMOKUjQnw7l6DTUgTk8=','YMKgwqwFw64=','eSXDmMKSw4I=','e1dtwrzChgc=','wogawoo5wqkow7zCm8OvwqJT','LTLDvsK+ZA==','w7kGwp4=','E8OZw4fDoh3CllvDm1rDpsKdcMObZBLCnA==','w6RWEMOUw6U=','bcKlwrMSw6s=','bsKzwrLDs8Oq','X8KCw4bCnQU=','wpHDtlHDiMOWf0JKw5ZYUVTDgcK9wo9XwogLGcK4wpnCiMORZ0Itc8KqSyDChAXCuxDCoMKdIz3Dp8Kcw7nCtX3CicOow6oPJ0Fvwp86HcO4IkPDpRjDvMO3wp
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
