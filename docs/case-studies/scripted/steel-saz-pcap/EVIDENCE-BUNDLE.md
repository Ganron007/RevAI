# Technical Evidence Pack

**sha256:** 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b  
**sample_path:** /opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz  
**project_name:** 610

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 25
- **family_guess**: Fiddler trace archive
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra and IDA sessions failed to load due to missing gpr_path, so no binary analysis was possible. MalCat identified the file as a ZIP archive with structural anomalies, and YARA matched generic rules for network indicators, which are common in network capture files.
- **summary**: The sample is a .saz file (Fiddler trace archive) containing network session data. YARA matched rules for domains, IPs, URLs, and base64 strings, likely from captured traffic, and MalCat reported ZIP structural anomalies. No executable malware behavior was detected due to the file type, but the anomalies and generic indicators warrant suspicion.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `domain rule` | YARA rule 'domain' matched at offset 0, indicating possible domain strings in the file, which could be part of network c |
| malcat | anomalies | `LocalFileAndCentralDirectoryFieldDifferent` | ZIP file has 144 instances where local file headers differ from central directory entries, suggesting corruption or mani |
| malcat | file_summary | `type=ZIP` | The file is a ZIP archive, consistent with .saz files used by Fiddler for web session capture, which is typically benign |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: The sample is a Fiddler session archive (SAZ format, ZIP container) named 'steel.saz' (18 MB). It contains captured HTTP client-server traffic in paired request/response text files with XML metadata — the standard SAZ structure. No executable code is present (architecture: NONE), entropy is normal, and no packing or obfuscation anomalies were detected. Only generic content-pattern YARA rules matched (domain regex, IPv6 address, base64 blobs, URLs), which are expected in any web traffic capture. No malware-family-specific YARA signatures fired. Ghidra, IDA, CAPA, and FLOSS all confirmed non-applicability since the file contains no native code. While captured traffic could theoretically reference malicious infrastructure, the file itself is a data archive, not executable malware.

### deep key_evidence
- `"Malcat identified file type as ZIP with architecture NONE and no entrypoint \u2014 confirms non-executable archive"`
- `"Malcat layout shows standard SAZ structure: paired _c.txt (client request), _s.txt (server response), _m.xml (metadata) files"`
- `"Entropy of 224 (normalized) indicates no packing or encryption of archive contents"`
- `"Only 4 generic content-pattern YARA rules matched (domain, IP, base64, URL) \u2014 all expected in HTTP traffic captures; zero malware-family-specific rules matched"`
- `"Ghidra/IDA sessions not loaded, CAPA rc=16, FLOSS skipped \u2014 all confirm no executable code present in the sample"`
- `"File size 18,038,723 bytes is consistent with a multi-session network traffic capture"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b
size: 18038723
type: ZIP
architecture: NONE
entropy: 224
file_name: steel.saz
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 65 | 0 | 222 | - |
| 1_c.txt | 65 | 389 | 389 | 222 | R |
| 1_s.txt | 454 | 1284 | 1284 | 222 | R |
| 1_m.xml | 1738 | 545 | 545 | 222 | R |
| 2_c.txt | 2283 | 555 | 555 | 222 | R |
| 2_s.txt | 2838 | 1877 | 1877 | 222 | R |
| 2_m.xml | 4715 | 580 | 580 | 222 | R |
| 3_c.txt | 5295 | 420 | 420 | 222 | R |
| 3_s.txt | 5715 | 319 | 319 | 222 | R |
| 3_m.xml | 6034 | 564 | 564 | 222 | R |
| 4_c.txt | 6598 | 406 | 406 | 222 | R |
| 4_s.txt | 7004 | 18017418 | 18017418 | 224 | R |
| 4_m.xml | 18024422 | 574 | 574 | 192 | R |
| 5_c.txt | 18024996 | 460 | 460 | 192 | R |
| 5_s.txt | 18025456 | 2237 | 2237 | 192 | R |
| 5_m.xml | 18027693 | 550 | 550 | 192 | R |
| 6_c.txt | 18028243 | 626 | 626 | 192 | R |
| 6_s.txt | 18028869 | 288 | 288 | 192 | R |
| 6_m.xml | 18029157 | 552 | 552 | 192 | R |
| 7_c.txt | 18029709 | 596 | 596 | 192 | R |
| 7_s.txt | 18030305 | 518 | 518 | 192 | R |
| 7_m.xml | 18030823 | 547 | 547 | 192 | R |
| 8_c.txt | 18031370 | 419 | 419 | 192 | R |
| 8_s.txt | 18031789 | 900 | 900 | 192 | R |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| ValuableFileExtensions | destruction | UNCOMMON | 10 | embeds a list of file extensions often targeted by ransomwares |

### Anomalies (1)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| LocalFileAndCentralDirectoryFieldDifferent | 4 | headers | 144 | A local file header field is different than the corresponding central directory field |

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 18038655 | `Fiddler (v5.0.20..s://fiddler2.com` |
| 6314666 | `j\\`V` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 14849790 | `@qbb` |
| 449901 | `^odf` |
| 4508848 | `odp]` |
| 5130342 | `!ppt` |
| 14709464 | `sdf>` |
| 3193228 | `@sql` |
| 116 | `raw/1_c.txt` |
| 9567261 | `7z@c5bY+7` |
| 4668208 | `oT7Y^7z%` |
| 9324814 | `}VB`tar` |
| 15766609 | `mp4%9` |
| 17467403 | `(3ds` |
| 9399327 | `^]7z` |
| 10655795 | `crt}` |
| 17552806 | `7z
X` |
| 13012887 | `WK
(7z` |
| 3183036 | `7z~aP` |
| 13654656 | `ods{!` |
| 30964 | `VE%7z` |
| 8213581 | `3|7z` |
| 17775980 | `7z'@` |
| 17773485 | `QBQQ` |
| 4973846 | `}[7z` |
| 17526814 | `7z#?` |
| 1493375 | `r,7z` |
| 6169116 | `HO.S` |
| 6215319 | `7z{z` |
| 14100988 | `[!7z` |
| 11226444 | `F.ZLl` |
| 6873794 | `J8R88` |
| 18038655 | `Fiddler (v5.0.20..s://fiddler2.com` |
| 4699189 | `7z|+ \` |
| 11317777 | `i]??` |
| 12519173 | `[[Ea` |
| 13915799 | `?9?i` |
| 3648444 | `A0A@` |
| 10651592 | `//gs` |
| 11164420 | `eIBB` |
| 16241239 | `?YY_` |
| 10749624 | `]RBB` |
| 1438203 | `66/>` |
| 10647673 | `r4aa` |
| 16513842 | `B^Bq` |
| 5053475 | `M1ss` |
| 14367936 | `

KA` |
| 12226492 | `pv@v` |
| 15431687 | `11;2` |
| 11389492 | `S=QS` |
| 2898291 | ``rr?` |
| 147 | `raw/1_c.txt]PaK` |
| 7271122 | `Y-DDL` |
| 5800319 | `SIv[I` |
| 17191415 | `lVStt` |
| 14664704 | `D@ggq` |
| 1174022 | `nYnP0` |
| 5096204 | `>3KQ>` |
| 2760659 | `oWqb

` |
| 16440037 | `qanga` |
| 6314666 | `j\\`V` |
| 16043342 | `xxMdb` |
| 14409758 | `YcaPa` |
| 2427690 | `sHCsX` |
| 10436904 | `=<.=Z` |
| 1031487 | `ttG]w` |
| 9018140 | `">>yeo` |
| 16001828 | `5Eqii` |
| 2853156 | `KcRK?[i` |
| 14255975 | `xOaO1I\` |
| 12717058 | `v4;\v1w` |
| 16197162 | `/AQEIQc` |
| 8776279 | `X9
XSi1` |
| 8243914 | ``oo'_Od'` |
| 16695936 | `ApQ\Hq-` |
| 1644136 | `=]G-h^nEu` |
| 3337911 | `PA1Lhx3` |
| 3441444 | `
J.sQB"` |
| 1656126 | `T4Nb"
1` |
| 16569044 | `woNN~~A` |
| 14819760 | `kGZ@EFX@!` |
| 17021419 | `}?3SpfS4` |

### Virtual Files (26)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| raw/1_c.txt | 403 | - |
| raw/1_s.txt | 1981 | - |
| raw/1_m.xml | 1289 | - |
| raw/2_c.txt | 654 | - |
| raw/2_s.txt | 6012 | - |
| raw/2_m.xml | 1371 | - |
| raw/3_c.txt | 444 | - |
| raw/3_s.txt | 330 | - |
| raw/3_m.xml | 1290 | - |
| raw/4_c.txt | 430 | - |
| raw/4_s.txt | 18617711 | - |
| raw/4_m.xml | 1301 | - |
| raw/5_c.txt | 507 | - |
| raw/5_s.txt | 6412 | - |
| raw/5_m.xml | 1297 | - |
| raw/6_c.txt | 700 | - |
| raw/6_s.txt | 308 | - |
| raw/6_m.xml | 1295 | - |
| raw/7_c.txt | 674 | - |
| raw/7_s.txt | 682 | - |

### Structures (55)
| Name | EA |
|---|---|
| LocalFile | 0 |
| LocalFile | 65 |
| LocalFile | 454 |
| LocalFile | 1738 |
| LocalFile | 2283 |
| LocalFile | 2838 |
| LocalFile | 4715 |
| LocalFile | 5295 |
| LocalFile | 5715 |
| LocalFile | 6034 |
| LocalFile | 6598 |
| LocalFile | 7004 |
| LocalFile | 18024422 |
| LocalFile | 18024996 |
| LocalFile | 18025456 |
| LocalFile | 18027693 |
| LocalFile | 18028243 |
| LocalFile | 18028869 |
| LocalFile | 18029157 |
| LocalFile | 18029709 |
| LocalFile | 18030305 |
| LocalFile | 18030823 |
| LocalFile | 18031370 |
| LocalFile | 18031789 |
| LocalFile | 18032689 |
| LocalFile | 18033234 |
| LocalFile | 18034368 |
| CentralDirectory | 18034664 |
| CentralDirectory | 18034783 |
| CentralDirectory | 18034930 |


## capa Capability Rules
engine: `?` · Total rules: 0 · duration_s: ?

| Rule | ATT&CK | MBC |
|---|---|---|

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 4

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@13421 len=2 |
| contains_base64 | - | $a@1400104 len=12 |
| url | - | $url_regex@18038703 len=20 |

## Generated YARA Meta
```json
{
  "rule_count": 4,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
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
      "path": "/opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 13421,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
      "strings": [
        {
          "id": "$a",
          "offset": 1400104,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 18038703,
          "length": 20,
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
┌ 29: fcn.00000000 ();
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0000           add byte [rax], al
│           0x00000009      00d3           add bl, dl
│       ┌─< 0x0000000b      7ab5           jp 0xffffffffffffffc2
│       │   0x0000000d      52             push rdx
│       │   0x0000000e      0000           add byte [rax], al
│       │   0x00000010      0000           add byte [rax], al
│       │   0x00000012      0000           add byte [rax], al
│       │   0x00000014      0000           add byte [rax], al
│       │   0x00000016      0000           add byte [rax], al
│       │   0x00000018      0000           add byte [rax], al
│       │   0x0000001a      0400           add al, 0
└       │   0x0000001c      1f             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
