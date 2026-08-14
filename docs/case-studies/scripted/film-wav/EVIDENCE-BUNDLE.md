# Technical Evidence Pack

**sha256:** 0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a  
**sample_path:** /opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav  
**project_name:** 710

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 85
- **family_guess**: trojan.fkmb
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra analysis failed due to program not found in project; IDA detected 70,200 strings but no functions; MalCat reported high entropy (7.48) and numerous obfuscated strings; YARA matched rules for domain, IP, base64, and indirect function calls; VirusTotal flagged as malicious with 9 detections and threat label trojan.fkmb.
- **summary**: The WAV file exhibits high entropy and contains strings matching YARA rules for domain, IP, base64, and malicious document patterns, suggesting embedded malicious content. VirusTotal corroborates with trojan detections, indicating malicious intent despite the non-standard file type.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| yara | yara matches | `domain rule` | File contains pattern matching domain regex at offset 0, indicating potential network communication or data reference. |
| yara | yara matches | `IP rule` | File contains IPv6 pattern at offset 880, suggesting embedded IP address for possible C2 or exfiltration. |
| yara | yara matches | `contains_base64 rule` | Base64-encoded string detected at offset 3750495, which may conceal commands or payloads. |
| yara | yara matches | `maldoc_indirect_function_call_3 rule` | Pattern indicative of indirect function calls at offset 1743485, commonly used in malicious documents to evade detection |
| malcat | static_profile | `file_summary` | High entropy (7.48) and numerous obfuscated strings suggest packing or encoding, which is a neutral signal but often ass |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The WAV file shows strong indicators of malicious activity, including YARA matches for network indicators, base64 encoding, and maldoc behavior, along with high entropy and obfuscated strings suggesting obfuscation or embedded threats. For persistence, not observed. {source: analysis, query_or_table: N/A, row_or_rule: N/A, why: No indicators like registry keys or scheduled tasks were identified in the summary}. For exfiltration, YARA matches for network indicators suggest potential exfiltration or C2 communication. {source: YARA analysis, query_or_table: YARA rules, row_or_rule: network_indicators, why: Matches indicate network-related strings that could facilitate data exfiltration}. For credential_access, not observed. {source: analysis, query_or_table: N/A, row_or_rule: N/A, why: No evidence of credential theft or access mechanisms in the provided summary}. For imports, not observed. {source: analysis, query_or_table: N/A, row_or_rule: N/A, why: No imported functions or DLLs were noted in the analysis}

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: domain", "why": "Matches domain regex, potentially indicating malicious network activity."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: IP", "why": "Matches IPv6 pattern, suggesting embedded network addresses common in malware."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: contains_base64", "why": "Contains base64 encoded data, often used for obfuscation in malicious files."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "rule: maldoc_indirect_function_call_3", "why": "Indicates indirect function calls typical in malicious documents, suspicious in an audio file."}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "entropy: 156", "why": "High entropy suggests encryption or compression, common in obfuscated or malicious files."}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "views", "row_or_rule": "strings", "why": "Obfuscated strings like '/L/M/8080n0n0.0.0P2P2' indicate potential malicious encoding or embedded code."}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a
size: 15179552
type: ?
architecture: NONE
entropy: 7.48
file_name: film.wav
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Rights |
|---|---|---|---|---|
|  | 0 | 15179552 | 15179552 | - |

### High-Signal Strings (14 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 985586 | `~qqbcTTHI@@==55...HHSS\\fglmqqttz{` |
| 2114692 | `rrff^^\\\\XXTTRS..#"""#"$$'&*+**""` |
| 90252 | `wwdd\\UUMMBB;;4466@@NNOO<<` |
| 2114452 | `xymlcc[[TTLLHHHH..SRWVYY\\ccjkrs|}` |
| 898172 | `&&44A@MLWV\]\\[Z..TURRTUWW^^fgqq{z` |
| 340556 | `++88BBFFBB::..&&&&00BB\\vv` |
| 2094152 | `on\\SRLLKJKKQQXXddmmssyy` |
| 571116 | `$$01::??@@DEFFGFGGHINNTU\\hhzz` |
| 8422904 | `+*::ONddhh\\VWZZWVMMLLDD` |
| 2100288 | `||\\KKFFJKRR]\edllttwwjjNO*+` |
| 448960 | `\\BBA@LM]]ffihdd\]TTRS_^||` |
| 809600 | `01<<CBGGOO\\ffdeaa[[KJ  ` |
| 182552 | `##(),-003276;;BB..PPWV\\bbkjqqvv}|` |
| 48756 | `\\44

` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 252868 | `zzsrppnnnnllhhff..NNIIDDCC>>77..##` |
| 958048 | `#"((1077;;>>@@CC..99222267AAQQcbvw` |
| 8705632 | `./<<IHSRXX``eeih..PPLLKKEE>?8811((` |
| 2096188 | `66NN^^hhjjjjffdd..89885523-,()%$! ` |
| 1411328 | `""&&+*--1144<<DE..xyvvttrrpqpptt{z` |
| 8000640 | `""''**..2366;:=<..A@=<884501,,()""` |
| 2095272 | `xxhiYXLMKJIH==,,..bbhhfgee__QPA@./` |
| 9326666 | `` ^,V.P6VLj`v^jB..,H.L:D>8::4L.b&p` |
| 393167 | `
,
,
;
:
H
H
S
R..S
S
Z
Z
f
f
t
u
` |
| 2104968 | `~~{zxxxxwvsslmdd..LLFGFFLLRS_^jkzz` |
| 8706004 | `""))..4588>>CBII..JJGGCB>?::54//&&` |
| 257100 | `xyaaNOBB@ABCIIPQ..;;89;;<<9922-,''` |
| 1445728 | `33BCIHFFDEBB==45..NOHH=<555588BB\]` |
| 1956567 | `
z
z
n
o
k
j
l
m..h
i
Z
Z
J
K
4
4
` |
| 1410872 | `  %$'&(()(++,-....&''&''''&&''%$! ` |
| 196124 | `%$**003298@@@@@@..VVRSLLIHCC::00$$` |
| 1323312 | `{znoa`SRHH@@=<;;..DDEEFGKJPQ[Zjj}|` |
| 2093028 | `~~wvmmbcVVLMHINN..QPOOHHAA8845..""` |
| 2106292 | `uubbTTMMLLJKFF>>..DDHIIHBC>>88,,  ` |
| 2098044 | `  11@@MLWVccnnxy..UU__hhooqqsruuyy` |
| 2058472 | `  89KKWWa`kjtuxx..NNIIBB<=66./&& !` |
| 247744 | `rsa`QQED@ACCIHTU..``UTMMKJQQ]]kk||` |
| 9399475 | `/L/M/8080n0n0.0.0P2P2` |
| 2107700 | `~~xxpqcbSSHI@A<=..EDJJPPYYbckkrs}}` |
| 2091412 | `||qpii__PPFFFGGG..))01::@AHHRS^^on` |
| 2093600 | `||zzzzxxll``ZZZZ..jkffedaa^_^^ders` |
| 1311564 | `&&66CCKKOOQQOOMM..vv~~~~yymmZZ@@ !` |
| 985586 | `~qqbcTTHI@@==55...HHSS\\fglmqqttz{` |
| 2088824 | `));;EDNN__kjrspp..CCFGCC::23..)(!!` |
| 877372 | `,,@@RRcbmmqqnndd..**1198BBLLYXggvv` |
| 879984 | `nn^^VVRRRSRRQPONMMHHFGGFKKTTbbvv` |
| 9325780 | `@2JJPP^NjJrNzZz`..RfcrlydrXfXdjn~x` |
| 8290448 | `"",,==LMZZffppxx..rrpplmhh]\ML<=,,` |
| 2099560 | `xyhiVVLLKKDD89,,..6789AALLVW_^hh{z` |
| 1756708 | `mmZ[JJ66*+&'((....::::::88::<<::00` |
| 626724 | `vvlliihhiikkooss..zz{{yyvwwvwvyx|}` |
| 9399667 | `/e/e/` |
| 8545763 | `/F/F/` |
| 2114692 | `rrff^^\\\\XXTTRS..#"""#"$$'&*+**""` |
| 977340 | `$%/.99>?BBHHMLSS..SROOII@@::01))##` |
| 8496207 | `/K/K/` |
| 8496199 | `/s/s/` |
| 8322039 | `/r/r/` |
| 7843272 | `""((./2298==>>@@..EEBB>>8922,-'& !` |
| 8901608 | `(#<6G?A65(4 ="F)..TLneuk]RLD\Vrlzt` |
| 90252 | `wwdd\\UUMMBB;;4466@@NNOO<<` |
| 9326846 | `:m>rZ|nwlnchd^fR..`vbrhrblNXBHVPxj` |
| 2110400 | `yxnocb[ZXXXXSRII..CKJTU`affiijkut~` |
| 9399675 | `/V0V0j/j/` |
| 9321540 | `*<FZT`XZPXBb4p.j..^<fHjZpfz^vPhRrV` |
| 1758396 | `,,66>>@@>>9822/...//..44A@PQ^_nn||` |
| 1455556 | `xxff^^aafggf^^PQFFOOmm` |
| 9072880 | ` z&p>tJnJZJJN@N6..tBuDp@vF~NzLvF~N` |
| 2065228 | `{{ttoohhddcbbbbc`acc``\]PPBB32` |
| 1650544 | `::XXkjqqmmbbTTHI??==A@JKXYjjyy` |
| 8706272 | `  $$((-,01547798..88664432//+*()$$` |
| 8700239 | `/6/7/V.V.I-I-` |
| 1883876 | `$$/.;;CCHHJJHICC:;321022::MMjk` |
| 605744 | `xxffXXONIHIIIHKJJJHI@@01` |
| 278012 | `{zturrpppprrrrnn..kkdd]\SSJKBB67++` |
| 1410360 | `{zuuppoollffcc__..JKBB::542201()!!` |
| 2039476 | `utXXDE=<::@AKJVW..ppxxzztthhXXDD&&` |
| 140844 | `89NN[[_^^_`aa`bba`UU<<` |
| 2096976 | `vvjj^^UUJKDDAA=<==<<?>9900&&` |
| 8548644 | `$$,-5589>>CCEDFGFFDECC>>::54..&&` |
| 1482848 | `rr[[GG55----99QQyy` |
| 2114452 | `xymlcc[[TTLLHHHH..SRWVYY\\ccjkrs|}` |
| 8555188 | `((22113399AA=<9988<=>>;:22**` |
| 1120420 | `..>>MM]]hionpponjkdd[[FF//` |
| 628724 | `pp__PQGFBCCBGFML..rrwwvvyxyy{z|}~~` |
| 1040552 | `54RRbcllqpssqqnnhh`aOO;;-,22HIgg` |
| 630736 | `uuii__VVTTVV\]bchiqqyy` |
| 2091616 | `utff]\WWUUTTNNDD992310..""

` |
| 898172 | `&&44A@MLWV\]\\[Z..TURRTUWW^^fgqq{z` |
| 1069872 | `iiMM==<<DDNOWWXXKK00` |
| 2076236 | `[[@@::55;:VV^^;:` |
| 220939 | `
7
7
V
V
`
`
e
d..O
N
C
B
<
<
0
1
` |
| 1397556 | `44LMZ[aaZZRSLLNN[Zjj` |
| 9011061 | `/i/Q/5/4/` |
| 2098196 | `++110110235411++..//76BBNOXXeeuu~~` |


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
| domain | - | $domain_regex@0 len=4 |
| IP | - | $ipv6@880 len=4 |
| contains_base64 | - | $a@3750495 len=12 |
| maldoc_indirect_function_call_3 | - | $a@1743485 len=9 |

## Generated YARA Meta
```json
{
  "rule_count": 4,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 0,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 880,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav",
      "strings": [
        {
          "id": "$a",
          "offset": 3750495,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_indirect_function_call_3",
      "path": "/opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav",
      "strings": [
        {
          "id": "$a",
          "offset": 1743485,
          "length": 9,
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
┌ 38: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           0x00000000      52             push rdx                    ; arg3
│           0x00000001      494646209f..   and byte [rdi + 0x415700e7], r11b ; [0x415700e7:1]=255 ; arg1
│           0x0000000a      56             push rsi                    ; arg2
│           0x0000000b      45666d         insw word [rdi], dx
│       ┌─< 0x0000000e      7420           je 0x30
│       │   0x00000010      1000           adc byte [rax], al
│       │   0x00000012      0000           add byte [rax], al
│       │   0x00000014      0100           add dword [rax], eax
│       │   0x00000016      0200           add al, byte [rax]
│       │   0x00000018      44ac           lodsb al, byte [rsi]
│       │   0x0000001a      0000           add byte [rax], al
│       │   0x0000001c      10b102000400   adc byte [rcx + 0x40002], dh ; arg4
│       │   0x00000022      1000           adc byte [rax], al
│       │   0x00000024      64             invalid
..
└      │└─> 0x00000030      06             invalid
```

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/710/0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a/film.wav",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
