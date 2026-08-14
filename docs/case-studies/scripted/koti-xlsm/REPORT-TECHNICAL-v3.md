> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:21:55 UTC

## 1. Executive Summary

This sample is an Excel macro-enabled workbook (XLSM) in OOXML format, identified as malicious with a score of 85 and associated with the XAgent malware family. The analysis relies on external threat intelligence, YARA matches, and MalCat structural analysis due to failures in Ghidra and IDA sessions. Key evidence includes high entropy (7.56) indicating possible encryption or compression, the presence of macro sheets (xl/macrosheets/sheet1.xml), and base64-encoded content detected by YARA. VirusTotal reports 34 malicious detections with tags like 'calls-wmi' and threat label 'trojan.msexcel/x97m', strongly suggesting malicious intent as a trojan downloader. While static tools confirm macro presence and obfuscation, direct behavioral evidence from dynamic analysis is not observed.

- **Verdict**: malicious (source: llm_judge, query_or_table: key_evidence, row_or_rule: verdict: malicious)
- **Family Guess**: XAgent (source: llm_judge, query_or_table: key_evidence, row_or_rule: family_guess: XAgent)
- **Key Evidence**: YARA base64 match (source: yara, query_or_table: matches, row_or_rule: contains_base64), VirusTotal 34 detections (source: virustotal, query_or_table: hash_lookup, row_or_rule: detections: 34 malicious), MalCat high entropy (source: malcat, query_or_table: file_summary, row_or_rule: entropy: 7.56).

## 2. Sample Metadata

The sample metadata is derived from MalCat file summary and structured evidence. It is a ZIP-based OOXML file with high entropy, indicating potential obfuscation.

| Attribute | Value | Source |
|---|---|---|
| SHA256 | 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e | (source: malcat, query_or_table: file_summary, row_or_rule: sha256) |
| Sample Path | /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm | (source: structured evidence) |
| Project Name | malware | (source: structured evidence) |
| File Type | ZIP (OOXML) | (source: malcat, query_or_table: file_summary, row_or_rule: type: ZIP) |
| Size | 26363 bytes | (source: malcat, query_or_table: file_summary, row_or_rule: size: 26363) |
| Entropy | 7.56 | (source: malcat, query_or_table: file_summary, row_or_rule: entropy: 7.56) |
| File Name | koti.xlsm | (source: malcat, query_or_table: file_summary, row_or_rule: file_name: koti.xlsm) |
| Architecture | NONE | (source: malcat, query_or_table: file_summary, row_or_rule: architecture: NONE) |

The high entropy of 7.56 likely indicates compressed or encrypted content within the ZIP structure, which is common in malware to evade detection. The OOXML format allows for embedded macros, as evidenced by the presence of xl/macrosheets/sheet1.xml.

## 3. File Layout & Structural Analysis

The file layout is extracted from MalCat's section/region analysis. The sample is structured as a ZIP archive containing OOXML components, with multiple XML files, images, and printer settings. We assess that the layout supports macro execution and payload delivery.

**File Layout Table (from MalCat):**
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

**(source: malcat, query_or_table: file_layout, row_or_rule: multiple rows)**

The presence of `xl/macrosheets/sheet1.xml` (EA 4688) confirms macro content, which is a common vector for malware execution. The high entropy values across sections suggest possible obfuscation, but we note that OOXML files often have inherent entropy due to compression. The structure includes images and printer settings, which might be used for steganography or payload hiding, though this is not confirmed.

**Virtual Files (from MalCat):**
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

**(source: malcat, query_or_table: virtual_files, row_or_rule: multiple rows)**

The virtual files show the unpacked OOXML contents, with the macrosheet being significant for potential malicious activity.

## 4. Static Code Analysis

Static analysis is limited due to OOXML format, but YARA matches and string extraction provide indicators of obfuscation and potential payloads. We assess that base64-encoded content and domain patterns suggest malicious intent, though direct code decompilation is not possible.

**Radare2 Disassembly:**
The radare2 disassembly at address 0x00000000 shows a small code block with instructions like `push rax` and `add` operations. This appears to be a snippet from a binary extract, but for an OOXML file, it may not be executable code. The instructions are:
```
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
**(source: radare2, query_or_table: disassembly, row_or_rule: 0x00000000)**
This disassembly is likely from a misinterpreted binary section and does not represent the macro code. The invalid instruction at the end suggests incomplete analysis, but for OOXML, the primary code is in VBA macros, which are not disassembled here.

**YARA Matches:**
Two YARA rules matched the sample:
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| contains_base64 | - | $a@1859 len=12 |

**(source: yara, query_or_table: matches, row_or_rule: multiple rows)**

The 'domain' rule match at offset 0 with length 2 is minimal and may indicate a domain pattern, but we assess it is likely a false positive or trivial match due to the short length. The 'contains_base64' match at offset 1859 with length 12 suggests base64-encoded data, which is often used for obfuscation in malware payloads. This aligns with the high entropy observed.

**High-Signal Strings (from MalCat):**
The top strings include OOXML paths and obfuscated content. Key strings from the MalCat string table:
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
| 6611 | `xl/macrosheets/_../sheet1.xml.rels` |
| 8296 | `23VBJe3w` |
| 16454 | `=1Hi`eeI` |

**(source: malcat, query_or_table: strings, row_or_rule: multiple rows)**

The string `xl/macrosheets/sheet1.xml` at EA 4718 confirms macro presence. Strings like `23VBJe3w` and `=1Hi`eeI` appear obfuscated and may be part of encoded payloads, possibly related to the YARA base64 match. These indicators suggest the macros may contain obfuscated code for downloading or executing payloads.

**capa Capability Rules:**
No capability rules matched (source: capa, query_or_table: capability_rules, row_or_rule: none). This is expected for OOXML files as capa primarily analyzes PE executables.

## 5. Behavioral & Dynamic Analysis

No dynamic behavioral evidence from Speakeasy or Frida is observed for this sample. The tool gate indicates that dynamic analysis tools are not applicable for OOXML format (source: deep_dive_agentic, query_or_table: tool_gate, row_or_rule: not_applicable: speakeasy, frida_probe). Therefore, we cannot confirm runtime behaviors such as network calls, process injection, or persistence mechanisms based on dynamic analysis alone.

## 6. Network Indicators & C2

Direct network indicators or command-and-control (C2) infrastructure are not identified in the provided evidence. However, VirusTotal tags include 'calls-wmi' (source: virustotal, query_or_table: hash_lookup, row_or_rule: tags: calls-wmi), which may imply the use of Windows Management Instrumentation for network activity, possibly for lateral movement or data collection. The YARA 'domain' rule match at offset 0 (source: yara, query_or_table: matches, row_or_rule: domain) is minimal and does not provide clear domain patterns. We assess that the macros likely contain download or C2 functionality, but specific indicators are not present in the static evidence.

## 7. Capabilities Assessment

Based on the evidence, the sample likely possesses the following capabilities:
- **Macro Execution**: The XLSM file contains macro sheets (source: malcat, query_or_table: file_summary, row_or_rule: virtual_files includes xl/macrosheets/sheet1.xml), enabling code execution upon user interaction.
- **Obfuscation**: High entropy (7.56) and base64-encoded content (source: yara, query_or_table: matches, row_or_rule: contains_base64) suggest payload obfuscation to evade detection.
- **Possible Download/Delivery**: VirusTotal categorizes it as a trojan downloader (source: virustotal, query_or_table: hash_lookup, row_or_rule: popular_threat_category: downloader) with threat label 'trojan.msexcel/x97m', indicating potential for downloading additional payloads.
- **WMI Usage**: Tags 'calls-wmi' (source: virustotal, query_or_table: hash_lookup, row_or_rule: tags: calls-wmi) suggest possible use of WMI for execution or reconnaissance.

No direct capabilities are confirmed from capa (source: capa, query_or_table: capability_rules, row_or_rule: none) or dynamic analysis.

## 8. Indicators of Compromise

IOCs are derived from multiple sources:

- **Hashes**: SHA256: 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e (source: malcat, query_or_table: file_summary, row_or_rule: sha256).
- **File Names**: koti.xlsm (source: malcat, query_or_table: file_summary, row_or_rule: file_name: koti.xlsm), and VirusTotal names include 'virussign.com_2781acaf22358b2027980adb1d74ac20.vir' and 'payload_1.bin' (source: virustotal, query_or_table: hash_lookup, row_or_rule: names).
- **YARA Rules**: 'domain' and 'contains_base64' (source: yara, query_or_table: matches, row_or_rule: multiple rows).
- **Suspicious Strings**: Base64-encoded content at offset 1859 (source: yara, query_or_table: matches, row_or_rule: contains_base64), and obfuscated strings like '23VBJe3w' (source: malcat, query_or_table: strings, row_or_rule: EA 8296).
- **Threat Intelligence**: VirusTotal detections (34 malicious), tags 'calls-wmi', 'xlsx', 'malware', and threat category 'trojan' and 'downloader' (source: virustotal, query_or_table: hash_lookup, row_or_rule: multiple rows).

## 9. Detection Engineering

To detect similar threats, we recommend the following detection rules and signatures:

- **YARA Rules**: Use rules that match base64-encoded content and domain patterns in OOXML files. For example, the 'contains_base64' rule can be adapted to detect base64 strings in macro sheets.
- **Behavioral Detection**: Monitor for Excel processes spawning WMI commands (associated with 'calls-wmi' tag) or making network connections.
- **File Indicators**: Flag XLSM files with entropy above 7.0 and containing macrosheets, as this combination may indicate obfuscated malware.
- **Static Strings**: Include strings like 'xl/macrosheets/sheet1.xml' and high-entropy strings in detection heuristics.

**(Evidence basis: yara matches, virustotal tags, malcat entropy)**

## 10. MITRE ATT&CK Mapping

Based on the evidence, the following MITRE ATT&CK techniques are likely involved:

- **T1204.002: User Execution: Malicious File**: The XLSM file requires user interaction to enable macros (source: malcat, query_or_table: file_summary, row_or_rule: type: ZIP with macrosheets).
- **T1027: Obfuscated Files or Information**: High entropy (7.56) and base64-encoded content (source: yara, query_or_table: matches, row_or_rule: contains_base64) indicate obfuscation.
- **T1047: Windows Management Instrumentation**: VirusTotal tag 'calls-wmi' (source: virustotal, query_or_table: hash_lookup, row_or_rule: tags: calls-wmi) suggests possible WMI usage for execution or discovery.
- **T1105: Ingress Tool Transfer**: The sample is categorized as a downloader (source: virustotal, query_or_table: hash_lookup, row_or_rule: popular_threat_category: downloader), implying potential payload delivery.

No direct evidence for other techniques such as persistence or lateral movement is observed.

## 11. What We Don't Know

Several gaps exist in this analysis:

- **Failed Tool Analysis**: Ghidra and IDA sessions failed due to errors (source: llm_judge, query_or_table: cross_engine_notes, row_or_rule: Ghidra and IDA analysis failed), so deep code analysis of macros is unavailable.
- **Macro Code Content**: The actual VBA macro code is not extracted or analyzed, so specific malicious functions are unknown.
- **Dynamic Behaviors**: No runtime behaviors are observed from dynamic analysis tools (Speakeasy/Frida not observed), so we cannot confirm network calls, process injection, or persistence mechanisms.
- **Network Infrastructure**: No specific C2 domains or IPs are identified in the evidence.
- **Payload Details**: The content of base64-encoded data and potential download payloads are not decoded or analyzed.
- **XOR Search Results**: XOR search returned no candidates (source: xorsearch, query_or_table: xorsearch, row_or_rule: xorsearch_ok: false), but this may not rule out other obfuscation methods.

We assess that the sample is likely malicious based on external TI, but full capabilities and behaviors remain unconfirmed.

## 12. Appendix A: Tool Evidence Trail

This appendix details the tools used and their outcomes from the structured evidence.

- **MalCat**: Successfully analyzed file structure, entropy, and strings (source: malcat, query_or_table: file_summary).
- **YARA**: Two rules matched: 'domain' and 'contains_base64' (source: yara, query_or_table: matches).
- **VirusTotal**: Provided external TI with 34 malicious detections and tags (source: virustotal, query_or_table: hash_lookup).
- **radare2**: Disassembled a small code snippet at 0x00000000, but it may not be relevant for OOXML (source: radare2, query_or_table: disassembly).
- **XOR Search**: No candidates found (source: xorsearch, query_or_table: xorsearch).
- **Ghidra/IDA**: Analysis failed due to session errors (source: llm_judge, query_or_table: cross_engine_notes).
- **capa**: No capability rules matched, as tool is not applicable for OOXML (source: capa, query_or_table: capability_rules).
- **Speakeasy/Frida**: Not observed due to format inapplicability (source: deep_dive_agentic, query_or_table: tool_gate).

## 13. Appendix B: Analysis Environment

The analysis environment is based on the tools referenced in the evidence, which include static analysis tools like MalCat, YARA, radare2, and external threat intelligence via VirusTotal. Dynamic analysis tools were not applicable for this OOXML sample. The environment is likely a controlled setting with access to these tools, but specific details such as OS version or network configuration are not provided in the evidence. We assume a standard malware analysis lab setup for reverse engineering and triage.
## Appendix: Full Structured Evidence Pack

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
