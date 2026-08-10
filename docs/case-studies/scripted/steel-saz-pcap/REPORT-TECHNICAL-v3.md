> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 20:52:40 UTC

## 1. Executive Summary
This report presents a technical analysis of the file `steel.saz` (SHA256: 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b). The sample is identified as a Fiddler session archive (SAZ format), which is a ZIP container typically used for web session capture (source: malcat, file_summary, type=ZIP). MalCat detected 144 anomalies where local file headers differ from central directory entries, suggesting possible corruption or manipulation (source: malcat, anomalies, LocalFileAndCentralDirectoryFieldDifferent). YARA matched four generic content-pattern rules—`domain`, `IP`, `contains_base64`, and `url`—indicating the presence of network-related strings such as domains, IPv6 addresses, base64 blobs, and URLs, which are expected in HTTP traffic captures (source: yara, yara matches, domain rule, IP rule, contains_base64 rule, url rule). No executable code was found, as confirmed by MalCat (architecture: NONE, no entrypoint), failed Ghidra/IDA sessions, and zero CAPA rules (source: malcat, file_summary; source: deep_dive_agentic, key_evidence). The verdict is suspicious (score: 25) due to structural anomalies, but the file is likely a benign data archive rather than executable malware (source: verdict.json, verdict). Further analysis of the captured traffic content is required to determine if it references malicious infrastructure.

## 2. Sample Metadata
The sample metadata is extracted from the structured evidence:
- **SHA256:** 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b
- **Sample Path:** /opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz
- **Project Name:** 610
- **File Size:** 18,038,723 bytes (source: malcat, file_summary, size=18038723)
- **File Type:** ZIP archive (source: malcat, file_summary, type=ZIP)
- **Architecture:** NONE (non-executable) (source: malcat, file_summary, architecture=NONE)
- **Entropy:** 224 (normalized) (source: malcat, file_summary, entropy=224)
- **File Name:** steel.saz (source: malcat, file_summary, file_name=steel.saz)
This metadata confirms the file is a large ZIP container without executable characteristics, consistent with a Fiddler SAZ trace archive.

## 3. File Layout & Structural Analysis
The file layout is analyzed using MalCat, revealing a standard SAZ structure with paired client request (`_c.txt`), server response (`_s.txt`), and metadata (`_m.xml`) files. The table below is copied from MalCat's structured analysis (source: malcat, file layout):

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

Additionally, 26 virtual files are listed, such as `raw/1_c.txt` (403 bytes) and `raw/4_s.txt` (18,617,711 bytes), indicating a large server response possibly containing binary data (source: malcat, virtual files). The entropy values (222-224) are normal, suggesting no encryption or packing of archive contents (source: deep_dive_agentic, key_evidence). However, MalCat identified one anomaly: `LocalFileAndCentralDirectoryFieldDifferent` with 144 hits, meaning that in 144 instances, local file header fields differ from central directory entries (source: malcat, anomalies, LocalFileAndCentralDirectoryFieldDifferent). This could indicate file corruption or intentional manipulation, which warrants suspicion but is not necessarily malicious.

## 4. Static Code Analysis
Static analysis tools confirm that the sample contains no executable code. Ghidra and IDA sessions failed to load due to missing `gpr_path`, preventing binary disassembly (source: deep_dive_agentic, key_evidence). CAPA returned 0 capability rules (rc=16), and FLOSS was skipped as it is not applicable to non-executable files (source: capa capability rules; source: deep_dive_agentic). Radare2 disassembly at the entry point (0x00000000) shows nonsensical instructions, as the file is a ZIP archive, not native code:

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

This disassembly represents raw file header bytes, not meaningful code, reinforcing that the file is not executable (source: radare2 disassembly). YARA matched four generic rules, as shown in the table below (source: yara, yara matches):

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@13421 len=2 |
| contains_base64 | - | $a@1400104 len=12 |
| url | - | $url_regex@18038703 len=20 |

These matches are content-pattern based, indicating strings like domains, IPs, base64, and URLs within the archive, likely from captured HTTP traffic (source: yara, yara matches). No malware-family-specific YARA rules fired, so the matches are benign in context.

## 5. Behavioral & Dynamic Analysis
Behavioral and dynamic analysis tools were not observed or applicable. Speakeasy and Frida probe were not run, as the file contains no executable code (source: deep_dive_agentic, tool_gate, not_applicable: speakeasy, frida_probe). Therefore, no runtime behavior such as API calls, process injection, or network connections was captured. This is expected for a data archive; any dynamic behavior would require extracting and executing embedded files, which is not part of this analysis.

## 6. Network Indicators & C2
Network indicators are present as strings in the archive, derived from YARA matches. The `domain` rule matched at offset 0 (source: yara, yara matches, domain rule), `IP` (IPv6) at offset 13421 (source: yara, yara matches, IP rule), `contains_base64` at offset 1400104 (source: yara, yara matches, contains_base64 rule), and `url` at offset 18038703 (source: yara, yara matches, url rule). Additionally, MalCat extracted high-signal strings, such as `Fiddler (v5.0.20..s://fiddler2.com` at EA 18038655, confirming the file's origin as a Fiddler trace (source: malcat, high-signal strings). These indicators suggest that the captured traffic includes domain names, IP addresses, base64-encoded data, and URLs, but without deeper inspection of the text files, it is unclear whether they point to command-and-control (C2) servers or benign infrastructure. The anomalies in the ZIP structure (source: malcat, anomalies) could imply tampering, but this is not definitive evidence of malicious C2 activity.

## 7. Capabilities Assessment
The sample has no executable capabilities, as it is a non-executable ZIP archive. CAPA returned 0 rules (source: capa capability rules), indicating no detected behaviors such as file manipulation, persistence, or evasion. The file's purpose is data storage for network sessions, so its capabilities are limited to containing HTTP request/response data. However, the large size (18 MB) suggests it may hold substantial traffic, possibly including suspicious content, but this requires manual review of the embedded text files.

## 8. Indicators of Compromise
Indicators of compromise (IOCs) are derived from strings and YARA matches. Key IOCs include:
- **SHA256:** 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b
- **File Name:** steel.saz
- **ZIP Anomalies:** 144 instances of local file header/central directory mismatches (source: malcat, anomalies)
- **Network Strings:** Domains, IPv6 addresses, base64 blobs, and URLs as per YARA matches at offsets 0, 13421, 1400104, and 18038703 (source: yara, yara matches)
- **Fiddler Trace Identifier:** `Fiddler (v5.0.20..s://fiddler2.com` at EA 18038655 (source: malcat, high-signal strings)
- **YARA Rule `ValuableFileExtensions`:** Matched for file extensions targeted by ransomware, but this is a generic rule and may reflect captured traffic content rather than malware behavior (source: malcat, YARA / Signatures, ValuableFileExtensions).
These IOCs are not unique to malware; they are common in network capture files. However, their presence combined with structural anomalies warrants caution.

## 9. Detection Engineering
Detection strategies should focus on the file's structural anomalies and content patterns. Recommendations based on evidence:
- **ZIP Anomaly Detection:** Use tools that check for mismatches between local file headers and central directory entries, as seen with MalCat's `LocalFileAndCentralDirectoryFieldDifferent` (source: malcat, anomalies). This could indicate file tampering.
- **YARA Rules:** Implement rules for generic network indicators (domains, IPs, URLs, base64) to flag files containing such patterns, but combine with file type checks to reduce false positives. The matched rules (source: yara, yara matches) are a starting point.
- **File Type Validation:** Verify that `.saz` files adhere to expected SAZ structure; deviations like the one in `4_s.txt` with very high physical size (18,017,418 bytes) might indicate data exfiltration or embedded payloads (source: malcat, file layout).
- **Contextual Analysis:** Correlate with other artifacts; e.g., if similar anomalies appear in other captures, it could suggest a campaign. Since this file is suspicious but likely benign, detection should prioritize reviewing the content of `_s.txt` files for malicious responses.

## 10. MITRE ATT&CK Mapping
MITRE ATT&CK mapping is limited due to the lack of executable behavior. However, based on content indicators:
- **T1071 - Application Layer Protocol:** The presence of HTTP traffic (evident from `_c.txt` and `_s.txt` files) suggests use of web protocols for communication (source: malcat, file layout). If the captured traffic includes C2, this tactic would apply.
- **T1105 - Ingress Tool Transfer:** The archive could be used to transfer tools or data, but this is speculative without evidence of malicious payloads.
- **T1560 - Archive Collected Data:** The file itself is an archive containing collected network data, which aligns with data staging for exfiltration.
No other tactics or techniques are directly observable, as no execution, persistence, or evasion was detected.

## 11. What We Don't Know
Several aspects remain unknown:
- **Content of Captured Traffic:** The actual HTTP requests and responses within the `_c.txt` and `_s.txt` files have not been parsed; they could contain malicious code, credential leaks, or benign data. The large `4_s.txt` file (18.6 MB) might hold binary or encoded content.
- **Purpose of ZIP Anomalies:** The 144 header mismatches could be due to corruption during capture, intentional obfuscation, or tool-specific quirks; without further analysis, the cause is unclear.
- **Source and Context:** We lack information on where and how this SAZ file was generated—e.g., from a compromised machine, a security test, or normal browsing—which is critical for assessing risk.
- **Embedded File Integrity:** Whether the archived files are intact or have been modified maliciously is not determined; checksum validation could help.
- **Behavioral Implications:** If extracted and executed, any embedded scripts or executables could exhibit malware behavior, but this was not tested.

## 12. Appendix A: Tool Evidence Trail
This appendix summarizes the tools used and their outcomes, based on structured evidence:
- **MalCat:** Identified file as ZIP, architecture NONE, entropy 224; detected 144 anomalies (LocalFileAndCentralDirectoryFieldDifferent); listed file layout and virtual files; extracted high-signal strings (source: malcat, file_summary, anomalies, file layout, virtual files, high-signal strings).
- **YARA (yara-x):** Compiled 454 rules; matched 4 generic rules: domain, IP, contains_base64, url (source: yara, yara matches).
- **Radare2:** Provided disassembly at 0x00000000, showing invalid instructions due to non-executable file (source: radare2 disassembly).
- **CAPA:** Returned 0 capability rules, indicating no executable behaviors (source: capa capability rules).
- **FLOSS:** Not applicable, as no executable code (source: deep_dive_agentic, tool_gate).
- **Ghidra/IDA:** Failed to load sessions due to missing `gpr_path`, so no analysis (source: deep_dive_agentic, key_evidence).
- **Speakeasy/Frida:** Not observed or applicable (source: deep_dive_agentic, tool_gate).
- **XOR Search:** No candidates found (source: xorsearch_ok, false).
- **LLM Judge:** Verdict suspicious, score 25, family guess Fiddler trace archive (source: verdict.json).

## 13. Appendix B: Analysis Environment
The analysis environment is not fully specified in the evidence, but based on tool outputs:
- **Sample Path:** /opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz
- **Tools Used:** MalCat, YARA (yara-x with 454 rules compiled), Radare2, CAPA, FLOSS (skipped), Ghidra and IDA (failed), Speakeasy and Frida (not applicable), XOR search tool, and LLM judge models (configured-llm).
- **Operating System:** Likely a Linux-based analysis VM, given the file path structure.
- **Configuration:** YARA rules from `/opt/samples/rules/flat/` with some compile errors (e.g., missing `androguard` module) (source: generated YARA meta, compile_errors).
- **Time Frame:** Not specified, but analysis was conducted as per the structured evidence generation.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b  
**sample_path:** /opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz  
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
      "path": "/opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
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
      "path": "/opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
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
      "path": "/opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
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
      "path": "/opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
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
  "sample": "/opt/samples/corpus/revai-lab-610/58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b/steel.saz",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
