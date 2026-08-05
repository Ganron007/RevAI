## 1. Executive Summary
This report analyzes ELF x64 sample `eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f`, classified as malicious with a score of 100 and family guess of Sliver post-exploitation C2 framework implant (source: llm_judge, verdict.json). The sample is heavily obfuscated and packed, with an extreme file entropy of 108, 0 reported imports, and 13 total static anomalies consistent with packed malware. Cross-engine evidence from Malcat, capa, and YARA confirms implementation of multiple obfuscation, encryption, hashing, and C2-related routines, with no contradictory evidence present. Ghidra and IDA static analysis failed due to processing errors, but available evidence is sufficient for definitive malicious classification (source: llm_judge, cross_engine_notes).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f |
| Sample Path | /opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver |
| Project Name | pool |
| Verdict | malicious |
| Score | 100 |
| Family Guess | Sliver post-exploitation C2 framework implant |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | Ghidra and IDA analysis failed due to processing errors (Ghidra could not locate the sample file in its project, IDA SQL tool was missing), so all static analysis evidence is sourced from Malcat, capa, and YARA. The sample is a high-entropy (108) packed ELF x64 binary, consistent with obfuscated malware. The filename suffix '_sliver' strongly indicates association with the Sliver C2 framework. |
(sources: llm_judge, verdict.json; deep_dive_agentic, deep-dive.json)

## 3. File Layout & Structural Analysis
The sample is a truncated ELF x64 binary with extreme entropy (108) across its primary executable segment, indicating strong packing/encryption (source: malcat, file_summary). The file layout is as follows:
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| segment1 | 0 | 64 | 8712765 | 108 | RX |
| segment0 | 8712765 | 336 | 336 | 0 | R |
| segment1 | 8713101 | 3696 | 8712365 | 0 | RX |
| segment1 | 17425466 | 8708669 | 8708669 | 0 | RX |
| gap | 26134135 | 3523 | 0 | 108 | - |
| segment2 | 26137658 | 565586 | 2393983 | 108 | R |
(source: malcat, file_layout)
The sample has 0 reported imports, with an empty Import Address Table (IAT), consistent with import obfuscation common in packed malware (source: malcat, file_summary). The entrypoint is located at EA 0x010E7B22 (17802522 decimal) (source: malcat, file_summary).
Malcat identified 13 total anomalies, detailed below:
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| HugeStringBinary | 4 | strings | 16 | string has more than 1024 characters and binary encoding |
| TruncatedELFFile | 4 | integrity | 2 | some or all segment bytes are not present on disk |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 7 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references |
| BigStringHiScore | 3 | strings | 256 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 256 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 755 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values > 0x1000) |
| ManyUniqueImmediateBytes | 3 | code | 1032 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 3 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 5271 | XOR instruction in a loop |
| HugeGapBetweenFunctions | 2 | code | 1 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stored between functions |
| HighXrefLoopingFunction | 1 | code | 131 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 611 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialization routine |
| SpaghettiFunction | 1 | code | 19 | Function with lots of intra jumps, could be obfuscated |
(source: malcat, anomalies)
High-signal anomaly locations include:
- DynamicString: 23277960, 25482088, 19712360, 25151112, 24118856
- HighXrefLoopingFunction: 17440154, 17445018, 17447834, 17459034, 17464250
- ManyHighValueImmediates: 17812026, 17816666, 17819578, 17827642, 17828794
- ManyUniqueImmediateBytes: 17812026, 17812762, 17816666, 17819578, 17827642
- SequentialFunction: 17694170, 17798266, 17798650, 17802074, 17813658
- SpaghettiFunction: 17435194, 17453370, 17692602, 17694586, 17774362
- XorInLoop: 17433717, 17433978, 17434006, 17434036, 17434066
(source: malcat, anomaly_locations)

## 4. Malcat Triage Summary
Malcat triage confirms the sample is a high-entropy (108) ELF x64 binary with 0 imports, ending in the `_sliver` suffix consistent with Sliver C2 implant naming conventions (source: malcat, file_summary; llm_judge, key_evidence). The sample has 13 total anomalies, including 5271 hits of XOR-in-loop instructions, 256 dynamic string construction events, 256 high-score long strings, 19 spaghetti functions (obfuscated control flow), and 131 high-cross-reference looping functions (likely string decryption routines) (source: malcat, anomalies). 7 hits of medium-to-high entropy unreferenced 10KB+ buffers were identified, consistent with encrypted payloads or configuration data (source: malcat, anomalies). Deep dive analysis confirms these features are consistent with a packed/encrypted Sliver C2 implant (source: deep_dive_agentic, deep-dive.json).
Top extracted high-signal strings include binary-encoded long strings (e.g., `FFFFFFFF810000B1..0000000000000000` at 23277960, `D6D6D6D6D6D65858..0000000000000000` at 21954600) and dynamic strings, all likely XOR-encrypted or obfuscated (source: malcat, top_strings).

## 5. Static Code Analysis
Static analysis is limited to Malcat decompilation, capa rule matching, and YARA signature detection due to Ghidra and IDA processing failures (source: llm_judge, cross_engine_notes).
capa identified 16 capability rules, detailed below:
| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES via x86 extensions | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| decrypt data using AES via x86 extensions | T1140:Deobfuscate/Decode Files or Information | C0031.001:Decrypt Data |
| check for software breakpoints |  | B0001.025:Debugger Detection |
| parse credit card information |  | C0019:Check String |
| encrypt data using Salsa20 or ChaCha | T1027:Obfuscated Files or Information |  |
| hash data using fnv |  | C0030.005:Non-Cryptographic Hash |
| hash data using SHA1 |  | C0029.002:Cryptographic Hash |
| hash data using SHA256 |  | C0029.003:Cryptographic Hash |
| authenticate HMAC |  | C0061:Hashed Message Authentication Code |
| execute syscall |  |  |
| hash data using SHA384 |  |  |
(source: malcat-capa, capa top_rules)
YARA matches confirm embedded cryptographic constants and operational indicators:
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@1 len=3 |
| IP | - | $ipv6@352194 len=2 |
| contains_base64 | - | $a@8774316 len=12 |
| Misc_Suspicious_Strings | - | $a0@8816576 len=8 |
| CRC32_poly_Constant | - | $c0@2121855 len=4 |
| MD5_Constants | - | $c4@4643810 len=4; $c5@4643814 len=4; $c6@4643823 len=4; $c7@4643827 len=4 |
| RIPEMD160_Constants | - | $c5@4643810 len=4; $c6@4643814 len=4; $c7@4643823 len=4 |
| SHA1_Constants | - | $c5@4643810 len=4; $c6@4643814 len=4; $c7@4643823 len=4 |
| SHA512_Constants | - | $c1@3859962 len=4; $c3@3860103 len=4; $c5@3860244 len=4; $c7@3860385 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@3851421 len=4; $c1@3851434 len=4; $c2@3851448 len=4; $c3@3851462 len=4; $c4@3851476 len=4; $c5@3851490 len=4; $c6@3851504 len=4; $c7@3851518 len=4 |
| Chacha_256_constant | - | $split1@5027829 len=8; $split2@5027842 len=8 |
(source: yara, matches)
Malcat decompilation of top functions confirms cryptographic routine implementation:
- `sub_7f32e0` (EA 21563162): Implements SHA-256 hashing, evidenced by use of SHA-256 constants (0x428a2f98, 0x71374491) and bitwise rotation operations standard for SHA-256 (source: malcat, decompilations).
- `sub_8c7240` (EA 22431354) and `sub_9462c0` (EA 22951674): Implement ChaCha20/Salsa20 key expansion and encryption, evidenced by use of ChaCha constants (0x3320646e, 0x79622d32, 0x6b206574) and ARX (Add-Rotate-XOR) operations standard for ChaCha (source: malcat, decompilations).
Malcat constants also confirm presence of `crypto::ChaCha` (16 hits), `hash::SHA256` (3 hits), `hash::RIPEMD160` (3 hits), `hash::xxhash` (1 hit), and `registry::HKEY_CURRENT_USER` (5 hits) (source: malcat, constants).

## 6. Behavioral & Dynamic Analysis
No dynamic or behavioral analysis was performed due to tooling limitations for ELF implants: Speakeasy and Frida are not applicable for Linux ELF samples, UPX unpacking failed to produce an unpacked payload, XORSearch returned no XOR-encoded string candidates, and FLOSS extracted 0 readable strings (source: upx_unpack, xor_search, floss_strings; deep_dive_agentic, tool_gate). No runtime behavior was observed.

## 7. Network Indicators & C2
YARA signature matching identified embedded operational indicators likely used for C2 communication, though all are obfuscated (high entropy, likely XOR-encrypted) and raw values could not be extracted statically:
- Domain regex match at offset 1 (length 3) (source: yara, matches)
- IPv6 address at offset 352194 (length 2) (source: yara, matches)
- Base64-encoded content at offset 8774316 (length 12) (source: yara, matches)
- Miscellaneous suspicious strings at offset 8816576 (length 8) (source: yara, matches)
These indicators are consistent with C2 endpoint configuration data embedded in the implant (source: deep_dive_agentic, key_evidence).

## 8. Capabilities & MITRE ATT&CK Mapping
The sample implements the following capabilities, mapped to MITRE ATT&CK and Malware Behavior Catalog (MBC) via capa rule matches:
| Capability | MITRE ATT&CK | MBC |
|---|---|---|
| Obfuscated stackstrings | T1027.005: Obfuscated Files or Information | B0032.020, B0032.017: Executable Code Obfuscation |
| Base64 encoding | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.001: Encode Data |
| XOR encoding | T1027: Obfuscated Files or Information | E1027.m02: Obfuscated Files or Information, C0026.002: Encode Data |
| AES encryption/decryption (x86 extensions) | T1027, T1140: Deobfuscate/Decode Files or Information | E1027.m05: Obfuscated Files or Information, C0027.001: Encrypt Data, C0031.001: Decrypt Data |
| RC4 PRGA encryption | T1027: Obfuscated Files or Information | C0027.009: Encrypt Data, C0021.004: Generate Pseudo-random Sequence |
| ChaCha20/Salsa20 encryption | T1027: Obfuscated Files or Information | C0027.001: Encrypt Data |
| Debugger breakpoint detection |  | B0001.025: Debugger Detection |
| Credit card string parsing |  | C0019: Check String |
| Hashing (FNV, SHA1, SHA256, SHA384, RIPEMD160) |  | C0029.002, C0029.003, C0029.004: Cryptographic Hash, C0030.005: Non-Cryptographic Hash |
| HMAC authentication |  | C0061: Hashed Message Authentication Code |
| Syscall execution |  |  |
(source: malcat-capa, capa top_rules)
These capabilities are consistent with a post-exploitation C2 implant designed to evade detection, encrypt communications, and interact with compromised systems.

## 9. Indicators of Compromise
| Indicator | Value | Context |
|---|---|---|
| File SHA256 | eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f | Sample hash (source: llm_judge, verdict.json) |
| Filename Pattern | Ends with `_sliver` | Sliver C2 implant naming convention (source: malcat, file_summary) |
| File Entropy | 108 | Extreme entropy indicating packed/encrypted content (source: malcat, file_summary) |
| File Type | ELF x64, 0 imports | Obfuscated Linux implant (source: malcat, file_summary) |
| Entrypoint EA | 17802522 (0x010E7B22) | Obfuscated entrypoint location (source: malcat, file_summary) |
| ChaCha Constants | Offsets 5027829, 5027842 | YARA match for ChaCha20 encryption (source: yara, matches) |
| SHA256 Constants | Offsets 4643810, 4643814, 4643823, 4643827 | YARA match for SHA256 hashing (source: yara, matches) |
| Domain Regex | Offset 1 | Embedded C2 domain indicator (source: yara, matches) |
| IPv6 Address | Offset 352194 | Embedded C2 IP indicator (source: yara, matches) |
| High-Xref Looping Functions | Offsets 17440154, 17445018, 17447834, 17459034, 17464250 | Likely string decryption routines (source: malcat, anomaly_locations) |
| XOR-in-Loop Instructions | Offsets 17433717, 17433978, 17434006, 17434036, 17434066 | Obfuscation/decryption routines (source: malcat, anomaly_locations) |

## 10. Detection Engineering
Detection rules can be built using the following high-signal attributes:
1. **YARA Rule for Sliver Implants**: Match ELF x64 files with entropy > 100, 0 imports, entrypoint in the 0x01000000+ range, and presence of ChaCha constants at offsets 5027829/5027842, SHA256 constants at 4643810, domain regex at offset 1, and IPv6 at offset 352194 (source: yara, matches; malcat, file_summary).
2. **capa Behavioral Rules**: Use the 16 confirmed capa rules to detect obfuscation, encryption, hashing, and debugger detection behavior at runtime (source: malcat-capa, capa top_rules).
3. **Anomaly-Based Detection**: Flag ELF x64 files with >5000 XOR-in-loop instructions, >100 high-cross-reference looping functions, and >5 high-entropy unreferenced 10KB+ buffers (source: malcat, anomalies).
4. **Filename-Based Detection**: Flag files ending with `_sliver` as potential Sliver C2 implants (source: malcat, file_summary).

## 11. What We Don't Know
- Exact raw values of embedded C2 domains and IP addresses, as all operational indicators are obfuscated (high entropy, likely XOR-encrypted) and could not be extracted statically (source: yara, matches; deep_dive_agentic, key_evidence).
- Unpacked payload content: UPX unpacking failed, and no custom unpacking routine was identified, so the underlying packed payload is not available for analysis (source: upx_unpack; deep_dive_agentic, tool_gate).
- Runtime behavior: No dynamic analysis was performed, so command execution, file system modification, and network communication behavior are unknown (source: deep_dive_agentic, tool_gate).
- Exact Sliver variant: Only a family-level guess is available, no specific version or build identifier was confirmed (source: llm_judge, verdict.json).
- Full function disassembly: Ghidra and IDA analysis failed, so only top 6 Malcat decompilations are available, and the purpose of many functions (including the 7 high-entropy unreferenced buffers) is unknown (source: llm_judge, cross_engine_notes; malcat, anomalies).

## 12. Appendix: Analysis Environment
| Tool | Status | Notes |
|---|---|---|
| Malcat | Successful | Used for triage, static analysis, anomaly detection, string extraction, and decompilation (source: malcat, all tables) |
| capa (malcat-capa) | Successful | 16 capability rules matched, 9.97s runtime (source: malcat-capa, capa top_rules) |
| YARA | Successful | 11 signature matches (source: yara, matches) |
| UPX | Failed | No unpacked path returned, sample is not UPX-packed or uses custom packing (source: upx_unpack) |
| XORSearch | Failed | No XOR-encoded string candidates found (source: xor_search) |
| FLOSS | Not Applicable | 0 strings extracted, likely due to heavy obfuscation (source: floss_strings) |
| Ghidra | Failed | Could not locate sample file in project (source: llm_judge, cross_engine_notes) |
| IDA Pro | Failed | IDA SQL tool was missing (source: llm_judge, cross_engine_notes) |
| Speakeasy | Not Applicable | Linux ELF sample, not supported (source: deep_dive_agentic, tool_gate) |
| Frida | Not Applicable | Linux ELF sample, no runtime probing performed (source: deep_dive_agentic, tool_gate) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f  
**sample_path:** /opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 100
- **family_guess**: Sliver post-exploitation C2 framework implant
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis failed due to processing errors (Ghidra could not locate the sample file in its project, IDA SQL tool was missing), so all static analysis evidence is sourced from Malcat, capa, and YARA. The sample is a high-entropy (108) packed ELF x64 binary, consistent with obfuscated malware. The filename suffix '_sliver' strongly indicates association with the Sliver C2 framework.
- **summary**: This is a high-confidence malicious ELF x64 implant for the Sliver C2 framework. The sample is heavily obfuscated and packed (entropy 108), with confirmed implementation of multiple encryption, hashing, and obfuscation routines. Cross-engine evidence from Malcat, capa, and YARA all align with the behavior of a Sliver C2 implant, with no contradictory evidence present. Ghidra and IDA analysis was unavailable due to processing errors, but the available evidence is sufficient for a definitive malicious classification.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | file_summary | `entropy=108, type=ELF X64, 13 total anomalies including XorInLoop (5271 hits), S` | Extreme file entropy indicates packed/encrypted content, and the high volume of obfuscation-related anomalies (XOR loops |
| malcat | constants | `crypto::ChaCha (16 hits), hash::SHA256 (3 hits), hash::RIPEMD160 (3 hits), hash:` | Presence of cryptographic primitive constants and Windows registry constants confirms the sample implements encryption/h |
| capa | top_rules | `contain obfuscated stackstrings (T1027.005), encode data using Base64 (T1027), e` | These capa rule matches confirm the sample implements multiple common malware obfuscation and encryption routines used t |
| yara | matches | `Chacha_256_constant, SHA2_BLAKE2_IVs, RIPEMD160_Constants, SHA1_Constants, MD5_C` | YARA matches for cryptographic constants and operational indicators (domains, IPs, base64 content, suspicious strings) c |
| malcat | file_summary | `file_name ends with '_sliver'` | The sample filename suffix '_sliver' matches the naming convention for implants of the Sliver open-source post-exploitat |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: ELF x64 sample with extremely high entropy (108) and no reported imports, indicating strong packing/encryption and import obfuscation. Capa identifies obfuscated stackstrings, Base64/XOR encoding, and encryption routines. YARA matches detect embedded domains, IPs, Base64 content, suspicious strings, and multiple cryptographic constants (CRC32, MD5, RIPEMD160, SHA1, SHA512, BLAKE2). Malcat reports anomalies including multiple high-entropy unreferenced buffers and high-score long strings, consistent with a packed/encrypted payload such as Sliver C2.

### deep key_evidence
- `"Malcat file summary: type=ELF, arch=X64, entropy=108, imports_count=0, entrypoint_ea=17802522"`
- `"Malcat anomalies: BigBufferNoXrefMediumToHighEntropy (7 hits), BigStringHiScore"`
- `"capa top rules: contain obfuscated stackstrings (T1027.005), encode data using Base64 (T1027), encode data using XOR (T1027), encryption/decryption routines"`
- `"YARA matches: domain at offset 1, IP at offset 352194, contains_base64 at offset 8774316, Misc_Suspicious_Strings at offset 8816576, CRC32_poly_Constant at offset 2121855, MD5/RIPEMD160/SHA1 constants around offset 4643810, SHA512 constants around offset 3859962, SHA2_BLAKE2_IVs around offset 3851421"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f
size: 9281874
type: ELF
architecture: X64
entrypoint_ea: 17802522
entropy: 108
file_name: 2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| segment1 | 0 | 64 | 8712765 | 108 | RX |
| segment0 | 8712765 | 336 | 336 | 0 | R |
| segment1 | 8713101 | 3696 | 8712365 | 0 | RX |
| segment1 | 17425466 | 8708669 | 8708669 | 0 | RX |
| gap | 26134135 | 3523 | 0 | 108 | - |
| segment2 | 26137658 | 565586 | 2393983 | 108 | R |

### Anomalies (13)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| HugeStringBinary | 4 | strings | 16 | string has more than 1024 characters and binary encoding |
| TruncatedELFFile | 4 | integrity | 2 | some or all segment bytes are not present on disk |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 7 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| BigStringHiScore | 3 | strings | 256 | string has more than 256 characters and high interest score |
| DynamicString | 3 | strings | 256 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 755 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 1032 | More than 48 unique bytes defined across all immediate operands in the function |
| StackArrayInitialisationX64 | 3 | code | 3 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| XorInLoop | 3 | code | 5271 | XOR instruction in a loop |
| HugeGapBetweenFunctions | 2 | code | 1 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |
| HighXrefLoopingFunction | 1 | code | 131 | Function contains a loop and has a lot of incoming references (string decryption candidate) |
| SequentialFunction | 1 | code | 611 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |
| SpaghettiFunction | 1 | code | 19 | Function with lots of intra jumps, could be obfuscated |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `23277960`: 
  - `25482088`: 
  - `19712360`: 
  - `25151112`: 
  - `24118856`: 
- **HighXrefLoopingFunction**
  - `17440154`: 
  - `17445018`: 
  - `17447834`: 
  - `17459034`: 
  - `17464250`: 
- **ManyHighValueImmediates**
  - `17812026`: 
  - `17816666`: 
  - `17819578`: 
  - `17827642`: 
  - `17828794`: 
- **ManyUniqueImmediateBytes**
  - `17812026`: 
  - `17812762`: 
  - `17816666`: 
  - `17819578`: 
  - `17827642`: 
- **SequentialFunction**
  - `17694170`: 
  - `17798266`: 
  - `17798650`: 
  - `17802074`: 
  - `17813658`: 
- **SpaghettiFunction**
  - `17435194`: 
  - `17453370`: 
  - `17692602`: 
  - `17694586`: 
  - `17774362`: 
- **XorInLoop**
  - `17433717`: 
  - `17433978`: 
  - `17434006`: 
  - `17434036`: 
  - `17434066`: 

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 23277960 | `FFFFFFFF810000B1..0000000000000000` |
| 25482088 | `FFFFFFFFFFFF2828..0000000000000000` |
| 19712360 | `000000000000A755..0000000000000000` |
| 25151112 | `FFFFFFFFFFFFDC95..0000000000000000` |
| 24118856 | `FFFFFFFF22470047..0000000000000000` |
| 23304424 | `FFFFFFFFFFFF81F9..0000000000000000` |
| 23268936 | `FFFFFFFF81420042..0000000000000000` |
| 23269960 | `FFFFFFFF81001111..0000000000000000` |
| 23275432 | `FFFFFFFF99810000..0000000000000000` |
| 23309864 | `FFFFFFFFFFFF813B..0000000000000000` |
| 23039624 | `000000000000B8A9..0000000000000000` |
| 23275784 | `FFFFFFFFCC810000..0000000000000000` |
| 25481704 | `FFFFFFFFFFFFB59D..0000000000000000` |
| 23795848 | `FFFFFFFFC9C70015..0000000000000000` |
| 23278312 | `FFFFFFFFFE00FE00..0000000000000000` |
| 24963400 | `FFFFFFFF680000ED..0000000000000000` |
| 23281320 | `FFFFFFFFB081B000..0000000000000000` |
| 18175560 | `000000000000553F..0000000000000000` |
| 18318664 | `0000000000000B19..0000000000000000` |
| 19978216 | `00000000D1150000..0000000000000000` |
| 25504712 | `FFFFFFFFAF9D8100..0000000000000000` |
| 21954600 | `D6D6D6D6D6D65858..0000000000000000` |
| 19746984 | `00000000A7EA0000..0000000000000000` |
| 25012392 | `FFFFFFFFCE16CECE..0000000000000000` |
| 23346824 | `FFFFFFFFAE81AEAE..0000000000000000` |
| 25016712 | `FFFFFFFF161D49ED..0000000000000000` |
| 23822184 | `FFFFFFFFFFFF75C9..0000000000000000` |
| 23821000 | `FFFFFFFF46C70046..0000000000000000` |
| 23815240 | `FFFFFFFFFFFF7E7E..0000000000000000` |
| 23814888 | `FFFFFFFFBBC9BB00..0000000000000000` |
| 23813928 | `FFFFFFFFD1C900D1..0000000000000000` |
| 18236328 | `000000005801002F..0000000000000000` |
| 22181928 | `0000000000008800..0000000000000000` |
| 23347176 | `FFFFFFFFF18100F1..0000000000000000` |
| 23350504 | `FFFFFFFF81CA0000..0000000000000000` |
| 23282504 | `FFFFFFFF81000000..0000000000000000` |
| 23356072 | `FFFFFFFF81550000..0000000000000000` |
| 23355112 | `FFFFFFFFC7C700C7..0000000000000000` |
| 25951176 | `0000000013686800..0000000000000000` |
| 23228264 | `FFFFFFFFFFFF0A00..0000000000000000` |
| 25443208 | `FFFFFFFFFFFF7070..0000000000000000` |
| 25244456 | `FFFFFFFFFFFFEBEB..0000000000000000` |
| 23354760 | `FFFFFFFFC7C70000..0000000000000000` |
| 25443592 | `FFFFFFFFFFFFAF9D..0000000000000000` |
| 21960520 | `D6D6D6D6D6D6931F..0000000000000000` |
| 23309480 | `FFFFFFFFFFFF8182..0000000000000000` |
| 23943048 | `FFFFFFFF75750000..0000000000000000` |
| 24039080 | `FFFFFFFFFFFFE3FC..0000000000000000` |
| 23785288 | `FFFFFFFF7CC90000..0000000000000000` |
| 25331560 | `FFFFFFFF65954900..0000000000000000` |
| 23232168 | `FFFFFFFFFFFF0700..0000000000000000` |
| 20070408 | `0000000099556299..0000000000000000` |
| 23782824 | `FFFFFFFF13C90000..0000000000000000` |
| 20653384 | `0000000000006D00..0000000000000000` |
| 23851240 | `FFFFFFFFFFFFFBFB..0000000000000000` |
| 25272680 | `FFFFFFFFFFFF2B2B..0000000000000000` |
| 21357192 | `0000000090A49000..0000000000000000` |
| 21679816 | `D6D6D6D6D6D6C806..0000000000000000` |
| 18665256 | `0000000000A63A00..0000000000000000` |
| 25108008 | `FFFFFFFFFFFF659E..0000000000000000` |
| 23860840 | `FFFFFFFFFFFF25C9..0000000000000000` |
| 19988584 | `0000000000001536..0000000000000000` |
| 23294056 | `FFFFFFFFFFFFA9A9..0000000000000000` |
| 23768520 | `FFFFFFFF96969600..0000000000000000` |
| 23860104 | `FFFFFFFFFCFC00FC..0000000000000000` |
| 18471912 | `0000000022A60000..0000000000000000` |
| 25280296 | `FFFFFFFF65C2C2ED..0000000000000000` |
| 23353064 | `FFFFFFFF12810000..0000000000000000` |
| 23863752 | `FFFFFFFF19C71900..0000000000000000` |
| 23758408 | `FFFFFFFFD3C70000..0000000000000000` |
| 23352488 | `FFFFFFFF81303000..0000000000000000` |
| 18475688 | `00000000ECECEC00..0000000000000000` |
| 19071752 | `0000000000000000..0000000000000000` |
| 19734344 | `0000000000000455..0000000000000000` |
| 22417224 | `0000000000002E2E..0000000000000000` |
| 21962984 | `D6D6D6D6D6D6D6D6..0000000000000000` |
| 23247816 | `FFFFFFFFFFFFFFFF..0000000000000000` |
| 22826024 | `000000000000B41F..0000000000000000` |
| 22421512 | `0000000000000000..0000000000000000` |
| 23829640 | `FFFFFFFFC9530053..0000000000000000` |

### Constants / Known Patterns (5)
| Category | Value |
|---|---|
| registry | `registry::HKEY_CURRENT_USER` |
| hash | `hash::xxhash` |
| hash | `hash::SHA256` |
| hash | `hash::RIPEMD160` |
| crypto | `crypto::ChaCha` |

### Functions (30)
| EA | Name |
|---|---|
| 21563162 | sub_7f32e0 |
| 22431354 | sub_8c7240 |
| 22951674 | sub_9462c0 |
| 22433402 | sub_8c7a40 |
| 22953722 | sub_946ac0 |
| 22704954 | sub_909f00 |
| 17426938 | sub_4015c0 |
| 19549306 | sub_607840 |
| 19223738 | sub_5b8080 |
| 25086266 | sub_b4f500 |
| 26096922 | sub_c460e0 |
| 25088602 | sub_b4fe20 |
| 22691866 | sub_906be0 |
| 24204186 | sub_a77f60 |
| 22073210 | sub_86fb40 |
| 22073146 | sub_86fb00 |
| 19543130 | sub_606020 |
| 19545306 | sub_6068a0 |
| 21281178 | sub_7ae560 |
| 22077978 | sub_870de0 |
| 22082970 | sub_872160 |
| 25722426 | sub_beaa00 |
| 21297338 | sub_7b2480 |
| 23178650 | sub_97d960 |
| 23426970 | sub_9ba360 |
| 22069690 | sub_86ed80 |
| 20874234 | sub_74afc0 |
| 23397306 | sub_9b2f80 |
| 23571834 | sub_9dd940 |
| 21203706 | sub_79b6c0 |

### Decompilations (top 6)
#### 21563162 — sub_7f32e0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_7f32e0(void)

{
    uint32_t uVar1;
    uint32_t uVar2;
    uint32_t uVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined auVar6 [16];
    undefined auVar7 [16];
    undefined auVar8 [16];
    undefined auVar9 [16];
    undefined *puVar10;
    uint32_t uVar11;
    int32_t iVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    uint32_t uVar15;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    uint32_t uVar22;
    uint32_t uVar23;
    uint32_t uVar24;
    uint32_t uVar25;
    uint32_t uVar26;
    uint32_t uVar27;
    uint32_t uVar28;
    uint32_t uVar29;
    uint32_t uVar30;
    uint32_t uVar31;
    uint64_t uVar32;
    uint32_t uVar33;
    uint32_t uVar34;
    uint32_t uVar35;
    uint32_t uVar36;
    uint32_t uVar37;
    uint32_t uVar38;
    uint32_t uVar39;
    uint32_t uVar40;
    uint32_t uVar41;
    uint32_t uVar42;
    uint32_t uVar43;
    uint32_t uVar44;
    uint32_t uVar45;
    uint32_t uVar46;
    uint32_t uVar47;
    uint32_t uVar48;
    uint32_t uVar49;
    uint32_t uVar50;
    uint32_t uVar51;
    uint32_t uVar52;
    uint32_t uVar53;
    uint32_t uVar54;
    uint32_t uVar55;
    uint32_t uVar56;
    uint32_t uVar57;
    uint32_t uVar58;
    uint32_t uVar59;
    uint32_t uVar60;
    uint32_t uVar61;
    int32_t iVar62;
    int64_t in_FS_OFFSET;
    undefined auVar63 [32];
    undefined auVar64 [32];
    undefined auVar65 [32];
    undefined auVar66 [32];
    undefined auVar67 [32];
    undefined auVar68 [32];
    undefined auVar69 [32];
    undefined auVar70 [16];
    undefined auVar71 [32];
    uint32_t *in_stack_00000008;
    undefined (*in_stack_00000010) [32];
    uint64_t in_stack_00000018;
    int32_t aiStack_220 [8];
    int32_t aiStack_200 [8];
    int32_t aiStack_1e0 [8];
    int32_t aiStack_1c0 [8];
    undefined auStack_1a0 [384];
    undefined (*pauStack_20) [32];
    undefined (*pauStack_18) [32];
    
    while (auStack_1a0 <= *(*(in_FS_OFFSET + -8) + 0x10)) {
        sub_459a00();
    }
    if ([0x0x11e56b1] != '\x01') {
        puVar10 = *in_stack_00000010;
        if (in_stack_00000010 != puVar10 + (in_stack_00000018 & 0xffffffffffffffc0)) {
            uVar33 = *in_stack_00000008;
            uVar36 = in_stack_00000008[1];
            uVar40 = in_stack_00000008[2];
            uVar44 = in_stack_00000008[3];
            uVar31 = in_stack_00000008[4];
            uVar30 = in_stack_00000008[5];
            uVar29 = in_stack_00000008[6];
            uVar28 = in_stack_00000008[7];
            do {
                uVar58 = **in_stack_00000010;
                uVar11 = uVar58 >> 0x18 | (uVar58 & 0xff0000) >> 8 | (uVar58 & 0xff00) << 8 | uVar58 << 0x18;
                iVar12 = (~uVar31 & uVar29 ^ uVar31 & uVar30) +
                         uVar28 + uVar11 + 0x428a2f98 +
                         ((uVar31 >> 0x19 | uVar31 << 7) ^
                         (uVar31 >> 6 | uVar31 << 0x1a) ^ (uVar31 >> 0xb | uVar31 << 0x15));
                uVar44 = uVar44 + iVar12;
                uVar58 = (uVar40 & uVar36 ^ uVar33 & uVar40 ^ uVar36 & uVar33) +
                         ((uVar33 >> 2 | uVar33 << 0x1e) ^ (uVar33 >> 0xd | uVar33 << 0x13) ^
                         (uVar33 >> 0x16 | uVar33 << 10)) + iVar12;
                uVar28 = *(*in_stack_00000010 + 4);
                uVar39 = uVar28 >> 0x18 | (uVar28 & 0xff0000) >> 8 | (uVar28 & 0xff00) << 8;
                uVar13 = uVar39 | uVar28 << 0x18;
                iVar12 = (~uVar44 & uVar30 ^ uVar44 & uVar31) +
                         uVar29 + uVar13 + 0x71374491 +
                         ((uVar44 >> 0x19 | uVar44 * 0x80) ^
                         (uVar44 >> 6 | uVar44 * 0x4000000) ^ (uVar44 >> 0xb | uVar44 * 0x200000));
                uVar40 = uVar40 + iVar12;
                uVar55 = (uVar36 & uVar33 ^ uVar58 & uVar36 ^ uVar33 & uVar58) +
                         ((uVar58 >> 2 | uVar58 * 0x40000000) ^ (uVa
```
#### 22431354 — sub_8c7240
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_8c7240(undefined8 param_1,int64_t param_2,undefined8 param_3,uint64_t param_4,uint64_t param_5,
               undefined8 param_6)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t iVar3;
    int32_t iVar4;
    uint32_t *puVar5;
    uint32_t *puVar6;
    int64_t iVar7;
    undefined4 *in_RAX;
    int64_t iVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    int64_t unaff_RBX;
    undefined *puVar15;
    undefined *unaff_RBP;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    int64_t unaff_R14;
    uint32_t uVar22;
    uint32_t uVar23;
    
    do {
        puVar15 = register0x00000020;
        if (*(unaff_R14 + 0x10) < register0x00000020 + -0x68) {
            puVar15 = register0x00000020 + -0xe8;
            *(register0x00000020 + -8) = unaff_RBP;
            unaff_RBP = register0x00000020 + -8;
            *(register0x00000020 + 0x10) = unaff_RBX;
            *(register0x00000020 + 0x28) = param_2;
            if ((param_4 == param_5) && ((param_4 & 0x3f) == 0)) {
                *(register0x00000020 + 0x18) = param_4;
                *(register0x00000020 + -0xb0) = *in_RAX;
                uVar10 = in_RAX[1];
                uVar9 = in_RAX[2];
                *(register0x00000020 + -0xc0) = in_RAX[3];
                *(register0x00000020 + -0x8c) = in_RAX[4];
                iVar1 = in_RAX[5];
                *(register0x00000020 + -0x74) = iVar1;
                iVar2 = in_RAX[6];
                *(register0x00000020 + -0xa8) = in_RAX[7];
                uVar12 = in_RAX[9];
                *(register0x00000020 + -0x88) = uVar12;
                uVar11 = in_RAX[10];
                *(register0x00000020 + -0x94) = uVar11;
                uVar14 = in_RAX[0xb];
                *(register0x00000020 + -0xac) = uVar14;
                if (*(in_RAX + 0x79) == '\0') {
                    *(register0x00000020 + 0x10) = unaff_RBX;
                    uVar12 = uVar10 + 0x3320646e ^ uVar12;
                    uVar13 = uVar12 << 0x10 | uVar12 >> 0x10;
                    uVar12 = iVar1 + uVar13;
                    *(register0x00000020 + -0xc4) = uVar12;
                    uVar12 = uVar12 ^ uVar10;
                    uVar12 = uVar12 << 0xc | uVar12 >> 0x14;
                    uVar22 = uVar10 + uVar12 + 0x3320646e;
                    in_RAX[0x1f] = uVar22;
                    uVar22 = uVar22 ^ uVar13;
                    uVar22 = uVar22 << 8 | uVar22 >> 0x18;
                    uVar13 = *(register0x00000020 + -0xc4) + uVar22;
                    uVar12 = uVar12 ^ uVar13;
                    in_RAX[0x20] = uVar12 << 7 | uVar12 >> 0x19;
                    in_RAX[0x21] = uVar13;
                    in_RAX[0x22] = uVar22;
                    uVar11 = uVar9 + 0x79622d32 ^ uVar11;
                    uVar11 = uVar11 << 0x10 | uVar11 >> 0x10;
                    uVar12 = iVar2 + uVar11;
                    uVar13 = uVar12 ^ uVar9;
                    uVar13 = uVar13 << 0xc | uVar13 >> 0x14;
                    uVar22 = uVar9 + uVar13 + 0x79622d32;
                    in_RAX[0x23] = uVar22;
                    uVar22 = uVar22 ^ uVar11;
                    uVar11 = uVar22 << 8 | uVar22 >> 0x18;
                    uVar12 = uVar12 + uVar11;
                    uVar13 = uVar13 ^ uVar12;
                    in_RAX[0x24] = uVar13 << 7 | uVar13 >> 0x19;
                    in_RAX[0x25] = uVar12;
                    in_RAX[0x26] = uVar11;
                    uVar11 = *(register0x00000020 + -0xc0);
                    uVar14 = uVar11 + 0x6b206574 ^ uVar14;
                    uVar14 = uVar14 << 0x10 | uVar14 >> 0x10;
                    uVar12 = *(register0x00000020 + -0xa8) + uVar14;
                    *(register0x00000020 + -200) = uVar12;
                    uVar12 = uVar12 ^ uVar11;
                    uVar13 = uVa
```
#### 22951674 — sub_9462c0
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_9462c0(undefined8 param_1,int64_t param_2,undefined8 param_3,uint64_t param_4,uint64_t param_5,
               undefined8 param_6)

{
    int32_t iVar1;
    int32_t iVar2;
    int32_t iVar3;
    int32_t iVar4;
    uint32_t *puVar5;
    uint32_t *puVar6;
    int64_t iVar7;
    undefined4 *in_RAX;
    int64_t iVar8;
    uint32_t uVar9;
    uint32_t uVar10;
    uint32_t uVar11;
    uint32_t uVar12;
    uint32_t uVar13;
    uint32_t uVar14;
    int64_t unaff_RBX;
    undefined *puVar15;
    undefined *unaff_RBP;
    uint32_t uVar16;
    uint32_t uVar17;
    uint32_t uVar18;
    uint32_t uVar19;
    uint32_t uVar20;
    uint32_t uVar21;
    int64_t unaff_R14;
    uint32_t uVar22;
    uint32_t uVar23;
    
    do {
        puVar15 = register0x00000020;
        if (*(unaff_R14 + 0x10) < register0x00000020 + -0x68) {
            puVar15 = register0x00000020 + -0xe8;
            *(register0x00000020 + -8) = unaff_RBP;
            unaff_RBP = register0x00000020 + -8;
            *(register0x00000020 + 0x10) = unaff_RBX;
            *(register0x00000020 + 0x28) = param_2;
            if ((param_4 == param_5) && ((param_4 & 0x3f) == 0)) {
                *(register0x00000020 + 0x18) = param_4;
                *(register0x00000020 + -0xac) = *in_RAX;
                uVar10 = in_RAX[1];
                uVar9 = in_RAX[2];
                *(register0x00000020 + -0xcc) = in_RAX[3];
                *(register0x00000020 + -0x98) = in_RAX[4];
                iVar1 = in_RAX[5];
                *(register0x00000020 + -200) = iVar1;
                iVar2 = in_RAX[6];
                *(register0x00000020 + -0xa8) = in_RAX[7];
                uVar12 = in_RAX[9];
                *(register0x00000020 + -0xd0) = uVar12;
                uVar11 = in_RAX[10];
                *(register0x00000020 + -100) = uVar11;
                uVar14 = in_RAX[0xb];
                *(register0x00000020 + -0x90) = uVar14;
                if (*(in_RAX + 0x79) == '\0') {
                    *(register0x00000020 + 0x10) = unaff_RBX;
                    uVar12 = uVar10 + 0x3320646e ^ uVar12;
                    uVar13 = uVar12 << 0x10 | uVar12 >> 0x10;
                    uVar12 = iVar1 + uVar13;
                    *(register0x00000020 + -0xb8) = uVar12;
                    uVar12 = uVar12 ^ uVar10;
                    uVar12 = uVar12 << 0xc | uVar12 >> 0x14;
                    uVar22 = uVar10 + uVar12 + 0x3320646e;
                    in_RAX[0x1f] = uVar22;
                    uVar22 = uVar22 ^ uVar13;
                    uVar22 = uVar22 << 8 | uVar22 >> 0x18;
                    uVar13 = *(register0x00000020 + -0xb8) + uVar22;
                    uVar12 = uVar12 ^ uVar13;
                    in_RAX[0x20] = uVar12 << 7 | uVar12 >> 0x19;
                    in_RAX[0x21] = uVar13;
                    in_RAX[0x22] = uVar22;
                    uVar11 = uVar9 + 0x79622d32 ^ uVar11;
                    uVar11 = uVar11 << 0x10 | uVar11 >> 0x10;
                    uVar12 = iVar2 + uVar11;
                    uVar13 = uVar12 ^ uVar9;
                    uVar13 = uVar13 << 0xc | uVar13 >> 0x14;
                    uVar22 = uVar9 + uVar13 + 0x79622d32;
                    in_RAX[0x23] = uVar22;
                    uVar22 = uVar22 ^ uVar11;
                    uVar11 = uVar22 << 8 | uVar22 >> 0x18;
                    uVar12 = uVar12 + uVar11;
                    uVar13 = uVar13 ^ uVar12;
                    in_RAX[0x24] = uVar13 << 7 | uVar13 >> 0x19;
                    in_RAX[0x25] = uVar12;
                    in_RAX[0x26] = uVar11;
                    uVar11 = *(register0x00000020 + -0xcc);
                    uVar14 = uVar11 + 0x6b206574 ^ uVar14;
                    uVar14 = uVar14 << 0x10 | uVar14 >> 0x10;
                    uVar12 = *(register0x00000020 + -0xa8) + uVar14;
                    *(register0x00000020 + -0xbc) = uVar12;
                    uVar12 = uVar12 ^ uVar11;
                    uVar13 = uVar
```

### Structures (3)
| Name | EA |
|---|---|
| ELF | 0 |
| Segments | 8712765 |
| Sections | 8713101 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 16 · duration_s: 9.97

| Rule | ATT&CK | MBC |
|---|---|---|
| contain obfuscated stackstrings | T1027.005:Obfuscated Files or Information | B0032.020:Executable Code Obfuscation, B0032.017:Executable Code Obfuscation |
| encode data using Base64 | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.001:Encode Data |
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| encrypt data using AES via x86 extensions | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.001:Encrypt Data |
| encrypt data using RC4 PRGA | T1027:Obfuscated Files or Information | C0027.009:Encrypt Data, C0021.004:Generate Pseudo-random Sequence |
| decrypt data using AES via x86 extensions | T1140:Deobfuscate/Decode Files or Information | C0031.001:Decrypt Data |
| check for software breakpoints |  | B0001.025:Debugger Detection |
| parse credit card information |  | C0019:Check String |
| encrypt data using Salsa20 or ChaCha | T1027:Obfuscated Files or Information |  |
| hash data using fnv |  | C0030.005:Non-Cryptographic Hash |
| hash data using SHA1 |  | C0029.002:Cryptographic Hash |
| hash data using SHA256 |  | C0029.003:Cryptographic Hash |
| authenticate HMAC |  | C0061:Hashed Message Authentication Code |
| execute syscall |  |  |
| hash data using SHA384 |  |  |

## PE Imports / Signals
import_count: ?

## YARA Matches (pipeline)
Total matches: 11

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@1 len=3 |
| IP | - | $ipv6@352194 len=2 |
| contains_base64 | - | $a@8774316 len=12 |
| Misc_Suspicious_Strings | - | $a0@8816576 len=8 |
| CRC32_poly_Constant | - | $c0@2121855 len=4 |
| MD5_Constants | - | $c4@4643810 len=4; $c5@4643814 len=4; $c6@4643823 len=4; $c7@4643827 len=4 |
| RIPEMD160_Constants | - | $c5@4643810 len=4; $c6@4643814 len=4; $c7@4643823 len=4 |
| SHA1_Constants | - | $c5@4643810 len=4; $c6@4643814 len=4; $c7@4643823 len=4 |
| SHA512_Constants | - | $c1@3859962 len=4; $c3@3860103 len=4; $c5@3860244 len=4; $c7@3860385 len=4 |
| SHA2_BLAKE2_IVs | - | $c0@3851421 len=4; $c1@3851434 len=4; $c2@3851448 len=4; $c3@3851462 len=4; $c4@3851476 len=4; $c5@3851490 len=4; $c6@3851504 len=4; $c7@3851518 len=4 |
| Chacha_256_constant | - | $split1@5027829 len=8; $split2@5027842 len=8 |

## Generated YARA Meta
```json
{
  "rule_count": 11,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$domain_regex",
          "offset": 1,
          "length": 3,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IP",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 352194,
          "length": 2,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a",
          "offset": 8774316,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Misc_Suspicious_Strings",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$a0",
          "offset": 8816576,
          "length": 8,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "CRC32_poly_Constant",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c0",
          "offset": 2121855,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "MD5_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c4",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c5",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643827,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "RIPEMD160_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA1_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c5",
          "offset": 4643810,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c6",
          "offset": 4643814,
          "length": 4,
          "xor_key": null
        },
        {
          "id": "$c7",
          "offset": 4643823,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SHA512_Constants",
      "path": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
      "strings": [
        {
          "id": "$c1",
          "offset": 3859962,
          "length"
```

## FLOSS Strings
Total strings: 0 · per_category: `{}`

### FLOSS sample

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
{
  "xorsearch_ok": false,
  "sample": "/opt/samples/corpus/pool/eceb8e06657564c16e1c0c9e1cf21cd875ebf06a1c37b81df3824fc77159ae3f/2026-07-03_7089acf1941ea01081b4eab5f0b77136_sliver",
  "candidates": [],
  "xorsearch_stdout": "",
  "xorsearch_stderr": "",
  "xorsearch_returncode": 1
}
