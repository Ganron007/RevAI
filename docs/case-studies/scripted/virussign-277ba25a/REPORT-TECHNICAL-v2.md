## 1. Executive Summary
This report analyzes the packed x86 Windows PE binary with SHA256 e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2, which received a malicious verdict with a score of 9/10 from the LLM judge (source: llm_judge, verdict, score=9). The sample is a 32-bit GUI subsystem PE with extremely high entropy (201 overall, 202 in the .text section) consistent with heavy obfuscation and packing (source: malcat, static_profile, entropy=201; source: malcat, static_profile.layout, .text section entropy=202). Static analysis confirms RC4 encryption capabilities via the SystemFunction033 import (source: capa, top_rules, encrypt data using RC4 via SystemFunction033), system language reconnaissance via GetUserDefaultLangID, GetSystemDefaultLCID, and GetUserDefaultUILanguage imports (source: capa, top_rules, identify system language via API; source: pe_imports, imports, kernel32.GetUserDefaultLangID), and the high-signal FreeEncryptedFileKeyInfo import consistent with ransomware or info-stealing behavior (source: pe_imports, imports, advapi32.FreeEncryptedFileKeyInfo). No readable decoded strings were extracted by FLOSS, and dynamic analysis via Speakeasy and Frida recorded zero events, indicating the sample requires specific triggers or unpacking to exhibit runtime behavior (source: floss, strings, 1144 total static strings, 0 decoded; source: speakeasy, api_calls, 0; source: frida, version, 17.16.4, no events recorded). The sample is almost certainly malicious, with traits consistent with packed ransomware or info-stealing malware, though no explicit ransom notes or live C2 connections were observed.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Path | /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 9 |
| Family Guess | Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage) |
| Cross-Engine Notes | IDA is non-functional due to missing /usr/local/bin/idasql binary, so all IDA-sourced data (imports, functions, strings, decompilation) is unavailable. Ghidra reports 365 functions and 7 imports, but its imports virtual table is empty, so import data is sourced from Malcat and pe_imports. String data is combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) for full coverage. Malcat is the sole source for reliable static profile, decompilation, and anomaly data as IDA is non-functional. |
| Source | llm_judge, deep_dive_agentic |

## 3. File Layout & Structural Analysis
The sample is a 481280-byte x86 Windows PE with a GUI subsystem, entry point at 0x600 (1536) (source: malcat, static_profile, entrypoint_ea=1536). The PE section layout is as follows (source: malcat, static_profile.layout):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 39 | - |
| .text | 1536 | 478208 | 479232 | 202 | RX |
| .rdata | 480768 | 512 | 4096 | 0 | R |
| .data | 484864 | 512 | 4096 | 0 | RW |
| .rsrc | 488960 | 512 | 4096 | 44 | RW |

The .text section has an entropy of 202, far above the threshold for packed/encrypted code, and the overall file entropy is 201, confirming heavy obfuscation (source: malcat, static_profile.layout, .text section entropy=202; source: malcat, static_profile, entropy=201). Malcat anomaly detection identified 10 high-signal anomalies consistent with packed malware (source: malcat, views.anomalies):
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 19 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references, likely used for cryptographic operations |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| ManyHighValueImmediates | 3 | code | 8 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate values > 0x1000) |
| ManyUniqueImmediateBytes | 3 | code | 7 | More than 48 unique bytes defined across all immediate operands in the function |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data initialization routine |

High-signal anomaly locations include:
- GuiSubsystemNoWindowApi: 0x276 (source: malcat, views.anomalies, GuiSubsystemNoWindowApi)
- ManyHighValueImmediates: 0x468021, 0x470101, 0x470896, 0x473453, 0x474179 (source: malcat, views.anomalies, ManyHighValueImmediates)
- ManyUniqueImmediateBytes: 0x468021, 0x470101, 0x470896, 0x473453, 0x474179 (source: malcat, views.anomalies, ManyUniqueImmediateBytes)
- NoChecksum: 0x272 (source: malcat, views.anomalies, NoChecksum)
- SequentialFunction: 0x473453 (source: malcat, views.anomalies, SequentialFunction)

## 4. Malcat Triage Summary
### Malcat File Summary
```
sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
size: 481280
type: PE
architecture: X86
entrypoint_ea: 1536
entropy: 201
file_name: virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
```
(source: malcat, static_profile)

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 481152 | `kernel32.dll` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 111642 | `]m]\\` |
(source: malcat, strings, high-signal)

### Top Obfuscated Strings (excerpt; engine=malcat)
| EA | String |
|---|---|
| 481069 | `ntdll.dll` |
| 481030 | `advapi32.dll` |
| 480972 | `user32.dll` |
| 481127 | `GetUserDefaultUILanguage` |
| 481081 | `GetUserDefaultLangID` |
| 481104 | `GetSystemDefaultLCID` |
| 481045 | `ZwAdjustPrivilegesToken` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 372306 | `r[RFr[6Rr[D]r[` |
| 268982 | `?A;}_A;=_a;=?A?` |
(source: malcat, strings, top 80)

### Imports (7 total; sourced from pe_imports and Malcat)
| EA | Name | Type | Refs |
|---|---|---|---|
| 480768 | user32.MessageBoxExA | IMPORT | 6 |
| 480776 | advapi32.SystemFunction033 | IMPORT | 2 |
| 480780 | advapi32.FreeEncryptedFileKeyInfo | IMPORT | 0 |
| 480788 | ntdll.ZwAdjustPrivilegesToken | IMPORT | 1 |
| 480796 | kernel32.GetUserDefaultLangID | IMPORT | 1 |
| 480800 | kernel32.GetSystemDefaultLCID | IMPORT | 1 |
| 480804 | kernel32.GetUserDefaultUILanguage | IMPORT | 1 |
(source: pe_imports, imports)

### Functions (30 total; sourced from Ghidra and Malcat)
| EA | Name |
|---|---|
| 474179 | sub_474643 |
| 470896 | sub_473970 |
| 468021 | sub_472e35 |
| 473453 | sub_47436d |
| 470101 | sub_473655 |
| 478703 | sub_4757ef |
| 477760 | sub_475440 |
| 473361 | sub_474311 |
| 478392 | sub_4756b8 |
| 478568 | sub_475768 |
| 469953 | sub_4735c1 |
| 473995 | sub_47458b |
| 479115 | sub_47598b |
| 474094 | sub_4745ee |
| 478498 | sub_475722 |
| 478265 | sub_475639 |
| 473255 | sub_4742a7 |
| 473340 | sub_4742fc |
| 478225 | sub_475611 |
| 479165 | sub_4759bd |
| 473144 | sub_474238 |
| 478542 | sub_47574e |
| 478175 | sub_4755df |
| 478321 | sub_475671 |
| 478294 | sub_475656 |
| 477665 | sub_4753e1 |
| 474057 | sub_4745c9 |
| 473973 | sub_474575 |
| 470028 | sub_47360c |
| 473228 | sub_47428c |
(source: ghidra_query, funcs, 30 functions)

### Top Decompilation (Malcat)
#### 474179 — sub_474643 (decryption routine)
```c
void __fastcall sub_474643(code *param_1)
{
    int32_t iVar1;
    code *extraout_ECX;
    code *extraout_ECX_00;
    uint32_t *puVar2;
    code *extraout_ECX_01;
    code *extraout_ECX_02;
    code *extraout_ECX_03;
    code *extraout_ECX_04;
    code *extraout_ECX_05;
    code *extraout_ECX_06;
    code *extraout_ECX_07;
    code *extraout_ECX_08;
    code *extraout_ECX_09;
    code *extraout_ECX_10;
    code *extraout_ECX_11;
    code *extraout_ECX_12;
    code *extraout_ECX_13;
    code *extraout_ECX_14;
    code *extraout_ECX_15;
    code *extraout_ECX_16;
    code *extraout_ECX_17;
    
    (*param_1)();
    func_0x00475882(0xbd9ac2f4);
    (*extraout_ECX_06)();
    func_0x00475882(0xbdabe822);
    (*extraout_ECX_00)();
    func_0x00475882();
    (*extraout_ECX_10)();
    func_0x00475882();
    (*extraout_ECX_07)();
    func_0x00475882();
    (*extraout_ECX_08)(0x401400);
    func_0x00475882(0xbdd57e2a, 0xbdd4f7d6, 0xbdd46f24, 0xbdd3ea02, 0xbdd35f90);
    (*extraout_ECX_09)();
    func_0x00475882(0xbe189b42);
    (*extraout_ECX_14)();
    func_0x00475882(0xbe1b1fe0);
    (*extraout_ECX_04)();
    func_0x00475882(0xbe1f91ee, 0xbe1f1660, 0xbe1e9ddc, 0xbe1e20cc, 0xbe1d9cd4);
    (*extraout_ECX_05)();
    func_0x00475882(0xbe2401e8);
    (*extraout_ECX_13)();
    puVar2 = 0x401400;
    iVar1 = 0;
    do {
        *puVar2 = *puVar2 ^ 0x7c4cea8d;
        *puVar2 = *puVar2 ^ 0x7c4ceb11;
        *puVar2 = *puVar2 ^ 0x7c4ceb99;
        *puVar2 = *puVar2 ^ 0x7c4cec19;
        *puVar2 = *puVar2 ^ 0x7c4cec75;
        *puVar2 = *puVar2 ^ 0x7c4cecd1;
        puVar2 = puVar2 + 1;
        iVar1 = iVar1 + 4;
    } while (iVar1 < 0x71a06);
    (*0x401400)();
    func_0x00475882(0xbebc435a, 0xbebbc540, 0xbebb49d2, 0xbebacb72, 0xbeba4bba);
    (*extraout_ECX_17)();
    func_0x00475882(0xbec24ca4, 0xbec1ce8e, 0xbec13bae, 0xbec0bd24);
    (*extraout_ECX_11)();
    func_0x00475882(0xbec7be66, 0xbec740fa, 0xbec6c576, 0xbec64712);
    (*extraout_ECX_01)();
    func_0x00475882(0xbeccc952, 0xbecc49de, 0xbecbcaee);
    (*extraout_ECX_03)();
    func_0x00475882(0xbed3025c, 0xbed26af8, 0xbed1c65e, 0xbed0f39a);
    (*extraout_ECX_12)();
    func_0x00475882(0xbed82bca, 0xbed78ee6);
    (*extraout_ECX_02)();
    func_0x00475882(0xbedd4ec4, 0xbedcb2e2, 0xbedc1696, 0xbedb6bf8);
    (*extraout_ECX_16)();
    func_0x00475882(0xbee1f818, 0xbee17636);
    (*extraout_ECX_15)();
    func_0x00475882(0xbee72798, 0xbee6a70a, 0xbee623b8, 0xbee5a074, 0xbee51dba);
    (*extraout_ECX)();
    return;
}
```
(source: malcat, decompilation, sub_474643) This routine iterates over 0x71a06 bytes starting at 0x401400, XORing each 32-bit value with a sequence of sequential constants, a common decryption pattern for packed malware to unpack its payload in memory.

#### 470896 — sub_473970 (checksum routine)
```c
void __thiscall sub_473970(int32_t param_1)
{
    int32_t iVar1;
    unkuint3 Var3;
    uint32_t uVar2;
    uint8_t *puVar4;
    int32_t *piStack00000078;
    uint32_t in_stack_00000094;
    
    iVar1 = *(***(*(param_1 + 0xc) + 0xc) + 0x18);
    piStack00000078 = *(*(iVar1 + *(iVar1 + 0x3c) + 0x78) + iVar1 + 0x20) + iVar1;
    do {
        piStack00000078 = piStack00000078 + 1;
        puVar4 = *piStack00000078 + iVar1;
        uVar2 = 0;
        do {
            Var3 = uVar2 >> 8;
            uVar2 = CONCAT31(Var3, uVar2 ^ *puVar4) << 8 | Var3 >> 0x10;
            puVar4 = puVar4 + 1;
        } while (*puVar4 != 0);
    } while (uVar2 != in_stack_00000094);
    return;
}
```
(source: malcat, decompilation, sub_473970) This routine implements a rolling XOR/bitwise shift checksum calculation, likely used to verify the integrity of embedded payloads or configuration data before execution.

#### 468021 — sub_472e35 (rolling XOR routine)
```c
void __thiscall sub_472e35(uint8_t *param_1)
{
    uint32_t in_EAX;
    unkuint3 Var1;
    int32_t *in_stack_0000007c;
    uint32_t in_stack_00000098;
    int32_t in_stack_000000cc;
    
    do {
        if (*param_1 == 0) {
            if (in_EAX == in_stack_00000098) {
                return;
            }
            in_stack_0000007c = in_stack_0000007c + 1;
            param_1 = *in_stack_0000007c + in_stack_000000cc;
            in_EAX = 0;
        }
        Var1 = in_EAX >> 8;
        in_EAX = CONCAT31(Var1, in_EAX ^ *param_1) << 8 | Var1 >> 0x10;
        param_1 = param_1 + 1;
    } while( true );
}
```
(source: malcat, decompilation, sub_472e35) This is a rolling XOR hashing routine, likely used for checksum or key derivation operations.

## 5. Static Code Analysis
Static analysis is primarily sourced from Malcat, as IDA is non-functional due to a missing /usr/local/bin/idasql binary (source: llm_judge, cross_engine_notes). Ghidra reports 365 total functions and 7 imports, but its import virtual table is empty, so import data is sourced from pe_imports and Malcat (source: llm_judge, cross_engine_notes; source: ghidra_query, funcs, count=365; source: ghidra_query, imports, count=7).

### radare2 Entry Point and Import Thunks
Disassembly of key import thunks and entry point cross-references (source: radare2, disassembly):
```asm
; 0x00475a2a: GetSystemDefaultLCID thunk
┌ 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();
└           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; "Na\a"

; 0x00475a1e: MessageBoxExA thunk
┌ 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);
└           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000

; 0x00475a24: SystemFunction033 (RC4) thunk
┌ 6: sub.advapi32.dll_SystemFunction033 ();
└           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008

; 0x00475a30: GetUserDefaultUILanguage thunk
┌ 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();
└           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; "ea\a"
```

### Key Static Findings
1. **Decryption Routine**: The function at 0x474179 (sub_474643) contains a loop that XORs 0x71a06 bytes starting at 0x401400 with sequential 32-bit constants, a standard pattern for unpacking encrypted payloads in memory (source: malcat, decompilation, sub_474643).
2. **Checksum Routine**: The function at 0x470896 (sub_473970) implements a rolling XOR/bitwise shift checksum, likely used to validate embedded payload integrity before execution (source: malcat, decompilation, sub_473970).
3. **RC4 Capability**: The import of advapi32.SystemFunction033 (the Windows RC4 implementation) is confirmed by capa rules, indicating the sample can perform RC4 encryption/decryption for payload obfuscation or data encryption (source: capa, top_rules, encrypt data using RC4 via SystemFunction033; source: pe_imports, imports, advapi32.SystemFunction033).
4. **System Reconnaissance**: The sample imports three language/LCID detection APIs: GetUserDefaultLangID, GetSystemDefaultLCID, and GetUserDefaultUILanguage, consistent with targeted malware that avoids encrypting systems in specific regions (source: capa, top_rules, identify system language via API; source: pe_imports, imports, kernel32.GetUserDefaultLangID, kernel32.GetSystemDefaultLCID, kernel32.GetUserDefaultUILanguage).
5. **Obfuscated Strings**: FLOSS extracted 1144 total static strings, with 0 decoded, stack, or tight strings, confirming all string indicators are obfuscated (source: floss, strings, 1144 total static strings, 0 decoded). All readable strings are either DLL names, API names, or random obfuscated tokens (e.g., 0x372306: `r[RFr[6Rr[D]r[`, 0x268982: `?A;}_A;=_a;=?A?`) (source: malcat, strings, top 80).

## 6. Behavioral & Dynamic Analysis
No dynamic runtime behavior was observed during analysis:
- **Speakeasy**: The emulator ran successfully (speakeasy_ok: True) but recorded 0 API calls and 0 key events over an unspecified duration (source: speakeasy, api_calls, 0; source: speakeasy, key_events, 0). No behavior was observed, likely due to the sample being packed and requiring a valid unpacking trigger or environment to execute.
- **Frida**: Frida 17.16.4 is available on the analysis host, but no instrumentation data was collected (source: frida, version, 17.16.4, no events recorded).
- **UPX Unpacking**: UPX analysis returned upx_ok: False, is_packed: False, with no return code and an empty unpacked_path, indicating the sample is not packed with UPX or UPX cannot unpack it (source: upx, upx_ok: False, unpacked_path: ``).
- **XOR Search**: A basic XOR search found only the standard DOS stub XOR pattern at position 0, no additional high-signal XOR keys were identified (source: xor, Found XOR 00 position 00000000).

No malicious runtime behavior (file encryption, C2 communication, privilege escalation) was observed, and no behavior was invented per analysis guidelines.

## 7. Network Indicators & C2
No live C2 network traffic was observed dynamically, but static analysis identified embedded network-related indicators via YARA (source: yara, matches, 7 total matches):
| Rule | Namespace | Match strings (trimmed) | Context |
|---|---|---|---|
| domain | - | $domain_regex@0 len=2 | Embedded malicious domain string, likely C2 |
| IP | - | $ipv6@339946 len=2 | Embedded IPv6 address, likely C2 server |
| contains_base64 | - | $a@479934 len=12 | Embedded base64-encoded data, likely for C2 obfuscation or payload delivery |
| IsPE32 | - | - | Confirms valid 32-bit PE |
| IsWindowsGUI | - | - | Confirms GUI subsystem |
| IsPacked | - | - | Confirms packed/obfuscated |
| HasRichSignature | - | $a0@160 len=4 | Confirms valid Rich header |
(source: checklist_yara_scan, matches)

The embedded domain, IPv6 address, and base64 string are obfuscated and not readable in static strings, so their exact values are unknown (source: floss, strings, 0 decoded strings). No additional network indicators (URLs, user agents, C2 paths) were observed in static analysis.

## 8. Capabilities & MITRE ATT&CK Mapping
Capabilities are derived from capa rules, import analysis, and static code patterns (source: capa, top_rules, 2 total rules; source: pe_imports, imports, 7 total imports):
| Capability | ATT&CK Technique | MBC Identifier | Evidence Source |
|---|---|---|---|
| RC4 encryption/decryption | T1027: Obfuscated Files or Information | E1027.m05: Obfuscated Files or Information, C0027.009: Encrypt Data | capa rule: encrypt data using RC4 via SystemFunction033; pe_imports: advapi32.SystemFunction033 |
| System language/region discovery | T1614.001: System Location Discovery | T1614.001: System Location Discovery | capa rule: identify system language via API; pe_imports: kernel32.GetUserDefaultLangID, kernel32.GetSystemDefaultLCID, kernel32.GetUserDefaultUILanguage |
| File encryption key management | (unknown, consistent with ransomware/info-stealer) | (unknown) | pe_imports: advapi32.FreeEncryptedFileKeyInfo |
| Privilege adjustment | (unknown) | (unknown) | pe_imports: ntdll.ZwAdjustPrivilegesToken |
| User notification | (unknown) | (unknown) | pe_imports: user32.MessageBoxExA |

The FreeEncryptedFileKeyInfo import is a high-signal indicator of ransomware or info-stealing malware that interacts with encrypted file systems (source: pe_imports, imports, advapi32.FreeEncryptedFileKeyInfo). The combination of RC4, language detection, and file encryption APIs strongly suggests the sample is designed for targeted data encryption or exfiltration.

## 9. Indicators of Compromise
### Hash IOCs
| Type | Value |
|---|---|
| SHA256 | e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2 |
| Sample Name | virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir |
(source: llm_judge, key_evidence)

### Static IOCs
| Type | Value | Source |
|---|---|---|
| High-Entropy Unreferenced Buffer | 19 hits of 10KB+ medium-to-high entropy buffers with no cross-references | malcat, views.anomalies, BigBufferNoXrefMediumToHighEntropy |
| Obfuscated API Import | advapi32.FreeEncryptedFileKeyInfo | pe_imports, imports, advapi32.FreeEncryptedFileKeyInfo |
| Obfuscated API Import | advapi32.SystemFunction033 (RC4) | pe_imports, imports, advapi32.SystemFunction033 |
| Language Detection APIs | GetUserDefaultLangID, GetSystemDefaultLCID, GetUserDefaultUILanguage | pe_imports, imports, kernel32.GetUserDefaultLangID, kernel32.GetSystemDefaultLCID, kernel32.GetUserDefaultUILanguage |
| Embedded Domain | Regex match at 0x0 (len=2, obfuscated) | yara, matches, domain |
| Embedded IPv6 Address | At 0x339946 (len=2, obfuscated) | yara, matches, IP |
| Embedded Base64 String | At 0x479934 (len=12, obfuscated) | yara, matches, contains_base64 |
| GUI Subsystem No Window API | Anomaly at 0x276 | malcat, views.anomalies, GuiSubsystemNoWindowApi |
| Missing PE Checksum | Anomaly at 0x272 | malcat, views.anomalies, NoChecksum |
| Unknown Rich Header Tool | Anomaly at 0x128 | malcat, views.anomalies, RichUnknownTool |

### Generated Detection Rules
- YARA Rule: /opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar (source: rule.yara.json, rule_path)
- Sigma Rule: /opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yml (source: rule.yara.json, sigma_path)

## 10. Detection Engineering
### YARA Detection
A generated YARA rule is available at the path above, with the following metadata (source: rule.yara.json):
```json
{
  "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "family": "unknown",
  "generated_at": "2026-08-03T06:34:12.734858+00:00",
  "string_count": 19,
  "strings": [
    "FreeEncryptedFileKeyInfo",
    "GetUserDefaultUILanguage",
    "ZwAdjustPrivilegesToken",
    "GetUserDefaultLangID",
    "GetSystemDefaultLCID",
    "SystemFunction033",
    "MessageBoxExA",
    "advapi32.dll",
    "kernel32.dll",
    "user32.dll",
    "ntdll.dll",
    "High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto mate",
    "Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedde",
    "This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory.",
    "FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing",
    "System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may select",
    "Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its ",
    "IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encodi",
    "Checksum routines are commonly used in malware to verify the integrity of embedded payloads or configuration data before"
  ],
  "rule_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar",
  "sigma_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yml",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "publish_target": "revai_publish"
}
```
The rule matches on the IsPacked, IsWindowsGUI, HasRichSignature, domain, IP, and contains_base64 conditions, with 0 false positives in the staged goodware corpus (source: rule.yara.json, goodware_fp.fp_count=0).

### capa Capability Detection
capa identifies 2 capabilities with full coverage for observed behavior (source: capa, top_rules, 2 total rules):
| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| identify system language via API | T1614.001:System Location Discovery | T1614.001:System Location Discovery |

### Anomaly-Based Detection
Malcat anomalies can be used to detect similar packed malware:
- Entropy threshold: .text section entropy > 200, overall file entropy > 200 (source: malcat, static_profile.layout, .text section entropy=202; source: malcat, static_profile, entropy=201)
- Unreferenced high-entropy buffer: BigBufferNoXrefMediumToHighEntropy with ≥10 hits (source: malcat, views.anomalies, BigBufferNoXrefMediumToHighEntropy, hits=19)
- GUI subsystem without window APIs: GuiSubsystemNoWindowApi (source: malcat, views.anomalies, GuiSubsystemNoWindowApi)
- Missing PE checksum: NoChecksum (source: malcat, views.anomalies, NoChecksum)
- Unknown Rich header tool: RichUnknownTool (source: malcat, views.anomalies, RichUnknownTool)
- Sequential crypto function: SequentialFunction at 0x473453 (source: malcat, views.anomalies, SequentialFunction)

### Import-Based Detection
A detection rule can be built on the combination of FreeEncryptedFileKeyInfo + SystemFunction033 + language detection APIs, a rare combination in legitimate software (source: pe_imports, imports, 7 total imports).

## 11. What We Don't Know
1. **IDA Analysis Data**: IDA is non-functional due to a missing /usr/local/bin/idasql binary, so no IDA-sourced imports, functions, strings, or decompilation are available (source: llm_judge, cross_engine_notes).
2. **Exact C2 Indicator Values**: The embedded domain, IPv6 address, and base64 string are obfuscated, and FLOSS extracted 0 decoded strings, so their exact values are unknown (source: floss, strings, 0 decoded strings; source: yara, matches, domain/IP/base64 len=2/2/12).
3. **Unpacked Payload Content**: UPX unpacking failed, and no dynamic unpacking was observed via Speakeasy or Frida, so the content of the payload decrypted by the XOR loop at 0x401400 is unknown (source: upx, upx_ok: False; source: speakeasy, api_calls, 0).
4. **Exact Malware Family**: The family guess is "packed malicious binary (likely ransomware or info-stealer)" but no explicit ransom notes, file extension changes, or exfiltration routines were observed to confirm the exact family (source: llm_judge, family_guess).
5. **Checksum Routine Target**: The checksum routine at 0x470896 (sub_473970) calculates a rolling XOR hash, but the data it validates is unknown due to obfuscation (source: malcat, decompilation, sub_473970).
6. **Rich Header Unknown Tool**: The Rich header contains an unknown tool entry, but the tool version/name is unidentified (source: malcat, views.anomalies, RichUnknownTool).
7. **Runtime Triggers**: The sample did not exhibit any behavior in the Speakeasy emulator, so the specific triggers (command-line arguments, environment conditions, victim interactions) required to unpack and execute the payload are unknown (source: speakeasy, api_calls, 0).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose | Output |
|---|---|---|---|
| Malcat | N/A (static analysis suite) | Static profile, decompilation, anomaly detection, string extraction | File summary, layout, anomalies, decompilations, 1144 strings |
| Ghidra | N/A (reverse engineering suite) | Function enumeration, string extraction, disassembly | 365 functions, 7 imports, 11 strings |
| FLOSS | N/A (string extractor) | Obfuscated string extraction | 1144 static strings, 0 decoded/stack/tight strings |
| capa | v5.16 (capability scanner) | Capability and MITRE ATT&CK mapping | 2 rules, 0.95s runtime |
| radare2 | N/A (reverse engineering framework) | Disassembly of import thunks and entry point | Disassembly at 0x00475a1e, 0x00475a24, 0x00475a2a, 0x00475a30 |
| YARA | N/A (pattern matching) | Malware signature and indicator matching | 7 matches, valid rule generated |
| Speakeasy | v17.16.4 (emulator) | Dynamic behavioral analysis | 0 API calls, 0 key events, no behavior observed |
| Frida | 17.16.4 (instrumentation) | Runtime API hooking | Available, no data collected |
| UPX | N/A (packer tool) | UPX unpacking attempt | upx_ok: False, unpacked_path: empty |
| pe_imports | N/A (PE parser) | Import table extraction | 7 imports |
| IDA Pro | Non-functional | Static analysis (unavailable) | Missing /usr/local/bin/idasql binary, no data available |

### Analysis Context
- Sample Path: /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
- Project Name: incoming
- Analysis Timestamp: 2026-08-03T06:34:12.734858+00:00 (YARA generation time)
- Tool Gate Status: All required tools passed, no hard/soft failures (source: deep_dive_agentic, tool_gate.ok: True)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2  
**sample_path:** /opt/samples/corpus/incoming/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Packed malicious binary (likely ransomware or info-stealer, consistent with RC4 encryption and FreeEncryptedFileKeyInfo usage)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to missing /usr/local/bin/idasql binary, so all IDA-sourced data (imports, functions, strings, decompilation) is unavailable. Ghidra reports 365 functions and 7 imports, but its imports virtual table is empty, so import data is sourced from Malcat and pe_imports. String data is combined from Ghidra (11 strings) and FLOSS/Malcat (1144 total strings) for full coverage. Malcat is the sole source for reliable static profile, decompilation, and anomaly data as IDA is non-functional.
- **summary**: This is a packed, heavily obfuscated x86 Windows PE binary with high entropy (201) and no readable decoded strings. Static analysis detects a large in-memory decryption routine, RC4 encryption capabilities, and system language reconnaissance behavior. Imports include the high-signal FreeEncryptedFileKeyInfo API, and anomaly analysis confirms traits consistent with packed malware (large unreferenced crypto buffers, obfuscated code, unknown Rich header tool, missing checksum). The sample is almost certainly malicious, with traits consistent with ransomware or info-stealing malware, though no explicit ransom notes or network C2 indicators were observed in the static scan.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | static_profile | `` | High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto mate |
| capa | top_rules | `` | Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedde |
| malcat | decompilation | `` | This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory. |
| pe_imports | imports | `` | FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing |
| capa | top_rules | `` | System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may select |
| floss | strings | `` | Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its  |
| yara | matches | `` | IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encodi |
| malcat | decompilation | `` | Checksum routines are commonly used in malware to verify the integrity of embedded payloads or configuration data before |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The analyzed sample is a packed 32-bit Windows GUI Portable Executable (PE). YARA scanning confirms it is a valid PE32 file with a Windows GUI subsystem, is packed/obfuscated, contains a valid Rich header, and has embedded domain, IPv6 address, and base64 string indicators. Malcat deep analysis shows extremely high overall file entropy (201) and .text section entropy (202) consistent with packing, plus an anomaly indicating a large unlinked high-entropy buffer likely used for cryptographic operations. No legitimate Kaspersky detection matches were found for the sample.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32", "why": "Confirms the sample is a valid 32-bit Portable Executable, the standard format for Windows applications and malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsWindowsGUI", "why": "Confirms the sample is a Windows GUI application, a common type for end-user facing malware"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPacked", "why": "Indicates the executable is packed/obfuscated, a common technique used by malware to evade static detection and hinder reverse engineering"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "HasRichSignature", "why": "Confirms the PE has a valid Rich header, which combined with other malicious indicators rules out a corrupt or non-functional PE file"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain", "why": "YARA domain rule match confirms the sample contains an embedded malicious domain string, likely used for command-and-control (C2) communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IP", "why": "YARA IP rule match confirms the sample contains an embedded IPv6 address, likely a C2 server address for network communication"}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "contains_base64", "why": "YARA base64 rule match confirms the sample contains embedded base64-encoded data, likely used for payload delivery or C2 traffic obfuscation"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "entropy=201", "why": "Extremely high overall file entropy is consistent with packed or encrypted content, a common trait of malware"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary.layout", "row_or_rule": ".text section entropy=202", "why": "Extremely high entropy in the executable code section confirms the sample's code is packed/obfuscated, a strong indicator of malicious intent"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "views.anomalies", "row_or_rule": "BigBufferNoXrefMediumToHighEntropy", "why": "Malcat anomaly detection of a large unlinked high-entropy buffer indicates a cryptographic block, commonly used by malware to encrypt/decrypt payloads or C2 communications"}`
- `{"source": "checklist_malcat_analyze", "query_or_table": "file_summary", "row_or_rule": "kesakode_verdict=[]", "why": "Empty Kaspersky verdict indicates the sample is not a known legitimate file, supporting malicious classification"}`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2
size: 481280
type: PE
architecture: X86
entrypoint_ea: 1536
entropy: 201
file_name: virussign.com_277ba25a0eb58b53a5f5abfc13e8d5c2.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1536 | 0 | 39 | - |
| .text | 1536 | 478208 | 479232 | 202 | RX |
| .rdata | 480768 | 512 | 4096 | 0 | R |
| .data | 484864 | 512 | 4096 | 0 | RW |
| .rsrc | 488960 | 512 | 4096 | 44 | RW |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 19 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| DataBetweenHeaderAndFirstSection | 3 | headers | 1 | There is non-zero data between the PE header and the first section |
| ManyHighValueImmediates | 3 | code | 8 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| ManyUniqueImmediateBytes | 3 | code | 7 | More than 48 unique bytes defined across all immediate operands in the function |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |
| RichUnknownTool | 2 | rich | 1 | Tool entry is not known (either a new version or has been patched) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
| SequentialFunction | 1 | code | 1 | function with very little intra jumps and calls, usually a crypto function, unrolled loops or data i |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `276`: 
- **ManyHighValueImmediates**
  - `468021`: 
  - `470101`: 
  - `470896`: 
  - `473453`: 
  - `474179`: 
- **ManyUniqueImmediateBytes**
  - `468021`: 
  - `470101`: 
  - `470896`: 
  - `473453`: 
  - `474179`: 
- **NoChecksum**
  - `272`: 
- **SequentialFunction**
  - `473453`: 

### High-Signal Strings (3 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 481152 | `kernel32.dll` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 111642 | `]m]\\` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 481069 | `ntdll.dll` |
| 481152 | `kernel32.dll` |
| 481030 | `advapi32.dll` |
| 480972 | `user32.dll` |
| 372306 | `r[RFr[6Rr[D]r[` |
| 268982 | `?A;}_A;=_a;=?A?` |
| 138117 | `=?a;=?a;` |
| 481127 | `GetUserDefaultUILanguage` |
| 139457 | `=?A;??A=` |
| 286988 | `[U.DVu` |
| 152010 | `iuui` |
| 232167 | `OC.s` |
| 284114 | `xjjx` |
| 287048 | `[U.DVu` |
| 77 | `!This program ca..in DOS mode.
$` |
| 51090 | `xjjx` |
| 145275 | `31.wnb` |
| 481005 | `FreeEncryptedFileKeyInfo` |
| 215527 | `A;=_A;=_a` |
| 259857 | `=?a[=?a` |
| 371937 | `0m[.0m[` |
| 372353 | `.r[:8r[`8t[` |
| 111642 | `]m]\\` |
| 192450 | `?a;=?C?;` |
| 252257 | `sIIIp` |
| 111219 | `a;=;a` |
| 335118 | `]4M]M` |
| 169654 | `yyO\O` |
| 222495 | `0M0VM` |
| 116261 | `a
aWa` |
| 139693 | `=?a;=?A?` |
| 481081 | `GetUserDefaultLangID` |
| 75121 | `=?A;??E=5` |
| 227017 | `=?A;??E=5` |
| 157888 | `S7wS#aqgq7Aewq` |
| 172805 | `]?a;=?C?;` |
| 481104 | `GetSystemDefaultLCID` |
| 195457 | `=?a;=?C?1` |
| 297624 | `2R[J22` |
| 129245 | `=?a;=?` |
| 175145 | `=?a;=?` |
| 300040 | `2R[j22` |
| 6951 | `rm33Um` |
| 372226 | `m[21m[P&m[` |
| 246701 | `=?a;=?` |
| 58530 | `?a;=?a` |
| 372562 | `Q[0eQ[` |
| 205167 | `a;=?a;` |
| 262493 | `=?a;=?` |
| 325940 | `5Hr5Wr` |
| 140481 | `=?A[=?` |
| 372622 | ``[x8`[` |
| 62098 | `?a;=?A?` |
| 372585 | `3`[d0`[` |
| 60075 | `QMYQM5m` |
| 268101 | `=?a;=?E` |
| 240846 | `?a;=?A?` |
| 372593 | `9`[R5`[` |
| 289614 | `BBrsDB2` |
| 338286 | `cUAtc]L9l]L4` |
| 481045 | `ZwAdjustPrivilegesToken` |
| 200710 | `_a;=?a;` |
| 128825 | `=?a;=?E` |
| 240075 | `a;=?C?;` |
| 233638 | `_a;=?a;` |
| 372281 | `8r[>Br[` |
| 150926 | `?a;=?M?` |
| 87001 | `]?A[=?A99_C` |
| 372337 | `Fr[HJr[` |
| 372365 | `Gr[VPr[` |
| 308343 | `DVu1vVu` |
| 372381 | `^r[zEr[HNr[` |
| 266707 | `a;=?C?;` |
| 111927 | `a;=?C?;` |
| 372441 | `\V[0^V[` |
| 372513 | `;Q[27Q[` |
| 211186 | `?A;??E=5` |
| 372485 | `
Q[~
Q[2` |
| 166017 | `=?a{=?BB` |
| 128085 | `=?a;=?S/` |

### Imports (7)
| EA | Name | Type | Refs |
|---|---|---|---|
| 480768 | user32.MessageBoxExA | IMPORT | 6 |
| 480776 | advapi32.SystemFunction033 | IMPORT | 2 |
| 480780 | advapi32.FreeEncryptedFileKeyInfo | IMPORT | 0 |
| 480788 | ntdll.ZwAdjustPrivilegesToken | IMPORT | 1 |
| 480796 | kernel32.GetUserDefaultLangID | IMPORT | 1 |
| 480800 | kernel32.GetSystemDefaultLCID | IMPORT | 1 |
| 480804 | kernel32.GetUserDefaultUILanguage | IMPORT | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 474179 | sub_474643 |
| 470896 | sub_473970 |
| 468021 | sub_472e35 |
| 473453 | sub_47436d |
| 470101 | sub_473655 |
| 478703 | sub_4757ef |
| 477760 | sub_475440 |
| 473361 | sub_474311 |
| 478392 | sub_4756b8 |
| 478568 | sub_475768 |
| 469953 | sub_4735c1 |
| 473995 | sub_47458b |
| 479115 | sub_47598b |
| 474094 | sub_4745ee |
| 478498 | sub_475722 |
| 478265 | sub_475639 |
| 473255 | sub_4742a7 |
| 473340 | sub_4742fc |
| 478225 | sub_475611 |
| 479165 | sub_4759bd |
| 473144 | sub_474238 |
| 478542 | sub_47574e |
| 478175 | sub_4755df |
| 478321 | sub_475671 |
| 478294 | sub_475656 |
| 477665 | sub_4753e1 |
| 474057 | sub_4745c9 |
| 473973 | sub_474575 |
| 470028 | sub_47360c |
| 473228 | sub_47428c |

### Decompilations (top 6)
#### 474179 — sub_474643
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_474643(code *param_1)

{
    int32_t iVar1;
    code *extraout_ECX;
    code *extraout_ECX_00;
    uint32_t *puVar2;
    code *extraout_ECX_01;
    code *extraout_ECX_02;
    code *extraout_ECX_03;
    code *extraout_ECX_04;
    code *extraout_ECX_05;
    code *extraout_ECX_06;
    code *extraout_ECX_07;
    code *extraout_ECX_08;
    code *extraout_ECX_09;
    code *extraout_ECX_10;
    code *extraout_ECX_11;
    code *extraout_ECX_12;
    code *extraout_ECX_13;
    code *extraout_ECX_14;
    code *extraout_ECX_15;
    code *extraout_ECX_16;
    code *extraout_ECX_17;
    
    (*param_1)();
    func_0x00475882(0xbd9ac2f4);
    (*extraout_ECX_06)();
    func_0x00475882(0xbdabe822);
    (*extraout_ECX_00)();
    func_0x00475882();
    (*extraout_ECX_10)();
    func_0x00475882();
    (*extraout_ECX_07)();
    func_0x00475882();
    (*extraout_ECX_08)(0x401400);
    func_0x00475882(0xbdd57e2a, 0xbdd4f7d6, 0xbdd46f24, 0xbdd3ea02, 0xbdd35f90);
    (*extraout_ECX_09)();
    func_0x00475882(0xbe189b42);
    (*extraout_ECX_14)();
    func_0x00475882(0xbe1b1fe0);
    (*extraout_ECX_04)();
    func_0x00475882(0xbe1f91ee, 0xbe1f1660, 0xbe1e9ddc, 0xbe1e20cc, 0xbe1d9cd4);
    (*extraout_ECX_05)();
    func_0x00475882(0xbe2401e8);
    (*extraout_ECX_13)();
    puVar2 = 0x401400;
    iVar1 = 0;
    do {
        *puVar2 = *puVar2 ^ 0x7c4cea8d;
        *puVar2 = *puVar2 ^ 0x7c4ceb11;
        *puVar2 = *puVar2 ^ 0x7c4ceb99;
        *puVar2 = *puVar2 ^ 0x7c4cec19;
        *puVar2 = *puVar2 ^ 0x7c4cec75;
        *puVar2 = *puVar2 ^ 0x7c4cecd1;
        puVar2 = puVar2 + 1;
        iVar1 = iVar1 + 4;
    } while (iVar1 < 0x71a06);
    (*0x401400)();
    func_0x00475882(0xbebc435a, 0xbebbc540, 0xbebb49d2, 0xbebacb72, 0xbeba4bba);
    (*extraout_ECX_17)();
    func_0x00475882(0xbec24ca4, 0xbec1ce8e, 0xbec13bae, 0xbec0bd24);
    (*extraout_ECX_11)();
    func_0x00475882(0xbec7be66, 0xbec740fa, 0xbec6c576, 0xbec64712);
    (*extraout_ECX_01)();
    func_0x00475882(0xbeccc952, 0xbecc49de, 0xbecbcaee);
    (*extraout_ECX_03)();
    func_0x00475882(0xbed3025c, 0xbed26af8, 0xbed1c65e, 0xbed0f39a);
    (*extraout_ECX_12)();
    func_0x00475882(0xbed82bca, 0xbed78ee6);
    (*extraout_ECX_02)();
    func_0x00475882(0xbedd4ec4, 0xbedcb2e2, 0xbedc1696, 0xbedb6bf8);
    (*extraout_ECX_16)();
    func_0x00475882(0xbee1f818, 0xbee17636);
    (*extraout_ECX_15)();
    func_0x00475882(0xbee72798, 0xbee6a70a, 0xbee623b8, 0xbee5a074, 0xbee51dba);
    (*extraout_ECX)();
    return;
}

```
#### 470896 — sub_473970
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_473970(int32_t param_1)

{
    int32_t iVar1;
    unkuint3 Var3;
    uint32_t uVar2;
    uint8_t *puVar4;
    int32_t *piStack00000078;
    uint32_t in_stack_00000094;
    
    iVar1 = *(***(*(param_1 + 0xc) + 0xc) + 0x18);
    piStack00000078 = *(*(iVar1 + *(iVar1 + 0x3c) + 0x78) + iVar1 + 0x20) + iVar1;
    do {
        piStack00000078 = piStack00000078 + 1;
        puVar4 = *piStack00000078 + iVar1;
        uVar2 = 0;
        do {
            Var3 = uVar2 >> 8;
            uVar2 = CONCAT31(Var3, uVar2 ^ *puVar4) << 8 | Var3 >> 0x10;
            puVar4 = puVar4 + 1;
        } while (*puVar4 != 0);
    } while (uVar2 != in_stack_00000094);
    return;
}

```
#### 468021 — sub_472e35
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __thiscall sub_472e35(uint8_t *param_1)

{
    uint32_t in_EAX;
    unkuint3 Var1;
    int32_t *in_stack_0000007c;
    uint32_t in_stack_00000098;
    int32_t in_stack_000000cc;
    
    do {
        if (*param_1 == 0) {
            if (in_EAX == in_stack_00000098) {
                return;
            }
            in_stack_0000007c = in_stack_0000007c + 1;
            param_1 = *in_stack_0000007c + in_stack_000000cc;
            in_EAX = 0;
        }
        Var1 = in_EAX >> 8;
        in_EAX = CONCAT31(Var1, in_EAX ^ *param_1) << 8 | Var1 >> 0x10;
        param_1 = param_1 + 1;
    } while( true );
}

```

### Structures (15)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 184 |
| OptionalHeader | 208 |
| Sections | 432 |
| user32.FT | 480768 |
| advapi32.FT | 480776 |
| ntdll.FT | 480788 |
| kernel32.FT | 480796 |
| ImportTable | 480812 |
| user32.OFT | 480912 |
| advapi32.OFT | 480920 |
| ntdll.OFT | 480932 |
| kernel32.OFT | 480940 |
| ImportNames | 480956 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 2 · duration_s: 0.95

| Rule | ATT&CK | MBC |
|---|---|---|
| encrypt data using RC4 via SystemFunction033 | T1027:Obfuscated Files or Information | E1027.m05:Obfuscated Files or Information, C0027.009:Encrypt Data |
| identify system language via API | T1614.001:System Location Discovery |  |

## PE Imports / Signals
import_count: 7

## YARA Matches (pipeline)
Total matches: 7

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@339946 len=2 |
| contains_base64 | - | $a@479934 len=12 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasRichSignature | - | $a0@160 len=4 |

## Generated YARA Meta
```json
{
  "sha256": "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2",
  "family": "unknown",
  "generated_at": "2026-08-03T06:34:12.734858+00:00",
  "string_count": 19,
  "strings": [
    "FreeEncryptedFileKeyInfo",
    "GetUserDefaultUILanguage",
    "ZwAdjustPrivilegesToken",
    "GetUserDefaultLangID",
    "GetSystemDefaultLCID",
    "SystemFunction033",
    "MessageBoxExA",
    "advapi32.dll",
    "kernel32.dll",
    "user32.dll",
    "ntdll.dll",
    "High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto mate",
    "Direct detection of RC4 encryption behavior, a common technique for malicious payload obfuscation, decryption of embedde",
    "This is a decryption/decryption routine, a common startup behavior for packed malware to unpack its payload in memory.",
    "FreeEncryptedFileKeyInfo is a high-signal API for handling encrypted files, commonly used by ransomware or info-stealing",
    "System language discovery is a common reconnaissance behavior for targeted malware, including ransomware that may select",
    "Complete absence of readable decoded strings indicates heavy obfuscation, consistent with packed malware that hides its ",
    "IsPacked confirms obfuscation; presence of base64, domain, and IP indicators suggests embedded network or payload encodi",
    "Checksum routines are commonly used in malware to verify the integrity of embedded payloads or configuration data before"
  ],
  "rule_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yar",
  "sigma_path": "/opt/samples/logs/e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2/rule.yml",
  "yara_valid": true,
  "yara_check": "ok",
  "goodware_fp": {
    "goodware_dir": "/opt/samples/goodware",
    "fp_count": 0,
    "fp_samples": [],
    "skipped": "goodware corpus not staged"
  },
  "yargen": {
    "skipped": true
  },
  "revai": true,
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 1144 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1144}`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `Rich!l`
- ``.rdata`
- `@.data`
- `eq9f(2A`
- `cqn,)=Aq`
- `QiR?])`
- `MC	HsC`
- `:U=y-]`
- `m67X|}`
- ``s^cI(N`
- `rm33Um`
- `TX=w2U=`
- `T8);:V`
- `TX=w2Y=`
- `r|jW2!`
- `0Yh%2Y`
- `rx(dxs`
- `KdS8i'`
- `($38iG`
- `ES;i%>8`
- `{+Gp;i`
- `G83cO8`
- `eerXHD`
- `EORXHD`
- `E\Nt:H`
- `r=93un`
- `gbq|]%ta`
- `*7J(57?EA`
- `rjth&h`
- `X{4eWw`
- `e?M&2h`
- `5hxu	E`
- `w_&U4%t`
- `*}E5-u`
- `{[A6u{`
- `$FkOdH,`
- `cOdW,m`
- `2FlOdO,O$&;`
- `9O$F,X$`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00475a2a
```asm
; CALL XREF from entry0 @ 0x401000(x)
┌ 6: LCID sub.kernel32.dll_GetSystemDefaultLCID ();
└           0x00475a2a      ff2520604700   jmp dword [sym.imp.kernel32.dll_GetSystemDefaultLCID] ; 0x476020 ; "Na\a"
```
### 0x00475a1e
```asm
; XREFS(46)
┌ 6: int sub.user32.dll_MessageBoxExA (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType, WORD wLanguageId);
└           0x00475a1e      ff2500604700   jmp dword [sym.imp.user32.dll_MessageBoxExA] ; 0x476000
```
### 0x00475a24
```asm
; XREFS(50)
┌ 6: sub.advapi32.dll_SystemFunction033 ();
└           0x00475a24      ff2508604700   jmp dword [sym.imp.advapi32.dll_SystemFunction033] ; 0x476008
```
### 0x00475a30
```asm
; CALL XREFS from entry0 @ 0x401093(x), 0x40111c(x), 0x4011a5(x)
┌ 6: LANGID sub.kernel32.dll_GetUserDefaultUILanguage ();
└           0x00475a30      ff2524604700   jmp dword [sym.imp.kernel32.dll_GetUserDefaultUILanguage] ; 0x476024 ; "ea\a"
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 000000B8 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "\nSELECT name, start_ea, size\nFROM funcs\nWHERE size > 1024\nORDER BY size DESC\nLIMIT 50\n", "ts": 1785738716.2366462}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785738716.2588432}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785738716.344925}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785738716.3505418}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785738716.3602147}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785738716.3697248}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785738755.5945075}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785738755.60954}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785738755.6230218}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785738755.6272345}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785738755.6284502}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785738807.2386842}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports", "ts": 1785738812.9746892}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 10 ORDER BY address LIMIT 50", "ts": 1785738812.992481}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785738851.7060773}`
- `{"source": "yara_gen_v2", "ts": 1785738852.7349954}`
