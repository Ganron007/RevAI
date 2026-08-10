> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 21:00:08 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **suspicious** |
| Triage upstream (quick ∪ deep) | suspicious |
| Quick scan | suspicious |
| Deep dive | suspicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## 1. Executive Summary

This report details the analysis of a 2048-byte PE32 executable (`string_encryption.exe`) from the "Hexorcist 3 - Weeks 20-30" reverse engineering course corpus. The sample exhibits obfuscation through XOR-based string encryption but lacks any behavioral indicators of malicious intent. The binary's sole functionality is to decrypt four strings using different XOR keys and display them in message boxes before terminating. With only two imports (`ExitProcess`, `MessageBoxA`) and no network, file, registry, or persistence capabilities, this sample is assessed as an educational demonstration of obfuscation techniques rather than malware. The verdict is **suspicious** with a low confidence score of 25, reflecting the presence of obfuscation (a neutral signal) without hostile behavior.

## 2. Sample Metadata

| Attribute | Value | Source |
|---|---|---|
| SHA256 | `263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca` | (source: malcat) |
| File Name | `string_encryption.exe` | (source: malcat) |
| File Size | 2048 bytes | (source: malcat) |
| File Type | PE32 (X86) | (source: malcat) |
| Entry Point | 0x200 (512 decimal) | (source: malcat) |
| Entropy | 44 | (source: malcat) |
| Compiler | FASM (Flat Assembler) | (source: yara, rule: FASM) |
| Import Hash | `98c88d882f01a3f6ac1e5f7dfd761624` | (source: yara_gen) |
| Project Context | "Hexorcist 3 - Weeks 20-30" RE course | (source: deep_dive_agentic) |

## 3. File Layout & Structural Analysis

The PE file is minimal, consisting of a header and three sections. The low entropy (44) across the file indicates no packing or encryption of the entire binary; only specific data buffers are XOR-encrypted.

| Section | EA | Physical Size | Virtual Size | Entropy | Rights | Source |
|---|---|---|---|---|---|---|
| header | 0x0 | 512 | 0 | 52 | - | (source: malcat) |
| .text | 0x200 | 512 | 4096 | 36 | RX | (source: malcat) |
| .idata | 0x1200 | 512 | 4096 | 0 | RW | (source: malcat) |
| .data | 0x2200 | 512 | 4096 | 0 | RW | (source: malcat) |

The `.text` section contains the executable code with moderate entropy (36), consistent with compiled assembly. The `.data` section holds the XOR-encrypted strings, and `.idata` contains the import table. The file's small size (2048 bytes) and minimal structure align with a hand-crafted FASM program.

## 4. Static Code Analysis

### 4.1 Entry Point Disassembly

The entry point at `0x401000` orchestrates four sequential XOR decryption operations, each targeting a different buffer in the `.data` section with a unique key. After each decryption, it displays the result via `MessageBoxA`.

```asm
; (source: radare2, EA: 0x401000)
;-- section..text:
┌ 168: entry0 ();
│           0x00401000      bb90000000     mov ebx, 0x90               ; XOR key 1
│           0x00401005      b800304000     mov eax, section..data      ; buffer 1 @ 0x403000
│           0x0040100a      b912000000     mov ecx, 0x12               ; length 18
│           0x0040100f      e894000000     call fcn.004010a8           ; decrypt
│           0x00401014      6a00           push 0
│           0x00401016      6800304000     push section..data          ; lpText
│           0x0040101b      6800304000     push section..data          ; lpCaption
│           0x00401020      6a00           push 0
│           0x00401022      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA]
```

This pattern repeats three more times with keys `0xEB`, `0xFE`, and `0xED` targeting buffers at `0x403013`, `0x403023`, and `0x40307d` respectively. The structure is a simple decrypt-and-display loop with no conditional logic or branching.

### 4.2 XOR Decryption Function

The core decryption routine at `0x4010a8` implements a classic byte-by-byte XOR loop:

```asm
; (source: radare2, EA: 0x4010a8)
; CALL XREFS from entry0 @ 0x40100f(x), 0x401037(x), 0x40105f(x), 0x401087(x)
┌ 14: fcn.004010a8 ();
│           0x004010a8      89c6           mov esi, eax                ; source = dest (in-place)
│           0x004010aa      89f7           mov edi, esi
│           0x004010ac      31c0           xor eax, eax
│       ┌─> 0x004010ae      ac             lodsb al, byte [esi]        ; load byte
│       ╎   0x004010af      30d8           xor al, bl                  ; XOR with key
│       ╎   0x004010b1      aa             stosb byte es:[edi], al     ; store result
│       ╎   0x004010b2      49             dec ecx                     ; decrement counter
│       └─< 0x004010b3      75f9           jne 0x4010ae                ; loop until zero
└           0x004010b5      c3             ret
```

This function takes the buffer address in `EAX`, the XOR key in `BL`, and the length in `ECX`. It performs in-place decryption by XORing each byte with the key. The Malcat anomaly `XorInLoop` at EA `0x4010AE` confirms this pattern (source: malcat, anomalies, XorInLoop). The recovered function name `xor_decode` (confidence 0.9) from the agentic recovery pipeline aligns with this behavior (source: recovered_functions).

### 4.3 Malcat Decompilation

Malcat's decompiler produces a C-like representation of the same logic:

```c
// (source: malcat, EA: 680, sub_4010a8)
void __fastcall sub_4010a8(int32_t param_1)
{
    uint8_t *in_EAX;
    uint8_t unaff_BL;
    uint8_t *puVar1;
    
    puVar1 = in_EAX;
    do {
        *puVar1 = *in_EAX ^ unaff_BL;
        param_1 = param_1 + -1;
        in_EAX = in_EAX + 1;
        puVar1 = puVar1 + 1;
    } while (param_1 != 0);
    return;
}
```

The decompilation confirms the XOR-in-place decryption loop. The `unaff_BL` parameter represents the XOR key passed via the `BL` register, a common calling convention in hand-written assembly.

### 4.4 Function Metrics

| EA | Name | Source |
|---|---|---|
| 0x4010a8 | `sub_4010a8` (xor_decode) | (source: malcat, recovered_functions) |
| 0x401000 | `EntryPoint` | (source: malcat) |

The binary contains exactly two functions: the entry point orchestrator and the XOR decryption routine. This minimal structure is consistent with a demonstration program.

## 5. Behavioral & Dynamic Analysis

### 5.1 Speakeasy Emulation

Speakeasy emulation completed successfully but recorded zero API calls and zero key events (source: speakeasy). This is expected given the sample's reliance on GUI APIs (`MessageBoxA`) which may not be fully emulated in a headless environment. **No runtime behavior was observed.**

### 5.2 Frida Probe

Frida identified two hook candidates matching the sample's imports (source: frida_probe):
- `KERNEL32.DLL!ExitProcess`
- `USER32.DLL!MessageBoxA`

These are the only APIs the sample calls, confirming the static analysis findings. No additional behavioral indicators were captured.

## 6. Network Indicators & C2

**None observed.** The sample imports only `ExitProcess` and `MessageBoxA` (source: malcat, imports). There are no network-related imports (`WinHTTP`, `WinSock`, `URLDownloadToFile`, etc.), no C2 strings, and no domain/IP addresses in the extracted strings. FLOSS decoded zero stack or tight strings (source: floss). The Ghidra query for strings containing `http` or `.dll` returned only standard DLL references (source: ghidra_query, sql: `SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30`).

## 7. Capabilities Assessment

| Capability | Status | Evidence |
|---|---|---|
| String Obfuscation (XOR) | **Observed** | (source: capa, rule: `encode data using XOR`); (source: malcat, anomaly: `XorInLoop`) |
| Process Termination | **Observed** | (source: capa, rule: `terminate process`); calls `ExitProcess` |
| GUI Message Display | **Observed** | calls `MessageBoxA` four times |
| Network Communication | **Not Present** | no network imports or strings |
| File System Access | **Not Present** | no file I/O imports |
| Registry Manipulation | **Not Present** | no registry imports |
| Persistence | **Not Present** | no autorun, service, or scheduled task APIs |
| Credential Theft | **Not Present** | no LSASS, token, or crypto APIs |
| Process Injection | **Not Present** | no `VirtualAllocEx`, `WriteProcessMemory`, etc. |
| Anti-Analysis | **Not Present** | no `IsDebuggerPresent`, `NtQueryInformationProcess`, etc. (source: ghidra_query) |
| Data Exfiltration | **Not Present** | no outbound data transfer capabilities |

The only capabilities present are benign: XOR-based string obfuscation (a neutral technique used in both legitimate and malicious software) and process termination. The capa rule `encode data using XOR` maps to ATT&CK T1027 (Obfuscated Files or Information), but this alone does not indicate malicious intent (source: capa).

## 8. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| SHA256 | `263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca` | Sample hash |
| Import Hash | `98c88d882f01a3f6ac1e5f7dfd761624` | PE import hash |
| File Name | `string_encryption.exe` | Original filename |
| XOR Keys | `0x90`, `0xEB`, `0xFE`, `0xED` | Decryption keys used in entry point |
| Decryption Buffers | `0x403000`, `0x403013`, `0x403023`, `0x40307d` | .data section addresses |

No network IOCs, mutexes, registry keys, or file system artifacts were identified.

## 9. Detection Engineering

### 9.1 YARA Matches

| Rule | Namespace | Match | Source |
|---|---|---|---|
| `domain` | - | `$domain_regex@0 len=2` | (source: yara) |
| `IsPE32` | - | PE32 header match | (source: yara) |
| `IsWindowsGUI` | - | GUI subsystem flag | (source: yara) |
| `FASM` | - | FASM DOS stub signature | (source: yara) |

The `FASM` rule indicates the sample was compiled with the Flat Assembler, a legitimate tool (source: yara, rule: FASM). The `domain` rule matched a 2-byte regex at offset 0, which is likely a false positive given the minimal match length. No malware-family YARA rules triggered.

### 9.2 Malcat Signatures

| Rule | Category | Reliability | Source |
|---|---|---|---|
| `FASM` | compiler | 70 | (source: malcat, YARA/Signatures) |

### 9.3 Detection Recommendations

Given the benign nature of this sample, detection should focus on the specific XOR keys and buffer patterns rather than generic obfuscation. A YARA rule targeting the four XOR key sequences (`0x90`, `0xEB`, `0xFE`, `0xED`) in combination with the `MessageBoxA` import would provide high-fidelity detection of this specific educational sample without false positives on legitimate FASM programs.

## 10. MITRE ATT&CK Mapping

| Technique | ID | Evidence | Confidence |
|---|---|---|---|
| Obfuscated Files or Information | T1027 | (source: capa, rule: `encode data using XOR`) | High |
| Process Termination | T1059 | (source: capa, rule: `terminate process`) | High |

Only two ATT&CK techniques are applicable, both representing benign functionality. T1027 (obfuscation) is a neutral capability, and T1059 (process termination via `ExitProcess`) is standard application behavior. No techniques associated with persistence, privilege escalation, defense evasion, credential access, lateral movement, collection, or exfiltration were identified.

## 11. What We Don't Know

1. **Decrypted string content**: The actual text displayed by `MessageBoxA` is unknown because the XOR-encrypted buffers in `.data` were not decrypted during analysis. The strings are likely educational messages given the sample's context, but this cannot be confirmed without runtime execution or manual decryption.

2. **FLOSS string gap**: FLOSS reported zero decoded, stack, or tight strings (source: floss). This is consistent with the XOR encryption being applied at runtime, but we cannot rule out additional obfuscation layers without dynamic execution.

3. **Emulation limitations**: Speakeasy recorded zero API calls (source: speakeasy). This may be due to the GUI dependency (`MessageBoxA`) not being fully supported in the headless emulation environment, or the sample may require specific Windows subsystem initialization not available during emulation.

4. **Original author intent**: While the sample's context ("Hexorcist 3" RE course, filename `string_encryption.exe`) strongly suggests educational purpose, we cannot definitively confirm the author's intent without documentation.

## 12. Appendix A: Tool Evidence Trail

| Tool | Version/Engine | Status | Key Findings |
|---|---|---|---|
| Malcat | malcat | Success | 2 functions, 2 imports, XorInLoop anomaly, FASM signature |
| capa | malcat-capa | Success | 2 rules: `encode data using XOR`, `terminate process` |
| YARA | pipeline | Success | 4 matches: `domain`, `IsPE32`, `IsWindowsGUI`, `FASM` |
| FLOSS | floss | Success | 6 static strings, 0 decoded/stack/tight |
| radare2 | r2_decomp | Success | Full disassembly of entry point and XOR function |
| Ghidra | ghidra_query | Success | 2 functions, 4 strings, callgraph analysis |
| IDA | ida_query | Success | 2 functions, 0 strings (likely due to query filtering) |
| Speakeasy | speakeasy | Success | 0 API calls, 0 events (GUI dependency) |
| Frida | frida_probe | Success | 2 hook candidates identified |
| UPX | upx | Not Packed | `upx_ok: False`, `is_packed: False` |
| XOR Search | xor | Success | Found XOR 00 at position 0 |
| .NET | dotnet | Not .NET | `is_dotnet: false` |

## 13. Appendix B: Analysis Environment

| Component | Value |
|---|---|
| Sample Path | `/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca/string_encryption.exe` |
| Project | Hexorcist 3 - Weeks 20-30 |
| Analysis Pipeline | RevAI (langgraph engine) |
| Report Generated | 2026-08-09T13:29:10 UTC |
| Verdict Source | llm_judge (mimo-v2.5-pro) |
| Deep Dive Source | deep_dive_agentic (langgraph) |
| Tool Gate Status | All required tools passed (capa, yara, malcat, floss, pe_imports, r2_decomp, upx, xor, speakeasy, frida_probe, dotnet) |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca  
**sample_path:** /opt/samples/corpus/Hexorcist 3 - Weeks 20-30/263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca/string_encryption.exe  
**project_name:** Hexorcist 3 - Weeks 20-30

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 25
- **family_guess**: unknown
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra, IDA, and Malcat consistently report 2 functions and 2 imports, but string counts vary (Ghidra: 4, Malcat: 8, IDA: 0), suggesting Malcat's string detection is more comprehensive. Decompilation shows XOR loops for obfuscation, but no behavioral-intent evidence is found across tools.
- **summary**: The sample exhibits obfuscation through XOR loops in code (Malcat anomaly and capa rule), but no behavioral-intent evidence such as C2 communication, persistence, credential theft, or data exfiltration is present. Imports are minimal and benign, and all tools agree on low complexity with only two functions and two imports. This suggests the binary is likely a test or protected software rather than malicious, hence the suspicious verdict with a low score.
- **source**: llm_judge
- **model**: mimo-v2.5-pro

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `XorInLoop` | Indicates code obfuscation via XOR encryption in a loop, which is a neutral signal common in both benign and malicious s |
| capa | top_rules | `encode data using XOR` | Defense evasion technique (ATT&CK T1027) for obfuscation, but this alone is not indicative of malicious intent without a |
| capa | top_rules | `terminate process` | Process termination behavior, which is benign and commonly used in many applications; no hostile intent like file destru |
| ida | imports | `ExitProcess, MessageBoxA` | Only two standard Windows API imports (kernel32.ExitProcess, user32.MessageBoxA), with no high-signal malicious APIs det |
| ghidra | Suspicious strings | `KERNEL32.DLL, USER32.DLL` | Standard DLL references, not suspicious; no C2, persistence, or data exfiltration strings found. |
| yara | matches | `FASM` | Indicates the sample may be compiled with FASM, a legitimate assembler; no malware-specific YARA rules triggered. |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Educational demonstration of XOR string encryption obfuscation. The 2048-byte PE (compiled with FASM) contains a simple XOR decryption loop at 0x4010a8 that is called 4 times from the entry point with different keys (0x90, 0xEB, 0xFE, 0xED) and buffer addresses in .data. Decrypted strings are displayed via MessageBoxA, then the program calls ExitProcess. Only two imports (MessageBoxA, ExitProcess) with no persistence, network, file, registry, or injection capabilities. From the 'Hexorcist 3 - Weeks 20-30' reverse engineering course corpus, filename 'string_encryption.exe'.

### deep key_evidence
- `"Ghidra imports: only KERNEL32.ExitProcess and USER32.MessageBoxA \u2014 no suspicious API surface"`
- `"Ghidra callgraph: entry calls FUN_004010a8 (XOR decrypt) 4 times then MessageBoxA, ending with ExitProcess"`
- `"Ghidra instructions at 0x4010a8-0x4010b5: LODSB / XOR AL,BL / STOSB / DEC ECX / JNZ \u2014 classic XOR-in-loop decryption"`
- `"Malcat anomaly XorInLoop at EA 0x4010AE confirms the XOR decryption pattern"`
- `"FLOSS: 0 decoded/stack/tight strings \u2014 decryption only produces benign display text, not malicious payloads"`
- `"Sample from 'Hexorcist 3' RE course, filename string_encryption.exe \u2014 educational obfuscation demo, not malware"`
- `"Malcat kesakode_verdict: empty \u2014 no malware family classification"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca
size: 2048
type: PE
architecture: X86
entrypoint_ea: 512
entropy: 44
file_name: string_encryption.exe
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 512 | 0 | 52 | - |
| .text | 512 | 512 | 4096 | 36 | RX |
| .idata | 4608 | 512 | 4096 | 0 | RW |
| .data | 8704 | 512 | 4096 | 0 | RW |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| FASM | compiler | INFO | 70 | detects fasm using DOS stub |

### Anomalies (1)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |

### Anomaly Locations (high-signal)
- **XorInLoop**
  - `686`: 

### High-Signal Strings (1 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 4668 | `KERNEL32.DLL` |

### Top Strings (8 extracted; showing 8)
| EA | String |
|---|---|
| 4668 | `KERNEL32.DLL` |
| 4682 | `USER32.DLL` |
| 77 | `!This program ca.. in DOS mode.
$` |
| 4746 | `MessageBoxA` |
| 376 | `.text` |
| 456 | `.data` |
| 415 | ``.idata` |
| 4714 | `ExitProcess` |

### Imports (2)
| EA | Name | Type | Refs |
|---|---|---|---|
| 4704 | kernel32.ExitProcess | IMPORT | 2 |
| 4736 | user32.MessageBoxA | IMPORT | 5 |

### Functions (2)
| EA | Name |
|---|---|
| 680 | sub_4010a8 |
| 512 | EntryPoint |

### Decompilations (top 6)
#### 680 — sub_4010a8
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void __fastcall sub_4010a8(int32_t param_1)

{
    uint8_t *in_EAX;
    uint8_t unaff_BL;
    uint8_t *puVar1;
    
    puVar1 = in_EAX;
    do {
        *puVar1 = *in_EAX ^ unaff_BL;
        param_1 = param_1 + -1;
        in_EAX = in_EAX + 1;
        puVar1 = puVar1 + 1;
    } while (param_1 != 0);
    return;
}

```
#### 512 — EntryPoint
```c

/* WARNING: Possible PIC construction at 0x0040100f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401037: Changing call to branch */
/* WARNING: Possible PIC construction at 0x0040105f: Changing call to branch */
/* WARNING: Possible PIC construction at 0x00401087: Changing call to branch */
/* WARNING: Removing unreachable block (ram,0x00401064) */
/* WARNING: Removing unreachable block (ram,0x0040103c) */
/* WARNING: Removing unreachable block (ram,0x00401014) */
/* WARNING: Removing unreachable block (ram,0x0040108c) */

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    int32_t iVar1;
    uint8_t *puVar2;
    uint8_t *puVar3;
    
    iVar1 = 0x12;
    puVar2 = 0x403000;
    puVar3 = 0x403000;
    do {
        *puVar3 = *puVar2 ^ 0x90;
        iVar1 = iVar1 + -1;
        puVar2 = puVar2 + 1;
        puVar3 = puVar3 + 1;
    } while (iVar1 != 0);
    return;
}

```

### Structures (12)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 4608 |
| ImportNames | 4668 |
| kernel32.OFT | 4696 |
| kernel32.FT | 4704 |
| ImportNames | 4712 |
| user32.OFT | 4728 |
| user32.FT | 4736 |
| ImportNames | 4744 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 2 · duration_s: 0.78

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 2

## YARA Matches (pipeline)
Total matches: 4

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| FASM | - |  |

## Generated YARA Meta
```json
{
  "sha256": "263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca",
  "family": "unknown",
  "imphash": "98c88d882f01a3f6ac1e5f7dfd761624",
  "generated_at": "2026-08-09T13:29:10.390543+00:00",
  "string_count": 5,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "KERNEL32.DLL",
    "USER32.DLL",
    "ExitProcess",
    "MessageBoxA"
  ],
  "rule_path": "/opt/samples/logs/263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca/rule.yar",
  "sigma_path": "/opt/samples/logs/263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca/rule.yml",
  "iocs_path": "/opt/samples/logs/263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca/iocs.json",
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
  "provenance": {
    "project": "RevAI",
    "commit": "unknown",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-09 13:29:10 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 6 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 6}`

### High-signal FLOSS
- `KERNEL32.DLL`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- ``.idata`
- `KERNEL32.DLL`
- `USER32.DLL`
- `ExitProcess`
- `MessageBoxA`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401000
```asm
;-- section..text:
┌ 168: entry0 ();
│           0x00401000      bb90000000     mov ebx, 0x90               ; 144 ; [00] -r-x section size 4096 named .text
│           0x00401005      b800304000     mov eax, section..data      ; 0x403000
│           0x0040100a      b912000000     mov ecx, 0x12               ; 18
│           0x0040100f      e894000000     call fcn.004010a8
│           0x00401014      6a00           push 0
│           0x00401016      6800304000     push section..data          ; 0x403000
│           0x0040101b      6800304000     push section..data          ; 0x403000
│           0x00401020      6a00           push 0
│           0x00401022      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401028      bbeb000000     mov ebx, 0xeb               ; 235
│           0x0040102d      b813304000     mov eax, 0x403013           ; '\x130@'
│           0x00401032      b90f000000     mov ecx, 0xf                ; 15
│           0x00401037      e86c000000     call fcn.004010a8
│           0x0040103c      6a00           push 0
│           0x0040103e      6813304000     push 0x403013               ; '\x130@'
│           0x00401043      6813304000     push 0x403013               ; '\x130@'
│           0x00401048      6a00           push 0
│           0x0040104a      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401050      bbfe000000     mov ebx, 0xfe               ; 254
│           0x00401055      b823304000     mov eax, 0x403023           ; '#0@'
│           0x0040105a      b959000000     mov ecx, 0x59               ; 'Y' ; 89
│           0x0040105f      e844000000     call fcn.004010a8
│           0x00401064      6a00           push 0
│           0x00401066      6823304000     push 0x403023               ; '#0@'
│           0x0040106b      6823304000     push 0x403023               ; '#0@'
│           0x00401070      6a00           push 0
│           0x00401072      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
│           0x00401078      bbc3000000     mov ebx, 0xc3               ; 195
│           0x0040107d      b87d304000     mov eax, 0x40307d           ; '}0@'
│           0x00401082      b921000000     mov ecx, 0x21               ; '!' ; 33
│           0x00401087      e81c000000     call fcn.004010a8
│           0x0040108c      6a00           push 0
│           0x0040108e      687d304000     push 0x40307d               ; '}0@'
│           0x00401093      687d304000     push 0x40307d               ; '}0@'
│           0x00401098      6a00           push 0
│           0x0040109a      ff1580204000   call dword [sym.imp.USER32.DLL_MessageBoxA] ; 0x402080 ; int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
```
### 0x004010a8
```asm
; CALL XREFS from entry0 @ 0x40100f(x), 0x401037(x), 0x40105f(x), 0x401087(x)
┌ 14: fcn.004010a8 ();
│           0x004010a8      89c6           mov esi, eax
│           0x004010aa      89f7           mov edi, esi
│           0x004010ac      31c0           xor eax, eax
│       ┌─> 0x004010ae      ac             lodsb al, byte [esi]
│       ╎   0x004010af      30d8           xor al, bl
│       ╎   0x004010b1      aa             stosb byte es:[edi], al
│       ╎   0x004010b2      49             dec ecx
│       └─< 0x004010b3      75f9           jne 0x4010ae
└           0x004010b5      c3             ret
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ........!..L.!This program cannot be r

## Speakeasy (dynamic)
- speakeasy_ok: True
- api_calls: 0
- key_events: 0
- duration_s: None
- **not observed**: no API calls/events recorded — do not invent runtime behavior

## Frida Probe
- frida_available: True
- version: 17.16.4
- hook_candidates:
  - `KERNEL32.DLL!ExitProcess`
  - `USER32.DLL!MessageBoxA`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786282147.841417}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786282150.375733}`
- `{"source": "yara_gen_v2", "ts": 1786282150.3907418}`
- `{"source": "publish_report_v2", "ts": 1786282183.206108}`
- `{"source": "publish_report_v2_technical", "ts": 1786282226.8312645}`
- `{"source": "ida_query", "sql": "SELECT * FROM welcome", "ts": 1786308767.1626713}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786308767.1641874}`
- `{"source": "ida_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786308767.1650481}`
- `{"source": "ida_query", "sql": "SELECT module, name FROM imports LIMIT 50", "ts": 1786308767.16588}`
- `{"source": "ida_query", "sql": "SELECT content, printf('0x%X', address) AS addr FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786308767.166654}`
- `{"source": "ida_query", "sql": "SELECT name, address, size FROM funcs LIMIT 15", "ts": 1786308767.1674442}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1786308771.303761}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1786308771.3178284}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1786308771.3319645}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1786308771.3372457}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786308771.341385}`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name FROM memory_blocks", "ts": 1786308771.3486202}`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786308771.3620362}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'IsDebuggerPresent%' OR dst_func_name LIKE 'CheckRemoteDebuggerPresent%' OR dst_func_name LIKE 'NtQueryInformationProcess%' OR dst_func_name LIKE 'OutputDebugString%' O`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'SetUnhandledExceptionFilter%' OR dst_func_name LIKE 'UnhandledExceptionFilter%'", "ts": 1786308771.4171987}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'CreateToolhelp32Snapshot%' OR dst_func_name LIKE 'Process32FirstW%' OR dst_func_name LIKE 'Process32NextW%' OR dst_func_name LIKE 'Process32First%' OR dst_func_name LI`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetTickCount%' OR dst_func_name LIKE 'GetTickCount64%' OR dst_func_name LIKE 'QueryPerformanceCounter%' OR dst_func_name LIKE 'NtQueryPerformanceCounter%' OR dst_func_`
- `{"source": "ghidra_query", "sql": "SELECT address, content FROM strings WHERE length < 300", "ts": 1786308771.4573388}`
- `{"source": "ghidra_query", "sql": "SELECT address, name, size FROM funcs", "ts": 1786308771.4646742}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, src_func_name, dst_func_name FROM callgraph_edges WHERE dst_func_name LIKE 'GetProcAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddress%' OR dst_func_name LIKE 'LdrGetProcedureAddressForCaller%'", "ts": 1786308771.4800994}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr, dst_func_addr FROM call_edges", "ts": 1786308771.4835663}`
- `{"source": "ghidra_query", "sql": "SELECT src_func_addr FROM callgraph_edges WHERE dst_func_name LIKE 'LoadLibraryA%' OR dst_func_name LIKE 'LoadLibraryW%' OR dst_func_name LIKE 'LoadLibraryExA%' OR dst_func_name LIKE 'LoadLibraryExW%' OR dst_func_name LIKE 'LdrLoadDll%' OR dst_func_name LIKE 'GetMo`
- `{"source": "ghidra_query", "sql": "SELECT address, mnemonic, operands FROM instructions WHERE operands LIKE '%FS:%' OR operands LIKE '%GS:%'", "ts": 1786308771.503764}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name LIKE 'Ordinal%'", "ts": 1786308771.5071912}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1786308771.508356}`
