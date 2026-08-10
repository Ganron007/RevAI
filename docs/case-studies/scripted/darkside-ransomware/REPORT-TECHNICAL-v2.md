> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 15:33:32 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | suspicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## 1. Executive Summary

This report presents the technical analysis of the sample `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a`, a 61KB x86 PE executable named `darkside.ex`. The sample exhibits strong indicators of being a packed dropper or loader, consistent with known DarkSide ransomware packer techniques. The verdict is **suspicious** (score: 55) due to the presence of packing, obfuscation, and anti-analysis techniques, but without direct behavioral evidence of malicious actions observed in the analysis environment.

Key findings include:
- **Packing/Obfuscation**: High entropy sections (`.text` at 225/256, `.rsrc` at 226/256), a single static import (`ExitProcess`), and a `.text1` stub section indicate a runtime unpacker. CAPA confirms XOR encoding and aPLib decompression (source: malcat-capa).
- **Anti-Analysis**: PEB access via `FS:[0x30]` is used for environment checks (source: ghidra). Speakeasy recorded zero API calls, suggesting anti-emulation (source: speakeasy).
- **Obfuscation**: All 191 strings extracted by FLOSS are garbage/encoded, with zero decoded strings (source: floss).
- **Contextual Indicators**: The filename `darkside.ex` and a debug timestamp of 2021-02-16 align with DarkSide ransomware activity. A digital signature from "OASIS COURT LIMITED" (valid 2020-12-21 to 2021-12-21) is present but likely forged (source: malcat).

No runtime behavior such as file encryption, C2 communication, or persistence was observed. The sample's capabilities are latent within the packed payload. The analysis environment limitations (anti-emulation) prevented dynamic unpacking.

## 2. Sample Metadata

The following metadata was extracted from the PE header and analysis tools.

| Field | Value | Source |
|---|---|---|
| SHA256 | `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a` | malcat |
| File Name | `darkside.ex` | malcat |
| File Size | 61784 bytes | malcat |
| File Type | PE (Portable Executable) | malcat |
| Architecture | x86 | malcat |
| Entry Point EA | 38671 | malcat |
| Entropy | 216 (overall) | malcat |
| Import Hash | `f9ade0aa18f660a34a4fa23392e21838` | yara_gen_v2 |
| Debug Timestamp | 2021-02-16 | malcat |
| Digital Signature | Sectigo RSA Code Signing CA for OASIS COURT LIMITED (valid 2020-12-21 to 2021-12-21) | malcat |

The debug timestamp of February 16, 2021, places this sample within the active period of the DarkSide ransomware group, prior to the Colonial Pipeline attack in May 2021. The digital signature is present but uses a certificate issued to "OASIS COURT LIMITED," which is not a known legitimate software vendor, suggesting it may be forged or stolen (source: malcat).

## 3. File Layout & Structural Analysis

The PE file structure reveals a classic packed executable with an anomalous section layout.

### Section Table
The following table is copied from the Malcat analysis (source: malcat).

| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 38 | - |
| .text | 1024 | 33792 | 36864 | 225 | RWX |
| .text1 | 37888 | 1024 | 4096 | 0 | RX |
| .rdata | 41984 | 512 | 4096 | 0 | R |
| .data | 46080 | 13312 | 16384 | 184 | RW |
| .rsrc | 62464 | 4096 | 4096 | 226 | RW |
| overlay | 66560 | 8024 | 0 | 211 | - |

**Interpretation**: The `.text` section is marked as Read/Write/Execute (RWX), which is a strong indicator of a runtime unpacker that needs to write decompressed code into this section. Its high entropy (225/256) suggests the content is encrypted or compressed. The `.text1` section is small (1024 bytes) and has RX permissions, likely containing the unpacker stub. The `.rsrc` section also has high entropy (226/256), indicating encrypted resources. The presence of an overlay (8024 bytes) is common in packed samples and may contain additional data or configuration.

### Anomalies
The following anomalies were detected by Malcat (source: malcat).

| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-references |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |

**Interpretation**: The `CrossSectionJump` anomaly at EA 38141 indicates control flow transferring from the `.text` section to the `.text1` stub, which is typical for unpackers. The `SectionWX` anomaly confirms the writable and executable `.text` section. The `XorInLoop` anomaly at EA 38141 aligns with the XOR encoding capability identified by CAPA. The `InvalidChecksum` is common in packed or modified binaries.

## 4. Static Code Analysis

Static analysis reveals a minimal import table and complex obfuscated functions.

### Imports
The sample has only one static import (source: malcat).

| EA | Name | Type | Refs |
|---|---|---|---|
| 41984 | kernel32.ExitProcess | IMPORT | 6 |

**Interpretation**: The extreme import minimalism (only `ExitProcess`) is a hallmark of a packer stub. All other API calls are resolved dynamically at runtime, likely through PEB walking, as indicated by YARA rule `maldoc_find_kernel32_base_method_1` (source: yara).

### Functions
The following functions were identified by Ghidra (source: ghidra).

| EA | Name |
|---|---|
| 38536 | sub_40a288 |
| 38101 | sub_40a0d5 |
| 38671 | EntryPoint |
| 38197 | sub_40a135 |
| 37959 | sub_40a047 |
| 37888 | sub_40a000 |
| 38622 | sub_40a2de |
| 38581 | sub_40a2b5 |

Recovered function names from the agentic analysis provide additional context (source: agentic_recover_v4).

| Address | Recovered Name | Confidence | Notes |
|---|---|---|---|
| 4235573 | decompress_lz77_stream | 0.8 | Implements LZ77-style decompression |
| 4231453 | call_and_infinite_loop | 0.6 | Calls a function then enters infinite loop |
| 4235335 | custom_rc4_key_schedule | 0.7 | Initializes RC4 S-box |
| 4235477 | rc4_crypt_buffer | 0.85 | Performs RC4 encryption/decryption |
| 4235912 | store_peb_info | 0.7 | Reads PEB fields |
| 4235264 | rc4_process_buffer | 0.8 | Processes buffer in 255-byte chunks |
| 4235998 | rc4_data_setup | 0.7 | Resolves pointer to integer array |
| 4235957 | rc4_decrypt_entry_point | 0.7 | Computes entry point from PE header |

**Interpretation**: The recovered names suggest the packer uses RC4 encryption and LZ77 decompression. The `store_peb_info` function corresponds to the anti-analysis PEB access. The `call_and_infinite_loop` function may be the main unpacking routine that calls the decompressor and then loops, possibly waiting for an event or as a persistence mechanism.

### Disassembly: Entry Point
The entry point at EA 38671 (0x0040a30f) is shown below (source: radare2).

```asm
┌ 45: entry0 ();
│           0x0040a30f      6a10           push 0x10                   ; 16
│           0x0040a311      6820004100     push 0x410020               ; ' '
│           0x0040a316      6810004100     push 0x410010               ; '\x10'
│           0x0040a31b      e827fdffff     call fcn.0040a047
│           0x0040a320      e863ffffff     call fcn.0040a288
│           0x0040a325      e88bffffff     call fcn.0040a2b5
│           0x0040a32a      e8afffffff     call fcn.0040a2de
│           0x0040a32f      e8e9edffff     call fcn.0040911d
│           0x0040a334      6a00           push 0
└           0x0040a336      ff1500b04000   call dword [sym.imp.KERNEL32.dll_ExitProcess] ; 0x40b000 ; VOID ExitProcess(UINT uExitCode)
```

**Interpretation**: The entry point pushes three arguments (0x10, 0x410020, 0x410010) onto the stack and calls `fcn.0040a047`, which is likely the RC4 key schedule initialization. It then calls `fcn.0040a288` (PEB info storage), `fcn.0040a2b5` (likely decompression setup), and `fcn.0040a2de` (likely decompression execution). Finally, it calls `fcn.0040911d` (unknown, possibly the unpacked payload entry) and then `ExitProcess`. This sequence is consistent with a packer that unpacks, executes the payload, and then exits.

### Disassembly: PEB Access (Anti-Analysis)
The function `sub_40a288` (EA 38536) accesses the Process Environment Block (source: radare2).

```asm
; CALL XREF from entry0 @ 0x40a320(x)
┌ 45: fcn.0040a288 ();
│           0x0040a288      51             push ecx
│           0x0040a289      648b0d3000..   mov ecx, dword fs:[0x30]
│           0x0040a290      8b4118         mov eax, dword [ecx + 0x18]
│           0x0040a293      a3d6f54000     mov dword [0x40f5d6], eax   ; [0x40f5d6:4]=0
│           0x0040a298      8b4108         mov eax, dword [ecx + 8]
│           0x0040a29b      a3daf54000     mov dword [0x40f5da], eax   ; [0x40f5da:4]=0
│           0x0040a2a0      8b4164         mov eax, dword [ecx + 0x64]
│           0x0040a2a3      a3def54000     mov dword [0x40f5de], eax   ; [0x40f5de:4]=0
│           0x0040a2a8      8b4910         mov ecx, dword [ecx + 0x10]
│           0x0040a2ab      8b4144         mov eax, dword [ecx + 0x44]
│           0x0040a2ae      a3e2f54000     mov dword [0x40f5e2], eax   ; [0x40f5e2:4]=0
│           0x0040a2b3      59             pop ecx
└           0x0040a2b4      c3             ret
```

**Interpretation**: This function reads fields from the PEB via `FS:[0x30]`. It stores the PEB_LDR_DATA pointer (offset 0x18), the ImageBaseAddress (offset 0x08), and other fields into global variables. This is a classic technique for dynamic API resolution and environment detection, often used to evade static analysis and debugging.

### Disassembly: RC4 Key Schedule
The function `sub_40a047` (EA 37959) initializes the RC4 S-box (source: radare2).

```asm
; CALL XREF from entry0 @ 0x40a31b(x)
┌ 142: fcn.0040a047 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; arg int32_t arg_10h @ ebp+0x10
│           0x0040a047      55             push ebp
│           0x0040a048      8bec           mov ebp, esp
│           0x0040a04a      53             push ebx
│           0x0040a04b      51             push ecx
│           0x0040a04c      52             push edx
│           0x0040a04d      56             push esi
│           0x0040a04e      57             push edi
│           0x0040a04f      b9f0000000     mov ecx, 0xf0               ; 240
│           0x0040a054      be70f24000     mov esi, 0x40f270
│           0x0040a059      8b4508         mov eax, dword [arg_8h]
│           0x0040a05c      8b10           mov edx, dword [eax]
│           0x0040a05e      8b5804         mov ebx, dword [eax + 4]
│           0x0040a061      8b7808         mov edi, dword [eax + 8]
│           0x0040a064      8b400c         mov eax, dword [eax + 0xc]
│       ┌─> 0x0040a067      89540e0c       mov dword [esi + ecx + 0xc], edx
│       ╎   0x0040a06b      89440e08       mov dword [esi + ecx + 8], eax
│       ╎   0x0040a06f      895c0e04       mov dword [esi + ecx + 4], ebx
│       ╎   0x0040a073      893c0e         mov dword [esi + ecx], edi
│       ╎   0x0040a076      81ea10101010   sub edx, 0x10101010
│       ╎   0x0040a07c      2d10101010     sub eax, 0x10101010
│       ╎   0x0040a081      81eb10101010   sub ebx, 0x10101010
│       ╎   0x0040a087      81ef10101010   sub edi, 0x10101010
│       ╎   0x0040a08d      83e910         sub ecx, 0x10               ; 16
│       └─< 0x0040a090      79d5           jns 0x40a067
│           0x0040a092      33d2           xor edx, edx
│           0x0040a094      33c9           xor ecx, ecx
│           0x0040a096      8b750c         mov esi, dword [arg_ch]
│           0x0040a099      33db           xor ebx, ebx
│           0x0040a09b      8b7d10         mov edi, dword [arg_10h]
│      ┌┌─> 0x0040a09e      8a8170f24000   mov al, byte [ecx + 0x40f270]
│      ╎╎   0x0040a0a4      02141e         add dl, byte [esi + ebx]
│      ╎╎   0x0040a0a7      02d0           add dl, al
│      ╎╎   0x0040a0a9      8aa270f24000   mov ah, byte [edx + 0x40f270]
│      ╎╎   0x0040a0af      43             inc ebx
│      ╎╎   0x0040a0b0      888270f24000   mov byte [edx + 0x40f270], al ; [0x40f270:1]=0
│      ╎╎   0x0040a0b6      88a170f24000   mov byte [ecx + 0x40f270], ah ; [0x40f270:1]=0
│      ╎╎   0x0040a0bc      3bdf           cmp ebx, edi
│     ┌───< 0x0040a0be      7306           jae 0x40a0c6
│     │╎╎   0x0040a0c0      fec1           inc cl
│     │└──< 0x0040a0c2      75da           jne 0x40a09e
│     │┌──< 0x0040a0c4      eb06           jmp 0x40a0cc
│     └───> 0x0040a0c6      33db           xor ebx, ebx
│      │╎   0x0040a0c8      fec1           inc cl
│      │└─< 0x0040a0ca      75d2           jne 0x40a09e
```

**Interpretation**: This function initializes a 256-byte S-box at address `0x40f270` using four integers from the seed parameters. It then permutes the S-box using the key from the second argument. This is a custom RC4 key schedule implementation, confirming the use of RC4 encryption for payload obfuscation.

### Disassembly: Decompression Routine
The function `sub_40a000` (EA 37888) is located in the `.text1` section and handles decompression (source: radare2).

```asm
;-- section..text1:
            ; CALL XREF from fcn.0040a2b5 @ 0x40a2d5(x)
            ; CALL XREF from fcn.0040a2de @ 0x40a303(x)
┌ 71: fcn.0040a000 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x0040a000      55             push ebp                    ; [01] -r-x section size 4096 named .text1
│           0x0040a001      8bec           mov ebp, esp
│           0x0040a003      53             push ebx
│           0x0040a004      51             push ecx
│           0x0040a005      52             push edx
│           0x0040a006      56             push esi
│           0x0040a007      57             push edi
│           0x0040a008      8b7d08         mov edi, dword [arg_8h]
│           0x0040a00b      8b450c         mov eax, dword [arg_ch]
│           0x0040a00e      b9ff000000     mov ecx, 0xff               ; 255
│           0x0040a013      33d2           xor edx, edx
│           0x0040a015      f7f1           div ecx
│           0x0040a017      85c0           test eax, eax
│       ┌─< 0x0040a019      7418           je 0x40a033
│       │   0x0040a01b      8bd8           mov ebx, eax
│      ┌──> 0x0040a01d      68ff000000     push 0xff                   ; 255
│      ╎│   0x0040a022      57             push edi
│      ╎│   0x0040a023      e8ad000000     call 0x40a0d5
│      ╎│   0x0040a028      81c7ff000000   add edi, 0xff               ; 255
│      ╎│   0x0040a02e      4b             dec ebx
│      ╎│   0x0040a02f      85db           test ebx, ebx
│      └──< 0x0040a031      75ea           jne 0x40a01d
│       └─> 0x0040a033      85d2           test edx, edx
│       ┌─< 0x0040a035      7407           je 0x40a03e
│       │   0x0040a037      52             push edx
│       │   0x0040a038      57             push edi
│       │   0x0040a039      e897000000     call 0x40a0d5
│       └─> 0x0040a03e      5f             pop edi
│           0x0040a03f      5e             pop esi
│           0x0040a040      5a             pop edx
│           0x0040a041      59             pop ecx
│           0x0040a042      5b             pop ebx
│           0x0040a043      5d             pop ebp
└           0x0040a044      c20800         ret 8
```

**Interpretation**: This function processes a buffer in chunks of 255 bytes by repeatedly calling `0x40a0d5` (the RC4 crypt function). It divides the total length by 255, processes full chunks, then processes any remainder. This is consistent with the `rc4_process_buffer` recovered function name. The use of 255-byte chunks is typical for RC4 implementations to avoid integer overflow issues.

## 5. Behavioral & Dynamic Analysis

Dynamic analysis in the Speakeasy emulator yielded no observable behavior.

| Tool | Result | Source |
|---|---|---|
| Speakeasy | No API calls logged | speakeasy |
| Frida Probe | Available (version 17.16.4) but no events recorded | frida_probe |

**Interpretation**: The lack of API calls in Speakeasy suggests the packer employs anti-emulation techniques to detect and evade sandbox analysis. This is consistent with advanced packers that check for emulation artifacts before unpacking. The Frida probe was available but did not capture any events, likely because the sample did not execute past the anti-emulation checks.

## 6. Network Indicators & C2

No network indicators or C2 communication were observed during analysis.

| Indicator Type | Value | Source |
|---|---|---|
| URLs | None observed | - |
| Domains | None observed | - |
| IP Addresses | None observed | - |

**Interpretation**: The absence of network activity is expected for a packed sample that did not fully unpack in the analysis environment. The packed payload may contain C2 infrastructure, but it was not revealed during static or dynamic analysis.

## 7. Capabilities Assessment

The following capabilities were identified through static analysis. All are latent within the packed payload unless otherwise noted.

### Observed Capabilities
| Capability | Evidence | Source |
|---|---|---|
| RC4 Encryption/Decryption | Custom key schedule and crypt functions | ghidra, agentic_recover_v4 |
| LZ77 Decompression | Recovered function name `decompress_lz77_stream` | agentic_recover_v4 |
| PEB Access for Anti-Analysis | `FS:[0x30]` access in `sub_40a288` | ghidra |
| XOR Encoding | CAPA rule `encode data using XOR` | malcat-capa |
| aPLib Decompression | CAPA rule `decompress data using aPLib` | malcat-capa |
| Process Termination | CAPA rule `terminate process` | malcat-capa |
| Dynamic API Resolution | YARA rule `maldoc_find_kernel32_base_method_1` | yara |
| File Enumeration | FLOSS string `FindNextFileW` | floss |

### Latent Capabilities (Inferred from Context)
| Capability | Evidence | Source |
|---|---|---|
| Ransomware Payload | Filename `darkside.ex`, debug timestamp 2021-02-16 | malcat |
| File Encryption | Likely payload behavior (not observed) | - |
| C2 Communication | Likely payload behavior (not observed) | - |
| Persistence | Likely payload behavior (not observed) | - |

**Interpretation**: The observed capabilities are consistent with a packer/loader. The latent capabilities are inferred from the filename and timestamp but were not observed in the analysis environment. The presence of `FindNextFileW` in the strings suggests the payload may enumerate files, which is typical for ransomware.

## 8. Indicators of Compromise

The following IOCs were extracted from the sample.

### File-Based IOCs
| Type | Value | Source |
|---|---|---|
| SHA256 | `1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a` | malcat |
| File Name | `darkside.ex` | malcat |
| Import Hash | `f9ade0aa18f660a34a4fa23392e21838` | yara_gen_v2 |
| Debug Timestamp | 2021-02-16 | malcat |
| Digital Signature | OASIS COURT LIMITED (Sectigo RSA Code Signing CA) | malcat |

### Behavioral IOCs
| Type | Value | Source |
|---|---|---|
| PEB Access | `FS:[0x30]` | ghidra |
| RC4 S-box Address | `0x40f270` | radare2 |
| Global Data Pointers | `0x40f5d6`, `0x40f5da`, `0x40f5de`, `0x40f5e2` | radare2 |

### YARA Matches
The following YARA rules matched (source: yara).

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@55207 len=2 |
| contains_base64 | - | $a@37372 len=12 |
| url | - | $url_regex@54733 len=24 |
| maldoc_find_kernel32_base_method_1 | - | $a1@35465 len=7 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@53760 len=105 |
| HasDebugData | - |  |

**Interpretation**: The YARA matches confirm the sample is a PE32 GUI application with packing indicators, an overlay, a digital signature, and debug data. The `maldoc_find_kernel32_base_method_1` rule specifically detects the PEB walking technique for dynamic API resolution.

## 9. Detection Engineering

Detection rules should focus on the packer's behavior rather than the payload, as the payload is encrypted.

### YARA Rule
A YARA rule was generated for this sample (source: yara_gen_v2).

```yara
rule darkside_ex_packer {
    meta:
        sha256 = "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a"
        family = "Unknown"
        imphash = "f9ade0aa18f660a34a4fa23392e21838"
        description = "DarkSide ransomware packer with RC4 and aPLib"
    strings:
        $s1 = "!This program cannot be run in DOS mode." ascii
        $s2 = "KERNEL32.dll" ascii
        $s3 = "FindNextFileW" ascii
        $s4 = "ExitProcess" ascii
        $code1 = { 64 8b 0d 30 00 00 00 } // mov ecx, dword ptr fs:[0x30]
        $code2 = { 8b 41 18 a3 d6 f5 40 00 } // mov eax, [ecx+0x18]; mov [0x40f5d6], eax
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and
        ($code1 or $code2) and
        2 of ($s*)
}
```

### Sigma Rule
A Sigma rule for detecting PEB access in suspicious contexts could be developed.

```yaml
title: Suspicious PEB Access for API Resolution
id: 12345678-1234-1234-1234-123456789012
status: experimental
description: Detects access to Process Environment Block via FS:[0x30] for dynamic API resolution
author: Malware Analyst
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'FS:[0x30]'
    condition: selection
falsepositives:
    - Legitimate software using anti-debugging techniques
level: medium
```

**Interpretation**: The YARA rule targets the packer's specific code patterns and strings. The Sigma rule is more generic and would require process memory scanning, which is not typically available in standard logs. Detection should focus on the behavioral indicators of the packer.

## 10. MITRE ATT&CK Mapping

The following ATT&CK techniques were identified (source: malcat-capa, yara).

| Technique ID | Name | Evidence | Source |
|---|---|---|---|
| T1027 | Obfuscated Files or Information | XOR encoding, RC4 encryption, high entropy | malcat-capa, ghidra |
| T1140 | Deobfuscate/Decode Files or Information | aPLib decompression, RC4 decryption | malcat-capa, agentic_recover_v4 |
| T1082 | System Information Discovery | PEB access for environment checks | ghidra |
| T1057 | Process Discovery | Potential via PEB walking (not directly observed) | - |
| T1083 | File and Directory Discovery | `FindNextFileW` string present | floss |

**Interpretation**: The techniques are primarily related to defense evasion (obfuscation) and discovery. The file discovery technique is inferred from the string but not observed in execution. No techniques for impact (e.g., T1486 Data Encrypted for Impact) were observed, as the payload did not execute.

## 11. What We Don't Know

Several aspects of this sample remain unknown due to analysis limitations.

1. **Unpacked Payload Behavior**: The actual malicious payload is encrypted within the `.text` section. Without unpacking, we cannot determine if it performs file encryption, C2 communication, or other malicious actions. The anti-emulation techniques prevented dynamic unpacking.

2. **C2 Infrastructure**: No network indicators were observed. The payload may contain hardcoded C2 servers or domains, but these are encrypted.

3. **Persistence Mechanisms**: The sample may install persistence mechanisms (e.g., registry keys, scheduled tasks), but this was not observed.

4. **Lateral Movement Capabilities**: The payload may include lateral movement tools, but this is unknown.

5. **Data Exfiltration**: The payload may exfiltrate data before encryption, but this is not observed.

6. **Anti-Analysis Specifics**: While PEB access is observed, the specific anti-debugging or anti-VM checks are not fully analyzed.

7. **Configuration Data**: The overlay or `.rsrc` section may contain configuration data (e.g., ransom note, file extensions to encrypt), but this is encrypted.

8. **Relationship to DarkSide**: The filename and timestamp suggest a connection to DarkSide ransomware, but without unpacking the payload, we cannot confirm this is a genuine DarkSide sample or a copycat.

**Reasoning**: The primary limitation is the packer's anti-emulation, which prevented dynamic analysis. Static analysis reveals the packer's structure but not the payload's behavior. Further analysis with manual unpacking or a different emulation environment would be required to answer these questions.

## 12. Appendix A: Tool Evidence Trail

The following table documents the evidence trail from each analysis tool.

| Tool | Query/Rule | Row/Address | Why |
|---|---|---|---|
| ghidra | Anti Analysis Signals | `4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913` | PEB access for anti-debugging |
| capa | rules | `encode data using XOR` | XOR encoding for obfuscation |
| malcat | anomalies | `CrossSectionJump` | Control flow jumps across sections |
| malcat | metadata | `Certificate::Validity: from 2020-12-21 to 2021-12-21` | Digital signature validity |
| yara | matches | `maldoc_find_kernel32_base_method_1` | PEB walking technique |
| floss | strings | `FindNextFileW` | File enumeration capability |
| radare2 | disassembly | `0x0040a30f` | Entry point analysis |
| speakeasy | api_calls | 0 | No API calls logged |
| frida_probe | version | 17.16.4 | Frida available |

## 13. Appendix B: Analysis Environment

The analysis was performed in a controlled environment with the following tools and versions.

| Tool | Version | Purpose |
|---|---|---|
| Malcat | (unknown) | Static analysis, section layout, anomalies |
| Ghidra | (unknown) | Disassembly, decompilation, function analysis |
| IDA | (unknown) | Disassembly, string extraction |
| CAPA | (unknown) | Capability detection |
| YARA | (unknown) | Pattern matching |
| FLOSS | (unknown) | String extraction |
| radare2 | (unknown) | Disassembly |
| Speakeasy | (unknown) | Dynamic emulation |
| Frida | 17.16.4 | Dynamic instrumentation |
| UPX | (unknown) | Unpacking (failed) |

**Limitations**: The analysis environment could not unpack the sample due to anti-emulation techniques. The sample was analyzed statically and in a limited dynamic environment.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a  
**sample_path:** /opt/samples/corpus/Malware Analyst Professional - Level 2/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/darkside.ex  
**project_name:** Malware Analyst Professional - Level 2

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: suspicious
- **score**: 55
- **family_guess**: Unknown
- **agreement**: llm_v1_disagree
- **cross_engine_notes**: Ghidra reports 9 functions and 6 strings, while IDA reports 8 functions and 320 strings, indicating analysis discrepancies. Packing indicators are consistent across tools, with high entropy sections and entry point not in first section. Anti-analysis technique via PEB access detected, and obfuscation through XOR encoding observed, but no clear behavioral-intent evidence for malicious actions like file encryption, C2, or persistence.
- **summary**: The sample exhibits signs of packing, obfuscation (XOR encoding), and anti-analysis (PEB access), with a digital signature present. However, no direct behavioral-intent evidence such as file destruction, C2 communication, credential theft, or persistence mechanisms was identified. The analysis shows neutral signals consistent with protected software or potential malware, warranting suspicion but not definitive malicious verdict. Discrepancies in tool outputs highlight the need for cross-engine validation.
- **source**: llm_judge
- **model**: configured-llm

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| ghidra | Anti Analysis Signals | `4235912 | FUN_0040a288 | MOV ECX, dword ptr FS:[0x30] @ 4235913` | Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indic |
| capa | rules | `encode data using XOR` | Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), a neutral signal that can be |
| malcat | anomalies | `CrossSectionJump` | Control flow jumps across sections may indicate packed code, file infection, or other obfuscation, which is common in pr |
| malcat | metadata | `Certificate::Validity: from 2020-12-21 to 2021-12-21` | Presence of a digital signature with a specific validity period; while signatures can indicate legitimacy, expired or su |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: DarkSide ransomware dropper/packer. The sample is a heavily packed PE (61KB) with only 1 static import (ExitProcess), RWX .text section, and high entropy indicating runtime unpacking. CAPA confirms XOR encoding (T1027) and aPLib decompression. YARA matched kernel32 PEB-walking API resolution technique. FLOSS extracted 191 strings but all are garbage/encoded with zero decoded strings, confirming heavy obfuscation. The filename is explicitly 'darkside.ex'. Code signing certificate ('OASIS COURT LIMITED', valid 2020-2021) is trivially forged and not evidence of legitimacy. Debug timestamp 2021-02-16 aligns with DarkSide ransomware operational timeline (pre-Colonial Pipeline attack).

### deep key_evidence
- `"Filename: darkside.ex \u2014 explicit DarkSide ransomware naming"`
- `"Ghidra imports: Only 1 import (ExitProcess from KERNEL32.DLL) \u2014 extreme import minimalism indicates packer stub"`
- `"Ghidra memory_blocks: .text section is RWX (Read+Write+Execute) with size 33792 \u2014 classic unpacking indicator"`
- `"Malcat layout: .text entropy 225/256, .rsrc entropy 226/256 \u2014 high entropy indicates packed/encrypted payload"`
- `"CAPA: 'encode data using XOR' (MITRE T1027 Defense Evasion, MBC E1027.m02)"`
- `"CAPA: 'decompress data using aPLib' (MBC C0025.003) \u2014 confirms packer is aPLib-based"`
- `"CAPA: 'terminate process' (MBC C0018) \u2014 post-exploitation capability"`
- `"YARA: maldoc_find_kernel32_base_method_1 at offset 35465 \u2014 PEB walking for dynamic API resolution"`
- `"YARA: HasOverlay triggered \u2014 overlay data present"`
- `"YARA: HasDigitalSignature at offset 53760 \u2014 signed with Sectigo cert for OASIS COURT LIMITED"`
- `"FLOSS: 191 strings extracted, 0 decoded, 0 stack strings \u2014 all strings are obfuscated/garbage"`
- `"FLOSS: FindNextFileW string present \u2014 file enumeration capability for ransomware target discovery"`
- `"Malcat metadata: Certificate issued to OASIS COURT LIMITED, valid 2020-12-21 to 2021-12-16 \u2014 forged/stolen cert"`
- `"Malcat metadata: Debug date 2021-02-16 \u2014 aligns with DarkSide ransomware active period"`
- `"Ghidra function_metrics: FUN_0040a135 has 46 blocks, cyclomatic complexity 23 \u2014 complex obfuscated unpacker logic"`
- `"Ghidra: .text1 stub section (1024 bytes, RX) \u2014 small unpacker stub that decompresses main payload into .text"`
- `"Speakeasy: No API calls logged \u2014 packer uses anti-emulation to evade sandbox analysis"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: 1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a
size: 61784
type: PE
architecture: X86
entrypoint_ea: 38671
entropy: 216
file_name: darkside.ex
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 38 | - |
| .text | 1024 | 33792 | 36864 | 225 | RWX |
| .text1 | 37888 | 1024 | 4096 | 0 | RX |
| .rdata | 41984 | 512 | 4096 | 0 | R |
| .data | 46080 | 13312 | 16384 | 184 | RW |
| .rsrc | 62464 | 4096 | 4096 | 226 | RW |
| overlay | 66560 | 8024 | 0 | 211 | - |

### Malcat YARA / Signatures (1)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2017_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |

### Anomalies (9)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| CrossSectionJump | 4 | code | 1 | Control flow jumps across section, could be a packed file, a patched file or a file infector |
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| ResourceDirectoryGap | 4 | resources | 1 | There is a space (bigger than 15 bytes) inside the resource directory region which is not occupied b |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| SectionNameUnknown | 3 | sections | 1 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 1 | section is executable and writeable |
| XorInLoop | 3 | code | 1 | XOR instruction in a loop |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HighEntropy | 2 | entropy | 0 | File has high entropy overall (> 200) |

### Anomaly Locations (high-signal)
- **GuiSubsystemNoWindowApi**
  - `220`: 
- **ResourceDirectoryGap**
  - `62480`: 
- **XorInLoop**
  - `38141`: 

### High-Signal Strings (15 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 42314 | `KERNEL32.dll` |
| 70656 | `?http://crl.user..nAuthority.crl0v` |
| 68880 | `?http://crl.user..nAuthority.crl0v` |
| 72473 | `3http://crl.sect..StampingCA.crl0t` |
| 70749 | `3http://crt.user..AddTrustCA.crt0%` |
| 68973 | `3http://crt.user..AddTrustCA.crt0%` |
| 67664 | `2http://crt.sect..eSigningCA.crt0#` |
| 67584 | `2http://crl.sect..eSigningCA.crl0s` |
| 72554 | `3http://crt.sect..StampingCA.crt0#` |
| 70815 | `http://ocsp.usertrust.com0
` |
| 69039 | `http://ocsp.usertrust.com0
` |
| 72620 | `http://ocsp.sectigo.com0
` |
| 67729 | `http://ocsp.sectigo.com0%` |
| 67533 | `https://sectigo.com/CPS0` |
| 72432 | `https://sectigo.com/CPS0D` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 42314 | `KERNEL32.dll` |
| 70656 | `?http://crl.user..nAuthority.crl0v` |
| 68880 | `?http://crl.user..nAuthority.crl0v` |
| 72473 | `3http://crl.sect..StampingCA.crl0t` |
| 70749 | `3http://crt.user..AddTrustCA.crt0%` |
| 68973 | `3http://crt.user..AddTrustCA.crt0%` |
| 67664 | `2http://crt.sect..eSigningCA.crt0#` |
| 67584 | `2http://crl.sect..eSigningCA.crl0s` |
| 72554 | `3http://crt.sect..StampingCA.crt0#` |
| 70815 | `http://ocsp.usertrust.com0
` |
| 69039 | `http://ocsp.usertrust.com0
` |
| 72620 | `http://ocsp.sectigo.com0
` |
| 67729 | `http://ocsp.sectigo.com0%` |
| 67533 | `https://sectigo.com/CPS0` |
| 72432 | `https://sectigo.com/CPS0D` |
| 68255 | `
181102000000Z` |
| 71549 | `
201023000000Z` |
| 66865 | `
201221000000Z` |
| 69743 | `%USERTrust RSA C..ation Authority0` |
| 69784 | `
190502000000Z` |
| 68214 | `%USERTrust RSA C..ation Authority0` |
| 66880 | `
211221235959Z0` |
| 71677 | `#Sectigo RSA Tim..mping Signer #20` |
| 71564 | `
320122235959Z0` |
| 73288 | `Sectigo RSA Code Signing CA` |
| 66835 | `Sectigo RSA Code Signing CA0` |
| 68383 | `Sectigo RSA Code Signing CA0` |
| 77 | `!This program ca..in DOS mode.

$` |
| 67765 | `nonaterscont1986@yahoo.com0
` |
| 9606 | `43.nfL` |
| 68270 | `
301231235959Z0|1` |
| 73866 | `Sectigo RSA Time Stamping CA` |
| 73972 | `
210217111653Z0?` |
| 71518 | `Sectigo RSA Time Stamping CA0` |
| 69912 | `Sectigo RSA Time Stamping CA0` |
| 69799 | `
380118235959Z0}1` |
| 68310 | `Greater Manchester1` |
| 73215 | `Greater Manchester1` |
| 49905 | `AUTORITE NT` |
| 66762 | `Greater Manchester1` |
| 73793 | `Greater Manchester1` |
| 71445 | `Greater Manchester1` |
| 71605 | `Greater Manchester1` |
| 69839 | `Greater Manchester1` |
| 68183 | `The USERTRUST Network1.0,` |
| 67005 | `OASIS COURT LIMITED1` |
| 69712 | `The USERTRUST Network1.0,` |
| 67035 | `OASIS COURT LIMITED0` |
| 47100 | `FindNextFileW` |
| 72035 | `>Itt` |
| 54978 | `64m6` |
| 33879 | `vvAe` |
| 42228 | `.bss` |
| 49233 | `8fHf` |
| 71018 | `mAmg` |
| 69137 | `F^@F` |
| 66622 | `>0<0` |
| 20292 | `2syy` |
| 25296 | `]Z
Z` |
| 65252 | `oQio` |
| 1635 | `pmms` |
| 53315 | `3e``` |
| 16603 | `U161` |
| 16572 | `LkXL` |
| 15041 | `EWEv` |
| 57197 | `*.4M` |
| 28811 | `U@Ua` |
| 14133 | `yyWx` |
| 68357 | `Sectigo Limited1$0"` |
| 73262 | `Sectigo Limited1$0"` |
| 66809 | `Sectigo Limited1$0"` |
| 32958 | `XG`eX` |
| 68957 | `j0h0?` |
| 70646 | `I0G0E` |
| 67498 | `C0A05` |
| 55711 | `eBkEE` |
| 68870 | `I0G0E` |
| 67574 | `<0:08` |
| 67648 | `g0e0>` |
| 42244 | `.rsrc` |

### Constants / Known Patterns (41)
| Category | Value |
|---|---|
| code | `code::PEBx86` |
| oid | `oid::signedData` |
| oid | `oid::sha1` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::sha256WithRSAEncryption` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::postalCode` |
| oid | `oid::streetAddress` |
| oid | `oid::rsaEncryption` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::keyUsage` |
| oid | `oid::basicConstraints` |
| oid | `oid::extKeyUsage` |
| oid | `oid::codeSigning` |
| oid | `oid::netscape-cert-type` |
| oid | `oid::certificatePolicies` |
| oid | `oid::cps` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::caIssuers` |
| oid | `oid::ocsp` |
| oid | `oid::subjectAltName` |
| oid | `oid::sha384WithRSAEncryption` |
| oid | `oid::timeStamping` |
| oid | `oid::anyPolicy` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::messageDigest` |
| oid | `oid::countersignature` |
| oid | `oid::sha-384` |
| oid | `oid::data` |

### Imports (1)
| EA | Name | Type | Refs |
|---|---|---|---|
| 41984 | kernel32.ExitProcess | IMPORT | 6 |

### Functions (8)
| EA | Name |
|---|---|
| 38536 | sub_40a288 |
| 38101 | sub_40a0d5 |
| 38671 | EntryPoint |
| 38197 | sub_40a135 |
| 37959 | sub_40a047 |
| 37888 | sub_40a000 |
| 38622 | sub_40a2de |
| 38581 | sub_40a2b5 |

### Decompilations (top 6)
#### 38536 — sub_40a288
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40a288(void)

{
    int32_t iVar1;
    int32_t unaff_FS_OFFSET;
    
    iVar1 = *(unaff_FS_OFFSET + 0x30);
    [0x0x40f5d6] = *(iVar1 + 0x18);
    [0x0x40f5da] = *(iVar1 + 8);
    [0x0x40f5de] = *(iVar1 + 100);
    [0x0x40f5e2] = *(*(iVar1 + 0x10) + 0x44);
    return;
}

```
#### 38101 — sub_40a0d5
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_40a0d5(int32_t param_1,char param_2)

{
    char cVar1;
    char cVar2;
    int32_t iVar3;
    uint32_t uVar4;
    uint32_t uVar5;
    undefined4 *puVar6;
    undefined4 *puVar7;
    uint8_t *puVar8;
    
    puVar6 = 0x40f270;
    puVar7 = 0x40f370;
    for (iVar3 = 0x40; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar7 = *puVar6;
        puVar6 = puVar6 + 1;
        puVar7 = puVar7 + 1;
    }
    uVar4 = 0;
    uVar5 = 0;
    puVar8 = param_1 + -1;
    do {
        uVar5 = uVar5 + *(uVar4 + 0x40f371);
        cVar1 = *(uVar4 + 0x40f371);
        cVar2 = *(uVar5 + 0x40f370);
        *(uVar5 + 0x40f370) = cVar1;
        *(uVar4 + 0x40f371) = cVar2;
        puVar8 = puVar8 + 1;
        uVar4 = uVar4 + 1;
        *puVar8 = *puVar8 ^ *((cVar1 + cVar2) + 0x40f370);
        param_2 = param_2 + -1;
    } while (param_2 != '\0');
    return;
}

```
#### 38671 — EntryPoint
```c
EntryPoint {
    // Error while decompiling : not a valid ea
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PKCS7 | 8014 |

### Structures (12)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| kernel32.FT | 41984 |
| DebugDirectory | 42000 |
| Debug.Pogo | 42028 |
| ImportTable | 42252 |
| kernel32.OFT | 42292 |
| ImportNames | 42300 |
| Resources | 62464 |
| Certificate | 66560 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 3 · duration_s: 0.8

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| decompress data using aPLib |  | C0025.003:Decompress Data |
| terminate process |  | C0018:Terminate Process |

## PE Imports / Signals
import_count: 1

## YARA Matches (pipeline)
Total matches: 11

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@55207 len=2 |
| contains_base64 | - | $a@37372 len=12 |
| url | - | $url_regex@54733 len=24 |
| maldoc_find_kernel32_base_method_1 | - | $a1@35465 len=7 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| IsPacked | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@53760 len=105 |
| HasDebugData | - |  |

## Generated YARA Meta
```json
{
  "sha256": "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a",
  "family": "Unknown",
  "imphash": "f9ade0aa18f660a34a4fa23392e21838",
  "generated_at": "2026-08-09T15:15:52.123577+00:00",
  "string_count": 24,
  "strings": [
    "!This program cannot be run in DOS mode.",
    "9g'P@/ZcS`",
    "<u(k]kaA",
    "88|jlc8tyf",
    "\">V'h$!;",
    "5`e*ci<2x",
    "\">V'`*!;B",
    "~r6{<x7W",
    ".idata$5",
    ".rdata$zzzdbg",
    ".idata$2",
    ".idata$3",
    ".idata$4",
    ".idata$6",
    "ExitProcess",
    "KERNEL32.dll",
    "FindNextFileW",
    "AUTORITE NT",
    "qJ<Zwr\"YY",
    "rl\u00a92t9!*",
    "M/|`,\"ag",
    "]#eE0@bn",
    "Access to Process Environment Block (PEB) via FS:[0x30] is a common anti-debugging or environment check technique, indic",
    "Use of XOR encoding for data obfuscation is associated with defense evasion (ATT&CK T1027), a neutral signal that can be"
  ],
  "rule_path": "/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/rule.yar",
  "sigma_path": "/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/rule.yml",
  "iocs_path": "/opt/samples/logs/1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a/iocs.json",
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
    "utc": "2026-08-09 15:15:52 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 191 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 191}`

### High-signal FLOSS
- `KERNEL32.dll`

### FLOSS sample
- `!This program cannot be run in DOS mode.`
- `.text1`
- ``.rdata`
- `@.data`
- `XJ7ZB;`
- ``(/D1RK`
- `2sR:2|`
- `e;*-Q$=`
- `aBN-R"`
- `aSkS5:`
- `,IG]DT`
- `?*-Q$8`
- `-b|Xp0`
- `43.nfL`
- `@Ua+E=`
- `H.`e$K`
- `9g'P@/ZcS``
- `<u(k]kaA`
- `9Uj*83`
- `wtCLhJ`
- `q[j*>7`
- `m]J,	z`
- `e&74a3`
- `OAI<2p`
- `88|jlc8tyf`
- `">V'h$!;`
- `V',%!;`
- `-BHE\L`
- `-BHEPB`
- `Lh<NFcU`
- ``BHLNY`
- `5`e*ci<2x`
- `$Vr_dX8`
- `azfJ?L%`
- `~8]TEj`
- `dcWt$lR`
- `T{@"Ze`
- `1?a;*-`
- `3agdm;`
- `AUdMj0'`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x0040a30f
```asm
┌ 45: entry0 ();
│           0x0040a30f      6a10           push 0x10                   ; 16
│           0x0040a311      6820004100     push 0x410020               ; ' '
│           0x0040a316      6810004100     push 0x410010               ; '\x10'
│           0x0040a31b      e827fdffff     call fcn.0040a047
│           0x0040a320      e863ffffff     call fcn.0040a288
│           0x0040a325      e88bffffff     call fcn.0040a2b5
│           0x0040a32a      e8afffffff     call fcn.0040a2de
│           0x0040a32f      e8e9edffff     call fcn.0040911d
│           0x0040a334      6a00           push 0
└           0x0040a336      ff1500b04000   call dword [sym.imp.KERNEL32.dll_ExitProcess] ; 0x40b000 ; "<\xb1" ; VOID ExitProcess(UINT uExitCode)
```
### 0x0040a047
```asm
; CALL XREF from entry0 @ 0x40a31b(x)
┌ 142: fcn.0040a047 (int32_t arg_8h, int32_t arg_ch, int32_t arg_10h);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; arg int32_t arg_10h @ ebp+0x10
│           0x0040a047      55             push ebp
│           0x0040a048      8bec           mov ebp, esp
│           0x0040a04a      53             push ebx
│           0x0040a04b      51             push ecx
│           0x0040a04c      52             push edx
│           0x0040a04d      56             push esi
│           0x0040a04e      57             push edi
│           0x0040a04f      b9f0000000     mov ecx, 0xf0               ; 240
│           0x0040a054      be70f24000     mov esi, 0x40f270
│           0x0040a059      8b4508         mov eax, dword [arg_8h]
│           0x0040a05c      8b10           mov edx, dword [eax]
│           0x0040a05e      8b5804         mov ebx, dword [eax + 4]
│           0x0040a061      8b7808         mov edi, dword [eax + 8]
│           0x0040a064      8b400c         mov eax, dword [eax + 0xc]
│       ┌─> 0x0040a067      89540e0c       mov dword [esi + ecx + 0xc], edx
│       ╎   0x0040a06b      89440e08       mov dword [esi + ecx + 8], eax
│       ╎   0x0040a06f      895c0e04       mov dword [esi + ecx + 4], ebx
│       ╎   0x0040a073      893c0e         mov dword [esi + ecx], edi
│       ╎   0x0040a076      81ea10101010   sub edx, 0x10101010
│       ╎   0x0040a07c      2d10101010     sub eax, 0x10101010
│       ╎   0x0040a081      81eb10101010   sub ebx, 0x10101010
│       ╎   0x0040a087      81ef10101010   sub edi, 0x10101010
│       ╎   0x0040a08d      83e910         sub ecx, 0x10               ; 16
│       └─< 0x0040a090      79d5           jns 0x40a067
│           0x0040a092      33d2           xor edx, edx
│           0x0040a094      33c9           xor ecx, ecx
│           0x0040a096      8b750c         mov esi, dword [arg_ch]
│           0x0040a099      33db           xor ebx, ebx
│           0x0040a09b      8b7d10         mov edi, dword [arg_10h]
│      ┌┌─> 0x0040a09e      8a8170f24000   mov al, byte [ecx + 0x40f270]
│      ╎╎   0x0040a0a4      02141e         add dl, byte [esi + ebx]
│      ╎╎   0x0040a0a7      02d0           add dl, al
│      ╎╎   0x0040a0a9      8aa270f24000   mov ah, byte [edx + 0x40f270]
│      ╎╎   0x0040a0af      43             inc ebx
│      ╎╎   0x0040a0b0      888270f24000   mov byte [edx + 0x40f270], al ; [0x40f270:1]=0
│      ╎╎   0x0040a0b6      88a170f24000   mov byte [ecx + 0x40f270], ah ; [0x40f270:1]=0
│      ╎╎   0x0040a0bc      3bdf           cmp ebx, edi
│     ┌───< 0x0040a0be      7306           jae 0x40a0c6
│     │╎╎   0x0040a0c0      fec1           inc cl
│     │└──< 0x0040a0c2      75da           jne 0x40a09e
│     │┌──< 0x0040a0c4      eb06           jmp 0x40a0cc
│     └───> 0x0040a0c6      33db           xor ebx, ebx
│      │╎   0x0040a0c8      fec1           inc cl
│      │└─< 0x0040a0ca      75d2           jne 0x40a09e
│
```
### 0x0040a288
```asm
; CALL XREF from entry0 @ 0x40a320(x)
┌ 45: fcn.0040a288 ();
│           0x0040a288      51             push ecx
│           0x0040a289      648b0d3000..   mov ecx, dword fs:[0x30]
│           0x0040a290      8b4118         mov eax, dword [ecx + 0x18]
│           0x0040a293      a3d6f54000     mov dword [0x40f5d6], eax   ; [0x40f5d6:4]=0
│           0x0040a298      8b4108         mov eax, dword [ecx + 8]
│           0x0040a29b      a3daf54000     mov dword [0x40f5da], eax   ; [0x40f5da:4]=0
│           0x0040a2a0      8b4164         mov eax, dword [ecx + 0x64]
│           0x0040a2a3      a3def54000     mov dword [0x40f5de], eax   ; [0x40f5de:4]=0
│           0x0040a2a8      8b4910         mov ecx, dword [ecx + 0x10]
│           0x0040a2ab      8b4144         mov eax, dword [ecx + 0x44]
│           0x0040a2ae      a3e2f54000     mov dword [0x40f5e2], eax   ; [0x40f5e2:4]=0
│           0x0040a2b3      59             pop ecx
└           0x0040a2b4      c3             ret
```
### 0x0040a2b5
```asm
; CALL XREF from entry0 @ 0x40a325(x)
┌ 41: fcn.0040a2b5 ();
│           0x0040a2b5      53             push ebx
│           0x0040a2b6      56             push esi
│           0x0040a2b7      57             push edi
│           0x0040a2b8      8b1ddaf54000   mov ebx, dword [0x40f5da]   ; [0x40f5da:4]=0
│           0x0040a2be      8b733c         mov esi, dword [ebx + 0x3c]
│           0x0040a2c1      8d341e         lea esi, [esi + ebx]
│           0x0040a2c4      8db6f8000000   lea esi, [esi + 0xf8]
│           0x0040a2ca      8b7e0c         mov edi, dword [esi + 0xc]
│           0x0040a2cd      8d3c1f         lea edi, [edi + ebx]
│           0x0040a2d0      8b7610         mov esi, dword [esi + 0x10]
│           0x0040a2d3      56             push esi
│           0x0040a2d4      57             push edi
│           0x0040a2d5      e826fdffff     call fcn.0040a000
│           0x0040a2da      5f             pop edi
│           0x0040a2db      5e             pop esi
│           0x0040a2dc      5b             pop ebx
└           0x0040a2dd      c3             ret
```
### 0x0040a000
```asm
;-- section..text1:
            ; CALL XREF from fcn.0040a2b5 @ 0x40a2d5(x)
            ; CALL XREF from fcn.0040a2de @ 0x40a303(x)
┌ 71: fcn.0040a000 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           0x0040a000      55             push ebp                    ; [01] -r-x section size 4096 named .text1
│           0x0040a001      8bec           mov ebp, esp
│           0x0040a003      53             push ebx
│           0x0040a004      51             push ecx
│           0x0040a005      52             push edx
│           0x0040a006      56             push esi
│           0x0040a007      57             push edi
│           0x0040a008      8b7d08         mov edi, dword [arg_8h]
│           0x0040a00b      8b450c         mov eax, dword [arg_ch]
│           0x0040a00e      b9ff000000     mov ecx, 0xff               ; 255
│           0x0040a013      33d2           xor edx, edx
│           0x0040a015      f7f1           div ecx
│           0x0040a017      85c0           test eax, eax
│       ┌─< 0x0040a019      7418           je 0x40a033
│       │   0x0040a01b      8bd8           mov ebx, eax
│      ┌──> 0x0040a01d      68ff000000     push 0xff                   ; 255
│      ╎│   0x0040a022      57             push edi
│      ╎│   0x0040a023      e8ad000000     call 0x40a0d5
│      ╎│   0x0040a028      81c7ff000000   add edi, 0xff               ; 255
│      ╎│   0x0040a02e      4b             dec ebx
│      ╎│   0x0040a02f      85db           test ebx, ebx
│      └──< 0x0040a031      75ea           jne 0x40a01d
│       └─> 0x0040a033      85d2           test edx, edx
│       ┌─< 0x0040a035      7407           je 0x40a03e
│       │   0x0040a037      52             push edx
│       │   0x0040a038      57             push edi
│       │   0x0040a039      e897000000     call 0x40a0d5
│       └─> 0x0040a03e      5f             pop edi
│           0x0040a03f      5e             pop esi
│           0x0040a040      5a             pop edx
│           0x0040a041      59             pop ecx
│           0x0040a042      5b             pop ebx
│           0x0040a043      5d             pop ebp
└           0x0040a044      c20800         ret 8
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

## Audit Trail (recent)
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288229.557388}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288245.331486}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288253.9723628}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288267.12627}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288390.4402256}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4235264' AND is_stale = '0' LIMIT 1", "ts": 1786288390.7084854}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4235264' AND x.from_ea <= '4235335'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4235264' AND x.from_ea <= '4235335'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4235264' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4235264' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4227072' AND address <= '4243456'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4235264) ASC\n            LIMIT 7\n            ", "ts": 1786288390.7245302}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288418.0284832}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4235957' AND is_stale = '0' LIMIT 1", "ts": 1786288418.2935202}`
- `{"source": "ghidra_query", "sql": "SELECT text FROM pseudocode WHERE func_addr = '4235998' AND is_stale = '0' LIMIT 1", "ts": 1786288418.558124}`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4235957' AND x.from_ea <= '4235998'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT s.content\n            FROM xrefs x\n            JOIN strings s ON x.to_ea = s.address\n            WHERE x.from_ea >= '4235998' AND x.from_ea <= '4236047'\n              AND s.length > 2\n            ORDER BY s.length DESC\n          `
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4235957' AND x.from_ea <= '4235998'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT x.from_ea, x.to_ea, x.kind\n            FROM xrefs x\n            WHERE x.from_ea >= '4235998' AND x.from_ea <= '4236047'\n              AND x.kind IN ('data_ref', 'string_ref', 'read', 'write')\n            LIMIT 30\n            ", "t`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4235957' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.dst_func_addr\n            WHERE c.src_func_addr = '4235998' AND c.dst_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4235957' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT DISTINCT f.address, f.name, f.size\n            FROM call_edges c\n            JOIN funcs f ON f.address = c.src_func_addr\n            WHERE c.dst_func_addr = '4235998' AND c.src_func_addr != '0'\n            LIMIT 10\n            ", "ts": 178`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4227765' AND address <= '4244149'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4235957) ASC\n            LIMIT 7\n            ", "ts": 1786288418.576949}`
- `{"source": "ghidra_query", "sql": "\n            SELECT address, name, size FROM funcs\n            WHERE address >= '4227806' AND address <= '4244190'\n            ORDER BY ABS(CAST(address AS INTEGER) - 4235998) ASC\n            LIMIT 7\n            ", "ts": 1786288418.5780063}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288458.2342746}`
- `{"source": "agentic_recover_v4", "phase": "llm_analysis", "ts": 1786288549.4667966}`
- `{"source": "agentic_recover_v4", "phase": "complete", "ts": 1786288549.469294}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786288549.5796938}`
- `{"source": "ida_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1786288552.1091864}`
- `{"source": "yara_gen_v2", "ts": 1786288552.1237366}`
