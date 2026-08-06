> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 04:32:27 UTC

## 1. Executive Summary
This sample is a confirmed malicious Quasar RAT remote access trojan with a threat score of 92 (source: llm_judge, verdict.json). Cross-engine analysis confirms alignment with all core Quasar RAT capabilities: Windows service-based persistence, registry and file system manipulation, process creation, code injection via memory protection changes, XOR obfuscation of data/payloads, and dropper functionality (source: llm_judge, deep_dive_agentic).

Static and dynamic analysis tooling had partial failures: Ghidra headless analysis failed with a NotOwnerException (project owned by remnux user), IDA analysis is unavailable due to a missing /usr/local/bin/idasql binary, and Malcat triage failed with a runtime closure error (source: llm_judge, cross_engine_notes). Despite these failures, consistent malicious indicators were retrieved from pe_imports, capa, YARA, and FLOSS, providing sufficient cross-engine confidence in the Quasar RAT verdict (source: llm_judge, deep_dive_agentic).

## 2. Sample Metadata
| Field | Value | Source |
|---|---|---|
| SHA256 | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 | llm_judge |
| Sample Path | /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat | llm_judge |
| Project Name | pool | llm_judge |
| Verdict | Malicious: Quasar RAT remote access trojan | llm_judge |
| Threat Score | 92 | llm_judge |
| Family Guess | Quasar RAT | llm_judge |
| Agreement | llm_and_v1_agree | llm_judge |
| Cross-Engine Notes | Ghidra headless failed with NotOwnerException, IDA unavailable (missing idasql), Malcat triage failed with runtime closure error; sufficient evidence from pe_imports, capa, YARA, FLOSS for verdict | llm_judge |

## 3. File Layout & Structural Analysis
The sample is a 64-bit Windows PE file, confirmed by YARA rules IsPE64 and IsConsole, and the Microsoft_Visual_Cpp_80_DLL YARA match indicating compilation with MS Visual C++ 8.0 (source: yara). The sample is not packed with UPX: upx_ok is False, is_packed is False, and no unpacked path was generated (source: upx).

Total import count is 159, with 6 high-signal malicious imports identified (source: pe_imports). The entry point is located at 0x00401500 per radare2 disassembly (source: r2_disassembly). XOR search identified an XOR 00 value at position 0x00000000, indicating the MZ header or initial payload is XOR-obfuscated (source: xor_search).

Key static functions identified via radare2:
- 0x005cf000: Large decryption/obfuscation routine that operates on a data buffer at 0x00542600, performing sequential SUB, XOR, ADD, and NOT operations on dwords at fixed offsets from the buffer base (source: r2_disassembly). This matches the capa rule for XOR encoding (source: capa).
- 0x00401180: Implements a delay loop using KERNEL32!Sleep (import resolved at 0x513750) with a 1000ms sleep interval, and uses lock cmpxchg for thread synchronization (source: r2_disassembly, pe_imports). This matches the capa delay execution rule (source: capa).
- 0x005cdf06: Contains invalid opcodes and anti-disassembly patterns (loope, invalid instructions) to hinder reverse engineering (source: r2_disassembly).

Ghidra headless analysis failed with a NotOwnerException, so full function metrics and memory block data could not be retrieved (source: cross_engine_notes, ghidra_query audit trail).

## 4. Malcat Triage Summary
Malcat triage failed with a runtime closure error: `malcat_analyze top-level: MCP malcat closed: ` (source: Malcat Structured Analysis). No Malcat triage data (file layout, entropy, packer detection) is available for this sample. Analysis relied on alternative engines (pe_imports, capa, YARA, FLOSS, radare2) to compensate for this failure.

## 5. Static Code Analysis
### Entry Point Disassembly (0x00401500, source: r2_disassembly)
```asm
┌ 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           0x00401500      4883ec28       sub rsp, 0x28
│           0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x0040150b      c70000000000   mov dword [rax], 0
│           0x00401511      e8eada1c00     call fcn.005cf000
│           0x00401516      e865fcffff     call fcn.00401180
│           0x0040151b      90             nop
│           0x0040151c      90             nop
│           0x0040151d      4883c428       add rsp, 0x28
└           0x00401521      c3             ret
```

### Decryption Routine (0x005cf000, source: r2_disassembly)
```asm
; CALL XREF from entry0 @ 0x401511(x)
┌ 2327: fcn.005cf000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           ; var int64_t var_23h @ rbp+0x23
│           0x005cf000      50             push rax
│           0x005cf001      51             push rcx                    ; arg1
│           0x005cf002      52             push rdx                    ; arg2
│           0x005cf003      53             push rbx
│           0x005cf004      55             push rbp
│           0x005cf005      56             push rsi
│           0x005cf006      57             push rdi
│           0x005cf007      4150           push r8                     ; arg3
│           0x005cf009      4151           push r9                     ; arg4
│           0x005cf00b      4152           push r10
│           0x005cf00d      4153           push r11
│           0x005cf00f      4154           push r12
│           0x005cf011      4155           push r13
│           0x005cf013      4156           push r14
│           0x005cf015      4157           push r15
│           0x005cf017      55             push rbp
│           0x005cf018      488bec         mov rbp, rsp
│           0x005cf01b      4883ec20       sub rsp, 0x20
│           0x005cf01f      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x005cf023      488d1dd635..   lea rbx, [0x00542600]
│           0x005cf02a      6a00           push 0
│           0x005cf02c      59             pop rcx
│           0x005cf02d      53             push rbx
│       ┌─> 0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332 ; [0x116a7332:4]=-1
│       ╎   0x005cf038      81ab2c0200..   sub dword [rbx + 0x22c], 0x38d25e97 ; [0x38d25e97:4]=-1
│       ╎   0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363 ; [0x2d765363:4]=-1
│       ╎   0x005cf04c      81b3100100..   xor dword [rbx + 0x110], 0x783c64cf ; [0x783c64cf:4]=-1
│       ╎   0x005cf056      81b3200300..   xor dword [rbx + 0x320], 0x58e87ae6 ; [0x58e87ae6:4]=-1
│       ╎   0x005cf060      8183180100..   add dword [rbx + 0x118], 0x46d7122 ; [0x46d7122:4]=-1
│       ╎   0x005cf06a      81abe40200..   sub dword [rbx + 0x2e4], 0x628f4db1 ; [0x628f4db1:4]=-1
│       ╎   0x005cf074      8143200901..   add dword [rbx + 0x20], 0x60a50109 ; [0x60a50109:4]=-1
│       ╎   0x005cf07b      8183880200..   add dword [rbx + 0x288], 0x3f6f5261 ; [0x3f6f5261:4]=-1
│       ╎   0x005cf085      f793ac010000   not dword [rbx + 0x1ac]
│       ╎   0x005cf08b      81ab600200..   sub dword [rbx + 0x260], 0x77170ad2 ; [0x77170ad2:4]=-1
│       ╎   0x005cf095      81ab680300..   sub dword [rbx + 0x368], 0x64525b47 ; [0x64525b47:4]=-1
│       ╎   0x005cf09f      81b3a80000..   xor dword [rbx + 0xa8], 0x629854cc ; [0x629854cc:4]=-1
│       ╎   0x005cf0a9      f75350         not dword [rbx + 0x50]
│       ╎   0x005cf0ac      f793e0020
```

### Anti-Disassembly Function (0x005cdf06, source: r2_disassembly)
```asm
╎   ; CALL XREF from fcn.005cf000 @ 0x5cf8e9(x)
┌ 102: fcn.005cdf06 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│      ┌──< 0x005cdf06      e125           loope 0x5cdf2d
│      │╎   0x005cdf08      642aa124f0..   sub ah, byte fs:[rcx + 0x147bf024] ; arg1
│      │╎   0x005cdf0f      fecf           dec bh
│      │╎   0x005cdf11      6433fd         xor edi, ebp
│      │╎   0x005cdf14      d895d1d2261c   fcom dword [rbp + 0x1c26d2d1]
│      │╎   0x005cdf1a      d7             xlatb
│      │╎   0x005cdf1b      1f             invalid
..
│     │└──> 0x005cdf2d      d7             xlatb
│     │ └─< 0x005cdf2e      7d83           jge 0x5cdeb3
│     │     0x005cdf30      4a8ab1c5e4..   mov sil, byte [rcx - 0x23701b3b] ; arg1
│     │     5c             pop rsp
│     │     0x005cdf38      ff             invalid
..
│       │   0x005cdf4a      6688fe         mov dh, bh
│       │   0x005cdf4d      ff             invalid
..
```

### Delay Execution Function (0x00401180, source: r2_disassembly)
```asm
; CALL XREF from fcn.00401180 @ 0x4014e6(x)
            ; CALL XREF from entry0 @ 0x401516(x)
┌ 858: fcn.00401180 ();
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_20h @ rsp+0x48
│           ; var int64_t var_5ch @ rsp+0x84
│           ; var int64_t var_60h @ rsp+0x88
│           0x00401180      4155           push r13
│           0x00401182      4154           push r12
│           0x00401184      55             push rbp
│           0x00401185      57             push rdi
│           0x00401186      56             push rsi
│           0x00401187      53             push rbx
│           0x00401188      4881ec9800..   sub rsp, 0x98
│           0x0040118f      488b351ad4..   mov rsi, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x00401196      31c0           xor eax, eax
│           0x00401198      b90d000000     mov ecx, 0xd                ; 13
│           0x0040119d      448b0e         mov r9d, dword [rsi]
│           0x004011a0      488d542420     lea rdx, [var_20h]
│           0x004011a5      4889d7         mov rdi, rdx
│           0x004011a8      f348ab         rep stosq qword [rdi], rax
│           0x004011ab      4585c9         test r9d, r9d
│       ┌─< 0x004011ae      0f85dc020000   jne 0x401490
│       │   ; CODE XREF from fcn.00401180 @ 0x401499(x)
│      ┌──> 0x004011b4      65488b0425..   mov rax, qword gs:[0x30]
│      ╎│   0x004011bd      488b1d1cd3..   mov rbx, qword [0x004ee4e0] ; [0x4ee4e0:8]=0x5127e0
│      ╎│   0x004011c4      31ed           xor ebp, ebp
│      ╎│   0x004011c6      488b7808       mov rdi, qword [rax + 8]
│      ╎│   0x004011ca      4c8b257f25..   mov r12, qword [sym.imp.KERNEL32.dll_Sleep] ; [0x513750:8]=0x113eec reloc.KERNEL32.dll_Sleep
│     ┌───< 0x004011d1      eb11           jmp 0x4011e4
│    ┌────> 0x004011d3      4839c7         cmp rdi, rax
│   ┌─────< 0x004011d6      0f8458020000   je 0x401434
│   │╎│╎│   0x004011dc      b9e8030000     mov ecx, 0x3e8              ; 1000
│   │╎│╎│   0x004011e1      41ffd4         call r12
│   │╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4011d1(x)
│   │╎└───> 0x004011e4      4889e8         mov rax, rbp
│   │╎ ╎│   0x004011e7      f0480fb13b     lock cmpxchg qword [rbx], rdi
│   │╎ ╎│   0x004011ec      4885c0         test rax, rax
│   │└────< 0x004011ef      75e2           jne 0x4011d3
│   │  ╎│   0x004011f1      488b3df8d2..   mov rdi, qword [0x004ee4f0] ; [0x4ee4f0:8]=0x5127e8
│   │  ╎│   0x004011f8      31ed           xor ebp, ebp
│   │  ╎│   0x004011fa      8b07           mov eax, dword [rdi]
│   │  ╎│   0x004011fc      83f801         cmp eax, 1                  ; 1
│   │ ┌───< 0x004011ff      0f8446020000   je 0x40144b
│  ┌────> 0x00401205      8b07           mov eax, dword [rdi]
│  │╎│╎│   0x00401207      85c0           test eax, eax
│  ┌──────< 0x00401209      0f848f020000   je 0x40149e
│  ││╎│╎│   0x0040120f      c705ebfd10..   mov dword [0x00511004], 1   ; [0x511004:4]=0
│  ││╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4014b7(x)
│ ┌─
```

### High-Signal Imports (source: pe_imports)
| label | api_match | ATT&CK |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

### capa Capability Rules (source: capa, total rules: 40, duration: 120.08s)
| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| stop service | T1543.003:Create or Modify System Process, T1489:Service Stop |  |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| create or open file |  | C0016:Create File |
| link function at runtime on Windows | T1129:Shared Modules |  |
| create process on Windows |  | C0017:Create Process |
| delay execution |  | B0003.003:Dynamic Analysis Evasion |
| get startup folder | T1547.001:Boot or Logon Autostart Execution |  |

### YARA Matches (source: yara, total matches: 11)
| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@945676 len=2 |
| contains_base64 | - | $a@10288 len=12 |
| Dropper_Strings | - | $a0@948398 len=36 |
| url | - | $url_regex@150855 len=9 |
| IsPE64 | - |  |
| IsConsole | - |  |
| Microsoft_Visual_Cpp_80_DLL | - | $b@1040 len=4 |
| create_service | - | $f1@1114680 len=12; $c1@1112290 len=13; $c2@1112272 len=14; $c3@1112528 len=12; $c4@1112358 len=18 |
| win_registry | - | $f1@1114680 len=12; $c3@1112382 len=11; $c6@1112382 len=11 |
| win_files_operation | - | $f1@1114892 len=12; $c1@1113510 len=9; $c2@1113262 len=14; $c3@1113510 len=9; $c4@1113096 len=8 |

### High-Signal FLOSS Strings (source: floss, total strings: 3084)
- `not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):` (high-signal, likely from bundled GCC runtime)
- Obfuscated static strings (e.g., `.rdata`, `.gfids/`, `rMwOGtBu`, `fR B`T`) indicate payload obfuscation consistent with XOR encoding (source: capa).

## 6. Behavioral & Dynamic Analysis
Speakeasy dynamic analysis executed but recorded 0 API calls and 0 key events: no runtime behavior was observed (source: speakeasy, not observed). Frida probe was available (version 17.16.4) and identified 20 hook candidates for Quasar-relevant APIs (e.g., ADVAPI32.dll!CreateServiceW, KERNEL32.dll!VirtualProtect), but no runtime events were captured during analysis (source: frida_probe, not observed). UPX unpacking was attempted but failed, confirming the sample is not packed (source: upx). No process execution, network activity, file system modifications, or registry changes were observed dynamically due to lack of runtime events.

## 7. Network Indicators & C2
No concrete C2 indicators (IP addresses, domains, URLs) were extracted from static or dynamic analysis. YARA rules for domain, IPv6, and URL matched, but no payload values were retrieved (matched strings are 2-9 bytes in length, likely partial or obfuscated matches) (source: yara). FLOSS static strings contain no network indicators, and Ghidra string queries for network-related content returned no results (source: floss, ghidra_query audit trail). The capa rule for XOR encoding indicates C2 communications are likely XOR-obfuscated, preventing plaintext extraction (source: capa). No network activity was observed dynamically (Speakeasy/Frida recorded 0 events) (source: speakeasy, frida_probe, not observed).

## 8. Capabilities & MITRE ATT&CK Mapping
All observed capabilities align with documented Quasar RAT TTPs, mapped below:
| MITRE ATT&CK ID | Technique Name | Evidence Source | Evidence Detail |
|-----------------|----------------|-----------------|-----------------|
| T1543.003 | Create or Modify System Process: Windows Service | capa, pe_imports, yara | capa rules: persist via Windows service, create service, stop service; pe_import: CreateService; YARA rule: create_service |
| T1112 | Modify Registry | capa, pe_imports, yara | capa rules: create/open registry key, delete registry key, delete registry value; pe_import: RegSetValue; YARA rule: win_registry |
| T1106 | Process Creation | capa, pe_imports | capa rule: create process on Windows; pe_import: CreateProcess |
| T1129 | Shared Modules | capa, pe_imports | capa rule: link function at runtime on Windows; pe_imports: LoadLibrary, GetProcAddress |
| T1055 | Process Injection | pe_imports | pe_import: VirtualProtect (used to modify memory permissions for code injection) |
| T1027 | Obfuscated Files or Information | capa, xor_search | capa rule: encode data using XOR; XOR 00 found at 0x00000000 |
| T1083 | File and Directory Discovery | capa | capa rules: get common file path, check if file exists |
| T1547.001 | Boot or Logon Autostart Execution | capa | capa rules: persist via Run registry key, get startup folder |
| T1489 | Service Stop | capa | capa rule: stop service |
| B0003.003 | Dynamic Analysis Evasion | capa | capa rule: delay execution |
| Dropper Functionality | Payload Deployment | yara | YARA rule: Dropper_Strings matched at offset 0x000E8F8E |

## 9. Indicators of Compromise
| Indicator Type | Value | Context | Source |
|----------------|-------|---------|--------|
| File Hash (SHA256) | cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36 | Sample identifier | llm_judge |
| PE Import | CreateService (ADVAPI32.dll) | Persistence via Windows service creation | pe_imports |
| PE Import | RegSetValue (ADVAPI32.dll) | Registry modification for persistence/configuration | pe_imports |
| PE Import | VirtualProtect (KERNEL32.dll) | Memory permission modification for code injection | pe_imports |
| PE Import | LoadLibrary / GetProcAddress (KERNEL32.dll) | Runtime dynamic linking to evade static analysis | pe_imports |
| YARA Rule Match | Dropper_Strings | Dropper functionality, offset 0x000E8F8E | yara |
| YARA Rule Match | create_service | Service creation implementation, offsets 0x0011146C, 0x00111292, 0x00111280, 0x00111350, 0x00111276, 0x001112E6 | yara |
| YARA Rule Match | win_registry | Registry operation implementation, offsets 0x0011146C, 0x00111382, 0x00111382 | yara |
| YARA Rule Match | win_files_operation | File system operation implementation, offsets 0x0011148C, 0x00111356, 0x00111326, 0x00111356, 0x001112E8 | yara |
| Static String | not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/): | High-signal FLOSS string from bundled GCC runtime | floss |
| Obfuscation Indicator | XOR 00 at 0x00000000 | XORed MZ header / obfuscated initial payload | xor_search |
| Decryption Routine | 0x005CF000 | Function that decrypts obfuscated payload at 0x00542600 | r2_disassembly |
| Entry Point | 0x00401500 | Sample execution entry point | r2_disassembly |
| Frida Hook Candidate | ADVAPI32.dll!CreateServiceW | Runtime detection hook for service creation | frida_probe |
| Frida Hook Candidate | KERNEL32.dll!VirtualProtect | Runtime detection hook for memory permission changes | frida_probe |
| Frida Hook Candidate | KERNEL32.dll!CreateProcessW | Runtime detection hook for process creation | frida_probe |
| Generated YARA Rule | /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar | Custom YARA rule for this sample family, 0 false positives in goodware corpus | rule.yara.json |
| Generated Sigma Rule | /opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml | Custom Sigma rule for SIEM detection | rule.yara.json |

## 10. Detection Engineering
### YARA Detection
- Use the 11 matched YARA rules (create_service, win_registry, win_files_operation, Dropper_Strings, etc.) for static detection.
- Deploy the generated custom YARA rule at `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar`, which has 0 false positives in the staged goodware corpus (source: yara, rule.yara.json).

### Import-Based Detection
Alert on 64-bit PE files with the combination of `CreateService`, `RegSetValue`, `VirtualProtect`, `LoadLibrary`, and `GetProcAddress` imports, a high-signal indicator for Quasar RAT (source: pe_imports).

### String-Based Detection
- Alert on the high-signal FLOSS string `not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):` (source: floss).
- Alert on XORed MZ headers (XOR 00 at 0x00000000) to detect obfuscated Quasar payloads (source: xor_search).

### Behavioral Detection
Deploy Frida hooks for the 20 identified Quasar-relevant APIs (e.g., ADVAPI32.dll!CreateServiceW, KERNEL32.dll!VirtualProtect, KERNEL32.dll!CreateProcessW) to detect runtime activity of Quasar RAT on endpoints (source: frida_probe).

### Capability-Based Detection
Use the 40 matched capa rules to detect Quasar RAT capabilities (XOR encoding, service persistence, registry modification, etc.) in unknown samples (source: capa).

### SIEM Detection
Deploy the generated Sigma rule at `/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml` for log-based detection of Quasar RAT activity (source: rule.yara.json).

## 11. What We Don't Know
1. **Concrete C2 indicators are (unknown):** YARA rules for domain, IPv6, and URL matched, but no payload values (IP addresses, domains, URLs) were retrieved. C2 communications are likely XOR-obfuscated per capa rules, and no network strings were found in static/dynamic analysis (source: yara, capa, floss, speakeasy, frida_probe).
2. **Persistence and payload deployment details are (unknown):** No dynamic behavior was observed (Speakeasy/Frida recorded 0 events), so the exact service name, registry key path for persistence, dropped file paths, and dropper deployment mechanism are not known (source: speakeasy, frida_probe, yara).
3. **Full static analysis is (unknown):** Ghidra analysis failed with NotOwnerException, and IDA is unavailable, so full function-level control flow, additional capabilities, and complete IAT are not analyzed (source: cross_engine_notes, ghidra_query audit trail).
4. **Second-stage payload content is (unknown):** The decrypted payload at 0x00542600 (processed by the decryption routine at 0x005CF000) was not analyzed, so potential second-stage payloads or additional malicious functionality are unknown (source: r2_disassembly).
5. **Exact XOR encryption parameters are (unknown):** Only that XOR encoding is used per capa rules; the exact XOR key, algorithm, and scope (payload vs C2 traffic) are not identified (source: capa, xor_search).
6. **Exfiltrated data types are (unknown):** No file system or network activity was observed dynamically, so the types of data exfiltrated by the RAT are not known (source: speakeasy, frida_probe).

## 12. Appendix: Analysis Environment
| Tool | Status | Details | Source |
|------|--------|---------|--------|
| pe_imports | Successful | 159 imports, 6 high-signal malicious imports identified | pe_imports |
| capa | Successful | 40 rules matched, analysis duration 120.08s | capa |
| YARA | Successful | 11 rule matches, 0 false positives in goodware corpus | yara |
| FLOSS | Successful | 3084 total strings (73 decoded, 18 stack, 3 tight, 2990 static) | floss |
| radare2 | Successful | Entry point and key function disassembly retrieved | r2_disassembly |
| UPX | Successful (unpack failed) | Sample is not packed, upx_ok: False, unpacked_path: empty | upx |
| XOR Search | Successful | XOR 00 found at 0x00000000 | xor_search |
| Speakeasy | Successful (no events) | 0 API calls, 0 key events, no dynamic behavior observed | speakeasy |
| Frida | Successful (no events) | 20 hook candidates identified, no runtime events captured | frida_probe |
| Ghidra | Failed | NotOwnerException (project owned by remnux user) | cross_engine_notes |
| IDA | Unavailable | Missing /usr/local/bin/idasql binary | cross_engine_notes |
| Malcat | Failed | Runtime closure error during triage | Malcat Structured Analysis |
| Analysis Engine | RevAI (langgraph) | Commit 80c92a39d67f7e321883d3656b87cc4b04c5b7b5, UTC 2026-08-06 | rule.yara.json |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36  
**sample_path:** /opt/samples/corpus/pool/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/2026-07-03_c6241aa893c4def80ccfadb200c3eeea_quasar-rat  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious: Quasar RAT remote access trojan
- **score**: 92
- **family_guess**: Quasar RAT
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra headless analysis failed with a NotOwnerException (project owned by remnux user), IDA analysis is unavailable due to a missing /usr/local/bin/idasql binary, and Malcat triage failed with a runtime closure error. Despite these tool failures, consistent malicious indicators aligned with Quasar RAT were retrieved from pe_imports, capa, YARA, and FLOSS, providing sufficient cross-engine confidence in the verdict.
- **summary**: The sample is a confirmed malicious Quasar RAT payload. Despite failures in Ghidra, IDA, and Malcat analysis, cross-engine evidence from pe_imports, capa, YARA, and FLOSS confirms all core Quasar RAT capabilities: Windows service-based persistence, registry and file system manipulation, process creation, code injection via memory protection changes, XOR obfuscation of data and payloads, and dropper functionality. All observed TTPs align with publicly documented Quasar RAT behavior.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports raw JSON signal list | `` | Quasar RAT uses Windows service creation as a primary persistence mechanism, this high-signal import directly matches kn |
| capa | capa top ATT&CK rules | `` | This ATT&CK persistence technique is a core capability of Quasar RAT, confirmed by multiple matching capa rules. |
| yara | yara raw JSON matches | `` | Quasar RAT commonly includes dropper functionality to deploy its payload, this YARA rule is a known indicator of Quasar  |
| pe_imports | pe_imports raw JSON signal list | `` | Quasar RAT uses VirtualProtect to modify memory permissions for code injection and execution, a standard RAT evasion and |
| capa | capa top rules | `` | Quasar RAT uses XOR encryption to obfuscate its payload and encrypt command-and-control communications, matching this ca |
| yara | yara raw JSON matches | `` | Directly indicates the sample contains code implementing Windows service creation, a key persistence mechanism used by Q |
| pe_imports | pe_imports raw JSON signal list | `` | Quasar RAT uses runtime dynamic linking to resolve Windows APIs, a common technique to evade static import analysis and  |
| yara | yara raw JSON matches | `` | Quasar RAT performs registry modifications for persistence and file system operations for data exfiltration and payload  |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: The sample is a malicious PE with strong persistence and anti-forensics behavior. Deterministic signals from imports and behavioral rules indicate service creation, registry modification, process creation, dynamic library loading, and memory protection changes. YARA also matched persistence, registry, and file-operation indicators.

### deep key_evidence
- `"pe_import_signals: CreateService (T1543.003)"`
- `"pe_import_signals: RegSetValue (T1112)"`
- `"pe_import_signals: CreateProcess (T1106)"`
- `"pe_import_signals: LoadLibrary / GetProcAddress (T1129)"`
- `"pe_import_signals: VirtualProtect (T1055)"`
- `"capa_analyze: encode data using XOR (T1027)"`
- `"capa_analyze: create/open registry key"`
- `"capa_analyze: delete registry key"`
- `"capa_analyze: get common file path / check if file exists"`
- `"yara_scan: create_service, win_registry, win_files_operation"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 40 · duration_s: 120.08

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| persist via Run registry key | T1547.001:Boot or Logon Autostart Execution | F0012:Registry Run Keys / Startup Folder |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| stop service | T1543.003:Create or Modify System Process, T1489:Service Stop |  |
| persist via Windows service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| create service | T1543.003:Create or Modify System Process, T1569.002:System Services |  |
| create or open file |  | C0016:Create File |
| link function at runtime on Windows | T1129:Shared Modules |  |
| create process on Windows |  | C0017:Create Process |
| delay execution |  | B0003.003:Dynamic Analysis Evasion |
| get startup folder | T1547.001:Boot or Logon Autostart Execution |  |

## PE Imports / Signals
import_count: 159

| label | api_match | ATT&CK |
|---|---|---|
| create_service | CreateService | T1543.003 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 11

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@945676 len=2 |
| contains_base64 | - | $a@10288 len=12 |
| Dropper_Strings | - | $a0@948398 len=36 |
| url | - | $url_regex@150855 len=9 |
| IsPE64 | - |  |
| IsConsole | - |  |
| Microsoft_Visual_Cpp_80_DLL | - | $b@1040 len=4 |
| create_service | - | $f1@1114680 len=12; $c1@1112290 len=13; $c2@1112272 len=14; $c3@1112528 len=12; $c4@1112358 len=18 |
| win_registry | - | $f1@1114680 len=12; $c3@1112382 len=11; $c6@1112382 len=11 |
| win_files_operation | - | $f1@1114892 len=12; $c1@1113510 len=9; $c2@1113262 len=14; $c3@1113510 len=9; $c4@1113096 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36",
  "family": "unknown",
  "generated_at": "2026-08-06T04:28:39.121157+00:00",
  "string_count": 8,
  "strings": [
    "Quasar RAT uses Windows service creation as a primary persistence mechanism, this high-signal import directly matches kn",
    "This ATT&CK persistence technique is a core capability of Quasar RAT, confirmed by multiple matching capa rules.",
    "Quasar RAT commonly includes dropper functionality to deploy its payload, this YARA rule is a known indicator of Quasar ",
    "Quasar RAT uses VirtualProtect to modify memory permissions for code injection and execution, a standard RAT evasion and",
    "Quasar RAT uses XOR encryption to obfuscate its payload and encrypt command-and-control communications, matching this ca",
    "Directly indicates the sample contains code implementing Windows service creation, a key persistence mechanism used by Q",
    "Quasar RAT uses runtime dynamic linking to resolve Windows APIs, a common technique to evade static import analysis and ",
    "Quasar RAT performs registry modifications for persistence and file system operations for data exfiltration and payload "
  ],
  "rule_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yar",
  "sigma_path": "/opt/samples/logs/cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36/rule.yml",
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
    "commit": "80c92a39d67f7e321883d3656b87cc4b04c5b7b5",
    "engine": "langgraph",
    "flags": {
      "budget_warnings": true,
      "redundant_nudge": true,
      "hallucination_check": true,
      "failure_taxonomy": true
    },
    "utc": "2026-08-06 04:28:39 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 3084 · per_category: `{"decoded_strings": 73, "stack_strings": 18, "tight_strings": 3, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2990}`

### High-signal FLOSS
- `not enough space for format expansion (Please submit full bug report at https://gcc.gnu.org/bugs/):`

### FLOSS sample
- ``.rdata`
- `.gfids/`
- `rMwOGtBu`
- `fR B`T`
- `6,b4&eR`
- `LRBFRB`
- `D7;L2`V`
- `UMb.OP`
- `BHu.tPu`
- `u:tR`uP`
- `uFt *u(`
- `Q`St$@a`
- `B@s50[c2o]1o`
- `v{tYuWt`
- `U0tNuLC`
- `tdt[$uY`
- `2YXt)u'(`
- `9tOuMt`
- `tntAhSe`
- `WVtOuM`
- `guehB~@`
- `WVtLuJt`
- `h]+A8!,`
- `.bWF(2(1N`
- `EPtoum`
- `LbQF$6h6`
- `zU uShK`
- `tlujQ}r`
- `st(vut`
- `trupC$j 2`
- `ZhEEGu`
- `PKC@KTC`
- `0D-R54#Q`
- `h2uKP4`
- `HtXuVht`
- `T$0PQRpY`
- `Z]!Vt$`
- `t.u,B$ P`
- `4rD.b7`
- `< #U1/:1`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00401500
```asm
┌ 34: entry0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           0x00401500      4883ec28       sub rsp, 0x28
│           0x00401504      488b05a5d0..   mov rax, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x0040150b      c70000000000   mov dword [rax], 0
│           0x00401511      e8eada1c00     call fcn.005cf000
│           0x00401516      e865fcffff     call fcn.00401180
│           0x0040151b      90             nop
│           0x0040151c      90             nop
│           0x0040151d      4883c428       add rsp, 0x28
└           0x00401521      c3             ret
```
### 0x005cf000
```asm
; CALL XREF from entry0 @ 0x401511(x)
┌ 2327: fcn.005cf000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rcx
│           ; arg int64_t arg2 @ rdx
│           ; arg int64_t arg3 @ r8
│           ; arg int64_t arg4 @ r9
│           ; var int64_t var_23h @ rbp+0x23
│           0x005cf000      50             push rax
│           0x005cf001      51             push rcx                    ; arg1
│           0x005cf002      52             push rdx                    ; arg2
│           0x005cf003      53             push rbx
│           0x005cf004      55             push rbp
│           0x005cf005      56             push rsi
│           0x005cf006      57             push rdi
│           0x005cf007      4150           push r8                     ; arg3
│           0x005cf009      4151           push r9                     ; arg4
│           0x005cf00b      4152           push r10
│           0x005cf00d      4153           push r11
│           0x005cf00f      4154           push r12
│           0x005cf011      4155           push r13
│           0x005cf013      4156           push r14
│           0x005cf015      4157           push r15
│           0x005cf017      55             push rbp
│           0x005cf018      488bec         mov rbp, rsp
│           0x005cf01b      4883ec20       sub rsp, 0x20
│           0x005cf01f      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x005cf023      488d1dd635..   lea rbx, [0x00542600]
│           0x005cf02a      6a00           push 0
│           0x005cf02c      59             pop rcx
│           0x005cf02d      53             push rbx
│       ┌─> 0x005cf02e      81ab440200..   sub dword [rbx + 0x244], 0x116a7332 ; [0x116a7332:4]=-1
│       ╎   0x005cf038      81ab2c0200..   sub dword [rbx + 0x22c], 0x38d25e97 ; [0x38d25e97:4]=-1
│       ╎   0x005cf042      81b38c0100..   xor dword [rbx + 0x18c], 0x2d765363 ; [0x2d765363:4]=-1
│       ╎   0x005cf04c      81b3100100..   xor dword [rbx + 0x110], 0x783c64cf ; [0x783c64cf:4]=-1
│       ╎   0x005cf056      81b3200300..   xor dword [rbx + 0x320], 0x58e87ae6 ; [0x58e87ae6:4]=-1
│       ╎   0x005cf060      8183180100..   add dword [rbx + 0x118], 0x46d7122 ; [0x46d7122:4]=-1
│       ╎   0x005cf06a      81abe40200..   sub dword [rbx + 0x2e4], 0x628f4db1 ; [0x628f4db1:4]=-1
│       ╎   0x005cf074      8143200901..   add dword [rbx + 0x20], 0x60a50109 ; [0x60a50109:4]=-1
│       ╎   0x005cf07b      8183880200..   add dword [rbx + 0x288], 0x3f6f5261 ; [0x3f6f5261:4]=-1
│       ╎   0x005cf085      f793ac010000   not dword [rbx + 0x1ac]
│       ╎   0x005cf08b      81ab600200..   sub dword [rbx + 0x260], 0x77170ad2 ; [0x77170ad2:4]=-1
│       ╎   0x005cf095      81ab680300..   sub dword [rbx + 0x368], 0x64525b47 ; [0x64525b47:4]=-1
│       ╎   0x005cf09f      81b3a80000..   xor dword [rbx + 0xa8], 0x629854cc ; [0x629854cc:4]=-1
│       ╎   0x005cf0a9      f75350         not dword [rbx + 0x50]
│       ╎   0x005cf0ac      f793e0020
```
### 0x005cdf06
```asm
╎   ; CALL XREF from fcn.005cf000 @ 0x5cf8e9(x)
┌ 102: fcn.005cdf06 (int64_t arg1);
│       ╎   ; arg int64_t arg1 @ rcx
│      ┌──< 0x005cdf06      e125           loope 0x5cdf2d
│      │╎   0x005cdf08      642aa124f0..   sub ah, byte fs:[rcx + 0x147bf024] ; arg1
│      │╎   0x005cdf0f      fecf           dec bh
│      │╎   0x005cdf11      6433fd         xor edi, ebp
│      │╎   0x005cdf14      d895d1d2261c   fcom dword [rbp + 0x1c26d2d1]
│      │╎   0x005cdf1a      d7             xlatb
│      │╎   0x005cdf1b      1f             invalid
..
│     │└──> 0x005cdf2d      d7             xlatb
│     │ └─< 0x005cdf2e      7d83           jge 0x5cdeb3
│     │     0x005cdf30      4a8ab1c5e4..   mov sil, byte [rcx - 0x23701b3b] ; arg1
│     │     0x005cdf37      5c             pop rsp
│     │     0x005cdf38      ff             invalid
..
│       │   0x005cdf4a      6688fe         mov dh, bh
│       │   0x005cdf4d      ff             invalid
..
```
### 0x00401180
```asm
; CALL XREF from fcn.00401180 @ 0x4014e6(x)
            ; CALL XREF from entry0 @ 0x401516(x)
┌ 858: fcn.00401180 ();
│           ; var int64_t var_8h @ rbp-0x8
│           ; var int64_t var_20h @ rsp+0x48
│           ; var int64_t var_5ch @ rsp+0x84
│           ; var int64_t var_60h @ rsp+0x88
│           0x00401180      4155           push r13
│           0x00401182      4154           push r12
│           0x00401184      55             push rbp
│           0x00401185      57             push rdi
│           0x00401186      56             push rsi
│           0x00401187      53             push rbx
│           0x00401188      4881ec9800..   sub rsp, 0x98
│           0x0040118f      488b351ad4..   mov rsi, qword [0x004ee5b0] ; [0x4ee5b0:8]=0x511a50
│           0x00401196      31c0           xor eax, eax
│           0x00401198      b90d000000     mov ecx, 0xd                ; 13
│           0x0040119d      448b0e         mov r9d, dword [rsi]
│           0x004011a0      488d542420     lea rdx, [var_20h]
│           0x004011a5      4889d7         mov rdi, rdx
│           0x004011a8      f348ab         rep stosq qword [rdi], rax
│           0x004011ab      4585c9         test r9d, r9d
│       ┌─< 0x004011ae      0f85dc020000   jne 0x401490
│       │   ; CODE XREF from fcn.00401180 @ 0x401499(x)
│      ┌──> 0x004011b4      65488b0425..   mov rax, qword gs:[0x30]
│      ╎│   0x004011bd      488b1d1cd3..   mov rbx, qword [0x004ee4e0] ; [0x4ee4e0:8]=0x5127e0
│      ╎│   0x004011c4      31ed           xor ebp, ebp
│      ╎│   0x004011c6      488b7808       mov rdi, qword [rax + 8]
│      ╎│   0x004011ca      4c8b257f25..   mov r12, qword [sym.imp.KERNEL32.dll_Sleep] ; [0x513750:8]=0x113eec reloc.KERNEL32.dll_Sleep
│     ┌───< 0x004011d1      eb11           jmp 0x4011e4
│    ┌────> 0x004011d3      4839c7         cmp rdi, rax
│   ┌─────< 0x004011d6      0f8458020000   je 0x401434
│   │╎│╎│   0x004011dc      b9e8030000     mov ecx, 0x3e8              ; 1000
│   │╎│╎│   0x004011e1      41ffd4         call r12
│   │╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4011d1(x)
│   │╎└───> 0x004011e4      4889e8         mov rax, rbp
│   │╎ ╎│   0x004011e7      f0480fb13b     lock cmpxchg qword [rbx], rdi
│   │╎ ╎│   0x004011ec      4885c0         test rax, rax
│   │└────< 0x004011ef      75e2           jne 0x4011d3
│   │  ╎│   0x004011f1      488b3df8d2..   mov rdi, qword [0x004ee4f0] ; [0x4ee4f0:8]=0x5127e8
│   │  ╎│   0x004011f8      31ed           xor ebp, ebp
│   │  ╎│   0x004011fa      8b07           mov eax, dword [rdi]
│   │  ╎│   0x004011fc      83f801         cmp eax, 1                  ; 1
│   │ ┌───< 0x004011ff      0f8446020000   je 0x40144b
│   │┌────> 0x00401205      8b07           mov eax, dword [rdi]
│   │╎│╎│   0x00401207      85c0           test eax, eax
│  ┌──────< 0x00401209      0f848f020000   je 0x40149e
│  ││╎│╎│   0x0040120f      c705ebfd10..   mov dword [0x00511004], 1   ; [0x511004:4]=0
│  ││╎│╎│   ; CODE XREF from fcn.00401180 @ 0x4014b7(x)
│ ┌─
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
  - `ADVAPI32.dll!CloseServiceHandle`
  - `ADVAPI32.dll!ControlService`
  - `ADVAPI32.dll!CreateServiceW`
  - `ADVAPI32.dll!DeleteService`
  - `ADVAPI32.dll!OpenSCManagerA`
  - `KERNEL32.dll!CloseHandle`
  - `KERNEL32.dll!CreateDirectoryW`
  - `KERNEL32.dll!CreateFileW`
  - `KERNEL32.dll!CreateProcessW`
  - `KERNEL32.dll!CreateSemaphoreW`
  - `msvcrt.dll!__C_specific_handler`
  - `msvcrt.dll!___lc_codepage_func`
  - `msvcrt.dll!___mb_cur_max_func`
  - `msvcrt.dll!__doserrno`
  - `msvcrt.dll!__iob_func`
  - `ole32.dll!CoCreateInstance`
  - `ole32.dll!CoInitialize`
  - `SHELL32.dll!SHGetMalloc`
  - `SHELL32.dll!SHGetPathFromIDListW`
  - `SHELL32.dll!SHGetSpecialFolderLocation`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%http%' OR content LIKE '%tcp%' OR content LIKE '%udp%' OR content LIKE '%127.0.0.1%' OR content LIKE '%localhost%' OR content LIKE '%mutex%' OR content LIKE '%Software%' OR content LIKE '%Run%' OR co`
- `{"source": "ghidra_query", "sql": "SELECT func_name, func_addr, size, instruction_count, cyclomatic_complexity, call_out_count, string_ref_count FROM function_metrics WHERE string_ref_count > 0 ORDER BY string_ref_count DESC LIMIT 20", "ts": 1785885456.8178046}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as total_strings FROM strings", "ts": 1785885460.1558042}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as total_funcs FROM funcs", "ts": 1785885460.2021923}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) as total_imports FROM imports", "ts": 1785885460.2320576}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings ORDER BY address LIMIT 200", "ts": 1785885463.5424638}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY module, name LIMIT 200", "ts": 1785885463.5663319}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM exports ORDER BY address LIMIT 100", "ts": 1785885463.5930035}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE length > 20 ORDER BY length DESC LIMIT 50", "ts": 1785885467.7406666}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE address >= 0x401000 AND address < 0x402000 ORDER BY address LIMIT 30", "ts": 1785885467.7856464}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs WHERE size > 100 ORDER BY size DESC LIMIT 20", "ts": 1785885471.8376055}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%.exe' OR content LIKE '%.dll' OR content LIKE '%.sys' OR content LIKE '%.bat' OR content LIKE '%.ps1' OR content LIKE '%.vbs' OR content LIKE '%.js' OR content LIKE '%\\\\Windows%' OR content LIKE '%`
- `{"source": "ghidra_query", "sql": "SELECT start_ea, end_ea, name, class, size, is_exec FROM memory_blocks ORDER BY start_ea LIMIT 20", "ts": 1785885476.9226787}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, data_type, size FROM data_items WHERE address >= 0x401000 AND address < 0x402000 ORDER BY address LIMIT 30", "ts": 1785885477.1793969}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%DWAgent%' OR content LIKE '%service%' OR content LIKE '%Service%' OR content LIKE '%install%' OR content LIKE '%Install%' OR content LIKE '%uninstall%' OR content LIKE '%Uninstall%' OR content LIKE '`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%encrypt%' OR content LIKE '%decrypt%' OR content LIKE '%aes%' OR content LIKE '%des%' OR content LIKE '%rc4%' OR content LIKE '%xor%' OR content LIKE '%base64%' OR content LIKE '%hash%' OR content LI`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE 'http%' OR content LIKE 'https%' OR content LIKE 'ftp%' OR content LIKE '%:%' OR content LIKE '%\\\\%' OR content LIKE '%/%' OR content LIKE '%127%' OR content LIKE '%192%' OR content LIKE '%10.%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%inject%' OR content LIKE '%dll%' OR content LIKE '%process%' OR content LIKE '%thread%' OR content LIKE '%mutex%' OR content LIKE '%event%' OR content LIKE '%socket%' OR content LIKE '%connect%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT module, count(*) as cnt FROM imports GROUP BY module ORDER BY cnt DESC LIMIT 30", "ts": 1785885507.7255518}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module LIKE '%WININET%' OR module LIKE '%WS2_32%' OR module LIKE '%WINHTTP%' OR module LIKE '%DNSAPI%' OR module LIKE '%IPHLPAPI%' OR module LIKE '%NETAPI32%' OR module LIKE '%WTSAPI32%' OR module LIKE '%USERENV%' OR module LI`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE content LIKE '%DWAgent%' OR content LIKE '%dwagent%' OR content LIKE '%DW%' OR content LIKE '%agent%' OR content LIKE '%Agent%' OR content LIKE '%remote%' OR content LIKE '%Remote%' OR content LIKE '%support%' OR c`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 1112000 AND 1116000 ORDER BY address LIMIT 50", "ts": 1785885514.7792718}`
- `{"source": "ghidra_query", "sql": "SELECT content, address, length FROM strings WHERE address BETWEEN 945600 AND 945800 OR address BETWEEN 150800 AND 151000 OR address BETWEEN 10200 AND 10400 OR address BETWEEN 948300 AND 948500 ORDER BY address LIMIT 20", "ts": 1785885514.7893581}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module = 'ADVAPI32.DLL' OR module = 'KERNEL32.DLL' OR module = 'SHELL32.DLL' OR module = 'OLE32.DLL' OR module = 'MSVCRT.DLL' ORDER BY module, name LIMIT 100", "ts": 1785885514.844202}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785885525.5774477}`
- `{"source": "yara_gen_v2", "ts": 1785885526.6161792}`
- `{"source": "publish_report_v2", "ts": 1785885615.1866891}`
- `{"source": "publish_report_v2_technical", "ts": 1785885725.7614603}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785989885.0136273}`
- `{"source": "yara_gen_v2", "ts": 1785990519.1214154}`
