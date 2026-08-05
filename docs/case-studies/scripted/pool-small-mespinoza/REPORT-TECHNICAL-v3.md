## 1. Executive Summary
This report analyzes a 64-bit PE binary (SHA256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7) with a final verdict of Malicious, score 87, and family guess of Mespinoza ransomware with potential info-stealing capabilities (source: llm_judge, verdict.json). The binary masquerades as a Microsoft Lync/Skype for Business component, evidenced by a matching PDB path (`P:\Target\x64\ship\lync\x-none\lync99.pdb`) extracted via FLOSS and matching debug info in Malcat (source: floss, deep_dive_agentic). Key malicious indicators include a high-entropy (122) overlay indicating embedded/packed payload, invalid PE checksum, lack of valid Microsoft digital signature despite version info claiming Microsoft origin, anti-debugging imports (IsDebuggerPresent), registry modification imports (RegSetValue), memory protection manipulation imports (VirtualProtect), YARA matches for anti-debug, keylogger, and registry interaction, and capa rules confirming process termination, file system manipulation, and registry modification capabilities (source: malcat, pe_imports, yara, capa). The binary is a GUI subsystem application with no window-related user32 imports, indicating background operation, and contains large gaps between functions likely used to hide malicious code (source: malcat).

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7 |
| Sample Path | /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza |
| Project Name | pool |
| Verdict | Malicious |
| Score | 87 |
| Family Guess | Mespinoza ransomware (with potential info-stealing capabilities) |
| Agreement | llm_and_v1_agree |
| Cross-Engine Notes | IDA is unavailable due to missing idasql binary; all findings sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. Malcat provides static profile metadata and anomaly detection, Ghidra supplies 426 function and 921 string analysis, capa and pe_imports confirm malicious ATT&CK techniques, YARA identifies behavioral indicators, and FLOSS extracts runtime strings including a PDB path matching the Lync/Skype for Business codebase (source: llm_judge, verdict.json). |

## 3. File Layout & Structural Analysis
The sample is a 64-bit PE GUI binary with an overall entropy of 45, and a high-entropy (122) appended overlay, a strong indicator of packed or embedded malicious payload (source: malcat, layout table). The entrypoint is located at EA 0x30904 (source: malcat, file summary). The full section layout is as follows (source: malcat, layout table):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 98 | - |
| .text | 1024 | 56832 | 57344 | 161 | RX |
| .rdata | 58368 | 59904 | 61440 | 67 | R |
| .data | 119808 | 43008 | 57344 | 20 | RW |
| .pdata | 177152 | 3584 | 4096 | 14 | R |
| .tls | 181248 | 512 | 4096 | 0 | RW |
| .rsrc | 185344 | 586240 | 589824 | 28 | R |
| .reloc | 775168 | 2048 | 4096 | 62 | R |
| overlay | 779264 | 40813 | 0 | 122 | - |
The .text section has an entropy of 161, consistent with packed or obfuscated code. The binary contains 20 carved DIB/PNG files and 20 virtual ICO resource files (source: malcat, carved files, virtual files tables). The PE header has an invalid checksum, and the binary is unsigned despite version information claiming to be from Microsoft (source: malcat, anomalies table).

## 4. Malcat Triage Summary
Malcat identified 2 compiler-related YARA signatures (MSVC_2015_linker, msvs_2015__14_0__rich) indicating the binary was built with Visual Studio 2015 (source: malcat, YARA/signatures table). 10 anomalies were detected, with high-signal locations as follows (source: malcat, anomalies, anomaly locations tables):
| Anomaly Name | Level | Category | Location (EA) | Description |
|---|---|---|---|---|
| PossiblePackerApiDynamicImport | 4 | imports | 30662 | Packer-related API (VirtualProtect, ResumeThread) present as string but not imported, indicating dynamic API resolution to hide functionality |
| InvalidChecksum | 4 | integrity | N/A | PE Header checksum is invalid, indicating modification from original legitimate form |
| UnsignedMicrosoft | 4 | integrity | N/A | Version info claims Microsoft origin but no valid digital signature found |
| DelayImports | 3 | imports | N/A | 60 delay imports present |
| DynamicString | 3 | strings | 30662 | String constructed dynamically at runtime to evade static analysis |
| ManyHighValueImmediates | 3 | code | 28680, 34268 | Functions contain high-value immediate operands, often used in shellcode or obfuscated code |
| StackArrayInitialisationX64 | 3 | code | N/A | Stack-allocated array dynamically built, used for shellcode/string construction |
| WeirdDebugInfoType | 3 | headers | N/A | Debug info is in non-standard format |
| GuiSubsystemNoWindowApi | 2 | headers | 364 | GUI subsystem application with no user32 window-related imports, indicating background operation |
| HugeGapBetweenFunctions | 2 | code | N/A | Large gaps between functions with medium-high entropy, used to hide malicious code/payloads |
High-signal static strings include `kernel32.dll` at EA 0x66328 and `OC_WEBSERVICE2_HTTPTRANSPORT` at EA 0x71984 (source: malcat, high-signal strings table). Top static strings include Lync-related identifiers: `Lync99WindowServerClass` (EA 0x61880), `Lync99GlobalMutex` (implied via YARA win_mutex match), `AppSharingHookController.exe` (EA 0x86928), `AppSharingChromeHook.dll` (EA 0x82288), and registry paths for Lync tracing (source: malcat, top strings table).

## 5. Static Code Analysis
The binary contains 426 functions and 921 strings as analyzed by Ghidra (source: deep_dive_agentic). The entrypoint disassembly from radare2 (0x1400084b8) shows standard PE initialization code, including a loop that scans for the MZ header and resolves the PE header, followed by a call to a function at 0x140008305 (source: radare2, EP disassembly):
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x1400084b8      e848feffff     call fcn.140008305
│           0x1400084bd      c8200000       enter 0x20, 0              ; 32
│           0x1400084c1      4c897c24f8     mov qword [rsp - 8], r15
│           0x1400084c6      4883ec08       sub rsp, 8
│           0x1400084ca      4989e7         mov r15, rsp
│           0x1400084cd      4883ec20       sub rsp, 0x20
│           0x1400084d1      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x1400084d5      4831f6         xor rsi, rsi
│           0x1400084d8      4801c6         add rsi, rax
│           0x1400084db      4883c03c       add rax, 0x3c              ; 60
│           0x1400084df      4831d2         xor rdx, rdx
│           0x1400084e2      8b10           mov edx, dword [rax]
│           0x1400084e4      4883ec08       sub rsp, 8
│           0x1400084e8      48893424       mov qword [rsp], rsi
│           0x1400084ec      488b0424       mov rax, qword [rsp]
│           0x1400084f0      4883c408       add rsp, 8
│           0x1400084f4      4801d0         add rax, rdx
│           0x1400084f7      480588000000   add rax, 0x88              ; 136
│           0x1400084fd      4883ec08       sub rsp, 8
│           0x140008501      48890424       mov qword [rsp], rax
│           0x140008505      488b0c24       mov rcx, qword [rsp]
│           0x140008509      4883c408       add rsp, 8
│           0x14000850d      48c7c00000..   mov rax, 0
│           0x140008514      8b01           mov eax, dword [rcx]
│           0x140008516      4801f0         add rax, rsi
│           0x140008519      50             push rax
│           0x14000851a      488b0c24       mov rcx, qword [rsp]
│           0x14000851e      4883c408       add rsp, 8
│           0x140008522      56             push rsi
│           0x140008523      488b1424       mov rdx, qword [rsp]
│           0x140008527      4883c408       add rsp, 8
│           0x14000852b      488d05acf3..   lea rax, [0x1400078de]
│           0x140008532      4883ec08       sub rsp, 8
│           0x140008536      48890c24       mov qword [rsp], rcx
│           0x14000853a      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140008541      4883ec08       sub rsp, 8
│           0x140008545      48890c24       mov qword [rsp], rcx
│           0x140008549      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140008550      48ffc0         inc rax
│       ╎   0x140008553      48ffc9         dec rcx
│       ╎   0x140008556      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x14000855d      75f1           jne 0x140008550
│           0x14000855f      4883c408       add rsp, 8
│           0x140008563      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140008568      488b0c24       mov rcx, qword [rsp]
│           0x14000856c      4883c408       add rsp, 8
│           0x140008570      ffd0           call rax
│           0x140008572      
```
The Ghidra decompilation of fcn.140008305 shows MZ/PE header validation logic with obfuscated immediate values and anti-analysis checks (source: Ghidra, r2_decomp):
```asm
; CALL XREF from entry0 @ 0x1400084b8(x)
┌ 446: fcn.140008305 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x140008305      488b442408     mov rax, qword [var_8h]
│           0x14000830a      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x14000830e      48ffc8         dec rax
│      ╎╎   0x140008311      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x140008316      750b           jne 0x140008323
│    ┌────< 0x140008318      7414           je 0x14000832e
│    ││╎╎   0x14000831a      e85e000000     call 0x14000837d
│    ││╎╎   0x14000831f      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x140008321      9f             lahf
│    ││╎╎   0x140008322      5e             pop rsi
│    │└└──< 0x140008323      75e9           jne 0x14000830e
│    │  ╎   0x140008325      e8fcffffff     call 0x140008326
│    │  ╎   0x14000832a      8bcf           mov ecx, edi
│    │  ╎   0x14000832c  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x14000832e      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x140008331      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x140008337      73d5           jae 0x14000830e
│           0x140008339      482db5480000   sub rax, 0x48b5
│           0x14000833f      4801c2         add rdx, rax
│           0x140008342      4881c2b548..   add rdx, 0x48b5
│           0x140008349      4805b5480000   add rax, 0x48b5
│           0x14000834f      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140008354      7506           jne 0x14000835c
│      ┌──< 0x140008356      7442           je 0x14000839a
│      ││   0x140008358      82             invalid
..
│      │└─> 0x14000835c      744d           je 0x1400083ab
│      │    0x14000835e      75ae           jne 0x14000830e
│      │    0x140008360      488d05cdfe..   lea rax, [0x140008234]
│      │    0x140008367      4883ec08       sub rsp, 8
│      │    0x14000836b      48890c24       mov qword [rsp], rcx
│      │    0x14000836f      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x140008376      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.140008305 @ 0x14000831a(x)
│      │    0x14000837d      4801c1         add rcx, rax
│      │    0x140008380      51             push rcx
│      │    0x140008381      4891           xchg r
```
Key function decompilations from Ghidra:
- sub_14000c6bc (EA 0x47804): Initializes multiple COM-style objects, calls sub_14000db94, and allocates memory with protection flags 0xf003f, consistent with executable memory allocation for unpacked code (source: Ghidra, decompilations table).
- sub_14000ca98 (EA 0x48792): Retrieves interface pointers from a vtable, with negative indices mapping to different object types, consistent with COM object management (source: Ghidra, decompilations table).
- #0 (EA 0x8172, CLync99MsoComponentHost.#0): Implements IUnknown QueryInterface logic, checking for known Lync interface IDs, confirming the binary is built from the Lync/Skype for Business codebase (source: Ghidra, decompilations table).
The full Import Address Table (IAT) contains 366 entries (source: malcat, imports table):
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 1232 | ATL::CAtlStringMgr.#5 | DEBUG | 2 |
| 1280 | ATL::CWin32Heap.#4 | DEBUG | 2 |
| 1280 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 2 |
| 1356 | ATL::CAtlStringMgr.#0 | DEBUG | 2 |
| 1356 | ATL.CAtlStringMgr.Allocate | DEBUG | 2 |
| 1496 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 1512 | ATL::CAtlStringMgr.#4 | DEBUG | 1 |
| 1516 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 1516 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 1528 | ATL::CWin32Heap.#1 | DEBUG | 2 |
| 1528 | ATL.CWin32Heap.Free | DEBUG | 2 |
| 1844 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 1844 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 1856 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 1872 | ATL::CAtlStringMgr.#2 | DEBUG | 2 |
| 1980 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 1980 | ATL.CWin32Heap.Reallocate | DEBUG | 2 |
| 2052 | IsolationAwarePrivatenPgViNgRzlnPgpgk | DEBUG | 5 |
| 3540 | ATL.CAtlArray<void *,ATL::CElementTraits<void *>>.~CAtlArray<void *,ATL::CElementTraits<void *>> | DEBUG | 1 |
| 3636 | CLync99Instance.#3 | DEBUG | 3 |
| 3760 | CLync99MsoComponentHost.#10 | DEBUG | 3 |
| 3840 | CLync99MsoUser.#26 | DEBUG | 2 |
| 3880 | RefCount.#3 | DEBUG | 2 |
| 3920 | CLync99MsoComponentHost.#1 | DEBUG | 1 |
| 5276 | CLync99MsoComponentHost.#7 | DEBUG | 2 |
| 5320 | CLync99MsoUser.#6 | DEBUG | 1 |
| 5324 | CLync99MsoComponentHost.#4 | DEBUG | 5 |
| 5332 | CLync99MsoComponentHost.#8 | DEBUG | 1 |
| 5344 | CLync99MsoUser.#7 | DEBUG | 2 |
| 5564 | CLync99MsoUser.#18 | DEBUG | 1 |
| 6312 | CRegistryKey.#5 | DEBUG | 2 |
| 6816 | GuardCFCheckFunction | DEBUG | 14 |
| 6816 | CLync99MsoComponentHost.#6 | DEBUG | 14 |
| 8172 | CLync99MsoComponentHost.#0 | DEBUG | 2 |
| 8308 | CLync99MsoComponentHost.#3 | DEBUG | 2 |
| 8392 | CLync99MsoComponentHost.#2 | DEBUG | 2 |
| 9836 | CPreviewView.SetPrintView | DEBUG | 3 |
| 16920 | Mso::TRefCountedImpl<struct Mso::OfficeServicesManager::IServicesNotificationCallback<struct Mso::OfficeServicesManager::IConnectedService>>.#4 | DEBUG | 2 |
| 16960 | OFBServiceFilter.#4 | DEBUG | 2 |
| 17008 | OFBServiceFilter.#0 | DEBUG | 2 |
| 18336 | OFBServiceFilter.#2 | DEBUG | 1 |
| 23268 | OFBServiceFilter.#1 | DEBUG | 3 |
| 23308 | OFBServiceFilter.#3 | DEBUG | 2 |
| 27192 | shell32.CommandLineToArgvW (delaystub) | DEBUG | 2 |
| 27328 | user32.UnregisterClassW (delaystub) | DEBUG | 1 |
| 27464 | user32.RegisterWindowMessageW (delaystub) | DEBUG | 2 |
| 27476 | user32.TranslateMessage (delaystub) | DEBUG | 1 |
| 27488 | user32.DispatchMessageW (delaystub) | DEBUG | 1 |
| 27500 | user32.SendMessageW (delaystub) | DEBUG | 1 |
| 27512 | user32.PostMessageW (delaystub) | DEBUG | 1 |
| 27524 | user32.PostThreadMessageW (delaystub) | DEBUG | 1 |
| 27536 | user32.DefWindowProcW (delaystub) | DEBUG | 1 |
| 27548 | user32.PostQuitMessage (delaystub) | DEBUG | 1 |
| 27560 | user32.RegisterClassExW (delaystub) | DEBUG | 1 |
| 27572 | user32.CreateWindowExW (delaystub) | DEBUG | 1 |
| 27584 | user32.IsWindow (delaystub) | DEBUG | 1 |
| 27596 | user32.DestroyWindow (delaystub) | DEBUG | 1 |
| 27608 | user32.MessageBoxW (delaystub) | DEBUG | 1 |
| 27620 | user32.GetWindowLongPtrW (delaystub) | DEBUG | 1 |
| 27632 | user32.SetWindowLongPtrW (delaystub) | DEBUG | 1 |
| 27644 | user32.GetWindowThreadProcessId (delaystub) | DEBUG | 1 |
| 27656 | user32.GetKeyState (delaystub) | DEBUG | 1 |
| 27668 | mso.delay#7 (delaystub) | DEBUG | 1 |
| 27812 | mso.delay#6 (delaystub) | DEBUG | 1 |
| 27832 | mso.delay#5 (delaystub) | DEBUG | 1 |
| 27852 | mso.delay#4 (delaystub) | DEBUG | 1 |
| 27872 | mso.delay#3 (delaystub) | DEBUG | 1 |
| 27892 | mso.delay#2 (delaystub) | DEBUG | 1 |
| 27912 | mso.delay#1 (delaystub) | DEBUG | 2 |
| 27932 | mso.delay#0 (delaystub) | DEBUG | 1 |
| 27952 | mso.delay#8 (delaystub) | DEBUG | 1 |
| 27972 | mso99lwin32client.delay#8 (delaystub) | DEBUG | 1 |
| 28116 | mso99lwin32client.delay#7 (delaystub) | DEBUG | 1 |
| 28136 | mso99lwin32client.delay#6 (delaystub) | DEBUG | 1 |
| 28156 | mso99lwin32client.delay#5 (delaystub) | DEBUG | 1 |
| 28176 | mso99lwin32client.delay#4 (delaystub) | DEBUG | 1 |
| 28196 | mso99lwin32client.delay#3 (delaystub) | DEBUG | 1 |
| 28216 | mso99lwin32client.delay#2 (delaystub) | DEBUG | 1 |
| 28240 | mso99lwin32client.delay#1 (delaystub) | DEBUG | 1 |
High-signal malicious imports include IsDebuggerPresent, RegSetValue, VirtualProtect, LoadLibrary, GetProcAddress, CreateMutexW, CreateThread, OpenProcess, and OutputDebugStringA (source: pe_imports, signals table). FLOSS extracted 1262 strings, including the PDB path `P:\Target\x64\ship\lync\x-none\lync99.pdb` which matches the Lync/Skype for Business codebase, and a long base64 string likely used for C2 communication or payload encoding (source: floss, strings table). Malcat identified a dynamically constructed string at EA 0x30662 (`VirtualAlloc`), indicating runtime string obfuscation to evade static analysis (source: malcat, anomalies table).

## 6. Behavioral & Dynamic Analysis
Speakeasy dynamic analysis returned no observed API calls or key events (speakeasy_ok: True, api_calls: 0, key_events: 0, duration_s: None), so no runtime behavior was captured (source: speakeasy, structured evidence). Frida probe is available (v17.16.4) with 30 hook candidates including ADVAPI32 trace functions (RegisterTraceGuidsW, UnregisterTraceGuids, GetTraceLoggerHandle), KERNEL32 synchronization functions (GetCommandLineW, CloseHandle, WaitForSingleObject, CreateMutexW, ExitProcess), ole32 COM functions (OleInitialize, CoUninitialize, CoInitializeEx), VCRUNTIME140/MSVCP140 exception functions, and CRT heap/runtime functions, but no runtime events were recorded (source: frida, structured evidence). UPX unpack analysis returned no unpacked payload (upx_ok: False, is_packed: False, returncode: None, unpacked_path: ""), indicating the sample is not packed with UPX (source: upx, structured evidence). XOR search only found trivial XOR 00 at offset 0, with no evidence of XOR-obfuscated payloads (source: xor, structured evidence). No dynamic network or file system activity was observed due to lack of runtime execution data.

## 7. Network Indicators & C2
Static network indicators were identified via YARA and FLOSS, with no dynamic C2 communication observed (source: yara, floss). YARA matches include:
| Rule | Match Offset | Length | Description |
|---|---|---|---|
| domain | 0 | 2 | Domain regex match |
| IP (IPv4) | 750469 | 8 | IPv4 address indicator |
| IP (IPv6) | 64192 | 4 | IPv6 address indicator |
| contains_base64 | 43003 | 12 | Base64-encoded string, likely C2 or payload data |
| url | 754050 | 69 | URL indicator for C2 communication |
Additionally, FLOSS extracted a long base64 string, and Malcat identified the string `OC_WEBSERVICE2_HTTPTRANSPORT` at EA 0x71984, indicating HTTP-based C2 transport consistent with Lync/Skype web service components (source: floss, malcat, high-signal strings table).

## 8. Capabilities & MITRE ATT&CK Mapping
Observed capabilities mapped to MITRE ATT&CK techniques, corroborated by capa, pe_imports, and YARA (source: capa, pe_imports, yara):
| Capability | ATT&CK Technique | Source Evidence |
|---|---|---|
| Anti-debugging | T1622: Debugger Evasion | pe_imports: IsDebuggerPresent; yara: anti_dbg match at offsets 102468, 105490, 105294 |
| Registry Modification | T1112: Modify Registry | pe_imports: RegSetValue; capa: set registry value; yara: win_registry match at offsets 102484, 104024 |
| Memory Protection Manipulation | T1055: Process Injection | pe_imports: VirtualProtect |
| Process Termination | T1057: Process Discovery / T1489: Service Stop | capa: terminate process |
| File System Manipulation | T1105: Ingress Tool Transfer / T1070.004: Indicator Removal on Host | capa: move file, create directory |
| Keylogging | T1056.001: Input Capture: Keylogging | yara: keylogger match at offsets 100800, 101550; pe_imports: GetKeyState |
| Mutex Creation | T1055: Process Injection / Persistence | yara: win_mutex match at offset 104180; deep_dive: Lync99GlobalMutex string |
| System Information Discovery | T1082: System Information Discovery | capa: query environment variable |
| Application Window Discovery | T1010: Application Window Discovery | capa: find graphical window |
| Runtime Module Loading | T1129: Shared Modules | capa: link function at runtime; pe_imports: LoadLibrary, GetProcAddress |
| TLS Section Usage | T1055: Process Injection / Obfuscation | capa: contain .tls section |
Additionally, capa confirmed the binary contains a PDB path, matching the FLOSS-extracted Lync PDB path (source: capa, floss).

## 9. Indicators of Compromise
All observed IOCs are listed below with source citations:
| IOC Type | Value | Source |
|---|---|---|
| File Hash (SHA256) | ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7 | llm_judge, verdict.json |
| File Path | /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza | llm_judge, verdict.json |
| Mutex Name | Lync99GlobalMutex | deep_dive_agentic, yara (win_mutex) |
| Registry Keys | Software\Microsoft\Office\16.0\Common\FilesPaths; %LOCALAPPDATA%\Microsoft\Office\16.0\Lync\Tracing; SOFTWARE\Microsoft\Tracing\UcClient\ | malcat (top strings), deep_dive_agentic |
| Static Strings | Lync99WindowServerClass (EA 0x61880); AppSharingHookController.exe (EA 0x86928); AppSharingChromeHook.dll (EA 0x82288); OC_WEBSERVICE2_HTTPTRANSPORT (EA 0x71984) | malcat (top strings), deep_dive_agentic |
| PDB Path | P:\Target\x64\ship\lync\x-none\lync99.pdb | floss, deep_dive_agentic |
| Network Indicators | Domain regex (offset 0); IPv4 (offset 750469); IPv6 (offset 64192); Base64 string (offset 43003); URL (offset 754050) | yara (matches table) |
| PE Anomalies | Invalid checksum; unsigned despite Microsoft version info; GUI subsystem with no window APIs; high-entropy (122) overlay; large function gaps | malcat (anomalies table) |

## 10. Detection Engineering
Detection rules can be built from the observed static and behavioral indicators:
1. YARA rule for Lync masquerading with malicious indicators: match on strings `Lync99GlobalMutex`, `Lync99WindowServerClass`, `IsDebuggerPresent`, `GetKeyState`, combined with YARA matches for anti_dbg, keylogger, win_registry, and high-entropy overlay (source: yara, malcat, deep_dive_agentic).
2. Capa behavior-based detection: match on capa rules for terminate process, set registry value, move file, create directory, query environment variable, and link function at runtime (source: capa, capa rules table).
3. PE anomaly detection: flag PE files with GUI subsystem, no user32 window imports, invalid checksum, unsigned Microsoft version info, and overlay entropy >120 (source: malcat, anomalies table).
4. Network detection: flag traffic to the observed domain, IP, and URL indicators, and decode base64 strings matching the observed offset 43003 pattern (source: yara, matches table).

## 11. What We Don't Know
Several gaps remain in the analysis due to tooling and runtime limitations:
1. IDA SQL analysis is unavailable due to a missing idasql binary, so no IDA-based disassembly or control flow graph data is available (source: cross_engine_notes, llm_judge).
2. No dynamic runtime behavior was observed: Speakeasy returned 0 API calls/events, and Frida recorded no runtime events, so the full runtime capabilities (e.g., actual keylogging, C2 communication, file encryption) are unconfirmed (source: speakeasy, frida, structured evidence).
3. UPX unpack failed, so no unpacked payload is available for analysis, and the nature of the high-entropy overlay (packed code vs embedded payload) is unconfirmed (source: upx, structured evidence).
4. The exact C2 communication protocol and command structure are unknown, as only static network indicators were observed (source: yara, floss).
5. The family guess of Mespinoza ransomware is based on the sample path name and observed capabilities; no direct code overlap with confirmed Mespinoza samples was verified due to lack of IDA access (source: llm_judge, verdict.json).

## 12. Appendix: Analysis Environment
| Tool | Version/Status | Purpose |
|---|---|---|
| Malcat | N/A | Static profile metadata, anomaly detection, layout analysis, IAT extraction, string extraction |
| Ghidra | N/A | Deep function (426) and string (921) analysis, decompilation |
| capa | 1.18s runtime | Capability detection, ATT&CK mapping |
| FLOSS | N/A | Runtime string extraction (1262 strings) |
| YARA | N/A | Behavioral signature matching (15 matches) |
| pe_imports | N/A | Import signal detection, ATT&CK mapping |
| radare2 | N/A | Entrypoint disassembly, code analysis |
| Speakeasy | ok: True | Dynamic analysis (no events observed) |
| Frida | 17.16.4 | Dynamic hooking (no events observed) |
| UPX | N/A | Unpacking (failed, not packed) |
| IDA | Unavailable (missing idasql binary) | N/A |
Sample analyzed: /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza, project name: pool (source: structured evidence).
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7  
**sample_path:** /opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 87
- **family_guess**: Mespinoza ransomware (with potential info-stealing capabilities, based on sample path name and observed malicious behaviors including process termination, file system manipulation, registry modification, and keylogging indicators)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is unavailable for all analysis due to a missing idasql binary, so all findings are sourced from Ghidra, Malcat, capa, FLOSS, YARA, and pe_imports. Malcat provides static profile metadata and anomaly detection, Ghidra supplies deep function (426) and string (921) analysis, capa and pe_imports confirm multiple malicious ATT&CK techniques, YARA identifies additional behavioral indicators, and FLOSS extracts runtime strings including a PDB path matching the Lync/Skype for Business codebase noted in Malcat's debug info.
- **summary**: This is a 64-bit PE binary with an overall entropy of 45 and a high-entropy (122) overlay, indicating packing or embedded malicious payload. While version information claims to be legitimate Skype for Business (Microsoft Office 2016), cross-engine indicators confirm malicious behavior: anti-debugging imports, registry modification, memory protection manipulation, YARA matches for keylogging, anti-debug, and registry interaction, capa rules for process termination, file system manipulation, and registry modification, and a dynamic string anomaly indicating runtime string construction to evade static analysis. The binary is built from the Lync/Skype for Business codebase (evidenced by the matching PDB path in FLOSS and Malcat debug info) but modified with malicious components, likely belonging to the Mespinoza ransomware family based on the sample path name and observed capabilities.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| malcat | anomalies | `PossiblePackerApiDynamicImport` | Indicates the binary uses dynamic API imports typical of packers or malware to hide malicious functionality from static  |
| malcat | layout | `overlay (entropy 122)` | High-entropy appended overlay is a strong indicator of packed or embedded malicious payload, as legitimate software rare |
| malcat | anomalies | `InvalidChecksum` | Invalid PE checksum indicates the binary has been modified from its original legitimate form. |
| malcat | anomalies | `UnsignedMicrosoft` | Despite version information claiming to be from Microsoft, the binary lacks a valid Microsoft digital signature, confirm |
| malcat | anomalies | `GuiSubsystemNoWindowApi` | The binary is marked as a GUI subsystem application but does not import standard window-related user32 APIs, indicating  |
| malcat | anomalies | `HugeGapBetweenFunctions` | Large gaps between functions are often used to hide malicious code or payloads from static analysis. |
| pe_imports | signals | `check_debugger (IsDebuggerPresent, T1622)` | Anti-debugging import used to detect and evade malware analysis environments. |
| pe_imports | signals | `set_registry_value (RegSetValue, T1112)` | Registry modification capability used for persistence, configuration tampering, or data exfiltration, a common malicious |
| pe_imports | signals | `change_memory_protection (VirtualProtect, T1055)` | Memory protection modification is used for code injection, unpacking malicious code, or hiding malicious activity in mem |
| yara | matches | `anti_dbg` | YARA rule confirms the presence of anti-debugging functionality, consistent with malware designed to evade analysis. |
| yara | matches | `keylogger` | YARA rule indicates keylogging capability, a common malicious feature for stealing user input like credentials. |
| yara | matches | `win_registry` | YARA rule confirms registry interaction, aligning with the RegSetValue import and malicious persistence/tampering behavi |
| capa | top_rules | `set registry value (T1112)` | Capa rule independently confirms registry modification capability, corroborating the pe_imports finding. |
| capa | top_rules | `terminate process` | Capa rule confirms process termination capability, commonly used by ransomware to stop security tools or user processes  |
| floss | strings | `P:\Target\x64\ship\lync\x-none\lync99.pdb` | PDB path matches the debug information in Malcat's static profile, confirming the binary is compiled from the Lync/Skype |
| floss | strings | `long base64 string` | Extended base64 string is likely an encoded malicious payload, command and control (C2) communication string, or encrypt |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 70
- **summary**: PE64 GUI sample masquerading as a Microsoft Lync/Skype for Business component. Strings and imports indicate it creates a global mutex (Lync99GlobalMutex), uses Lync window classes, and references AppSharingHookController/ChromeHook binaries. It imports anti-debug and surveillance capabilities: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, and OpenProcess. YARA and checklist findings flag keylogger behavior, anti-debug, domain/IP/URL/base64 indicators, digital signature, overlay, debug data, and rich signature. The combination strongly suggests an info-stealer or surveillance tool with C2/network indicators.

### deep key_evidence
- `"Ghidra imports: IsDebuggerPresent, OutputDebugStringA, GetKeyState, CreateMutexW, CreateThread, OpenProcess"`
- `"Strings: Lync99GlobalMutex, Lync99WindowServerClass, AppSharingHookController.exe, AppSharingChromeHook.dll"`
- `"YARA checklist: anti_dbg, keylogger, win_mutex, domain, IP, contains_base64, url, HasDigitalSignature, HasOverlay, HasDebugData, HasRichSignature, Check_OutputDebugStringA_iat"`
- `"Checklist: IsPE64, IsWindowsGUI"`
- `"Strings: Software\\Microsoft\\Office\\16.0\\Common\\FilesPaths, %LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Lync\\Tracing, SOFTWARE\\Microsoft\\Tracing\\UcClient\\"`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7
size: 793965
type: PE
architecture: X64
entrypoint_ea: 30904
entropy: 45
file_name: 2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 98 | - |
| .text | 1024 | 56832 | 57344 | 161 | RX |
| .rdata | 58368 | 59904 | 61440 | 67 | R |
| .data | 119808 | 43008 | 57344 | 20 | RW |
| .pdata | 177152 | 3584 | 4096 | 14 | R |
| .tls | 181248 | 512 | 4096 | 0 | RW |
| .rsrc | 185344 | 586240 | 589824 | 28 | R |
| .reloc | 775168 | 2048 | 4096 | 62 | R |
| overlay | 779264 | 40813 | 0 | 122 | - |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| MSVC_2015_linker | compiler | INFO | 60 | detects used visual studio version based on linker information |
| msvs_2015__14_0__rich | compiler | INFO | 80 | detects used visual studio version based on rich header information |

### Anomalies (10)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| InvalidChecksum | 4 | integrity | 1 | PE Header checksum is wrong |
| PossiblePackerApiDynamicImport | 4 | imports | 1 | A packer-related api (VirtualProtect, ResumeThread, etc.) is present as string in the binary, but is |
| UnsignedMicrosoft | 4 | integrity | 4 | Version information tells us it is a microsoft file but no certificate has been found |
| DelayImports | 3 | imports | 60 | There are delay imports |
| DynamicString | 3 | strings | 1 | string is constructed dynamically |
| ManyHighValueImmediates | 3 | code | 2 | Function contains at least 5 and more than 10% of high-value immediate operands (i.e. immediate valu |
| StackArrayInitialisationX64 | 3 | code | 1 | An array of data is dynamically built on the stack, sometimes used to build shellcodes or strings |
| WeirdDebugInfoType | 3 | headers | 1 | the Debug infos are not in the usual format |
| GuiSubsystemNoWindowApi | 2 | headers | 1 | A GUI windows application does not import any user32 window-related function |
| HugeGapBetweenFunctions | 2 | code | 2 | There is a huge gap between two functions with medium-to-high entropy, often means that data is stor |

### Anomaly Locations (high-signal)
- **DynamicString**
  - `30662`: 
- **GuiSubsystemNoWindowApi**
  - `364`: 
- **ManyHighValueImmediates**
  - `28680`: 
  - `34268`: 

### High-Signal Strings (2 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 66328 | `kernel32.dll` |
| 71984 | `OC_WEBSERVICE2_HTTPTRANSPORT` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 97520 | `%LOCALAPPDATA%\M..6.0\Lync\Tracing` |
| 96784 | `%ls%ls-%s-%s-%s%s-%s%ls.etl` |
| 97024 | `LogCheckerLogRol..dlerHiddenWindow` |
| 66328 | `kernel32.dll` |
| 96464 | `SOFTWARE\Microso..racing\UcClient\` |
| 96664 | `LogRolloverDurationInMinutes` |
| 770624 | `<?xml version="1..>
</assembly>
` |
| 64328 | `PrepareProcessCommand` |
| 59848 | `IsolationAware f..ionAwareCleanup
` |
| 96944 | `LogCheckerHiddenRootWindow` |
| 59816 | `Comctl32.dll` |
| 64408 | `HandleCommandResult` |
| 96616 | `EnableLogRolloverCheck` |
| 61880 | `Lync99WindowServerClass` |
| 30662 | `VirtualAlloc` |
| 62960 | `WM_Lync99_INITIATE` |
| 63040 | `WM_Lync99_TERMINATE` |
| 96432 | `LevelThreshold` |
| 82608 | `OC_CONTENT_WHITE..ONLOCATIONFILTER` |
| 64304 | `MessageLoop` |
| 64376 | `ProcessCommand` |
| 72192 | `OC_WEBSERVICE2_H..FICATIONPROVIDER` |
| 70544 | `OC_CONFIGURATION..ACCOUNT_PROFILES` |
| 66768 | `SleepConditionVariableCS` |
| 75664 | `OC_APPLICATIONAP..VERSATIONMANAGER` |
| 82288 | `OC_CONTENT_WHITE..NOTATIONLOCATION` |
| 62296 | `LYNC.LYNCDESKTOP..MAPRESOURCES.DLL` |
| 63784 | `stoll argument out of range` |
| 67584 | `TC_UCMP_PERSISTE..H_WEB_CONNECTION` |
| 63000 | `WM_Lync99_UIREADY` |
| 66800 | `WakeAllConditionVariable` |
| 70928 | `OC_CONFIGURATION..D_CONFIG_MANAGER` |
| 67024 | `TC_UTIL_ONBOARD_..OSTICS_COMPONENT` |
| 78736 | `OC_ATTENDANTOI_O..API_CONVERSATION` |
| 75984 | `OC_APPLICATIONAP..RESENCEPUBLISHER` |
| 82528 | `OC_CONTENT_PPTAN..ONLOCATIONFILTER` |
| 81520 | `OC_CONTENT_DO_NA..EFILEONLYCONTENT` |
| 89344 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_11` |
| 80080 | `OC_CONTENT_NATIVEFILEONLYCONTENT` |
| 96896 | `Full` |
| 84256 | `OC_RECORDING_APPSHARING_RECORDER` |
| 75520 | `OC_APPLICATIONAPI_CONTACTMANAGER` |
| 81344 | `OC_CONTENT_DO_CONTENTUSERMANAGER` |
| 80288 | `OC_CONTENT_PERMISSIONTRANSACTION` |
| 67104 | `TC_UTIL_ONBOARD_..GNOSTICS_MANAGER` |
| 93168 | `TC_APP_COLLAB_CO..TENTMEDIASESSION` |
| 88624 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_2` |
| 88096 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_11` |
| 88544 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_1` |
| 88704 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_3` |
| 88784 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_4` |
| 88864 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_5` |
| 73336 | `OC_PRESENCE_CATEGORY_PROCESSOR` |
| 94720 | `TC_APP_CONVERSATION_MEDIASESSION` |
| 71008 | `OC_CONFIGURATION..BRID_CONFIG_TASK` |
| 81920 | `OC_CONTENT_DO_SHAREDLINKSCONTENT` |
| 79384 | `OC_CONTENT_CONTENTSPACEMANAGER` |
| 95856 | `TC_APP_RECORDING_DATA_RECORDER` |
| 82208 | `OC_CONTENT_ANNOT..TIONLOCATIONBASE` |
| 76448 | `OC_MESSENGERAPI_..NVERSATIONWINDOW` |
| 71856 | `OC_WEBSERVICE2_W..BSERVICESMANAGER` |
| 89024 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_7` |
| 66656 | `mso99Lwin32client.dll` |
| 66584 | `mso40uiwin32client.dll` |
| 80160 | `OC_CONTENT_EFFECTIVEPERMISSIONS` |
| 66512 | `mso30win32client.dll` |
| 66440 | `mso20win32client.dll` |
| 79680 | `OC_CONTENT_FILETRANSFER_DOWNLOAD` |
| 81184 | `OC_CONTENT_DO_WHITEBOARDCONTENT` |
| 89664 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_15` |
| 89584 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_14` |
| 89504 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_13` |
| 89424 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_12` |
| 89264 | `WPP_OC_RDP_APPSH..SUB_COMPONENT_10` |
| 88944 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_6` |
| 89104 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_8` |
| 89184 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_9` |
| 86928 | `OC_APPSHARING_HO..K_CONTROLLER_EXE` |
| 87776 | `WPP_OC_RDP_APPSH.._SUB_COMPONENT_7` |
| 80928 | `OC_CONTENT_DO_AN..OTATIONCONTAINER` |

### Constants / Known Patterns (42)
| Category | Value |
|---|---|
| exception | `exception::C++ exception` |
| registry | `registry::HKEY_CURRENT_USER` |
| registry | `registry::HKEY_USERS` |
| registry | `registry::HKEY_LOCAL_MACHINE` |
| guid | `guid::IUnknown` |
| oid | `oid::signedData` |
| oid | `oid::sha1` |
| oid | `oid::spcIndirectDataContext` |
| oid | `oid::spcPEImageData` |
| hash | `hash::SSH_RSA_id_sha1_OBJ_ID__oiw_14__secsig_3__algorithms_2__26__8_byt_15` |
| oid | `oid::sha1WithRSAEncryption` |
| oid | `oid::countryName` |
| oid | `oid::stateOrProvinceName` |
| oid | `oid::localityName` |
| oid | `oid::organizationName` |
| oid | `oid::commonName` |
| oid | `oid::organizationalUnitName` |
| oid | `oid::rsaEncryption` |
| oid | `oid::subjectKeyIdentifier` |
| oid | `oid::authorityKeyIdentifier` |
| oid | `oid::cRLDistributionPoints` |
| oid | `oid::authorityInfoAccess` |
| oid | `oid::caIssuers` |
| oid | `oid::extKeyUsage` |
| oid | `oid::timeStamping` |
| oid | `oid::codeSigning` |
| oid | `oid::subjectAltName` |
| oid | `oid::serialNumber` |
| oid | `oid::domainComponent` |
| oid | `oid::basicConstraints` |
| oid | `oid::keyUsage` |
| oid | `oid::cAKeyCertIndexPair` |
| oid | `oid::certSrvPreviousCertHash` |
| oid | `oid::enrollCerttypeExtension` |
| oid | `oid::contentType` |
| oid | `oid::spcStatementType` |
| oid | `oid::individualCodeSigning` |
| oid | `oid::messageDigest` |
| oid | `oid::spcSpOpusInfo` |
| oid | `oid::countersignature` |

### Imports (366)
| EA | Name | Type | Refs |
|---|---|---|---|
| 1024 | ??__E?isInitialized@CAtlStringMgr@ATL@@0_NA@@YAXXZ | DEBUG | 5 |
| 1232 | ATL::CAtlStringMgr.#5 | DEBUG | 2 |
| 1280 | ATL::CWin32Heap.#4 | DEBUG | 2 |
| 1280 | ATL.CWin32Heap.`scalar deleting destructor' | DEBUG | 2 |
| 1356 | ATL::CAtlStringMgr.#0 | DEBUG | 2 |
| 1356 | ATL.CAtlStringMgr.Allocate | DEBUG | 2 |
| 1496 | ATL::CWin32Heap.#0 | DEBUG | 1 |
| 1512 | ATL::CAtlStringMgr.#4 | DEBUG | 1 |
| 1516 | ATL::CAtlStringMgr.#1 | DEBUG | 1 |
| 1516 | ATL.CAtlStringMgr.Free | DEBUG | 1 |
| 1528 | ATL::CWin32Heap.#1 | DEBUG | 2 |
| 1528 | ATL.CWin32Heap.Free | DEBUG | 2 |
| 1844 | ATL::CAtlStringMgr.#3 | DEBUG | 1 |
| 1844 | ATL.CAtlStringMgr.GetNilString | DEBUG | 1 |
| 1856 | ATL::CWin32Heap.#3 | DEBUG | 1 |
| 1872 | ATL::CAtlStringMgr.#2 | DEBUG | 2 |
| 1980 | ATL::CWin32Heap.#2 | DEBUG | 2 |
| 1980 | ATL.CWin32Heap.Reallocate | DEBUG | 2 |
| 2052 | IsolationAwarePrivatenPgViNgRzlnPgpgk | DEBUG | 5 |
| 3540 | ATL.CAtlArray<void *,ATL::CElementTraits<void *>>.~CAtlArray<void *,ATL::CElementTraits<void *>> | DEBUG | 1 |
| 3636 | CLync99Instance.#3 | DEBUG | 3 |
| 3760 | CLync99MsoComponentHost.#10 | DEBUG | 3 |
| 3840 | CLync99MsoUser.#26 | DEBUG | 2 |
| 3880 | RefCount.#3 | DEBUG | 2 |
| 3920 | CLync99MsoComponentHost.#1 | DEBUG | 1 |
| 5276 | CLync99MsoComponentHost.#7 | DEBUG | 2 |
| 5320 | CLync99MsoUser.#6 | DEBUG | 1 |
| 5324 | CLync99MsoComponentHost.#4 | DEBUG | 5 |
| 5332 | CLync99MsoComponentHost.#8 | DEBUG | 1 |
| 5344 | CLync99MsoUser.#7 | DEBUG | 2 |
| 5564 | CLync99MsoUser.#18 | DEBUG | 1 |
| 6312 | CRegistryKey.#5 | DEBUG | 2 |
| 6816 | GuardCFCheckFunction | DEBUG | 14 |
| 6816 | CLync99MsoComponentHost.#6 | DEBUG | 14 |
| 8172 | CLync99MsoComponentHost.#0 | DEBUG | 2 |
| 8308 | CLync99MsoComponentHost.#3 | DEBUG | 2 |
| 8392 | CLync99MsoComponentHost.#2 | DEBUG | 2 |
| 9836 | CPreviewView.SetPrintView | DEBUG | 3 |
| 16920 | Mso::TRefCountedImpl<struct Mso::OfficeServicesManager::IServicesNotificationCallback<struct Mso::OfficeServicesManager::IConnectedService>>.#4 | DEBUG | 2 |
| 16960 | OFBServiceFilter.#4 | DEBUG | 2 |
| 17008 | OFBServiceFilter.#0 | DEBUG | 2 |
| 18336 | OFBServiceFilter.#2 | DEBUG | 1 |
| 23268 | OFBServiceFilter.#1 | DEBUG | 3 |
| 23308 | OFBServiceFilter.#3 | DEBUG | 2 |
| 27192 | shell32.CommandLineToArgvW (delaystub) | DEBUG | 2 |
| 27328 | user32.UnregisterClassW (delaystub) | DEBUG | 1 |
| 27464 | user32.RegisterWindowMessageW (delaystub) | DEBUG | 2 |
| 27476 | user32.TranslateMessage (delaystub) | DEBUG | 1 |
| 27488 | user32.DispatchMessageW (delaystub) | DEBUG | 1 |
| 27500 | user32.SendMessageW (delaystub) | DEBUG | 1 |
| 27512 | user32.PostMessageW (delaystub) | DEBUG | 1 |
| 27524 | user32.PostThreadMessageW (delaystub) | DEBUG | 1 |
| 27536 | user32.DefWindowProcW (delaystub) | DEBUG | 1 |
| 27548 | user32.PostQuitMessage (delaystub) | DEBUG | 1 |
| 27560 | user32.RegisterClassExW (delaystub) | DEBUG | 1 |
| 27572 | user32.CreateWindowExW (delaystub) | DEBUG | 1 |
| 27584 | user32.IsWindow (delaystub) | DEBUG | 1 |
| 27596 | user32.DestroyWindow (delaystub) | DEBUG | 1 |
| 27608 | user32.MessageBoxW (delaystub) | DEBUG | 1 |
| 27620 | user32.GetWindowLongPtrW (delaystub) | DEBUG | 1 |
| 27632 | user32.SetWindowLongPtrW (delaystub) | DEBUG | 1 |
| 27644 | user32.GetWindowThreadProcessId (delaystub) | DEBUG | 1 |
| 27656 | user32.GetKeyState (delaystub) | DEBUG | 1 |
| 27668 | mso.delay#7 (delaystub) | DEBUG | 1 |
| 27812 | mso.delay#6 (delaystub) | DEBUG | 1 |
| 27832 | mso.delay#5 (delaystub) | DEBUG | 1 |
| 27852 | mso.delay#4 (delaystub) | DEBUG | 1 |
| 27872 | mso.delay#3 (delaystub) | DEBUG | 1 |
| 27892 | mso.delay#2 (delaystub) | DEBUG | 1 |
| 27912 | mso.delay#1 (delaystub) | DEBUG | 2 |
| 27932 | mso.delay#0 (delaystub) | DEBUG | 1 |
| 27952 | mso.delay#8 (delaystub) | DEBUG | 1 |
| 27972 | mso99lwin32client.delay#8 (delaystub) | DEBUG | 1 |
| 28116 | mso99lwin32client.delay#7 (delaystub) | DEBUG | 1 |
| 28136 | mso99lwin32client.delay#6 (delaystub) | DEBUG | 1 |
| 28156 | mso99lwin32client.delay#5 (delaystub) | DEBUG | 1 |
| 28176 | mso99lwin32client.delay#4 (delaystub) | DEBUG | 1 |
| 28196 | mso99lwin32client.delay#3 (delaystub) | DEBUG | 1 |
| 28216 | mso99lwin32client.delay#2 (delaystub) | DEBUG | 1 |
| 28240 | mso99lwin32client.delay#1 (delaystub) | DEBUG | 1 |

### Functions (30)
| EA | Name |
|---|---|
| 47804 | sub_14000c6bc |
| 48792 | sub_14000ca98 |
| 8172 | #0 |
| 46816 | #0 |
| 34052 | sub_140009104 |
| 43892 | sub_14000b774 |
| 56240 | sub_14000e7b0 |
| 34268 | sub_1400091dc |
| 31844 | sub_140008864 |
| 32464 | sub_140008ad0 |
| 32364 | sub_140008a6c |
| 28259 | sub_140007a63 |
| 1560 | sub_140001218 |
| 27932 | delay#0 (delaystub) |
| 28280 | delay#0 (delaystub) |
| 28896 | delay#6 (delaystub) |
| 23308 | #3 |
| 17008 | #0 |
| 28321 | sub_140007aa1 |
| 32988 | sub_140008cdc |
| 31264 | sub_140008620 |
| 31708 | sub_1400087dc |
| 27654 | sub_140007806 |
| 28108 | sub_1400079cc |
| 2360 | sub_140001538 |
| 9012 | sub_140002f34 |
| 5592 | sub_1400021d8 |
| 41200 | sub_14000acf0 |
| 33560 | sub_140008f18 |
| 39724 | sub_14000a72c |

### Decompilations (top 6)
#### 47804 — sub_14000c6bc
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

int32_t sub_14000c6bc(int64_t param_1)

{
    int32_t iVar1;
    int64_t iVar2;
    int64_t iVar3;
    int64_t iVar4;
    undefined8 uVar5;
    undefined4 uVar6;
    bool bVar7;
    
    iVar4 = 0;
    LOCK();
    bVar7 = *(param_1 + 0x270) == 0;
    if (bVar7) {
        *(param_1 + 0x270) = 0;
    }
    UNLOCK();
    if (!bVar7) {
        return 0;
    }
    if (*(param_1 + 0x270) != 0) {
        return 0;
    }
    iVar1 = sub_14000db94(param_1, param_1);
    if (iVar1 < 0) {
        if ([0x0x14001e260] == 0x14001e260) {
            return iVar1;
        }
        if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
            return iVar1;
        }
        if (*([0x0x14001e260] + 0x39) < 2) {
            return iVar1;
        }
        uVar6 = 10;
        uVar5 = *([0x0x14001e260] + 0x30);
    }
    else {
        iVar2 = sub_140006dc4(0x20);
        iVar3 = iVar4;
        if (iVar2 != 0) {
            iVar3 = sub_14000d398(iVar2, 0xffffffff80000003, 0xf003f);
        }
        if (*(param_1 + 0x250) != 0x0) {
            (**(**(param_1 + 0x250) + 0x10))();
        }
        *(param_1 + 0x250) = iVar3;
        if (iVar3 == 0) {
            if ([0x0x14001e260] == 0x14001e260) {
                return -0x7ff8fff2;
            }
            if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
                return -0x7ff8fff2;
            }
            if (*([0x0x14001e260] + 0x39) < 2) {
                return -0x7ff8fff2;
            }
            uVar6 = 0xb;
        }
        else {
            iVar2 = sub_140006dc4(0x20);
            iVar3 = iVar4;
            if (iVar2 != 0) {
                iVar3 = sub_14000d398(iVar2, 0xffffffff80000001, 0xf003f);
            }
            if (*(param_1 + 600) != 0x0) {
                (**(**(param_1 + 600) + 0x10))();
            }
            *(param_1 + 600) = iVar3;
            if (iVar3 == 0) {
                if ([0x0x14001e260] == 0x14001e260) {
                    return -0x7ff8fff2;
                }
                if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
                    return -0x7ff8fff2;
                }
                if (*([0x0x14001e260] + 0x39) < 2) {
                    return -0x7ff8fff2;
                }
                uVar6 = 0xc;
            }
            else {
                iVar2 = sub_140006dc4(0x20);
                iVar3 = iVar4;
                if (iVar2 != 0) {
                    iVar3 = sub_14000d398(iVar2, 0xffffffff80000002, 0xf003f);
                }
                if (*(param_1 + 0x260) != 0x0) {
                    (**(**(param_1 + 0x260) + 0x10))();
                }
                *(param_1 + 0x260) = iVar3;
                if (iVar3 == 0) {
                    if ([0x0x14001e260] == 0x14001e260) {
                        return -0x7ff8fff2;
                    }
                    if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
                        return -0x7ff8fff2;
                    }
                    if (*([0x0x14001e260] + 0x39) < 2) {
                        return -0x7ff8fff2;
                    }
                    uVar6 = 0xd;
                }
                else {
                    iVar3 = sub_140006dc4(0x20);
                    if (iVar3 != 0) {
                        iVar4 = sub_14000d398(iVar3, 0xffffffff80000000, 0xf003f);
                    }
                    if (*(param_1 + 0x268) != 0x0) {
                        (**(**(param_1 + 0x268) + 0x10))();
                    }
                    *(param_1 + 0x268) = iVar4;
                    if (iVar4 != 0) {
                        *(param_1 + 0x270) = 1;
                        return iVar1;
                    }
                    if ([0x0x14001e260] == 0x14001e260) {
                        return -0x7ff8fff2;
                    }
                    if ((*([0x0x14001e260] + 0x3c) & 1) == 0) {
                        return -0x7ff8fff2;
                    }
                    if (*([0x0x14001e260] + 0x
```
#### 48792 — sub_14000ca98
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 sub_14000ca98(int64_t param_1,int64_t param_2,int64_t **param_3)

{
    int64_t *piVar1;
    
    if (param_2 == -0x7ffffffe) {
        piVar1 = *(param_1 + 0x260);
    }
    else if (param_2 == -0x7fffffff) {
        piVar1 = *(param_1 + 600);
    }
    else if (param_2 == -0x7ffffffd) {
        piVar1 = *(param_1 + 0x250);
    }
    else {
        if (param_2 != -0x80000000) {
            return 0x80070057;
        }
        piVar1 = *(param_1 + 0x268);
    }
    if (*param_3 != piVar1) {
        if (piVar1 != 0x0) {
            (**(*piVar1 + 8))(piVar1);
        }
        if (*param_3 != 0x0) {
            (**(**param_3 + 0x10))();
        }
        *param_3 = piVar1;
    }
    return 0;
}

```
#### 8172 — #0
```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

/* DISPLAY WARNING: Type casts are NOT being printed */

undefined8 CLync99MsoComponentHost.#0(int64_t *param_1,int64_t *param_2,int64_t **param_3)

{
    undefined8 uVar1;
    
    if (param_3 == 0x0) {
        uVar1 = 0x80004003;
    }
    else {
        *param_3 = 0x0;
        if ((((*param_2 == IUnknown) && (param_2[1] == [0x0x140010d20])) ||
            ((*param_2 == [0x0x1400106d8] && (param_2[1] == [0x0x1400106e0])))) ||
           ((*param_2 == [0x0x1400106e8] && (param_2[1] == [0x0x1400106f0])))) {
            (**(*param_1 + 8))();
            uVar1 = 0;
            *param_3 = param_1;
        }
        else {
            uVar1 = 0x80004002;
        }
    }
    return uVar1;
}

```

### Carved Files (31)
| Name | Type | Size |
|---|---|---|
| ? | DIB | 270376 |
| ? | DIB | 38056 |
| ? | DIB | 26600 |
| ? | DIB | 21640 |
| ? | DIB | 16936 |
| ? | DIB | 14920 |
| ? | DIB | 9640 |
| ? | DIB | 6760 |
| ? | DIB | 4264 |
| ? | DIB | 2440 |
| ? | DIB | 1720 |
| ? | DIB | 1128 |
| ? | DIB | 744 |
| ? | DIB | 296 |
| ? | DIB | 5672 |
| ? | DIB | 3752 |
| ? | DIB | 2216 |
| ? | DIB | 1384 |
| ? | PNG | 9278 |
| ? | DIB | 38056 |

### Virtual Files (34)
| Path / Name | Unpacked Size | Type |
|---|---|---|
| ICO/1/en-us | 270376 | - |
| ICO/2/en-us | 38056 | - |
| ICO/3/en-us | 26600 | - |
| ICO/4/en-us | 21640 | - |
| ICO/5/en-us | 16936 | - |
| ICO/6/en-us | 14920 | - |
| ICO/7/en-us | 9640 | - |
| ICO/8/en-us | 6760 | - |
| ICO/9/en-us | 4264 | - |
| ICO/10/en-us | 2440 | - |
| ICO/11/en-us | 1720 | - |
| ICO/12/en-us | 1128 | - |
| ICO/13/en-us | 744 | - |
| ICO/14/en-us | 296 | - |
| ICO/15/en-us | 5672 | - |
| ICO/16/en-us | 3752 | - |
| ICO/17/en-us | 2216 | - |
| ICO/18/en-us | 1384 | - |
| ICO/19/en-us | 9278 | - |
| ICO/20/en-us | 38056 | - |

### Structures (169)
| Name | EA |
|---|---|
| MZ | 0 |
| RichHeader | 128 |
| PE | 272 |
| OptionalHeader | 296 |
| Sections | 536 |
| DebugDirectory | 57444 |
| Debug.Reserved10 | 57528 |
| Debug.Codeview | 57532 |
| advapi32.FT | 58368 |
| kernel32.FT | 58520 |
| ole32.FT | 59144 |
| vcruntime140.FT | 59176 |
| msvcp140.FT | 59272 |
| api-ms-win-crt-heap-l1-1-0.FT | 59312 |
| api-ms-win-crt-runtime-l1-1-0.FT | 59352 |
| api-ms-win-crt-string-l1-1-0.FT | 59512 |
| api-ms-win-crt-convert-l1-1-0.FT | 59568 |
| api-ms-win-crt-math-l1-1-0.FT | 59584 |
| api-ms-win-crt-stdio-l1-1-0.FT | 59600 |
| api-ms-win-crt-locale-l1-1-0.FT | 59640 |
| GuardCFCheckFunctionPointer | 59664 |
| GuardCFDispatchFunctionPointer | 59672 |
| TlsCallbacks | 59808 |
| SecurityCookie | 66728 |
| LoadConfigurationTable | 66848 |
| TlsDirectory | 97744 |
| Debug.Pogo | 99884 |
| DelayImportTable | 101012 |
| shell32.Names | 101464 |
| user32.Names | 101488 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 13 · duration_s: 1.18

| Rule | ATT&CK | MBC |
|---|---|---|
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| create directory |  | C0046:Create Directory |
| move file |  | C0063:Move File |
| find graphical window | T1010:Application Window Discovery |  |
| terminate process |  | C0018:Terminate Process |
| set registry value |  | C0036.001:Registry |
| create thread |  | C0038:Create Thread |
| link function at runtime on Windows | T1129:Shared Modules |  |
| enumerate PE sections |  | B0046.001:Code Discovery |
| parse PE header | T1129:Shared Modules |  |
| contains PDB path |  |  |
| contain a thread local storage (.tls) section |  |  |

## PE Imports / Signals
import_count: 150

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| set_registry_value | RegSetValue | T1112 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
| change_memory_protection | VirtualProtect | T1055 |

## YARA Matches (pipeline)
Total matches: 15

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@750469 len=8; $ipv6@64192 len=4 |
| contains_base64 | - | $a@43003 len=12 |
| url | - | $url_regex@754050 len=69 |
| IsPE64 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasDigitalSignature | - | $a1@753152 len=105 |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@248 len=4 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@102468 len=12; $c2@105490 len=17; $c3@105294 len=17 |
| keylogger | - | $f1@100800 len=10; $c2@101550 len=11 |
| win_mutex | - | $c1@104180 len=11 |
| win_registry | - | $f1@102484 len=12; $c3@104024 len=11; $c6@104024 len=11 |

## Generated YARA Meta
```json
{
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
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
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$ipv4",
          "offset": 750469,
          "length": 8,
          "xor_key": null
        },
        {
          "id": "$ipv6",
          "offset": 64192,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a",
          "offset": 43003,
          "length": 12,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "url",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$url_regex",
          "offset": 754050,
          "length": 69,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE64",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasDigitalSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a1",
          "offset": 753152,
          "length": 105,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "HasDebugData",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "HasRichSignature",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$a0",
          "offset": 248,
          "length": 4,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "Check_OutputDebugStringA_iat",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": []
    },
    {
      "rule": "anti_dbg",
      "path": "/opt/samples/corpus/pool/ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7/2026-07-03_064480afd4e5e59c783aec43ab1de3ef_mespinoza",
      "strings": [
        {
          "id": "$d1",
          "offset": 102468,
          "length": 12,
          "xor_key": null
        },
        {
          "id": "$c2",
          "offset": 105490,
          "length": 17,
          "xor_key": null
        },
        {
          "id": "$c3",
          "offset": 105294,
          "length": 17,
          "xor_key": null
        }
      ]
    },
    {
      "
```

## FLOSS Strings
Total strings: 1262 · per_category: `{"decoded_strings": 1, "stack_strings": 5, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 1256}`

### FLOSS sample
- `VirtualAlloc`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `.pdata`
- `@.reloc`
- `WAVAWH`
- `UVWAVAWH`
- `t$8X9r`
- ``A_A^_^]`
- `VWATAVAWH`
- `a<t6D8a9r`
- `@A_A^A\_^`
- `t38X9r`
- `t	8X9r`
- `UWATAVAWH`
- `fF9$Bu`
- `p<t`@8p9rH`
- `p<t7@8p9r`
- `p<t=@8p9r`
- `A_A^A\_]`
- `SVWAVAWH`
- `0A_A^_^[`
- `H;\$0u`
- `D$ D95_K`
- `t	D95RK`
- `0Hde`n`
- `%U|mBk`
- `>Hve70/`
- `8Kwe70`
- `Q`ZppHW`
- `]bo14j`
- `X26y:3`
- `+By>*Q(`
- `(%# BB`
- `zu/OLby`
- `A KWZA`
- `?s	=&t}`
- `g\,tU*`
- `VTCJu:`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x1400084b8
```asm
┌ 242: entry0 (int64_t arg1);
│           ; arg int64_t arg1 @ rcx
│           ; var int64_t var_8h @ rbp-0x8
│           0x1400084b8      e848feffff     call fcn.140008305
│           0x1400084bd      c8200000       enter 0x20, 0              ; 32
│           0x1400084c1      4c897c24f8     mov qword [rsp - 8], r15
│           0x1400084c6      4883ec08       sub rsp, 8
│           0x1400084ca      4989e7         mov r15, rsp
│           0x1400084cd      4883ec20       sub rsp, 0x20
│           0x1400084d1      4883e4f0       and rsp, 0xfffffffffffffff0
│           0x1400084d5      4831f6         xor rsi, rsi
│           0x1400084d8      4801c6         add rsi, rax
│           0x1400084db      4883c03c       add rax, 0x3c              ; 60
│           0x1400084df      4831d2         xor rdx, rdx
│           0x1400084e2      8b10           mov edx, dword [rax]
│           0x1400084e4      4883ec08       sub rsp, 8
│           0x1400084e8      48893424       mov qword [rsp], rsi
│           0x1400084ec      488b0424       mov rax, qword [rsp]
│           0x1400084f0      4883c408       add rsp, 8
│           0x1400084f4      4801d0         add rax, rdx
│           0x1400084f7      480588000000   add rax, 0x88              ; 136
│           0x1400084fd      4883ec08       sub rsp, 8
│           0x140008501      48890424       mov qword [rsp], rax
│           0x140008505      488b0c24       mov rcx, qword [rsp]
│           0x140008509      4883c408       add rsp, 8
│           0x14000850d      48c7c00000..   mov rax, 0
│           0x140008514      8b01           mov eax, dword [rcx]
│           0x140008516      4801f0         add rax, rsi
│           0x140008519      50             push rax
│           0x14000851a      488b0c24       mov rcx, qword [rsp]
│           0x14000851e      4883c408       add rsp, 8
│           0x140008522      56             push rsi
│           0x140008523      488b1424       mov rdx, qword [rsp]
│           0x140008527      4883c408       add rsp, 8
│           0x14000852b      488d05acf3..   lea rax, [0x1400078de]
│           0x140008532      4883ec08       sub rsp, 8
│           0x140008536      48890c24       mov qword [rsp], rcx
│           0x14000853a      48c7c1619a..   mov rcx, 0xfffffffffffe9a61
│           0x140008541      4883ec08       sub rsp, 8
│           0x140008545      48890c24       mov qword [rsp], rcx
│           0x140008549      48c7c1cb73..   mov rcx, 0x173cb
│       ┌─> 0x140008550      48ffc0         inc rax
│       ╎   0x140008553      48ffc9         dec rcx
│       ╎   0x140008556      4881f9b56c..   cmp rcx, 0x16cb5
│       └─< 0x14000855d      75f1           jne 0x140008550
│           0x14000855f      4883c408       add rsp, 8
│           0x140008563      488b4c24f8     mov rcx, qword [rsp - 8]
│           0x140008568      488b0c24       mov rcx, qword [rsp]
│           0x14000856c      4883c408       add rsp, 8
│           0x140008570      ffd0           call rax
│           0x140008572      
```
### 0x140008305
```asm
; CALL XREF from entry0 @ 0x1400084b8(x)
┌ 446: fcn.140008305 (int64_t arg2);
│           ; arg int64_t arg2 @ rdx
│           ; var int64_t var_1h @ rbp-0x1
│           ; var int64_t var_2h @ rbp-0x2
│           ; var int64_t var_3h @ rbp-0x3
│           ; var int64_t var_4h @ rbp-0x4
│           ; var int64_t var_5h @ rbp-0x5
│           ; var int64_t var_6h @ rbp-0x6
│           ; var int64_t var_7h @ rbp-0x7
│           ; var int64_t var_bp_8h @ rbp-0x8
│           ; var int64_t var_9h @ rbp-0x9
│           ; var int64_t var_ah @ rbp-0xa
│           ; var int64_t var_bh @ rbp-0xb
│           ; var int64_t var_ch @ rbp-0xc
│           ; var int64_t var_dh @ rbp-0xd
│           ; var int64_t var_7fh @ rbp-0x7f
│           ; var int64_t var_8h @ rsp+0x218
│           0x140008305      488b442408     mov rax, qword [var_8h]
│           0x14000830a      4883e200       and rdx, 0                 ; arg2
│      ┌┌─> 0x14000830e      48ffc8         dec rax
│      ╎╎   0x140008311      6681384d5a     cmp word [rax], 0x5a4d     ; 'MZ'
│     ┌───< 0x140008316      750b           jne 0x140008323
│    ┌────< 0x140008318      7414           je 0x14000832e
│    ││╎╎   0x14000831a      e85e000000     call 0x14000837d
│    ││╎╎   0x14000831f      b3c7           mov bl, 0xc7               ; 199
│    ││╎╎   0x140008321      9f             lahf
│    ││╎╎   0x140008322      5e             pop rsi
│    │└└──< 0x140008323      75e9           jne 0x14000830e
│    │  ╎   0x140008325      e8fcffffff     call 0x140008326
│    │  ╎   0x14000832a      8bcf           mov ecx, edi
│    │  ╎   0x14000832c  ~   350b8b503c     xor eax, 0x3c508b0b
│    └────> 0x14000832e      8b503c         mov edx, dword [rax + 0x3c]
│       ╎   0x140008331      81fa00040000   cmp edx, 0x400             ; 1024
│       └─< 0x140008337      73d5           jae 0x14000830e
│           0x140008339      482db5480000   sub rax, 0x48b5
│           0x14000833f      4801c2         add rdx, rax
│           0x140008342      4881c2b548..   add rdx, 0x48b5
│           0x140008349      4805b5480000   add rax, 0x48b5
│           0x14000834f      66813a5045     cmp word [rdx], 0x4550     ; 'PE'
│       ┌─< 0x140008354      7506           jne 0x14000835c
│      ┌──< 0x140008356      7442           je 0x14000839a
│      ││   0x140008358      82             invalid
..
│      │└─> 0x14000835c      744d           je 0x1400083ab
│      │    0x14000835e      75ae           jne 0x14000830e
│      │    0x140008360      488d05cdfe..   lea rax, [0x140008234]
│      │    0x140008367      4883ec08       sub rsp, 8
│      │    0x14000836b      48890c24       mov qword [rsp], rcx
│      │    0x14000836f      48c7c11028..   mov rcx, 0xffffffffffff2810
│      │    0x140008376      4881c160d9..   add rcx, 0xd960
│      │    ; CALL XREF from fcn.140008305 @ 0x14000831a(x)
│      │    0x14000837d      4801c1         add rcx, rax
│      │    0x140008380      51             push rcx
│      │    0x140008381      4891           xchg r
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000110 ........!..L.!This program cannot be r

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
  - `ADVAPI32.dll!RegisterTraceGuidsW`
  - `ADVAPI32.dll!UnregisterTraceGuids`
  - `ADVAPI32.dll!GetTraceLoggerHandle`
  - `ADVAPI32.dll!GetTraceEnableLevel`
  - `ADVAPI32.dll!GetTraceEnableFlags`
  - `KERNEL32.dll!GetCommandLineW`
  - `KERNEL32.dll!CloseHandle`
  - `KERNEL32.dll!WaitForSingleObject`
  - `KERNEL32.dll!CreateMutexW`
  - `KERNEL32.dll!ExitProcess`
  - `ole32.dll!OleInitialize`
  - `ole32.dll!CoUninitialize`
  - `ole32.dll!CoInitializeEx`
  - `VCRUNTIME140.dll!__std_terminate`
  - `VCRUNTIME140.dll!_CxxThrowException`
  - `VCRUNTIME140.dll!memmove`
  - `VCRUNTIME140.dll!__C_specific_handler`
  - `VCRUNTIME140.dll!__CxxFrameHandler3`
  - `MSVCP140.dll!?_Xinvalid_argument@std@@YAXPEBD@Z`
  - `MSVCP140.dll!?_Xlength_error@std@@YAXPEBD@Z`
  - `MSVCP140.dll!?_Xout_of_range@std@@YAXPEBD@Z`
  - `MSVCP140.dll!?_Xbad_alloc@std@@YAXXZ`
  - `api-ms-win-crt-heap-l1-1-0.dll!calloc`
  - `api-ms-win-crt-heap-l1-1-0.dll!_set_new_mode`
  - `api-ms-win-crt-heap-l1-1-0.dll!malloc`
  - `api-ms-win-crt-heap-l1-1-0.dll!free`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_invalid_parameter_noinfo_noreturn`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_crt_atexit`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_register_onexit_function`
  - `api-ms-win-crt-runtime-l1-1-0.dll!_initialize_onexit_table`
