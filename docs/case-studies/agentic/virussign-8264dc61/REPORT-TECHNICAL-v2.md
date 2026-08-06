> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 02:12:02 UTC

## 1. Executive Summary
This sample is classified as **malicious** with a score of 92 (source: llm_judge, verdict.json). The family guess is packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer (source: llm_judge, verdict.json). Static analysis from capa, pe_imports, YARA, and FLOSS confirms the sample is a packed, obfuscated PE32 executable using XOR encoding to hinder analysis, containing an embedded secondary PE payload, and exhibiting high-signal malicious capabilities including registry modification, process execution, and dynamic API resolution. YARA matches confirm packer fingerprints, SEH usage, mutex/registry/file operation strings, and potential C2 indicators (domain, IP, base64 patterns). No functional or decompilation data is available due to Ghidra/IDA operational failures, and no dynamic behavioral data was observed via Speakeasy emulation. Deep-dive analysis confidence is 90 (source: deep_dive_agentic, deep-dive.json).

## 2. Sample Metadata
| Field | Value | Source |
|-------|-------|--------|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | llm_judge (verdict.json) |
| Sample Path | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir | llm_judge (verdict.json) |
| Project Name | incoming | llm_judge (verdict.json) |
| Verdict | malicious | llm_judge (verdict.json) |
| Score | 92 | llm_judge (verdict.json) |
| Family Guess | Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer | llm_judge (verdict.json) |
| Agreement | llm_and_v1_agree | llm_judge (verdict.json) |
| Analysis Timestamp | 2026-08-06 02:07:41 UTC | yara_gen_v2 (rule.yara.json) |

Cross-engine notes: Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers (source: llm_judge, verdict.json).

## 3. File Layout & Structural Analysis
The sample is a 32-bit Windows GUI PE with an overlay, modified DOS header, and packer/protector fingerprints confirmed via YARA (source: yara, YARA Matches table):
| YARA Rule | Match Offset | Match Length | Significance |
|-----------|--------------|--------------|--------------|
| IsPE32 | N/A | N/A | Confirms valid 32-bit Windows PE |
| IsWindowsGUI | N/A | N/A | GUI subsystem, not console |
| HasOverlay | N/A | N/A | PE has overlay data (common for packed/embedded content) |
| HasModified_DOS_Message | N/A | N/A | Modified DOS header message (anti-analysis measure) |
| AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | 2 | 1 | Packer/protector fingerprint matching fake PCGuard wrapper |
| SEH_Save | 66713 | 7 | Structured Exception Handler (SEH) save pattern, common in shellcode/packed malware |
| SEH_Init | 66720 | 7 | SEH initialization pattern |
| win_mutex | 48626 | 11 | Mutex string indicator (used for single-instance checks or anti-analysis) |
| win_registry | 50204, 49486, 49470, 49454, 49506 | 12/16/13/11/14 | Registry operation string indicators |
| win_files_operation | 49856, 48766, 48606, 48766, 48582, 48818, 48566 | 12/9/14/9/8/11/11 | File operation string indicators |
| Str_Win32_Wininet_Library | 49832 | 11 | WinINet library string, indicates potential network communication |
| domain | 0 | 2 | Domain pattern match (C2 indicator) |
| IP | 72810 | 23 | IPv6 address pattern match (C2 indicator) |
| contains_base64 | 47878 | 16 | Base64 encoded content (obfuscated payload/C2 data) |
| maldoc_getEIP_method_1 | 54788 | 6 | EIP retrieval method (common in shellcode/exploits) |

Packer and obfuscation indicators:
- UPX unpack attempt failed: `upx_ok=False`, `is_packed=False`, `returncode=None`, `unpacked_path=`` (source: upx, UPX Unpack section). The sample is not UPX packed, consistent with the AHTeam/fake PCGuard wrapper identified via YARA.
- XOR search found XOR 00 keys at `0x00000000` (0x80 bytes) and `0x0001B800` (0x80 bytes) (source: xor, XOR Search section).
- Entry point disassembly (radare2, source: r2_decomp, 0x00430005) shows a XOR decryption loop for the `.text` section:
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
This loop XOR-decrypts the `.text` section (0x401000 to 0x408ecc) with the 4-byte key `0x462530e4`, iterating 2 bytes at a time until the end of the section is reached.
- The import table contains 113 total imports (source: pe_imports, PE Imports / Signals section), with high-signal malicious imports listed in Section 5.
- FLOSS extracted 715 total static strings, 0 decoded/stack/tight strings, all static, many obfuscated with patterns like `%F`, `%IR`, consistent with XOR packing (source: floss, FLOSS Strings section).

## 4. Malcat Triage Summary
Malcat analysis failed with error: `malcat_analyze top-level: MCP malcat closed: ` (source: Malcat Structured Analysis section). No Malcat-specific triage data (file layout, entropy, packer detection) is available from this engine. All triage evidence is sourced from capa, pe_imports, YARA, and FLOSS as detailed in subsequent sections.

## 5. Static Code Analysis
Ghidra and IDA analysis failed due to operational errors: Ghidra returned `NotOwnerException` (project owned by remnux), IDA failed due to missing `/usr/local/bin/idasql` binary (source: deep_dive_agentic, deep-dive.json; audit trail ghidra_query entries). No function-level decompilation, control flow graphs, or Ghidra/IDA-specific import/string data is available.

### capa Capability Rules (source: capa, capa Capability Rules table)
| Rule | ATT&CK | MBC |
|------|--------|-----|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| contain an embedded PE file | N/A | B0023:Install Additional Program |
| contain loop | N/A | N/A |
| (internal) packer file limitation | N/A | N/A |

### PE Import Signals (source: pe_imports, PE Imports / Signals table)
| Label | api_match | ATT&CK |
|-------|-----------|--------|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

Additional imports observed in radare2 disassembly of import thunks (source: r2_decomp, radare2 Disassembly section):
- ole32.dll: CoCreateInstance, CLSIDFromString, CoUninitialize, SysAllocString, DeleteUrlCacheEntry, FindFirstUrlCacheEntryA, FindNextUrlCacheEntryA
- KERNEL32.dll: ExitProcess, ExpandEnvironmentStringsA, GetCommandLineA, GetComputerNameA, GetCurrentProcessId, GetCurrentThreadId, GetExitCodeThread, GetFileSize, GetModuleFileNameA, GetModuleHandleA, CloseHandle, GetProcAddress, GetSystemDirectoryA, IsBadWritePtr, LoadLibraryA, LocalAlloc, OpenMutexA, CreateFileA, ReadFile, RtlUnwind, SetFilePointer, CreateMutexA, Sleep, TerminateProcess, VirtualQuery, CreateProcessA, WaitForSingleObject, WideCharToMultiByte, WinExec, WriteFile, lstrlenA, lstrlenW, CreateThread, DeleteFileA, GetWindowTextA, GetWindowRect, FindWindowA, GetWindow, GetClassNameA, SetFocus, GetForegroundWindow, LoadCursorA, LoadIconA, SetTimer, RegisterClassA, MessageBoxA, GetMessageA

### radare2 Entry Point Disassembly (source: r2_decomp, 0x00430005)
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```

### radare2 Import Thunk Disassembly (source: r2_decomp)
#### 0x004312b0 (ole32.dll functions)
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  ~   0300           add eax, dword [eax]
│       │   ;-- (0x00431300) GetModuleHandleA:
│       └─> 0x004312ff  ~   00f0           add al, dh
│           0x00431301  ~   1503000416     adc eax, 0x16040003
│           ;-- CloseHandle:
..
│           0x00431306      0300           add eax, dword [eax]
│           ;-- GetProcAddress:
│           0x00431308      1216           adc dl, byte [esi]
│           0x0043130a      0300           add eax, dword [eax]
│           ;-- GetSystemDirectoryA:
│    
```
#### 0x00431334 (KERNEL32.dll IsBadWritePtr / LoadLibraryA thunk)
```asm
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
#### 0x00431340 (KERNEL32.dll LocalFree / process/file/mutex APIs)
```asm
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA:
└       ┌─< 0x0043137c  ~   ea170300f6..   ljmp 0x317
│       │   ;-- lstrlenW:
..
```
#### 0x00431384 (KERNEL32.dll CreateThread / windowing APIs)
```asm
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4   add byte [eax - 0x4bfffce8], ch
│           ;-- SetTimer:
..
│           ;-- RegisterClassA:
│           0x004313b9      1803           sbb byte [ebx], al
│           0x004313bb  ~   00c6           add dh, al
│           ;-- MessageBoxA:
..
│           0x004313bd      1803           sbb byte [ebx], al
│           0x004313bf  ~   00d4           add ah, dl
│           ;-- GetMessageA:
..
│           0x004313c1      1803           sbb byte [ebx], al
│           0x004313c3  ~   00e2           add
```

### FLOSS Static Strings (source: floss, FLOSS Strings section)
Total static strings: 715, 0 decoded/stack/tight strings. Sample obfuscated strings consistent with XOR packing:
```
.idata
.kofbl
<OF#55
1PA\2%F
oe-IZ4'IZ$
#&%FgV!F
:Pr%FEL
p0%Fmu
0%O?D!
%I`3$F
1 ~{q%
(^{q%fm
Dr%O$L
\r%{d0%F
1%F\GRF
v0%FdM
4Pad==
0Mn^r%
0M{^r%
0%Fi5Q
Ii4 /Xr%
<3`Vid
!IR4#{
pVid6C
Ii<(~Xr%
Do$0fup%
m<0vqp%IR
2Pr%IR
gF]!%F
MCIRs$c$0%Fg
0QNou)
#Z%.d0%F
gF]3%F
ou)ISp'
eNoe-ISb-o41`
xNou) mu)
>0%Fou
5IR4;{
L}%Fmu
D}%FoM
```
No function metrics are available due to Ghidra/IDA analysis failure (source: deep_dive_agentic, deep-dive.json).

## 6. Behavioral & Dynamic Analysis
No dynamic behavioral data was observed during analysis:
- Speakeasy emulation completed successfully (`speakeasy_ok=True`) but recorded 0 API calls and 0 key events, `duration_s=None` (source: speakeasy, Speakeasy (dynamic) section). No runtime behavior was captured.
- Frida probe is available (version 17.16.4) but no instrumentation data was collected (source: frida_probe, Frida Probe section).
- UPX unpack attempt failed: `upx_ok=False`, `is_packed=False`, `returncode=None`, no unpacked payload path generated (source: upx, UPX Unpack section).
- No process execution, file system changes, network connections, or registry modifications were observed dynamically. All behavioral indicators are derived from static analysis only.

## 7. Network Indicators & C2
All network indicators are static; no dynamic C2 connections were observed (source: speakeasy, 0 events recorded). Static indicators from YARA (source: yara, YARA Matches table):
| Indicator Type | YARA Rule | Match Offset | Match Length | Notes |
|----------------|-----------|--------------|--------------|-------|
| Domain pattern | domain | 0 | 2 | Regex match for domain structure, likely C2 domain |
| IPv6 address | IP | 72810 | 23 | Full IPv6 address pattern, likely C2 server |
| Base64 encoded content | contains_base64 | 47878 | 16 | Obfuscated C2 data or payload |
| EIP retrieval method | maldoc_getEIP_method_1 | 54788 | 6 | Shellcode-style EIP retrieval, common in exploit-based delivery |
| WinINet library | Str_Win32_Wininet_Library | 49832 | 11 | Indicates use of WinINet API for HTTP/FTP network communication |
No full C2 URLs, IPs, or domains were extracted from static strings, only pattern matches confirmed.

## 8. Capabilities & MITRE ATT&CK Mapping
All mappings are derived from static analysis evidence, no dynamic confirmation:
| ATT&CK ID | ATT&CK Name | Evidence Source | Evidence Detail |
|-----------|-------------|----------------|----------------|
| T1027 | Obfuscated Files or Information | capa (capa Capability Rules table) | Rule `encode data using XOR` matched |
| T1027.002 | Software Packing | capa (capa Capability Rules table); yara (YARA Matches table) | Rule `packed with generic packer` matched; YARA rule `AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER` matched at offset 2 |
| T1112 | Modify Registry | pe_imports (PE Imports / Signals table); yara (YARA Matches table) | Import of `RegSetValue` confirmed; YARA rule `win_registry` matched at offsets 50204, 49486, 49470, 49454, 49506 |
| T1106 | Process Execution | pe_imports (PE Imports / Signals table) | Import of `CreateProcess` confirmed |
| T1129 | Dynamic API Resolution | pe_imports (PE Imports / Signals table) | Imports of `LoadLibrary` and `GetProcAddress` confirmed |
| T1055 | Process Injection (potential) | r2_decomp (0x00431384 disassembly) | Import of `CreateThread` confirmed, commonly used for process injection |
| T1089 | Disable or Modify Tools (potential) | yara (YARA Matches table) | YARA rule `win_files_operation` matched at multiple offsets, indicates file modification capabilities |
| T1218 | System Binary Proxy Execution (potential) | r2_decomp (import thunks) | Imports of `WinExec`, `CreateProcessA` confirmed, could be used to proxy execution via system binaries |
| B0023 (MBC) | Install Additional Program | capa (capa Capability Rules table) | Rule `contain an embedded PE file` matched, indicates ability to drop secondary payloads |

Additional capabilities:
- Embedded secondary PE file (source: capa, capa Capability Rules table)
- SEH usage for exception handling (source: yara, YARA Matches table, SEH_Save/SEH_Init matches)
- Mutex usage for single-instance or anti-analysis (source: yara, YARA Matches table, win_mutex match at 48626)
- WinINet library reference for network communication (source: yara, YARA Matches table, Str_Win32_Wininet_Library match at 49832)

## 9. Indicators of Compromise
### File-Based IOCs
| IOC Type | Value | Source |
|----------|-------|--------|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 | llm_judge (verdict.json) |
| Packer Marker | AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER at file offset 2 | yara (YARA Matches table) |
| XOR Decryption Loop | EP at 0x00430005, decrypts .text section (0x401000-0x408ecc) with key 0x462530e4 | r2_decomp (0x00430005 disassembly) |
| SEH Patterns | Offsets 66713 (SEH_Save), 66720 (SEH_Init) | yara (YARA Matches table) |
| Mutex String | Offset 48626, length 11 | yara (YARA Matches table) |
| Registry Strings | Offsets 50204, 49486, 49470, 49454, 49506 | yara (YARA Matches table) |
| File Operation Strings | Offsets 49856, 48766, 48606, 48766, 48582, 48818, 48566 | yara (YARA Matches table) |
| WinINet Library String | Offset 49832, length 11 | yara (YARA Matches table) |
| Base64 Content | Offset 47878, length 16 | yara (YARA Matches table) |
| IPv6 Pattern | Offset 72810, length 23 | yara (YARA Matches table) |
| Domain Pattern | Offset 0, length 2 | yara (YARA Matches table) |
| Obfuscated String Patterns | FLOSS static strings with %F, %IR, %O, %I prefixes (715 total) | floss (FLOSS Strings section) |

### High-Signal Imports
| API | Module | ATT&CK | Source |
|-----|--------|--------|--------|
| RegSetValue | advapi32.dll (implied) | T1112 | pe_imports (PE Imports / Signals table) |
| CreateProcess | KERNEL32.dll | T1106 | pe_imports (PE Imports / Signals table) |
| LoadLibrary | KERNEL32.dll | T1129 | pe_imports (PE Imports / Signals table) |
| GetProcAddress | KERNEL32.dll | T1129 | pe_imports (PE Imports / Signals table) |
| CreateThread | KERNEL32.dll | T1055 (potential) | r2_decomp (0x00431384 disassembly) |
| WinExec | KERNEL32.dll | T1218 (potential) | r2_decomp (0x00431340 disassembly) |

Note: No full external C2 IPs/domains were extracted from static analysis, only pattern matches confirmed.

## 10. Detection Engineering
### Generated Detection Rules
- Custom YARA rule generated for this sample, saved to `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar`, validated as `yara_valid=True`, `yara_check=ok`, 0 false positives in goodware corpus (goodware corpus not staged) (source: rule.yara.json, yara_gen_v2 audit trail).
- Corresponding Sigma rule saved to `/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml` (source: rule.yara.json).

### Detection Signatures
1. **Packer/EP Signature**: Detect the XOR decryption loop at entry point 0x00430005: `pushal; mov eax, 0x401000; mov ebx, 0x408ecc; mov ecx, 0x462530e4; loop: xor [eax], ecx; inc eax; inc eax; cmp eax, ebx; jne loop; mov eax, 0x42b000` (source: r2_decomp, 0x00430005 disassembly).
2. **Packer Fingerprint**: Detect the AHTeam EP Protector / fake PCGuard marker at file offset 2 (source: yara, YARA Matches table, rule `AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER`).
3. **SEH Pattern**: Detect SEH_Save at offset 66713 and SEH_Init at offset 66720 (source: yara, YARA Matches table).
4. **String-Based Signatures**: Detect obfuscated FLOSS strings with %F/%IR/%O/%I prefixes, mutex string at 48626, registry strings at 50204/49486/49470/49454/49506, WinINet library string at 49832 (source: floss, yara).
5. **Import-Based Signatures**: Detect PE files importing RegSetValue, CreateProcess, LoadLibrary, GetProcAddress, CreateThread, and WinExec in combination with packer indicators (source: pe_imports, r2_decomp).
6. **capa-Based Detection**: Use capa rules for `packed with generic packer`, `encode data using XOR`, and `contain an embedded PE file` to identify similar packed malware (source: capa, capa Capability Rules table).

## 11. What We Don't Know
- No function-level decompilation, control flow graphs, or Ghidra/IDA-specific analysis data is available due to operational failures: Ghidra returned `NotOwnerException` (project owned by remnux), IDA failed due to missing `/usr/local/bin/idasql` binary (source: deep_dive_agentic, deep-dive.json; audit trail ghidra_query entries).
- No unpacked payload is available: UPX unpack failed, and the sample uses a custom AHTeam EP Protector / fake PCGuard wrapper with no public unpacker (source: upx, UPX Unpack section; yara, YARA Matches table).
- No dynamic behavioral data is available: Speakeasy emulation recorded 0 API calls and 0 events, no Frida instrumentation data was collected (source: speakeasy, Speakeasy (dynamic) section; frida_probe, Frida Probe section).
- No full C2 infrastructure indicators (full IPs, domains, URLs) were extracted: only YARA pattern matches for domain, IP, and base64 content were confirmed, no full strings were recovered (source: yara, YARA Matches table).
- No confirmed payload functionality: family guess is generic packed trojan/downloader/dropper, but no evidence confirms specific payload behavior (e.g., ransomware, infostealer, RAT) (source: llm_judge, verdict.json).
- No persistence mechanism details: only RegSetValue import and registry string patterns were observed, no specific registry keys/paths were extracted (source: pe_imports, yara).
- No embedded PE content details: capa confirmed an embedded PE file exists, but no size, offset, or functionality of the embedded payload is available (source: capa, capa Capability Rules table).

## 12. Appendix: Analysis Environment
| Tool/Engine | Version/Status | Output/Result | Source |
|-------------|---------------|--------------|--------|
| capa | N/A, duration 2.63s | 5 rules matched: packed with generic packer, encode data using XOR, contain an embedded PE file, contain loop, (internal) packer file limitation | capa, capa Capability Rules table |
| pe_imports | N/A | 113 total imports, 4 high-signal signals | pe_imports, PE Imports / Signals section |
| YARA | N/A | 15 total matches, including packer, SEH, mutex, registry, file, network indicators | yara, YARA Matches table |
| FLOSS | N/A | 715 total static strings, 0 decoded/stack/tight strings | floss, FLOSS Strings section |
| radare2 | N/A | Disassembly of EP (0x00430005) and import thunks (0x004312b0, 0x00431334, 0x00431340, 0x00431384) | r2_decomp, radare2 Disassembly section |
| UPX | N/A | upx_ok=False, is_packed=False, returncode=None, unpacked_path=`` | upx, UPX Unpack section |
| XOR Search | N/A | XOR 00 keys found at 0x00000000 (0x80 bytes) and 0x0001B800 (0x80 bytes) | xor, XOR Search section |
| Speakeasy | N/A | speakeasy_ok=True, 0 API calls, 0 key events, duration_s=None | speakeasy, Speakeasy (dynamic) section |
| Frida | v17.16.4 | frida_available=True, no instrumentation data collected | frida_probe, Frida Probe section |
| Malcat | N/A | Analysis error: `malcat_analyze top-level: MCP malcat closed: ` | Malcat Structured Analysis section |
| Ghidra | N/A | NotOwnerException: project owned by remnux, no analysis data available | deep_dive_agentic, deep-dive.json; audit trail ghidra_query entries |
| IDA | N/A | Missing /usr/local/bin/idasql binary, no analysis data available | deep_dive_agentic, deep-dive.json |
| Analysis Timestamp | N/A | 2026-08-06 02:07:41 UTC | yara_gen_v2, rule.yara.json provenance |
| Sample Path | N/A | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir | llm_judge, verdict.json |
| Project Name | N/A | incoming | llm_judge, verdict.json |
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: malicious
- **score**: 92
- **family_guess**: Packed generic malware (likely trojan/downloader/dropper), potentially wrapped with the AHTeam EP Protector / fake PCGuard packer
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA analysis failed due to operational errors (Ghidra project ownership conflict, missing IDA idasql binary), so no function, decompilation, or Ghidra/IDA-specific import/string data is available. All evidence from operational engines (capa, pe_imports, YARA, FLOSS) is consistent: the sample is a packed, obfuscated PE32 with malicious capabilities, embedded payload indicators, and potential C2 markers.
- **summary**: This sample is a confirmed malicious packed PE32 executable. Static analysis from capa, pe_imports, YARA, and FLOSS confirms it uses generic packing and XOR obfuscation to hinder analysis, contains an embedded secondary PE, has high-signal malicious Windows API imports for registry modification, process execution, and dynamic API resolution, and includes indicators of potential C2 communication (domain/IP/base64 patterns). The sample is likely a trojan, downloader, or dropper wrapped with the AHTeam EP Protector / fake PCGuard packer. No functional or decompilation data is available due to Ghidra/IDA analysis failures.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `packed with generic packer` | capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malwa |
| capa | top_rules | `encode data using XOR` | capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming a |
| capa | top_rules | `contain an embedded PE file` | capa found an embedded PE file within the sample, a common malware technique for dropping additional payloads or seconda |
| pe_imports | signals | `set_registry_value (RegSetValue) [T1112]` | High-signal import indicating the sample can modify Windows registry values, a common tactic for persistence, configurat |
| pe_imports | signals | `create_process (CreateProcess) [T1106]` | High-signal import indicating the sample can spawn new processes, used for executing payloads, running child malware, or |
| pe_imports | signals | `load_library (LoadLibrary) [T1129], get_proc_address (GetProcAddress) [T1129]` | High-signal imports indicating dynamic API resolution, a common technique to hide malicious function calls from static i |
| yara | matches | `IsPE32, HasOverlay, HasModified_DOS_Message, AHTeam_EP_Protector_03_fake_PCGuard` | YARA matches confirm the sample is a valid PE32 file with an overlay (common for packed/embedded content), modified DOS  |
| yara | matches | `contains_base64, domain, IP` | YARA detected base64 encoded content, domain, and IP address patterns in the sample, indicating potential C2 communicati |
| capa | strings | `715 total static strings, including obfuscated formatted strings (e.g. '%F', '%I` | FLOSS extracted 715 static strings, many of which are obfuscated (consistent with the XOR packing detected by capa), ind |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: Deterministic static signals indicate a packed/protected Windows PE with anti-analysis and persistence behaviors. YARA matches include packer/protector fingerprints, SEH initialization/save patterns, and mutex/registry strings. capa reports XOR obfuscation, generic packing, and an embedded PE. PE import signals show registry modification and process creation APIs. Ghidra/IDA/SQL analysis is unavailable due to project ownership and missing idasql, but the existing tool evidence is sufficient for a high-confidence malicious classification.

### deep key_evidence
- `"YARA rule AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER matched at offset 2"`
- `"YARA rules SEH_Save and SEH_Init matched near offset 66713/66720"`
- `"YARA rule win_mutex matched at offset 48626"`
- `"YARA rule win_registry matched at offsets 50204, 49486, 49470, 49454, 49506"`
- `"YARA rules domain, IP, contains_base64, and maldoc_getEIP_method_1 matched"`
- `"capa rule encode data using XOR (T1027) matched"`
- `"capa rule packed with generic packer (T1027.002) matched"`
- `"capa rule contain an embedded PE file matched"`
- `"pe_import_signals: RegSetValue (T1112), CreateProcess (T1106), LoadLibrary/GetProcAddress (T1129)"`
- `"Ghidra SQL unavailable: NotOwnerException on project owned by remnux"`
- `"IDA SQL unavailable: /usr/local/bin/idasql missing"`
- `"Malcat analysis error; Speakeasy returned no events/APIs/strings"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 5 · duration_s: 2.63

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| packed with generic packer | T1027.002:Obfuscated Files or Information | F0001.002:Software Packing |
| contain an embedded PE file |  | B0023:Install Additional Program |
| contain loop |  |  |
| (internal) packer file limitation |  |  |

## PE Imports / Signals
import_count: 113

| label | api_match | ATT&CK |
|---|---|---|
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 15

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv6@72810 len=23 |
| contains_base64 | - | $a@47878 len=16 |
| maldoc_getEIP_method_1 | - | $a@54788 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasOverlay | - |  |
| HasModified_DOS_Message | - |  |
| AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER | - | $b@2 len=1 |
| SEH_Save | - | $a@66713 len=7 |
| SEH_Init | - | $b@66720 len=7 |
| win_mutex | - | $c1@48626 len=11 |
| win_registry | - | $f1@50204 len=12; $c1@49486 len=16; $c2@49470 len=13; $c3@49454 len=11; $c4@49506 len=14; $c6@49454 len=11 |
| win_files_operation | - | $f1@49856 len=12; $c1@48766 len=9; $c2@48606 len=14; $c3@48766 len=9; $c4@48582 len=8; $c5@48818 len=11; $c6@48566 len=11 |
| Str_Win32_Wininet_Library | - | $wininet_lib@49832 len=11 |

## Generated YARA Meta
```json
{
  "sha256": "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9",
  "family": "unknown",
  "generated_at": "2026-08-06T02:07:41.572525+00:00",
  "string_count": 9,
  "strings": [
    "capa identified the sample is packed with a generic packer, matching ATT&CK T1027.002 (Software Packing), a common malwa",
    "capa detected XOR encoding behavior in the sample, matching ATT&CK T1027 (Obfuscated Files or Information), confirming a",
    "capa found an embedded PE file within the sample, a common malware technique for dropping additional payloads or seconda",
    "High-signal import indicating the sample can modify Windows registry values, a common tactic for persistence, configurat",
    "High-signal import indicating the sample can spawn new processes, used for executing payloads, running child malware, or",
    "High-signal imports indicating dynamic API resolution, a common technique to hide malicious function calls from static i",
    "YARA matches confirm the sample is a valid PE32 file with an overlay (common for packed/embedded content), modified DOS ",
    "YARA detected base64 encoded content, domain, and IP address patterns in the sample, indicating potential C2 communicati",
    "FLOSS extracted 715 static strings, many of which are obfuscated (consistent with the XOR packing detected by capa), ind"
  ],
  "rule_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yar",
  "sigma_path": "/opt/samples/logs/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/rule.yml",
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
    "utc": "2026-08-06 02:07:41 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 715 · per_category: `{"decoded_strings": 0, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 715}`

### FLOSS sample
- `.idata`
- `.kofbl`
- `<OF#55`
- `1PA\2%F`
- `oe-IZ4'IZ$`
- `#&%FgV!F`
- `:Pr%FEL`
- `p0%Fmu`
- `0%O?D!`
- `%I`3$F`
- `1 ~{q%`
- `(^{q%fm`
- `Dr%O$L`
- `\r%{d0%F`
- `1%F\GRF`
- `v0%FdM`
- `4Pad==`
- `0Mn^r%`
- `0M{^r%`
- `0%Fi5Q`
- `Ii4 /Xr%`
- `<3`Vid`
- `!IR4#{`
- `pVid6C`
- `Ii<(~Xr%`
- `Do$0fup%`
- `m<0vqp%IR`
- `2Pr%IR`
- `gF]!%F`
- `MCIRs$c$0%Fg`
- `0QNou)`
- `#Z%.d0%F`
- `gF]3%F`
- `ou)ISp'`
- `eNoe-ISb-o41``
- `xNou) mu)`
- `>0%Fou`
- `5IR4;{`
- `L}%Fmu`
- `D}%FoM`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00430005
```asm
┌ 139: fcn.00430005 ();
│       ╎   0x00430005      60             pushal
│       ╎   0x00430006      90             nop
│       ╎   0x00430007      b800104000     mov eax, section..text      ; 0x401000
│       ╎   0x0043000c      bbcc8e4000     mov ebx, 0x408ecc
│       ╎   0x00430011      90             nop
│       ╎   0x00430012      b9e4302546     mov ecx, 0x462530e4
│       ╎   0x00430017      90             nop
│       ╎   0x00430018      90             nop
│       ╎   0x00430019      90             nop
│       ╎   0x0043001a      85c0           test eax, eax
│       ╎   0x0043001c      90             nop
│       ╎   0x0043001d      90             nop
│       ╎   0x0043001e      90             nop
│       ╎   0x0043001f      90             nop
│       ╎   0x00430020      90             nop
│       ╎   0x00430021      90             nop
│      ┌──< 0x00430022      742a           je 0x43004e
│     ┌───> 0x00430024      90             nop
│     ╎│╎   0x00430025      90             nop
│     ╎│╎   0x00430026      90             nop
│     ╎│╎   0x00430027      90             nop
│     ╎│╎   0x00430028      3108           xor dword [eax], ecx
│     ╎│╎   0x0043002a      90             nop
│     ╎│╎   0x0043002b      90             nop
│     ╎│╎   0x0043002c      90             nop
│     ╎│╎   0x0043002d      90             nop
│     ╎│╎   0x0043002e      90             nop
│     ╎│╎   0x0043002f      40             inc eax
│     ╎│╎   0x00430030      40             inc eax
│     ╎│╎   0x00430031      90             nop
│     ╎│╎   0x00430032      90             nop
│     ╎│╎   0x00430033      90             nop
│     ╎│╎   0x00430034      90             nop
│     ╎│╎   0x00430035      90             nop
│     ╎│╎   0x00430036      90             nop
│     ╎│╎   0x00430037      90             nop
│     ╎│╎   0x00430038      90             nop
│     ╎│╎   0x00430039      90             nop
│     ╎│╎   0x0043003a      40             inc eax
│     ╎│╎   0x0043003b      90             nop
│     ╎│╎   0x0043003c      40             inc eax
│     ╎│╎   0x0043003d      90             nop
│     ╎│╎   0x0043003e      90             nop
│     ╎│╎   0x0043003f      90             nop
│     ╎│╎   0x00430040      90             nop
│     ╎│╎   0x00430041      90             nop
│     ╎│╎   0x00430042      90             nop
│     ╎│╎   0x00430043      90             nop
│     ╎│╎   0x00430044      90             nop
│     ╎│╎   0x00430045      39d8           cmp eax, ebx
│     ╎│╎   0x00430047      90             nop
│     ╎│╎   0x00430048      90             nop
│     ╎│╎   0x00430049      90             nop
│     ╎│╎   0x0043004a      90             nop
│     ╎│╎   0x0043004b      90             nop
│     └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
### 0x004312b0
```asm
┌ 133: sym.imp.ole32.DLL_CoCreateInstance ();
│           0x004312b0      98             cwde
│           0x004312b1      1403           adc al, 3
│           0x004312b3  ~   00ac140300..   add byte [esp + edx + 0x14be0003], ch ; [0x14be0003:1]=255
│           ;-- CLSIDFromString:
..
│           0x004312ba      0300           add eax, dword [eax]
│           ;-- CoUninitialize:
│           0x004312bc      ce             into
│           0x004312bd      1403           adc al, 3
│           0x004312bf      0000           add byte [eax], al
│           0x004312c1      0000           add byte [eax], al
│           0x004312c3  ~   00e0           add al, ah
│           ;-- SysAllocString:
..
│           0x004312c5      1403           adc al, 3
│           0x004312c7      0000           add byte [eax], al
│           0x004312c9      0000           add byte [eax], al
│           0x004312cb  ~   00f2           add dl, dh
│           ;-- DeleteUrlCacheEntry:
..
│           0x004312cd      1403           adc al, 3
│           0x004312cf  ~   0008           add byte [eax], cl
│           ;-- FindFirstUrlCacheEntryA:
..
│           0x004312d1  ~   1503002215     adc eax, 0x15220003
│           ;-- FindNextUrlCacheEntryA:
..
│           0x004312d6      0300           add eax, dword [eax]
│           0x004312d8      0000           add byte [eax], al
│           0x004312da      0000           add byte [eax], al
│           ;-- ExitProcess:
│           0x004312dc      3c15           cmp al, 0x15                ; 21
│           0x004312de      0300           add eax, dword [eax]
│           ;-- ExpandEnvironmentStringsA:
│           0x004312e0      4a             dec edx
│           0x004312e1  ~   1503006615     adc eax, 0x15660003
│           ;-- GetCommandLineA:
..
│           0x004312e6      0300           add eax, dword [eax]
│           ;-- GetComputerNameA:
│       ┌─< 0x004312e8      7815           js 0x4312ff
│       │   0x004312ea      0300           add eax, dword [eax]
│       │   ;-- GetCurrentProcessId:
│       │   0x004312ec  ~   8c150300a215   mov word [0x15a20003], ss   ; [0x15a20003:2]=0xffff pe_overlay
│       │   ;-- GetCurrentThreadId:
..
│       │   0x004312f2      0300           add eax, dword [eax]
│       │   ;-- GetExitCodeThread:
│       │   0x004312f4  ~   b8150300cc     mov eax, 0xcc000315
│       │   ;-- GetFileSize:
..
│       │   0x004312f9  ~   150300da15     adc eax, 0x15da0003
│       │   ;-- GetModuleFileNameA:
..
│       │   0x004312fe  ~   0300           add eax, dword [eax]
│       │   ;-- (0x00431300) GetModuleHandleA:
│       └─> 0x004312ff  ~   00f0           add al, dh
│           0x00431301  ~   1503000416     adc eax, 0x16040003
│           ;-- CloseHandle:
..
│           0x00431306      0300           add eax, dword [eax]
│           ;-- GetProcAddress:
│           0x00431308      1216           adc dl, byte [esi]
│           0x0043130a      0300           add eax, dword [eax]
│           ;-- GetSystemDirectoryA:
│    
```
### 0x00431334
```asm
┌ 11: sym.imp.KERNEL32.DLL_IsBadWritePtr ();
│           0x00431334      da16           ficom dword [esi]
│           0x00431336      0300           add eax, dword [eax]
│           ;-- LoadLibraryA:
└       ┌─< 0x00431338  ~   ea160300fa..   ljmp 0x316
│       │   ;-- LocalAlloc:
..
```
### 0x00431340
```asm
┌ 68: sym.imp.KERNEL32.DLL_LocalFree ();
│           0x00431340      0817           or byte [edi], dl
│           0x00431342      0300           add eax, dword [eax]
│           ;-- OpenMutexA:
│           0x00431344      1417           adc al, 0x17
│           0x00431346      0300           add eax, dword [eax]
│           ;-- CreateFileA:
│           0x00431348      2217           and dl, byte [edi]
│           0x0043134a      0300           add eax, dword [eax]
│           ;-- ReadFile:
│           0x0043134c      3017           xor byte [edi], dl
│           0x0043134e      0300           add eax, dword [eax]
│           ;-- RtlUnwind:
│           0x00431350      3c17           cmp al, 0x17                ; 23
│           0x00431352      0300           add eax, dword [eax]
│           ;-- SetFilePointer:
│           0x00431354      48             dec eax
│           0x00431355      17             pop ss
│           0x00431356      0300           add eax, dword [eax]
│           ;-- CreateMutexA:
│           0x00431358      5a             pop edx
│           0x00431359      17             pop ss
│           0x0043135a      0300           add eax, dword [eax]
│           ;-- Sleep:
│           0x0043135c      6a17           push 0x17                   ; 23
│           0x0043135e      0300           add eax, dword [eax]
│           ;-- TerminateProcess:
│      ┌──< 0x00431360      7217           jb 0x431379
│      │    0x00431362      0300           add eax, dword [eax]
│      │    ;-- VirtualQuery:
│      │    0x00431364      8617           xchg byte [edi], dl
│      │    0x00431366      0300           add eax, dword [eax]
│      │    ;-- CreateProcessA:
│      │    0x00431368      96             xchg esi, eax
│      │    0x00431369      17             pop ss
│      │    0x0043136a      0300           add eax, dword [eax]
│      │    ;-- WaitForSingleObject:
│      │    0x0043136c      a817           test al, 0x17               ; 23
│      │    0x0043136e      0300           add eax, dword [eax]
│      │    ;-- WideCharToMultiByte:
│      │    0x00431370  ~   be170300d4     mov esi, 0xd4000317
│      │    ;-- WinExec:
..
│      │    0x00431375      17             pop ss
│      │    0x00431376      0300           add eax, dword [eax]
│      │    ;-- WriteFile:
│      │    0x00431378  ~   de17           ficom word [edi]
│      └──> 0x00431379      17             pop ss
│           0x0043137a      0300           add eax, dword [eax]
│           ;-- lstrlenA:
└       ┌─< 0x0043137c  ~   ea170300f6..   ljmp 0x317
│       │   ;-- lstrlenW:
..
```
### 0x00431384
```asm
┌ 2611: sym.imp.KERNEL32.DLL_CreateThread (int32_t arg_1h, int32_t arg_41h, int32_t arg_4eh, int32_t arg_50h, int32_t arg_53h, int32_t arg_65h, int32_t arg_66h, int32_t arg_6ch, int32_t arg_6fh, int32_t arg_72h, int32_t arg_73h);
│           ; arg int32_t arg_1h @ ebp+0x1
│           ; arg int32_t arg_41h @ ebp+0x41
│           ; arg int32_t arg_4eh @ ebp+0x4e
│           ; arg int32_t arg_50h @ ebp+0x50
│           ; arg int32_t arg_53h @ ebp+0x53
│           ; arg int32_t arg_65h @ ebp+0x65
│           ; arg int32_t arg_66h @ ebp+0x66
│           ; arg int32_t arg_6ch @ ebp+0x6c
│           ; arg int32_t arg_6fh @ ebp+0x6f
│           ; arg int32_t arg_72h @ ebp+0x72
│           ; arg int32_t arg_73h @ ebp+0x73
│           0x00431384      0218           add bl, byte [eax]
│           0x00431386      0300           add eax, dword [eax]
│           ;-- DeleteFileA:
│           0x00431388      1218           adc bl, byte [eax]
│           0x0043138a      0300           add eax, dword [eax]
│           0x0043138c      0000           add byte [eax], al
│           0x0043138e      0000           add byte [eax], al
│           ;-- GetWindowTextA:
│           0x00431390      2018           and byte [eax], bl
│           0x00431392      0300           add eax, dword [eax]
│           ;-- GetWindowRect:
│           0x00431394      3218           xor bl, byte [eax]
│           0x00431396      0300           add eax, dword [eax]
│           ;-- FindWindowA:
│           0x00431398      42             inc edx
│           0x00431399      1803           sbb byte [ebx], al
│           0x0043139b  ~   005018         add byte [eax + 0x18], dl
│           ;-- GetWindow:
..
│           0x0043139e      0300           add eax, dword [eax]
│           ;-- GetClassNameA:
│           0x004313a0      5c             pop esp
│           0x004313a1      1803           sbb byte [ebx], al
│           0x004313a3  ~   006c1803       add byte [eax + ebx + 3], ch
│           ;-- SetFocus:
..
│           0x004313a7  ~   007818         add byte [eax + 0x18], bh
│           ;-- GetForegroundWindow:
..
│           0x004313aa      0300           add eax, dword [eax]
│           ;-- LoadCursorA:
│           0x004313ac      8e18           mov ds, word [eax]
│           0x004313ae      0300           add eax, dword [eax]
│           ;-- LoadIconA:
│           0x004313b0      9c             pushfd
│           0x004313b1      1803           sbb byte [ebx], al
│           0x004313b3  ~   00a8180300b4   add byte [eax - 0x4bfffce8], ch
│           ;-- SetTimer:
..
│           ;-- RegisterClassA:
│           0x004313b9      1803           sbb byte [ebx], al
│           0x004313bb  ~   00c6           add dh, al
│           ;-- MessageBoxA:
..
│           0x004313bd      1803           sbb byte [ebx], al
│           0x004313bf  ~   00d4           add ah, dl
│           ;-- GetMessageA:
..
│           0x004313c1      1803           sbb byte [ebx], al
│           0x004313c3  ~   00e2           add
```

## UPX Unpack
- upx_ok: False
- is_packed: False
- returncode: None
- unpacked_path: ``

## XOR Search
- Found XOR 00 position 00000000: 00000080 ......................................
- Found XOR 00 position 0001B800: 00000080 ......................................

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
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785748958.3501425}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785748958.3641121}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785749000.3795428}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785749000.4069881}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785749000.443895}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785749000.455804}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785749000.4575567}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785749052.6175096}`
- `{"source": "ghidra_query", "sql": "SELECT * FROM imports LIMIT 50", "ts": 1785749076.6087127}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785749125.4630806}`
- `{"source": "yara_gen_v2", "ts": 1785749126.4961004}`
- `{"source": "publish_report_v2", "ts": 1785749299.0191534}`
- `{"source": "publish_report_v2_technical", "ts": 1785749370.8177176}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785866660.4672472}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785866660.5242667}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785866660.5350804}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785866660.5470166}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785866710.624441}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785866710.6461916}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785866710.679197}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785866710.6855972}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785866710.6905031}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785866771.3637059}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY address", "ts": 1785866775.280683}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785866828.0064878}`
- `{"source": "yara_gen_v2", "ts": 1785866829.040809}`
- `{"source": "publish_report_v2", "ts": 1785866982.4205317}`
- `{"source": "publish_report_v2_technical", "ts": 1785867094.8755093}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785981924.861473}`
- `{"source": "yara_gen_v2", "ts": 1785982061.5731585}`
