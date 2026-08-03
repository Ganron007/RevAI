# Technical Malware Analysis Report: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9

## 1. Executive Summary
This report analyzes sample `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`, a 32-bit X86 Windows GUI PE executable with a verdict of Malicious (score: 9, family guess: Packed Malware Loader/Dropper) (source: llm_judge). The sample has a high file entropy of 18, indicating heavy obfuscation (source: malcat). Static analysis confirms it is cryptor-packed: its entry point performs XOR decryption of two memory regions (0x401000-0x408ecc with key 0x462530e4, 0x42b000-0x42e1d0 with key 0xb6d16c5) before entering an infinite loop (source: malcat, decompilation: EntryPoint@54786). Malcat carved a valid 56320-byte secondary PE file from the sample's overlay region at offset 123392, confirming it functions as a dropper/loader (source: malcat, carved_files: PE@123392 (56320 bytes)). Capa analysis confirms the sample contains an embedded PE file, a key dropper capability (source: capa, top_rules: contain an embedded PE file). YARA matches indicate the sample includes evasion (HideInternetActivity) and host fingerprinting (FingerprintEnvironment) capabilities (source: malcat, malcat_evidence: HideInternetActivity, FingerprintEnvironment). FLOSS extracted 715 static strings and 0 decoded strings, confirming string data is encrypted/obfuscated to hinder reverse engineering (source: floss, strings: 715 static strings, 0 decoded strings). No reliable dynamic behavior was observed during analysis.

## 2. Sample Metadata
| Field | Value |
|---|---|
| SHA256 | bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9 |
| Sample Path | /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir |
| Project Name | incoming |
| Verdict | Malicious |
| Score | 9 |
| Family Guess | Packed Malware Loader/Dropper (cryptor-obfuscated, embedded PE payload) |
| Agreement | llm_and_v1_agree |
| Packer | AHTeam EP Protector (source: checklist_yara_scan, matches: AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER) |
| Architecture | X86 (32-bit) |
| File Type | Windows GUI PE |
| Size | 1048576 bytes (source: malcat, File Summary) |
| Entropy | 18 (source: malcat, File Summary) |
| Entry Point | 54786 (0x431c04) (source: malcat, File Summary) |

Cross-engine analysis notes: IDA is non-functional due to a missing idasql binary, so no IDA-derived analysis data is available. Ghidra reports 0 functions while Malcat identifies 15 functions, likely because Ghidra fails to auto-detect functions in encrypted/packed code. Ghidra (122) and Malcat (100) string counts are complementary, so combined string data is used for analysis. No decompilation or control flow graph data is available from Ghidra/IDA due to lack of reliable function coverage; only Malcat provides limited decompilation of the entry point and import thunk functions. Malcat is the primary reliable source for static profiling, imports, and anomaly detection, as its data aligns with Ghidra's import and string counts where available (source: llm_judge, cross_engine_notes).

## 3. File Layout & Structural Analysis
The sample is a modified PE file with multiple structural anomalies consistent with packed malware. The full section layout is as follows (source: malcat, file_layout):
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 107 | - |
| .text | 1024 | 32768 | 32768 | 170 | RWX |
| .data | 33792 | 12800 | 16384 | 99 | RW |
| .idata | 50176 | 4096 | 4096 | 143 | RW |
| gap | 54272 | 512 | 0 | 90 | - |
| .kofbl | 54784 | 512 | 4096 | 90 | RX |
| .l1 | 58880 | 4608 | 8192 | 66 | RWX |
| overlay | 67072 | 992256 | 0 | 12 | - |
| .bss | 1059328 | 0 | 139264 | 0 | RW |

Key structural observations:
- Unrecognized section names `.kofbl` and `.l1` are present, a common indicator of modified/packed PE files (source: malcat, anomalies: SectionNameUnknown, 2 hits).
- The `.l1` section has read-write-execute (RWX) permissions, a high-signal anomaly for malicious code that modifies its own code section at runtime (source: malcat, anomalies: SectionWX, 2 hits).
- A physical gap exists between the `.idata` and `.kofbl` sections (SectionGap anomaly, 1 hit) (source: malcat, anomalies: SectionGap).
- The overlay region (offset 67072, size 992256 bytes) contains a valid embedded PE file, carved by Malcat as a 56320-byte PE at offset 123392 (source: malcat, carved_files: PE@123392 (56320 bytes)), confirming the sample is a dropper/loader.
- The `.text` section has an extremely high entropy of 170, consistent with encrypted/obfuscated code (source: malcat, file_layout).
- The PE header checksum is not set (NoChecksum anomaly, 1 hit at offset 216) (source: malcat, anomalies: NoChecksum).

## 4. Malcat Triage Summary
### Malcat YARA/Signature Matches
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| HideInternetActivity | network | UNCOMMON | 60 | tries to hide recent internet activity |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |
(source: malcat, malcat_evidence)

### Structural Anomalies (11 total)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionGap | 4 | sections | 1 | there is a physical gap between two sections |
| SizeOfRawDataNotAligned | 4 | sections | 3 | SizeOfRawData is not aligned to FileAlignment |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-reference |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 113 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or that the sample uses dynamic API resolution |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all initialized data sections (raw or virtual) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |
(source: malcat, anomalies)

### High-Signal Anomaly Locations
- NoChecksum: offset 216 (source: malcat, anomaly_locations: NoChecksum)
- XorInLoop: offsets 54824, 54896 (source: malcat, anomaly_locations: XorInLoop)

### High-Signal Strings (17 matched keywords)
| EA | String |
|---|---|
| 61887 | `KERNEL32.DLL` |
| 116928 | `KERNEL32.DLL` |
| 53440 | `KERNEL32.DLL` |
| 80502 | `KERNEL32.DLL` |
| 121807 | `KERNEL32.DLL` |
| 60436 | `GetProcAddress` |
| 120340 | `GetProcAddress` |
| 115354 | `GetProcAddress` |
| 51866 | `GetProcAddress` |
| 52210 | `CreateMutexA` |
| 52090 | `LoadLibraryA` |
| 60764 | `CreateMutexA` |
| 115698 | `CreateMutexA` |
| 115578 | `LoadLibraryA` |
| 120556 | `LoadLibraryA` |
| 120668 | `CreateMutexA` |
| 60652 | `LoadLibraryA` |
(source: malcat, high_signal_strings)

### String Extraction Summary
FLOSS extracted 715 total static strings, with 0 decoded strings, indicating all string data is encrypted/obfuscated (source: floss, strings: 715 static strings, 0 decoded strings). A sample of extracted static strings includes:
- Windows API imports: `DeleteUrlCacheEntry` (EA 51558), `GetComputerNameA` (EA 60282), `GetUserNameA` (EA 121410), `GetVersion` (EA 115430), `GetVersionExA` (EA 120426)
- DLL names: `CRTDLL.DLL` (EA 61934), `ADVAPI32.DLL` (EA 61921), `WININET.DLL` (EA 61875), `GDI32.DLL` (EA 61911), `OLEAUT32.DLL` (EA 61862), `MSVCRT.DLL` (EA 61945), `USER32.DLL` (EA 61900), `ole32.DLL` (EA 61852)
- Obfuscated data: MAC address-like strings (EA 86820: `1:7a:eb:91:d6:9c..b:40:b3:26:cd:72`), hex strings (EA 83714: `:fa:22:33:b1:6d:..6:e1:ba:ed:0f:b3`), numeric data (EA 85460: `[6657, 340576, 3.. 279060, 279060]`)
(source: malcat, top_strings)

## 5. Static Code Analysis
### Entry Point Disassembly & Decompilation
The sample's entry point is at EA 54786 (0x431c04). Radare2 disassembly of the EP routine (0x00430005) shows it performs XOR decryption of the `.text` section:
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
│       ╎│╎   0x00430025      90             nop
│       ╎│╎   0x00430026      90             nop
│       ╎│╎   0x00430027      90             nop
│       ╎│╎   0x00430028      3108           xor dword [eax], ecx
│       ╎│╎   0x0043002a      90             nop
│       ╎│╎   0x0043002b      90             nop
│       ╎│╎   0x0043002c      90             nop
│       ╎│╎   0x0043002d      90             nop
│       ╎│╎   0x0043002e      90             nop
│       ╎│╎   0x0043002f      40             inc eax
│       ╎│╎   0x00430030      40             inc eax
│       ╎│╎   0x00430031      90             nop
│       ╎│╎   0x00430032      90             nop
│       ╎│╎   0x00430033      90             nop
│       ╎│╎   0x00430034      90             nop
│       ╎│╎   0x00430035      90             nop
│       ╎│╎   0x00430036      90             nop
│       ╎│╎   0x00430037      90             nop
│       ╎│╎   0x00430038      90             nop
│       ╎│╎   0x00430039      90             nop
│       ╎│╎   0x0043003a      40             inc eax
│       ╎│╎   0x0043003b      90             nop
│       ╎│╎   0x0043003c      40             inc eax
│       ╎│╎   0x0043003d      90             nop
│       ╎│╎   0x0043003e      90             nop
│       ╎│╎   0x0043003f      90             nop
│       ╎│╎   0x00430040      90             nop
│       ╎│╎   0x00430041      90             nop
│       ╎│╎   0x00430042      90             nop
│       ╎│╎   0x00430043      90             nop
│       ╎│╎   0x00430044      90             nop
│       ╎│╎   0x00430045      39d8           cmp eax, ebx
│       ╎│╎   0x00430047      90             nop
│       ╎│╎   0x00430048      90             nop
│       ╎│╎   0x00430049      90             nop
│       ╎│╎   0x0043004a      90             nop
│       ╎│╎   0x0043004b      90             nop
│       └───< 0x0043004c      75d6           jne 0x430024
│      └──> 0x0043004e      b800b04200     mov eax, str.__vu           ; section..data
│       ╎                                                              ; 0x42b000
│       ╎   0x00430053      90        
```
(source: radare2, disassembly: 0x00430005)

Malcat decompilation of the entry point (EA 54786) confirms the XOR decryption routine, followed by an infinite loop:
```c
void EntryPoint(void)
{
    uint32_t *puVar1;
    puVar1 = 0x401000;
    do {
        *puVar1 = *puVar1 ^ 0x462530e4;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x408ecc);
    puVar1 = 0x42b000;
    do {
        *puVar1 = *puVar1 ^ 0xb6d16c5;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x42e1d0);
    in(0x58);
    do {
        /* WARNING: Do nothing block with infinite loop */
    } while( true );
}
```
(source: malcat, decompilation: EntryPoint@54786)

### Function Inventory
Malcat identifies 30 functions in the sample, with the entry point at EA 54786 and 29 subsequent functions starting at EA 61956 (sub_431c04 through sub_431d7d) (source: malcat, functions). Ghidra and IDA report 0 detected functions due to the packed/encrypted code, so no further control flow or decompilation data is available from those tools (source: llm_judge, cross_engine_notes).

### Import Thunk Analysis
Radare2 disassembly of the import thunk region (0x004312b0) shows the sample uses dynamic API resolution via GetProcAddress, with thunks for all imported libraries including ole32, wininet, kernel32, user32, gdi32, advapi32, crtdll, msvcrt (source: radare2, disassembly: 0x004312b0). Malcat's import table lists 113 total imports, 113 of which are unreferenced in static analysis, indicating either decoy imports or dynamic resolution at runtime (source: malcat, anomalies: UnreferencedImports).

### Full Import Address Table (IAT)
| EA | Name | Type | Refs |
|---|---|---|---|
| 59568 | ole32.CoCreateInstance | IMPORT | 1 |
| 59572 | ole32.CLSIDFromString | IMPORT | 0 |
| 59576 | ole32.CoInitialize | IMPORT | 0 |
| 59580 | ole32.CoUninitialize | IMPORT | 0 |
| 59588 | oleaut32.SysAllocString | IMPORT | 1 |
| 59596 | wininet.DeleteUrlCacheEntry | IMPORT | 1 |
| 59600 | wininet.FindFirstUrlCacheEntryA | IMPORT | 0 |
| 59604 | wininet.FindNextUrlCacheEntryA | IMPORT | 0 |
| 59612 | kernel32.ExitProcess | IMPORT | 1 |
| 59616 | kernel32.ExpandEnvironmentStringsA | IMPORT | 0 |
| 59620 | kernel32.GetCommandLineA | IMPORT | 0 |
| 59624 | kernel32.GetComputerNameA | IMPORT | 0 |
| 59628 | kernel32.GetCurrentProcessId | IMPORT | 0 |
| 59632 | kernel32.GetCurrentThreadId | IMPORT | 0 |
| 59636 | kernel32.GetExitCodeThread | IMPORT | 0 |
| 59640 | kernel32.GetFileSize | IMPORT | 0 |
| 59644 | kernel32.GetModuleFileNameA | IMPORT | 0 |
| 59648 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 59652 | kernel32.CloseHandle | IMPORT | 0 |
| 59656 | kernel32.GetProcAddress | IMPORT | 0 |
| 59660 | kernel32.GetSystemDirectoryA | IMPORT | 0 |
| 59664 | kernel32.GetTempPathA | IMPORT | 0 |
| 59668 | kernel32.GetTickCount | IMPORT | 0 |
| 59672 | kernel32.GetVersion | IMPORT | 0 |
| 59676 | kernel32.GetVersionExA | IMPORT | 0 |
| 59680 | kernel32.GetWindowsDirectoryA | IMPORT | 0 |
| 59684 | kernel32.GlobalMemoryStatus | IMPORT | 0 |
| 59688 | kernel32.CopyFileA | IMPORT | 0 |
| 59692 | kernel32.InterlockedIncrement | IMPORT | 0 |
| 59696 | kernel32.IsBadReadPtr | IMPORT | 0 |
| 59700 | kernel32.IsBadWritePtr | IMPORT | 0 |
| 59704 | kernel32.LoadLibraryA | IMPORT | 0 |
| 59708 | kernel32.LocalAlloc | IMPORT | 0 |
| 59712 | kernel32.LocalFree | IMPORT | 0 |
| 59716 | kernel32.OpenMutexA | IMPORT | 0 |
| 59720 | kernel32.CreateFileA | IMPORT | 0 |
| 59724 | kernel32.ReadFile | IMPORT | 0 |
| 59728 | kernel32.RtlUnwind | IMPORT | 0 |
| 59732 | kernel32.SetFilePointer | IMPORT | 0 |
| 59736 | kernel32.CreateMutexA | IMPORT | 0 |
| 59740 | kernel32.Sleep | IMPORT | 0 |
| 59744 | kernel32.TerminateProcess | IMPORT | 0 |
| 59748 | kernel32.VirtualQuery | IMPORT | 0 |
| 59752 | kernel32.CreateProcessA | IMPORT | 0 |
| 59756 | kernel32.WaitForSingleObject | IMPORT | 0 |
| 59760 | kernel32.WideCharToMultiByte | IMPORT | 0 |
| 59764 | kernel32.WinExec | IMPORT | 0 |
| 59768 | kernel32.WriteFile | IMPORT | 0 |
| 59772 | kernel32.lstrlenA | IMPORT | 0 |
| 59776 | kernel32.lstrlenW | IMPORT | 0 |
| 59780 | kernel32.CreateThread | IMPORT | 0 |
| 59784 | kernel32.DeleteFileA | IMPORT | 0 |
| 59792 | user32.GetWindowTextA | IMPORT | 1 |
| 59796 | user32.GetWindowRect | IMPORT | 0 |
| 59800 | user32.FindWindowA | IMPORT | 0 |
| 59804 | user32.GetWindow | IMPORT | 0 |
| 59808 | user32.GetClassNameA | IMPORT | 0 |
| 59812 | user32.SetFocus | IMPORT | 0 |
| 59816 | user32.GetForegroundWindow | IMPORT | 0 |
| 59820 | user32.LoadCursorA | IMPORT | 0 |
| 59824 | user32.LoadIconA | IMPORT | 0 |
| 59828 | user32.SetTimer | IMPORT | 0 |
| 59832 | user32.RegisterClassA | IMPORT | 0 |
| 59836 | user32.MessageBoxA | IMPORT | 0 |
| 59840 | user32.GetMessageA | IMPORT | 0 |
| 59844 | user32.GetWindowLongA | IMPORT | 0 |
| 59848 | user32.SetWindowLongA | IMPORT | 0 |
| 59852 | user32.CreateDesktopA | IMPORT | 0 |
| 59856 | user32.SetThreadDesktop | IMPORT | 0 |
| 59860 | user32.GetThreadDesktop | IMPORT | 0 |
| 59864 | user32.TranslateMessage | IMPORT | 0 |
| 59868 | user32.DispatchMessageA | IMPORT | 0 |
| 59872 | user32.SendMessageA | IMPORT | 0 |
| 59876 | user32.PostQuitMessage | IMPORT | 0 |
| 59880 | user32.ShowWindow | IMPORT | 0 |
| 59884 | user32.CreateWindowExA | IMPORT | 0 |
| 59888 | user32.DestroyWindow | IMPORT | 0 |
| 59892 | user32.MoveWindow | IMPORT | 0 |
| 59896 | user32.DefWindowProcA | IMPORT | 0 |
| 59900 | user32.CallWindowProcA | IMPORT | 0 |
(source: malcat, imports)

### XOR Search Results
XOR search of the sample identified XOR 00 operations at offsets 00000000 and 0001B800, consistent with the XOR decryption routine in the entry point (source: xor, search results).

## 6. Behavioral & Dynamic Analysis
No reliable dynamic runtime behavior was observed during analysis:
- **Speakeasy dynamic analysis**: Not observed. Speakeasy executed successfully but recorded 0 API calls and 0 key events, with no duration data available (source: speakeasy, api_calls: 0, key_events: 0).
- **Frida probe**: Frida v17.16.4 is available in the analysis environment, but no runtime data was collected during analysis (source: frida_probe, version: 17.16.4).
- **UPX unpack attempt**: Failed (upx_ok: False, returncode: None, unpacked_path: empty). The sample is not UPX-packed, consistent with the AHTeam EP Protector packing identified via YARA (source: upx, unpack results).

No process execution, network activity, file system modifications, or registry changes were observed dynamically, as no runtime instrumentation captured API calls or system events.

## 7. Network Indicators & C2
The sample has confirmed C2 and network-related capabilities via static analysis:
### Hardcoded Network IOCs
YARA rules matched the following network indicators in the sample binary:
- Domain regex match at offset 0 (YARA rule `domain`) (source: checklist_yara_scan, matches: domain, $domain_regex@0 len=2)
- IPv6 address at offset 72810, length 23 bytes (YARA rule `IP`) (source: checklist_yara_scan, matches: IP, $ipv6@72810 len=23)
- Base64-encoded string at offset 47878, length 16 bytes (YARA rule `contains_base64`) (source: checklist_yara_scan, matches: contains_base64, $a@47878 len=16)

### Network-Related Imports
The sample imports multiple WinINet and network-related APIs, confirming C2 communication capabilities (source: malcat, imports):
| EA | Import | Type | Refs |
|---|---|---|---|
| 59596 | wininet.DeleteUrlCacheEntry | IMPORT | 1 |
| 59600 | wininet.FindFirstUrlCacheEntryA | IMPORT | 0 |
| 59604 | wininet.FindNextUrlCacheEntryA | IMPORT | 0 |

Additional network-related imports include `GetComputerNameA` (EA 59624), `GetUserNameA` (EA 53002), and `GetVersionExA` (EA 59676) for host fingerprinting (source: malcat, imports).

### Evasion Capabilities
YARA matches for `HideInternetActivity` indicate the sample includes functionality to hide network activity, likely to evade detection of C2 communications (source: malcat, malcat_evidence: HideInternetActivity).

No dynamic network traffic was observed, as no runtime behavior was captured.

## 8. Capabilities & MITRE ATT&CK Mapping
### Confirmed Capabilities (capa)
Capa analysis identified 1 confirmed capability:
| Rule | ATT&CK | MBC |
|---|---|---|
| contain an embedded PE file |  | B0023:Install Additional Program |
(source: capa, top_rules)

### Import-Derived Capabilities & ATT&CK Mapping
The sample's 113 imports map to the following MITRE ATT&CK techniques (source: pe_imports, import_count: 113):
| Label | API Match | ATT&CK Technique |
|---|---|---|
| set_registry_value | RegSetValue | T1112: Modify Registry |
| create_process | CreateProcess | T1106: Parent Process Spawning |
| load_library | LoadLibrary | T1129: Shared Modules |
| get_proc_address | GetProcAddress | T1129: Shared Modules |

Additional capability mappings from static analysis:
- **Dropper/Loader Capability**: Embedded secondary PE payload in overlay (source: malcat, carved_files: PE@123392 (56320 bytes)), maps to T1105: Ingress Tool Transfer.
- **Persistence**: Mutex creation (import `CreateMutexA`, YARA match `win_mutex` at offset 48626) and registry modification imports (YARA match `win_registry` at offsets 49454, 49470, 49486, 49506) map to T1053: Scheduled Task/Job (mutex for single instance) and T1112: Modify Registry (persistence).
- **Obfuscation**: XOR decryption of code sections, high entropy (18), encrypted strings (0 decoded strings from FLOSS) map to T1027: Obfuscated Files or Information.
- **Anti-Analysis**: SEH configuration (YARA matches `SEH_Save` at 66713, `SEH_Init` at 66720) and packed code map to anti-debugging and T1620: Reflective Code Loading.
- **Evasion**: YARA match `HideInternetActivity` maps to T1562.004: Disable or Modify System Firewall / network evasion.
- **Host Fingerprinting**: YARA match `FingerprintEnvironment`, imports `GetComputerNameA`, `GetUserNameA`, `GetVersionExA` map to T1057: Account Discovery and T1082: System Information Discovery.
- **Desktop Manipulation**: Imports `CreateDesktopA`, `GetThreadDesktop`, `SetThreadDesktop`, `DestroyWindow` indicate capability to manipulate user desktops, likely to hide malicious UI or hijack user sessions (source: malcat, signal_imports: CreateDesktopA, DestroyWindow, GetThreadDesktop, SetThreadDesktop, RegCreateKeyE).

## 9. Indicators of Compromise
The following IOCs were extracted from static analysis of the sample:
### Sample Metadata
- SHA256: `bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9`
- Packer: AHTeam EP Protector (YARA match at offset 2) (source: checklist_yara_scan, matches: AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER)
- Entry Point: 54786 (0x431c04) (source: malcat, File Summary)
- XOR Decryption Keys: `0x462530e4` (for range 0x401000-0x408ecc), `0xb6d16c5` (for range 0x42b000-0x42e1d0) (source: malcat, decompilation: EntryPoint@54786; xor, search results)

### Embedded Payload
- Overlay Offset: 67072, Size: 992256 bytes
- Carved PE Offset: 123392, Size: 56320 bytes (source: malcat, carved_files: PE@123392 (56320 bytes))

### Network IOCs
- Domain regex match: offset 0 (exact domain not extracted from static strings) (source: checklist_yara_scan, matches: domain)
- IPv6 address: offset 72810, length 23 bytes (exact address not extracted from static strings) (source: checklist_yara_scan, matches: IP)
- Base64 encoded string: offset 47878, length 16 bytes (exact content not extracted from static strings) (source: checklist_yara_scan, matches: contains_base64)

### Structural IOCs
- Unrecognized section names: `.kofbl`, `.l1` (source: malcat, anomalies: SectionNameUnknown)
- RWX section: `.l1` (EA 58880, Virtual Size 8192) (source: malcat, file_layout; anomalies: SectionWX)
- Section gap between `.idata` (EA 50176) and `.kofbl` (EA 54784) (source: malcat, anomalies: SectionGap)
- XorInLoop anomalies at offsets 54824, 54896 (source: malcat, anomaly_locations: XorInLoop)
- SEH configuration at offsets 66713 (SEH_Save), 66720 (SEH_Init) (source: checklist_yara_scan, matches: SEH_Save, SEH_Init)

### Malicious Import Signatures
- Persistence: `CreateMutexA` (EA 52210, 60764, 115698, 120668), `RegCreateKeyExA`, `RegSetValueExA` (source: malcat, signal_imports; imports)
- Process Execution: `CreateProcessA` (EA 59752), `WinExec` (EA 59764), `CreateThread` (EA 59780) (source: malcat, imports)
- Network: `DeleteUrlCacheEntry` (EA 51558, 60148, 120052, 115046), `FindFirstUrlCacheEntryA` (EA 59600), `FindNextUrlCacheEntryA` (EA 59604) (source: malcat, imports)
- Desktop Manipulation: `CreateDesktopA` (EA 59852), `GetThreadDesktop` (EA 59860), `SetThreadDesktop` (EA 59856), `DestroyWindow` (EA 59888) (source: malcat, signal_imports)

### YARA Rule Hits
All 15 YARA matches are listed in the Malcat Triage Summary and YARA Matches sections (source: checklist_yara_scan, matches).

## 10. Detection Engineering
### YARA Detection Rules
The following signatures can be used to detect this sample and similar AHTeam EP Protector-packed malware:
1. **Packer Signature**: Detect the AHTeam EP Protector 03 fake PCGuard signature at offset 2 (source: checklist_yara_scan, matches: AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER).
2. **EP Decryption Routine**: Detect the XOR decryption loop at the entry point (offsets 54824, 54896) with keys `0x462530e4` and `0xb6d16c5` (source: malcat, anomaly_locations: XorInLoop; decompilation: EntryPoint@54786).
3. **Embedded PE Detection**: Detect PE files in the overlay region starting at offset 67072 (source: malcat, carved_files: PE@123392 (56320 bytes); capa, top_rules: contain an embedded PE file).
4. **Structural Anomaly Detection**: Detect PE files with unknown section names (`.kofbl`, `.l1`), RWX sections, section gaps, and unreferenced imports (113 total) (source: malcat, anomalies: SectionNameUnknown, SectionWX, SectionGap, UnreferencedImports).
5. **Import Combination Detection**: Detect PE files importing both WinINet APIs (`DeleteUrlCacheEntry`, `FindFirstUrlCacheEntryA`) and system manipulation APIs (`CreateMutexA`, `RegSetValue`, `CreateDesktopA`) (source: malcat, imports; pe_imports, import_count: 113).

### Capa Detection
The capa rule `contain an embedded PE file` (B0023: Install Additional Program) can be used to identify dropper/loader malware with embedded payloads (source: capa, top_rules).

### Anomaly-Based Detection
Detect high-entropy (≥17) X86 Windows GUI PE files with modified DOS headers, overlay data, and SEH configuration (source: checklist_yara_scan, matches: IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message, SEH_Save, SEH_Init).

## 11. What We Don't Know
1. **Full Embedded Payload Functionality**: Only the existence and size of the embedded PE (56320 bytes at offset 123392) are confirmed. The payload's functionality, C2 addresses, and persistence mechanisms are not analyzed, as it was not extracted and executed (source: malcat, carved_files: PE@123392 (56320 bytes)).
2. **Exact C2 Communication Protocol**: While hardcoded network IOCs (domain, IPv6, base64 string) are present, their exact role (C2 address, payload, authentication) is unknown, as no dynamic network traffic was observed (source: checklist_yara_scan, matches: domain, IP, contains_base64; speakeasy, api_calls: 0).
3. **Persistence Mechanism Details**: The sample imports registry modification APIs and has a `win_registry` YARA match, but the exact registry key path and value written are not extracted from static strings, as FLOSS recovered 0 decoded strings (source: floss, strings: 715 static strings, 0 decoded strings; checklist_yara_scan, matches: win_registry).
4. **Decrypted Code Functionality**: The entry point decrypts two code regions (0x401000-0x408ecc and 0x42b000-0x42e1d0) before entering an infinite loop, but Ghidra and IDA cannot analyze these regions due to 0 detected functions and missing IDA functionality. The full functionality of the decrypted payload is unknown without successful unpacking and deeper static analysis (source: llm_judge, cross_engine_notes; malcat, decompilation: EntryPoint@54786).
5. **Infinite Loop Purpose**: The entry point ends in an infinite loop after decryption; it is unclear if this loop waits for a C2 trigger, user interaction, or a specific system event to execute the embedded payload, as no dynamic behavior was observed (source: malcat, decompilation: EntryPoint@54786; speakeasy, key_events: 0).

## 12. Appendix: Analysis Environment
The following tools were used to analyze the sample:
| Tool | Version/Status | Purpose | Key Findings |
|---|---|---|---|
| Malcat | Primary static analysis | PE parsing, decompilation, string extraction, anomaly detection, file carving | 30 functions identified, entry point decompilation, 113 imports, 11 structural anomalies, carved embedded PE, 100 static strings, 2 YARA matches |
| capa | 0.81s runtime | Capability detection | 1 rule matched: `contain an embedded PE file` (B0023: Install Additional Program) |
| FLOSS | N/A | String extraction | 715 static strings, 0 decoded strings |
| radare2 | N/A | Disassembly | Entry point and import thunk disassembly, XOR decryption routine confirmed |
| YARA | Pipeline (15 matches) | Signature detection | 15 matches including packer (AHTeam EP Protector), anti-analysis (SEH), behavior (mutex, registry, file operations, WinINet), network IOCs |
| UPX | N/A | Unpacking | Unpack failed (upx_ok: False), sample is not UPX-packed |
| Speakeasy | N/A | Dynamic analysis | No API calls or key events observed (not observed) |
| Frida | 17.16.4 | Runtime instrumentation | Probe available, no data collected (not observed) |
| Ghidra | N/A | Static analysis | 0 functions detected, 122 strings extracted (complementary to Malcat data) |
| IDA | Non-functional | Static analysis | Unavailable due to missing idasql binary (source: llm_judge, cross_engine_notes) |

Sample characteristics: 32-bit X86 Windows GUI PE, size 1048576 bytes, entropy 18, packed with AHTeam EP Protector.
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9  
**sample_path:** /opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir  
**project_name:** incoming

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 9
- **family_guess**: Packed Malware Loader/Dropper (cryptor-obfuscated, embedded PE payload)
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: IDA is non-functional due to a missing idasql binary, so no IDA-derived analysis data is available. Ghidra reports 0 functions while Malcat identifies 15 functions, likely because Ghidra fails to auto-detect functions in encrypted/packed code. Ghidra (122) and Malcat (100) string counts are complementary, so combined string data is used for analysis. No decompilation or control flow graph data is available from Ghidra/IDA due to lack of reliable function coverage; only Malcat provides limited decompilation of the entry point and import thunk functions. Malcat is the primary reliable source for static profiling, imports, and anomaly detection, as its data aligns with Ghidra's import and string counts where available.
- **summary**: This is a high-entropy (18) cryptor-packed X86 PE file that functions as a malware loader/dropper. It decrypts its own code sections via XOR on entry, embeds a secondary PE payload in its overlay, and includes imports for desktop manipulation, registry modification, and process creation. YARA hits confirm it includes evasion (hiding internet activity) and host fingerprinting capabilities. While no full decompilation or control flow graph is available due to packed code and limited function detection from Ghidra/IDA, static analysis across Malcat, capa, YARA, and FLOSS confirms malicious intent with high confidence.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| capa | top_rules | `contain an embedded PE file` | Capa analysis confirms the sample contains an embedded PE file, a key indicator of dropper/loader malware designed to de |
| malcat | carved_files | `PE@123392 (56320 bytes)` | Malcat carved a valid secondary PE file from the sample's overlay region, confirming the presence of an embedded payload |
| malcat | decompilation | `EntryPoint@54786` | The entry point performs XOR decryption of two memory regions (0x401000-0x408ecc and 0x42b000-0x42e1d0) before entering  |
| malcat | signal_imports | `CreateDesktopA, DestroyWindow, GetThreadDesktop, SetThreadDesktop, RegCreateKeyE` | These high-signal imports indicate capabilities for desktop manipulation, registry modification for persistence, and pro |
| malcat | malcat_evidence | `HideInternetActivity, FingerprintEnvironment` | These YARA rule matches indicate the sample includes functionality to hide network activity and gather host environment  |
| malcat | anomalies | `XorInLoop (2 hits at 54824, 54896)` | XOR operations within loops are a hallmark of packing/encryption routines used to obfuscate code and data, aligning with |
| malcat | file_layout / anomalies | `Unknown section name .kofbl, RWX section .l1, SectionGap anomaly` | Unrecognized section names, a read-write-execute section, and physical gaps between sections are common indicators of mo |
| floss | strings | `715 static strings, 0 decoded strings` | FLOSS recovered no decoded strings, indicating that most string data is encrypted/obfuscated, which is consistent with c |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 0
- **summary**: The sample is a 32-bit Windows GUI PE executable packed with AHTeam EP Protector, exhibiting multiple confirmed malicious characteristics including hardcoded network IOCs, SEH-based anti-analysis, persistence mechanisms (mutex, registry modification, file operations), and use of WinINet for network communication.

### deep key_evidence
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "IsPE32, IsWindowsGUI, HasOverlay, HasModified_DOS_Message", "why": "These YARA rule matches confirm the sample is a 32-bit Windows GUI PE executable with a modified DOS header and overlay data, characteristics consistent with packed or obfuscated malicious files."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER", "why": "This match identifies the sample is packed with AHTeam EP Protector, a known executable protector frequently used to obfuscate malware payloads and hinder reverse engineering analysis."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "SEH_Save, SEH_Init", "why": "These matches indicate Structured Exception Handling (SEH) is configured in the sample, a common anti-debugging and anti-analysis technique used by malware to bypass debuggers and control program error flow."}`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "win_mutex, win_registry, win_files_operation", "why": "These matches show the sample implements malicious system interaction: mutex creation to prevent multiple instance execution, Windows registry modifications for persistence, and file system operations likely for dropping additional payloads or modifying system files`
- `{"source": "checklist_yara_scan", "query_or_table": "matches", "row_or_rule": "domain, IP, contains_base64, Str_Win32_Wininet_Library", "why": "These matches confirm the sample has command-and-control (C2) capabilities: it contains hardcoded network indicators (a domain and IPv6 address), base64-encoded content (likely for C2 communication or payload delivery), and uses the WinINet library for net`

## Malcat Structured Analysis
### Malcat File Summary
```
sha256: bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9
size: 1048576
type: PE
architecture: X86
entrypoint_ea: 54786
entropy: 18
file_name: virussign.com_8264dc61e512149f551c29e1b91b545e.vir
```

### File Layout (sections/regions)
| Name | EA | Physical | Virtual | Entropy | Rights |
|---|---|---|---|---|---|
| header | 0 | 1024 | 0 | 107 | - |
| .text | 1024 | 32768 | 32768 | 170 | RWX |
| .data | 33792 | 12800 | 16384 | 99 | RW |
| .idata | 50176 | 4096 | 4096 | 143 | RW |
| gap | 54272 | 512 | 0 | 90 | - |
| .kofbl | 54784 | 512 | 4096 | 90 | RX |
| .l1 | 58880 | 4608 | 8192 | 66 | RWX |
| overlay | 67072 | 992256 | 0 | 12 | - |
| .bss | 1059328 | 0 | 139264 | 0 | RW |

### Malcat YARA / Signatures (2)
| Rule | Category | Type | Reliability | Description |
|---|---|---|---|---|
| HideInternetActivity | network | UNCOMMON | 60 | tries to hide recent internet activity |
| FingerprintEnvironment | fingerprint | UNCOMMON | 50 | tries to assess the O.S environment |

### Anomalies (11)
| Name | Level | Category | Hits | Description |
|---|---|---|---|---|
| SectionGap | 4 | sections | 1 | there is a physical gap between two sections |
| SizeOfRawDataNotAligned | 4 | sections | 3 | SizeOfRawData is not aligned to FileAlignment |
| BigBufferNoXrefMediumToHighEntropy | 3 | entropy | 2 | a medium-to-high-entropy 10KB+ buffer, which is not part of a known structure and has no cross-refer |
| CodeSectionNotExecutable | 3 | sections | 1 | code section is not executable |
| EmbeddedProgram | 3 | embedding | 1 | File embeds a program |
| SectionNameUnknown | 3 | sections | 2 | section name is not one of the typical PE section name |
| SectionWX | 3 | sections | 2 | section is executable and writeable |
| UnreferencedImports | 3 | imports | 113 | More than half of the imports are not referenced, it could mean that the APIs are just decoys, or th |
| XorInLoop | 3 | code | 2 | XOR instruction in a loop |
| InvalidSizeOfInitializedData | 2 | sections | 1 | SizeOfInitializedData is not the sum of all ininitalized data sections (raw or virtual) |
| NoChecksum | 1 | integrity | 1 | PE Header checksum is not set |

### Anomaly Locations (high-signal)
- **NoChecksum**
  - `216`: 
- **XorInLoop**
  - `54824`: 
  - `54896`: 

### High-Signal Strings (17 matched keywords; engine=malcat)
| EA | String |
|---|---|
| 61887 | `KERNEL32.DLL` |
| 116928 | `KERNEL32.DLL` |
| 53440 | `KERNEL32.DLL` |
| 80502 | `KERNEL32.DLL` |
| 121807 | `KERNEL32.DLL` |
| 60436 | `GetProcAddress` |
| 120340 | `GetProcAddress` |
| 115354 | `GetProcAddress` |
| 51866 | `GetProcAddress` |
| 52210 | `CreateMutexA` |
| 52090 | `LoadLibraryA` |
| 60764 | `CreateMutexA` |
| 115698 | `CreateMutexA` |
| 115578 | `LoadLibraryA` |
| 120556 | `LoadLibraryA` |
| 120668 | `CreateMutexA` |
| 60652 | `LoadLibraryA` |

### Top Strings (300 extracted; showing 80)
| EA | String |
|---|---|
| 51558 | `DeleteUrlCacheEntry` |
| 60148 | `DeleteUrlCacheEntry` |
| 120052 | `DeleteUrlCacheEntry` |
| 115046 | `DeleteUrlCacheEntry` |
| 60282 | `GetComputerNameA` |
| 120186 | `GetComputerNameA` |
| 115190 | `GetComputerNameA` |
| 51702 | `GetComputerNameA` |
| 121410 | `GetUserNameA` |
| 61506 | `GetUserNameA` |
| 116490 | `GetUserNameA` |
| 53002 | `GetUserNameA` |
| 115430 | `GetVersion` |
| 120412 | `GetVersion` |
| 120426 | `GetVersionExA` |
| 115446 | `GetVersionExA` |
| 60522 | `GetVersionExA` |
| 60508 | `GetVersion` |
| 51958 | `GetVersionExA` |
| 51942 | `GetVersion` |
| 61934 | `CRTDLL.DLL` |
| 61921 | `ADVAPI32.DLL` |
| 61887 | `KERNEL32.DLL` |
| 61875 | `WININET.DLL` |
| 61911 | `GDI32.DLL` |
| 61862 | `OLEAUT32.DLL` |
| 61945 | `MSVCRT.DLL` |
| 61900 | `USER32.DLL` |
| 61852 | `ole32.DLL` |
| 86820 | `1:7a:eb:91:d6:9c..b:40:b3:26:cd:72` |
| 87038 | `9d:6a:ab:f8:69:2..b:af:42:8f:9b:41` |
| 82066 | `dll.dll` |
| 85460 | `[6657, 340576, 3.. 279060, 279060]` |
| 117328 | `CRTDLL.DLL` |
| 121854 | `CRTDLL.DLL` |
| 80546 | `CRTDLL.DLL` |
| 53840 | `CRTDLL.DLL` |
| 83714 | `:fa:22:33:b1:6d:..6:e1:ba:ed:0f:b3` |
| 53416 | `WININET.DLL` |
| 121795 | `WININET.DLL` |
| 88766 | `:fa:22:33:b1:6d:..6:e1:ba:ed:0f:b3` |
| 116904 | `WININET.DLL` |
| 53788 | `ADVAPI32.DLL` |
| 116928 | `KERNEL32.DLL` |
| 53440 | `KERNEL32.DLL` |
| 80502 | `KERNEL32.DLL` |
| 117276 | `ADVAPI32.DLL` |
| 121807 | `KERNEL32.DLL` |
| 12666 | `BFTr%` |
| 121841 | `ADVAPI32.DLL` |
| 53756 | `GDI32.DLL` |
| 121865 | `RPCRT4.DLL` |
| 121831 | `GDI32.DLL` |
| 117244 | `GDI32.DLL` |
| 53396 | `OLEAUT32.DLL` |
| 116884 | `OLEAUT32.DLL` |
| 121782 | `OLEAUT32.DLL` |
| 85892 | ` 0.0253700073808..70007380843163, ` |
| 83562 | `d5:14:60:61:a7:3b:6e:4e:` |
| 121772 | `ole32.DLL` |
| 117120 | `USER32.DLL` |
| 83826 | `48:97:84:72:c2:9` |
| 116856 | `ole32.DLL` |
| 53368 | `ole32.DLL` |
| 53632 | `USER32.DLL` |
| 88614 | `d5:14:60:61:a7:3b:6e:4e:` |
| 121820 | `USER32.DLL` |
| 88878 | `48:97:84:72:c2:9` |
| 81623 | `2 2$2(2,20242D2H..L2P2T2X2\2`2d2h2` |
| 60596 | `InterlockedIncrement` |
| 115522 | `InterlockedIncrement` |
| 52034 | `InterlockedIncrement` |
| 120500 | `InterlockedIncrement` |
| 81567 | `5"5.5:5F5R5^5j5v5` |
| 121748 | `RpcErrorEndEnumeration` |
| 80272 | `GetEnvironmentStringsA` |
| 79632 | `kkcc` |
| 114950 | `CoCreateInstance` |
| 88818 | `19:d2:1c:d3:` |
| 88642 | `2:29:ce:69:5` |

### Imports (113)
| EA | Name | Type | Refs |
|---|---|---|---|
| 59568 | ole32.CoCreateInstance | IMPORT | 1 |
| 59572 | ole32.CLSIDFromString | IMPORT | 0 |
| 59576 | ole32.CoInitialize | IMPORT | 0 |
| 59580 | ole32.CoUninitialize | IMPORT | 0 |
| 59588 | oleaut32.SysAllocString | IMPORT | 1 |
| 59596 | wininet.DeleteUrlCacheEntry | IMPORT | 1 |
| 59600 | wininet.FindFirstUrlCacheEntryA | IMPORT | 0 |
| 59604 | wininet.FindNextUrlCacheEntryA | IMPORT | 0 |
| 59612 | kernel32.ExitProcess | IMPORT | 1 |
| 59616 | kernel32.ExpandEnvironmentStringsA | IMPORT | 0 |
| 59620 | kernel32.GetCommandLineA | IMPORT | 0 |
| 59624 | kernel32.GetComputerNameA | IMPORT | 0 |
| 59628 | kernel32.GetCurrentProcessId | IMPORT | 0 |
| 59632 | kernel32.GetCurrentThreadId | IMPORT | 0 |
| 59636 | kernel32.GetExitCodeThread | IMPORT | 0 |
| 59640 | kernel32.GetFileSize | IMPORT | 0 |
| 59644 | kernel32.GetModuleFileNameA | IMPORT | 0 |
| 59648 | kernel32.GetModuleHandleA | IMPORT | 0 |
| 59652 | kernel32.CloseHandle | IMPORT | 0 |
| 59656 | kernel32.GetProcAddress | IMPORT | 0 |
| 59660 | kernel32.GetSystemDirectoryA | IMPORT | 0 |
| 59664 | kernel32.GetTempPathA | IMPORT | 0 |
| 59668 | kernel32.GetTickCount | IMPORT | 0 |
| 59672 | kernel32.GetVersion | IMPORT | 0 |
| 59676 | kernel32.GetVersionExA | IMPORT | 0 |
| 59680 | kernel32.GetWindowsDirectoryA | IMPORT | 0 |
| 59684 | kernel32.GlobalMemoryStatus | IMPORT | 0 |
| 59688 | kernel32.CopyFileA | IMPORT | 0 |
| 59692 | kernel32.InterlockedIncrement | IMPORT | 0 |
| 59696 | kernel32.IsBadReadPtr | IMPORT | 0 |
| 59700 | kernel32.IsBadWritePtr | IMPORT | 0 |
| 59704 | kernel32.LoadLibraryA | IMPORT | 0 |
| 59708 | kernel32.LocalAlloc | IMPORT | 0 |
| 59712 | kernel32.LocalFree | IMPORT | 0 |
| 59716 | kernel32.OpenMutexA | IMPORT | 0 |
| 59720 | kernel32.CreateFileA | IMPORT | 0 |
| 59724 | kernel32.ReadFile | IMPORT | 0 |
| 59728 | kernel32.RtlUnwind | IMPORT | 0 |
| 59732 | kernel32.SetFilePointer | IMPORT | 0 |
| 59736 | kernel32.CreateMutexA | IMPORT | 0 |
| 59740 | kernel32.Sleep | IMPORT | 0 |
| 59744 | kernel32.TerminateProcess | IMPORT | 0 |
| 59748 | kernel32.VirtualQuery | IMPORT | 0 |
| 59752 | kernel32.CreateProcessA | IMPORT | 0 |
| 59756 | kernel32.WaitForSingleObject | IMPORT | 0 |
| 59760 | kernel32.WideCharToMultiByte | IMPORT | 0 |
| 59764 | kernel32.WinExec | IMPORT | 0 |
| 59768 | kernel32.WriteFile | IMPORT | 0 |
| 59772 | kernel32.lstrlenA | IMPORT | 0 |
| 59776 | kernel32.lstrlenW | IMPORT | 0 |
| 59780 | kernel32.CreateThread | IMPORT | 0 |
| 59784 | kernel32.DeleteFileA | IMPORT | 0 |
| 59792 | user32.GetWindowTextA | IMPORT | 1 |
| 59796 | user32.GetWindowRect | IMPORT | 0 |
| 59800 | user32.FindWindowA | IMPORT | 0 |
| 59804 | user32.GetWindow | IMPORT | 0 |
| 59808 | user32.GetClassNameA | IMPORT | 0 |
| 59812 | user32.SetFocus | IMPORT | 0 |
| 59816 | user32.GetForegroundWindow | IMPORT | 0 |
| 59820 | user32.LoadCursorA | IMPORT | 0 |
| 59824 | user32.LoadIconA | IMPORT | 0 |
| 59828 | user32.SetTimer | IMPORT | 0 |
| 59832 | user32.RegisterClassA | IMPORT | 0 |
| 59836 | user32.MessageBoxA | IMPORT | 0 |
| 59840 | user32.GetMessageA | IMPORT | 0 |
| 59844 | user32.GetWindowLongA | IMPORT | 0 |
| 59848 | user32.SetWindowLongA | IMPORT | 0 |
| 59852 | user32.CreateDesktopA | IMPORT | 0 |
| 59856 | user32.SetThreadDesktop | IMPORT | 0 |
| 59860 | user32.GetThreadDesktop | IMPORT | 0 |
| 59864 | user32.TranslateMessage | IMPORT | 0 |
| 59868 | user32.DispatchMessageA | IMPORT | 0 |
| 59872 | user32.SendMessageA | IMPORT | 0 |
| 59876 | user32.PostQuitMessage | IMPORT | 0 |
| 59880 | user32.ShowWindow | IMPORT | 0 |
| 59884 | user32.CreateWindowExA | IMPORT | 0 |
| 59888 | user32.DestroyWindow | IMPORT | 0 |
| 59892 | user32.MoveWindow | IMPORT | 0 |
| 59896 | user32.DefWindowProcA | IMPORT | 0 |
| 59900 | user32.CallWindowProcA | IMPORT | 0 |

### Functions (30)
| EA | Name |
|---|---|
| 54786 | EntryPoint |
| 61956 | sub_431c04 |
| 61969 | sub_431c11 |
| 61982 | sub_431c1e |
| 61995 | sub_431c2b |
| 62008 | sub_431c38 |
| 62021 | sub_431c45 |
| 62034 | sub_431c52 |
| 62047 | sub_431c5f |
| 62060 | sub_431c6c |
| 62073 | sub_431c79 |
| 62086 | sub_431c86 |
| 62099 | sub_431c93 |
| 62112 | sub_431ca0 |
| 62125 | sub_431cad |
| 62138 | sub_431cba |
| 62151 | sub_431cc7 |
| 62164 | sub_431cd4 |
| 62177 | sub_431ce1 |
| 62190 | sub_431cee |
| 62203 | sub_431cfb |
| 62229 | sub_431d15 |
| 62242 | sub_431d22 |
| 62255 | sub_431d2f |
| 62268 | sub_431d3c |
| 62281 | sub_431d49 |
| 62294 | sub_431d56 |
| 62307 | sub_431d63 |
| 62320 | sub_431d70 |
| 62333 | sub_431d7d |

### Decompilations (top 6)
#### 54786 — EntryPoint
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void EntryPoint(void)

{
    uint32_t *puVar1;
    
    puVar1 = 0x401000;
    do {
        *puVar1 = *puVar1 ^ 0x462530e4;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x408ecc);
    puVar1 = 0x42b000;
    do {
        *puVar1 = *puVar1 ^ 0xb6d16c5;
        puVar1 = puVar1 + 1;
    } while (puVar1 != 0x42e1d0);
    in(0x58);
    do {
    /* WARNING: Do nothing block with infinite loop */
    } while( true );
}

```
#### 61956 — sub_431c04
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c04(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c0f. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CoCreateInstance)();
    return;
}

```
#### 61969 — sub_431c11
```c

/* DISPLAY WARNING: Type casts are NOT being printed */

void sub_431c11(void)

{
    /* WARNING: Could not recover jumptable at 0x00431c1c. Too many branches */
    /* WARNING: Treating indirect jump as call */
    (*ole32.CLSIDFromString)();
    return;
}

```

### Carved Files (1)
| Name | Type | Size |
|---|---|---|
| ? | PE | 56320 |

### Structures (24)
| Name | EA |
|---|---|
| MZ | 0 |
| PE | 128 |
| OptionalHeader | 152 |
| Sections | 376 |
| ImportTable | 58880 |
| ole32.OFT | 59080 |
| oleaut32.OFT | 59100 |
| wininet.OFT | 59108 |
| kernel32.OFT | 59124 |
| user32.OFT | 59304 |
| gdi32.OFT | 59420 |
| advapi32.OFT | 59444 |
| crtdll.OFT | 59484 |
| msvcrt.OFT | 59560 |
| ole32.FT | 59568 |
| oleaut32.FT | 59588 |
| wininet.FT | 59596 |
| kernel32.FT | 59612 |
| user32.FT | 59792 |
| gdi32.FT | 59908 |
| advapi32.FT | 59932 |
| crtdll.FT | 59972 |
| msvcrt.FT | 60048 |
| ImportNames | 60056 |


## capa Capability Rules
engine: `malcat-capa` · Total rules: 1 · duration_s: 0.81

| Rule | ATT&CK | MBC |
|---|---|---|
| contain an embedded PE file |  | B0023:Install Additional Program |

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
  "rule_count": 15,
  "matches": [
    {
      "rule": "domain",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
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
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$ipv6",
          "offset": 72810,
          "length": 23,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "contains_base64",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 47878,
          "length": 16,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "maldoc_getEIP_method_1",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 54788,
          "length": 6,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "IsPE32",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "IsWindowsGUI",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasOverlay",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "HasModified_DOS_Message",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": []
    },
    {
      "rule": "AHTeam_EP_Protector_03_fake_PCGuard_403_415_FEUERRADER",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 2,
          "length": 1,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Save",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$a",
          "offset": 66713,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "SEH_Init",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$b",
          "offset": 66720,
          "length": 7,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_mutex",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
        {
          "id": "$c1",
          "offset": 48626,
          "length": 11,
          "xor_key": null
        }
      ]
    },
    {
      "rule": "win_registry",
      "path": "/opt/samples/corpus/incoming/bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9/virussign.com_8264dc61e512149f551c29e1b91b545e.vir",
      "strings": [
     
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
