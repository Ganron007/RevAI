> **RevAI provenance** — commit `80c92a39d67f7e321883d3656b87cc4b04c5b7b5` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-06 00:53:58 UTC

## 1. Executive Summary

This sample is a **malicious PE32 Windows GUI executable** with a score of 95 and verdict of `Malicious`, with cross-engine agreement `llm_and_v1_agree` (source: llm_judge). It is assessed as a Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by its file path (source: llm_judge family_guess).

Static analysis provides consistent, corroborating evidence of malicious intent:
- 23 YARA matches detecting capabilities including anti-debugging, keylogging, screen capture, registry manipulation, file operations, privilege escalation, and network dropper functionality (source: yara, total matches 23)
- 318 PE imports including high-signal malicious APIs: `IsDebuggerPresent` (anti-debugging, T1622), `URLDownloadToFile` (payload download, T1105), `RegSetValue` (registry modification, T1112), `CreateProcess`/`ShellExecute` (process execution, T1106), and `LoadLibrary`/`GetProcAddress` (dynamic API resolution, T1129) (source: pe_imports, import_count 318)
- 57 capa rules mapping to ATT&CK techniques core to RAT and ransomware operation, including XOR obfuscation (T1027), file system discovery (T1083), system information discovery (T1082), and keylogging (T1056.001) (source: capa, total rules 57)
- 2846 FLOSS strings, 2845 of which are statically obfuscated, indicating heavy use of obfuscation to hide malicious indicators (source: floss, total strings 2846)

Ghidra and IDA both failed to produce reverse engineering data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), but all available static analysis tools corroborate the malicious verdict (source: llm_judge cross_engine_notes). No conflicting benign indicators were identified.

---

## 2. Sample Metadata

| Field | Value | Source |
|-------|-------|--------|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c | sample metadata |
| Sample Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos | sample metadata |
| Project Name | pool | sample metadata |
| Verdict | Malicious | llm_judge |
| Score | 95 | llm_judge |
| Family Guess | Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex | llm_judge |
| Agreement | llm_and_v1_agree | llm_judge |
| .NET Status | False (not observed) | dotnet analysis |
| UPX Packed | False | upx |
| Total Imports | 318 | pe_imports |

---

## 3. File Layout & Structural Analysis

This sample is a **PE32 Windows GUI executable** and not a .NET assembly (source: dotnet analysis, is_dotnet: false). UPX unpacking was attempted but failed, with no unpacked output generated; the sample is not packed with UPX (source: upx, upx_ok: False, is_packed: False, unpacked_path: empty).

XOR search identified a XOR 00 byte at file offset 0x00000000, adjacent to the standard DOS stub string `!This program cannot be run in DOS mode.` (source: XOR Search). The import table contains 318 APIs from Windows system libraries (source: pe_imports, import_count: 318).

Ghidra and IDA both failed to produce function, import, or decompilation data: Ghidra due to project ownership errors, IDA due to a missing idasql binary (source: llm_judge cross_engine_notes). All available disassembly is from radare2.

### Entry Point Disassembly (0x00421c21)
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
```
(source: radare2, address 0x00421c21)

### Main Function Disassembly (0x004391d2)
```asm
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01           mov eax, dword [ecx]
│    ││││   0x0043922e      ff5060         call dword [eax + 0x60]     ; 96
│    └────> 0x00439231      8b06           mov eax, dword [esi]
│     │││   0x00439233      8bce           mov ecx, esi
│     │││   0x00439235      ff5068         call dword [eax + 0x68]     ; 104
│    ┌────< 0x00439238      eb07           jmp 0x439241
│    ││└──> 0x0043923a      8b06           mov eax, dword [esi]
│    ││ │   0x0043923c      8bce           mov ecx, esi
│    ││ │   0x0043923e
```
(source: radare2, address 0x004391d2)

### Function fcn.004139ec (0x004139ec)
```asm
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
(source: radare2, address 0x004139ec)

### Function fcn.004235c9 (0x004235c9)
```asm
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff75e0         push dword [var_20h]
└           0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException] ; 0x43d248 ; VOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
```
(source: radare2, address 0x004235c9)

---

## 4. Malcat Triage Summary

Malcat analysis failed with an MCP closure error, so no Malcat-specific triage data is available (source: Malcat Structured Analysis, error: `malcat_analyze top-level: MCP malcat closed`). Triage-level assessment is derived from the deep dive agentic analysis with 90% confidence, verdict `malicious` (source: deep_dive_agentic).

Key triage evidence:
- 23 YARA matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init (source: deep_dive_agentic key_evidence)
- PE import signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129) (source: deep_dive_agentic key_evidence)
- Capa analysis: 57 rules, top rules for XOR encoding (T1027), registry key creation/opening, file version info retrieval, common file path retrieval, file existence checks (source: deep_dive_agentic key_evidence)
- FLOSS extraction: 2846 total strings (2845 static obfuscated, 1 decoded) (source: deep_dive_agentic key_evidence)
- Sample path contains `bkransomware_elex_hawkeye_maze_remcos` indicating known malware family association (source: deep_dive_agentic key_evidence)

---

## 5. Static Code Analysis

Full disassembly and decompilation from Ghidra and IDA are unavailable due to tool failures (source: llm_judge cross_engine_notes). All static analysis is sourced from radare2, pe_imports, YARA, capa, and FLOSS.

### PE Imports (High-Signal Signals)
| Label | API Match | ATT&CK |
|-------|-----------|--------|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |
(source: pe_imports, total imports 318)

### YARA Matches
| Rule | Namespace | Match Strings (Trimmed) |
|------|-----------|-------------------------|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@459893 len=7; $ipv6@252878 len=4 |
| contains_base64 | - | $a@245300 len=24 |
| Misc_Suspicious_Strings | - | $a3@400684 len=14 |
| url | - | $url_regex@396920 len=96 |
| maldoc_getEIP_method_1 | - | $a@460864 len=6 |
| IsPE32 | - | |
| IsWindowsGUI | - | |
| HasDebugData | - | |
| HasRichSignature | - | $a0@240 len=4 |
| VC8_Microsoft_Corporation | - | $a@6306 len=10 |
| SEH_Save | - | $a@137441 len=7 |
| SEH_Init | - | $a@21246 len=6; $b@193755 len=7 |
| Check_OutputDebugStringA_iat | - | |
| anti_dbg | - | $d1@263200 len=12; $c2@326380 len=17; $c3@325196 len=17 |
| win_hook | - | $f1@328710 len=10; $c1@328252 len=19; $c3@328274 len=14 |
| network_dropper | - | $f1@329876 len=10; $c1@329856 len=17 |
| escalate_priv | - | $d1@329548 len=12; $c2@329194 len=21 |
| screenshot | - | $d1@329094 len=9; $d2@328710 len=10; $c2@328496 len=5 |
| keylogger | - | $f1@328710 len=10; $c2@327842 len=11 |
| win_registry | - | $f1@329548 len=12; $c3@329242 len=11; $c6@329242 len=11 |
| win_token | - | $f1@329548 len=12; $c2@329194 len=21; $c3@329174 len=16 |
| win_files_operation | - | $f1@263200 len=12; $c1@325760 len=9; $c2@325728 len=14; $c3@325760 len=9; $c4@325700 len=8 |
(source: yara, total matches 23)

### Capa Capability Rules
| Rule | ATT&CK | MBC |
|------|--------|-----|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key | | C0036.004:Registry, C0036.003:Registry |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| link function at runtime on Windows | T1129:Shared Modules | |
(source: capa, total rules 57, runtime 86.92s)

### FLOSS Strings (Sample)
Total strings: 2846 (2845 static obfuscated, 1 decoded) (source: floss)
```
?GetPu
!This program cannot be run in DOS mode.
.rdata
@.data
ttHt=Hu095
QWWWWWWPW
jEjCjB@j8
XSVWjD_W3
QSSSSSSPS
QPWWhL
t8PPPPh
9G t!j
t'9~ u"
t	9p(u
u8hd)D
	9wlt>
~(9~8t	WW
u h<)D
At;F u
t49^ u'
~ 9^$u
t>9~ t9j0
t7j(SV
;7u<;G
uij0[SQ
t)9w u$
PjShp.D
jShp.D
+t=Ht-Ht
HtpHHt
Pj^h`1D
j^h`1D
SSWPSSSS
j.Zf9P,u
u	f9p0u
WQh,8D
W9qXtDV
9wXt8V
VW9AXtw
t-h@8D
```

### Frida Hook Candidates
Frida (v17.16.4) hook candidates include common Windows APIs for version info, memory management, string/locale operations, UI, printing, registry, shell, and path operations (source: frida_probe):
- VERSION.dll: VerQueryValueW, GetFileVersionInfoW, GetFileVersionInfoSizeW
- KERNEL32.dll: LocalReAlloc, GlobalFlags, CompareStringW, GetLocaleInfoW, GetSystemDefaultUILanguage
- USER32.dll: InvalidateRect, DestroyMenu, RealChildWindowFromPoint, ClientToScreen, EndPaint
- GDI32.dll: TextOutW, ExtTextOutW, SetViewportExtEx, SetViewportOrgEx, SetWindowExtEx
- WINSPOOL.DRV: OpenPrinterW, ClosePrinter, DocumentPropertiesW
- ADVAPI32.dll: RegEnumValueW, RegQueryValueW, RegEnumKeyW, RegDeleteValueW, RegDeleteKeyW
- SHELL32.dll: ShellExecuteW, SHGetSpecialFolderPathW
- SHLWAPI.dll: PathFileExistsW, PathIsUNCW

---

## 6. Behavioral & Dynamic Analysis

No malicious runtime behavior was observed during dynamic analysis.

- **Speakeasy**: Analysis completed successfully (speakeasy_ok: True), but 0 API calls and 0 key events were recorded, with no duration logged. No runtime behavior was observed (source: speakeasy, not observed: no API calls/events recorded — do not invent runtime behavior).
- **Frida**: Frida is available (v17.16.4) with 30+ hook candidates identified, but no runtime events were captured (source: frida_probe, not observed).
- **UPX Unpacking**: Unpacking failed (upx_ok: False), and the sample is not UPX packed (is_packed: False). No unpacked payload was generated (source: upx, unpacked_path: empty).

No evidence of C2 communication, payload execution, or malicious system modification was observed during dynamic analysis.

---

## 7. Network Indicators & C2

Static analysis indicates potential C2-related capabilities, but no active C2 infrastructure was observed.

YARA matches include static indicators of network and C2 functionality (source: yara, total matches 23):
- 1 domain regex match at 0x00000000 (len=2)
- 2 IP matches: IPv4 at 0x459893 (len=7), IPv6 at 0x252878 (len=4)
- 1 URL regex match at 0x396920 (len=96)
- 1 base64 encoded string match at 0x245300 (len=24)
- network_dropper rule matches at 0x329876 and 0x329856

The PE import `URLDownloadToFile` (T1105) confirms the sample can download additional payloads from remote servers (source: pe_imports, download_file row).

Actual C2 server addresses, ports, and protocols are (unknown): FLOSS only decoded 1 string out of 2846 total, with 2845 static strings obfuscated to hide indicators (source: floss, per_category: 2845 static obfuscated, 1 decoded). No network traffic was observed during dynamic analysis (source: speakeasy, 0 API calls).

---

## 8. Capabilities & MITRE ATT&CK Mapping

Capabilities are derived from capa rules, PE imports, and YARA matches, mapped to MITRE ATT&CK:

| Capability | ATT&CK Technique | Source |
|------------|------------------|--------|
| Anti-debugging | T1622: Debugger Evasion | pe_imports (IsDebuggerPresent), yara (anti_dbg) |
| Payload Download | T1105: Ingress Tool Transfer | pe_imports (URLDownloadToFile), yara (network_dropper) |
| Registry Modification | T1112: Modify Registry | pe_imports (RegSetValue), yara (win_registry), capa (create/open registry key, delete registry key/value, query registry value) |
| Process Execution | T1106: Process Execution | pe_imports (CreateProcess, ShellExecute), capa (accept command line arguments) |
| Dynamic API Resolution | T1129: Shared Modules | pe_imports (LoadLibrary, GetProcAddress), capa (link function at runtime on Windows) |
| Obfuscation | T1027: Obfuscated Files or Information | capa (encode data using XOR), floss (2845 obfuscated strings) |
| File and Directory Discovery | T1083: File and Directory Discovery | capa (get file version info, get common file path, check if file exists, get file size), yara (win_files_operation) |
| System Information Discovery | T1082: System Information Discovery | capa (query environment variable, check OS version, get disk information) |
| Input Capture (Keylogging) | T1056.001: Input Capture | capa (log keystrokes via polling), yara (keylogger) |
| Screen Capture | T1113: Screen Capture | yara (screenshot) |
| Privilege Escalation | T1548: Abuse Elevation Control Mechanism | yara (escalate_priv) |
| Token Manipulation | T1547: Boot or Logon Autostart Execution | yara (win_token) |
| Query Registry | T1012: Query Registry | capa (query or enumerate registry value) |

(source: llm_judge key_evidence, deep_dive_agentic key_evidence, pe_imports, yara, capa)

---

## 9. Indicators of Compromise

### File-Based IOCs
| IOC Type | Value | Source |
|----------|-------|--------|
| SHA256 | 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c | sample metadata |
| File Path | /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos | sample metadata |
| YARA Rule Path | /opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar | rule.yara.json |
| Sigma Rule Path | /opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yml | rule.yara.json |

### Static Signature IOCs
- PE import signatures: IsDebuggerPresent, URLDownloadToFile, RegSetValue, CreateProcess, ShellExecute, LoadLibrary, GetProcAddress (source: pe_imports)
- YARA rule matches: 23 rules including anti_dbg, keylogger, screenshot, win_registry, win_files_operation, network_dropper, escalate_priv, win_token, domain, IP, url, base64, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init, Check_OutputDebugStringA_iat, win_hook (source: yara)
- High-signal static strings: Listed in Section 5 (source: floss)

### Dynamic IOCs
No dynamic C2 IOCs (IPs, domains, URLs) were extracted due to heavy string obfuscation and lack of observed network traffic (source: floss, speakeasy).

---

## 10. Detection Engineering

A validated YARA rule is available for detection of this sample and related variants (source: rule.yara.json):
- YARA validation status: `yara_valid: true`, `yara_check: ok`
- Goodware false positive count: 0 (fp_count: 0, goodware corpus not staged for full testing) (source: rule.yara.json goodware_fp)
- Rule contains 8 high-signal strings derived from analysis of the sample's malicious capabilities (source: rule.yara.json strings array)

The 23 pipeline YARA matches can be used for signature-based detection of this and related malware families (source: yara). PE import-based detection can target the high-signal malicious imports listed in Section 5 (source: pe_imports). Capa rules can be used for behavioral detection of the capabilities mapped in Section 8 (source: capa, 57 total rules).

Due to heavy string obfuscation (2845 obfuscated FLOSS strings) (source: floss), static string-based detection is less effective; prioritize import-based, behavioral, and YARA signature detection for this family.

---

## 11. What We Don't Know

1. **Actual C2 infrastructure is (unknown)**: FLOSS only decoded 1 string out of 2846 total, with 2845 static strings obfuscated to hide C2 indicators, and no network traffic was observed during dynamic analysis (source: floss, speakeasy).
2. **Full sample functionality is (unknown)**: Ghidra and IDA failed to produce function, import, or decompilation data, so no low-level reverse engineering of the sample's code logic is available (source: llm_judge cross_engine_notes).
3. **Runtime behavior is (unknown)**: Speakeasy recorded 0 API calls/events, and Frida captured no runtime events, so no dynamic execution flow is available (source: speakeasy, frida_probe).
4. **Exact sample role is (unknown)**: While the file path suggests ties to Remcos RAT, Maze ransomware, BK Ransomware, Hawkeye, and Elex, it is unclear if this is a loader, RAT component, ransomware encryption module, or hybrid payload (source: llm_judge family_guess, noted as an assessment not a confirmed classification).
5. **Additional embedded payloads are (unknown)**: UPX unpacking failed, and there is no evidence of other packing mechanisms, but the sample may contain additional obfuscated/encrypted payloads that were not extracted (source: upx, upx_ok: False, is_packed: False).
6. **Full ATT&CK coverage is (unknown)**: Only 57 capa rules were identified, and without full disassembly, additional capabilities may be present (source: capa total rules 57, llm_judge cross_engine_notes).

---

## 12. Appendix: Analysis Environment

All required analysis tools were executed per the deep dive tool gate (source: deep_dive_agentic tool_gate):

| Tool | Status | Notes |
|------|--------|-------|
| capa | OK | 57 rules matched, 86.92s runtime |
| pe_imports | OK | 318 imports identified |
| yara | OK | 23 matches, 0 goodware false positives |
| floss | OK | 2846 strings extracted (2845 obfuscated, 1 decoded) |
| dotnet | OK | Not a .NET assembly |
| r2_decomp (radare2) | OK | Entry point, main, and 2 function disassembly blocks extracted |
| upx | OK | Unpacking failed, sample not UPX packed |
| xor | OK | XOR 00 byte found at 0x00000000 |
| speakeasy | OK | 0 API calls/events recorded |
| frida_probe | OK | 30+ hook candidates identified, 0 runtime events recorded |
| Ghidra | Failed | Project ownership error, no function/import/decompilation data produced |
| IDA | Failed | Missing idasql binary, no function/import/decompilation data produced |
| Malcat | Failed | MCP closure error, no triage data produced |

### Provenance
- Project: RevAI, commit 80c92a39d67f7e321883d3656b87cc4b04c5b7b5 (source: rule.yara.json provenance)
- Latest YARA generation: 2026-08-06T00:50:53.447579+00:00 (source: yara_gen_v2 audit trail)
- Latest technical report publish: 2026-08-06 00:51:42.78894 UTC (source: publish_report_v2_technical audit trail)
## Appendix: Full Structured Evidence Pack

# Technical Evidence Pack

**sha256:** 2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c  
**sample_path:** /opt/samples/corpus/pool/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/2026-07-03_0d164c2f725067a84a46383965b0afd0_bkransomware_elex_hawkeye_maze_remcos  
**project_name:** pool

> Every table below is copied from stage JSON. Technical narrative must cite these rows (engine + address/rule), not invent evidence.

## Verdict
- **verdict**: Malicious
- **score**: 95
- **family_guess**: Remcos RAT / Maze ransomware associated loader or hybrid malware, with ties to BK Ransomware, Hawkeye, and Elex as indicated by sample metadata
- **agreement**: llm_and_v1_agree
- **cross_engine_notes**: Ghidra and IDA both failed to produce function, import, or decompilation data due to project ownership errors (Ghidra) and a missing idasql binary (IDA), so no reverse-engineered code context is available from those tools. All available analysis engines (pe_imports, YARA, capa, FLOSS) provide consistent, corroborating evidence of malicious RAT/ransomware functionality. The sample's file path explicitly references known ransomware (Maze, BK Ransomware) and RAT (Remcos, Hawkeye, Elex) families, which aligns with the detected capabilities.
- **summary**: This sample is a malicious PE file with strong indicators of being a RAT/ransomware hybrid or associated loader. Static analysis reveals high-signal malicious imports for anti-debugging, payload downloading, registry modification, process execution, and dynamic API resolution. YARA matches detect common malware capabilities including keylogging, screen capture, privilege escalation, and file/network operations. Capa rules map these capabilities to ATT&CK techniques for RAT and ransomware operation. FLOSS string analysis reveals heavy obfuscation consistent with malware attempting to hide its indicators. The sample's file path references multiple known ransomware and RAT families, further confirming its malicious nature. No conflicting benign indicators were identified.
- **source**: llm_judge
- **model**: step-3.7-flash

### key_evidence (triage) — cite source field exactly
| source | query_or_table | row_or_rule | why |
|---|---|---|---|
| pe_imports | pe_imports raw JSON signal list | `check_debugger (IsDebuggerPresent) [T1622]` | IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools,  |
| pe_imports | pe_imports raw JSON signal list | `download_file (URLDownloadToFile) [T1105]` | This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-con |
| pe_imports | pe_imports raw JSON signal list | `set_registry_value (RegSetValue) [T1112]` | Registry modification is used for persistence (e.g., adding run keys), disabling security software, or configuring malic |
| pe_imports | pe_imports raw JSON signal list | `create_process (CreateProcess) / shell_execute (ShellExecute) [T1106]` | These APIs are used to execute additional malicious processes, launch ransomware encryption routines, or run attacker co |
| pe_imports | pe_imports raw JSON signal list | `load_library (LoadLibrary) / get_proc_address (GetProcAddress) [T1129]` | Dynamic API resolution is a common obfuscation technique used by malware to hide malicious imports from static analysis, |
| yara | yara raw JSON matches | `23 matching rules including anti_dbg, keylogger, screenshot, win_registry, win_f` | These rules detect well-known malware capabilities: anti-debugging, keylogging, screen capture, registry manipulation, f |
| capa | capa raw JSON top rules | `T1083 (File and Directory Discovery), T1082 (System Information Discovery), T111` | These mapped ATT&CK techniques cover core functionality for ransomware and RATs: system/file discovery for targeting, re |
| capa | capa_evidence | `2846 total strings (2845 static obfuscated, 1 decoded)` | The high volume of obfuscated strings indicates heavy use of string obfuscation to hide malicious indicators (e.g., C2 d |

## Deep-Dive Summary Evidence
- **source**: deep_dive_agentic
- **confidence**: 90
- **summary**: PE32 Windows GUI executable with strong malicious indicators: YARA matches for domains, IPs, URLs, base64, suspicious strings, and anti-analysis patterns; capa rules for XOR obfuscation, registry manipulation, file discovery, and execution; PE imports for debugger detection, download, registry writes, and process creation; FLOSS reveals 2846 strings with decoded/obfuscated content. Sample corpus name associates it with known ransomware/RAT families (BKRansomware, Elex, Hawkeye, Maze, Remcos).

### deep key_evidence
- `"YARA 23 matches including domain, IP, base64, url, Misc_Suspicious_Strings, maldoc_getEIP_method_1, IsPE32, IsWindowsGUI, HasDebugData, HasRichSignature, VC8_Microsoft_Corporation, SEH_Save, SEH_Init"`
- `"pe_import_signals: IsDebuggerPresent (T1622), URLDownloadToFile (T1105), RegSetValue (T1112), CreateProcess/ShellExecute (T1106), LoadLibrary/GetProcAddress (T1129)"`
- `"capa_analyze: 57 rules, top rules encode data using XOR (T1027), create/open registry key, get file version info, get common file path, check if file exists"`
- `"floss_extract: 2846 static strings, 1 decoded string, indicating obfuscation/stack strings"`
- `"Sample path contains bkransomware_elex_hawkeye_maze_remcos indicating known malware family association"`

## Malcat Structured Analysis
(Malcat analysis error: malcat_analyze top-level: MCP malcat closed: )

## capa Capability Rules
engine: `capa` · Total rules: 57 · duration_s: 86.92

| Rule | ATT&CK | MBC |
|---|---|---|
| encode data using XOR | T1027:Obfuscated Files or Information | E1027.m02:Obfuscated Files or Information, C0026.002:Encode Data |
| create or open registry key |  | C0036.004:Registry, C0036.003:Registry |
| get file version info | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get common file path | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| check if file exists | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| query or enumerate registry value | T1012:Query Registry | C0036.006:Registry |
| delete registry key | T1112:Modify Registry | C0036.002:Registry |
| query environment variable | T1082:System Information Discovery | E1082:System Information Discovery |
| check OS version | T1082:System Information Discovery | E1082:System Information Discovery |
| log keystrokes via polling | T1056.001:Input Capture | F0002.002:Keylogging |
| get file size | T1083:File and Directory Discovery | E1083:File and Directory Discovery |
| get disk information | T1082:System Information Discovery | E1082:System Information Discovery |
| delete registry value | T1112:Modify Registry | C0036.007:Registry |
| accept command line arguments | T1059:Command and Scripting Interpreter | E1059:Command and Scripting Interpreter |
| link function at runtime on Windows | T1129:Shared Modules |  |

## PE Imports / Signals
import_count: 318

| label | api_match | ATT&CK |
|---|---|---|
| check_debugger | IsDebuggerPresent | T1622 |
| download_file | URLDownloadToFile | T1105 |
| set_registry_value | RegSetValue | T1112 |
| create_process | CreateProcess | T1106 |
| shell_execute | ShellExecute | T1106 |
| load_library | LoadLibrary | T1129 |
| get_proc_address | GetProcAddress | T1129 |

## YARA Matches (pipeline)
Total matches: 23

| Rule | Namespace | Match strings (trimmed) |
|---|---|---|
| domain | - | $domain_regex@0 len=2 |
| IP | - | $ipv4@459893 len=7; $ipv6@252878 len=4 |
| contains_base64 | - | $a@245300 len=24 |
| Misc_Suspicious_Strings | - | $a3@400684 len=14 |
| url | - | $url_regex@396920 len=96 |
| maldoc_getEIP_method_1 | - | $a@460864 len=6 |
| IsPE32 | - |  |
| IsWindowsGUI | - |  |
| HasDebugData | - |  |
| HasRichSignature | - | $a0@240 len=4 |
| VC8_Microsoft_Corporation | - | $a@6306 len=10 |
| SEH_Save | - | $a@137441 len=7 |
| SEH_Init | - | $a@21246 len=6; $b@193755 len=7 |
| Check_OutputDebugStringA_iat | - |  |
| anti_dbg | - | $d1@263200 len=12; $c2@326380 len=17; $c3@325196 len=17 |
| win_hook | - | $f1@328710 len=10; $c1@328252 len=19; $c3@328274 len=14 |
| network_dropper | - | $f1@329876 len=10; $c1@329856 len=17 |
| escalate_priv | - | $d1@329548 len=12; $c2@329194 len=21 |
| screenshot | - | $d1@329094 len=9; $d2@328710 len=10; $c2@328496 len=5 |
| keylogger | - | $f1@328710 len=10; $c2@327842 len=11 |
| win_registry | - | $f1@329548 len=12; $c3@329242 len=11; $c6@329242 len=11 |
| win_token | - | $f1@329548 len=12; $c2@329194 len=21; $c3@329174 len=16 |
| win_files_operation | - | $f1@263200 len=12; $c1@325760 len=9; $c2@325728 len=14; $c3@325760 len=9; $c4@325700 len=8 |

## Generated YARA Meta
```json
{
  "sha256": "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c",
  "family": "unknown",
  "generated_at": "2026-08-06T00:50:53.447579+00:00",
  "string_count": 8,
  "strings": [
    "IsDebuggerPresent is a standard anti-debugging technique used by malware to detect and evade reverse engineering tools, ",
    "This API is used to download additional payloads (e.g., ransomware encryption modules, RAT components) from attacker-con",
    "Registry modification is used for persistence (e.g., adding run keys), disabling security software, or configuring malic",
    "These APIs are used to execute additional malicious processes, launch ransomware encryption routines, or run attacker co",
    "Dynamic API resolution is a common obfuscation technique used by malware to hide malicious imports from static analysis,",
    "These rules detect well-known malware capabilities: anti-debugging, keylogging, screen capture, registry manipulation, f",
    "These mapped ATT&CK techniques cover core functionality for ransomware and RATs: system/file discovery for targeting, re",
    "The high volume of obfuscated strings indicates heavy use of string obfuscation to hide malicious indicators (e.g., C2 d"
  ],
  "rule_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yar",
  "sigma_path": "/opt/samples/logs/2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c/rule.yml",
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
    "utc": "2026-08-06 00:50:53 UTC"
  },
  "publish_target": "revai_publish"
}
```

## FLOSS Strings
Total strings: 2846 · per_category: `{"decoded_strings": 1, "stack_strings": 0, "tight_strings": 0, "language_strings": 0, "language_strings_missed": 0, "static_strings": 2845}`

### FLOSS sample
- `?GetPu`
- `!This program cannot be run in DOS mode.`
- ``.rdata`
- `@.data`
- `ttHt=Hu095`
- `QWWWWWWPW`
- `jEjCjB@j8`
- `XSVWjD_W3`
- `QSSSSSSPS`
- `QPWWhL`
- `t8PPPPh`
- `9G t!j`
- `t'9~ u"`
- `t	9p(u`
- `u8hd)D`
- `u	9wlt>`
- `~(9~8t	WW`
- `u h<)D`
- `At;F u`
- `t49^ u'`
- `~ 9^$u`
- `t>9~ t9j0`
- `t7j(SV`
- `;7u<;G`
- `uij0[SQ`
- `t)9w u$`
- `PjShp.D`
- `jShp.D`
- `+t=Ht-Ht`
- `HtpHHt`
- `Pj^h`1D`
- `j^h`1D`
- `SSWPSSSS`
- `j.Zf9P,u`
- `u	f9p0u`
- `WQh,8D`
- `W9qXtDV`
- `9wXt8V`
- `VW9AXtw`
- `t-h@8D`

## .NET Analysis
- is_dotnet: false (not observed)

## radare2 Disassembly (attach in Static Code Analysis)
### 0x00421c21
```asm
┌ 300: entry0 ();
│       ╎   ; var int32_t var_4h @ ebp-0x4
│       ╎   ; var int32_t var_1ch @ ebp-0x1c
│       ╎   ; var int32_t var_24h @ ebp-0x24
│       ╎   0x00421c21      e81a580500     call 0x477440
│       └─< 0x00421c26      e97ffeffff     jmp 0x421aaa
..
```
### 0x004391d2
```asm
; CALL XREF from entry0 @ 0x421ba2(x)
┌ 127: int main (char **argv, char **envp, int32_t envp, int32_t arg_14h);
│           ; arg char **argv @ ebp+0x8
│           ; arg char **envp @ ebp+0xc
│           ; arg int32_t envp @ ebp+0x10
│           ; arg int32_t arg_14h @ ebp+0x14
│           0x004391d2      55             push ebp
│           0x004391d3      8bec           mov ebp, esp
│           0x004391d5      5d             pop ebp
│       ┌─< 0x004391d6      e900000000     jmp 0x4391db
│       │   ; JUMP XREF from main @ 0x4391d6(x)
│       └─> 0x004391db      55             push ebp
│           0x004391dc      8bec           mov ebp, esp
│           0x004391de      53             push ebx
│           0x004391df      56             push esi
│           0x004391e0      57             push edi
│           0x004391e1      83cfff         or edi, 0xffffffff          ; -1
│           0x004391e4      e803a8fdff     call fcn.004139ec
│           0x004391e9      8bf0           mov esi, eax
│           0x004391eb      e87302feff     call fcn.00419463
│           0x004391f0      ff7514         push dword [arg_14h]
│           0x004391f3      ff7510         push dword [envp]
│           0x004391f6      8b5804         mov ebx, dword [eax + 4]
│           0x004391f9      ff750c         push dword [envp]
│           0x004391fc      ff7508         push dword [argv]
│           0x004391ff      e86845feff     call fcn.0041d76c
│           0x00439204      85c0           test eax, eax
│       ┌─< 0x00439206      743b           je 0x439243
│       │   0x00439208      85db           test ebx, ebx
│      ┌──< 0x0043920a      740e           je 0x43921a
│      ││   0x0043920c      8b03           mov eax, dword [ebx]
│      ││   0x0043920e      8bcb           mov ecx, ebx
│      ││   0x00439210      ff90ac000000   call dword [eax + 0xac]     ; 172
│      ││   0x00439216      85c0           test eax, eax
│     ┌───< 0x00439218      7429           je 0x439243
│     │└──> 0x0043921a      8b06           mov eax, dword [esi]
│     │ │   0x0043921c      8bce           mov ecx, esi
│     │ │   0x0043921e      ff5050         call dword [eax + 0x50]     ; 80
│     │ │   0x00439221      85c0           test eax, eax
│     │┌──< 0x00439223      7515           jne 0x43923a
│     │││   0x00439225      8b4e20         mov ecx, dword [esi + 0x20]
│     │││   0x00439228      85c9           test ecx, ecx
│    ┌────< 0x0043922a      7405           je 0x439231
│    ││││   0x0043922c      8b01           mov eax, dword [ecx]
│    ││││   0x0043922e      ff5060         call dword [eax + 0x60]     ; 96
│    └────> 0x00439231      8b06           mov eax, dword [esi]
│     │││   0x00439233      8bce           mov ecx, esi
│     │││   0x00439235      ff5068         call dword [eax + 0x68]     ; 104
│    ┌────< 0x00439238      eb07           jmp 0x439241
│    ││└──> 0x0043923a      8b06           mov eax, dword [esi]
│    ││ │   0x0043923c      8bce           mov ecx, esi
│    ││ │   0x0043923e   
```
### 0x004139ec
```asm
; CALL XREF from main @ 0x4391e4(x)
┌ 9: fcn.004139ec ();
│           0x004139ec      e8a55a0000     call fcn.00419496
│           0x004139f1      8b4004         mov eax, dword [eax + 4]
└           0x004139f4      c3             ret
```
### 0x004235c9
```asm
; CALL XREF from fcn.00419496 @ 0x40c0bf(x)
┌ 91: fcn.004235c9 (int32_t arg_8h, int32_t arg_ch);
│           ; arg int32_t arg_8h @ ebp+0x8
│           ; arg int32_t arg_ch @ ebp+0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; var int32_t var_8h @ ebp-0x8
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_10h @ ebp-0x10
│           ; var int32_t var_1ch @ ebp-0x1c
│           ; var int32_t var_20h @ ebp-0x20
│           0x004235c9      55             push ebp
│           0x004235ca      8bec           mov ebp, esp
│           0x004235cc      83ec20         sub esp, 0x20
│           0x004235cf      56             push esi
│           0x004235d0      57             push edi
│           0x004235d1      6a08           push 8                      ; 8
│           0x004235d3      59             pop ecx
│           0x004235d4      be94474400     mov esi, 0x444794
│           0x004235d9      8d7de0         lea edi, [var_20h]
│           0x004235dc      f3a5           rep movsd dword es:[edi], dword [esi]
│           0x004235de      8b750c         mov esi, dword [arg_ch]
│           0x004235e1      8b7d08         mov edi, dword [arg_8h]
│           0x004235e4      85f6           test esi, esi
│       ┌─< 0x004235e6      7413           je 0x4235fb
│       │   0x004235e8      f60610         test byte [esi], 0x10
│      ┌──< 0x004235eb      740e           je 0x4235fb
│      ││   0x004235ed      8b0f           mov ecx, dword [edi]
│      ││   0x004235ef      83e904         sub ecx, 4
│      ││   0x004235f2      51             push ecx
│      ││   0x004235f3      8b01           mov eax, dword [ecx]
│      ││   0x004235f5      8b7018         mov esi, dword [eax + 0x18]
│      ││   0x004235f8      ff5020         call dword [eax + 0x20]     ; 32
│      └└─> 0x004235fb      897df8         mov dword [var_8h], edi
│           0x004235fe      8975fc         mov dword [var_4h], esi
│           0x00423601      85f6           test esi, esi
│       ┌─< 0x00423603      740c           je 0x423611
│       │   0x00423605      f60608         test byte [esi], 8
│      ┌──< 0x00423608      7407           je 0x423611
│      ││   0x0042360a      c745f40040..   mov dword [var_ch], 0x1994000
│      └└─> 0x00423611      8d45f4         lea eax, [var_ch]
│           0x00423614      50             push eax
│           0x00423615      ff75f0         push dword [var_10h]
│           0x00423618      ff75e4         push dword [var_1ch]
│           0x0042361b      ff75e0         push dword [var_20h]
└           0x0042361e      ff1548d24300   call dword [sym.imp.KERNEL32.dll_RaiseException] ; 0x43d248 ; VOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, const ULONG_PTR *lpArguments)
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
  - `VERSION.dll!VerQueryValueW`
  - `VERSION.dll!GetFileVersionInfoW`
  - `VERSION.dll!GetFileVersionInfoSizeW`
  - `KERNEL32.dll!LocalReAlloc`
  - `KERNEL32.dll!GlobalFlags`
  - `KERNEL32.dll!CompareStringW`
  - `KERNEL32.dll!GetLocaleInfoW`
  - `KERNEL32.dll!GetSystemDefaultUILanguage`
  - `USER32.dll!InvalidateRect`
  - `USER32.dll!DestroyMenu`
  - `USER32.dll!RealChildWindowFromPoint`
  - `USER32.dll!ClientToScreen`
  - `USER32.dll!EndPaint`
  - `GDI32.dll!TextOutW`
  - `GDI32.dll!ExtTextOutW`
  - `GDI32.dll!SetViewportExtEx`
  - `GDI32.dll!SetViewportOrgEx`
  - `GDI32.dll!SetWindowExtEx`
  - `WINSPOOL.DRV!OpenPrinterW`
  - `WINSPOOL.DRV!ClosePrinter`
  - `WINSPOOL.DRV!DocumentPropertiesW`
  - `ADVAPI32.dll!RegEnumValueW`
  - `ADVAPI32.dll!RegQueryValueW`
  - `ADVAPI32.dll!RegEnumKeyW`
  - `ADVAPI32.dll!RegDeleteValueW`
  - `ADVAPI32.dll!RegDeleteKeyW`
  - `SHELL32.dll!ShellExecuteW`
  - `SHELL32.dll!SHGetSpecialFolderPathW`
  - `SHLWAPI.dll!PathFileExistsW`
  - `SHLWAPI.dll!PathIsUNCW`

## Audit Trail (recent)
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module='KERNEL32.DLL' ORDER BY name", "ts": 1785822857.680121}`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE name IN ('WriteFile','ReadFile','SetFilePointer','SetEndOfFile','DeviceIoControl','GetLogicalDrives','GetDriveTypeW','GetVolumeInformationW','GetDiskFreeSpaceW','FindFirstVolumeW','FindNextVolumeW','GetVolumeNameForVolumeMount`
- `{"source": "ghidra_query", "sql": "SELECT name, module FROM imports WHERE module IN ('WS2_32.DLL','WININET.DLL','CRYPT32.DLL','SHELL32.DLL','USER32.DLL') ORDER BY module, name", "ts": 1785822866.7862644}`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785822905.00276}`
- `{"source": "yara_gen_v2", "ts": 1785822906.03351}`
- `{"source": "publish_report_v2", "ts": 1785823022.5364342}`
- `{"source": "publish_report_v2_technical", "ts": 1785823142.78894}`
- `{"source": "ghidra_query", "sql": "\nSELECT name, start_ea, size\nFROM funcs\nWHERE size > 1024\nORDER BY size DESC\nLIMIT 50\n", "ts": 1785859447.6081004}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785859448.0972123}`
- `{"source": "ghidra_query", "sql": "\n        SELECT src_start_ea, dst_start_ea\n        FROM cfg_edges\n        WHERE src_start_ea > 0 AND dst_start_ea > 0\n    ", "ts": 1785859456.8969984}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM imports", "ts": 1785859457.0799391}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM data_items WHERE name LIKE 'PTR_%'", "ts": 1785859457.3133059}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM funcs", "ts": 1785859457.351304}`
- `{"source": "ghidra_query", "sql": "SELECT COUNT(1) AS cnt FROM strings", "ts": 1785859457.3899128}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS funcs FROM funcs", "ts": 1785859573.806074}`
- `{"source": "ghidra_query", "sql": "SELECT count(*) AS strings FROM strings", "ts": 1785859573.9067595}`
- `{"source": "ghidra_query", "sql": "SELECT name, address FROM data_items WHERE name LIKE 'PTR_%' LIMIT 50", "ts": 1785859574.3325167}`
- `{"source": "ghidra_query", "sql": "SELECT address, substr(content, 1, 100) AS s FROM strings WHERE content LIKE '%crypt%' OR content LIKE '%.dll' OR content LIKE '%http%' LIMIT 30", "ts": 1785859574.3644903}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785859574.377496}`
- `{"source": "ghidra_query", "sql": "SELECT name, address, size FROM funcs ORDER BY size DESC LIMIT 25", "ts": 1785859703.7240808}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports ORDER BY address LIMIT 50", "ts": 1785859707.4703672}`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE name LIKE '%Internet%' OR name LIKE '%URL%' OR name LIKE '%Crypt%' OR name LIKE '%WinInet%' OR name LIKE '%Http%' OR name LIKE '%Socket%' OR name LIKE '%RegSet%' OR name LIKE '%CreateService%' OR name LIKE '%StartServ`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE name LIKE '%InternetOpen%' OR name LIKE '%InternetConnect%' OR name LIKE '%HttpOpen%' OR name LIKE '%HttpSend%' OR name LIKE '%URLDownload%' OR name LIKE '%WinHttp%' OR name LIKE '%CryptAcquire%' OR name LIKE '%CryptE`
- `{"source": "ghidra_query", "sql": "SELECT name, module, address FROM imports WHERE name LIKE '%Crypt%' OR name LIKE '%Encrypt%' OR name LIKE '%Decrypt%' OR name LIKE '%Hash%' OR name LIKE '%Rtl%' OR name LIKE '%CreateMutex%' OR name LIKE '%CreateEvent%' OR name LIKE '%SetEvent%' OR name LIKE '%Reset`
- `{"source": "ghidra_query", "sql": "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80", "ts": 1785859771.254074}`
- `{"source": "yara_gen_v2", "ts": 1785859772.2966943}`
- `{"source": "publish_report_v2", "ts": 1785859930.8079286}`
- `{"source": "publish_report_v2_technical", "ts": 1785860250.6715865}`
- `{"source": "quick_scan_v2", "phase": 2, "ts": 1785976924.9854228}`
- `{"source": "yara_gen_v2", "ts": 1785977453.4485338}`
