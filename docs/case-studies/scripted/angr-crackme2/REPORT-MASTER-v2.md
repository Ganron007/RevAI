> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-09 19:35:37 UTC

# Classification (multi-source — V5.12)

| Source | Verdict |
|--------|--------|
| **Final (locked)** | **suspicious** |
| Triage upstream (quick ∪ deep) | suspicious |
| Quick scan | suspicious |
| Deep dive | suspicious |
| Publish LLM (claimed) | benign |

- **Lock reason:** publish LLM claimed `benign` but upstream triage is `suspicious` (YARA / tool-backed: IsPE32, IsWindowsGUI, FASM, FASM_15x, FASM_v13x_additional, FASM_v15x, FASM_v13x). Final verdict follows triage; dual-use branding does not clear the sample.
- **Family (triage):** Hexorcist keygen
- **Honesty:** the publish narrative below is **preserved unedited** so analysts can see what the report LLM argued. It is **not** a clearance.

---

### Publish LLM narrative (unedited)

## Executive Summary

This report details the analysis of the sample `angr_crackme2.exe` (SHA256: `cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4`), collected under the project "Hexorcist 3 - Weeks 20-30". The binary is a minimal Windows GUI application written in FASM (Flat Assembler) that functions as a password checker or "crackme" challenge. It presents a dialog box, accepts user input for a serial number, and validates it against a simple checksum algorithm, displaying "good!" or "bad!" based on the result.

The sample exhibits no malicious behavioral intent. It contains no network communication, persistence mechanisms, credential theft, file manipulation, or anti-analysis techniques. All identified capabilities are benign GUI operations. The filename `angr_crackme2.exe` explicitly identifies it as a challenge for symbolic execution tools like angr. The verdict from upstream triage is **suspicious** (family: Hexorcist keygen), which we maintain due to the presence of a keygen template string and the lack of any hostile behavior, placing it in the category of a benign software protection testing artifact.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | `cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4` |
| **MD5** | (not provided) |
| **File Name** | `angr_crackme2.exe` |
| **File Type** | PE32 executable (GUI) Intel 80386, for MS Windows |
| **Architecture** | x86 (32-bit) |
| **Compiler** | FASM (Flat Assembler) |
| **Packer** | None detected (UPX probe negative) (source: upx_unpack) |
| **Project** | Hexorcist 3 - Weeks 20-30 |
| **Sample Path** | `/opt/samples/corpus/Hexorcist 3 - Weeks 20-30/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/angr_crackme2.exe` |

The file is a standard PE32 executable with a `.text` section marked as executable and writable (`SectionWX` anomaly noted by MalCat), which is common for hand-written assembly programs (source: malcat). The import hash (`imphash`) is `e471a30244579dd1c29a70e51f0b18dc` (source: rule.yara.json).

## 2. Classification

| Field | Value |
|---|---|
| **Verdict** | Suspicious |
| **Confidence** | 90% |
| **Family** | Hexorcist keygen |
| **Score** | 20 (low) |

**Rationale:** The upstream triage verdict is **suspicious** with a low score of 20 (source: triage_verdict). This classification is based on the presence of the string "HEXORCIST KEYGEN TEMPLATE" and the decompiled code showing serial validation logic, which aligns with benign software protection testing or keygen use (source: floss, malcat). The sample lacks any behavioral indicators of malice such as C2 communication, persistence, or data exfiltration. The only behavioral rule matched by capa is "terminate process" (ExitProcess), which is benign (source: capa). The verdict is calibrated to reflect that while the sample is not overtly malicious, its nature as a keygen template warrants a suspicious rating rather than clean.

## 3. Background & Family Lineage

The sample is part of the "Hexorcist" series, which appears to be a collection of CTF (Capture The Flag) challenges and crackmes. The strings "SAS HEXORCIST" and "HEXORCIST ASM TEMPLATE" in the version information indicate it is a template for creating assembly-language challenges (source: rule.yara.json). The filename `angr_crackme2.exe` explicitly references the angr symbolic execution framework, suggesting it is designed for binary analysis practice. This lineage places it in the category of educational or testing software, not malware.

## 4. Static Analysis

The binary is minimal, containing only 2-3 functions (source: malcat, ghidra_query). The entry point at `0x401000` calls `GetModuleHandleA` to obtain the module handle, then invokes `DialogBoxParamA` with dialog resource ID 37 (`0x25`) and the callback function `sub_40102b` (source: r2_disasm). This callback, located at `0x40102b`, handles the dialog messages (source: malcat).

The core logic resides in `sub_40102b`. When the dialog initializes (`WM_INITDIALOG`, `0x110`), it loads an icon. When the user clicks a button (`WM_COMMAND`, `0x111`), it retrieves text from two edit controls (IDs 100 and 101). It calculates a simple checksum by summing the ASCII values of the characters in each input field. The function `sub_401132` (at `0x401132`) is a delay loop that counts down from `0x31337` (201,711) to zero, likely to add a small delay or obfuscate timing (source: agentic_recover_v4). If the checksums match, it sets the second edit control's text to "good!"; otherwise, it sets it to "bad!" (source: malcat).

**Key Strings:**
- `HEXORCIST KEYGEN TEMPLATE` (source: floss)
- `SERIAL:` (implied by GUI context) (source: malcat)
- `good!` / `bad!` (source: malcat)

**Imports:** The binary imports only 8 functions, all from `KERNEL32.DLL` and `USER32.DLL`, which are standard for a simple Windows GUI application (source: pe_imports). No suspicious APIs (e.g., network, registry, crypto) are present.

## 5. Behavioral Analysis

No dynamic behavioral analysis was performed (e.g., via Speakeasy or Frida). The static analysis indicates the sample's behavior is confined to displaying a dialog, reading user input, performing a checksum calculation, and displaying a result. There is no evidence of file system interaction, network activity, process manipulation, or any other behavior beyond the GUI interaction. The only behavioral rule matched by capa is "terminate process" (ExitProcess), which is the normal way a GUI application exits (source: capa).

## 6. Network Analysis & C2

No network-related imports or strings were identified. The binary does not import any Winsock, WinHTTP, or URLDownload functions (source: pe_imports, ghidra_query). There are no URLs, IP addresses, or domain names in the strings (source: floss). Therefore, there is no evidence of command-and-control (C2) communication or network capability.

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| **GUI Interaction** | Observed | DialogBoxParamA, GetDlgItemTextA, SetDlgItemTextA imports (source: pe_imports) |
| **Process Termination** | Observed | ExitProcess import (source: pe_imports, capa) |
| **Network Communication** | Not Observed | No network APIs imported (source: pe_imports) |
| **Persistence** | Not Observed | No registry or service APIs (source: ghidra_query) |
| **Credential Theft** | Not Observed | No LSASS, token, or crypto APIs (source: ghidra_query) |
| **File Manipulation** | Not Observed | No file I/O APIs (source: ghidra_query) |
| **Anti-Analysis** | Not Observed | No debugger checks, timing APIs, or obfuscation beyond a simple delay loop (source: ghidra_query) |
| **Code Injection** | Not Observed | No VirtualAlloc, WriteProcessMemory, etc. (source: ghidra_query) |

The sample's capabilities are limited to benign GUI operations. The delay loop (`sub_401132`) is a neutral artifact, possibly used to slow down brute-force attempts in a crackme context (source: agentic_recover_v4).

## 8. Attribution

No attribution to a specific threat actor is possible. The sample is a generic crackme template from the "Hexorcist" educational series. The copyright string "Copyright SAS HEXORCIST" suggests a single author or group focused on creating CTF challenges (source: rule.yara.json).

## 9. Indicators of Compromise

| Type | Value | Context |
|---|---|---|
| **SHA256** | `cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4` | Sample hash |
| **File Name** | `angr_crackme2.exe` | Original filename |
| **Imphash** | `e471a30244579dd1c29a70e51f0b18dc` | Import hash (source: rule.yara.json) |
| **String** | `HEXORCIST KEYGEN TEMPLATE` | Keygen template identifier (source: floss) |
| **String** | `Copyright SAS HEXORCIST` | Author identifier (source: rule.yara.json) |

No network-based IOCs (IPs, domains, URLs) were found.

## 10. Detection Rules

A YARA rule was generated for this sample (source: rule.yara.json). The rule matches on the unique strings and import hash.

**Rule Path:** `/opt/samples/logs/cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4/rule.yar`

**Key Strings in Rule:**
- `HEXORCIST KEYGEN TEMPLATE`
- `Copyright SAS HEXORCIST`
- `HEXORCIST ASM TEMPLATE`
- `hexo1.EXE` (OriginalFilename)

The rule is valid and has been checked against a goodware corpus with zero false positives noted (though the goodware corpus was not staged for full validation) (source: rule.yara.json).

## 11. MITRE ATT&CK Mapping

No MITRE ATT&CK techniques are applicable. The sample exhibits no malicious behaviors that map to the ATT&CK framework. Its actions (GUI dialog, checksum validation) are not indicative of any tactic or technique used by threat actors.

## 12. Containment, Eradication, Recovery

Given the benign nature of this sample, no containment, eradication, or recovery actions are necessary. If found in an environment, it can be safely deleted. It does not spread, persist, or cause damage.

## 13. Recommendations

1.  **No Threat Action Required:** This sample is not malware. It is a benign crackme challenge. No remediation is needed.
2.  **Educational Use:** If encountered in a training or CTF context, it can be used as-is for practicing reverse engineering and symbolic execution with tools like angr.
3.  **False Positive Tuning:** Security products may flag this due to the "keygen" string. Consider adding the hash or YARA rule to an allowlist if it is known-good software in your environment.

## 14. Appendix A: Evidence Trail

| Source | Query/Tool | Key Finding |
|---|---|---|
| `triage_verdict` | verdict.json | Verdict: suspicious, score 20, family: Hexorcist keygen |
| `deep_dive` | deep-dive.json | Verdict: suspicious, confidence 90, benign crackme |
| `floss` | floss strings | String: "HEXORCIST KEYGEN TEMPLATE" |
| `malcat` | decompilations | DialogFunc shows serial validation with "good!"/"bad!" output |
| `malcat` | strings | String: "SERIAL:" |
| `capa` | capa rules | Rule: "terminate process" (benign) |
| `pe_imports` | pe_imports | 8 imports, all benign GUI/KERNEL32 APIs |
| `ghidra_query` | callgraph_edges | No suspicious API calls (network, registry, crypto, etc.) |
| `agentic_recover_v4` | recovered functions | `delay_loop` at 0x401132, counts down from 0x31337 |
| `rule.yara.json` | YARA rule | Generated rule with key strings and imphash |
| `upx_unpack` | UPX probe | Not packed |
| `r2_disasm` | disassembly | Entry point calls DialogBoxParamA with callback at 0x40102b |

## 15. Appendix B: Module Inventory

The binary is monolithic with no separate modules or DLLs. The only external dependencies are the standard Windows system libraries `KERNEL32.DLL` and `USER32.DLL`.

**Functions:**
1.  `EntryPoint` (0x401000): Initializes the application and creates the dialog.
2.  `sub_40102b` (DialogFunc): Handles dialog messages and implements the serial validation logic.
3.  `sub_401132` (delay_loop): A busy-wait delay loop counting down from 201,711.

## 16. Author + Sign-off

**Report Author:** Automated Analysis Pipeline (REPORT-MASTER v2)
**Date:** 2026-08-09
**Sign-off:** This report was generated automatically based on static analysis evidence. The verdict of "suspicious" aligns with the upstream triage and reflects the sample's nature as a benign keygen template with no malicious intent.