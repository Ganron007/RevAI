> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-14 03:29:16 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | malicious |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a JavaScript file named 'loveyou.js' (SHA256: f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1). The sample is a heavily obfuscated trojan downloader designed to deliver an Android Meterpreter payload. Analysis confirms it is malicious, with a high confidence score of 90/100. The file employs multiple layers of Base64 encoding, function indirection, and obfuscated variable names to evade detection. Its primary function is to decode and execute a large embedded payload at runtime, which is identified as an Android Meterpreter reverse shell component. The social engineering filename 'loveyou.js' is intended to entice user execution. Key evidence includes YARA rule matches for 'android_meterpreter' and 'BASE64_table', a high file entropy of 5.74 bits/byte indicating obfuscation, and a massive Base64-encoded payload string. External threat intelligence from VirusTotal reports 44 out of 61 AV engines detecting this file as malicious, classifying it as a trojan downloader. The sample does not exhibit persistence, exfiltration, or credential theft mechanisms in the analyzed payload, but its core capability is command and control (C2) via the Meterpreter framework. We assess this sample poses a significant risk as a delivery mechanism for remote access trojans.

## 1. Sample Identification

| Attribute | Value |
|---|---|
| **SHA256** | f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1 |
| **File Name** | loveyou.js |
| **File Path** | /opt/samples/corpus/malware/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/loveyou.js |
| **File Type** | text/utf8 (JavaScript) |
| **Architecture** | NONE (script) |
| **File Size** | Not specified in evidence |
| **Entropy** | 5.74 bits/byte (source: malcat) |
| **Project** | malware |

The sample is a UTF-8 encoded JavaScript file. Its high entropy of 5.74 bits/byte, while not extreme for a script, is elevated due to the heavy use of Base64 encoding and obfuscated strings, which is a common indicator of packed or obfuscated malware (source: malcat).

## 2. Classification

| Field | Value |
|---|---|
| **Verdict** | **Malicious** |
| **Confidence** | 90/100 |
| **Family** | trojan.dwnldr/skeeyah (source: triage verdict) |
| **Type** | Trojan Downloader / Android Meterpreter Loader |
| **Detection Rate** | 44/61 (72%) AV engines (source: VirusTotal) |

The classification is **malicious** based on multiple converging lines of evidence. The upstream triage verdict assigns a score of 85 and identifies the family as 'trojan.dwnldr/skeeyah' (source: triage verdict). The deep-dive analysis increases confidence to 90, citing the confirmed presence of an Android Meterpreter payload signature (source: deep-dive). The high detection rate from VirusTotal (44/61 engines) provides strong external corroboration (source: triage verdict). The sample's obfuscation techniques (Base64 encoding, function indirection) are neutral signals alone, but the embedded Meterpreter payload constitutes clear behavioral-intent evidence for malicious remote access capability (source: yara, deep-dive).

## 3. Background & Family Lineage

The sample is identified as belonging to the 'trojan.dwnldr/skeeyah' family (source: triage verdict). This family is typically associated with downloader trojans that fetch and execute additional payloads. The specific payload identified here is an Android Meterpreter component, which is part of the Metasploit Framework's mobile penetration testing suite. While Meterpreter is a legitimate tool for authorized security testing, its unsolicited delivery via an obfuscated JavaScript file with a social engineering filename ('loveyou.js') is a hallmark of malicious activity. Attackers frequently abuse dual-use tools like Meterpreter to establish covert command and control channels on compromised systems. The 'skeeyah' designation may refer to a specific campaign or variant within the downloader family that targets Android devices or uses Android payloads as a stage in a multi-platform attack chain. No additional lineage information was found in the provided evidence.

## 4. Static Analysis

Static analysis reveals a heavily obfuscated JavaScript file designed to resist analysis and signature detection.

**Obfuscation Techniques:**
1.  **Base64 Encoding:** The file contains a massive Base64-encoded payload string of 4,509 characters (source: deep-dive, malcat). Multiple YARA rules confirm the presence of Base64 tables and packed functions: 'BASE64_table' (offset 3337), 'contains_base64' (offset 4), and 'possible_includes_base64_packed_functions' (offsets 4, 3415) (source: yara).
2.  **Function Indirection:** The YARA rule 'function_through_object' matched at offsets 3737 and 4117, indicating that function calls are obfuscated by routing them through object properties, a technique to break static analysis patterns (source: yara).
3.  **Obfuscated Identifiers:** Variable and function names are obfuscated, such as 'adfgkdafkhjgrsgfksghkod_0x515c' and 'adfgkdafkhjgrsgfksghkod_0x442408' (source: deep-dive, ida_query). This hinders readability and signature matching.
4.  **High Entropy:** The file's entropy is 5.74 bits/byte (source: malcat). While not conclusive alone, this is consistent with encoded or packed content.

**Embedded Payload:**
The core of the file is a large Base64-encoded string that, when decoded and executed at runtime, is identified as an Android Meterpreter payload. The YARA rule 'android_meterpreter' matched at offset 9687 with the string '$stopEval' (source: yara, deep-dive). This confirms the file's primary purpose is to deliver a Meterpreter reverse shell or RAT component.

**Social Engineering:**
The filename 'loveyou.js' is a classic social engineering lure, designed to entice a user into executing the file (source: deep-dive).

## 5. Behavioral Analysis

Dynamic analysis tools (Speakeasy, Frida) were not run against this sample. Therefore, no runtime behavior such as process creation, network calls, or file system modifications was observed. The behavioral analysis is based entirely on static indicators.

The static analysis strongly implies the following intended behavior:
1.  **Execution of Obfuscated Payload:** The JavaScript code is designed to decode the large Base64 string and execute it, likely using `eval()` or a similar dynamic code execution function (inferred from the 'stopEval' string match).
2.  **Establishment of C2 Channel:** The decoded payload is an Android Meterpreter component, which inherently establishes a reverse shell connection to a command and control server (source: deep-dive). This is the primary malicious behavior.
3.  **Defense Evasion:** The extensive obfuscation (Base64, function indirection, obfuscated names) is intended to impair security defenses and avoid detection (source: deep-dive).

No evidence of persistence mechanisms, data exfiltration, or credential harvesting was found in the static analysis (source: deep-dive).

## 6. Network Analysis & C2

No live network traffic was captured. However, the payload's nature provides strong indicators of C2 capability.

The embedded Android Meterpreter payload is designed to establish a reverse shell connection. This means the compromised host would initiate an outbound connection to an attacker-controlled server to receive commands (source: deep-dive). The specific C2 server address (IP or domain) is not visible in the obfuscated payload strings provided in the evidence. The YARA rule 'domain' matched, indicating the presence of domain-like patterns in the file, which could be part of the C2 configuration (source: triage verdict). However, without decoding the full payload, the exact C2 endpoints cannot be confirmed.

**Assessment:** The sample has latent C2 capability via the Meterpreter framework. The actual C2 infrastructure details are obfuscated within the Base64 payload.

## 7. Capability Assessment

| Capability | Status | Evidence |
|---|---|---|
| **Command & Control** | **Observed (Latent)** | Android Meterpreter payload establishes reverse shell (source: yara, deep-dive). |
| **Defense Impairment** | **Observed** | Heavy obfuscation (Base64, function indirection) to evade detection (source: deep-dive). |
| **Persistence** | Not Observed | No persistence mechanisms identified (source: deep-dive). |
| **Exfiltration** | Not Observed | No data theft patterns found (source: deep-dive). |
| **Credential Access** | Not Observed | No credential harvesting code present (source: deep-dive). |
| **Lateral Movement** | Not Observed | No indicators found. |
| **Initial Access** | **Observed** | Social engineering via filename 'loveyou.js' (source: deep-dive). |

The sample's primary capability is as a loader for a Meterpreter RAT. The obfuscation is a defensive capability to ensure delivery. No other hostile capabilities (persistence, exfiltration, etc.) were observed in the analyzed payload.

## 8. Attribution

No specific threat actor attribution is possible based on the provided evidence. The sample uses the Metasploit Framework's Meterpreter payload, which is publicly available and used by a wide range of actors, from penetration testers to cybercriminals. The 'trojan.dwnldr/skeeyah' family label (source: triage verdict) may correspond to a known campaign, but no further attribution data was provided. The social engineering filename suggests a broad, opportunistic campaign rather than a targeted attack.

## 9. Indicators of Compromise

**File-Based IOCs:**
| Type | Value |
|---|---|
| SHA256 | f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1 |
| File Name | loveyou.js |

**YARA Rules (from rule.yara.json):**
-   `android_meterpreter` (source: yara)
-   `BASE64_table` (source: yara)
-   `contains_base64` (source: yara)
-   `possible_includes_base64_packed_functions` (source: yara)
-   `function_through_object` (source: yara)
-   `domain` (source: yara)

**Potential Network IOCs (Obfuscated):**
-   Domain patterns detected by YARA rule 'domain' (source: yara). Specific domains are embedded within the Base64 payload and require decoding.

## 10. Detection Rules

**YARA Rule (Generated):**
A YARA rule was generated for this sample and is located at `/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/rule.yar` (source: rule.yara.json). The rule is based on 4 strings and is valid (source: rule.yara.json).

**Sigma Rule:**
A Sigma rule was also generated and is located at `/opt/samples/logs/f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1/rule.yml` (source: rule.yara.json).

**Detection Logic:**
Detection should focus on:
1.  The specific file hash (SHA256).
2.  The presence of the YARA strings, particularly the 'android_meterpreter' signature and large Base64 blocks.
3.  Behavioral detection for JavaScript files decoding and executing large Base64 payloads.

## 11. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| **Initial Access** | Phishing: Spearphishing Attachment | T1566.001 | Social engineering filename 'loveyou.js' (source: deep-dive). |
| **Execution** | Command and Scripting Interpreter: JavaScript | T1059.007 | Sample is a JavaScript file (source: malcat). |
| **Defense Evasion** | Obfuscated Files or Information | T1027 | Heavy Base64 encoding and function indirection (source: yara, deep-dive). |
| **Command and Control** | Ingress Tool Transfer | T1105 | Payload is a Meterpreter RAT designed for C2 (source: yara, deep-dive). |
| **Command and Control** | Application Layer Protocol | T1071 | Meterpreter uses standard protocols for C2 (inferred). |

## 12. Containment, Eradication, Recovery

**Containment:**
1.  Immediately isolate any system where this file is found or has been executed.
2.  Block the file hash (SHA256) at the network perimeter and endpoint security solutions.
3.  Search for and quarantine any copies of 'loveyou.js' across the environment.

**Eradication:**
1.  Terminate any processes spawned from the execution of this script.
2.  If the Meterpreter payload executed, identify and remove any persistence mechanisms it may have established (though none were observed in the static payload).
3.  Scan for and remove any additional tools or payloads downloaded by the Meterpreter session.

**Recovery:**
1.  Restore affected systems from known-good backups if compromise is confirmed.
2.  Change credentials for any accounts that may have been accessible from the compromised system.
3.  Conduct a thorough investigation to determine the initial infection vector and scope of compromise.

## 13. Recommendations

1.  **Block Indicators:** Add the provided file hash and YARA rules to security tool blocklists and detection signatures.
2.  **User Awareness:** Educate users about the risks of executing unsolicited JavaScript files, especially those with enticing filenames.
3.  **Email Filtering:** Enhance email gateway filters to block or quarantine JavaScript attachments.
4.  **Endpoint Detection:** Ensure endpoint detection and response (EDR) solutions are configured to detect and block the execution of obfuscated scripts and known Meterpreter payloads.
5.  **Network Monitoring:** Monitor for outbound connections that may indicate Meterpreter C2 traffic, particularly to unusual IP addresses or domains.
6.  **Threat Hunting:** Proactively hunt for other instances of this file or similar obfuscated JavaScript loaders in the environment.

## 14. Appendix A: Evidence Trail

| Source | Query/Table | Row/Rule | Why |
|---|---|---|---|
| yara | yara matches | android_meterpreter | Indicates presence of Android Meterpreter RAT strings, suggesting malicious remote access capability and behavioral intent. |
| yara | yara matches | domain | Matches domain regex patterns, potentially indicating C2 communication endpoints, which is behavioral evidence of network activity. |
| malcat | constants | crypto::Base64 | Use of Base64 encoding constant, common in obfuscation and payload delivery in malware, though neutral alone, supports other indicators. |
| malcat | strings | base64-like strings | Multiple strings resembling Base64 encoded data (e.g., 'wpHDtlHDiMOWf0JK..'), which may contain obfuscated malicious code or payloads. |
| external | VirusTotal | 44 malicious detections | High detection rate from multiple AV engines (44 malicious out of 61) confirms malicious nature and aligns with threat labels like trojan.dwnldr/skeeyah. |
| deep-dive | YARA rules | android_meterpreter signature | Meterpreter reverse shell payload inherently establishes command and control connections. |
| deep-dive | obfuscation methods | base64 encoding and function indirection | Techniques used to evade detection and impair security defenses. |
| rule.yara.json | yara matches | 4 strings | Generated YARA rule based on key indicators. |
| ida_query | strings | adfgkdafkhjgrsgfksghkod_0x515c | Obfuscated array containing base64-encoded values. |
| malcat | strings | Large base64 payload at address 9679 | The core obfuscated payload. |

## 15. Appendix B: Module Inventory

The sample is a single JavaScript file. Analysis did not reveal distinct, separable modules. The file contains:
1.  **Obfuscation Layer:** Code for decoding Base64 and routing function calls through objects.
2.  **Payload:** A large Base64-encoded string containing the Android Meterpreter payload.
3.  **Execution Logic:** Code to decode and execute the payload at runtime.

No external imports or dependencies were identified (source: deep-dive).

## 16. Author + Sign-off

**Report Author:** Automated Malware Analysis System (LLM Judge)
**Date:** 2026-08-12
**Sign-off:** This report was generated based on automated analysis tools and threat intelligence. The findings and recommendations are based on the evidence provided. Manual verification by a human analyst is recommended for critical decisions.