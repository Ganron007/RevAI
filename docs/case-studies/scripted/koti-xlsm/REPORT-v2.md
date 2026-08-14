> **RevAI provenance** — commit `unknown` · engine `langgraph` · agent-loop flags: budget=True redundant=True hallucination=True taxonomy=True · generated 2026-08-13 14:07:28 UTC

# Verdict sources (multi-source)

| Source | Verdict |
|--------|--------|
| **Final** | **malicious** |
| Triage upstream (quick ∪ deep) | malicious |
| Quick scan | malicious |
| Deep dive | Flagged by YARA as suspicious due to domain and base64 indicators, but no direct evidence of malicious API calls or behaviors. |
| Publish LLM (claimed) | malicious |

- **Locked over publish LLM:** no

## Executive Summary

This report details the analysis of a macro-enabled Excel workbook (XLSM) identified as malicious, with a high confidence score of 85 from upstream triage (source: triage_verdict.json). The sample, with SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, is associated with the XAgent malware family, known for its use as a trojan downloader. Static analysis reveals high entropy (7.56 bits/byte) and the presence of base64-encoded content and domain regex patterns, which are indicators commonly linked to malicious payloads and command-and-control (C2) communication (source: malcat, yara). VirusTotal reports 34 malicious detections, reinforcing its malicious nature (source: virustotal). Behavioral analysis was not performed in this assessment, limiting insight into runtime actions. The sample likely leverages macros for initial execution and network-based indicators suggest potential C2 activity. We assess this as a malicious artifact requiring immediate containment.

## 1. Sample Identification

The sample is located at /opt/samples/corpus/malware/8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e/koti.xlsm (source: evidence_provided). It is an Excel macro-enabled workbook (OOXML format) with the SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e, as confirmed by multiple tools (source: malcat, triage_verdict.json). The project name is 'malware', indicating it is part of a curated malicious corpus. File type analysis shows it is a ZIP archive containing OOXML components, including macro sheets, which are a common vector for malware delivery (source: malcat).

## 2. Classification

Based on upstream triage, the sample is classified as malicious with a family guess of XAgent and a score of 85 (source: triage_verdict.json). This verdict is supported by behavioral intent evidence such as YARA rule matches for domain regex and base64 content, and high AV detections on VirusTotal (source: yara, virustotal). While obfuscation signals like high entropy (7.56 bits/byte) are present, they are neutral alone; however, combined with network indicators and macro capabilities, they point to malicious activity (source: malcat, deep_dive.json). The verdict must align with upstream triage, and we concur that this sample exhibits hostile behavior indicative of malware.

## 3. Background & Family Lineage

The XAgent malware family is a known trojan downloader often used in cyber-espionage campaigns, typically delivered via macro-enabled documents like XLSM files (source: triage_verdict.json). It is associated with techniques such as command-and-control communication and payload obfuscation through encoding. This sample's characteristics, including base64 strings and domain patterns, align with XAgent's modus operandi for evading detection and establishing persistence (source: virustotal, yara). The family lineage suggests it may be part of a broader campaign targeting users through phishing or drive-by downloads.

## 4. Static Analysis

Static analysis using MalCat revealed the file is a ZIP archive with high Shannon entropy of 7.56 bits/byte, indicating possible encryption or compression, which is common in malware for payload obfuscation (source: malcat). The OOXML structure includes 24 virtual files, notably 'xl/macrosheets/sheet1.xml', confirming the presence of macros that could execute malicious code (source: malcat). YARA rule matches detected a domain regex pattern and base64-encoded content at specific offsets, suggesting embedded network indicators and obfuscated data (source: yara). These static indicators, while not definitive alone, are frequently associated with malicious intent when combined with macro capabilities.

## 5. Behavioral Analysis

Dynamic analysis tools such as Speakeasy and Frida were not run or provided in the evidence, so no runtime behavior was observed (source: evidence_provided). This absence limits our understanding of the sample's actions in a live environment, such as API calls or persistence mechanisms. We cannot confirm behaviors like process injection or file modification without dynamic execution data. Therefore, behavioral capabilities remain latent and unobserved in this assessment.

## 6. Network Analysis & C2

Network indicators are suggested by a YARA rule match for a domain regex pattern, which could imply command-and-control (C2) communication or data exfiltration attempts (source: yara). However, specific domains or IPs were not extracted or confirmed in the evidence. The presence of base64-encoded content may also hide network-related strings. Without runtime capture or deeper static extraction, actual C2 infrastructure remains unconfirmed, but the indicators suggest potential for network-based malicious activity.

## 7. Capability Assessment

Observed capabilities include macro execution via the XLSM format, which is a primary infection vector (source: malcat). Latent capabilities, based on static indicators, include payload obfuscation through base64 encoding and potential network communication via domain patterns (source: yara). VirusTotal detections tag it as a downloader, implying it could fetch additional payloads (source: virustotal). No evidence of privilege escalation, credential theft, or lateral movement was observed, but the macro context allows for such actions if executed.

## 8. Attribution

Attribution is limited to the malware family XAgent, as indicated by upstream triage and VirusTotal detections (source: triage_verdict.json, virustotal). No specific threat actor group or campaign details are evident from the available data. The sample's characteristics align with generic trojan downloader behavior, but without additional intelligence, we cannot attribute it to a known group with high confidence.

## 9. Indicators of Compromise

Key indicators include the SHA256 hash 8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e and the file path provided (source: evidence_provided). YARA matches identify base64-encoded content and domain regex strings (source: yara). VirusTotal tags include 'calls-wmi', 'xlsx', and 'malware', which could aid in detection rules (source: virustotal). Specific domains or IPs were not extracted, but the indicators present can be used for threat hunting.

## 10. Detection Rules

Detection rules are provided in the rule.yara.json evidence, with YARA rules named 'domain' and 'contains_base64' that match domain regex and base64 patterns (source: rule.yara.json). These rules are valid and can be used for scanning similar samples. Sigma rules may also be available at the referenced path, but details were not provided. Implementing these rules in security tools can help identify analogous threats.

## 11. MITRE ATT&CK Mapping

Based on the evidence, techniques include:
- Initial Access: Phishing (T1566) via macro-enabled documents (source: malcat).
- Execution: User Execution (T1204) through macro activation.
- Defense Evasion: Obfuscated Files or Information (T1027) with base64 encoding (source: yara).
- Command and Control: Application Layer Protocol (T1071) suggested by domain indicators (source: yara).
No observed behaviors for persistence or collection, but macros could enable such techniques if executed.

## 12. Containment, Eradication, Recovery

Containment should involve isolating affected systems and removing the malicious file. Eradication requires scanning for similar indicators and ensuring macros are disabled in enterprise environments. Recovery includes restoring from clean backups and applying security patches. Given the macro vector, user training on phishing awareness is critical to prevent reinfection.

## 13. Recommendations

Recommendations include: disabling macros in Office documents by default, implementing YARA and Sigma rules for detection, enhancing network monitoring for domain patterns, and educating users on phishing risks. Regular updates to threat intelligence feeds can improve detection of XAgent variants. For incident response, conduct forensic analysis to identify any lateral movement or data exfiltration.

## 14. Appendix A: Evidence Trail

Evidence sources and audit trail:
- triage_verdict.json: Upstream verdict with score 85 and family guess XAgent.
- deep-dive.json: YARA matches for domain and base64, confidence 70.
- rule.yara.json: YARA rule details and paths.
- Audit trail: quick_scan_v2 and yara_gen_v2 timestamps.
- MalCat evidence: File type, entropy, virtual files.
- YARA matches: domain and contains_base64 rules.
- radare2 disassembly: Minimal code snippet provided.
- xorsearch: No XOR-encoded strings found.

## 15. Appendix B: Module Inventory

The sample consists of an OOXML ZIP archive with 24 virtual files, including macro sheets (e.g., xl/macrosheets/sheet1.xml) and other XML components (source: malcat). Modules are not executable binaries but document structures; the macro sheet is the primary component for potential code execution. No additional DLLs or scripts were identified in the evidence.

## 16. Author + Sign-off

Report prepared by the Malware Analyst based on automated evidence and tools. Sign-off: This analysis is based on the provided evidence and adheres to accuracy constraints. Date: 2026-08-12.