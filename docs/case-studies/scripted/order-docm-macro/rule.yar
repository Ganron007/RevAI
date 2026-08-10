// yara_gen_v2.py — 2026-08-09T16:12:12.971653+00:00
rule CADRE_v2_generic_macro_malware_385966f3d6be {
    meta:
        description = "RevAI v2 auto rule for generic macro malware"
        sha256 = "385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73"
        family = "generic_macro_malware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Rule matched indicating the presence of VBA macro code in the document, a common vector for malicious payloads." ascii wide
        $s1 = "Confirms the document contains VBA macro code, supporting the likelihood of executable content." ascii wide
        $s2 = "Base64 encoded strings detected, which may be used for obfuscation in malicious macros to evade detection." ascii wide
        $s3 = "Domain-related string found, potentially indicating command and control (C2) communication or data exfiltration." ascii wide
        $s4 = "IP address string found, suggesting network activity that could be associated with malicious infrastructure." ascii wide
        $s5 = "File is an OOXML document (ZIP-based) containing vbaProject.bin, which hosts VBA macros and is a common delivery mechani" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}