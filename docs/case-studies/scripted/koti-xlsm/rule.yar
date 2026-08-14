// yara_gen_v2.py — 2026-08-12T22:57:34.478302+00:00
rule CADRE_v2_x97m_8e516c5e0ca2 {
    meta:
        description = "RevAI v2 auto rule for X97M"
        sha256 = "8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e"
        family = "x97m"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Matches domain regex, suggesting possible command-and-control (C2) communication or malicious network activity, a behavi" ascii wide
        $s1 = "Contains base64 encoded strings, commonly used in malware to obfuscate payloads, exfiltrate data, or evade detection." ascii wide
        $s2 = "Indicates a macro-enabled Excel document (OOXML), which is a prevalent vector for delivering malware via phishing or dri" ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}