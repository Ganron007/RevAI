// yara_gen_v2.py — 2026-08-12T23:15:09.280684+00:00
rule CADRE_v2_dwnldr_f3e743c919c1 {
    meta:
        description = "RevAI v2 auto rule for dwnldr"
        sha256 = "f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1"
        family = "dwnldr"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Matches YARA rule for android_meterpreter, a known malicious payload associated with Metasploit, indicating direct behav" ascii wide
        $s1 = "Indicates presence of Base64-encoded content, which is commonly used in malware to obfuscate payloads or configuration d" ascii wide
        $s2 = "High entropy value for a text file suggests obfuscation or packing, a neutral signal but often observed in malicious scr" ascii wide
        $s3 = "Detection of Base64 cryptography constant, indicating use of encoding that can hide malicious code or data." ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}