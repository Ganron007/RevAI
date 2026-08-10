// yara_gen_v2.py — 2026-08-09T13:46:47.782117+00:00
rule CADRE_v2_powershell_based_malware_14a42d6418b3 {
    meta:
        description = "RevAI v2 auto rule for PowerShell-based malware"
        sha256 = "14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2"
        family = "powershell_based_malware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "YARA rule indicates the script starts a shell, a behavioral signal for lateral movement or command execution, which is c" ascii wide
        $s1 = "YARA rule confirms the script is PowerShell-based, which is frequently abused in malicious campaigns for payload deliver" ascii wide
        $s2 = "YARA rule matched for PowerShell content, corroborating the script's nature and potential for malicious use." ascii wide
        $s3 = "Base64 strings suggest obfuscation, a neutral but suspicious technique often used in malicious scripts to evade detectio" ascii wide
        $s4 = "APIs related to process execution (e.g., ProcessStartInfo, RedirectStandardOutput) indicate the script can launch and co" ascii wide
        $s5 = "High entropy for a text file (2800 bytes) may indicate encoded or obfuscated content, supporting suspicion of malicious " ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}