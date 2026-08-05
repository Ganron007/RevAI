// yara_gen_v2.py — 2026-08-03T06:59:00.413343+00:00
rule CADRE_v2_unknown_8059ade0d39e {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "8059ade0d39e4c82cbb94e8d1e1bc92436dd613009a69275f86fe256852a9075"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "@*\\AC:\\Users\\Owner\\Desktop\\Darty Crypter Source\\Payload\\Project1.vbp" ascii wide
        $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii wide
        $s3 = "ConvertStringSecurityDescriptorToSecurityDescriptorA" ascii wide
        $s4 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $s5 = "127.0.2.5\\tliveupdate.symantecliveupdate.com\\r\\n" ascii wide
        $s6 = "select name from Win32_Process where name='---'" ascii wide
        $s7 = "127.0.2.5\\tsecurityresponse.symantec.com\\r\\n" ascii wide
        $s8 = "127.0.2.5\\twindowsupdate.microsoft.com\\r\\n" ascii wide
        $s9 = "127.0.2.5\\twww.networkassociates.com\\r\\n" ascii wide
        $s10 = "127.0.2.5\\thousecall.trendmicro.com\\r\\n" ascii wide
        $s11 = "127.0.2.5\\tliveupdate.symantec.com\\r\\n" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}