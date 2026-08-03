// yara_gen_v2.py — 2026-08-03T06:34:12.730647+00:00
rule CADRE_v2_unknown_e891b8f4825a {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "e891b8f4825a86999ef858ac13af749d982c91e9d3e92baf922862636912fec2"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "FreeEncryptedFileKeyInfo" ascii wide
        $s1 = "GetUserDefaultUILanguage" ascii wide
        $s2 = "ZwAdjustPrivilegesToken" ascii wide
        $s3 = "GetUserDefaultLangID" ascii wide
        $s4 = "GetSystemDefaultLCID" ascii wide
        $s5 = "SystemFunction033" ascii wide
        $s6 = "MessageBoxExA" ascii wide
        $s7 = "advapi32.dll" ascii wide
        $s8 = "kernel32.dll" ascii wide
        $s9 = "user32.dll" ascii wide
        $s10 = "ntdll.dll" ascii wide
        $s11 = "High entropy confirms heavy obfuscation; the anomaly set (large unreferenced high-entropy buffers likely for crypto mate" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}