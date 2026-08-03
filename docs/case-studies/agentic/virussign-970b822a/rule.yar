// yara_gen_v2.py — 2026-08-03T11:03:39.217557+00:00
rule CADRE_v2_unknown_62a5c9c2f17d {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "62a5c9c2f17d2ae56ea45e9c222c5cd437125c7f687f4fc73ee31126bdc795cb"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Microsoft Firewall" ascii wide
        $s1 = "Xiang Corporation" ascii wide
        $s2 = "GetModuleHandleA" ascii wide
        $s3 = "OriginalFilename" ascii wide
        $s4 = "VS_VERSION_INFO" ascii wide
        $s5 = "FileDescription" ascii wide
        $s6 = "LegalTrademarks" ascii wide
        $s7 = "GetProcAddress" ascii wide
        $s8 = "StringFileInfo" ascii wide
        $s9 = "LegalCopyright" ascii wide
        $s10 = "ProductVersion" ascii wide
        $s11 = "kernel32.dll" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}