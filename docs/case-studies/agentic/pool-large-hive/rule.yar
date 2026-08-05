// yara_gen_v2.py — 2026-08-05T10:20:12.708850+00:00
rule CADRE_v2_unknown_4660766415cd {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "4660766415cdc4a6ff3bffb20f35c6f3a7ccfd494816b1a135de8c11e7151860"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "VirtualProtect" ascii wide
        $s1 = "KERNEL32.DLL" ascii wide
        $s2 = "LoadLibraryA" ascii wide
        $s3 = "ExitProcess" ascii wide
        $s4 = "YARA rule match confirms the sample is packed with UPX 3.9x LZMA compression for x64, a common packer used to obfuscate " ascii wide
        $s5 = "Capa identifies UPX packing, mapping to the ATT&CK Defense Evasion technique Obfuscated Files or Information: Software P" ascii wide
        $s6 = "These high-signal imports are commonly used by packed malware to dynamically resolve API addresses at runtime and modify" ascii wide
        $s7 = "Multiple high-severity anomalies consistent with packed/obfuscated malware: patched UPX header, overall high entropy (>2" ascii wide
        $s8 = "Runtime function linking is a common malware technique to avoid static detection by resolving APIs only at runtime, and " ascii wide
        $s9 = "All extracted strings are static/obfuscated with no decoded meaningful strings, consistent with packed/encrypted malware" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}