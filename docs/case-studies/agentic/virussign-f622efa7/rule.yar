// yara_gen_v2.py — 2026-08-03T10:23:45.078827+00:00
rule CADRE_v2_unknown_91b176fb0d65 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "91b176fb0d650dcc59ff87f5aab50c7a8371fb859f096f93f7cee9920c90dacc"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "GetProcAddress" ascii wide
        $s1 = "VirtualProtect" ascii wide
        $s2 = "KERNEL32.DLL" ascii wide
        $s3 = "OLEAUT32.dll" ascii wide
        $s4 = "LoadLibraryA" ascii wide
        $s5 = "VirtualAlloc" ascii wide
        $s6 = "VirtualFree" ascii wide
        $s7 = "ExitProcess" ascii wide
        $s8 = "MSVCRT.dll" ascii wide
        $s9 = "USER32.dll" ascii wide
        $s10 = "wsprintfA" ascii wide
        $s11 = "Directly identifies the sample as packed with UPX, mapping to defense evasion via software packing, confirming the core " ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}