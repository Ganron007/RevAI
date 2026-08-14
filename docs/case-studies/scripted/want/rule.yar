// yara_gen_v2.py — 2026-08-12T19:40:37.248136+00:00
import "pe"
rule CADRE_v2_ransomware_lockbit_d52f0647e519 {
    meta:
        description = "RevAI v2 auto rule for ransomware.lockbit"
        sha256 = "d52f0647e519edcea013530a23e9e5bf871cf3bd8acb30e5c870ccc8c7b89a09"
        family = "ransomware_lockbit"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "PECompact2" ascii wide
        $s2 = "`J L5''m" ascii wide
        $s3 = "#L6@2'}!" ascii wide
        $s4 = "GetProcAddress" ascii wide
        $s5 = "kernel32.dll" ascii wide
        $s6 = "LoadLibraryA" ascii wide
        $s7 = "VirtualAlloc" ascii wide
        $s8 = "VirtualFree" ascii wide
        $s9 = "Mw0qb`Y[4" ascii wide
        $s10 = "PpLH U(s8" ascii wide
        $s11 = "lWR% uLCQ" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "09d0478591d4f788cb3e5ea416c25237"
}