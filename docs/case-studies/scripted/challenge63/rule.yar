// yara_gen_v2.py — 2026-08-12T23:34:53.041596+00:00
import "pe"
rule CADRE_v2_luder_98ab99efa9cc {
    meta:
        description = "RevAI v2 auto rule for luder"
        sha256 = "98ab99efa9cc35e89d3a43ec1976c52d2ac91055c3ac787f2497b7e733c63648"
        family = "luder"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "msvcrt.dll" ascii wide
        $s2 = "ADVAPI32.dll" ascii wide
        $s3 = "KERNEL32.dll" ascii wide
        $s4 = "NTDLL.DLL" ascii wide
        $s5 = "GDI32.dll" ascii wide
        $s6 = "USER32.dll" ascii wide
        $s7 = "COMCTL32.dll" ascii wide
        $s8 = "comdlg32.dll" ascii wide
        $s9 = "SHELL32.dll" ascii wide
        $s10 = "AUTHZ.dll" ascii wide
        $s11 = "ACLUI.dll" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "6a2fc8d37b8a0d3e10059a4768a803d7"
}