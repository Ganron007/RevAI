// yara_gen_v2.py — 2026-08-12T17:53:17.593191+00:00
import "pe"
rule CADRE_v2_locky_28046c14ea33 {
    meta:
        description = "RevAI v2 auto rule for Locky"
        sha256 = "28046c14ea3325885ee1e731cd0bcf9f38445df02675836b851cb2ae94c050eb"
        family = "locky"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "QSSjPSSSPS" ascii wide
        $s2 = "D$$PWWWW" ascii wide
        $s3 = "s89D$Dw2+D$Dj" ascii wide
        $s4 = "t\"SS9] u" ascii wide
        $s5 = "PPPPPPPP" ascii wide
        $s6 = "UQPXY]Y[" ascii wide
        $s7 = "Unknown exception" ascii wide
        $s8 = "CorExitProcess" ascii wide
        $s9 = "HH:mm:ss" ascii wide
        $s10 = "dddd, MMMM dd, yyyy" ascii wide
        $s11 = "MM/dd/yy" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "31553623c43827d554ad9e1b7dfa6a5a"
}