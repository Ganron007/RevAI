// yara_gen_v2.py — 2026-08-12T17:27:05.186553+00:00
import "pe"
rule CADRE_v2_upatre_a59b2cb9f6c7 {
    meta:
        description = "RevAI v2 auto rule for upatre"
        sha256 = "a59b2cb9f6c706635b4d97edc574a72ac54fba47f9a4a1eae77cf58a96ccf567"
        family = "upatre"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "`X+ww76m@@" ascii wide
        $s2 = "|`|s\\$:~" ascii wide
        $s3 = "2uPj1hp@@" ascii wide
        $s4 = "GGGGBBBBIu" ascii wide
        $s5 = "SwW&:~8Ol" ascii wide
        $s6 = "dip quip" ascii wide
        $s7 = "DestroyWindow" ascii wide
        $s8 = "SetTimer" ascii wide
        $s9 = "KillTimer" ascii wide
        $s10 = "SetWindowPos" ascii wide
        $s11 = "GetWindowRect" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "a3e8b5e80d5f9f266119a4ac18211954"
}