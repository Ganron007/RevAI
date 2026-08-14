// yara_gen_v2.py — 2026-08-12T17:05:45.401945+00:00
import "pe"
rule CADRE_v2_usbles26_cd78cf4af8e3 {
    meta:
        description = "RevAI v2 auto rule for usbles26"
        sha256 = "cd78cf4af8e37b4a9de479867167027887a28527e2738c481a1c6891d707f21a"
        family = "usbles26"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "WATAUAVAWH" ascii wide
        $s2 = "@A_A^A]A\\_" ascii wide
        $s3 = "t$ WATAUH" ascii wide
        $s4 = "A_A^A]A\\_" ascii wide
        $s5 = "x ATAUAVH" ascii wide
        $s6 = "s\\HcL$HH" ascii wide
        $s7 = "0A_A^A]A\\_" ascii wide
        $s8 = "@SUVWATAUAVH" ascii wide
        $s9 = "PA^A]A\\_^][" ascii wide
        $s10 = "UVWATAUH" ascii wide
        $s11 = "D$&8\\$&t-8X" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "a675367c6d79f8c7b7603d13cfd0a3ff"
}