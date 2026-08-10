// yara_gen_v2.py — 2026-08-09T17:49:23.374741+00:00
import "pe"
rule CADRE_v2_sunburst_32519b85c0b4 {
    meta:
        description = "RevAI v2 auto rule for Sunburst"
        sha256 = "32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77"
        family = "sunburst"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "'@y+.A8f" ascii wide
        $s2 = "v4.0.30319" ascii wide
        $s3 = "#Strings" ascii wide
        $s4 = "get_LIBCODE_JM0_10" ascii wide
        $s5 = "<>9__41_10" ascii wide
        $s6 = "<UpdateThresholds>b__41_10" ascii wide
        $s7 = "<.cctor>b__529_10" ascii wide
        $s8 = "get_LIBCODE_JM0_20" ascii wide
        $s9 = "get_LIBCODE_PS0_20" ascii wide
        $s10 = "get_LIBCODE_PCC_20" ascii wide
        $s11 = "get_LIBCODE_JM0_30" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "dae02f32a21e03ce65412f6e56942daa"
}