// yara_gen_v2.py — 2026-08-12T20:54:04.085168+00:00
import "pe"
rule CADRE_v2_trojan_poison_symmi_65fdb5d460b0 {
    meta:
        description = "RevAI v2 auto rule for trojan.poison/symmi"
        sha256 = "65fdb5d460b079279a4afcb45671b4ec4d7a2d734dcf5f45232dcbdb6d08275b"
        family = "trojan_poison_symmi"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "HHtpHHtl" ascii wide
        $s2 = "SS@SSPVSS" ascii wide
        $s3 = "t.;t$$t(" ascii wide
        $s4 = "VC20XC00U" ascii wide
        $s5 = "__GLOBAL_HEAP_SELECTED" ascii wide
        $s6 = "__MSVCRT_HEAP_SELECT" ascii wide
        $s7 = "runtime error" ascii wide
        $s8 = "TLOSS error" ascii wide
        $s9 = "SING error" ascii wide
        $s10 = "DOMAIN error" ascii wide
        $s11 = "- unable to initialize heap" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "e39378c4fb2416ba4fcdfda97cdd80df"
}