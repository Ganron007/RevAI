// yara_gen_v2.py — 2026-08-12T16:45:56.083761+00:00
import "pe"
rule CADRE_v2_trojan_blocker_bckn_botnet_trojan_f47060d0f7de {
    meta:
        description = "RevAI v2 auto rule for trojan.blocker/bckn (botnet trojan)"
        sha256 = "f47060d0f7de5ee651878eb18dd2d24b5003bdb03ef4f49879f448f05034a21e"
        family = "trojan_blocker_bckn_botnet_trojan"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "UVATAVAWH" ascii wide
        $s2 = "\\$ D9d$x" ascii wide
        $s3 = "0A_A^A\\^]" ascii wide
        $s4 = "\\$ UVWATAUAVAWH" ascii wide
        $s5 = "A_A^A]A\\_^]" ascii wide
        $s6 = "UVWATAUAVAWH" ascii wide
        $s7 = "\\$ UVATAUAWH" ascii wide
        $s8 = "A_A]A\\^]" ascii wide
        $s9 = "D8D$0u9D" ascii wide
        $s10 = "D$<D9D$`t" ascii wide
        $s11 = "t$\\D9D$`t" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "475b069fec5e5868caeb7d4d89236c89"
}