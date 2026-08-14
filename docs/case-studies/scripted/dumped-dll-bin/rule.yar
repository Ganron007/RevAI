// yara_gen_v2.py — 2026-08-13T00:57:52.671515+00:00
import "pe"
rule CADRE_v2_xmrig_a2923d838f2d {
    meta:
        description = "RevAI v2 auto rule for xmrig"
        sha256 = "a2923d838f2d301a7c4b46ac598a3f9c08358b763b1973b4b4c9a7c6ed8b6395"
        family = "xmrig"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "efefefefefefefe" ascii wide
        $s1 = "efefefefefe" ascii wide
        $s2 = "!This program cannot be run in DOS mode." ascii wide
        $s3 = "L$ SUVWH" ascii wide
        $s4 = "@WATAUAVAWH" ascii wide
        $s5 = "0A_A^A]A\\_" ascii wide
        $s6 = "t$ WAVAWH" ascii wide
        $s7 = "\\$ UVWAVAWH" ascii wide
        $s8 = "0A_A^_^]" ascii wide
        $s9 = "|$ ATAUAVAWH" ascii wide
        $s10 = "|$@A_A^A]A\\" ascii wide
        $s11 = "UVWATAUAVAWH" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "0c4c8e94664e68ee06fc2a3faae408ec"
}