// yara_gen_v2.py — 2026-08-12T21:51:39.938491+00:00
import "pe"
rule CADRE_v2_trioris_cerbu_trojan_38b1bbc48c35 {
    meta:
        description = "RevAI v2 auto rule for Trioris/Cerbu trojan"
        sha256 = "38b1bbc48c35a5decd8eaf475a5b32f742c28c5d0b5f9c85c1a667fbf2cbdb73"
        family = "trioris_cerbu_trojan"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "</tq<\\tm<.um" ascii wide
        $s1 = "s-9>w)+>" ascii wide
        $s2 = "<0r><9w:" ascii wide
        $s3 = "SVWjA_jZ+" ascii wide
        $s4 = "uBjAYjZ+" ascii wide
        $s5 = "j/_j\\[f;" ascii wide
        $s6 = "PPPPPPPP" ascii wide
        $s7 = ">0t<NAj0X" ascii wide
        $s8 = "tHHt*Ht#" ascii wide
        $s9 = "~';_t|%3" ascii wide
        $s10 = "UQPXY]Y[" ascii wide
        $s11 = "Ht+Ht$Ht" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "b5f4ee827c576f7005f9e544e6955bfb"
}