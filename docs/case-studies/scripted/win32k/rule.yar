// yara_gen_v2.py — 2026-08-12T18:18:50.098218+00:00
import "pe"
rule CADRE_v2_trojan_dyreza_battdil_8088f08a5636 {
    meta:
        description = "RevAI v2 auto rule for trojan.dyreza/battdil"
        sha256 = "8088f08a5636cec3bf8b9f05b6ca2d0b21a76a56199d6ccd1777a6f6a7b9fdde"
        family = "trojan_dyreza_battdil"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "=&&jL66Zl??A~" ascii wide
        $s1 = "&jL&6Zl6?A~?" ascii wide
        $s2 = "jL&&Zl66A~??" ascii wide
        $s3 = "L&&jl66Z~??A" ascii wide
        $s4 = "unknown_64bit" ascii wide
        $s5 = "daYdnceM" ascii wide
        $s6 = "daYdnceMm" ascii wide
        $s7 = "daYdnceMmb" ascii wide
        $s8 = "daYdnceMmbN" ascii wide
        $s9 = "daYdnceMmbNJ" ascii wide
        $s10 = "daYdnceMmbNJX" ascii wide
        $s11 = "daYdnceMmbNJXp" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "8d7e3e41cd993d5a41f4e96d6076c4f7"
}