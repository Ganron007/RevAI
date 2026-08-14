// yara_gen_v2.py — 2026-08-12T18:57:48.589329+00:00
import "pe"
rule CADRE_v2_trojan_graftor_skeeyah_ef2d290a0b2c {
    meta:
        description = "RevAI v2 auto rule for trojan.graftor/skeeyah"
        sha256 = "ef2d290a0b2ca89c9a70011414afca3cfa7605a07912753b8b109283b4110c98"
        family = "trojan_graftor_skeeyah"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "DataABackup.lnk" ascii wide
        $s1 = "!This program cannot be run in DOS mode." ascii wide
        $s2 = "D$@9|$Ts" ascii wide
        $s3 = "D$tPQPVU" ascii wide
        $s4 = "\\$@9|$8r" ascii wide
        $s5 = "?????????????" ascii wide
        $s6 = "??????????????????" ascii wide
        $s7 = "+F(_^[;E" ascii wide
        $s8 = "F(@@;F,v" ascii wide
        $s9 = "tj9~8u@j" ascii wide
        $s10 = "<at9<rt,<wt" ascii wide
        $s11 = "j\"^SSSSS" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "fbed62d6575587ffd7907c1f823fa846"
}