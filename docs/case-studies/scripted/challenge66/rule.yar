// yara_gen_v2.py — 2026-08-12T23:53:21.584228+00:00
import "pe"
rule CADRE_v2_ghost_sifreleyici_modernize_hayalet_likely_a_rat_9451a7c4f32e {
    meta:
        description = "RevAI v2 auto rule for Ghost Şifreleyici Modernize Hayalet (likely a RAT/trojan, possibly related to llac/babar based on VT)"
        sha256 = "9451a7c4f32eb94a89a021009de3cba933502d7baebfbd8ce7023a98fecd8ba6"
        family = "ghost_sifreleyici_modernize_hayalet_likely_a_rat"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "1^2e2.3C9" ascii wide
        $s2 = "Sk8OF6.v" ascii wide
        $s3 = "8!7(+6l%" ascii wide
        $s4 = "Oc2->a\"6" ascii wide
        $s5 = "winsck.ocx@SW" ascii wide
        $s6 = "e6rFRICHTX32.OCX" ascii wide
        $s7 = "DrderSty" ascii wide
        $s8 = "BAFM~omctlJ" ascii wide
        $s9 = "^;RS_<M_" ascii wide
        $s10 = "rm1.Insertar_Objeto2" ascii wide
        $s11 = "GraficAudio~Calc_Pictu" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "b4e06d942b341e012040239c1cca0b7d"
}