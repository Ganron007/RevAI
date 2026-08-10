// yara_gen_v2.py — 2026-08-09T18:26:56.418694+00:00
import "pe"
rule CADRE_v2_wannacry_ec3fd41b2298 {
    meta:
        description = "RevAI v2 auto rule for WannaCry"
        sha256 = "ec3fd41b2298954946999dcb3145cbdc927a5ca9a150a8c57741da5fe3198cda"
        family = "wannacry"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "oftware\\" ascii wide
        $s1 = "!This program cannot be run in DOS mode." ascii wide
        $s2 = "=j&&LZ66lA??~" ascii wide
        $s3 = "f\"\"D~**T" ascii wide
        $s4 = "V22dN::t" ascii wide
        $s5 = "o%%Jr..\\$" ascii wide
        $s6 = "&&Lj66lZ??~A" ascii wide
        $s7 = "\"\"Df**T~" ascii wide
        $s8 = ";22dV::tN" ascii wide
        $s9 = "%%Jo..\\r" ascii wide
        $s10 = "&Lj&6lZ6?~A?" ascii wide
        $s11 = "\"Df\"*T~*" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "68f013d7437aa653a8a98a05807afeb1"
}