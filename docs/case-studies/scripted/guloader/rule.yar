// yara_gen_v2.py — 2026-08-09T15:51:26.938306+00:00
import "pe"
rule CADRE_v2_unknown_visualbasic_loader_c5e1c2b5307e {
    meta:
        description = "RevAI v2 auto rule for Unknown (VisualBasic Loader)"
        sha256 = "c5e1c2b5307ebcb325ab8a4e6a266f263fac56348c0588c6b1abdc8bbe944509"
        family = "unknown_visualbasic_loader"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "MSVBVM60.DLL" ascii wide
        $s2 = "Borderadamasprei" ascii wide
        $s3 = "Startsym1" ascii wide
        $s4 = "adamasprei" ascii wide
        $s5 = "REBALANCES" ascii wide
        $s6 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s7 = "VBA6.DLL" ascii wide
        $s8 = "__vbaAryDestruct" ascii wide
        $s9 = "__vbaVarMove" ascii wide
        $s10 = "__vbaStrVarMove" ascii wide
        $s11 = "__vbaI2I4" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "e5dc9f90e63a8223ac7d0f9627dcbb68"
}