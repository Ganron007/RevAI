// yara_gen_v2.py — 2026-08-09T15:15:52.117497+00:00
import "pe"
rule CADRE_v2_unknown_1d4c0b32aea6 {
    meta:
        description = "RevAI v2 auto rule for Unknown"
        sha256 = "1d4c0b32aea68056755daf70689699200ffa09688495ccd65a0907cade18bd2a"
        family = "unknown"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "9g'P@/ZcS`" ascii wide
        $s2 = "<u(k]kaA" ascii wide
        $s3 = "88|jlc8tyf" ascii wide
        $s4 = "\">V'h$!;" ascii wide
        $s5 = "5`e*ci<2x" ascii wide
        $s6 = "\">V'`*!;B" ascii wide
        $s7 = "~r6{<x7W" ascii wide
        $s8 = ".idata$5" ascii wide
        $s9 = ".rdata$zzzdbg" ascii wide
        $s10 = ".idata$2" ascii wide
        $s11 = ".idata$3" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "f9ade0aa18f660a34a4fa23392e21838"
}