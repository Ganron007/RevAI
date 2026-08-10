// yara_gen_v2.py — 2026-08-09T13:29:10.384329+00:00
import "pe"
rule CADRE_v2_unknown_263db9906127 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "263db990612712d732763838e245002d526705f6aece1b6508a46d2a3ed6d3ca"
        family = "unknown"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "KERNEL32.DLL" ascii wide
        $s2 = "USER32.DLL" ascii wide
        $s3 = "ExitProcess" ascii wide
        $s4 = "MessageBoxA" ascii wide
        $h0 = { 4D 5A 80 00 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "98c88d882f01a3f6ac1e5f7dfd761624"
}