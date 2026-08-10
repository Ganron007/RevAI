// yara_gen_v2.py — 2026-08-09T17:07:38.276355+00:00
import "pe"
rule CADRE_v2_hexorcist_crackme_7_fc5a215c0f6d {
    meta:
        description = "RevAI v2 auto rule for Hexorcist Crackme 7"
        sha256 = "fc5a215c0f6d3bdbf5c1e0dca72161871a37d833fdcfd62bb984c7892004365f"
        family = "hexorcist_crackme_7"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "KERNEL32.DLL" ascii wide
        $s2 = "USER32.DLL" ascii wide
        $s3 = "GetModuleHandleA" ascii wide
        $s4 = "AddVectoredExceptionHandler" ascii wide
        $s5 = "ExitProcess" ascii wide
        $s6 = "DialogBoxParamA" ascii wide
        $s7 = "GetDlgItemTextA" ascii wide
        $s8 = "MessageBoxA" ascii wide
        $s9 = "LoadIconA" ascii wide
        $s10 = "SendMessageA" ascii wide
        $s11 = "EndDialog" ascii wide
        $h0 = { 4D 5A 80 00 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "d7f03e6d403ce99bd9054453497aa12e"
}