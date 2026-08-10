// yara_gen_v2.py — 2026-08-09T17:29:14.188048+00:00
import "pe"
rule CADRE_v2_hexorcist_keygen_cbddf52b9cc0 {
    meta:
        description = "RevAI v2 auto rule for Hexorcist keygen"
        sha256 = "cbddf52b9cc0cf6f25b24890930e6d2137a60c647361a4c7b0081182b20841f4"
        family = "hexorcist_keygen"
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
        $s4 = "ExitProcess" ascii wide
        $s5 = "DialogBoxParamA" ascii wide
        $s6 = "GetDlgItemTextA" ascii wide
        $s7 = "SetDlgItemTextA" ascii wide
        $s8 = "LoadIconA" ascii wide
        $s9 = "SendMessageA" ascii wide
        $s10 = "EndDialog" ascii wide
        $s11 = "HEXORCIST KEYGEN TEMPLATE" ascii wide
        $h0 = { 4D 5A 80 00 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "e471a30244579dd1c29a70e51f0b18dc"
}