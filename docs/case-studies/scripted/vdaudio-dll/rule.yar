// yara_gen_v2.py — 2026-08-09T14:12:26.836648+00:00
import "pe"
rule CADRE_v2_unknown_backdoor_trojan_possible_delphi_based_1e9f21f514ee {
    meta:
        description = "RevAI v2 auto rule for Unknown backdoor/Trojan (possible Delphi-based)"
        sha256 = "1e9f21f514ee4793cfae7baa21549be0d9b432c59513d2efed860c2b1501da39"
        family = "unknown_backdoor_trojan_possible_delphi_based"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "Z_^B[B]BX" ascii wide
        $s2 = "ntdll.dll" ascii wide
        $s3 = "advapi32" ascii wide
        $s4 = "DestroyCursor" ascii wide
        $s5 = "LoadMenuA" ascii wide
        $s6 = "PtInRect" ascii wide
        $s7 = "RegisterClassExA" ascii wide
        $s8 = "ReplyMessage" ascii wide
        $s9 = "CallWindowProcW" ascii wide
        $s10 = "USER32.dll" ascii wide
        $s11 = "DeleteFileA" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "0302695b505772b990fb0f7026657050"
}