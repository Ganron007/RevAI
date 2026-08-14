// yara_gen_v2.py — 2026-08-12T19:20:59.426679+00:00
import "pe"
rule CADRE_v2_trojan_lotusblossom_explorerhijack_bf0d6cc20fa7 {
    meta:
        description = "RevAI v2 auto rule for trojan.lotusblossom/explorerhijack"
        sha256 = "bf0d6cc20fa7a20ed7b5d0c9283d7670f73c33d7f8b3c3261aae04969c40ce76"
        family = "trojan_lotusblossom_explorerhijack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "\\Internet Explorer\\iexplore.exe" ascii wide
        $s1 = "000A758C8FEAE5F.TMP" ascii wide
        $s2 = "($7/+.1$" ascii wide
        $s3 = "!This program cannot be run in DOS mode." ascii wide
        $s4 = "UQPXY]Y[" ascii wide
        $s5 = "Invalid parameter passed to C runtime function." ascii wide
        $s6 = "%d/%02d/%02d %02d:%02d:%02d -" ascii wide
        $s7 = "ReleaseFile Error->FindResource Failed[%d]." ascii wide
        $s8 = "ReleaseFile Error->Size=0." ascii wide
        $s9 = "Kernel32.dll" ascii wide
        $s10 = "ReleaseFile Error->LoadLibrary Failed[%d]." ascii wide
        $s11 = "LoadResource" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "aee2f8f6aa200110e796682791bc8758"
}