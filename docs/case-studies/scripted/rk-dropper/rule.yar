// yara_gen_v2.py — 2026-08-12T22:36:52.323329+00:00
import "pe"
rule CADRE_v2_adload_fugrafa_1196afa54d18 {
    meta:
        description = "RevAI v2 auto rule for adload/fugrafa"
        sha256 = "1196afa54d18ff2ddf0be7a77616657dbd286147f6705d16357239b2dd941ea0"
        family = "adload_fugrafa"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "!WK[TWKd" ascii wide
        $s2 = "!gM^rJxH" ascii wide
        $s3 = "zah@*]?t" ascii wide
        $s4 = "97Lt:_lC" ascii wide
        $s5 = "hqn,4r[)" ascii wide
        $s6 = "u8:aIGu\\YJ" ascii wide
        $s7 = "<r{EL=KJ" ascii wide
        $s8 = "GetNumberOfConsoleInputEvents" ascii wide
        $s9 = "GetEnhMetaFilePaletteEntries" ascii wide
        $s10 = "ottrcvfayshjoutoyipnezimhtv" ascii wide
        $s11 = "WritePrivateProfileSectionW" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "b15aa3f8f2c4f386d6157b8cf32ec572"
}