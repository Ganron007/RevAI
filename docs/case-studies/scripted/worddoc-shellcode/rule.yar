// yara_gen_v2.py — 2026-08-09T13:45:23.447609+00:00
rule CADRE_v2_cobalt_strike_9feae4f91d05 {
    meta:
        description = "RevAI v2 auto rule for Cobalt Strike"
        sha256 = "9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f"
        family = "cobalt_strike"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = ".aaa.stage.15914547.tunnelcs.fax-email.us.XXXXXXXXXXXXXXXXXXXXX.." ascii wide
        $s1 = ".Sj.Sj.hH...j.Phj" ascii wide
        $s2 = "d.R0.R..R..r(." ascii wide
        $s3 = "iPhdnsaThLw&." ascii wide
        $s4 = "a.....@..C..." ascii wide
        $s5 = ".D$$[[aYZQ" ascii wide
        $s6 = "RW.R..B<." ascii wide
        $s7 = "P.H..X ." ascii wide
        $s8 = "f..K.X.." ascii wide
        $s9 = "a.....HH" ascii wide
        $s10 = "Rule matches strings at offsets 163 and 420 associated with Cobalt Strike, a known malicious tool used for command and c" ascii wide
        $s11 = "Extremely high entropy indicates possible encryption, compression, or obfuscation, which is a neutral signal but common " ascii wide
    condition:
        uint16(0) == 0x5A4D and 2 of them
}