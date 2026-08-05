// yara_gen_v2.py — 2026-08-05T07:07:37.850974+00:00
rule CADRE_v2_unknown_0c00aedf9707 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "0c00aedf97071653467dc7734823429a163445eec89926f961eed9b47769e9e5"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "© M2-Team and Contributors. All rights reserved." ascii wide
        $s1 = "E:\\Projects\\NSudo\\Output\\Release\\x64\\NSudo.pdb" ascii wide
        $s2 = "??0exception@@QEAA@AEBQEBD@Z" ascii wide
        $s3 = "InitializeCriticalSectionEx" ascii wide
        $s4 = "??0exception@@QEAA@AEBV0@@Z" ascii wide
        $s5 = "?what@exception@@UEBAPEBDXZ" ascii wide
        $s6 = "SetUnhandledExceptionFilter" ascii wide
        $s7 = "GetSystemWindowsDirectoryW" ascii wide
        $s8 = "ExpandEnvironmentStringsW" ascii wide
        $s9 = "ChangeWindowMessageFilter" ascii wide
        $s10 = "IsProcessorFeaturePresent" ascii wide
        $s11 = "InterlockedPushEntrySList" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}