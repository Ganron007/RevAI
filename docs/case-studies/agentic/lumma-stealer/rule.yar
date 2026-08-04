// yara_gen_v2.py — 2026-08-04T04:38:11.911415+00:00
rule CADRE_v2_unknown_706a49b55ba7 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "706a49b55ba73d1294bdad8570017230a5c66a0e5d171d6ad20830226c096c50"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "WritePrivateProfileStringW" ascii wide
        $s1 = "SHGetSpecialFolderLocation" ascii wide
        $s2 = "ExpandEnvironmentStringsW" ascii wide
        $s3 = "GetPrivateProfileStringW" ascii wide
        $s4 = "GetFileVersionInfoSizeW" ascii wide
        $s5 = "SystemParametersInfoW" ascii wide
        $s6 = "SetCurrentDirectoryW" ascii wide
        $s7 = "GetWindowsDirectoryW" ascii wide
        $s8 = "SHGetPathFromIDListW" ascii wide
        $s9 = "MultiByteToWideChar" ascii wide
        $s10 = "WideCharToMultiByte" ascii wide
        $s11 = "WaitForSingleObject" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}