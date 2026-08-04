// yara_gen_v2.py — 2026-08-04T07:46:29.824538+00:00
rule CADRE_v2_unknown_7fbde4a47c91 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "7fbde4a47c916e4e3bbbb8c0e77d947216452f1f30e7b27f9e68a7642c8f72a6"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "E:\\workplace\\AndroidEmulator\\7KMarket_Git_Release64\\Basic\\Client\\Output\\Binfinal\\GameDownload\\GameDownload.pdb" ascii wide
        $s1 = "Copyright © 2020 Tencent. All Rights Reserved." ascii wide
        $s2 = "InitializeCriticalSectionAndSpinCount" ascii wide
        $s3 = "WinHttpGetIEProxyConfigForCurrentUser" ascii wide
        $s4 = "GdipSetImageAttributesColorMatrix" ascii wide
        $s5 = "SystemTimeToTzSpecificLocalTime" ascii wide
        $s6 = "GetLogicalProcessorInformation" ascii wide
        $s7 = "SetUnhandledExceptionFilter" ascii wide
        $s8 = "MsgWaitForMultipleObjectsEx" ascii wide
        $s9 = "GdipCreateHBITMAPFromBitmap" ascii wide
        $s10 = "RegisterWaitForSingleObject" ascii wide
        $s11 = "IDR_CUSTOM_FOR_EXTRACE_ICON" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}