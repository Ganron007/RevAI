// yara_gen_v2.py — 2026-08-03T09:25:26.491112+00:00
rule CADRE_v2_unknown_bf95bc98c0a4 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "bf95bc98c0a4fc259c81adce084e0e5cf72772f19b5b5a963d4744e59785c2e9"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "ExpandEnvironmentStringsA" ascii wide
        $s1 = "FindFirstUrlCacheEntryA" ascii wide
        $s2 = "FindNextUrlCacheEntryA" ascii wide
        $s3 = "GetWindowsDirectoryA" ascii wide
        $s4 = "InterlockedIncrement" ascii wide
        $s5 = "DeleteUrlCacheEntry" ascii wide
        $s6 = "GetCurrentProcessId" ascii wide
        $s7 = "GetSystemDirectoryA" ascii wide
        $s8 = "WaitForSingleObject" ascii wide
        $s9 = "WideCharToMultiByte" ascii wide
        $s10 = "GetForegroundWindow" ascii wide
        $s11 = "CreateBrushIndirect" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}