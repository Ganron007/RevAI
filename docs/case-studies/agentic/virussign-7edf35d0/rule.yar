// yara_gen_v2.py — 2026-08-03T12:20:42.530882+00:00
rule CADRE_v2_unknown_3476906b2c72 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "3476906b2c724a601697ee517190121f2e141a09c2dc10d08426b1b37460a544"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "StringLoaderB.?ReadBufferFromFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s1 = "StringLoaderB.?ReadBufferFromFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s2 = "StringLoaderB.?WriteBufferToFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s3 = "StringLoaderB.?WriteBufferToFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s4 = "StringLoaderB.?IsBufferContainUnicode@CStringLoader@@SA_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s5 = "StringLoaderB.?ReadStringFromBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z" ascii wide
        $s6 = "StringLoaderB.?ReadBufferFromFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s7 = "StringLoaderB.?WriteStringToBuffer@CStringLoader@@MAEIPAUSMemoryBufferInfo@@@Z" ascii wide
        $s8 = "StringLoaderB.?WriteBufferToFile@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s9 = "?ReadBufferFromFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s10 = "?ReadBufferFromFileInWinNT@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $s11 = "?WriteBufferToFileInWin95@CStringLoader@@MAE_NPAUSMemoryBufferInfo@@@Z" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}