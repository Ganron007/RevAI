// yara_gen_v2.py — 2026-08-05T08:03:22.244628+00:00
rule CADRE_v2_unknown_669cf448a0b2 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "669cf448a0b2b308e648691d8bec3daecbbeb3cd4f3bc1341c9b03a904089db2"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "?OCREC_GetPostPublishJobDirectoryManager@@YAJAEAV?$CRefCountedPtr@UITaskDirectoryManager@@@@@Z" ascii wide
        $s1 = "Microsoft® is a registered trademark of Microsoft Corporation." ascii wide
        $s2 = "Windows® is a registered trademark of Microsoft Corporation." ascii wide
        $s3 = "P:\\Target\\x64\\ship\\lync\\x-none\\ocpubmgr.pdb" ascii wide
        $s4 = "_register_thread_local_exe_atexit_callback" ascii wide
        $s5 = "Skype for Business Recording Manager 2015" ascii wide
        $s6 = "InitializeCriticalSectionAndSpinCount" ascii wide
        $s7 = "CreateXmlReaderInputWithEncodingName" ascii wide
        $s8 = "api-ms-win-crt-filesystem-l1-1-0.dll" ascii wide
        $s9 = "GdipSetStringFormatDigitSubstitution" ascii wide
        $s10 = "__initialize_lconv_for_unsigned_char" ascii wide
        $s11 = "__vcrt_InitializeCriticalSectionEx" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}