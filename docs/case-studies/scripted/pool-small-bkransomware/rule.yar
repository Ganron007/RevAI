// yara_gen_v2.py — 2026-08-04T05:55:06.028127+00:00
rule CADRE_v2_unknown_2f2c6d9466e8 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "2f2c6d9466e8572bce76ca8d766b43d014eadfcff81f6e35e1b42766af59d60c"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate." ascii wide
        $s1 = "This program is linked to the missing export %s in the file %s. This machine may have an incompatible version of %s." ascii wide
        $s2 = "Another installation is in progress. You must complete that installation before continuing this one." ascii wide
        $s3 = ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_WPAVCDocument@@PAV3@@@" ascii wide
        $s4 = ".?AV?$CMap@PAVCDocument@@PAV1@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_W@@" ascii wide
        $s5 = "Setup needs to restart your system to complete the installation.  Do you want to restart now?" ascii wide
        $s6 = "Initialization: Failed to open %s file, Make sure the file is not used by another process." ascii wide
        $s7 = "Initialization: Unable to locate alternative INI file \"%s\", revert to the default INI." ascii wide
        $s8 = ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_WV12@PB_W@@" ascii wide
        $s9 = "This operating system is not supported by this installation.  Setup will now terminate." ascii wide
        $s10 = "Failed to extract VCRT64 command line from ini. Hence using default command line %s." ascii wide
        $s11 = ".?AV?$CMap@V?$CStringT@_WV?$StrTraitMFC@_WV?$ChTraitsCRT@_W@ATL@@@@@ATL@@PB_W_N_N@@" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}