// yara_gen_v2.py — 2026-08-05T05:00:02.988670+00:00
rule CADRE_v2_unknown_ba3558c89e9f {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "ba3558c89e9ff2e308d3191c9b8717c6462a0763a46f25730f09ab56e55c65c7"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = ".?AU?$IServicesNotificationCallback@UIConnectedService@OfficeServicesManager@Mso@@@OfficeServicesManager@Mso@@" ascii wide
        $s1 = "ERROR : Unable to initialize critical section in CAtlBaseModule" ascii wide
        $s2 = "Microsoft® is a registered trademark of Microsoft Corporation." ascii wide
        $s3 = "Windows® is a registered trademark of Microsoft Corporation." ascii wide
        $s4 = "IsolationAware function called after IsolationAwareCleanup" ascii wide
        $s5 = "%LOCALAPPDATA%\\Microsoft\\Office\\16.0\\Lync\\Tracing" ascii wide
        $s6 = "Software\\Microsoft\\Office\\16.0\\Common\\FilesPaths" ascii wide
        $s7 = "OC_CONTENT_WHITEBOARDANNOTATIONLOCATIONFILTER" ascii wide
        $s8 = "OC_WEBSERVICE2_HANGINGNOTIFICATIONPROVIDER" ascii wide
        $s9 = "_register_thread_local_exe_atexit_callback" ascii wide
        $s10 = "P:\\Target\\x64\\ship\\lync\\x-none\\lync99.pdb" ascii wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}