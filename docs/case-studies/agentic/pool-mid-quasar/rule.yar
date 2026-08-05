// yara_gen_v2.py — 2026-08-04T06:23:04.871124+00:00
rule CADRE_v2_unknown_cde83fd3b872 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "RegisterServiceCtrlHandlerW" ascii wide
        $s1 = "StartServiceCtrlDispatcherW" ascii wide
        $s2 = "SetUnhandledExceptionFilter" ascii wide
        $s3 = "SHGetSpecialFolderLocation" ascii wide
        $s4 = "InitializeCriticalSection" ascii wide
        $s5 = "UnhandledExceptionFilter" ascii wide
        $s6 = "GetSystemTimeAsFileTime" ascii wide
        $s7 = "QueryPerformanceCounter" ascii wide
        $s8 = "SetEnvironmentVariableW" ascii wide
        $s9 = "RtlLookupFunctionEntry" ascii wide
        $s10 = "DeleteCriticalSection" ascii wide
        $s11 = "QueryServiceStatusEx" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}