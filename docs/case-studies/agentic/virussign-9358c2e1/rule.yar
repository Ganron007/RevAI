// yara_gen_v2.py — 2026-08-03T13:02:12.036635+00:00
rule CADRE_v2_unknown_c7e2c9b73000 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "c7e2c9b730007847a0942a90087f4b0d7a5c553f8e59bc10edcd11fbd222cfd5"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "GetUserProfileDirectoryW" ascii wide
        $s1 = "GetAdaptersAddresses" ascii wide
        $s2 = "GetProcessMemoryInfo" ascii wide
        $s3 = "VirtualProtect" ascii wide
        $s4 = "CertOpenStore" ascii wide
        $s5 = "ADVAPI32.dll" ascii wide
        $s6 = "IPHLPAPI.DLL" ascii wide
        $s7 = "KERNEL32.DLL" ascii wide
        $s8 = "LoadLibraryA" ascii wide
        $s9 = "CRYPT32.dll" ascii wide
        $s10 = "USERENV.dll" ascii wide
        $s11 = "ExitProcess" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}