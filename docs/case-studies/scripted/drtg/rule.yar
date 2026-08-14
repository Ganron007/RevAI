// yara_gen_v2.py — 2026-08-12T20:01:58.690028+00:00
import "pe"
rule CADRE_v2_satana_ransomware_683a09da2199 {
    meta:
        description = "RevAI v2 auto rule for Satana ransomware"
        sha256 = "683a09da219918258c58a7f61f7dc4161a3a7a377cf82a31b840baabfb9a4a96"
        family = "satana_ransomware"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "ZwProtectVirtualMemory" ascii wide
        $s1 = "ZwWriteVirtualMemory" ascii wide
        $s2 = "GetModuleFileNameW" ascii wide
        $s3 = "FlushInstructionCache" ascii wide
        $s4 = "ZwUnmapViewOfSection" ascii wide
        $s5 = "NtAllocateVirtualMemory" ascii wide
        $s6 = "?456789:;<=" ascii wide
        $s7 = "!\"#$%&'()*+,-./0123" ascii wide
        $s8 = "SetUnhandledExceptionFilter" ascii wide
        $s9 = "RtlDecompressBuffer" ascii wide
        $s10 = "!This program cannot be run in DOS mode." ascii wide
        $s11 = "ntdll.dll" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "a3bc0305643e7601d6deca72652f4ab5"
}