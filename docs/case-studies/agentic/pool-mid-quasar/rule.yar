// yara_gen_v2.py — 2026-08-06T04:28:39.114926+00:00
rule CADRE_v2_unknown_cde83fd3b872 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "cde83fd3b872670a8c56376ddba525e5744dcf615174ea894aa6a2d6c9094e36"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Quasar RAT uses Windows service creation as a primary persistence mechanism, this high-signal import directly matches kn" ascii wide
        $s1 = "This ATT&CK persistence technique is a core capability of Quasar RAT, confirmed by multiple matching capa rules." ascii wide
        $s2 = "Quasar RAT commonly includes dropper functionality to deploy its payload, this YARA rule is a known indicator of Quasar " ascii wide
        $s3 = "Quasar RAT uses VirtualProtect to modify memory permissions for code injection and execution, a standard RAT evasion and" ascii wide
        $s4 = "Quasar RAT uses XOR encryption to obfuscate its payload and encrypt command-and-control communications, matching this ca" ascii wide
        $s5 = "Directly indicates the sample contains code implementing Windows service creation, a key persistence mechanism used by Q" ascii wide
        $s6 = "Quasar RAT uses runtime dynamic linking to resolve Windows APIs, a common technique to evade static import analysis and " ascii wide
        $s7 = "Quasar RAT performs registry modifications for persistence and file system operations for data exfiltration and payload " ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}