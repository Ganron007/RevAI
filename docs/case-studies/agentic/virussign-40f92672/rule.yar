// yara_gen_v2.py — 2026-08-06T01:40:39.037814+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        revai = true
        revai_commit = "80c92a39d67f7e321883d3656b87cc4b04c5b7b5"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "Matches ATT&CK T1106 (Process Execution), a core malware capability for launching malicious processes or executing paylo" ascii wide
        $s1 = "Matches ATT&CK T1129 (Dynamic API Resolution), commonly used by malware to evade static analysis by resolving functions " ascii wide
        $s2 = "Matches ATT&CK T1055 (Process Injection), used by malware to allocate and modify memory for injecting malicious code int" ascii wide
        $s3 = "YARA matches confirm the sample contains indicators of common malware capabilities including privilege escalation, DEP b" ascii wide
        $s4 = "YARA matches confirm the sample is a 32-bit Windows GUI PE compiled with Borland/Delphi, consistent with runtime strings" ascii wide
        $s5 = "Large volume of Delphi RTL/VCL runtime strings confirms the sample is a functional Delphi-compiled PE, not empty or stri" ascii wide
        $h0 = { 4D 5A 50 00 02 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}