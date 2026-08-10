// yara_gen_v2.py — 2026-08-09T14:40:33.650907+00:00
import "pe"
rule CADRE_v2_nspack_2627682eb7e8 {
    meta:
        description = "RevAI v2 auto rule for nSpack"
        sha256 = "2627682eb7e8180fc4f71017da6cde7d261668689a9dd377c69084bc826b27f5"
        family = "nspack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!packed by nspack$@" ascii wide
        $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" ascii wide
        $s2 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" ascii wide
        $s3 = "<assemblyIdentity" ascii wide
        $s4 = "name=\"Microsoft.Windows.Shell.calc\"" ascii wide
        $s5 = "processorArchitecture=\"x86\"" ascii wide
        $s6 = "version=\"5.1.0.0\"" ascii wide
        $s7 = "type=\"win32\"/>" ascii wide
        $s8 = "<description>Windows Shell</description>" ascii wide
        $s9 = "<dependency>" ascii wide
        $s10 = "<dependentAssembly>" ascii wide
        $s11 = "type=\"win32\"" ascii wide
        $h0 = { 4D 5A 40 00 01 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "4ddd9e53a5be88aaffc4455bfc877c19"
}