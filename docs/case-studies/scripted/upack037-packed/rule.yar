// yara_gen_v2.py — 2026-08-09T23:45:07.511240+00:00
rule CADRE_v2_upack_36137a22c973 {
    meta:
        description = "RevAI v2 auto rule for Upack"
        sha256 = "36137a22c973fdb6a5029319d8f69014a964f4dc998e4249d9b845f10ad013c9"
        family = "upack"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "MZKERNEL32.DLL" ascii wide
        $s1 = "LoadLibraryA" ascii wide
        $s2 = "GetProcAddress" ascii wide
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" ascii wide
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" ascii wide
        $s5 = "<assemblyIdentity" ascii wide
        $s6 = "name=\"Microsoft.Windows.Shell.calc\"" ascii wide
        $s7 = "processorArchitecture=\"x86\"" ascii wide
        $s8 = "version=\"5.1.0.0\"" ascii wide
        $s9 = "type=\"win32\"/>" ascii wide
        $s10 = "<description>Windows Shell</description>" ascii wide
        $s11 = "<dependency>" ascii wide
        $h0 = { 4D 5A 4B 45 52 4E 45 4C }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}