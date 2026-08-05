// yara_gen_v2.py — 2026-08-04T05:20:31.859168+00:00
rule CADRE_v2_unknown_e29d2bd94621 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "e29d2bd946212328bcdf783eb434e1b384445f4c466c5231f91a07a315484819"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "No mapping for the Unicode character exists in the target multi-byte code page" ascii wide
        $s1 = "Cannot have multiple single cast observers added to the observers collection" ascii wide
        $s2 = "No single cast observer with ID %d was added to the observer collection" ascii wide
        $s3 = "No multi cast observer with ID %d was added to the observer collection" ascii wide
        $s4 = "Cannot call BeginInvoke on a TComponent in the process of destruction" ascii wide
        $s5 = "CheckSynchronize called from thread $%x, which is NOT the main thread" ascii wide
        $s6 = "Access violation at address %p in module '%s'. %s of address %p" ascii wide
        $s7 = "Overflow while converting variant of type (%s) into type (%s)" ascii wide
        $s8 = "Type '%s' is not declared in the interface section of a unit" ascii wide
        $s9 = "Pringle Setup" ascii wide
        $s10 = "%s Service Pack %4:d (Version %1:d.%2:d, Build %3:d, %5:s)" ascii wide
        $s11 = "VAR and OUT arguments must match parameter type exactly" ascii wide
        $h0 = { 4D 5A 50 00 02 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}