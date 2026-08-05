// yara_gen_v2.py — 2026-08-03T08:54:03.094419+00:00
rule CADRE_v2_unknown_353ab6827b75 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "353ab6827b750979ba12450e38e73669daa850445d28861f62d273492a32f68c"
        family = "unknown"
        revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "For more detailed information, please visit https://jrsoftware.org/ishelp/index.php?topic=setupcmdline" ascii wide
        $s1 = "aTEnumerator<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>(" ascii wide
        $s2 = "aTEnumerable<System.Generics.Collections.TPair<System.TClass,System.Classes.TFieldsCache.TFields>>'" ascii wide
        $s3 = "]TEnumerator<System.Generics.Collections.TPair<System.string,System.Classes.TPersistentClass>>(" ascii wide
        $s4 = "]TEnumerable<System.Generics.Collections.TPair<System.string,System.Classes.TPersistentClass>>'" ascii wide
        $s5 = "]TEnumerable<System.Generics.Collections.TPair<System.string,System.Classes.TPersistentClass>>," ascii wide
        $s6 = "\\TEnumerator<System.Generics.Collections.TPair<System.Integer,System.Classes.IInterfaceList>>(" ascii wide
        $s7 = "\\TEnumerable<System.Generics.Collections.TPair<System.Integer,System.Classes.IInterfaceList>>'" ascii wide
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>XV@" ascii wide
        $s9 = "VTEnumerator<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>(" ascii wide
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.Pointer,System.Rtti.TRttiObject>>'" ascii wide
        $s11 = "VTEnumerator<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>(" ascii wide
        $h0 = { 4D 5A 50 00 02 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}