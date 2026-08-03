// yara_gen_v2.py — 2026-08-03T06:11:36.722407+00:00
rule CADRE_v2_unknown_6878836f0ab5 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "6878836f0ab5bdf0b1567ed45818d733c3426480251992985f6daa6f20de5b4d"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii wide
        $s1 = ".IEC 61966-2.1 Default RGB colour space - sRGB" ascii wide
        $s2 = ".IEC 61966-2.Y Default RGB colour space - sRGB" ascii wide
        $s3 = ",Reference Viewing Condition in IEC61966-2.1" ascii wide
        $s4 = "Copyright (c) 1998 Hewlett-Packard Company" ascii wide
        $s5 = "zhttp://ns.adobe.com/xap/1.0/" ascii wide
        $s6 = "SetLayeredWindowAttributes" ascii wide
        $s7 = "EVENT_SINK_QueryInterface" ascii wide
        $s8 = "__vbaGenerateBoundsError" ascii wide
        $s9 = "Adobe Photoshop CC 2018" ascii wide
        $s10 = "IEC http://www.iec.ch" ascii wide
        $s11 = "cropWhenPrintingbool" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}