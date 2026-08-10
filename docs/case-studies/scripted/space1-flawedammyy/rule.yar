// yara_gen_v2.py — 2026-08-09T16:37:08.302644+00:00
import "pe"
rule CADRE_v2_unknown_5f251ed33fb1 {
    meta:
        description = "RevAI v2 auto rule for unknown"
        sha256 = "5f251ed33fb1b6960b4d5641b44b44f67277765aa69649977a27ec79cb6153da"
        family = "unknown"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "QueryPerformanceFrequency" ascii wide
        $s1 = "QueryPerformanceCounter" ascii wide
        $s2 = "IsBadCodePtr" ascii wide
        $s3 = "!This program cannot be run in DOS mode." ascii wide
        $s4 = "VC20XC00U" ascii wide
        $s5 = "UQPXY]Y[" ascii wide
        $s6 = "bad allocation" ascii wide
        $s7 = "kernel32.dll" ascii wide
        $s8 = "&*^@QDSJGIO" ascii wide
        $s9 = "&JTEH$WHD" ascii wide
        $s10 = "V><MDNbyfui6y2iuow" ascii wide
        $s11 = "fliudsifIUJGowpdury2387ihdtfkj56uy34e3wopefjawhe78yr632894iorpdkjfiut8fr3w87r632498yuwqfijwhqiuhtroi3j21932y6" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "1905143b6a38c11e2b30615cb955fd08"
}