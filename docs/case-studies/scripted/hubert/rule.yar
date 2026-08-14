// yara_gen_v2.py — 2026-08-12T20:23:18.326384+00:00
import "pe"
rule CADRE_v2_trojan_tibs_0598e95ea5f2 {
    meta:
        description = "RevAI v2 auto rule for Trojan.Tibs"
        sha256 = "0598e95ea5f28e3e591a8ab26bd6794e06f038282cac8ecf302009c6636cd0bc"
        family = "trojan_tibs"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "!This program cannot be run in DOS mode." ascii wide
        $s1 = "Pkdpqmjwl" ascii wide
        $s2 = "`a%u`wvjk%qwl`v%qj%vq`di%|jpw%udvvrjwav%dka%uwlsdq`%lkcjwhdqljk+%Filfn%jk%qm`%h`vvdb`%qj%uw`s`kq%la`kqlq|%qm`cq+" ascii wide
        $s3 = "Pkdpqmjvwl" ascii wide
        $s4 = "`a%dff`vv%qj%|jpw%fjhupq`w$%Filfn%jk%qm`%h`vvdb`%qj%lkvqdii%pu(qj(adq`%dkqlslwpv%vjcqrdw`+" ascii wide
        $s5 = "Mdwhcpi%slwpv`v%a`q`fq`a%jk%|jpw%fjhupq`w+%Filfn%jk%qm`%h`vvdb`%qj%vfdk%|jpw%fjhupq`w%cjw%v`fpwlq|%qmw`dqv%cjw%cw``+" ascii wide
        $s6 = "<1=51=354163<2766<6<<2062567<160<255<2245757" ascii wide
        $s7 = "A`c`kv`%F`kq`w" ascii wide
        $s8 = "Software\\" ascii wide
        $s9 = "\\license.dat" ascii wide
        $s10 = "a`cfkq+`}`" ascii wide
        $s11 = "Windows Security Alert" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "c69e7c5c6b975b5dd44f2d4469eea107"
}