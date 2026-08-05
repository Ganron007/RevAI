// yara_gen_v2.py — 2026-08-05T05:26:10.684374+00:00
rule CADRE_v2_unknown_28ea44a49cb4 {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "28ea44a49cb4277edb82609efa4af573d953cdaa77a1973e3e7fc412b97450a9"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "_ZNK10__cxxabiv120__si_class_type_info12__do_dyncastExNS_17__class_type_info10__sub_kindEPKS1_PKvS4_S6_RNS1_16__dyncast_resultE" ascii wide
        $s1 = ".xdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s2 = ".pdata$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s3 = ".text$_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s4 = ".xdata$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE" ascii wide
        $s5 = ".pdata$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE" ascii wide
        $s6 = ".text$_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE" ascii wide
        $s7 = "_ZNK10__cxxabiv117__class_type_info12__do_dyncastExNS0_10__sub_kindEPKS0_PKvS3_S5_RNS0_16__dyncast_resultE" ascii wide
        $s8 = "_ZNK10__cxxabiv120__si_class_type_info11__do_upcastEPKNS_17__class_type_infoEPKvRNS1_15__upcast_resultE" ascii wide
        $s9 = ".xdata$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_" ascii wide
        $s10 = ".pdata$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_" ascii wide
        $s11 = ".text$_ZNK10__cxxabiv120__si_class_type_info20__do_find_public_srcExPKvPKNS_17__class_type_infoES2_" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}