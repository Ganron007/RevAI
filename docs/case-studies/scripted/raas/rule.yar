// yara_gen_v2.py — 2026-08-12T21:21:56.611912+00:00
import "pe"
rule CADRE_v2_ransomware_shaitan_troldesh_c04836696d71 {
    meta:
        description = "RevAI v2 auto rule for ransomware.shaitan/troldesh"
        sha256 = "c04836696d715c544382713eebf468aeff73c15616e1cd8248ca8c4c7e931505"
        family = "ransomware_shaitan_troldesh"
        revai = true
        revai_commit = "unknown"
        revai_engine = "langgraph"
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "wpespy.dll" ascii wide
        $s1 = "pstorec.dll" ascii wide
        $s2 = "avghookx.dll" ascii wide
        $s3 = "HARDWARE\\DESCRIPTION\\System" ascii wide
        $s4 = "avghooka.dll" ascii wide
        $s5 = "dwmapi.dll" ascii wide
        $s6 = "VideoBiosVersion" ascii wide
        $s7 = "SOFTWARE\\VMware, Inc.\\VMware Tools" ascii wide
        $s8 = "SystemBiosVersion" ascii wide
        $s9 = "ollydbg.exe" ascii wide
        $s10 = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" ascii wide
        $s11 = "WinDbgFrameClass" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them or pe.imphash() == "b53f6e0803fd24f3dd50f45f3b463d3f"
}