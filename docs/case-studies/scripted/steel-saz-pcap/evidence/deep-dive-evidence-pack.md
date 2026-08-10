## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=58c043e134dc09b2 | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=224, sha256=58c043e134dc09b27e86973d327ab252745662f12231695f6eeb5c5deb9b691b
  Anomalies (1): LocalFileAndCentralDirectoryFieldDifferent×144 (headers)
  YARA (info, 1 total): ValuableFileExtensions
  Strings (other, 300 items, omitted)
  Virtual files (26): raw/1_c.txt, raw/1_s.txt, raw/1_m.xml, raw/2_c.txt, raw/2_s.txt, raw/2_m.xml, raw/3_c.txt, raw/3_s.txt, raw/3_m.xml, raw/4_c.txt
  Recovered structures (55): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## YARA matches (4)
  Rules: domain, IP, contains_base64, url

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 29: fcn.00000000 ();
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0000           add byte [rax], al
│           0x00000009      00d3           add bl, dl
│       ┌─< 0x0000000b      7ab5           jp 0xffffffffffffffc2
│       │   0x0000000d      52             push rdx
│       │   0x0000000e      0000           add byte [rax], al
│       │   0x00000010      0000           add byte [rax], al
│       │   0x00000012      0000           add byte [rax], al
│       │   0x00000014      0000           add byte [rax], al
│       │   0x00000016      0000           add byte [rax], al
│       │   0x00000018      0000           add byte [rax], al
│       │   0x0000001a      0400           add al, 0
└       │   0x0000001c      1f             invalid
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 1737/60000 chars across 4 tools -->