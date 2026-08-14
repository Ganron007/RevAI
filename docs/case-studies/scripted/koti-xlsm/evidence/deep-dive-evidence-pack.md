## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=8e516c5e0ca2a7ff | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=195, sha256=8e516c5e0ca2a7ffed56b38b8e10544653d4fa3b9c647895b1967eba16ae025e
  Strings (other, 300 items, omitted)
  Virtual files (24): [Content_Types].xml, _rels/.rels, xl/_rels/workbook.xml.rels, xl/workbook.xml, xl/theme/theme1.xml, xl/macrosheets/sheet1.xml, xl/worksheets/_rels/sheet1.xml.rels, xl/macrosheets/_rels/sheet1.xml.rels, xl/worksheets/_rels/sheet2.xml.rels, xl/drawings/_rels/drawing1.xml.rels
  Recovered structures (49): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## YARA matches (2)
  Rules: domain, contains_base64

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 24: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0006           add byte [rsi], al          ; arg2
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      00888fbe01c2   add byte [rax - 0x3dfe4171], cl
│           0x00000013      0100           add dword [rax], eax
│           0x00000015      0007           add byte [rdi], al          ; arg1
└           0x00000017      07             invalid
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 1681/60000 chars across 4 tools -->