## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=0f02beee4c93cd48 | packaging=v6.1 -->

## MalCat evidence
  File: type=?, architecture=NONE, entropy=156, sha256=0f02beee4c93cd483befe638edd443bac7f6ccc931260613f07944f44519186a
  Strings/paths (11 total): ~qqbcTTHI@@==55...HHSS\\fglmqqttz{, rrff^^\\\\XXTTRS..#"""#"$$'&*+**"", wwdd\\UUMMBB;;4466@@NNOO<<, xymlcc[[TTLLHHHH..SRWVYY\\ccjkrs|}, on\\SRLLKJKKQQXXddmmssyy, $$01::??@@DEFFGFGGHINNTU\\hhzz, +*::ONddhh\\VWZZWVMMLLDD, ||\\KKFFJKRR]\edllttwwjjNO*+, \\BBA@LM]]ffihdd\]TTRS_^||, 01<<CBGGOO\\ffdeaa[[KJ, ##(),-003276;;BB..PPWV\\bbkjqqvv}|
  Strings (other, 289 items, omitted)

## YARA matches (4)
  Rules: domain, IP, contains_base64, maldoc_indirect_function_call_3

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 38: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           0x00000000      52             push rdx                    ; arg3
│           0x00000001      494646209f..   and byte [rdi + 0x415700e7], r11b ; [0x415700e7:1]=255 ; arg1
│           0x0000000a      56             push rsi                    ; arg2
│           0x0000000b      45666d         insw word [rdi], dx
│       ┌─< 0x0000000e      7420           je 0x30
│       │   0x00000010      1000           adc byte [rax], al
│       │   0x00000012      0000           add byte [rax], al
│       │   0x00000014      0100           add dword [rax], eax
│       │   0x00000016      0200           add al, byte [rax]
│       │   0x00000018      44ac           lodsb al, byte [rsi]
│       │   0x0000001a      0000           add byte [rax], al
│       │   0x0000001c      10b102000400   adc byte [rcx + 0x40002], dh ; arg4
│       │   0x00000022      1000           adc byte [rax], al
│       │   0x00000024      64             invalid
..
└      │└─> 0x00000030      06             invalid
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 1969/60000 chars across 4 tools -->