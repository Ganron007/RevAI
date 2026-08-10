## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=9feae4f91d053d1e | packaging=v6.1 -->

## MalCat evidence
  File: type=?, architecture=NONE, entropy=100, sha256=9feae4f91d053d1e59217f84b90a20efbc42987db93af12ae738915c12db370f
  Strings (other, 37 items, omitted)

## YARA matches (3)
  Rules: domain, contains_base64, Cobalt_functions

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 7: fcn.00000000 ();
│           0x00000000      fc             cld
│           0x00000001      e82e2e2e2e     call 0x2e2e2e34
└           0x00000006      60             invalid
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 541/60000 chars across 4 tools -->