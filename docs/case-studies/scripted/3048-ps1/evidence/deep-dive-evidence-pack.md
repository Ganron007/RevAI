## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=14a42d6418b38103 | packaging=v6.1 -->

## MalCat evidence
  File: type=text/utf8, architecture=NONE, entropy=148, sha256=14a42d6418b38103a7fdccc5b1d37e4fb0efcad2f847c9996465c5fdc78632c2
  YARA (signal): Powershell
  YARA (info, 1 total): RunShell
  Strings/suspicious (2 total): powershell
  Strings/apis (9 total): StreamReader, ProcessStartInfo, UseShellExecute, WindowsPowerShell, MemoryStream, CreateNoWindow, FileName, ReadToEnd, WindowStyle
  Strings (other, 98 items, omitted)

## YARA matches (5)
  Rules: domain, powershell, IP, contains_base64, Antivirus

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 1906: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_31h, int64_t arg_32h, int64_t arg_36h, int64_t arg_41h, int64_t arg_49h, int64_t arg_4ah, int64_t arg_56h, int64_t arg_63h, int64_t arg_6ah, int64_t arg_79h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_31h @ rbp+0x31
│           ; arg int64_t arg_32h @ rbp+0x32
│           ; arg int64_t arg_36h @ rbp+0x36
│           ; arg int64_t arg_41h @ rbp+0x41
│           ; arg int64_t arg_49h @ rbp+0x49
│           ; arg int64_t arg_4ah @ rbp+0x4a
│           ; arg int64_t arg_56h @ rbp+0x56
│           ; arg int64_t arg_63h @ rbp+0x63
│           ; arg int64_t arg_6ah @ rbp+0x6a
│           ; arg int64_t arg_79h @ rbp+0x79
│           0x00000000      6966285b49..   imul esp, dword [rsi + 0x28], 0x746e495b
│           0x00000007      50             push rax
│       ┌─< 0x00000008      7472           je 0x7c
│       │   0x0000000a      5d             pop rbp
│       │   0x0000000b      3a3a           cmp bh, byte [arg_49h]      ; arg3
│       │   0x0000000d      53             push rbx
│       │   0x0000000e      697a65202d..   imul edi, dword [rdx + 0x65], 0x71652d20
│       │   0x00000015      203429         and byte [rcx + rbp], dh    ; arg4
│      ┌──< 0x00000018      7b24           jnp 0x3e
│      ││   0x0000001a      62             invalid
..
    │││││   ; DATA XREF from fcn.00000000 @ 0x1a0(w)
│  ││││└──> 0x0000003e      657253         jb 0x94
│  ││││││   ; DATA XREF from fcn.00000000 @ 0x70e(w)
│  ││││││   0x00000041      68656c6c5c     push 0x5c6c6c65             ; 'ell\\'
│ ┌───────< 0x00000046      7631           jbe 0x79
│ │││││││   0x00000048      2e305c706f     xor byte cs:[rax + rsi*2 + 0x6f], bl
│ │││││││   ; DATA XREF from fcn.00000000 @ 0x6aa(r)
│ ────────< 0x0000004d      7765           ja 0xb4
│ ────────< 0x0000004f      7273           jb 0xc4
│ │││││││   0x00000051      68656c6c2e     push 0x2e6c6c65             ; 'ell.'
│ ────────< 0x00000056      657865         js 0xbe
│ │││││││   0x00000059      27             invalid
  │││││││   ; DATA XREFS from fcn.00000000 @ 0x72c(r), 0x7b7(r)
..
  │││││││   ; DATA XREF from fcn.00000000 @ 0xb3(r)
  │││││││   ; DATA XREF from fcn.00000000 @ 0x3e4(w)
  │││││││   ; DATA XREF from fcn.00000
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 3141/60000 chars across 4 tools -->