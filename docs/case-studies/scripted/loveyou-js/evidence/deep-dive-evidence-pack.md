## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=f3e743c919c1deaf | packaging=v6.1 -->

## MalCat evidence
  File: type=text/utf8, architecture=NONE, entropy=124, sha256=f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1
  * Constants/crypto (1): crypto::Base64
  Strings (other, 300 items, omitted)

## YARA matches (6)
  Rules: domain, possible_includes_base64_packed_functions, function_through_object, contains_base64, BASE64_table, android_meterpreter

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 1375: fcn.00000000 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg_4fh, int64_t arg_68h);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg2 @ rsi
│           ; arg int64_t arg3 @ rdx
│           ; arg int64_t arg4 @ rcx
│           ; arg int64_t arg5 @ r8
│           ; arg int64_t arg6 @ r9
│           ; arg int64_t arg_4fh @ rbp+0x4f
│           ; arg int64_t arg_68h @ rbp+0x68
│       ┌─< 0x00000000      7661           jbe 0x63
│      ┌──< 0x00000002      7220           jb 0x24
│      ││   0x00000004      61             invalid
..
│      └──> 0x00000024      27             invalid
..
        │   ; XREFS: DATA 0x000001d2  DATA 0x0000027a  DATA 0x00000298  
        │   ; XREFS: DATA 0x00000321  DATA 0x0000044e  DATA 0x00000468  
        │   ; XREFS: DATA 0x00000495  DATA 0x000004e4  
      │││   ; DATA XREFS from fcn.00000000 @ 0x277(r), 0x2ca(r), 0x492(r), 0x576(r), 0x70f(r)
     ││││   ; DATA XREFS from fcn.00000000 @ 0x3a4(w), 0x5a3(w)
    │││││   ; DATA XREF from fcn.00000000 @ 0x4cd(r)
   ││││││   ; DATA XREF from fcn.00000000 @ 0x25b(w)
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x8d(w)
│ │││││ └─> 0x00000063      7737           ja 0x9c
│ │││││ ┌─< 0x00000065      44447068       jo 0xd1
│ │││││ │   ; DATA XREF from fcn.00000000 @ 0x49a(w)
│ │││││ │   0x00000069      50             push rax
│ │││││┌──< 0x0000006a      447156         jno 0xc3
│ ││││└───> 0x0000006d      6458           pop rax
│ ││││ ││   0x0000006f      57             push rdi                    ; arg1
│ ││││ ││   0x00000070      4648446948..   imul r9d, dword [rax + 0x63], 0x272c273d
│ ││││ ││   0x0000007a      4d51           push r9                     ; arg6
│ │││└┌───< 0x0000007c      7a44           jp 0xc2
│ │││┌────< 0x0000007e      724d           jb 0xcd
│ ────────< 0x00000080      4b647736       ja 0xba
│ │││││││   0x00000084      673d272c2754   cmp eax, 0x54272c27         ; '\',\'T'
│ │ │││││   0x0000008a      6c             insb byte [rdi], dx
│ │┌──────< 0x0000008b      7243           jb 0xd0
│ │││││││   0x0000008d      6a63           push 0x63                   ; 'c' ; "w7DDphPDqVdXWFHDiHc=','MQzDrMKdw6g=','TlrCjcK1w4E=','worDr8OkOBc=','e8KNbsKWBA==','XXZsw6wnJMK6eG3CrRs=','ZMKKwpMzw44Wd8Kow7NBJ3w1w4XCiT0=','wqvCtBk3K8KJUSHDsg7Cv8KHfsKSd0NDIsOJPkMhwqrCklzCpcKTw4EcQcKEHkhkAGzDsSQtEBIef8OPw7rClCcUwoAUL2TCjMOzwpbDgA==','wqdREMKJCQ==','XsK5UMO5','wqR0wpILaCFPRz9JwqjCp8KIw6UJwpbCnsKPRcK9w7tXwqzCrsKQw6PDssKTw4N
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 2998/60000 chars across 4 tools -->