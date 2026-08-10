## Tool evidence (stage=deep_dive, signal-prioritized)
<!-- stage: deep_dive | sha=385966f3d6be7b23 | packaging=v6.1 -->

## MalCat evidence
  File: type=ZIP, architecture=NONE, entropy=215, sha256=385966f3d6be7b234a790e2dfa2573f1ab1bc72e78bce73bb479a11a54784c73
  Strings (other, 287 items, omitted)
  Virtual files (15): [Content_Types].xml, docProps/app.xml, docProps/core.xml, word/document.xml, word/fontTable.xml, word/settings.xml, word/styles.xml, word/vbaData.xml, word/vbaProject.bin, word/webSettings.xml
  Recovered structures (31): LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile, LocalFile

## YARA matches (6)
  Rules: domain, IP, docx_macro, contains_base64, Contains_VBA_macro_code, office_document_vba

## radare2 (pdf (disasm)) — 1 functions (asm)
  ### 0x00000000
```c
┌ 94: fcn.00000000 (int64_t arg1, int64_t arg4);
│           ; arg int64_t arg1 @ rdi
│           ; arg int64_t arg4 @ rcx
│           0x00000000      50             push rax
│           0x00000001      4b030414       add rax, qword [r12 + r10]
│           0x00000005      0000           add byte [rax], al
│           0x00000007      0008           add byte [rax], cl
│           0x00000009      0000           add byte [rax], al
│           0x0000000b      0021           add byte [rcx], ah          ; arg4
│           0x0000000d      005bc3         add byte [rbx - 0x3d], bl
│           0x00000010      0c0c           or al, 0xc
│           0x00000012      8801           mov byte [rcx], al          ; arg4
│       ╎   0x00000014      0000           add byte [rax], al
│      ┌──< 0x00000016      e105           loope 0x1d
│      │╎   0x00000018      0000           add byte [rax], al
│      │╎   0x0000001a      1300           adc eax, dword [rax]
│      │╎   0x0000001c  ~   0000           add byte [rax], al
│      └──> 0x0000001d      005b43         add byte [rbx + 0x43], bl
│       ╎   0x00000020      6f             outsd dx, dword [rsi]
│       ╎   0x00000021      6e             outsb dx, byte [rsi]
│      ┌──< 0x00000022      7465           je 0x89
│      │╎   0x00000024      6e             outsb dx, byte [rsi]
│     ┌───< 0x00000025      745f           je 0x86
│     ││╎   0x00000027      54             push rsp
│    ┌────< 0x00000028      7970           jns 0x9a
│   ┌─────< 0x0000002a      65735d         jae 0x8a
│ ┌───────< 0x0000002d      2e786d         js 0x9d
│ │╎││││╎   0x00000030      6c             insb byte [rdi], dx
│ │╎││││╎   0x00000031      b554           mov ch, 0x54                ; 'T'
│ │╎││││╎   0x00000033      4b4fc3         ret
..
  │╎││││╎   ; DATA XREF from fcn.00000000 @ 0x31(r)
│ ││││└───> 0x00000086      c5             invalid
..
│ ││││ └──> 0x00000089  ~   b8181d1e0c     mov eax, 0xc1e1d18          ; '\x18\x1d\x1e\f'
│ ││└─────> 0x0000008a      181d1e0c272b   sbb byte [0x2b270cae], bl
│ ││ │      0x00000090      8f             invalid
..
│ ││ └────> 0x0000009a  ~   29a39aa38158   sub dword [rbx + 0x5881a39a], esp ; [0x5881a39a:4]=-1
│ └───────> 0x0000009d      a38158388f..   movabs dword [0xbb52b968f385881], eax ; [0xbb52b968f385881:4]=-1
└       │   0x000000a6      06             invalid
```

## xorsearch
  (no XOR-encoded strings found)


<!-- evidence_assembler: used 3167/60000 chars across 4 tools -->