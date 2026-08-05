# Tool Stack (24 tools)

The pipeline runs **24 tools automatically** via `TOOL_MANIFEST`, plus **agent-callable
tools** in the deep-dive `ToolRegistry`. All tools are format-aware — each runs only
when it applies to the sample's file type.

## Core tools

| Tool | What it does |
| :--- | :--- |
| **Ghidra** (SQL-first) | Static analysis via ghidrasql — functions, imports, strings, decompile |
| **IDA Pro** (optional) | Same SQL-first analysis via idasql when installed |
| **Malcat** | Native capa engine + full MCP analysis (triage views, constants, anomalies, decompile) |
| **capa** | Capability detection (Mandiant fallback when Malcat absent) |
| **FLOSS** | Obfuscated/decoded/stack strings |
| **YARA** | Signature scanning (in-process yara-x engine) |
| **radare2** | Disassembly / decompile |
| **Speakeasy** | Windows API emulation |
| **Frida** | Static probe + runtime trace |
| **oletools** | Office/VBA macro analysis |
| **pefile / LIEF** | PE structure, entropy, imports, overlay, TLS |
| **z3** | MBA / opaque-predicate verification |
| **angr** | CFF-deflatten / symbolic execution |

## Extended tools

| Tool | Applies to | What it does |
| :--- | :--- | :--- |
| **LIEF** | PE / ELF / Mach-O / dotnet | Binary structure: sections, entropy, imports, exports, imphash, overlay, TLS, Authenticode |
| **diec** (Detect It Easy CLI) | PE / ELF / Mach-O / dotnet | Packer / compiler / language identification |
| **pdfid** | PDF | Suspicious PDF element counts (JS, OpenAction, Launch, …) |
| **FindCrypt** | PE / ELF / dotnet | Crypto constant detection via Ghidra headless (124 signatures) |
| **GoReSym** | PE / ELF | Go binary symbol recovery (version, modules, functions) |
| **RIFT** | PE / ELF | Rust metadata: version, crates, architecture, compiler |
| **ilspycmd** | dotnet | .NET C# decompilation (headless ILSpy) |
| **pycdc** | unknown | Python bytecode (.pyc) decompilation |
| **scdbg** | PE (shellcode) | x86 shellcode emulation via Wine console exe |
| **ELF wrapper** | ELF | readelf/objdump/nm structural summary |
| **signature_match** | agent-callable | Function matching vs crypto/stdlib/winapi DBs |
| **z3 / angr** | agent-callable | MBA deobfuscation / CFF deflatten |

## Agent-callable tools (deep-dive ToolRegistry)

ghidra_query · ida_query · ghidra_decompile · signature_match · z3_solve · angr_analyze
· malcat_analyze · capa_analyze · pe_import_signals · yara_scan · floss_extract ·
dotnet_analyze · speakeasy_emulate · frida_static_probe · r2_decompile · upx_unpack ·
xor_string_search · olevba_analyze · peepdf_analyze

## Format-aware routing

`TOOL_MANIFEST` declares each tool's `applies_to` formats and a wall-clock timeout.
The runner only executes tools that apply to the detected file type — Speakeasy is
never required for .NET, FLOSS is never run on ELF, etc. — and each tool's timeout is
enforced so a hung scanner cannot stall the pipeline.

## Related

- Per-tool operational details: [`docs/OPERATE.md`](OPERATE.md)
- Install/prereqs: [`docs/PREREQUISITES.md`](PREREQUISITES.md)
