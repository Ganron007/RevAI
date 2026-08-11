# Tool Stack (28 tools)

The pipeline runs **28 tools automatically** via `TOOL_MANIFEST`, plus **agent-callable
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
| **emulation_oracle** (`emulation_oracle.py`) | PE (all) | Bounded Speakeasy pass: dynamically resolved imports, executed-address mapping to functions, memory regions. Env-gated (`REVAI_ENABLE_EMULATION_ORACLE=1`), runs in deep-dive; evidence persisted `deep_dive/03-oracle.json` and surfaced to the agent. Oracle only — never verdicts |
| **Frida** | Static probe + runtime trace |
| **oletools** | Office/VBA macro analysis |
| **pefile / LIEF** | PE structure, entropy, imports, overlay, TLS |
| **z3** | MBA / opaque-predicate verification |
| **angr** | CFF-deflatten / symbolic execution (pipx venv; enabled via `ENABLE_DEOBFUSCATION_PASS=1`) |
| **revai-tools** (`revai_tools_sec`) | PE / ELF | Mitigations-with-consequence: PE claim-vs-fact (ASLR/DEP/CFG/GS per section flags) and ELF header-fact findings, each with an exploitation consequence note. Runs in quick_scan phase-A and the deep-dive checklist; fail-open — evidence only, never gates |
| **revai-tools** (`revai_tools_sinks`) | PE / ELF / dotnet | Dangerous-API call sites (memcpy, recv, system, …) located inside named functions via radare2 (r2); honest 0-site results recorded. Runs in quick_scan phase-A and the deep-dive checklist; fail-open |
| **revai-tools** (`revai_tools_audit`) | PE / ELF / dotnet | Sink sites with exploitable argument provenance: constant-length vs subtraction/register-source patterns, sink reachability from entry. Deep-dive checklist + agent-callable; fail-open |
| **revai-tools** (`revai_tools_iocs`) | PE / ELF / dotnet / scripts | IOC-export extension: cryptocurrency wallets (BTC/ETH) + defanged IOC merge into `iocs.json` (yara_gen) |

## Extended tools

| Tool | Applies to | What it does |
| :--- | :--- | :--- |
| **LIEF** | PE / ELF / Mach-O / dotnet | Binary structure: sections, entropy, imports, exports, imphash, overlay, TLS, Authenticode |
| **diec** (Detect It Easy CLI) | PE / ELF / Mach-O / dotnet | Packer / compiler / language identification |
| **packer_intake** (`packer_intake.py`) | PE | Deterministic packer-suspicion checklist + section entropy: exec/writable sections, EP location, raw-vs-virtual mismatch, memory-only sections, exec-section entropy, few-imports with loader APIs, embedded-payload hint. Runs in quick_scan Phase A; feeds the evidence pack |
| **pdfid** | PDF | Suspicious PDF element counts (JS, OpenAction, Launch, …) |
| **FindCrypt** | PE / ELF / dotnet | Crypto constant detection via Ghidra headless (124 signatures) |
| **GoReSym** | PE / ELF | Go binary symbol recovery (version, modules, functions) |
| **RIFT** | PE / ELF | Rust metadata: version, crates, architecture, compiler |
| **ilspycmd** | dotnet | .NET C# decompilation (headless ILSpy) |
| **pycdc** | unknown | Python bytecode (.pyc) decompilation |
| **scdbg** | PE (shellcode) | x86 shellcode emulation via Wine console exe |
| **unpack_oracle** (`unpack_oracle.py`) | PE (packed) | Emulation-assisted generic unpacking: detects memory-only executable sections, polls the emulated PC for the OEP transition, and carves the unpacked image from emulated memory (FixDump-style raw=virtual rebuild). Output: `unpacked_<name>` payload + OEP + in-memory import/IAT readout. Env-gated (`REVAI_ENABLE_UNPACK_PASS=1`), runs in deep-dive when the packer checklist flags the sample; artifacts under `logs/<sha>/unpack/` |
| **ELF wrapper** | ELF | readelf/objdump/nm structural summary |
| **signature_match** | agent-callable | Function matching vs crypto/stdlib/winapi DBs |
| **z3 / angr** | agent-callable | MBA deobfuscation / CFF deflatten |

## Agent-callable tools (deep-dive ToolRegistry)

ghidra_query · ida_query · ghidra_decompile · signature_match · z3_solve · angr_analyze
· malcat_analyze · capa_analyze · pe_import_signals · yara_scan · floss_extract ·
dotnet_analyze · speakeasy_emulate · frida_static_probe · r2_decompile · upx_unpack ·
xor_string_search · olevba_analyze · peepdf_analyze · revai_tools_sec ·
revai_tools_sinks · revai_tools_audit

## Format-aware routing

`TOOL_MANIFEST` declares each tool's `applies_to` formats and a wall-clock timeout.
The runner only executes tools that apply to the detected file type — Speakeasy is
never required for .NET, FLOSS is never run on ELF, etc. — and each tool's timeout is
enforced so a hung scanner cannot stall the pipeline.

## revai-tools integration

`revai_tools_*` wrappers (in `v2_lib.py`) invoke the **revai-tools** package
(`revai_tools.cli` subprocess), which ships in this repo at `revai/revai_tools/`
(deployed to `/opt/scripts/revai_tools`). All four are **fail-open**: an error,
timeout, or format mismatch is recorded (`error`/`skipped` +
`reason:not_applicable:<fmt>`) and never gates a stage. Results persist in
`quick_scan/00-tools-raw.json` (`revai_tools_sec` / `revai_tools_sinks`), the
deep-dive evidence pack, and `iocs.json` (`revai_tools` provenance block).

## Related

- Per-tool operational details: [`docs/OPERATE.md`](OPERATE.md)
- Install/prereqs: [`docs/PREREQUISITES.md`](PREREQUISITES.md)
