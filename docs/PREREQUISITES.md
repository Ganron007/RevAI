# Prerequisites (required before or during setup)

CADRE-RevAI expects these on the REMnux analysis VM. `install/setup-remnux.sh`
installs Python deps and will **build `ghidrasql`** when possible. Two items
are **vendor / licensed** and must be placed manually.

## Required

| Component | Expected path | How to get it |
|-----------|---------------|---------------|
| **Ghidra** | `/opt/ghidra` (with `support/analyzeHeadless`) | Official NSA/Ghidra build or REMnux package; symlink to `/opt/ghidra` if needed |
| **CADRE PE Loader** | `/opt/ghidra/Ghidra/Extensions/CADRE/` | Custom Ghidra PE loader extension — ensures import references are created for packed/binder PEs. Pre-installed on the deployment VM; source in `extensions/cadre-pe-loader/`. |
| **ghidrasql** | `/usr/local/bin/ghidrasql` | Built by `install/install-ghidrasql.sh` (clones [0xeb/libghidra](https://github.com/0xeb/libghidra) + [0xeb/ghidrasql](https://github.com/0xeb/ghidrasql); uses Ghidra's bundled Gradle wrapper) |
| **Malcat** | `/opt/malcat/bin/malcat.mcp.py` | **Optional** — download from [malcat.fr](https://malcat.fr/download.html), install under `/opt/malcat`, activate license. Pipeline runs without it (Malcat sections soft-fail). |
| **LLM API** | `/opt/cadre-v3-tools/llm.env` | Copy `config/llm.env.template` and fill model / URL / key |
| **JDK 21 + CMake** | on `PATH` | Used to build LibGhidraHost + ghidrasql (setup installs via apt when missing); Gradle is provided by Ghidra's bundled wrapper |

## Extended tool stack (V7)

These tools are wired into `TOOL_MANIFEST` and run automatically per file format. Installed on the deployment VM; the exact install steps vary by tool (see below).

| Tool | Applies to | What it does |
|------|-----------|--------------|
| **LIEF** | PE / ELF / Mach-O / dotnet | Binary structure: section entropy, imports, exports, imphash, overlay, TLS, Authenticode |
| **diec** (Detect It Easy CLI) | PE / ELF / Mach-O / dotnet | Packer / compiler / language identification |
| **pdfid** | PDF | Suspicious PDF element counts (JS, OpenAction, Launch, etc.) |
| **FindCrypt** | PE / ELF / dotnet | Crypto constant detection via Ghidra headless (124 signatures) |
| **GoReSym** | PE / ELF | Go binary symbol recovery (version, modules, functions) |
| **RIFT** | PE / ELF | Rust metadata: version, crates, architecture, compiler |
| **ilspycmd** | dotnet | .NET C# decompilation (headless ILSpy) |
| **pycdc** | unknown | Python bytecode (.pyc) decompilation |
| **scdbg** | PE (shellcode) | x86 shellcode emulation via Wine console exe |
| **ELF wrapper** | ELF | readelf/objdump/nm structural summary |
| **signature_match** | agent-callable | Function matching vs crypto/stdlib/winapi DBs |
| **z3 / angr** | agent-callable | MBA deobfuscation / CFF deflatten (extensions/deobfuscation) |

**Install notes:**
- `diec`, `pdfid`, `pycdc`, `ilspycmd`, `scdbg`: available via apt / pip (`pdfid`) on REMnux
- `GoReSym`: download `GoReSym-linux.zip` from [mandiant/GoReSym releases](https://github.com/mandiant/GoReSym/releases), extract to `/opt/goresym/`
- `RIFT`: clone [microsoft/RIFT](https://github.com/microsoft/RIFT) to `/opt/rift/`, `pip install ar lief Requests`, create `rift_config_linux.cfg` with Linux paths
- `FindCrypt`: clone [d3v1l401/FindCrypt-Ghidra](https://github.com/d3v1l401/FindCrypt-Ghidra), copy `FindCrypt.java` to `/opt/ghidra/Ghidra/Features/BytePatterns/ghidra_scripts/`, `findcrypt_ghidra/` DB to `~/`
- `signature_match` DBs: `crypto.json` / `stdlib.json` / `winapi.json` under `/opt/cadre-v4-tools/signatures/`

## Optional

| Component | Notes |
|-----------|--------|
| **IDA Pro 9.x** | `/opt/ida` + `idasql` on PATH — used alongside Ghidra when present |
| **Ghidra Function ID** | FIDB files ship with Ghidra (`Ghidra/Features/FunctionID/data/`); applied automatically during analysis |

## Malcat install (Linux)

1. Download the Linux package from https://malcat.fr/download.html  
2. Extract/install to `/opt/malcat` so that `/opt/malcat/bin/malcat.mcp.py` exists  
3. Activate per Malcat docs (`license.malcat.fr`)  
4. Confirm: `python3 /opt/malcat/bin/malcat.mcp.py --help` (or equivalent MCP entry)

Audited pipeline runs require Malcat. For non-audited runs, the pipeline works without it (`--skip-malcat` on `quick_scan_v2.py`).

## Verify

```bash
./install/verify-remnux.sh
```

Expect `Result: PASS` with ghidrasql + Ghidra + deployed scripts present (Malcat optional).
