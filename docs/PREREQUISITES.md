# Prerequisites (required before or during setup)

RevAI expects these on the REMnux analysis VM. `install/setup-remnux.sh`
installs Python deps and will **build `ghidrasql`** when possible. Two items
are **vendor / licensed** and must be placed manually.

> **Malcat is optional, not required.** The pipeline fully works without it —
> every Malcat-dependent stage soft-fails and falls back to other engines
> (Mandiant capa, FLOSS, pe_imports, Ghidra). We strongly **recommend** it
> because its native capa engine is measurably faster and more reliable (see
> [Why Malcat's capa engine](#why-malcats-capa-engine)). Not everyone can use
> commercial tools — that is respected.

## Required

| Component | Expected path | How to get it |
|-----------|---------------|---------------|
| **Ghidra** | `/opt/ghidra` (with `support/analyzeHeadless`) | Official NSA/Ghidra build or REMnux package; symlink to `/opt/ghidra` if needed |
| **CADRE PE Loader** | `/opt/ghidra/Ghidra/Extensions/CADRE/` | Custom Ghidra PE loader extension — ensures import references are created for packed/binder PEs. Pre-installed on the deployment VM; source in `extensions/cadre-pe-loader/`. |
| **ghidrasql** | `/usr/local/bin/ghidrasql` | Built by `install/install-ghidrasql.sh` (clones [0xeb/libghidra](https://github.com/0xeb/libghidra) + [0xeb/ghidrasql](https://github.com/0xeb/ghidrasql); uses Ghidra's bundled Gradle wrapper) |
| **LLM API** | `/opt/revai/config/llm.env` | Copy `config/llm.env.template` and fill model / URL / key |
| **JDK 21 + CMake** | on `PATH` | Used to build LibGhidraHost + ghidrasql (setup installs via apt when missing); Gradle is provided by Ghidra's bundled wrapper |

## Recommended (optional): Malcat

| Component | Expected path | How to get it |
|-----------|---------------|---------------|
| **Malcat** | `/opt/malcat/bin/malcat.mcp.py` + `malcat.capa.py` | **Optional** — download from [malcat.fr](https://malcat.fr/download.html), install under `/opt/malcat`, activate license. Pipeline soft-fails without it. |

**What you get:** Malcat provides (1) its native **capa engine** (`malcat.capa.py`) used as the primary capability detector, and (2) a full static-analysis MCP server (`malcat.mcp.py`) for triage views, constants, anomalies, and carved files.

**Install:**
1. Download the Linux package from https://malcat.fr/download.html (Ubuntu 24.04 build)
2. **Rename the downloaded archive to `malcat.zip`** and drop it at `internal/malcat.zip` in this repo — the setup script auto-installs from there (any Malcat version works; we intentionally don't hardcode a version suffix)
3. Extract to `/opt/malcat` so `/opt/malcat/bin/malcat.mcp.py` exists (or let `install/setup-remnux.sh` do it)
4. Install Python deps: `sudo pip3 install --break-system-packages -r /opt/malcat/requirements.txt`
5. Register the native module: `sudo bash -c 'echo /opt/malcat/bin > /usr/lib/python3/dist-packages/malcat.pth'`
6. Activate your license (run the GUI once, or the activation flow per Malcat docs)

`install/setup-remnux.sh` includes an **optional Malcat step** that performs steps 2–4 automatically if the archive is present at `internal/malcat.zip`; it soft-fails (warns and continues) if the archive is missing or the install errors.

### Why Malcat's capa engine

Measured 10-sample benchmark on real malware (Malcat 0.9.15 native vs Mandiant capa 9.4.0 vs capa-rs):

| Metric | Winner |
|--------|--------|
| **Speed** | **Malcat** — ~1–7s on all 10 samples; Mandiant 0.6–145s when it finishes, 3/10 timeout at 300s |
| **Reliability** | **Malcat** — 10/10 OK; Mandiant 7/10; capa-rs 2/10 (SMDA/parse failures) |
| **Usable signal on hard samples (3–8 MB, installer/packer-packed)** | **Malcat only** — Mandiant times out |

Full per-sample table is in the top-level [`README.md`](../README.md#why-malcats-capa-engine). If Malcat is absent, the pipeline falls back to Mandiant capa automatically — results are still honest, just potentially slower or incomplete on hard samples.

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
- `signature_match` DBs: `crypto.json` / `stdlib.json` / `winapi.json` under `/opt/revai/signatures/`

## Optional

| Component | Notes |
|-----------|--------|
| **IDA Pro 9.x** | `/opt/ida` + `idasql` on PATH — used alongside Ghidra when present |
| **Ghidra Function ID** | FIDB files ship with Ghidra (`Ghidra/Features/FunctionID/data/`); applied automatically during analysis |

## Verify

```bash
./install/verify-remnux.sh
```

Expect `Result: PASS` with ghidrasql + Ghidra + deployed scripts present (Malcat and IDA optional — the verifier soft-fails on their absence).
