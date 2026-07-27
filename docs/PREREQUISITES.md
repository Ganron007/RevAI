# Prerequisites (required before or during setup)

CADRE-RevAI expects these on the REMnux analysis VM. `install/setup-remnux.sh`
installs Python deps and will **build `ghidrasql`** when possible. Two items
are **vendor / licensed** and must be placed manually.

## Required

| Component | Expected path | How to get it |
|-----------|---------------|---------------|
| **Ghidra** | `/opt/ghidra` (with `support/analyzeHeadless`) | Official NSA/Ghidra build or REMnux package; symlink to `/opt/ghidra` if needed |
| **ghidrasql** | `/usr/local/bin/ghidrasql` | Built by `install/install-ghidrasql.sh` (clones [0xeb/libghidra](https://github.com/0xeb/libghidra) + [0xeb/ghidrasql](https://github.com/0xeb/ghidrasql); uses Ghidra's bundled Gradle wrapper) |
| **Malcat** | `/opt/malcat/bin/malcat.mcp.py` | **Optional** — download from [malcat.fr](https://malcat.fr/download.html), install under `/opt/malcat`, activate license. Pipeline runs without it (`--skip-malcat`). |
| **LLM API** | `/opt/cadre-v3-tools/llm.env` | Copy `config/llm.env.template` and fill model / URL / key |
| **JDK 21 + CMake** | on `PATH` | Used to build LibGhidraHost + ghidrasql (setup installs via apt when missing); Gradle is provided by Ghidra's bundled wrapper |

## Optional

| Component | Notes |
|-----------|--------|
| **IDA Pro 9.x** | `/opt/ida` + `idasql` on PATH — used alongside Ghidra when present |

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
