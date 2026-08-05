# CADRE PE Loader — Custom Ghidra Extension

RevAI ships its **own custom Ghidra PE loader** — a differentiator you won't find in
stock Ghidra or other RE pipelines.

## The problem it solves

Ghidra's stock `PeLoader` sometimes fails to create external references for PE import
tables on:

- **Packed** executables (UPX, Themida, VMProtect, …)
- **Binder / dropper** outer PE images
- PEs with **non-standard import-directory layouts**

Downstream tools (ghidrasql, capa, import analysis) then see an empty `imports` table
even though the binary calls dozens of Windows APIs — silently starving the evidence
pack that the agentic deep dive and LLM verdict rely on.

## What `CADREPeLoader` does

`CADREPeLoader` extends Ghidra's stock `PeLoader` with a **robust second pass over the
import descriptor table**:

1. **Delegates to the stock loader** — all normal PE loading (memory blocks, headers,
   exports) is handled by the parent `PeLoader`.
2. **Disables heavy analyzers** — skips `Decompiler Parameter ID`, `WindowsPE RTTI
   Analyzer`, and `Symbolic Propagator` by default for faster headless import.
3. **Import fixup pass** — walks the import descriptor table and for every import entry:
   - Creates pointer data at the IAT slot (if missing or not a pointer)
   - Creates an `ExternalReference` for `dll!name` at the IAT address
   - Handles both named and ordinal imports
   - Skips entries that already have external references (idempotent)

## Architecture

```
CADREPeLoader extends PeLoader
├── findSupportedLoadSpecs()  — delegates to stock PE detection
├── load()                    — calls super.load(), then fixupImports()
├── disableHeavyAnalyzers()   — turns off slow analyzers for headless
└── fixupImports()            — second-pass import descriptor walk
    └── processImportDirectory()
        ├── reads ImportDataDirectory
        ├── walks each ImportDescriptor → DLL
        ├── walks each ThunkData → function name or ordinal
        ├── creates Pointer data at IAT slot
        └── adds ExternalReference (dll, name, SourceType.IMPORTED)
```

## Why it matters

Packed/binder samples get a **real, populated import table in the SQL evidence** —
which means the agentic deep dive and LLM verdict see the actual API surface instead
of an empty table. The pipeline uses it automatically during intake.

## Installation

The extension is pre-installed on the deployment VM at
`/opt/ghidra/Ghidra/Extensions/CADRE/` (installed by `install/setup-remnux.sh`).

To rebuild from source (on a machine with `GHIDRA_HOME` set):

```bash
cd extensions/cadre-pe-loader
bash build.sh
```

## Usage

Pass `-loader "CADRE PE Loader"` to `analyzeHeadless`:

```bash
/opt/ghidra/support/analyzeHeadless /path/to/project ProjectName \
    -import /path/to/sample.exe \
    -loader "CADRE PE Loader" \
    -max-cpu 8
```

The RevAI pipeline uses this loader automatically during intake (`revai/intake_v2.py`).

## Why "CADRE" opinion?

`data/languages/CADRE.opinion` mirrors the stock PE `x86`/`x86_64` language constraints
so that `analyzeHeadless` can resolve a language/compiler spec even when the loader has
a custom display name.

## Related

- `ghidra_scripts/PopulateImportsFromPTR.py` — standalone Ghidra script that populates
  imports from pointer data (alternative for cases where a custom loader is not available).
- Source + build: [`extensions/cadre-pe-loader/`](../extensions/cadre-pe-loader/)

## License

MIT — see [LICENSE](../LICENSE).
