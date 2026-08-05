# CADRE PE Loader — Custom Ghidra Extension

A custom Ghidra PE loader that ensures Windows API import references are correctly created for PE binaries, including packed, compound, and binder/dropper files where Ghidra's stock `PeLoader` fails to populate the import table.

## Problem

Ghidra's stock `PeLoader` sometimes fails to create external references for PE import tables. The result is that downstream tools (ghidrasql, capa, etc.) report an empty `imports` table even though the binary uses many Windows APIs. This is common with:

- Packed executables (UPX, VMProtect, Themida, etc.)
- Binder/dropper outer PE images
- PEs with non-standard import directory layouts

## Solution

`CADREPeLoader` extends Ghidra's stock `PeLoader` with a robust second pass over the PE import directory:

1. **Delegates to stock loader** — all normal PE loading (memory blocks, headers, exports) is handled by the parent `PeLoader`.
2. **Disables heavy analyzers** — skips `Decompiler Parameter ID`, `WindowsPE RTTI Analyzer`, and `Symbolic Propagator` by default for faster headless import.
3. **Import fixup pass** — walks the import descriptor table and for every import entry:
   - Creates pointer data at the IAT slot (if missing or not a pointer)
   - Creates an `ExternalReference` for `dll!name` at the IAT address
   - Handles both named imports and ordinal imports
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

## Installation

The extension is pre-installed on the RevAI deployment VM at:
```
/opt/ghidra/Ghidra/Extensions/CADRE/
├── Module.manifest
├── extension.properties
├── data/languages/CADRE.opinion   # PE language/compiler constraints
└── lib/CADRE.jar                  # compiled extension
```

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

The RevAI pipeline uses this loader automatically during intake (`intake_v2.py`).

## Why "CADRE" opinion?

`data/languages/CADRE.opinion` mirrors the stock PE `x86`/`x86_64` language constraints so that `analyzeHeadless` can resolve a language/compiler spec even when the loader has a custom display name.

## Related

- `ghidra_scripts/PopulateImportsFromPTR.py` — standalone Ghidra script that populates imports from pointer data (alternative approach for cases where a custom loader is not available).
- `revai/intake_v2.py` — pipeline intake that invokes this loader.

## License

MIT — see [LICENSE](../../LICENSE).
