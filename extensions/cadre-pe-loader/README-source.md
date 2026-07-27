# CADRE PE Loader

Custom Ghidra PE loader that ensures external references are created for PE import tables, including embedded PEs in binder/dropper files.

## Installation

Run `build.sh` on the REMnux lab VM. It installs the extension to `$GHIDRA_HOME/Ghidra/Extensions/CADRE`.

## Usage

When running `analyzeHeadless`, pass `-loader "CADRE PE Loader"` to use the loader.
The loader extends the stock `PeLoader` and runs a robust second pass over the PE
import directory (and any embedded PEs) to create `ExternalReference` objects.
