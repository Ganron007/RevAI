#!/usr/bin/env python3
"""
force_pe_imports.py - GhidraScript (Java-ish subset that Ghidra accepts via -postScript)
that re-runs the PE/COFF ImportTable analyzer on a loaded program. Useful when
the auto-analyzer skipped the PE imports module (e.g. mixed-mode .NET PEs).

Usage from analyzeHeadless:
    analyzeHeadless ./. git-import_test -import <bin> \
      -postScript /opt/scripts/force_pe_imports.java

Or via ProjectLoader (script name without .java):
    ghidraSupport::analyzeHeadless ./. git-import_test -import <bin> \
      -postScript /opt/scripts/force_pe_imports.java

The Java-equivalent body (Ghidra uses a stripped Java subset for script files,
acceptable inside a .java file when run as a script):

    import ghidra.app.script.GhidraScript;
    import ghidra.program.model.listing.Program;
    import ghidra.program.model.symbol.SymbolTable;
    import ghidra.program.model.symbol.SourceType;
    import ghidra.framework.plugin.PluginManager;
    import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
    import ghidra.app.services.AnalysisProvider;
    import ghidra.app.analyzers.ReduxAnalyzer;
    ...

This file documents the approach. The actual .java variant lives next to
this file as `force_pe_imports.java`. If you cannot use auto-analysis rebuild,
fall back to calling `ImportInfoCmd` directly against the program.

When run, it:
  1. Forces re-analysis of the PE/COFF ImportTable analyzer (ghidra.app.analyzers.PEAnalyzer).
  2. Logs the new imports count vs the old.
  3. No-ops if the analyzer is already populated.

This file is documentation; the Java variant lives at the path below.
"""
from __future__ import annotations
import os
from pathlib import Path

HERE = Path(__file__).parent
JAVA_FILE = HERE / "force_pe_imports.java"

if not JAVA_FILE.is_file():
    raise SystemExit(f"expected Java script at {JAVA_FILE}")

print(f"Java post-script lives at: {JAVA_FILE}", flush=True)
print(f"size: {JAVA_FILE.stat().st_size} bytes", flush=True)
