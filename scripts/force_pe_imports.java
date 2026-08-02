// force_pe_imports.java - GhidraScript that re-runs the PE/COFF ImportTable analyzer
// on a loaded program.  Used as an analyzeHeadless -postScript.
//
// Motivation:
//   Some mixed-mode / stripped .NET PEs come back with 0 rows in the ghidrasql
//   `imports` virtual table after the default auto-analysis pipeline. The PE
//   ImportTable analyzer didn't register an import for some symbols.  Forcing
//   the analyzer to re-run restores the labels for unresolved imports.
//
// invoke from .41:
//   /opt/ghidra/support/analyzeHeadless ./. import_test -import <bin> \
//     -postScript /opt/scripts/force_pe_imports.java
//
// Behavior:
//   - Inspects the current SymbolTable for import Namespaces. If non-zero, returns early.
//   - Otherwise finds the PE analyzer class by name and runs it with PHASE = ANALYSIS.
//   - Logs counts before/after.
import ghidra.app.script.GhidraScript;
import ghidra.app.analyzers.PEAnalyzer;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;

public class force_pe_imports extends GhidraScript {

    private static final String MARKER_DIR = "/opt/scripts/agentic-re-skills/logs";
    private static final String MARKER_FILE = "force_pe_imports.log";

    private int countImports(Program p) {
        Namespace ns = p.getSymbolTable().getNamespace("Imports");
        if (ns == null) return 0;
        int n = 0;
        for (var s : p.getSymbolTable().getSymbols(ns)) { n++; }
        return n;
    }

    @Override
    public void run() throws Exception {
        Program program = getCurrentProgram();
        if (program == null) { return; }
        monitor.setMessage("force_pe_imports: start");

        int before = countImports(program);
        monitor.setMessage("force_pe_imports: imports-before=" + before);

        if (before > 0) {
            println("force_pe_imports: imports already populated, skipping");
            return;
        }

        try {
            PEAnalyzer pe = new PEAnalyzer();
            pe.added(program, monitor);
        } catch (Exception e) {
            printerr("force_pe_imports: re-run failed: " + e.getMessage());
        }

        int after = countImports(program);
        monitor.setMessage("force_pe_imports: imports-after=" + after);
        println("force_pe_imports: imports-after=" + after);

        try {
            java.nio.file.Files.createDirectories(java.nio.file.Paths.get(MARKER_DIR));
            java.nio.file.Path p = java.nio.file.Paths.get(MARKER_DIR, MARKER_FILE);
            String body = String.format("ts=%d\nprogram=%s\nbefore=%d\nafter=%d\nstatus=%s\n",
                System.currentTimeMillis(),
                program.getName(),
                before, after, after > before ? "fixed" : (after == before ? "no-change" : "regressed"));
            java.nio.file.Files.write(p, body.getBytes());
        } catch (Exception e) {
            printerr("force_pe_imports: could not write marker: " + e.getMessage());
        }
    }
}
