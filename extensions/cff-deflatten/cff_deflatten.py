#!/usr/bin/env python3
"""CFF Deflatten v1.0 — global dispatcher-pattern detector.

RevAI / tools/cff-deflatten/cff_deflatten.py

Detects control-flow flattening (CFF) in a binary by scanning every
basic block, not relying on Ghidra's function ID. Works for binaries
where Ghidra has trouble (e.g., the CFF test fixture itself gets
fragmented by Ghidra's auto-analysis because of indirect jumps).

Invoke via PyGhidra:
    python3 cff_deflatten.py --input /path/to/binary.exe [--json]

Algorithm:
  1. Walk every basic block in the program via BasicBlockModel.
  2. For each block with outdegree >= N, count how many of its
     destinations have ALL outgoing edges coming back to it.
  3. If >= M case-target blocks return to it, flag as dispatcher.
  4. For each case-target, scan the LAST STORE-before-back-edge for
     a constant — that constant is the "next state" value.
  5. Report the dispatcher (with its containing function if known).

KNOWN LIMITATIONS (v1):
  - Depends on Ghidra's basic-block analysis enumerating indirect
    (jump-table) destinations. If the jump-table resolver failed
    on a particular function, this script will see outdegree=1
    and miss the dispatcher.
  - The script does NOT re-emit a deflattened function. It only
    reports the recovered edges. v2 would patch the Ghidra listing.
  - Tested against synthetic CFF fixtures; not yet validated on
    real-world CFF-protected samples (VMProtect, Themida, etc.).

RevAI extension — see ../README.md for context.
"""
import argparse
import json
import os
import sys
from pathlib import Path

DISPATCHER_OUTDEGREE_MIN = 3
MIN_CASE_TARGETS = 2

#: Ghidra ships its own PyGhidra as source rather than as an installed package,
#: so `import pyghidra` only works when that source directory happens to be on
#: PYTHONPATH. That is why this script failed on every pipeline run from
#: 2026-09-28: the interpreter had no pyghidra, and nothing set PYTHONPATH, so
#: the leg was a silent no-op inside a stage that still exited rc=0.
GHIDRA_CANDIDATES = (
    os.environ.get("GHIDRA_INSTALL_DIR", ""),
    "/opt/ghidra",
    os.environ.get("GHIDRA_HOME", ""),
    "/usr/share/ghidra",
)


def _import_pyghidra():
    """Import pyghidra, falling back to Ghidra's own bundled copy.

    Prefers an installed pyghidra (a venv with `pip install pyghidra` is the
    tidiest setup), then adds Ghidra's `Features/PyGhidra/pypkg/src` to the
    path. Doing this here rather than relying on the caller's environment means
    the tool works when run directly, from a pipeline stage, or from setup,
    with no PYTHONPATH contract for a caller to get wrong.

    Raises with the searched locations listed, because a bare
    ModuleNotFoundError tells an operator nothing about where it looked.
    """
    try:
        import pyghidra  # noqa: F401
        return pyghidra
    except ImportError:
        pass

    searched = []
    for root in filter(None, GHIDRA_CANDIDATES):
        src = Path(root) / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "src"
        searched.append(str(src))
        if not src.is_dir():
            continue
        sys.path.insert(0, str(src))
        # pyghidra locates Ghidra through this variable; without it `start()`
        # fails with a much less obvious error.
        os.environ.setdefault("GHIDRA_INSTALL_DIR", root)
        try:
            import pyghidra
            return pyghidra
        except ImportError:
            sys.path.pop(0)
            continue

    raise ImportError(
        "pyghidra not importable and Ghidra's bundled copy was not found. "
        f"Searched: {searched}. Install it (pip install pyghidra in the "
        "interpreter running this script) or set GHIDRA_INSTALL_DIR to a "
        "Ghidra installation directory."
    )


def find_state_assignment(flat_api, from_block, monitor):
    """Scan the instructions in from_block for the LAST STORE of a
    constant - that's almost always the 'state = K' terminator in
    a CFF dispatcher loop. Returns the constant value, or None."""
    instr_iter = flat_api.getCurrentProgram().getListing().getInstructions(
        from_block.getFirstStartAddress(), True)
    last_assignment = None
    while instr_iter.hasNext():
        instr = instr_iter.next()
        if not from_block.contains(instr.getAddress()):
            break
        pcode = list(instr.getPcode())
        for i in range(len(pcode)):
            p = pcode[i]
            if str(p.getMnemonic()).upper() == "STORE":
                if p.getNumInputs() >= 3 and p.getInput(2).isConstant():
                    last_assignment = p.getInput(2).getOffset()
    return last_assignment


def contains_addr(addrset_view, addr):
    """Check if address is in AddressSetView."""
    it = addrset_view.iterator()
    while it.hasNext():
        r = it.next()
        if r.contains(addr):
            return True
    return False


def get_destination_blocks(block, monitor):
    """Return list of destination CodeBlocks for the given block."""
    dests = []
    it = block.getDestinations(monitor)
    while True:
        try:
            if not it.hasNext():
                break
            d = it.next()
        except Exception:
            break
        db = d.getDestinationBlock()
        if db is not None:
            dests.append(db)
    return dests


def _block_key(block):
    """Stable identity for a basic block, comparable across wrapper objects.

    Ghidra hands out a fresh Java `CodeBlockImpl` on each query, so `==` is
    reference equality and two queries for the same block compare unequal. The
    start address is the identity that actually holds.
    """
    for getter in ("getFirstStartAddress", "getMinAddress"):
        fn = getattr(block, getter, None)
        if fn is None:
            continue
        try:
            addr = fn()
        except Exception:
            continue
        if addr is not None:
            return str(addr)
    return repr(block)


def find_dispatchers(all_blocks, get_dests, outdeg_min, min_case_targets):
    """Return [(block, outdegree, back_count, case_targets)] for dispatchers.

    A control-flow-flattening dispatcher is a block that fans out to several
    case arms, each of which flows back to it. Two subtleties, both of which
    made this return nothing on a known-flattened binary before:

    1. Blocks are compared by start address, never by object identity. Ghidra
       returns a fresh `CodeBlockImpl` wrapper per query, so `==` is reference
       equality and is false for two queries about the same block.
    2. A case arm qualifies when it has *a* back edge to the dispatcher, not
       only when *every* successor is the dispatcher. Real arms end in the
       indirect dispatch and may also fall through; demanding all-successors
       excludes genuine flattening.

    `get_dests` is injected so this is testable without Ghidra.
    """
    candidates = []
    for b in all_blocks:
        b_addr = _block_key(b)
        dests = get_dests(b)
        if len(dests) < outdeg_min:
            continue
        back_count = 0
        case_targets = []
        for db in dests:
            if _block_key(db) == b_addr:
                continue
            inner = get_dests(db)
            if not inner:
                continue
            if any(_block_key(d) == b_addr for d in inner):
                back_count += 1
                case_targets.append(db)
        if back_count < min_case_targets:
            continue
        candidates.append((b, len(dests), back_count, case_targets))
    return candidates


def collect_all_blocks(program, monitor, bbm):
    """Walk the entire program and return all blocks."""
    af = program.getAddressFactory()
    img_base = af.getAddress("0x0")
    addr_set = program.getMemory().getAllInitializedAddressSet()
    it = bbm.getCodeBlocksContaining(addr_set, monitor)
    blks = []
    while True:
        try:
            if not it.hasNext():
                break
            blks.append(it.next())
        except Exception:
            break
    return blks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--function", default=None,
                    help="filter results to a specific function name")
    ap.add_argument("--min-outdegree", type=int, default=None,
                    help="minimum dispatch outdegree to consider (default 3)")
    ap.add_argument("--min-case-targets", type=int, default=None,
                    help="minimum case targets returning to dispatcher (default 2)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    # operator-supplied overrides
    global DISPATCHER_OUTDEGREE_MIN, MIN_CASE_TARGETS
    if args.min_outdegree is not None:
        DISPATCHER_OUTDEGREE_MIN = args.min_outdegree
    if args.min_case_targets is not None:
        MIN_CASE_TARGETS = args.min_case_targets

    pyghidra = _import_pyghidra()
    pyghidra.start()

    with pyghidra.open_program(args.input, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        fm = program.getFunctionManager()

        from ghidra.util.task import TaskMonitor
        from ghidra.program.model.block import BasicBlockModel
        monitor = TaskMonitor.DUMMY
        bbm = BasicBlockModel(program)

        all_blocks = collect_all_blocks(program, monitor, bbm)
        if not all_blocks:
            print("No blocks found.", file=sys.stderr)
            return

        # find dispatcher candidates
        candidates = find_dispatchers(
            all_blocks,
            lambda b: get_destination_blocks(b, monitor),
            DISPATCHER_OUTDEGREE_MIN,
            MIN_CASE_TARGETS,
        )

        # resolve each candidate's containing function
        results = []
        for disp, outdeg, backcount, case_targets in candidates:
            fn_name = "<unknown>"
            fn_entry = ""
            try:
                fn = fm.getFunctionContaining(disp.getFirstStartAddress())
                if fn is not None:
                    fn_name = fn.getName()
                    fn_entry = str(fn.getEntryPoint())
            except Exception:
                pass
            if args.function is not None and fn_name != args.function:
                continue
            edges = []
            for tgt in case_targets:
                nxt = find_state_assignment(flat_api, tgt, monitor)
                if nxt is not None:
                    edges.append((str(tgt.getFirstStartAddress()), int(nxt)))
            results.append({
                "function": fn_name,
                "function_entry": fn_entry,
                "dispatcher": str(disp.getFirstStartAddress()),
                "dispatcher_outdegree": outdeg,
                "back_edge_count": backcount,
                "total_blocks_in_program": len(all_blocks),
                "recovered_edges": [
                    {"case_target": c, "next_state": "0x%x" % n} for c, n in edges
                ],
            })

    if args.json:
        print(json.dumps({
            "binary": args.input,
            "total_blocks": len(all_blocks),
            "cff_candidates": results,
        }, indent=2))
    else:
        print("=" * 64)
        print("CFF Deflatten v1 - global scan of " + args.input)
        print("Total blocks: " + str(len(all_blocks)))
        print("=" * 64)
        if not results:
            print("No CFF candidates detected.")
        for r in results:
            print("")
            print("Function: " + r["function"] + " @ " + r["function_entry"])
            print("  dispatcher @ " + r["dispatcher"] +
                  "  outdeg=" + str(r["dispatcher_outdegree"]) +
                  "  back_edges=" + str(r["back_edge_count"]))
            print("  recovered edges:")
            for e in r["recovered_edges"]:
                print("    " + e["case_target"] + "  -- when state=" +
                      e["next_state"] + " -->")
        print("=" * 64)


if __name__ == "__main__":
    main()
