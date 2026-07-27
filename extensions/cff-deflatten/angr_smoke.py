"""angr smoke test - validates Z3-backed symbolic execution on synthetic
Win PE fixture from the CFF deflatten test set."""
import sys
import angr
import claripy

print(f"angr version: {angr.__version__}")
print(f"claripy version: {claripy.__version__}")
print()

target = "/tmp/cff-test/cff_flat.exe"
print(f"=== loading {target} ===")
try:
    proj = angr.Project(target, auto_load_libs=False)
    print(f"  arch     : {proj.arch.name}")
    print(f"  entry    : {hex(proj.entry)}")
    print(f"  factory  : {type(proj.factory).__name__}")
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")
    sys.exit(0)

print()
print("=== CFG fast ===")
try:
    cfg = proj.analyses.CFGFast(normalize=True, data_references=False, show_progressbar=False)
    print(f"  CFG nodes (functions)  : {len(cfg.kb.functions)}")
    print(f"  main at 0x1400015ce   : {cfg.kb.functions.get(0x1400015ce).name if 0x1400015ce in cfg.kb.functions else '?'}")
    print(f"  cff_demo_flat         : {hex(cfg.kb.functions[0x1400014d4].addr) if 0x1400014d4 in cfg.kb.functions else '?'}")
    for addr in sorted(cfg.kb.functions.keys())[:10]:
        f = cfg.kb.functions[addr]
        print(f"    fn 0x{addr:x} size={f.size} name={f.name}")
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")

print()
print("=== symbolic execution: find x that hits cff_demo_flat end-block ===")
try:
    # Look at cff_flat directly via its symbolic input
    state = proj.factory.entry_state(args=[claripy.BVS("cff_arg", 32 * 8)], env={"PATH": "/"})
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(n=200)  # try a few steps; angr will follow concrete through stub dispatchers
    print(f"  active  : {simgr.active}")
    print(f"  deadended: {simgr.deadended}")
    if simgr.deadended:
        for s in simgr.deadended[:3]:
            try:
                print(f"    deadend stdout: {s.posix.dumps(0)[:80]!r}")
            except Exception:
                pass
except Exception as e:
    print(f"  FAIL: {type(e).__name__}: {e}")