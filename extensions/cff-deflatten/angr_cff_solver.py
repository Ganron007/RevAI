"""angr CFF-state-machine solver.

For cff_demo_flat, symbolic-execute each case-state destination and ask:
what concrete value of x causes control to reach that branch? This is
the symbolic-execution counterpart to the CFF deflatten pattern-match
script - it bypasses the broken auto-analysis that confuses Ghidra by
starting from the `cff_demo_flat` function entry and walking constraints
manually through Z3-backed claripy.
"""
import sys
import angr
import claripy

target = "/tmp/cff-test/cff_flat.exe"
DEMO_FN = 0x1400014d4  # real entry per angr's CFG
DISPATCHER = 0x14000151e  # jmp *%rax in the dispatcher

print(f"target: {target}")
p = angr.Project(target, auto_load_libs=False)
print(f"entry: {hex(p.entry)}")

state = p.factory.blank_state(
    addr=DEMO_FN,
    add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                 angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
)
x = claripy.BVS("x", 32)
state.regs.rcx = x     # first arg in MS x64 ABI

print("=== blank_state at cff_demo_flat; symbolic rcx = x ===")
sm = p.factory.simulation_manager(state)
sm.explore(find=DEMO_FN + 0xf9)  # up to ret instr approx
print(f"explored: active={len(sm.active)}, deadended={len(sm.deadended)}")