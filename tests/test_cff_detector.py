#!/usr/bin/env python3
"""cff_deflatten returned zero candidates on a genuinely flattened binary.

A GCC computed-goto positive control (real indirect dispatch, every case arm
branching back to the dispatcher) was flattened by construction and reported
`cff_candidates: []` at every optimisation level, while block analysis plainly
showed blocks of outdegree 3 and 4. Installing the missing pyghidra dependency
had exposed the tool at all -- and it was then found to be inert.

Two defects, both pinned here against stand-in blocks so they are testable
without Ghidra:

  1. blocks were compared with `==` on separately-obtained `CodeBlockImpl`
     wrappers, which is reference equality and is false for two queries about
     the same block -- so no case arm was ever recognised as returning.
  2. a case arm had to have the dispatcher as *every* successor. Real arms end
     in the indirect dispatch and frequently fall through as well, so genuine
     flattening was excluded.

The negative controls matter as much: an ordinary binary must produce nothing,
or the detector is just noisy.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _layout import resolve  # noqa: E402

# The repo keeps this under extensions/; the VM deploys it flat into
# /opt/scripts. Resolved for both so this tripwire runs on the VM, which is
# where the deobfuscation defects it guards actually occur.
_CFF = resolve("extensions/cff-deflatten/cff_deflatten.py")
if not _CFF.is_file():
    _CFF = ROOT / "cff_deflatten.py"
SPEC = importlib.util.spec_from_file_location("cff_deflatten", _CFF)
cff = importlib.util.module_from_spec(SPEC)
sys.modules["cff_deflatten"] = cff
SPEC.loader.exec_module(cff)


class FakeBlock:
    """Stands in for CodeBlockImpl: address-derived, like the real thing."""

    def __init__(self, addr):
        self.addr = addr

    def getFirstStartAddress(self):
        return self.addr

    def getMinAddress(self):
        return self.addr


def _graph(pairs):
    """pairs: {addr: [successor addrs]}. Returns a get_dests callable."""
    def get(block):
        return [FakeBlock(a) for a in pairs.get(block.addr, [])]
    return get


def _flattened_graph():
    """The shape of a CFF dispatcher with four case arms.

    0x10 fans out to the four arms; each arm flows back to 0x10 and then on to
    the next thing -- exactly the layout the all-successors test rejected.
    """
    return _graph({
        "0x10": ["0x20", "0x30", "0x40", "0x50"],
        "0x20": ["0x10", "0x99"],   # back edge plus a fall-through
        "0x30": ["0x10"],
        "0x40": ["0x10"],
        "0x50": ["0x10"],
        "0x99": ["0x10"],
    })


# ------------------------------------------------------------ the two defects

def test_dispatcher_is_found_when_case_arms_fall_through():
    """Defect 2: a back edge is the signal, not sole succession.

    0x20 has successors 0x10 and 0x99. Requiring every successor to be the
    dispatcher excluded it; the arm is still a flattened case.
    """
    got = cff.find_dispatchers([FakeBlock("0x10")], _flattened_graph(), 3, 2)
    assert len(got) == 1, got
    disp, outdeg, back_count, cases = got[0]
    assert outdeg == 4
    assert back_count == 4, cases
    assert {cff._block_key(c) for c in cases} == {"0x20", "0x30", "0x40", "0x50"}


def test_blocks_are_compared_by_address_not_identity():
    """Defect 1: fresh wrappers for the same block must compare equal."""
    graph = _flattened_graph()
    got = cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2)
    assert got, "a dispatcher with four returning arms must be found"


def test_block_key_is_stable_across_distinct_wrapper_objects():
    a, b = FakeBlock("0x40"), FakeBlock("0x40")
    assert a is not b
    # No __eq__, so object equality IS identity -- which is exactly why the
    # detector could not recognise a block it had queried twice.
    assert a != b, "identity comparison is the bug being fixed"
    assert cff._block_key(a) == cff._block_key(b) == "0x40"


def test_self_loop_does_not_count_as_a_case_target():
    """A block that only branches to itself is not flattening."""
    graph = _graph({"0x10": ["0x10", "0x10", "0x10", "0x10"]})
    assert cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2) == []


# ------------------------------------------------------------------ thresholds

def test_outdegree_floor_is_respected():
    graph = _graph({"0x10": ["0x20", "0x30"], "0x20": ["0x10"], "0x30": ["0x10"]})
    assert cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2) == []
    assert len(cff.find_dispatchers([FakeBlock("0x10")], graph, 2, 2)) == 1


def test_case_target_floor_is_respected():
    """One returning arm is a switch, not a flattening dispatcher."""
    graph = _graph({
        "0x10": ["0x20", "0x30", "0x40"],
        "0x20": ["0x10"],
        "0x30": ["0x99"],
        "0x40": ["0x99"],
    })
    assert cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2) == []
    assert len(cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 1)) == 1


def test_leaf_case_arms_are_not_counted():
    """An arm with no successors has not returned anywhere."""
    graph = _graph({
        "0x10": ["0x20", "0x30", "0x40"],
        "0x20": ["0x10"],
        "0x30": [],
        "0x40": [],
    })
    assert cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2) == []


# ------------------------------------------------------------ negative controls

def test_ordinary_control_flow_produces_nothing():
    """A diamond and a straight line are not flattening."""
    pairs = {
        "0x10": ["0x20", "0x30"],   # diamond
        "0x20": ["0x40"],
        "0x30": ["0x40"],
        "0x40": ["0x50"],          # straight line
        "0x50": [],
    }
    graph = _graph(pairs)
    assert cff.find_dispatchers(
        [FakeBlock(a) for a in pairs], graph, 3, 2) == []


def test_high_outdegree_without_returns_is_not_a_dispatcher():
    """A jump table where targets do NOT return is not a dispatcher loop."""
    graph = _graph({
        "0x10": ["0x20", "0x30", "0x40", "0x50"],
        "0x20": ["0x60"], "0x30": ["0x60"],
        "0x40": ["0x60"], "0x50": ["0x60"],
        "0x60": [],
    })
    assert cff.find_dispatchers([FakeBlock("0x10")], graph, 3, 2) == []


def test_empty_program_is_clean():
    assert cff.find_dispatchers([], _graph({}), 3, 2) == []


# ------------------------------------------------------- dependency location

def test_import_helper_reports_where_it_looked(monkeypatch, tmp_path):
    """A bare ModuleNotFoundError tells an operator nothing about where."""
    import builtins
    real_import = builtins.__import__

    def no_pyghidra(name, *a, **kw):
        if name == "pyghidra":
            raise ImportError("No module named 'pyghidra'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", no_pyghidra)
    monkeypatch.setattr(cff, "GHIDRA_CANDIDATES", (str(tmp_path),))
    monkeypatch.delitem(sys.modules, "pyghidra", raising=False)

    try:
        cff._import_pyghidra()
    except ImportError as exc:
        # Compared on the searched leaf, not the full string: the path
        # separator differs between pathlib and pytest's repr across platforms.
        assert "PyGhidra" in str(exc), exc
        assert "GHIDRA_INSTALL_DIR" in str(exc), "must say how to fix it"
    else:
        raise AssertionError("expected ImportError when nothing provides it")


def test_import_helper_prefers_an_installed_pyghidra(monkeypatch):
    """A working install must win over the bundled-source fallback."""
    import builtins
    sentinel = object()
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        if name == "pyghidra":
            sys.modules["pyghidra"] = sentinel
            return sentinel
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(cff, "GHIDRA_CANDIDATES", ("/nonexistent",))
    monkeypatch.delitem(sys.modules, "pyghidra", raising=False)
    assert cff._import_pyghidra() is sentinel


def test_import_helper_falls_back_to_bundled_source(monkeypatch, tmp_path):
    """Ghidra ships pyghidra as source under Features/PyGhidra/pypkg/src."""
    src = tmp_path / "Ghidra" / "Features" / "PyGhidra" / "pypkg" / "src"
    src.mkdir(parents=True)
    (src / "pyghidra.py").write_text("VERSION='bundled'\n", encoding="utf-8")

    import builtins
    sentinel = object()
    real_import = builtins.__import__

    def fake_import(name, *a, **kw):
        # Fails until the bundled source directory has been put on sys.path,
        # so the fallback branch is actually exercised rather than short-
        # circuited by the installed-package branch.
        if name == "pyghidra":
            if any("PyGhidra" in p for p in sys.path):
                return sentinel
            raise ImportError("No module named 'pyghidra'")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    monkeypatch.setattr(cff, "GHIDRA_CANDIDATES", (str(tmp_path),))
    monkeypatch.delitem(sys.modules, "pyghidra", raising=False)
    sys_path_len = len(sys.path)

    try:
        assert cff._import_pyghidra() is sentinel
        assert any("PyGhidra" in p for p in sys.path), \
            f"bundled src must be on sys.path, got {sys.path[:3]}"
        assert sys.path.index(str(src)) < sys_path_len, \
            "bundled src must lead sys.path, ahead of later candidates"
        import os
        assert os.environ["GHIDRA_INSTALL_DIR"] == str(tmp_path), \
            "pyghidra.start() needs this to find Ghidra"
    finally:
        while str(src) in sys.path:
            sys.path.remove(str(src))