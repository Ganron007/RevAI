#!/usr/bin/env python3
"""The deobfuscation leg failed silently on every run since 2026-09-28.

Two separate defects, tested here separately:

  1. the leg's absence was never stated. `deobfuscation.error` sat in
     function_recovery.json while the stage exited rc=0 and nothing downstream
     knew that no function in the case had received flattened control flow.

  2. the recorded error was a leading `stderr[:300]` clip, and a Python
     traceback carries its cause on its LAST line -- so the clip is only safe
     for shallow tracebacks. Measured across all nine recorded artifacts it did
     NOT truncate this one (258 chars, cause intact), which is why this is the
     second defect and not the first.

The honest summary: the cause was on disk in plain text from the first run. The
failure was that nothing in the pipeline asked whether the leg had contributed,
so a recorded, readable error sat unread across a dozen runs. These tests pin
the visibility half.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import hollow_success as hs  # noqa: E402
from recovery.deobfuscator import (  # noqa: E402
    DeobfuscatorPass, _clip, _reason_from_stderr)


# ------------------------------------------------- the reason survives the clip

# The exact stderr the VM produced for cff_deflatten on winservices.exe. Taken
# verbatim from the live run, not written to fit the assertion.
REAL_CFF_STDERR = """Traceback (most recent call last):
  File "/opt/revai/cff-deflatten/cff_deflatten.py", line 222, in <module>
    main()
  File "/opt/revai/cff-deflatten/cff_deflatten.py", line 125, in main
    import pyghidra
ModuleNotFoundError: No module named 'pyghidra'
"""


def test_real_traceback_yields_the_cause_not_the_frames():
    got = _reason_from_stderr(REAL_CFF_STDERR)
    assert got == "ModuleNotFoundError: No module named 'pyghidra'", got


def test_this_traceback_was_never_truncated_in_practice():
    """The measured truth, pinned so nobody re-derives a false story about it.

    All nine recorded `deobfuscation.error` values are 258 chars and end in the
    cause. So `stderr[:300]` was NOT what hid this bug, and a commit claiming
    otherwise would be wrong.
    """
    # 258 as recorded, trailing newline included -- the artifact stored raw
    # stderr, and that length is what the old `[:300]` slice saw.
    assert len(REAL_CFF_STDERR) == 258, "fixture drifted from the VM"
    assert "ModuleNotFoundError" in REAL_CFF_STDERR[:300], \
        "if the clip ever hid the cause here, revisit which half mattered"


def test_a_deeper_traceback_WOULD_lose_the_cause_to_the_clip():
    """The latent half: more frames than fit, and the cause is gone."""
    deep = "Traceback (most recent call last):\n"
    for i in range(12):
        deep += (f'  File "/opt/ghidra/Ghidra/Framework/Project/Project'
                 f'Data{i}.java", line {40 + i}, in resolve{i}\n')
        deep += f"    return helper{i}();\n"
    deep += "ModuleNotFoundError: No module named 'pyghidra'\n"

    assert "ModuleNotFoundError" not in deep[:300], \
        "if 12 frames fit in 300 chars the premise is wrong"
    assert _reason_from_stderr(deep) == \
        "ModuleNotFoundError: No module named 'pyghidra'"


def test_import_error_with_a_long_module_path_is_not_truncated():
    err = ("Traceback (most recent call last):\n"
           '  File "x.py", line 1, in <module>\n'
           "    import some.extremely.long.optional.dependency.name\n"
           "ModuleNotFoundError: No module named 'some.extremely.long."
           "optional.dependency.name'\n")
    got = _reason_from_stderr(err)
    assert got.startswith("ModuleNotFoundError:")
    assert "dependency.name'" in got, got


def test_non_traceback_exception_line_is_found():
    err = ("Traceback (most recent call last):\n"
           '  File "a.py", line 3, in go\n'
           "    return 1 / 0\n"
           "ZeroDivisionError: division by zero\n")
    assert _reason_from_stderr(err) == "ZeroDivisionError: division by zero"


def test_chained_exception_reports_the_root_cause():
    err = ("Traceback (most recent call last):\n"
           '  File "a.py", line 9, in go\n'
           "    inner()\n"
           "During handling of the above exception, another exception occurred:\n"
           "\n"
           "Traceback (most recent call last):\n"
           '  File "b.py", line 4, in <module>\n'
           "    go()\n"
           "RuntimeError: Ghidra headless launch failed\n")
    assert _reason_from_stderr(err) == "RuntimeError: Ghidra headless launch failed"


def test_frames_only_stderr_keeps_the_location():
    """No exception line (SIGKILL, JVM abort) -- keep where it died."""
    err = ('Traceback (most recent call last):\n'
           '  File "/opt/ghidra/support/analyzeHeadless", line 44, in run\n')
    got = _reason_from_stderr(err)
    assert "analyzeHeadless" in got and "line 44" in got, got


def test_plain_error_text_passes_through():
    assert _reason_from_stderr("java.lang.OutOfMemoryError\n") == \
        "java.lang.OutOfMemoryError"


def test_empty_stderr_is_empty_not_the_string_none():
    """Regression guard: the old f-string could render a literal 'None'."""
    assert _reason_from_stderr("") == ""
    assert _reason_from_stderr(None) == ""
    assert _clip(None) == ""


# ------------------------------------------------------- status, not a no-op

def test_status_reports_the_missing_dependency(tmp_path, monkeypatch):
    tool = tmp_path / "cff_deflatten.py"
    tool.write_text("# stub\n", encoding="utf-8")
    monkeypatch.setattr("recovery.deobfuscator.CFF_DEFLATTEN_PY", str(tool))
    deob = DeobfuscatorPass.__new__(DeobfuscatorPass)
    deob.sample_path = str(tool)

    # Force the probe to fail the way the VM's interpreter does.
    import subprocess
    real = subprocess.run

    def fake(cmd, **kw):
        if "import pyghidra" in cmd[-1] if isinstance(cmd[-1], str) else False:
            return subprocess.CompletedProcess(
                cmd, 1, "", "ModuleNotFoundError: No module named 'pyghidra'\n")
        return real(cmd, **kw)

    monkeypatch.setattr("recovery.deobfuscator.subprocess.run", fake)
    st = deob.deobfuscation_status()
    assert st["available"] is False
    assert "pyghidra" in st["reason"], st


def test_missing_tool_is_distinguished_from_a_broken_one(tmp_path, monkeypatch):
    monkeypatch.setattr("recovery.deobfuscator.CFF_DEFLATTEN_PY",
                        str(tmp_path / "nope.py"))
    deob = DeobfuscatorPass.__new__(DeobfuscatorPass)
    deob.sample_path = str(tmp_path / "nope.py")
    st = deob.deobfuscation_status()
    assert st["available"] is False
    assert "missing" in st["reason"], st


def test_run_reports_a_reason_when_the_tool_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr("recovery.deobfuscator.CFF_DEFLATTEN_PY",
                        str(tmp_path / "nope.py"))
    deob = DeobfuscatorPass.__new__(DeobfuscatorPass)
    deob.sample_path = str(tmp_path / "nope.py")
    out = deob.run_cff_deflatten(timeout=5)
    assert out["unavailable"] == "missing_tool"
    assert "not found" in out["error"]


# ------------------------------------------- the leg's absence must be visible

def test_deobfuscation_leg_skipped_is_reported_as_advisory(tmp_path):
    """A leg that contributed nothing is a depth statement, not a verdict.

    Advisory, not a gate: the obfuscation flags are still computed heuristically
    and the verdict does not depend on flattening. But it must be visible --
    the whole failure mode was a silent no-op inside a green stage.
    """
    (tmp_path / "function_recovery.json").write_text(json.dumps({
        "function_results": [
            {"source": "llm_judge", "function_name": f"f_{i}",
             "confidence": 0.8, "normalized_pseudocode": "int f(){}"}
            for i in range(20)],
        "deobfuscation": {
            "skipped": True,
            "unavailable": "missing_dependency",
            "reason": "ModuleNotFoundError: No module named 'pyghidra'",
            "status": {"available": False},
        },
    }), encoding="utf-8")

    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is True, "must not gate"
    adv = out["advisory"]
    assert adv["deobfuscation_leg"] == "skipped"
    assert "pyghidra" in adv["deobfuscation_reason"]


def test_running_deobfuscation_leg_leaves_advisory_unset(tmp_path):
    (tmp_path / "function_recovery.json").write_text(json.dumps({
        "function_results": [
            {"source": "llm_judge", "function_name": f"f_{i}",
             "confidence": 0.8, "normalized_pseudocode": "int f(){}"}
            for i in range(20)],
        "deobfuscation": {"functions": 12, "status": {"available": True}},
    }), encoding="utf-8")
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is True
    assert "deobfuscation_leg" not in out["advisory"]


def test_healthy_case_advisory_has_no_deobfuscation_noise(tmp_path):
    """The common case must not grow a new field that always reads the same."""
    (tmp_path / "function_recovery.json").write_text(json.dumps({
        "function_results": [
            {"source": "llm_judge", "function_name": "memset",
             "confidence": 0.9, "normalized_pseudocode": "void *m(){}"}],
    }), encoding="utf-8")
    out = hs.evaluate_case(tmp_path)
    assert out["ok"] is True
    assert out["advisory"] == {} or "deobfuscation_leg" not in out["advisory"]