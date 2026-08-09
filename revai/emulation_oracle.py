#!/usr/bin/env python3
"""
emulation_oracle.py — bounded Speakeasy emulation pass (REMnux, no Windows VM).

Industry alignment (2026-08-09):
  - MAoS REM: run the sample and observe what it actually DOES — dynamic API
    resolution, unpacking/deobfuscation loops (custom code between API calls),
    network/communication attempts.
  - FOR610 pyramid stage 3 (behavioral): "static theories need behavioral
    validation"; emulate first, then suggest functions to analyze.
  - FOR710 Lab 1.3: runtime-resolved APIs (hash or LoadLibrary+GetProcAddress)
    name the real functions of packed/stripped samples.

Design (verified against speakeasy on REMnux 2026-08-09):
  - In-process Speakeasy with a wall-clock stop timer + speakeasy's internal
    60s emulation cap (defense in depth). Never blocks the pipeline: caller
    runs it in a subprocess with a hard kill timeout.
  - add_code_hook collects executed addresses (sampled, capped) — maps to
    functions via the funcs address range (ghidrasql) in the caller.
  - get_dyn_imports() = dynamically resolved imports (packed-sample core
    evidence; verified: UPX hive resolves the full kernel32 surface).
  - get_memory_dumps() = mapped regions incl. the module image (unpacked
    payload evidence).
  - Honest limitation (this speakeasy build): per-call API tracing via
    add_api_hook did not fire for dynamically-resolved calls; evidence is
    dyn-import resolution + executed address ranges + memory regions, not a
    call-level trace.

Failure-safe: returns {"ok": False, "error": ...} on any failure; the oracle
never produces a verdict — it corroborates/contradicts other evidence.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_WALL_BUDGET = 45       # seconds of wall-clock emulation budget
DEFAULT_EMU_SECONDS = 3        # emulated seconds per run_module
MAX_EXECUTED_ADDRS = 2000      # cap on collected executed addresses
MAX_DYN_IMPORTS = 500
_ORACLE_ENABLED = "REVAI_ENABLE_EMULATION_ORACLE"


def _collect(sample_path: str, wall_budget: int, emu_seconds: int) -> dict:
    """Run the emulation in-process and return structured evidence. Never raises.
    Self-contained (constants inlined) so the subprocess can execute the
    function source via inspect.getsource.

    Two phases (verified 2026-08-09):
      P1 evidence run: NO code hook (the hook's per-instruction Python call
        makes 3 emu-seconds exceed the wall budget and a mid-run stop loses
        get_dyn_imports state). Fast, self-bounding; dyn imports + regions.
      P2 coverage run: code hook only; stops early once the executed-address
        set fills. Executed addresses map to functions in the caller.
    """
    MAX_EXECUTED_ADDRS = 2000
    MAX_DYN_IMPORTS = 500
    out: dict[str, Any] = {"engine": "emulation_oracle", "ok": False}
    try:
        import speakeasy  # noqa: F401  (installed on REMnux; import guarded)

        t0 = time.time()

        def _finish(se) -> None:
            try:
                se.stop()
            except Exception:
                pass

        # ---- Phase 1: evidence run (no hook, dyn imports preserved) ----
        se1 = speakeasy.Speakeasy()
        timer1 = threading.Timer(wall_budget, lambda: se1.stop())
        try:
            mod = se1.load_module(sample_path)
            timer1.start()
            se1.run_module(mod, emu_seconds)
        except Exception as e:  # sample-specific quirks are evidence, not fatal
            out["run_note"] = f"{type(e).__name__}: {str(e)[:200]}"
        finally:
            timer1.cancel()
        _finish(se1)

        report = se1.get_report()
        dyn = []
        try:
            dyn = list(se1.get_dyn_imports() or [])[:MAX_DYN_IMPORTS]
        except Exception:
            pass
        dyn_names: list[str] = []
        for entry in dyn:
            if isinstance(entry, (tuple, list)) and len(entry) >= 3:
                dyn_names.append(str(entry[2]))
            elif isinstance(entry, dict):
                dyn_names.append(str(entry.get("name") or entry.get("api") or entry))

        regions: list[dict] = []
        try:
            for d in list(se1.get_memory_dumps()):
                if isinstance(d, tuple) and len(d) >= 3:
                    regions.append({
                        "name": str(d[0])[:80],
                        "addr": str(d[1]),
                        "size": int(d[2] or 0),
                    })
        except Exception:
            pass

        # ---- Phase 2: coverage run (code hook, early stop) ----
        executed: set[int] = set()
        insn_count = {"n": 0}

        def code_hook(emu, address, size, opaque) -> None:  # noqa: ARG001
            insn_count["n"] += 1
            if len(executed) < MAX_EXECUTED_ADDRS:
                executed.add(address)
                if len(executed) >= MAX_EXECUTED_ADDRS:
                    emu.stop()

        se2 = speakeasy.Speakeasy()
        timer2 = threading.Timer(max(10, wall_budget // 2), lambda: se2.stop())
        try:
            se2.add_code_hook(code_hook)
            mod2 = se2.load_module(sample_path)
            timer2.start()
            se2.run_module(mod2, emu_seconds)
        except Exception as e:
            out.setdefault("coverage_note", f"{type(e).__name__}: {str(e)[:200]}")
        finally:
            timer2.cancel()
        _finish(se2)

        out.update({
            "ok": True,
            "sample": os.path.basename(sample_path),
            "wall_s": round(time.time() - t0, 2),
            "instructions_executed": insn_count["n"],
            "executed_addresses": sorted(executed)[:MAX_EXECUTED_ADDRS],
            "executed_address_count": len(executed),
            "dyn_imports": dyn_names,
            "dyn_import_count": len(dyn_names),
            "memory_regions": regions[:20],
            "memory_region_count": len(regions),
            "emu_runtime": report.get("emulation_total_runtime"),
            "entry_points": report.get("entry_points"),
            "strings_seen": len(report.get("strings") or []),
            "note": "Oracle only — corroborates/contradicts, never verdicts. "
                    "Call-level API trace unavailable in this speakeasy build; "
                    "evidence = dyn-import resolution + executed addresses + "
                    "memory regions (MAoS REM / FOR610).",
        })
    except Exception as e:  # never break the pipeline
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def run_emulation_oracle(sample_path: str, wall_budget: int = DEFAULT_WALL_BUDGET,
                         emu_seconds: int = DEFAULT_EMU_SECONDS,
                         hard_timeout: int = DEFAULT_WALL_BUDGET + 20) -> dict:
    """Run the oracle in a subprocess with a hard kill timeout.

    Env-gated by the caller (REVAI_ENABLE_EMULATION_ORACLE). Returns the
    structured evidence dict (or {"ok": False, "error": ...}).
    """
    script = inspect_getsource()
    argv = [
        sys.executable, "-c",
        f"import os, time, threading, json, sys\n{script}\n"
        f"r = _collect(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))\n"
        f"print(json.dumps(r, default=str))\n",
        sample_path, str(wall_budget), str(emu_seconds),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=hard_timeout)
        if proc.returncode != 0:
            return {"ok": False, "error": f"oracle subprocess rc={proc.returncode}: {proc.stderr[-300:]}"}
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        return data
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"oracle subprocess timed out after {hard_timeout}s"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def inspect_getsource() -> str:
    """Return this module's _collect source for the subprocess (no file needed)."""
    import inspect
    return inspect.getsource(_collect)


def oracle_enabled() -> bool:
    return os.environ.get(_ORACLE_ENABLED, "0").strip().lower() in ("1", "true", "yes")


if __name__ == "__main__":
    sys.path.insert(0, "/opt/scripts")
    path = sys.argv[1]
    print(json.dumps(run_emulation_oracle(path), indent=2, default=str))
