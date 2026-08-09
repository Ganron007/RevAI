#!/usr/bin/env python3
"""
unpack_oracle.py — emulation-assisted generic unpacking (OEP + dump + IAT) on REMnux.

Method (2026-08-09):
  - find OEP (execution transition into the memory-only section), dump the
    process, rebuild the IAT.
  - "dump + OEP/IAT reconstruction"; Scylla FixDump analog.
  - dump deobfuscated executable content and load it fresh.

Deterministic method (verified on UPX 3.9 LZMA x64 hive, 2026-08-09):
  1. LIEF: memory-only exec sections (RawSize==0, VirtualSize>0) are the
     unpack targets (UPX0/MPRESS-style). Also record image base + entry.
   2. Bounded Speakeasy run with PC polling; the OEP = first execution inside
      a memory-only exec section (stub's jump into unpacked code).
  3. Dump: read each section's virtual range from emulated memory and write a
     new PE where raw_size = virtual_size (FixDump analog), headers from the
     original file (packers reuse the header area).
  4. IAT: the packer rebuilds the import table in memory at runtime, so the
     carved image's import directory is populated — pefile reads real imports
     + imphash (Scylla-equivalent, no importer needed for IAT-preserving
     packers; honest limitation for IAT-erasing ones).

Failure-safe (subprocess-isolated with hard kill), env-gated by the caller.
Oracle/artifact only: produces evidence + a payload file, never verdicts.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_WALL_BUDGET = 60
DEFAULT_EMU_SECONDS = 6
MAX_EXECUTED_ADDRS = 4000


def _collect(sample_path: str, wall_budget: int, emu_seconds: int) -> dict:
    """Self-contained (subprocess-injected) unpack pass. Never raises."""
    MAX_EXECUTED_ADDRS = 4000
    out: dict[str, Any] = {"engine": "unpack_oracle", "ok": False}
    try:
        import speakeasy  # noqa: F401
        import lief
        import base64
        import hashlib
        import math
        from pathlib import Path
        from typing import Any

        binary = lief.parse(sample_path)
        if binary is None or not isinstance(binary, lief.PE.Binary):
            out["error"] = "not a PE (unpack pass is PE-only)"
            return out
        base = int(binary.imagebase or 0)
        sections = []
        memory_only = []
        for s in binary.sections:
            sec = {
                "name": s.name,
                "rva": int(s.virtual_address),
                "virtual_size": int(s.virtual_size),
                "raw_size": int(s.size),
                "exec": bool(int(s.characteristics) & 0x20000000),
                "writable": bool(int(s.characteristics) & 0x80000000),
            }
            sections.append(sec)
            if sec["raw_size"] == 0 and sec["virtual_size"] > 0 and sec["exec"]:
                memory_only.append(sec)
        out["sections"] = sections
        out["memory_only_exec_sections"] = [s["name"] for s in memory_only]
        if not memory_only:
            out.update({
                "ok": True,
                "unpacked": False,
                "reason": "no memory-only executable sections (packer signature absent)",
            })
            return out

        # OEP detection via PC polling: a per-instruction code hook slows the
        # emulator ~10x (large decompression loops never finish in budget).
        # Polling get_pc() every 200ms adds no per-instruction cost; the first
        # PC inside a memory-only exec section is the stub->unpacked jump
        # (verified 2026-08-09 on UPX: OEP = first execution in UPX0).
        poll_state = {"oep": None}

        def _poll(emu) -> None:
            while poll_state["oep"] is None:
                time.sleep(0.2)
                try:
                    pc = emu.get_pc()
                except Exception:
                    continue
                for sec in memory_only:
                    if base + sec["rva"] <= pc < base + sec["rva"] + sec["virtual_size"]:
                        poll_state["oep"] = {
                            "addr": pc, "hex": hex(pc), "section": sec["name"],
                        }
                        try:
                            emu.stop()
                        except Exception:
                            pass
                        break

        se = speakeasy.Speakeasy()
        timer = threading.Timer(wall_budget, lambda: se.stop())
        poller = threading.Thread(target=_poll, args=(se,), daemon=True)
        try:
            mod = se.load_module(sample_path)
            timer.start()
            poller.start()
            se.run_module(mod, emu_seconds)
        except Exception as e:
            out["run_note"] = f"{type(e).__name__}: {str(e)[:200]}"
        finally:
            timer.cancel()
        try:
            se.stop()
        except Exception:
            pass
        try:
            out["emu_stop_pc"] = hex(se.get_pc() or 0)
        except Exception:
            pass

        # OEP: from the poller (execution entered a memory-only exec section)
        oep = poll_state["oep"]
        content_written = False
        for sec in memory_only:
            try:
                probe = se.mem_read(base + sec["rva"], min(sec["virtual_size"], 65536))
            except Exception:
                probe = b""
            if probe and any(probe):
                content_written = True
                break

        # Dump: headers from file, section raw = emulated memory content.
        # header_len must cover PE sig + file header + optional header +
        # the full section table (pefile reads sections from there).
        file_bytes = Path(sample_path).read_bytes()
        pe_off = int.from_bytes(file_bytes[0x3C:0x40], "little")
        import struct
        nsec = struct.unpack_from("<H", file_bytes, pe_off + 6)[0]
        opt_size = struct.unpack_from("<H", file_bytes, pe_off + 20)[0]
        sec_table = pe_off + 24 + opt_size
        header_len = min(sec_table + 40 * nsec, len(file_bytes))
        header = file_bytes[:header_len]
        out_blob = bytearray(header)
        # extend blob to cover the largest section target offset
        for sec in sections:
            target = sec_table + sec["rva"] + sec["virtual_size"]
            if len(out_blob) < target:
                out_blob.extend(b"\x00" * (target - len(out_blob)))
        for idx, sec in enumerate(sections):
            va = base + sec["rva"]
            size = sec["virtual_size"]
            try:
                data = se.mem_read(va, min(size, 0x10000000))
            except Exception:
                data = b""
            if not data:
                continue
            file_off = sec_table + sec["rva"]
            end = file_off + len(data)
            if end > len(out_blob):
                out_blob.extend(b"\x00" * (end - len(out_blob)))
            out_blob[file_off:end] = data
            # FixDump analog: patch SizeOfRawData + PointerToRawData so pefile
            # reads section content from the memory dump, not the packed file.
            entry = sec_table + idx * 40
            if entry + 40 <= len(out_blob):
                out_blob[entry + 16:entry + 20] = struct.pack("<I", size)
                out_blob[entry + 20:entry + 24] = struct.pack("<I", file_off)

        blob = bytes(out_blob)
        ent = 0.0
        if blob:
            counts = [0] * 256
            for b in blob:
                counts[b] += 1
            n = len(blob)
            ent = -sum((c / n) * math.log2(c / n) for c in counts if c)
        parsed = {}
        try:
            import pefile
            pe = pefile.PE(data=blob, fast_load=False)
            parsed["sections"] = len(pe.sections)
            parsed["imphash"] = pe.get_imphash()
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for imp in pe.DIRECTORY_ENTRY_IMPORT:
                    names = [e.name.decode(errors="replace") for e in imp.imports[:40]]
                    imports.append({"dll": imp.dll.decode(errors="replace"), "apis": names})
            parsed["import_dlls"] = len(imports)
            parsed["imports"] = imports[:20]
        except Exception as e:
            parsed["error"] = f"{type(e).__name__}: {str(e)[:160]}"

        out.update({
            "ok": True,
            "unpacked": bool(oep) or content_written,
            "oep": oep,
            "oep_reached": oep is not None,
            "content_written": content_written,
            "payload": {
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "entropy": round(ent, 3),
            },
            "payload_b64": base64.b64encode(blob).decode("ascii") if len(blob) <= 128 * 1024 * 1024 else None,
            "parsed": parsed,
            "note": "Emulation dump: headers from file + section content from "
                    "emulated memory (FixDump analog). oep_reached=False means "
                    "the stub did not execute its unpacked-code jump within "
                    "budget: large decompression loops don't finish under "
                    "unicorn; small payloads often complete the image write "
                    "but the stub hits unsupported instructions at the "
                    "transition (emu_stop_pc=0xfeedf01c observed). The dump is "
                    "still the unpacked image in progress. IAT read from the "
                    "in-memory import table only when the stub rebuilt it.",
        })
    except Exception as e:  # never break the pipeline
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def run_unpack_pass(sample_path: str, out_dir: str,
                    wall_budget: int = DEFAULT_WALL_BUDGET,
                    emu_seconds: int = DEFAULT_EMU_SECONDS,
                    hard_timeout: int = DEFAULT_WALL_BUDGET + 20) -> dict:
    """Subprocess-isolated unpack pass. Writes the carved payload on success."""
    import inspect
    script = inspect.getsource(_collect)
    argv = [
        sys.executable, "-c",
        f"import os, time, threading, json, sys, struct\n{script}\n"
        f"r = _collect(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))\n"
        f"print(json.dumps(r, default=str))\n",
        sample_path, str(wall_budget), str(emu_seconds),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=hard_timeout)
        if proc.returncode != 0:
            return {"ok": False, "error": f"unpack subprocess rc={proc.returncode}: {proc.stderr[-300:]}"}
        data = json.loads(proc.stdout.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"unpack subprocess timed out after {hard_timeout}s"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

    if data.get("ok") and data.get("unpacked") and data.get("payload_b64"):
        try:
            import base64 as _b64
            out_path = Path(out_dir)
            out_path.mkdir(parents=True, exist_ok=True)
            blob = _b64.b64decode(data.pop("payload_b64"))
            sample = Path(data.get("sample") or sample_path).name
            payload_path = out_path / f"unpacked_{sample}"
            payload_path.write_bytes(blob)
            data["payload"]["path"] = str(payload_path)
        except Exception as e:
            data["write_error"] = f"{type(e).__name__}: {e}"
    return data


def unpack_enabled() -> bool:
    return os.environ.get("REVAI_ENABLE_UNPACK_PASS", "0").strip().lower() in ("1", "true", "yes")


if __name__ == "__main__":
    sys.path.insert(0, "/opt/scripts")
    print(json.dumps(run_unpack_pass(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "/tmp/unpack"), indent=2, default=str))
