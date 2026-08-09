#!/usr/bin/env python3
"""
packer_intake.py — deterministic packer-suspicion checklist + section entropy (LIEF).

Industry alignment (2026-08-09):
  - MAoS BEM: per-section entropy via Detect It Easy (".7 suspicious; .data at 7.24
    = packed payload"), unusual size ratios (file vs section -> embedded payload),
    RW/executable sections (runtime unpacking / code injection suspects), very few
    imports incl. LoadLibrary/GetProcAddress.
  - Hexorcist step 1 (packer-suspicion PE checklist): fancy/empty section names,
    section count <3 or >6, last section executable (stub at end) / writable,
    first section writable (in-place decrypt), RawSize==0 with VirtualSize!=0,
    RawSize vs VirtualSize mismatch, EP in last/non-first section, EP with no
    standard API calls, import table with only GetModuleHandle/GetProcAddress/
    LoadLibrary, no strings (encrypted data).

Every item is computed from the actual PE structure via LIEF; nothing heuristic
beyond the checklist mapping. Failure-safe: returns {"ok": False, "error": ...}
on non-PE/parse failure so the pipeline never breaks.
"""
from __future__ import annotations

import math
import time
from typing import Any

# checklist item -> weight (sum >=6 => "packed", >=3 => "suspicious")
CHECKLIST_WEIGHTS = {
    "last_section_exec": 2,      # stub appended at end
    "ep_in_last_section": 3,     # packers move EP to stub
    "first_section_writable": 2, # in-place self-decrypt
    "few_imports": 2,            # <=3 imports incl. loader APIs
    "high_entropy_exec_section": 2,  # exec section entropy > 6.0 bits/byte
    "last_section_writable": 1,
    "ep_not_in_first_section": 1,
    "raw_vs_virtual_mismatch": 1,
    "memory_only_section": 1,    # RawSize==0 and VirtualSize!=0 (BSS-legal only)
    "section_count_outlier": 1,  # <3 or >10 sections
}
PACKED_THRESHOLD = 6
SUSPICIOUS_THRESHOLD = 3
EXEC_ENTROPY_HIGH = 6.0       # dense/compressed CODE
EMBED_ENTROPY_HIGH = 6.5      # non-exec section, likely embedded payload


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n) for c in counts if c
    )


def run_packer_scan(sample_path: str) -> dict:
    """Deterministic packer-suspicion checklist over the PE structure."""
    t0 = time.time()
    out: dict[str, Any] = {"engine": "packer_intake", "ok": False}
    try:
        import lief  # noqa: F401  (verified installed on VM; v2_lib uses it)

        binary = lief.parse(str(sample_path))
        # lief.Binary.FORMAT was removed in newer LIEF — use isinstance (version-agnostic)
        is_pe = binary is not None and isinstance(binary, lief.PE.Binary)
        if binary is None or not is_pe:
            out.update({
                "ok": True,
                "not_applicable": True,
                "reason": "not a PE (packer checklist is PE-only)",
                "elapsed_s": round(time.time() - t0, 3),
            })
            return out

        sections = []
        for sec in binary.sections:
            raw = bytes(sec.content) if hasattr(sec, "content") else b""
            sections.append({
                "name": sec.name,
                "entropy": round(_entropy(raw), 3),
                "raw_size": int(sec.size),
                "virtual_size": int(sec.virtual_size),
                "exec": bool(sec.characteristics & 0x20000000),
                "writable": bool(sec.characteristics & 0x80000000),
            })
        n = len(sections)
        ep = binary.entrypoint if hasattr(binary, "entrypoint") else 0
        first = sections[0] if sections else None
        last = sections[-1] if sections else None

        # EP section: LIEF entrypoint is a VA; sections are RVAs -> add imagebase.
        ep_section = None
        base = int(getattr(binary, "imagebase", 0) or 0)
        for sec in binary.sections:
            va = int(sec.virtual_address) + base
            vsz = int(sec.virtual_size)
            if va <= ep < va + vsz:
                ep_section = sec.name
                break

        imports = [imp.name for imp in binary.imports]
        import_names = []
        for imp in binary.imports:
            for e in imp.entries:
                if e.name:
                    import_names.append(e.name)
        loader_apis = any(
            n.lower().startswith(("loadlibrary", "getprocaddress", "getmodulehandle"))
            for n in import_names
        )

        checks: dict[str, bool] = {
            "last_section_exec": bool(last and last.get("exec")),
            "last_section_writable": bool(last and last.get("writable")),
            "first_section_writable": bool(first and first.get("writable")),
            "ep_in_last_section": bool(ep_section and last and ep_section == last.get("name")),
            "ep_not_in_first_section": bool(ep_section and first and ep_section != first.get("name")),
            "raw_vs_virtual_mismatch": any(
                abs(s.get("virtual_size") - s.get("raw_size")) > 0x1000 for s in sections
            ),
            "memory_only_section": any(
                s.get("raw_size") == 0 and s.get("virtual_size") > 0 for s in sections
            ),
            "high_entropy_exec_section": any(
                s.get("entropy", 0) > EXEC_ENTROPY_HIGH and s.get("exec") for s in sections
            ),
            "few_imports": len(imports) <= 3 and loader_apis,
            "section_count_outlier": n < 3 or n > 10,
        }
        embedded_payload_hint = any(
            s.get("entropy", 0) > EMBED_ENTROPY_HIGH and not s.get("exec") for s in sections
        )
        score = sum(CHECKLIST_WEIGHTS.get(k, 0) for k, v in checks.items() if v)
        label = "packed" if score >= PACKED_THRESHOLD else (
            "suspicious" if score >= SUSPICIOUS_THRESHOLD else "none"
        )
        out.update({
            "ok": True,
            "label": label,
            "score": score,
            "sections": sections,
            "checks": checks,
            "embedded_payload_hint": embedded_payload_hint,
            "entry_point": ep,
            "ep_section": ep_section,
            "import_count": len(imports),
            "imports_sample": import_names[:40],
            "elapsed_s": round(time.time() - t0, 3),
            "note": "MAoS BEM entropy + Hexorcist packer checklist; heuristic label, "
                    "unpacking loop still required for non-UPX packers.",
        })
    except Exception as e:  # never break the pipeline
        out["error"] = f"{type(e).__name__}: {e}"
    return out


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(run_packer_scan(sys.argv[1]), indent=2, default=str))
