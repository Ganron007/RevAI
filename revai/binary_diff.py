"""Structural comparison of two binaries (loader vs payload, packed vs unpacked).

Deterministic facts only: container metadata, section names, imports, imphash and
byte-level chunk containment. There is no "similarity score" beyond what is
measured, and no claim about common authorship or family - the caller reads the
facts and decides. Works on PE; falls back to raw byte comparison for anything
else so an unknown container still yields size/hash/containment evidence.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

CHUNK = 64
#: Containment above this is reported as "largely contained" - a measured
#: threshold, stated in the output rather than implied by a score.
CONTAINMENT_HINT = 0.5


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "pe"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "macho"
    return "raw"


def _chunks(data: bytes) -> set[str]:
    """Content-defined-enough chunk set: fixed 64-byte windows, whole chunks only."""
    out: set[str] = set()
    for offset in range(0, len(data) - CHUNK + 1, CHUNK):
        out.add(hashlib.blake2b(data[offset:offset + CHUNK], digest_size=8).hexdigest())
    return out


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    import math
    return -sum((c / length) * math.log2(c / length) for c in counts if c)


def _pe_facts(path: Path) -> dict | None:
    """Parse PE facts with the repo's own parser; None when it does not apply."""
    try:
        import pe as pe_mod
        import hashes as hashes_mod

        pe = pe_mod.parse_pe(str(path))
    except Exception:
        return None

    sections = []
    for section in pe.sections:
        raw = pe.data[section.raw_pointer:section.raw_pointer + section.raw_size]
        sections.append({
            "name": section.name,
            "virtual_size": getattr(section, "virtual_size", None),
            "raw_size": section.raw_size,
            "entropy": round(_entropy(raw), 3),
        })

    imports = sorted({
        f"{imp.dll}!{fn}".lower()
        for imp in getattr(pe, "imports", []) for fn in imp.functions
    })
    entry_section = None
    for section in pe.sections:
        if section.virtual_address <= pe.entry_point < section.virtual_address + max(
                section.raw_size, getattr(section, "virtual_size", 0) or 0):
            entry_section = section.name
            break

    try:
        imphash = hashes_mod.imphash([i.__dict__ for i in pe.imports])
    except Exception:
        imphash = None

    return {
        "machine": pe.to_dict().get("architecture"),
        "subsystem": pe.subsystem_name,
        "entry_point": hex(pe.entry_point),
        "entry_section": entry_section,
        "imphash": imphash,
        "sections": sections,
        "imports": imports,
    }


def _facts(path: str) -> dict:
    p = Path(path)
    data = p.read_bytes()
    facts = {
        "path": str(p),
        "size": len(data),
        "sha256": _sha256(data),
        "format": _detect(data),
    }
    pe_facts = _pe_facts(p) if facts["format"] == "pe" else None
    if pe_facts is None:
        facts["pe_parsed"] = False
    else:
        facts["pe_parsed"] = True
        facts.update(pe_facts)
    facts["_chunks"] = _chunks(data)
    return facts


def _section_map(facts: dict) -> dict[str, dict]:
    return {s["name"]: s for s in facts.get("sections") or []}


def compare(path_a: str, path_b: str) -> dict:
    """Compare two files; ``a`` is the reference (e.g. the loader)."""
    a = _facts(path_a)
    b = _facts(path_b)
    chunks_a, chunks_b = a.pop("_chunks"), b.pop("_chunks")

    containment_b_in_a = (
        len(chunks_b & chunks_a) / len(chunks_b) if chunks_b else 0.0)
    containment_a_in_b = (
        len(chunks_a & chunks_b) / len(chunks_a) if chunks_a else 0.0)

    result: dict = {
        "a": a,
        "b": b,
        "size_ratio_b_to_a": round(b["size"] / a["size"], 4) if a["size"] else None,
        "byte_containment": {
            "b_in_a": round(containment_b_in_a, 4),
            "a_in_b": round(containment_a_in_b, 4),
            "chunk_bytes": CHUNK,
            "largely_contained_threshold": CONTAINMENT_HINT,
            "largely_contained": {
                "b_in_a": containment_b_in_a >= CONTAINMENT_HINT,
                "a_in_b": containment_a_in_b >= CONTAINMENT_HINT,
            },
        },
        "signals": {},
    }

    if a.get("pe_parsed") and b.get("pe_parsed"):
        sec_a, sec_b = _section_map(a), _section_map(b)
        shared = sorted(set(sec_a) & set(sec_b))
        imports_a, imports_b = set(a.get("imports") or []), set(b.get("imports") or [])
        result["signals"] = {
            "same_imphash": bool(a.get("imphash")) and a.get("imphash") == b.get("imphash"),
            "shared_sections": shared,
            "only_in_a_sections": sorted(set(sec_a) - set(sec_b)),
            "only_in_b_sections": sorted(set(sec_b) - set(sec_a)),
            "section_entropy_delta": {
                name: round(b_sec["entropy"] - sec_a[name]["entropy"], 3)
                for name, b_sec in ((n, sec_b[n]) for n in shared)
            },
            "shared_imports": sorted(imports_a & imports_b)[:50],
            "shared_import_count": len(imports_a & imports_b),
            "only_in_a_imports": sorted(imports_a - imports_b)[:50],
            "only_in_b_imports": sorted(imports_b - imports_a)[:50],
            "entry_section": {
                "a": a.get("entry_section"),
                "b": b.get("entry_section"),
                "same": a.get("entry_section") == b.get("entry_section"),
            },
        }
    else:
        result["signals"] = {
            "pe_comparison": "skipped",
            "reason": "at least one input is not a parseable PE (raw byte comparison only)",
        }

    result["notes"] = [
        "Facts only: no similarity score, no authorship or family claim.",
        "Containment is exact 64-byte chunk overlap between the two files as given; "
        "it is sensitive to alignment and does not account for recompression.",
    ]
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Structural comparison of two binaries (loader vs payload).")
    parser.add_argument("a", help="reference file (e.g. the loader/sample)")
    parser.add_argument("b", help="file to compare (e.g. the dropped payload)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    result = compare(args.a, args.b)
    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    a, b = result["a"], result["b"]
    print(f"A: {a['path']} ({a['format']}, {a['size']} bytes, {a['sha256'][:16]})")
    print(f"B: {b['path']} ({b['format']}, {b['size']} bytes, {b['sha256'][:16]})")
    print(f"size ratio B/A: {result['size_ratio_b_to_a']}")
    bc = result["byte_containment"]
    print(f"containment: B in A {bc['b_in_a']:.2%}, A in B {bc['a_in_b']:.2%}")
    signals = result["signals"]
    if signals.get("pe_comparison") == "skipped":
        print(f"PE signals: skipped ({signals['reason']})")
    else:
        print(f"imphash equal: {signals['same_imphash']}")
        print(f"shared sections: {', '.join(signals['shared_sections']) or '-'}")
        print(f"shared imports: {signals['shared_import_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
