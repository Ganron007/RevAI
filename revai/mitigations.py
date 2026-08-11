"""Exploit mitigations — PE (claim-vs-fact) and ELF (header-fact).

PE: DYNAMIC_BASE without .reloc still loads at preferred base; GUARD_CF with
an empty guard function table checks nothing; NO_SEH claim vs reality; stack
cookie presence.
ELF: NX from PT_GNU_STACK (absent header = executable stack), RELRO from
DT_BIND_NOW/DF_1_NOW + PT_GNU_RELRO, ASLR/PIE from ET_DYN, stack canary from
__stack_chk_fail in dynamic imports, TEXTREL = writable text.
"""

from __future__ import annotations

from typing import Any

import elf as elf_mod
import pe as pe_mod

_MITIGATIONS: list[tuple[str, int, str, str]] = [
    ("aslr", pe_mod.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
     "Address Space Layout Randomization",
     "Without ASLR the image loads at a fixed base — a predictable address for "
     "ret2libc-style exploitation and ROP gadget pivots."),
    ("high_entropy_va", pe_mod.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
     "64-bit high-entropy ASLR",
     "Without 64-bit entropy the entropy of the address space is reduced "
     "relative to the full 64-bit layout."),
    ("dep", pe_mod.IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
     "Data Execution Prevention",
     "Without NX-compat, writable memory can be executable — classic "
     "shellcode-on-stack/heap works directly."),
    ("cfg", pe_mod.IMAGE_DLLCHARACTERISTICS_GUARD_CF,
     "Control Flow Guard",
     "Without CFG, indirect calls are unvalidated — vtable and function-"
     "pointer overwrites become direct code-flow hijack."),
    ("seh", pe_mod.IMAGE_DLLCHARACTERISTICS_NO_SEH,
     "Structured Exception Handling",
     "The NO_SEH flag claims no SEH handlers exist; if a handler is still "
     "present the claim is false — an exception can overwrite the handler "
     "chain for control-flow hijack."),
    ("force_integrity", pe_mod.IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
     "Signed-image enforcement",
     "Without forced integrity, a tampered image is not rejected by the "
     "loader's integrity checks."),
]


def analyze_mitigations(pe: pe_mod.PE | elf_mod.ELF) -> dict[str, Any]:
    if isinstance(pe, elf_mod.ELF):
        return _analyze_elf(pe)
    return _analyze_pe(pe)


def _analyze_pe(pe: pe_mod.PE) -> dict[str, Any]:
    flags = pe.dll_characteristics
    has_reloc = any(s.name.lower() in (".reloc", "reloc") for s in pe.sections)
    guard_table_present = pe.guard_cf_table_rva != 0 and pe.guard_cf_table_size > 0
    stack_cookie_ref = any(
        fn.lower() in ("__security_check_cookie", "__security_cookie")
        for imp in pe.imports for fn in imp.functions
    )

    findings: list[dict[str, Any]] = []
    for key, bit, name, consequence in _MITIGATIONS:
        claimed = bool(flags & bit)
        if key == "aslr":
            present = claimed and has_reloc
            note = "claim only: DYNAMIC_BASE set but no .reloc section — loads at preferred base"
            if not claimed:
                note = "no DYNAMIC_BASE flag"
        elif key == "cfg":
            present = claimed and guard_table_present
            note = "claim only: GUARD_CF set but guard function table empty — checks nothing"
            if not claimed:
                note = "no GUARD_CF flag"
        elif key == "seh":
            present = not claimed
            note = "NO_SEH flag set — no SEH handlers claimed"
            if not claimed:
                note = "no NO_SEH flag — SEH handlers may exist"
        else:
            present = claimed
            note = f"{name} flag {'set' if claimed else 'not set'}"
        findings.append({"name": name, "present": present, "claimed": claimed,
                         "note": note, "consequence": consequence})

    findings.append({
        "name": "Stack cookie (/GS)",
        "present": stack_cookie_ref,
        "claimed": stack_cookie_ref,
        "note": ("__security_check_cookie referenced" if stack_cookie_ref
                 else "no __security_cookie reference found"),
        "consequence": ("Without a stack cookie, linear buffer overflows can "
                        "overwrite the return address directly on the stack."),
    })
    return {"format": "pe", "findings": findings}


def _analyze_elf(e: elf_mod.ELF) -> dict[str, Any]:
    has_nx = e.has_gnu_stack and any(
        p["type"] == elf_mod.PT_GNU_STACK and p["flags"] & 1 == 0
        for p in e.program_headers
    )
    bind_now = bool(e.flags & elf_mod.DF_BIND_NOW) or bool(e.flags1 & elf_mod.DF_1_NOW)
    relro_full = bind_now and e.has_gnu_relro
    relro_partial = e.has_gnu_relro and not bind_now
    canary = any("__stack_chk_fail" in s for s in e.dyn_imports)
    textrel = bool(e.flags & elf_mod.DF_TEXTREL)

    findings: list[dict[str, Any]] = [
        {
            "name": "Non-executable stack (NX)",
            "present": has_nx,
            "claimed": has_nx,
            "note": ("PT_GNU_STACK present with stack non-executable" if has_nx
                     else "no PT_GNU_STACK or stack marked executable — "
                           "stack-smashing shellcode runs directly"),
            "consequence": "An executable stack lets a linear overflow become "
                           "direct shellcode execution.",
        },
        {
            "name": "RELRO",
            "present": relro_full or relro_partial,
            "claimed": relro_full,
            "note": ("full RELRO (BIND_NOW + PT_GNU_RELRO)" if relro_full
                     else "partial RELRO (PT_GNU_RELRO without BIND_NOW)" if relro_partial
                     else "no RELRO — GOT is writable"),
            "consequence": "Without full RELRO, a write primitive can rewrite "
                           "GOT entries for direct control-flow hijack.",
        },
        {
            "name": "ASLR / PIE",
            "present": e.is_pie,
            "claimed": e.is_pie,
            "note": ("ET_DYN (PIE) — base randomized" if e.is_pie
                     else "ET_EXEC — fixed load address"),
            "consequence": "A fixed base gives predictable addresses for "
                           "ret2libc and ROP pivots.",
        },
        {
            "name": "Stack canary",
            "present": canary,
            "claimed": canary,
            "note": ("__stack_chk_fail referenced" if canary
                     else "no __stack_chk_fail — no canary"),
            "consequence": "Without a canary, linear overflows can overwrite "
                           "the return address directly.",
        },
        {
            "name": "Writable text (TEXTREL)",
            "present": bool(textrel),
            "claimed": bool(textrel),
            "note": ("DT_TEXTREL set — text segment relocations (writable text)" if textrel
                     else "no TEXTREL"),
            "consequence": "Writable code pages can be patched at runtime for "
                           "code-flow hijack.",
        },
    ]
    return {"format": "elf", "findings": findings}
