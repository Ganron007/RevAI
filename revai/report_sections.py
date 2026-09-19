"""Deterministic alignment sections derived from evidence (plan #12, prose half).

Three report sections that code can produce without the LLM, so they are always
present and cannot be paraphrased away:

* **Component inventory** - the PE's structure (sections with structural roles,
  imports by module, overlay, entry point). Roles are descriptors read from
  section flags and names, never a behaviour claim.
* **Analysis environment** - tool versions as *reported by the tools in this run*
  (plus an optional install-time capture at `/opt/revai/config/tool-versions.json`).
* **MBC vocabulary** - the Malware Behavior Catalog entries that capa's own rule
  metadata carries, alongside the ATT&CK mapping the report already has.

Nothing is inferred: a section is omitted when its evidence is absent, and
unreadable input yields the input unchanged.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

_VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+){0,3}\b")
#: Tool-result keys whose value is a version-ish string (kept narrow on purpose -
#: sizes, durations and counts must not be mistaken for versions).
_VERSION_KEYS = ("version", "tool_version", "yara_version", "r2_version")
#: Keys that name the engine/backend used, not its version.
_ENGINE_KEYS = ("engine",)
_BACKEND_KEYS = ("capa_bin",)
_INSTALL_VERSIONS = Path("/opt/revai/config/tool-versions.json")


def _load(path: Path) -> dict | None:
    try:
        if path.is_file():
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return data if isinstance(data, dict) else None
    except Exception:
        return None
    return None


def _tool_results(case_root: Path | None) -> dict:
    """Merge the run's raw tool results (deep-dive overrides quick-scan)."""
    merged: dict = {}
    if case_root is None:
        return merged
    for rel in ("quick_scan/00-tools-raw.json", "deep_dive/01-tools-raw.json"):
        data = _load(case_root / rel)
        if data:
            merged.update(data)
    return merged


def _walk(node, visit) -> None:
    if isinstance(node, dict):
        visit(node)
        for value in node.values():
            _walk(value, visit)
    elif isinstance(node, list):
        for item in node:
            _walk(item, visit)


# --- component inventory ---------------------------------------------------


def _section_role(section) -> str:
    """Structural descriptor from section flags/name (never behaviour)."""
    name = (section.name or "").lower()
    if section.memory_only:
        return "memory-only (no raw data)"
    if name.startswith(".rsrc"):
        return "resources"
    if name.startswith(".reloc"):
        return "relocations"
    if name.startswith(".tls"):
        return "thread-local storage"
    if name in (".idata",):
        return "import table"
    if section.executable and section.writable:
        return "writable executable (unusual)"
    if section.executable:
        return "executable code"
    if name in (".rdata", ".rodata"):
        return "read-only data"
    if section.writable:
        return "writable data"
    return "data"


def format_component_inventory(sample_path: str | Path | None,
                               limit: int = 30) -> str:
    """PE structure with per-section structural roles (omitted when not PE)."""
    if not sample_path:
        return ""
    path = Path(sample_path)
    if not path.is_file():
        return ""
    try:
        import pe as pe_mod
        import sections as sections_mod

        parsed = pe_mod.parse_pe(str(path))
    except Exception:
        return ""

    lines = ["## Component Inventory", "",
             "Structure only: roles are read from section flags and names, not "
             "from behaviour.", ""]

    lines += [
        f"- **file**: `{path.name}` ({len(parsed.data)} bytes, "
        f"{'PE32+' if parsed.is_64 else 'PE32'} {hex(parsed.machine)})",
        f"- **subsystem**: {parsed.subsystem_name}",
        f"- **entry point**: {hex(parsed.entry_point)}"
        + (f" (section `{_entry_section(parsed)}`)" if _entry_section(parsed) else ""),
        f"- **image base**: {hex(parsed.image_base)}",
    ]
    if parsed.guard_cf_table_size:
        lines.append(f"- **guard CF table**: present ({parsed.guard_cf_table_size} bytes)")

    lines += ["", "| Section | Raw | Virtual | Entropy | Flags | Role |",
              "|---|---|---|---|---|---|"]
    for section in parsed.sections[:limit]:
        raw = parsed.data[section.raw_pointer:section.raw_pointer + section.raw_size]
        entropy = sections_mod.shannon_entropy(raw) if raw else 0.0
        flags = "".join(c for c, ok in (("R", True), ("W", section.writable),
                                        ("X", section.executable)) if ok)
        lines.append(f"| `{section.name}` | {section.raw_size} | {section.virtual_size} "
                     f"| {entropy:.2f} | {flags} | {_section_role(section)} |")

    if parsed.imports:
        lines += ["", "| Import module | Functions |", "|---|---|"]
        for imp in sorted(parsed.imports, key=lambda i: -len(i.functions))[:limit]:
            lines.append(f"| {imp.dll} | {len(imp.functions)} |")
        lines.append(f"| **total** | **{sum(len(i.functions) for i in parsed.imports)}** |")
    else:
        lines += ["", "No import directory was parsed."]

    overlay = len(parsed.data) - _end_of_last_section(parsed)
    if overlay > 0:
        lines.append(f"- **overlay**: {overlay} byte(s) beyond the last section "
                     "(content not characterised here)")
    return "\n".join(lines) + "\n"


def _end_of_last_section(parsed) -> int:
    end = 0
    for section in parsed.sections:
        end = max(end, section.raw_pointer + section.raw_size)
    return end


def _entry_section(parsed) -> str | None:
    for section in parsed.sections:
        span = max(section.raw_size, section.virtual_size)
        if section.virtual_address <= parsed.entry_point < section.virtual_address + span:
            return section.name
    return None


# --- analysis environment --------------------------------------------------


def format_analysis_environment(case_root: Path | None,
                                provenance: dict | None = None) -> str:
    """Tool versions reported by this run (plus an optional install-time capture).

    Versions, engine names and backends are kept apart on purpose: an engine
    string such as ``malcat-capa`` is not a version, and a backend path is not
    either, so neither goes in the version table.
    """
    versions: dict[str, str] = {}
    engines: dict[str, str] = {}
    backends: dict[str, str] = {}

    install = _load(_INSTALL_VERSIONS)
    if install:
        for key, value in install.items():
            if isinstance(value, str) and value.strip():
                versions[str(key)] = value.strip()

    tools = _tool_results(case_root)
    for tool, result in tools.items():
        if not isinstance(result, dict):
            continue
        for key, value in result.items():
            low = key.lower()
            if not isinstance(value, str) or not value.strip():
                continue
            value = value.strip()
            if low in _BACKEND_KEYS:
                backends.setdefault(f"{tool}.{key}", value)
                continue
            if low in _ENGINE_KEYS:
                engines.setdefault(f"{tool}.{key}", value)
                continue
            if low in _VERSION_KEYS or any(t in low for t in ("version", "build")):
                match = _VERSION_RE.search(value)
                if match:
                    versions.setdefault(f"{tool}.{key}", match.group(0))

    if not versions and not engines and not backends and not provenance:
        return ""

    lines = ["## Appendix: Analysis Environment", ""]
    if provenance:
        for key in ("commit", "engine", "generated_utc", "flags"):
            if provenance.get(key):
                lines.append(f"- **RevAI {key}**: {provenance[key]}")
    if install:
        lines.append("- **capture**: install-time manifest "
                     f"(`{_INSTALL_VERSIONS}`)")
    if engines:
        lines.append("- **tool engines**: "
                     + ", ".join(f"{k.split('.', 1)[0]}={v}" for k, v in sorted(engines.items())))
    if backends:
        lines.append("- **capa backend**: "
                     + ", ".join(sorted(backends.values())))
    if versions:
        lines += ["", "| Component | Version |", "|---|---|"]
        for key in sorted(versions):
            lines.append(f"| {key} | {versions[key]} |")
    lines += ["", "_Versions are as reported by the tools in this run; this is not a "
              "full environment manifest._", ""]
    return "\n".join(lines)


# --- MBC vocabulary --------------------------------------------------------


def format_mbc_vocabulary(case_root: Path | None, limit: int = 20) -> str:
    """Malware Behavior Catalog entries carried by capa's rule metadata."""
    tools = _tool_results(case_root)
    entries: dict[str, dict] = {}

    def _visit(node: dict) -> None:
        for key, value in node.items():
            if "mbc" not in key.lower():
                continue
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    parts = item.get("parts") or []
                    entry = {
                        "id": str(item.get("id") or item.get("mbc") or "").strip(),
                        "objective": item.get("objective") or (parts[0] if parts else ""),
                        "behavior": item.get("behavior") or (parts[1] if len(parts) > 1 else ""),
                        "method": item.get("method") or (parts[2] if len(parts) > 2 else ""),
                    }
                elif isinstance(item, str):
                    entry = {"id": "", "objective": "", "behavior": item, "method": ""}
                else:
                    continue
                key = entry["id"] or f"{entry['objective']}|{entry['behavior']}|{entry['method']}"
                if key and key not in entries:
                    entries[key] = entry

    _walk(tools, _visit)
    if not entries:
        return ""

    lines = ["## MBC Vocabulary (from capa rule metadata)", "",
             "The Malware Behavior Catalog objective/behavior/method for the "
             "capabilities capa matched, alongside the ATT&CK mapping above.", "",
             "| MBC ID | Objective | Behavior | Method |", "|---|---|---|---|"]
    for key in sorted(entries)[:limit]:
        entry = entries[key]
        lines.append(f"| {entry['id'] or '-'} | {entry['objective'] or '-'} "
                     f"| {entry['behavior'] or '-'} | {entry['method'] or '-'} |")
    if len(entries) > limit:
        lines.append(f"| ... | {len(entries) - limit} more | | |")
    return "\n".join(lines) + "\n"


# --- attachment ------------------------------------------------------------


def attach_alignment_sections(technical_md: str, *,
                              case_root: Path | None = None,
                              sample_path: str | Path | None = None,
                              provenance: dict | None = None) -> str:
    """Append component inventory, MBC vocabulary and the environment appendix.

    Each part is presence-gated independently; an error in one never removes the
    others and never breaks the report.
    """
    text = technical_md or ""
    resolved_sample = _resolve_sample_path(case_root, sample_path)
    for formatter in (
        lambda: format_component_inventory(resolved_sample),
        lambda: format_mbc_vocabulary(case_root),
        lambda: format_analysis_environment(case_root, provenance=provenance),
    ):
        try:
            block = formatter()
        except Exception:
            block = ""
        if block:
            text = text.rstrip() + "\n\n" + block
    return text


def _resolve_sample_path(case_root: Path | None,
                         sample_path: str | Path | None) -> str | Path | None:
    """Find the analyzed sample when the caller did not pass it.

    session.json lives in the case dir for flat runs and in its parent for
    mode-keyed runs, so both are checked before giving up.
    """
    if sample_path:
        return sample_path
    if case_root is None:
        return None
    for candidate in (case_root / "session.json", case_root.parent / "session.json"):
        session = _load(candidate)
        if session and session.get("sample_path"):
            return session["sample_path"]
    return None
