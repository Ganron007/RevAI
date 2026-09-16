"""Offline Windows-API lookup index (runtime).

Deterministic knowledge base for the deep-dive agent: what a Windows API does
and how malware abuses it, so API claims are grounded in a local index instead
of model recall. Knowledge lookup only -- no verdicts, no capability matching
(the pipeline's own `capa` stage owns that; this module never duplicates it).

Sources for the index are documented in `assets/api_index/NOTICE.md`. The index
itself is a SQLite file built by `api_index_build.py`; this module only reads it.

Design contract (matches the rest of revai-tools):
  * stdlib only (sqlite3 / json / re / os) -- flat module, no package, no env
    var required to import;
  * fail-open: every public function returns a dict and never raises; an absent
    or broken index degrades to ``{"available": False, ...}``;
  * read-only connection per call, so concurrent agent steps cannot corrupt
    state.

Index path resolution, first hit wins:
  1. ``$REVAI_API_INDEX``
  2. ``<repo>/assets/api_index/api_index.db``
  3. ``/opt/revai/api_index/api_index.db`` (VM runtime)
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import zlib
from pathlib import Path

INDEX_PATH_ENV = "REVAI_API_INDEX"
SCHEMA_VERSION = 1

_MODULE_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _MODULE_DIR.parent
_CANDIDATE_PATHS = (
    _REPO_ROOT / "assets" / "api_index" / "api_index.db",
    Path("/opt/revai/api_index/api_index.db"),
)

# --- symbol normalization -------------------------------------------------
# Mirrors the upstream plugin's normalize layer so a symbol copied out of a
# disassembler resolves to the row a human would expect: A/W variants, Nt/Zw
# twins, import-thunk decoration and stdcall suffixes all fold together.

_APISET_RE = re.compile(r"^(?:api|ext)-ms-win-", re.IGNORECASE)
_STDCALL_RE = re.compile(r"^_(?P<name>[A-Za-z_][A-Za-z0-9_]*)@\d+$")
_ORDINAL_RE = re.compile(r"^#(?P<ordinal>\d+)$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_MODULE_ALIASES = {
    "kernelbase": "kernel32",
    "ntoskrnl": "ntdll",
    "wow64win": "win32u",
    "sechost": "advapi32",
}

_NATIVE_PREFIXES = ("Nt", "Zw", "Rtl", "Ldr", "Ke", "Csr", "Dbg")


def strip_decoration(name: str) -> str:
    """``__imp_CreateProcessW`` / ``_VirtualAllocEx@20`` -> bare function name."""
    name = (name or "").strip()
    for prefix in ("__imp__", "__imp_", "_imp__", "_imp_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    stdcall = _STDCALL_RE.match(name)
    return stdcall.group("name") if stdcall else name


def fold_charset_suffix(name: str) -> str:
    """Fold an ANSI/Unicode variant onto its base name without eating acronyms."""
    if len(name) < 2 or name[-1] not in ("A", "W"):
        return name
    preceding = name[-2]
    if preceding.islower() or preceding.isdigit():
        return name[:-1]
    if preceding == "_" and len(name) > 2:
        return name[:-2]
    return name


def fold_zw_to_nt(name: str) -> str:
    """``ZwOpenProcess`` -> ``NtOpenProcess`` (same export, different spelling)."""
    if len(name) > 2 and name.startswith("Zw") and name[2].isupper():
        return "Nt" + name[2:]
    return name


def is_native_api(function: str) -> bool:
    return any(
        function.startswith(p) and len(function) > len(p) and function[len(p)].isupper()
        for p in _NATIVE_PREFIXES
    )


def canonical(name: str) -> str:
    """Key stored in ``api.name_norm``; applied identically at build and lookup."""
    return fold_zw_to_nt(fold_charset_suffix(strip_decoration(name))).lower()


def normalize_module(module: str | None) -> tuple[str | None, bool]:
    """Return ``(module_or_None, is_apiset)``; apiset stubs name no real DLL."""
    if not module:
        return None, False
    module = module.strip().strip("<>&").lower()
    for suffix in (".dll", ".exe", ".sys", ".drv", ".lib"):
        if module.endswith(suffix):
            module = module[: -len(suffix)]
    if _APISET_RE.match(module):
        return None, True
    if not module:
        return None, False
    return _MODULE_ALIASES.get(module, module), False


def _build_lookup_keys(function: str) -> list[str]:
    """Ordered exact-spelling candidates, most specific first."""
    keys: list[str] = []

    def push(key: str) -> None:
        if key and key not in keys:
            keys.append(key)

    base = fold_charset_suffix(function)
    push(function)
    push(fold_zw_to_nt(function))
    push(base)
    if not is_native_api(function):
        push(base + "A")
        push(base + "W")
    return keys


def parse_symbol(raw: str) -> dict:
    """Parse anything a disassembler shows into lookup keys.

    Handles ``VirtualAllocEx``, ``kernel32.VirtualAllocEx``, ``<k.VirtualAllocEx>``,
    ``JMP.&GetProcAddress``, ``qword ptr ds:[<&CreateProcessW>]``,
    ``__imp_CreateProcessW``, ``_VirtualAllocEx@20`` and ``kernel32.#123``.
    Module names are advisory metadata only -- never a lookup filter.
    """
    out = {"raw": raw, "function": "", "module": None, "is_apiset": False,
           "ordinal": None, "lookup_keys": [], "canonical_key": ""}
    text = (raw or "").strip()
    if not text:
        return out

    bracketed = re.search(r"\[([^\[\]]+)\]", text)
    if bracketed:
        text = bracketed.group(1)
    text = text.strip().strip("<>").lstrip("&").strip()

    for mnemonic in ("jmp.", "call."):
        if text.lower().startswith(mnemonic):
            text = text[len(mnemonic):].lstrip("&")
            break
    text = text.strip().strip("<>").lstrip("&").strip()
    if not text:
        return out

    module_part: str | None = None
    function_part = text
    # WinDbg/!address style: module!Function
    if "!" in text:
        head, _, tail = text.rpartition("!")
        if head and tail:
            module_part, function_part = head, tail
    elif "." in text:
        head, _, tail = text.rpartition(".")
        if tail.lower() in ("dll", "exe", "sys", "drv"):
            module_part, function_part = text, ""
        elif head:
            module_part, function_part = head, tail

    out["module"], out["is_apiset"] = normalize_module(module_part)
    if not function_part:
        return out

    ordinal = _ORDINAL_RE.match(function_part)
    if ordinal:
        out["ordinal"] = int(ordinal.group("ordinal"))
        return out

    function_part = strip_decoration(function_part)
    if not _IDENT_RE.match(function_part):
        return out

    out["function"] = function_part
    out["lookup_keys"] = _build_lookup_keys(function_part)
    out["canonical_key"] = canonical(function_part)
    return out


# --- index access ---------------------------------------------------------


def index_path() -> Path | None:
    """Resolve the index location; ``None`` when no candidate exists."""
    env = os.environ.get(INDEX_PATH_ENV)
    if env:
        candidate = Path(env)
        return candidate if candidate.is_file() else None
    for candidate in _CANDIDATE_PATHS:
        if candidate.is_file():
            return candidate
    return None


def available() -> bool:
    return index_path() is not None


def _connect() -> tuple[sqlite3.Connection | None, dict]:
    """Open a read-only connection. Returns ``(conn, error)``; error is ``{}`` on success."""
    path = index_path()
    if path is None:
        return None, {
            "available": False,
            "reason": "api index not found",
            "hint": (
                "build it with: python3 api_index_build.py --malapi "
                "assets/api_index/malapi.json --out assets/api_index/api_index.db "
                "(or set REVAI_API_INDEX)"
            ),
        }
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn, {}
    except sqlite3.Error as exc:
        return None, {"available": False, "reason": f"api index unreadable: {exc}"}


def _read(query: str, params: tuple = (), limit: int | None = None):
    """Run a read query fail-open; returns ``(rows, error_dict)``."""
    conn, err = _connect()
    if conn is None:
        return None, err
    try:
        cur = conn.execute(query, params)
        return (cur.fetchall() if limit is None else cur.fetchmany(limit)), {}
    except sqlite3.Error as exc:
        return None, {"available": False, "reason": f"api index query failed: {exc}"}
    finally:
        conn.close()


def _strip_html(text: str | None) -> str:
    if not text:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text)).strip()


def _text_flag(conn: sqlite3.Connection) -> bool:
    """True when documentation fields are zlib-compressed (index meta key)."""
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key = 'text_compression'").fetchone()
    except sqlite3.Error:
        return False
    return bool(row) and str(row[0]).lower() == "zlib"


def _text(value, compressed: bool) -> str | None:
    """Decode a stored documentation field (plain TEXT or zlib BLOB)."""
    if value is None:
        return None
    if isinstance(value, str):
        return value or None
    raw = bytes(value)
    if compressed:
        try:
            raw = zlib.decompress(raw)
        except zlib.error:
            return None
    return raw.decode("utf-8", "replace") or None


def _resolve(symbol: str):
    """Resolve a raw symbol to an API row (exact spellings first, then folded)."""
    parsed = parse_symbol(symbol)
    if not parsed["lookup_keys"]:
        return None
    conn, err = _connect()
    if conn is None:
        return None
    try:
        for key in parsed["lookup_keys"]:
            row = conn.execute(
                "SELECT * FROM api WHERE name = ? LIMIT 1", (key,)
            ).fetchone()
            if row:
                return row
        return conn.execute(
            "SELECT a.* FROM api a LEFT JOIN malapi m ON m.api_id = a.id"
            " WHERE a.name_norm = ?"
            " ORDER BY (m.api_id IS NOT NULL) DESC, a.name LIMIT 1",
            (parsed["canonical_key"],),
        ).fetchone()
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def _malapi_intent(conn, row):
    """Intent row for the API, following charset siblings (labelled by caller)."""
    return conn.execute(
        "SELECT m.*, a.name AS documented_as FROM malapi m"
        " JOIN api a ON a.id = m.api_id"
        " WHERE a.name_norm = ? ORDER BY (a.name = ?) DESC, a.name LIMIT 1",
        (row["name_norm"], row["name"]),
    ).fetchone()


def _categories(conn, row) -> list[str]:
    return [
        r[0]
        for r in conn.execute(
            "SELECT DISTINCT t.name FROM api a"
            " JOIN api_attack aa ON aa.api_id = a.id"
            " JOIN attack t ON t.id = aa.attack_id"
            " WHERE a.name_norm = ? ORDER BY t.name",
            (row["name_norm"],),
        )
    ]


def _syntax_for(conn, row) -> tuple[str | None, str | None]:
    """Signature, following charset siblings; the spelling it came from is returned."""
    if row["syntax"]:
        return row["syntax"], row["name"]
    sibling = conn.execute(
        "SELECT syntax, name FROM api"
        " WHERE name_norm = ? AND syntax IS NOT NULL AND syntax != ''"
        " ORDER BY (name = ?) DESC, name LIMIT 1",
        (row["name_norm"], row["name"]),
    ).fetchone()
    if not sibling:
        return None, None
    return sibling["syntax"], sibling["name"]


def lookup(symbol: str) -> dict:
    """Answer "what is this API and how is it abused?" for one symbol.

    Returns a plain dict (JSON-ready) so it can be handed to the agent verbatim.
    """
    if not (symbol or "").strip():
        return {"available": True, "found": False, "symbol": symbol,
                "note": "empty symbol"}

    conn, err = _connect()
    if conn is None:
        return err
    try:
        row = _resolve(symbol)
        if row is None:
            parsed = parse_symbol(symbol)
            return {
                "available": True,
                "found": False,
                "symbol": symbol,
                "function": parsed["function"] or None,
                "note": (
                    "no index entry -- it may be an internal/non-Windows function "
                    "or misspelled. Do not guess at its behaviour; report it as "
                    "not found."
                ),
            }

        intent = _malapi_intent(conn, row)
        syntax, syntax_name = _syntax_for(conn, row)
        compressed = _text_flag(conn)
        params = conn.execute(
            "SELECT name, desc_text FROM api_param WHERE api_id = ? ORDER BY ord",
            (row["id"],),
        ).fetchall()

        result = {
            "available": True,
            "found": True,
            "name": row["name"],
            "dll": row["dll"],
            "header": row["header"],
            "source": row["source"],
            "doc_url": row["doc_url"],
            "doc": _text(row["doc_text"], compressed),
            "returns": _text(row["return_text"], compressed),
            "params": [
                {"name": p["name"],
                 "description": _strip_html(_text(p["desc_text"], compressed))}
                for p in params
            ],
        }
        if syntax:
            result["syntax"] = syntax
            if syntax_name != row["name"]:
                result["syntax_documented_as"] = syntax_name
        if intent:
            result["malicious_use"] = {
                "description": intent["description"],
                "documented_as": intent["documented_as"],
                "categories": _categories(conn, row),
                "credits": intent["credits"],
                "source_url": intent["source_url"],
            }
        else:
            result["malicious_use"] = None
            result["note"] = (
                "no malicious-use write-up: this API is not among the catalogued "
                "commonly abused APIs. Absence of curated data, not evidence of "
                "benign behaviour."
            )
        return result
    except sqlite3.Error as exc:
        return {"available": False, "reason": f"api lookup failed: {exc}"}
    finally:
        conn.close()


def _fts_expression(query: str) -> str | None:
    """Turn typed input into a safe FTS5 expression (last token becomes a prefix)."""
    query = (query or "").strip()
    if not query:
        return None
    if any(ch in query for ch in '"*():') or re.search(r"\b(AND|OR|NOT|NEAR)\b", query):
        return query
    tokens = re.findall(r"[A-Za-z0-9_]+", query)
    if not tokens:
        return None
    quoted = [f'"{t}"' for t in tokens[:-1]]
    quoted.append(f'"{tokens[-1]}"*')
    return " ".join(quoted)


def search(query: str, limit: int = 20) -> dict:
    """Full-text search across API names and descriptions."""
    expression = _fts_expression(query)
    if not expression:
        return {"available": True, "found": False, "query": query,
                "note": "empty query"}
    limit = max(1, min(int(limit or 20), 50))

    conn, err = _connect()
    if conn is None:
        return err
    try:
        sql = (
            "SELECT a.name, a.dll, snippet(api_fts, 1, '', '', '...', 12) AS excerpt"
            " FROM api_fts f JOIN api a ON a.id = f.rowid"
            " WHERE api_fts MATCH ? ORDER BY rank LIMIT ?"
        )
        try:
            rows = conn.execute(sql, (expression, limit)).fetchall()
        except sqlite3.OperationalError:
            literal = '"{}"'.format(query.replace('"', ""))
            try:
                rows = conn.execute(sql, (literal, limit)).fetchall()
            except sqlite3.OperationalError:
                rows = []
        return {
            "available": True,
            "found": bool(rows),
            "query": query,
            "results": [
                {"name": r["name"], "dll": r["dll"],
                 "excerpt": _strip_html(r["excerpt"])}
                for r in rows
            ],
        }
    except sqlite3.Error as exc:
        return {"available": False, "reason": f"api search failed: {exc}"}
    finally:
        conn.close()


def attack_categories() -> dict:
    """The malapi.io attack categories and how many APIs each covers."""
    rows, err = _read(
        "SELECT t.name AS name, COUNT(*) AS n FROM attack t"
        " JOIN api_attack aa ON aa.attack_id = t.id"
        " GROUP BY t.name ORDER BY n DESC, t.name"
    )
    if rows is None:
        return err
    return {"available": True,
            "categories": [{"name": r["name"], "api_count": r["n"]} for r in rows]}


def apis_by_attack(category: str, limit: int = 50) -> dict:
    """APIs catalogued under one attack category."""
    limit = max(1, min(int(limit or 50), 200))
    rows, err = _read(
        "SELECT a.name AS name, a.dll AS dll, m.description AS description"
        " FROM api a JOIN api_attack aa ON aa.api_id = a.id"
        " JOIN attack t ON t.id = aa.attack_id JOIN malapi m ON m.api_id = a.id"
        " WHERE t.name = ? COLLATE NOCASE ORDER BY a.name LIMIT ?",
        (category, limit),
    )
    if rows is None:
        return err
    if not rows:
        known = [r["name"] for r in (attack_categories().get("categories") or [])]
        return {"available": True, "category": category, "apis": [],
                "note": f"no category {category!r}", "known_categories": known}
    return {
        "available": True,
        "category": category,
        "apis": [
            {"name": r["name"], "dll": r["dll"],
             "description": (r["description"] or "")[:200]}
            for r in rows
        ],
    }


def index_info() -> dict:
    """Coverage, build provenance and the attribution stored in the index."""
    conn, err = _connect()
    if conn is None:
        return err
    try:
        meta = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM meta")}
        counts = {
            "apis": conn.execute("SELECT COUNT(*) FROM api").fetchone()[0],
            "with_malicious_use": conn.execute(
                "SELECT COUNT(*) FROM malapi").fetchone()[0],
            "attack_categories": conn.execute(
                "SELECT COUNT(*) FROM attack").fetchone()[0],
            "with_signature": conn.execute(
                "SELECT COUNT(*) FROM api WHERE syntax IS NOT NULL AND syntax != ''"
            ).fetchone()[0],
        }
        return {
            "available": True,
            "path": str(index_path()),
            "schema_version": meta.get("schema_version"),
            "built_utc": meta.get("built_utc"),
            "counts": counts,
            "sources": meta.get("sources"),
            "attribution": {k: v for k, v in meta.items()
                            if k.startswith("attribution.")},
        }
    except sqlite3.Error as exc:
        return {"available": False, "reason": f"api index info failed: {exc}"}
    finally:
        conn.close()


# --- CLI rendering --------------------------------------------------------


def render(result: dict) -> str:
    """Plain-text rendering for the CLI (never HTML)."""
    if not result or not result.get("available"):
        reason = (result or {}).get("reason", "unavailable")
        hint = (result or {}).get("hint", "")
        return f"api_lookup: {reason}" + (f"\n  {hint}" if hint else "")

    if "results" in result:
        if not result.get("results"):
            return f"no matches for {result.get('query')!r}"
        out = [f"{len(result['results'])} matches for {result['query']!r}:"]
        for item in result["results"]:
            dll = f"{item['dll']}!" if item.get("dll") else ""
            out.append(f"  {dll}{item['name']}: {item.get('excerpt', '')}")
        return "\n".join(out)

    if "categories" in result:
        out = ["malapi.io attack categories:"]
        out += [f"  {c['name']}: {c['api_count']} APIs" for c in result["categories"]]
        return "\n".join(out)

    if "apis" in result:
        if not result["apis"]:
            return f"no APIs for category {result.get('category')!r}"
        out = [f"{len(result['apis'])} APIs in {result['category']}:"]
        for item in result["apis"]:
            dll = f"{item['dll']}!" if item.get("dll") else ""
            out.append(f"  {dll}{item['name']}: {item.get('description', '')}")
        return "\n".join(out)

    if "counts" in result:
        lines = [f"index: {result.get('path')}",
                 f"built: {result.get('built_utc')}",
                 f"sources: {result.get('sources')}"]
        lines += [f"  {k}: {v:,}" for k, v in result["counts"].items()]
        attribution = result.get("attribution") or {}
        if attribution:
            lines.append("attribution:")
            lines += [f"  {v}" for _, v in sorted(attribution.items())]
        return "\n".join(lines)

    if not result.get("found"):
        return f"no index entry for {result.get('symbol')!r}\n  {result.get('note', '')}"

    header = result["name"]
    if result.get("dll"):
        header = f"{result['dll']}!{result['name']}"
    out = [header, "=" * len(header)]

    intent = result.get("malicious_use")
    if intent:
        out += ["", "MALICIOUS USE", f"  {intent['description']}"]
        if intent.get("documented_as") and intent["documented_as"] != result["name"]:
            out.append(f"  (malapi.io documents this as {intent['documented_as']})")
        if intent.get("categories"):
            out.append(f"  Categories: {', '.join(intent['categories'])}")
    elif result.get("note"):
        out += ["", f"NOTE: {result['note']}"]

    if result.get("syntax"):
        out.append("")
        out.append("SYNTAX")
        if result.get("syntax_documented_as"):
            out.append(f"  (signature shown is {result['syntax_documented_as']}'s)")
        out += [f"  {line}" for line in result["syntax"].splitlines()]

    if result.get("doc"):
        out += ["", "DOCUMENTATION", f"  {result['doc'][:1200]}"]
    if result.get("params"):
        out += ["", "PARAMETERS"]
        for p in result["params"]:
            out.append(f"  {p['name']}")
            if p.get("description"):
                out.append(f"    {p['description'][:300]}")
    if result.get("returns"):
        out += ["", "RETURN VALUE", f"  {result['returns'][:400]}"]
    if result.get("header") or result.get("doc_url"):
        out.append("")
        if result.get("header"):
            out.append(f"Header: {result['header']}")
        if result.get("doc_url"):
            out.append(f"Docs:   {result['doc_url']}")
    return "\n".join(out)


def lookup_json(symbol: str) -> str:
    """Convenience for the CLI: compact JSON result."""
    return json.dumps(lookup(symbol), ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    """Standalone entry point (``python3 api_lookup.py <symbol|--search q>``)."""
    import argparse

    parser = argparse.ArgumentParser(description="offline Windows-API lookup index")
    parser.add_argument("symbol", nargs="?", help="API symbol as a disassembler shows it")
    parser.add_argument("--search", metavar="QUERY", help="full-text search instead")
    parser.add_argument("--category", metavar="NAME", help="APIs in one attack category")
    parser.add_argument("--categories", action="store_true", help="list attack categories")
    parser.add_argument("--info", action="store_true", help="index provenance and coverage")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    if args.info:
        result = index_info()
    elif args.categories:
        result = attack_categories()
    elif args.category:
        result = apis_by_attack(args.category)
    elif args.search:
        result = search(args.search)
    elif args.symbol:
        result = lookup(args.symbol)
    else:
        parser.error("provide a symbol, --search, --category, --categories or --info")

    print(json.dumps(result, ensure_ascii=False, indent=1)
          if args.json else render(result))
    return 0 if result.get("available") else 2


if __name__ == "__main__":
    raise SystemExit(main())
