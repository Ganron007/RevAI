"""Build the offline Windows-API lookup index (`api_index.db`).

Stdlib only. Two sources, merged into one SQLite file:

  * `malapi.json` (required) -- malapi.io's malicious-use descriptions, the
    eight attack categories, and a signature/parameter fallback for the APIs
    Microsoft does not document in markdown (the Nt*/Rtl* natives).
  * `--sdk-api DIR` (optional) -- a checkout of MicrosoftDocs/sdk-api (plus
    windows-driver-docs-ddi) whose `nf-*.md` function pages extend coverage from
    369 APIs to essentially all of Win32. Markdown is rendered to plain text;
    no third-party HTML renderer is needed because the consumer is a text/LLM
    pipeline, not a rich-text panel.

Usage:

    python3 api_index_build.py --malapi assets/api_index/malapi.json \\
        --out assets/api_index/api_index.db
    python3 api_index_build.py --malapi assets/api_index/malapi.json \\
        --sdk-api /path/to/sdk-api/sdk-api-src/content --out api_index.db

Attribution for the redistributed content is written into the index's `meta`
table (see `assets/api_index/NOTICE.md`) so it travels with the file.

The capability ("capa combination") layer of the upstream plugin is
deliberately NOT ingested: capability matching is already performed by the
pipeline's own `capa` stage, and a second, weaker answer to the same question
adds no evidence.
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
import zlib
from datetime import datetime, timezone
from pathlib import Path

from api_lookup import SCHEMA_VERSION, canonical

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_MALAPI = _REPO_ROOT / "assets" / "api_index" / "malapi.json"
_DEFAULT_OUT = _REPO_ROOT / "assets" / "api_index" / "api_index.db"

#: malapi.io's attack categories, declared so an unexpected ninth fails loudly.
KNOWN_ATTACKS = (
    "Anti-Debugging",
    "Enumeration",
    "Evasion",
    "Helper",
    "Injection",
    "Internet",
    "Ransomware",
    "Spying",
)

ATTRIBUTION_MALAPI = (
    "API abuse descriptions and attack categories from malapi.io "
    "(https://malapi.io), curated by mr.d0x and contributors. "
    "Not affiliated with or endorsed by malapi.io."
)
ATTRIBUTION_SDK_API = (
    "Windows API reference documentation (c) Microsoft Corporation, from "
    "MicrosoftDocs/sdk-api and MicrosoftDocs/windows-driver-docs-ddi, "
    "licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/)."
)

SCHEMA = """
PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE api (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    name_norm TEXT NOT NULL,
    dll       TEXT,
    header    TEXT,
    syntax    TEXT,
    doc_text  TEXT,
    return_text TEXT,
    doc_url   TEXT,
    source    TEXT NOT NULL
);
CREATE INDEX api_name_norm_idx ON api (name_norm);

CREATE TABLE api_param (
    api_id    INTEGER NOT NULL,
    ord       INTEGER NOT NULL,
    name      TEXT NOT NULL,
    desc_text TEXT,
    PRIMARY KEY (api_id, ord)
) WITHOUT ROWID;

CREATE TABLE malapi (
    api_id      INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    credits     TEXT,
    created     TEXT,
    last_update TEXT,
    source_url  TEXT
);

CREATE TABLE attack (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE api_attack (
    api_id    INTEGER NOT NULL,
    attack_id INTEGER NOT NULL,
    PRIMARY KEY (api_id, attack_id)
) WITHOUT ROWID;
CREATE INDEX api_attack_attack_idx ON api_attack (attack_id);

CREATE VIRTUAL TABLE api_fts USING fts5 (
    name,
    body,
    tokenize = 'unicode61'
);
"""

# --- markdown -> plain text (only what sdk-api pages contain) --------------

_FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", re.DOTALL)
_SECTION_RE = re.compile(r"^##\s+-(\w[\w-]*)\s*$", re.MULTILINE)
_PARAM_RE = re.compile(r"^###\s+-param\s+(\S+)\s*(?:\[([^\]]*)\])?\s*$", re.MULTILINE)
_SCALAR_RE = re.compile(r"^([\w.\-]+):[ \t]*(.*)$")
_LIST_ITEM_RE = re.compile(r"^[ \t]*-[ \t]*(.+?)[ \t]*$")
_FUNCTION_UID_RE = re.compile(r"^N[FC]:", re.IGNORECASE)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

_CODE_FENCE_RE = re.compile(r"^\s*```.*$", re.MULTILINE)
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_TAG_RE = re.compile(r"<[^>]+>")
_EMPH_RE = re.compile(r"[*_`]{1,3}")
_WS_RE = re.compile(r"[ \t]+")


def markdown_to_text(text: str | None) -> str | None:
    """Flatten markdown/HTML prose to plain text (links keep their label)."""
    if not text or not text.strip():
        return None
    text = _CODE_FENCE_RE.sub("", text)
    text = _LINK_RE.sub(r"\1", text)
    text = _TAG_RE.sub(" ", text)
    text = _EMPH_RE.sub("", text)
    text = text.replace("\r\n", "\n")
    paragraphs = []
    for chunk in re.split(r"\n\s*\n", text):
        collapsed = _WS_RE.sub(" ", chunk.replace("\n", " ")).strip()
        if collapsed:
            paragraphs.append(collapsed)
    return "\n".join(paragraphs) or None


def parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """Split a document into a small frontmatter mapping and its body."""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text
    header, body = match.group(1), match.group(2)
    fields: dict[str, object] = {}
    current_list: list[str] | None = None

    for line in header.splitlines():
        if not line.strip():
            continue
        if current_list is not None:
            item = _LIST_ITEM_RE.match(line)
            if item and (line.startswith((" ", "\t", "-"))):
                current_list.append(_unquote(item.group(1)))
                continue
            current_list = None
        scalar = _SCALAR_RE.match(line)
        if not scalar:
            continue
        key, value = scalar.group(1), scalar.group(2).strip()
        if value:
            fields[key] = _unquote(value)
        else:
            current_list = []
            fields[key] = current_list
    return fields, body


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def split_sections(body: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(body))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        sections[match.group(1).lower()] = body[match.end():end].strip()
    return sections


def split_params(section: str) -> list[tuple[str, str]]:
    params: list[tuple[str, str]] = []
    matches = list(_PARAM_RE.finditer(section))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        params.append((match.group(1).strip(), section[match.end():end].strip()))
    return params


def _normalize_dll(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    dll = value.split(",")[0].strip()
    for suffix in (".dll", ".sys", ".lib", ".exe"):
        if dll.lower().endswith(suffix):
            dll = dll[: -len(suffix)]
            break
    return dll.lower() or None


def _first_token(value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.split(",")[0].strip() or None


def _maybe_compress(text: str | None) -> bytes | None:
    """zlib-compress a documentation field (stored compressed, read by the runtime).

    Plain text at 46k documented APIs is tens of megabytes; per-row zlib with no
    dictionary keeps the artifact small and the runtime trivial
    (`zlib.decompress`). Uniform: every non-empty field is compressed, so the
    reader has one path, signalled by the index's `text_compression` meta key.
    """
    if not text:
        return None
    return zlib.compress(text.encode("utf-8"), 9)


def load_sdk_api(root: Path, limit: int | None = None) -> list[dict]:
    """Read ``nf-*.md`` function pages into plain rows (one per declared name)."""
    rows: list[dict] = []
    paths = sorted(root.rglob("nf-*.md"))
    if limit:
        paths = paths[: limit * 2]
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fields, body = parse_frontmatter(text)
        if not _FUNCTION_UID_RE.match(str(fields.get("UID") or "")):
            continue
        names, is_interface = _pick_names(fields, str(fields.get("UID") or ""))
        if not names:
            continue
        sections = split_sections(body)
        syntax = markdown_to_text(sections.get("syntax", ""))
        doc = markdown_to_text(sections.get("description", ""))
        returns = markdown_to_text(sections.get("returns", ""))
        params = [
            {"name": name, "description": markdown_to_text(desc)}
            for name, desc in split_params(sections.get("parameters", ""))
        ]
        doc_url = None
        if path.stem.startswith("nf-"):
            doc_url = ("https://learn.microsoft.com/windows/win32/api/"
                       f"{path.parent.name}/{path.stem}")
        for name in names:
            rows.append({
                "name": name,
                "dll": _normalize_dll(fields.get("req.dll")),
                "header": _first_token(fields.get("req.header")),
                "syntax": syntax,
                "doc_text": doc,
                "return_text": returns,
                "doc_url": doc_url,
                "params": params,
                "interface_method": is_interface,
            })
            if limit and len(rows) >= limit:
                return rows
    return rows


def _pick_names(fields: dict[str, object], uid: str) -> tuple[list[str], bool]:
    """Function names a document declares, plus whether they are interface methods.

    Most pages carry plain Win32 names. A large minority describe COM interface
    methods as ``IThing.Method`` (or ``IThing::Method``); those yield the method
    name alone, flagged so that on a name collision a real function always wins
    over an interface method of the same name (``Next``, ``Reset``, ...).
    """
    api_name = fields.get("api_name")
    if isinstance(api_name, list):
        candidates = api_name
    elif isinstance(api_name, str):
        candidates = [api_name]
    else:
        candidates = []

    plain: list[str] = []
    interface: list[str] = []
    for candidate in candidates:
        raw = str(candidate).strip()
        derived = "::" in raw or "." in raw
        name = raw
        if "::" in name:
            name = name.rsplit("::", 1)[-1].strip()
        if "." in name:
            name = name.rsplit(".", 1)[-1].strip()
        if not name or not _IDENTIFIER_RE.match(name):
            continue
        target = interface if derived else plain
        if name not in target:
            target.append(name)

    if plain:
        return plain, False
    if interface:
        return interface, True

    # UID looks like "NF:memoryapi.VirtualAllocEx": keep the last segment.
    tail = uid.split(":", 1)[-1].rsplit(".", 1)[-1].strip()
    if tail and _IDENTIFIER_RE.match(tail):
        return [tail], True
    return [], True


def load_malapi(path: Path) -> list[dict]:
    """Read the malapi.json snapshot (list of entries)."""
    entries = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON array of API entries")
    out: list[dict] = []
    for entry in entries:
        name = (entry.get("name") or "").strip()
        if not name:
            raise ValueError(f"{path}: entry without a name: {entry!r}")
        attacks = list(entry.get("attacks") or ())
        unknown = set(attacks) - set(KNOWN_ATTACKS)
        if unknown:
            raise ValueError(f"{name}: unrecognised attack categories {sorted(unknown)}")
        dll = entry.get("dll_normalized") or entry.get("library") or None
        if isinstance(dll, str):
            dll = _normalize_dll(dll)
        out.append({
            "name": name,
            "dll": dll,
            "header": entry.get("header") or None,
            "syntax": (entry.get("syntax") or "").strip() or None,
            # malapi's `description` is the malicious-use write-up, not reference
            # documentation; it is stored in the malapi table, not duplicated here.
            "doc_text": None,
            "return_text": markdown_to_text(entry.get("return_value")),
            "doc_url": entry.get("syntax_url") or entry.get("documentation_url") or None,
            "params": [
                {"name": (p.get("name") or "").strip(),
                 "description": markdown_to_text(p.get("description"))}
                for p in entry.get("parameters") or ()
            ],
            "malapi": {
                "description": (entry.get("description") or "").strip(),
                "credits": entry.get("credits") or None,
                "created": entry.get("created") or None,
                "last_update": entry.get("last_update") or None,
                "source_url": entry.get("source_url") or None,
            },
            "attacks": attacks,
        })
    return out


def build(malapi_path: Path, out_path: Path,
          sdk_api_root: Path | None = None,
          sdk_api_roots: list[Path] | None = None,
          limit: int | None = None) -> dict:
    """Build the index. Returns a summary dict (also written to stdout by main)."""
    roots: list[Path] = []
    for root in ([] if sdk_api_roots is None else list(sdk_api_roots)) + (
            [] if sdk_api_root is None else [sdk_api_root]):
        if root is not None and root not in roots:
            roots.append(root)

    malapi_rows = load_malapi(malapi_path)
    if limit:
        malapi_rows = malapi_rows[:limit]

    merged: dict[str, dict] = {}
    for row in malapi_rows:
        row["source"] = "malapi"
        row["malapi_info"] = row.pop("malapi")
        row["attacks"] = row.pop("attacks")
        merged[row["name"]] = row

    sdk_count = 0
    interface_kept = 0
    interface_shadowed = 0
    for root in roots:
        for row in load_sdk_api(root, limit=limit):
            sdk_count += 1
            row["source"] = "sdk-api"
            row["malapi_info"] = None
            row["attacks"] = []
            existing = merged.get(row["name"])
            if existing is None:
                merged[row["name"]] = row
                interface_kept += 1 if row.get("interface_method") else 0
                continue
            # A COM interface method must never displace a real function or a
            # malapi entry that happens to share the method's name.
            if row.get("interface_method") and not existing.get("interface_method"):
                interface_shadowed += 1
                continue
            # Merge: Microsoft's documentation wins where it exists; malapi's
            # intent layer and any signature it alone carries are preserved.
            for field in ("doc_text", "return_text", "doc_url", "header", "dll"):
                if row.get(field):
                    existing[field] = row[field]
            if row.get("syntax") and not existing.get("syntax"):
                existing["syntax"] = row["syntax"]
            if row.get("params"):
                existing["params"] = row["params"]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()

    conn = sqlite3.connect(str(out_path))
    try:
        conn.executescript(SCHEMA)
        attacks_seen: dict[str, int] = {}
        api_rows = sorted(merged.values(), key=lambda r: r["name"].lower())
        for api_id, row in enumerate(api_rows, start=1):
            conn.execute(
                "INSERT INTO api (id, name, name_norm, dll, header, syntax,"
                " doc_text, return_text, doc_url, source)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (api_id, row["name"], canonical(row["name"]), row.get("dll"),
                 row.get("header"), row.get("syntax"),
                 _maybe_compress(row.get("doc_text")),
                 _maybe_compress(row.get("return_text")),
                 row.get("doc_url"), row["source"]),
            )
            for ord_, param in enumerate(row.get("params") or ()):
                conn.execute(
                    "INSERT INTO api_param (api_id, ord, name, desc_text)"
                    " VALUES (?,?,?,?)",
                    (api_id, ord_, param.get("name") or "",
                     _maybe_compress(param.get("description"))),
                )
            if row.get("malapi_info"):
                info = row["malapi_info"]
                conn.execute(
                    "INSERT INTO malapi (api_id, description, credits, created,"
                    " last_update, source_url) VALUES (?,?,?,?,?,?)",
                    (api_id, info["description"], info.get("credits"),
                     info.get("created"), info.get("last_update"),
                     info.get("source_url")),
                )
            for attack in row.get("attacks") or ():
                attacks_seen.setdefault(attack, 0)
                attacks_seen[attack] += 1
                conn.execute("INSERT OR IGNORE INTO attack (name) VALUES (?)",
                             (attack,))
                attack_id = conn.execute(
                    "SELECT id FROM attack WHERE name = ?", (attack,)
                ).fetchone()[0]
                conn.execute(
                    "INSERT OR IGNORE INTO api_attack (api_id, attack_id) VALUES (?,?)",
                    (api_id, attack_id),
                )
            # FTS holds a plain-text excerpt only: the full text is compressed in
            # `api`, and duplicating all 46k documents into the FTS index would
            # double the artifact for no lookup benefit.
            body = row.get("doc_text") or (row.get("malapi_info") or {}).get(
                "description") or ""
            conn.execute(
                "INSERT INTO api_fts (rowid, name, body) VALUES (?,?,?)",
                (api_id, row["name"], body[:600]),
            )

        sources = "malapi" if not roots else "malapi+sdk-api"
        meta = {
            "schema_version": str(SCHEMA_VERSION),
            "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generator": "revai/api_index_build.py",
            "sources": sources,
            "text_compression": "zlib",
            "api_count": str(len(api_rows)),
            "malapi_count": str(sum(1 for r in api_rows if r.get("malapi_info"))),
            "sdk_api_count": str(sdk_count),
            "interface_method_count": str(interface_kept),
            "attribution.malapi": ATTRIBUTION_MALAPI,
        }
        if roots:
            meta["attribution.sdk-api"] = ATTRIBUTION_SDK_API
        conn.executemany("INSERT INTO meta (key, value) VALUES (?,?)",
                         sorted(meta.items()))
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()

    return {
        "out": str(out_path),
        "apis": len(merged),
        "sdk_api_pages": sdk_count,
        "interface_methods": interface_kept,
        "interface_shadowed": interface_shadowed,
        "attacks": attacks_seen,
        "size_bytes": out_path.stat().st_size,
        "sources": "malapi" if not roots else "malapi+sdk-api",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the offline Windows-API lookup index.")
    parser.add_argument("--malapi", type=Path, default=_DEFAULT_MALAPI,
                        help="malapi.json snapshot (required source)")
    parser.add_argument("--sdk-api", type=Path, action="append", default=None,
                        help="sdk-api content root containing nf-*.md pages "
                             "(repeatable: sdk-api + windows-driver-docs-ddi)")
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT,
                        help="output SQLite index path")
    parser.add_argument("--limit", type=int, default=None,
                        help="build a truncated index (for tests)")
    args = parser.parse_args(argv)

    if not args.malapi.is_file():
        print(f"api_index_build: malapi source not found: {args.malapi}",
              file=sys.stderr)
        return 2
    for root in args.sdk_api or []:
        if not root.is_dir():
            print(f"api_index_build: --sdk-api is not a directory: {root}",
                  file=sys.stderr)
            return 2

    summary = build(args.malapi, args.out, sdk_api_roots=args.sdk_api,
                    limit=args.limit)
    print(f"api_index_build: {summary['apis']} APIs "
          f"({summary['sdk_api_pages']} sdk-api pages, "
          f"{summary['interface_methods']} interface methods, "
          f"{summary['interface_shadowed']} shadowed) -> {summary['out']} "
          f"({summary['size_bytes'] / 1024:.0f} KB, sources={summary['sources']})")
    for name, count in sorted(summary["attacks"].items()):
        print(f"  {name}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
