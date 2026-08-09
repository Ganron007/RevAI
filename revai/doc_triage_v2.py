#!/usr/bin/env python3
"""Initial document triage PDF / OLE / VBA.

Runs at intake/quick when magic is document-like. Does NOT open the file in a GUI viewer.

Tools expected on Remnux (best-effort):
  - pdfid / pdfid.py, pdf-parser.py
  - olevba (oletools)

Corpus for exercising this path (generator, not analyzer):
  Tools/malicious-pdf/  → generate fixtures under /opt/samples/.../test-pdfs/

Usage:
  python3 doc_triage_v2.py <path-or-sha> [--out logs/<sha>/doc_triage.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SAMPLE_ROOT = Path(os.environ.get("REVAI_SAMPLES", "/opt/samples"))


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_sample(arg: str) -> Path:
    p = Path(arg)
    if p.is_file():
        return p.resolve()
    # SHA256 → session sample_path
    if len(arg) == 64 and all(c in "0123456789abcdef" for c in arg.lower()):
        sess = SAMPLE_ROOT / "sessions" / f"{arg.lower()}.json"
        if sess.is_file():
            try:
                data = json.loads(sess.read_text(encoding="utf-8", errors="replace"))
                sp = data.get("sample_path") or ""
                if sp and Path(sp).is_file():
                    return Path(sp).resolve()
            except Exception:
                pass
        # corpus by-sha layout used by intake_v2
        lib = SAMPLE_ROOT / "corpus" / "malware-sample-library" / arg.lower()
        if lib.is_dir():
            for child in lib.iterdir():
                if child.is_file():
                    return child.resolve()
    for cand in (
        SAMPLE_ROOT / "inbox" / arg,
        SAMPLE_ROOT / arg,
        SAMPLE_ROOT / "by-sha" / arg / "sample.bin",
        SAMPLE_ROOT / "logs" / arg / "sample.bin",
    ):
        if cand.is_file():
            return cand.resolve()
    raise FileNotFoundError(f"sample not found for {arg}")


def magic_kind(path: Path) -> str:
    raw = path.read_bytes()[:8]
    if raw.startswith(b"%PDF"):
        return "pdf"
    if raw[:2] == b"PK":
        return "ooxml_or_zip"
    if raw[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    try:
        out = subprocess.check_output(
            ["file", "-b", str(path)], text=True, stderr=subprocess.DEVNULL
        )
        low = out.lower()
        if "pdf" in low:
            return "pdf"
        if "microsoft" in low or "ole" in low or "composite document" in low:
            return "ole"
        if "zip" in low:
            return "ooxml_or_zip"
    except (OSError, subprocess.CalledProcessError):
        pass
    return "unknown"


def run_cmd(argv: list[str], timeout: int = 60) -> dict[str, Any]:
    if not shutil.which(argv[0]) and not Path(argv[0]).is_file():
        return {"ok": False, "skipped": True, "reason": f"missing:{argv[0]}", "argv": argv}
    try:
        cp = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return {
            "ok": cp.returncode == 0,
            "skipped": False,
            "returncode": cp.returncode,
            "stdout": (cp.stdout or "")[:20000],
            "stderr": (cp.stderr or "")[:4000],
            "argv": argv,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "skipped": False, "reason": "timeout", "argv": argv}


def triage_pdf(path: Path) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for argv in (["pdfid", str(path)], ["pdfid.py", str(path)]):
        r = run_cmd(argv)
        if not r.get("skipped"):
            tools["pdfid"] = r
            break
    tools["pdf-parser"] = run_cmd(["pdf-parser.py", "-a", str(path)])
    blob = "\n".join(
        str(t.get("stdout", "")) for t in tools.values() if isinstance(t, dict)
    )
    flags = {
        "has_javascript": "/JS" in blob or "/JavaScript" in blob,
        "has_openaction": "/OpenAction" in blob or "/AA" in blob,
        "has_launch": "/Launch" in blob,
        "has_embedded_file": "/EmbeddedFile" in blob or "/EF" in blob,
        "has_xfa": "/XFA" in blob,
    }
    return {"tools": tools, "flags": flags}


def triage_ole_office(path: Path) -> dict[str, Any]:
    tools = {"olevba": run_cmd(["olevba", "-a", str(path)], timeout=120)}
    blob = tools["olevba"].get("stdout", "") or ""
    no_vba = "no vba" in blob.lower() or "no macros" in blob.lower()
    flags = {
        "has_vba": (not no_vba) and ("vba" in blob.lower() or "macro" in blob.lower()),
        "autoexec": "autoexec" in blob.lower(),
        "suspicious": "suspicious" in blob.lower(),
        "ioc": "ioc:" in blob.lower() or "\nioc" in blob.lower(),
    }
    return {"tools": tools, "flags": flags}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sample", help="Path or sha256")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--logs-root", type=Path, default=SAMPLE_ROOT / "logs")
    args = ap.parse_args()

    path = resolve_sample(args.sample)
    sha = sha256_file(path)
    kind = magic_kind(path)
    result: dict[str, Any] = {
        "schema": "v6.2.1-doc-triage",
        "sha256": sha,
        "path": str(path),
        "kind": kind,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "analyst_next": [],
    }

    if kind == "pdf":
        result["triage"] = triage_pdf(path)
        result["analyst_next"] = [
            "Do not open in host Adobe until isolated viewer + FakeNet ready",
            "If EmbeddedFile/JS: extract streams with pdf-parser; re-intake any PE drop",
            "Exercise corpus only: Tools/malicious-pdf/malicious-pdf.py <interact-url>",
        ]
    elif kind in ("ole", "ooxml_or_zip"):
        result["triage"] = triage_ole_office(path)
        result["analyst_next"] = [
            "Review olevba for AutoExec / shell / URL",
            "If macro drops PE: save payload → intake as child sample",
            "HITL: Word/Excel on Flare snapshot only",
        ]
    else:
        result["triage"] = {"tools": {}, "flags": {}}
        result["skipped"] = True
        result["reason"] = f"not a document magic ({kind})"
        print(json.dumps({"skipped": True, "kind": kind, "sha256": sha}))
        return 0

    out = args.out
    if out is None:
        out_dir = args.logs_root / sha
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "doc_triage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    flags = (result.get("triage") or {}).get("flags") or {}
    md = out.with_suffix(".md")
    md.write_text(
        "\n".join(
            [
                f"# Document triage — `{sha[:16]}…`",
                "",
                f"kind: **{kind}**",
                "",
                "## Flags",
                "",
                *[f"- `{k}`: {v}" for k, v in flags.items()],
                "",
                "## Analyst next",
                "",
                *[f"- {x}" for x in result["analyst_next"]],
                "",
            ]
        ),
        encoding="utf-8",
    )
    print(f"wrote {out}")
    print(f"wrote {md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
