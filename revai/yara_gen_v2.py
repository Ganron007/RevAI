#!/usr/bin/env python3
"""
yara_gen_v2.py — YARA + Sigma from SQL strings, yarGen optional, goodware FP check (plan v2 T4).

Usage:
  python3 /opt/scripts/yara_gen_v2.py <sha256> [--family unknown] [--yargen]
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/opt/scripts")
from ioc_confidence import annotate as annotate_ioc_confidence  # noqa: E402
from v2_lib import (  # noqa: E402
    McpGhidraClient,
    audit_write,
    case_dir,
    goodware_fp_scan,
    hitl_checkpoint,
    ida_query_remote,
    load_session,
    revai_provenance,
    revai_tools_iocs,
    yara_rule_validate,
)

LOGS = Path("/opt/samples/logs")
YARGEN_BIN = "yarGen"


def slugify(text: str) -> str:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    text = re.sub(r"[^a-zA-Z0-9_]+", "_", text).strip("_").lower()
    return (text[:48] or "rule")


def compute_imphash(sample_path: Path) -> str | None:
    """Imphash as a detection anchor. pefile, failure-safe."""
    try:
        import pefile  # verified installed (v2_lib uses it)

        # NOTE: fast_load=True skips the import directory -> get_imphash fails.
        pe = pefile.PE(str(sample_path))
        try:
            return pe.get_imphash()
        finally:
            pe.close()
    except Exception:
        return None


def file_hashes(sample_path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        data = sample_path.read_bytes()
        out["sha256"] = hashlib.sha256(data).hexdigest()
        out["sha1"] = hashlib.sha1(data).hexdigest()
        out["md5"] = hashlib.md5(data).hexdigest()
    except Exception:
        pass
    return out


def collect_strings(session_id: str, ida_id: str | None, verdict: dict | None,
                    sha256: str | None = None) -> list[str]:
    strings: list[str] = []
    # FLOSS / XOR-recovered strings from the quick_scan cache (deterministic tools
    # already ran; reuse, don't re-run). Gap #7: rules were SQL-strings-only.
    if sha256:
        try:
            qs = json.loads((case_dir(sha256) / "quick_scan" / "00-tools-raw.json").read_text())
            for src_key in ("floss", "xor"):
                rows = (qs.get(src_key) or {}).get("strings") or []
                if isinstance(rows, list):
                    for item in rows:
                        s = str(item if isinstance(item, str) else (item.get("string") or item.get("s") or ""))
                        if 8 <= len(s) <= 128 and s.isprintable():
                            strings.append(s)
        except Exception:
            pass
    sql_g = "SELECT content FROM strings WHERE length(content) >= 8 ORDER BY length(content) DESC LIMIT 80"
    # Ghidra may be down (e.g. analyzeHeadless died) — never abort yara_gen.
    try:
        client = McpGhidraClient()
        try:
            r = client.ghidra_query(session_id, sql_g, max_rows=80)
            for row in r.get("rows") or []:
                s = (row.get("content") or "").strip()
                if 8 <= len(s) <= 128 and s.isprintable():
                    strings.append(s)
        finally:
            client.close()
    except Exception:
        pass
    if ida_id:
        try:
            r = ida_query_remote(ida_id, sql_g)
            for row in r.get("rows") or []:
                s = (row.get("content") or "").strip()
                if 8 <= len(s) <= 128 and s.isprintable():
                    strings.append(s)
        except Exception:
            pass
    if verdict:
        for item in verdict.get("key_evidence") or []:
            if isinstance(item, dict) and item.get("why"):
                strings.append(str(item["why"])[:120])
        for item in verdict.get("iocs") or []:
            strings.append(str(item)[:120])
    seen: set[str] = set()
    out = []
    for s in strings:
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out[:24]


# Strings effectively universal across PE/CRT binaries — they must never
# carry a detection condition on their own. WinRE flagged near-universal
# CADRE_v2 rules caused by counting the DOS-header hex signature plus one
# generic API string toward "2 of them".
_GENERIC_TOKENS = {
    "kernel32", "kernel32.dll", "user32", "user32.dll", "advapi32",
    "advapi32.dll", "ntdll", "ntdll.dll", "msvcrt", "msvcrt.dll",
    "gdi32", "gdi32.dll", "ole32", "ole32.dll", "shell32", "shell32.dll",
    "ws2_32", "ws2_32.dll", "vcruntime140.dll", "ucrtbase.dll",
    "exitprocess", "loadlibrarya", "loadlibraryw", "loadlibraryexa",
    "loadlibraryexw", "getprocaddress", "virtualalloc", "virtualprotect",
    "virtualfree", "createthread", "createprocessa", "createprocessw",
    "createfilea", "createfilew", "writefile", "readfile", "closehandle",
    "getlasterror", "getmodulehandlea", "getmodulehandlew",
    "getmodulefilenamea", "getmodulefilenamew", "setunhandledexceptionfilter",
    "unhandledexceptionfilter", "initializecriticalsection",
    "initializecriticalsectionex", "entercriticalsection",
    "leavecriticalsection", "deletecriticalsection",
    "interlockedpushentryslist", "interlockedpopentryslist",
    "expandenvironmentstringsw", "getsystemwindowsdirectoryw",
    "changewindowmessagefilter", "changewindowmessagefilterex",
    "isprocessorfeaturepresent", "gettickcount", "queryperformancecounter",
    "heapalloc", "heapfree", "getprocessheap", "widechartomultibyte",
    "multibytetowidechar", "lstrlena", "lstrlenw", "comparestringa",
    "comparestringw", "regopenkeyexa", "regopenkeyexw", "regcreatekeyexa",
    "regcreatekeyexw", "regsetvalueexa", "regsetvalueexw", "regqueryvalueexa",
    "regqueryvalueexw", "regclosekey", "regdeletevaluea", "regdeletevaluew",
    "gettemppatha", "gettemppathw", "getwindowscurrentdirectory",
    "setfileattributesa", "setfileattributesw", "getfileattributesa",
    "getfileattributesw", "deletefilea", "deletefilew", "sleep",
}

_GENERIC_MARKERS = (
    "this program cannot be run in dos mode", "<?xml", "manifestversion",
    "assemblyidentity", "requestedexecutionlevel", "urn:schemas-microsoft-com",
    "mscoree", ".net framework", "all rights reserved",
)

# Single CamelCase token with an optional A/W/Ex suffix: the shape of a
# Windows API / runtime function name. Bare API names are import-surface
# boilerplate, not detection material (WinRE FP finding).
_API_NAME_RE = re.compile(r"^[A-Z][A-Za-z0-9]{4,39}(ExA|ExW|Ex|A|W)?$")


def is_generic_rule_string(s: str) -> bool:
    """True for strings too common to support a detection condition."""
    t = s.strip().lower()
    if not t:
        return True
    if t in _GENERIC_TOKENS:
        return True
    if s.strip().startswith("?"):  # MSVC-mangled C++ symbols (?...@@ / ??...@@)
        return True
    if t.startswith(("api-ms-win-", "ext-ms-win-")):
        return True
    if _API_NAME_RE.match(s.strip()):  # AllocateAndInitializeSid, SleepEx, ...
        return True
    return any(m in t for m in _GENERIC_MARKERS)


def distinctive_strings(strings: list[str], limit: int = 12) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in strings:
        if s in seen or is_generic_rule_string(s):
            continue
        seen.add(s)
        out.append(s)
    return out[:limit]


def build_yara_rule(family: str, sha256: str, strings: list[str],
                    imphash: str | None = None,
                    sample_path: Path | None = None) -> str:
    name = f"CADRE_v2_{slugify(family)}_{sha256[:12]}"
    _prov = revai_provenance()
    chosen = distinctive_strings(strings)
    degraded = False
    if not chosen and not imphash:
        # No distinctive strings and no imphash: keep an honest weak rule
        # rather than silently emitting a near-universal one.
        chosen = strings[:12]
        degraded = True
    is_elf = False
    if sample_path is not None and sample_path.is_file():
        try:
            with sample_path.open("rb") as f:
                is_elf = f.read(4) == b"\x7fELF"
        except Exception:
            is_elf = False
    lines = [
        f"// yara_gen_v2.py — {datetime.now(timezone.utc).isoformat()}",
    ]
    if imphash:
        # yara-x validates pe.imphash() only with the module imported (verified 2026-08-09)
        lines.append('import "pe"')
    desc = f"RevAI v2 auto rule for {family}"
    if degraded:
        desc += " (low-confidence: no distinctive strings)"
    lines += [
        f"rule {name} {{",
        "    meta:",
        f'        description = "{desc}"',
        f'        sha256 = "{sha256}"',
        f'        family = "{slugify(family)}"',
        "        revai = true",
        f'        revai_commit = "{_prov["commit"]}"',
        f'        revai_engine = "{_prov["engine"]}"',
        '        severity = "high"',
        '        confidence = "low"' if degraded else '        confidence = "medium"',
        "    strings:",
    ]
    for i, s in enumerate(chosen[:12]):
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'        $s{i} = "{esc}" ascii wide')
    # Condition: file-type gate + distinctive strings only ($s* — no header
    # bytes), with imphash as an independent exact fingerprint branch.
    conds: list[str] = []
    if chosen:
        n = len(chosen)
        k = 2 if n >= 2 else 1
        fmt = "uint32(0) == 0x464C457F" if is_elf else "uint16(0) == 0x5A4D"
        conds.append(f"{fmt} and {k} of ($s*)")
    if imphash:
        conds.append(f'pe.imphash() == "{imphash}"')
    if not conds:
        conds.append("uint16(0) == 0x5A4D or uint32(0) == 0x464C457F")
    lines += [
        "    condition:",
        "        " + " or ".join(conds),
        "}",
    ]
    return "\n".join(lines)


def extract_iocs(sha256: str, sample_path: Path, verdict: dict | None,
                 strings: list[str]) -> dict:
    """Structured IOC pack: hunt TTPs + generate IOCs; analyst IOC handoff.

    Deterministic regex extraction over known strings + verdict evidence.
    """
    domain_re = re.compile(r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?![\w.-])", re.IGNORECASE)
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_re = re.compile(r"(?:https?|ftp)://[^\s\"']+", re.IGNORECASE)
    file_re = re.compile(r"\b[\w.-]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|tmp|dat)\b", re.IGNORECASE)
    reg_re = re.compile(r"\bHK(?:LM|CU|CR|U)\\[A-Za-z0-9_\\ .-]+", re.IGNORECASE)
    mutex_re = re.compile(r"\b(?:Global\\|Local\\)?[A-Za-z0-9_]{8,64}(?:Mutex|_mutex|msi|shell)\b", re.IGNORECASE)

    text_pool: list[str] = []
    for s in strings:
        text_pool.append(s)
    if verdict:
        for item in verdict.get("key_evidence") or []:
            if isinstance(item, dict):
                text_pool.append(str(item.get("why") or item.get("detail") or ""))
        for item in verdict.get("iocs") or []:
            text_pool.append(str(item))
    joined = "\n".join(text_pool)

    _FILE_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
                  ".tmp", ".dat", ".sys", ".bin", ".doc", ".docx", ".pdf", ".zip")

    def _clean(matches: list[str], *, exclude_ext: bool = False) -> list[str]:
        seen: set[str] = set()
        out = []
        for m in matches:
            m = m.strip().strip(".,;:()[]{}'\"")
            if len(m) < 4:
                continue
            if exclude_ext and m.lower().endswith(_FILE_EXTS):
                continue
            if m.lower() in seen:
                continue
            seen.add(m.lower())
            out.append(m)
        return out[:50]

    hashes = file_hashes(sample_path)
    return {
        "sha256": sha256,
        "family": (verdict or {}).get("family_guess") or "unknown",
        "verdict": f"{((verdict or {}).get('verdict') or 'unknown')}@{((verdict or {}).get('confidence') or '')}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hashes": hashes,
        "domains": _clean([m.group(0) for m in domain_re.finditer(joined)], exclude_ext=True),
        "ips": _clean([m.group(0) for m in ip_re.finditer(joined)]),
        "urls": _clean([m.group(0) for m in url_re.finditer(joined)]),
        "files": _clean([m.group(0) for m in file_re.finditer(joined)]),
        "registry_keys": _clean([m.group(0) for m in reg_re.finditer(joined)]),
        "mutexes": _clean([m.group(0) for m in mutex_re.finditer(joined)]),
        "source": ["verdict.key_evidence", "verdict.iocs", "floss/xor cache", "ghidra/ida strings"],
        "note": "Deterministic regex extraction; analyst review before sharing (incident-response practice: "
                "victim-specific data in ransom notes is sensitive).",
    }


def build_sigma_rule(family: str, sha256: str, strings: list[str]) -> str:
    title = f"RevAI v2: {family} activity"
    rule_id = slugify(family) + "_" + sha256[:12]
    _prov = revai_provenance()
    distinctive = [s for s in strings if 12 <= len(s) <= 80][:3]
    selection = []
    for s in distinctive:
        esc = s.replace("\\", "\\\\").replace('"', '\\"')[:50]
        selection.append(f'            CommandLine|contains: "*{esc}*"')
    if not selection:
        selection.append(f'            Hashes|contains: "{sha256}"')
    sel_block = "\n".join(selection)
    return f"""title: "{title}"
id: {rule_id}
status: experimental
level: high
description: "Auto-generated Sigma rule for {family} (sha256 prefix {sha256[:12]})"
author: RevAI yara_gen_v2
date: {datetime.now(timezone.utc).strftime("%Y/%m/%d")}
reference: "commit {_prov['commit']} · engine {_prov['engine']}"
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
{sel_block}
    condition: selection
falsepositives:
    - Review against goodware corpus
"""


def run_yargen(sample_path: Path, family: str) -> dict:
    """Optional yarGen bootstrap when binary is staged alone."""
    out: dict = {"yargen_ok": False}
    try:
        subprocess.run(["which", YARGEN_BIN], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        out["error"] = "yarGen not installed"
        return out
    with tempfile.TemporaryDirectory(prefix="yargen-") as td:
        mal_dir = Path(td) / "mal"
        mal_dir.mkdir()
        link = mal_dir / sample_path.name
        try:
            link.symlink_to(sample_path)
        except OSError:
            import shutil
            shutil.copy2(sample_path, link)
        yar_out = Path(td) / "yargen.yar"
        cmd = [YARGEN_BIN, "-m", str(mal_dir), "-o", str(yar_out), "-a", family[:32]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out["yargen_ok"] = proc.returncode == 0 and yar_out.is_file()
        if yar_out.is_file():
            out["rule_excerpt"] = yar_out.read_text()[:2000]
        if proc.stderr:
            out["stderr"] = proc.stderr[:300]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sha256")
    ap.add_argument("--family", default="unknown")
    ap.add_argument("--yargen", action="store_true", help="Also run yarGen bootstrap")
    args = ap.parse_args()

    session = load_session(args.sha256)
    # Mode-aware paths: prefer the run's mode section (scripted/agentic/ui),
    # fall back to the legacy flat dir for pre-mode runs.
    case = case_dir(args.sha256)
    verdict_path = case / "verdict.json"
    if not verdict_path.is_file():
        verdict_path = LOGS / args.sha256 / "verdict.json"
    verdict = json.loads(verdict_path.read_text()) if verdict_path.is_file() else None

    # Gap #7: family auto-propagates from the verdict when not given explicitly.
    family = args.family if args.family and args.family != "unknown" else (
        (verdict or {}).get("family_guess") or "unknown"
    )

    strings = collect_strings(session["session_id"], session.get("ida_session_id"),
                              verdict, args.sha256)
    sample_path = Path(session["sample_path"])
    imphash = compute_imphash(sample_path) if sample_path.is_file() else None

    hitl_checkpoint("yara_gen_v2", "pre_emit", {"string_count": len(strings), "family": family})

    rule = build_yara_rule(family, args.sha256, strings,
                           imphash=imphash, sample_path=sample_path)
    sigma = build_sigma_rule(family, args.sha256, strings)

    yargen_meta = run_yargen(sample_path, family) if args.yargen else {"skipped": True}

    # Mode-aware output: rules + IOC pack land in the run's mode section so
    # audit_pipeline (case_dir-based) finds them; legacy flat only when no
    # REVAI_RUN_MODE is set.
    out_dir = case
    out_dir.mkdir(parents=True, exist_ok=True)
    yar_path = out_dir / "rule.yar"
    sigma_path = out_dir / "rule.yml"
    meta_path = out_dir / "rule.yara.json"
    ioc_path = out_dir / "iocs.json"
    yar_path.write_text(rule)
    sigma_path.write_text(sigma)

    # Gap #10: structured IOC pack (hashes/domains/ips/urls/files/registry/mutexes).
    iocs = extract_iocs(args.sha256, sample_path, verdict, strings)
    # revai-tools IOC extension (fail-open): wallets + defanged output.
    try:
        rt = revai_tools_iocs(sample_path)
        if rt.get("ok") or rt.get("source") == "revai_tools":
            iocs["wallets_btc"] = list(dict.fromkeys(iocs.get("wallets_btc", []) +
                                                      (rt.get("wallets_btc") or [])))
            iocs["wallets_eth"] = list(dict.fromkeys(iocs.get("wallets_eth", []) +
                                                      (rt.get("wallets_eth") or [])))
            for k in ("urls", "ips", "domains", "emails", "registry_keys"):
                rt_v = rt.get(k) or []
                merged = list(dict.fromkeys(iocs.get(k, []) + rt_v))
                if rt_v:
                    iocs[k] = merged
            iocs["revai_tools"] = {
                "count": sum(len(rt.get(k) or []) for k in
                             ("wallets_btc", "wallets_eth", "urls", "ips",
                              "domains", "emails", "registry_keys")),
                "source": "revai_tools_iocs",
            }
        else:
            iocs["revai_tools"] = {"error": str(rt.get("error")), "source": "revai_tools_iocs"}
    except Exception as e:
        iocs["revai_tools"] = {"error": str(e), "source": "revai_tools_iocs"}
    # Gap #14a: deterministic per-IOC confidence tiers (additive; the per-type
    # lists above are unchanged so existing consumers keep working).
    iocs["confidence"] = annotate_ioc_confidence(iocs)
    ioc_path.write_text(json.dumps(iocs, indent=2))

    valid, vmsg = yara_rule_validate(yar_path)
    fp = goodware_fp_scan(yar_path)

    meta = {
        "sha256": args.sha256,
        "family": family,
        "imphash": imphash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "string_count": len(strings),
        "strings": strings,
        "rule_path": str(yar_path),
        "sigma_path": str(sigma_path),
        "iocs_path": str(ioc_path),
        "yara_valid": valid,
        "yara_check": vmsg,
        "goodware_fp": fp,
        "yargen": yargen_meta,
        "revai": True,
        "provenance": revai_provenance(),
        "publish_target": "revai_publish",
    }
    meta_path.write_text(json.dumps(meta, indent=2))
    audit_write(args.sha256, {"source": "yara_gen_v2", "meta": meta})

    print(f"[yara_gen_v2] -> {yar_path} ({len(strings)} strings, imphash={imphash}, "
          f"valid={valid}, fp={fp.get('fp_count', 0)})")
    print(f"[yara_gen_v2] iocs -> {ioc_path} "
          f"(domains={len(iocs.get('domains', []))} ips={len(iocs.get('ips', []))} "
          f"urls={len(iocs.get('urls', []))})")
    print(rule)


if __name__ == "__main__":
    main()
