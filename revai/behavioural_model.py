"""revai/behavioural_model.py -- plan #8: what the sample DOES, as a model.

The capability ledger (#56) answers "which domains did we examine, and is each
determination backed by evidence". This module answers the question an analyst
actually opens the report for: **what does the sample do?**

The difference is the unit. The ledger is a coverage record -- one row per
capability domain, each with a provenance tier. A behavioural model is a picture
of the sample's behaviour: the capabilities it has, the concrete objects those
capabilities act on, the observations backing each, and the gaps. Those are four
different things and conflating them is how a report ends up listing capabilities
without ever saying what the binary touches.

Built deterministically from the run's artifacts, never authored by the model.
That is the same rule the IoC section and the capability ledger follow, and for
the same reason: a model-authored behavioural model is a plausible story, and a
plausible story about a malware sample is the most expensive kind of wrong.

Env-gated: REVAI_ENABLE_BEHAVIOURAL_MODEL=1. Off by default, so a static-only
deployment is byte-identical.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

MODEL_ENV = "REVAI_ENABLE_BEHAVIOURAL_MODEL"

#: iocs.json keys that name an OBJECT the sample acts on, in the order an
#: analyst reads them. `domains` is a list of dicts; the rest are string lists.
_OBJECT_KINDS = (
    ("registry_keys", "Registry keys"),
    ("urls", "URLs"),
    ("domains", "Domains"),
    ("ips", "IP addresses"),
    ("files", "Files / paths"),
    ("mutexes", "Mutexes"),
)


def behavioural_model_enabled() -> bool:
    return os.environ.get(MODEL_ENV, "").strip().lower() in (
        "1", "true", "yes", "on")


def _load_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _object_values(v: Any) -> list[str]:
    """Normalise an iocs.json value to a list of strings.

    `domains` is a list of dicts; everything else is a list of strings. Both
    shapes occur in the wild, so both are handled rather than assuming one.
    """
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        return []
    out = []
    for item in v:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            for key in ("domain", "url", "ip", "path", "value", "name"):
                if item.get(key):
                    out.append(str(item[key]).strip())
                    break
    return out


def build_behavioural_model(sha: str, logs_dir: Path | None = None,
                            case_root: Path | None = None) -> dict:
    """The behavioural model for a case, assembled from its own artifacts.

    Returns {} when there is nothing to assemble -- a run with no capability
    ledger (flat engine, or REVAI_DOMAIN_GRAPH off) and no IoCs. Absence is
    reported as absence; it is never padded into a model.
    """
    try:
        from v2_lib import LOGS_DIR, build_capability_coverage
        base = Path(logs_dir) if logs_dir else LOGS_DIR
    except Exception:
        return {}

    root = Path(case_root) if case_root else base / sha
    if not root.is_dir():
        return {}
    if case_root is not None:
        # Derive the LOGS root from the case root -- the directory that CONTAINS
        # <sha>. Passing the module default made build_capability_coverage look
        # in the real /opt/samples/logs for a case living in a test fixture.
        #   flat layout   <logs>/<sha>            -> base = root.parent
        #   mode-keyed    <logs>/<sha>/<mode>     -> base = root.parent.parent
        base = root.parent if root.name == sha else root.parent.parent

    cov = build_capability_coverage(sha, logs_dir=base)
    iocs = {}
    for cand in (root / "iocs.json", base / sha / "iocs.json"):
        if cand.is_file():
            iocs = _load_json(cand)
            if iocs:
                break

    if not cov and not iocs:
        return {}

    # --- capabilities: one row per domain, with its provenance -------------
    capabilities = []
    try:
        import domain_graph as dg
        titles = {d["key"]: d["title"] for d in dg.DOMAINS}
        order = list(dg.DOMAIN_KEYS)
    except Exception:
        titles, order = {}, []

    domains = (cov or {}).get("domains") or {}
    keys = [k for k in order if k in domains] or list(domains)
    for key in keys:
        e = domains[key] or {}
        capabilities.append({
            "key": key,
            "title": titles.get(key, key),
            "status": e.get("status"),
            "provenance": e.get("provenance"),
            "determination": str(e.get("answer") or "")[:600],
            "evidence_count": e.get("evidence") or 0,
            "unpack_evidence": e.get("unpack_evidence"),
            "truncated": e.get("truncated"),
            "contradicts_answer": e.get("contradicts_answer"),
        })

    # --- objects: the concrete things the sample acts on -------------------
    objects: dict[str, list[str]] = {}
    for key, label in _OBJECT_KINDS:
        vals = _object_values(iocs.get(key))
        if vals:
            objects[label] = vals[:40]

    # --- observations: the evidence items, grouped by engine/table --------
    observations: list[dict] = []
    for key in keys:
        e = domains.get(key) or {}
        if e.get("provenance") != "observed":
            continue
        for item in (e.get("evidence_items") or [])[:8]:
            text = str(item)
            m = re.match(r"^\s*([a-z_0-9]+)\s+([a-z_0-9 /-]+?)\s*:", text)
            obs = {"domain": key, "text": text[:400]}
            if m:
                obs["engine"] = m.group(1)
                obs["table"] = m.group(2).strip()
            observations.append(obs)

    pc = (cov or {}).get("provenance_counts") or {}
    model = {
        "engine": "behavioural-model",
        "sha256": sha,
        "objective": str(iocs.get("family") or iocs.get("note") or "")[:200],
        "capabilities": capabilities,
        "objects": objects,
        "observations": observations,
        "provenance_counts": pc,
        "unknown": (cov or {}).get("unknown") or [],
        "verdict_hint": (cov or {}).get("honest"),
        "iocs_present": bool(iocs),
    }
    return model


def format_behavioural_model(model: dict) -> str:
    """The model as a report section. Deterministic; nothing is inferred."""
    if not model or not model.get("capabilities"):
        return ""

    caps = model["capabilities"]
    by_prov: dict[str, list[dict]] = {}
    for c in caps:
        by_prov.setdefault(str(c.get("provenance") or "unknown"), []).append(c)

    lines = ["## Behavioural Model", "",
             "What the sample does, assembled from this run's evidence. "
             "Capabilities carry the provenance the capability-coverage ledger "
             "assigned: *observed* means the determination is backed by cited "
             "evidence, *inferred* means the domain was investigated without a "
             "usable determination, *unknown* means it was never examined.",
             ""]

    lines.append("### Capabilities")
    lines.append("")
    lines.append("| Capability | Provenance | Determination |")
    lines.append("|---|---|---|")
    for c in caps:
        prov = str(c.get("provenance") or "unknown")
        if prov == "observed":
            prov_md = "**observed**"
        elif prov == "inferred":
            prov_md = "inferred"
        else:
            prov_md = "**unknown**"
        det = " ".join(str(c.get("determination") or "").split())
        if len(det) > 220:
            det = det[:217] + "..."
        if not det:
            det = "not examined to a determination"
        flags = []
        if c.get("truncated"):
            flags.append("truncated")
        if c.get("contradicts_answer"):
            flags.append("status contradicts its own answer")
        if flags:
            det += f" ({', '.join(flags)})"
        lines.append(f"| {c['title']} | {prov_md} | {det} |")

    obs = model.get("observations") or []
    if obs:
        lines += ["", "### Observed actions", "",
                  "The concrete observations behind the observed capabilities.",
                  "", "| Domain | Engine / table | Observation |", "|---|---|---|"]
        for o in obs[:40]:
            eng = o.get("engine") or "-"
            tbl = o.get("table") or ""
            src = f"{eng} {tbl}".strip()
            txt = " ".join(str(o.get("text") or "").split())
            txt = re.sub(r"^\s*[a-z_0-9]+\s+[a-z_0-9 /-]+?\s*:\s*", "", txt)
            if len(txt) > 200:
                txt = txt[:197] + "..."
            lines.append(f"| {o['domain']} | {src} | {txt} |")

    objs = model.get("objects") or {}
    if objs:
        lines += ["", "### Objects acted on", ""]
        for label, vals in objs.items():
            shown = ", ".join(f"`{v}`" for v in vals[:12])
            more = f" (+{len(vals) - 12} more)" if len(vals) > 12 else ""
            lines.append(f"- **{label}** ({len(vals)}): {shown}{more}")

    pc = model.get("provenance_counts") or {}
    lines += ["",
              f"**Model provenance: {pc.get('observed', 0)} observed, "
              f"{pc.get('inferred', 0)} inferred, {pc.get('unknown', 0)} unknown, "
              f"of {len(caps)} capability domains**"
              + (f"; not examined: {', '.join(model['unknown'])}"
                 if model.get("unknown") else "")
              + f". Observations: {len(obs)}.", ""]
    if model.get("unknown"):
        lines += ["The domains listed as *unknown* are gaps in this analysis, not "
                  "findings about the sample.", ""]
    return "\n".join(lines)


def attach_behavioural_model(md: str, sha: str, *,
                             logs_dir: Path | None = None) -> str:
    """Append the behavioural model to a report.

    No-ops when there is nothing to append (flat engine, no ledger, or the
    feature is off), so an unmodelled run is byte-identical. Opt out with
    REVAI_DISABLE_BEHAVIOURAL_MODEL=1.
    """
    if os.environ.get("REVAI_DISABLE_BEHAVIOURAL_MODEL", "").strip().lower() \
            in ("1", "true", "yes", "on"):
        return md
    try:
        model = build_behavioural_model(sha, logs_dir=logs_dir)
        block = format_behavioural_model(model)
        if not block:
            return md
        return (md or "").rstrip() + "\n\n" + block
    except Exception:
        return md


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="behavioural model")
    ap.add_argument("target", nargs="?",
                    help="case directory or sha256")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    args = ap.parse_args()

    case = None
    target = args.target or os.environ.get("REVAI_CASE_DIR", "")
    if target:
        p = Path(target)
        if p.is_dir():
            case = p
        else:
            try:
                from v2_lib import LOGS_DIR, case_dir
                _logs = Path(os.environ.get("REVAI_LOGS_DIR") or LOGS_DIR)
                if not (_logs / target).exists():
                    print(f"[behavioural_model] case for {target[:16]}... does "
                          "not exist: run the pipeline first.", file=sys.stderr)
                    return 3
                case = case_dir(target)
            except Exception:
                case = p

    if case is None:
        print(f"behavioural_model enabled: {behavioural_model_enabled()}")
        return 0

    sha = case.name if len(case.name) == 64 else case.parent.name
    model = build_behavioural_model(sha, case_root=case)
    if not model:
        print("[behavioural_model] nothing to assemble: no capability ledger "
              "and no IoCs for this case.", file=sys.stderr)
        return 0
    if args.json:
        print(json.dumps(model, indent=2))
        return 0
    out = case / "behavioural_model.json"
    try:
        out.write_text(json.dumps(model, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"[behavioural_model] could not write: {exc}", file=sys.stderr)
    print(format_behavioural_model(model))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
