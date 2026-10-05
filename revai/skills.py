"""revai/skills.py — the RE agent skills layer.

A *skill* is a cited, versioned procedure the deep-dive agent loads on demand.
It is NOT prompt prose the generator re-summarises. That distinction is the whole
point, and it is the same lesson as #42 (indicators no tool observed) and #35
(report prose that drifted from the check): when methodology lives in prompt text,
the model paraphrases it, the paraphrase drifts, and nothing can tell you.

Here methodology is a structured artifact with a version and cited sources, so a
gate can check it and a report can cite it.

Design principles (adopted from the internal KB navigation layer, which solved the
same problem at 15k documents / 645k chunks):

1. **Methodology is not evidence.** A skill is loaded from a file, never recalled.
   The agent cannot get the procedure without reading the file.
2. **Progressive disclosure.** A one-line index goes in every prompt; the full
   skill body is fetched on demand. This replaces the anti-pattern of shipping the
   whole ghidrasql schema dump in every prompt.
3. **Provenance always.** Each skill ships `sources.jsonl` — the chunks it was
   extracted from, with chunk_id + rel_path + line range. See the attribution note
   below.
4. **Coverage accounting.** Each skill declares what it does NOT cover, so "the
   skill was silent" is distinguishable from "no source existed".

ATTRIBUTION NOTE. The source knowledge base is internal and this repo is public.
Per the repo rule, material used here is copied in and never referenced. A
citation is therefore PROVENANCE METADATA: an operator with KB access can re-verify
every range, and the extraction is auditable, but the cited path does not exist in
this repository and must never be presented as a resolvable link. Every skill
header states this so no reader mistakes a citation for a reference.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

#: Where the skills live. Alongside the modules, per the deploy contract
#: (the repo's `revai/` deploys FLAT to /opt/scripts, so this directory becomes
#: /opt/scripts/skills/ -- NOT revai/skills/).
SKILLS_DIR = Path(__file__).resolve().parent / "skills"

#: Bump when a skill's *meaning* changes. A wording fix that does not change what
#: the agent will do does not require a bump; a changed stop condition does.
SKILL_SCHEMA_VERSION = 1

#: The index every prompt carries. One entry per skill: what it is for, and the
#: one sentence that tells the agent WHEN to load it. Deliberately short -- this
#: is the only part that always costs tokens.
SKILL_INDEX: tuple[dict[str, str], ...] = (
    {"name": "re-methodology",
     "use": "the canonical static-analysis sequence and its stop conditions; "
            "load before a long manual walkthrough"},
    {"name": "unpack-and-verify",
     "use": "unpack, dump, rebuild the import table, re-analyse, and the "
            "honesty rule for a rebuilt import"},
    {"name": "obfuscation-recognition",
     "use": "the tells and standard attacks for CFF, MBA, string encryption "
            "and flattening"},
    {"name": "ghidra-sql-recipes",
     "use": "the query patterns against our SQL bridges, with the recipes "
            "already traded"},
    {"name": "verdict-calibration",
     "use": "the calibration contract verbatim; load before rendering any "
            "judgment"},
)


def skill_index_text() -> str:
    """The one-line-per-skill block that goes in the deep-dive prompt."""
    return "\n".join(f"- `{s['name']}` — {s['use']}." for s in SKILL_INDEX)


def list_skills() -> list[str]:
    """Available skill names, in index order."""
    return [n for n in sorted(p.name for p in SKILLS_DIR.glob("*")
                              if p.is_dir() and (p / "SKILL.md").is_file())]


#: The prompt fragment that tells the model the procedures exist and that they
#: must be LOADED, not recalled. Shared by both engines (the custom engine's
#: build_messages and the LangGraph system prompt) because two copies of a
#: prompt fragment is how the LangGraph engine came to run with the skills
#: layer bound but never mentioned -- proven by the 2026-10-05 sample run,
#: where 42 agent steps produced zero load_skill calls on the default engine.
#:
#: Wording rules that make this load-bearing rather than decorative:
#:   * "BEFORE attempting the work it covers" -- a procedure loaded afterwards
#:     is a procedure the answer was already written without.
#:   * "not evidence" -- methodology is not a finding, and must not be cited.
#:   * verdict-calibration is called out by name and tied to "any judgment",
#:     because that is the one whose absence directly degrades the verdict.
SKILL_GROUNDING = """PROCEDURE GROUNDING: reverse-engineering procedures are not recalled
from memory -- they are LOADED. Call `load_skill` with the name of the procedure
that covers the work you are about to do, BEFORE you do it. A procedure recalled
from memory is not evidence and must not be cited as one.

Available procedures: {index}

- If a procedure covers the next step, load it first and follow it.
- Load `verdict-calibration` before rendering ANY judgment about the sample.
- A procedure tells you HOW to investigate, never WHAT to conclude. It is not
  evidence, and its content must not be reported as a finding or cited as a source.
- An unknown name is an error; do not substitute a guess."""


def skill_grounding_block() -> str:
    """The procedure-grounding fragment with the live index substituted in."""
    names = list_skills()
    if not names:
        # No skills deployed: an empty index would invite a call that cannot
        # succeed, and a silent omission would leave the engine with no
        # instruction at all. Say what is true.
        return (
            "PROCEDURE GROUNDING: no reverse-engineering procedures are deployed "
            "for this host (skills/ is absent or empty), so there is nothing to "
            "load. Methodology is not evidence; investigate and cite only tool "
            "output.")
    return SKILL_GROUNDING.format(index=", ".join(sorted(names)))


def _read_skill_file(name: str) -> tuple[dict, str] | None:
    """(manifest, body) for a skill, or None when it does not exist.

    The manifest is the leading block of `key: value` lines (an optional `---`
    fence is tolerated). Parsed by hand rather than with a YAML import because the
    surface is `key: value` lines and one scalar list, and a stdlib-only repo must
    not gain a dependency for it.
    """
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")
    if safe != name:
        return None
    path = SKILLS_DIR / name / "SKILL.md"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    manifest: dict[str, object] = {}
    body = text
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            head, body = text[3:end], text[end + 4:].lstrip("\n")
        else:
            head, body = "", text
    else:
        # Header without a fence: the leading `key: value` run, ended by the
        # first blank line or a line that is not a pair. Deliberately not
        # requiring the fence -- a missing fence must mean "no manifest", not
        # "the whole file is manifest" or "there is no manifest at all", and a
        # skill whose `covers` silently parses to [] is exactly the kind of
        # quiet failure this layer exists to prevent.
        head_lines: list[str] = []
        idx = 0
        for idx, line in enumerate(text.splitlines()):
            if not line.strip():
                break
            if line.startswith(("#", " ", "\t")) or ":" not in line:
                break
            head_lines.append(line)
        head = "\n".join(head_lines)
        body = text.split("\n", len(head_lines))[-1].lstrip("\n") \
            if head_lines else text
    for line in (head or "").splitlines():
        if ":" not in line or line.startswith((" ", "\t", "#")):
            continue
        k, _, v = line.partition(":")
        k = k.strip()
        if not k:
            continue
        v = v.strip()
        if v.startswith("[") and v.endswith("]"):
            manifest[k] = [i.strip() for i in v[1:-1].split(",") if i.strip()]
        else:
            manifest[k] = v
    return manifest, body


def load_skill(name: str) -> dict:
    """Resolve a skill to {name, version, covers, does_not_cover, body, sources}.

    Raises KeyError for an unknown name so a caller can report it honestly rather
    than silently falling back -- a skill that cannot be loaded must be visible.
    """
    loaded = _read_skill_file(name)
    if loaded is None:
        raise KeyError(f"unknown skill: {name!r} (available: {list_skills()})")
    manifest, body = loaded
    sources: list[dict] = []
    src_path = SKILLS_DIR / name / "sources.jsonl"
    if src_path.is_file():
        for line in src_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                sources.append(json.loads(line))
            except Exception:
                continue
    return {
        "name": name,
        "version": manifest.get("version", SKILL_SCHEMA_VERSION),
        "covers": manifest.get("covers", []),
        "does_not_cover": manifest.get("does_not_cover", []),
        "body": body,
        "sources": sources,
        "attribution": (
            "Sources are internal KB citations held as provenance metadata. "
            "The paths are not resolvable in this public repository."),
    }


def skill_citation(name: str) -> str:
    """A one-line provenance string for a report to cite.

    Returns "" when the skill does not exist, so a caller can omit the citation
    rather than emit a broken one.
    """
    try:
        s = load_skill(name)
    except KeyError:
        return ""
    n = len(s["sources"])
    return (f"{s['name']} skill v{s['version']} "
            f"({n} cited source{'s' if n != 1 else ''}; provenance internal)")


def _cli() -> int:
    """`python3 skills.py [name]` — list, or dump one as JSON."""
    import argparse

    ap = argparse.ArgumentParser(description="RE agent skills")
    ap.add_argument("name", nargs="?", help="skill name; omit to list")
    args = ap.parse_args()
    if not args.name:
        print("skills:", ", ".join(list_skills()) or "(none)")
        print()
        print(skill_index_text())
        return 0
    print(json.dumps(load_skill(args.name), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
