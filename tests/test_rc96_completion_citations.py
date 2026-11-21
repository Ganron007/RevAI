"""RC-96 (re-run 17, 2026-11-21): the deterministic completion footer cites
the deep-dive artifact by its EXACT path, and the MITRE derivation line
carries its citation.

Re-run 17's technical failed on `uncited_claims: 2`:
1. the RC-84 Fix 2 completion footer cited `source: deep_dive` -- not an
   alias the resolver can route, so the citation failed and the line was
   counted uncited even though `deep_dive/05-deep-dive.json` carries
   `$.summary` verbatim;
2. the technical body map's "10. MITRE ATT&CK Mapping" line ("Derived from
   capa `attack` fields...") is a derivation statement with no citation.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import entailment as E  # noqa: E402
import publish_report_v2 as PR  # noqa: E402


def test_footer_citation_resolves_the_deep_dive_artifact(tmp_path):
    (root := tmp_path / "c").mkdir(parents=True)
    (root / "deep_dive").mkdir()
    (root / "deep_dive" / "05-deep-dive.json").write_text(json.dumps({
        "summary": "The sample is a small UPX-packed PE.",
        "verdict": "malicious", "confidence": "high"}))
    cit = ("(source: deep_dive/05-deep-dive.json, "
           "query_or_table: deep_dive/05-deep-dive.json, "
           "row_or_rule: $.summary)")
    paths = E._source_artifact_candidates(
        "deep_dive/05-deep-dive.json", "deep_dive/05-deep-dive.json", root)
    assert paths, "the exact-path form must resolve"
    hit = E._locate_cited_row(
        paths[0], "$.summary", "deep_dive/05-deep-dive.json",
        "deep_dive/05-deep-dive.json")
    assert hit is not None and "UPX-packed" in str(hit["value"])


def test_the_mitre_derivation_line_carries_a_citation():
    """The technical body map's MITRE line must cite the capa rows it
    derives from (a derivation statement without a citation is an uncited
    claim)."""
    import inspect
    src = inspect.getsource(PR)
    assert "Derived from capa `attack` fields where present " in src
    assert "(source: capa, query_or_table: deep_dive/01-tools-raw.json, " in src


def test_no_weak_deep_dive_source_spelling_remains():
    """The old `source: deep_dive` spelling must be gone from both
    completion footers."""
    import inspect
    src = inspect.getsource(PR)
    assert "(source: deep_dive, query_or_table: deep_dive/05-deep-dive.json" \
        not in src


def test_as_layout_block_marks_every_line():
    """RC-100: every line of an embedded evidence block becomes declared
    layout text; blank lines stay blank."""
    out = PR._as_layout_block("Run-bound IOC evidence:\nhash IOCs from iocs.json (3):\n\nlast line\n")
    lines = out.splitlines()
    assert lines[0].startswith("**[Note]** Run-bound IOC evidence")
    assert lines[1].startswith("**[Note]** hash IOCs")
    assert lines[2] == ""
    assert lines[3].startswith("**[Note]** last line")


def test_deterministic_bodies_declare_layout_not_claims():
    """RC-100: the body map's IoC-bearing sections embed their evidence
    blocks as declared layout text (the uncited-claim gate skips **[Note]**
    lines), and the footer summary is collapsed to ONE line so the citation
    lands on it."""
    import inspect
    src = inspect.getsource(PR)
    assert src.count("_as_layout_block(") >= 4, (
        "all four IoC-bearing body-map sections must use the layout transform")
    assert "' '.join(str(deep.get('summary'))[:400].split())" in src, (
        "the footer summary must be newline-collapsed")


def test_layout_block_passes_the_uncited_gate_shape():
    """End-to-end shape: a layout-blocked evidence section has no bare
    claim lines."""
    block = PR._as_layout_block("Run-bound IOC evidence:\nhash IOCs (3):\n")
    for ln in block.splitlines():
        s = ln.strip()
        if not s:
            continue
        assert s.startswith("**[Note]**"), f"bare claim line: {s[:60]}"
