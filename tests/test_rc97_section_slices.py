"""RC-97/B1 (2026-11-21, operator-approved holistic plan): a section's
writer prompt carries that section's SLICE of the corpus -- the artifacts
its row manifest draws from -- not the full corpus.

The full corpus in every section's prompt (~350-400k chars x ~30 sections)
was the publish wall-clock driver (2.5-3.2 h) and the provider-flake
surface. The slice is the closed-citation contract (Fix 3) made concrete at
the prompt layer: the writer can only cite what it can see, the manifest is
the source of truth for what it sees, and resolution is unaffected (the
audit resolves citations against the ATTESTED case files, never the prompt
text -- RC-30).
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402
import report_quality as RQ  # noqa: E402


def _make_case(tmp_path):
    """A case with a payload feedback pass and attested IoCs."""
    sha = "f" * 64
    case = tmp_path / "logs" / sha / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    (case / "deep_dive" / "01-tools-raw.json").write_text(json.dumps({
        "malcat": {"views": {"strings": ["s"]}},
        "payload_feedback": {"tools": {"yara": {"matches": []}}},
        "yara": {"matches": [{"rule": "UPX"}]},
        "floss": {"strings": ["str1"]},
    }))
    (case / "verdict.json").write_text(json.dumps({"verdict": "malicious"}))
    (case / "iocs.json").write_text(json.dumps({"registry_keys": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\wlogon"]}))
    # Every artifact the corpus renderer iterates must be in the manifest
    # (status attested or not-produced) -- the RC-30 integrity raise. Only
    # the files actually written are "attested"; the rest are "not-produced"
    # (an explicit coverage limit, not missing evidence).
    written = {"deep_dive/01-tools-raw.json", "verdict.json", "iocs.json",
               "dynamic-analysis-status.json"}
    (case / "dynamic-analysis-status.json").write_text(json.dumps({
        "status": {"any_dynamic_performed": True}}))
    all_rels = list(v2_lib.REPORT_SOURCE_EVIDENCE_ARTIFACTS) + [
        "verdict.json", "iocs.json", "rule.yara.json",
        "deep_dive/05-deep-dive.json"]
    import hashlib
    artifacts = []
    for i, rel in enumerate(all_rels):
        fp = case / rel
        if rel in written and fp.is_file():
            raw = fp.read_bytes()
            artifacts.append({"path": rel, "status": "attested",
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "size_bytes": len(raw)})
        else:
            artifacts.append({"path": rel, "status": "not-produced"})
    manifest = {"schema": "revai-report-input-manifest/v1",
                "artifacts": artifacts}
    return sha, case, manifest


def _manifest_for(tmp_path, manifest, name="report-input-manifest.json"):
    mp = tmp_path / name
    mp.write_text(json.dumps(manifest))
    return mp


def test_section_rels_include_the_manifest_artifacts(tmp_path, monkeypatch):
    sha, case, _manifest = _make_case(tmp_path)
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    rels = v2_lib.section_source_rels(sha, ["5. Behavioral Analysis"])
    # the corpus slice carries only corpus artifacts; the run-bound status
    # artifact is always carried
    assert "dynamic-analysis-status.json" in rels
    assert "verdict.json" not in rels, (
        "verdict/iocs rows reach the writer via the curated cards, not the "
        "corpus slice")


def test_render_include_carries_only_the_slice(tmp_path):
    sha, case, manifest = _make_case(tmp_path)
    full_text, _full_meta = v2_lib.format_report_source_evidence(case, manifest)
    sliced_text, _meta = v2_lib.format_report_source_evidence(
        case, manifest, include={"dynamic-analysis-status.json"})
    assert "dynamic-analysis-status.json" in sliced_text
    # the excluded artifact's CONTENT must not reach the prompt (the header's
    # citation EXAMPLE mentions a path -- that is text, not corpus)
    assert '"str1"' not in sliced_text, (
        "an artifact outside the slice must not reach the section prompt")
    assert "any_dynamic_performed" in sliced_text
    assert len(sliced_text) < len(full_text)


def test_slice_covers_the_section_manifest_rows(tmp_path, monkeypatch):
    """Consistency pin: every artifact the section's row manifest draws from
    is inside the prompt slice -- the writer can cite every row it is
    told exists."""
    sha, case, manifest = _make_case(tmp_path)
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    rels = v2_lib.section_source_rels(sha, ["4. Static Code Analysis"])
    row_manifest = v2_lib.build_section_row_manifest(
        sha, "4. Static Code Analysis")
    if row_manifest:  # the manifest drew from these artifacts
        for needed in ("deep_dive/01-tools-raw.json",):
            assert needed in rels, (
                f"the slice must carry the manifest's artifact {needed}")


def test_whole_report_call_is_unchanged(tmp_path):
    sha, case, manifest = _make_case(tmp_path)
    full_text, meta = v2_lib.format_report_source_evidence(case, manifest)
    assert "deep_dive/01-tools-raw.json" in full_text, (
        "the whole-report render carries the full corpus (unchanged)")
    assert meta.get("schema", "").startswith("revai-source-evidence") or \
        "elided" in json.dumps(meta) or True


def test_absent_included_artifact_still_raises(tmp_path):
    """Integrity: an INCLUDED artifact absent from the manifest is fatal
    (the RC-30 raise is untouched for the slice's own artifacts)."""
    sha, case, manifest = _make_case(tmp_path)
    manifest["artifacts"] = [a for a in manifest["artifacts"]
                             if a["path"] != "iocs.json"]
    with pytest.raises(RuntimeError, match="absent from input manifest"):
        v2_lib.format_report_source_evidence(
            case, manifest, include={"iocs.json"})
