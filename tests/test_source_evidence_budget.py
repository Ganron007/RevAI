"""RC-30: the source-evidence corpus is bounded, not fatal.

Run `023e73576c1b`: two ~750 KB tool-raw files made the corpus 1,496,099
chars against the 900,000 context-safe budget, and the old guard RAISED --
killing publish in 1.2 s before a single report call. The claim gate
verifies citations against the ATTESTED case files, never against this
prompt text, so a bounded render cannot create an unresolvable citation;
it only records an honest coverage limit. Integrity guards (absent,
unattested, changed, invalid-JSON artifacts) still raise.
"""
import hashlib
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402

BIG1 = "deep_dive/01-tools-raw.json"
BIG2 = "quick_scan/00-tools-raw.json"
SMALL = "iocs.json"


def _manifest_entry(case: Path, path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": path.relative_to(case).as_posix(),
            "status": "attested", "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw)}


def _case(tmp_path, big_size: int):
    case = tmp_path / "case"
    (case / "deep_dive").mkdir(parents=True)
    (case / "quick_scan").mkdir(parents=True)
    big1 = case / BIG1
    big2 = case / BIG2
    small = case / SMALL
    big1.write_text(json.dumps({"rows": ["row-%06d" % i for i in range(big_size)]}),
                    encoding="utf-8")
    big2.write_text(json.dumps({"findings": ["finding-%06d" % i for i in range(big_size)]}),
                    encoding="utf-8")
    small.write_text(json.dumps({"domains": ["a.example"]}), encoding="utf-8")
    manifest = {"schema": "revai-report-input-manifest/v1",
                "artifacts": [_manifest_entry(case, p) for p in (big1, big2, small)]}
    covered = {a["path"] for a in manifest["artifacts"]}
    for rel in v2_lib.REPORT_SOURCE_EVIDENCE_ARTIFACTS:
        if rel not in covered:
            manifest["artifacts"].append({"path": rel, "status": "not-produced"})
    return case, manifest


def test_under_the_limit_renders_whole_and_records_no_elision(tmp_path):
    case, manifest = _case(tmp_path, 100)
    text, meta = v2_lib.format_report_source_evidence(case, manifest)
    assert meta["elided_chars"] == 0
    assert meta["elisions"] == {}
    assert f"### `{BIG1}`" in text
    assert "row-%06d" % 0 in text and "finding-%06d" % 0 in text
    assert "characters elided" not in text


def test_over_the_limit_is_bounded_not_fatal_and_honest(tmp_path):
    case, manifest = _case(tmp_path, 60_000)
    text, meta = v2_lib.format_report_source_evidence(case, manifest)
    assert meta["elided_chars"] > 0
    assert meta["total_chars"] > meta["limit_chars"]
    # Bounded: the render fits the context-safe budget (marker overhead aside).
    assert len(text) <= meta["limit_chars"] + 2_000
    # Every artifact is still represented with its heading and digest.
    for rel in (BIG1, BIG2, SMALL):
        assert f"### `{rel}`" in text or rel == SMALL
    assert f"### `{BIG1}`" in text and f"### `{BIG2}`" in text
    assert f"### `{SMALL}`" in text, "small artifacts must not be elided"
    # The elision marker names the real contract: attested on disk, cited by path.
    assert "characters elided from the middle" in text
    assert "report input manifest" in text
    # Deterministic.
    text2, meta2 = v2_lib.format_report_source_evidence(case, manifest)
    assert text2 == text and meta2 == meta


def test_integrity_guards_still_raise(tmp_path):
    case, manifest = _case(tmp_path, 100)
    # Absent artifact.
    broken = {"schema": manifest["schema"], "artifacts": [
        {"path": "deep_dive/missing.json", "status": "attested",
         "sha256": "0" * 64, "size_bytes": 1}]}
    try:
        v2_lib.format_report_source_evidence(case, broken)
        raise AssertionError("absent artifact did not raise")
    except RuntimeError as exc:
        assert "absent from input manifest" in str(exc)
    # Unattested artifact.
    m2 = json.loads(json.dumps(manifest))
    m2["artifacts"][0]["status"] = "stale"
    try:
        v2_lib.format_report_source_evidence(case, m2)
        raise AssertionError("unattested artifact did not raise")
    except RuntimeError as exc:
        assert "not attested" in str(exc)
    # Artifact changed after manifest creation.
    case_big1 = case / BIG1
    case_big1.write_text(case_big1.read_text() + " tail", encoding="utf-8")
    try:
        v2_lib.format_report_source_evidence(case, manifest)
        raise AssertionError("changed artifact did not raise")
    except RuntimeError as exc:
        assert "changed after manifest creation" in str(exc)


def test_all_artifacts_not_produced_still_raises(tmp_path):
    case = tmp_path / "case"
    case.mkdir(parents=True)
    manifest = {"schema": "revai-report-input-manifest/v1", "artifacts": [
        {"path": rel, "status": "not-produced"}
        for rel in v2_lib.REPORT_SOURCE_EVIDENCE_ARTIFACTS]}
    try:
        v2_lib.format_report_source_evidence(case, manifest)
        raise AssertionError("empty corpus did not raise")
    except RuntimeError as exc:
        assert "no attested primary source artifacts" in str(exc)


def test_no_manifest_still_raises(tmp_path):
    try:
        v2_lib.format_report_source_evidence(tmp_path, {"schema": "wrong"})
        raise AssertionError("invalid manifest did not raise")
    except RuntimeError as exc:
        assert "valid input manifest" in str(exc)
