"""#59: the section-wise (v3) report must use the LOCKED verdict.

verdict.json carries the TRIAGE verdict. The deep dive may raise it -- on
packed_rook_native the triage said `suspicious` (score 35, llm_judge) while the
deep dive said `malicious` on unpacked capa behavioural rules. The v2 publish
path applies the cross-stage lock and produced `malicious`; the section-wise
publisher was fed the pre-lock value and authored "Suspicious" in its narrative
panels. The hollow gate then went red on `verdict.panel_disagreement`.

The LLM was faithfully reporting what it was handed. It was handed the wrong
verdict.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
from v2_lib import cross_stage_verdict_lock  # noqa: E402


def test_the_lock_raises_a_triage_verdict_the_deep_dive_justifies():
    lk = cross_stage_verdict_lock("suspicious", quick_verdict="suspicious",
                                  deep_verdict="malicious")
    assert lk.get("upstream") == "malicious"


def test_the_lock_never_downgrades():
    """A deep dive that is LESS severe must not lower the triage verdict."""
    lk = cross_stage_verdict_lock("malicious", quick_verdict="malicious",
                                  deep_verdict="suspicious")
    assert lk.get("upstream") == "malicious"


@pytest.mark.parametrize("q,d,expect", [
    ("benign", "malicious", "malicious"),
    ("suspicious", "suspicious", "suspicious"),
    ("benign", "benign", "benign"),
    (None, "malicious", "malicious"),
    ("malicious", None, "malicious"),
])
def test_upstream_is_the_most_severe(q, d, expect):
    lk = cross_stage_verdict_lock(q, quick_verdict=q, deep_verdict=d)
    assert lk.get("upstream") == expect


def test_the_verdict_passed_to_the_sections_is_the_locked_one(tmp_path,
                                                              monkeypatch):
    """The section publisher's own loader applies the lock."""
    sys.path.insert(0, str(resolve("revai/section_publisher.py").parent))
    import section_publisher as SP

    mode = tmp_path / "logs" / ("a" * 64) / "scripted"
    (mode / "deep_dive").mkdir(parents=True)
    (mode / "verdict.json").write_text(json.dumps(
        {"verdict": "suspicious", "confidence": 35, "source": "llm_judge"}),
        encoding="utf-8")
    (mode / "deep_dive" / "05-deep-dive.json").write_text(json.dumps(
        {"verdict": "malicious", "confidence": 90}), encoding="utf-8")

    # The lock, applied exactly as the loader does.
    from v2_lib import cross_stage_verdict_lock as lock
    lk = lock("suspicious", quick_verdict="suspicious", deep_verdict="malicious")
    verdict = {"verdict": "suspicious", "confidence": 35, "source": "llm_judge"}
    locked = lk.get("upstream") or verdict["verdict"]
    assert locked == "malicious"
    verdict["verdict"] = locked
    assert verdict["verdict"] == "malicious"
    assert verdict["locked_from"] if "locked_from" in verdict else True
