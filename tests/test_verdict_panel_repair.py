"""Publishers preserve generated verdict claims and fail on lock conflicts."""
from __future__ import annotations

import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import add_module_dir, source  # noqa: E402

add_module_dir("revai/report_quality.py")
import report_quality as rq  # noqa: E402


def test_verdict_conflict_is_a_quality_failure_and_does_not_rewrite_draft():
    draft = (
        "# Report\n\nVerdict: suspicious. "
        "The observed sample remains suspicious based on the evidence.\n"
    )
    upstream_lock = {
        "ok": False,
        "conflict": True,
        "upstream": "malicious",
        "publish": "suspicious",
        "reason": "publish=suspicious downgrades upstream=malicious",
    }

    result = rq.evaluate_report_markdown(
        draft,
        required_sections=[],
        source="llm_judge",
        min_total_chars=0,
        label="technical_v2",
        verdict_lock=upstream_lock,
    )

    assert result["ok"] is False
    assert any(issue.startswith("technical_v2:verdict_lock_conflict:")
               for issue in result["issues"])
    assert draft == (
        "# Report\n\nVerdict: suspicious. "
        "The observed sample remains suspicious based on the evidence.\n"
    )


def test_publishers_do_not_scrub_claims_or_rewrite_verdict_panels():
    for path in ("revai/publish_report_v2.py", "revai/section_publisher.py"):
        src = source(path)
        assert "scrub_report_indicators(" not in src
        assert "repair_verdict_panel(" not in src
        assert "align_publish_markdown_to_upstream(" not in src
        assert "surface_verdict_sources_panel(" not in src
