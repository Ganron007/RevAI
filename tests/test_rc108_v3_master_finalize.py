"""RC-108 (re-run 28, 2026-11-23): the v3 MASTER's FINAL pre-passes.

Re-run 28 (marker `d03d1fe` = RC-107 live): **BOTH v2 reports finished
fully clean (0/0/0, unverified [], lock ok) and publish rc=0 after
11,013.6 s -- the first fully green v2 publish of the arc** -- and the v3
master failed on `table_orphans: 3` with uncited 0 (RC-107 live-proven on
the v3 path too).

The class is the same finalize-order gap RC-101 fixed on the v2 master and
RC-106d on the v2 technical, now on the THIRD path: the v3 master's
assembly runs the deterministic pre-passes once (RC-40), but the
unverified-IoC repair REGENERATES sections, and a regenerated section can
place two tables back to back. The re-evaluation after the repair read the
un-pre-passed markdown. Replay on re-run 28's own REPORT-MASTER-v3.md:
orphans 3 -> 0.
"""

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as PR  # noqa: E402
import section_publisher as SP  # noqa: E402
from report_quality import count_table_orphans  # noqa: E402
from section_publisher import _fix_orphan_tables  # noqa: E402


def test_the_v3_master_runs_the_final_prepasses_after_its_repair():
    """The FINAL pre-passes must sit AFTER the repair retry, not only at
    assembly time (RC-40)."""
    src = inspect.getsource(SP.run_section_based_publish)
    repair_at = src.find("retry_unverified_ioc_sections(")
    assert repair_at > 0, "the v3 master's IoC repair must exist"
    after = src[repair_at:]
    assert "_fix_orphan_tables(report_markdown)" in after, (
        "the orphan pre-pass must run after the v3 master's repair retry")
    assert "_strip_unverified_indicators(report_markdown, sha)" in after, (
        "the indicator scrub must run after the v3 master's repair retry")
    # And BEFORE the post-repair re-evaluation that the gate reads.
    eval_at = after.find("master_quality = evaluate_report_markdown(")
    assert eval_at > 0
    assert after.find("_fix_orphan_tables(report_markdown)") < eval_at, (
        "the pre-passes must precede the post-repair quality evaluation")


def test_all_three_report_paths_run_the_final_prepasses():
    """Every publish path runs the FINAL deterministic pre-passes after
    ALL of its repair passes: v2 master, v2 technical, v3 master."""
    v2 = inspect.getsource(PR.main)
    assert v2.count("_fix_orphan_tables(") >= 2, "v2 master + v2 technical"
    v3 = inspect.getsource(SP.run_section_based_publish)
    assert "_fix_orphan_tables(" in v3, "v3 master"


def test_the_orphan_repair_closes_the_rerun28_shape():
    """Re-run 28's master_v3 shape: three adjacent table pairs."""
    table = "| Col | Val |\n| --- | --- |\n| a | 1 |\n"
    blocks: list[str] = []
    for i in range(1, 4):
        blocks.extend([f"## {i}. Section", "", table, table])
    md = "\n".join(blocks)
    assert count_table_orphans(md) == 3
    fixed = _fix_orphan_tables(md)
    assert count_table_orphans(fixed) == 0
    # The content is preserved -- only a separator is inserted.
    assert md.count("| a | 1 |") == fixed.count("| a | 1 |")


def test_the_prepass_is_idempotent_on_a_clean_report():
    """A repair that changed nothing leaves the markdown byte-identical."""
    md = ("## 1. Section\n\nProse between the tables.\n\n"
          + "| Col | Val |\n| --- | --- |\n| a | 1 |\n\n"
          + "More prose.\n\n"
          + "| Col | Val |\n| --- | --- |\n| b | 2 |\n")
    assert count_table_orphans(md) == 0
    assert _fix_orphan_tables(md) == md
