"""The depth STAGE must drive the convergence loop, not just report state.

#26 was "implemented" once already as vocabulary + state + cost accounting with
nothing calling the loop -- a hollow stage that exited rc=0 in 0.1s. This pins
the wiring so that cannot happen again silently.
"""
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402


def _build(monkeypatch):
    sys.path.insert(0, str(resolve("revai/pipeline_single.py").parent))
    import pipeline_single as P
    monkeypatch.setenv("REVAI_DEPTH", "1")
    return P.build_stages("a" * 64, None)


def test_the_depth_stage_passes_run(monkeypatch):
    stages = _build(monkeypatch)
    hit = [c for n, c, _ in stages if n == "depth_understanding"]
    assert hit, "the depth stage is not in the spine"
    assert "--run" in hit[0], (
        "the depth stage only REPORTS state; it must drive the convergence loop")


def test_the_depth_stage_is_last_after_the_audit(monkeypatch):
    stages = _build(monkeypatch)
    names = [n for n, _, _ in stages]
    assert names[-1] == "depth_understanding", (
        f"depth must run last so it reads the whole pipeline; got {names}")
    assert names.index("audit") < names.index("depth_understanding")


def test_the_depth_stage_is_absent_when_disabled(monkeypatch):
    sys.path.insert(0, str(resolve("revai/pipeline_single.py").parent))
    import pipeline_single as P
    monkeypatch.delenv("REVAI_DEPTH", raising=False)
    names = [n for n, _, _ in P.build_stages("a" * 64, None)]
    assert "depth_understanding" not in names
