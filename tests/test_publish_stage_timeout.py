"""The publish timeout must cover the work the stage actually does."""
import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/pipeline_single.py").parent))


def _default(env: str) -> int:
    src = (resolve("revai/pipeline_single.py")).read_text(encoding="utf-8")
    import re
    m = re.search(r'_stage_timeout\("%s",\s*(\d+)\)\)' % env, src)
    assert m, f"no _stage_timeout default found for {env}"
    return int(m.group(1))


def test_the_publish_timeout_covers_26_llm_calls():
    """A full v2 pass can exceed two hours before v3 even starts."""
    val = _default("REVAI_STAGE_TIMEOUT_PUBLISH")
    assert val >= 14400, (
        f"publish timeout {val}s does not cover the observed 2-hour v2 run")


def test_both_publish_stages_share_the_knob():
    src = (resolve("revai/pipeline_single.py")).read_text(encoding="utf-8")
    assert src.count('_stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH"') == 2, (
        "publish_v2 and publish_v3 must both honour the knob")
    orchestrator = (resolve("revai/stage_orchestrator.py")).read_text(
        encoding="utf-8")
    assert orchestrator.count(
        '_stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH", 14400)') == 2


def test_the_env_override_still_wins(monkeypatch):
    sys.path.insert(0, str(resolve("revai/pipeline_single.py").parent))
    import pipeline_single as PS
    monkeypatch.setenv("REVAI_STAGE_TIMEOUT_PUBLISH", "1800")
    assert PS._stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH", 14400) == 1800
    monkeypatch.delenv("REVAI_STAGE_TIMEOUT_PUBLISH", raising=False)
    assert PS._stage_timeout("REVAI_STAGE_TIMEOUT_PUBLISH", 14400) == 14400
