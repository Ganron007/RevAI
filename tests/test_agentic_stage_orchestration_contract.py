"""Agentic planning must schedule every enabled product stage exactly once."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/stage_orchestrator.py").parent))
import stage_orchestrator as so  # noqa: E402

SHA = "a" * 64


def test_enabled_optional_stages_appear_in_policy_order():
    order = so._planner_stage_order(
        need_intake=True,
        winre=True,
        function_recovery=True,
        artifact_gen=True,
        behavioural_model=True,
        depth=True,
    )
    assert order.split(" → ") == [
        "run_intake",
        "run_quick_scan",
        "run_winre_dynamic",
        "run_deep_dive_agentic",
        "read_verdicts",
        "run_function_recovery",
        "run_artifact_gen",
        "run_behavioural_model",
        "run_yara_gen",
        "run_publish",
        "run_section_publish",
        "run_audit",
        "check_quality",
        "run_depth",
    ]


def test_disabled_optional_stages_are_absent_from_the_policy_order():
    order = so._planner_stage_order(
        need_intake=False,
        winre=False,
        function_recovery=False,
        artifact_gen=False,
        behavioural_model=False,
        depth=False,
    )
    assert order == (
        "run_quick_scan → run_deep_dive_agentic → read_verdicts → run_yara_gen → "
        "run_publish → run_section_publish → run_audit → "
        "check_quality"
    )


def test_agentic_publish_stages_use_the_shared_timeout_and_disable_timeout_retries(
    monkeypatch,
):
    monkeypatch.setenv("REVAI_STAGE_TIMEOUT_PUBLISH", "8100")
    calls = []

    def record(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append((name, timeout, retry_timeouts))
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "_run", record)
    monkeypatch.setattr(so.StageRunner, "_ensure_yara_artifacts", lambda self: None)
    runner = so.StageRunner(SHA, None, [])
    runner.run_publish()
    runner.run_section_publish()
    assert calls == [
        ("run_publish", 8100, False),
        ("run_section_publish", 8100, False),
    ]


def test_agentic_report_stages_are_single_shot_even_if_planner_repeats_them(
    monkeypatch,
):
    calls = []

    def record(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append(name)
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    monkeypatch.setattr(so.StageRunner, "_run", record)
    # This test is about the single-shot guard, not the RC-83 precondition.
    monkeypatch.setattr(so.StageRunner, "_ensure_yara_artifacts", lambda self: None)
    events = []
    runner = so.StageRunner(SHA, None, events)

    first_publish = runner.run_publish()
    first_section_publish = runner.run_section_publish()
    repeated_publish = runner.run_publish()
    repeated_section_publish = runner.run_section_publish()

    assert first_publish["ok"] and first_section_publish["ok"]
    assert repeated_publish["ok"] is False and repeated_publish["rc"] == 1
    assert repeated_section_publish["ok"] is False and repeated_section_publish["rc"] == 1
    assert calls == ["run_publish", "run_section_publish"]
    assert [event["tool"] for event in events] == [
        "run_publish", "run_section_publish",
    ]
    assert all("duplicate" in event["failure_reason"] for event in events)


def test_publish_stages_reconcile_deep_verdict_before_reading_evidence(
    monkeypatch, tmp_path,
):
    case = tmp_path / SHA
    deep_dir = case / "deep_dive"
    deep_dir.mkdir(parents=True)
    (case / "verdict.json").write_text(json.dumps({"verdict": "suspicious"}))
    deep_path = deep_dir / "05-deep-dive.json"
    deep_path.write_text(json.dumps({
        "verdict": "undetermined_packed",
        "summary": "Packed sample; behavior is unknown.",
    }))
    monkeypatch.setattr(so, "case_dir", lambda _sha: case)
    monkeypatch.delenv("REVAI_HITL_VERDICT", raising=False)
    # RC-83: satisfy the publisher precondition so the test exercises only
    # the verdict reconciliation it was written for.
    (case / "rule.yara.json").write_text("{}")
    (case / "iocs.json").write_text("{}")
    observed = []

    def publish_after_reconciliation(self, name, cmd, timeout, *, retry_timeouts=True):
        observed.append((name, json.loads(deep_path.read_text())["verdict"]))
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "_run", publish_after_reconciliation)
    runner = so.StageRunner(SHA, None, [])
    assert runner.run_publish()["ok"]
    assert runner.run_section_publish()["ok"]

    assert observed == [
        ("run_publish", "suspicious"),
        ("run_section_publish", "suspicious"),
    ]
    reconciled = json.loads(deep_path.read_text())
    assert reconciled["verdict_reconciled"]["from"] == "undetermined_packed"
    assert reconciled["verdict_reconciled"]["to"] == "suspicious"
    assert not list(deep_dir.glob("*.tmp"))


def test_hitl_publish_keeps_conflicting_deep_verdict_unmodified(monkeypatch, tmp_path):
    case = tmp_path / SHA
    deep_dir = case / "deep_dive"
    deep_dir.mkdir(parents=True)
    (case / "verdict.json").write_text(json.dumps({"verdict": "suspicious"}))
    deep_path = deep_dir / "05-deep-dive.json"
    original = {"verdict": "undetermined_packed", "summary": "Packed sample."}
    deep_path.write_text(json.dumps(original))
    monkeypatch.setattr(so, "case_dir", lambda _sha: case)
    monkeypatch.setenv("REVAI_HITL_VERDICT", "1")
    runner = so.StageRunner(SHA, None, [])

    result = runner.run_publish()

    assert result["skipped"] is True
    assert json.loads(deep_path.read_text()) == original
    assert runner.events[0]["data"]["reason"] == "hitl_verdict_enabled"


def test_non_resumable_publish_timeout_is_not_retried(monkeypatch, tmp_path):
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(
        so, "run_profile",
        lambda: {"stage_retries": 1, "retry_transient_only": True},
    )
    attempts = []

    def timed_out(cmd, **kwargs):
        attempts.append((cmd, kwargs["timeout"]))
        raise subprocess.TimeoutExpired(cmd, kwargs["timeout"])

    monkeypatch.setattr(so.subprocess, "run", timed_out)
    runner = so.StageRunner(SHA, None, [])
    result = runner._run(
        "run_publish", ["publish_report_v2.py", SHA], 7200,
        retry_timeouts=False,
    )
    assert len(attempts) == 1
    assert result["rc"] == 124 and result["timed_out"] is True
    assert result["retry_suppressed"] == "timed_out_non_resumable_stage"
    tool_events = [e for e in runner.events if e.get("type") == "tool_result"]
    assert tool_events[-1]["timed_out"] is True
    assert runner.report_terminal["stage"] == "run_publish"


def test_depth_full_invokes_the_convergence_loop(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setitem(sys.modules, "depth_agent", SimpleNamespace(
        depth_requested=lambda: True,
        depth_profile=lambda: "full",
        ceiling_seconds=lambda: 30,
    ))
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so, "SCRIPTS", tmp_path)
    captured = {}

    def completed(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(cmd, 0, stdout='{"regions": 1}', stderr="")

    monkeypatch.setattr(so.subprocess, "run", completed)
    runner = so.StageRunner(SHA, None, [])
    result = runner.run_depth()
    assert result["ok"] is True
    assert captured["cmd"][-1] == "--run"
    assert captured["env"]["REVAI_DEPTH"] == "full"
    assert captured["env"]["REVAI_CASE_DIR"] == str(tmp_path)


def test_winre_runs_before_deep_dive_even_if_planner_omits_tool(monkeypatch, tmp_path):
    monkeypatch.setenv("REVAI_WINRE_RUN", "1")
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so, "SCRIPTS", tmp_path)
    calls = []

    def run_winre():
        calls.append("run_winre_dynamic")
        runner.events.append({"type": "tool_result", "tool": "run_winre_dynamic"})
        return {"ok": True, "rc": 0, "pack_present": True}

    def run_stage(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append(name)
        return {"ok": True, "rc": 0}

    runner = so.StageRunner(SHA, None, [])
    monkeypatch.setattr(runner, "run_winre_dynamic", run_winre)
    monkeypatch.setattr(so.StageRunner, "_run", run_stage)
    runner.run_deep_dive_agentic()
    assert calls == ["run_winre_dynamic", "run_deep_dive_agentic"]


def test_winre_driver_exception_is_a_failed_requested_tool(monkeypatch, tmp_path):
    from types import SimpleNamespace

    monkeypatch.setenv("REVAI_WINRE_RUN", "1")
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    runner = so.StageRunner(SHA, None, [])
    fake_driver = SimpleNamespace(
        availability=lambda: (True, "ready"),
        run_dynamic=lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("driver failed")),
    )
    monkeypatch.setitem(sys.modules, "winre_runner", fake_driver)
    out = runner.run_winre_dynamic()
    assert out["ok"] is False
    assert out["state"] == "error" and "driver failed" in out["error"]
    assert runner.events[-1]["tool"] == "run_winre_dynamic"
    assert runner.events[-1]["ok"] is False


def test_failed_publish_freezes_evidence_but_allows_audit(monkeypatch, tmp_path):
    """A publisher failure must not be followed by evidence-mutating stages.

    The 2026-10-20 run failed run_publish and then restarted intake, quick scan,
    deep dive and YARA. That replay changed verdict.json after the report-input
    manifest and made section publication fail for a second, unrelated reason.
    """
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    # This test is about the stop guard, not the RC-83 precondition.
    monkeypatch.setattr(so.StageRunner, "_ensure_yara_artifacts", lambda self: None)
    calls = []

    def fake_run(cmd, **kwargs):
        name = Path(cmd[1]).name
        calls.append(name)
        rc = 1 if name == "publish_report_v2.py" else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")

    monkeypatch.setattr(so.subprocess, "run", fake_run)
    events = []
    runner = so.StageRunner(SHA, None, events)

    published = runner.run_publish()
    assert published["ok"] is False and published["rc"] == 1
    assert runner.report_terminal["stage"] == "run_publish"

    quick = runner.run_quick_scan()
    yara = runner.run_yara_gen()
    depth = runner.run_depth()
    assert quick["blocked"] is True and quick["artifacts_written"] is False
    assert yara["blocked"] is True
    assert depth["blocked"] is True
    assert quick["blocked_by"] == "run_publish"

    audit = runner.run_audit()
    assert audit["ok"] is True
    assert calls == ["publish_report_v2.py", "audit_pipeline.py"]
    assert any(
        e.get("type") == "observe" and e.get("tool") == "report_stage_stop_guard"
        for e in events
    )


def test_publish_preflight_failure_freezes_the_run(monkeypatch, tmp_path):
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    failure = {
        "ok": False,
        "rc": 1,
        "failure_reason": "verdict reconciliation failed",
    }
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: failure)
    runner = so.StageRunner(SHA, None, [])

    assert runner.run_publish() is failure
    assert runner.report_terminal["stage"] == "run_publish"
    assert runner.report_terminal["reason"] == "verdict reconciliation failed"
    assert runner.run_quick_scan()["blocked"] is True


def test_hitl_publish_stop_freezes_the_run(monkeypatch, tmp_path):
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    (tmp_path / "deep_dive").mkdir()
    (tmp_path / "verdict.json").write_text(
        json.dumps({"verdict": "malicious"}), encoding="utf-8",
    )
    (tmp_path / "deep_dive" / "05-deep-dive.json").write_text(
        json.dumps({"verdict": "clean"}), encoding="utf-8",
    )
    monkeypatch.setenv("REVAI_HITL_VERDICT", "1")
    runner = so.StageRunner(SHA, None, [])

    stopped = runner.run_publish()
    assert stopped["ok"] is False and stopped["hitl"] is True
    assert runner.report_terminal["reason"] == "hitl_verdict_conflict"
    assert runner.run_quick_scan()["blocked"] is True


def test_section_publish_failure_freezes_the_run(monkeypatch, tmp_path):
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")

    monkeypatch.setattr(so.subprocess, "run", fake_run)
    runner = so.StageRunner(SHA, None, [])

    assert runner.run_section_publish()["ok"] is False
    assert runner.report_terminal["stage"] == "run_section_publish"
    assert runner.run_quick_scan()["blocked"] is True


def test_successful_publishers_do_not_freeze_the_run(monkeypatch, tmp_path):
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    # This test is about the stop guard, not the RC-83 precondition.
    monkeypatch.setattr(so.StageRunner, "_ensure_yara_artifacts", lambda self: None)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(Path(cmd[1]).name)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(so.subprocess, "run", fake_run)
    runner = so.StageRunner(SHA, None, [])

    assert runner.run_publish()["ok"] is True
    assert runner.run_section_publish()["ok"] is True
    assert runner.report_terminal is None
    assert calls == ["publish_report_v2.py", "section_publisher.py"]

def test_planner_tool_results_are_capped_at_six_thousand_chars():
    payload = {"data": "x" * 10000}
    result = so._bounded_tool_payload(payload, 6000)
    assert len(result) > 6000
    assert result.endswith("chars)")


# --------------------------------------------------------------------------
# RC-83 (2026-11-19, S2 mode-a re-run 5): the planner called run_publish
# BEFORE run_yara_gen (and never ran yara_gen at all), so the full publish
# template hard-crashed on its missing required input `rule.yara.json` and
# the stop-guard froze the deterministic backstop (it is gated on
# report_terminal being None). The precondition below makes the publishers
# satisfy their own required inputs — deterministic, bounded, single-shot.
# --------------------------------------------------------------------------
def test_publish_runs_yara_gen_when_its_required_input_is_missing(monkeypatch, tmp_path):
    """A planner ordering slip no longer kills publish: run_publish runs the
    deterministic yara_gen precondition first when the artifacts are absent."""
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    monkeypatch.delenv("REVAI_HITL_VERDICT", raising=False)
    (tmp_path / "verdict.json").write_text(json.dumps({"verdict": "suspicious"}))
    calls = []

    def yara(self):
        calls.append("run_yara_gen")
        (tmp_path / "rule.yara.json").write_text("{}")
        (tmp_path / "iocs.json").write_text("{}")
        return {"ok": True, "rc": 0}

    def publish(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append(name)
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "run_yara_gen", yara)
    monkeypatch.setattr(so.StageRunner, "_run", publish)
    runner = so.StageRunner(SHA, None, [])

    out = runner.run_publish()
    assert out["ok"] is True
    assert calls == ["run_yara_gen", "run_publish"], calls
    assert runner.report_terminal is None
    # The second publisher sees the artifacts and does NOT re-run yara.
    out2 = runner.run_section_publish()
    assert out2["ok"] is True
    assert calls == ["run_yara_gen", "run_publish", "run_section_publish"], calls


def test_yara_precondition_failure_freezes_the_run(monkeypatch, tmp_path):
    """If the precondition itself fails, the publisher does not run and the
    stop-guard owns the run (evidence-mutating stages stay blocked)."""
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    monkeypatch.delenv("REVAI_HITL_VERDICT", raising=False)
    calls = []

    def yara_failed(self):
        calls.append("run_yara_gen")
        return {"ok": False, "rc": 1, "failure_reason": "yara crashed"}

    def publish(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append(name)
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "run_yara_gen", yara_failed)
    monkeypatch.setattr(so.StageRunner, "_run", publish)
    runner = so.StageRunner(SHA, None, [])

    out = runner.run_publish()
    assert out["ok"] is False and out["rc"] == 1
    assert calls == ["run_yara_gen"], calls
    assert runner.report_terminal is not None
    assert runner.report_terminal["stage"] == "run_publish"
    # The publisher subprocess never ran; evidence-mutating stages are blocked.
    assert "run_publish" not in calls


def test_yara_precondition_does_not_run_when_artifacts_exist(monkeypatch, tmp_path):
    """With both required inputs present the publishers proceed as before —
    no extra yara attempt, byte-identical behavior to the pre-RC-83 path."""
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    monkeypatch.delenv("REVAI_HITL_VERDICT", raising=False)
    (tmp_path / "rule.yara.json").write_text("{}")
    (tmp_path / "iocs.json").write_text("{}")
    calls = []

    def yara(self):
        calls.append("run_yara_gen")
        return {"ok": True, "rc": 0}

    def publish(self, name, cmd, timeout, *, retry_timeouts=True):
        calls.append(name)
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "run_yara_gen", yara)
    monkeypatch.setattr(so.StageRunner, "_run", publish)
    runner = so.StageRunner(SHA, None, [])

    assert runner.run_publish()["ok"] is True
    assert runner.run_section_publish()["ok"] is True
    assert calls == ["run_publish", "run_section_publish"], calls


def test_yara_precondition_rescues_a_prior_failed_yara_attempt(monkeypatch, tmp_path):
    """A failed planner yara_gen that left no artifacts is retried ONCE by the
    precondition (bounded recovery, not an unbounded loop: the publishers stay
    single-shot)."""
    monkeypatch.setattr(so, "case_dir", lambda _sha: tmp_path)
    monkeypatch.setattr(so.StageRunner, "_prepare_publish", lambda self, stage: None)
    monkeypatch.delenv("REVAI_HITL_VERDICT", raising=False)
    attempts = []

    def yara_flaky(self):
        attempts.append("run_yara_gen")
        if len(attempts) == 1:
            return {"ok": False, "rc": 1}
        (tmp_path / "rule.yara.json").write_text("{}")
        (tmp_path / "iocs.json").write_text("{}")
        return {"ok": True, "rc": 0}

    def publish(self, name, cmd, timeout, *, retry_timeouts=True):
        return {"ok": True, "rc": 0}

    monkeypatch.setattr(so.StageRunner, "run_yara_gen", yara_flaky)
    monkeypatch.setattr(so.StageRunner, "_run", publish)
    runner = so.StageRunner(SHA, None, [])

    # Simulate the planner's own failed yara attempt (recorded, no artifacts).
    runner.run_yara_gen()
    assert attempts == ["run_yara_gen"]
    out = runner.run_publish()
    assert out["ok"] is True
    assert attempts == ["run_yara_gen", "run_yara_gen"], attempts
