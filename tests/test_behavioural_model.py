"""#8: the behavioural model -- what the sample DOES, as a model.

The capability ledger answers "which domains did we examine, and is each
determination backed by evidence". This answers the question an analyst opens the
report for. The unit is different: capabilities, the objects they act on, the
observations backing each, and the gaps -- four things that must not be
conflated, because a report listing capabilities without saying what the binary
touches is not a behavioural model.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/behavioural_model.py").parent))
import behavioural_model as B  # noqa: E402

SHA = "a" * 64


def _case(tmp_path, domains, answers=None, evidence_for=None, iocs=None):
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = []
    for k, st in domains.items():
        ev = ["ghidra_query imports: RegSetValueExA present",
              "ghidra_query strings: 'SOFTWARE\\...\\Run' at 4254488"] \
            if (evidence_for or {}).get(k) else []
        hist.append({"tool": f"domain:{k}",
                     "result": {"status": st,
                                "answer": (answers or {}).get(k, f"{k} answer"),
                                "evidence": ev,
                                "tool_calls_used": 3, "format": "json"}})
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": domains}},
         "history": hist}), encoding="utf-8")
    if iocs is not None:
        (case / "iocs.json").write_text(json.dumps(iocs), encoding="utf-8")
    return case


ALL = {"surface": "understood", "persistence": "understood",
       "c2_network": "partial", "evasion": "partial",
       "execution_injection": "partial", "credential_access": "partial",
       "exfiltration": "partial", "defense_impairment": "partial",
       "crypto": "partial"}


def _ev(*keys):
    return {k: True for k in keys}


# ------------------------------------------------------------------- the model
def test_the_model_carries_capabilities_with_provenance(tmp_path):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface", "persistence"),
                 iocs={"registry_keys": ["HKCU\\...\\Run"]})
    m = B.build_behavioural_model(SHA, case_root=case)
    caps = {c["key"]: c for c in m["capabilities"]}
    assert caps["surface"]["provenance"] == "observed"
    assert caps["persistence"]["provenance"] == "observed"
    assert caps["crypto"]["provenance"] == "inferred"


def test_the_model_carries_the_objects_the_sample_acts_on(tmp_path):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface"),
                 iocs={"registry_keys": ["HKCU\\...\\Run"],
                       "urls": ["http://evil.example/"],
                       "domains": [{"domain": "evil.example"}],
                       "ips": ["1.2.3.4"],
                       "files": ["C:\\temp\\a.exe"],
                       "mutexes": ["Global\\m"]})
    m = B.build_behavioural_model(SHA, case_root=case)
    objs = m["objects"]
    assert objs["Registry keys"] == ["HKCU\\...\\Run"]
    assert objs["URLs"] == ["http://evil.example/"]
    assert objs["Domains"] == ["evil.example"], (
        "domains is a list of dicts; it must still yield the values")
    assert objs["IP addresses"] == ["1.2.3.4"]
    assert len(objs) == 6, objs


def test_observations_come_only_from_observed_capabilities(tmp_path):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface"),
                 iocs={"urls": ["http://x/"]})
    m = B.build_behavioural_model(SHA, case_root=case)
    assert m["observations"], "an observed domain's evidence must be listed"
    assert all(o["domain"] == "surface" for o in m["observations"]), (
        "an inferred domain's evidence is not an observation")
    engs = {o.get("engine") for o in m["observations"]}
    assert "ghidra_query" in engs


def test_nothing_to_assemble_reports_absence_not_a_model(tmp_path):
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    assert B.build_behavioural_model(SHA, case_root=case) == {}


def test_cli_handles_case_with_nothing_to_assemble(tmp_path):
    case = tmp_path / "logs" / SHA / "agentic"
    case.mkdir(parents=True)
    proc = subprocess.run(
        [sys.executable, str(resolve("revai/behavioural_model.py")), str(case)],
        capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    assert "nothing to assemble" in proc.stderr
    assert "NameError" not in proc.stderr


def test_an_unknown_domain_is_listed_as_a_gap(tmp_path):
    d = dict(ALL)
    d["crypto"] = "not-explored"
    case = _case(tmp_path, d, evidence_for=_ev("surface"), iocs={"urls": ["u"]})
    m = B.build_behavioural_model(SHA, case_root=case)
    assert "crypto" in m["unknown"]
    assert "gaps in this analysis" in B.format_behavioural_model(m)


# ------------------------------------------------------------------ rendering
def test_the_section_lists_capabilities_objects_and_provenance(tmp_path):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface", "persistence"),
                 iocs={"registry_keys": ["HKCU\\...\\Run"],
                       "urls": ["http://evil.example/"]})
    md = B.format_behavioural_model(
        B.build_behavioural_model(SHA, case_root=case))
    assert "## Behavioural Model" in md
    assert "### Capabilities" in md
    assert "### Observed actions" in md
    assert "### Objects acted on" in md
    assert "**observed**" in md
    assert "HKCU\\...\\Run" in md
    assert "Model provenance: 2 observed, 7 inferred, 0 unknown" in md


def test_a_truncated_or_contradicting_domain_is_flagged(tmp_path):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface"),
                 iocs={"urls": ["u"]})
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps({
        "findings": {"domain_graph": {"domains": ALL}},
        "history": [{"tool": "domain:c2_network",
                     "result": {"status": "partial", "answer": "a",
                                "evidence": ["e"],
                                "truncated": True,
                                "status_contradicts_answer": True,
                                "tool_calls_used": 3, "format": "json"}}],
    }), encoding="utf-8")
    md = B.format_behavioural_model(
        B.build_behavioural_model(SHA, case_root=case))
    assert "truncated" in md and "contradicts its own answer" in md


def test_attach_is_a_noop_without_a_model(tmp_path):
    md = "## Report\n\nbody\n"
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    assert B.attach_behavioural_model(md, SHA, logs_dir=tmp_path / "logs") == md


def test_attach_appends_and_opt_out_is_honoured(tmp_path, monkeypatch):
    case = _case(tmp_path, ALL, evidence_for=_ev("surface"),
                 iocs={"urls": ["http://x/"]})
    md = "## Report\n\nbody\n"
    out = B.attach_behavioural_model(md, SHA, logs_dir=tmp_path / "logs")
    assert out.startswith(md.rstrip()) and "## Behavioural Model" in out
    monkeypatch.setenv("REVAI_DISABLE_BEHAVIOURAL_MODEL", "1")
    assert B.attach_behavioural_model(md, SHA, logs_dir=tmp_path / "logs") == md


def test_the_feature_gate_is_off_by_default(monkeypatch):
    monkeypatch.delenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", raising=False)
    assert B.behavioural_model_enabled() is False
    monkeypatch.setenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", "1")
    assert B.behavioural_model_enabled() is True


@pytest.mark.parametrize("mode", ["scripted", "agentic"])
def test_stage_runner_executes_model_for_the_selected_case(tmp_path, monkeypatch, mode):
    """Execute the real child CLI: rc=0 alone cannot prove the model was built.

    Deliberately set the inherited mode and case env to a different directory.
    The selected case must receive the model and its subprocess trace.
    """
    import stage_orchestrator as so

    case = _case(tmp_path, ALL, evidence_for=_ev("surface"),
                 iocs={"urls": ["http://observed.example/"]})
    if mode == "agentic":
        case = case.rename(case.with_name(mode))
    monkeypatch.setenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", "1")
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic" if mode == "scripted" else "scripted")
    monkeypatch.setenv("REVAI_CASE_DIR", str(tmp_path / "wrong-case"))
    monkeypatch.setattr(so, "case_dir", lambda sha: case)
    monkeypatch.setattr(so, "SCRIPTS", resolve("revai/behavioural_model.py").parent)
    monkeypatch.setattr(so, "run_profile", lambda: {"stage_retries": 0})
    runner = so.StageRunner(SHA, None, [])
    result = runner.run_behavioural_model()
    assert result.get("ok") is True, result
    assert result.get("rc") == 0
    model = json.loads((case / "behavioural_model.json").read_text(encoding="utf-8"))
    assert model["observations"]
    assert model["objects"]["URLs"] == ["http://observed.example/"]
    assert any(e.get("tool") == "behavioural_model" and e.get("rc") == 0
               for e in runner.events)
    assert not (tmp_path / "wrong-case" / "behavioural_model.json").exists()


def test_stage_runner_records_model_child_failure(tmp_path, monkeypatch):
    import stage_orchestrator as so

    case = tmp_path / "case"
    case.mkdir()
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "behavioural_model.py").write_text("raise SystemExit(7)\n", encoding="utf-8")
    monkeypatch.setenv("REVAI_ENABLE_BEHAVIOURAL_MODEL", "1")
    monkeypatch.setattr(so, "case_dir", lambda sha: case)
    monkeypatch.setattr(so, "SCRIPTS", scripts)
    monkeypatch.setattr(so, "run_profile", lambda: {"stage_retries": 0})
    runner = so.StageRunner(SHA, None, [])
    result = runner.run_behavioural_model()
    assert result["ok"] is False and result["rc"] == 7
    assert runner.events[-1]["rc"] == 7
