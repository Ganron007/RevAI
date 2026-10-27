"""Evidence-conditioned behavioral/dynamic report sections (RC-27).

Operator decision 2026-10-27: report sections follow the pipeline's own
presence-gating. Without a WinRE detonation there is no behavioral evidence
to interpret, so "5. Behavioral & Dynamic Analysis" (technical, both v2 and
v3) and the master's "5. Behavioral Analysis" render deterministically from
the run's dynamic-analysis status -- no LLM call, no stall magnet, nothing
for the dynamic gates to misparse. With a detonation the LLM path is
unchanged.
"""
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402
import report_quality as RQ  # noqa: E402
import entailment as E  # noqa: E402

from _report_fixtures import structured_tool_response  # noqa: E402

SHA = "a" * 64

_STATUS_SENTENCE = (
    "Run-scoped status -- RevAI Speakeasy: emulation produced a trace; "
    "RevAI Frida probe: static-only, not sample execution; WinRE detonation: "
    "no runtime pack or run status; launch unverified; WinRE Frida runtime: "
    "no runtime trace artifact present; packet capture: no packet capture "
    "artifact present."
)


def _record(winre_ran: bool | None = None) -> dict:
    """A dynamic-analysis-status record in the persisted-record shape."""
    return {
        "schema_version": 1,
        "sha256": SHA,
        "sentence": _STATUS_SENTENCE,
        "status": {
            "sentence": _STATUS_SENTENCE,
            "emulation": {"present": True, "ok": True, "engine_ran": True,
                          "state": "emulation produced a trace"},
            "frida_static_probe": {"execution_proven": False},
            "frida_runtime": {"trace_artifact_present": False,
                              "observed_runtime_events": False},
            "winre": {"pack_present": False, "pack_correlated": False,
                      "detonation_ran": winre_ran},
            "packet_capture": {"present": False},
        },
    }


# ------------------------------------------------------------------ helpers
def test_the_condition_reads_both_record_shapes():
    assert v2_lib.dynamic_evidence_substantive(_record(winre_ran=True)) is True
    assert v2_lib.dynamic_evidence_substantive(_record(winre_ran=None)) is False
    assert v2_lib.dynamic_evidence_substantive(
        _record(winre_ran=None)["status"]) is False
    assert v2_lib.dynamic_evidence_substantive(None) is False
    assert v2_lib.dynamic_evidence_substantive({}) is False


def test_the_renderer_quotes_the_status_and_cites_it():
    md = v2_lib.deterministic_dynamic_section_md(_record())
    assert "## 5. Behavioral & Dynamic Analysis" in md
    assert _STATUS_SENTENCE in md
    assert md.count("(source: dynamic_analysis_status") == 3
    master = v2_lib.deterministic_dynamic_section_md(
        _record(), title="5. Behavioral Analysis", heading_level=1)
    assert "# 5. Behavioral Analysis" in master


# ------------------------------------------------------------- technical v2
def _fake_llm_recording_titles(monkeypatch, import_name):
    import importlib
    mod = importlib.import_module(import_name)
    requested: list[str] = []

    def fake(prompt, **kwargs):
        head = prompt.split("Rules", 1)[0]
        titles = [t for t in mod.TECHNICAL_REPORT_SECTIONS if f"- {t}" in head]
        requested.extend(titles)
        body = "\n\n".join(
            f"## {t}\n\nGrounded analysis of {t.split('. ', 1)[-1]} explains "
            "the observed artifact, its source and the limits of the finding. "
            "The import table is small and the strings are listed in the "
            "evidence appendix."
            for t in titles)
        return structured_tool_response(body), {"markdown": body}

    monkeypatch.setattr(mod, "llm_report_structured", fake)
    return requested


def test_no_detonation_renders_section5_without_an_llm_call(monkeypatch):
    import publish_report_v2 as pub
    requested = _fake_llm_recording_titles(monkeypatch, "publish_report_v2")
    md, audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE",
        dynamic_status=_record(winre_ran=None)["status"])
    assert "5. Behavioral & Dynamic Analysis" not in requested, requested
    assert "No runtime-analysis mechanism observed this sample" in md
    assert _STATUS_SENTENCE in md
    assert any(a.get("deterministic") for a in audits)
    assert not errors, errors


def test_a_detonation_keeps_the_llm_path_for_section5(monkeypatch):
    import publish_report_v2 as pub
    requested = _fake_llm_recording_titles(monkeypatch, "publish_report_v2")
    md, _audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE",
        dynamic_status=_record(winre_ran=True)["status"])
    assert "5. Behavioral & Dynamic Analysis" in requested, requested
    assert "No runtime-analysis mechanism observed this sample" not in md
    assert not errors, errors


def test_an_unknown_status_defaults_to_the_llm_path(monkeypatch):
    import publish_report_v2 as pub
    requested = _fake_llm_recording_titles(monkeypatch, "publish_report_v2")
    _md, _audits, errors = pub.generate_technical_chunked(
        {"sha256": SHA, "sample_path": "/x", "project_name": "p"},
        {}, {}, {}, [], "EVIDENCE",
        dynamic_status=None)
    assert "5. Behavioral & Dynamic Analysis" in requested, requested
    assert not errors, errors


# ------------------------------------------------------------------- gates
def _rq_status(winre_ran, emulation_ran=False, sentence=_STATUS_SENTENCE) -> dict:
    """The report-quality gate's own status shape.

    The sentence MUST match the emulation flag: quoting a status sentence
    that says 'emulation produced a trace' while the status says the engine
    did not run is exactly the RC-05 fabrication shape.
    """
    return {
        "any_dynamic_performed": bool(winre_ran or emulation_ran),
        "emulation": {"present": emulation_ran, "ok": emulation_ran,
                      "engine_ran": emulation_ran,
                      "state": "emulation produced a trace" if emulation_ran
                      else "emulation stage produced no oracle result"},
        "winre": {"pack_present": False, "detonation_ran": winre_ran},
        "frida_runtime": {"trace_artifact_present": False,
                          "observed_runtime_events": False},
        "packet_capture": {"present": False},
        "sentence": sentence,
    }


def test_the_deterministic_section_passes_the_dynamic_gates():
    # Run-5-like pairing: the emulation oracle ran, WinRE did not.
    md = v2_lib.deterministic_dynamic_section_md(_record())
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _rq_status(None, emulation_ran=True))
    assert not any("dynamic_execution_claimed" in v
                   for v in result["violations"]), result
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in result["violations"]), result
    # All-absent pairing: nothing ran, including the emulation oracle.
    quiet = (_STATUS_SENTENCE
             .replace("RevAI Speakeasy: emulation produced a trace",
                      "RevAI Speakeasy: emulation stage produced no oracle "
                      "result"))
    md_quiet = v2_lib.deterministic_dynamic_section_md(
        {"sentence": quiet, "status": {"winre": {"detonation_ran": None}}})
    result = RQ._cross_report_consistency(
        md_quiet, md_quiet, "", 6.96, _rq_status(None, sentence=quiet))
    assert not any("dynamic_execution_claimed" in v
                   for v in result["violations"]), result
    assert not any("dynamic_performed_but_report_says_none" in v
                   for v in result["violations"]), result
    # A real detonation: the deterministic section is never produced, but the
    # text must still not trip the gates if it ever appears in a report.
    result = RQ._cross_report_consistency(
        md, md, "", 6.96, _rq_status(True, emulation_ran=True))
    assert not any("dynamic_execution_claimed" in v
                   for v in result["violations"]), result


def test_the_deterministic_section_is_not_a_stub_for_the_quality_gate():
    md = v2_lib.deterministic_dynamic_section_md(_record())
    pack = RQ.evaluate_report_markdown(
        md, required_sections=["5. Behavioral & Dynamic Analysis"],
        min_total_chars=0, label="technical_v2")
    assert not any("orphan_tables" in i for i in pack["issues"]), pack["issues"]
    assert not any("stub" in i for i in pack["issues"]), pack["issues"]
    assert not pack.get("missing"), pack


# --------------------------------------------------------------- citations
def test_the_deterministic_citation_resolves(tmp_path):
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    record = _record()
    record["_cadre_provenance"] = {
        "schema": "revai-artifact-provenance/v1", "sha256": SHA,
        "run_id": "1" * 32, "mode": "scripted",
        "artifact": "dynamic-analysis-status.json"}
    (case / "dynamic-analysis-status.json").write_text(
        json.dumps(record), encoding="utf-8")
    located, check = E._ground_citation(
        {"source": "dynamic_analysis_status",
         "query": "dynamic-analysis-status.json",
         "row": "$.sentence"}, case)
    assert located is not None, check
    assert check["status"] == "traceable-row", check


# ------------------------------------------------------------------ v3
def test_v3_section5_is_deterministic_without_a_detonation(monkeypatch):
    import section_publisher as sp

    calls: list[str] = []

    def fake_llm(prompt, **kwargs):
        calls.append(prompt)
        return structured_tool_response("## 5. Behavioral & Dynamic Analysis\n"
                                        "LLM wrote this.")

    monkeypatch.setattr(sp, "llm_report_structured", fake_llm)
    monkeypatch.setattr(v2_lib, "dynamic_analysis_status",
                        lambda sha, **k: _record(winre_ran=None))
    result = sp._generate_technical_section(
        "5. Behavioral & Dynamic Analysis", [], "header", SHA)
    assert result["deterministic"] is True
    assert result["llm_ok"] is True
    assert "No runtime-analysis mechanism observed this sample" \
        in result["markdown"]
    assert not calls, "the v3 section-5 branch still called the LLM"


def test_v3_section5_keeps_the_llm_path_on_a_detonation(monkeypatch):
    import section_publisher as sp

    calls: list[str] = []

    def fake_llm(prompt, **kwargs):
        calls.append(prompt)
        body = "## 5. Behavioral & Dynamic Analysis\nThe detonation produced " \
               "3,214 runtime events across 41 API calls."
        return structured_tool_response(body), {"markdown": body}

    monkeypatch.setattr(sp, "llm_report_structured", fake_llm)
    monkeypatch.setattr(v2_lib, "dynamic_analysis_status",
                        lambda sha, **k: _record(winre_ran=True))
    result = sp._generate_technical_section(
        "5. Behavioral & Dynamic Analysis", [], "header", SHA)
    assert calls, "the LLM path was not used despite a detonation"
    assert result.get("deterministic") is not True
    assert "3,214 runtime events" in result["markdown"]


def test_v3_section5_falls_back_to_llm_when_status_is_unreadable(monkeypatch):
    import section_publisher as sp

    calls: list[str] = []

    def fake_llm(prompt, **kwargs):
        calls.append(prompt)
        body = "## 5. Behavioral & Dynamic Analysis\nStatus read failed; the " \
               "writer states the run status from the evidence pack."
        return structured_tool_response(body), {"markdown": body}

    def broken_status(sha, **k):
        raise RuntimeError("logs unavailable")

    monkeypatch.setattr(sp, "llm_report_structured", fake_llm)
    monkeypatch.setattr(v2_lib, "dynamic_analysis_status", broken_status)
    result = sp._generate_technical_section(
        "5. Behavioral & Dynamic Analysis", [], "header", SHA)
    assert calls, "an unreadable status must fall through to the LLM path"
    assert result.get("deterministic") is not True
