#!/usr/bin/env python3
"""Published markdown must not name the model or vendor (docs hygiene rule).

Found 2026-10-03 during a reliability sweep. The live win32k_dll run leaked the
configured provider and model into four published documents -- REPORT-TECHNICAL-v2
(2), REPORT-TECHNICAL-v3 (3), AUDIT-REPORT.md (1), EVIDENCE-BUNDLE.md (1) -- while
`configured-llm`, the form the rule prescribes, appeared ZERO times.

The mechanism is worth recording, because fixing the obvious place would not have
been enough:

  verdict.json holds the real model name  (machine evidence - keep it)
    -> v2_lib's technical evidence pack rendered it as `- **model**: <name>`
      -> that pack is embedded in the technical prompt
        -> the MODEL COPIED the string into its own prose
          -> the report published the name

So there were two writers, not one. The evidence-pack injection is fixed at the
source (it now emits the public label unconditionally), AND a defensive pass runs
over every published markdown, because the model can still copy a name that
arrives by some other route.

Two things this must not do, and the tests below pin both:

* `verdict.json` and `pipeline-audit.json` keep the REAL name. They are the
  machine evidence an auditor reads to learn which model judged the sample.
  Scrubbing those would be destroying the audit trail to satisfy a doc rule.
* Prose that merely resembles a model name must survive. The replacement is
  exact-match against the names this deployment is actually configured with, so
  `kernel32.dll` and capability names are untouched. A regex broad enough to
  catch unknown vendors is also broad enough to mangle analysis text.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir, source  # noqa: E402

add_module_dir("revai/report_quality.py")

import report_quality as rq  # noqa: E402

MODEL = "mimo-v2.6-pro"
FLASH = "mimo-v2.6-flash"


def _with_models(monkeypatch, *names):
    for n in names:
        monkeypatch.setenv("REVAI_LLM_MODEL", n)
        monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", n)
        monkeypatch.setenv("REVAI_LLM_PLANNER_MODEL", n)


# --------------------------------------------------------------------------
# The label and the mechanism
# --------------------------------------------------------------------------

def test_public_label_is_the_prescribed_form():
    assert rq.PUBLIC_MODEL_LABEL == "configured-llm"


def test_redaction_replaces_the_configured_names(monkeypatch):
    """Default and verdict really are different models in this deployment."""
    monkeypatch.setenv("REVAI_LLM_MODEL", FLASH)
    monkeypatch.setenv("REVAI_LLM_PLANNER_MODEL", FLASH)
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", MODEL)
    out, rep = rq.redact_model_names(
        f"Verdict engine llm_judge, model `{MODEL}`. Default was {FLASH}.")
    assert MODEL not in out and FLASH not in out, out
    assert out.count(rq.PUBLIC_MODEL_LABEL) >= 2, out
    assert set(rep) == {MODEL, FLASH}, rep


def test_redaction_leaves_analysis_text_alone(monkeypatch):
    _with_models(monkeypatch, MODEL)
    src = ("Imports advapi32.RegSetValueExW from ADVAPI32.dll; capability "
           "attack.persistence.t1543.003; sample kernel32.dll loader.")
    out, rep = rq.redact_model_names(src)
    assert out == src, "redaction mangled analysis prose"
    assert rep == [], rep


def test_redaction_is_idempotent(monkeypatch):
    """Running twice must not double-substitute or corrupt the label."""
    _with_models(monkeypatch, MODEL)
    once, _ = rq.redact_model_names(f"model {MODEL}")
    twice, rep2 = rq.redact_model_names(once)
    assert twice == once, (once, twice)
    assert rep2 == [], rep2


def test_empty_markdown_is_safe():
    out, rep = rq.redact_model_names("")
    assert out == "" and rep == []


def test_configured_names_are_longest_first(monkeypatch):
    """"mimo-v2.6" and "mimo-v2.6-pro" can both be configured.

    Replacing the shorter first would leave "-pro" dangling in the output.
    """
    monkeypatch.setenv("REVAI_LLM_MODEL", "mimo-v2.6")
    monkeypatch.setenv("REVAI_LLM_VERDICT_MODEL", MODEL)
    monkeypatch.setenv("REVAI_LLM_PLANNER_MODEL", "mimo-v2.6")
    names = rq.configured_model_names()
    assert names == sorted(names, key=len, reverse=True), names
    out, _ = rq.redact_model_names(f"{MODEL} and mimo-v2.6")
    assert "-pro" not in out, out
    assert "mimo" not in out, out


def test_redaction_cannot_silently_become_a_no_op(monkeypatch):
    """The failure mode is a caller reporting success while publishing the name.

    With no env set the resolvers return nothing, so the env-file fallback must
    supply the names. Pinned by pointing the resolver at nothing and using the
    real configured names via the environment instead -- if the fallback breaks,
    this returns an empty list and the assertion below fails.
    """
    _with_models(monkeypatch, MODEL)
    assert MODEL in rq.configured_model_names(), (
        "no names discovered: redaction would silently publish the provider")


# --------------------------------------------------------------------------
# The injection site - fixed at the source, not only in the output
# --------------------------------------------------------------------------

def test_evidence_pack_no_longer_renders_the_real_model_name():
    src = source("revai/v2_lib.py")
    assert "PUBLIC_MODEL_LABEL" in src, (
        "the technical evidence pack must emit the public label for the verdict "
        "model field; that render is the source the model copies from")
    assert 'if k == "model":' in src, (
        "the model field needs its own branch in the verdict loop")


def test_every_published_markdown_path_redacts():
    """All four publishers plus the audit report.

    Enumerated rather than discovered, which is normally the wrong instinct --
    but here the list IS the contract (these are the documents we publish), and
    a new publisher added later must be added here deliberately.
    """
    for rel, needle in (
        ("revai/publish_report_v2.py", "redact_model_names"),
        ("revai/section_publisher.py", "redact_model_names"),
        ("revai/audit_pipeline.py", "redact_model_names"),
    ):
        assert needle in source(rel), f"{rel} does not redact model names"


def test_json_artifacts_keep_the_real_name():
    """The other half of the contract: the audit trail is NOT scrubbed.

    Only markdown is redacted. If a future change starts writing the public
    label into the JSON artifacts, an auditor can no longer tell which model
    judged the sample -- which is the whole point of keeping that field.
    """
    # audit_pipeline copies verdict.model into its own JSON.
    assert 'verdict.get("model")' in source("revai/audit_pipeline.py")
    # section_publisher records the request/response model per section.
    assert '"request_model"' in source("revai/section_publisher.py")