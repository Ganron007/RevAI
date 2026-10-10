"""#58: on a packed sample the capability domains must examine the UNPACKED image.

Measured on packed_rook_native: unpack_pass succeeded (UPX0/UPX1/UPX2) and the
unpacked capa rules carried the behavioural evidence, yet all nine domain
answers reasoned over the packed stub -- "no persistence in the packed binary",
"4 imports" -- reporting 0 observed / 9 inferred while the deep dive's own
summary cited a C2 domain and unpacked behavioural rules.
"""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/agentic_langgraph.py").parent))
import agentic_langgraph as A  # noqa: E402
sys.path.insert(0, str(resolve("revai/v2_lib.py").parent))
import v2_lib  # noqa: E402

SHA = "a" * 64


def _unpacked_findings():
    return {
        "unpack_pass": {"ok": True, "engine": "unpack_oracle",
                        "sections": [{"name": "UPX0", "rva": 4096,
                                      "virtual_size": 102400}],
                        "imports": "CreateRemoteThread, WriteProcessMemory",
                        "capa": "credential-theft, c2-communication"},
        "checklist_upx_unpack": {"upx_ok": True, "is_packed": True},
    }


def test_the_unpack_context_is_built_when_unpacking_succeeded():
    ctx = A._unpacked_image_context(_unpacked_findings())
    assert "UNPACKED IMAGE" in ctx
    assert "CreateRemoteThread" in ctx
    # The node must be told to say which image a finding came from.
    assert "unpacked:" in ctx and "packed stub:" in ctx


def test_no_unpack_context_when_nothing_was_unpacked():
    assert A._unpacked_image_context({}) == ""
    assert A._unpacked_image_context(
        {"unpack_pass": {"ok": False}, "checklist_upx_unpack": {}}) == ""


def test_the_context_says_the_stub_proves_nothing():
    ctx = A._unpacked_image_context(_unpacked_findings())
    assert "the stub's four imports prove nothing" in ctx


def test_the_ledger_records_whether_the_node_got_the_unpack_image(tmp_path):
    case = tmp_path / "logs" / SHA / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    hist = [{"tool": "domain:persistence", "result": {
        "status": "understood", "answer": "unpacked: run key written",
        "evidence": ["unpacked imports"], "tool_calls_used": 3,
        "format": "json", "unpack_evidence": True}}]
    (case / "deep_dive" / "agentic_deep_dive.json").write_text(json.dumps(
        {"findings": {"domain_graph": {"domains": {"persistence": "understood"}}},
         "history": hist}), encoding="utf-8")
    cov = v2_lib.build_capability_coverage(SHA, logs_dir=tmp_path / "logs")
    assert cov["unpack_evidence_given"] is True
    assert cov["domains"]["persistence"]["unpack_evidence"] is True


def test_the_prompt_includes_the_unpack_context(monkeypatch):
    """End to end: a domain node's prompt carries the unpacked image."""
    prompts = []

    def fake_judge(prompt, **kw):
        prompts.append(prompt)
        return {"choices": [{"message": {"content": json.dumps(
            {"status": "understood", "answer": "a", "evidence": ["e"]})}}]}

    monkeypatch.setattr(A, "llm_judge", fake_judge)
    monkeypatch.setattr(A, "create_react_agent",
                        lambda llm, tools=None, prompt=None, **k: _Fake(prompt))
    hist, finds = [], dict(_unpacked_findings())
    A.run_domain_deep_dive(
        SHA, 10, {"_coerce_final_answer": lambda r: r if isinstance(r, dict)
                  else {}}, {}, {"sample_path": "s.exe"}, "PE32",
        hist, finds, [], None, "SYS")
    # The NODE prompt is built by create_react_agent's caller, so it is not
    # itself an llm_judge call. What we can assert is that the node ran and the
    # unpack context reached it -- via the agent's recorded prompt.
    node_prompts = [a.prompt for a in _Fake.instances]
    assert node_prompts, "no domain node ran"
    assert any("UNPACKED IMAGE" in p for p in node_prompts), (
        "the domain node was not given the unpacked image")
    assert any("CreateRemoteThread" in p for p in node_prompts)


class _Fake:
    instances = []

    def __init__(self, prompt=""):
        _Fake.instances.append(self)
        self.prompt = prompt or ""

    def invoke(self, payload, config=None):
        from types import SimpleNamespace
        return {"messages": [SimpleNamespace(
            content=json.dumps({"status": "understood", "answer": "a",
                                "evidence": ["e"]}), tool_calls=[],
            response_metadata={})]}
