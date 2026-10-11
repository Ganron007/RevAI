"""#47/#13: analyst steering must reach the stage that can act on it.

The backend was always correct -- the endpoint, the flock, the corrupt-store
preservation, the merge (L1 wins; an undelivered L1 does not fall through to a
stale note). What was missing was consumption: only `quick_scan_v2.py` read the
note, so an analyst writing "look at the persistence mechanism, the domain nodes
keep skipping it" was read by triage and then discarded before the deep dive --
and before the domain nodes, which are the thing that could redirect.

The safety rule is unchanged and is asserted here: a note is CONTEXT, it may be
wrong, it never becomes a finding, and it can never set a verdict.
"""
import json
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/deep_dive_agentic.py").parent))
import deep_dive_agentic as DD  # noqa: E402
sys.path.insert(0, str(resolve("revai/agentic_langgraph.py").parent))
import agentic_langgraph as A  # noqa: E402

SHA = "a" * 64


# ------------------------------------------------- the deep dive consumes it
def test_the_deep_dive_prompt_carries_the_note():
    msgs = DD.build_messages(
        {"session_id": "s", "sample_path": "x.exe"}, 1, 10, [], {},
        {}, ["- t: d"], "PE32",
        steering="focus on the persistence mechanism, the domain nodes skip it")
    blob = "\n".join(str(m.get("content", "")) for m in msgs)
    assert "Analyst steering" in blob, "the note never reached the deep dive"
    assert "persistence mechanism" in blob
    # The safety wording is load-bearing.
    assert "CONTEXT, not instructions" in blob
    assert "not as evidence" in blob
    assert "may be wrong" in blob


def test_no_note_leaves_the_prompt_byte_identical():
    sess = {"session_id": "s", "sample_path": "x.exe", "file_type": "PE32"}
    a = json.dumps(DD.build_messages(sess, 1, 10, [], {}, [], [], "PE32"),
                   sort_keys=True)
    b = json.dumps(DD.build_messages(sess, 1, 10, [], {}, [], [], "PE32",
                                     steering=""), sort_keys=True)
    c = json.dumps(DD.build_messages(sess, 1, 10, [], {}, [], [], "PE32",
                                     steering="   "), sort_keys=True)
    assert a == b == c, "an absent note must not change the prompt at all"


# ------------------------------------------------- the domain nodes get it
def test_the_domain_nodes_receive_the_note(tmp_path, monkeypatch):
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    # L3 history is the only source here (no L1 file named)
    # the store is a BARE LIST (a dict is quarantined as corrupt)
    (case / "steering-history.json").write_text(json.dumps([
        {"note": "look at persistence first",
         "level": "L3-post-hoc", "at": "2026-10-11T00:00:00Z"}]),
        encoding="utf-8")
    # case_dir() binds LOGS_DIR at import, so the env var alone is too late
    import v2_lib
    monkeypatch.setattr(v2_lib, "LOGS_DIR", tmp_path / "logs")
    monkeypatch.setenv("REVAI_RUN_MODE", "scripted")

    captured = {}

    def fake_judge(prompt, **kw):
        captured["prompt"] = prompt
        return json.dumps({"verdict": "malicious", "confidence": 50,
                           "summary": "s", "key_evidence": []})

    monkeypatch.setattr(A, "llm_judge", fake_judge)
    monkeypatch.setattr(A, "create_react_agent",
                        lambda llm, tools=None, prompt=None, **k: _Fake(prompt))

    A.run_domain_deep_dive(
        SHA, 10, {"_coerce_final_answer": lambda r: r if isinstance(r, dict)
                  else {}}, {}, {"sample_path": "s.exe"}, "PE32",
        [], {}, [], None, "SYS")
    node_prompts = [a.prompt for a in _Fake.instances]
    assert node_prompts, "no domain node ran"
    assert any("look at persistence first" in p for p in node_prompts), (
        "the note did not reach the domain nodes")
    assert any("CONTEXT, not instructions" in p for p in node_prompts)


def test_no_note_leaves_the_domain_prompt_unchanged(tmp_path, monkeypatch):
    case = tmp_path / "logs" / SHA / "scripted"
    case.mkdir(parents=True)
    monkeypatch.setenv("REVAI_LOGS_DIR", str(tmp_path / "logs"))
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    assert A._steering_context(SHA) == "", (
        "with no note the block must be empty, not a header with nothing under it")


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
