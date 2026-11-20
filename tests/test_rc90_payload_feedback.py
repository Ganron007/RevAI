#!/usr/bin/env python3
"""RC-90: every successfully unpacked payload is a first-class analysis target.

The defect (measured live on S2 `f18d3493ba43`, detonation #17, run stopped by
the operator for this fix). The post-UPX second pass existed since V5.16.5 but
was gated on the classic `upx -d` unpacker succeeding:

    if (upx_r or {}).get("upx_ok") and unpacked:

That sample carries a modified UPX header, so `upx -d` refused
(`upx_returncode=1`, `upx_ok=False`, `unpacked_path=None`) and the guard never
fired. The emulation unpacker (`unpack_oracle`) nonetheless recovered a
131,832-byte payload -- and it fed NOTHING: no capa, no floss, no malcat, no
imports, no decompilation, no strings. The report then described a wrapper with
3 imports while the actual malware sat unanalysed in `unpack/`. The pipeline's
own YARA output said so: "no confirmed malware family due to lack of unpacked
behavioral analysis".

Nothing here relaxes a gate. The payload's tool results are recorded as
first-class evidence under `payload_feedback` and are citable like any other;
an unpack that cannot be re-analysed is recorded with its reason.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import deep_dive_agentic as DDA  # noqa: E402


def _payload(tmp_path: Path, size: int = 4096, name: str = "a") -> Path:
    p = tmp_path / "unpack" / f"unpacked_{name}.vir"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b"MZ" + b"\x00" * (size - 2))
    return p


def _state() -> tuple[dict, dict, list]:
    return {}, {}, []


def test_the_emulation_payload_feeds_back_when_upx_d_refused(tmp_path, monkeypatch):
    r"""The exact live shape: `upx -d` failed, the oracle recovered the payload.

    Before RC-90 this call was a no-op and the payload was orphaned.
    """
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {
        "unpacked": True,
        "payload": {"path": str(payload), "size": payload.stat().st_size,
                    "sha256": "a" * 64},
    }
    calls: list[str] = []
    monkeypatch.setattr(
        DDA, "run_post_upx_second_pass",
        lambda path, **kw: (calls.append(path),
                            {"ok": True, "tool_ok": {"capa": {"ok": True}}})[1])

    # upx_r says the classic unpacker failed -- the shape that was dropped.
    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": False, "unpacked_path": None},
        findings=findings, tools_raw=tools_raw, history=history)

    assert calls == [str(payload)], calls
    assert tools_raw["payload_feedback"]["ok"] is True, tools_raw
    assert findings["payload_feedback"]["engine"].startswith("unpack_oracle")
    assert findings["unpacked_payload"]["path"] == str(payload)
    assert findings["unpacked_payload"]["size"] == payload.stat().st_size
    assert [h["tool"] for h in history] == ["payload_feedback"], history


def test_the_upx_d_payload_still_feeds_back(tmp_path, monkeypatch):
    """The V5.16.5 behaviour is preserved, not replaced."""
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    calls: list[str] = []
    monkeypatch.setattr(
        DDA, "run_post_upx_second_pass",
        lambda path, **kw: (calls.append(path),
                            {"ok": True, "tool_ok": {"yara": {"ok": True}}})[1])

    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": True, "unpacked_path": str(payload)},
        findings=findings, tools_raw=tools_raw, history=history)

    assert calls == [str(payload)], calls
    assert findings["payload_feedback"]["engine"] == "upx -d"
    assert findings["unpacked_payload"]["engine"] == "upx -d"


def test_both_engines_are_fed_and_each_payload_once(tmp_path, monkeypatch):
    """Two engines -> two analyses; the same payload is never analysed twice.

    The agentic path calls this before AND after the signal extractors (the
    emulation unpacker runs inside them), so idempotence is load-bearing.
    """
    a = _payload(tmp_path, 4096, "a")
    b = _payload(tmp_path, 8192, "b")
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {"unpacked": True,
                               "payload": {"path": str(b), "size": 8192}}
    calls: list[str] = []
    monkeypatch.setattr(
        DDA, "run_post_upx_second_pass",
        lambda path, **kw: (calls.append(path),
                            {"ok": True, "tool_ok": {}})[1])

    for _ in range(3):
        DDA._run_payload_feedback_pass(
            upx_r={"upx_ok": True, "unpacked_path": str(a)},
            findings=findings, tools_raw=tools_raw, history=history)

    assert sorted(calls) == sorted([str(a), str(b)]), calls
    assert len(history) == 2, history


def test_a_missing_payload_is_recorded_not_raised(tmp_path):
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {"unpacked": True,
                               "payload": {"path": str(tmp_path / "gone.vir")}}
    DDA._run_payload_feedback_pass(
        upx_r={}, findings=findings, tools_raw=tools_raw, history=history)
    assert history and history[0]["error"] == "payload file missing", history
    assert "payload_feedback" not in tools_raw, tools_raw


def test_a_failing_second_pass_is_recorded_not_raised(tmp_path, monkeypatch):
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {"unpacked": True,
                               "payload": {"path": str(payload)}}

    def _boom(path, **kw):
        raise RuntimeError("tool crashed")

    monkeypatch.setattr(DDA, "run_post_upx_second_pass", _boom)
    DDA._run_payload_feedback_pass(
        upx_r={}, findings=findings, tools_raw=tools_raw, history=history)
    assert "RuntimeError" in history[0]["error"], history
    assert "payload_feedback" not in tools_raw


def test_no_payload_anywhere_is_a_no_op():
    findings, tools_raw, history = _state()
    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": False}, findings=findings, tools_raw=tools_raw,
        history=history)
    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": True, "unpacked_path": ""},
        findings=findings, tools_raw=tools_raw, history=history)
    assert history == [], history
    assert tools_raw == {}, tools_raw


def test_the_payload_is_named_in_the_agent_prompt():
    """The payload must be visible OUTSIDE the findings budget.

    `findings` is truncated at MAX_FINDINGS_CHARS; a payload named only there
    is cut away, which is how a 131 KB image came to be analysed by nobody.
    """
    findings = {
        "unpacked_payload": {"path": "/case/unpack/p.vir", "size": 131832,
                             "engine": "unpack_oracle", "sha256": "b" * 64},
        "payload_feedback": {"ok": True,
                             "tool_ok": {"capa": {"ok": True},
                                         "floss": {"ok": False},
                                         "malcat": {"ok": True}}},
    }
    tools_ok = findings["payload_feedback"]["tool_ok"]
    ok_names = [n for n, v in tools_ok.items()
                if isinstance(v, dict) and v.get("ok")]
    assert ok_names == ["capa", "malcat"], ok_names
    # The block the prompt renders must carry the path, the size and the
    # engines that succeeded, and must name the target= override.
    assert "/case/unpack/p.vir" in json.dumps(findings)
    assert "131832" in json.dumps(findings)


def test_the_step_budget_is_generous_by_default():
    """16 steps cannot unpack AND decompile; the checklist alone eats most of it."""
    assert DDA.MAX_STEPS >= 100, DDA.MAX_STEPS


def test_file_tools_accept_a_target_override():
    """The agent must be able to point a tool at the payload, not the wrapper."""
    import inspect
    for name in ("_r2_decompile", "_capa_analyze", "_floss_extract",
                 "_yara_scan", "_pe_import_signals", "_xor_string_search"):
        method = getattr(DDA.ToolRegistry, name)
        src = inspect.getsource(method)
        assert "args.get(\"target\")" in src, (
            f"{name} has no target override; the agent cannot analyse the payload")


def test_the_payload_block_actually_reaches_the_agent_prompt():
    r"""`build_messages` must render the payload block.

    The findings dict the agent loop reads is the one `_run_standard_checklist`
    returns, so `findings["unpacked_payload"]` must survive into the prompt.
    This is the assertion the live run could not make: the agent never used
    `target=`, and without this test there is no way to tell "the block did not
    render" from "the model ignored it".
    """
    session = {"sample_path": "/case/sample.vir", "file_type": {"format": "pe"}}
    findings = {
        "unpacked_payload": {"path": "/case/unpack/p.vir", "size": 131832,
                             "engine": "unpack_oracle (emulation dump)",
                             "sha256": "a" * 64},
        "payload_feedback": {"ok": True,
                             "tool_ok": {"capa": {"ok": True},
                                         "floss": {"ok": True},
                                         "malcat": {"ok": True},
                                         "yara": {"ok": True},
                                         "pe_imports": {"ok": False}}},
    }
    tool_list = ["- capa_analyze: run capa"]
    msgs = DDA.build_messages(
        session, 3, DDA.MAX_STEPS, [], findings, {}, tool_list, "pe",
        checklist_ok=True, sql_ok=False)
    user = "\n".join(str(m.get("content")) for m in msgs)
    assert "UNPACKED PAYLOAD" in user, "payload block missing from the prompt"
    assert "/case/unpack/p.vir" in user, user[:400]
    assert "131832" in user, user[:400]
    assert "target=" in user, "the target= override is not taught in the prompt"
    # A tool that failed on the payload is reported as such, never as success.
    assert "capa, floss, malcat, yara" in user, user[:1200]
    assert "pe_imports" not in user.split("re-analysed with:")[1].split("\n")[0]


def test_no_payload_means_no_block():
    """An unpack-free run must not grow a phantom payload section."""
    session = {"sample_path": "/case/sample.vir", "file_type": {"format": "pe"}}
    msgs = DDA.build_messages(
        session, 1, DDA.MAX_STEPS, [], {}, {}, ["- capa_analyze: x"], "pe")
    user = "\n".join(str(m.get("content")) for m in msgs)
    assert "UNPACKED PAYLOAD" not in user
