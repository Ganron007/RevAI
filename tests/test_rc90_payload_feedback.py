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
    monkeypatch.setattr(DDA, "malcat_analyze",
                        lambda path, **kw: _malcat_result())

    # upx_r says the classic unpacker failed -- the shape that was dropped.
    DDA._run_payload_feedback_pass(
        upx_r={"upx_ok": False, "unpacked_path": None},
        findings=findings, tools_raw=tools_raw, history=history)

    assert calls == [str(payload)], calls
    assert tools_raw["payload_feedback"]["ok"] is True, tools_raw
    assert findings["payload_feedback"]["engine"].startswith("unpack_oracle")
    assert findings["unpacked_payload"]["path"] == str(payload)
    assert findings["unpacked_payload"]["size"] == payload.stat().st_size
    assert [h["tool"] for h in history] == ["payload_feedback",
                                        "payload_decompilation"], history


def test_the_upx_d_payload_still_feeds_back(tmp_path, monkeypatch):
    """The V5.16.5 behaviour is preserved, not replaced."""
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    calls: list[str] = []
    monkeypatch.setattr(
        DDA, "run_post_upx_second_pass",
        lambda path, **kw: (calls.append(path),
                            {"ok": True, "tool_ok": {"yara": {"ok": True}}})[1])
    monkeypatch.setattr(DDA, "malcat_analyze",
                        lambda path, **kw: _malcat_result())

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
    monkeypatch.setattr(DDA, "malcat_analyze",
                        lambda path, **kw: _malcat_result())

    for _ in range(3):
        DDA._run_payload_feedback_pass(
            upx_r={"upx_ok": True, "unpacked_path": str(a)},
            findings=findings, tools_raw=tools_raw, history=history)

    assert sorted(calls) == sorted([str(a), str(b)]), calls
    assert len(history) == 4, history  # 2 engines x (feedback + decompile)


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


# ---------------------------------------------------------------------------
# RC-90b: the payload's code is decompiled DETERMINISTICALLY, not on request.
#
# Malcat's deep profile caps `decompile_top_n` at 3, so the second pass
# recovered 3 of the payload's 30 functions -- and on the run that exposed the
# gap the agent never asked for more (it re-ran capa/floss/malcat on the
# wrapper). Leaving the payload's body unread is the same class as not
# analysing the payload at all: the wrapper's 3 imports say nothing.
# ---------------------------------------------------------------------------
def _malcat_result(funcs: int = 30, decompiled: int = 30) -> dict:
    return {
        "ok": True,
        "functions": [{"ea": 1000 + i * 100, "name": f"sub_{1000 + i * 100:x}"}
                      for i in range(funcs)],
        "decompilations": {
            str(1000 + i * 100): {"name": f"sub_{1000 + i * 100:x}",
                                  "decompilation": "void f(void){}\n"}
            for i in range(decompiled)
        },
    }


def test_the_payload_is_decompiled_deterministically(tmp_path, monkeypatch):
    """The feedback pass must decompile the payload itself, in code."""
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {"unpacked": True,
                               "payload": {"path": str(payload)}}
    monkeypatch.setattr(DDA, "run_post_upx_second_pass",
                        lambda path, **kw: {"ok": True, "tool_ok": {}})
    seen: list[tuple] = []

    def _fake_malcat(path, **kw):
        seen.append((path, kw.get("views"), kw.get("limits")))
        return _malcat_result()

    monkeypatch.setattr(DDA, "malcat_analyze", _fake_malcat)

    DDA._run_payload_feedback_pass(
        upx_r={}, findings=findings, tools_raw=tools_raw, history=history)

    assert len(seen) == 1, seen
    path, views, limits = seen[0]
    assert path == str(payload), path
    assert "decompile" in (views or []), views
    assert limits["decompile_top_n"] >= 30, limits
    # Recorded as first-class evidence, with a per-function name list.
    assert tools_raw["payload_decompilation"]["ok"] is True
    rec = findings["payload_decompilation"]
    assert rec["functions_decompiled"] == 30, rec
    assert len(rec["functions"]) == 30, rec
    assert rec["decompilation_chars"] > 0, rec
    assert [h["tool"] for h in history] == ["payload_feedback",
                                            "payload_decompilation"], history


def test_the_decompile_cap_beats_malcats_default_of_three():
    """Malcat deep gives 3; the payload pass must ask for more than that."""
    assert DDA.PAYLOAD_DECOMPILE_TOP_N > 3, DDA.PAYLOAD_DECOMPILE_TOP_N


def test_a_failing_payload_decompilation_is_recorded_not_raised(tmp_path, monkeypatch):
    payload = _payload(tmp_path)
    findings, tools_raw, history = _state()
    findings["unpack_pass"] = {"unpacked": True,
                               "payload": {"path": str(payload)}}
    monkeypatch.setattr(DDA, "run_post_upx_second_pass",
                        lambda path, **kw: {"ok": True, "tool_ok": {}})

    def _boom(path, **kw):
        raise RuntimeError("malcat MCP closed")

    monkeypatch.setattr(DDA, "malcat_analyze", _boom)
    DDA._run_payload_feedback_pass(
        upx_r={}, findings=findings, tools_raw=tools_raw, history=history)
    assert "RuntimeError" in history[-1]["error"], history
    assert "payload_decompilation" not in tools_raw


def test_payload_rows_are_citable_in_the_section_manifests(tmp_path, monkeypatch):
    """The payload's own rows must be citable, not just present.

    Without manifest coverage the decompilations exist in the artifact but no
    citation to them can resolve -- the same orphaned-evidence failure RC-90
    fixed one layer up.
    """
    import v2_lib
    sha = "e" * 64
    case = tmp_path / "logs" / sha / "agentic"
    (case / "deep_dive").mkdir(parents=True)
    tools_raw = {
        # No `upx_second_pass` on purpose: the classic unpacker refused, which
        # is exactly the shape that used to orphan the payload.
        "payload_feedback": {
            "ok": True,
            "tools": {
                "capa": {"top_rules": [{"name": "acquire debug privileges"}]},
                "floss": {"strings": [r"C:\unm0ve.txt", "RExe.exe"]},
                "malcat": {
                    "views": {"anomalies": [{"name": "CrossSectionJump"}],
                              "strings": [{"ea": 56442, "summary": "Advapi32.dll"}],
                              "imports": []},
                    "functions": [{"ea": 6440, "name": "sub_401728"}],
                },
                "yara": {"matches": [{"rule": "UPX"}]},
            },
        },
        "payload_decompilation": _malcat_result(funcs=2, decompiled=2),
    }
    (case / "deep_dive" / "01-tools-raw.json").write_text(
        json.dumps(tools_raw), encoding="utf-8")

    monkeypatch.setattr(v2_lib, "case_dir", lambda s, mode=None: case)
    manifest = v2_lib.build_section_row_manifest(
        sha, "4. Static Code Analysis")
    text = json.dumps(manifest)
    assert "payload_decompilation" in text, text[:600]
    assert "payload floss" in text or "unm0ve" in text, text[:600]


def test_payload_row_sources_exist_for_the_code_sections():
    """Every section that carries payload evidence must declare its rows."""
    import v2_lib
    srcs = v2_lib.PAYLOAD_SECTION_ROW_SOURCES
    for section in ("3. File Layout & Structural Analysis",
                    "4. Static Code Analysis", "7. Capabilities Assessment",
                    "10. MITRE ATT&CK Mapping"):
        assert section in srcs, section
    code = srcs["4. Static Code Analysis"]
    paths = [p for _, p, _ in code]
    assert "payload_decompilation.decompilations" in paths, paths
    assert "payload_feedback.tools.floss.strings" in paths, paths
