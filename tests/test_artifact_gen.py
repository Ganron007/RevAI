#!/usr/bin/env python3
"""Plan #11 - verifiable artifact generation: the verification contract.

The stage's value is not that an LLM writes a script; it is that *code* re-derives
what the script claims. These tests pin that contract, including the failure modes:

- a correct extraction is verified and can be re-derived independently
- a lying script (wrong offset / wrong method) is caught, not trusted
- G DATA's anti-cheat rule is measured: values already visible in the generation
  prompt, or hardcoded in the script, are flagged as not independent
- unsupported methods are kept but never counted as verified
- the stage is opt-in, presence-gated, and never gates the verdict
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

from artifact_gen import (  # noqa: E402
    _result_artifacts,
    build_prompt,
    extract_script,
    high_entropy_regions,
    rederive,
    run_generated_script,
    verify_claims,
)
from v2_lib import attach_analysis_scripts, load_artifact_gen_summary  # noqa: E402

SHA = "b" * 64


# --- a sample with one XOR-obfuscated blob and one plain string -------------


def _sample() -> tuple[Path, bytes, int, str, int]:
    import tempfile

    tmp = Path(tempfile.mkdtemp())
    plain = b"http://c2.example/gate.php"
    xored = bytes(b ^ 0x41 for b in b"kernel32!secret_marker")
    data = bytearray(b"\x00" * 64)
    off_plain = len(data)
    data += plain
    off_xor = len(data)
    data += xored
    path = tmp / "sample.bin"
    path.write_bytes(bytes(data))
    return path, bytes(data), off_plain, plain.decode(), off_xor


# --- re-derivation ---------------------------------------------------------


def test_rederive_raw_at_offset():
    _, data, off, plain, _ = _sample()
    ok, basis = rederive(data, {"value": plain, "offset": off, "method": "raw"})
    assert ok is True
    assert "raw_at_offset" in basis


def test_rederive_utf16le_at_offset():
    import tempfile

    text = "SOFTWARE\\Malware\\Run"
    data = text.encode("utf-16le")
    ok, basis = rederive(data, {"value": text, "offset": 0, "method": "utf16le"})
    assert ok is True
    assert "utf16le_at_offset" in basis


def test_rederive_xor_with_key():
    _, data, _, _, off_xor = _sample()
    ok, basis = rederive(data, {
        "value": "kernel32!secret_marker", "offset": off_xor, "method": "xor", "key": 0x41,
    })
    assert ok is True
    assert "xor_0x41" in basis


def test_rederive_base64():
    import base64

    encoded = base64.b64encode(b"payload-bytes-here")
    ok, basis = rederive(encoded, {
        "value": "payload-bytes-here", "offset": 0, "method": "base64",
    })
    assert ok is True
    assert "base64_decoded" in basis


def test_wrong_offset_is_caught():
    _, data, _, plain, _ = _sample()
    ok, basis = rederive(data, {"value": plain, "offset": 9999, "method": "raw"})
    assert ok is False
    assert "mismatch" in basis


def test_wrong_method_is_caught():
    _, data, _, plain, _ = _sample()
    ok, _ = rederive(data, {"value": plain, "offset": 64, "method": "hex"})
    assert ok is False


def test_unsupported_method_is_none_not_true():
    _, data, _, _, off_xor = _sample()
    ok, basis = rederive(data, {
        "value": "whatever", "offset": off_xor, "method": "aes-gcm", "key": "deadbeef",
    })
    assert ok is None
    assert "method_unsupported" in basis


def test_claim_without_offset_must_exist_in_the_file():
    _, data, _, plain, _ = _sample()
    ok, basis = rederive(data, {"value": plain, "offset": None, "method": "raw"})
    assert ok is True
    assert "present_in_sample" in basis
    ok2, _ = rederive(data, {"value": "not-in-file-at-all", "offset": None, "method": "raw"})
    assert ok2 is False


# --- the anti-cheat measurements -------------------------------------------


def test_pre_seeded_value_is_flagged_not_independent():
    _, data, off, plain, _ = _sample()
    prompt = f"...the sample contains the string {plain} at offset {off}..."
    src = "import sys\ndata = open(sys.argv[1],'rb').read()\nprint('ok')\n"
    out = verify_claims(_sample()[0], [{"value": plain, "offset": off, "method": "raw"}],
                        prompt, src)
    assert out["claims_verified"] == 1          # the derivation is still true ...
    assert out["values_pre_seeded_in_prompt"] == 1
    assert out["independence"] == "not_independent"   # ... but not independent
    assert out["input_read"] is True


def test_hardcoded_literal_in_the_script_is_flagged():
    sample, _, off, plain, _ = _sample()
    src = f'import sys\nprint("{plain}")\n'
    out = verify_claims(sample, [{"value": plain, "offset": off, "method": "raw"}], "", src)
    assert out["hardcoded_output_literals"] == 1
    assert out["independence"] == "not_independent"
    assert out["input_read"] is False


def test_clean_extraction_is_independent():
    sample, _, off, plain, _ = _sample()
    src = ("import json, sys\n"
           "data = open(sys.argv[1], 'rb').read()\n"
           "off = 64\n"
           "value = data[off:off+24].decode()\n"
           "json.dump({'artifacts': [{'kind': 'url', 'value': value, 'offset': off,"
           " 'method': 'raw'}]}, open(sys.argv[2] + '/result.json', 'w'))\n")
    out = verify_claims(sample, [{"value": plain, "offset": off, "method": "raw"}], "", src)
    assert out["claims_verified"] == 1
    assert out["claims_unverified"] == 0
    assert out["independence"] == "independent"
    assert out["input_read"] is True


def test_no_claims_is_not_a_pass():
    sample, _, _, _, _ = _sample()
    out = verify_claims(sample, [], "", "x = 1")
    assert out["claims_total"] == 0
    assert out["independence"] == "no_claims"


# --- generated-script handling --------------------------------------------


def test_extract_script_handles_fenced_json():
    fenced = {
        "applicability": "applicable",
        "reason": "",
        "targets": ["c2 url"],
        "script": "```python\nimport sys\nprint('hi')\n```",
    }
    resp = {"choices": [{"message": {"content": json.dumps(fenced)}}]}
    src, meta = extract_script(resp)
    assert meta["parse_ok"] is True
    assert meta["applicability"] == "applicable"
    assert src.startswith("import sys")
    assert "```" not in src


def test_extract_script_reports_not_applicable_without_a_script():
    resp = {"choices": [{"message": {"content": json.dumps(
        {"applicability": "not_applicable", "reason": "no config blob", "script": ""})}}]}
    src, meta = extract_script(resp)
    assert src == ""
    assert meta["applicability"] == "not_applicable"
    assert meta["reason"] == "no config blob"


def test_extract_script_survives_a_non_json_response():
    resp = {"choices": [{"message": {"content": "I cannot help with that."}}]}
    src, meta = extract_script(resp)
    assert src == ""
    assert meta["parse_ok"] is False


def test_result_artifacts_prefers_result_json(tmp_path=None):
    import tempfile

    out = Path(tempfile.mkdtemp())
    (out / "result.json").write_text(json.dumps(
        {"artifacts": [{"kind": "key", "value": "abc", "offset": 1, "method": "raw"}]}))
    arts, note = _result_artifacts(out, {})
    assert len(arts) == 1
    assert note == ""


def test_run_generated_script_executes_and_is_bounded(tmp_path=None):
    """The generated code really runs, and a hanging script is cut off."""
    import tempfile

    base = Path(tempfile.mkdtemp())
    sample = base / "s.bin"
    sample.write_bytes(b"hello world payload")
    good = base / "good.py"
    good.write_text(
        "import json, sys\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "json.dump({'artifacts': [{'kind': 'other', 'value': 'hello',"
        " 'offset': 0, 'method': 'raw'}]}, open(sys.argv[2] + '/result.json', 'w'))\n"
    )
    out = base / "out1"
    out.mkdir()
    rec = run_generated_script(good, sample, out)
    assert rec["rc"] == 0, rec.get("stderr")
    arts, _ = _result_artifacts(out, rec)
    assert arts and arts[0]["value"] == "hello"

    bad = base / "hang.py"
    bad.write_text("while True:\n    pass\n")
    out2 = base / "out2"
    out2.mkdir()
    rec2 = run_generated_script(bad, sample, out2, timeout_s=3)
    assert rec2["rc"] == 124 and rec2["timed_out"] is True

    boom = base / "boom.py"
    boom.write_text("raise SystemExit(3)\n")
    out3 = base / "out3"
    out3.mkdir()
    assert run_generated_script(boom, sample, out3)["rc"] == 3


def test_generated_script_cannot_see_the_llm_key(tmp_path=None):
    """The sandbox env is scrubbed: a generated script gets no RevAI secrets."""
    import os
    import tempfile

    base = Path(tempfile.mkdtemp())
    sample = base / "s.bin"
    sample.write_bytes(b"x" * 32)
    script = base / "peek.py"
    script.write_text(
        "import json, os, sys\n"
        "leaked = [k for k in os.environ if k.startswith('REVAI_')]\n"
        "json.dump({'artifacts': [], 'leaked': leaked},"
        " open(sys.argv[2] + '/result.json', 'w'))\n"
    )
    out = base / "out"
    out.mkdir()
    os.environ["REVAI_LLM_API_KEY"] = "sentinel-not-for-generated-code"
    rec = run_generated_script(script, sample, out)
    data = json.loads((out / "result.json").read_text())
    assert "REVAI_LLM_API_KEY" not in data.get("leaked", []), rec.get("stderr")


# --- report block (presence-gated) ----------------------------------------


def test_absence_is_byte_identical(monkeypatch, tmp_path=None):
    import tempfile

    monkeypatch.delenv("REVAI_DISABLE_ANALYSIS_SCRIPTS", raising=False)
    base = Path(tempfile.mkdtemp())
    evidence = "## Evidence\n\nunchanged"
    assert attach_analysis_scripts(evidence, SHA, logs_dir=base) == evidence
    assert load_artifact_gen_summary(SHA, logs_dir=base) == {}


def test_block_lists_only_rederived_values(monkeypatch, tmp_path=None):
    import tempfile

    monkeypatch.delenv("REVAI_DISABLE_ANALYSIS_SCRIPTS", raising=False)
    base = Path(tempfile.mkdtemp())
    (base / "artifact_gen").mkdir()
    (base / "artifact_gen" / "artifact-gen.json").write_text(json.dumps({
        "status": "ran", "ok": True, "artifacts_total": 2, "artifacts_verified": 1,
        "artifacts_unverified": 1, "independence": "partially_independent",
        "input_read": True, "values_pre_seeded_in_prompt": 1,
        "hardcoded_output_literals": 0, "script_sha256": "a" * 64,
        "targets": ["c2 url", "mutex"],
        "execution": {"network_isolation": "unshare_net_applied"},
        "verified_artifacts": [
            {"kind": "url", "value_preview": "http://c2.example/gate.php",
             "offset": 64, "method": "raw", "basis": "raw_at_offset"},
        ],
    }))
    out = attach_analysis_scripts("## Evidence", SHA, logs_dir=base)
    assert "Appendix: Analysis Scripts" in out
    assert "1 of 2 claimed values" in out
    assert "partially_independent" in out
    assert "03-generated.py" in out


def test_block_states_a_non_run_honestly(monkeypatch, tmp_path=None):
    import tempfile

    monkeypatch.delenv("REVAI_DISABLE_ANALYSIS_SCRIPTS", raising=False)
    base = Path(tempfile.mkdtemp())
    (base / "artifact_gen").mkdir()
    (base / "artifact_gen" / "artifact-gen.json").write_text(json.dumps({
        "status": "not_applicable", "reason": "no config blob", "artifacts_total": 0,
    }))
    out = attach_analysis_scripts("## Evidence", SHA, logs_dir=base)
    assert "did not produce a run" in out
    assert "no config blob" in out
    assert "http" not in out


def test_opt_out_env(monkeypatch, tmp_path=None):
    import tempfile

    monkeypatch.setenv("REVAI_DISABLE_ANALYSIS_SCRIPTS", "1")
    base = Path(tempfile.mkdtemp())
    (base / "artifact_gen").mkdir()
    (base / "artifact_gen" / "artifact-gen.json").write_text(json.dumps({"status": "ran"}))
    assert attach_analysis_scripts("## Evidence", SHA, logs_dir=base) == "## Evidence"


def test_block_never_leaks_a_secret(monkeypatch, tmp_path=None):
    import tempfile

    monkeypatch.delenv("REVAI_DISABLE_ANALYSIS_SCRIPTS", raising=False)
    base = Path(tempfile.mkdtemp())
    (base / "artifact_gen").mkdir()
    (base / "artifact_gen" / "artifact-gen.json").write_text(json.dumps({
        "status": "ran", "artifacts_total": 1, "artifacts_verified": 1,
        "artifacts_unverified": 0, "independence": "independent", "input_read": True,
        "script_sha256": "b" * 64,
        "execution": {"network_isolation": "unshare_net_unavailable_rc_1"},
    }))
    out = attach_analysis_scripts("## Evidence", SHA, logs_dir=base)
    assert "network isolation" in out
    assert "sk-" not in out


# --- evidence pack ---------------------------------------------------------


def test_high_entropy_regions_finds_the_blob():
    import tempfile

    data = bytearray(b"\x00" * 4096)
    data += bytes(range(256)) * 16          # high entropy
    path = Path(tempfile.mkdtemp()) / "s.bin"
    path.write_bytes(bytes(data))
    regions = high_entropy_regions(bytes(data))
    assert regions and regions[0]["offset"] == 4096
    assert regions[0]["entropy"] >= 7.0


def test_prompt_declares_what_was_withheld():
    pack = {"sha256": SHA, "size": 10, "withheld_from_prompt": ["decoded plaintext"]}
    prompt = build_prompt(pack)
    assert "SCRIPT CONTRACT" in prompt
    assert "decoded plaintext" in prompt
