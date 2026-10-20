"""Claim review requires source-bound evidence and semantic support."""
import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

sys.path.insert(0, str(resolve("revai/entailment.py").parent))
import entailment as E  # noqa: E402


def _review_supported(batch, **_kwargs):
    return {"reviews": [
        {"id": item["id"], "verdict": "supported",
         "evidence_ids": [row["evidence_id"] for row in item.get("evidence", [])]}
        for item in batch
    ]}


def _case(tmp_path, reports: dict, artifacts: dict | None = None):
    sha = "a" * 64
    run_id = "1" * 32
    case = tmp_path / "logs" / sha / "scripted"
    (case / "deep_dive").mkdir(parents=True)
    for name, md in reports.items():
        (case / name).write_text(md, encoding="utf-8")
    for rel, txt in (artifacts or {}).items():
        p = case / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt, encoding="utf-8")

    # Real audit inputs are bound to one execution. Build the same contract in
    # fixtures so tests exercise report/evidence integrity, not legacy fallback.
    for rel, fallback in (
        ("verdict.json", {"verdict": "unknown"}),
        ("quick_scan/00-tools-raw.json", {"fixture": True}),
    ):
        p = case / rel
        if not p.is_file():
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(fallback), encoding="utf-8")

    for p in case.rglob("*.json"):
        if p.name in {"execution-context.json", "report-input-manifest.json",
                      "report-output-manifest.json"}:
            continue
        try:
            payload = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            rel = p.relative_to(case).as_posix()
            payload["_cadre_provenance"] = {
                "schema": "revai-artifact-provenance/v1",
                "sha256": sha, "run_id": run_id, "mode": "scripted",
                "artifact": rel,
            }
            p.write_text(json.dumps(payload), encoding="utf-8")

    context = {
        "schema": "revai-execution-context/v1", "sha256": sha,
        "run_id": run_id, "mode": "scripted", "engine": "test",
        "started_at": "2026-10-18T00:00:00+00:00",
    }
    (case / "execution-context.json").write_text(
        json.dumps(context), encoding="utf-8")
    import v2_lib
    manifest = v2_lib.report_input_manifest(
        sha, context, case, list(v2_lib.REPORT_INPUT_ARTIFACTS))
    publish = case / "publish"
    publish.mkdir(exist_ok=True)
    (publish / "report-input-manifest.json").write_text(
        json.dumps(manifest), encoding="utf-8")
    manifest_digest = v2_lib.report_input_manifest_digest(manifest)
    execution_comment = v2_lib.report_execution_comment(
        sha, context, manifest_digest) + "\n\n"
    for report in case.glob("REPORT-*.md"):
        report.write_text(execution_comment + report.read_text(encoding="utf-8"),
                          encoding="utf-8")
    v2_lib.record_report_outputs(case, sha, context, manifest_digest)
    return case

# ------------------------------------------------------------- literal vs summary
@pytest.mark.parametrize("row,expect", [
    ("KERNEL32 (21", False),
    ('"KERNEL32 (21', False),
    ("MFC42 (131), MSVCRT (25)", False),
    ("Ghidra=104 vs IDA=218 (2.1x", False),
    ("load_library (T1129", True),
    ("CreateRemoteThread", True),
    ("offset 0x401000", True),
    ("contains_base64@51729", True),
    ("UPX", False),
    ('says "cmd.exe /c" inside', True),
])
def test_a_literal_row_is_distinguished_from_a_summary(row, expect):
    assert E._row_is_literal(row) is expect, row


# ------------------------------------------------------------------- circular
def test_a_claim_citing_the_summary_as_its_evidence_is_circular():
    c = {"source": "llm_judge", "query": "summary",
         "row": "GUI subsystem with zero window APIs", "text": "the sample"}
    assert E.verify_claim(c, "llm_judge was called", None)["status"] == "circular"


def test_verdict_summary_is_also_circular():
    """feodo cited `query_or_table: verdict summary` 20 times."""
    c = {"source": "llm_judge", "query": "verdict summary",
         "row": "C2 URLs hardcoded", "text": "the sample"}
    assert E.verify_claim(c, "llm_judge", None)["status"] == "circular"


def test_a_real_citation_is_not_circular():
    c = {"source": "ghidra_query", "query": "imports",
         "row": "CreateRemoteThread", "text": "the sample injects"}
    r = E.verify_claim(c, "ghidra_query import table", Path("."))
    assert r["status"] != "circular", r


# ----------------------------------------------------------------- extraction
def test_claims_are_extracted_with_their_citation():
    md = ("The sample writes an HKCU Run key for persistence "
          "(source: ghidra_query, query_or_table: imports, "
          "row_or_rule: RegSetValueExA).")
    claims = E.extract_claims(md)
    assert len(claims) == 1
    assert claims[0]["source"] == "ghidra_query"
    assert claims[0]["row"] == "RegSetValueExA"


def test_claim_extraction_keeps_every_citation_on_a_sentence():
    md = ("The sample imports CreateRemoteThread and WinHttpOpen "
          "(source: ghidra_query, query_or_table: imports, "
          "row_or_rule: CreateRemoteThread) "
          "(source: ghidra_query, query_or_table: imports, "
          "row_or_rule: WinHttpOpen).")
    claims = E.extract_claims(md)
    assert len(claims) == 1
    assert [c["row"] for c in claims[0]["citations"]] == [
        "CreateRemoteThread", "WinHttpOpen"]


def test_grouped_jsonpaths_are_reviewed_as_separate_exact_fields(tmp_path):
    report = (
        "The file is a 64-bit PE image "
        "(source: malcat, query_or_table: deep_dive/01-tools-raw.json, "
        "row_or_rule: $.malcat.file_summary.type, "
        "$.malcat.file_summary.architecture)."
    )
    artifact = tmp_path / "deep_dive" / "01-tools-raw.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(json.dumps({"malcat": {"file_summary": {
        "type": "PE32+", "architecture": "x86-64",
    }}}), encoding="utf-8")

    claims = E.extract_claims(report)

    assert len(claims) == 1
    citations = claims[0]["citations"]
    assert [item["row"] for item in citations] == [
        "$.malcat.file_summary.type",
        "$.malcat.file_summary.architecture",
    ]
    grounded = [E._ground_citation(item, tmp_path) for item in citations]
    assert [check["status"] for _, check in grounded] == [
        "traceable-row", "traceable-row",
    ]
    assert [item["json_path"] for item, _ in grounded if item] == [
        "$.malcat.file_summary.type",
        "$.malcat.file_summary.architecture",
    ]


def test_grouped_jsonpath_claim_review_receives_both_source_fields(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md": (
            "The sample is a 64-bit PE image "
            "(source: malcat, query_or_table: deep_dive/01-tools-raw.json, "
            "row_or_rule: $.malcat.file_summary.type, "
            "$.malcat.file_summary.architecture)."
        ),
    }, {
        "deep_dive/01-tools-raw.json": json.dumps({"malcat": {
            "file_summary": {"type": "PE32+", "architecture": "x86-64"},
        }}),
    })
    reviewed = []

    def reviewer(batch):
        reviewed.extend(batch)
        return {"reviews": [{
            "id": item["id"], "verdict": "supported",
            "evidence_ids": [row["evidence_id"] for row in item["evidence"]],
            "reason": "both cited fields establish the format and architecture",
        } for item in batch]}

    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=reviewer, use_cache=False)

    assert result["ok"] is True, result
    assert len(reviewed) == 1
    assert [row["json_path"] for row in reviewed[0]["evidence"]] == [
        "$.malcat.file_summary.type",
        "$.malcat.file_summary.architecture",
    ]


def test_claim_extraction_does_not_truncate_a_report_by_default():
    md = "\n".join(
        f"The sample has observed marker_{i:03d} "
        f"(source: yara, query_or_table: strings, row_or_rule: marker_{i:03d})."
        for i in range(250)
    )

    assert len(E.extract_claims(md)) == 250
    assert len(E.extract_claims(md, limit=40)) == 40


# The house citation format ends with `, why: ...`. Until 2026-10-11 the closer
# was demanded right after row_or_rule, so these three shapes -- all copied
# verbatim from wiper_wipe32p's technical report -- did not parse at all and
# the claims never reached the gate: 244 raw citations, 32 extracted, 18 of 21
# prose-citing rows invisible.
def test_a_quoted_row_whose_parens_contain_a_comma_still_parses():
    md = ("The wipe engine fills buffers pseudo-randomly "
          "(source: llm_judge, query_or_table: summary, row_or_rule: "
          "'writes pseudo-random wipe patterns generated by a dedicated "
          "srand/rand function (fcn.00401170, 789 B)', why: the 789-byte "
          "function size indicates a simple non-cryptographic RNG).")
    claims = E.extract_claims(md)
    assert len(claims) == 1, claims
    assert claims[0]["query"] == "summary"
    assert "pseudo-random wipe patterns" in claims[0]["row"]
    # the why-text is context, not the row
    assert "789-byte function size indicates" not in claims[0]["row"]


def test_an_unquoted_row_with_a_why_tail_still_parses():
    md = ("File size is confirmed by both engines "
          "(source: llm_judge, query_or_table: verdict.metadata, "
          "row_or_rule: size=20480, why: both engines report the same "
          "on-disk size, confirming a single unpacked PE32 image).")
    claims = E.extract_claims(md)
    assert len(claims) == 1, claims
    assert claims[0]["query"] == "verdict.metadata"
    assert claims[0]["row"] == "size=20480"


def test_a_citation_row_with_an_in_row_paren_and_a_why_tail_parses():
    """927/929's shape: `row_or_rule: "text (parens)", why: ...` parsed before
    only by accident (the in-row `)` doubling as the closer)."""
    md = ("The verdict names the toolchain "
          "(source: llm_judge, query_or_table: verdict.summary, row_or_rule: "
          "\"built with MSVC 2022 (v17.14.2)\", why: the Rich header / MSVC "
          "version stamp in the PE was read by the verdict engine).")
    claims = E.extract_claims(md)
    assert len(claims) == 1, claims
    assert claims[0]["query"] == "verdict.summary"
    assert "MSVC 2022" in claims[0]["row"]


def test_query_locator_with_parentheses_and_commas_is_preserved():
    md = (
        "The imports are LoadLibraryA "
        "(source: malcat, query_or_table: Imports (5), "
        "row_or_rule: kernel32.LoadLibraryA).\n"
        "Six packer rules matched "
        "(source: malcat, query_or_table: YARA (info, 10 total), "
        "row_or_rule: UPX, upx_290_lzma_02)."
    )

    claims = E.extract_claims(md)

    assert len(claims) == 2
    assert claims[0]["query"] == "Imports (5)"
    assert claims[0]["row"] == "kernel32.LoadLibraryA"
    assert claims[1]["query"] == "YARA (info, 10 total)"
    assert claims[1]["row"] == "UPX, upx_290_lzma_02"


def test_a_prose_citation_hidden_behind_a_why_tail_reaches_the_gate(tmp_path):
    """Extraction fixed means the gate now SEES the class: the same row,
    offered the analysis's own summary as evidence, must fire circular."""
    case = _case(tmp_path, {
        "REPORT-TECHNICAL-v3.md":
            "The wipe engine fills buffers pseudo-randomly "
            "(source: llm_judge, query_or_table: summary, row_or_rule: "
            "'writes pseudo-random wipe patterns (fcn.00401170, 789 B)', "
            "why: the function size indicates a simple RNG)."},
        {"deep_dive/01-tools-raw.json": '{"yara": []}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["by_status"].get("circular", 0) == 1, res


def test_a_sentence_about_the_analysis_is_not_a_claim():
    """`(source: <engine>)` is the report explaining its own format."""
    md = ("All citations use the format `(source: <engine>)` and reference the "
          "exact table, rule name, or SQL query that produced the evidence.")
    assert E.extract_claims(md) == []


def test_uncited_sentences_are_not_claims():
    assert E.extract_claims("The sample is malicious and does bad things.") == []


def test_fenced_blocks_are_not_claims():
    md = "```\nsome evidence dump (source: yara)\n```"
    assert E.extract_claims(md) == []


# ------------------------------------------------- source-side prevention
def test_the_pack_never_renders_the_verdict_source_as_a_citable_pair():
    """Where the wiper's circular citations were MANUFACTURED: the pack
    rendered `- **summary**: <prose>` directly above `- **source**: llm_judge`,
    and the report writer joined the two bullets into
    `(source: llm_judge, query_or_table: summary, ...)`. The pack must label
    both prose blocks as narrative context and must not present the pairing."""
    import v2_lib
    pack = v2_lib.build_technical_evidence_block(
        {"sha256": "a" * 64},
        {"verdict": "suspicious", "confidence": "0.8",
         "summary": "the verdict prose", "source": "llm_judge"},
        {"summary": "deep prose", "source": "llm_judge",
         "confidence": "0.9"},
        None, {}, [])
    assert "## Verdict" in pack
    assert "## Deep-Dive Summary Evidence" in pack
    assert pack.count("NARRATIVE CONTEXT") >= 2, (
        "both prose blocks must carry the non-citable label")
    assert "- **source**: llm_judge" not in pack, (
        "a plain source bullet next to summary is the pairing a writer copies")


def test_the_pack_excludes_verdict_cross_engine_guidance_from_evidence():
    """Cross-engine notes are LLM-authored guidance, not observed evidence.

    Including them in the evidence pack led the report writer to publish the
    instruction as a fact, which then tripped the dynamic consistency gate.
    Keep the source JSON intact, but do not expose this field as evidence.
    """
    import v2_lib
    guidance = (
        "If Speakeasy/Frida show zero events, write 'not observed' — "
        "never invent runtime behavior."
    )
    pack = v2_lib.build_technical_evidence_block(
        {"sha256": "a" * 64},
        {"verdict": "suspicious", "cross_engine_notes": guidance},
        None, None, {}, [])
    assert "cross_engine_notes" not in pack
    assert guidance not in pack


# ------------------------------------------------------------------- the gate
def test_the_gate_fires_on_a_circular_citation(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample uses WinINet for C2 "
            "{source: llm_judge, query_or_table: summary, "
            "row_or_rule: \"WinINet observed\"}."},
        {"deep_dive/01-tools-raw.json": '{"yara": []}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["ok"] is False
    assert res["by_status"]["circular"] == 1
    assert res["violations"][0]["status"] == "circular"


def test_the_gate_passes_a_report_with_real_citations(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    res = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=_review_supported)
    assert res["ok"] is True, res["violations"]
    assert res["by_status"]["semantically-supported"] == 1
    assert res["by_status"].get("circular", 0) == 0


def test_existing_reports_are_reviewed_when_an_expected_output_is_missing(
        tmp_path):
    import v2_lib

    case = _case(tmp_path, {
        "REPORT-MASTER-v3.md": (
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."),
    }, {"deep_dive/00-sql-evidence.json":
        '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    sha = "a" * 64
    context = v2_lib.read_execution_context(
        sha, mode="scripted", case_root=case)
    input_manifest = json.loads((case / "publish" /
                                 "report-input-manifest.json").read_text())
    digest = v2_lib.report_input_manifest_digest(input_manifest)
    output = v2_lib.record_report_outputs(
        case, sha, context, digest,
        report_names=["REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md",
                      "REPORT-MASTER-v3.md", "REPORT-TECHNICAL-v3.md"],
        allow_missing=True)
    assert output["missing_reports"] == [
        "REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md",
        "REPORT-TECHNICAL-v3.md"]

    result = E.check_report_entailment(
        sha, case_root=case, semantic_reviewer=_review_supported,
        use_cache=False)
    assert result["status"] == "failed"
    assert result["ok"] is False
    assert result["by_status"]["semantically-supported"] == 1
    assert result["by_status"]["missing-report"] == 3
    assert "provenance-invalid" not in result["by_status"]


def test_uncited_factual_claims_and_table_rows_block_green(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md": (
            "The sample creates a scheduled task for persistence.\n\n"
            "| Behavior | Evidence |\n|---|---|\n"
            "| Contacts c2.example.test | network observation |"
        ),
    })
    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=_review_supported)
    assert result["ok"] is False
    assert result["by_status"].get("missing-citation") == 2, result


def test_report_output_hash_mismatch_blocks_review(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    report = case / "REPORT-MASTER-v2.md"
    report.write_text(report.read_text(encoding="utf-8") + "\nEdited after manifest.\n",
                      encoding="utf-8")
    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=_review_supported)
    assert result["ok"] is False
    assert result["status"] == "provenance-invalid"
    assert "report output changed" in result["reason"]


def test_evidence_hash_mismatch_blocks_review(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    evidence = case / "deep_dive" / "00-sql-evidence.json"
    evidence.write_text(evidence.read_text(encoding="utf-8") + " ", encoding="utf-8")
    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=_review_supported)
    assert result["ok"] is False
    assert result["status"] == "provenance-invalid"
    assert "changed after manifest" in result["reason"]


def test_a_summary_citation_is_not_treated_as_supported(tmp_path):
    """A summary label without a resolving observation cannot pass the gate."""
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "Imports are KERNEL32 (21), USER32 (10) "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: KERNEL32 (21), USER32 (10))."},
        {"deep_dive/00-sql-evidence.json":
             '{"ghidra": {"imports": ["KERNEL32"]}}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["by_status"].get("unresolved-row", 0) == 1
    assert res["ok"] is False


def test_an_unresolved_literal_row_blocks_green(tmp_path):
    """A literal absent from its cited source artifact cannot pass."""
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample calls CreateRemoteThread (source: ghidra_query, "
            "query_or_table: imports, row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": ["ExitProcess"]}}'})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["by_status"].get("unresolved-row", 0) == 1
    assert res["ok"] is False


def test_a_row_from_another_engine_cannot_resolve_the_citation(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample includes an observed capability marker "
            "(source: capa, query_or_table: rules, row_or_rule: SharedMarker)."},
        {"deep_dive/01-tools-raw.json": json.dumps({
            "capa": {"rules": ["DifferentRule"]},
            "malcat": {"strings": ["SharedMarker"]},
        })})
    result = E.check_report_entailment("a" * 64, case_root=case)
    assert result["ok"] is False
    assert result["by_status"].get("unresolved-row") == 1, result


def test_no_reports_is_not_applicable(tmp_path):
    case = _case(tmp_path, {}, {})
    res = E.check_report_entailment("a" * 64, case_root=case)
    assert res["applicable"] is False
    assert res["ok"] is False


def test_the_cli_emits_parseable_json(tmp_path, capsys):
    case = _case(tmp_path, {"REPORT-MASTER-v2.md":
                            "The sample persists "
                            "(source: ghidra_query, query_or_table: imports, "
                            "row_or_rule: RegSetValueExA)."},
                 {"deep_dive/00-sql-evidence.json":
                  '{"ghidra": {"imports": "RegSetValueExA"}}'})
    original_reviewer = E._semantic_review_batch
    E._semantic_review_batch = _review_supported
    argv = sys.argv
    sys.argv = ["entailment.py", "a" * 64, "--case", str(case)]
    try:
        rc = E._cli()
        out = capsys.readouterr().out
    finally:
        sys.argv = argv
        E._semantic_review_batch = original_reviewer
    assert rc == 0
    json.loads(out), "the CLI must emit parseable JSON, not a truncated document"


def test_the_cli_fails_on_a_circular_citation(tmp_path, capsys):
    case = _case(tmp_path, {"REPORT-MASTER-v2.md":
                            "The sample persists "
                            "{source: llm_judge, query_or_table: summary, "
                            "row_or_rule: \"persistence\"}."})
    argv = sys.argv
    sys.argv = ["entailment.py", "a" * 64, "--case", str(case)]
    try:
        rc = E._cli()
        out = capsys.readouterr().out
    finally:
        sys.argv = argv
    assert rc == 1
    assert json.loads(out)["by_status"]["circular"] == 1


def test_semantic_review_must_quote_the_exact_primary_evidence(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    def wrong_quote(batch):
        return {"reviews": [{"id": item["id"], "verdict": "supported",
                             "evidence_quote": "not present"} for item in batch]}
    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=wrong_quote)
    assert result["ok"] is False
    assert result["by_status"]["invalid-review"] == 1


def test_semantic_review_api_failure_is_not_a_pass(tmp_path):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    def unavailable(_batch):
        raise TimeoutError("review endpoint unavailable")
    result = E.check_report_entailment(
        "a" * 64, case_root=case, semantic_reviewer=unavailable)
    assert result["ok"] is False
    assert result["status"] == "verification-error"
    assert result["by_status"]["verification-error"] == 1


def test_completed_semantic_review_is_cached_by_report_and_evidence_hash(tmp_path, monkeypatch):
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    calls = []
    def reviewer(batch, **_kwargs):
        calls.append(len(batch))
        return _review_supported(batch)
    monkeypatch.setattr(E, "_semantic_review_batch", reviewer)
    first = E.check_report_entailment("a" * 64, case_root=case)
    second = E.check_report_entailment("a" * 64, case_root=case)
    assert first["ok"] is True and second["ok"] is True
    assert calls == [1]


def test_claim_review_cache_invalidates_when_methodology_changes(tmp_path, monkeypatch):
    import skills
    case = _case(tmp_path, {
        "REPORT-MASTER-v2.md":
            "The sample imports CreateRemoteThread "
            "(source: ghidra_query, query_or_table: imports, "
            "row_or_rule: CreateRemoteThread)."},
        {"deep_dive/00-sql-evidence.json":
         '{"ghidra": {"imports": "CreateRemoteThread"}}'})
    calls = []
    method = {"text": "review method v1"}

    def reviewer(batch, **kwargs):
        calls.append(kwargs.get("methodology_block"))
        return _review_supported(batch)

    monkeypatch.setattr(skills, "report_methodology_block", lambda _scope: method["text"])
    monkeypatch.setattr(E, "_semantic_review_batch", reviewer)
    first = E.check_report_entailment("a" * 64, case_root=case)
    method["text"] = "review method v2"
    second = E.check_report_entailment("a" * 64, case_root=case)
    third = E.check_report_entailment("a" * 64, case_root=case)

    assert first["ok"] and second["ok"] and third["ok"]
    assert calls == ["review method v1", "review method v2"]
    assert first["analysis_identity"]["review_methodology_sha256"] != \
        second["analysis_identity"]["review_methodology_sha256"]


def test_dynamic_citations_resolve_to_saved_winre_source_rows(tmp_path):
    case = _case(tmp_path, {"REPORT-MASTER-v2.md": ""}, {
        "deep_dive/02-dynamic-pack.json": json.dumps({
            "meta": {"ok": True, "error": None, "producer": "winre"},
            "job_meta": {"detonation_ran": True, "sample_pid": 123,
                         "window": {"effective_s": 13.9}},
            "network_intel": {"captures": [{"dns_queries": ["c2.example.test"]}]},
            "procmon_sample_events": [{
                "row": 3, "pid": 456, "operation": "CreateFile",
                "path": r"C:\\ProgramData\\Upkeep\\payload.bin",
            }],
        }),
    })
    path = case / "deep_dive" / "02-dynamic-pack.json"
    meta = E._locate_cited_row(path, "ok, error", "META.json")
    assert meta and "true" in meta["excerpt"] and "null" in meta["excerpt"]
    window = E._locate_cited_row(
        path, "window.effective_s", "META.job.json")
    assert window and "13.9" in window["excerpt"]
    dns = E._locate_cited_row(
        path, "captures[0].dns_queries", "network_intel.json")
    assert dns and "c2.example.test" in dns["excerpt"]
    procmon = E._locate_cited_row(
        path, "data row 3; PID 456; operation CreateFile", "procmon.csv")
    assert procmon and "payload.bin" in procmon["excerpt"]


def test_report_input_manifest_rejects_windows_and_posix_traversal(tmp_path):
    import v2_lib
    sha = "a" * 64
    case = _case(tmp_path, {"REPORT-MASTER-v2.md": ""}, {})
    context = v2_lib.read_execution_context(sha, mode="scripted", case_root=case)
    manifest_path = case / "publish" / "report-input-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"][0]["path"] = "../outside.json"
    with pytest.raises(RuntimeError, match="invalid or unapproved"):
        v2_lib.validate_report_input_manifest(manifest, sha, context, case)
    manifest["artifacts"][0]["path"] = r"C:\outside.json"
    with pytest.raises(RuntimeError, match="invalid or unapproved"):
        v2_lib.validate_report_input_manifest(manifest, sha, context, case)


def test_artifact_provenance_must_bind_exact_artifact_path():
    import v2_lib
    payload = {"_cadre_provenance": {
        "schema": "revai-artifact-provenance/v1", "sha256": "a" * 64,
        "run_id": "1" * 32, "mode": "scripted", "artifact": "other.json",
    }}
    with pytest.raises(RuntimeError, match="artifact"):
        v2_lib.validate_case_artifact_identity(
            payload, "a" * 64, {"run_id": "1" * 32, "mode": "scripted"},
            "verdict.json")
