"""Regression tests for RC-113: entropy path, dynamic sub-containers, TI paths, and master_v3 orphan pass."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import entailment as E  # noqa: E402
import report_quality as Q  # noqa: E402
import section_publisher as S  # noqa: E402
import v2_lib as V  # noqa: E402


def test_malcat_file_summary_entropy_not_rewritten_to_views(tmp_path):
    dd = tmp_path / "deep_dive"
    dd.mkdir()
    doc = {
        "malcat": {
            "file_summary": {"entropy": 7.51, "file_size": 235520},
            "views": {
                "entropy": {"file_entropy": 195, "regions": []},
                "imports": ["kernel32.dll!LoadLibraryA"],
            },
        }
    }
    (dd / "01-tools-raw.json").write_text(json.dumps(doc), encoding="utf-8")

    hit, check = E._ground_citation(
        {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
         "row": "$.malcat.file_summary.entropy"},
        tmp_path,
    )
    assert check["status"] == "traceable-row"
    assert json.loads(hit["excerpt"]) == 7.51
    assert hit["json_path"] == "$.malcat.file_summary.entropy"

    # View keys mistakenly placed under file_summary still alias cleanly.
    imp_hit, imp_check = E._ground_citation(
        {"source": "malcat", "query": "deep_dive/01-tools-raw.json",
         "row": "$.malcat.file_summary.imports[0]"},
        tmp_path,
    )
    assert imp_check["status"] == "traceable-row"
    assert json.loads(imp_hit["excerpt"]) == "kernel32.dll!LoadLibraryA"


def test_dynamic_pack_container_query_routes_frida_and_network_intel(tmp_path):
    dd = tmp_path / "deep_dive"
    dd.mkdir()
    pack = {
        "frida_summary": {"top_apis": [{"api": "CreateFileW", "count": 5}]},
        "network_intel": {"captures": [{"dns_queries": [{"query": "a.test"}]}]},
    }
    (dd / "02-dynamic-pack.json").write_text(json.dumps(pack), encoding="utf-8")

    f_hit, f_chk = E._ground_citation(
        {"source": "frida", "query": "frida_summary.json", "row": "top_apis[0]"},
        tmp_path,
    )
    assert f_chk["status"] == "traceable-row"
    assert json.loads(f_hit["excerpt"]) == {"api": "CreateFileW", "count": 5}

    n_hit, n_chk = E._ground_citation(
        {"source": "winre", "query": "network_intel.json",
         "row": "$.captures[0].dns_queries[0]"},
        tmp_path,
    )
    assert n_chk["status"] == "traceable-row"
    assert json.loads(n_hit["excerpt"]) == {"query": "a.test"}


def test_ti_evidence_cites_enabled_and_attribution_cites_verdict():
    rendered = V.format_ti_hash_enrichment_evidence({"enabled": True, "sha256": "a" * 64})
    assert "row_or_rule: $.enabled]" in rendered
    assert "hash_lookup_enabled" not in rendered

    attr = V._sec_attribution_evidence({
        "verdict": {"family_guess": "upx_packed"},
        "ti_enrich": {"enabled": False, "sha256": "a" * 64},
    })
    assert "row_or_rule: $.family_guess)" in attr


def test_master_v3_fix_orphan_tables_separates_adjacent_tables():
    md = (
        "# 5. Behavioral Analysis\n\n"
        "| API | Count |\n| --- | --- |\n| CreateFileW | 5 |\n\n"
        "| Time | Op |\n| --- | --- |\n| 12:00 | RegSetValue |\n"
    )
    assert Q.count_table_orphans(md) >= 1
    fixed = S._fix_orphan_tables(md)
    assert Q.count_table_orphans(fixed) == 0
