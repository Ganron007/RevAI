"""Tests for the advisory claimed-IOC fact-verification pass (plan #10)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import report_quality as rq  # noqa: E402


REPORT = """## 8. Indicators of Compromise

- C2: hxxp[:]//evil-c2[.]biz/gate.php (source: yara)
- IP: 203.0.113.10 (source: floss)
- Domain: benign-update[.]microsoft[.]com (source: strings)
- SHA256: 5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b5aa765d61d8327deb882cf99
- Key: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Contact: bad@evil-c2.biz
"""

EVIDENCE = """
urls: hxxp[:]//evil-c2[.]biz/gate.php
ips: 203.0.113.10
registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
strings: contact bad@evil-c2.biz for instructions
"""


def test_verifies_present_and_flags_absent():
    result = rq.verify_claimed_iocs(REPORT, EVIDENCE)
    assert result["advisory"] is True
    values = {i["value"] for i in result["unverified_items"]}
    # The invented hash is not in the evidence and must be flagged.
    assert "5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b5aa765d61d8327deb882cf99" in values
    assert result["verified"] >= 3
    assert result["excluded"] >= 1  # vendor/telemetry domain


def test_benign_domain_is_excluded_not_unverified():
    result = rq.verify_claimed_iocs(REPORT, EVIDENCE)
    reasons = [i["reason"] for i in result["excluded_items"]]
    assert any("vendor" in r for r in reasons)
    assert all("microsoft" not in i["value"] for i in result["unverified_items"])


def test_empty_inputs_are_safe():
    result = rq.verify_claimed_iocs("", "")
    assert result["claims"] == 0
    assert result["unverified_items"] == []


PROV = "52d7c4523f5df47cc6baf2666b407788a2b1cf9a"


def test_provenance_commit_is_excluded_not_unverified():
    """Rehearsal regression (2026-09-21): the provenance banner carries the
    pipeline commit (64-hex) — build metadata, not a sample indicator."""
    banner = REPORT + (
        f"\n> **RevAI provenance** — commit `{PROV}` · engine langgraph\n"
    )
    result = rq.verify_claimed_iocs(banner, EVIDENCE, provenance_commit=PROV)
    assert all(i["value"] != PROV for i in result["unverified_items"])
    reasons = [i["reason"] for i in result["excluded_items"]]
    assert any("provenance" in r for r in reasons)


def test_provenance_commit_from_env(monkeypatch):
    monkeypatch.setenv("REVAI_COMMIT", PROV)
    result = rq.verify_claimed_iocs(REPORT + f"\ncommit `{PROV}`\n", EVIDENCE)
    assert all(i["value"] != PROV for i in result["unverified_items"])
    reasons = [i["reason"] for i in result["excluded_items"]]
    assert any("provenance" in r for r in reasons)


def test_other_64hex_hashes_are_still_flagged():
    # The exclusion is limited to the pipeline's own commit; an unrelated
    # 64-hex claim must still be reported unverified.
    result = rq.verify_claimed_iocs(REPORT, EVIDENCE, provenance_commit=PROV)
    values = {i["value"] for i in result["unverified_items"]}
    assert "5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b5aa765d61d8327deb882cf99" in values


def test_collect_evidence_text_reads_known_files(tmp_path):
    (tmp_path / "deep_dive").mkdir()
    (tmp_path / "deep_dive" / "01-tools-raw.json").write_text('{"a": "evil-c2.biz"}')
    (tmp_path / "iocs.json").write_text('{"domains": ["evil-c2[.]biz"]}')
    text, used = rq.collect_evidence_text(tmp_path)
    assert "evil-c2.biz" in text
    assert any("01-tools-raw.json" in u for u in used)
    assert any("iocs.json" in u for u in used)
    assert "REPORT" not in text


def test_collect_evidence_text_is_bounded(tmp_path):
    (tmp_path / "iocs.json").write_text("x" * 5000)
    text, _used = rq.collect_evidence_text(tmp_path, max_bytes=1000)
    assert len(text) <= 1000


# --- artifact exclusions + promotion --------------------------------------


def test_generic_hive_keys_are_excluded():
    md = "Persistence via HKEY_CURRENT_USER\\Run and HKLM\\Run."
    result = rq.verify_claimed_iocs(md, "")
    assert result["unverified"] == 0
    assert result["excluded"] == 2
    assert all("specific subkey" in i["reason"] for i in result["excluded_items"])


def test_benign_url_host_is_excluded():
    md = "Namespace: http://xml.org/schemas/xml/lexical-handler"
    result = rq.verify_claimed_iocs(md, "")
    assert result["unverified"] == 0
    assert result["excluded"] >= 1


def test_prose_identifiers_are_not_claims():
    md = "The `powershell.exe` path uses capability.attack.execution telemetry."
    result = rq.verify_claimed_iocs(md, "")
    assert result["claims"] == 0


def test_ioc_factcheck_issue_modes(monkeypatch):
    monkeypatch.delenv("REVAI_IOC_FACTCHECK", raising=False)
    assert rq._ioc_factcheck_issue({"unverified": 2}) == "report:unverified_iocs:2"
    assert rq._ioc_factcheck_issue({"unverified": 0}) is None
    monkeypatch.setenv("REVAI_IOC_FACTCHECK", "advisory")
    assert rq._ioc_factcheck_issue({"unverified": 2}) is None


# --- behavior prerequisites (#14d) ----------------------------------------


MD_BEHAVIOR = ("The sample performs process injection and establishes persistence "
               "through a Run key.")


def test_behavior_prerequisites_flags_unsupported():
    surface = "createremotethread\nwriteprocessmemory"
    result = rq.verify_behavior_prerequisites(MD_BEHAVIOR, surface)
    assert result["advisory"] is True
    behaviors = {i["behavior"] for i in result["unsupported_items"]}
    assert behaviors == {"persistence"}
    assert result["analysis_incomplete"] is False


def test_behavior_prerequisites_supported_is_clean():
    surface = "createremotethread\nregsetvalueex"
    result = rq.verify_behavior_prerequisites(MD_BEHAVIOR, surface)
    assert result["unsupported"] == 0
    assert result["checked"] == 2


def test_behavior_prerequisites_packed_reads_incomplete():
    result = rq.verify_behavior_prerequisites(MD_BEHAVIOR, "", packed=True)
    assert result["analysis_incomplete"] is True
    assert result["packed"] is True


def test_behavior_prerequisites_empty_report():
    result = rq.verify_behavior_prerequisites("", "anything")
    assert result["checked"] == 0
    assert result["unsupported_items"] == []


def test_collect_import_surface_prefers_structured(tmp_path):
    (tmp_path / "quick_scan").mkdir()
    (tmp_path / "quick_scan" / "00-tools-raw.json").write_text(
        '{"pe_imports": {"signals": [{"api_match": "CreateRemoteThread"}]}}')
    surface, sources = rq.collect_import_surface(tmp_path)
    assert "createremotethread" in surface
    assert any("00-tools-raw.json" in s for s in sources)
