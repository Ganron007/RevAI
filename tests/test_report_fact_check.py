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
