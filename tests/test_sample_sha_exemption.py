#!/usr/bin/env python3
"""The analysed sample's own sha256 is identity, not an indicator.

WannaCry's scripted and agentic audits both went red on
`report:unverified_iocs:1`, and the item was the sample's own sha256
(`ed01ebfbc9eb5bbe...`). Every report states it in Sample Metadata -- the
pipeline writes it -- but it is not in the tool-output corpus the claims are
verified against, so it was flagged as an unverified indicator.

Same class as the provenance-commit exclusion that already existed: identity and
build metadata are not indicators.

Also pins the two failure modes this fix must not have:
  * the exemption must be inert when the case dir is unknown (a claim must never
    exempt itself by appearing in its own report), and
  * real indicators must still be checked -- the exemption is one value.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

SHA = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
CASE_DIR = f"/opt/samples/logs/{SHA}/scripted"
EV = "iocs.json verdict.json deep_dive/05-deep-dive.json"

#: A report whose only hash claim is the sample's own sha256, exactly as the
#: Sample Metadata table states it.
MD = (
    "# Sample Metadata\n\n"
    "| Field | Value |\n|---|---|\n"
    f"| SHA-256 | `{SHA}` |\n"
    "| Format | PE32 |\n\n"
    "## Verdict\n\n**Verdict: malicious** (confidence: 95/100)\n"
)


def _mod():
    sys.modules.pop("report_quality", None)
    d = resolve("revai/report_quality.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import report_quality as rq  # noqa: PLC0415
    return rq


def _clear():
    os.environ.pop("REVAI_CASE_DIR", None)


def test_the_samples_own_sha256_is_not_an_unverified_indicator(monkeypatch):
    rq = _mod()
    monkeypatch.setenv("REVAI_CASE_DIR", CASE_DIR)
    res = rq.verify_claimed_iocs(MD, EV)
    assert res.get("unverified") == 0, res.get("unverified_items")
    assert any("own sha256" in str(e.get("reason", ""))
               for e in res.get("excluded_items") or []), (
        "the exclusion must be recorded, not silent")


def test_the_exemption_is_inert_without_the_case_dir(monkeypatch):
    """A claim must never exempt itself by appearing in its own report."""
    rq = _mod()
    monkeypatch.delenv("REVAI_CASE_DIR", raising=False)
    res = rq.verify_claimed_iocs(MD, EV)
    assert res.get("unverified") == 1, (
        "without knowing which sample this is, the hash is an ordinary claim")
    assert not any("own sha256" in str(e.get("reason", ""))
                   for e in res.get("excluded_items") or [])


def test_a_real_indicator_hash_is_still_checked(monkeypatch):
    """The exemption is one value, not a blanket pass for hashes."""
    rq = _mod()
    monkeypatch.setenv("REVAI_CASE_DIR", CASE_DIR)
    other = "68f013d7437aa653a8a98a05807afeb1" * 2
    md = MD + f"\nThe dropped payload hash is `{other[:64]}`.\n"
    res = rq.verify_claimed_iocs(md, EV)
    unv = [i.get("value") for i in res.get("unverified_items") or []]
    assert other[:64] in unv, (
        "an unrelated hash must still be verified against the evidence")


def test_the_sha_is_read_from_the_mode_keyed_case_dir(monkeypatch):
    """logs/<sha>/<mode>/ puts the mode last, not the sha."""
    rq = _mod()
    for case in (CASE_DIR, f"/opt/samples/logs/{SHA}",
                 f"/opt/samples/logs/{SHA}/agentic"):
        monkeypatch.setenv("REVAI_CASE_DIR", case)
        assert rq._sample_sha256() == SHA, case
    monkeypatch.setenv("REVAI_CASE_DIR", "/opt/samples/logs/not-a-sha/scripted")
    assert rq._sample_sha256() == "", "a non-sha dir must exempt nothing"
