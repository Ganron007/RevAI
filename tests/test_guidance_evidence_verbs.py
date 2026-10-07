#!/usr/bin/env python3
"""Guidance exemption: evidence-collection verbs, and the claim side staying red.

WannaCry's audit stayed red on `report:unverified_iocs:1` with
`HKLM\\SYSTEM\\CurrentControlSet\\Services`. The SAME path was correctly excused
in REPORT-MASTER-v3 ("Delete the service entry created under ...") and counted as
a claim in REPORT-TECHNICAL-v3, where it appeared in a sentence recommending what
evidence to capture:

    "Resolution: execute the sample in an isolated VM ... capture the full
     process tree, registry writes under HKLM\\...\\Services\\*, and ..."

That is the same speech act -- telling the analyst what to do -- but the verb
vocabulary only covered inspect/clean verbs, not evidence-collection ones. A
path the report recommends GATHERING DATA ABOUT was read as an assertion that the
sample wrote there.

The second half of this file is the load-bearing half: widening the vocabulary
must not turn the check into a pass. A sentence that actually asserts the write
must still be red.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
from _layout import resolve  # noqa: E402

PATH = "HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services"

#: The real WannaCry sentence that stayed red.
GUIDANCE = (
    "Resolution: execute the sample in an isolated VM (preferably Windows 7 x86 "
    "SP1, SMBv1 enabled) with Process Monitor, Wireshark, and a memory-dump "
    "agent; capture the full process tree, registry writes under " + PATH +
    "\\\\*, and outbound SMB/ICMP traffic."
)
#: The real WannaCry sentence that was already excused.
GUIDANCE_DELETE = ("2. Delete the service entry created under " + PATH +
                   " and any `HKCU` `Run`-key value.")
#: A genuine claim: the report asserts the sample wrote there.
CLAIM = ("The sample creates a service by writing to " + PATH +
         " at install time, which survives a reboot.")


def _rq():
    sys.modules.pop("report_quality", None)
    d = resolve("revai/report_quality.py").parent
    if str(d) not in sys.path:
        sys.path.insert(0, str(d))
    import report_quality as rq  # noqa: PLC0415
    return rq


def _spans(rq, md, raw):
    scan = rq._claims_text(md)
    m = rq._CLAIM_REGKEY_RE.search(scan)
    key = ("registry_key", rq._plain_claim(raw).lower())
    return {key: [(m.start(), m.end())]} if m else {}


def test_evidence_collection_guidance_is_excused():
    rq = _rq()
    md = "# Gaps\n\n" + GUIDANCE + "\n"
    raw = PATH
    assert rq._is_guidance_reference(rq._claims_text(md), raw,
                                     _spans(rq, md, raw)), (
        "a path the report recommends gathering evidence about is guidance, "
        "not a claim that the sample wrote there")


def test_the_cleanup_guidance_is_still_excused():
    """The original exemption must keep working (regression guard)."""
    rq = _rq()
    md = "# Recommendations\n\n" + GUIDANCE_DELETE + "\n"
    raw = PATH
    assert rq._is_guidance_reference(rq._claims_text(md), raw,
                                     _spans(rq, md, raw))


def test_a_real_claim_is_still_a_claim():
    """Widening the vocabulary must not turn the check into a pass."""
    rq = _rq()
    md = "# Persistence\n\n" + CLAIM + "\n"
    raw = PATH
    assert not rq._is_guidance_reference(rq._claims_text(md), raw,
                                         _spans(rq, md, raw)), (
        "this sentence asserts the sample wrote to the path; it is a claim and "
        "must still be verified")


def test_the_same_path_in_both_speech_acts_is_judged_per_occurrence():
    """The occurrence-level rule: every occurrence must be guidance."""
    rq = _rq()
    raw = PATH
    md = ("# A\n\n" + GUIDANCE + "\n\n# B\n\n" + CLAIM + "\n")
    scan = rq._claims_text(md)
    key = ("registry_key", rq._plain_claim(raw).lower())
    spans = {key: [(m.start(), m.end())
                   for m in rq._CLAIM_REGKEY_RE.finditer(scan)]}
    assert len(spans[key]) == 2, spans
    assert not rq._is_guidance_reference(scan, raw, spans), (
        "one guidance mention must not excuse the bare assertion later")
