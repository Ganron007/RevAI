"""RC-109 (re-run 29, 2026-11-23): a domain-shaped token inside a file path
is a path segment, not a domain claim -- and the scrub and the checker must
agree on case.

Re-run 29 ran the FULL documented order (360-minute watcher window):
publish rc=0 (8,572 s), section_publish rc=1 (3,548.2 s), audit rc=1. Three
of the four reports finished fully clean (master v2, technical v2,
technical v3 all ok=True 0/0/0), the v3 master's verdict lock held clean for
the FIRST time (it states suspicious, matching the calibration -- the
v2/v3 divergence class is dead), and RC-108's FINAL pre-passes were
live-proven (v3 master uncited 0, orphans 0).

The one remaining red: master_v3 `unverified_iocs:1` = `Microsoft.NET`
(type: domain). The writer restated the procmon dll_sideload row verbatim
-- `samples=['C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\
mscoreei.dll', ...]`, cited from deep_dive/02-dynamic-pack.json, which
carries the full path -- and the checker's `_CLAIM_DOMAIN_RE` lookbehind
(`(?<![\w.-])`) did not reject a path separator, so the directory name was
extracted as a fabricated domain.

The second half of the same defect: the scrub's `_domain_shape` was
LOWERCASE-ONLY while the checker's regex is case-insensitive, so an
uppercase fabricated domain in prose (`Evil.Example.COM`) would escape the
scrub entirely and ship as an unverified IoC. Both sides now agree.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import report_quality as RQ  # noqa: E402
import section_publisher as SP  # noqa: E402

# The exact re-run 29 procmon row (truncated the way the writer rendered it).
PROCMON_LINE = (
    "- [procmon_summary.persistence[0]] dll_sideload=label=DLL load from "
    "non-system path, count=2744, samples=['C:\\Windows\\Microsoft.NET\\"
    "Framework64\\v4.0.30319\\mscoreei.dll', 'C:\\Windows\\Microsoft.NET\\"
    "Framework64\\v4.0.30319\\mscorsvc.dll'] (source: deep_dive/"
    "02-dynamic-pack.json, query_or_table: deep_dive/02-dynamic-pack.json, "
    "row_or_rule: $.procmon_summary.persistence[0])")

CIT = ("(source: network, query_or_table: deep_dive/02-dynamic-pack.json, "
       "row_or_rule: $.network_intel.domains[0])")


@pytest.fixture
def scrub(monkeypatch):
    monkeypatch.setattr(SP, "collect_evidence_text",
                        lambda root: ("no domains here", ["synthetic"]))
    monkeypatch.setattr(SP, "case_dir", lambda sha: Path("/nonexistent"))


def _domain_candidates(text: str) -> list[str]:
    return [m.group(0) for m in RQ._CLAIM_DOMAIN_RE.finditer(text)]


# ---------------------------------------------------------------------------
# The checker: a path segment is not a domain claim
# ---------------------------------------------------------------------------

def test_a_path_segment_is_not_a_domain_claim():
    """The re-run 29 shape: `Microsoft.NET` inside the real Windows path."""
    cands = _domain_candidates(PROCMON_LINE)
    assert "Microsoft.NET" not in cands
    assert cands == [], f"no domain claim in the procmon row: {cands}"


@pytest.mark.parametrize("text,expected", [
    ("writes C:\\Windows\\Microsoft.NET\\Framework64\\mscoreei.dll", []),
    ("drops /usr/share/evil.example.com/lib.so", []),
    ("reads C:\\Evil\\Bad.Domain\\x.dll", []),
], ids=["windows-dotnet", "unix-path", "windows-invented"])
def test_path_embedded_tokens_are_not_domains(text, expected):
    assert _domain_candidates(text) == expected


def test_a_url_path_domain_still_extracts():
    """A forward slash AFTER the token stays permitted -- `evil.com/gate.php`
    is a domain with a URL path, not a path segment."""
    cands = _domain_candidates("- The sample requested evil.com/gate.php. " + CIT)
    assert "evil.com" in cands


def test_a_prose_domain_is_still_a_claim():
    """The #42 class is untouched: a domain-shaped token in prose, absent
    from the corpus, is still an unverified claim."""
    cands = _domain_candidates(
        "- The sample beaconed to evil-c2.example.com for tasking. " + CIT)
    assert "evil-c2.example.com" in cands


# ---------------------------------------------------------------------------
# The scrub: case-insensitive, and path segments are spared
# ---------------------------------------------------------------------------

def test_the_scrub_leaves_the_real_windows_path_intact(scrub):
    """The scrub (now case-insensitive) must not mangle a real observed
    path -- the checker no longer claims it, so the scrub must not redact
    it."""
    out = SP._strip_unverified_indicators(PROCMON_LINE, "a" * 64)
    assert out == PROCMON_LINE
    assert "Microsoft.NET" in out


def test_an_uppercase_fabricated_domain_is_still_scrubbed(scrub):
    """The lowercase-only pattern let `Evil.Example.COM` escape the scrub
    entirely while the case-insensitive checker flagged it."""
    line = ("- The sample beaconed to Evil-C2.Example.COM every 60 seconds. "
            + CIT)
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted: not in evidence]" in out
    assert "Evil-C2.Example.COM" not in out


def test_the_scrub_keeps_a_corpus_carried_uppercase_domain(monkeypatch):
    """Case-insensitivity must not redact a value the corpus carries in its
    own spelling -- the probe lowercases both sides."""
    monkeypatch.setattr(
        SP, "collect_evidence_text",
        lambda root: ("observed EVIL-C2.EXAMPLE.COM in traffic", ["synthetic"]))
    monkeypatch.setattr(SP, "case_dir", lambda sha: Path("/nonexistent"))
    line = "- The sample beaconed to Evil-C2.Example.COM. " + CIT
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "Evil-C2.Example.COM" in out
    assert "[redacted" not in out


def test_the_two_sides_agree_on_prose_tokens():
    """The scrub and the checker must recognise the same prose tokens as
    domain-shaped (the re-run 29 case divergence, in both directions)."""
    for token in ("evil.example.com", "Evil.Example.COM", "c2.bad-domain.net"):
        line = f"- beacon to {token} " + CIT
        scrub_hit = any(
            m.group(0) == token
            for m in __import__("re").finditer(
                r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
                line, __import__("re").IGNORECASE))
        checker_hit = token in _domain_candidates(line)
        assert scrub_hit == checker_hit, (
            f"{token}: scrub={scrub_hit} checker={checker_hit}")
