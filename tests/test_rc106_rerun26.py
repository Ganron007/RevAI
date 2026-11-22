"""RC-106 (re-run 26, 2026-11-22): the three reds re-run 26 exposed.

1. The scrub's hive TRIGGER tuple named HKEY_/HKLM/HKCU but not HKCR, so a
   line carrying only HKCR paths never entered the registry branch --
   re-run 26's master_v2 shipped `HKCR\\WOW6432Node\\CLSID\\{...}\\CurVer`
   (a subkey no evidence artifact carries) as unverified_iocs:1.

2. The scrub's registry corpus probe tried only the SINGLE-separator
   spelling, while the corpus carries the raw tool artifacts verbatim --
   JSON-escaped, with each separator as TWO characters
   (`HKCR\\\\WOW6432Node\\\\CLSID\\\\{...}` in deep_dive/02-dynamic-pack.json).
   A report quoting an observed path in the only correct prose spelling
   failed the probe and was redacted as "not in evidence".

3. The checker's candidate strip removed a CLSID path's closing brace
   (`}` is in the punctuation strip set), so `HKCR\\CLSID\\{GUID}` was probed
   as `HKCR\\CLSID\\{GUID` and shipped as unverified_iocs:1 on the
   technical_v2.

4. The v2 TECHNICAL never received RC-101's FINAL deterministic pre-passes
   (the master did); RC-95's pass runs per-chunk inside
   generate_technical_chunked, before the assembly-level transforms.
   Re-run 26: technical_v2 orphan_tables:6 while the master finished at 0.

5. A missed RC-97 B1 call site left `source_evidence_for` referenced in
   main's repair retries -- the NameError that fired live. The
   undefined-name guard skipped nested scopes, so it never saw it.
"""

import inspect
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "revai"))

import publish_report_v2 as PR  # noqa: E402
import report_quality as RQ  # noqa: E402
import section_publisher as SP  # noqa: E402
from section_publisher import _fix_orphan_tables  # noqa: E402

# The real corpus shapes from re-run 26's case: the dynamic pack's
# JSON-escaped procmon rows. `CurVer` appears in NO evidence artifact, and
# the plain (non-WOW6432Node) CLSID spelling does not either.
ESCAPED_CORPUS = (
    '{"path": "HKCR\\\\WOW6432Node\\\\CLSID\\\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}\\\\InprocServer32"}\n'
    '{"path": "HKCR\\\\WOW6432Node\\\\CLSID\\\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}\\\\ProgID"}\n'
    '{"path": "HKLM\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer'
    '\\\\ShellExecuteHooks\\\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}"}\n'
)


@pytest.fixture
def scrub_with_real_corpus(monkeypatch):
    """The scrub pointed at re-run 26's real corpus shapes."""
    monkeypatch.setattr(SP, "collect_evidence_text",
                        lambda root: (ESCAPED_CORPUS, ["synthetic"]))
    monkeypatch.setattr(SP, "case_dir", lambda sha: Path("/nonexistent"))


# ---------------------------------------------------------------------------
# 1. the hive trigger must cover every hive the token regex can match
# ---------------------------------------------------------------------------

def test_the_scrub_trigger_names_every_hive_the_token_matches():
    """RC-103 added HKCR to the TOKEN regex; the TRIGGER tuple was missed."""
    src = inspect.getsource(SP._strip_unverified_indicators)
    trigger = next(ln for ln in src.splitlines()
                   if "for pattern in" in ln)
    for hive in ("HKEY_", "HKLM", "HKCU", "HKCR"):
        assert hive in trigger, f"the trigger tuple must name {hive}"


def test_an_hkcr_only_line_is_scrubbed(scrub_with_real_corpus):
    """The re-run 26 master shape: an HKCR-only table row whose subkey
    appears in no evidence artifact is redacted, not published."""
    line = ("| 03:33:38.6399084 | HKCR\\WOW6432Node\\CLSID"
            "\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}\\CurVer | (Default) | "
            "WinCryptography.Encrypt.1 | (source: procmon, query_or_table: "
            "procmon.csv, row_or_rule: data row 99610; PID 2816; operation "
            "RegSetValue) |")
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted: not in evidence]" in out
    assert "CurVer" not in out


# ---------------------------------------------------------------------------
# 2. the corpus probe must accept the JSON-escaped spelling
# ---------------------------------------------------------------------------

def test_an_observed_path_survives_the_escaped_probe(scrub_with_real_corpus):
    """A path the corpus carries ONLY JSON-escaped is kept in its prose
    spelling -- the checker's evidence_json_plain unescapes for exactly
    this class, and the scrub must agree with it."""
    line = ("- The sample created COM registry keys under HKCR\\WOW6432Node"
            "\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB} with "
            "InprocServer32 default=crypto.dll. (source: procmon, "
            "query_or_table: deep_dive/02-dynamic-pack.json, row_or_rule: "
            "$.procmon_sample_event_rows[?(@.row==99415)])")
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted" not in out
    assert "HKCR\\WOW6432Node\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}" in out


def test_a_normalized_path_is_still_redacted(scrub_with_real_corpus):
    """Dropping the WOW6432Node segment makes a DIFFERENT path -- the #42
    class is untouched by the new probe variant."""
    line = ("- The sample performed persistent registry modifications under "
            "HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}, and "
            "dropped four files.")
    out = SP._strip_unverified_indicators(line, "a" * 64)
    assert "[redacted: not in evidence]" in out
    assert "310DE29C" not in out


# ---------------------------------------------------------------------------
# 3. the checker's candidate strip must keep a CLSID's closing brace
# ---------------------------------------------------------------------------

def _candidate(line: str) -> str:
    m = list(RQ._EVIDENCE_REGKEY_RE.finditer(line))[0]
    raw = m.group(0).strip().strip(".,;:()[]{}'\"`*_\\")
    tail = m.group(0).rstrip().rstrip(".,;:()[]'\"`*_\\")
    if tail.endswith("}") and raw.count("{") > raw.count("}"):
        raw += "}"
    return raw


@pytest.mark.parametrize("line,expected", [
    ("modifications under HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}, and dropped",
     "HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}"),
    ("keys under HKCR\\WOW6432Node\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}.",
     "HKCR\\WOW6432Node\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB}"),
    ("keys under HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160C",
     "HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160C"),
    ("writes HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run once.",
     "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Run"),
], ids=["clsid+comma", "clsid+period", "writer-truncated", "ordinary"])
def test_the_candidate_keeps_a_closing_brace_it_should(line, expected):
    """The strip exists for trailing PROSE; a brace that closes a GUID is
    part of the path (RC-88: a registry path is atomic). A writer who
    truncated mid-GUID has no `}` anywhere, so the abbreviated class is
    untouched."""
    assert _candidate(line) == expected


def test_a_restored_clsid_candidate_resolves_its_parts():
    raw = _candidate("under HKCR\\CLSID\\{310DE29C-0AD3-4A43-A2DB-221F1160CACB},")
    parts = RQ._regkey_parts(raw)
    assert parts is not None
    hive, subkeys = parts
    assert hive == "hkcr"
    assert subkeys[-1] == "{310de29c-0ad3-4a43-a2db-221f1160cacb}"


# ---------------------------------------------------------------------------
# 4. the v2 technical receives the FINAL pre-passes before its gate
# ---------------------------------------------------------------------------

def test_the_technical_path_runs_the_final_prepasses():
    """Both reports run the FINAL deterministic pre-passes after ALL repair
    passes (RC-101's master pattern; the technical was the gap)."""
    src = inspect.getsource(PR.main)
    # The master's pass and the technical's pass are both present.
    assert src.count("_fix_orphan_tables(") >= 2, (
        "both the master and the technical must run the orphan pre-pass")
    assert src.count("_strip_unverified_indicators(") >= 2, (
        "both the master and the technical must run the indicator scrub")
    # The technical's pass sits before its gate evaluation, not after.
    tech_pass = src.find("tech_md = _fix_orphan_tables(tech_md)")
    tech_gate = src.find("q_tech = evaluate_report_markdown(")
    assert 0 < tech_pass < tech_gate, (
        "the technical's pre-passes must run BEFORE its quality gate")


def test_the_orphan_repair_closes_six_adjacent_pairs():
    """Re-run 26's shape: six back-to-back table pairs on the technical."""
    table = "| Col | Val |\n| --- | --- |\n| a | 1 |\n"
    blocks: list[str] = []
    for i in range(1, 7):
        blocks.extend([f"## {i}. Section", "", table, table])
    md = "\n".join(blocks)
    fixed = _fix_orphan_tables(md)
    assert RQ.count_table_orphans(md) >= 6
    assert RQ.count_table_orphans(fixed) == 0


# ---------------------------------------------------------------------------
# 5. the missed B1 call site and the guard that must catch its class
# ---------------------------------------------------------------------------

def test_main_no_longer_reads_the_unbound_slice_helper():
    """RC-97's refactor left `source_evidence_for` referenced in main's
    repair retries -- a name bound nowhere (re-run 26's NameError)."""
    src = inspect.getsource(PR.main)
    assert "source_evidence_for(" not in src
    assert src.count("_sliced_source_evidence([section])") >= 3, (
        "every main-level repair retry slices its own evidence")


def test_the_undefined_name_guard_walks_nested_scopes():
    """The guard skipped nested scopes; the NameError lived in a nested
    retry closure. A synthetic snippet pins the walk in both directions."""
    import ast
    import test_review_regressions as TRR

    def _scan_source(source: str) -> list[str]:
        tree = ast.parse(source)
        problems: list[str] = []

        def _scan(body, bound, where):
            stack = list(body)
            while stack:
                sub = stack.pop()
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    _scan(sub.body, bound | TRR._locals_of(sub),
                          f"{where}.{sub.name}")
                    continue
                if isinstance(sub, ast.ClassDef):
                    _scan(sub.body, bound | TRR._locals_of(sub),
                          f"{where}.{sub.name}")
                    continue
                if (isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)
                        and sub.id not in bound
                        and sub.id not in ("self", "cls")):
                    problems.append(f"{sub.lineno} `{where}` reads `{sub.id}`")
                stack.extend(ast.iter_child_nodes(sub))

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "main":
                _scan(node.body, TRR._locals_of(node) | set(dir(__builtins__))
                      | set(TRR._builtin_names()), "main")
        return problems

    bad = ("def main():\n"
           "    ok = 1\n"
           "    def _retry():\n"
           "        return missing_helper(ok)\n"
           "    return _retry\n")
    good = ("def main():\n"
            "    def _sliced(x):\n"
            "        return x\n"
            "    def _retry():\n"
            "        return _sliced(1)\n"
            "    return _retry\n")
    assert any("missing_helper" in p for p in _scan_source(bad))
    assert _scan_source(good) == []
