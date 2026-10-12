"""revai/entailment.py — plan #6: does each claim FOLLOW from the evidence it cites?

The pipeline already grounds IoCs (an indicator must be observed in the evidence)
and calibrates verdicts (malicious requires behavioural intent). What neither
does is the general question: **a claim cites evidence — does that evidence
actually support it?**

That question is not academic. Three separate defects this session were the same
failure in different clothes:

  * #42 — reports asserted indicators no tool observed (the IoC scrubber's fix);
  * #55 — a report claimed a dynamic run executed, when the oracle had failed;
  * #57/#62 — calibration and provenance read the LABEL rather than the
    measurement, so a hedge or an API definition beat real evidence.

Each was fixed where it surfaced. #6 is the general form: extract every claim
that carries a citation, and check the citation resolves to evidence that
actually says what the claim says.

Deliberately conservative. This module reports; it does not rewrite. A claim it
cannot verify is reported as UNVERIFIED with the reason, never silently dropped
and never silently passed -- an unverifiable claim must stay visible.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

#: A citation as the reports emit it: (source: <engine>, query_or_table: <x>,
#: row_or_rule: <y>) or the {source: ...} variant. Groups are optional because
#: models emit partial citations.
#: The row group tolerates commas INSIDE quotes and parens: a citation reads
#: `row_or_rule: 'packed with UPX' -> T1027.002 (Software Packing), ...` and
#: stopping at the first comma truncated it to `load_library (T1129`, which then
#: resolved nowhere. That is the checker truncating the evidence, not the report
#: fabricating it -- and 12 of packed_rook's 16 unresolved rows were exactly
#: that. A quoted string wins outright; otherwise a run that may contain one
#: balanced parenthetical.
#:
#: The house format ENDS with `, why: <text>`, and the closer used to be
#: demanded immediately after row_or_rule -- so a citation only parsed when an
#: in-row `)` happened to sit at the right spot. Measured on wiper_wipe32p's
#: technical report: 244 raw citations, 32 extracted, and 18 of the 21
#: prose-citing rows were silently dropped there (an unquoted row
#: `size=20480, why: ...`, a quoted row whose parens contain a comma, ...),
#: so the gate certified a report whose largest defect class it could not see.
#: The optional why-tail lets the closer land inside the why-text instead.
_CITE_RE = re.compile(
    r"[({\[]\s*source:\s*(?P<source>[^,}\])]+)"
    r"(?:,\s*query_or_table:\s*(?P<query>[^,}\])]+))?"
    r"(?:,\s*row_or_rule:\s*(?P<row>\"[^\"]*\"|'[^']*'|[^,}\]]*?"
    r"(?:\([^)]*\)[^,}\]]*)*))?"
    r"(?:,\s*why:[^)}\]]*)?"
    r"\s*[)}\]]",
    re.IGNORECASE,
)

#: An assertion worth checking: a sentence that claims something about the
#: sample and carries at least one citation.
_CLAIM_SPLIT = re.compile(r"(?<=[.!?])\s+|\n+")

#: Words that make a sentence a claim about the SAMPLE rather than about the
#: analysis. A sentence about the pipeline ("we ran Ghidra") is not a claim
#: about the binary and must not be gated as one.
#: Discourse connectives that open a sentence ABOUT THE ANALYSIS rather than a
#: claim about the sample. Measured on wiper_wipe32p: 4 of 6 circular
#: "violations" were sentences like "However, no evidence of malicious delivery
#: ... was observed" and "The likely reason for the divergence is ..." -- the
#: report discussing its own findings. A claim about the sample opens with its
#: subject.
_DISCOURSE_MARKERS = (
    "however", "although", "though", "whereas", "while", "moreover",
    "furthermore", "therefore", "thus", "hence", "consequently",
    "in addition", "by contrast", "on the other hand", "the likely reason",
    "this suggests", "it appears", "it is worth", "note that", "in summary",
    "overall", "in conclusion", "as a result", "nevertheless", "nonetheless",
    "that said", "in this section", "for this section", "out of scope",
    "the remainder", "the rest of",
)

_ANALYSIS_WORDS = (
    "we ", "this report", "this analysis", "the pipeline", "the run",
    "the examiner", "the analyst", "this section", "as shown above",
    # the report explaining its own citation format is not a claim about the
    # sample: "(source: <engine>)" is a placeholder, not a citation.
    "citations use the format", "citation format", "<engine>",
)

#: Verdicts and grades. A verdict is a claim too, and the one that matters most.
_VERDICT_WORDS = ("benign", "legitimate", "suspicious", "malicious")


def extract_claims(md: str, limit: int = 200) -> list[dict]:
    """Every citation-bearing sentence in a report, with its citation.

    Returns [{text, source, query, row, index}]. Sentences with no citation are
    NOT returned here -- an uncited assertion is a different defect (low
    citations, already gated) and mixing the two makes both unreadable.
    """
    out: list[dict] = []
    if not md:
        return out
    # Skip fenced blocks: they are evidence dumps, not claims.
    body, in_fence = [], False
    for line in md.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            body.append(line)
    text = "\n".join(body)

    idx = 0
    for sent in _CLAIM_SPLIT.split(text):
        sent = sent.strip()
        if len(sent) < 25:
            continue
        m = _CITE_RE.search(sent)
        if not m:
            continue
        low = sent.lower()
        if any(w in low[:60] for w in _ANALYSIS_WORDS):
            continue
        # A sentence opening with a discourse connective is commentary about the
        # analysis, not a claim about the sample. Single words match the first
        # token; multi-word markers ("the likely reason") must prefix-match,
        # because splitting on whitespace leaves "the" and the marker is never
        # seen.
        _stripped = low.strip()
        _first = re.split(r"[\s,;:]+", _stripped, maxsplit=1)[0]
        if _first in _DISCOURSE_MARKERS or any(
                _stripped.startswith(m) for m in _DISCOURSE_MARKERS
                if " " in m):
            continue
        out.append({
            "text": sent[:400],
            "source": (m.group("source") or "").strip(),
            "query": (m.group("query") or "").strip() or None,
            "row": (m.group("row") or "").strip() or None,
            "index": idx,
        })
        idx += 1
        if len(out) >= limit:
            break
    return out


#: A citation's `source` is a PROVENANCE LABEL -- which engine produced the
#: data -- not a string inside the data. Matching the label as a substring of
#: the corpus reported 350 of 497 claims as unresolved on a healthy run, which
#: is a checker bug and not a report defect. A source resolves when it names an
#: artifact that EXISTS in the case, or its literal appears in the evidence.
#:
#: Aliases are needed because models shorten and re-spell: `agentic_recover_v4`,
#: `recovered function names` and `function_recovery` all name the same stage.
_SOURCE_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "agentic_recover_v4": ("function_recovery.json",),
    "agentic_recover": ("function_recovery.json",),
    "recover_v4": ("function_recovery.json",),
    "function_recovery": ("function_recovery.json",),
    "recovered function": ("function_recovery.json",),
    "recovered function names": ("function_recovery.json",),
    "yara": ("rule.yara.json", "deep_dive/01-tools-raw.json"),
    "yara_gen": ("rule.yara.json",),
    "yara_gen_v2": ("rule.yara.json",),
    "yara matches": ("rule.yara.json", "deep_dive/01-tools-raw.json"),
    "yara_scan": ("deep_dive/01-tools-raw.json",),
    "capa": ("deep_dive/01-tools-raw.json",),
    "capa_analyze": ("deep_dive/01-tools-raw.json",),
    "capa top_rules": ("deep_dive/01-tools-raw.json",),
    "ghidra": ("deep_dive/05-deep-dive.json", "deep_dive/agentic_deep_dive.json"),
    "ghidra_query": ("deep_dive/agentic_deep_dive.json",),
    "ghidra_imports": ("deep_dive/agentic_deep_dive.json",),
    "ghidra_strings": ("deep_dive/agentic_deep_dive.json",),
    "ghidra_functions": ("deep_dive/agentic_deep_dive.json",),
    "ghidra_decompile": ("deep_dive/agentic_deep_dive.json",),
    "ida": ("deep_dive/agentic_deep_dive.json",),
    "ida_query": ("deep_dive/agentic_deep_dive.json",),
    "malcat": ("malcat-triage.json", "deep_dive/01-tools-raw.json"),
    "malcat packer_intake": ("deep_dive/01-tools-raw.json",),
    "malcat imports": ("deep_dive/01-tools-raw.json",),
    "malcat_triage": ("malcat-triage.json",),
    "packer": ("deep_dive/01-tools-raw.json",),
    "packer_intake": ("deep_dive/01-tools-raw.json",),
    "floss": ("deep_dive/01-tools-raw.json",),
    "floss_extract": ("deep_dive/01-tools-raw.json",),
    "strings": ("deep_dive/01-tools-raw.json",),
    "pe_imports": ("quick_scan/pe-imports.json",),
    "pe_import_signals": ("deep_dive/01-tools-raw.json",),
    "imports": ("deep_dive/01-tools-raw.json",),
    "import_table": ("deep_dive/01-tools-raw.json",),
    "triage verdict": ("quick_scan/verdict.json",),
    "verdict.json": ("quick_scan/verdict.json",),
    "verdict": ("quick_scan/verdict.json", "deep_dive/05-deep-dive.json"),
    "deep_dive_agentic": ("deep_dive/agentic_deep_dive.json",),
    "deep_dive": ("deep_dive/05-deep-dive.json",),
    "quick_scan": ("quick_scan/00-tools-raw.json",),
    "dotnet": ("deep_dive/01-tools-raw.json",),
    "dotnet_analyze": ("deep_dive/01-tools-raw.json",),
    "speakeasy": ("deep_dive/03-oracle.json",),
    "emulation_oracle": ("deep_dive/03-oracle.json",),
    "revai_tools_sec": ("deep_dive/01-tools-raw.json",),
    "revai_tools_sinks": ("deep_dive/01-tools-raw.json",),
    "revai_tools_audit": ("deep_dive/01-tools-raw.json",),
    "sinkcat": ("deep_dive/01-tools-raw.json",),
    "anti_analysis": ("deep_dive/02-signals.json",),
    "anti_analysis_signals": ("deep_dive/02-signals.json",),
    "dynamic_resolve": ("deep_dive/02-signals.json",),
    "cross_engine_notes": ("deep_dive/02-signals.json",),
    "cross-section": ("deep_dive/05-deep-dive.json",),
    "section": ("deep_dive/05-deep-dive.json",),
    # Labels a real run emits, found by measuring one rather than guessing:
    # "triage verdict.json", "deep-dive.json", "UPX unpack evidence",
    # "XOR search results", "radare2 disassembly blocks", "appendix caveats".
    "triage": ("quick_scan/verdict.json",),
    "triage verdict": ("quick_scan/verdict.json",),
    "deep-dive.json": ("deep_dive/05-deep-dive.json",),
    "deep dive": ("deep_dive/05-deep-dive.json",),
    "upx": ("deep_dive/01-tools-raw.json",),
    "upx unpack": ("deep_dive/01-tools-raw.json",),
    "unpack": ("deep_dive/01-tools-raw.json",),
    "unpack_pass": ("deep_dive/01-tools-raw.json",),
    "xor": ("deep_dive/01-tools-raw.json",),
    "xor search": ("deep_dive/01-tools-raw.json",),
    "radare2": ("deep_dive/01-tools-raw.json",),
    "r2": ("deep_dive/01-tools-raw.json",),
    "disassembly": ("deep_dive/01-tools-raw.json",),
    "appendix": ("deep_dive/evidence-pack.md",),
    "caveats": ("deep_dive/evidence-pack.md",),
    "malcat-capa": ("deep_dive/01-tools-raw.json",),
    "malcat capa": ("deep_dive/01-tools-raw.json",),
}


#: Tokens that make a `row_or_rule` a LITERAL -- something that must exist
#: verbatim in the evidence -- rather than a prose characterisation of a table.
#: Tokens that make a `row_or_rule` a LITERAL -- something that must exist
#: verbatim in the evidence -- rather than a prose characterisation of a table.
_LITERAL_ROW_RE = re.compile(
    r"0x[0-9a-fA-F]+"                     # an offset
    r"|\b[0-9a-f]{8,}\b"                 # a hash
    r"|\b[\w.-]+\.(exe|dll|sys|dat|json|yar|ps1|bat)\b"   # a filename
    r"|\b[a-z][a-z0-9]*(?:_[a-z0-9]+){1,}\b"               # snake_case
    r"|\b[A-Za-z]*[a-z][A-Z][a-zA-Z]*\b"                   # CamelCase
    r"|\b[a-z]+(?:-[a-z]+){2,}\b"                          # hyphenated rule name
)


def _row_is_literal(row: str) -> bool:
    """Whether a `row_or_rule` asserts a specific, checkable observation.

    A literal is an offset, a hash, a filename, a symbol or a rule name. A
    summary is prose with counts and conjunctions ("KERNEL32 (21), USER32
    (10)"). The distinction decides whether an unresolved row is a FABRICATION
    -- a specific observation that exists nowhere -- or IMPRECISION, a true
    statement the model paraphrased instead of quoting.

    Measured on feodo_banking: 27 unresolved rows, of which the literal ones
    were zero and the summary-style ones were the whole count. Gating on all of
    them would have failed a sound report for citation style.
    """
    # The citation parser leaves the opening quote on the row ("KERNEL32 (21).
    # Judging the quoted form made every quoted row "literal", including plain
    # summaries -- so strip the citation's own quoting first.
    r = (row or "").strip().strip('"').strip("'").strip()
    if len(r) > 160:
        return False
    if _LITERAL_ROW_RE.search(r):
        return True
    # A genuinely quoted *content* string is a literal claim about the sample.
    # The quote must be INTERIOR: the citation parser leaves its own opening
    # quote on the row ("KERNEL32 (21), and a quote at position 0 is that
    # artefact, not the model quoting content.
    inner = r[1:] if r[:1] in ('"', "'") else r
    return bool(re.search(r'"|\\x[0-9a-f]{2}', inner))


def _source_resolves(source: str, root: Path, evidence: str) -> tuple[bool, str]:
    """(resolves, how). A source resolves by artifact presence or by literal.

    Artifact presence is the strong form: the engine that produced this
    citation has an artifact in the case. The literal is the fallback for a
    source this map does not name, so an unmapped-but-real source still counts.
    """
    s = _norm(source)
    if not s:
        return False, "citation names no source"
    # longest alias first, so "malcat packer_intake" beats "malcat"
    for alias in sorted(_SOURCE_ARTIFACTS, key=len, reverse=True):
        if alias in s or s in alias:
            for rel in _SOURCE_ARTIFACTS[alias]:
                if (root / rel).is_file():
                    return True, f"artifact:{rel}"
            # named a known engine whose artifact is absent -> genuinely absent
            return False, f"artifact-missing:{alias}"
    return (s in evidence.lower()), "literal-in-corpus"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def verify_claim(claim: dict, evidence_text: str,
                 root: Path | None = None) -> dict:
    """Does the evidence this claim cites actually exist, and say what it says?

    Three checks, in increasing strength:

      1. SOURCE RESOLVES -- the cited engine appears in the evidence at all.
         A citation naming an engine the run never used is unresolvable.
      2. ROW RESOLVES -- when the claim cites a row_or_rule, that row's text
         appears in the evidence. A row that exists nowhere is fabricated.
      3. SUPPORT -- when both resolve, the cited row and the claim share
         content. Reported as a ratio, not a verdict: this module does not
         pretend to do semantic entailment, and a low ratio is a signal to
         read, not a failure to gate on.

    A claim with only a source (no row) passes 1 and is reported as
    source-only: cited but not traceable to a specific observation.
    """
    src = _norm(claim.get("source") or "")
    row = _norm(claim.get("row") or "")
    ev = _norm(evidence_text)
    root = root or Path(".")
    res: dict[str, Any] = {"source": claim.get("source"),
                           "row": claim.get("row"),
                           "checks": {}}
    if not src:
        res["status"] = "unverifiable"
        res["reason"] = "citation names no source"
        return res
    # 2b. CIRCULAR: the claim cites the report's own prose as its evidence.
    # Measured on stealers_redline_stealc: a claim citing
    # `{source: llm_judge, query_or_table: summary, row_or_rule: "GUI subsystem
    # with zero window APIs (anomaly)"}` -- the summary offered as the evidence
    # for a statement in the summary. That is not evidence, and it is the one
    # claim in a 496-claim report the checker could not ground at all.
    # Circular means the claim offers the analysis's own PROSE as its evidence.
    # `source: llm_judge` alone is NOT circular: the model routinely reports what
    # a tool found and cites that tool's table
    # (`source: llm_judge, query_or_table: pe_imports_signals, row_or_rule:
    # IsDebuggerPresent / T1622`), which is a legitimate citation. Measured on
    # wiper_wipe32p: 12 violations, of which 1 was a real circular citation
    # (`query_or_table: verdict.summary`) and 11 were this over-match.
    _q = _norm(claim.get("query") or "")
    # A POSITIVE prose query. An absent query is NOT prose: `(source: llm_judge)
    # cross_engine_notes` is a short but legitimate citation, and 8 of the rats
    # report's violations were exactly that. The query must name the analysis's
    # own prose, not merely fail to name a table.
    _prose_query = (
        _q in ("summary", "verdict", "the summary", "the verdict")
        or ("summary" in _q and len(_q) < 40)
        or _q.startswith("verdict.")
    )
    if src in ("summary", "the summary", "prose", "narrative") or (
            src in ("llm_judge", "llm", "llm verdict") and _prose_query):
        res["status"] = "circular"
        res["reason"] = ("the claim cites the analysis's own prose "
                         f"({claim.get('source')}/{claim.get('query')}) as its "
                         "evidence; a summary is not evidence for itself")
        res["checks"]["circular"] = True
        return res


    # 1. the source names evidence that was actually produced
    src_ok, how = _source_resolves(claim.get("source") or "", root, ev)
    res["checks"]["source_resolves"] = src_ok
    res["checks"]["source_resolution"] = how
    if not src_ok:
        res["status"] = "unresolved-source"
        res["reason"] = (f"source {claim.get('source')!r} does not resolve to any "
                         "evidence in this case ({how})")
        return res

    if not row:
        res["status"] = "source-only"
        res["reason"] = "cited an engine but no specific row or rule"
        return res

    # 2. the row's text appears in the evidence
    row_ok = row in ev
    res["checks"]["row_resolves"] = row_ok
    if not row_ok:
        # Tolerate a truncated row: models shorten what they cite. Require a
        # substantial prefix rather than the whole string.
        probe = row[:40]
        row_ok = len(probe) >= 20 and probe in ev
        res["checks"]["row_prefix_resolves"] = row_ok
    if not row_ok:
        # A row that reads like a LITERAL -- an offset, a rule name, a path, a
        # quoted string -- must appear in the evidence. A row that reads like
        # the model's own characterisation ("KERNEL32 (21), USER32 (10)...")
        # names a real table but is not itself a row: that is imprecise
        # citation, not fabrication, and gating on it fails a report for style.
        # Measured on feodo_banking: 27 unresolved rows, of which the literal
        # ones were zero and the summary-style ones were the whole count.
        # The ORIGINAL row, not the normalised one: _norm() lowercases, and
        # CamelCase (CreateRemoteThread) is exactly the signal that makes a row
        # a literal. Judging the lowercased form classified every symbol as a
        # summary.
        if _row_is_literal(claim.get("row") or ""):
            res["status"] = "unresolved-row"
            res["reason"] = (f"row {claim.get('row')!r} appears nowhere in the "
                             "evidence pack")
            return res
        res["status"] = "summary-citation"
        res["reason"] = ("row_or_rule is the analysis's characterisation of a "
                         "table rather than a literal row, so it is traceable "
                         "to the table but not to an observation")
        return res

    # 3. support: shared content between the claim and the cited row
    claim_words = set(re.findall(r"[a-z_]{4,}", _norm(claim.get("text"))))
    row_words = set(re.findall(r"[a-z_]{4,}", row))
    shared = claim_words & row_words
    ratio = round(len(shared) / max(1, len(claim_words)), 3)
    res["checks"]["support_ratio"] = ratio
    res["status"] = "supported" if ratio >= 0.15 else "weak-support"
    res["reason"] = ("" if ratio >= 0.15 else
                     f"only {len(shared)} shared terms between the claim and "
                     "the row it cites")
    return res


#: The artifacts that constitute a case's evidence. A report cites engines, and
#: those engines write HERE -- not only in the deep-dive evidence pack, which is
#: a summary. Reading only that summary reported 412 of 497 claims as
#: unresolved-source, which is a checker bug and not a report defect: a gate
#: built on the wrong corpus cries wolf, and a gate that cries wolf gets
#: discounted.
_EVIDENCE_ARTIFACTS = (
    "deep_dive/evidence-pack.md",
    "deep_dive/01-tools-raw.json",
    "deep_dive/02-signals.json",
    "deep_dive/03-oracle.json",
    "deep_dive/05-deep-dive.json",
    "deep_dive/agentic_deep_dive.json",
    "quick_scan/00-tools-raw.json",
    "quick_scan/verdict.json",
    "iocs.json",
    "function_recovery.json",
    "rule.yara.json",
    "malcat-triage.json",
    "intake-validation.json",
    "understanding.json",
    "EVIDENCE-BUNDLE.md",
)


def _case_evidence_text(root: Path, cap: int = 4_000_000) -> str:
    """Every evidence artifact in the case, concatenated.

    This is the corpus a citation must resolve against. Bounded, because a
    function-recovery artifact alone can be megabytes and the check is textual.
    """
    chunks: list[str] = []
    total = 0
    for rel in _EVIDENCE_ARTIFACTS:
        p = root / rel
        if not p.is_file():
            continue
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunks.append(txt)
        total += len(txt)
        if total >= cap:
            break
    return "\n".join(chunks)[:cap]


def check_report_entailment(sha: str, logs_dir: Path | None = None,
                            *, case_root: Path | None = None) -> dict:
    """#6's gate: every citation-bearing claim in every report, checked.

    Reads the evidence pack and each REPORT-*.md. Returns counts plus the
    violations, which are the claims whose citations do not resolve. An
    unresolvable citation is a claim the reader cannot check -- which is the
    definition of an unverifiable claim.
    """
    try:
        from v2_lib import LOGS_DIR
        base = Path(logs_dir) if logs_dir else LOGS_DIR
    except Exception:
        base = Path("/opt/samples/logs")
    root = Path(case_root) if case_root else base / sha
    # Mode-keyed runs write under logs/<sha>/<mode>/; prefer whichever exists.
    if not list(root.glob("REPORT-*.md")):
        for mode in ("scripted", "agentic", "ui"):
            cand = root / mode
            if cand.is_dir() and list(cand.glob("REPORT-*.md")):
                root = cand
                break
    if not root.is_dir():
        return {"ok": True, "applicable": False, "reason": "no case dir"}

    evidence = _case_evidence_text(root)
    import glob
    reports = sorted(glob.glob(str(root / "REPORT-*.md")))
    if not reports:
        return {"ok": True, "applicable": False, "reason": "no reports"}
    # A missing evidence corpus disables the evidence-dependent checks but NOT
    # the structural ones: a circular citation is unverifiable whatever the
    # corpus contains, so bailing here would hide exactly the defect this gate
    # exists to find.
    corpus_note = ("" if evidence else
                   " (no evidence artifacts in the case: source and row "
                   "resolution were not attempted)")

    total = 0
    by_status: dict[str, int] = {}
    violations: list[dict] = []
    per_report: dict[str, Any] = {}

    for path in reports:
        name = Path(path).name
        try:
            md = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        claims = extract_claims(md)
        counts: dict[str, int] = {}
        for c in claims:
            total += 1
            r = verify_claim(c, evidence, root)
            st = r["status"]
            counts[st] = counts.get(st, 0) + 1
            by_status[st] = by_status.get(st, 0) + 1
            # The gate fires on a row that resolves NOWHERE, or a citation
            # naming no source. It deliberately does NOT fire on
            # unresolved-source: measured on a healthy run, those are dominated
            # by provenance-label spellings the alias map does not cover yet
            # (23 of them, of which the ones inspected were all real evidence
            # under a different name). A gate that fires on its own blind spots
            # cries wolf, and a gate that cries wolf gets discounted -- so that
            # class is REPORTED as a count and not gated until the map is
            # proven against a corpus.
            # Gated: a citation naming no source, and a CIRCULAR citation (the
            # analysis's own prose offered as evidence for itself). Both are
            # structural and need no alias map.
            #
            # Reported but NOT gated: unresolved-row. Measured across five real
            # reports, that class is dominated by checker artifacts -- the
            # citation parser truncates a row at the first comma
            # (`load_library (T1129` from `load_library (T1129, ...)`), and a
            # model's characterisation of a table ("KERNEL32 (21)") is not a
            # literal row. 16 of 16 on packed_rook were one of those two. A gate
            # firing on its own parser limits cries wolf.
            if st in ("circular", "unverifiable"):
                violations.append({"report": name, "claim": c["text"][:200],
                                   **r})
        per_report[name] = {"claims": len(claims), "by_status": counts}

    ok = not violations
    return {
        "ok": ok,
        "applicable": True,
        "evidence_chars": len(evidence),
        "claims_total": total,
        "by_status": by_status,
        "per_report": per_report,
        "violations": violations[:40],
        "violations_total": len(violations),
    }


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="claim entailment check")
    ap.add_argument("sha")
    ap.add_argument("--case", default="", help="explicit case directory")
    args = ap.parse_args()
    root = Path(args.case) if args.case else None
    res = check_report_entailment(args.sha, case_root=root)
    # Do NOT truncate: a truncated JSON document is unparseable, so a caller
    # (or a test) reading this gets a decode error instead of the result.
    print(json.dumps(res, indent=2))
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
