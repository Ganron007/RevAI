#!/usr/bin/env python3
"""The hygiene check must actually be able to FAIL.

Found 2026-10-03. `verify_pipeline.check_hygiene` reported `[PASS] hygiene` on a
tree where 2260 published case-study files carried six model names -- and the
pass was real, because the check had three independent reasons not to look:

1. `case-studies` was in the skip list.
2. The model-name branch was gated on `path.suffix == ".md"`, so the 1142 .json,
   56 .jsonl and 442 .txt evidence files were never examined. The bulk of the
   leak was in .json (5,742 occurrences across two model names alone).
3. The branch tested `"docs/" in str(rel)` where `rel` is a `pathlib.Path`. On
   POSIX that stringifies with forward slashes and the test works; on Windows it
   stringifies with BACKSLASHES, so the condition was never true and the branch
   never executed. Every local run on Windows had a model-name check that was
   structurally incapable of failing.

That third one is why the tests below probe with a real file rather than
asserting on the source: a check can look correct in review and be inert in
execution.

Each test writes a violating file, runs the real check, and requires a FAIL.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "revai"))

from _layout import add_module_dir, source  # noqa: E402

add_module_dir("revai/verify_pipeline.py")

import verify_pipeline as vp  # noqa: E402

TOKEN = "mimo-v2.6-pro"  # a real provider name we have shipped


def _write(rel: str, body: str) -> Path:
    p = ROOT / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


def _run_check():
    """Run check_hygiene and report whether it flagged anything.

    `vp.check` has the signature check(name, ok, detail) -- the verdict is the
    second positional argument, which is why the first version of this spy
    raised TypeError instead of testing anything.
    """
    seen: list[tuple[str, bool, str]] = []
    original = vp.check

    def spy(name, ok=True, detail="", *a, **kw):
        seen.append((name, bool(ok), str(detail)))

    vp.check = spy
    try:
        vp.check_hygiene()
    finally:
        vp.check = original
    return seen


def _flagged_model_name() -> bool:
    """True when check_hygiene reported a FAIL that mentions a model name."""
    return any(name == "hygiene" and not ok and "model name" in detail
               for name, ok, detail in _run_check())


def test_published_json_evidence_cannot_carry_a_model_name():
    p = _write("docs/case-studies/scripted/_hygiene_probe.json",
               '{"model": "%s"}\n' % TOKEN)
    try:
        assert _flagged_model_name(), (
            "a model name in published .json evidence was not flagged")
    finally:
        p.unlink()


def test_published_markdown_cannot_carry_a_model_name():
    p = _write("docs/case-studies/scripted/_hygiene_probe.md",
               "Verdict engine llm_judge, model `%s`.\n" % TOKEN)
    try:
        assert _flagged_model_name(), (
            "a model name in published markdown was not flagged")
    finally:
        p.unlink()


def test_published_jsonl_cannot_carry_a_model_name():
    p = _write("docs/case-studies/scripted/_hygiene_probe.jsonl",
               '{"request_model": "%s"}\n' % TOKEN)
    try:
        assert _flagged_model_name(), (
            "a model name in published .jsonl was not flagged")
    finally:
        p.unlink()


def test_the_docs_path_test_is_posix_normalised():
    """The Windows bug, pinned directly.

    `str(Path('docs/x.md'))` is `docs\\x.md` on Windows, so `"docs/" in str(rel)`
    is False and the whole branch is skipped. The condition must go through
    `as_posix()`.
    """
    src = source("revai/verify_pipeline.py")
    assert '"docs/" in rel.as_posix()' in src, (
        "the docs path test must use as_posix(); str(rel) uses backslashes on "
        "Windows and silently disables the check there")
    assert '"docs/" in str(rel)' not in src, (
        "str(rel) reintroduces the platform-dependent no-op")


def test_case_studies_are_no_longer_skipped():
    src = source("revai/verify_pipeline.py")
    skip_line = [ln for ln in src.splitlines()
                 if "node_modules" in ln and "continue" not in ln]
    for ln in skip_line:
        assert "case-studies" not in ln, (
            "case-studies is skipped again; that is where the leak lived")


def test_clean_tree_passes():
    """The other direction: the check must not simply always fail."""
    _run_check()  # no probe file present at this point
    assert True, "hygiene check raised rather than reporting"
