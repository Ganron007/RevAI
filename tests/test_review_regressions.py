#!/usr/bin/env python3
"""Regressions for defects found in the 2026-10-05 review of the last 9 commits.

Every test here pins a defect that EXISTED while the suite was green. They are
grouped by what the earlier tests got wrong, because that is the more useful
lesson than the individual bugs:

A unit test that exercises a helper is not evidence the entry point works.
`tests/test_light_steering.py` and `test_post_hoc_steering.py` called
`build_prompt` and passed 39/39 while `quick_scan_v2.main()` raised `NameError`
on its very first steering line -- `main()` has no local `sha`, and no test in
the tree called `main()`. So these tests exercise the CALLERS, or read the
source structurally, rather than only the helper.

A check that cannot fail is worse than no check. The skills layer shipped with
`load_skill` absent from the LangGraph tool list while the prompt told the model
to call it: on the default engine the call could never execute, and 668 tests
were green. The tripwire below is written so it FAILS when the name is missing.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

from _layout import resolve, source  # noqa: E402

import pytest  # noqa: E402

REPO = TESTS.parent


def _builtin_names() -> set[str]:
    """Assert-safe set of builtin names.

    `__builtins__` is the builtins *module* in a script but its `__dict__`
    in an imported module, and `vars()` on the module is fine while `vars()`
    on the dict is not. Handle both.
    """
    import builtins as _b  # noqa: PLC0415
    return set(dir(_b))


def _module_names(path: Path) -> set[str]:
    """Every name bound at module level, without descending into defs/classes."""
    names: set[str] = set()
    stack = list(ast.parse(path.read_text(encoding="utf-8")).body)
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
            continue
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                names.add(a.asname or a.name.split(".")[0])
            continue
        if isinstance(n, ast.Assign):
            for t in n.targets:
                for x in ast.walk(t):
                    if isinstance(x, ast.Name):
                        names.add(x.id)
            continue
        if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
            names.add(n.target.id)
            continue
        stack.extend(getattr(n, "body", None) or [])
        stack.extend(getattr(n, "orelse", None) or [])
        stack.extend(getattr(n, "finalbody", None) or [])
        for h in getattr(n, "handlers", None) or []:
            stack.extend(h.body)
    return names


def _locals_of(fn: ast.FunctionDef) -> set[str]:
    """Names bound inside `fn`, without descending into nested defs/classes.

    Nested scopes are deliberately NOT descended into: their names are not
    visible in the enclosing function, and treating them as bound is how the
    first version of this scan produced a page of false positives.
    """
    out: set[str] = {a.arg for a in fn.args.args}
    stack = list(getattr(fn, "body", None) or [])
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            out.add(n.id)
        elif isinstance(n, ast.arg):
            out.add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                out.add(a.asname or a.name.split(".")[0])
        elif isinstance(n, ast.ExceptHandler) and n.name:
            out.add(n.name)
        elif isinstance(n, ast.Global):
            out.update(n.names)
        elif isinstance(n, ast.Lambda):
            for a in n.args.args:
                out.add(a.arg)
            stack.extend(getattr(n.body, "body", None) or [])
            continue
        stack.extend(ast.iter_child_nodes(n))
    return out


# ===========================================================================
# A. P0 -- the stage entry point could not run at all
# ===========================================================================

STAGE_ENTRY_POINTS = [
    "revai/quick_scan_v2.py",
    "revai/deep_dive_agentic.py",
    "revai/audit_pipeline.py",
    "revai/publish_report_v2.py",
    "revai/section_publisher.py",
    "revai/yara_gen_v2.py",
    "revai/pipeline_single.py",
    "revai/depth_agent.py",
    "revai/winre_runner.py",
    "revai/agentic_recover_v4.py",
    "revai/artifact_gen.py",
]


@pytest.mark.parametrize("relpath", STAGE_ENTRY_POINTS)
def test_no_entry_point_reads_an_undefined_name(relpath):
    """A stage's `main()`/`_cli()` must not read a name it never bound.

    This is the test that was missing. `quick_scan_v2.main()` referenced `sha`
    on the line added for steering -- a name that only exists as a local of
    `build_prompt`. The stage reached that line after all the tool work had
    succeeded, wrote its artifacts, then died with NameError before any
    `llm_judge` call. `tests/test_light_steering.py` called `build_prompt`
    directly and passed, because the bug was never in `build_prompt`.

    The AST scan is structural on purpose: it does not need a sample, a session,
    a Ghidra server, or a VM, so it runs in every layout.
    """
    path = resolve(relpath)
    if not path.is_file():
        pytest.skip(f"{relpath} absent in this layout")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mod = _module_names(path)
    builtins_ = _builtin_names()
    problems: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in ("main", "_cli", "run"):
            continue
        bound = _locals_of(node) | mod | builtins_
        stack = list(getattr(node, "body", None) or [])
        while stack:
            sub = stack.pop()
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue  # a nested scope's names are not ours
            if (isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load)
                    and sub.id not in bound and sub.id not in ("self", "cls")):
                problems.append(f"{relpath}:{sub.lineno} `{node.name}` reads "
                                f"undefined name `{sub.id}`")
            stack.extend(ast.iter_child_nodes(sub))
    assert not problems, "undefined names in an entry point:\n  " + "\n  ".join(problems)


def test_quick_scan_steering_wiring_names_the_real_sha_variable():
    """The specific P0: main() must use args.sha256, not the bare name `sha`."""
    src = source("revai/quick_scan_v2.py")
    hits = [ln.strip() for ln in src.splitlines()
            if "effective_steering_note(case_dir(" in ln]
    assert hits, "the steering call site moved -- this test needs to move with it"
    for ln in hits:
        assert "sha)" not in ln or "args.sha256)" in ln, (
            f"case_dir(<bare sha>) is undefined in main(): {ln}")


def test_quick_scan_records_the_note_the_prompt_actually_used():
    """`steering.json` must carry the merged note, not only the L1 file.

    L3 notes reach the prompt through `effective_steering_note`, so an artifact
    that re-reads only the L1 file reports "" for a run that WAS steered, and the
    report then cites a direction the prompt never saw.
    """
    src = source("revai/quick_scan_v2.py")
    assert "record_steering(case_dir(args.sha256), _eff_note)" in src, (
        "record_steering must be given the same merged note the prompt used")
    assert "_eff_note = effective_steering_note(case_dir(args.sha256))" in src
    assert "steering=_eff_note," in src, (
        "the prompt must use the shared note, not re-resolve it")


# ===========================================================================
# B. P5 -- a note that was given but not delivered must not fall through
# ===========================================================================

@pytest.fixture()
def steering_mods():
    sys.modules.pop("steering", None)
    sys.modules.pop("steering_history", None)
    add = resolve("revai/steering.py").parent
    if str(add) not in sys.path:
        sys.path.insert(0, str(add))
    import steering  # noqa: PLC0415
    import steering_history as sh  # noqa: PLC0415
    yield steering, sh
    sys.modules.pop("steering", None)
    sys.modules.pop("steering_history", None)


def test_a_named_but_undelivered_note_does_not_substitute_a_stale_one(steering_mods, monkeypatch, tmp_path):
    """A typo'd REVAI_STEERING_FILE must leave the run with NO direction."""
    steering, sh = steering_mods
    case = tmp_path / "case"
    case.mkdir()
    sh.append_steering_note(case, "the post-hoc direction")

    monkeypatch.setenv("REVAI_STEERING_FILE", str(tmp_path / "notes.mdd"))
    assert steering.effective_steering_note(case) == "", (
        "a missing file fell through to the stale post-hoc note -- the run is "
        "steered by a direction the analyst already disagreed with")


def test_an_empty_note_file_does_not_substitute_a_stale_one(steering_mods, monkeypatch, tmp_path):
    steering, sh = steering_mods
    case = tmp_path / "case"
    case.mkdir()
    sh.append_steering_note(case, "the post-hoc direction")
    f = tmp_path / "notes.md"
    f.write_text("   \n\n", encoding="utf-8")
    monkeypatch.setenv("REVAI_STEERING_FILE", str(f))
    assert steering.effective_steering_note(case) == ""


def test_with_no_note_file_at_all_the_latest_post_hoc_note_still_applies(steering_mods, monkeypatch, tmp_path):
    steering, sh = steering_mods
    case = tmp_path / "case"
    case.mkdir()
    sh.append_steering_note(case, "the post-hoc direction")
    monkeypatch.delenv("REVAI_STEERING_FILE", raising=False)
    assert steering.effective_steering_note(case) == "the post-hoc direction"


def test_a_delivered_pre_run_note_still_wins(steering_mods, monkeypatch, tmp_path):
    steering, sh = steering_mods
    case = tmp_path / "case"
    case.mkdir()
    sh.append_steering_note(case, "the post-hoc direction")
    f = tmp_path / "notes.md"
    f.write_text("the pre-run direction", encoding="utf-8")
    monkeypatch.setenv("REVAI_STEERING_FILE", str(f))
    assert steering.effective_steering_note(case) == "the pre-run direction"


# ===========================================================================
# C. P4 -- the note history was destroyed, not preserved
# ===========================================================================

def test_an_unreadable_history_is_preserved_not_overwritten(steering_mods, tmp_path):
    _, sh = steering_mods
    case = tmp_path / "case"
    case.mkdir()
    store = case / "steering-history.json"
    store.write_text('[{"level":"L3","note":"CRITICAL: check the C2 beacon","at":"t"},',
                     encoding="utf-8")
    assert sh.read_steering_history(case) == []
    sh.append_steering_note(case, "a later note")
    preserved = list(case.glob("steering-history.json.corrupt-*"))
    assert preserved, "the unreadable store was overwritten -- every note lost"
    assert "CRITICAL: check the C2 beacon" in preserved[0].read_text(encoding="utf-8")


def test_concurrent_appends_do_not_lose_notes(steering_mods, tmp_path):
    _, sh = steering_mods
    case = tmp_path / "c"
    case.mkdir()
    errs: list[BaseException] = []

    def worker(i):
        try:
            sh.append_steering_note(case, f"note-{i}")
        except BaseException as exc:  # noqa: BLE001
            errs.append(exc)

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    hist = sh.read_steering_history(case)
    assert not errs, f"appends raised: {errs}"
    assert sorted(h["note"] for h in hist) == [f"note-{i}" for i in range(6)], (
        f"notes lost to a read-modify-write race: {sorted(h['note'] for h in hist)}")


def test_a_truncated_note_is_reported_not_silently_cut(steering_mods, tmp_path, capsys):
    _, sh = steering_mods
    case = tmp_path / "c"
    case.mkdir()
    sh.append_steering_note(case, "x" * 50000)
    err = capsys.readouterr().err
    assert "truncated" in err, "the note was silently cut to the cap"
    assert len(sh.read_steering_history(case)[0]["note"]) <= 8000


# ===========================================================================
# D. P2 -- the depth stage looked green while doing nothing
# ===========================================================================

def _import_depth():
    sys.modules.pop("depth_agent", None)
    add = resolve("revai/depth_agent.py").parent
    if str(add) not in sys.path:
        sys.path.insert(0, str(add))
    import depth_agent  # noqa: PLC0415
    return depth_agent


def test_depth_cli_resolves_a_sha_to_a_case_dir_and_fails_loudly_when_absent(capsys, tmp_path):
    """A sha passed to `depth_agent.py` must resolve, or exit 3 -- never rc=0
    with an empty map.

    The first wiring passed the sha as the positional argument to a CLI that
    treats its argument as a case directory: `load_state(Path(sha))` read
    `<cwd>/<sha>/understanding.json`, which never exists, so the stage reported
    `{"regions_total": 0}` and rc=0. That is indistinguishable in the trace from
    "the sample has no functions".
    """
    da = _import_depth()
    rc = da._cli.__wrapped__ if hasattr(da._cli, "__wrapped__") else None
    # invoke the CLI the way the stage does
    argv = sys.argv
    sys.argv = ["depth_agent.py", "f" * 64]
    try:
        out = capsys.readouterr()
        rc = da._cli()
    finally:
        sys.argv = argv
    err = capsys.readouterr()
    assert rc == 3, f"a sha with no case dir must fail loudly, got rc={rc}"
    assert "not found" in (err.out + err.err), err


def test_depth_cli_reports_a_real_case_dir(capsys, tmp_path, monkeypatch):
    da = _import_depth()
    case = tmp_path / "case"
    case.mkdir()
    (case / "understanding.json").write_text(
        json.dumps({"sha256": "a" * 64, "regions": {}, "spend": {}}), encoding="utf-8")
    argv = sys.argv
    sys.argv = ["depth_agent.py", str(case)]
    try:
        rc = da._cli()
        out = capsys.readouterr().out
    finally:
        sys.argv = argv
    assert rc == 0
    data = json.loads(out)
    assert data["case_dir"] == str(case)
    assert data["regions_total"] == 0
    assert data["converged"] is False


def test_depth_stage_runs_last_after_the_audit():
    """Depth mode is post-pipeline: its starting context is the whole pipeline.

    Appending it after deep_dive put a stage with a 2-hour default ceiling in
    front of yara_gen, publish_v2, publish_v3 and audit -- delaying the reports
    a human waits for, and starting the loop before iocs.json or any report
    exists to read.

    Asserted on the VALUE `build_stages()` returns, not on where a literal
    appears in the file. The first version checked source positions, and a
    mutation to `stages.insert(1, ...)` -- which puts depth FIRST at runtime --
    left every literal in exactly the same place, so the test stayed green.
    """
    from pipeline_single import build_stages
    os.environ["REVAI_DEPTH"] = "1"
    os.environ.pop("REVAI_WINRE_RUN", None)
    try:
        names = [s[0] for s in build_stages("a" * 64, None)]
    finally:
        os.environ.pop("REVAI_DEPTH", None)
    assert names.index("depth_understanding") == len(names) - 1, (
        f"depth_understanding must be the LAST stage, got order: {names}")
    for must_precede in ("yara_gen", "publish_v2", "publish_v3", "audit"):
        assert names.index(must_precede) < names.index("depth_understanding"), (
            f"{must_precede} runs after depth_understanding -- depth mode must "
            f"follow the pipeline it claims to understand: {names}")


def test_the_default_spine_is_the_static_only_order():
    """With no flags the pipeline is byte-for-byte the historical order."""
    from pipeline_single import build_stages
    for var in ("REVAI_WINRE_RUN", "REVAI_DEPTH",
               "REVAI_ENABLE_AGENTIC_RECOVERY", "ENABLE_AGENTIC_RECOVERY",
               "REVAI_ENABLE_ARTIFACT_GEN"):
        os.environ.pop(var, None)
    names = [s[0] for s in build_stages("a" * 64, None)]
    assert names == ["quick_scan", "deep_dive", "yara_gen",
                     "publish_v2", "publish_v3", "audit"], names


def test_the_winre_reorder_puts_detonation_before_the_deep_dive():
    """R1: triage -> dynamic -> deep_dive, so the dive can ingest the pack."""
    from pipeline_single import build_stages
    os.environ["REVAI_WINRE_RUN"] = "1"
    os.environ.pop("REVAI_DEPTH", None)
    try:
        names = [s[0] for s in build_stages("a" * 64, None)]
    finally:
        os.environ.pop("REVAI_WINRE_RUN", None)
    assert names.index("winre_dynamic") < names.index("deep_dive"), names
    assert names.index("deep_dive") < names.index("yara_gen"), names


def test_depth_uses_the_shared_helpers_not_inline_copies():
    """A second copy of the ceiling parse is a second thing that can disagree."""
    src = source("revai/pipeline_single.py")
    assert "depth_enabled()" in src, "pipeline_single should ask depth_agent whether depth is on"
    assert "depth_ceiling_seconds()" in src
    assert "REVAI_DEPTH_CEILING_SECONDS\", \"7200\"" not in src, (
        "the inline ceiling parse is back -- it raises ValueError on a "
        "non-numeric value where the helper falls back")


def test_a_malformed_status_is_not_silently_dropped():
    """A status outside the vocabulary must not vanish from both sets.

    `unknown_set` and `cost_summary` used membership in fixed vocabularies, so a
    typo'd status was excluded from the unknown set (a loop would terminate with
    the region never understood) AND from the counts (regions_total
    under-counted). Only has_converged noticed, and nothing called it.
    """
    da = _import_depth()
    regions = {"good": {"status": "understood"},
               "typo": {"status": "undrestoed"},
               "open": {"status": "not-explored"}}
    assert da.unrecognised_statuses(regions) == ["typo"]
    assert "typo" in da.unknown_set(regions)
    assert da.has_converged(regions) is False
    summary = da.cost_summary(regions, {})
    assert summary["regions_total"] == 3, summary
    assert summary["malformed_status"] == 1, summary
    assert summary["unknown_remaining"] == 2, summary


# ===========================================================================
# E. load_skill was unreachable on the DEFAULT engine
# ===========================================================================

def test_load_skill_is_bound_to_the_langgraph_agent():
    """The tool the prompt names must be a tool the graph can execute.

    `deep_dive_agentic` defaults to REVAI_AGENTIC_ENGINE=langgraph, whose
    inventory is built from AGENT_TOOL_NAMES. load_skill was in the registry and
    in the prompt ("the procedures below are loaded with the load_skill tool")
    but NOT in that list: on the default engine the model's call could not
    execute, so the procedure never arrived and the agent fell back to recall --
    exactly what the skills layer exists to prevent. 14 of 26 tools are visible
    there; a missing one must fail loudly, because every one of them is silent.
    """
    src = source("revai/agentic_langgraph.py")
    tree = ast.parse(src)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "AGENT_TOOL_NAMES":
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            names.add(sub.value)
    assert names, "AGENT_TOOL_NAMES not found or empty -- the probe is broken"
    assert "load_skill" in names, (
        "load_skill is not bound to the LangGraph agent: the prompt instructs "
        "the model to call it and the graph cannot execute it")


def test_every_tool_the_deep_dive_prompt_names_is_bound_to_the_agent():
    """The prompt's instruction list and the graph's tool list must agree."""
    dd = source("revai/deep_dive_agentic.py")
    lg = source("revai/agentic_langgraph.py")
    named = {t for t in ("load_skill", "api_lookup", "compare_files")
             if f"`{t}`" in dd or f'"{t}": self.' in dd}
    bound: set[str] = set()
    tree = ast.parse(lg)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "AGENT_TOOL_NAMES":
                    for sub in ast.walk(node.value):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            bound.add(sub.value)
    missing = sorted(named - bound)
    assert not missing, (
        f"the prompt tells the model to call {missing} but the agent graph does "
        "not bind them -- the call is consumed and the work is never done")


def test_a_skill_is_not_truncated_by_the_shared_tool_result_cap():
    """A procedure must arrive whole, or its stop conditions are what is cut.

    Asserted on the cap the tool ACTUALLY uses, not merely on the constant's
    existence. A test that only checks `TOOL_RESULT_CHARS = { ... }` stays green
    while `_cap = max_chars` makes the dict dead.
    """
    import re as _re
    lg = source("revai/agentic_langgraph.py")
    # the per-tool lookup must be live in the runner
    assert "TOOL_RESULT_CHARS.get(name, max_chars)" in lg, (
        "load_skill must have its own result cap: a skill is a procedure "
        "document, and the shared 2000-char cap cuts the 'Stop conditions' and "
        "'What this skill does NOT cover' sections -- and for "
        "verdict-calibration, the calibration contract itself")
    assert "_truncate(json.dumps(result, default=str), _cap)" in lg
    m = _re.search(r'TOOL_RESULT_CHARS\s*=\s*\{[^}]*"load_skill":\s*(\d+)', lg)
    assert m, "could not read load_skill's cap"
    assert int(m.group(1)) > 2000, (
        "load_skill's cap must exceed the shared 2000-char budget or the "
        "procedure is cut to 42-60% of its text")


def test_a_skill_result_actually_gets_its_larger_cap():
    """Behavioural: the largest skill must not be cut at the shared 2000.

    Reads the skill files through skills.py so the numbers are real, then
    asserts the cap the agent assigns to load_skill is above the longest body.
    """
    lg = source("revai/agentic_langgraph.py")
    import re as _re
    m = _re.search(r'TOOL_RESULT_CHARS\s*=\s*\{[^}]*"load_skill":\s*(\d+)', lg)
    if not m:
        pytest.skip("load_skill cap moved shape")
    cap = int(m.group(1))
    sys.path.insert(0, str(resolve("revai/skills.py").parent))
    sys.modules.pop("skills", None)
    import skills as skills_mod  # noqa: PLC0415
    bodies = []
    for name in skills_mod.list_skills():
        try:
            bodies.append(len(skills_mod.load_skill(name).get("text", "")))
        except Exception:  # pragma: no cover - a corrupt skill is not this test
            continue
    assert bodies, "no skills found -- the probe cannot tell whether the cap is enough"
    longest = max(bodies)
    assert cap >= longest, (
        f"load_skill's cap ({cap}) is below the longest skill body ({longest}): "
        "the procedure is truncated on every load")


def test_the_deep_dive_prompt_names_load_skill_with_its_args():
    src = source("revai/deep_dive_agentic.py")
    assert "load_skill" in src
    # the tool must be registered in the custom registry too
    assert '"load_skill": self._load_skill' in src, (
        "the custom engine lost its load_skill registration")


# ===========================================================================
# F. R1 -- the dynamic pack was computed and discarded
# ===========================================================================

def test_the_dynamic_pack_reaches_the_deep_dive_prompt():
    """Ingestion must put the pack where the model reads it.

    The first version computed `block`, kept `len(block)`, and discarded the
    text: `05-deep-dive.json` recorded `{"chars": 4200}` and the log line said
    "ingested", while nothing in the prompt contained one observed domain. R1's
    stated purpose -- "deep_dive reads it" -- was unfulfilled, and the artifact
    claimed otherwise.
    """
    dd = source("revai/deep_dive_agentic.py")
    assert '"evidence_text": block' in dd, (
        "the dynamic block must be carried on the history entry the prompt "
        "renders, not only counted")
    assert 'if isinstance(h, dict) and h.get("evidence_text")' in dd, (
        "build_messages must render evidence_text observations")
    assert "DYNAMIC_EVIDENCE_CHARS" in dd


def _import_dda():
    sys.modules.pop("deep_dive_agentic", None)
    add = resolve("revai/deep_dive_agentic.py").parent
    if str(add) not in sys.path:
        sys.path.insert(0, str(add))
    import deep_dive_agentic as dda  # noqa: PLC0415
    return dda


def _prompt(dda, history):
    sess = {"sample_path": "/tmp/s.exe", "file_type": {"format": "PE32"},
            "sha256": "a" * 64}
    return dda.build_messages(sess, 3, 10, history, {"capa": {"a": 1}},
                              {}, ["- ghidra_query"], "PE32")[1]["content"]


def _findings_of(text):
    i = text.index("Current findings:\n")
    return text[i:text.index("\n\n", i)]


def test_a_dynamic_pack_does_not_move_the_findings_truncation_boundary():
    """A pack must not shift the findings boundary.

    `findings` is serialised under MAX_FINDINGS_CHARS (4000). Storing the block
    there meant (a) a real pack was always cut away entirely, and (b) the chars
    it added moved the truncation boundary, silently dropping the same number of
    chars out of some OTHER finding -- so a pack-present run differed from a
    pack-absent one in a way the reader could not see, breaking the block's own
    "presence-gated: no pack, no change" claim.

    Asserted behaviourally, not by matching source text: the rendered prompt is
    the thing that has to stay identical.
    """
    dda = _import_dda()
    base_hist = [{"step": 1, "tool": "ghidra_query", "args": {}, "reason": "entry",
                  "result": {"rows": []}, "error": None}]
    pack_hist = base_hist + [{
        "step": 2, "tool": "winre_dynamic_pack", "args": {}, "reason": "pack",
        "result": {}, "error": None,
        "evidence_text": "## Dynamic Corroboration (WinRE detonation)\n\n"
                         "- **domains**: `evil1.biz`, `evil2.biz`\n",
    }]
    base, packed = _prompt(dda, base_hist), _prompt(dda, pack_hist)
    assert _findings_of(base) == _findings_of(packed), (
        "the findings text moved when the pack was added -- another finding "
        "lost characters to the truncation boundary")
    # and the pack content must be present, intact, in the packed prompt
    assert "evil1.biz" in packed, "the pack never reached the model"
    assert "evil1.biz" not in base, "the pack leaked into the static prompt"


def test_a_failed_pack_ingest_is_visible_to_the_model():
    dd = source("revai/deep_dive_agentic.py")
    assert "[ERR: " in dd, (
        "a bare [ERR] tells the model a step failed but not why, so it cannot "
        "tell 'no pack exists' from 'the pack exists and could not be read'")


def test_the_dynamic_opt_out_is_one_shared_definition():
    """A second copy of the falsy tuple is a second thing that can drift.

    Checked by AST on the FUNCTION BODY, not by substring: the docstring of
    `_dynamic_pack_evidence_text` names the helper, so a substring check stays
    green when the guard itself has been deleted. This failing that way is
    exactly how the guard was shipped unusable in the first place.
    """
    src = source("revai/v2_lib.py")
    readers = [ln for ln in src.splitlines()
               if '"REVAI_DISABLE_DYNAMIC_CORROBORATION"' in ln]
    assert len(readers) == 1, (
        f"the opt-out env var is read in {len(readers)} places: {readers}")
    assert "not dynamic_corroboration_enabled()" in src, (
        "winre_dynamic_status should defer to the shared helper")

    rq_path = resolve("revai/report_quality.py")
    rq_src = rq_path.read_text(encoding="utf-8")
    tree = ast.parse(rq_src)
    called = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name != "_dynamic_pack_evidence_text":
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id == "dynamic_corroboration_enabled"):
                called = True
    assert called, (
        "_dynamic_pack_evidence_text must DEFER to the shared opt-out: without "
        "it, a run with REVAI_DISABLE_DYNAMIC_CORROBORATION=1 still grounds "
        "claims against the pack while the published report shows no dynamic "
        "block -- a claim certified 'verified' against a source the reader "
        "cannot see")


# ===========================================================================
# G. the UI and the stages must agree on the case directory
# ===========================================================================

def test_api_steer_resolves_the_same_case_dir_the_stage_will_use():
    """P1: the app process and the stage process resolved different dirs.

    The app has no REVAI_RUN_MODE, so `case_dir(sha)` resolved to
    `logs/<sha>`; each stage gets REVAI_RUN_MODE=ui from get_stage_env, so the
    same call resolved to `logs/<sha>/ui`. A note recorded in one place was
    invisible to the re-run it was written for, and the UI showed it as
    recorded. Both sides were correct uses of case_dir(), which is exactly why
    no structural check caught it.
    """
    app = source("revai/app.py")
    assert "case_dir(sha, mode=run_mode_for(sha))" in app, (
        "api_steer must resolve the case dir with the mode the stage will use")
    for ln in app.splitlines():
        if '"REVAI_RUN_MODE"' in ln and ":" in ln and '"ui"' in ln:
            assert "run_mode_for(" in ln, (
                f"the run mode is defined in two places again: {ln.strip()}")


def test_run_mode_for_and_get_stage_env_agree():
    app = source("revai/app.py")
    assert "def run_mode_for(" in app
    assert "run_mode_for(rc)" in app, (
        "get_stage_env must take the mode from the shared helper")
