#!/usr/bin/env python3
"""Pipeline verification harness (read-only, stdlib only).

Answers "is the pipeline wired the way we designed it?" with checks that fail
loudly instead of silently drifting. Every check is deterministic and
side-effect free; run it in the repo (source layout) or on the VM (flat layout).

    python3 verify_pipeline.py            # human output, exit 1 on failure
    python3 verify_pipeline.py --json     # machine output

Checks
  1. syntax          every Python file compiles
  2. registry        TOOL_MANIFEST <-> real functions, ToolRegistry <->
                     TOOL_DESCRIPTIONS, LangGraph tool list <- ToolRegistry
  3. docs counts     README / architecture / tool-stack / SVGs agree with code
  4. hygiene         no private-repo references, lab IPs, model names, secrets
  5. regression      the tests that guard past regressions are present
  6. env contract    REVAI_* names documented vs referenced in code
"""

from __future__ import annotations

import argparse
import json
import py_compile
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent if (HERE.parent / "assets").is_dir() else HERE
#: On the VM the flat runtime dir is both "code" and "root".
CODE = HERE

FAILURES: list[str] = []
WARNINGS: list[str] = []
RESULTS: list[dict] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    if not ok:
        FAILURES.append(f"{name}: {detail}")
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""))


def warn(name: str, detail: str) -> None:
    WARNINGS.append(f"{name}: {detail}")
    RESULTS.append({"check": name, "ok": True, "detail": detail, "warning": True})
    print(f"[WARN] {name} - {detail}")


# --- 1. syntax -------------------------------------------------------------


def check_syntax() -> None:
    files = sorted(CODE.glob("*.py"))
    bad: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        for path in files:
            try:
                py_compile.compile(str(path), cfile=str(Path(tmp) / (path.stem + ".pyc")),
                                   doraise=True)
            except py_compile.PyCompileError as exc:
                bad.append(f"{path.name}: {str(exc).splitlines()[-1][:120]}")
    check("syntax", not bad, f"{len(files)} files" if not bad else "; ".join(bad[:4]))


# --- 2. registry coherence -------------------------------------------------


def _read(name: str) -> str:
    return (CODE / name).read_text(encoding="utf-8", errors="replace")


def check_registry() -> None:
    v2 = _read("v2_lib.py")
    manifest_block = v2[v2.find("TOOL_MANIFEST = {"):]
    entries = re.findall(r'^    "([A-Za-z0-9_]+)": \{\n(.*?)^    \},',
                         manifest_block, re.M | re.S)
    manifest = {name: body for name, body in entries}
    missing_fn = []
    for name, body in manifest.items():
        fn = re.search(r'"fn": "([A-Za-z0-9_]+)"', body)
        if not fn or f"def {fn.group(1)}(" not in v2:
            missing_fn.append(f"{name}->{fn.group(1) if fn else '?'}")
    check("manifest.fn", not missing_fn,
          f"{len(manifest)} manifest tools" if not missing_fn
          else f"missing callables: {', '.join(missing_fn[:5])}")

    dd = _read("deep_dive_agentic.py")
    reg_block = dd[dd.find("class ToolRegistry"):]
    registry = re.findall(r'"([A-Za-z0-9_]+)": self\.', reg_block[:3000])
    desc_block = dd[dd.find("TOOL_DESCRIPTIONS"):]
    descriptions = re.findall(r'^    "([A-Za-z0-9_]+)": "', desc_block[:9000], re.M)
    undescribed = sorted(set(registry) - set(descriptions))
    check("registry.descriptions", not undescribed,
          f"{len(registry)} agent tools" if not undescribed
          else f"no description: {', '.join(undescribed)}")
    phantom = sorted(set(descriptions) - set(registry))
    check("registry.no_phantom_descriptions", not phantom,
          "descriptions match registry" if not phantom
          else f"described but not callable: {', '.join(phantom)}")

    lg = _read("agentic_langgraph.py")
    names_block = lg[lg.find("AGENT_TOOL_NAMES"):]
    names = re.findall(r'^    "([A-Za-z0-9_]+)",$', names_block[:1200], re.M)
    unknown = sorted(set(names) - set(registry))
    check("langgraph.tools_exist", not unknown,
          f"{len(names)} langgraph tools" if not unknown
          else f"not in ToolRegistry: {', '.join(unknown)}")

    # Tools that exist only to be called by the agent must be reachable in the
    # default (LangGraph) engine, otherwise they are dead weight.
    agent_only = {"api_lookup", "compare_files"}
    unreachable = sorted(agent_only - set(names))
    check("langgraph.agent_only_reachable", not unreachable,
          "api_lookup + compare_files exposed" if not unreachable
          else f"missing from AGENT_TOOL_NAMES: {', '.join(unreachable)}")

    # Regression guards shipped with fixes
    guarded = {
        "tests/test_pe_parser.py": ["image_base", "NumberOfRvaAndSizes", "imports"],
        "tests/test_yara_gen_rule.py": ["rule"],
        "tests/test_dynamic_pack.py": ["pack"],
        "tests/test_report_alignment.py": ["dynamic", "gap"],
        "tests/test_report_sections.py": ["component", "mbc"],
        "tests/test_ioc_confidence.py": ["tier"],
        "tests/test_report_fact_check.py": ["unverified"],
        "tests/test_agent_observability.py": ["stream"],
    }
    tests_dir = REPO / "tests" if (REPO / "tests").is_dir() else CODE / "tests"
    absent, thin = [], []
    for rel, tokens in guarded.items():
        path = tests_dir / rel.split("/")[-1]
        if not path.is_file():
            absent.append(rel.split("/")[-1])
            continue
        text = path.read_text(encoding="utf-8", errors="replace").lower()
        if not any(t.lower() in text for t in tokens):
            thin.append(rel.split("/")[-1])
    check("regression.guards_present", not absent and not thin,
          f"{len(guarded)} guard files present" if not (absent or thin)
          else f"missing={absent} thin={thin}")


# --- 3. docs counts --------------------------------------------------------


def _nums(pattern: str, text: str) -> set[int]:
    return {int(m) for m in re.findall(pattern, text, re.I)}


_MANIFEST_PATTERNS = (
    r"Tool Stack \((\d+) tools\)",
    r"(\d+) format-aware manifest tools",
    r"(\d+) tools automatically",
    r"the (\d+)-tool manifest",
    r"\((\d+) tools\)",
)
_AGENT_PATTERNS = (
    r"(\d+) agent-callable",
    r"(\d+) RE tools",
)


def check_docs_counts() -> None:
    v2 = _read("v2_lib.py")
    manifest_block = v2[v2.find("TOOL_MANIFEST = {"):]
    n_manifest = len(re.findall(r'^    "([A-Za-z0-9_]+)": \{\n(.*?)^    \},',
                                manifest_block, re.M | re.S))
    dd = _read("deep_dive_agentic.py")
    reg_block = dd[dd.find("class ToolRegistry"):]
    n_agent = len(re.findall(r'"([A-Za-z0-9_]+)": self\.', reg_block[:3000]))

    docs = {
        "README.md": REPO / "README.md",
        "docs/tool-stack.md": REPO / "docs" / "tool-stack.md",
        "docs/architecture.md": REPO / "docs" / "architecture.md",
        "docs/img/architecture_v2.svg": REPO / "docs" / "img" / "architecture_v2.svg",
        "assets/revai-architecture.svg": REPO / "assets" / "revai-architecture.svg",
    }
    present = {k: p for k, p in docs.items() if p.is_file()}
    if not present:
        warn("docs.counts", "not in a source checkout (flat VM layout) - skipped")
        return

    problems: list[str] = []
    for name, path in present.items():
        text = path.read_text(encoding="utf-8", errors="replace")
        found_manifest: set[int] = set()
        for pattern in _MANIFEST_PATTERNS:
            found_manifest |= _nums(pattern, text)
        for value in sorted(v for v in found_manifest if v != n_manifest):
            problems.append(f"{name}: manifest count {value} != {n_manifest}")
        found_agent: set[int] = set()
        for pattern in _AGENT_PATTERNS:
            found_agent |= _nums(pattern, text)
        for value in sorted(v for v in found_agent if v != n_agent):
            problems.append(f"{name}: agent tool count {value} != {n_agent}")
    check("docs.counts", not problems,
          f"manifest={n_manifest} agent={n_agent}" if not problems
          else "; ".join(problems[:4]))


# --- 4. hygiene ------------------------------------------------------------

_FORBIDDEN = (
    "Integrations", "revai_tools/", "REVAI_TOOLS_DIR", "192.168.77.41",
)
_MODEL_NAMES = ("stepfun", "step-3", "step-5", "mimo", "deepseek", "gpt-4",
                "claude-", "qwen")
_SECRET_VALUE_RE = re.compile(r"(?:API_KEY|TOKEN|SECRET|PASSWORD)\s*[=:]\s*(\S+)", re.I)
_PLACEHOLDER_RE = re.compile(r"[<>${}%]|^$|your|example|placeholder|redacted|<|xxx", re.I)


def _looks_like_secret(value: str) -> bool:
    """A literal secret, not a placeholder, template or code expression."""
    if len(value) < 20 or _PLACEHOLDER_RE.search(value):
        return False
    if value.startswith(("os.environ", "os.getenv", "\"", "'", "f\"")):
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_\-\.+/=]+", value))


def check_hygiene() -> None:
    if not (REPO / "docs").is_dir():
        warn("hygiene", "no docs dir (flat VM layout) - skipped")
        return
    bad: list[str] = []
    scanned = 0
    # Local-only, gitignored files document these audit rules themselves and are
    # never published, so they are excluded from the published-content scan. The
    # harness itself necessarily contains the forbidden tokens as its patterns.
    skip_names = {"AGENTS.md", "CHANGELOG.md", "verify_pipeline.py"}
    for path in REPO.rglob("*"):
        if not path.is_file() or path.suffix not in (".py", ".md", ".svg", ".sh", ".json"):
            continue
        if any(part in ("node_modules", ".git", "case-studies", "internal")
               for part in path.parts):
            continue
        if path.name in skip_names:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        scanned += 1
        rel = path.relative_to(REPO)
        for token in _FORBIDDEN:
            if token in text:
                bad.append(f"{rel}: {token}")
        if path.suffix == ".md" and "docs/" in str(rel):
            for token in _MODEL_NAMES:
                if token.lower() in text.lower():
                    bad.append(f"{rel}: model name '{token}'")
        for match in _SECRET_VALUE_RE.finditer(text):
            if _looks_like_secret(match.group(1)):
                bad.append(f"{rel}: possible secret")
    check("hygiene", not bad,
          f"{scanned} files scanned" if not bad else "; ".join(bad[:4]))


# --- 5. env contract -------------------------------------------------------

#: Documented but intentionally deploy-time/ops-only (not read by Python).
_ENV_ALLOWLIST = {
    "REVAI_FORCE_API_INDEX", "REVAI_HOME", "REVAI_LLM_TIMEOUT",
    "REVAI_PROGRESS_STREAM_SECONDS", "REVAI_IOC_FACTCHECK",
    "REVAI_DISABLE_IOC_CONFIDENCE", "REVAI_DISABLE_DYNAMIC_SECTION",
    "REVAI_DISABLE_GAP_SECTION", "REVAI_WINRE_LOGS",
    # Written by the sync/deploy step (provenance), not a user knob.
    "REVAI_COMMIT",
    # Runtime layout / set automatically by the Console at launch, not user knobs.
    "REVAI_HOME", "REVAI_LLM_MODEL_REQUESTED",
}


def check_env_contract() -> None:
    docs_dir = REPO / "docs"
    if not docs_dir.is_dir():
        return
    documented: set[str] = set()
    for path in list(docs_dir.glob("*.md")) + [REPO / "README.md"]:
        if path.is_file():
            documented |= set(re.findall(r"REVAI_[A-Z_]+", path.read_text(
                encoding="utf-8", errors="replace")))
    in_code: set[str] = set()
    # Only actual environment lookups count - literal marker strings such as
    # r2backend's REVAI_MARK_* are data, not configuration.
    lookup_re = re.compile(
        r"os\.environ(?:\.get)?[\(\[]\s*[\"'](REVAI_[A-Z_]+)[\"']"
        r"|os\.getenv\(\s*[\"'](REVAI_[A-Z_]+)[\"']")
    for path in CODE.glob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in lookup_re.finditer(text):
            name = match.group(1) or match.group(2)
            if name:
                in_code.add(name)
    undocumented = sorted(in_code - documented - _ENV_ALLOWLIST)
    check("env.documented", not undocumented,
          f"{len(in_code)} env vars in code" if not undocumented
          else f"read by code but not documented: {', '.join(undocumented[:6])}")


# --- main ------------------------------------------------------------------


def run_checks() -> tuple[list[dict], list[str], list[str]]:
    """Run every check; returns (results, failures, warnings)."""
    RESULTS.clear()
    FAILURES.clear()
    WARNINGS.clear()
    check_syntax()
    check_registry()
    check_docs_counts()
    check_hygiene()
    check_env_contract()
    return RESULTS, FAILURES, WARNINGS


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RevAI pipeline verification harness")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    print(f"layout={'source' if (REPO / 'docs').is_dir() else 'flat'} root={REPO}")
    results, failures, warnings = run_checks()

    failed = [r for r in results if not r["ok"]]
    if args.json:
        print(json.dumps({"root": str(REPO), "results": results,
                          "failures": failures, "warnings": warnings}, indent=2))
    print()
    print(f"{len(results) - len(failed)}/{len(results)} checks passed, "
          f"{len(failures)} failure(s), {len(warnings)} warning(s)")
    for item in failures:
        print(f"  FAIL {item}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
