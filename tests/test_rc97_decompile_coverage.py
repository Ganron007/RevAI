"""RC-97 / A1 (2026-11-21, operator: "are we even deciphering every piece of
code within the PE?"): the SAMPLE's functions are decompiled under an
explicit budget, walking malcat's own relevance-ranked list, with a coverage
record and citable rows.

Before this change the decompile loop took the FIRST `decompile_top_n`
functions of the ranked list (1 triage / 3 deep) -- the sample's code was
sampled, not deciphered, and no gate measured it. The budget now defaults ON
(100 functions / 1200 s), the enumeration is raised to cover the budget,
every skip is recorded with its reason, and the decompiled rows are citable
via `malcat.decompilation_rows` in the section manifests.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "revai"))

import v2_lib  # noqa: E402


class _FakeMalcatCLI:
    """Scripted fns_top_list + fn_decompile responses."""

    def __init__(self, n_functions: int, fail_eas: set[int] | None = None,
                 slow: bool = False):
        self.n = n_functions
        self.fail_eas = fail_eas or set()
        self.slow = slow
        self.decompile_calls: list[int] = []

    def call_tool(self, tool: str, arguments: dict):
        if tool == "analyse_file":
            return {"analysis_id": "A1", "functions_total": self.n}
        if tool == "fns_top_list":
            return [{"ea": 1000 + i, "name": f"sub_{1000 + i}"}
                    for i in range(self.n)]
        if tool == "fn_decompile":
            ea = arguments["ea"]
            self.decompile_calls.append(ea)
            if ea in self.fail_eas:
                raise RuntimeError("decompile boom")
            return f"int sub_{ea}(void) {{ return {ea}; }}"
        if tool == "anomalies_list":
            return []
        return None


@pytest.fixture()
def fake_cli_cls(monkeypatch):
    holders = {}

    def install(cli: _FakeMalcatCLI, **_kw):
        holders["cli"] = cli

        class _FakeCls:
            def __init__(self, *a, **k):
                pass

            def __enter__(self):
                return cli

            def __exit__(self, *a):
                return False

            def close(self):
                pass

            def call_tool(self, tool, arguments):
                return cli.call_tool(tool, arguments)

        monkeypatch.setattr(v2_lib, "McpJsonClient", _FakeCls)
        return cli

    return install


BASE_VIEWS = ["functions", "decompile"]


def test_budget_default_decompiles_beyond_the_profile_cap(
        fake_cli_cls, monkeypatch):
    """Deep profile top_n=3; the budget default (100) must walk past it."""
    monkeypatch.delenv("REVAI_DECOMPILE_MAX_FUNCS", raising=False)
    cli = fake_cli_cls(_FakeMalcatCLI(8))
    out = v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS,
                                profile="deep")
    cov = out.get("decompile_coverage") or {}
    assert cov.get("decompiled") == 8, (
        "the budget default must cover ALL enumerated functions")
    assert cov.get("skipped_cap") == 0 and cov.get("skipped_budget") == 0
    assert len(out.get("decompilation_rows") or []) == 8


def test_env_cap_stops_with_a_recorded_reason(fake_cli_cls, monkeypatch):
    monkeypatch.setenv("REVAI_DECOMPILE_MAX_FUNCS", "2")
    cli = fake_cli_cls(_FakeMalcatCLI(8))
    out = v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS,
                                profile="deep")
    cov = out.get("decompile_coverage") or {}
    assert cov.get("decompiled") == 2
    assert cov.get("skipped_cap") == 6, (
        "every skipped function is recorded with its reason")
    assert len(cli.decompile_calls) == 2


def test_wall_clock_deadline_stops_gracefully(fake_cli_cls, monkeypatch):
    monkeypatch.setenv("REVAI_DECOMPILE_BUDGET_S", "30")
    cli = fake_cli_cls(_FakeMalcatCLI(50), slow=True)
    out = v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS,
                                profile="deep")
    cov = out.get("decompile_coverage") or {}
    assert cov.get("attempted") == cov.get("decompiled"), (
        "no function may be half-attempted")
    assert cov.get("decompiled") >= 1, "at least one row before the deadline"


def test_enumeration_covers_the_budget(fake_cli_cls, monkeypatch):
    """`functions_max` (deep: 30) must be raised to the decompile budget --
    malcat's ranked list cannot hide the rows the budget is meant to reach."""
    seen = {}

    class _Recording(_FakeMalcatCLI):
        def call_tool(self, tool, arguments):
            if tool == "fns_top_list":
                seen["max"] = arguments.get("maximum_number_of_functions")
            return super().call_tool(tool, arguments)

    monkeypatch.setenv("REVAI_DECOMPILE_MAX_FUNCS", "100")
    fake_cli_cls(_Recording(0))
    v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS, profile="deep")
    assert seen.get("max") == 100, (
        "the enumeration must cover the decompile budget, not the profile cap")


def test_failed_decompiles_are_recorded_not_fatal(fake_cli_cls):
    cli = fake_cli_cls(_FakeMalcatCLI(4, fail_eas={1001, 1002}))
    out = v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS,
                                profile="deep")
    cov = out.get("decompile_coverage") or {}
    assert cov.get("decompiled") == 2 and cov.get("failed") == 2
    assert any("fn_decompile(1001)" in e for e in out.get("errors") or [])


def test_decompilation_rows_are_manifest_citable(fake_cli_cls, monkeypatch):
    sha = "d" * 64
    monkeypatch.setenv("REVAI_RUN_MODE", "agentic")
    monkeypatch.setattr(v2_lib, "LOGS_DIR", Path(str(ROOT)) / "nonexistent-logs")
    cli = fake_cli_cls(_FakeMalcatCLI(3))
    out = v2_lib.malcat_analyze("/x/sample.vir", views=BASE_VIEWS,
                                profile="deep")
    assert out.get("decompilation_rows")
    # the row source is registered for the static-analysis sections
    srcs = dict(v2_lib.SECTION_ROW_SOURCES).get(
        "4. Static Code Analysis") or ()
    assert any("malcat.decompilation_rows" in s[1] for s in srcs), (
        "the writer can only cite rows the manifest carries")
