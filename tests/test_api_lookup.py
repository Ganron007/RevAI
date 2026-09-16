"""Tests for the offline Windows-API lookup index (build + runtime)."""

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "revai"))

import api_lookup  # noqa: E402
import api_index_build  # noqa: E402


def _find_malapi() -> Path:
    """Locate the bundled snapshot in both layouts.

    Repo checkout: ``<repo>/assets/api_index/malapi.json``.
    VM runtime:    ``/opt/revai/api_index/malapi.json`` (deploy.sh installs it).
    """
    for candidate in (
        REPO / "assets" / "api_index" / "malapi.json",
        Path("/opt/revai/api_index/malapi.json"),
    ):
        if candidate.is_file():
            return candidate
    return REPO / "assets" / "api_index" / "malapi.json"


MALAPI = _find_malapi()


# --- name folding ---------------------------------------------------------


def test_canonical_folds_charset_zw_and_decoration():
    assert api_lookup.canonical("CreateProcessW") == "createprocess"
    assert api_lookup.canonical("CreateProcessA") == "createprocess"
    assert api_lookup.canonical("ZwOpenProcess") == "ntopenprocess"
    assert api_lookup.canonical("__imp_CreateFileW") == "createfile"
    assert api_lookup.canonical("_VirtualAllocEx@20") == "virtualallocex"
    # `Ex` is a different function and must never collapse.
    assert api_lookup.canonical("VirtualAlloc") != api_lookup.canonical("VirtualAllocEx")
    # All-caps acronym ending in A/W is not a charset variant.
    assert api_lookup.canonical("RSA") == "rsa"


def test_parse_symbol_shapes():
    variants = [
        "VirtualAllocEx",
        "kernel32.VirtualAllocEx",
        "<kernel32.VirtualAllocEx>",
        "kernel32!VirtualAllocEx",
        "JMP.&GetProcAddress",
        "qword ptr ds:[<&CreateProcessW>]",
        "__imp_CreateProcessW",
        "_VirtualAllocEx@20",
    ]
    for raw in variants:
        parsed = api_lookup.parse_symbol(raw)
        assert parsed["lookup_keys"], raw
        assert parsed["canonical_key"], raw

    assert api_lookup.parse_symbol("kernel32!VirtualAllocEx")["function"] == "VirtualAllocEx"
    assert api_lookup.parse_symbol("kernel32.#123")["ordinal"] == 123
    assert api_lookup.parse_symbol("kernel32.dll")["lookup_keys"] == []


# --- build + read ---------------------------------------------------------


@pytest.fixture(scope="module")
def index(tmp_path_factory):
    out = tmp_path_factory.mktemp("apiidx") / "api_index.db"
    summary = api_index_build.build(MALAPI, out)
    assert summary["apis"] == 369
    return out


@pytest.fixture()
def env(monkeypatch, index):
    monkeypatch.setenv(api_lookup.INDEX_PATH_ENV, str(index))
    return index


def test_malapi_snapshot_is_bundled_and_valid():
    entries = json.loads(MALAPI.read_text(encoding="utf-8"))
    assert len(entries) == 369
    known = set(api_index_build.KNOWN_ATTACKS)
    for entry in entries:
        assert entry["name"]
        assert set(entry.get("attacks") or ()) <= known


def test_lookup_named_api(env):
    result = api_lookup.lookup("VirtualAllocEx")
    assert result["available"] and result["found"]
    assert result["name"] == "VirtualAllocEx"
    assert result["dll"] == "kernel32"
    assert result["syntax"]
    assert "Injection" in result["malicious_use"]["categories"]


def test_lookup_folds_variants(env):
    # W variant folds onto the A write-up malapi.io catalogued.
    wide = api_lookup.lookup("CreateFileW")
    assert wide["found"] and wide["name"] == "CreateFileA"
    assert wide["malicious_use"]["documented_as"] == "CreateFileA"

    # Nt/Zw twins resolve to one entry.
    zw = api_lookup.lookup("ZwOpenProcess")
    assert zw["found"] and zw["name"] == "NtOpenProcess"

    # Import-thunk / operand spelling resolves too.
    assert api_lookup.lookup("qword ptr ds:[<&CreateRemoteThread>]" )["found"]
    assert api_lookup.lookup("__imp_VirtualAllocEx")["found"]


def test_lookup_unknown_is_explicit(env):
    result = api_lookup.lookup("TotallyMadeUpApi")
    assert result["available"] and not result["found"]
    assert "not found" in result["note"].lower() or "no index entry" in result["note"].lower()


def test_search(env):
    result = api_lookup.search("process hollowing")
    assert result["available"] and result["found"]
    names = {r["name"] for r in result["results"]}
    assert "CreateProcessA" in names


def test_attack_categories_and_members(env):
    categories = api_lookup.attack_categories()
    assert categories["available"]
    by_name = {c["name"]: c["api_count"] for c in categories["categories"]}
    assert len(by_name) == 8
    assert by_name["Injection"] == 91

    members = api_lookup.apis_by_attack("Injection", limit=200)
    assert members["apis"]
    assert any(a["name"] == "CreateRemoteThread" for a in members["apis"])

    unknown = api_lookup.apis_by_attack("NotACategory")
    assert unknown["apis"] == [] and unknown["known_categories"]


def test_index_info(env):
    info = api_lookup.index_info()
    assert info["available"]
    assert info["counts"]["apis"] == 369
    assert info["counts"]["attack_categories"] == 8
    assert info["sources"] == "malapi"
    assert info["attribution"]


def test_render_smoke(env):
    text = api_lookup.render(api_lookup.lookup("CreateRemoteThread"))
    assert "CreateRemoteThread" in text
    assert "MALICIOUS USE" in text


# --- fail-open ------------------------------------------------------------


def test_missing_index_is_fail_open(monkeypatch, tmp_path):
    monkeypatch.setenv(api_lookup.INDEX_PATH_ENV, str(tmp_path / "nope.db"))
    assert api_lookup.available() is False
    for result in (
        api_lookup.lookup("CreateFileW"),
        api_lookup.search("injection"),
        api_lookup.attack_categories(),
        api_lookup.apis_by_attack("Injection"),
        api_lookup.index_info(),
    ):
        assert result["available"] is False
        assert "reason" in result
    # Rendering an unavailable result must not raise.
    assert api_lookup.render(api_lookup.lookup("CreateFileW"))
