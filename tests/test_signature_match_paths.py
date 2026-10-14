"""The shipped signature databases must work in source and flat layouts."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import v2_lib  # noqa: E402


def test_signature_match_loads_sibling_db_and_reports_its_source(tmp_path, monkeypatch):
    runtime = tmp_path / "scripts"
    runtime.mkdir()
    fake_module = runtime / "v2_lib.py"
    fake_module.touch()
    db_dir = runtime / "signatures"
    db_dir.mkdir()

    (db_dir / "00_crypto.json").write_text(json.dumps({
        "signatures": [{
            "name": "TestCrypto",
            "score": 0.85,
            "indicators": {
                "external_symbol_contains": ["CryptAcquireContext"],
                "string_refs": ["rsa provider"],
            },
        }],
    }))
    # A later-loaded database must not overwrite the provenance of the match.
    (db_dir / "99_unrelated.json").write_text(json.dumps({
        "signatures": [{
            "name": "Unrelated",
            "score": 0.85,
            "indicators": {"external_symbol_contains": ["NeverCalled"]},
        }],
    }))
    monkeypatch.setattr(v2_lib, "__file__", str(fake_module))

    result = v2_lib.signature_match(
        "sub_401000",
        imports=["advapi32.CryptAcquireContextW"],
        strings=["RSA Provider"],
    )

    assert result["matched"] is True
    assert result["name"] == "TestCrypto"
    assert result["source_db"] == "00_crypto"
