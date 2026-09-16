"""Tests for deterministic per-IOC confidence tiers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "revai"))

import ioc_confidence as ic  # noqa: E402


def test_classify_ip():
    assert ic.classify_ip("10.1.2.3") == "private"
    assert ic.classify_ip("192.168.1.1") == "private"
    assert ic.classify_ip("172.16.5.4") == "private"
    assert ic.classify_ip("127.0.0.1") == "private"
    assert ic.classify_ip("169.254.10.1") == "special"
    assert ic.classify_ip("224.0.0.1") == "special"
    assert ic.classify_ip("0.0.0.0") == "special"
    assert ic.classify_ip("8.8.8.8") == "public"
    assert ic.classify_ip("not-an-ip") == "special"


def test_is_benign_domain():
    assert ic.is_benign_domain("microsoft.com")
    assert ic.is_benign_domain("update.microsoft.com")
    assert ic.is_benign_domain("schemas.xmlsoap.org")
    assert not ic.is_benign_domain("evil-c2.biz")


def _tiers(block):
    return {item["value"]: item["tier"] for item in block["items"]}


def test_annotate_tiers_and_additivity():
    pack = {
        "urls": ["hxxp[:]//evil-c2[.]biz/gate.php"],
        "domains": ["evil-c2[.]biz", "update.microsoft.com"],
        "ips": ["8.8.8.8", "192.168.1.10"],
        "files": ["dropper.exe"],
        "registry_keys": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "mutexes": ["Global\\abcMutex"],
        "wallets_btc": ["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"],
        "emails": ["bad@evil-c2.biz"],
    }
    before = {k: list(v) for k, v in pack.items()}
    block = ic.annotate(pack)

    # Additive: the original per-type lists are untouched.
    assert {k: v for k, v in pack.items()} == before

    tiers = _tiers(block)
    assert tiers["hxxp[:]//evil-c2[.]biz/gate.php"] == "high"
    # The domain is both in the URL and standalone -> high, with a boost reason.
    domain_item = next(i for i in block["items"] if i["value"] == "evil-c2[.]biz")
    assert domain_item["tier"] == "high"
    assert any("more than one indicator type" in r for r in domain_item["reasons"])
    assert ic.is_benign_domain("update.microsoft.com")
    assert tiers["update.microsoft.com"] == "low"
    assert tiers["8.8.8.8"] == "medium"
    assert tiers["192.168.1.10"] == "low"
    assert tiers["dropper.exe"] == "medium"
    assert tiers["Global\\abcMutex"] == "low"
    assert tiers["1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"] == "high"
    # Full registry path (two separators) is structural -> high.
    assert tiers["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"] == "high"


def test_annotate_shape_and_counts():
    block = ic.annotate({"ips": ["8.8.8.8", "10.0.0.1"]})
    assert block["version"] == 1
    assert set(block["rubric"]) == {"high", "medium", "low"}
    assert block["counts"]["medium"] == 1
    assert block["counts"]["low"] == 1
    assert all(0 <= item["score"] <= 100 for item in block["items"])
    assert all(item["reasons"] for item in block["items"])


def test_annotate_empty_pack():
    block = ic.annotate({})
    assert block["items"] == []
    assert block["counts"] == {"high": 0, "medium": 0, "low": 0}
