"""Deterministic per-IOC confidence tiers.

Every indicator in the pack gets a confidence tier derived from *how* it was
extracted and the context it appears in - never from a behavioural claim about
the sample. The rubric is fixed and explainable, so an analyst can audit any
tier by reading its reasons and filter the pack without guesswork.

Tiers:

* **high** - explicit or structurally complete evidence: a URL with scheme and
  host, a full registry path, a strict-format wallet address, or the sample's
  own hashes.
* **medium** - a well-formed but context-free string match (bare public IP,
  bare domain, filename, heuristic mutex name).
* **low** - a pattern match with weak structure, a private/reserved address, or
  a well-known vendor domain (telemetry/update endpoints are not hunt targets).

Values may be defanged (``hxxp[:]//evil[.]example``); classification works on the
plain form while the report keeps the original string.
"""

from __future__ import annotations

import re

TIERS = ("high", "medium", "low")
_SCORES = {"high": 85, "medium": 60, "low": 30}

#: Domains that show up in benign telemetry/update code paths. Seeing one is not
#: evidence of anything, so they are reported but tiered low rather than dropped.
BENIGN_DOMAIN_SUFFIXES = (
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msn.com", "bing.com", "live.com", "office.com", "office365.com",
    "w3.org", "xmlsoap.org", "schemas.xmlsoap.org", "ietf.org", "rfc-editor.org",
    "verisign.com", "digicert.com", "globalsign.com", "sectigo.com",
    "adobe.com", "google.com", "gstatic.com", "mozilla.org", "apple.com",
    "apache.org", "openssl.org", "python.org", "gnu.org", "kernel.org",
    "github.com", "githubusercontent.com", "debian.org", "ubuntu.com",
    "intel.com", "nvidia.com", "vmware.com", "ntp.org", "pool.ntp.org",
    "example.com", "schemas.microsoft.com",
)

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def undefang(value: str) -> str:
    """Reverse the defanging used across the pack (for classification only)."""
    return (value.replace("[.]", ".").replace("[:]", ":")
                 .replace("[@]", "@").replace("[at]", "@"))


def classify_ip(ip: str) -> str:
    """Return ``private``, ``special`` or ``public`` for an IPv4 literal."""
    if not _IPV4_RE.match(ip):
        return "special"
    try:
        a, b, _c, _d = (int(p) for p in ip.split("."))
    except ValueError:
        return "special"
    if a in (10, 127) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return "private"
    if a == 0 or a >= 224 or (a == 169 and b == 254):
        return "special"
    return "public"


def is_benign_domain(domain: str) -> bool:
    domain = domain.lower().lstrip(".")
    return any(domain == s or domain.endswith("." + s)
               for s in BENIGN_DOMAIN_SUFFIXES)


def _in_any(value: str, haystack: list[str]) -> bool:
    return any(value and value in item for item in haystack)


def url_host(value: str) -> str:
    """Plain (undefanged, lowercased) host of a URL-ish string; '' if none."""
    plain = undefang(value)
    rest = plain.split("://", 1)[-1] if "://" in plain else plain
    host = rest.split("/", 1)[0].split("@")[-1]
    return host.split(":")[0].strip().lower()


def _score(tier: str, reasons: list[str], boost: bool) -> int:
    score = _SCORES[tier]
    if boost:
        score = min(95, score + 10)
    return score


def annotate(iocs: dict) -> dict:
    """Annotate an IOC pack with a deterministic confidence block.

    Accepts both pack shapes in use (the pipeline's raw-extraction pack and the
    revai-tools pack): only the keys present are scored. Purely additive - the
    original per-type lists are left untouched so existing consumers keep working.
    """
    urls = list(iocs.get("urls") or [])
    ips = list(iocs.get("ips") or [])
    domains = list(iocs.get("domains") or [])
    files = list(iocs.get("files") or [])
    registry = list(iocs.get("registry_keys") or [])
    mutexes = list(iocs.get("mutexes") or [])
    wallets = list(iocs.get("wallets_btc") or []) + list(iocs.get("wallets_eth") or [])
    emails = list(iocs.get("emails") or [])

    # Cross-source corroboration: the same value appearing under several types
    # is stronger evidence than any single extraction.
    sources: dict[str, set[str]] = {}

    def _note(value: str, kind: str) -> None:
        key = undefang(value).lower()
        if key:
            sources.setdefault(key, set()).add(kind)

    for u in urls:
        _note(u, "url")
        _note(url_host(u), "url_host")
    for i in ips:
        _note(i, "ip")
    for d in domains:
        _note(d, "domain")
    for f in files:
        _note(f, "file")
    for r in registry:
        _note(r, "registry_key")
    for m in mutexes:
        _note(m, "mutex")
    for w in wallets:
        _note(w, "wallet")

    items: list[dict] = []

    def _add(kind: str, value: str, tier: str, reasons: list[str]) -> None:
        boost = len(sources.get(undefang(value).lower(), ())) > 1
        if boost:
            reasons = reasons + ["appears in more than one indicator type"]
        items.append({
            "type": kind,
            "value": value,
            "tier": tier,
            "score": _score(tier, reasons, boost),
            "reasons": reasons,
        })

    for value in urls:
        plain = undefang(value)
        host = plain.split("//", 1)[-1].split("/", 1)[0].split("@")[-1]
        host_plain = host.split(":")[0]
        if is_benign_domain(host_plain):
            _add("url", value, "low", ["well-known vendor/telemetry domain"])
        else:
            _add("url", value, "high", ["explicit scheme and host"])

    for value in ips:
        plain = undefang(value)
        kind = classify_ip(plain)
        if kind == "private":
            _add("ip", value, "low", ["private address range (RFC1918)"])
        elif kind == "special":
            _add("ip", value, "low", ["reserved, loopback or multicast address"])
        elif _in_any(value, urls):
            _add("ip", value, "high", ["public address embedded in a URL"])
        else:
            _add("ip", value, "medium", ["public address matched as a bare string"])

    for value in domains:
        plain = undefang(value)
        if is_benign_domain(plain):
            _add("domain", value, "low", ["well-known vendor/telemetry domain"])
        elif _in_any(value, urls):
            _add("domain", value, "high", ["host component of an extracted URL"])
        else:
            _add("domain", value, "medium", ["well-formed domain matched as a bare string"])

    for value in files:
        _add("file", value, "medium", ["filename pattern from string evidence"])

    for value in registry:
        depth = undefang(value).count("\\")
        if depth >= 2:
            _add("registry_key", value, "high", ["full registry path with subkey"])
        else:
            _add("registry_key", value, "medium", ["registry root with a single segment"])

    for value in mutexes:
        _add("mutex", value, "low", ["heuristic mutex-name pattern"])

    for value in wallets:
        _add("wallet", value, "high", ["strict address format"])

    for value in emails:
        _add("email", value, "medium", ["well-formed address matched as a string"])

    counts = {tier: sum(1 for item in items if item["tier"] == tier) for tier in TIERS}
    return {
        "version": 1,
        "rubric": {
            "high": "explicit or structurally complete evidence (scheme+host, full "
                    "registry path, strict format, or the sample's own hashes)",
            "medium": "well-formed but context-free string match",
            "low": "weak structure, private/reserved address, or a well-known "
                   "vendor/telemetry domain",
        },
        "counts": counts,
        "items": items,
    }
