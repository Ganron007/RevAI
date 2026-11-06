"""IOC extraction: URLs, IPs, domains, emails, wallets, registry keys, paths.

All string hits are defanged before return (brackets around dots / colons) so
the output is safe to paste into reports and detections.
"""

from __future__ import annotations

import re

# Control characters are excluded from the open-ended class: a "URL" pulled
# from binary data must not absorb NUL-separated fragments (run 36: a malformed
# URL row carried literal NUL bytes through iocs.json -> the row manifests ->
# the published reports; RC-47).
_URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s\x00-\x1f\x7f\"'<>()\[\]{}\\]+"
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_BTC_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_REGKEY_RE = re.compile(
    r"(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[A-Za-z0-9_\\ .-]+"
)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)


#: C0 control characters (except the markdown-significant \t) and DEL never
#: belong in an indicator. Belt-and-braces on top of the regex classes: a value
#: that reaches extraction through a different path is still clean.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

#: Loopback hosts are infrastructure, never indicators (RC-50b, run 36: a
#: malformed `http://localhost:` URL extracted from binary data was cited as
#: an indicator and contradicted three times by the reviewer).
_LOOPBACK_HOST_RE = re.compile(
    r"(?i)^https?://(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)")


def _strip_control_chars(value: str) -> str:
    return _CTRL_RE.sub("", value)


def _defang_url(url: str) -> str:
    return url.replace(".", "[.]").replace("://", "[:]//")


def _defang_domain(domain: str) -> str:
    return domain.replace(".", "[.]")


def _defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")


def _defang_email(email: str) -> str:
    return email.replace("@", "[@]").replace(".", "[.]")


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    iocs: dict[str, list[str]] = {"urls": [], "ips": [], "domains": [],
                                  "emails": [], "wallets_btc": [],
                                  "wallets_eth": [], "registry_keys": []}
    seen: dict[str, set[str]] = {k: set() for k in iocs}

    for u in _URL_RE.findall(text):
        d = _defang_url(_strip_control_chars(u.strip(".,;")))
        if _LOOPBACK_HOST_RE.match(u):
            continue
        if d not in seen["urls"]:
            seen["urls"].add(d)
            iocs["urls"].append(d)
    for ip in _IPV4_RE.findall(text):
        if _valid_ip(ip) and not ip.startswith("0."):
            d = _defang_ip(_strip_control_chars(ip))
            if d not in seen["ips"]:
                seen["ips"].add(d)
                iocs["ips"].append(d)
    for e in _EMAIL_RE.findall(text):
        d = _defang_email(_strip_control_chars(e))
        if d not in seen["emails"]:
            seen["emails"].add(d)
            iocs["emails"].append(d)
    for b in _BTC_RE.findall(text):
        b = _strip_control_chars(b)
        if b not in seen["wallets_btc"]:
            seen["wallets_btc"].add(b)
            iocs["wallets_btc"].append(b)
    for e in _ETH_RE.findall(text):
        e = _strip_control_chars(e)
        if e not in seen["wallets_eth"]:
            seen["wallets_eth"].add(e)
            iocs["wallets_eth"].append(e)
    for r in _REGKEY_RE.findall(text):
        r = _strip_control_chars(r)
        if r not in seen["registry_keys"]:
            seen["registry_keys"].add(r)
            iocs["registry_keys"].append(r)
    for d in _DOMAIN_RE.findall(text):
        low = d.lower()
        if low in ("example.com", "microsoft.com", "windows.com", "google.com"):
            continue
        if not low.endswith((".com", ".net", ".org", ".io", ".ru", ".cn", ".xyz",
                             ".info", ".biz", ".top", ".cc", ".us", ".de", ".uk")):
            continue
        if low in seen["domains"]:
            continue
        seen["domains"].add(low)
        iocs["domains"].append(_defang_domain(low))
    return iocs
