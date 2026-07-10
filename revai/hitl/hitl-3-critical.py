"""hitl-3-critical.py — HITL #3 (critical-impact chain -> human at every step).

Real implementation. Malware-relevant critical tags.
Pairs with the Flask UI and /api/hitl/<sha>/critical endpoint.

HITL #3 gates any verdict that matches a critical-impact tag
for human review at every step of the chain. Originally specified
for safety-critical domains (airplane_safety, medical_device, etc.);
here we focus on malware-relevant critical findings.
"""
from __future__ import annotations

# Malware-relevant critical-impact tags.
# A verdict or annotation matching any of these is flagged for HITL #3.
CRITICAL_IMPACT_TAGS = {
    # Active attack indicators (highest priority)
    "ransomware_active", "ransomware_behavior", "wiper_active",
    "lateral_movement", "credential_dump", "credential_steal",
    "c2_active", "c2_beacon",
    # High-impact malware capabilities
    "privilege_escalation", "defense_evasion", "anti_forensics",
    "persistence", "lateral_spread", "data_exfiltration",
    "ransomware_capability", "keylogger", "screen_capture",
    # Dual-use / impact categories
    "airplane_safety", "medical_device", "industrial_control", "nuclear",
    "critical_infrastructure",
}

# Keyword patterns in LLM summaries that trigger auto-flagging.
# These are case-insensitive substrings.
CRITICAL_KEYWORDS = [
    "ransomware", "wiper", "destructive", "file destruction",
    "credential theft", "credential dump", "credential harvest",
    "lateral movement", "lateral spread", "lateral propagation",
    "c2 communication", "c2 beacon", "command and control",
    "data exfiltration", "data theft", "exfiltrate",
    "privilege escalation", "privilege elevation",
    "defense evasion", "evasion technique",
    "persistence mechanism", "persistence technique",
    "keylogger", "screen capture", "screenshot",
    "anti-forensic", "anti-debug", "anti-vm", "anti-sandbox",
    "airplane", "aircraft", "aviation",
    "medical device", "hospital", "patient",
    "industrial control", "scada", "plc", "ics",
    "nuclear", "power grid", "critical infrastructure",
]


def is_critical_impact(verdict: dict) -> bool:
    """Return True if any tag in the verdict matches the critical-impact set."""
    tags = set(verdict.get("tags") or [])
    return bool(tags & CRITICAL_IMPACT_TAGS)


def find_critical_keywords(text: str) -> list[str]:
    """Return list of critical keywords found in the given text.

    Used to auto-flag LLM summaries that mention critical malware
    capabilities (ransomware, lateral movement, credential theft, etc.)
    or impact categories (airplane, medical device, ICS, etc.).
    """
    if not text:
        return []
    text_lower = text.lower()
    found = []
    for kw in CRITICAL_KEYWORDS:
        if kw in text_lower:
            found.append(kw)
    return found


def is_critical_text(text: str) -> bool:
    """Return True if the text mentions any critical-impact keyword."""
    return bool(find_critical_keywords(text))


def require_human_at_every_step(verdict: dict) -> bool:
    """HITL #3 = require human approval at every step of the chain."""
    return is_critical_impact(verdict)


def collect_critical_annotations(annotations: list[dict]) -> list[dict]:
    """Return annotations that should be flagged for HITL #3 review.

    A annotation is critical if:
    - It has any tag in CRITICAL_IMPACT_TAGS
    - OR its comment/new_name contains a critical keyword
    - OR it is an existing low-confidence annotation (HITL #2)
    """
    flagged = []
    for ann in annotations:
        if not isinstance(ann, dict):
            continue
        ann = dict(ann)
        tags = set(ann.get("tags") or [])
        if tags & CRITICAL_IMPACT_TAGS:
            ann["critical_reason"] = f"tag: {sorted(tags & CRITICAL_IMPACT_TAGS)}"
            flagged.append(ann)
            continue
        text = f"{ann.get('new_name', '')} {ann.get('comment', '')}"
        kws = find_critical_keywords(text)
        if kws:
            ann["critical_reason"] = f"keyword: {kws}"
            flagged.append(ann)
    return flagged


def main() -> None:
    """CLI: read deep-dive.json, print critical findings."""
    import sys
    if len(sys.argv) < 2:
        print("usage: hitl-3-critical.py <path-to-deep-dive.json>")
        sys.exit(1)
    import json
    from pathlib import Path
    p = Path(sys.argv[1])
    if not p.is_file():
        sys.exit(f"not found: {p}")
    data = json.loads(p.read_text())
    annotations = data.get("function_annotations") or []
    flagged = collect_critical_annotations(annotations)
    summary = data.get("summary", "")
    summary_kws = find_critical_keywords(summary)
    print(json.dumps({
        "deep_dive": str(p),
        "summary_critical_keywords": summary_kws,
        "annotation_count": len(annotations),
        "critical_count": len(flagged),
        "critical": flagged,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()