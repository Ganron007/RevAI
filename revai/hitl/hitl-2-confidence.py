"""hitl-2-confidence.py — HITL #2 (confidence < 0.5 -> queue for review).

Real implementation. Pairs with the Flask UI Annotate tab and
the /api/hitl/<sha>/* endpoints in app.py.

Workflow:
  1. deep_dive_v2.py detects LLM confidence < 50 -> sets hitl_required: true
     on the annotation in deep-dive.json.
  2. Flask UI /api/hitl/<sha>/pending shows the pending annotations.
  3. Analyst clicks Approve or Reject in the UI.
  4. /api/hitl/<sha>/approve calls ghidra/ida annotate on approved ones.
  5. /api/hitl/<sha>/reject removes them from the pending list.
  6. hitl_approve.py CLI can also approve/reject via state files.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# Mirrors the threshold in deep_dive_v2.py and v2_lib.py::hitl_checkpoint.
HITL_2_CONFIDENCE_THRESHOLD = 50

# Tags that make an annotation "critical" (HITL #3 cross-references).
# See hitl-3-critical.py for the canonical definition.
CRITICAL_IMPACT_TAGS = {
    "airplane_safety", "medical_device", "industrial_control", "nuclear",
    "ransomware_active", "lateral_movement", "credential_dump",
}


def should_queue_for_review(llm_confidence: int) -> bool:
    """Return True if LLM confidence is below the threshold; queue for human review."""
    return llm_confidence < HITL_2_CONFIDENCE_THRESHOLD


def is_critical_impact(annotation: dict) -> bool:
    """Return True if annotation tags include any critical-impact tag."""
    tags = set(annotation.get("tags") or [])
    return bool(tags & CRITICAL_IMPACT_TAGS)


def collect_pending(annotations: list[dict]) -> list[dict]:
    """Return annotations that need human review (low confidence or critical).

    Each returned dict is augmented with:
      - hitl_required: bool
      - hitl_status: "pending" | "approved" | "rejected"
      - hitl_review: reviewer name (if approved/rejected)
      - hitl_ts: float timestamp (if approved/rejected)
    """
    pending = []
    for ann in annotations:
        ann = dict(ann)
        conf = int(ann.get("confidence") or 100)
        status = ann.get("hitl_status", "pending")
        ann["hitl_required"] = should_queue_for_review(conf) or is_critical_impact(ann)
        ann["hitl_status"] = status
        if ann["hitl_required"] and status == "pending":
            pending.append(ann)
    return pending


def main() -> None:
    """CLI: read deep-dive.json, print pending annotations."""
    if len(sys.argv) < 2:
        print("usage: hitl-2-confidence.py <path-to-deep-dive.json>")
        sys.exit(1)
    p = Path(sys.argv[1])
    if not p.is_file():
        sys.exit(f"not found: {p}")
    data = json.loads(p.read_text())
    annotations = data.get("function_annotations") or []
    confidence = int(data.get("confidence") or 0)
    pending = collect_pending(annotations)
    print(json.dumps({
        "deep_dive": str(p),
        "overall_confidence": confidence,
        "hitl_threshold": HITL_2_CONFIDENCE_THRESHOLD,
        "annotation_count": len(annotations),
        "pending_count": len(pending),
        "pending": pending,
    }, indent=2, default=str))


if __name__ == "__main__":
    main()