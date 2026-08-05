# hitl/ — Human-in-the-loop gates

This folder implements HITL #2 (confidence-based review) and HITL #3 (critical-impact review) for RevAI.

| File | Purpose |
|------|---------|
| `README.md` | this file |
| `hitl-2-confidence.py` | HITL #2 — confidence < 50 → queue for review (one-at-a-time approve/reject) |
| `hitl-3-critical.py` | HITL #3 — critical-impact tags → human at every step |

## HITL gates

| HITL # | When | What |
|--------|------|------|
| 1 | LLM-vs-v1 disagreement | tie-breaker verdict (record-only in v2, see `v2_lib.py::hitl_checkpoint`) |
| 2 | Confidence < 50 | queue for review |
| 3 | Critical-impact chain | human at every step |

## HITL #2 details

- Threshold: `confidence < 50` → queue.
- API: `/api/hitl/<sha>/pending` (GET), `/api/hitl/<sha>/approve` (POST), `/api/hitl/<sha>/reject` (POST).
- Approve → apply to Ghidra + IDA. Reject → log to `verdict.json`.

## HITL #3 details

- Critical-impact tags: `ransomware_active`, `lateral_movement`, `credential_dump`, `c2_active`, `privilege_escalation`, `defense_evasion`, `data_exfiltration`, `keylogger`, `screen_capture`, `airplane_safety`, `medical_device`, `industrial_control`, `nuclear`, `critical_infrastructure`.
- Keyword detection: `ransomware`, `lateral movement`, `credential theft`, `c2 communication`, `keylogger`, `anti-vm`, etc.
- API: `/api/hitl/<sha>/critical` (GET).
