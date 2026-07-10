# regression/ — baseline samples

Baseline samples used for regression testing on CADRE-RevAI.

## v2 baseline samples (4/4 PASS set)

| # | Sample | Source | Expected verdict | Actual verdict | v1 | LLM |
|---|--------|--------|------------------|----------------|-----|-----|
| 1 | apt29 | blackorbird/APT_RE_Toolkit | malicious | malicious | matches | matches |
| 2 | wannacry | embedded in blackorbird/APT_RE_Toolkit | malicious | malicious | matches | matches |
| 3 | busybox | mrphrazer/binary-cartography (control) | clean | clean | matches | matches |
| 4 | smartape | custom | suspicious | benign -> NEEDS_HUMAN_REVIEW | matches | disagrees (HITL #1 fires) |

## Files

| File | Purpose |
|------|---------|
| `v2-baseline-2026-06-29.md` | 4/4 PASS record |
| `regression-runner.py` | one-command runner to re-run the baseline set |
