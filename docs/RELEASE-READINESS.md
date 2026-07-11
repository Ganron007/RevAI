# CADRE-RevAI Release Readiness

> **Created:** 2026-07-11
> **Status:** READY FOR TESTING / CONDITIONAL PASS FOR PUBLIC RELEASE REVIEW
> **Scope:** repository audit for secrets, courseware/trademark residue, path leaks, stale docs, and licensing posture
> **Owner:** User

---

## TL;DR

Current audit results are good for a clean test baseline: no API-key patterns were found, no hardcoded Windows workspace paths remain in tracked docs/scripts, and courseware/trademark wording has been removed from release-facing docs and code comments. Remaining experimental/optional wording is intentional and should stay until the corresponding features are either shipped or explicitly removed.

This repo is now in a workable state for testing and further cleanup before a public release.

---

## 1. Verified Clean

- ✅ **MIT license declared** in [LICENSE](../LICENSE)
- ✅ **No secret-pattern hits** from the current repo scan (`sk-`, `AKIA`, `ghp_`, `glpat_`, `xox*`, `AIza*`)
- ✅ **No hardcoded Windows workspace paths** remain in tracked content after cleanup
- ✅ **No courseware/trademark scan hits** remain in release-facing docs/comments after cleanup
- ✅ **Operational examples were corrected** to match the actual CLI signatures
- ✅ **Readiness artifact is local-only** and the repo now has a cleaner test baseline

---

## 2. Intentional / Acceptable Residuals

These are not blockers for testing, but they should be reviewed before any final public release if you want a stricter polish pass.

- **Private REMnux paths** such as `/opt/...` are intentionally present because this project is designed for a public VM workflow.
- **Private IP examples** are acceptable in this repo because they describe lab / VM deployment topology.
- **Optional preview / experimental labels** remain for future features and are not secret material.
- **Placeholder UI strings** remain in the browser and config templates as normal user-facing input hints.

---

## 3. What Was Cleaned

- [docs/DEPLOY.md](../docs/DEPLOY.md) now uses a neutral API-key placeholder and avoids courseware wording.
- [docs/OPERATE.md](../docs/OPERATE.md) now shows commands that match the actual CLI.
- [revai/rag/reveng_rag.py](../revai/rag/reveng_rag.py) now uses neutral public-corpus wording in its doc comment.
- [revai/quick_scan_v2.py](../revai/quick_scan_v2.py) now refers to a public reference corpus instead of courseware.

---

## 4. Residual Review Items

These are the only things I would still manually inspect before public release:

- Confirm the optional preview / experimental flags are still desired in public docs.
- Confirm the browser placeholder text for the API key field is acceptable to ship as-is.
- Run the project tests and a service smoke test before release.

---

## 5. Evidence

| Check | Result |
|---|---|
| Secret scan | no matches |
| Hardcoded Windows path scan | no matches |
| Courseware/trademark scan | no matches |
| Readiness of operational docs | fixed |

Suggested commands used during the audit:

```powershell
rg -n -i "courseware|OffSec|HTB|AI-300|COAE" --glob "!**/node_modules/**" --glob "!**/.venv/**"
rg -n "C:\\STUDY\\Github\\CADRE-Platform\\CADRE-RevAI|C:\\Users\\|file:///|vscode://" --glob "!**/node_modules/**" --glob "!**/.venv/**"
rg -n "sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}" --glob "!**/node_modules/**" --glob "!**/.venv/**"
```

---

## 6. Next Actions

1. Run the project test suite and the main REMnux smoke test.
2. Decide whether to keep the optional preview / experimental labels in public docs.
3. If you want a stricter release polish pass, trim remaining placeholder text in the UI templates.
