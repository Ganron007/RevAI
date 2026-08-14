# RAW-EVIDENCE.md — loveyou-js

- **SHA256:** `f3e743c919c1deaf5108d361c4ff610187606f450fabda0bea3786d4063511b1`
- **Verdict:** malicious (confidence ?)
- **Audit:** all_green=True
- **Index generated:** 2026-08-14 04:54:29 UTC

## Files copied

- `AUDIT-REPORT.md`
- `EVIDENCE-BUNDLE.md`
- `REPORT-MASTER-v2.md`
- `REPORT-MASTER-v3.md`
- `REPORT-TECHNICAL-v2.md`
- `REPORT-TECHNICAL-v3.md`
- `REPORT-v2.md`
- `evidence/00-quick-scan-tools.json`
- `evidence/anti-analysis.txt`
- `evidence/audit.jsonl`
- `evidence/capa.txt`
- `evidence/deep-dive-01-tools-gate.json`
- `evidence/deep-dive-01-tools-raw.json`
- `evidence/deep-dive-02-signals.json`
- `evidence/deep-dive-05-verdict.json`
- `evidence/deep-dive-agentic-history.json`
- `evidence/deep-dive-evidence-pack.md`
- `evidence/dyn-resolve.txt`
- `evidence/entropy-evidence-patch.json`
- `evidence/intake-ghidra-headless.log`
- `evidence/intake-validation.json`
- `evidence/malcat-triage.json`
- `evidence/oracle.txt`
- `evidence/pe-imports.txt`
- `evidence/pipeline-audit.json`
- `evidence/quick-scan-evidence-pack.md`
- `evidence/recovery.txt`
- `evidence/source-decisions.json`
- `evidence/strings.txt`
- `evidence/unpack.txt`
- `evidence/yara.txt`
- `iocs.json`
- `rule.yar`
- `rule.yara.json`
- `rule.yml`
- `section-results-v3.json`
- `stage_trace.json`
- `verdict.json`

## Files absent from this run (honest listing)

- `evidence/deep-dive-03-oracle.json` (not produced — stage not enabled or not applicable)
- `evidence/function-recovery.json` (not produced — stage not enabled or not applicable)
- `evidence/packer.txt` (not produced — stage not enabled or not applicable)
- `evidence/quick-scan-prompt.txt` (not produced — stage not enabled or not applicable)
- `evidence/ti-enrich.json` (not produced — stage not enabled or not applicable)

## Verification

Every claim in the published reports can be checked against the tool
outputs above: `00-quick-scan-tools.json`, `deep-dive-01-tools-raw.json`,
`audit.jsonl` (complete query trail) and `pipeline-audit.json` (gate
results per stage). The pipeline provenance (commit, engine, flags) is
recorded in each report's provenance banner.