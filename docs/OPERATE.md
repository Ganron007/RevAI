# Operation Guide

## Start and stop the service

```bash
sudo systemctl start revai
sudo systemctl stop revai
sudo systemctl restart revai
```

View logs:

```bash
sudo journalctl -u revai -f
```

## Stage a sample

### From the UI

1. Open `http://<remnux-ip>:5000`.
2. Click the **Intake** tab.
3. Drop or select a sample file and enter a family name.
4. Click **Stage**. The sample is copied to `/opt/samples/sessions/<sha256>/`.

### From the shell

```bash
python3 /opt/scripts/intake_v2.py --file /path/to/sample.exe --family MyFamily
```

## Run pipeline stages

From the UI, click each stage button in order:

1. **intake** — create session, hashes, Ghidra project.
2. **quick_scan** — triage with capa/YARA/FLOSS/Malcat, LLM verdict, RAG context.
3. **deep_dive** — Ghidra/IDA SQL, decompilation, behavior, deobfuscation.
4. **yara_gen** — generate YARA/Sigma rules.
5. **publish** — produce `REPORT-v2.md`, `REPORT-MASTER-v2.md`, `REPORT-TECHNICAL-v2.md`.
6. **correlate** — cross-sample section correlation (optional).

From the shell, run a single stage:

```bash
python3 /opt/scripts/quick_scan_v2.py --session /opt/samples/sessions/<sha256>/session.json
```

## Re-running and resetting

- Re-running a stage from the UI overwrites that stage's outputs.
- To reset all stage outputs while keeping the staged sample, click the **🗑 Reset outputs** button in the UI header or call:
  ```bash
  curl -X POST http://<remnux-ip>:5000/api/reset/<sha256>
  ```
- The workspace header shows a **staged** pill for samples that have already been staged.

## HITL checkpoints

Low-confidence or critical-impact findings are queued for human review in the **Annotate** tab. Click **Approve** or **Reject** to continue or halt the pipeline.

## Verification and tests

Quick smoke test:

```bash
python3 /opt/scripts/v2_validate.py --smoke-only
```

Full pipeline regression on built-in samples:

```bash
python3 /opt/cadre-v3-tools/regression/regression-runner.py --v3
```

Unit tests:

```bash
python3 /opt/scripts/tests/test_file_type.py
python3 /opt/scripts/tests/test_hybrid_search.py
python3 /opt/cadre-v3-tools/deobfuscation/z3_mba_tests.py
python3 /opt/cadre-v3-tools/deobfuscation/angr_cff_tests.py
```

## Directory layout on REMnux

```text
/opt/scripts/               # pipeline code
/opt/cadre-v3-tools/        # RAG, deobfuscation, HITL, regression
/opt/cadre-v4-tools/        # optional agentic function recovery
/opt/samples/sessions/        # staged samples + session.json
/opt/samples/logs/            # per-stage outputs and reports
/opt/samples/corpus/          # sample corpus
/opt/samples/shortlist/       # shortlist of interesting samples
/opt/samples/incoming/        # manual-drop, vr-hunt-pull, cadre-push
/opt/revai/config/            # alternative config location
```

## Where outputs live

For a sample with SHA256 `abc123...`:

- Session: `/opt/samples/sessions/abc123.../session.json`
- Logs/outputs: `/opt/samples/logs/abc123.../`
- Reports: `/opt/samples/logs/abc123.../REPORT-*.md`
- Status: `/opt/samples/logs/abc123.../pipeline-status.json`

## Goodware fingerprints

To mark a known-good binary so the pipeline short-circuits to clean:

```bash
cp binary /opt/samples/goodware/<sha256>
cat > /opt/samples/goodware/<sha256>.json <<'EOF'
{"name": "clean.exe", "source": "internal", "added": "2026-07-10"}
EOF
```

`quick_scan_v2.py` will return `verdict: clean` (source `goodware_fingerprint`) on SHA256 match.

## Tips

- Keep `/opt/samples/` on a disk with plenty of space; Ghidra projects and reports can grow quickly.
- The Flask UI runs a development server. For production, place it behind a reverse proxy with HTTPS and authentication.
- Set `STAGE_TIMEOUT_S` in the service environment if a stage exceeds the default 4-hour timeout.
