# Operation Guide 

## Start and stop the service

```bash
sudo systemctl start revai
sudo systemctl stop revai
sudo systemctl restart revai
sudo journalctl -u revai -f
```

The pipeline runs **LLM-only**: tools produce a stage-tagged evidence pack and the LLM writes the verdict/report.

## Stage a sample

### UI

1. Open `http://<remnux-ip>:5000`.
2. **+ Stage New Sample** → pick file + family → Stage.
3. Run stages in order (or **Run All**).

### Shell

```bash
python3 /opt/scripts/intake_v2.py /path/to/sample.exe --project-name MyFamily
```

Intake auto-sets `pipeline_mode` to `standard` or `large`. Override with:

```bash
CADRE_PIPELINE_MODE=standard python3 /opt/scripts/intake_v2.py /path/to/sample.exe
# or
CADRE_PIPELINE_MODE=large python3 /opt/scripts/intake_v2.py /path/to/sample.exe
```

## Pipeline stages 

1. **intake** — session + Ghidra (optional IDA)  
2. **quick_scan** — triage tools → `evidence-pack.md` → LLM verdict  
3. **deep_dive** — `deep_dive_v2` (standard) or `deep_dive_agentic` (large)  
4. **yara_gen** — YARA + Sigma  
5. **publish** — REPORT-MASTER  
6. **correlate** — section Map-Reduce report (optional)  
7. **audit** — `audit_pipeline.py --mode standard|large` → `all_green`

Shell examples:

```bash
python3 /opt/scripts/quick_scan_v2.py <sha256>
python3 /opt/scripts/deep_dive_v2.py <sha256>          # standard
python3 /opt/scripts/deep_dive_agentic.py <sha256>     # large
python3 /opt/scripts/yara_gen_v2.py --family MyFamily <sha256>
python3 /opt/scripts/publish_report_v2.py --template full <sha256>
python3 /opt/scripts/audit_pipeline.py --mode standard <sha256>
```

## Reset outputs

UI **Reset outputs**, or:

```bash
curl -X POST http://<remnux-ip>:5000/api/reset/<sha256>
```

## HITL

Low-confidence findings appear under **Annotate** — Approve / Reject as needed.

## More

- Prerequisites: [`PREREQUISITES.md`](PREREQUISITES.md)  
- Install: [`INSTALL.md`](INSTALL.md)  
- Deploy: [`DEPLOY.md`](DEPLOY.md)  
- Configure: [`CONFIGURE.md`](CONFIGURE.md)  
