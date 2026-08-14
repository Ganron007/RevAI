# RevAI — Pipeline Runs & Case Studies

Real analysis reports produced by the RevAI pipeline against live malware
samples. Each case study includes the full report set, verdict, audit, YARA
rules, and stage trace — plus the raw tool-extracted evidence behind every
claim.

## Evidence contract

Every case study ships the **raw tool-extracted evidence** in its `evidence/`
folder (see [`scripted/darkside-ransomware/evidence/RAW-EVIDENCE.md`](scripted/darkside-ransomware/evidence/RAW-EVIDENCE.md) for an index example):

- full uncapped tool outputs as structured JSON (`00-quick-scan-tools.json`,
  `deep-dive-01-tools-raw.json`, `deep-dive-02-signals.json`,
  `deep-dive-03-oracle.json`, `deep-dive-agentic-history.json`, ...)
- the complete audit trail (`audit.jsonl`, `pipeline-audit.json`)
- engine artifacts (`malcat-triage.json`, `intake-validation.json`,
  `source-decisions.json`, `doc-triage.json`, `function-recovery.json`)
- human-readable extracts: `strings.txt`, `yara.txt`, `capa.txt`,
  `pe-imports.txt`, `packer.txt`, `anti-analysis.txt`, `dyn-resolve.txt`,
  `oracle.txt`, `unpack.txt`, `recovery.txt`
- `RAW-EVIDENCE.md` — an index of exactly what was copied (and what was
  absent) for that run

This lets reviewers verify every claim in a report against the actual
extracted data, per the evidence-before-claims contract. Reports are
published only after the sample passes the full quality gate (`all_green`
+ `quality_green`).

## Organization — grouped by pipeline mode

| Directory | Mode | Description |
|-----------|------|-------------|
| [`scripted/`](scripted/) | Scripted (`pipeline_single.py`) | Fixed-order stages: intake → quick_scan → deep_dive → (function_recovery, optional) → yara → publish → section → audit |
| [`agentic/`](agentic/) | Agentic (`stage_orchestrator.py`) | LangGraph ReAct planner decides stage order; retries on failure; HITL before publish |
| [`ui/`](ui/) | Web Console (manual) | Interactive per-stage runs from `http://<host>:5000` |

## Case studies (newest first within each mode)

**56 published.** The full feature inventory with env gates and per-feature
status lives in [`../FEATURES.md`](../FEATURES.md).

### Scripted

| Sample | Description | Verdict | Report | Audit |
|--------|-------------|---------|--------|-------|
| `loveyou-js` | JavaScript loader script | [malicious](scripted/loveyou-js/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/loveyou-js/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/loveyou-js/AUDIT-REPORT.md) |
| `challenge66` | Course challenge, asserted-unknown label | [malicious](scripted/challenge66/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/challenge66/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/challenge66/AUDIT-REPORT.md) |
| `svchost` | Locky ransomware | [malicious](scripted/svchost/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/svchost/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/svchost/AUDIT-REPORT.md) |
| `brbbot` | Botnet trojan (WinINet C2, RC4 config) | [malicious](scripted/brbbot/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/brbbot/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/brbbot/AUDIT-REPORT.md) |
| `getdown` | Trojan downloader (usbles26) | [malicious](scripted/getdown/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/getdown/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/getdown/AUDIT-REPORT.md) |
| `ghyte` | ZProtect-protected PE | [malicious](scripted/ghyte/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/ghyte/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/ghyte/AUDIT-REPORT.md) |
| `win32k` | DLL — process injection, HTTP exfiltration | [malicious](scripted/win32k/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/win32k/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/win32k/AUDIT-REPORT.md) |
| `msdsrv` | Dropper | [malicious](scripted/msdsrv/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/msdsrv/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/msdsrv/AUDIT-REPORT.md) |
| `ishelp` | DLL | [malicious](scripted/ishelp/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/ishelp/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/ishelp/AUDIT-REPORT.md) |
| `want` | LockBit, PECompact-packed | [malicious](scripted/want/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/want/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/want/AUDIT-REPORT.md) |
| `drtg` | Satana ransomware dropper | [malicious](scripted/drtg/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/drtg/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/drtg/AUDIT-REPORT.md) |
| `hubert` | DLL | [malicious](scripted/hubert/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/hubert/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/hubert/AUDIT-REPORT.md) |
| `vbprop` | Armadillo-packed PE | [malicious](scripted/vbprop/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/vbprop/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/vbprop/AUDIT-REPORT.md) |
| `raas` | WS2_32 networking malware | [malicious](scripted/raas/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/raas/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/raas/AUDIT-REPORT.md) |
| `trojan-4982` | Trojan | [malicious](scripted/trojan-4982/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/trojan-4982/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/trojan-4982/AUDIT-REPORT.md) |
| `rk-dropper` | Rootkit dropper (3.3MB) | [malicious](scripted/rk-dropper/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/rk-dropper/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/rk-dropper/AUDIT-REPORT.md) |
| `koti-xlsm` | Excel macro document | [malicious](scripted/koti-xlsm/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/koti-xlsm/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/koti-xlsm/AUDIT-REPORT.md) |
| `challenge63` | Course challenge, asserted-unknown label | [malicious](scripted/challenge63/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/challenge63/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/challenge63/AUDIT-REPORT.md) |
| `film-wav` | WAVE audio, edge format | [malicious](scripted/film-wav/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/film-wav/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/film-wav/AUDIT-REPORT.md) |
| `dumped-dll-bin` | Raw dump, edge format | [malicious](scripted/dumped-dll-bin/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/dumped-dll-bin/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/dumped-dll-bin/AUDIT-REPORT.md) |
| `upack037-packed` | UPack 0.37, corrupt-header stub | [suspicious](scripted/upack037-packed/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/upack037-packed/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/upack037-packed/AUDIT-REPORT.md) |
| `nspack-packed` | NSPack stub | [suspicious](scripted/nspack-packed/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/nspack-packed/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/nspack-packed/AUDIT-REPORT.md) |
| `worddoc-shellcode` | Raw Cobalt-Stager shellcode | [malicious](scripted/worddoc-shellcode/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/worddoc-shellcode/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/worddoc-shellcode/AUDIT-REPORT.md) |
| `darkside-ransomware` | DarkSide 1.1.x | [suspicious](scripted/darkside-ransomware/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/darkside-ransomware/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/darkside-ransomware/AUDIT-REPORT.md) |
| `guloader` | GuLoader / CloudEyE | [suspicious](scripted/guloader/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/guloader/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/guloader/AUDIT-REPORT.md) |
| `space1-flawedammyy` | FlawedAmmyy RAT | [malicious](scripted/space1-flawedammyy/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/space1-flawedammyy/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/space1-flawedammyy/AUDIT-REPORT.md) |
| `sunburst-dotnet` | Sunburst .NET backdoor | [malicious](scripted/sunburst-dotnet/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/sunburst-dotnet/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/sunburst-dotnet/AUDIT-REPORT.md) |
| `tasksche` | C2-scheduled task PE | [malicious](scripted/tasksche/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/tasksche/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/tasksche/AUDIT-REPORT.md) |
| `vdaudio-dll` | DLL, C2 markers + anti-forensics | [malicious](scripted/vdaudio-dll/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/vdaudio-dll/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/vdaudio-dll/AUDIT-REPORT.md) |
| `3048-ps1` | PowerShell loader script | [malicious](scripted/3048-ps1/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/3048-ps1/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/3048-ps1/AUDIT-REPORT.md) |
| `order-docm-macro` | Word macro, VBA stomping | [suspicious](scripted/order-docm-macro/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/order-docm-macro/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/order-docm-macro/AUDIT-REPORT.md) |
| `steel-saz-pcap` | Fiddler .saz capture, C2 flow | [suspicious](scripted/steel-saz-pcap/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/steel-saz-pcap/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/steel-saz-pcap/AUDIT-REPORT.md) |
| `crackme7` | angr/emulation crackme | [suspicious](scripted/crackme7/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/crackme7/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/crackme7/AUDIT-REPORT.md) |
| `angr-crackme2` | angr exercise | [suspicious](scripted/angr-crackme2/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/angr-crackme2/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/angr-crackme2/AUDIT-REPORT.md) |
| `string-encryption` | 2KB angr decryption target | [suspicious](scripted/string-encryption/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/string-encryption/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/string-encryption/AUDIT-REPORT.md) |
| `virussign-01984caa` | Unicorn, VB6 info-stealer/dropper | [malicious](scripted/virussign-01984caa/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-01984caa/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-01984caa/AUDIT-REPORT.md) |
| `virussign-277ba25a` | Unidentified packed/obfuscated PE | [malicious](scripted/virussign-277ba25a/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-277ba25a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-277ba25a/AUDIT-REPORT.md) |
| `virussign-780d28e3` | Darty Crypter | [malicious](scripted/virussign-780d28e3/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/virussign-780d28e3/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/virussign-780d28e3/AUDIT-REPORT.md) |
| `remcos` | Remcos RAT | [malicious](scripted/remcos/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/remcos/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/remcos/AUDIT-REPORT.md) |
| `pool-small-bkransomware` | BK ransomware / elex / maze / remcos tags | [malicious](scripted/pool-small-bkransomware/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-bkransomware/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-bkransomware/AUDIT-REPORT.md) |
| `pool-small-mespinoza` | Mespinoza / Pysa ransomware | [malicious](scripted/pool-small-mespinoza/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-mespinoza/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-mespinoza/AUDIT-REPORT.md) |
| `pool-small-conti` | Conti ransomware | [malicious](scripted/pool-small-conti/verdict.json) | [REPORT-TECHNICAL-v3.md](scripted/pool-small-conti/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](scripted/pool-small-conti/AUDIT-REPORT.md) |

### Agentic

| Sample | Description | Verdict | Report | Audit |
|--------|-------------|---------|--------|-------|
| `virussign-40f92672` | Packed Delphi-based loader | [malicious](agentic/virussign-40f92672/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-40f92672/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-40f92672/AUDIT-REPORT.md) |
| `virussign-8264dc61` | Generic packed dropper/loader | [malicious](agentic/virussign-8264dc61/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-8264dc61/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-8264dc61/AUDIT-REPORT.md) |
| `virussign-f622efa7` | UPX-packed malware/loader | [malicious](agentic/virussign-f622efa7/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-f622efa7/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-f622efa7/AUDIT-REPORT.md) |
| `virussign-970b822a` | ASPack-packed loader/dropper | [malicious](agentic/virussign-970b822a/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-970b822a/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-970b822a/AUDIT-REPORT.md) |
| `virussign-7edf35d0` | Themida-packed payload, T1027.002 | [malicious](agentic/virussign-7edf35d0/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-7edf35d0/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-7edf35d0/AUDIT-REPORT.md) |
| `virussign-9358c2e1` | UPX-packed dropper/loader | [malicious](agentic/virussign-9358c2e1/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/virussign-9358c2e1/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/virussign-9358c2e1/AUDIT-REPORT.md) |
| `lumma-stealer` | Lumma Stealer info-stealer | [malicious](agentic/lumma-stealer/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/lumma-stealer/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/lumma-stealer/AUDIT-REPORT.md) |
| `koi-stealer` | Packed Delphi-based loader/dropper | [malicious](agentic/koi-stealer/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/koi-stealer/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/koi-stealer/AUDIT-REPORT.md) |
| `pool-mid-quasar` | Quasar RAT | [malicious](agentic/pool-mid-quasar/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-quasar/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-quasar/AUDIT-REPORT.md) |
| `pool-large-darkgate` | darkgate/elex multi-family | [malicious](agentic/pool-large-darkgate/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-darkgate/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-darkgate/AUDIT-REPORT.md) |
| `pool-mid-vidar` | Vidar stealer, NSudo masquerade | [malicious](agentic/pool-mid-vidar/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-vidar/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-vidar/AUDIT-REPORT.md) |
| `pool-mid-mespinoza` | Mespinoza/Pysa ransomware, MS masquerade | [malicious](agentic/pool-mid-mespinoza/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-mid-mespinoza/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-mid-mespinoza/AUDIT-REPORT.md) |
| `pool-large-hive` | Hive ransomware, UPX-packed | [malicious](agentic/pool-large-hive/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-hive/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-hive/AUDIT-REPORT.md) |
| `pool-large-sliver` | Sliver C2 implant, packed ELF | [malicious](agentic/pool-large-sliver/verdict.json) | [REPORT-TECHNICAL-v3.md](agentic/pool-large-sliver/REPORT-TECHNICAL-v3.md) | [AUDIT-REPORT.md](agentic/pool-large-sliver/AUDIT-REPORT.md) |

### UI (manual runs)

| Sample | Description | Verdict | Report | Audit |
|--------|-------------|---------|--------|-------|

### Sample pool

150 InTheWild samples (50 small/mid/large) staged on the VM: see [`pool/`](pool/).
