# WinRE Remote Driver (Optional) — dynamic analysis for RevAI

RevAI is static-first. Optional Windows dynamic analysis — detonation and
debugger-driven unpacking — is provided by
[WinRE](https://github.com/Ganron007/WinRE), a FlareVM-based analysis pipeline
with a remote driver. This page covers **both halves**: installing WinRE on the
RevAI host, and driving it from the RevAI Console / pipeline so RevAI stays the
single control point.

Two repositories, one product:

| Repo | Role | What you get |
|---|---|---|
| **[RevAI](https://github.com/Ganron007/RevAI)** (this repo) | control plane | static pipeline, Console UI, LLM config, **WinRE ingestion** (reports/status) and the **optional trigger** |
| **[WinRE](https://github.com/Ganron007/WinRE)** | execution plane + FlareVM side | `winre.pipeline` remote driver, detonation/debug passes, FlareVM provisioning scripts, its own docs |

Both are public — cloning either is a plain `git clone`. RevAI works fully
without WinRE; WinRE can also be used standalone.

## Topology

```
RevAI host (this machine)                    Windows analysis VM (FlareVM-based)
  winre.remote_driver process                  tools only, air-gapped
  - LangGraph agent + all LLM calls      ───►  Ghidra/IDA/Malcat SQL+MCP
  - WinRE package + Python deps          SSH   x64dbg/WinDbg MCP
  - SSH/SCP to the Windows VM            SCP   detonation job (FakeNet,
  - the only machine holding LLM keys          Procmon, Frida, pe-sieve)
```

The driver process runs on the RevAI host; the Windows VM only executes tools.
The Windows VM never receives, stores, or needs LLM configuration — which is
what keeps it safe to air-gap, including during detonation.

## Setup

### 1. Optional WinRE install on the RevAI host (one step)

`install/setup-remnux.sh` can install WinRE for you (opt-in, soft-fail):

```bash
REVAI_WITH_WINRE=1 sudo -E ./install/setup-remnux.sh
```

It clones the public WinRE repo into `/opt/winre` (pin a ref with
`REVAI_WINRE_REF=<tag|branch>`, override the URL with `REVAI_WINRE_REPO`),
creates `/opt/winre/venv`, installs the driver extras, and scaffolds
`/opt/winre/.env` from WinRE's template. Air-gapped installs: drop a WinRE
archive at `internal/winre.zip` instead. Without the flag, the step just warns —
RevAI stays static-only.

### 2. Windows VM (FlareVM)

Provision the Windows VM with WinRE's own scripts (from the WinRE repository):
`install/setup-flarevm.ps1` then `install/verify-flarevm.ps1`. Keep WinRE's
`.env` on the Windows side free of LLM keys and make SSH reachable from the
RevAI host (`docs/SSH-CONTRACT.md` in WinRE).

Manual alternative for the RevAI host (if you prefer):

```bash
scp -r WinRE/winre <revai-user>@<revai-host>:/opt/winre/
python3 -m venv --system-site-packages /opt/winre/venv
/opt/winre/venv/bin/pip install langgraph langchain-openai langchain-core pydantic
```

### 3. SSH access to the Windows VM

```bash
mkdir -p /opt/winre/.ssh && chmod 700 /opt/winre/.ssh
ssh-keygen -t ed25519 -N "" -f /opt/winre/.ssh/winre-flare
# Authorize the public key on the Windows VM (administrator users: place it in
# the OpenSSH administrators_authorized_keys file), then verify:
ssh -i /opt/winre/.ssh/winre-flare <windows-user>@<windows-vm> "echo OK"
```

### 4. Point RevAI at the FlareVM

Two equivalent places — pick either; they resolve in this order:
**process environment → Console Settings → `/opt/winre/.env`** (WinRE's own file
is the fallback for standalone use).

**Console (recommended):** Settings → **Dynamic analysis (WinRE — optional)**

| Field | Meaning | Default |
|---|---|---|
| Enable dynamic analysis | master switch | Off |
| FlareVM address | host-only IP/hostname of the Windows VM | — |
| SSH user / port | e.g. `FLARE-VM`, `22` | `FLARE-VM` / `22` |
| SSH key path | path **on the RevAI VM**, chmod 600 — the Console never stores key material | `~/.ssh/winre-flare` |
| Detonation window (s) | WinRE `--max-seconds`; delayed C2 needs a longer window | 150 |
| Mode | `agentic` (LLM-driven) or `static` (deterministic) | agentic |
| Snapshot gate | `observe` / `enforce` (block without a clean snapshot marker) / `off` | observe |

The panel has a **Test connection** button (SSH probe, no detonation) and shows
the resolved state (e.g. `flare_key_missing: …`).

**CLI equivalents:** `REVAI_WINRE_ENABLED=1`, `FLARE_HOST`, `FLARE_USER`,
`FLARE_SSH_PORT`, `FLARE_SSH_KEY`, `REVAI_WINRE_MODE`, `REVAI_WINRE_WINDOW`,
`REVAI_WINRE_SNAPSHOT_GATE`, `REVAI_WINRE_LOGS`, `REVAI_WINRE_ROOT`,
`REVAI_WINRE_PY`, `REVAI_WINRE_TIMEOUT` (full table in
[`OPERATE.md`](OPERATE.md)).

### 5. WinRE's own configuration (unchanged, WinRE-owned)

WinRE keeps its LLM/detonation config in `/opt/winre/.env` (600; never commit):

```
# /opt/winre/.env  (chmod 600; gitignored)
WINRE_LLM_BASE_URL=https://<endpoint>/v1
WINRE_LLM_MODEL=<model>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=high
WINRE_SNAPSHOT_GATE=observe
```

Same key across RevAI and WinRE, or per-project keys: both are supported. Note
that they are **two independent files**: RevAI never reads WinRE's key and WinRE
never reads RevAI's, so "the same key" means the same values are written in both
files (`REVAI_LLM_*` in `/opt/revai/config/llm.env`, `WINRE_LLM_*` in
`/opt/winre/.env`). The FlareVM never holds LLM configuration. The authoritative
wiring contract (resolution order, spawn-site mapping, troubleshooting) lives in
the WinRE repository:
[`docs/REVAI-BRIDGE.md`](https://github.com/Ganron007/WinRE/blob/master/docs/REVAI-BRIDGE.md).

## Running it from RevAI (optional, three ways)

WinRE only runs when **both** the master switch is on **and** a trigger fires.
All three triggers use the same runner (`revai/winre_runner.py`) and the same
settings:

| Trigger | How | Notes |
|---|---|---|
| **Per-case button** | Console → a case → **Run WinRE** (next to the winre chip) | confirmation prompt; runs in the background; status lands in the case |
| **Before publish (per run)** | Settings → Run configuration → **Detonate with WinRE before publish** = On | the orchestrator/scripted pipeline runs the detonation as an optional stage before publishing, so the report includes the fresh pack |
| **CLI** | `REVAI_WINRE_RUN=1 python3 stage_orchestrator.py --sha <sha>` (or `pipeline_single.py <sample>`) | same settings resolution; `winre_runner.py <sha>` runs the detonation alone |

Failure semantics are honest and soft: unavailable FlareVM, missing key, snapshot
gate refusal, timeout, or a non-zero WinRE exit are **recorded**
(`logs/<sha>/<mode>/winre-run.json` + `winre-run.log`) and never block the static
pipeline. Without a pack the reports stay byte-identical to a WinRE-less install.

Standalone WinRE (no RevAI trigger), for reference:

```bash
cd /opt/winre
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode static
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode agentic
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode agentic --agentic-dbg
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode static --dynamic --pesieve
```

| Mode | LLM required | Windows VM keys/internet | Purpose |
|---|---|---|---|
| `--mode static` | no | no | deterministic static deep dive on Windows tooling |
| `--mode agentic` | yes | no | agent-driven Windows static analysis |
| `--mode agentic --agentic-dbg` | yes | no | debugger-assisted unpacking (OEP/dumps/bp-trace) |
| `--dynamic` | no | no | detonation (FakeNet, Procmon, Frida, pe-sieve, memory) |

## Verify

```bash
cd /opt/winre
./venv/bin/python -c "from winre.llm_client import available; print('LLM reachable:', available())"
```

Results land in the driver's evidence directory (`/opt/winre/logs/<sha>/<mode>/`).
Detonation artifacts are corroborating evidence only: high-signal static YARA
cannot be cleared by dynamic findings (`static_yara_wins`).

`install/verify-remnux.sh` reports the WinRE state (install/venv/.env/FlareVM
address) as warnings when WinRE is absent — a static-only install always passes.

## Troubleshooting

| Symptom | Check |
|---|---|
| `winre_disabled` / availability `ok=false` | enable Settings → Dynamic analysis (WinRE); availability reasons are returned verbatim by `GET /api/winre/status/<sha>` |
| `flare_key_missing` | the SSH key path must exist on the RevAI host (mode 600, readable by the service user); the path is the only thing the Console stores |
| SSH probe fails | `ssh -i <key> -p <port> <user>@<flare-host> echo ok` from the RevAI host; the Windows VM's OpenSSH server must be running |
| Detonation ran but WinRE logs `dynamic=not-run` / `no fresh META from this run` | clock skew: the analysis host and the Windows VM must agree on time. Check `timedatectl` on the RevAI host and enable NTP (`sudo timedatectl set-ntp true`). A skewed control-plane clock fails WinRE's freshness check; the pack is still ingested by RevAI and the corroboration block still renders |
| `no dumps captured`, no unpack artifact | pe-sieve had nothing to dump (sample exited early or unpacked nothing) — expected for small samples; the run is still valid evidence, reported honestly |
| Reports unchanged after a detonation | corroboration is presence-gated: re-run publish + section for the case with the same mode (`REVAI_RUN_MODE=<mode> python3 publish_report_v2.py <sha> --template full`, then `section_publisher.py <sha>`) |

## Reporting integration (RevAI side)

RevAI discovers WinRE packs automatically: `load_dynamic_pack()` scans
`REVAI_WINRE_LOGS` (default `/opt/winre/logs`, mode-keyed sections) and the
RevAI case directory. When a pack exists for the sample, the technical report
and evidence bundle gain a deterministic **"Dynamic Corroboration (WinRE
detonation)"** block:

- detonation window actually used, with a coverage caveat (activity outside the
  window may be missed);
- runtime network indicators (DNS/SNI/HTTP) and dropped file paths;
- the agentic-dbg unpack artifact, with a static pass (pefile + `capa`) when the
  dump is PE-valid;
- an explicit `static_yara_wins` policy line — dynamic evidence corroborates,
  never overrides, static findings or the verdict gates.

The block is **presence-gated**: samples analyzed without WinRE produce exactly
the same reports as before (no empty sections). Disable it explicitly with
`REVAI_DISABLE_DYNAMIC_CORROBORATION=1`.

## Console reference (RevAI side)

| Where | What |
|---|---|
| Settings → **Dynamic analysis (WinRE)** | enable switch, FlareVM address/user/port, SSH key path, window, mode, snapshot gate, **Test connection** |
| Settings → Run configuration → **Dynamic corroboration** | `On` (default) uses detonation packs when present; `Off` writes static-only reports (drives both the evidence block and the report section) |
| Settings → Run configuration → **Detonate with WinRE before publish** | opt-in per-run detonation stage |
| Case view → **Run WinRE** | operator-triggered detonation for the selected case |
| Orchestrator panel → **winre dynamic** chip | `running…` during a detonation, `pack · N DNS` when a pack exists, `no pack`, `not configured`, `off` (failed runs show `failed` with the reason in the tooltip) |
| `GET /api/winre/status/<sha>?mode=…` | pack status + last run (`run`) + availability (`available`) |
| `POST /api/winre/test` | SSH probe with the saved settings |
| `POST /api/winre/run/<sha>` | start a detonation (202; 409 while running; 400 with the reason when unavailable) |

The status surfaces are read-only and fail open; with no WinRE install the
pipeline behaves exactly as without it.

## Safety

- The Windows VM runs malware: restore its clean snapshot after every
  detonation and keep it on an isolated lab network.
- LLM keys live only on the RevAI host, in `/opt/winre/.env` (or the process
  environment). Never place them on the Windows VM.
- No secrets in the Console: WinRE settings store the SSH key **path** only.
