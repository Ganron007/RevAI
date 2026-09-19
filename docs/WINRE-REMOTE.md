# WinRE Remote Driver (Optional)

RevAI is static-first. Optional Windows dynamic analysis — detonation and
debugger-driven unpacking — is provided by [WinRE](https://github.com/Ganron007/WinRE),
a FlareVM-based analysis pipeline with a remote driver. This page covers
driving WinRE **from the RevAI host** so that RevAI stays the single control
point.

## Topology

```
RevAI host (this machine)                    Windows analysis VM (FlareVM-based)
  winre.remote_driver process                  tools only, air-gapped
  - LangGraph agent + all LLM calls      ───►  Ghidra/IDA/Malcat SQL+MCP
  - WinRE package + Python deps          SSH   x64dbg/WinDbg MCP
  - SSH/SCP to the Windows VM            SCP   detonation job (FakeNet,
  - the only machine holding LLM keys          Procmon, Frida, pe-sieve)
```

The driver process runs on the RevAI host; the Windows VM only executes
tools. The Windows VM never receives, stores, or needs LLM configuration —
which is what keeps it safe to air-gap, including during detonation.

## Setup

### 1. Windows VM

Install WinRE and its tool stack per the WinRE repository (`INSTALL` /
`PREREQS` docs there), then make SSH reachable from the RevAI host. Keep
WinRE's own `.env` free of LLM keys on this machine.

### 2. RevAI host

Copy the WinRE package (a repo clone, or at minimum its `winre/` directory)
onto the RevAI host, for example from the machine holding the clone:

```bash
scp -r WinRE/winre <revai-user>@<revai-host>:/opt/winre/
```

Then, on the RevAI host, create the driver's virtualenv:

```bash
ssh <revai-user>@<revai-host>
python3 -m venv /opt/winre/venv
/opt/winre/venv/bin/pip install langgraph langchain-openai langchain-core pydantic
```

### 3. SSH access to the Windows VM

```bash
mkdir -p /opt/winre/.ssh && chmod 700 /opt/winre/.ssh
ssh-keygen -t ed25519 -N "" -f /opt/winre/.ssh/winre-flare
# Authorize the public key on the Windows VM (administrator users: place it
# in the OpenSSH administrators_authorized_keys file), then verify:
ssh -i /opt/winre/.ssh/winre-flare <windows-user>@<windows-vm> "echo OK"
```

### 4. Driver configuration

WinRE reads a WinRE-owned environment file — keep it out of RevAI's
`llm.env` so each project's secret has a single, clearly-owned surface:

```
# /opt/winre/.env  (chmod 600; gitignored)
FLARE_HOST=<windows-vm>
FLARE_USER=<windows-user>
FLARE_SSH_KEY=/opt/winre/.ssh/winre-flare
FLARE_SSH_PORT=22
WINRE_LLM_BASE_URL=https://<endpoint>/v1
WINRE_LLM_MODEL=<model>
WINRE_LLM_API_KEY=<key>
WINRE_LLM_REASONING=high
WINRE_SNAPSHOT_GATE=observe
WINRE_PIPELINE_LOGS=/opt/winre/logs
```

Same key across RevAI and WinRE, or per-project keys: both are supported.
The surfaces stay separate either way — the choice is a one-line value, no
code change and no rewiring. Process environment variables override the file
for a single run.

The authoritative wiring contract (resolution order, spawn-site mapping,
troubleshooting) lives in the WinRE repository:
[`docs/REVAI-BRIDGE.md`](https://github.com/Ganron007/WinRE/blob/master/docs/REVAI-BRIDGE.md).

## Running

```bash
cd /opt/winre

# Deterministic static deep dive on the Windows VM (no LLM calls)
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode static

# Agentic deep dive (uses the configured LLM on the RevAI host)
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode agentic

# Agentic + bounded x64dbg debug tools (unpack assist; no detonation)
./venv/bin/python -m winre.pipeline <sample> --driver remote --mode agentic --agentic-dbg

# Full static + detonation (needs a restored VM snapshot; restore after)
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

## Console options (RevAI side)

WinRE is optional in the Console, and its state is visible before a run:

| Where | What |
|---|---|
| Settings -> Run configuration -> **Dynamic corroboration** | `On` (default) uses detonation packs when present; `Off` writes static-only reports. The toggle drives both halves — the evidence-pack corroboration block and the deterministic "Dynamic Analysis (WinRE detonation)" report section |
| Run configuration -> pack root override | point a case at packs that live outside `/opt/winre/logs` (`REVAI_WINRE_LOGS`) |
| Orchestrator panel -> **winre dynamic** chip | `pack · N DNS` when a pack exists for the open case, `no pack` when the root is reachable but this sample has none, `not configured` when the root is absent, `off` when the toggle is disabled |
| `GET /api/winre/status/<sha>?mode=<scripted|agentic|ui>` | the same status for scripts: `pack_present`, `source`, `dns`/`http`/`sni`/`dropped` counts, `unpack_artifact`, `section_renders` |

The chip and endpoint are read-only and fail open; with no WinRE install the
pipeline behaves exactly as without it.

## Safety

- The Windows VM runs malware: restore its clean snapshot after every
  detonation and keep it on an isolated lab network.
- LLM keys live only on the RevAI host, in `/opt/winre/.env` (or the process
  environment). Never place them on the Windows VM.
