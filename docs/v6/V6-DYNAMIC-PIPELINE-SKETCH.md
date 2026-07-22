# V6 Track B — Dynamic Analysis Pipeline (sketch)

> **Start after V6.1→RevAI.** Parent: `PLAN-v6-LLM-ONLY-AND-DYNAMIC.md` Track **V6.2**.  
> **V6.3** (agentic) follows V6.2→RevAI.  
> Home: `Tools/v6_deploy/` · Related: V1.9 Flare-VM manual dynamic scripts (`Tools/flarevm-deploy/dynamic/`).

## Problem

Remnux standard/large spine is **static-first** + light Speakeasy Unicorn emulation. That misses:

| Gap | Why Speakeasy/Remnux falls short |
|-----|----------------------------------|
| Full network / C2 | Needs real sockets + DNS + (optional) fake sink |
| Multi-process / injection | Needs real Windows process model |
| Kernel / drivers | Needs kernel debugger or driver load path |
| .NET CLR | Speakeasy is native-PE oriented |
| Sleep/evasion | Emulators skip or fail long delays |
| GUI / user interaction | Needs desktop session |
| Modern packers / Rust binders | Often don't unpack under Unicorn |

## Recommendation (do **not** fork the whole product)

Keep **one product, two modes** (same pattern as standard/large):

```
STATIC spine (today)          DYNAMIC spine (V6)
intake → quick → deep → …     dynamic_intake → detonate → collect → merge → publish
         \_______________________________________________/
                         evidence merge into same logs/<sha>/
```

- **Do not** replace Ghidra/IDA/capa with sandbox-only verdicts.
- **Do** add an optional stage `dynamic_run_v2.py` that writes `logs/<sha>/dynamic/` and feeds publish/section_publisher like other tools.
- Verdict policy stays: high-signal YARA + local tools win; sandbox is corroboration.

## Preferred host: Flare-VM (.42), not more Speakeasy on Remnux

You already have Flare-VM with Malcat/Ghidra/IDA + Frida/x64dbg/WinDbg/API Monitor scripts (V1.9). Use that as the **detonation worker**.

### Network layout (lab)

```
Remnux .41 (orchestrator)          Flare-VM .42 (detonate)
  quick_scan / deep_dive    --SMB/SCP-->  C:\samples\<sha>\sample.exe
  dynamic_run_v2.py         --WinRM/SSH--> run frida/procmon/inetsim-like sink
  pull artifacts            <--JSON/PCAP--  C:\samples\<sha>\dynamic\
  merge into logs/<sha>/
```

Practical options (pick one later):

1. **WinRM + PowerShell** from Remnux → Flare (scripted, CADRE-like Ansible style)
2. **SMB share** of `/opt/samples` → `\\flare\samples` + scheduled task / watcher on Flare
3. **Small HTTP agent** on Flare (`dynamic_agent.py`) that accepts job JSON and returns artifact zip

Start with (1)+(2): Remnux copies sample, kicks `frida_api_trace.py` + procmon filter, pulls `*.trace.json` + procmon CSV + optional pcap.

### What to collect (MVP)

| Artifact | Tool on Flare | Merge as |
|----------|---------------|----------|
| API trace JSONL | existing `frida_api_trace.py` | `dynamic/frida_trace.json` |
| Process/file/reg | procmon (filter from `apimon_filter.py`) | `dynamic/procmon.csv` |
| Network summary | FakeNet-NG / INetSim / Wireshark on Flare host-only NIC | `dynamic/network.json` + pcap |
| Screenshots | optional | `dynamic/screens/` |

### What to defer

- Full kernel driver fuzzing
- Interactive GUI click-farm
- Unrestricted internet (use sink / allowlist only)

## Speakeasy role after V6

Keep Speakeasy on Remnux as **cheap pre-filter** for small native PEs (already in deep).  
If Speakeasy produces rich API events → skip Flare for that sample.  
If Speakeasy empty/timeout/large/Rust/.NET → queue Flare detonation.

## Checklist IDs (Track B — under V6.2)

| ID | Item |
|----|------|
| V6.2.1 | Spec: dynamic evidence schema under `logs/<sha>/dynamic/` |
| V6.2.2 | Remnux→Flare job transport (WinRM or agent) |
| V6.2.3 | Wire V1.9 Frida/procmon scripts into non-interactive job |
| V6.2.4 | Network sink (FakeNet/INetSim) on Flare lab NIC |
| V6.2.5 | `dynamic_run_v2.py` + TOOL_MANIFEST entry + publish cards |
| V6.2.6 | Accuracy policy: sandbox cannot clear CADRE_* YARA |
| V6.2.7 | Standard PE E2E + one large PE E2E packs |

## Relation to V5 / V6.1 / V7

- **V5.13**: optional VT/HA *hash* enrich on Remnux (no detonation).
- **V6.1**: LLM-only live static path (RAG off) — primary focus after S9.
- **V6.2**: real Windows dynamic on Flare — this sketch.
- **V7**: RAG may return after RE-primary KB.
