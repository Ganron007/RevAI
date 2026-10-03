#!/usr/bin/env bash
# instrument-live-log.sh -- read a run's outcome from its artifacts in ONE pass.
#
# The standing rule is to monitor a run live and act on the FIRST error, and that
# "0 errors" is not evidence a stage worked -- measure the artifact. This makes
# both mechanical: one command, one read of each file, no grepping about in
# multiple SSH calls (each of which is a fresh shell, so nothing carries over and
# a stale read is easy to mistake for a current one).
#
# Exit codes:
#   0  the run finished and every gate is green
#   1  the run finished but something FAILED (stage rc, truncation, hollow, or
#      an unverified/indicators-removed finding)
#   2  the run is still in progress
#   3  usage error
#
# Usage:
#   ./instrument-live-log.sh                     # newest run in /opt/samples/logs
#   ./instrument-live-log.sh <sha256|case-dir>   # one specific run
#   ./instrument-live-log.sh --wait <sha256>     # block until the run ends

set -uo pipefail

LOGS_DIR="${REVAI_LOGS_DIR:-/opt/samples/logs}"
POLL_S=20
WAIT=0
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --wait) WAIT=1; shift ;;
    --poll) POLL_S="${2:?--poll requires seconds}"; shift 2 ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 3 ;;
    *) TARGET="$1"; shift ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 3; }; }
need python3

# ---------------------------------------------------------------- locate run
if [[ -z "$TARGET" ]]; then
  newest=$(ls -1dt "$LOGS_DIR"/*/ 2>/dev/null | head -1)
  [[ -z "$newest" ]] && { echo "no runs under $LOGS_DIR" >&2; exit 3; }
  CASE_DIR="${newest%/}"
elif [[ -f "$TARGET" ]]; then
  # A log file. The run-watched log lives BESIDE the case dirs and is named
  # `_watched_<sha12>.log`, so its parent is not the case dir -- resolve the
  # case from the sha embedded in the filename instead.
  LOG_OVERRIDE="$TARGET"
  base="$(basename "$TARGET")"
  sha12="${base#_watched_}"
  sha12="${sha12%.log}"
  case_dir=""
  [[ -n "$sha12" ]] && case_dir=$(ls -1dt "$LOGS_DIR/$sha12"* 2>/dev/null | head -1)
  if [[ -n "$case_dir" && -d "$case_dir" ]]; then
    CASE_DIR="$case_dir"
  else
    CASE_DIR="$(dirname "${TARGET%/}")"
    echo "  ! could not resolve a case dir from '$base'; using $CASE_DIR"
  fi
else
  if [[ -d "$TARGET" ]]; then
    CASE_DIR="${TARGET%/}"
  elif [[ -d "$LOGS_DIR/$TARGET" ]]; then
    CASE_DIR="$LOGS_DIR/$TARGET"
  else
    hit=$(ls -1d "$LOGS_DIR/$TARGET"* 2>/dev/null | head -1)
    [[ -z "$hit" ]] && { echo "no case dir for '$TARGET'" >&2; exit 3; }
    CASE_DIR="$hit"
  fi
fi
for sub in scripted agentic ui single; do
  [[ -f "$CASE_DIR/$sub/pipeline-audit.json" || -f "$CASE_DIR/$sub/pipeline_single.log" ]] && CASE_DIR="$CASE_DIR/$sub" && break
done

STAGE_JSON="$CASE_DIR/pipeline-audit.json"
# A log file passed on the command line wins: the run-watched log keeps the full
# stage history after the watchdog has quarantined the case dir.
LOG="${LOG_OVERRIDE:-$CASE_DIR/pipeline_single.log}"

[[ -d "$CASE_DIR" ]] || { echo "not a case dir: $CASE_DIR" >&2; exit 3; }
if [[ ! -f "$LOG" && ! -f "$STAGE_JSON" ]]; then
  echo "no run log or audit under $CASE_DIR (is a run started?)" >&2
  exit 3
fi

echo "== case: $CASE_DIR"

# ------------------------------------------------------------------- wait
if [[ "$WAIT" == "1" ]]; then
  if pgrep -f "pipeline_single.py" >/dev/null 2>&1; then
    for ((i=1; i<=3; i++)); do
      pgrep -f "pipeline_single.py" >/dev/null 2>&1 || break
      sleep "$POLL_S"
    done
    pgrep -f "pipeline_single.py" >/dev/null 2>&1 || echo "== run finished"
  fi
fi

RUNNING=0
pgrep -f "pipeline_single.py" >/dev/null 2>&1 && RUNNING=1
if [[ "$RUNNING" == "1" ]]; then
  echo "== run is STILL IN PROGRESS ($(uptime -p))"
fi

python3 - "$CASE_DIR" "$RUNNING" "$LOG" <<'PY'
import json, re, sys
from pathlib import Path

case = Path(sys.argv[1])
running = sys.argv[2] == "1"
# The shell resolved WHICH log to read (a run-watched log keeps the full
# stage history after the case dir has been quarantined); deriving it from
# the case dir here would ignore that override and read a rotated-away log.
log = Path(sys.argv[3])

text = log.read_text(errors="replace") if log.is_file() else ""
start = text.rfind("===== RUN START ")
slice_ = text[start:] if start >= 0 else text
if log.is_file() and start < 0:
    # No banner: the log predates the boundary (a legacy or hand-run stage). All
    # of it describes the current run.
    print("  ! no RUN START banner in the log; judging the whole file")

stages = re.findall(r"\[pipeline_single\]\s+([a-z_0-9]+)\s+rc=(\d+)\s+([0-9.]+)s", slice_)
total_s = 0.0
bad = []
print("== stages")
if not stages:
    print("   (none recorded yet)")
for name, rc, secs in stages:
    total_s += float(secs)
    flag = "ok  " if rc == "0" else "FAIL"
    print(f"   {flag} {name:22} rc={rc} {secs}s")
    if rc != "0":
        bad.append(f"stage {name} rc={rc}")
print(f"   elapsed across stages: {total_s:.1f}s")

print("== finish_reason across all LLM calls")
fin = {}
for m in re.finditer(r"finish=([a-zA-Z]+)", slice_):
    fin[m.group(1)] = fin.get(m.group(1), 0) + 1
if fin:
    for k in sorted(fin):
        marker = "  <-- truncation!" if k == "length" else ""
        print(f"   {k:10} {fin[k]}{marker}")
    if fin.get("length"):
        bad.append(f"{fin['length']} finish=length (truncated) calls")
else:
    print("   (no LLM timing lines)")

needles = [
    ("timeout", "llm timeout"),
    ("Traceback", "exception"),
    ("RC != 0", "stage non-zero rc"),
    ("empty content", "empty LLM response"),
]
print("== anomalies")
found_anom = False
for needle, label in needles:
    n = slice_.count(needle)
    if n:
        print(f"   {label:24} {n}")
        found_anom = True
        if needle in ("timeout", "Traceback"):
            bad.append(f"{label} x{n}")
if not found_anom:
    print("   none")

audit = case / "pipeline-audit.json"
if audit.is_file():
    try:
        d = json.loads(audit.read_text(errors="replace"))
        print("== audit")
        print(f"   all_green = {d.get('all_green')}")
        for k, v in (d.get("stage_ok") or {}).items():
            if v is False:
                print(f"   FAIL stage {k}")
                bad.append(f"audit stage {k}")
        qp = ((d.get("stages") or {}).get("publish") or {})
        cs = ((qp.get("quality_pack") or {}).get("checks") or {})
        ci = cs.get("claimed_ioc_verification") or {}
        if ci:
            print(f"   iocs: claims={ci.get('claims')} verified={ci.get('verified')} "
                  f"unverified={ci.get('unverified')} excluded={ci.get('excluded')}")
            if ci.get("unverified"):
                for it in (ci.get("unverified_items") or [])[:5]:
                    print(f"      UNVERIFIED {it.get('type')}: {str(it.get('value'))[:70]}")
                bad.append(f"unverified_iocs={ci['unverified']}")
        for name in ("master_v2", "technical_v2", "technical_v3"):
            c = cs.get(name) or {}
            if c:
                miss = c.get("missing_sections") or []
                stub = c.get("stub_sections") or []
                if miss or stub:
                    bad.append(f"{name} missing={len(miss)} stub={len(stub)}")
        print(f"   quality issues: {(qp.get('quality_pack') or {}).get('issues') or ['none']}")
        hs = (d.get("stages") or {}).get("hollow_success") or {}
        if hs.get("ok") is False:
            for f in (hs.get("findings") or [])[:6]:
                print(f"   HOLLOW {f.get('check')}: {str(f.get('detail'))[:80]}")
            bad.append("hollow_success failed")
        elif "ok" in hs:
            print(f"   hollow_success ok={hs.get('ok')} "
                  f"findings={len(hs.get('findings') or [])}")
    except Exception as exc:
        print(f"== audit: unreadable ({exc})")
        bad.append("audit json unreadable")
else:
    print("== audit: not written yet")

print("== report artifacts")
for name in ("REPORT-MASTER-v2.md", "REPORT-TECHNICAL-v2.md",
             "REPORT-MASTER-v3.md", "REPORT-TECHNICAL-v3.md"):
    p = case / name
    if p.is_file():
        print(f"   {name:26} {p.stat().st_size:,} bytes")
    else:
        print(f"   {name:26} MISSING")

print("== indicator scrub (plan #42)")
for fname in ("report-v2.json", "report-technical-v2.json",
              "report-technical-v3.json"):
    p = case / fname
    if not p.is_file():
        continue
    try:
        d = json.loads(p.read_text(errors="replace"))
    except Exception:
        continue
    s = d.get("indicator_scrub") or {}
    if s:
        rm = s.get("indicators_removed", 0)
        left = s.get("remaining_unverified")
        print(f"   {fname:26} removed={rm} remaining_unverified={left}")
        if left:
            bad.append(f"{fname} unverified indicators remain")
sr = case / "section-results-v3.json"
if sr.is_file():
    try:
        d = json.loads(sr.read_text(errors="replace"))
        s = d.get("master_v3_indicator_scrub") or {}
        if s:
            print(f"   master_v3 record          removed={s.get('indicators_removed')} "
                  f"remaining={s.get('remaining_unverified')}")
    except Exception:
        pass

verdict = case / "verdict.json"
if verdict.is_file():
    try:
        d = json.loads(verdict.read_text(errors="replace"))
        print(f"== verdict: {d.get('verdict')} score={d.get('score')} "
              f"source={d.get('source')}")
    except Exception:
        pass

print()
if bad:
    print(f"RESULT: {len(bad)} problem(s)")
    for b in bad:
        print(f"   - {b}")
    sys.exit(1)
if running:
    print("RESULT: still running, nothing to report yet")
    sys.exit(2)
print("RESULT: all gates green")
sys.exit(0)
PY
rc=$?
echo "== exit=$rc"
exit $rc