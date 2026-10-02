#!/usr/bin/env bash
# run-watched.sh — run a sample under a watcher that acts on the FIRST error.
#
# Why this exists (plan item #43, 2026-10-02): a full win32k_dll run finished at
# some point and roughly eight hours passed before the result was read. The
# standing rule is to monitor a run live and act on the first error rather than
# reacting afterwards. Monitoring depended on remembering to look, so it did not
# happen. This puts the watching in the run itself.
#
# It does three things a background launch cannot:
#   1. streams each stage line as it appears, so progress is observable
#   2. classifies the FIRST anomaly the moment it is written, with the stage it
#      belongs to, instead of dumping a log to be read hours later
#   3. optionally aborts on a fatal signal, so a doomed run stops burning time
#
# Usage:
#   scripts/run-watched.sh <sample-path> [--sha <sha256>] [--abort-on-error]
#                          [--timeout-minutes N] [--no-reboot]
#
# Exit codes: 0 run completed and every stage rc=0 · 1 a stage failed ·
#             2 a fatal signal fired (aborted) · 3 usage/environment error.
#
# REBOOT BEFORE EVERY SAMPLE RUN (docs/OPERATE.md). --no-reboot exists only for
# the case where the operator has just rebooted by hand; passing it on a loaded
# VM invalidates the run and the summary says so.
set -uo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPTS_DIR")"

SAMPLE=""
SHA=""
ABORT_ON_ERROR=0
TIMEOUT_MINUTES=240
REBOOT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha) SHA="$2"; shift 2 ;;
    --abort-on-error) ABORT_ON_ERROR=1; shift ;;
    --timeout-minutes) TIMEOUT_MINUTES="$2"; shift 2 ;;
    --no-reboot) REBOOT=0; shift ;;
    -h|--help) sed -n '2,26p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 3 ;;
    *) SAMPLE="$1"; shift ;;
  esac
done

if [[ -z "$SAMPLE" ]]; then
  echo "usage: $(basename "$0") <sample-path> [--sha <sha>] [--abort-on-error]" >&2
  exit 3
fi
if [[ ! -f "$SAMPLE" ]]; then
  echo "sample not found: $SAMPLE" >&2
  exit 3
fi

log() { printf '[watch] %s\n' "$*"; }
fail() { printf '[watch] ERROR: %s\n' "$*" >&2; }

# --------------------------------------------------------------------- reboot
if [[ "$REBOOT" == "1" ]]; then
  log "rebooting before the run (mandatory; see docs/OPERATE.md)"
  sudo reboot
  log "reboot issued — this script cannot continue across it. Re-run it once SSH"
  log "is back; it will detect the fresh boot and skip the reboot."
  exit 0
fi

UPTIME_MIN=$(uptime -p | grep -oE '[0-9]+' | head -1)
UPTIME_MIN="${UPTIME_MIN:-9999}"
if [[ "$UPTIME_MIN" -gt 20 ]]; then
  log "WARNING: VM uptime is ${UPTIME_MIN} minutes. Runs on a loaded VM are not"
  log "comparable with a fresh-boot run (intake alone varied 45.8s -> 658.8s)."
fi
command -v timedatectl >/dev/null && {
  timedatectl 2>/dev/null | grep -q "System clock synchronized: yes" \
    || fail "clock is not synchronised; a skewed clock breaks WinRE freshness checks"
}

# ------------------------------------------------------------------ preflight
if [[ -z "$SHA" ]]; then
  if command -v sha256sum >/dev/null; then
    SHA=$(sha256sum "$SAMPLE" | awk '{print $1}')
  else
    fail "cannot determine sha256; pass --sha"
    exit 3
  fi
fi
log "sha256: $SHA"
log "sample: $SAMPLE"

LOG_DIR=/opt/samples/logs
CASE_DIR="$LOG_DIR/$SHA/scripted"
RUN_LOG="$LOG_DIR/_watched_${SHA:0:12}.log"

# Quarantine any previous case dir so the run starts clean and the previous
# artifacts stay available for comparison.
if [[ -d "$CASE_DIR" ]]; then
  STAMP=$(date -u +%Y%m%dT%H%M%SZ)
  mv "$CASE_DIR" "$CASE_DIR.pre-watched-$STAMP"
  log "quarantined previous case dir -> $(basename "$CASE_DIR").pre-watched-$STAMP"
fi

# ------------------------------------------------------------------- launch
set -a
# shellcheck disable=SC1091
[[ -f /opt/revai/config/llm.env ]] && . /opt/revai/config/llm.env
set +a

export REVAI_RUN_MODE="${REVAI_RUN_MODE:-scripted}"
export REVAI_ENABLE_ARTIFACT_GEN="${REVAI_ENABLE_ARTIFACT_GEN:-1}"
export REVAI_ENABLE_AGENTIC_RECOVERY="${REVAI_ENABLE_AGENTIC_RECOVERY:-1}"
export REVAI_ENABLE_EMULATION_ORACLE="${REVAI_ENABLE_EMULATION_ORACLE:-1}"
export REVAI_ENABLE_UNPACK_PASS="${REVAI_ENABLE_UNPACK_PASS:-1}"
export REVAI_TI_ENRICH="${REVAI_TI_ENRICH:-0}"
# Scripted mode is deterministic by contract.
export REVAI_STAGE_RETRIES="${REVAI_STAGE_RETRIES:-0}"
export REVAI_TOOL_RETRIES="${REVAI_TOOL_RETRIES:-0}"

: > "$RUN_LOG"
log "log: $RUN_LOG"

# Resolve the directory that actually holds pipeline_single.py. Two layouts:
#   deployed  -> /opt/scripts/run-watched.sh, so SCRIPTS_DIR is the scripts dir
#   from repo -> <repo>/scripts/run-watched.sh, and the module lives in revai/
# Getting this wrong is not hypothetical: an earlier revision assumed
# SCRIPTS_DIR/.. and cd'd to /opt, so every run died instantly with
# "can't open file '/opt/pipeline_single.py'".
if [[ -f "$SCRIPTS_DIR/pipeline_single.py" ]]; then
  RUN_DIR="$SCRIPTS_DIR"
elif [[ -f "$REPO_ROOT/revai/pipeline_single.py" ]]; then
  RUN_DIR="$REPO_ROOT/revai"
else
  fail "cannot locate pipeline_single.py near $SCRIPTS_DIR or $REPO_ROOT/revai"
  exit 3
fi
log "run dir: $RUN_DIR"
cd "$RUN_DIR" || { fail "cannot cd to $RUN_DIR"; exit 3; }
[[ -f pipeline_single.py ]] || { fail "pipeline_single.py missing in $RUN_DIR"; exit 3; }

python3 pipeline_single.py "$SAMPLE" > "$RUN_LOG" 2>&1 &
RUN_PID=$!
log "pid: $RUN_PID"

# ------------------------------------------------------------------- watch
# First-error classification. Each pattern is fatal enough to stop a scripted
# run early: a failed stage cannot be fixed by letting the rest proceed, and an
# exhausted LLM call means a chunk of analysis is silently absent from the
# report.
declare -A SEEN
FIRST_ERROR=""
START=$(date +%s)

watch_loop() {
  local deadline=$(( START + TIMEOUT_MINUTES * 60 ))
  while kill -0 "$RUN_PID" 2>/dev/null; do
    local now; now=$(date +%s)
    if (( now > deadline )); then
      printf '[watch] TIMEOUT after %s minutes\n' "$TIMEOUT_MINUTES"
      kill -TERM "$RUN_PID" 2>/dev/null
      return 2
    fi

    # 1. a stage that exited non-zero
    while read -r stage rc secs; do
      [[ -z "$stage" ]] && continue
      [[ "${SEEN[$stage]:-}" == "1" ]] && continue
      SEEN[$stage]=1
      if [[ "$rc" == "0" ]]; then
        printf '[watch]   %-20s ok %8ss\n' "$stage" "$secs"
      else
        printf '[watch]   %-20s FAILED rc=%s (%ss)\n' "$stage" "$rc" "$secs"
        [[ -z "$FIRST_ERROR" ]] && FIRST_ERROR="stage $stage rc=$rc"
      fi
    done < <(grep -aoE '\[[a-z_0-9]+\] [a-z_0-9]+ rc=[0-9]+ [0-9.]+s' "$RUN_LOG" 2>/dev/null \
             | sed -E 's/^\[[a-z_0-9]+\] ([a-z_0-9]+) rc=([0-9]+) ([0-9.]+)s$/\1 \2 \3/')

    # 2. fatal signals, reported once each, with the stage they belong to
    check_signal() {
      local label="$1" pattern="$2" fatal="$3" current prev
      # `grep -c` prints 0 AND exits 1 when there are no matches, so `|| echo 0`
      # appends a second line and the arithmetic below sees "0\n0". Take grep's
      # own count and default only when it printed nothing (no file yet).
      current=$(grep -acE "$pattern" "$RUN_LOG" 2>/dev/null)
      [[ -z "$current" ]] && current=0
      prev="${SEEN[$label]:-0}"
      (( current > prev )) || return 0
      SEEN[$label]=$current
      local stage
      stage=$(tail -40 "$RUN_LOG" 2>/dev/null \
              | grep -aoE 'CMD \S+ ([a-z_0-9]+)\.py' | tail -1 | sed -E 's/.* ([a-z_0-9]+)\.py/\1/')
      printf '[watch]   ! %s x%s (in: %s)\n' "$label" "$current" "${stage:-?}"
      [[ -z "$FIRST_ERROR" ]] && FIRST_ERROR="$label during ${stage:-unknown}"
      [[ "$fatal" == "1" && "$ABORT_ON_ERROR" == "1" ]] && {
        printf '[watch] aborting on first error (--abort-on-error)\n'
        kill -TERM "$RUN_PID" 2>/dev/null
        sleep 5
        kill -KILL "$RUN_PID" 2>/dev/null
        return 2
      }
    }

    check_signal "stage-kill"    '^===== TIMEOUT$'                            1
    check_signal "llm-timeout"   'attempt [0-9]+/[0-9]+ timed out'            1
    check_signal "llm-empty"     'returned no usable content'                 0
    check_signal "http-429"      'HTTP 429'                                   0
    check_signal "http-5xx"      'HTTP 50[0-9]'                               0
    check_signal "hollow"        'hollow_success.*false'                      1

    sleep 20
  done
  return 0
}

watch_loop
WATCH_RC=$?
wait "$RUN_PID" 2>/dev/null
RUN_RC=$?

# ------------------------------------------------------------------ summary
printf '\n'
log "==================================================================="
log "run finished (watch rc=$WATCH_RC, pipeline rc=$RUN_RC)"
log "sha256: $SHA"
log "log   : $RUN_LOG"
[[ -d "$CASE_DIR" ]] && log "case  : $CASE_DIR"
printf '\n'
grep -aoE '\[[a-z_0-9]+\] [a-z_0-9]+ rc=[0-9]+ [0-9.]+s' "$RUN_LOG" 2>/dev/null \
  | sed -E 's/^\[[a-z_0-9]+\] ([a-z_0-9]+) rc=([0-9]+) ([0-9.]+)s$/\1 rc=\2 \3s/' \
  | awk '{printf "  %-22s %-10s %s\n", $1, $2, $3}'

printf '\n'
for sig in stage-kill llm-timeout llm-empty http-429 http-5xx hollow; do
  case "$sig" in
    stage-kill)  p='^===== TIMEOUT$' ;;
    llm-timeout) p='attempt [0-9]+/[0-9]+ timed out' ;;
    llm-empty)   p='returned no usable content' ;;
    http-429)    p='HTTP 429' ;;
    http-5xx)    p='HTTP 50[0-9]' ;;
    hollow)      p='hollow_success.*false' ;;
  esac
  # Same `grep -c` caveat as check_signal: it prints 0 and exits 1 on no match.
  n=$(grep -acE "$p" "$RUN_LOG" 2>/dev/null)
  [[ -z "$n" ]] && n=0
  printf '  %-12s %s\n' "$sig" "$n"
done

if [[ -f "$CASE_DIR/report-technical-v3.json" ]]; then
  python3 - "$CASE_DIR" <<'PY' 2>/dev/null || true
import json, sys, pathlib
case = pathlib.Path(sys.argv[1])
print("\n  report sidecars:")
for p in sorted(case.glob("report-*.json")):
    d = json.loads(p.read_text(errors="replace"))
    q = d.get("quality") or {}
    print(f"    {p.name:28s} source={str(d.get('source')):24s} "
          f"complete={d.get('sections_complete')} "
          f"missing={len(d.get('sections_missing') or [])} "
          f"stub={len(d.get('sections_stub') or [])} quality_ok={q.get('ok')}")
PY
fi

if [[ -n "$FIRST_ERROR" ]]; then
  printf '\n'
  fail "first error: $FIRST_ERROR"
  [[ "$WATCH_RC" == "2" ]] && exit 2
  exit 1
fi
if [[ "$RUN_RC" != "0" ]]; then
  printf '\n'
  fail "pipeline exited rc=$RUN_RC with no classified signal; read $RUN_LOG"
  exit 1
fi
log "every stage rc=0 and no fatal signal"
exit 0