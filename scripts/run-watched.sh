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
# Where the signals live (fixed 2026-10-03, they were grepped in the wrong
# file and could never fire): pipeline_single.py redirects every stage's
# stdout/stderr into CASE_DIR/pipeline_single.log — the TIMEOUT marker, the
# llm_judge timeout/empty messages and the HTTP errors are all in THERE, while
# RUN_LOG (this script's capture of pipeline_single's own stdout) only ever
# holds the `[pipeline_single] <stage> rc=<rc> <secs>s` lines. The hollow gate
# result is not printed anywhere: it lives in CASE_DIR/pipeline-audit.json,
# written by the audit stage, so it is polled as JSON.
#
# Usage:
#   scripts/run-watched.sh <sample-path> [--sha <sha256>] [--mode scripted]
#                          [--abort-on-error] [--timeout-minutes N] [--no-reboot]
#
# Exit codes: 0 run completed and every stage rc=0 · 1 a stage failed ·
#             2 a fatal signal fired or the watch timed out (run killed) ·
#             3 usage/environment error.
#
# REBOOT BEFORE EVERY SAMPLE RUN (docs/OPERATE.md). --no-reboot exists only for
# the case where the operator has just rebooted by hand; passing it on a loaded
# VM invalidates the run and the summary says so.
set -uo pipefail

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPTS_DIR")"

SAMPLE=""
SHA=""
# Capture the caller's mode BEFORE llm.env is sourced below: the env config is
# not the place where the run mode is decided, and the case dir derived here
# must match the one pipeline_single actually writes to (mode-keyed contract).
INHERITED_MODE="${REVAI_RUN_MODE:-}"
MODE_FLAG=""
MODE=""
ABORT_ON_ERROR=0
TIMEOUT_MINUTES=240
REBOOT=1

# A missing option value must exit with the documented usage code. Under `set -u`
# a trailing `--sha` used to abort the shell with exit 1, which a caller reads as
# "a stage failed"; the header documents 3 as a usage/environment error.
need_value() {
  if [[ $# -lt 2 ]]; then
    echo "$1 requires a value" >&2
    exit 3
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha) need_value "$@"; SHA="$2"; shift 2 ;;
    --mode) need_value "$@"; MODE_FLAG="$2"; shift 2 ;;
    --abort-on-error) ABORT_ON_ERROR=1; shift ;;
    --timeout-minutes) need_value "$@"; TIMEOUT_MINUTES="$2"; shift 2 ;;
    --no-reboot) REBOOT=0; shift ;;
    -h|--help) sed -n '2,42p' "${BASH_SOURCE[0]}"; exit 0 ;;
    -*) echo "unknown option: $1" >&2; exit 3 ;;
    *) SAMPLE="$1"; shift ;;
  esac
done

if [[ -z "$SAMPLE" ]]; then
  echo "usage: $(basename "$0") <sample-path> [--sha <sha>] [--mode scripted] [--abort-on-error]" >&2
  exit 3
fi
# Validate the wall-clock bound BEFORE any input check. A non-integer used to
# reach the deadline arithmetic inside watch_loop -- after the run was already
# started -- so the arithmetic error orphaned it, the same "watcher dies, run
# survives" failure mode kill_run was fixed for. It is checked here, next to the
# argument parsing that produced it, so no later input check can mask it.
if ! [[ "$TIMEOUT_MINUTES" =~ ^[0-9]+$ ]]; then
  echo "--timeout-minutes must be a whole number of minutes (got '$TIMEOUT_MINUTES')" >&2
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
  if ! sudo reboot; then
    # A failed reboot used to exit 0, which this script's header defines as
    # "every stage rc=0" — so a caller scripting `run-watched.sh … && deploy`
    # treated the reboot rule as honoured when it had not happened at all. The
    # rule is load-bearing, so its failure must not look like success.
    fail "reboot failed; the reboot-before-every-run rule did NOT happen"
    exit 1
  fi
  log "reboot issued — this script cannot continue across it. Re-run it once SSH"
  log "is back; it will detect the fresh boot and skip the reboot."
  exit 0
fi

# /proc/uptime, not `uptime -p`: the -p output's first number is HOURS once the
# VM has been up for an hour, so the "minutes" check only ever fired in the
# 20-59 minute window — exactly not the multi-hour loaded case it warns about.
UPTIME_SEC="$(cut -d. -f1 /proc/uptime 2>/dev/null)"
UPTIME_MIN=$(( ${UPTIME_SEC:-360000} / 60 ))
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

# Mode: --mode flag > the caller's exported REVAI_RUN_MODE > scripted.
MODE="${MODE_FLAG:-${INHERITED_MODE:-scripted}}"
log "mode: $MODE"

LOG_DIR=/opt/samples/logs
CASE_DIR="$LOG_DIR/$SHA/$MODE"
# Named after the scripted driver so existing tooling keeps working; in
# agentic mode the orchestrator writes its own trace alongside it.
STAGE_LOG="$CASE_DIR/pipeline_single.log"
AUDIT_JSON="$CASE_DIR/pipeline-audit.json"
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
# The resolved mode wins over anything llm.env set via `set -a`.
export REVAI_RUN_MODE="$MODE"
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
log "stage log: $STAGE_LOG"

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

# `setsid` puts the run in its own session AND its own process group, which is
# what lets kill_run signal the whole tree. Without it the stages are
# grandchildren of THIS process, and killing only the parent left them running
# (defect B1).
# Dispatch on the mode. pipeline_single.py does NOT branch to
# stage_orchestrator on REVAI_RUN_MODE -- it only uses the variable for its
# case-dir default -- so a hardcoded pipeline_single.py here meant
# `--mode agentic` ran the deterministic scripted spine and filed it under the
# agentic case dir, where it looked exactly like an agentic run. Fail loudly on
# an unrecognised mode instead: a run in the wrong mode is worse than no run.
case "$MODE" in
  scripted)
    DRIVER="pipeline_single.py"
    ;;
  agentic)
    DRIVER="stage_orchestrator.py"
    ;;
  *)
    fail "unknown mode '$MODE' (expected scripted|agentic); refusing to run " \
         "the wrong spine and file it under $CASE_DIR"
    exit 3
    ;;
esac
[[ -f "$DRIVER" ]] || { fail "$DRIVER missing in $RUN_DIR"; exit 3; }
log "driver: $DRIVER (mode: $MODE)"

setsid python3 "$DRIVER" "$SAMPLE" > "$RUN_LOG" 2>&1 &
RUN_PID=$!
log "pid: $RUN_PID"

# ------------------------------------------------------------------- watch
# First-error classification. Each pattern is fatal enough to stop a scripted
# run early: a failed stage cannot be fixed by letting the rest proceed, and an
# exhausted LLM call means a chunk of analysis is silently absent from the
# report. Stage-rc lines come from RUN_LOG (pipeline_single's stdout); every
# other signal comes from STAGE_LOG (the stages' own output) or AUDIT_JSON.
declare -A SEEN
FIRST_ERROR=""
START=$(date +%s)

kill_run() {
  # Kill the whole PROCESS GROUP, not just the parent.
  #
  # `pipeline_single.py` runs each stage with subprocess.run, so the stage is a
  # GRANDCHILD of this watcher. Signalling only "$RUN_PID" left the stage -- a
  # Ghidra headless analyse, an LLM-heavy deep dive -- running for hours after
  # the watcher had already reported exit 2 "run killed", while `wait` returned
  # promptly and printed a clean-looking summary over a live process. On
  # --abort-on-error that is the difference between stopping a doomed run and
  # leaving it burning tokens.
  #
  # The run is launched with `setsid` so it becomes a group leader in its own
  # right; killing the negative PID signals every member. A pattern kill
  # A pattern kill is deliberately NOT used -- AGENTS.md records that it also
  # kills the invoking shell.
  local pgid
  pgid="$(ps -o pgid= -p "$RUN_PID" 2>/dev/null | tr -d ' ')"
  if [[ -n "$pgid" ]]; then
    kill -TERM "-$pgid" 2>/dev/null
    sleep 5
    kill -KILL "-$pgid" 2>/dev/null
  fi
  # Always signal the direct child too: the group may already be gone, and the
  # parent is what `wait` is blocked on.
  kill -TERM "$RUN_PID" 2>/dev/null
  sleep 3
  kill -KILL "$RUN_PID" 2>/dev/null
}

# The stage a signal belongs to: the last `CMD <python> <stage>.py` line in the
# stage log. These lines are written by pipeline_single into STAGE_LOG (not
# stdout), so attribution used to always print "?".
current_stage() {
  grep -aoE 'CMD \S+ ([a-z_0-9]+)\.py' "$STAGE_LOG" 2>/dev/null \
    | tail -1 | sed -E 's/.* ([a-z_0-9]+)\.py/\1/'
}

# A stage that exited non-zero. One report per stage.
check_stage_rc() {
  local stage rc secs
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
}

# A textual signal in the stage log, reported once per label.
check_signal() {
  local label="$1" pattern="$2" fatal="$3" current prev stage
  # `grep -c` prints 0 AND exits 1 when there are no matches, so `|| echo 0`
  # appends a second line and the arithmetic below sees "0\n0". Take grep's
  # own count and default only when it printed nothing (no file yet).
  current=$(grep -acE "$pattern" "$STAGE_LOG" 2>/dev/null)
  [[ -z "$current" ]] && current=0
  prev="${SEEN[$label]:-0}"
  (( current > prev )) || return 0
  SEEN[$label]=$current
  stage=$(current_stage)
  printf '[watch]   ! %s x%s (in: %s)\n' "$label" "$current" "${stage:-?}"
  [[ -z "$FIRST_ERROR" ]] && FIRST_ERROR="$label during ${stage:-unknown}"
  if [[ "$fatal" == "1" && "$ABORT_ON_ERROR" == "1" ]]; then
    printf '[watch] aborting on first error (--abort-on-error)\n'
    kill_run
    return 2
  fi
  return 0
}

# The hollow gate does not print to any log; the audit stage writes its verdict
# into pipeline-audit.json (`hollow_success.ok` + findings). Poll it as JSON —
# a line-grep on "hollow_success...false" matches nothing anywhere.
check_hollow() {
  [[ -f "$AUDIT_JSON" ]] || return 0
  local out bad count
  out=$(python3 - "$AUDIT_JSON" <<'PY' 2>/dev/null
import json, sys
try:
    h = json.load(open(sys.argv[1], encoding="utf-8")).get("hollow_success") or {}
except Exception:
    h = {}
print(0 if h.get("ok", True) else 1, len(h.get("findings") or []))
PY
)
  [[ -z "$out" ]] && return 0
  read -r bad count <<< "$out"
  [[ "$bad" == "1" && "${SEEN[hollow]:-0}" == "0" ]] || return 0
  SEEN[hollow]=1
  printf '[watch]   ! hollow x%s (pipeline-audit.json)\n' "$count"
  [[ -z "$FIRST_ERROR" ]] && FIRST_ERROR="hollow_success: ${count} finding(s)"
  if [[ "$ABORT_ON_ERROR" == "1" ]]; then
    printf '[watch] aborting on first error (--abort-on-error)\n'
    kill_run
    return 2
  fi
  return 0
}

watch_loop() {
  local deadline=$(( START + TIMEOUT_MINUTES * 60 ))
  while kill -0 "$RUN_PID" 2>/dev/null; do
    local now; now=$(date +%s)
    if (( now > deadline )); then
      printf '[watch] TIMEOUT after %s minutes\n' "$TIMEOUT_MINUTES"
      FIRST_ERROR="watch timeout after ${TIMEOUT_MINUTES} minutes"
      kill_run
      return 2
    fi

    check_stage_rc
    check_signal "stage-kill"  '^===== TIMEOUT$'                     1 || return 2
    check_signal "llm-timeout" 'attempt [0-9]+/[0-9]+ timed out'     1 || return 2
    check_signal "llm-empty"   'returned no usable content'          0 || return 2
    check_signal "http-429"    'HTTP 429'                            0 || return 2
    check_signal "http-5xx"    'HTTP 50[0-9]'                        0 || return 2
    check_hollow                                                     || return 2

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
log "stages: $STAGE_LOG"
[[ -d "$CASE_DIR" ]] && log "case  : $CASE_DIR"
printf '\n'
grep -aoE '\[[a-z_0-9]+\] [a-z_0-9]+ rc=[0-9]+ [0-9.]+s' "$RUN_LOG" 2>/dev/null \
  | sed -E 's/^\[[a-z_0-9]+\] ([a-z_0-9]+) rc=([0-9]+) ([0-9.]+)s$/\1 rc=\2 \3s/' \
  | awk '{printf "  %-22s %-10s %s\n", $1, $2, $3}'

printf '\n'
for sig in stage-kill llm-timeout llm-empty http-429 http-5xx; do
  case "$sig" in
    stage-kill)  p='^===== TIMEOUT$' ;;
    llm-timeout) p='attempt [0-9]+/[0-9]+ timed out' ;;
    llm-empty)   p='returned no usable content' ;;
    http-429)    p='HTTP 429' ;;
    http-5xx)    p='HTTP 50[0-9]' ;;
  esac
  # Same `grep -c` caveat as check_signal: it prints 0 and exits 1 on no match.
  n=$(grep -acE "$p" "$STAGE_LOG" 2>/dev/null)
  [[ -z "$n" ]] && n=0
  printf '  %-12s %s\n' "$sig" "$n"
done
# Hollow is reported from the audit JSON, not a log grep.
if [[ -f "$AUDIT_JSON" ]]; then
  hollow_n=$(python3 - "$AUDIT_JSON" <<'PY' 2>/dev/null
import json, sys
try:
    h = json.load(open(sys.argv[1], encoding="utf-8")).get("hollow_success") or {}
except Exception:
    h = {}
print(0 if h.get("ok", True) else len(h.get("findings") or []))
PY
)
  printf '  %-12s %s\n' "hollow" "${hollow_n:-?}"
fi

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

# Exit contract: 2 = this script killed the run (fatal signal or watch
# timeout); 1 = the run ended on its own with a failure; 0 = clean.
if [[ "$WATCH_RC" == "2" ]]; then
  printf '\n'
  fail "run killed: $FIRST_ERROR"
  exit 2
fi
if [[ -n "$FIRST_ERROR" ]]; then
  printf '\n'
  fail "first error: $FIRST_ERROR"
  exit 1
fi
if [[ "$RUN_RC" != "0" ]]; then
  printf '\n'
  fail "pipeline exited rc=$RUN_RC with no classified signal; read $RUN_LOG"
  exit 1
fi
log "every stage rc=0 and no fatal signal"
exit 0
