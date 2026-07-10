#!/bin/bash
# run_agent_sandbox.sh — bwrap sandbox for v2 agents (Manning lesson).
# Usage: run_agent_sandbox.sh <agent_script.py> [args...]
set -euo pipefail

AGENT="$1"
shift
WORKDIR="${CADRE_SANDBOX_WORKDIR:-/opt/samples/logs/.sandbox-$$}"
mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"

BIND_RO=(
  --ro-bind /opt/scripts /opt/scripts
  --ro-bind /opt/samples /opt/samples
  --ro-bind /opt/capa-rules /opt/capa-rules
  --ro-bind /opt/malcat /opt/malcat
  --ro-bind /opt/ghidra /opt/ghidra
  --ro-bind /usr /usr
  --ro-bind /usr/lib/jvm /usr/lib/jvm
  --ro-bind /home/remnux/.malcat /home/remnux/.malcat
  --ro-bind /home/remnux/.local /home/remnux/.local
  --ro-bind /home/remnux/.ssh /home/remnux/.ssh
  --ro-bind /lib /lib
  --ro-bind /lib64 /lib64
  --ro-bind /bin /bin
  --ro-bind /etc /etc
  --ro-bind /run /run
  --bind /home/remnux/ghidra-projects /home/remnux/ghidra-projects
  --ro-bind /opt/secrets /opt/secrets
)

BIND_RW=(
  --bind /opt/samples/logs /opt/samples/logs
  --bind /opt/samples/sessions /opt/samples/sessions
  --bind "$WORKDIR" "$WORKDIR"
)

exec bwrap \
  --unshare-uts \
  --unshare-pid \
  --die-with-parent \
  --new-session \
  --chdir "$WORKDIR" \
  "${BIND_RO[@]}" \
  "${BIND_RW[@]}" \
  --dev /dev \
  --proc /proc \
  --tmpfs /tmp \
  --setenv PYTHONPATH /opt/scripts \
  --setenv HOME /home/remnux \
  --setenv JAVA_HOME /usr/lib/jvm/default-java \
  --setenv PATH "/home/remnux/.local/bin:/usr/local/bin:/usr/lib/jvm/default-java/bin:/usr/bin:/bin" \
  /usr/bin/python3 "$AGENT" "$@""
