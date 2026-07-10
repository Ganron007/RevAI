#!/bin/bash
# CADRE-RevAI RAM/disk check — quick snapshot of VM resource state.
# Usage: bash rescheck.sh [label]
LABEL="${1:-baseline}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=== $LABEL  $TS ==="
echo
echo "## RAM"
free -h
echo
echo "## Swap"
swapon --show 2>/dev/null || echo "(no swap)"
echo
echo "## Disk (df -h, all mounts)"
df -h --output=source,size,used,avail,pcent,target 2>/dev/null | grep -vE "tmpfs|devtmpfs|^Filesystem"
echo
echo "## Disk (du of /opt and /home and /var) — heavy dirs"
for d in /opt /home /var/log /var/tmp /var/cache /tmp; do
  if [ -d "$d" ]; then
    du -sh "$d" 2>/dev/null
  fi
done
echo
echo "## Top-10 by size under /opt (excluding /opt/samples/runs/* cache if huge)"
du -sh /opt/* 2>/dev/null | sort -h | tail -15
echo
echo "## Per-sample staging size (corpus)"
du -sh /opt/samples 2>/dev/null
du -sh /opt/samples/* 2>/dev/null
echo
echo "## Largest 10 files in /opt/samples (pe artifacts + logs)"
find /opt/samples -type f -printf "%s\t%p\n" 2>/dev/null | sort -rn | head -10
echo
echo "## Ghidra project size (.gpr + .rep bundles per sha)"
du -sh /home/remnux/ghidra-projects/* 2>/dev/null | sort -h | tail -10
echo
echo "## IDA staging (optional, not measured here)"
echo "## Logs (per-sample /opt/samples/logs/<sha>)"
du -sh /opt/samples/logs/* 2>/dev/null | sort -h | tail -5
echo
echo "## Load + uptime"
uptime
echo "load average (1, 5, 15 min):"
cat /proc/loadavg
echo
echo "## Top 8 processes by RESident memory (kB)"
ps -eo pid,user,pcpu,pmem,rss,comm --sort=-rss 2>/dev/null | head -8 | awk 'BEGIN{printf "%-7s %-9s %-6s %-6s %-10s %s\n","PID","USER","%CPU","%MEM","RSS_MB","COMM"} {printf "%-7s %-9s %-6s %-6s %-10.1f %s\n",$1,$2,$3,$4,$5/1024,$6}'
echo
echo "## (end $LABEL)  $TS"
