#!/usr/bin/env bash
# Configure REMnux as a passive, run-scoped WinRE VMnet2 packet sensor.
# This script does not route guest traffic or configure FlareVM networking.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi

GUEST_IP="${WINRE_GUEST_IP:-192.168.77.42}"
CAPTURE_HOST_IP="${WINRE_CAPTURE_HOST_IP:-192.168.77.43}"
IFACE="${WINRE_ANALYSIS_INTERFACE:-}"
CONFIG_DIR=/etc/revai
CONFIG_PATH="$CONFIG_DIR/winre-capture.json"

valid_ipv4() {
  python3 - "$1" <<'PY'
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ipaddress.AddressValueError:
    raise SystemExit(1)
PY
}

valid_ipv4 "$GUEST_IP" || { echo "Invalid WINRE_GUEST_IP: $GUEST_IP" >&2; exit 2; }
valid_ipv4 "$CAPTURE_HOST_IP" || { echo "Invalid WINRE_CAPTURE_HOST_IP: $CAPTURE_HOST_IP" >&2; exit 2; }
[[ "$GUEST_IP" != "$CAPTURE_HOST_IP" ]] || {
  echo "Guest and capture host IPs must differ" >&2
  exit 2
}

for bin in ip sysctl systemctl python3 tcpdump setcap getcap nft; do
  command -v "$bin" >/dev/null || { echo "Required command missing: $bin" >&2; exit 2; }
done

if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -4 addr show | awk -v want="$CAPTURE_HOST_IP" '{split($4,a,"/"); if (a[1] == want) {print $2; exit}}')"
fi
[[ -n "$IFACE" ]] || {
  echo "No interface owns $CAPTURE_HOST_IP; set WINRE_ANALYSIS_INTERFACE" >&2
  exit 2
}
ip -o link show dev "$IFACE" | grep -Fq 'state UP' || {
  echo "Capture interface $IFACE is not up" >&2
  exit 2
}
ip -o -4 addr show dev "$IFACE" | awk -v want="$CAPTURE_HOST_IP" \
  '{split($4,a,"/"); if (a[1] == want) found=1} END {exit !found}' || {
  echo "$IFACE does not own $CAPTURE_HOST_IP" >&2
  exit 2
}

# Keep REMnux as a sensor, not an accidental router for a guest or the lab.
install -d -m 0755 "$CONFIG_DIR" /etc/sysctl.d
cat > /etc/sysctl.d/99-winre-capture.conf <<'EOF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
EOF
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
sysctl -w net.ipv6.conf.default.forwarding=0 >/dev/null

# Remove WinRE's old gateway simulators and policy objects. The guest now runs
# FakeNet itself, so REMnux is only a passive sensor during remote detonation.
systemctl disable --now winre-guest-guard.service winre-dnsmasq.service \
  >/dev/null 2>&1 || true
if [[ -x /etc/init.d/inetsim ]]; then
  # INetSim is packaged as a SysV init script on REMnux/Ubuntu. systemctl's
  # combined `disable --now` can disable its generated unit while leaving the
  # daemon alive, so stop the init script explicitly and remove its boot-start
  # links through the native SysV manager.
  service inetsim stop >/dev/null
  update-rc.d inetsim disable
elif systemctl list-unit-files --type=service --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -Fxq 'inetsim.service'; then
  systemctl disable --now inetsim.service
fi
if systemctl is-active --quiet inetsim.service; then
  echo "INetSim is still active after attempting to disable the legacy responder" >&2
  exit 1
fi
if systemctl is-enabled --quiet inetsim.service; then
  echo "INetSim is still enabled after attempting to disable the legacy responder" >&2
  exit 1
fi
nft delete table inet winre_guest_guard 2>/dev/null || true
nft delete table ip winre_guest_nat 2>/dev/null || true
rm -f /etc/systemd/system/winre-guest-guard.service \
  /etc/systemd/system/winre-dnsmasq.service \
  /etc/revai/winre-guest-guard.nft \
  /etc/revai/winre-dnsmasq.conf \
  /etc/revai/winre-gateway.json \
  /etc/sudoers.d/winre-gateway-nft \
  /usr/local/sbin/winre-guest-guard \
  /etc/sysctl.d/99-winre-gateway.conf
systemctl daemon-reload

# tcpdump needs packet-socket access and CAP_NET_ADMIN to request promiscuous
# mode when the RevAI service runs as the unprivileged remnux account.
TCPDUMP="$(command -v tcpdump)"
setcap cap_net_admin,cap_net_raw+eip "$TCPDUMP"
getcap "$TCPDUMP" | grep -q 'cap_net_admin,cap_net_raw' || {
  echo "tcpdump capture capabilities could not be configured" >&2
  exit 1
}

python3 - "$CONFIG_PATH" "$IFACE" "$GUEST_IP" "$CAPTURE_HOST_IP" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
record = {
    "schema": "winre-capture/v1",
    "enabled": True,
    "mode": "passive",
    "promiscuous": True,
    "interface": sys.argv[2],
    "guest_ip": sys.argv[3],
    "host_ip": sys.argv[4],
    "capture_filter": f"host {sys.argv[3]}",
    "forwarding": False,
}
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
path.chmod(0o644)
PY

if [[ "$(sysctl -n net.ipv4.ip_forward)" != "0" ||
      "$(sysctl -n net.ipv6.conf.all.forwarding)" != "0" ||
      "$(sysctl -n net.ipv6.conf.default.forwarding)" != "0" ]]; then
  echo "Packet sensor forwarding must remain disabled" >&2
  exit 1
fi
[[ "$(getcap "$TCPDUMP")" == *cap_net_admin,cap_net_raw* ]] || {
  echo "tcpdump cannot request promiscuous packet capture" >&2
  exit 1
}
echo "WINRE_CAPTURE_READY mode=passive interface=$IFACE guest=$GUEST_IP host_ip=$CAPTURE_HOST_IP promiscuous=1 forwarding=0"
