#!/usr/bin/env bash
# Configure REMnux as the isolated FlareVM gateway, simulator and packet sensor.
# Run from setup-remnux.sh or directly with sudo.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 2
fi

GUEST_IP="${WINRE_GUEST_IP:-192.168.77.42}"
GATEWAY_IP="${WINRE_GATEWAY_IP:-192.168.77.43}"
MANAGEMENT_IP="${WINRE_MANAGEMENT_IP:-192.168.77.1}"
IFACE="${WINRE_ANALYSIS_INTERFACE:-}"
CONFIG_DIR=/etc/revai
INETSIM_CONF=/etc/inetsim/inetsim.conf

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
valid_ipv4 "$GATEWAY_IP" || { echo "Invalid WINRE_GATEWAY_IP: $GATEWAY_IP" >&2; exit 2; }
valid_ipv4 "$MANAGEMENT_IP" || { echo "Invalid WINRE_MANAGEMENT_IP: $MANAGEMENT_IP" >&2; exit 2; }
[[ "$GUEST_IP" != "$GATEWAY_IP" ]] || { echo "Guest and gateway IPs must differ" >&2; exit 2; }
python3 - "$GATEWAY_IP" "$MANAGEMENT_IP" "$GUEST_IP" <<'PY'
import ipaddress, sys
gateway, management, guest = map(ipaddress.IPv4Address, sys.argv[1:])
network = ipaddress.IPv4Network(f"{gateway}/24", strict=False)
if management not in network or management in {gateway, guest}:
    raise SystemExit("WINRE_MANAGEMENT_IP must be another address in the gateway /24")
PY

for bin in ip nft sysctl systemctl python3 dumpcap setcap getcap ss dnsmasq sudo visudo su; do
  command -v "$bin" >/dev/null || { echo "Required command missing: $bin" >&2; exit 2; }
done
[[ -x "$(command -v inetsim || true)" ]] || { echo "INetSim is not installed" >&2; exit 2; }
[[ -f "$INETSIM_CONF" ]] || { echo "Missing $INETSIM_CONF" >&2; exit 2; }

if [[ -z "$IFACE" ]]; then
  IFACE="$(ip -o -4 addr show | awk -v want="$GATEWAY_IP" '{split($4,a,"/"); if (a[1] == want) {print $2; exit}}')"
fi
[[ -n "$IFACE" ]] || { echo "No interface owns $GATEWAY_IP; set WINRE_ANALYSIS_INTERFACE" >&2; exit 2; }
ip -o -4 addr show dev "$IFACE" | awk -v want="$GATEWAY_IP" \
  '{split($4,a,"/"); if (a[1] == want) found=1} END {exit !found}' || {
  echo "$IFACE does not own $GATEWAY_IP" >&2
  exit 2
}

install -d -m 0755 "$CONFIG_DIR" /etc/sysctl.d
cat > /etc/sysctl.d/99-winre-gateway.conf <<'EOF'
# FlareVM traffic is captured on the private interface and never forwarded.
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.default.forwarding=0
EOF
sysctl -w net.ipv4.ip_forward=0 >/dev/null
sysctl -w net.ipv6.conf.all.forwarding=0 >/dev/null
sysctl -w net.ipv6.conf.default.forwarding=0 >/dev/null

# Bind the simulator only to the private VMnet2 address. Preserve package and
# operator settings outside the directives managed below.
python3 - "$INETSIM_CONF" "$GATEWAY_IP" <<'PY'
from pathlib import Path
import re, sys

path = Path(sys.argv[1])
ip = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
managed = {"service_bind_address", "dns_default_ip"}
out = []
services = {"http", "https", "smtp", "smtps", "pop3", "pop3s",
            "ftp", "ftps", "tftp", "ntp", "irc"}
seen_services = set()
for line in lines:
    stripped = line.strip()
    if stripped.startswith("# CADRE-WINRE-MANAGED-BEGIN"):
        break
    directive = stripped.split(None, 1)[0] if stripped and not stripped.startswith("#") else ""
    if directive in managed:
        continue
    if directive == "start_service" and len(stripped.split()) == 2:
        service = stripped.split()[-1].lower()
        # INetSim 1.3.2's DNS child does not bind with the current Ubuntu
        # Net::DNS 1.44 library. A dedicated dnsmasq instance serves DNS.
        if service == "dns":
            continue
        if service in seen_services:
            continue
        seen_services.add(service)
    out.append(line)
while out and not out[-1].strip():
    out.pop()
out.extend([
    "",
    "# CADRE-WINRE-MANAGED-BEGIN",
    "# Private FlareVM simulator endpoint; edited by install/setup-winre-gateway.sh.",
    *[f"start_service {service}" for service in sorted(services - seen_services)],
    f"service_bind_address {ip}",
    f"dns_default_ip {ip}",
    "# CADRE-WINRE-MANAGED-END",
    "",
])
path.write_text("\n".join(out), encoding="utf-8")
PY

# The Ubuntu 24.04 INetSim 1.3.2 package can report its DNS child started
# while Net::DNS 1.44 immediately exits without binding port 53. Keep INetSim
# for HTTP(S)/mail/FTP/etc. and use a no-upstream dnsmasq instance for DNS.
cat > /etc/revai/winre-dnsmasq.conf <<EOF
port=53
listen-address=$GATEWAY_IP
bind-interfaces
no-resolv
no-hosts
address=/#/$GATEWAY_IP
EOF
chmod 0644 /etc/revai/winre-dnsmasq.conf
cat > /etc/systemd/system/winre-dnsmasq.service <<'EOF'
[Unit]
Description=WinRE isolated DNS simulator
Wants=network-online.target
After=network-online.target winre-guest-guard.service
Requires=winre-guest-guard.service

[Service]
Type=simple
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file=/etc/revai/winre-dnsmasq.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# nftables observes guest packets at the gateway, redirects common protocols
# into INetSim, permits only those simulator ports to the host, and drops all
# forwarding. Other guest traffic is still visible on the capture interface
# but receives no route to the Internet.
cat > /etc/revai/winre-guest-guard.nft <<EOF
table inet winre_guest_guard {
  chain forward {
    type filter hook forward priority -300; policy drop;
  }
  chain input {
    type filter hook input priority -100; policy accept;
    ct state established,related accept
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr $GATEWAY_IP icmp type echo-request accept
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr $GATEWAY_IP udp dport { 53, 69, 123 } accept
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr $GATEWAY_IP tcp dport { 21, 25, 53, 80, 110, 143, 443, 465, 587, 990, 993, 995, 194, 6667 } accept
    iifname "$IFACE" ip saddr $MANAGEMENT_IP tcp dport 22 accept
    iifname "$IFACE" drop
  }
}

table ip winre_guest_nat {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP udp dport 53 dnat to $GATEWAY_IP:53
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP tcp dport 53 dnat to $GATEWAY_IP:53
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP tcp dport { 21, 25, 80, 110, 143, 443, 465, 587, 990, 993, 995, 194, 6667 } dnat to $GATEWAY_IP
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP tcp dport 8080 dnat to $GATEWAY_IP:80
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP tcp dport 8443 dnat to $GATEWAY_IP:443
    iifname "$IFACE" ip saddr $GUEST_IP ip daddr != $GATEWAY_IP udp dport { 69, 123 } dnat to $GATEWAY_IP
  }
}
EOF

cat > /usr/local/sbin/winre-guest-guard <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-start}" in
  start|reload)
    nft delete table inet winre_guest_guard 2>/dev/null || true
    nft delete table ip winre_guest_nat 2>/dev/null || true
    nft -f /etc/revai/winre-guest-guard.nft
    ;;
  stop)
    nft delete table inet winre_guest_guard 2>/dev/null || true
    nft delete table ip winre_guest_nat 2>/dev/null || true
    ;;
  *) echo "Usage: $0 {start|reload|stop}" >&2; exit 2 ;;
esac
EOF
chmod 0755 /usr/local/sbin/winre-guest-guard
cat > /etc/systemd/system/winre-guest-guard.service <<'EOF'
[Unit]
Description=WinRE isolated guest capture and no-forward policy
DefaultDependencies=no
After=systemd-sysctl.service nftables.service
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/winre-guest-guard start
ExecReload=/usr/local/sbin/winre-guest-guard reload
ExecStop=/usr/local/sbin/winre-guest-guard stop

[Install]
WantedBy=multi-user.target
EOF

python3 - "$CONFIG_DIR/winre-gateway.json" "$IFACE" "$GUEST_IP" "$GATEWAY_IP" "$MANAGEMENT_IP" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
record = {
    "schema": "winre-gateway/v1",
    "enabled": True,
    "interface": sys.argv[2],
    "guest_ip": sys.argv[3],
    "gateway_ip": sys.argv[4],
    "management_ip": sys.argv[5],
    "capture_filter": f"host {sys.argv[3]} and not tcp port 22 and not tcp port 9094 and not tcp port 9095",
    "simulator": "inetsim",
    "forwarding": False,
}
path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
path.chmod(0o644)
PY

systemctl daemon-reload
systemctl enable winre-guest-guard.service
systemctl restart winre-guest-guard.service
systemctl enable winre-dnsmasq.service
systemctl restart winre-dnsmasq.service
# Ubuntu ships INetSim as a SysV init script. On some systemd versions,
# `enable --now` reports success for the generated unit without actually
# starting it, so enable and restart explicitly, then validate the listeners.
systemctl enable inetsim.service
systemctl restart inetsim.service

# The RevAI service and normal WinRE CLI run as `remnux`, while nftables
# inspection requires CAP_NET_ADMIN. Give that worker account only the exact
# read-only rule-list commands used by external_capture.verify_gateway.
CAPTURE_USER=remnux
id "$CAPTURE_USER" >/dev/null 2>&1 || {
  echo "Required RevAI/WinRE service user is missing: $CAPTURE_USER" >&2
  exit 2
}
NFT_BIN="$(command -v nft)"
cat > /etc/sudoers.d/winre-gateway-nft <<EOF
$CAPTURE_USER ALL=(root) NOPASSWD: \\
  $NFT_BIN list table inet winre_guest_guard, \\
  $NFT_BIN list table ip winre_guest_nat, \\
  $NFT_BIN list chain inet winre_guest_guard input, \\
  $NFT_BIN list chain ip winre_guest_nat prerouting, \\
  $NFT_BIN -j list table inet winre_guest_guard
EOF
chmod 0440 /etc/sudoers.d/winre-gateway-nft
visudo -cf /etc/sudoers.d/winre-gateway-nft >/dev/null || {
  echo "Read-only WinRE nftables sudo policy is invalid" >&2
  exit 1
}
if ! su -s /bin/sh "$CAPTURE_USER" -c \
  "sudo -n '$NFT_BIN' list table inet winre_guest_guard >/dev/null && sudo -n '$NFT_BIN' list table ip winre_guest_nat >/dev/null && sudo -n '$NFT_BIN' list chain inet winre_guest_guard input >/dev/null && sudo -n '$NFT_BIN' list chain ip winre_guest_nat prerouting >/dev/null && sudo -n '$NFT_BIN' -j list table inet winre_guest_guard >/dev/null"; then
  echo "WinRE service user cannot inspect the gateway firewall non-interactively" >&2
  exit 1
fi

if [[ "$(sysctl -n net.ipv4.ip_forward)" != "0" ]]; then
  echo "IPv4 forwarding is not disabled" >&2
  exit 1
fi
nft list table inet winre_guest_guard >/dev/null
nft list table ip winre_guest_nat >/dev/null
systemctl is-active --quiet inetsim.service
systemctl is-enabled --quiet inetsim.service
systemctl is-active --quiet winre-guest-guard.service
systemctl is-enabled --quiet winre-guest-guard.service
systemctl is-active --quiet winre-dnsmasq.service
systemctl is-enabled --quiet winre-dnsmasq.service
nft -j list table inet winre_guest_guard | python3 -c '
import json, sys
data = json.load(sys.stdin)
chains = [item["chain"] for item in data["nftables"] if "chain" in item]
if not any(c.get("name") == "forward" and c.get("hook") == "forward" and c.get("policy") == "drop" for c in chains):
    raise SystemExit("The guest forwarding drop policy is missing")
' || exit 1
grep -Fq "iifname \"$IFACE\" drop" < <(nft list chain inet winre_guest_guard input) || {
  echo "The guest-facing input chain must drop all other guest ingress (including IPv6)" >&2
  exit 1
}
grep -Fq "iifname \"$IFACE\" ip saddr $MANAGEMENT_IP tcp dport 22 accept" \
  < <(nft list chain inet winre_guest_guard input) || {
  echo "The configured host-management SSH exception is missing" >&2
  exit 1
}
grep -Fq 'ct state established,related accept' \
  < <(nft list chain inet winre_guest_guard input) || {
  echo "The guest-facing input chain must permit replies to established flows" >&2
  exit 1
}
LISTENERS="$(ss -H -lntup)"
grep -Fq "$GATEWAY_IP:53" <<<"$LISTENERS" || {
  echo "WinRE dnsmasq is not listening on $GATEWAY_IP:53" >&2
  exit 1
}
grep -Fq "$GATEWAY_IP:80" <<<"$LISTENERS" || {
  echo "INetSim HTTP is not listening on $GATEWAY_IP:80" >&2
  exit 1
}

DUMPCAP="$(command -v dumpcap)"
setcap cap_net_admin,cap_net_raw+eip "$DUMPCAP"
getcap "$DUMPCAP" | grep -q 'cap_net_admin,cap_net_raw' || {
  echo "dumpcap capture capabilities could not be configured" >&2
  exit 1
}
echo "WINRE_GATEWAY_READY interface=$IFACE guest=$GUEST_IP gateway=$GATEWAY_IP management=$MANAGEMENT_IP forwarding=0"
