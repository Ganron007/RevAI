"""Keep WinRE remote capture passive, host-filtered, and non-routing."""
from _layout import source


def test_capture_setup_installs_guest_only_promiscuous_tcpdump_contract():
    setup = source("install/setup-winre-capture.sh")
    installer = source("install/setup-remnux.sh")
    verifier = source("install/verify-remnux.sh")

    assert '"mode": "passive"' in setup
    assert '"promiscuous": True' in setup
    assert '"capture_filter": f"host {sys.argv[3]}"' in setup
    assert "net.ipv4.ip_forward=0" in setup
    assert "net.ipv6.conf.all.forwarding=0" in setup
    assert "setcap cap_net_admin,cap_net_raw+eip" in setup
    assert "nft delete table inet winre_guest_guard" in setup
    assert "nft delete table ip winre_guest_nat" in setup
    assert "inetsim.service" in setup
    assert "service inetsim stop" in setup
    assert "update-rc.d inetsim disable" in setup
    assert "INetSim is still active" in setup
    assert "WINRE_CAPTURE_READY" in setup

    # The normal setup installs tcpdump and invokes the passive sensor setup.
    assert "inetsim dnsmasq-base nftables tcpdump tshark" in installer
    assert '"$REPO_ROOT/install/setup-winre-capture.sh"' in installer
    assert "REMnux does not act" in installer

    # Release verification fails if capture is missing, unscoped, non-promiscuous,
    # forwarding is enabled, or legacy WinRE peer filters remain.
    assert "cfg.get('promiscuous') is True" in verifier
    assert "cfg.get('capture_filter') == f'host {guest}'" in verifier
    assert "net.ipv4.ip_forward" in verifier
    assert "legacy WinRE gateway firewall tables still block guest traffic" in verifier
    assert "legacy WinRE INetSim responder is still active/enabled" in verifier
