import subprocess
import sys
from pathlib import Path

import pytest
from scapy.all import ARP, Ether, IP

import arp_detector

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def clear_state():
    # The detector keeps its state in module level variables, so reset it for each test
    arp_detector.ip_to_macs.clear()
    arp_detector.mac_to_ips.clear()
    arp_detector.alerts_seen.clear()


def arp_packet(ip, mac, op=2):
    return Ether(src=mac) / ARP(op=op, psrc=ip, hwsrc=mac, pdst="192.168.56.99")


def test_normal_traffic_gives_no_alerts():
    assert arp_detector.check_packet(arp_packet("192.168.56.1", "aa:aa:aa:aa:aa:01")) == []
    assert arp_detector.check_packet(arp_packet("192.168.56.20", "bb:bb:bb:bb:bb:02")) == []
    # the same host talking again is fine
    assert arp_detector.check_packet(arp_packet("192.168.56.20", "bb:bb:bb:bb:bb:02")) == []


def test_one_mac_claiming_two_ips():
    arp_detector.check_packet(arp_packet("192.168.56.1", "cc:cc:cc:cc:cc:03"))
    alerts = arp_detector.check_packet(arp_packet("192.168.56.20", "cc:cc:cc:cc:cc:03"))
    assert len(alerts) == 1
    assert "MAC cc:cc:cc:cc:cc:03" in alerts[0]


def test_one_ip_claimed_by_two_macs():
    arp_detector.check_packet(arp_packet("192.168.56.1", "aa:aa:aa:aa:aa:01"))
    alerts = arp_detector.check_packet(arp_packet("192.168.56.1", "cc:cc:cc:cc:cc:03"))
    assert len(alerts) == 1
    assert "IP 192.168.56.1" in alerts[0]


def test_same_alert_is_not_repeated():
    arp_detector.check_packet(arp_packet("192.168.56.1", "cc:cc:cc:cc:cc:03"))
    first = arp_detector.check_packet(arp_packet("192.168.56.20", "cc:cc:cc:cc:cc:03"))
    second = arp_detector.check_packet(arp_packet("192.168.56.20", "cc:cc:cc:cc:cc:03"))
    assert len(first) == 1
    assert second == []


def test_forged_request_is_caught_too():
    arp_detector.check_packet(arp_packet("192.168.56.1", "aa:aa:aa:aa:aa:01", op=2))
    alerts = arp_detector.check_packet(arp_packet("192.168.56.1", "cc:cc:cc:cc:cc:03", op=1))
    assert len(alerts) == 1


def test_mac_case_does_not_matter():
    arp_detector.check_packet(arp_packet("192.168.56.1", "AA:AA:AA:AA:AA:01"))
    assert arp_detector.check_packet(arp_packet("192.168.56.1", "aa:aa:aa:aa:aa:01")) == []


def test_probe_with_empty_source_is_ignored():
    packet = Ether() / ARP(op=1, psrc="0.0.0.0", hwsrc="dd:dd:dd:dd:dd:04", pdst="192.168.56.5")
    assert arp_detector.check_packet(packet) == []
    assert arp_detector.ip_to_macs == {}


def test_non_arp_packet_is_ignored():
    assert arp_detector.check_packet(Ether() / IP(dst="192.168.56.1")) == []


def test_demo_capture_end_to_end():
    # Runs the real script on the demo capture, no root needed
    pcap = ROOT / "samples" / "demo_attack.pcap"
    result = subprocess.run(
        [sys.executable, "arp_detector.py", "--pcap", str(pcap)],
        cwd=ROOT, capture_output=True, text=True,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0
    assert "MAC 08:00:27:cc:cc:03 is claiming 2 IPs" in output
    assert "IP 192.168.56.1 is claimed by 2 MACs" in output
    assert "IP 192.168.56.20 is claimed by 2 MACs" in output
    assert "Alerts raised: 3" in output


def test_missing_capture_file_gives_friendly_error():
    result = subprocess.run(
        [sys.executable, "arp_detector.py", "--pcap", "does_not_exist.pcap"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "Could not find the capture file" in result.stdout + result.stderr
