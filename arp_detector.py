"""Simple ARP cache poisoning detector.

It watches ARP traffic and raises an alert when:
  1. one MAC address claims more than one IP address, or
  2. one IP address is claimed by more than one MAC address.
"""

import argparse
import logging

from scapy.all import ARP, sniff
from scapy.error import Scapy_Exception

# What we have seen so far: the MACs that claimed each IP, and the IPs each MAC claimed
ip_to_macs = {}
mac_to_ips = {}

# Stops the same alert being printed again and again
alerts_seen = set()

log = logging.getLogger("arp_detector")


def check_packet(packet):
    """Look at one packet and return a list of alert messages (empty if all is fine)."""
    if not packet.haslayer(ARP):
        return []

    arp = packet[ARP]

    # 1 is a request and 2 is a reply. Spoofing tools mostly send replies,
    # but some send forged requests, so we check both.
    if arp.op not in (1, 2):
        return []

    ip = arp.psrc
    mac = arp.hwsrc.lower()

    # 0.0.0.0 shows up in address conflict probes, it is not a real claim
    if ip == "0.0.0.0":
        return []

    log.debug(f"{ip} is at {mac}")

    ip_to_macs.setdefault(ip, set()).add(mac)
    mac_to_ips.setdefault(mac, set()).add(ip)

    alerts = []

    ips = mac_to_ips[mac]
    if len(ips) > 1:
        # The count is in the key so we alert again if the MAC claims yet another IP
        key = ("mac", mac, len(ips))
        if key not in alerts_seen:
            alerts_seen.add(key)
            alerts.append(f"Poisoning detected: MAC {mac} is claiming {len(ips)} IPs: {sorted(ips)}")

    macs = ip_to_macs[ip]
    if len(macs) > 1:
        key = ("ip", ip, len(macs))
        if key not in alerts_seen:
            alerts_seen.add(key)
            alerts.append(f"Poisoning detected: IP {ip} is claimed by {len(macs)} MACs: {sorted(macs)}")

    return alerts


def handle_packet(packet):
    for message in check_packet(packet):
        log.warning(message)


def main():
    parser = argparse.ArgumentParser(description="Detect ARP cache poisoning on the local network.")
    parser.add_argument("-i", "--iface", help="network interface to watch (default: scapy picks one)")
    parser.add_argument("-r", "--pcap", help="read packets from a capture file instead of live traffic")
    parser.add_argument("-l", "--log", help="also write the output to this file")
    parser.add_argument("-v", "--verbose", action="store_true", help="show every ARP packet, not just alerts")
    args = parser.parse_args()

    handlers = [logging.StreamHandler()]
    if args.log:
        handlers.append(logging.FileHandler(args.log))

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=handlers,
    )

    log.info("ARP cache poisoning detection started")

    try:
        if args.pcap:
            sniff(offline=args.pcap, prn=handle_packet, store=0)
        else:
            sniff(iface=args.iface, filter="arp", prn=handle_packet, store=0)
    except PermissionError:
        log.error("Not enough rights to capture packets. On Linux run it with sudo.")
        return 1
    except FileNotFoundError:
        log.error(f"Could not find the capture file: {args.pcap}")
        return 1
    except Scapy_Exception as error:
        log.error(f"Could not start the capture: {error}")
        log.error("Windows needs Npcap installed. Linux needs libpcap (comes with tcpdump).")
        return 1
    except KeyboardInterrupt:
        pass

    log.info(f"Stopped. Alerts raised: {len(alerts_seen)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
