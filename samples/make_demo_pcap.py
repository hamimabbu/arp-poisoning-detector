"""Builds demo_attack.pcap, a small fake capture of an ARP poisoning attack.

All addresses are made up. Run it from the repo root:
    python samples/make_demo_pcap.py
"""

from scapy.all import ARP, Ether, wrpcap

GATEWAY_IP, GATEWAY_MAC = "192.168.56.1", "08:00:27:aa:aa:01"
VICTIM_IP, VICTIM_MAC = "192.168.56.20", "08:00:27:bb:bb:02"
ATTACKER_MAC = "08:00:27:cc:cc:03"


def reply(src_ip, src_mac, dst_ip, dst_mac):
    # "src_ip is at src_mac", sent to dst
    return Ether(src=src_mac, dst=dst_mac) / ARP(
        op=2, psrc=src_ip, hwsrc=src_mac, pdst=dst_ip, hwdst=dst_mac
    )


packets = [
    # Normal traffic first
    reply(GATEWAY_IP, GATEWAY_MAC, VICTIM_IP, VICTIM_MAC),
    reply(VICTIM_IP, VICTIM_MAC, GATEWAY_IP, GATEWAY_MAC),
]

# Then the attacker poisons both sides, like arpspoof does.
# Replies come from the attacker's MAC but claim someone else's IP.
for _ in range(3):
    packets.append(Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) / ARP(
        op=2, psrc=GATEWAY_IP, hwsrc=ATTACKER_MAC, pdst=VICTIM_IP, hwdst=VICTIM_MAC))
    packets.append(Ether(src=ATTACKER_MAC, dst=GATEWAY_MAC) / ARP(
        op=2, psrc=VICTIM_IP, hwsrc=ATTACKER_MAC, pdst=GATEWAY_IP, hwdst=GATEWAY_MAC))

wrpcap("samples/demo_attack.pcap", packets)
print(f"Wrote {len(packets)} packets to samples/demo_attack.pcap")
