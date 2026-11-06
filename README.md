# ARP Poisoning Detector

A small Python tool that watches ARP traffic on a local network and warns you when it looks like someone is poisoning ARP caches.

It started as a group assignment for CSCI262 at the University of Wollongong. This version is tidied up and extended with a capture file mode, a log file option and tests.

## The problem

ARP has no authentication. Any machine on the LAN can say "this IP belongs to my MAC address" and most systems will believe it. An attacker uses this to sit between a victim and the gateway (a man-in-the-middle attack) and read or change the traffic.

## How the detector works

It sniffs ARP packets with Scapy and keeps track of which MAC addresses have claimed which IP addresses. It raises an alert in two cases:

1. One MAC address claims more than one IP address. This is what an attacker looks like when it pretends to be both the victim and the gateway.
2. One IP address is claimed by more than one MAC address. This is what the victim sees when the real gateway and the attacker both answer for the same IP.

Each alert is only printed once, so a running attack does not flood the screen.

## Setup

You need Python 3.11 or newer. It is tested on 3.11, 3.12 and 3.13.

```
pip install -r requirements.txt
```

For live capture, Windows needs [Npcap](https://npcap.com/) and Linux needs libpcap (it comes with tcpdump). Kali has it already.

## Try it without root

The repo includes a fake capture of an attack (made-up addresses), so you can see the output straight away:

```
python arp_detector.py --pcap samples/demo_attack.pcap
```

Output:

```
[WARNING] Poisoning detected: IP 192.168.56.1 is claimed by 2 MACs: ['08:00:27:aa:aa:01', '08:00:27:cc:cc:03']
[WARNING] Poisoning detected: MAC 08:00:27:cc:cc:03 is claiming 2 IPs: ['192.168.56.1', '192.168.56.20']
[WARNING] Poisoning detected: IP 192.168.56.20 is claimed by 2 MACs: ['08:00:27:bb:bb:02', '08:00:27:cc:cc:03']
```

You can also run it on your own Wireshark captures with `--pcap yourfile.pcap`.

## Live use

Capturing live traffic needs admin rights.

```
sudo python3 arp_detector.py -i eth0
```

Options:

| Option | What it does |
| --- | --- |
| `-i`, `--iface` | Network interface to watch |
| `-r`, `--pcap` | Read from a capture file instead of live traffic |
| `-l`, `--log` | Also write the output to a file |
| `-v`, `--verbose` | Show every ARP packet, not just alerts |

## Testing it in a lab

The original assignment tested it in virtual machines, with Kali Linux as the attacker and Metasploitable as the victim. Only try this on machines and networks you own.

On the attacker, poison both directions (one terminal each):

```
arpspoof -i eth0 -t <victim-ip> <gateway-ip>
arpspoof -i eth0 -t <gateway-ip> <victim-ip>
```

Run the detector on the victim machine. It prints an alert once it sees the conflicting ARP packets.

## Tests

```
pip install pytest
python -m pytest
```

The tests cover normal traffic, both alert types, repeated alerts, forged requests, ignored packets and a full run on the demo capture.

## Limitations

- It only detects. It does not block the attacker or fix the ARP cache.
- It only sees the packets that reach the machine it runs on. Poisoning replies are sent straight to the victim, so run it on the machine you want to protect. On a switched network, a bystander machine will not see them.
- It can give false alarms on networks where one device legitimately answers for several IPs (some routers, proxy ARP, virtual machine hosts) or where a device changes MAC address (failover, NIC swaps).
- If the detector starts after the attack has already begun, it may learn the attacker's MAC as the "normal" one.
- Stronger defences are Dynamic ARP Inspection on managed switches, static ARP entries for critical hosts, and Secure ARP. This tool is for networks where you cannot use those.

## Project files

```
arp_detector.py          the detector
requirements.txt         Python dependency (Scapy)
tests/test_detector.py   tests
samples/                 demo capture and the script that makes it
```
