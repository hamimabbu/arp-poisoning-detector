# ARP poisoning detector

A Python and Scapy tool that watches ARP traffic and reports conflicting IP and MAC address claims.

It started as a CSCI262 group assignment at the University of Wollongong. This version adds an offline capture mode, file logging and automated tests.

## The problem

ARP has no authentication. A machine on the LAN can claim an IP address using its own MAC address. Forged claims can redirect traffic through an attacker between a victim and the gateway.

## How the detector works

It sniffs ARP packets with Scapy and keeps track of which MAC addresses have claimed which IP addresses. It raises an alert in two cases:

1. One MAC address claims more than one IP address, as it might when impersonating both a victim and a gateway.
2. One IP address is claimed by more than one MAC address, as it might when the real gateway and an attacker answer for the same IP.

Repeated claims do not repeat the same alert. A new claim that increases the number of conflicting addresses raises another alert. These are warning signs; ordinary network changes can also trigger them, as noted in the limitations below.

## Setup

You need Python 3.11 or newer. The test workflow covers Python 3.11, 3.12 and 3.13 on Windows and Linux. Check the latest Actions run for its results.

```
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

For live capture, Windows needs [Npcap](https://npcap.com/) and Linux needs libpcap (it comes with tcpdump). Kali has it already.

The included capture-file demo and automated tests do not need administrator rights or a live network. Scapy may warn that no capture driver is installed; this does not stop the offline demo. Live capture still needs the driver and suitable permissions.

## Offline demo

The repo includes a synthetic attack capture with made-up addresses:

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

For example, `python arp_detector.py --pcap samples/demo_attack.pcap --log alerts.log` also writes the three demo alerts to a UTF-8 log. The parent folder must already exist. Invalid log paths, missing or unsupported capture files and unavailable interfaces produce an error and exit with status 1.

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
python -m pip install -r requirements-dev.txt
python -m pytest
```

The 14 tests cover normal traffic, both alert types, repeated alerts, forged requests, ignored packets, the demo capture, log output and error handling. They passed on Windows and Linux with Python 3.11, 3.12 and 3.13: [test run](https://github.com/hamimabbu/arp-poisoning-detector/actions/runs/42325270782). The workflow uses offline checks and does not capture live traffic.

## Limitations

- It only detects. It does not block the attacker or fix the ARP cache.
- It only sees the packets that reach the machine it runs on. Poisoning replies are sent straight to the victim, so run it on the machine you want to protect. On a switched network, a bystander machine will not see them.
- It can give false alarms on networks where one device legitimately answers for several IPs (some routers, proxy ARP, virtual machine hosts) or where a device changes MAC address (failover, NIC swaps).
- If the detector starts after the attack has already begun, it may learn the attacker's MAC as the "normal" one.
- Learned mappings stay in memory until the process ends. This is a short-session lab tool; long-running capture on a busy network can use increasing memory.
- This learning tool does not replace network controls such as Dynamic ARP Inspection or deliberately configured static ARP entries.

## Project files

```
arp_detector.py          the detector
requirements.txt         Python dependency (Scapy)
requirements-dev.txt     Test dependencies
tests/test_detector.py   tests
samples/                 demo capture and the script that makes it
.github/workflows/       Offline Windows/Linux checks
```
