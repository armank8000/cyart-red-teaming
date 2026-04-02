#!/usr/bin/env python3
"""
test_packets.py
---------------
Generates crafted test packets using Scapy to trigger Snort IDS rules.
Simulates four attack scenarios:
  1. SYN flood — triggers the SYN Packet Detected rule (sid:1000001)
  2. Port scan  — triggers the Potential Port Scan rule (sid:1000002)
  3. ICMP ping sweep — triggers ICMP-based detection rules
  4. UDP probe  — tests UDP service discovery rules

Requirements:
    pip install scapy
    Must be run with root privileges: sudo python3 test_packets.py

Usage:
    sudo python3 test_packets.py --target 192.168.1.100
    sudo python3 test_packets.py --target 192.168.1.100 --iface eth0 --delay 0.05
"""

import argparse
import time
import random
from typing import Optional

# Import Scapy layers — suppress the IPv6 warning on some systems
from scapy.all import (
    IP, TCP, UDP, ICMP,
    send, conf,
    RandShort
)


# ─── Configuration Defaults ───────────────────────────────────────────────────

DEFAULT_TARGET  = "192.168.1.100"   # Metasploitable 2 target
DEFAULT_SOURCE  = "192.168.1.50"    # Our Kali Linux source IP
DEFAULT_IFACE   = "eth0"            # Network interface
DEFAULT_DELAY   = 0.05              # Seconds between packets (50ms)
SYN_FLOOD_COUNT = 20                # Number of SYN flood packets
PORT_SCAN_RANGE = range(1, 1025)    # Ports 1–1024 for port scan
ICMP_SWEEP_COUNT = 10               # ICMP echo requests to send


# ─── Helper ───────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    """Print a formatted status message with timestamp."""
    print(f"[*] {msg}")


def log_ok(msg: str) -> None:
    """Print a success message."""
    print(f"[+] {msg}")


def log_warn(msg: str) -> None:
    """Print a warning message."""
    print(f"[!] {msg}")


# ─── Attack 1: SYN Flood ──────────────────────────────────────────────────────

def syn_flood(
    target: str,
    count: int = SYN_FLOOD_COUNT,
    delay: float = DEFAULT_DELAY,
    iface: Optional[str] = None
) -> None:
    """
    Send a burst of TCP SYN packets to a single port (port 80) on the target.

    Triggers Snort rule:
        alert tcp any any -> any any (msg:"SYN Packet Detected"; flags:S; sid:1000001;)

    SYN packets have only the SYN flag set (flags="S"), making them identifiable
    as potential flood or half-open connection attempts. We use a random source
    port each time to simulate different 'clients'.

    Args:
        target:  Destination IP address
        count:   Number of SYN packets to send
        delay:   Delay in seconds between each packet
        iface:   Network interface to send on (None = auto)
    """
    log(f"Starting SYN flood → {target}:80 ({count} packets)...")

    for i in range(count):
        # Build the IP layer pointing to the target
        ip_layer = IP(dst=target)

        # Build TCP layer with:
        #   dport=80  — targeting HTTP port
        #   sport=RandShort() — random ephemeral source port
        #   flags="S"  — SYN flag only (no ACK, no data)
        #   seq=random — random sequence number (mimics real TCP)
        tcp_layer = TCP(
            dport=80,
            sport=RandShort(),
            flags="S",
            seq=random.randint(1000, 900000)
        )

        # Assemble and send the packet (verbose=0 suppresses Scapy output)
        packet = ip_layer / tcp_layer
        send(packet, verbose=0, iface=iface)
        time.sleep(delay)

    log_ok(f"SYN flood complete — {count} SYN packets sent to {target}:80")


# ─── Attack 2: TCP Port Scan ──────────────────────────────────────────────────

def port_scan(
    target: str,
    ports: range = PORT_SCAN_RANGE,
    delay: float = DEFAULT_DELAY,
    iface: Optional[str] = None
) -> None:
    """
    Send a TCP SYN packet to each port in the specified range, simulating
    a SYN (half-open/stealth) port scan.

    Triggers Snort rule:
        alert tcp any any -> any 1-1024 (msg:"Potential Port Scan"; flags:S; sid:1000002;)

    By sending SYN packets across ports 1–1024, Snort's pattern matching
    detects the scan via the port range and SYN flag combination.

    Args:
        target:  Destination IP address
        ports:   Range of ports to scan
        delay:   Delay between each packet (lower = faster scan)
        iface:   Network interface to send on
    """
    log(f"Starting SYN port scan → {target} ports {ports.start}–{ports.stop - 1}...")

    for port in ports:
        ip_layer  = IP(dst=target)

        # SYN packet to each port — this is the hallmark of a stealth scan
        tcp_layer = TCP(
            dport=port,        # Incrementing destination port
            sport=RandShort(), # Randomised source port (evades naive filters)
            flags="S",         # SYN only — no handshake completion
            seq=random.randint(1000, 900000)
        )

        packet = ip_layer / tcp_layer
        send(packet, verbose=0, iface=iface)
        time.sleep(delay)

    log_ok(f"Port scan complete — SYN packets sent to {len(ports)} ports on {target}")


# ─── Attack 3: ICMP Ping Sweep ────────────────────────────────────────────────

def icmp_sweep(
    target: str,
    count: int = ICMP_SWEEP_COUNT,
    delay: float = DEFAULT_DELAY,
    iface: Optional[str] = None
) -> None:
    """
    Send multiple ICMP echo request (ping) packets to a target host.
    Used for host discovery and liveness checks in reconnaissance.

    Triggers Snort rule (if configured):
        alert icmp any any -> any any (msg:"ICMP Ping Detected"; itype:8; sid:1000003;)

    ICMP type 8 = Echo Request (the standard ping packet type).

    Args:
        target:  Destination IP address
        count:   Number of ICMP packets to send
        delay:   Delay between each packet
        iface:   Network interface to send on
    """
    log(f"Starting ICMP sweep → {target} ({count} echo requests)...")

    for i in range(count):
        ip_layer   = IP(dst=target)

        # ICMP echo request:
        #   type=8  → Echo Request
        #   code=0  → Standard (no error code for echo)
        #   id=1    → ICMP identifier (links request to reply)
        #   seq=i   → Sequence number increments per packet
        icmp_layer = ICMP(type=8, code=0, id=1, seq=i)

        packet = ip_layer / icmp_layer
        send(packet, verbose=0, iface=iface)
        time.sleep(delay)

    log_ok(f"ICMP sweep complete — {count} echo requests sent to {target}")


# ─── Attack 4: UDP Probe ──────────────────────────────────────────────────────

def udp_probe(
    target: str,
    ports: list[int] = [53, 69, 123, 161, 137],
    delay: float = DEFAULT_DELAY,
    iface: Optional[str] = None
) -> None:
    """
    Send UDP probe packets to common service ports to fingerprint running
    UDP services and trigger UDP-based Snort detection rules.

    Target ports:
        53  → DNS
        69  → TFTP
        123 → NTP
        161 → SNMP
        137 → NetBIOS Name Service

    Args:
        target:  Destination IP address
        ports:   List of UDP ports to probe
        delay:   Delay between each packet
        iface:   Network interface to send on
    """
    log(f"Starting UDP probe → {target} ({len(ports)} ports)...")

    for port in ports:
        ip_layer  = IP(dst=target)

        # UDP layer with no payload — empty probe to elicit ICMP Port Unreachable
        # responses, which reveal whether the service is active
        udp_layer = UDP(
            dport=port,        # Destination service port
            sport=RandShort()  # Random source port
        )

        packet = ip_layer / udp_layer
        send(packet, verbose=0, iface=iface)
        time.sleep(delay)

    log_ok(f"UDP probe complete — packets sent to {len(ports)} ports on {target}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    """
    Parse arguments and execute all test attack scenarios sequentially.
    Each scenario is designed to trigger specific Snort IDS rules.
    """
    parser = argparse.ArgumentParser(
        description="Scapy Test Packet Generator — triggers Snort IDS rules for testing"
    )
    parser.add_argument(
        "--target", "-t",
        default=DEFAULT_TARGET,
        help=f"Target IP address (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--iface", "-i",
        default=DEFAULT_IFACE,
        help=f"Network interface (default: {DEFAULT_IFACE})"
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=DEFAULT_DELAY,
        help=f"Delay between packets in seconds (default: {DEFAULT_DELAY})"
    )
    parser.add_argument(
        "--syn-only",
        action="store_true",
        help="Run only the SYN flood test"
    )
    parser.add_argument(
        "--scan-only",
        action="store_true",
        help="Run only the port scan test"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("   Scapy IDS Test Packet Generator")
    print("=" * 60)
    print(f"   Target  : {args.target}")
    print(f"   Interface: {args.iface}")
    print(f"   Delay   : {args.delay}s between packets")
    print("=" * 60)
    print()

    # Suppress Scapy IPv6 routing warnings
    conf.verb = 0

    if args.syn_only:
        syn_flood(args.target, delay=args.delay, iface=args.iface)
    elif args.scan_only:
        port_scan(args.target, delay=args.delay, iface=args.iface)
    else:
        # Run all four attack simulations in sequence
        print("[1/4] SYN Flood Test")
        syn_flood(args.target, delay=args.delay, iface=args.iface)
        print()

        print("[2/4] TCP Port Scan Test")
        port_scan(args.target, delay=args.delay, iface=args.iface)
        print()

        print("[3/4] ICMP Ping Sweep Test")
        icmp_sweep(args.target, delay=args.delay, iface=args.iface)
        print()

        print("[4/4] UDP Service Probe Test")
        udp_probe(args.target, delay=args.delay, iface=args.iface)
        print()

    print("=" * 60)
    print("[+] All test scenarios complete.")
    print("[*] Check Snort console for triggered alerts.")
    print("=" * 60)


if __name__ == "__main__":
    main()
