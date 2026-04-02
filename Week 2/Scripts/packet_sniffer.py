#!/usr/bin/env python3
"""
packet_sniffer.py
-----------------
Captures 100 network packets on a specified interface using Scapy,
analyzes protocol distribution, and generates a bar chart report.

Requirements:
    pip install scapy matplotlib
    Run with root privileges: sudo python3 packet_sniffer.py

Usage:
    sudo python3 packet_sniffer.py                  # Uses default interface
    sudo python3 packet_sniffer.py --iface eth0     # Specify interface
    sudo python3 packet_sniffer.py --iface lo       # Loopback interface
"""

import argparse                      # for command-line argument parsing
import collections                   # for counting protocol occurrences
import datetime                      # for timestamping output
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw  # core Scapy imports
import matplotlib.pyplot as plt      # for generating the bar chart
import matplotlib.patches as mpatches


# ─── Configuration ────────────────────────────────────────────────────────────

PACKET_COUNT   = 100          # number of packets to capture
DEFAULT_IFACE  = None         # None = Scapy auto-selects the best interface
CHART_OUTPUT   = "protocol_distribution.png"
REPORT_OUTPUT  = "packet_report.txt"


# ─── Protocol Identification ──────────────────────────────────────────────────

def identify_protocol(packet) -> str:
    """
    Inspect a Scapy packet and return its highest-level protocol name.
    Checks layers from most specific to most general.

    Args:
        packet: A Scapy packet object

    Returns:
        str: Protocol name (e.g., 'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'Other')
    """
    # DNS sits on top of UDP — check before generic UDP
    if packet.haslayer(DNS):
        return "DNS"

    # Layer 4 protocols (transport layer)
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"

    # Layer 2/3 protocols
    if packet.haslayer(ARP):
        return "ARP"

    # Any IP packet not matched above
    if packet.haslayer(IP):
        return "IP (Other)"

    # Non-IP traffic (e.g., raw Ethernet frames, 802.11)
    return "Other"


# ─── Packet Capture ───────────────────────────────────────────────────────────

def capture_packets(count: int, iface=None) -> list:
    """
    Capture a specified number of packets from the network interface.

    Args:
        count: Number of packets to capture
        iface: Network interface name (None = auto)

    Returns:
        list: List of captured Scapy packet objects
    """
    print(f"\n[*] Starting packet capture — collecting {count} packets...")
    print(f"[*] Interface: {iface if iface else 'auto-selected'}")
    print("[*] Press Ctrl+C to stop early.\n")

    # sniff() blocks until 'count' packets are captured
    packets = sniff(count=count, iface=iface, store=True)

    print(f"[+] Captured {len(packets)} packets.\n")
    return packets


# ─── Analysis ─────────────────────────────────────────────────────────────────

def analyze_packets(packets: list) -> dict:
    """
    Analyze captured packets and count occurrences of each protocol.

    Args:
        packets: List of Scapy packet objects

    Returns:
        dict: Protocol name → count mapping, sorted descending
    """
    protocol_counts = collections.Counter()

    for pkt in packets:
        proto = identify_protocol(pkt)
        protocol_counts[proto] += 1

    # Return as regular dict sorted by count (most common first)
    return dict(sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True))


# ─── Chart Generation ─────────────────────────────────────────────────────────

def generate_chart(protocol_counts: dict, output_file: str = CHART_OUTPUT):
    """
    Generate a bar chart showing protocol distribution and save to PNG.

    Args:
        protocol_counts: dict of protocol → packet count
        output_file: Path to save the PNG image
    """
    # Color palette for each protocol bar
    colors = {
        "TCP":      "#2E86AB",   # blue
        "UDP":      "#A23B72",   # purple
        "ICMP":     "#F18F01",   # orange
        "DNS":      "#C73E1D",   # red
        "ARP":      "#3B1F2B",   # dark
        "IP (Other)":"#44BBA4",  # teal
        "Other":    "#95A5A6",   # gray
    }

    labels  = list(protocol_counts.keys())
    values  = list(protocol_counts.values())
    bar_colors = [colors.get(l, "#95A5A6") for l in labels]
    total   = sum(values)

    fig, ax = plt.subplots(figsize=(10, 6))

    bars = ax.bar(labels, values, color=bar_colors, edgecolor="white",
                  linewidth=1.2, width=0.6)

    # Add count + percentage labels on top of each bar
    for bar, val in zip(bars, values):
        pct = val / total * 100
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.5,
            f"{val}\n({pct:.1f}%)",
            ha="center", va="bottom", fontsize=10, fontweight="bold"
        )

    # Styling
    ax.set_title("Captured Packet Protocol Distribution (n=100)",
                 fontsize=14, fontweight="bold", pad=20)
    ax.set_xlabel("Protocol", fontsize=12, labelpad=10)
    ax.set_ylabel("Packet Count", fontsize=12, labelpad=10)
    ax.set_ylim(0, max(values) * 1.25)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

    # Timestamp watermark
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fig.text(0.99, 0.01, f"Generated: {ts}", ha="right",
             fontsize=8, color="gray", style="italic")

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[+] Protocol distribution chart saved to: {output_file}")


# ─── Text Report ──────────────────────────────────────────────────────────────

def generate_text_report(packets: list, protocol_counts: dict,
                          output_file: str = REPORT_OUTPUT, iface=None):
    """
    Generate a human-readable text report of sniffing results.

    Args:
        packets:         Captured Scapy packets
        protocol_counts: Analyzed protocol → count dict
        output_file:     Path to save the report
        iface:           Interface name used
    """
    ts    = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(packets)
    lines = []

    lines.append("=" * 65)
    lines.append("         SCAPY PACKET SNIFFER — CAPTURE REPORT")
    lines.append("=" * 65)
    lines.append(f"  Timestamp       : {ts}")
    lines.append(f"  Interface       : {iface if iface else 'auto-selected'}")
    lines.append(f"  Packets Captured: {total}")
    lines.append("=" * 65)
    lines.append("")
    lines.append("  PROTOCOL DISTRIBUTION:")
    lines.append(f"  {'Protocol':<15} {'Count':<8} {'Percentage'}")
    lines.append(f"  {'-'*13:<15} {'-'*6:<8} {'-'*10}")

    for proto, count in protocol_counts.items():
        pct = count / total * 100
        lines.append(f"  {proto:<15} {count:<8} {pct:.1f}%")

    lines.append("")
    lines.append("  SAMPLE PACKET DETAILS (first 10 packets):")
    lines.append(f"  {'#':<5} {'Protocol':<12} {'Source':<22} {'Destination'}")
    lines.append(f"  {'-'*3:<5} {'-'*10:<12} {'-'*20:<22} {'-'*20}")

    for i, pkt in enumerate(packets[:10]):
        proto = identify_protocol(pkt)
        src   = pkt[IP].src  if pkt.haslayer(IP) else "N/A"
        dst   = pkt[IP].dst  if pkt.haslayer(IP) else "N/A"
        lines.append(f"  {i+1:<5} {proto:<12} {src:<22} {dst}")

    lines.append("")
    lines.append("=" * 65)
    lines.append("  Capture complete.")
    lines.append("=" * 65)

    report = "\n".join(lines)
    print("\n" + report)

    with open(output_file, "w") as f:
        f.write(report + "\n")

    print(f"\n[+] Text report saved to: {output_file}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scapy Packet Sniffer — capture and analyze 100 network packets"
    )
    parser.add_argument(
        "--iface", "-i",
        default=DEFAULT_IFACE,
        help="Network interface to capture on (e.g., eth0, lo, wlan0). Default: auto"
    )
    parser.add_argument(
        "--count", "-n",
        type=int, default=PACKET_COUNT,
        help=f"Number of packets to capture (default: {PACKET_COUNT})"
    )
    args = parser.parse_args()

    # Step 1: Capture packets
    packets = capture_packets(count=args.count, iface=args.iface)

    # Step 2: Analyze protocol distribution
    protocol_counts = analyze_packets(packets)
    print("[*] Protocol distribution:")
    for proto, count in protocol_counts.items():
        print(f"    {proto:<15}: {count} packets ({count/len(packets)*100:.1f}%)")

    # Step 3: Generate bar chart
    generate_chart(protocol_counts, output_file=CHART_OUTPUT)

    # Step 4: Generate text report
    generate_text_report(packets, protocol_counts,
                         output_file=REPORT_OUTPUT, iface=args.iface)


if __name__ == "__main__":
    main()
