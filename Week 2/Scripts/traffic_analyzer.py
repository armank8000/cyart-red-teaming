#!/usr/bin/env python3
"""
traffic_analyzer.py
--------------------
Parses a PCAP file of HTTPS/network traffic, extracts packet metadata,
counts packets per source/destination IP pair, analyzes inter-arrival
timing, and generates a publication-quality bar chart of packet size
distribution.

Requirements:
    pip install pyshark scapy matplotlib pandas

Usage:
    python3 traffic_analyzer.py --pcap capture.pcap
    python3 traffic_analyzer.py --pcap capture.pcap --output report.txt --chart sizes.png
    python3 traffic_analyzer.py --demo          # Run with simulated data (no PCAP needed)

Notes:
    - Requires tshark to be installed for pyshark (sudo apt install tshark)
    - Run with appropriate permissions if reading live capture files
    - Use --demo flag to run with synthetic data for testing/demonstration
"""

import argparse
import csv
import os
import random
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# Optional imports — graceful fallback if libraries unavailable
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    print("[!] pyshark not installed — use --demo mode or: pip install pyshark")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


# ─── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_PCAP   = "capture.pcap"
DEFAULT_CHART  = "packet_size_distribution.png"
DEFAULT_OUTPUT = "traffic_report.txt"
HTTPS_PORT     = 443


# ─── Data Structures ───────────────────────────────────────────────────────────

class PacketRecord:
    """Holds metadata for a single parsed packet."""

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        length: int,
    ) -> None:
        self.timestamp = timestamp   # Unix epoch float
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.src_port  = src_port
        self.dst_port  = dst_port
        self.protocol  = protocol
        self.length    = length      # Packet size in bytes

    def __repr__(self) -> str:
        return (
            f"PacketRecord(src={self.src_ip}:{self.src_port} → "
            f"dst={self.dst_ip}:{self.dst_port}, "
            f"proto={self.protocol}, len={self.length}B)"
        )


# ─── PCAP Parsing ──────────────────────────────────────────────────────────────

def parse_pcap(pcap_path: str, max_packets: int = 5000) -> list[PacketRecord]:
    """
    Parse a PCAP file using pyshark and extract metadata for each packet.

    pyshark wraps tshark (Wireshark's CLI engine), providing a Pythonic API
    to iterate over packets and access protocol fields by name. It is preferred
    over raw Scapy here because it handles HTTPS/TLS dissection more cleanly
    and supports all Wireshark dissectors out of the box.

    Args:
        pcap_path:   Path to the .pcap or .pcapng file
        max_packets: Maximum packets to read (prevents memory exhaustion)

    Returns:
        List of PacketRecord objects with extracted metadata
    """
    if not PYSHARK_AVAILABLE:
        raise RuntimeError("pyshark is required. Install with: pip install pyshark")

    print(f"[*] Parsing PCAP: {pcap_path}")
    records: list[PacketRecord] = []

    # Open the capture file with tshark in the background
    cap = pyshark.FileCapture(
        pcap_path,
        display_filter="ip",           # Only IP packets (skips raw Ethernet frames)
        keep_packets=False,            # Don't buffer all packets in memory
    )

    for i, pkt in enumerate(cap):
        if i >= max_packets:
            print(f"[*] Reached max_packets limit ({max_packets})")
            break

        try:
            # Extract IP layer fields
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            proto  = pkt.transport_layer or pkt.highest_layer
            length = int(pkt.length)
            ts     = float(pkt.sniff_timestamp)

            # Extract transport-layer ports (TCP/UDP)
            src_port: Optional[int] = None
            dst_port: Optional[int] = None
            if hasattr(pkt, "tcp"):
                src_port = int(pkt.tcp.srcport)
                dst_port = int(pkt.tcp.dstport)
            elif hasattr(pkt, "udp"):
                src_port = int(pkt.udp.srcport)
                dst_port = int(pkt.udp.dstport)

            records.append(PacketRecord(ts, src_ip, dst_ip, src_port, dst_port, proto, length))

        except AttributeError:
            # Skip malformed or incomplete packets
            continue

    cap.close()
    print(f"[+] Parsed {len(records)} packets from {pcap_path}")
    return records


# ─── Synthetic Demo Data ────────────────────────────────────────────────────────

def generate_demo_data(n: int = 1000) -> list[PacketRecord]:
    """
    Generate synthetic packet records for demonstration purposes.
    Simulates 5 minutes of mixed HTTPS + DNS + general TCP traffic.

    Packet size distribution follows a bimodal pattern:
      - Small ACK/control packets: ~40–120 bytes  (40% of traffic)
      - Large data/TLS record packets: ~800–1500 bytes (60% of traffic)

    Args:
        n: Number of synthetic packets to generate

    Returns:
        List of synthetic PacketRecord objects
    """
    random.seed(42)  # Reproducible results
    records: list[PacketRecord] = []

    # Representative host IPs in a small office network
    hosts = [
        "192.168.1.10", "192.168.1.11", "192.168.1.12",
        "192.168.1.20", "192.168.1.21",
    ]
    # Common public-facing servers (HTTPS/CDN)
    servers = [
        "142.250.80.46",   # Google
        "151.101.1.140",   # Fastly CDN
        "52.94.236.248",   # AWS
        "104.16.132.229",  # Cloudflare
        "13.107.4.52",     # Microsoft
    ]
    protocols = ["TCP", "TCP", "TCP", "UDP", "TLS"]  # Weight toward TCP
    base_ts    = time.time() - 300  # 5 minutes ago

    for i in range(n):
        # Bimodal size: small control packets vs large data packets
        if random.random() < 0.40:
            size = int(random.gauss(72, 20))         # ACK/control
            size = max(40, min(size, 200))
        else:
            size = int(random.gauss(1100, 250))      # TLS data records
            size = max(200, min(size, 1500))

        # Random inter-arrival time: exponential with mean 0.3s
        ts = base_ts + i * random.expovariate(1/0.3)

        src_ip   = random.choice(hosts)
        dst_ip   = random.choice(servers) if random.random() > 0.3 else random.choice(hosts)
        protocol = random.choice(protocols)
        src_port = random.randint(49152, 65535)   # Ephemeral source port
        dst_port = HTTPS_PORT if random.random() > 0.2 else random.choice([80, 53, 22])

        records.append(PacketRecord(ts, src_ip, dst_ip, src_port, dst_port, protocol, size))

    return records


# ─── Analysis Functions ────────────────────────────────────────────────────────

def compute_ip_stats(records: list[PacketRecord]) -> dict[str, dict]:
    """
    Count packets and total bytes grouped by source IP.

    Returns a dict mapping src_ip → {"packets": N, "bytes": B, "avg_size": F}
    """
    stats: dict[str, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for rec in records:
        stats[rec.src_ip]["packets"] += 1
        stats[rec.src_ip]["bytes"]   += rec.length

    # Compute average packet size per source
    for ip, data in stats.items():
        data["avg_size"] = round(data["bytes"] / data["packets"], 1)

    # Sort by packet count descending
    return dict(sorted(stats.items(), key=lambda x: x[1]["packets"], reverse=True))


def compute_flow_matrix(records: list[PacketRecord]) -> dict[tuple[str, str], int]:
    """
    Build a flow matrix: (src_ip, dst_ip) → packet_count.
    Useful for identifying heavy-talker host pairs.
    """
    flows: dict[tuple[str, str], int] = defaultdict(int)
    for rec in records:
        flows[(rec.src_ip, rec.dst_ip)] += 1
    return dict(sorted(flows.items(), key=lambda x: x[1], reverse=True))


def compute_interarrival_stats(records: list[PacketRecord]) -> dict[str, float]:
    """
    Compute inter-arrival time statistics (gap between consecutive packets).
    High variance in IAT can indicate bursty/scanning traffic.
    """
    if len(records) < 2:
        return {}

    # Sort by timestamp first
    sorted_recs = sorted(records, key=lambda r: r.timestamp)
    iats = [
        sorted_recs[i].timestamp - sorted_recs[i-1].timestamp
        for i in range(1, len(sorted_recs))
    ]

    arr = np.array(iats)
    return {
        "min_ms":    round(float(arr.min()) * 1000, 3),
        "max_ms":    round(float(arr.max()) * 1000, 3),
        "mean_ms":   round(float(arr.mean()) * 1000, 3),
        "median_ms": round(float(np.median(arr)) * 1000, 3),
        "std_ms":    round(float(arr.std()) * 1000, 3),
    }


def bin_packet_sizes(
    records: list[PacketRecord],
    bins: list[tuple[int, int]] | None = None
) -> dict[str, int]:
    """
    Bin packet lengths into human-readable size ranges.

    Default bins match common network packet categories:
      - Tiny    (<  64B):  ACKs, empty TCP segments
      - Small   ( 64–127B): DNS, small HTTP requests
      - Medium  (128–511B): HTTP headers, TLS handshakes
      - Large   (512–1023B): HTTP responses, partial TLS records
      - Maximum (1024–1500B): Full MTU TLS data records
      - Jumbo   (> 1500B):  Reassembled or jumbo frames
    """
    if bins is None:
        bins = [
            (0,    63,   "Tiny\n(<64B)"),
            (64,   127,  "Small\n(64–127B)"),
            (128,  511,  "Medium\n(128–511B)"),
            (512,  1023, "Large\n(512–1023B)"),
            (1024, 1499, "Max MTU\n(1024–1499B)"),
            (1500, 9999, "Jumbo\n(≥1500B)"),
        ]

    counts: dict[str, int] = {label: 0 for _, _, label in bins}
    for rec in records:
        for lo, hi, label in bins:
            if lo <= rec.length <= hi:
                counts[label] += 1
                break

    return counts


# ─── Visualization ─────────────────────────────────────────────────────────────

def generate_size_chart(
    records: list[PacketRecord],
    output_path: str = DEFAULT_CHART
) -> None:
    """
    Generate a bar chart of packet size distribution and save to disk.

    Two-panel figure:
      Left:  Binned packet size distribution (bar chart with percentages)
      Right: Cumulative distribution function (CDF) of raw packet sizes

    Args:
        records:     List of PacketRecord objects to visualize
        output_path: File path for the saved PNG
    """
    sizes = [r.length for r in records]
    bins  = bin_packet_sizes(records)
    total = sum(bins.values())

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.patch.set_facecolor("#F8F9FA")

    # ── Left: Binned bar chart ──────────────────────────────────────────────
    labels = list(bins.keys())
    counts = list(bins.values())
    colors = ["#2E86AB", "#1ABC9C", "#F18F01", "#E74C3C", "#8E44AD", "#95A5A6"]

    ax1.set_facecolor("#F8F9FA")
    bars = ax1.bar(labels, counts, color=colors[:len(labels)],
                   edgecolor="white", linewidth=1.5, width=0.65)

    # Annotate each bar with count + percentage
    for bar, val in zip(bars, counts):
        pct = val / total * 100 if total > 0 else 0
        ax1.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(counts) * 0.015,
            f"{val}\n({pct:.1f}%)",
            ha="center", fontsize=9, fontweight="bold", color="#2C3E50"
        )

    ax1.set_title(
        f"HTTPS Traffic — Packet Size Distribution\n(n={total:,} packets)",
        fontsize=12, fontweight="bold", pad=14
    )
    ax1.set_xlabel("Packet Size Range", fontsize=10)
    ax1.set_ylabel("Packet Count", fontsize=10)
    ax1.set_ylim(0, max(counts) * 1.18)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax1.set_axisbelow(True)

    # ── Right: CDF of raw sizes ─────────────────────────────────────────────
    ax2.set_facecolor("#F8F9FA")
    sorted_sizes = np.sort(sizes)
    cdf = np.arange(1, len(sorted_sizes) + 1) / len(sorted_sizes)

    ax2.plot(sorted_sizes, cdf * 100, color="#2E86AB", lw=2.5)
    ax2.fill_between(sorted_sizes, cdf * 100, alpha=0.15, color="#2E86AB")

    # Mark 25th, 50th, 75th percentiles
    for pct_val, color in [(25, "#F18F01"), (50, "#E74C3C"), (75, "#8E44AD")]:
        p = np.percentile(sorted_sizes, pct_val)
        ax2.axvline(x=p, color=color, linestyle="--", lw=1.5, alpha=0.8)
        ax2.axhline(y=pct_val, color=color, linestyle=":", lw=1, alpha=0.6)
        ax2.text(p + 10, pct_val + 1.5, f"p{pct_val}={int(p)}B",
                 fontsize=8, color=color, fontweight="bold")

    ax2.set_title(
        "Cumulative Distribution Function (CDF)\nof Raw Packet Sizes",
        fontsize=12, fontweight="bold", pad=14
    )
    ax2.set_xlabel("Packet Size (bytes)", fontsize=10)
    ax2.set_ylabel("Cumulative % of Packets", fontsize=10)
    ax2.set_xlim(0, min(max(sizes) + 50, 1550))
    ax2.set_ylim(0, 105)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.yaxis.grid(True, linestyle="--", alpha=0.4)
    ax2.set_axisbelow(True)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fig.text(0.99, 0.01, f"traffic_analyzer.py | {ts}",
             ha="right", fontsize=7, color="gray", style="italic")

    plt.tight_layout(pad=2.5)
    plt.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"[+] Chart saved → {output_path}")


# ─── Report Output ─────────────────────────────────────────────────────────────

def print_report(
    records: list[PacketRecord],
    output_path: Optional[str] = None
) -> None:
    """
    Print (and optionally save) a structured text report covering:
      - Capture summary
      - Per-IP packet counts and byte totals
      - Top-10 conversation flows
      - Packet size bin distribution
      - Inter-arrival time statistics
    """
    lines: list[str] = []

    def emit(line: str = "") -> None:
        lines.append(line)
        print(line)

    emit("=" * 70)
    emit("  HTTPS Traffic Analysis Report — traffic_analyzer.py")
    emit(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    emit("=" * 70)
    emit()

    # Summary
    emit(f"Total packets analysed : {len(records):,}")
    if records:
        ts_sorted = sorted(records, key=lambda r: r.timestamp)
        duration  = ts_sorted[-1].timestamp - ts_sorted[0].timestamp
        emit(f"Capture duration       : {duration:.1f} seconds")
        emit(f"Avg packet size        : {sum(r.length for r in records) / len(records):.1f} bytes")
        emit(f"Total bytes captured   : {sum(r.length for r in records):,} bytes")
        emit(f"Avg packet rate        : {len(records) / max(duration, 1):.1f} pkt/sec")

    emit()
    emit("─" * 70)
    emit(" PACKET COUNTS BY SOURCE IP (Top 15)")
    emit("─" * 70)
    emit(f"  {'Source IP':<22} {'Packets':>9}  {'Bytes':>12}  {'Avg Size':>10}")
    emit(f"  {'-'*22}  {'-'*9}  {'-'*12}  {'-'*10}")
    ip_stats = compute_ip_stats(records)
    for i, (ip, data) in enumerate(ip_stats.items()):
        if i >= 15:
            break
        emit(f"  {ip:<22} {data['packets']:>9,}  {data['bytes']:>12,}  {data['avg_size']:>9.1f}B")

    emit()
    emit("─" * 70)
    emit(" TOP-10 CONVERSATION FLOWS  (src IP → dst IP)")
    emit("─" * 70)
    emit(f"  {'Source IP':<22} → {'Dest IP':<22}  {'Packets':>8}")
    emit(f"  {'-'*22}    {'-'*22}  {'-'*8}")
    flows = compute_flow_matrix(records)
    for i, ((src, dst), count) in enumerate(flows.items()):
        if i >= 10:
            break
        emit(f"  {src:<22}   {dst:<22}  {count:>8,}")

    emit()
    emit("─" * 70)
    emit(" PACKET SIZE DISTRIBUTION")
    emit("─" * 70)
    size_bins = bin_packet_sizes(records)
    total = sum(size_bins.values())
    for label, count in size_bins.items():
        pct  = count / total * 100 if total > 0 else 0
        bar  = "█" * int(pct / 2)
        emit(f"  {label.replace(chr(10), ' '):<28} {count:>6,}  ({pct:5.1f}%)  {bar}")

    emit()
    emit("─" * 70)
    emit(" INTER-ARRIVAL TIME STATISTICS")
    emit("─" * 70)
    iat = compute_interarrival_stats(records)
    for k, v in iat.items():
        emit(f"  {k:<18} {v:>10.3f} ms")

    emit()
    emit("=" * 70)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"[+] Report saved → {output_path}")


# ─── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point — parse CLI arguments and run the full analysis pipeline."""
    parser = argparse.ArgumentParser(
        description="HTTPS Traffic Analyser — parses PCAP and generates packet metadata report"
    )
    parser.add_argument("--pcap",   "-p", default=DEFAULT_PCAP,
                        help=f"Path to PCAP file (default: {DEFAULT_PCAP})")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT,
                        help=f"Text report output path (default: {DEFAULT_OUTPUT})")
    parser.add_argument("--chart",  "-c", default=DEFAULT_CHART,
                        help=f"Chart PNG output path (default: {DEFAULT_CHART})")
    parser.add_argument("--max",    "-m", type=int, default=5000,
                        help="Max packets to parse (default: 5000)")
    parser.add_argument("--demo",         action="store_true",
                        help="Run with synthetic demo data instead of a real PCAP")
    args = parser.parse_args()

    if args.demo:
        print("[*] Running in DEMO mode — generating 1,000 synthetic packets...")
        records = generate_demo_data(1000)
    elif os.path.exists(args.pcap):
        records = parse_pcap(args.pcap, max_packets=args.max)
    else:
        print(f"[!] PCAP file not found: {args.pcap}")
        print("[*] Falling back to DEMO mode...")
        records = generate_demo_data(1000)

    # Run analysis and output
    print_report(records, output_path=args.output)
    generate_size_chart(records, output_path=args.chart)
    print("[+] Analysis complete.")


if __name__ == "__main__":
    main()
