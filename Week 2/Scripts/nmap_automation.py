#!/usr/bin/env python3
"""
nmap_automation.py
------------------
Automates an Nmap SYN scan using the python-nmap library.
Accepts a target IP or hostname, performs the scan, and generates
a structured text report saved to scan_report.txt.

Requirements:
    pip install python-nmap
    (Nmap must be installed on the system)
"""

import nmap          # python-nmap wrapper library
import datetime      # for timestamping the report
import sys           # for command-line argument handling
import os            # for file path operations


def run_syn_scan(target: str) -> dict:
    """
    Perform a SYN scan (-sS) on the given target.
    Returns the raw scan result dictionary from python-nmap.

    Args:
        target: IP address or hostname to scan (e.g., "192.168.1.100")

    Returns:
        dict: Full nmap scan result
    """
    scanner = nmap.PortScanner()

    print(f"[*] Starting SYN scan on target: {target}")
    print("[*] This may take a moment...")

    # -sS = SYN (stealth) scan
    # -sV = version detection for services
    # --open = show only open ports
    scan_result = scanner.scan(
        hosts=target,
        arguments="-sS -sV --open"
    )

    print("[+] Scan complete.")
    return scanner


def extract_port_data(scanner, target: str) -> list:
    """
    Extract open ports, service names, and versions from scan results.

    Args:
        scanner: nmap.PortScanner object after scan
        target: the scanned IP/hostname string

    Returns:
        list of dicts with keys: port, state, service, version
    """
    ports_data = []

    # Check if the host was found in scan results
    if target not in scanner.all_hosts():
        print(f"[-] No scan results found for {target}.")
        return ports_data

    host_info = scanner[target]

    # Iterate over TCP protocol ports only (SYN scan is TCP)
    if "tcp" in host_info:
        for port, details in sorted(host_info["tcp"].items()):
            ports_data.append({
                "port":    port,
                "state":   details.get("state", "unknown"),
                "service": details.get("name", "unknown"),
                "version": details.get("version", "N/A") or "N/A",
            })

    return ports_data


def generate_report(target: str, ports_data: list, output_file: str = "scan_report.txt"):
    """
    Generate a formatted text report and save it to a file.

    Args:
        target:      The scanned target IP/hostname
        ports_data:  List of port dicts from extract_port_data()
        output_file: Filename to save the report (default: scan_report.txt)
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the report as a list of lines
    lines = []
    lines.append("=" * 65)
    lines.append("          NMAP AUTOMATION SCAN REPORT")
    lines.append("=" * 65)
    lines.append(f"  Scan Timestamp : {timestamp}")
    lines.append(f"  Target IP      : {target}")
    lines.append(f"  Scan Type      : SYN Scan (-sS) with Version Detection (-sV)")
    lines.append(f"  Total Open Ports Found: {len(ports_data)}")
    lines.append("=" * 65)
    lines.append("")

    if not ports_data:
        lines.append("  No open ports detected.")
    else:
        # Table header
        lines.append(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'VERSION'}")
        lines.append(f"  {'-'*8:<10} {'-'*8:<10} {'-'*13:<15} {'-'*20}")

        # Table rows
        for entry in ports_data:
            lines.append(
                f"  {str(entry['port']) + '/tcp':<10} "
                f"{entry['state']:<10} "
                f"{entry['service']:<15} "
                f"{entry['version']}"
            )

    lines.append("")
    lines.append("=" * 65)
    lines.append("  Scan completed successfully.")
    lines.append(f"  Report saved to: {os.path.abspath(output_file)}")
    lines.append("=" * 65)

    report_text = "\n".join(lines)

    # Print to console
    print("\n" + report_text)

    # Save to file
    with open(output_file, "w") as f:
        f.write(report_text + "\n")

    print(f"\n[+] Report written to '{output_file}'")


def main():
    """
    Main entry point. Reads target from command-line argument,
    runs the scan, and generates the report.
    """
    # Validate command-line usage
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_automation.py <target_ip_or_hostname>")
        print("Example: python3 nmap_automation.py 192.168.1.100")
        sys.exit(1)

    target = sys.argv[1]

    # Step 1: Run the SYN scan
    scanner = run_syn_scan(target)

    # Step 2: Extract port/service data
    ports_data = extract_port_data(scanner, target)

    # Step 3: Generate and save the report
    generate_report(target, ports_data, output_file="scan_report.txt")


# Entry point guard — only run main() when executed directly
if __name__ == "__main__":
    main()
