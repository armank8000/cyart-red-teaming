#!/usr/bin/env python3
"""
osint_recon.py
--------------
Automated OSINT and passive reconnaissance script.
Performs subdomain enumeration, DNS lookups, WHOIS queries,
and Shodan API queries to gather intelligence on a target domain.

Usage:
    python3 osint_recon.py --target example.com
    python3 osint_recon.py --target example.com --shodan-key YOUR_API_KEY
    python3 osint_recon.py --target example.com --output results.json

ATT&CK Techniques:
    T1595.002 - Active Scanning: Vulnerability Scanning
    T1590     - Gather Victim Network Information
    T1593     - Search Open Websites/Domains
"""

import argparse
import json
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional

# Optional imports — install with: pip install requests shodan python-whois dnspython
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False
    print("[!] requests not installed: pip install requests")

try:
    import shodan
    SHODAN_OK = True
except ImportError:
    SHODAN_OK = False

try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False


# ─── Configuration ─────────────────────────────────────────────────────────────

COMMON_SUBDOMAINS: list[str] = [
    "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "webmail",
    "admin", "vpn", "dev", "staging", "api", "cdn", "blog", "shop",
    "portal", "test", "secure", "login", "remote", "help", "support",
    "docs", "status", "dashboard", "mobile", "app", "static",
]

DNS_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


# ─── Data Classes ──────────────────────────────────────────────────────────────

class SubdomainResult:
    """Holds result for a single subdomain enumeration."""

    def __init__(self, subdomain: str, ip: str, ttl: int = 0) -> None:
        self.subdomain = subdomain
        self.ip        = ip
        self.ttl       = ttl
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {"subdomain": self.subdomain, "ip": self.ip, "ttl": self.ttl}


# ─── DNS Enumeration ───────────────────────────────────────────────────────────

def enumerate_subdomains(
    domain: str,
    wordlist: Optional[list[str]] = None,
    delay: float = 0.1
) -> list[SubdomainResult]:
    """
    Perform subdomain brute-force enumeration via DNS resolution.
    Uses a wordlist of common subdomain prefixes and attempts to resolve each.

    Args:
        domain:   Base domain to enumerate (e.g., 'example.com')
        wordlist: Custom list of subdomain prefixes (defaults to COMMON_SUBDOMAINS)
        delay:    Delay between DNS requests to avoid rate limiting

    Returns:
        List of SubdomainResult objects for resolved subdomains
    """
    if wordlist is None:
        wordlist = COMMON_SUBDOMAINS

    results: list[SubdomainResult] = []
    print(f"\n[*] Starting subdomain enumeration for: {domain}")
    print(f"[*] Testing {len(wordlist)} subdomain prefixes...\n")

    for prefix in wordlist:
        fqdn = f"{prefix}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            result = SubdomainResult(fqdn, ip)
            results.append(result)
            print(f"[+] FOUND: {fqdn:<40} -> {ip}")
            time.sleep(delay)
        except socket.gaierror:
            pass  # Subdomain does not resolve — expected for most

    print(f"\n[*] Enumeration complete — {len(results)} subdomains found")
    return results


def query_dns_records(domain: str) -> dict[str, list[str]]:
    """
    Query multiple DNS record types for a domain.
    Useful for mapping mail servers (MX), name servers (NS), and SPF/DKIM (TXT).

    Args:
        domain: Target domain to query

    Returns:
        Dict mapping record type → list of record values
    """
    records: dict[str, list[str]] = {}

    if not DNS_OK:
        print("[!] dnspython not installed — using socket fallback for A records only")
        try:
            ip = socket.gethostbyname(domain)
            records["A"] = [ip]
        except socket.gaierror:
            records["A"] = []
        return records

    print(f"\n[*] Querying DNS records for {domain}:")
    resolver = dns.resolver.Resolver()

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
            print(f"  {rtype:<8} {records[rtype]}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.Timeout, dns.exception.DNSException):
            records[rtype] = []

    return records


# ─── WHOIS Lookup ──────────────────────────────────────────────────────────────

def whois_lookup(domain: str) -> dict:
    """
    Perform WHOIS lookup on a domain to gather registration information.
    Useful for identifying registrar, registration date, and contact details.

    Args:
        domain: Target domain to query WHOIS for

    Returns:
        Dict of WHOIS data fields
    """
    if not WHOIS_OK:
        print("[!] python-whois not installed: pip install python-whois")
        return {}

    print(f"\n[*] WHOIS lookup for {domain}:")
    try:
        w = whois.whois(domain)
        data = {
            "registrar":   str(w.registrar or ""),
            "creation":    str(w.creation_date or ""),
            "expiration":  str(w.expiration_date or ""),
            "name_servers":str(w.name_servers or ""),
            "status":      str(w.status or ""),
            "emails":      str(w.emails or ""),
            "org":         str(w.org or ""),
        }
        for k, v in data.items():
            if v and v != "None":
                print(f"  {k:<20} {v}")
        return data
    except Exception as e:
        print(f"[!] WHOIS failed: {e}")
        return {}


# ─── Shodan Query ──────────────────────────────────────────────────────────────

def shodan_search(
    query: str,
    api_key: Optional[str] = None,
    limit: int = 10
) -> list[dict]:
    """
    Query Shodan for hosts matching a search filter.
    Useful for discovering exposed services, IoT devices, and misconfigurations.

    Args:
        query:   Shodan search query (e.g., 'apache country:US port:80')
        api_key: Shodan API key (from shodan.io)
        limit:   Maximum results to return

    Returns:
        List of dicts containing host information
    """
    if not SHODAN_OK:
        print("[!] shodan not installed: pip install shodan")
        return []
    if not api_key:
        print("[!] Shodan API key required for live queries (--shodan-key)")
        return []

    print(f"\n[*] Shodan query: {query}")
    try:
        api     = shodan.Shodan(api_key)
        results = api.search(query, limit=limit)
        hosts: list[dict] = []
        for match in results["matches"]:
            host = {
                "ip":       match.get("ip_str", ""),
                "port":     match.get("port", 0),
                "org":      match.get("org", ""),
                "hostnames":match.get("hostnames", []),
                "banner":   match.get("data", "")[:200],
                "country":  match.get("location", {}).get("country_name", ""),
                "vulns":    list(match.get("vulns", {}).keys()),
            }
            hosts.append(host)
            print(f"[+] {host['ip']}:{host['port']} — {host['org']} ({host['country']})")
            if host["vulns"]:
                print(f"    CVEs: {', '.join(host['vulns'][:3])}")
        return hosts
    except shodan.APIError as e:
        print(f"[!] Shodan API error: {e}")
        return []


# ─── Report Output ─────────────────────────────────────────────────────────────

def save_report(
    target: str,
    subdomains: list[SubdomainResult],
    dns_records: dict,
    whois_data: dict,
    shodan_hosts: list[dict],
    output_path: str
) -> None:
    """Save all recon results to a JSON report file."""
    report = {
        "target":      target,
        "timestamp":   datetime.now().isoformat(),
        "subdomains":  [s.to_dict() for s in subdomains],
        "dns_records": dns_records,
        "whois":       whois_data,
        "shodan":      shodan_hosts,
        "summary": {
            "subdomains_found": len(subdomains),
            "shodan_hosts":     len(shodan_hosts),
        }
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n[+] Report saved → {output_path}")


def print_summary(
    target: str,
    subdomains: list[SubdomainResult],
    shodan_hosts: list[dict]
) -> None:
    """Print a formatted summary to stdout."""
    print("\n" + "="*60)
    print(f"  OSINT Recon Summary — {target}")
    print("="*60)
    print(f"  Subdomains discovered : {len(subdomains)}")
    print(f"  Shodan hosts found    : {len(shodan_hosts)}")
    if subdomains:
        print("\n  Top Subdomains:")
        for s in subdomains[:10]:
            print(f"    {s.subdomain:<40} {s.ip}")
    print("="*60)


# ─── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point — parse args and orchestrate OSINT collection."""
    parser = argparse.ArgumentParser(
        description="OSINT & Passive Recon Tool — subdomain enum, DNS, WHOIS, Shodan"
    )
    parser.add_argument("--target",      "-t", required=True,
                        help="Target domain (e.g., example.com)")
    parser.add_argument("--shodan-key",  "-s", default=None,
                        help="Shodan API key for live host queries")
    parser.add_argument("--shodan-query","-q", default=None,
                        help="Custom Shodan query (default: apache country:US)")
    parser.add_argument("--output",      "-o", default="osint_report.json",
                        help="Output JSON report path")
    parser.add_argument("--delay",       "-d", type=float, default=0.1,
                        help="Delay between DNS queries in seconds (default: 0.1)")
    args = parser.parse_args()

    print(f"[*] OSINT Recon started for: {args.target}")
    print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 1. Subdomain enumeration
    subdomains = enumerate_subdomains(args.target, delay=args.delay)

    # 2. DNS record queries
    dns_records = query_dns_records(args.target)

    # 3. WHOIS lookup
    whois_data = whois_lookup(args.target)

    # 4. Shodan query
    shodan_query = args.shodan_query or f"hostname:{args.target}"
    shodan_hosts = shodan_search(shodan_query, api_key=args.shodan_key)

    # 5. Save and print report
    print_summary(args.target, subdomains, shodan_hosts)
    save_report(
        args.target, subdomains, dns_records,
        whois_data, shodan_hosts, args.output
    )


if __name__ == "__main__":
    main()
