# Week 2 — Networking, Security Monitoring & Penetration Testing

Tasks 01–05 covering Nmap scanning, packet analysis, IDS/Snort,
secure network design, Metasploit exploitation, and SIEM/forensics.

## Structure

```
Week 2/
├── Documentation/          ← CyArt-formatted Word reports (Tasks 01–05)
├── Scripts/                ← Python tools written during the tasks
└── Screenshots/            ← All generated diagrams and charts
```

## Tasks Covered

| Task | Topic | Key Tools |
|------|-------|-----------|
| Task 01 | Nmap Scanning & Automation | Nmap, Python (nmap lib) |
| Task 02 | Packet Sniffing & Firewall | Scapy, iptables, OpenVAS |
| Task 03 | Network Security Monitoring | Wireshark, Snort, Scapy |
| Task 04 | Secure Design & Pentest | Metasploit, Wireshark, pyshark |
| Task 05 | SIEM, Forensics & Threat Hunting | ELK Stack, Wazuh, Sigma |

## Scripts

| File | Purpose |
|------|---------|
| `nmap_automation.py` | Automated Nmap scanning with python-nmap, generates scan_report.txt |
| `packet_sniffer.py` | Scapy-based packet capture with protocol distribution chart |
| `test_packets.py` | Scapy IDS test traffic generator (SYN flood, port scan, ICMP, UDP) |
| `traffic_analyzer.py` | pyshark PCAP parser — metadata extraction, size distribution chart |

## Screenshots

17 diagrams embedded across the reports including:
- Nmap port risk charts
- Scapy protocol distribution
- iptables firewall architecture
- Snort IDS alert timeline & architecture
- Secure network topology (DMZ, VLANs, VPN)
- Metasploit console panels
- Wireshark HTTPS capture
- ELK Stack / Kibana dashboard
- Incident forensics timeline
- Threat hunting IOC dashboard

## Environment

| Component | Details |
|-----------|---------|
| Attacker / Scanner | Kali Linux 2024.1 — 192.168.1.50 |
| Target | Metasploitable 2 — 192.168.1.100 |
| Network | VMware Host-Only — 192.168.1.0/24 |
