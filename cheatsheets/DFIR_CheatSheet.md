# DFIR Analyst Quick Reference & Cheat Sheet
> Digital Forensics & Incident Response — Field Reference

---

## Table of Contents
1. [Triage Checklist](#triage-checklist)
2. [Windows Artifacts](#windows-artifacts)
3. [Linux Artifacts](#linux-artifacts)
4. [Memory Forensics (Volatility)](#memory-forensics-volatility)
5. [Disk Forensics](#disk-forensics)
6. [Network Forensics](#network-forensics)
7. [Log Analysis](#log-analysis)
8. [Malware Analysis Quick Wins](#malware-analysis-quick-wins)
9. [Timeline Analysis](#timeline-analysis)
10. [IOC Hunting](#ioc-hunting)
11. [Evidence Collection](#evidence-collection)
12. [Common Tools Reference](#common-tools-reference)

---

## Triage Checklist

### First 5 Minutes (Live System)
```
[ ] Identify scope — single host, lateral movement, or enterprise-wide?
[ ] Note system time vs UTC (time skew matters for timeline)
[ ] Collect volatile data FIRST (RAM > running processes > network > disk)
[ ] Do NOT reboot / shutdown before capturing memory
[ ] Hash everything before you touch it (MD5 + SHA256)
[ ] Document chain of custody
```

### Volatile Data Order of Collection (RFC 3227)
```
1. CPU registers / cache
2. RAM (full memory dump)
3. Running processes & network connections
4. Login sessions
5. Open files / handles
6. Disk image (non-volatile but time-sensitive)
7. Remote logging / monitoring data
8. Physical configuration
9. Archival media
```

---

## Windows Artifacts

### Key Registry Hives & Locations
| Hive | Path |
|------|------|
| SYSTEM | `C:\Windows\System32\config\SYSTEM` |
| SOFTWARE | `C:\Windows\System32\config\SOFTWARE` |
| SAM | `C:\Windows\System32\config\SAM` |
| SECURITY | `C:\Windows\System32\config\SECURITY` |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` |
| UsrClass.dat | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |

### Persistence Locations (Check These First)
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SYSTEM\CurrentControlSet\Services          # Services / drivers
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
C:\Windows\System32\Tasks\                       # Scheduled tasks
C:\Windows\SysWOW64\Tasks\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

### Windows Event Log IDs — Must Know
| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff |
| 4648 | Logon with explicit credentials (runas) |
| 4672 | Special privileges assigned (admin logon) |
| 4688 | Process creation (with command line if audited) |
| 4698 | Scheduled task created |
| 4720 | User account created |
| 4732 | Member added to local group |
| 4768 / 4769 | Kerberos TGT / service ticket requested |
| 4771 | Kerberos pre-auth failed (bad password) |
| 4776 | NTLM authentication attempt |
| 7034 | Service crashed unexpectedly |
| 7045 | New service installed |

### Logon Types
| Type | Description |
|------|-------------|
| 2 | Interactive (local keyboard) |
| 3 | Network (SMB, mapped drives) |
| 4 | Batch (scheduled tasks) |
| 5 | Service |
| 7 | Unlock |
| 8 | NetworkCleartext (basic auth) |
| 9 | NewCredentials (runas /netonly) |
| 10 | RemoteInteractive (RDP) |
| 11 | CachedInteractive |

### User Activity Artifacts
```
# Recent files
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\

# Jump lists
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

# Shellbags (folder access history — even deleted folders)
HKCU\SOFTWARE\Microsoft\Windows\Shell\BagMRU
HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\

# Prefetch (evidence of execution)
C:\Windows\Prefetch\*.pf

# PowerShell history
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Browser artifacts
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History
C:\Users\<user>\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\places.sqlite
```

### Quick Windows Commands (Live Response)
```powershell
# Running processes with full path
Get-Process | Select-Object Name, Id, Path, Company | Sort-Object Name

# Network connections
netstat -anob
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Select-Object TaskName, TaskPath, State

# Services
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, DisplayName, StartType

# Installed software
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion

# Local users & groups
Get-LocalUser
Get-LocalGroupMember -Group "Administrators"

# Recently modified files (last 24h)
Get-ChildItem C:\ -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}

# Prefetch listing
Get-ChildItem C:\Windows\Prefetch\ | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime | Select-Object -First 20

# Check for unsigned drivers
Get-WinEvent -LogName System | Where-Object {$_.Id -eq 7045}
```

---

## Linux Artifacts

### Key Files to Check
```bash
/etc/passwd                    # User accounts
/etc/shadow                    # Password hashes
/etc/sudoers                   # Sudo permissions
/etc/crontab                   # System cron jobs
/var/spool/cron/crontabs/      # User cron jobs
/etc/rc.local                  # Startup script
/etc/init.d/                   # SysV init scripts
/etc/systemd/system/           # Systemd units (persistence)
~/.bashrc / ~/.bash_profile    # Shell rc files (persistence)
~/.ssh/authorized_keys         # SSH persistence
/tmp/ /var/tmp/ /dev/shm/      # Common malware drop zones
```

### Quick Linux Commands (Live Response)
```bash
# Who is logged in / recent logins
who
w
last -a | head -50
lastlog | grep -v "Never logged in"

# Processes
ps auxf                        # Full process tree
ps aux --sort=-%cpu | head     # Top CPU consumers
ls -la /proc/*/exe 2>/dev/null | grep deleted  # Deleted binaries still running

# Network connections
ss -antp
netstat -antp
lsof -i -n -P

# Cron jobs (all users)
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null && echo "User: $user"; done

# SUID/SGID binaries (privilege escalation check)
find / -perm /4000 -type f 2>/dev/null
find / -perm /2000 -type f 2>/dev/null

# Recently modified files
find /etc /var /tmp /usr /home -mtime -1 -type f 2>/dev/null

# Check /tmp for executables
find /tmp /var/tmp /dev/shm -executable -type f 2>/dev/null

# Bash history
cat ~/.bash_history
cat /root/.bash_history
find /home -name ".bash_history" -exec cat {} \;

# Systemd persistence
systemctl list-units --type=service --state=running
systemctl list-timers

# Kernel modules (rootkit check)
lsmod
cat /proc/modules

# Check for world-writable files
find / -xdev -perm -o+w -type f 2>/dev/null
```

### Linux Log Files
```
/var/log/auth.log        # Authentication (Debian/Ubuntu)
/var/log/secure          # Authentication (RHEL/CentOS)
/var/log/syslog          # General system log
/var/log/messages        # General (RHEL/CentOS)
/var/log/kern.log        # Kernel messages
/var/log/cron            # Cron job execution
/var/log/wtmp            # Login records (binary — use last)
/var/log/btmp            # Failed logins (binary — use lastb)
/var/log/lastlog         # Last login per user (use lastlog)
/var/log/audit/audit.log # Auditd logs
/var/log/apache2/        # Apache access/error logs
/var/log/nginx/          # Nginx logs
```

---

## Memory Forensics (Volatility)

### Setup
```bash
# Volatility 3
python3 vol.py -f <image.mem> <plugin>

# Identify OS profile (Vol 2)
python2 vol.py -f <image.mem> imageinfo
python2 vol.py -f <image.mem> kdbgscan
```

### Essential Plugins — Windows
```bash
# Process analysis
python3 vol.py -f mem.raw windows.pslist         # Process list (PEB)
python3 vol.py -f mem.raw windows.pstree         # Process tree
python3 vol.py -f mem.raw windows.psscan         # Scan for EPROCESS (finds hidden)
python3 vol.py -f mem.raw windows.cmdline        # Command line args
python3 vol.py -f mem.raw windows.dlllist        # DLLs per process
python3 vol.py -f mem.raw windows.handles        # Open handles

# Network
python3 vol.py -f mem.raw windows.netstat        # Active connections
python3 vol.py -f mem.raw windows.netscan        # Scan for connections

# Code injection
python3 vol.py -f mem.raw windows.malfind        # Find injected code (RWX memory)
python3 vol.py -f mem.raw windows.vadinfo        # Virtual address descriptors

# Registry
python3 vol.py -f mem.raw windows.registry.hivelist
python3 vol.py -f mem.raw windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Dump artifacts
python3 vol.py -f mem.raw windows.dumpfiles --pid <PID>
python3 vol.py -f mem.raw windows.memmap --pid <PID> --dump

# Rootkit detection
python3 vol.py -f mem.raw windows.ssdt           # SSDT hooks
python3 vol.py -f mem.raw windows.modules        # Kernel modules
python3 vol.py -f mem.raw windows.modscan        # Scan for modules (finds hidden)
```

### Red Flags in Memory
```
- Process with no parent (orphan process)
- svchost.exe not parented by services.exe
- explorer.exe not parented by userinit.exe
- Multiple instances of single-instance processes (lsass, csrss)
- Process name typos (svch0st, lsas, explorerr)
- Process running from unusual path (%TEMP%, Downloads)
- Executable memory pages (RWX) in non-module regions (malfind hits)
- Network connections from unexpected processes (notepad, calc)
```

---

## Disk Forensics

### Image Acquisition
```bash
# DD
sudo dd if=/dev/sda of=/mnt/external/case001.img bs=4M conv=noerror,sync status=progress

# DC3DD (with hashing)
sudo dc3dd if=/dev/sda of=/mnt/external/case001.img hash=sha256 log=/mnt/external/case001.log

# FTK Imager (Windows) — GUI preferred for write-blocked acquisition

# Verify integrity
md5sum case001.img
sha256sum case001.img
```

### Autopsy / Sleuth Kit Quick Reference
```bash
# Mount image read-only
sudo mount -o ro,loop,offset=$((512*2048)) case001.img /mnt/evidence

# Sleuth Kit timeline
fls -r -m / case001.img > body.txt
mactime -b body.txt -d > timeline.csv

# Find deleted files
fls -r -d case001.img

# Recover deleted file by inode
icat case001.img <inode> > recovered_file

# File system info
fsstat case001.img

# Search for string in image
srch_strings case001.img | grep -i "password"
```

### NTFS Artifacts
```
$MFT          — Master File Table (every file/folder record)
$LogFile      — NTFS transaction journal
$UsnJrnl      — Change journal (file creation/deletion/rename history)
$I30          — Directory index (shows deleted entries)
$Recycle.Bin  — Recycle bin ($I files = metadata, $R files = content)
pagefile.sys  — Virtual memory (may contain process artifacts)
hiberfil.sys  — Hibernation file (essentially a memory image)
```

---

## Network Forensics

### Wireshark / tshark Quick Filters
```bash
# tshark basics
tshark -r capture.pcap -Y "http" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri

# Common display filters (Wireshark)
http.request.method == "POST"            # POST requests
dns.qry.name contains "evil"             # DNS queries
tcp.flags.syn == 1 && tcp.flags.ack == 0 # SYN scan detection
ip.addr == 192.168.1.100                 # Filter by IP
tcp.port == 4444                         # Filter by port (common C2)
frame.time >= "2024-01-01 00:00:00"      # Time filter

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,/output/dir/

# Follow TCP stream (tshark)
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Top talkers
tshark -r capture.pcap -q -z conv,ip | head -20

# DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name
```

### C2 Traffic Indicators
```
- Beaconing: Regular interval connections (every X seconds/minutes)
- Unusual user-agents or missing standard headers
- Long DNS queries or high-entropy subdomains (DNS tunneling)
- Base64 / encoded data in HTTP GET parameters
- HTTPS to non-standard ports
- JA3/JA3S fingerprint mismatches
- Large outbound data transfers (exfiltration)
- Connections to new/recently registered domains
- Geographic anomalies in connection destinations
```

### zeek / Bro Quick Reference
```bash
# Read pcap with Zeek
zeek -r capture.pcap

# Key log files generated:
conn.log      # All connections (src, dst, port, bytes, duration)
dns.log       # DNS queries and responses
http.log      # HTTP requests
ssl.log       # SSL/TLS connections (JA3 fingerprints)
files.log     # File transfers
weird.log     # Protocol anomalies
notice.log    # Alerts

# Parse conn.log
zeek-cut id.orig_h id.resp_h id.resp_p proto duration orig_bytes resp_bytes < conn.log | sort -k5 -rn | head
```

---

## Log Analysis

### Windows Event Log — PowerShell Queries
```powershell
# Failed logins last 24h
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1)} |
    Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='Source';e={$_.Properties[19].Value}}

# Process creation with command line
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
    Select-Object TimeCreated, @{n='Process';e={$_.Properties[5].Value}}, @{n='CommandLine';e={$_.Properties[8].Value}}

# New services installed
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
    Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ImagePath';e={$_.Properties[1].Value}}

# RDP logins
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
    Where-Object {$_.Properties[8].Value -eq 10} |
    Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='Source';e={$_.Properties[18].Value}}

# Export event logs for offline analysis
wevtutil epl Security C:\output\Security.evtx
```

### Linux Log Grep Patterns
```bash
# Failed SSH logins
grep "Failed password" /var/log/auth.log | awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn

# Successful SSH logins
grep "Accepted" /var/log/auth.log

# sudo usage
grep "sudo:" /var/log/auth.log | grep -v "pam_unix"

# New user creation
grep "useradd\|adduser" /var/log/auth.log /var/log/secure 2>/dev/null

# Cron job execution
grep "CRON" /var/log/syslog | tail -50

# Web server errors (Apache)
grep " 500 \| 403 \| 404 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Suspicious commands in auth log
grep -E "wget|curl|chmod|base64|/tmp|python|perl|bash -i" /var/log/auth.log
```

---

## Malware Analysis Quick Wins

### Static Analysis (No Execution)
```bash
# File identification
file malware.exe
exiftool malware.exe

# Hashing & VirusTotal lookup
sha256sum malware.exe
md5sum malware.exe
# Submit hash to: virustotal.com

# Strings extraction
strings -a malware.exe | grep -E "http|ftp|cmd|powershell|reg|schtask"
strings -a -el malware.exe  # Unicode strings (Windows PE)
floss malware.exe            # FLARE FLOSS — finds obfuscated strings too

# PE header analysis
pestudio malware.exe         # GUI (Windows)
pefile-python script or:
objdump -f malware.exe
readpe malware.exe

# Entropy check (high entropy = packed/encrypted)
python3 -c "import math,sys; data=open(sys.argv[1],'rb').read(); freq={b:data.count(b) for b in set(data)}; entropy=-sum((c/len(data))*math.log2(c/len(data)) for c in freq.values()); print(f'Entropy: {entropy:.2f}/8.0')" malware.exe

# YARA scan
yara -r rules/ malware.exe

# Detect packer/protector
PEiD, Detect-It-Easy (DIE), ExeinfoPE
```

### Dynamic Analysis (Sandbox / Isolated VM)
```
Automated sandboxes (submit sample):
- Any.run (interactive): any.run
- Hybrid Analysis: hybrid-analysis.com
- Joe Sandbox: joesandbox.com
- Triage: tria.ge

Manual dynamic analysis tools:
- Process Monitor (Procmon) — file/registry/network activity
- Process Hacker / Process Explorer — process inspection
- Wireshark — network traffic
- Regshot — registry snapshots before/after
- FakeNet-NG — fake network services to capture C2 comms
- x64dbg / OllyDbg — debugger
- IDA Pro / Ghidra — disassembler/decompiler
```

### Common Malware Behaviors to Look For
```
Execution:
  - Spawns cmd.exe / powershell.exe as child
  - Drops file in %TEMP% or %APPDATA% and executes
  - Process hollowing (legitimate process with injected code)
  - Runs from unusual paths (C:\Users\Public, C:\ProgramData)

Persistence:
  - Registry Run key modification
  - Scheduled task creation
  - Service installation
  - DLL side-loading

C2 Communication:
  - DNS lookups for high-entropy domains
  - HTTP POST with encoded data
  - Connection on non-standard ports (4444, 1337, 8888)
  - Use of legitimate platforms (Pastebin, GitHub, Discord, Telegram)

Defense Evasion:
  - Timestomping ($STANDARD_INFORMATION vs $FILE_NAME mismatch)
  - Log clearing (Event ID 1102 / 104)
  - Process name spoofing
  - LOLBAS (Living off the land binaries): certutil, bitsadmin, mshta, regsvr32, wscript
```

---

## Timeline Analysis

### Super Timeline with Plaso (log2timeline)
```bash
# Create timeline from disk image
log2timeline.py --storage-file case001.plaso /dev/sdb

# Filter and export
psort.py -o l2tcsv -w timeline.csv case001.plaso

# Filter by time range
psort.py -o l2tcsv -w filtered.csv case001.plaso "date > '2024-01-01 00:00:00' AND date < '2024-01-02 00:00:00'"
```

### Quick MACB Timestamps
```
M — Modified  (file content last changed)
A — Accessed  (file last read)
C — Changed   ($MFT metadata record changed — permissions, rename, etc.)
B — Born      (file creation time)

Timestomping tells: $STANDARD_INFORMATION (easily modified) vs $FILE_NAME (harder to change)
If SI times are earlier than FN times → possible timestomping
```

---

## IOC Hunting

### Quick IOC Hunt Commands
```powershell
# Windows — search for hash in running processes
$targetHash = "d41d8cd98f00b204e9800998ecf8427e"
Get-Process | ForEach-Object {
    $path = $_.Path
    if ($path -and (Test-Path $path)) {
        $hash = (Get-FileHash $path -Algorithm MD5).Hash
        if ($hash -eq $targetHash) { Write-Host "MATCH: $($_.Name) PID: $($_.Id) Path: $path" }
    }
}

# Windows — search for IP in network connections
$targetIP = "185.220.101.1"
Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq $targetIP}

# Linux — search for IP in connections
ss -antp | grep "185.220.101.1"
lsof -i @185.220.101.1

# Linux — find files matching hash
find / -type f -exec md5sum {} \; 2>/dev/null | grep "d41d8cd98f00b204e9800998ecf8427e"
```

### YARA Rule Skeleton
```yara
rule Suspicious_PowerShell_Download {
    meta:
        author      = "Analyst Name"
        description = "Detects PowerShell download cradle patterns"
        date        = "2024-01-01"
        severity    = "high"

    strings:
        $ps1 = "powershell" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "WebClient" nocase
        $enc = "-enc" nocase
        $bypass = "bypass" nocase

    condition:
        $ps1 and (2 of ($dl*, $enc, $bypass))
}
```

---

## Evidence Collection

### Velociraptor / KAPE Quick Targets
```
KAPE targets for rapid triage:
!EvidenceOfExecution     — Prefetch, Amcache, Shimcache
!EventLogs               — All Windows event logs
!Persistence             — Registry Run keys, scheduled tasks
!BrowserHistory          — Chrome, Firefox, Edge artifacts
!FileSystemActivity      — $MFT, $UsnJrnl, $LogFile
!NetworkActivity         — SRUM, netsh firewall logs
!PowerShellArtifacts     — PS history, transcript logs
!UserActivity            — LNK files, shellbags, jump lists
```

### Memory Acquisition Tools
```
Windows:
  - WinPmem (free): winpmem_mini_x64.exe -o memory.raw
  - Magnet RAM Capture (free GUI)
  - DumpIt (free)
  - F-Response + RAM acquisition

Linux:
  - LiME (Loadable Kernel Module): insmod lime.ko "path=/mnt/mem.lime format=lime"
  - avml: sudo avml /mnt/memory.raw
  - fmem (older kernels)
```

---

## Common Tools Reference

| Category | Tool | Use |
|----------|------|-----|
| Memory | Volatility 3 | Memory image analysis |
| Memory | Rekall | Memory analysis (Google) |
| Disk | Autopsy | GUI disk forensics |
| Disk | Sleuth Kit | CLI disk forensics |
| Disk | FTK Imager | Acquisition + triage |
| Timeline | Plaso / log2timeline | Super timeline creation |
| Network | Wireshark / tshark | PCAP analysis |
| Network | Zeek (Bro) | Network log generation |
| Network | NetworkMiner | PCAP carving |
| Log Analysis | Chainsaw | Windows event log hunting |
| Log Analysis | Hayabusa | Windows event log analysis |
| Log Analysis | Sigma | Detection rule format |
| Malware | FLOSS | String extraction |
| Malware | pestudio | PE static analysis |
| Malware | Any.run | Interactive sandbox |
| Malware | YARA | Pattern matching |
| OSINT | MISP | Threat intel sharing |
| OSINT | OpenCTI | Threat intel platform |
| Triage | KAPE | Artifact collection |
| Triage | Velociraptor | Enterprise DFIR |
| Triage | Eric Zimmerman Tools | Windows artifact parsers |

### Eric Zimmerman Tools (Windows Artifact Parsing)
```
MFTECmd      — Parse $MFT
PECmd        — Parse Prefetch files
LECmd        — Parse LNK files
JLECmd       — Parse Jump Lists
SBECmd       — Parse Shellbags
AppCompatCacheParser — Parse Shimcache
AmcacheParser — Parse Amcache
RBCmd        — Parse Recycle Bin
MFTECmd      — Parse $UsnJrnl
EvtxECmd     — Parse EVTX logs with maps
Timeline Explorer — Visualize timelines (GUI)
```

---

## Quick Reference Card

### Artifact → Execution Evidence
```
Prefetch          C:\Windows\Prefetch\*.pf
Shimcache         HKLM\SYSTEM\...\AppCompatCache
Amcache           C:\Windows\AppCompat\Programs\Amcache.hve
BAM/DAM           HKLM\SYSTEM\...\Services\bam\State\UserSettings
UserAssist        HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist
SRUM              C:\Windows\System32\sru\SRUDB.dat
```

### Artifact → Account Usage
```
Security.evtx     4624, 4625, 4648, 4672
NTUSER.DAT        RecentDocs, TypedPaths, UserAssist
SAM               C:\Windows\System32\config\SAM (password hashes)
WMI               C:\Windows\System32\wbem\Repository
```

### Artifact → File/Folder Access
```
Shellbags         NTUSER.DAT + UsrClass.dat
LNK files         C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\
Jump Lists        AutomaticDestinations + CustomDestinations
$MFT              File system record (all files ever created)
$UsnJrnl          Change journal (create/delete/rename)
```

---

*Last updated: 2026-03 | MITRE ATT&CK: attack.mitre.org | DFIR.training for lab resources*
