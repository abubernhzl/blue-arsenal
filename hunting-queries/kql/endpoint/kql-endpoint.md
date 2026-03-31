# KQL Hunting Queries — Endpoint Persistence & Execution
> Platform: Microsoft Defender XDR | Defender for Endpoint | Microsoft Sentinel
> ATT&CK: T1053, T1059, T1547, T1543, T1136, T1055

---

## Table of Contents
1. [Suspicious PowerShell Execution](#suspicious-powershell-execution)
2. [Encoded PowerShell Commands](#encoded-powershell-commands)
3. [LOLBAS Abuse](#lolbas-abuse)
4. [Scheduled Task Creation](#scheduled-task-creation)
5. [New Local Admin Created](#new-local-admin-created)
6. [Service Installation](#service-installation)
7. [Registry Run Key Persistence](#registry-run-key-persistence)
8. [Process Injection Indicators](#process-injection-indicators)
9. [Suspicious Child Processes](#suspicious-child-processes)
10. [Credential Dumping Indicators](#credential-dumping-indicators)

---

## Suspicious PowerShell Execution
> ATT&CK: T1059.001 — PowerShell

```kql
// Detect suspicious PowerShell execution patterns
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
    "DownloadString",
    "DownloadFile",
    "WebClient",
    "IEX",
    "Invoke-Expression",
    "FromBase64String",
    "-enc",
    "-EncodedCommand",
    "bypass",
    "Hidden",
    "NonInteractive",
    "Start-Process",
    "Net.WebClient",
    "System.Reflection"
)
| project TimeGenerated, DeviceName, AccountName, 
    ProcessCommandLine, InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Encoded PowerShell Commands
> ATT&CK: T1059.001, T1027 — Obfuscated Files or Information

```kql
// Detect base64 encoded PowerShell — common evasion technique
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|-EncodedCommand|-ec)\s+[A-Za-z0-9+/=]{20,}"
| extend DecodedHint = base64_decode_tostring(
    extract(@"(?i)(?:-enc|-EncodedCommand|-ec)\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
)
| project TimeGenerated, DeviceName, AccountName, 
    ProcessCommandLine, DecodedHint
| order by TimeGenerated desc
```

---

## LOLBAS Abuse
> ATT&CK: T1218 — System Binary Proxy Execution

```kql
// Detect Living Off the Land Binary abuse
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName in~ (
    "certutil.exe",
    "bitsadmin.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "msiexec.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "ieexec.exe",
    "pcalua.exe"
)
| where ProcessCommandLine has_any (
    "http",
    "ftp",
    "\\\\",  // UNC path
    "decode",
    "urlcache",
    "transfer",
    "script"
)
| project TimeGenerated, DeviceName, AccountName,
    FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Scheduled Task Creation
> ATT&CK: T1053.005 — Scheduled Task/Job

```kql
// Detect scheduled task creation — common persistence mechanism
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create", "-create")
| project TimeGenerated, DeviceName, AccountName,
    ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
```

```kql
// Sentinel — Windows Security Event 4698 (Scheduled task created)
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName),
    TaskContent = tostring(EventData.TaskContent)
| project TimeGenerated, Computer, Account, TaskName, TaskContent
| order by TimeGenerated desc
```

---

## New Local Admin Created
> ATT&CK: T1136.001 — Create Account: Local Account

```kql
// Detect new local user added to Administrators group
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "UserAccountAddedToLocalGroup"
| extend GroupName = tostring(AdditionalFields.GroupName),
    AddedUser = tostring(AdditionalFields.MemberName)
| where GroupName =~ "Administrators"
| project TimeGenerated, DeviceName, AddedUser, GroupName, 
    InitiatingProcessAccountName, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Service Installation
> ATT&CK: T1543.003 — Create or Modify System Process: Windows Service

```kql
// Detect new service installation — Event ID 7045
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 7045
| extend ServiceName = tostring(EventData.ServiceName),
    ServiceFileName = tostring(EventData.ImagePath),
    ServiceType = tostring(EventData.ServiceType),
    StartType = tostring(EventData.StartType)
| where ServiceFileName has_any (
    "\\Temp\\",
    "\\AppData\\",
    "\\Users\\Public\\",
    "\\Downloads\\",
    "powershell",
    "cmd.exe",
    "wscript",
    "mshta"
)
| project TimeGenerated, Computer, ServiceName, 
    ServiceFileName, ServiceType, StartType
| order by TimeGenerated desc
```

---

## Registry Run Key Persistence
> ATT&CK: T1547.001 — Boot or Logon Autostart: Registry Run Keys

```kql
// Detect modifications to common persistence registry keys
DeviceRegistryEvents
| where TimeGenerated > ago(24h)
| where RegistryKey has_any (
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\SYSTEM\\CurrentControlSet\\Services",
    "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, DeviceName, AccountName, ActionType,
    RegistryKey, RegistryValueName, RegistryValueData,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Process Injection Indicators
> ATT&CK: T1055 — Process Injection

```kql
// Detect potential process injection indicators
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType in (
    "CreateRemoteThreadApiCall",
    "WriteProcessMemoryApiCall", 
    "SetThreadContextApiCall",
    "QueueUserApcRemoteApiCall"
)
| project TimeGenerated, DeviceName, AccountName, ActionType,
    FileName, ProcessCommandLine, 
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields
| order by TimeGenerated desc
```

---

## Suspicious Child Processes
> ATT&CK: T1059 — Command and Scripting Interpreter

```kql
// Detect suspicious processes spawned from Office apps or browsers
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "onenote.exe",
    "msedge.exe", "chrome.exe", "firefox.exe",
    "acrord32.exe", "foxit.exe"
)
| where FileName in~ (
    "cmd.exe", "powershell.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "net.exe", "whoami.exe", "systeminfo.exe"
)
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

## Credential Dumping Indicators
> ATT&CK: T1003 — OS Credential Dumping

```kql
// Detect LSASS access — common credential dumping indicator
DeviceEvents
| where TimeGenerated > ago(24h)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ (
    "MsMpEng.exe",   // Defender
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsaiso.exe",
    "svchost.exe"
)
| project TimeGenerated, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields
| order by TimeGenerated desc
```

```kql
// Detect common credential dumping tools by name or commandline
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName has_any ("mimikatz", "procdump", "dumpert")
    or ProcessCommandLine has_any (
        "sekurlsa", "lsadump", "kerberos::list",
        "privilege::debug", "vault::cred",
        "comsvcs.dll,MiniDump",
        "lsass.exe",
        "ntdsutil"
    )
| project TimeGenerated, DeviceName, AccountName,
    FileName, ProcessCommandLine
| order by TimeGenerated desc
```

---

*ATT&CK References: attack.mitre.org | Platform: Microsoft Defender XDR / Sentinel*
*Last updated: 2026-03 | Author: @abubernhzl*
