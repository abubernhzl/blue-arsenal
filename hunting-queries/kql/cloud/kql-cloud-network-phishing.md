# KQL Hunting Queries — Cloud Resource Abuse
> Platform: Microsoft Sentinel | Defender for Cloud Apps | Azure Activity
> ATT&CK: T1078.004, T1530, T1537, T1619

---

## Table of Contents
1. [Azure Suspicious Resource Deletion](#azure-suspicious-resource-deletion)
2. [Diagnostic Settings Disabled](#diagnostic-settings-disabled)
3. [New Owner Role Assignment](#new-owner-role-assignment)
4. [Bulk Key Vault Secret Access](#bulk-key-vault-secret-access)
5. [Conditional Access Policy Modified](#conditional-access-policy-modified)
6. [Suspicious Automation Runbook](#suspicious-automation-runbook)
7. [Mass Download from SharePoint](#mass-download-from-sharepoint)
8. [OAuth App Consent Grant](#oauth-app-consent-grant)

---

## Azure Suspicious Resource Deletion
> ATT&CK: T1485 — Data Destruction

```kql
// Detect bulk resource deletions — possible destruction or cleanup
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue endswith "delete"
| where ActivityStatusValue == "Success"
| summarize 
    DeleteCount = count(),
    Resources = make_set(Resource, 20)
    by Caller, bin(TimeGenerated, 1h)
| where DeleteCount >= 5
| order by DeleteCount desc
```

---

## Diagnostic Settings Disabled
> ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs

```kql
// Detect diagnostic settings deleted or disabled — log tampering
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "diagnosticSettings"
| where OperationNameValue has "delete"
    or OperationNameValue has "write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup, 
    Resource, OperationNameValue, Properties
| order by TimeGenerated desc
```

---

## New Owner Role Assignment
> ATT&CK: T1078.004 — Cloud Accounts

```kql
// Detect Owner role assigned at subscription scope — critical
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue == "Success"
| extend RoleAssignment = parse_json(Properties)
| extend RoleName = tostring(RoleAssignment.roleDefinitionName)
| where RoleName == "Owner"
| project TimeGenerated, Caller, ResourceGroup, 
    RoleName, Properties
| order by TimeGenerated desc
```

---

## Bulk Key Vault Secret Access
> ATT&CK: T1552.001 — Credentials in Files

```kql
// Detect bulk secret access from Key Vault — possible exfiltration
AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| where ResultType == "Success"
| summarize 
    SecretAccessCount = count(),
    Secrets = make_set(id_s, 20)
    by CallerIPAddress, identity_claim_upn_s, bin(TimeGenerated, 1h)
| where SecretAccessCount >= 10
| order by SecretAccessCount desc
```

---

## Conditional Access Policy Modified
> ATT&CK: T1556 — Modify Authentication Process

```kql
// Detect CA policy changes — weakening security controls
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "conditional access"
| where OperationName has_any ("update", "delete", "create")
| extend 
    PolicyName = tostring(TargetResources[0].displayName),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    ModifiedProps = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, InitiatedBy, PolicyName, 
    OperationName, ModifiedProps
| order by TimeGenerated desc
```

---

## Suspicious Automation Runbook
> ATT&CK: T1059 — Command and Scripting Interpreter

```kql
// Detect automation account runbook creation/modification
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "automation"
| where OperationNameValue has_any ("runbook", "job")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup,
    Resource, OperationNameValue
| order by TimeGenerated desc
```

---

## Mass Download from SharePoint
> ATT&CK: T1530 — Data from Cloud Storage

```kql
// Detect mass file downloads from SharePoint/OneDrive
OfficeActivity
| where TimeGenerated > ago(24h)
| where RecordType in ("SharePointFileOperation", "OneDrive")
| where Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize 
    DownloadCount = count(),
    Files = make_set(SourceFileName, 20)
    by UserId, ClientIP, bin(TimeGenerated, 1h)
| where DownloadCount >= 50
| order by DownloadCount desc
```

---

## OAuth App Consent Grant
> ATT&CK: T1550.001 — Use Alternate Authentication Material

```kql
// Detect OAuth consent grants — especially offline_access or mail permissions
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend 
    AppName = tostring(TargetResources[0].displayName),
    ConsentedBy = tostring(InitiatedBy.user.userPrincipalName),
    Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any (
    "offline_access",
    "Mail.Read",
    "Mail.ReadWrite", 
    "Files.ReadWrite.All",
    "Directory.ReadWrite.All"
)
| project TimeGenerated, ConsentedBy, AppName, Permissions
| order by TimeGenerated desc
```

---
---

# KQL Hunting Queries — Network & C2 Detection
> Platform: Microsoft Sentinel | Defender for Endpoint
> ATT&CK: T1071, T1572, T1568, T1048

---

## DNS Beaconing Detection
> ATT&CK: T1071.004 — DNS

```kql
// Detect regular interval DNS queries — C2 beaconing pattern
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "DnsQueryResponse"
| summarize 
    QueryCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by DeviceName, RemoteUrl
| extend DurationHours = datetime_diff('hour', LastSeen, FirstSeen)
| where QueryCount >= 20 and DurationHours >= 1
| extend QueriesPerHour = todouble(QueryCount) / todouble(DurationHours)
| where QueriesPerHour >= 5  // Regular beaconing pattern
| order by QueriesPerHour desc
```

---

## High Entropy Domain Detection
> ATT&CK: T1568 — Dynamic Resolution (DGA)

```kql
// Detect high entropy domain names — possible DGA or DNS tunneling
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "DnsQueryResponse"
| extend DomainPart = tostring(split(RemoteUrl, ".")[0])
| extend DomainLength = strlen(DomainPart)
| where DomainLength >= 15  // Long subdomain = suspicious
| summarize 
    Count = count(),
    Devices = make_set(DeviceName)
    by RemoteUrl, DomainLength
| order by DomainLength desc
```

---

## Suspicious Outbound Connections
> ATT&CK: T1071 — Application Layer Protocol

```kql
// Detect outbound connections to uncommon ports
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (
    4444,   // Metasploit default
    1337,   // Common C2
    8888,   // Common C2
    9001,   // Tor
    9030,   // Tor
    1080,   // SOCKS proxy
    6667,   // IRC
    6697    // IRC SSL
)
| project TimeGenerated, DeviceName, AccountName,
    LocalIPAddress, RemoteIPAddress, RemotePort, 
    RemoteUrl, InitiatingProcessFileName
| order by TimeGenerated desc
```

---

## Data Exfiltration via HTTPS
> ATT&CK: T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

```kql
// Detect large outbound data transfers — possible exfiltration
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 443
| summarize 
    TotalBytesSent = sum(SentBytes),
    ConnectionCount = count(),
    Destinations = make_set(RemoteIPAddress, 10)
    by DeviceName, AccountName, bin(TimeGenerated, 1h)
| where TotalBytesSent >= 100000000  // 100MB threshold
| extend TotalMB = TotalBytesSent / 1000000
| order by TotalBytesSent desc
```

---
---

# KQL Hunting Queries — Phishing & Email Threats
> Platform: Defender for Office 365 | Microsoft Sentinel
> ATT&CK: T1566, T1598, T1114

---

## Phishing Email Delivered
> ATT&CK: T1566.001 — Spearphishing Attachment

```kql
// Detect phishing emails that bypassed filters and were delivered
EmailEvents
| where TimeGenerated > ago(24h)
| where DeliveryAction == "Delivered"
| where ThreatTypes has_any ("Phish", "Malware", "Spam")
| project TimeGenerated, SenderMailFromAddress, SenderFromAddress,
    RecipientEmailAddress, Subject, ThreatTypes, 
    DeliveryLocation, UrlCount, AttachmentCount
| order by TimeGenerated desc
```

---

## Malicious URL Clicked
> ATT&CK: T1566.002 — Spearphishing Link

```kql
// Detect users who clicked malicious URLs in emails
UrlClickEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ClickAllowed"
| where ThreatTypes has_any ("Phish", "Malware")
| project TimeGenerated, AccountUpn, Url, 
    ThreatTypes, IPAddress, IsClickedThrough
| order by TimeGenerated desc
```

---

## Email Forwarding Rule Created
> ATT&CK: T1114.003 — Email Forwarding Rule

```kql
// Detect email forwarding rules — common post-compromise persistence
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in (
    "New-InboxRule",
    "Set-InboxRule",
    "UpdateInboxRules"
)
| where Parameters has_any (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo"
)
| project TimeGenerated, UserId, ClientIP, 
    Operation, Parameters
| order by TimeGenerated desc
```

---

## Suspicious Attachment Types
> ATT&CK: T1566.001 — Spearphishing Attachment

```kql
// Detect emails with high-risk attachment types
EmailAttachmentInfo
| where TimeGenerated > ago(24h)
| where FileType in~ (
    "exe", "dll", "ps1", "vbs", "js", "hta",
    "iso", "img", "lnk", "bat", "cmd",
    "docm", "xlsm", "pptm"  // Macro-enabled Office
)
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| project TimeGenerated, SenderMailFromAddress, 
    RecipientEmailAddress, Subject, FileName, FileType,
    ThreatTypes, DeliveryLocation
| order by TimeGenerated desc
```

---

## BEC — Finance/Executive Impersonation
> ATT&CK: T1566 — Phishing, Business Email Compromise

```kql
// Detect emails impersonating executives or finance keywords
EmailEvents
| where TimeGenerated > ago(24h)
| where DeliveryAction == "Delivered"
| where Subject has_any (
    "wire transfer",
    "urgent payment",
    "invoice",
    "bank account",
    "payment confirmation",
    "fund transfer",
    "confidential"
)
| where SenderMailFromDomain != RecipientEmailAddress  // External sender
| project TimeGenerated, SenderMailFromAddress, 
    RecipientEmailAddress, Subject, DeliveryLocation
| order by TimeGenerated desc
```

---

*ATT&CK References: attack.mitre.org | Platform: Microsoft Defender / Sentinel*
*Last updated: 2026-03 | Author: @abubernhzl*
