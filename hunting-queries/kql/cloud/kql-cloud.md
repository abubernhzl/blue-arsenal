# KQL Hunting Queries — Cloud Resource Abuse
> Platform: Microsoft Sentinel | Defender for Cloud Apps | Azure Activity Log
> ATT&CK: T1078.004, T1530, T1537, T1562.008

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

**False Positive Notes:** Legitimate cleanup scripts may trigger this. Verify with change management records.

---

## Diagnostic Settings Disabled
> ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs

```kql
// Detect diagnostic settings deleted or disabled — log tampering indicator
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
> ATT&CK: T1078.004 — Cloud Accounts — High Severity

```kql
// Detect Owner role assigned at subscription scope
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
// Detect CA policy changes — possible weakening of security controls
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
// Detect automation account runbook creation or modification
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
// Detect mass file downloads from SharePoint or OneDrive
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
// Detect OAuth consent grants with sensitive permissions
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

*ATT&CK References: attack.mitre.org | Platform: Microsoft Sentinel / Defender for Cloud Apps*
*Last updated: 2026-03 | Author: @abubernhzl*
