# Azure Attack Paths
> Realistic attacker chains in Azure/Microsoft cloud environments.
> Each path includes technique steps, detection mapping, and mitigations.
> Reference: MITRE ATT&CK Cloud | Microsoft Security Blog | Real-world IR cases

---

## Table of Contents

### Critical
1. [Token Theft via Device Code Phishing](#-token-theft-via-device-code-phishing)
2. [Entra ID Global Admin Takeover](#-entra-id-global-admin-takeover)
3. [OIDC Federation Backdoor](#-oidc-federation-backdoor)
4. [Managed Identity to Subscription Takeover](#-managed-identity-to-subscription-takeover)
5. [Service Principal Credential Theft](#-service-principal-credential-theft)

### High
6. [Azure VM IMDS Credential Theft](#-azure-vm-imds-credential-theft)
7. [Key Vault Secret Exfiltration](#-key-vault-secret-exfiltration)
8. [Automation Account Runbook Abuse](#-automation-account-runbook-abuse)
9. [Logic App HTTP Trigger Persistence](#-logic-app-http-trigger-persistence)
10. [Diagnostic Settings Tampering](#-diagnostic-settings-tampering)
11. [Conditional Access Policy Bypass](#-conditional-access-policy-bypass)
12. [Storage Account SAS Token Abuse](#-storage-account-sas-token-abuse)
13. [Azure AD Connect Abuse](#-azure-ad-connect-abuse)
14. [PIM Role Activation Abuse](#-pim-role-activation-abuse)
15. [Guest Account Privilege Escalation](#-guest-account-privilege-escalation)
16. [OAuth App Consent Phishing](#-oauth-app-consent-phishing)
17. [Federated Identity Credential Backdoor](#-federated-identity-credential-backdoor)

---

## Critical Attack Chains

---

### 🔴 Token Theft via Device Code Phishing
**Requires:** Social engineering — no prior credentials needed.
> ATT&CK: T1528 — Steal Application Access Token

```
Attacker Chain:
  1. Attacker initiates device code flow: az login --use-device-code
  2. Generates a device code and sends to victim via phishing email/Teams
  3. Victim enters code at microsoft.com/devicelogin — authenticates normally
  4. Attacker receives valid OAuth tokens (access + refresh) for victim's session
  5. Uses tokens to access M365, Azure resources as the victim
  6. Refresh token valid for 90 days — persistent access without password
```

**Technique Steps:** `Device Code Flow Abuse` → `Token Theft` → `Resource Access as Victim`

**Why It's Dangerous:** Bypasses MFA completely — victim already completed MFA during device code auth.

**Detection:**
```kql
// Detect device code flow sign-ins — especially from unexpected locations
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationProtocol == "deviceCode"
| project TimeGenerated, UserPrincipalName, IPAddress,
    Location, AppDisplayName, AuthenticationProtocol
| order by TimeGenerated desc
```

**Mitigations:**
- Block device code flow via Conditional Access policy
- Alert on any device code authentication
- User awareness training — never enter device codes from unsolicited requests

---

### 🔴 Entra ID Global Admin Takeover
**Requires:** Any privileged role that can assign roles (e.g. Privileged Role Administrator).
> ATT&CK: T1078.004, T1098

```
Attacker Chain:
  1. Compromise account with Privileged Role Administrator role
  2. Assign Global Administrator role to attacker-controlled account
  3. Use new Global Admin to disable MFA for target accounts
  4. Access all M365 services, Azure subscriptions, and tenant settings
  5. Create backdoor Global Admin with inconspicuous name for persistence
  6. Optionally add federated identity provider for long-term access
```

**Technique Steps:** `Privileged Role Compromise` → `Role Assignment` → `MFA Bypass` → `Backdoor Account Creation`

**Detection:**
```kql
// Detect Global Admin role assignment
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has "Global Administrator"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, Role, TargetResources

// Detect MFA disabled for user
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has "StrongAuthenticationMethod"
| where OperationName has "delete" or OperationName has "update"
```

**Mitigations:**
- Require PAM/PIM for all privileged role activations
- Alert on any Global Admin assignment — no exceptions
- Enable Conditional Access for all admin roles
- Regular review of Global Admin members

---

### 🔴 OIDC Federation Backdoor
**Requires:** `microsoft.directory/applications/credentials/update`
> ATT&CK: T1098.001 — Account Manipulation: Additional Cloud Credentials

```
Attacker Chain:
  1. Attacker adds federated identity credential to existing app registration
  2. Points trust to attacker-controlled OIDC provider
  3. Issues OIDC tokens from their IdP matching the trust conditions
  4. Uses tokens to authenticate as the app's service principal
  5. Persists through password rotation — no secrets needed
  6. Survives even if original compromise is remediated
```

**Technique Steps:** `App Registration Access` → `Federated Credential Addition` → `Token Issuance` → `Persistent SP Access`

**Detection:**
```kql
// Detect federated identity credential added to app
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "federated"
    or OperationName == "Update application – Certificates and secrets management"
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, TargetApp, OperationName
```

**Mitigations:**
- Restrict who can modify app registrations
- Alert on any federated credential additions
- Regularly audit app registration credentials

---

### 🔴 Managed Identity to Subscription Takeover
**Requires:** Code execution on Azure resource with Managed Identity assigned.
> ATT&CK: T1552.005 — Cloud Instance Metadata API

```
Attacker Chain:
  1. Gain code execution on VM, Function App, or Container with Managed Identity
  2. Query IMDS endpoint for access token:
     curl http://169.254.169.254/metadata/identity/oauth2/token
  3. Use token to call Azure Resource Manager API
  4. If Managed Identity has Contributor/Owner role → full subscription access
  5. Create backdoor resources, exfiltrate data, or pivot to other services
  6. Token auto-refreshes — no credential rotation needed
```

**Technique Steps:** `Code Execution on Azure Resource` → `IMDS Token Theft` → `ARM API Abuse` → `Privilege Escalation`

**Detection:**
```kql
// Detect Managed Identity used from unexpected IP
AzureActivity
| where TimeGenerated > ago(24h)
| where Authorization has "ManagedIdentity"
| where CallerIpAddress !startswith "10."      // Not internal
    and CallerIpAddress !startswith "172.16."
    and CallerIpAddress !startswith "192.168."
| project TimeGenerated, Caller, CallerIpAddress,
    OperationNameValue, ResourceGroup

// Detect high-privilege operations by Managed Identity
AzureActivity
| where TimeGenerated > ago(24h)
| where Caller has "ManagedIdentity"
| where OperationNameValue has_any ("roleAssignments", "write", "delete")
| project TimeGenerated, Caller, OperationNameValue, ResourceGroup
```

**Mitigations:**
- Apply least privilege to Managed Identity role assignments
- Avoid assigning Owner/Contributor at subscription scope
- Monitor ARM API calls from Managed Identities
- Use User-assigned Managed Identities for better visibility

---

### 🔴 Service Principal Credential Theft
**Requires:** Access to application code, CI/CD pipeline, or secrets store.
> ATT&CK: T1552 — Unsecured Credentials

```
Attacker Chain:
  1. Find SP credentials in code repo, pipeline vars, or config files
  2. Authenticate as SP: az login --service-principal
  3. Enumerate SP permissions across subscriptions
  4. If SP has high privileges → access resources, create backdoors
  5. Add new credentials to SP for persistence before original is rotated
  6. New credentials survive secret rotation of original
```

**Technique Steps:** `Credential Discovery` → `SP Authentication` → `Permission Enumeration` → `Backdoor Credential Addition`

**Detection:**
```kql
// Detect new credentials added to service principal
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add password",
    "Add key credentials to service principal"
)
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend TargetSP = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, TargetSP, OperationName
```

**Mitigations:**
- Never store SP credentials in code — use Key Vault or Managed Identity
- Rotate SP credentials regularly
- Alert on any SP credential additions
- Use certificate-based auth instead of secrets where possible

---

## High Severity Attack Chains

---

### 🟠 Azure VM IMDS Credential Theft
**Requires:** Code execution or SSRF on Azure VM.
> ATT&CK: T1552.005 — Cloud Instance Metadata API

```
Attacker Chain:
  1. Gain foothold via RCE, SSRF, or compromised SSH/RDP
  2. Query IMDS: curl -H "Metadata:true" 
     http://169.254.169.254/metadata/identity/oauth2/token
  3. Retrieve Managed Identity access token
  4. Use token to access Azure resources the VM identity can reach
  5. Common targets: Storage blobs, Key Vault, other VMs via ARM
```

**Mitigations:**
- Restrict outbound IMDS access via NSG where possible
- Apply least privilege to VM Managed Identity
- Enable Microsoft Defender for Servers
- Monitor for unusual ARM API calls from VM identities

---

### 🟠 Key Vault Secret Exfiltration
**Requires:** Any identity with Key Vault Secrets Officer or access policy.
> ATT&CK: T1552.001 — Credentials in Files

```
Attacker Chain:
  1. Compromise identity with Key Vault access
  2. Enumerate all Key Vaults in subscription
  3. List and retrieve all secrets in bulk
  4. Use extracted secrets to pivot to databases, APIs, and other services
  5. Secrets often contain connection strings, API keys, certificates
```

**Detection:**
```kql
// Detect bulk Key Vault secret access
AzureDiagnostics
| where TimeGenerated > ago(1h)
| where ResourceType == "VAULTS"
| where OperationName == "SecretGet"
| summarize Count = count() by CallerIPAddress, identity_claim_upn_s
| where Count >= 10
| order by Count desc
```

**Mitigations:**
- Enable Key Vault audit logging — always
- Use RBAC instead of access policies
- Alert on bulk secret reads
- Enable soft-delete and purge protection

---

### 🟠 Automation Account Runbook Abuse
**Requires:** `Microsoft.Automation/automationAccounts/runbooks/write` + `jobs/write`
> ATT&CK: T1059 — Command and Scripting Interpreter

```
Attacker Chain:
  1. Attacker creates or modifies a runbook in Automation Account
  2. Runbook code: creates backdoor user, exfiltrates data, or modifies RBAC
  3. Attacker triggers runbook execution via job creation
  4. Runbook runs with Automation Account's Run As identity (often high-privilege)
  5. Can be scheduled for persistence — runs automatically
```

**Detection:**
```kql
// Detect runbook creation or modification
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue has "automation/automationAccounts/runbooks"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup, 
    Resource, OperationNameValue
```

---

### 🟠 Logic App HTTP Trigger Persistence
**Requires:** `Microsoft.Logic/workflows/write`
> ATT&CK: T1546 — Event Triggered Execution

```
Attacker Chain:
  1. Create Logic App with HTTP trigger endpoint
  2. Logic App workflow: performs malicious actions on trigger
  3. Attacker calls HTTP endpoint to execute actions at any time
  4. Logic App runs with its own Managed Identity or connection credentials
  5. Survives remediation — persists as legitimate-looking Azure resource
```

**Mitigations:**
- Monitor Logic App creation — especially with HTTP triggers
- Audit Logic App managed identity permissions
- Alert on new Logic Apps in production subscriptions

---

### 🟠 Diagnostic Settings Tampering
**Requires:** `microsoft.insights/diagnosticSettings/write` or `delete`
> ATT&CK: T1562.008 — Impair Defenses: Disable Cloud Logs

```
Attacker Chain:
  1. Delete or modify diagnostic settings on target resources
  2. Activity logs, resource logs no longer sent to Log Analytics / Sentinel
  3. Attacker's subsequent actions not logged
  4. Can also modify Log Analytics retention to reduce evidence window
  5. Change Activity Log export settings to prevent audit trail
```

**Detection:**
```kql
// Detect diagnostic settings modification — critical alert
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "diagnosticSettings"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup,
    Resource, OperationNameValue
```

**Mitigations:**
- Lock diagnostic settings with Resource Lock (CanNotDelete)
- Alert immediately on any diagnostic settings change
- Send logs to immutable storage or separate security tenant

---

### 🟠 Conditional Access Policy Bypass
**Requires:** `Policy.ReadWrite.ConditionalAccess` permission.
> ATT&CK: T1556 — Modify Authentication Process

```
Attacker Chain:
  1. Modify CA policy to exclude attacker's IP or device from MFA requirement
  2. Or create new named location and exclude it from all CA policies
  3. Sign in from excluded IP/location — bypasses MFA
  4. Access all resources the compromised account can reach without MFA challenge
  5. Changes may go unnoticed if no alerting on CA policy modifications
```

**Detection:**
```kql
// Detect CA policy changes
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "conditional access"
| where OperationName has_any ("update", "delete", "create")
| extend InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
```

---

### 🟠 Storage Account SAS Token Abuse
**Requires:** `Microsoft.Storage/storageAccounts/listkeys/action`
> ATT&CK: T1530 — Data from Cloud Storage

```
Attacker Chain:
  1. List storage account keys via ARM API
  2. Generate long-lived SAS token with full permissions
  3. SAS token provides access independent of Azure RBAC
  4. Share or use SAS token for data exfiltration
  5. SAS token survives key rotation if generated before rotation
  6. Access logs may not capture SAS token generation origin clearly
```

**Detection:**
```kql
// Detect storage key listing — precursor to SAS token generation
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "listkeys"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, ResourceGroup, Resource
```

---

### 🟠 Azure AD Connect Abuse
**Requires:** Access to Azure AD Connect server (on-premises).
> ATT&CK: T1556.007 — Hybrid Identity

```
Attacker Chain:
  1. Compromise on-premises server running Azure AD Connect
  2. Extract MSOL sync account credentials from ADSync database
  3. MSOL account has DirectorySync permissions in Entra ID
  4. Use MSOL account to reset passwords of any synced account including admins
  5. Effectively full tenant compromise from on-premises foothold
```

**Mitigations:**
- Protect Azure AD Connect server like a Domain Controller
- Monitor MSOL account for any sign-in outside expected service behavior
- Enable PHS (Password Hash Sync) monitoring
- Alert on any password reset performed by MSOL sync account

---

### 🟠 PIM Role Activation Abuse
**Requires:** Eligible role assignment in PIM.
> ATT&CK: T1078.004 — Cloud Accounts

```
Attacker Chain:
  1. Compromise account with eligible (not active) privileged role in PIM
  2. Activate role — may or may not require MFA/approval depending on config
  3. Use activated role during activation window (typically 1-8 hours)
  4. Perform privileged actions: RBAC changes, user creation, policy modification
  5. Role deactivates automatically — harder to detect post-facto
```

**Detection:**
```kql
// Detect PIM role activation — especially outside business hours
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has "PIM"
| where OperationName has "activate"
| extend ActivatedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Role = tostring(TargetResources[0].displayName)
| extend Hour = hourofday(TimeGenerated)
| where Hour !between (8 .. 18)  // Outside business hours
| project TimeGenerated, ActivatedBy, Role, Hour
```

---

### 🟠 Guest Account Privilege Escalation
**Requires:** Guest account in tenant + misconfigured permissions.
> ATT&CK: T1078 — Valid Accounts

```
Attacker Chain:
  1. Attacker invited as Guest or compromises existing Guest account
  2. Enumerate tenant resources accessible to guests
  3. Exploit overly permissive guest settings (e.g. guest can read all users)
  4. Find sensitive resources, SharePoint sites, or Teams channels
  5. If guest has resource permissions → access or exfiltrate data
  6. Guest accounts often overlooked in access reviews
```

**Mitigations:**
- Restrict guest access permissions in Entra ID External Collaboration settings
- Regular guest account access reviews
- Monitor guest account activity — especially outside business hours

---

### 🟠 OAuth App Consent Phishing
**Requires:** Social engineering — attacker registers malicious OAuth app.
> ATT&CK: T1528 — Steal Application Access Token

```
Attacker Chain:
  1. Attacker registers OAuth app in their own tenant
  2. Requests permissions: Mail.Read, Files.ReadWrite.All, offline_access
  3. Sends phishing link to victim — looks like legitimate Microsoft consent page
  4. Victim consents → attacker receives OAuth tokens for victim's account
  5. offline_access scope = refresh token → long-term persistent access
  6. Access persists even after password change
```

**Detection:**
```kql
// Detect OAuth consent grants with sensitive permissions
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any (
    "offline_access", "Mail.Read", "Mail.ReadWrite",
    "Files.ReadWrite.All", "Directory.ReadWrite.All"
)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ConsentedBy, Permissions
```

---

### 🟠 Federated Identity Credential Backdoor
**Requires:** Permission to update app registration credentials.
> ATT&CK: T1098.001 — Additional Cloud Credentials

```
Attacker Chain:
  1. Add federated identity credential to high-privilege app registration
  2. Trust points to attacker-controlled GitHub repo or IdP
  3. Attacker triggers workflow/token issuance from their controlled identity
  4. Assumes app's service principal permissions
  5. No secrets to rotate — persists indefinitely until credential removed
  6. May not appear in traditional credential audit as no password/cert added
```

---

## Detection Mapping — Azure

| Attack Technique | Log Source | Key Event / Operation |
|-----------------|------------|----------------------|
| Device code phishing | SigninLogs | `AuthenticationProtocol == deviceCode` |
| Global Admin assignment | AuditLogs | `Add member to role` → Global Administrator |
| OIDC federation backdoor | AuditLogs | Federated credential update on app |
| Managed Identity abuse | AzureActivity | ARM calls from unexpected IPs |
| SP credential added | AuditLogs | `Add password` / `Add key credentials` |
| Key Vault bulk access | AzureDiagnostics | `SecretGet` high frequency |
| Runbook abuse | AzureActivity | `automation/runbooks/write` |
| Diagnostic settings deleted | AzureActivity | `diagnosticSettings/delete` |
| CA policy modified | AuditLogs | `conditional access` update/delete |
| Storage key listed | AzureActivity | `listkeys` action |
| PIM activation off-hours | AuditLogs | PIM activate outside 08:00-18:00 |
| OAuth consent phishing | AuditLogs | `Consent to application` with sensitive scopes |

---

## Key Permissions to Monitor (Azure)

```
Identity & Access:
  microsoft.directory/applications/credentials/update
  microsoft.directory/servicePrincipals/credentials/update
  microsoft.directory/roleAssignments/create
  microsoft.directory/conditionalAccessPolicies/update

Resource Abuse:
  Microsoft.Authorization/roleAssignments/write
  Microsoft.Automation/automationAccounts/runbooks/write
  Microsoft.Logic/workflows/write
  Microsoft.Compute/virtualMachines/runCommand/action

Defense Evasion:
  microsoft.insights/diagnosticSettings/delete
  microsoft.insights/diagnosticSettings/write
  Microsoft.OperationalInsights/workspaces/delete

Exfiltration:
  Microsoft.Storage/storageAccounts/listkeys/action
  Microsoft.KeyVault/vaults/secrets/read
  Microsoft.Backup/backupVaults/delete
```

---

## References & Credits

| Resource | Link |
|----------|------|
| MITRE ATT&CK Cloud | [attack.mitre.org/matrices/enterprise/cloud](https://attack.mitre.org/matrices/enterprise/cloud) |
| Microsoft IR Playbooks | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/) |
| Entra ID Attack Techniques | [SpecterOps - Azure AD](https://posts.specterops.io) |
| Azure Threat Research Matrix | [microsoft/Azure-Threat-Research-Matrix](https://github.com/microsoft/Azure-Threat-Research-Matrix) |
| Detecting.Cloud | [detecting.cloud](https://detecting.cloud) |

---

*Last updated: 2026-03 | Author: @abubernhzl | Built from real-world IR work*
