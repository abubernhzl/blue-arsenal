# Cloud Forensics Cheat Sheet
> DFIR Field Reference — Azure (Primary) | AWS | GCP

---

## Table of Contents
1. [Azure Forensics](#azure-forensics)
2. [AWS Forensics](#aws-forensics)
3. [GCP Forensics](#gcp-forensics)
4. [Cross-Cloud IOC Indicators](#cross-cloud-ioc-indicators)
5. [Cloud IR Toolkit](#cloud-ir-toolkit)

---

## Azure Forensics

### 🗂️ Log Sources & Locations

| Log Source | Location / Service | What It Captures |
|------------|-------------------|-----------------|
| **Azure Activity Log** | Monitor > Activity Log | Control plane ops — who did what to which resource |
| **Azure AD Sign-In Logs** | Entra ID > Monitoring > Sign-in logs | All user/service principal logins |
| **Azure AD Audit Logs** | Entra ID > Monitoring > Audit logs | User/group/role/app changes |
| **Microsoft Defender for Cloud** | Defender for Cloud > Alerts | Threat detections across resources |
| **Microsoft Sentinel** | Sentinel > Logs (Log Analytics) | SIEM — aggregated logs + detections |
| **Unified Audit Log** | Purview / compliance.microsoft.com | M365 + Azure activity combined |
| **NSG Flow Logs** | Network Watcher > NSG flow logs | Network traffic allowed/denied |
| **Storage Account Logs** | Diagnostic settings on storage | Blob/file/queue/table access |
| **Key Vault Audit Logs** | Key Vault > Diagnostic settings | Secret/key/cert access & changes |
| **VM Guest Logs** | Azure Monitor Agent / Log Analytics | Windows Event Logs, Syslog from VMs |
| **App Service Logs** | App Service > Diagnostic logs | Web app HTTP access + errors |
| **Resource Diagnostic Logs** | Per-resource > Diagnostic settings | Resource-specific operational logs |

---

### 🔑 Key Artifacts to Collect

```
Azure AD / Entra ID:
  - Sign-in logs (interactive + non-interactive + service principal)
  - Audit logs (role assignments, app registrations, MFA changes)
  - Conditional Access policy changes
  - Privileged Identity Management (PIM) activation logs
  - Risky users / risky sign-ins (Identity Protection)

Subscription / Resource Level:
  - Activity Log (last 90 days, exportable)
  - Resource locks status
  - RBAC role assignments (current + history)
  - Azure Policy compliance state
  - Defender for Cloud alerts + recommendations

Compute (VMs):
  - VM boot diagnostics
  - Serial console logs
  - Azure Monitor Agent logs → Log Analytics workspace
  - Disk snapshot (for offline analysis)
  - VM extensions installed (potential persistence)

Networking:
  - NSG flow logs
  - Azure Firewall logs
  - DDoS protection logs
  - VPN Gateway / ExpressRoute connection logs
  - Private endpoint activity

Identity:
  - Service principal credentials & permissions
  - Managed identity assignments
  - App registration secrets / certificates
  - OAuth consent grants
  - Guest account activity
```

---

### 🚨 Detection Indicators (Azure)

```
Authentication Anomalies:
  - Sign-ins from impossible travel (two countries, short timeframe)
  - Sign-ins from anonymizing proxies / Tor exit nodes
  - Successful MFA bypass (NPS extension, legacy auth)
  - Legacy authentication protocols used (IMAP, POP3, SMTP AUTH)
  - Password spray pattern (many users, few attempts each)
  - Bulk failed logins → single success (credential stuffing)
  - Service principal login from unexpected geography

Privilege Escalation:
  - New Owner/Contributor/Global Admin role assigned
  - PIM role activated outside business hours
  - Custom role creation with wildcard permissions (*)
  - Role assignment at subscription or management group scope

Persistence:
  - New app registration created
  - New service principal credentials added
  - Federated identity credential added (OIDC abuse)
  - New OAuth consent grant (especially offline_access)
  - VM extension installed (CustomScript, RunCommand abuse)
  - Automation Account runbook created/modified
  - Logic App created with HTTP trigger

Defense Evasion:
  - Diagnostic settings deleted or disabled
  - Activity log retention reduced
  - Defender for Cloud alerts suppressed
  - Policy assignment deleted
  - Key Vault soft-delete / purge protection disabled

Data Exfiltration:
  - Large storage blob download (unusual volume)
  - Storage account SAS token generated with full permissions
  - Backup vault accessed / backup deleted
  - Key Vault secrets bulk read
  - Email forwarding rule created (M365)
  - SharePoint/OneDrive mass download
```

---

### ⚡ IR Commands — Azure CLI & PowerShell

```bash
# ── AZURE CLI ──────────────────────────────────────────────

# Login & set subscription
az login
az account set --subscription "<subscription-id>"
az account show

# Activity log — last 24h for a resource group
az monitor activity-log list \
  --resource-group <rg-name> \
  --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ) \
  --output table

# Activity log — filter by caller (user/SP)
az monitor activity-log list \
  --caller "user@domain.com" \
  --start-time 2024-01-01T00:00:00Z \
  --output json

# List all role assignments in subscription
az role assignment list --all --output table

# List role assignments for specific user
az role assignment list --assignee "user@domain.com" --all

# List service principals
az ad sp list --all --output table
az ad sp show --id "<app-id>"

# Check SP credentials (secrets/certs)
az ad app credential list --id "<app-id>"

# List VM extensions (persistence check)
az vm extension list --resource-group <rg> --vm-name <vm> --output table

# Run command on VM (live triage)
az vm run-command invoke \
  --resource-group <rg> \
  --name <vm-name> \
  --command-id RunPowerShellScript \
  --scripts "Get-Process | Select Name,Id,Path | Sort Name"

# Snapshot a VM disk (evidence preservation)
az snapshot create \
  --resource-group <rg> \
  --name evidence-snapshot-001 \
  --source <disk-resource-id>

# List storage accounts
az storage account list --output table

# List blobs in container
az storage blob list \
  --account-name <storage-account> \
  --container-name <container> \
  --output table

# Check Key Vault access policies
az keyvault show --name <vault-name>
az keyvault secret list --vault-name <vault-name>

# List Logic Apps
az logic workflow list --output table

# List Automation Accounts & runbooks
az automation account list --output table
az automation runbook list --automation-account-name <name> --resource-group <rg>
```

```powershell
# ── AZURE POWERSHELL ──────────────────────────────────────

Connect-AzAccount

# Get all resources in subscription
Get-AzResource | Select-Object Name, ResourceType, ResourceGroupName | Sort-Object ResourceType

# Activity log query
Get-AzActivityLog -StartTime (Get-Date).AddDays(-7) -EndTime (Get-Date) |
    Select-Object EventTimestamp, Caller, OperationName, Status | Sort-Object EventTimestamp -Descending

# All role assignments
Get-AzRoleAssignment | Select-Object DisplayName, RoleDefinitionName, Scope | Sort-Object RoleDefinitionName

# Check for new owners (high severity)
Get-AzRoleAssignment | Where-Object {$_.RoleDefinitionName -eq "Owner"}

# Network security groups + rules
Get-AzNetworkSecurityGroup | ForEach-Object {
    $_.SecurityRules | Select-Object @{n='NSG';e={$_.Name}}, Name, Access, Direction, SourceAddressPrefix, DestinationPortRange
}

# NSG Flow logs status
Get-AzNetworkWatcherFlowLogStatus -NetworkWatcher (Get-AzNetworkWatcher) -TargetResourceId <nsg-id>
```

```powershell
# ── MICROSOFT GRAPH (Entra ID / AAD) ─────────────────────

Connect-MgGraph -Scopes "AuditLog.Read.All","Directory.Read.All"

# Sign-in logs — last 24h
Get-MgAuditLogSignIn -Filter "createdDateTime ge $(((Get-Date).AddDays(-1)).ToString('yyyy-MM-ddTHH:mm:ssZ'))" |
    Select-Object CreatedDateTime, UserPrincipalName, AppDisplayName, IPAddress, Status

# Failed sign-ins only
Get-MgAuditLogSignIn -Filter "status/errorCode ne 0" -Top 100 |
    Select-Object CreatedDateTime, UserPrincipalName, IPAddress, @{n='Error';e={$_.Status.FailureReason}}

# Risky users
Get-MgIdentityProtectionRiskyUser -Filter "riskState eq 'atRisk'" |
    Select-Object UserPrincipalName, RiskLevel, RiskDetail, RiskLastUpdatedDateTime

# Audit logs — role assignment changes
Get-MgAuditLogDirectoryAudit -Filter "category eq 'RoleManagement'" -Top 50 |
    Select-Object ActivityDateTime, ActivityDisplayName, InitiatedBy, TargetResources

# App registrations with credentials
Get-MgApplication | ForEach-Object {
    $creds = Get-MgApplicationPassword -ApplicationId $_.Id
    if ($creds) { [PSCustomObject]@{App=$_.DisplayName; AppId=$_.AppId; Secrets=$creds.Count} }
}

# OAuth consent grants
Get-MgOauth2PermissionGrant | Select-Object ClientId, ConsentType, PrincipalId, Scope
```

---

### 📊 KQL Queries — Microsoft Sentinel / Defender

```kql
// ── Sign-in anomalies ──────────────────────────────────

// Failed then successful login (brute force pattern)
SigninLogs
| where TimeGenerated > ago(1h)
| summarize FailCount = countif(ResultType != "0"), SuccessCount = countif(ResultType == "0") by UserPrincipalName, IPAddress
| where FailCount > 5 and SuccessCount > 0
| project UserPrincipalName, IPAddress, FailCount, SuccessCount

// Legacy authentication usage
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in ("IMAP", "POP3", "SMTP Auth", "Exchange ActiveSync")
| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress

// Sign-ins from new country
SigninLogs
| where TimeGenerated > ago(1d)
| summarize Countries = make_set(Location) by UserPrincipalName
| where array_length(Countries) > 1

// ── Privilege escalation ───────────────────────────────

// New Owner/Contributor assignment
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role contains "Owner" or Role contains "Global Administrator"
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), Role, TargetResources

// ── Persistence ────────────────────────────────────────

// New app registration credentials added
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("Add password", "Add key credentials to service principal")
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), TargetResources

// VM RunCommand execution
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue contains "runCommand"
| project TimeGenerated, Caller, ResourceGroup, Resource, Properties

// ── Defense evasion ────────────────────────────────────

// Diagnostic settings deleted
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue contains "diagnosticSettings" and ActivityStatusValue == "Success"
| where OperationNameValue contains "delete"
| project TimeGenerated, Caller, ResourceGroup, Resource

// Defender alert suppression
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertName contains "suppression"
```

---

## AWS Forensics

### 🗂️ Log Sources & Locations

| Log Source | Location | What It Captures |
|------------|----------|-----------------|
| **CloudTrail** | S3 bucket / CloudWatch Logs | All API calls — who did what |
| **CloudWatch Logs** | CloudWatch > Log Groups | Application, VPC flow, Lambda logs |
| **VPC Flow Logs** | CloudWatch / S3 | Network traffic metadata |
| **S3 Access Logs** | Target S3 bucket | Object-level access |
| **GuardDuty Findings** | GuardDuty console / EventBridge | Threat detections |
| **AWS Config** | Config console / S3 | Resource configuration changes |
| **IAM Access Advisor** | IAM console | Last used permissions per service |
| **CloudTrail Lake** | CloudTrail Lake | SQL-queryable event store |
| **Security Hub** | Security Hub | Aggregated findings |
| **Route53 Resolver Logs** | CloudWatch | DNS query logs |

---

### 🔑 Key Artifacts to Collect (AWS)

```
Identity & Access:
  - CloudTrail events for ConsoleLogin, AssumeRole, CreateUser, AttachPolicy
  - IAM credential report (last used, MFA status)
  - Access key usage history
  - STS temporary credential usage

Compute:
  - EC2 instance metadata (user data scripts — common persistence)
  - Systems Manager Session Manager logs
  - EC2 serial console output
  - EBS snapshot for disk acquisition

Networking:
  - VPC Flow Logs (src/dst IP, port, action)
  - Security group rule changes (CloudTrail)
  - Route table modifications

Storage:
  - S3 bucket policies + ACLs (check for public access)
  - S3 server access logs / CloudTrail data events
  - Secrets Manager / Parameter Store access logs
```

---

### ⚡ IR Commands — AWS CLI

```bash
# ── CLOUDTRAIL HUNTING ─────────────────────────────────

# Recent API calls by a user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=suspicious-user \
  --start-time 2024-01-01T00:00:00Z \
  --output json

# Console login events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --output table

# Root account usage (critical)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=root \
  --output json

# ── IAM INVESTIGATION ─────────────────────────────────

# IAM credential report
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d

# List all users
aws iam list-users --output table

# Check user's attached policies
aws iam list-attached-user-policies --user-name <username>

# Check for inline policies
aws iam list-user-policies --user-name <username>

# List access keys
aws iam list-access-keys --user-name <username>

# ── EC2 INVESTIGATION ─────────────────────────────────

# List running instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].[InstanceId,PublicIpAddress,PrivateIpAddress,LaunchTime,Tags[?Key==`Name`].Value|[0]]' \
  --output table

# Get user data (check for backdoors)
aws ec2 describe-instance-attribute \
  --instance-id <instance-id> \
  --attribute userData \
  --query 'UserData.Value' --output text | base64 -d

# Isolate instance (IR containment)
aws ec2 modify-instance-attribute \
  --instance-id <instance-id> \
  --groups <isolation-sg-id>

# Create snapshot for evidence
aws ec2 create-snapshot \
  --volume-id <volume-id> \
  --description "IR Evidence - Case001"

# ── S3 INVESTIGATION ──────────────────────────────────

# List buckets
aws s3 ls

# Check bucket public access block
aws s3api get-public-access-block --bucket <bucket-name>

# Check bucket policy
aws s3api get-bucket-policy --bucket <bucket-name>

# List objects with last modified
aws s3 ls s3://<bucket-name>/ --recursive --human-readable | sort -k1,2
```

---

### 🚨 Detection Indicators (AWS)

```
- Root account login (should never happen)
- CloudTrail logging disabled (DeleteTrail, StopLogging)
- New IAM user created + access key immediately generated
- AssumeRole to cross-account from unexpected source
- GetSecretValue on bulk secrets
- S3 bucket ACL changed to public
- Security group opened to 0.0.0.0/0 on port 22/3389
- Lambda function created with broad IAM role
- GuardDuty findings: CryptoCurrency, Backdoor, Trojan categories
- EC2 instance launched in unused region
- Large S3 data transfer (exfiltration)
```

---

## GCP Forensics

### 🗂️ Log Sources & Locations

| Log Source | Location | What It Captures |
|------------|----------|-----------------|
| **Cloud Audit Logs** | Cloud Logging | Admin Activity, Data Access, System Events |
| **VPC Flow Logs** | Cloud Logging | Network traffic metadata |
| **Cloud Armor Logs** | Cloud Logging | WAF + DDoS events |
| **Security Command Center** | SCC console | Threat detections + misconfigs |
| **Chronicle SIEM** | Chronicle | Google's native SIEM |
| **Access Transparency** | Cloud Logging | Google staff access to your data |
| **Firewall Rules Logging** | Cloud Logging | Allowed/denied traffic per rule |

---

### ⚡ IR Commands — gcloud CLI

```bash
# ── AUDIT LOG HUNTING ─────────────────────────────────

# Recent admin activity
gcloud logging read \
  'logName="projects/<project>/logs/cloudaudit.googleapis.com%2Factivity"' \
  --limit 100 \
  --format json

# Filter by user
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="user@domain.com"' \
  --limit 50

# IAM policy changes
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' \
  --limit 50

# ── IAM INVESTIGATION ─────────────────────────────────

# List IAM bindings for project
gcloud projects get-iam-policy <project-id> --format json

# List service accounts
gcloud iam service-accounts list

# Check service account keys
gcloud iam service-accounts keys list \
  --iam-account <sa-email>

# ── COMPUTE INVESTIGATION ─────────────────────────────

# List running instances
gcloud compute instances list

# Get instance metadata (check startup scripts)
gcloud compute instances describe <instance-name> \
  --zone <zone> \
  --format="json(metadata)"

# Create disk snapshot
gcloud compute disks snapshot <disk-name> \
  --snapshot-names evidence-snapshot-001 \
  --zone <zone>

# SSH via IAP (no public IP needed)
gcloud compute ssh <instance-name> --tunnel-through-iap
```

---

### 🚨 Detection Indicators (GCP)

```
- SetIamPolicy granting roles/owner or roles/editor to external user
- Service account key creation (especially external download)
- Compute instance created in unexpected region
- VPC firewall rule opened to 0.0.0.0/0
- Cloud Storage bucket IAM changed to allUsers/allAuthenticatedUsers
- Secret Manager secret accessed in bulk
- GKE cluster kubeconfig downloaded
- Logging sink deleted or modified (log tampering)
- SCC findings: active threats, anomalous IAM grants
```

---

## Cross-Cloud IOC Indicators

### Universal Red Flags

```
Authentication:
  - Login from Tor / VPN / datacenter IP to management console
  - Service account / API key used from unexpected region
  - Impossible travel between cloud console logins
  - MFA disabled on privileged accounts

Privilege Abuse:
  - Wildcard permissions granted (*/*)
  - Permissions granted at highest scope (root/subscription/org level)
  - New admin accounts created during off-hours
  - Permission escalation chain: low-priv → assume role → admin

Persistence:
  - New API keys / service account keys created
  - Backdoor accounts created with generic names
  - Cloud functions / Lambda / Cloud Run deployed with broad IAM
  - VM startup scripts modified

Defense Evasion:
  - Audit logging disabled (highest severity indicator)
  - Alert suppression rules created
  - Threat detection service disabled (GuardDuty, Defender, SCC)
  - Log retention reduced or export disabled

Exfiltration:
  - Bulk storage download (GB-scale from buckets/blobs)
  - Secrets/credentials accessed in bulk
  - Data copied to external storage account/bucket
  - Large egress to unknown IPs
```

---

## Cloud IR Toolkit

| Tool | Platform | Use |
|------|----------|-----|
| **Azurehound** | Azure | AD attack path mapping |
| **Stormspotter** | Azure | Blast radius visualization |
| **Hawk** | Azure / M365 | IR data collection tool |
| **DFIR-O365RC** | M365 | Unified audit log collection |
| **Sparrow** | Azure / M365 | Solorigate-style compromise detection |
| **ROADtools** | Azure AD | Entra ID enumeration & dumping |
| **ScoutSuite** | AWS/Azure/GCP | Multi-cloud security auditing |
| **Prowler** | AWS | AWS security assessment |
| **Pacu** | AWS | AWS IR / attack simulation |
| **CloudFox** | AWS/Azure | Privilege escalation path finder |
| **gcp-firewall-enforcer** | GCP | GCP security remediation |
| **Leonidas** | AWS/Azure/GCP | Cloud attack simulation |

### Quick Containment Actions

```
Azure:
  - Revoke all sessions: Revoke-AzureADUserAllRefreshToken
  - Disable user: Update-MgUser -UserId <id> -AccountEnabled $false
  - Remove role: Remove-AzRoleAssignment
  - Lock resource: az lock create --lock-type CanNotDelete

AWS:
  - Disable access key: aws iam update-access-key --status Inactive
  - Attach deny-all policy to user
  - Isolate EC2: move to isolation security group (no inbound/outbound)
  - Revoke STS sessions via IAM policy condition

GCP:
  - Remove IAM binding: gcloud projects remove-iam-policy-binding
  - Disable service account: gcloud iam service-accounts disable
  - Revoke OAuth tokens via Admin SDK
```

---

*Last updated: 2026-03 | References: MITRE ATT&CK Cloud (attack.mitre.org/matrices/enterprise/cloud) | Microsoft IR Playbooks | AWS Security Incident Response Guide*
