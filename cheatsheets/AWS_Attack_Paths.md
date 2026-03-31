# AWS Cloud Attack Paths
> Source: [detecting.cloud](https://detecting.cloud/attack-paths) — Realistic attacker chains in cloud environments.
> Each path is composed of reusable technique steps. Use this for threat hunting, detection engineering, and red team awareness.

---

## Table of Contents
1. [Critical Attack Chains](#critical-attack-chains)
2. [High Severity Attack Chains](#high-severity-attack-chains)
3. [Detection Mapping](#detection-mapping)
4. [Key Permissions to Monitor](#key-permissions-to-monitor)

---

## Critical Attack Chains

---

### 🔴 EC2 IMDS to S3 Exfiltration
**Requires:** Code execution on EC2 (RCE, compromised app, or stolen SSH keys) — no prior AWS credentials needed.

```
Attacker Chain:
  1. Gain foothold on EC2 instance
  2. Query IMDS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  3. Retrieve temporary IAM role credentials
  4. Use creds to assume cross-account role OR directly access S3
  5. Download sensitive objects → exfiltration complete
```

**Technique Steps:** `EC2 IMDS Credential Theft` → `STS AssumeRole Abuse` → `S3 Data Exfiltration`

**Detection KQL / CloudWatch:**
```
# CloudTrail: IMDS credential use from unexpected source
{ $.eventName = "AssumeRole" && $.userAgent = "aws-sdk*" && $.sourceIPAddress != "expected-range" }

# Look for GetObject calls from EC2 instance role to unusual buckets
{ $.eventName = "GetObject" && $.userIdentity.type = "AssumedRole" }
```

**Mitigations:**
- Enforce IMDSv2 (token required): `aws ec2 modify-instance-metadata-options --http-tokens required`
- Apply least privilege to EC2 instance roles — no broad S3 access
- Enable S3 data events in CloudTrail
- Monitor cross-account AssumeRole from EC2 roles

---

### 🔴 PassRole Lambda Privilege Escalation
**Requires:** `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction`

```
Attacker Chain:
  1. Attacker has iam:PassRole on a high-privilege role (e.g., AdministratorAccess)
  2. Creates Lambda function, assigns high-privilege role as execution role
  3. Lambda code: creates backdoor IAM user + attaches admin policy + generates access keys
  4. Invokes Lambda → runs with full admin permissions
  5. Uses generated keys for persistent access
```

**Technique Steps:** `IAM PassRole Abuse` → `Lambda Function Code Execution` → `Backdoor IAM User Creation` → `Access Key Generation`

**Detection:**
```bash
# CloudTrail: PassRole + CreateFunction in same session
{ $.eventName = "CreateFunction" && $.requestParameters.role != null }

# New IAM user created by Lambda execution role
{ $.eventName = "CreateUser" && $.userIdentity.sessionContext.sessionIssuer.type = "Role" }

# Access key created shortly after user creation
{ $.eventName = "CreateAccessKey" }
```

**Mitigations:**
- Restrict `iam:PassRole` with conditions: `iam:PassedToService: lambda.amazonaws.com`
- Require SCP to deny Lambda creation with admin roles
- Alert on Lambda functions assuming roles with `*` permissions

---

### 🔴 IAM Policy Escalation Chain
**Requires:** `iam:CreatePolicyVersion` on a managed policy the attacker is already attached to.

```
Attacker Chain:
  1. Attacker already attached to a managed policy
  2. Creates new policy version: Action: *, Resource: *
  3. Sets new version as default → permissions apply immediately
  4. No additional API calls needed — attacker now has full access
  5. Uses escalated permissions to assume cross-account roles
```

**Technique Steps:** `Create Policy Version Escalation` → `IAM Policy Attachment` → `STS AssumeRole Abuse`

**Detection:**
```bash
# CloudTrail: New policy version created and set as default
{ $.eventName = "CreatePolicyVersion" && $.requestParameters.setAsDefault = "true" }

# Policy document with wildcard — parse requestParameters
{ $.eventName = "CreatePolicyVersion" }  # Then inspect policy document for Action: *
```

**Mitigations:**
- Restrict `iam:CreatePolicyVersion` — rarely needed by regular users
- SCP: Deny policy versions with `Action: *` or `Resource: *`
- Periodic IAM Access Analyzer review of managed policies

---

### 🔴 External IMDS SSRF to S3
**Requires:** SSRF vulnerability in a web application running on EC2 — no AWS credentials needed.

```
Attacker Chain:
  1. Find web app vulnerable to SSRF running on EC2
  2. Inject URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
  3. Server fetches its own IAM credentials and returns them in response
  4. Use stolen credentials to access S3 buckets
  5. Exfiltrate sensitive data
```

**Technique Steps:** `External IMDS SSRF (No Credentials)` → `S3 Data Exfiltration`

**Detection:**
```bash
# WAF: Requests containing IMDS IP in parameters
169.254.169.254

# CloudTrail: Credentials used from unexpected external IP
{ $.eventName = "GetObject" && $.sourceIPAddress != "known-ec2-range" }
```

**Mitigations:**
- **Enforce IMDSv2** — single most effective control, breaks most SSRF attacks
- WAF rule blocking `169.254.169.254` in request parameters
- Network-level egress filtering on EC2

---

### 🔴 Trust Policy Backdoor Persistence
**Requires:** `iam:UpdateAssumeRolePolicy`

```
Attacker Chain:
  1. Modify role's trust policy to add attacker's AWS account as trusted principal
  2. Attacker can now call sts:AssumeRole from their account at any time
  3. Persists through key rotation and original compromise remediation
  4. Cross-account backdoor established indefinitely
```

**Technique Steps:** `IAM Trust Policy Modification` → `STS AssumeRole Abuse`

**Detection:**
```bash
# CloudTrail: Trust policy updated
{ $.eventName = "UpdateAssumeRolePolicy" }

# Check for external account IDs added to trust policies
# Parse responseElements for new principals outside your org
```

**Mitigations:**
- Alert on any `UpdateAssumeRolePolicy` — this should be rare
- SCP: Restrict cross-account trust to known account IDs only
- Regular audit of all role trust policies

---

### 🔴 OIDC Trust Misconfiguration Initial Access
**Requires:** Misconfigured IAM role trust policy trusting OIDC provider with wildcard subject claim.

```
Attacker Chain:
  1. Find IAM role trusting GitHub/GitLab OIDC with wildcard sub claim (e.g., repo:*:*)
  2. Create attacker-controlled repository
  3. Configure GitHub Actions to request OIDC tokens
  4. Use tokens to call sts:AssumeRoleWithWebIdentity
  5. Gain access — no stolen credentials required
```

**Technique Steps:** `OIDC Trust Policy Misconfiguration` → `STS AssumeRole Abuse`

**Detection:**
```bash
# CloudTrail: AssumeRoleWithWebIdentity from unexpected repo
{ $.eventName = "AssumeRoleWithWebIdentity" }
# Inspect $.requestParameters.webIdentityToken subject claim
# Flag: sub not matching your org's repos
```

**Mitigations:**
- Never use wildcard `sub` claims — specify exact repo: `repo:org/repo:ref:refs/heads/main`
- Audit all OIDC providers and their trust conditions
- Alert on `AssumeRoleWithWebIdentity` from unknown subjects

---

### 🔴 CloudFront Orphaned Origin Takeover
**Requires:** Deleted S3 bucket that CloudFront still uses as origin.

```
Attacker Chain:
  1. Find CloudFront distribution with deleted S3 bucket as origin
  2. Origin domain (bucket-name.s3.amazonaws.com) still resolves
  3. Create new S3 bucket with the same name as the deleted one
  4. CloudFront now serves content from attacker's bucket
  5. Serve malicious content via trusted CloudFront URL
```

**Technique Steps:** `CloudFront Orphaned Origin Takeover`

**Detection:**
- Monitor for S3 bucket creation that matches names of previously deleted buckets used by CloudFront
- Audit CloudFront origins regularly for deleted bucket references

**Mitigations:**
- Always update/remove CloudFront distributions before deleting S3 buckets
- Enable S3 Block Public Access on buckets used as origins
- Monitor CloudFront origin health and alert on `AccessDenied` errors

---

## High Severity Attack Chains

---

### 🟠 Lambda Persistence Backdoor
**Requires:** `iam:PassRole` + `lambda:CreateFunction` + `events:PutRule` + `events:PutTargets`

```
Attacker Chain:
  1. Deploy backdoor Lambda with privileged execution role
  2. Lambda code: creates backdoor users or exfiltrates data on each invocation
  3. Create EventBridge rule to trigger Lambda on schedule (e.g., every 5 min)
  4. Disable/modify CloudTrail to reduce detection likelihood
  5. Self-sustaining backdoor — survives initial compromise remediation
```

**Technique Steps:** `IAM PassRole Abuse` → `Lambda Function Code Execution` → `Lambda Persistence via Event Triggers` → `CloudTrail Logging Disruption`

---

### 🟠 IAM Backdoor & Data Exfiltration
**Requires:** IAM privileges to create users and modify S3 bucket policies.

```
Attacker Chain:
  1. Create hidden backdoor IAM user with low-profile name
  2. Attach inline admin policy (harder to detect than managed policy)
  3. Generate access keys for backdoor user
  4. Modify S3 bucket policies to grant backdoor user explicit access
  5. Exfiltrate data — survives key rotation of original compromised creds
```

**Technique Steps:** `Backdoor IAM User Creation` → `Access Key Generation` → `S3 Bucket Policy Modification` → `S3 Data Exfiltration`

**Detection:**
```bash
# CloudTrail: New IAM user + inline policy + access key in short window
{ $.eventName = "CreateUser" }
{ $.eventName = "PutUserPolicy" }
{ $.eventName = "CreateAccessKey" }

# S3 bucket policy modified
{ $.eventName = "PutBucketPolicy" }
```

---

### 🟠 GuardDuty Evasion Chain
**Requires:** GuardDuty management permissions.

```
Attacker Chain:
  1. guardduty:UpdateDetector → disable detector or reduce sensitivity
  2. guardduty:CreateIPSet / UpdateIPSet → add attacker IPs to trusted list
  3. guardduty:CreateFilter / UpdateFilter → suppress specific finding types
  4. Security monitoring now blind to attacker's subsequent activity
```

**Technique Steps:** `GuardDuty Detector Modification` → `GuardDuty IP Trust List Evasion` → `GuardDuty Filter Suppression`

**Detection:**
```bash
# CloudTrail: Any GuardDuty modification — treat as critical
{ $.eventName = "UpdateDetector" }
{ $.eventName = "CreateIPSet" || $.eventName = "UpdateIPSet" }
{ $.eventName = "CreateFilter" || $.eventName = "UpdateFilter" }
```

**Mitigations:**
- SCP: Deny `guardduty:UpdateDetector`, `guardduty:DeleteDetector` for all roles except break-glass
- Alert immediately on any GuardDuty config change

---

### 🟠 CloudTrail Evasion Chain
**Requires:** CloudTrail + S3 management permissions.

```
Attacker Chain:
  1. cloudtrail:UpdateTrail → disable logging or redirect to attacker-controlled bucket
  2. cloudtrail:PutEventSelectors → exclude data/management events from logging
  3. s3:PutBucketLifecycleConfiguration → add lifecycle rule to delete logs quickly
  4. Audit trail coverage degraded or eliminated
```

**Technique Steps:** `CloudTrail Configuration Update` → `CloudTrail Event Selectors Modification`

**Detection:**
```bash
# CloudTrail: Trail modifications
{ $.eventName = "UpdateTrail" }
{ $.eventName = "StopLogging" }
{ $.eventName = "PutEventSelectors" }
{ $.eventName = "PutBucketLifecycleConfiguration" && $.requestParameters.bucketName = "<cloudtrail-bucket>" }
```

**Mitigations:**
- Enable CloudTrail log file validation (detects tampering)
- SCP: Deny `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`
- Send logs to separate security account (log archive) — attackers can't touch it
- Alert on any trail modification immediately

---

### 🟠 Volume Snapshot Credential Loot
**Requires:** `ec2:CreateSnapshot` + `ec2:ModifySnapshotAttribute`

```
Attacker Chain:
  1. Create snapshot of EC2 root/data volume
  2. Share snapshot with attacker's account or make temporarily public
  3. Copy snapshot to attacker account, attach as volume to attacker's EC2
  4. Mount volume, extract: ~/.aws/credentials, app config files, secrets
  5. Use extracted credentials for further access
```

**Mitigations:**
- Encrypt all EBS volumes with KMS (attacker can't read without key access)
- Never store credentials on EC2 filesystems — use Secrets Manager / Parameter Store
- Alert on `ModifySnapshotAttribute` with `createVolumePermission` changes

---

### 🟠 SSM Access via CreateTags Lateral Movement
**Requires:** `ec2:CreateTags` or `ssm:AddTagsToResource`

```
Attacker Chain:
  1. Target uses tag-based SSM Session Manager access control
  2. Attacker adds required tags to target instances (satisfies session policy)
  3. Use ssm:StartSession → interactive shell access
  4. No SSH keys or open port 22 needed — bypasses tag-based controls
```

**Detection:**
```bash
# CloudTrail: Tags added to EC2 instances
{ $.eventName = "CreateTags" && $.requestParameters.resourcesSet.items[0].resourceId = "i-*" }

# SSM Session started from unexpected principal
{ $.eventName = "StartSession" }
```

---

### 🟠 GetFederationToken Persistence
**Requires:** `sts:GetFederationToken`

```
Attacker Chain:
  1. Attacker creates federation token BEFORE their access key is rotated/deleted
  2. Federation tokens are NOT revoked when original key is deleted
  3. Store token credentials
  4. Use token for persistent access even after org thinks they removed attacker
```

**Mitigations:**
- Restrict `sts:GetFederationToken` — deny for most roles via SCP
- Monitor usage of federation tokens
- When revoking access, also invalidate all outstanding sessions via IAM policy

---

### 🟠 ECS Task Credential Theft Chain
**Requires:** Code execution in ECS container.

```
Attacker Chain:
  1. Gain code execution in container (vulnerable app)
  2. Retrieve task role credentials via metadata endpoint or env vars
  3. If task role has sts:AssumeRole or iam:CreateAccessKey:
     → Assume higher-privilege role OR create persistent access keys
  4. Escalate from container-level to broader account access
```

**Detection:**
```bash
# CloudTrail: ECS task role used from unexpected IP
{ $.userIdentity.sessionContext.sessionIssuer.type = "Role" &&
  $.userIdentity.sessionContext.sessionIssuer.userName = "ecsTaskRole*" &&
  $.sourceIPAddress != "known-ecs-cluster-range" }
```

---

### 🟠 Cognito Identity Pool Privilege Escalation
**Requires:** Cognito Identity Pool with unauthenticated access enabled + overprivileged IAM role.

```
Attacker Chain:
  1. Call GetCredentialsForIdentity without authentication
  2. Receive temporary AWS credentials scoped to the unauthenticated role
  3. If role has broad S3/resource access → exfiltrate data
  4. No account or credentials required
```

**Mitigations:**
- Disable unauthenticated access on Cognito Identity Pools unless explicitly needed
- Apply strict least-privilege to the unauthenticated IAM role
- Regularly audit Cognito Identity Pool configurations

---

### 🟠 Bedrock Agent Hijacking
**Requires:** `bedrock:UpdateAgent` + `lambda:UpdateFunctionCode`

```
Attacker Chain:
  1. Modify Bedrock agent's Lambda function with attacker-controlled code
  2. When agent is invoked (via API or app), malicious Lambda executes
  3. Runs with agent's IAM role permissions
  4. Use for privilege escalation or data exfiltration
  5. Appears as legitimate agent usage — hard to detect
```

---

## Detection Mapping

| Attack Technique | CloudTrail Event to Alert On |
|-----------------|------------------------------|
| IMDS credential theft | `GetObject` from EC2 role to unusual bucket |
| PassRole abuse | `CreateFunction` + `PassRole` in same session |
| IAM policy escalation | `CreatePolicyVersion` with `setAsDefault=true` |
| Trust policy backdoor | `UpdateAssumeRolePolicy` |
| OIDC misconfiguration | `AssumeRoleWithWebIdentity` from unknown subject |
| Backdoor user creation | `CreateUser` + `PutUserPolicy` + `CreateAccessKey` |
| GuardDuty evasion | `UpdateDetector`, `CreateIPSet`, `CreateFilter` |
| CloudTrail evasion | `StopLogging`, `UpdateTrail`, `PutEventSelectors` |
| Snapshot loot | `ModifySnapshotAttribute` with volume permissions |
| SSM lateral movement | `CreateTags` on instances + `StartSession` |
| Federation token persistence | `GetFederationToken` |
| ECS credential theft | Task role used from unexpected IP |

---

## Key Permissions to Monitor

These permissions are **high-value targets** for attackers — alert on any unexpected usage:

```
Privilege Escalation:
  iam:PassRole
  iam:CreatePolicyVersion
  iam:PutUserPolicy
  iam:AttachUserPolicy
  iam:CreateUser
  iam:CreateAccessKey
  sts:AssumeRole
  sts:GetFederationToken
  iam:UpdateAssumeRolePolicy
  iam:CreateOpenIDConnectProvider

Defense Evasion:
  cloudtrail:StopLogging
  cloudtrail:UpdateTrail
  cloudtrail:PutEventSelectors
  guardduty:UpdateDetector
  guardduty:DeleteDetector
  guardduty:CreateFilter

Persistence:
  lambda:CreateFunction
  lambda:UpdateFunctionCode
  events:PutRule
  events:PutTargets
  ec2:ModifyInstanceAttribute  # user data injection
  ec2:RunInstances             # with instance profile
  rolesanywhere:CreateTrustAnchor

Exfiltration:
  s3:GetObject                 # bulk reads
  s3:PutBucketPolicy           # granting external access
  ec2:CreateSnapshot
  ec2:ModifySnapshotAttribute
  secretsmanager:GetSecretValue
```

---

## Recommended AWS Detection Rules (CloudTrail)

```json
// Alert: IAM user created outside business hours
{
  "eventName": "CreateUser",
  "time": "outside 08:00-18:00 local"
}

// Alert: PassRole + Lambda CreateFunction (escalation chain start)
// Correlate within 10-minute window per user/role:
"CreateFunction" AND "PassRole" by same principal

// Alert: GuardDuty detector disabled
{
  "eventName": "UpdateDetector",
  "requestParameters.enable": false
}

// Alert: CloudTrail stopped
{
  "eventName": "StopLogging"
}

// Alert: Snapshot shared externally
{
  "eventName": "ModifySnapshotAttribute",
  "requestParameters.createVolumePermission": { "add": { "userId": "<external-account>" } }
}
```

---

## References

| Resource | URL |
|----------|-----|
| **Detecting.Cloud** | [detecting.cloud/attack-paths](https://detecting.cloud/attack-paths) |
| MITRE ATT&CK Cloud | [attack.mitre.org/matrices/enterprise/cloud](https://attack.mitre.org/matrices/enterprise/cloud) |
| AWS Security IR Guide | [docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html) |
| CloudGoat (lab) | [github.com/RhinoSecurityLabs/cloudgoat](https://github.com/RhinoSecurityLabs/cloudgoat) |
| Pacu (AWS IR/attack) | [github.com/RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) |

---

*Source: detecting.cloud | Last updated: 2026-03*
