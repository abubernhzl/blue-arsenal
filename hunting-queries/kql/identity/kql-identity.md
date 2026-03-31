# KQL Hunting Queries — Identity & Authentication Anomalies
> Platform: Microsoft Sentinel | Defender XDR | Defender for Identity
> ATT&CK: T1078, T1110, T1556, T1621, T1606

---

## Table of Contents
1. [Password Spray Detection](#password-spray-detection)
2. [Brute Force to Successful Login](#brute-force-to-successful-login)
3. [Impossible Travel](#impossible-travel)
4. [Legacy Authentication Usage](#legacy-authentication-usage)
5. [MFA Fatigue / Push Bombing](#mfa-fatigue--push-bombing)
6. [Privileged Role Assignment](#privileged-role-assignment)
7. [New Global Admin Added](#new-global-admin-added)
8. [Service Principal Credential Added](#service-principal-credential-added)
9. [Suspicious Sign-in from New Country](#suspicious-sign-in-from-new-country)
10. [Guest Account Sign-in Anomaly](#guest-account-sign-in-anomaly)

---

## Password Spray Detection
> ATT&CK: T1110.003 — Password Spraying

```kql
// Detect password spray: many users, few attempts each from same IP
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize 
    FailedAttempts = count(),
    DistinctUsers = dcount(UserPrincipalName),
    Users = make_set(UserPrincipalName, 20)
    by IPAddress, bin(TimeGenerated, 10m)
| where DistinctUsers >= 10 and FailedAttempts >= 10
| extend Ratio = todouble(FailedAttempts) / todouble(DistinctUsers)
| where Ratio < 3  // Low attempts per user = spray pattern
| project TimeGenerated, IPAddress, FailedAttempts, DistinctUsers, Ratio, Users
| order by DistinctUsers desc
```

**False Positive Notes:** Shared corporate proxies, VPN egress IPs may trigger this. Whitelist known corporate IPs.

---

## Brute Force to Successful Login
> ATT&CK: T1110.001 — Password Guessing

```kql
// Detect multiple failures followed by success — same user, same IP
let FailureThreshold = 5;
let TimeWindow = 30m;
let Failures = SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize FailCount = count(), FirstFail = min(TimeGenerated)
    by UserPrincipalName, IPAddress;
let Successes = SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| project UserPrincipalName, IPAddress, SuccessTime = TimeGenerated;
Failures
| where FailCount >= FailureThreshold
| join kind=inner Successes on UserPrincipalName, IPAddress
| where SuccessTime > FirstFail
| project UserPrincipalName, IPAddress, FailCount, FirstFail, SuccessTime
| order by FailCount desc
```

---

## Impossible Travel
> ATT&CK: T1078 — Valid Accounts

```kql
// Detect sign-ins from two different countries within short timeframe
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, IPAddress, 
    Country = tostring(LocationDetails.countryOrRegion),
    City = tostring(LocationDetails.city)
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevTime = prev(TimeGenerated, 1),
    PrevCountry = prev(Country, 1),
    PrevUser = prev(UserPrincipalName, 1)
| where UserPrincipalName == PrevUser
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where Country != PrevCountry
    and TimeDiffMinutes < 120  // Less than 2 hours between different countries
| project UserPrincipalName, TimeGenerated, Country, PrevCountry, 
    TimeDiffMinutes, IPAddress
| order by TimeDiffMinutes asc
```

---

## Legacy Authentication Usage
> ATT&CK: T1078, T1550 — Bypasses MFA via legacy protocols

```kql
// Detect legacy auth protocols — bypasses conditional access and MFA
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed in (
    "Exchange ActiveSync",
    "IMAP4",
    "MAPI over HTTP",
    "POP3",
    "SMTP Auth",
    "Authenticated SMTP",
    "Exchange Online PowerShell",
    "Other clients"
)
| where ResultType == "0"
| summarize 
    Count = count(),
    LastSeen = max(TimeGenerated),
    Protocols = make_set(ClientAppUsed)
    by UserPrincipalName, IPAddress
| order by Count desc
```

**Recommendation:** Block legacy authentication via Conditional Access policy.

---

## MFA Fatigue / Push Bombing
> ATT&CK: T1621 — Multi-Factor Authentication Request Generation

```kql
// Detect excessive MFA push requests — sign of MFA fatigue attack
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "50074" // MFA required
    or ResultType == "50076"  // MFA interrupted
    or ResultType == "500121" // MFA denied by user
| summarize 
    MFARequests = count(),
    FirstRequest = min(TimeGenerated),
    LastRequest = max(TimeGenerated)
    by UserPrincipalName, IPAddress
| where MFARequests >= 5
| extend DurationMinutes = datetime_diff('minute', LastRequest, FirstRequest)
| order by MFARequests desc
```

---

## Privileged Role Assignment
> ATT&CK: T1078.004 — Cloud Accounts, Privilege Escalation

```kql
// Detect any privileged role assignment in Entra ID
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| extend 
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    Role = tostring(TargetResources[0].modifiedProperties[1].newValue),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Role has_any (
    "Global Administrator",
    "Privileged Role Administrator", 
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Conditional Access Administrator",
    "Authentication Administrator"
)
| project TimeGenerated, InitiatedBy, TargetUser, Role
| order by TimeGenerated desc
```

---

## New Global Admin Added
> ATT&CK: T1078.004 — High Severity

```kql
// Alert: New Global Administrator added — always investigate
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName == "Add member to role"
| extend 
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    Role = tostring(TargetResources[0].modifiedProperties[1].newValue),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName)
| where Role has "Global Administrator"
| project TimeGenerated, InitiatedBy, TargetUser, Role
```

---

## Service Principal Credential Added
> ATT&CK: T1098.001 — Account Manipulation: Additional Cloud Credentials

```kql
// Detect new credentials added to service principals / app registrations
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Add password",
    "Add key credentials to service principal",
    "Update application – Certificates and secrets management"
)
| extend 
    TargetApp = tostring(TargetResources[0].displayName),
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    AppId = tostring(TargetResources[0].id)
| project TimeGenerated, InitiatedBy, TargetApp, AppId, OperationName
| order by TimeGenerated desc
```

---

## Suspicious Sign-in from New Country
> ATT&CK: T1078 — Valid Accounts

```kql
// Detect first-time sign-in from a country not seen in last 30 days
let LookbackPeriod = 30d;
let RecentWindow = 1d;
let HistoricCountries = SigninLogs
| where TimeGenerated between (ago(LookbackPeriod) .. ago(RecentWindow))
| where ResultType == "0"
| summarize HistoricCountries = make_set(tostring(LocationDetails.countryOrRegion))
    by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(RecentWindow)
| where ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=leftouter HistoricCountries on UserPrincipalName
| where not(HistoricCountries has Country)
| project TimeGenerated, UserPrincipalName, Country, IPAddress, AppDisplayName
| order by TimeGenerated desc
```

---

## Guest Account Sign-in Anomaly
> ATT&CK: T1078 — Valid Accounts (External/Guest)

```kql
// Hunt for guest account activity — especially outside business hours
SigninLogs
| where TimeGenerated > ago(7d)
| where UserType == "Guest"
| where ResultType == "0"
| extend 
    Hour = hourofday(TimeGenerated),
    Country = tostring(LocationDetails.countryOrRegion)
| where Hour !between (8 .. 18)  // Outside business hours
| summarize 
    SigninCount = count(),
    Apps = make_set(AppDisplayName),
    Countries = make_set(Country)
    by UserPrincipalName, bin(TimeGenerated, 1d)
| order by SigninCount desc
```

---

*ATT&CK References: attack.mitre.org | Platform: Microsoft Sentinel / Defender XDR*
*Last updated: 2026-03 | Author: @abubernhzl*
