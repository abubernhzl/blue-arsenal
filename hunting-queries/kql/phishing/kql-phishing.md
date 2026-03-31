# KQL Hunting Queries — Phishing & Email Threats
> Platform: Microsoft Defender for Office 365 | Microsoft Sentinel
> ATT&CK: T1566, T1598, T1114, T1534

---

## Table of Contents
1. [Phishing Email Delivered](#phishing-email-delivered)
2. [Malicious URL Clicked](#malicious-url-clicked)
3. [Email Forwarding Rule Created](#email-forwarding-rule-created)
4. [Suspicious Attachment Types](#suspicious-attachment-types)
5. [BEC — Finance & Executive Impersonation](#bec--finance--executive-impersonation)
6. [External Email Forwarding](#external-email-forwarding)
7. [Suspicious Email Volume Spike](#suspicious-email-volume-spike)

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

**False Positive Notes:** Bulk marketing emails may appear as spam. Focus on Phish and Malware threat types.

---

## Malicious URL Clicked
> ATT&CK: T1566.002 — Spearphishing Link

```kql
// Detect users who clicked malicious URLs in emails
// High priority — user already interacted with threat
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
> ATT&CK: T1114.003 — Email Collection: Email Forwarding Rule

```kql
// Detect inbox forwarding rules — common post-compromise persistence
// Attacker maintains email access even after password reset
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
// Detect emails with high-risk attachment file types
EmailAttachmentInfo
| where TimeGenerated > ago(24h)
| where FileType in~ (
    "exe", "dll", "ps1", "vbs", "js", "hta",
    "iso", "img", "lnk", "bat", "cmd",
    "docm", "xlsm", "pptm"
)
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| project TimeGenerated, SenderMailFromAddress, 
    RecipientEmailAddress, Subject, FileName, FileType,
    ThreatTypes, DeliveryLocation
| order by TimeGenerated desc
```

---

## BEC — Finance & Executive Impersonation
> ATT&CK: T1566 — Phishing: Business Email Compromise

```kql
// Detect emails with BEC-related keywords from external senders
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
    "confidential",
    "urgent request"
)
| where SenderMailFromDomain != tostring(split(RecipientEmailAddress, "@")[1])
| project TimeGenerated, SenderMailFromAddress, 
    RecipientEmailAddress, Subject, DeliveryLocation
| order by TimeGenerated desc
```

---

## External Email Forwarding
> ATT&CK: T1114.003 — Email Forwarding Rule

```kql
// Detect emails being forwarded to external domains
// Indicates possible account compromise and data exfiltration via email
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation == "Set-Mailbox"
| where Parameters has "ForwardingSmtpAddress"
| extend ForwardingAddress = extract("ForwardingSmtpAddress:([^,]+)", 1, Parameters)
| where isnotempty(ForwardingAddress)
| project TimeGenerated, UserId, ClientIP, 
    Operation, ForwardingAddress, Parameters
| order by TimeGenerated desc
```

---

## Suspicious Email Volume Spike
> ATT&CK: T1534 — Internal Spearphishing

```kql
// Detect unusual outbound email volume — possible account compromise sending spam
EmailEvents
| where TimeGenerated > ago(24h)
| where EmailDirection == "Outbound"
| summarize 
    EmailCount = count(),
    Recipients = dcount(RecipientEmailAddress)
    by SenderMailFromAddress, bin(TimeGenerated, 1h)
| where EmailCount >= 50
| order by EmailCount desc
```

---

*ATT&CK References: attack.mitre.org | Platform: Microsoft Defender for Office 365 / Sentinel*
*Last updated: 2026-03 | Author: @abubernhzl*
