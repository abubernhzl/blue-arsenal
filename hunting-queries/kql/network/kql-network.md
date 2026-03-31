# KQL Hunting Queries — Network & C2 Detection
> Platform: Microsoft Defender for Endpoint | Microsoft Sentinel
> ATT&CK: T1071, T1572, T1568, T1048, T1095

---

## Table of Contents
1. [DNS Beaconing Detection](#dns-beaconing-detection)
2. [High Entropy Domain Detection](#high-entropy-domain-detection)
3. [Suspicious Outbound Connections](#suspicious-outbound-connections)
4. [Large Outbound Data Transfer](#large-outbound-data-transfer)
5. [Uncommon User Agent Strings](#uncommon-user-agent-strings)
6. [TOR Exit Node Connections](#tor-exit-node-connections)

---

## DNS Beaconing Detection
> ATT&CK: T1071.004 — Application Layer Protocol: DNS

```kql
// Detect regular interval DNS queries — C2 beaconing pattern
// High query count to same domain over sustained period
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
| where QueriesPerHour >= 5
| order by QueriesPerHour desc
```

**False Positive Notes:** CDN domains, telemetry services, and update services may show beaconing patterns. Build a whitelist of known-good domains.

---

## High Entropy Domain Detection
> ATT&CK: T1568.002 — Dynamic Resolution: Domain Generation Algorithms

```kql
// Detect high entropy domain names — possible DGA or DNS tunneling
// Long random-looking subdomains are common in malware C2
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "DnsQueryResponse"
| extend DomainPart = tostring(split(RemoteUrl, ".")[0])
| extend DomainLength = strlen(DomainPart)
| where DomainLength >= 15
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
// Detect outbound connections to ports commonly used by C2 frameworks
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (
    4444,   // Common C2 default
    1337,   // Common C2
    8888,   // Common C2
    9001,   // Tor
    9030,   // Tor directory
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

## Large Outbound Data Transfer
> ATT&CK: T1048 — Exfiltration Over Alternative Protocol

```kql
// Detect large outbound data transfers over HTTPS — possible exfiltration
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

## Uncommon User Agent Strings
> ATT&CK: T1071.001 — Web Protocols

```kql
// Detect uncommon or suspicious HTTP user agents
// Malware often uses hardcoded or minimal user agent strings
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| extend UserAgent = tostring(AdditionalFields.UserAgent)
| where isnotempty(UserAgent)
| where UserAgent !has "Mozilla"
    and UserAgent !has "Chrome"
    and UserAgent !has "Safari"
    and UserAgent !has "Edge"
    and UserAgent !has "Windows Update"
| summarize 
    Count = count(),
    Devices = make_set(DeviceName),
    Destinations = make_set(RemoteUrl, 10)
    by UserAgent
| order by Count asc  // Rare user agents first
```

---

## TOR Exit Node Connections
> ATT&CK: T1090.003 — Proxy: Multi-hop Proxy

```kql
// Detect connections to known TOR ports from internal devices
// Combine with TI feed for known TOR exit node IPs
DeviceNetworkEvents
| where TimeGenerated > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemotePort in (9001, 9030, 9050, 9051, 9150)
| project TimeGenerated, DeviceName, AccountName,
    RemoteIPAddress, RemotePort, RemoteUrl,
    InitiatingProcessFileName
| order by TimeGenerated desc
```

---

*ATT&CK References: attack.mitre.org | Platform: Microsoft Defender for Endpoint / Sentinel*
*Last updated: 2026-03 | Author: @abubernhzl*
