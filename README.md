# 🔵 Blue Arsenal

> **Practitioner-built DFIR & Threat Hunting resource — cloud-first, real investigations, not just tool lists.**
> Built by a DFIR Analyst specializing in Azure, Microsoft Sentinel, and cloud incident response.

[![GitHub stars](https://img.shields.io/github/stars/abubernhzl/blue-arsenal?style=flat-square&color=blue)](https://github.com/abubernhzl/blue-arsenal/stargazers)
[![Last Updated](https://img.shields.io/github/last-commit/abubernhzl/blue-arsenal?style=flat-square&color=blue)](https://github.com/abubernhzl/blue-arsenal/commits/main)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

---

## 🎯 What Is This?

Most DFIR GitHub repos are either tool lists with no real content, red team focused, or stuck in on-premises Windows land.

**Blue Arsenal is different:**
- ✅ Real content — cheatsheets, queries, and rules from actual IR work
- ✅ Cloud-first — Azure, AWS, and GCP forensics as first-class citizens
- ✅ Practitioner perspective — written for analysts, by an analyst
- ✅ ATT&CK aligned — every detection maps to a technique
- ✅ Living resource — updated regularly from field work

---

## 📁 Repository Structure

```
blue-arsenal/
│
├── cheatsheets/               # Quick reference field guides
├── hunting-queries/
│   └── kql/                   # Microsoft Sentinel & Defender XDR
│       ├── identity/          # Entra ID, AAD hunting
│       ├── endpoint/          # Defender for Endpoint
│       ├── cloud/             # Azure & AWS activity
│       └── network/           # Network hunting
├── sigma-rules/               # Platform-agnostic detection rules
│   ├── windows/
│   ├── linux/
│   └── cloud/
├── yara-rules/                # Malware & webshell detection
│   ├── malware/
│   └── webshells/
├── scripts/                   # Triage & response automation
│   ├── windows/               # PowerShell
│   └── linux/                 # Bash
├── attack-paths/              # Attacker chain analysis + detection mapping
│   ├── aws/
│   └── azure/
└── detection-engineering/     # Methodology, templates & testing
    ├── methodology.md
    ├── templates/
    ├── testing/
    └── threat-modeling/
```

---

## 📋 Contents

### 📄 Cheatsheets
| File | Description |
|------|-------------|
| [DFIR_CheatSheet.md](cheatsheets/DFIR_CheatSheet.md) | Master DFIR field reference — triage, artifacts, memory, network, malware |
| [Cloud_Forensics.md](cheatsheets/Cloud_Forensics.md) | Azure (primary), AWS & GCP forensics — log sources, artifacts, IR commands |
| [AWS_Attack_Paths.md](cheatsheets/AWS_Attack_Paths.md) | AWS attack chain reference with detection mapping |

---

### 🔎 KQL Hunting Queries
Microsoft Sentinel & Defender XDR queries organized by domain.

| Category | Focus |
|----------|-------|
| [identity/](hunting-queries/kql/identity/) | Sign-in anomalies, MFA abuse, privilege escalation, risky users |
| [endpoint/](hunting-queries/kql/endpoint/) | Process execution, persistence, lateral movement |
| [cloud/](hunting-queries/kql/cloud/) | Azure activity, resource changes, defender alerts |
| [network/](hunting-queries/kql/network/) | DNS anomalies, C2 beaconing, exfiltration |

> Convert KQL to other platforms using [Sigma](https://github.com/SigmaHQ/sigma) + [sigma-cli](https://github.com/SigmaHQ/sigma-cli)

---

### 🎯 Sigma Rules
Platform-agnostic detection rules — write once, deploy anywhere.

```bash
# Convert to KQL (Microsoft Sentinel)
sigma convert -t kusto -p microsoft_365_defender rule.yml

# Convert to Splunk
sigma convert -t splunk rule.yml

# Convert to Elastic
sigma convert -t elasticsearch rule.yml
```

| Category | Rules |
|----------|-------|
| [windows/](sigma-rules/windows/) | Process creation, registry, event log detections |
| [linux/](sigma-rules/linux/) | Auth, cron, bash history, persistence |
| [cloud/](sigma-rules/cloud/) | CloudTrail, Azure Activity, GCP audit |

---

### 🦠 YARA Rules
| Category | Focus |
|----------|-------|
| [malware/](yara-rules/malware/) | Malware family detection patterns |
| [webshells/](yara-rules/webshells/) | Webshell detection |

---

### ⚙️ Scripts
Live response and triage automation.

| Platform | Focus |
|----------|-------|
| [windows/](scripts/windows/) | PowerShell — process, network, persistence, registry triage |
| [linux/](scripts/linux/) | Bash — auth logs, cron, SUID, process analysis |

---

### ⛓️ Attack Paths
Attacker chain analysis from initial access to impact — with detection mapping per step.

| Platform | Chains |
|----------|--------|
| [aws/](attack-paths/aws/) | IMDS abuse, PassRole escalation, GuardDuty evasion, CloudTrail tampering |
| [azure/](attack-paths/azure/) | Coming soon |

> Attack path concepts referenced from [detecting.cloud](https://detecting.cloud/attack-paths).
> Detection logic, KQL queries, and mitigations by [@abubernhzl](https://github.com/abubernhzl).

---

### 🔬 Detection Engineering
The methodology behind how detections are built, tested, and maintained.

| File | Description |
|------|-------------|
| [methodology.md](detection-engineering/methodology.md) | Detection development process |
| [templates/](detection-engineering/templates/) | Sigma & KQL starter templates |
| [testing/](detection-engineering/testing/) | How to validate detections work |
| [threat-modeling/](detection-engineering/threat-modeling/) | Threat models used to prioritize coverage |

---

## 🧰 Key Tools Referenced

| Tool | Use |
|------|-----|
| [Microsoft Sentinel](https://azure.microsoft.com/en-us/products/microsoft-sentinel) | Cloud-native SIEM |
| [Defender XDR](https://security.microsoft.com) | Endpoint + identity detection |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Memory forensics |
| [KAPE](https://www.kroll.com/kape) | Artifact collection |
| [Eric Zimmerman Tools](https://ericzimmerman.github.io) | Windows artifact parsing |
| [Sigma](https://github.com/SigmaHQ/sigma) | Detection rule format |
| [Chainsaw](https://github.com/WithSecureLabs/chainsaw) | Windows event log hunting |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa) | Windows event log analysis |
| [detecting.cloud](https://detecting.cloud) | Cloud attack research & detection |

---

## 🌐 Key References

| Resource | Link |
|----------|------|
| MITRE ATT&CK | [attack.mitre.org](https://attack.mitre.org) |
| MITRE ATT&CK Cloud | [attack.mitre.org/matrices/enterprise/cloud](https://attack.mitre.org/matrices/enterprise/cloud) |
| DFIR Training | [dfir.training](https://dfir.training) |
| Detecting.Cloud | [detecting.cloud](https://detecting.cloud) |
| AWS Security IR Guide | [AWS IR Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/welcome.html) |
| Microsoft IR Playbooks | [Microsoft Security Blog](https://www.microsoft.com/en-us/security/blog/) |

---

## 🚀 Quick Start

```bash
git clone https://github.com/abubernhzl/blue-arsenal.git
cd blue-arsenal
```

No dependencies. No setup. Grab what you need.

---

## 🗺️ Roadmap

- [x] DFIR Master Cheatsheet
- [x] Cloud Forensics — Azure, AWS, GCP
- [x] AWS Attack Paths
- [ ] Azure Attack Paths
- [ ] KQL Identity Hunting Queries
- [ ] KQL Cloud Hunting Queries
- [ ] Sigma Rules — Windows
- [ ] Sigma Rules — Cloud
- [ ] PowerShell Live Response Scripts
- [ ] Detection Engineering Methodology
- [ ] 🔴 Red Arsenal (future)

---

## 🤝 Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

Found a bug, have a better detection, or want to add a new attack path? Open a PR.

---

## ⚠️ Disclaimer

All content is for **authorized incident response, forensic investigation, threat hunting, and research purposes only**. Always ensure proper authorization before use.

---

## 📬 Connect

- LinkedIn: [Abu Bakar Huzail](https://www.linkedin.com/in/abubakarhuzail/)
- GitHub: [@abubernhzl](https://github.com/abubernhzl)

---

*Built from real-world IR work | Updated regularly | Cloud-first DFIR*

<!-- Topics: dfir, blue-team, threat-hunting, azure-forensics, cloud-dfir, kql, sigma-rules, incident-response, detection-engineering, blue-arsenal, microsoft-sentinel, digital-forensics -->
