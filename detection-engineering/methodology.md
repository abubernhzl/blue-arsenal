# Detection Engineering Methodology

> How detections are built, tested, and maintained in Blue Arsenal.

---

## The Process — 6 Steps

```
1. Identify Threat    →    2. Find Log Source    →    3. Write Detection
         ↑                                                     ↓
6. Document                                          4. Test & Validate
         ↑                                                     ↓
5. Deploy & Monitor   ←         Tune False Positives          ←
```

---

### Step 1 — Identify the Threat
- Start with a real incident, threat intel report, or ATT&CK technique
- Ask: *"What would this look like in my environment?"*
- Reference: [MITRE ATT&CK](https://attack.mitre.org)

### Step 2 — Find the Log Source
- What log captures this activity?
- Is it enabled in your environment?
- Common sources: Security.evtx, Azure Activity Log, CloudTrail, Sysmon, EDR telemetry

### Step 3 — Write the Detection
- Start with Sigma (platform-agnostic)
- Convert to KQL for Sentinel deployment
- Tag with ATT&CK technique ID
- Use templates in [templates/](templates/)

### Step 4 — Test & Validate
- Use Atomic Red Team to simulate the technique
- Verify the detection fires
- Check for false positives in your environment
- See [testing/](testing/) for validation guide

### Step 5 — Deploy & Monitor
- Deploy to Sentinel / SIEM
- Set appropriate severity and response actions
- Monitor false positive rate for first 2 weeks

### Step 6 — Document
- Add to this repo with description, ATT&CK mapping, and false positive notes
- Update CHANGELOG.md
- Commit to `dev` branch → PR to `main` when stable

---

## Detection Quality Checklist

Before committing any detection:

```
[ ] ATT&CK technique ID tagged
[ ] Log source documented
[ ] Tested against simulated activity
[ ] False positives assessed
[ ] Description explains WHAT and WHY
[ ] Severity level justified
```

---

## Branching Workflow

```
main     ← stable, production-ready detections
dev      ← work in progress, drafts, testing
```

Always work on `dev` → PR to `main` when ready.

---

*Good detections are specific, tested, and documented. Bad detections are noise.*
