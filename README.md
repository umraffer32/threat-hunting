# Threat Hunts
 
A personal collection of threat hunting writeups, CTFs, and incident response exercises. Each hunt is a self-contained directory with its own README, queries, and lessons learned.
 
---
 
## Index
 
| Hunt | Scenario | Platform | Status |
|---|---|---|---|
| [Hunt 02](https://github.com/umraffer32/scattered-spider-hunt) | BEC via MFA fatigue — Scattered Spider | Microsoft Sentinel | ✅ Complete |
|  |  |  |  |
 
---
 
## Directory Structure
 
Each hunt follows roughly the same shape:
 
```
hunt-name/
├── README.md          # TL;DR, timeline, IOCs, MITRE mapping
├── Section 01.md      # Question-by-question writeup
├── Section 02.md
└── ...
```
 
The top-level README is the executive summary. The section files are where the actual queries live, alongside the reasoning behind each step.
 
---
 
## Conventions
 
- **AM/PM time format** — easier to read at a glance in narrative writeups than 24-hour
- **Flags called out explicitly** — every solved question ends with `**Flag:** value` so they're greppable
- **Lessons over flags** — the answer is rarely the point; the reasoning is. Every question gets a Lesson callout if there's something worth carrying forward
- **MITRE-mapped where relevant** — technique IDs in the README, tactic context in the writeup
- **IOCs block in the README** — IPs, accounts, domains, hashes pulled out so they're easy to copy into a SIEM
 
---
 
## Tools & Platforms
 
What tends to show up across these hunts:
 
- **Microsoft Sentinel** — KQL, `SigninLogs`, `CloudAppEvents`, `EmailEvents`, `DeviceEvents`
- **Splunk** — SPL, when the lab/scenario uses it
- **MITRE ATT&CK** — the common vocabulary across every writeup
- **CTF platforms** — LetsDefend, TryHackMe, BTLO, HTB, and similar, depending on source
