# Hunt 02 — Scattered Spider BEC Investigation

A KQL-driven incident response investigation into a Business Email Compromise (BEC) attack on **LogN Pacific Financial Services**. The attacker hijacked a finance department user's account via MFA fatigue, established email rule persistence, and redirected **£24,500** in fraudulent wire transfers before being detected.

This writeup walks the full kill chain across 29 questions, eight sections, and three Microsoft Sentinel tables (`SigninLogs`, `CloudAppEvents`, `EmailEvents`).

---

## TL;DR

| | |
|---|---|
| **Victim** | LogN Pacific Financial Services — Finance department |
| **Compromised Account** | `m.smith@lognpacific.org` |
| **Attacker IP** | `205.147.16.190` (Netherlands) |
| **Attacker Device** | Linux + Firefox 147.0, unmanaged |
| **Initial Access** | MFA fatigue (T1621) — 3 failed prompts, user-approved on 4th |
| **Persistence** | Two malicious inbox rules (T1564.008) — one forwarder, one cleanup |
| **Exfiltration** | Forward to `insights@duck.com` filtered on `invoice, payment, wire, transfer` |
| **Fraud** | Thread-hijacked email to `j.reynolds@lognpacific.org` requesting updated banking details |
| **Loss** | £24,500 wire redirected |
| **Session Anchor** | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` ties the entire chain together |
| **Attributed Group** | Scattered Spider (UNC3944 / Octo Tempest / Muddled Libra) |

---

## Table of Contents

| Section | Theme | Flags |
|---|---|---|
| [01 — How Did They Beat MFA?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/How%20did%20they%20beat%20MFA.md) | Identifying the compromise and reconstructing the MFA fatigue sequence | Q01–Q08 |
| [02 — What Did They Leave Behind?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/What%20did%20they%20leave%20behind.md) | Post-auth recon and inbox rule persistence | Q09–Q14 |
| [03 — What Are They Hiding?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/What%20are%20they%20hiding.md) | The deletion rule and full persistence architecture | Q15–Q16 |
| [04 — Who Took The Bait?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/Who%20took%20the%20bait.md) | The fraudulent email and its target | Q17–Q20 |
| [05 — What Else Did They Access?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/What%20else%20did%20they%20access.md) | OneDrive, SharePoint, and session correlation | Q21–Q23 |
| [06 — How Do We Catch This Next Time?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/How%20do%20we%20catch%20this%20next%20time.md) | Defensive gaps and MITRE mapping | Q24–Q26 |
| [07 — Where Did The Password Come From?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/Where%20did%20the%20password%20come%20from.md) | Infostealer supply chain | Q27 |
| [08 — What Do We Do First?](https://github.com/umraffer32/threat-hunting/blob/main/Scattered%20Spider/What%20do%20we%20do%20first.md) | Containment and threat actor attribution | Q28–Q29 |

---

## Attack Timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 9:54:24 PM | First sign-in attempt from `205.147.16.190` — MFA challenge issued (`50074`) | SigninLogs |
| 9:54:55 PM | Failed sign-in (`50140`) | SigninLogs |
| 9:55:15 PM | Failed sign-in (`50140`) | SigninLogs |
| 9:59:52 PM | ✅ Successful sign-in — Mark approved push to make notifications stop | SigninLogs |
| 9:56:24 PM | First post-auth action — `MailItemsAccessed` (recon) | CloudAppEvents |
| 9:57:53 PM | Continued mailbox recon | CloudAppEvents |
| 10:02:33 PM | `New-InboxRule` — forwarder (`.`) created | CloudAppEvents |
| 10:03:59 PM | `New-InboxRule` — cleanup (`..`) created | CloudAppEvents |
| 10:04:34 PM | `Create` + `Send` — fraudulent invoice email | CloudAppEvents |
| 10:06:39 PM | Email received by `j.reynolds@lognpacific.org` | EmailEvents |
| 10:07:16 PM | OneDrive file browsing — recon for additional financial docs | CloudAppEvents |

---

## The Persistence Architecture

The attacker created two inbox rules that worked as a system:

| Rule | Name | Trigger Keywords | Action |
|---|---|---|---|
| Forwarder | `.` | `invoice, payment, wire, transfer` | Forward to `insights@duck.com` |
| Cleanup | `..` | `suspicious, security, phishing, unusual, compromised, verify` | Delete from inbox |

The forwarder silently exfiltrates anything finance-related. The cleanup deletes any warning emails so the legitimate user never sees finance, IT, or security trying to flag the fraud. The fraud stays invisible to the victim even after the attacker is long gone.

---

## MITRE ATT&CK Mapping

| Phase | Technique | Tactic |
|---|---|---|
| Initial credential acquisition | T1589 — Gather Victim Identity Information (purchased from infostealer logs) | Reconnaissance |
| MFA bombing | T1621 — Multi-Factor Authentication Request Generation | Credential Access |
| Account takeover | T1078.004 — Valid Accounts: Cloud Accounts | Defense Evasion / Persistence / Initial Access |
| Mailbox recon | T1114.002 — Email Collection: Remote Email Collection | Collection |
| Email forwarding rule | T1114.003 — Email Collection: Email Forwarding Rule | Collection |
| Inbox rule cleanup | T1564.008 — Hide Artifacts: Email Hiding Rules | Defense Evasion |
| Cloud storage access | T1530 — Data from Cloud Storage | Collection |
| Internal spearphishing | T1534 — Internal Spearphishing | Lateral Movement |

---

## Indicators of Compromise

**Network:**
- `205.147.16.190` (NL — primary attacker IP)
- `205.147.16.192` (NL — secondary, brief activity)

**Identity:**
- Compromised UPN: `m.smith@lognpacific.org`
- Session ID: `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

**Email:**
- Exfiltration destination: `insights@duck.com`
- Fraudulent subject: `RE: Invoice #INV-2026-0892 - Updated Banking Details`
- Internal target: `j.reynolds@lognpacific.org`

**Behavioral:**
- Inbox rule names: `.` and `..` (single and double period)
- Linux + Firefox 147.0 sign-ins on a finance user account
- `ConditionalAccessStatus: notApplied` on attacker auth

---

## Defensive Gaps

This attack succeeded because of a stack of missing controls, any one of which would have broken the chain:

1. **No Conditional Access on finance users** — geo-fencing alone would have blocked the NL sign-in
2. **Push-based MFA in use** — vulnerable to fatigue; FIDO2/certificate-based MFA would have been unphishable
3. **No device compliance enforcement** — `isManaged: false` should have failed at policy
4. **No alerting on inbox rule creation** — two rules created in 90 seconds with `ForwardTo` to an external domain went unflagged
5. **Browser-stored passwords** — the upstream credential leak that enabled everything downstream
6. **No dark web credential monitoring** — would have caught the credential exposure before it was used

---

## Tools & Techniques

- **Microsoft Sentinel** for log access and KQL execution
- **KQL operators used:** `where`, `between`, `summarize`, `count()`, `countif()`, `make_set()`, `hourofday()`, `parse_json()`, `mv-expand`, `extend`, `tostring()`, `project`, `distinct`, `order by`
- **Azure AD result codes:** `0` (success), `50074` (MFA required), `50140` (KMSI interrupt)
- **Tables:** `SigninLogs` (auth layer), `CloudAppEvents` (data plane), `EmailEvents` (mail flow)

---

## Lessons Learned

A few takeaways worth carrying forward into real IR work:

- **Scope before you query.** When the briefing gives a time window, use it. Searching 90 days when the attack window is 3 hours produces noise, not signal.
- **Identity tables and activity tables use different vocabularies.** `SigninLogs.AppDisplayName` and `CloudAppEvents.Application` describe the same services with different strings. Cross-reference both.
- **Aggregate before you drill.** `summarize` with `countif()` exposes anomalies far faster than eyeballing raw rows.
- **Read every column in every result.** Q03, Q04, Q12, Q13, Q14, Q16, Q19, and Q20 were all answered as side effects of queries written for other questions.
- **Hints disambiguate, they don't override.** When the natural reading of a question doesn't match the data, the hint usually clarifies *how the platform logs the event*, not the underlying concept.
- **Containment ordering matters.** Revoke sessions before resetting passwords. A password reset doesn't kill an active token.
- **Attribution lives outside the logs.** The data tells you the technique; threat intel context tells you the group.

And one final lesson the lab gave us for free: **always read the browser tab name.** Sometimes the threat actor is named right there in plain sight from question one.

---

## Final Score

29 of 29 flags solved.
