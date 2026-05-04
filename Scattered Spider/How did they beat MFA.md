# Hunt 02 — How Did They Beat MFA?

A KQL-driven investigation into a Business Email Compromise (BEC) incident at **LogN Pacific Financial Services**. The attacker hijacked a finance department user's account via an MFA fatigue attack and redirected £24,500 of company funds.

This writeup covers Section 01 — identifying the compromise, the attacker, and how MFA was defeated.

---

## Environment

| | |
|---|---|
| **Platform** | Microsoft Sentinel |
| **Workspace** | `law-cyber-range` |
| **Tables** | `SigninLogs`, `CloudAppEvents`, `EmailEvents` |
| **Attack Window** | 25 Feb 2026, 21:00 UTC → 26 Feb 2026, 00:00 UTC |
| **Target** | Finance department |

---

## The Brief

> *"We have a confirmed BEC. £24,500 redirected. Finance say they got an email from Mark Smith with updated banking details. Mark reported weird MFA notifications last night. He approved one to make them stop. I need you in the sign-in logs. Confirm the compromise, find the attacker's infrastructure. Clock is running."* — IR Lead

---

## Q01 — Compromised Account

**Goal:** Identify the compromised user's UPN.

**Approach:** The IR Lead named "Mark Smith" but never gave the email format. Searching `UserDisplayName contains "Mark Smith"` returned nothing — most users in `SigninLogs` show as hashed strings, not real names. Casting a wider net across both display name and UPN (looking for either "mark" OR "smith") surfaced him immediately.

```kql
SigninLogs
| where TimeGenerated > ago(90d)
| where UserDisplayName contains "mark" 
    or UserDisplayName contains "smith"
    or UserPrincipalName contains "mark"
    or UserPrincipalName contains "smith"
| distinct UserDisplayName, UserPrincipalName
```

<img width="466" height="126" alt="image" src="https://github.com/user-attachments/assets/d2481226-e735-43cc-b0b5-174fb032dfc3" />


**Flag:** `m.smith@lognpacific.org`

> **Lesson:** When a name search returns nothing, the issue is usually UPN format (initials, dots, different domain), not missing data. Always search across multiple identity fields with OR conditions.

---

## Q02 — Attacker Source IP

**Goal:** Find the IP the attacker authenticated from.

**Approach:** Once the attack window from the brief was applied (`25 Feb 21:00 → 26 Feb 00:00 UTC`), the IP candidates collapsed quickly. Filtering to that 3-hour window and counting sign-ins per IP shows the brute force pattern immediately — one IP with the *failed* attempts that match an MFA fatigue attack, then the success.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize 
    Attempts = count(),
    Failures = countif(ResultType != 0),
    Successes = countif(ResultType == 0),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by IPAddress, Location
| order by Attempts desc
```
<img width="1439" height="156" alt="image" src="https://github.com/user-attachments/assets/dee28b50-d491-4a60-abdd-5d0538f3a3a6" />

The result that stands out: **`205.147.16.190` (NL)** — multiple failures *followed by* a success in a tight window, from a country Mark has never logged in from. That is the MFA fatigue signature.

**Flag:** `205.147.16.190`

> **Lesson:** When the brief gives you a time window, use it. Searching 90 days of `SigninLogs` produced 13 candidate IPs; scoping to the 3-hour attack window made the attacker obvious. Counting failures vs successes per IP is a far better anomaly signal than raw login counts.

---

## Q03 — Attack Origin Country

**Goal:** Identify the country the attack came from.

**Approach:** Already in the data from Q02 — the `Location` field on `205.147.16.190` was `NL` across every event.

**Flag:** `NL` (Netherlands)

> **Lesson:** A good investigative query often answers more than just the question in front of you. Always look at *all* the columns, not just the one you came for.

---

## Q04 — MFA Denial Error Code
 
**Goal:** Identify the Azure AD error code logged when MFA was required.
 
**Approach:** Now that the attacker IP is confirmed (`205.147.16.190`), drill into every sign-in event from that IP within the attack window and group by result code. The codes preceding the success tell the story of what the attacker hit.
 
```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| summarize Count = count() by ResultType, ResultDescription
| order by Count desc
```
 
The result shows:
- `0` — successful sign-ins (after the user approved)
- `50140` — *"This occurred due to 'Keep me signed in' interrupt"* (failed/interrupted attempts)
- **`50074`** — *"Strong Authentication is required"* (MFA challenge issued)
`50074` is the code Azure AD logs when MFA is required but not yet satisfied — the entry point of the fatigue attack.
 
**Flag:** `50074`

<img width="789" height="226" alt="image" src="https://github.com/user-attachments/assets/e15a452e-f49b-4424-8921-68a325dc9ab3" />

---

## Q05 — MFA Fatigue Intensity

**Goal:** Count how many MFA push requests Mark denied before he approved one.

**Approach:** This one had a twist. The natural reading is "count `50074` events" — but that gave 1 (or 2 with a wider window), both wrong. The hint clarified: count **all failed entries** before the successful auth. That includes `50140` ("Keep me signed in" interrupts), not just `50074`.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType != 0
| where TimeGenerated < datetime(2026-02-25 21:59:52)
| project TimeGenerated, ResultType, ResultDescription
| order by TimeGenerated asc
```


**Flag:** `3`

<img width="957" height="198" alt="image" src="https://github.com/user-attachments/assets/df67be55-a8f2-4547-9ec6-91d9560dd157" />


> **Lesson:** When the question's natural interpretation doesn't match the data, the answer is in *how the platform logs the event*, not in your understanding of the attack. Real-world IR has the same friction.

## Q06 — Application Accessed

**Goal:** Identify the application the attacker successfully signed into.

**Approach:** Filter to the attacker's IP within the attack window and look at successful sign-ins only (`ResultType == 0`). The `AppDisplayName` field tells us which app the auth was for.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, AppDisplayName, ResultType
| order by TimeGenerated asc
```

The first successful sign-in at 21:59:52 lands on **One Outlook Web** — the attacker's first foothold was Mark's mailbox. Classic BEC entry point: get into the inbox, set up forwarding rules, redirect financial conversations.

**Flag:** `One Outlook Web`

<img width="1555" height="296" alt="image" src="https://github.com/user-attachments/assets/036e72bf-6ca8-464d-8866-7875e193048f" />

## Q07 — Attacker Operating System

**Goal:** Identify the OS the attacker used.

**Approach:** Azure AD parses device info into the `DeviceDetail` JSON field on every sign-in. Pull it from the successful auth event and look at the `operatingSystem` property.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, DeviceDetail
| take 1
```

`DeviceDetail` returns:
```json
{"deviceId":"","operatingSystem":"Linux","browser":"Firefox 147.0","isCompliant":false,"isManaged":false}
```

Mark is a finance user who normally signs in from corporate Windows or Mac endpoints. A Linux session — combined with `isManaged: false` (not a corporate device) — is a strong anomaly indicator on its own, even before the IP and country are factored in.

**Flag:** `Linux`

<img width="933" height="176" alt="image" src="https://github.com/user-attachments/assets/cc8571a2-a79d-4699-a01d-9515dd6d9df1" />

## Q08 — Attacker Browser

**Goal:** Identify the browser used (in the format Azure logs it).

**Approach:** Already visible in the `DeviceDetail` JSON pulled for Q07 — the `browser` property reads `Firefox 147.0`.

The trap on this one was *format*. The `UserAgent` field on the same event shows `Firefox/147.0` (with a slash, classic UA string format). The challenge specifically pointed to `DeviceDetail`, where Azure normalizes it as `Firefox 147.0` (with a space). Submitting the slash version was rejected.

**Flag:** `Firefox 147.0`

> **Lesson:** When a hint points to a specific field, use that field exactly. The same data gets normalized differently depending on where Azure stores it.
