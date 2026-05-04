# Hunt 02 — How Do We Catch This Next Time?

Section 06 — the post-mortem. The fraud is contained, the attacker's actions are mapped, and the IOCs are captured. The IR Lead's final question shifts from *what happened* to *what failed in our defenses*. This section identifies the missing controls and maps the attack chain to MITRE ATT&CK for downstream detection engineering.

---

## Q24 — Conditional Access Status

**Goal:** Determine whether Conditional Access policies were evaluated on the attacker's successful sign-in.

**Approach:** The `ConditionalAccessStatus` field on every `SigninLogs` row records whether any CA policy was applied to that authentication. Pull it for the attacker's successful sign-in:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| distinct ConditionalAccessStatus
```

The result: **`notApplied`**. No Conditional Access policy was evaluated on this sign-in — meaning no location restrictions, no device compliance enforcement, no risk-based MFA escalation, and no session controls intervened. Azure AD authenticated an unmanaged Linux/Firefox session originating from the Netherlands without challenge.

<img width="413" height="165" alt="image" src="https://github.com/user-attachments/assets/29c564c5-924c-4abd-8a10-cd6f6a77b553" />


**Flag:** `notApplied`

> **Lesson:** This is the single biggest defensive failure in the incident, and it's the answer to the IR Lead's question *"Could we have stopped this?"* — **yes, trivially, with policy that didn't exist.** Any of the following Conditional Access controls would have broken the attack chain:
>
> - **Block sign-ins from non-corporate countries** — Mark works in the UK; the auth was from NL. A geo-fencing policy would have blocked at the front door.
> - **Require compliant or hybrid-joined devices for finance users** — `DeviceDetail.isManaged` was `false`. A device compliance requirement on the Finance Azure AD group would have rejected the auth regardless of MFA outcome.
> - **Require phishing-resistant MFA (FIDO2 / certificate-based)** — push notifications are vulnerable to fatigue attacks. A policy requiring FIDO2 for finance roles makes "approve to make it stop" impossible.
> - **Sign-in risk policies** — Microsoft Entra ID Protection would almost certainly have flagged this auth (impossible travel, unfamiliar location, anonymous IP) as `medium` or `high` risk. A policy that blocks or step-ups on `medium+` risk catches it.
>
> When writing the post-incident report, "Conditional Access not applied to high-risk roles" is the headline finding. Everything downstream — the MFA fatigue, the inbox rules, the £24,500 wire — was enabled by this single configuration gap.

## Q25 — MFA Fatigue MITRE ID

**Goal:** Map the MFA fatigue technique to MITRE ATT&CK.

**Approach:** Pure recall — no query needed. MITRE ATT&CK catalogs MFA push bombing under **T1621 – Multi-Factor Authentication Request Generation**, sitting under the *Credential Access* tactic.

**Flag:** `T1621`

> **Lesson:** Knowing the MITRE ID is what turns an incident report into something a SOC can act on. Detection engineers map ATT&CK techniques to KQL/Sigma rules; tabletop exercises drill against them; threat intel feeds tag campaigns by them. For T1621 specifically, the canonical detection is *"more than N MFA challenges within M minutes for the same user from the same IP, followed by a success"* — which is exactly the pattern Q05 walked through in this investigation.

## Q26 — Email Rules MITRE ID

**Goal:** Map the inbox rule defense evasion to MITRE ATT&CK (technique + sub-technique).

**Approach:** Recall, no query. MITRE catalogs malicious email rules under **T1564.008 – Hide Artifacts: Email Hiding Rules**, a sub-technique of T1564 (Hide Artifacts). It sits under the *Defense Evasion* tactic and specifically covers using inbox rules to delete, move, or forward messages to conceal malicious activity from the legitimate user.

**Flag:** `T1564.008`

> **Lesson:** The full attack chain in this incident maps to four MITRE techniques across four tactics:
>
> | Phase | Technique | Tactic |
> |---|---|---|
> | MFA bombing | `T1621` – Multi-Factor Authentication Request Generation | Credential Access |
> | Account takeover | `T1078.004` – Valid Accounts: Cloud Accounts | Defense Evasion / Persistence / Initial Access |
> | Inbox rule cleanup | `T1564.008` – Email Hiding Rules | Defense Evasion |
> | Email exfiltration | `T1114.003` – Email Collection: Email Forwarding Rule | Collection |
>
> A clean MITRE mapping turns the writeup from a story into a detection backlog. Every ID above maps to specific KQL hunting queries, Sigma rules, and Sentinel analytics templates that already exist in public threat intel repositories — and every one of them would have caught this attack if deployed before the incident, not after.
