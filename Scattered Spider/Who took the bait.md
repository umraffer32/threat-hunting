# Hunt 02 — Who Took The Bait?

Section 04 of the LogN Pacific BEC investigation. Persistence is mapped. Now we follow the money — find the fraudulent email itself, identify who received it, and capture the IOCs (subject, direction, sender IP) for downstream containment.

This section pivots to a new table: **`EmailEvents`**, which logs every email that flowed through the tenant (sender, recipient, subject, direction, network metadata).

---

## Q17 — BEC Target

**Goal:** Identify the recipient of the fraudulent invoice email.

**Approach:** Filter `EmailEvents` to mail sent from the compromised account *and* from the attacker's IP within the attack window. The IP filter is critical — without it, Mark's legitimate sends would also appear in the results, drowning the signal.

```kql
EmailEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where SenderFromAddress == "m.smith@lognpacific.org"
| where SenderIPv4 == "205.147.16.190"
| project Timestamp, RecipientEmailAddress, Subject, EmailDirection, SenderIPv4
| order by Timestamp asc
```

Exactly one row came back — sent at `10:06:39 PM` to **`j.reynolds@lognpacific.org`**. That's the finance recipient who acted on the fake banking details.

<img width="953" height="264" alt="image" src="https://github.com/user-attachments/assets/8d8fed85-ac9a-423c-b561-508180d0c943" />


**Flag:** `j.reynolds@lognpacific.org`

> **Lesson:** When pivoting to a new table mid-investigation, always anchor your filter on something *specific* to the malicious activity — not just the user. Filtering only on `SenderFromAddress` would have returned every email Mark sent that day, including legitimate ones. Adding `SenderIPv4 == "205.147.16.190"` reduced the result to a single row: the attacker's send. The principle generalizes — when an attacker uses a compromised identity, your filter has to separate *the identity's normal activity* from *the attacker's activity through that identity*. IP, device fingerprint, and time-of-day are the usual separators.

## Q18 — BEC Subject Line

**Goal:** Capture the exact subject line of the fraudulent email.

**Approach:** Already returned in the Q17 query results. The `Subject` field on the malicious email read `RE: Invoice #INV-2026-0892 - Updated Banking Details`.

**Flag:** `RE: Invoice #INV-2026-0892 - Updated Banking Details`

> **Lesson:** Two details in this subject line carry weight. First, the `RE:` prefix — the attacker hijacked an existing email thread instead of opening a new conversation. That's why the recon phase (`MailItemsAccessed`) mattered so much: the attacker needed to find a real, ongoing invoice thread to reply to. To Reynolds, this email looked like a continuation of an existing legitimate conversation, not a cold ask. Second, `Updated Banking Details` is the payload framing — innocuous-sounding administrative language that makes the fraud feel like routine vendor maintenance. Both are textbook social engineering moves.

## Q19 — Email Direction

**Goal:** Determine whether the fraudulent email was sent externally or internally.

**Approach:** Already returned in the Q17 query. The `EmailDirection` field on the malicious email read `Intra-org` — sent from one mailbox in the tenant to another, never traversing the external email gateway.

**Flag:** `Intra-org`

> **Lesson:** This is why BEC via account takeover is so effective. Most enterprise email security stacks (Defender for O365, Proofpoint, Mimecast) apply their heaviest scrutiny to **inbound external** mail — link rewriting, attachment sandboxing, anti-spoofing, banner injection. Intra-org mail typically bypasses all of it because the assumption is that internal senders are trusted. Once an attacker has valid credentials and an authentic mailbox to send from, the email gateway becomes irrelevant. Defense has to shift to behavioral signals — anomalous send patterns, new external forward rules, sign-ins from unusual geographies — not content scanning.

## Q20 — BEC Sender IP

**Goal:** Confirm the IP address that sent the fraudulent email.

**Approach:** Already returned in the Q17 query. The `SenderIPv4` field on the malicious email read `205.147.16.190` — identical to the attacker's sign-in IP from Section 01.

**Flag:** `205.147.16.190`

> **Lesson:** This is the cross-correlation that ties the entire incident together. The same IP that brute-forced MFA, signed in at `9:59:52 PM`, accessed the mailbox, created the inbox rules, and sent the fraudulent invoice — all from `205.147.16.190`. One session, one IP, one continuous attack chain. In real-world IR, this kind of single-IP correlation is rare (mature attackers rotate infrastructure between phases), but when it does line up cleanly, it makes attribution and timeline reconstruction trivial. Capture this IP everywhere — sign-in logs, mailbox audit, email headers — and the case writes itself.
