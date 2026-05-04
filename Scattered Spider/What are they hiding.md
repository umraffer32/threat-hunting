# Hunt 02 — What Are They Hiding?

Section 03 of the LogN Pacific BEC investigation. The forward rule explained how the attacker exfiltrated finance emails. This section focuses on the *cleanup* rule — the second piece of the persistence architecture, designed to keep the victim and the security team blind to the attack as it unfolds.

---

## Q15 — Delete Rule Name

**Goal:** Identify the name of the second inbox rule — the one that deletes incoming alerts.

**Approach:** Already surfaced during the Q11 investigation. The earlier query that enumerated `Name` parameters across all `New-InboxRule` events returned two distinct rules:

| Timestamp | RuleName | Purpose |
|---|---|---|
| 10:02:33 PM | `.` | Forward finance emails to attacker |
| 10:03:59 PM | `..` | Delete incoming security alerts |

The `..` rule had `DeleteMessage: True` paired with keywords like `suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify` — exactly the language a finance team or IT security would use when raising the alarm about the fraudulent invoice. By auto-deleting those replies, the attacker ensures Mark never sees the warnings, and the fraud stays invisible until someone notices the missing money.

**Flag:** `..`

> **Lesson:** Sophisticated BEC isn't just about getting the money out — it's about staying invisible long enough for the wire to clear. The forward rule is the offense; the delete rule is the defense. Detection engineers should treat *paired rule creation events* (two `New-InboxRule` events from the same session within minutes) as a much stronger signal than either rule alone.

## Q16 — Delete Keywords

**Goal:** Identify the keywords the delete rule filtered on.

**Approach:** Already surfaced from the Q11 investigation. The `..` rule's Parameters array included `SubjectOrBodyContainsWords: "suspicious, security, phishing, unusual, compromised, verify"` — the vocabulary of a security alert or a concerned colleague trying to flag the fraud.

**Flag:** `suspicious, security, phishing, unusual, compromised, verify`

> **Lesson:** Compare this keyword list to the forward rule's (`invoice, payment, wire, transfer`). Together they tell you exactly what the attacker is doing and what they're afraid of:
> - **Forward keywords** = what they're stealing (financial conversations)
> - **Delete keywords** = what they're hiding from (incident response language)
> 
> When triaging a suspected BEC, the delete rule's keywords often reveal the attacker's threat model — what they expect detection to look like. That's intel you can use to harden response workflows for the next incident.
