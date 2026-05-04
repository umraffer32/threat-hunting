# Hunt 02 — What Do We Do First?

Section 08 — the operational close. The investigation is mapped, the IOCs are captured, the kill chain is documented. Now the IR Lead asks the only question that matters in the moment: *with the attacker still holding a valid session right now, what's the single most important thing we do?* This section is about decisions, not queries.

---

## Q28 — Immediate Containment

**Goal:** Identify the first containment action when an attacker still holds an active session in a compromised account.

**Approach:** No query — pure IR decision-making. Recall what Q23 established: every attacker action in this incident hangs off a single `AADSessionId` (`00225cfa-a0ff-fb46-a079-5d152fcdf72a`). That session is the attacker's foothold. Reset Mark's password and the session keeps working. Disable the inbox rules and the attacker creates new ones. Disable the account entirely and Mark loses access to his own work alongside the attacker. The surgical first move is to invalidate the session itself, forcing the attacker to re-authenticate (which they can't do without triggering MFA again, and now Mark is alert).

In Microsoft Entra ID, this is the **Revoke sessions** action — a button in the user's admin pane that invalidates every active token tied to the account. PowerShell equivalent is `Revoke-AzureADUserAllRefreshToken`. Industry IR documentation (Palo Alto Unit 42, Prophet Security, ReliaQuest) uniformly recommends this as the first containment step in BEC, ahead of password reset.

**Flag:** `Revoke Sessions`

> **Lesson:** Containment ordering matters. The instinct in a panic is to reset the password first — but a password reset doesn't kill an active session. The attacker's refresh token, issued during the original successful auth, remains valid until either it expires naturally or it gets explicitly revoked. Doing the password reset first means buying yourself the illusion of containment while the attacker keeps operating uninterrupted. The correct sequence is: (1) revoke sessions to kill the active foothold, (2) reset the password to prevent re-authentication with the known credential, (3) require MFA re-registration to invalidate the trusted-device record from the fatigue-approved push, (4) disable the malicious inbox rules, (5) audit for any other persistence the attacker may have established. Step one is what Q28 is testing.

## Q29 — Threat Actor Attribution

**Goal:** Identify the threat group behind the campaign.

**Approach:** No query needed — and frankly, no investigation either. The lab tab in every Sentinel screenshot from Q01 onward read `Scattered Sp...*`. The challenge wasn't being subtle. The threat group's name was sitting in the browser tab the entire time, gently mocking us as we hunted MFA fatigue events and parsed inbox rules.

The TTPs in the briefing are also unambiguous on their own:
- **MFA fatigue / push bombing** — group's signature initial access technique
- **BEC targeting finance** — common monetization path
- **Anonymizing infrastructure (NL VPS, Linux/Firefox)** — operational pattern
- **MGM Resorts and Caesars Entertainment (2023)** — the breaches that put this group on every CISO's radar

This group is tracked under multiple names: **Scattered Spider** (CrowdStrike, Mandiant), **UNC3944** (Mandiant's internal designator), **Octo Tempest** (Microsoft), and **Muddled Libra** (Palo Alto Unit 42). All four labels refer to the same financially motivated cluster — predominantly young, English-speaking operators known for slick social engineering, help-desk impersonation, and an unusually high tolerance for direct confrontation with victims (a behavioral fingerprint that's actually used as a soft attribution signal).

**Flag:** `Scattered Spider`

> **Lesson:** Attribution rarely lives in the logs. The data tells you the *technique* — MFA fatigue, inbox rules, infostealer-sourced credentials — but the name on the wanted poster comes from threat intel context: which groups use this exact playbook, which industries they target, what infrastructure they favor. For Scattered Spider specifically, the canonical detection profile is: English-speaking social engineering against help desk + MFA bombing + cloud-native persistence + financial sector or hospitality targeting. If three of those four light up in a single incident, attribution is reasonable even without malware samples or C2 overlap. And if the lab literally names the browser tab after them, attribution is *very* reasonable.
