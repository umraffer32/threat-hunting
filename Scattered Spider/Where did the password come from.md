# Hunt 02 — Where Did The Password Come From?

Section 07 — the threat intel coda. Every other section answered *what happened in the logs*. This one zooms out to ask the upstream question: how did the attacker have Mark's password before the MFA fatigue even started? The MFA bombing only works if step one — the password — is already done. This question identifies the supply chain that fed it.

---

## Q27 — Credential Source

**Goal:** Identify the malware category that typically supplies credentials to threat groups running BEC and account takeover operations.

**Approach:** Pure threat intel recall — no query. The question describes malware that *"steals saved passwords, session tokens, and browser data from infected machines"* and feeds those credentials to threat groups via underground markets. That's the textbook description of an **infostealer**: a class of malware (RedLine, Lumma, Vidar, StealC, Raccoon) that silently harvests browser-stored credentials and active session cookies, packages them into "logs," and sells them to Initial Access Brokers (IABs). Threat groups like Scattered Spider don't typically phish or breach to get the initial credential — they *buy* it from the IAB market, where a fresh corporate login costs as little as $10–$100.

**Flag:** `infostealer`

> **Lesson:** This is the most important takeaway in the entire investigation. The MFA fatigue at `9:54 PM` looks like step one of the attack — but it's actually step *three*. Step one was an infostealer infection on some endpoint that had Mark's saved password (his personal laptop, a contractor machine, a family member's PC he used briefly). Step two was the credential appearing in a stealer log on a market like Russian Market or Genesis. Only then did the attacker buy the log, look up the corporate domain, and start hammering MFA prompts.
>
> What this means for defense:
> - **Password complexity is irrelevant** if the password is being stolen post-typing from the browser's password store. Length and entropy don't matter when the malware reads it from disk.
> - **Browser-stored credentials are the single biggest leak point** in modern enterprise. Block browser password storage via Group Policy / Intune; force users into a managed password manager with 2FA on the vault.
> - **Session token theft bypasses MFA entirely** — stealers grab live cookies that the attacker can replay without ever seeing a password or prompt. Phishing-resistant MFA (FIDO2) helps; short session lifetimes and device-bound tokens help more.
> - **Dark web credential monitoring** is no longer optional. Services that scan stealer log dumps for your domain catch exposures *before* the credential gets used. The window between "credential appears in a log" and "attacker uses it" is often days or weeks — that's a real detection opportunity if you're watching.
