# Hunt 02 — What Did They Leave Behind?

Section 02 of the LogN Pacific BEC investigation. With initial access confirmed, the focus shifts from *how* the attacker got in to *what they did once inside* — recon, persistence, and the fraudulent send. This section moves out of `SigninLogs` and into `CloudAppEvents`, the table that logs O365 data-plane activity (mailbox operations, rule creation, file access).

---

## Q09 — First Post-Auth Action

**Goal:** Identify the very first action the attacker performed after authenticating.

**Approach:** Switch tables to `CloudAppEvents` and filter on the same attacker IP (`205.147.16.190`) within the attack window. Sort ascending by timestamp and look at the first `ActionType`. Note: `CloudAppEvents` uses `Timestamp`, not `TimeGenerated` — a common gotcha when pivoting between tables.

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| project Timestamp, ActionType, AccountDisplayName, Application
| order by Timestamp asc
| take 10
```

The first event at `9:56:24 PM` is **`MailItemsAccessed`** — the attacker's first move inside Mark's mailbox was *reading*, not exfiltrating or sending. That sequencing matters: it tells us the attacker was doing reconnaissance before acting, looking for the right financial thread to hijack.

The full sequence in the first 11 minutes paints the entire BEC playbook:

| Time | Action | Translation |
|---|---|---|
| 9:56:24 PM | `MailItemsAccessed` | Reading Mark's inbox (recon) |
| 9:57:53 PM | `MailItemsAccessed` | More reading |
| 10:02:33 PM | `New-InboxRule` | Setting up persistence |
| 10:03:59 PM | `New-InboxRule` | Second rule |
| 10:04:34 PM | `Create` + `Send` | Fraudulent email going out |
| 10:07 PM+ | SharePoint / OneDrive access | Hunting for more financial docs |

**Flag:** `MailItemsAccessed`

<img width="851" height="375" alt="image" src="https://github.com/user-attachments/assets/e2e87a68-4fa0-4fb2-b4c1-992f48ad661b" />

> **Lesson:** `CloudAppEvents` is where post-auth O365 activity lives — mailbox reads, rule creation, file access, sends. When `SigninLogs` runs out, this is the next pivot. Also worth noting: `AccountDisplayName` shows `Mark Smith` for control-plane actions (PowerShell, rule creation) but a session GUID for data-plane operations like `MailItemsAccessed`. Same actor, different log shape.

## Q10 — Rule Creation Method

**Goal:** Identify the `ActionType` Azure logs when an inbox rule is created.

**Approach:** Already visible in the Q09 results — at `10:02:33 PM` and `10:03:59 PM`, the attacker triggered an `ActionType` of `New-InboxRule`. That's the underlying PowerShell cmdlet name, which O365 logs verbatim whether the rule was created via Outlook UI, OWA, or direct Exchange Online PowerShell. No new query needed.

**Flag:** `New-InboxRule`

> **Lesson:** Inbox rules are a top-tier BEC persistence mechanism — silent, durable, and rarely audited by users. Detection engineering tip: alert on any `New-InboxRule` event where the rule body contains keywords like `delete`, `move to RSS`, or external forward addresses. That signature catches BEC persistence with very low false positive rates.

## Q11 — Forward Rule Name

**Goal:** Identify the exact name of the forwarding inbox rule the attacker created.

**Approach:** This one took three iterations. The challenge hint pointed at the `RawEventData` JSON, but didn't say *which* of the two `New-InboxRule` events held the forward rule — that had to be reasoned out.

### Step 1 — Pull the raw rule JSON

Start by examining `RawEventData` on the rule creation events:

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project Timestamp, RawEventData
```

The first rule we expanded had `SubjectOrBodyContainsWords: "suspicious, security, phishing, unusual, compromised, verify"` and `DeleteMessage: True` — that's a **delete** rule, not a forward rule. Wrong one. The challenge title said **Forward Rule Name**, so we needed to look at the *other* event.

<img width="1075" height="215" alt="image" src="https://github.com/user-attachments/assets/bacfc883-118e-4cee-b994-c68c9fc8f723" />


### Step 2 — Compare both rule names side by side

Before opening the second rule's JSON, isolate just the `Name` parameter from both events at once:

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend Params = parse_json(RawEventData).Parameters
| mv-expand Params
| where tostring(Params.Name) == "Name"
| project Timestamp, RuleName = tostring(Params.Value)
```

Two distinct names came back:

| Timestamp | RuleName |
|---|---|
| 10:02:33 PM | `.` (one dot) |
| 10:03:59 PM | `..` (two dots) |

The format hint — *"may be a single character"* — was the tell that the answer was likely the single-dot rule, not the two-dot one. But we still needed to confirm *which rule does the forwarding* before submitting.

<img width="422" height="148" alt="image" src="https://github.com/user-attachments/assets/d9368514-3699-4233-87d9-2921575e17fb" />


### Step 3 — Confirm by inspecting the second rule

Going back to the Step 1 query and expanding the `10:02:33 PM` rule's `RawEventData` showed the smoking gun in its Parameters array:

- `ForwardTo`: `insights@duck.com`
- `Name`: `.`
- `SubjectOrBodyContainsWords`: `invoice, payment, wire, transfer`
- `StopProcessingRules`: `True`

That confirmed it: the `.` rule is the forwarder, the `..` rule is the cleanup.

<img width="1063" height="213" alt="image" src="https://github.com/user-attachments/assets/014dc784-65e5-430a-8cc9-bab35969f29d" />
<br>

**Flag:** `.`

### The Full Persistence Architecture

| Rule | Name | Trigger Words | Action |
|---|---|---|---|
| 10:02:33 PM | `.` | invoice, payment, wire, transfer | **Forward to `insights@duck.com`** |
| 10:03:59 PM | `..` | suspicious, security, phishing, unusual, compromised, verify | **Delete from inbox** |

The two rules work as a system. Rule one silently exfiltrates anything finance-related to the attacker's external mailbox. Rule two deletes any incoming warning emails — so when finance, IT, or security try to flag the fraud, Mark's inbox never shows the alert. The fraud stays invisible to the legitimate user even after the attacker is long gone.

> **Lesson:** When the challenge title contradicts what your first query result implies, trust the title and keep digging. "Forward Rule" was the keyword — once that lined up with the rule containing `ForwardTo`, the right answer fell out. Also, single-character or punctuation-only rule names are a real-world red flag pattern: detection rules should treat any inbox rule with a name shorter than 3 characters or consisting only of punctuation as suspicious by default.

## Q12 — Forward Destination

**Goal:** Identify the external email address receiving forwarded messages.

**Approach:** Already visible in the Q11 investigation. The forward rule's `Parameters` array included `ForwardTo: insights@duck.com` — that's the attacker-controlled inbox catching every email matching the finance keyword filter.

**Flag:** `insights@duck.com`

> **Lesson:** This is the single most actionable IOC in the entire incident. Block the domain at the email gateway, audit every mailbox in the tenant for inbox rules referencing `duck.com` (or any suspicious external domain), and add it to the deny list immediately. Forward destinations are gold for both containment and threat hunting across the rest of the org.

## Q13 — Forward Keywords

**Goal:** Identify the keywords the forward rule filtered on.

**Approach:** Already visible from the Q11 investigation. The forward rule's Parameters array included `SubjectOrBodyContainsWords: "invoice, payment, wire, transfer"` — exactly the financial vocabulary you'd expect for invoice fraud.

**Flag:** `invoice, payment, wire, transfer`

> **Lesson:** Keyword lists are a window into attacker intent. `invoice, payment, wire, transfer` is unambiguous BEC — they want financial threads. Other keyword sets to watch for in the wild: credential phishing rules tend to filter on `password, reset, login, MFA`; data theft rules on `confidential, NDA, contract, M&A`. If you see an inbox rule whose `SubjectOrBodyContainsWords` reads like a category instead of a topic, that's the rule moving the data.

## Q14 — Rule Processing Flag

**Goal:** Identify the rule parameter that prevents any subsequent rules from processing the matched emails.

**Approach:** Already visible from the Q11 investigation. The forward rule's Parameters array included `StopProcessingRules: True`. When set, Exchange halts rule evaluation as soon as this rule matches — no other inbox rules see the email afterward. That means even if Mark had his own rules (a "flag suspicious emails" filter, for example), they'd never fire on anything matching the attacker's keyword list.

**Flag:** `StopProcessingRules`

> **Lesson:** `StopProcessingRules: True` combined with `DeleteMessage: True` or `ForwardTo` on a rule the user didn't create is a near-certain BEC signature. Threat hunters can flag this combination directly: any rule containing both flags, created by a session not matching the user's normal IP/device pattern, deserves a deep look. This single combination of parameters is what makes inbox-rule-based BEC so resilient — the attacker's logic always wins, the user's safety nets never trigger.
