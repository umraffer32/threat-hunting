# Hunt 02 — What Else Did They Access?

Section 05 of the LogN Pacific BEC investigation. Email fraud is confirmed and contained on paper — but BEC is rarely just about one email. The IR Lead's question now: did the attacker exfiltrate anything *else*? File stores, shared drives, sensitive documents? Scoping the full blast radius is the difference between a contained incident and a slow-burning data breach.

This section returns to **`CloudAppEvents`**, this time filtering for file-access `ActionType`s instead of mailbox operations.

---

## Q21 — Cloud App Accessed

**Goal:** Identify the cloud application the attacker accessed beyond email.

**Approach:** Filter `CloudAppEvents` to the attacker's IP within the attack window, scoped to file-related actions. The `Application` field tells us which cloud service the access landed on.

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType in ("FileAccessed", "FileDownloaded", "FilePreviewed", "FileSyncDownloadedFull")
| project Timestamp, ActionType, Application, ObjectName
| order by Timestamp asc
```

A `FileAccessed` event landed at `10:07:16 PM` — under a minute after the fraudulent email was sent — on **`Microsoft OneDrive for Business`**. The `ObjectName` URL points at Mark's personal OneDrive root: `.../personal/m_smith_lognpacific_org/Documents/Forms/All.aspx`. That `All.aspx` path is OneDrive's full-library browse view, meaning the attacker was scanning every file Mark had stored, not opening a specific known document.

<img width="1254" height="227" alt="image" src="https://github.com/user-attachments/assets/31f0c759-66fd-4f52-a2b9-90419311091a" />

**Flag:** `Microsoft OneDrive for Business`

> **Lesson:** BEC investigations frequently stop at "the fake invoice was sent" — but a session with valid credentials usually does more than one thing. The attacker had `9:59 PM` to whenever the session expired, and they used it to browse OneDrive looking for more material. In real-world response, you scope BEC by listing every cloud app touched during the attacker's session window: Exchange, SharePoint, OneDrive, Teams, Power Platform. Each one extends the breach surface and adds to the regulatory disclosure picture.

## Q22 — SharePoint App Accessed

**Goal:** Identify the SharePoint application the attacker authenticated to.

**Approach:** This question burned five wrong submissions before landing the flag, and the lesson learned is more valuable than the flag itself. The challenge instructions said *"Query SigninLogs for the attacker's IP"* — but the platform's flag checker was looking for a value that lives in `CloudAppEvents`, not `SigninLogs`. Two tables, two naming conventions for the same activity.

### Step 1 — Follow the instructions (wrong table)

The question pointed at `SigninLogs`, so the first query mirrored the Q06 approach:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| distinct AppDisplayName
```

Four candidates returned: `One Outlook Web`, `Office 365 SharePoint Online`, `SharePoint Online Web Client Extensibility`, `OfficeHome`. With Q06 already claiming `One Outlook Web`, the obvious next pick was **`Office 365 SharePoint Online`**. **Rejected.**

<img width="440" height="199" alt="image" src="https://github.com/user-attachments/assets/8b8295e3-c743-4f1e-abe5-ff460d97a73c" />


### Step 2 — Try the other SharePoint candidate

The 35-point hint confirmed *"The application name contains SharePoint. Submit the full application display name as shown in the logs."* That should have made **`SharePoint Online Web Client Extensibility`** correct. **Rejected.**

### Step 3 — Try OfficeHome

With both SharePoint candidates burned, the only remaining `AppDisplayName` worth attempting was **`OfficeHome`**. **Rejected.**

### Step 4 — Pivot to `ResourceDisplayName`

At this point all the SigninLogs `AppDisplayName` values were exhausted (with `One Outlook Web` already taken by Q06). Pulled in the `ResourceDisplayName` column to see if the answer lived in a related field:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| distinct AppDisplayName, ResourceDisplayName
```

This surfaced **`Office 365 Exchange Online`** as the resource backing the Outlook session — a value that hadn't appeared in any earlier query. **Rejected.**

<img width="537" height="196" alt="image" src="https://github.com/user-attachments/assets/0ac0a3b1-0341-4d79-a3d5-da091f109769" />


### Step 5 — One last guess from frustration

With every reasonable candidate burned and the SharePoint hint contradicting every SharePoint-related submission, **`One Outlook Web`** went in as a frustration shot. **Rejected.**

### Step 6 — Pivot to `CloudAppEvents`

The breakthrough came from re-reading Q21's answer pattern: `Microsoft OneDrive for Business`. That string never appeared in `SigninLogs` at all — it only existed in `CloudAppEvents.Application`. If Q21's flag came from there, Q22's might too, regardless of what the question text said.

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| distinct Application
```

Three values came back:
- `Microsoft Exchange Online`
- `Microsoft OneDrive for Business`
- **`Microsoft SharePoint Online`** ← never seen in `SigninLogs`

<img width="382" height="177" alt="image" src="https://github.com/user-attachments/assets/ad57d75c-144b-48be-96b5-7ae172c92424" />


That was the flag.

**Flag:** `Microsoft SharePoint Online`

### The Real Lesson — Two Tables, Two Naming Conventions

`SigninLogs` is an **identity** table. Each row describes an *authentication event* — the auth surface the user logged into. Its `AppDisplayName` field uses values like `One Outlook Web` (the OWA login flow), `OfficeHome` (the office.com portal), `SharePoint Online Web Client Extensibility` (a background OAuth token grant). These are *auth client names*.

`CloudAppEvents` is an **activity** table. Each row describes *something a user did inside a cloud workload*. Its `Application` field uses values like `Microsoft Exchange Online`, `Microsoft OneDrive for Business`, `Microsoft SharePoint Online`. These are *workload product names*.

The same user action — "the attacker accessed SharePoint" — produces:
- A `SigninLogs` row with `AppDisplayName = SharePoint Online Web Client Extensibility` (or `Office 365 SharePoint Online`, depending on the auth flow)
- A `CloudAppEvents` row with `Application = Microsoft SharePoint Online`

Microsoft's identity stack and its workload stack do not share a naming convention. The same service shows up under different strings depending on which lens you're querying through.

> **Lesson:** Never trust a single log table to authoritatively name "what app was accessed." Cross-reference at minimum `SigninLogs` (auth layer) and `CloudAppEvents` (data layer). When scoping containment — disabling apps, auditing data access — the **workload-layer name** is what matters, because that's what your tenant administration tools and DLP policies key off of. When hunting authentication anomalies — token theft, unusual OAuth grants — the **identity-layer name** matters, because that's where the auth flow is logged. Same incident, two lenses, two vocabularies. Pick the lens that matches the question being asked, not the one the instructions point you at.

## Q23 — Session Correlation

**Goal:** Identify the single session ID that ties every attacker action together — sign-in, mailbox access, rule creation, fraudulent send, and file browsing.

**Approach:** Two queries — one to extract the session ID from the inbox rule's `RawEventData`, one to confirm it matches the successful sign-in. If both return the same GUID, the entire attack chain is provably one continuous session.

### Step 1 — Pull the SessionId from the inbox rule events

The session ID is buried inside `RawEventData` under `AppAccessContext.AADSessionId`. Parse the JSON and project it:

```kql
CloudAppEvents
| where Timestamp between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| extend SessionId = tostring(parse_json(RawEventData).AppAccessContext.AADSessionId)
| project Timestamp, SessionId
```

Both rule events returned the same session: `00225cfa-a0ff-fb46-a079-5d152fcdf72a`.

<img width="559" height="155" alt="image" src="https://github.com/user-attachments/assets/a30a0c7b-8fa2-4472-ab16-eccbb404d833" />


### Step 2 — Confirm it matches the successful sign-in

`SigninLogs` exposes `SessionId` directly as a column, no JSON parsing needed:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-02-25 21:00:00) .. datetime(2026-02-26 00:00:00))
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, SessionId
| distinct SessionId
```

Same GUID. The successful authentication at `9:59:52 PM`, the mailbox reads, both inbox rules, the fraudulent send to Reynolds, and the SharePoint/OneDrive browsing — all share `00225cfa-a0ff-fb46-a079-5d152fcdf72a`.
<br>
<img width="322" height="113" alt="image" src="https://github.com/user-attachments/assets/3ae836ad-71bb-42b7-bfc8-18f8baca754e" />


**Flag:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

> **Lesson:** `AADSessionId` is the most powerful pivot in any Azure AD-based incident. From a single GUID you can pull every authentication event, every mailbox operation, every file access, every admin action — all provably tied to one token. In real-world IR this matters for two reasons. **For containment**, revoking the session (via `Revoke-AzureADUserAllRefreshToken` or the Conditional Access "sign-in risk" trigger) instantly kills every downstream operation. **For attribution and legal**, the session ID is what lets you say "all of these actions were the same actor in the same authenticated context" — not separate incidents that happened to share an IP. When writing IR reports, lead with the session ID; everything else hangs off it.
