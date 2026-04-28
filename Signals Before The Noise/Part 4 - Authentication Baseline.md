# PRACTICEHunt 03 — Q11 — Total External Auth Volume

**Goal:** Count externally sourced authentication events recorded for the device.

**Approach:** First pivot off the network table — Phase 03 shifts from "who knocked" (`DeviceNetworkEvents`) to "who tried to get in" (`DeviceLogonEvents`). The hint confirmed the table switch. "Externally sourced" maps to `RemoteIPType == "Public"`, but after the Q07 trap, it was worth running a diagnostic groupby first to see the full distribution and confirm no blank-cell drops were going to bite again.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| summarize EventCount = count() by RemoteIPType, ActionType, LogonType
| order by EventCount desc
```

<img width="697" height="464" alt="image" src="https://github.com/user-attachments/assets/2d1c0271-9587-45d3-bc69-e20a5d22fac4" />


The breakdown showed three populations:

| RemoteIPType | Total |
|---|---|
| Public | 693 |
| *(blank)* | 746 |
| Private | 19 |

The blank rows clustered on `LogonType` values like `Batch`, `Interactive`, and `Unknown` — all local logon types that have no remote IP because they didn't come from the network. Unlike Q07, where the blank-cell trap meant we were dropping legitimate inbound events, here the blank cells *are* genuinely not externally sourced. The filter is correct as written.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| count
```
<img width="614" height="139" alt="image" src="https://github.com/user-attachments/assets/a130a766-d751-4174-938f-5fc1b5d9842d" />

**Flag:** `693`

> **Lesson:** A blank `RemoteIPType` means different things in different tables, and the difference matters. In `DeviceNetworkEvents`, blank `RemoteIPType` on `ConnectionAttempt` rows was a *classification gap* — those were real inbound public events that just didn't get tagged (the Q07 trap). In `DeviceLogonEvents`, blank `RemoteIPType` on `Interactive`/`Batch`/local logon types is *semantically correct* — there's no remote side to classify because the auth happened locally. Same blank cell, opposite implications.
>
> The diagnostic-first habit pays off either way. A `summarize by` that includes the column you're about to filter on tells you not just *what's there* but *what you're about to drop*. If the dropped rows are real events misclassified, your filter is wrong. If the dropped rows are conceptually not part of the population (local logons aren't external), your filter is right. You can't tell which without looking — and looking costs one extra query.
>
> The volume itself is also worth pausing on: 693 external auth events against a single workstation in 14 days is far above any realistic legitimate baseline. A normal user signs in a handful of times a day, almost always from the same handful of IPs. Hundreds of external auth events on one host is the unmistakable signature of brute-force activity, and it's the cue to start carving the data by failure reason, source IP, and account name in the next questions.

# PRACTICEHunt 03 — Q12 — RDP Auth Volume

**Goal:** Count externally sourced authentication events related to Remote Desktop on the device.

**Approach:** This question burned an attempt and a 15-point hint before landing — and the lesson is in *why* the obvious read of the 0-point hint sent the answer in the wrong direction.

### Attempt 1 — Network + RemoteInteractive + Unlock (680, wrong)

The 0-point hint said: *"RDP surfaces across more than one logon type depending on how the session progresses."* That read like the lab telling us not to filter on `RemoteInteractive` alone. The natural extension was to think about every logon type RDP can produce as a session progresses through its lifecycle:

- `Network` — pre-auth credential check (NLA / CredSSP) before the desktop session is established
- `RemoteInteractive` — the desktop session itself, after auth completes
- `Unlock` — re-auth when an existing RDP session is unlocked from idle

Diagnostic to confirm the breakdown across the public-sourced rows from Q11:

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("RemoteInteractive", "Network", "Unlock")
| summarize EventCount = count() by ActionType, LogonType
| order by EventCount desc
```

<img width="562" height="208" alt="image" src="https://github.com/user-attachments/assets/d52e8c84-60ab-40fc-ba93-727e55993284" />

Total: 680. Submitted — rejected.

### Reasoning between attempts

With 680 wrong, the candidates left were 13 (RemoteInteractive + Unlock), 34 (successful logons only), or some subset that excluded one of the three types. The cleanest "session progresses" reading was 13 — RemoteInteractive (initial session) → Unlock (later in same session) — because Network logons happen *before* a session exists, not as part of one progressing. But confidence was around 70%, and with one attempt already burned, dropping a second 70% guess would put the question at three attempts. The right move was to unlock the 15-point hint and convert a coin flip into a known answer.

### Hint reveal — `LogonType in ('Network', 'RemoteInteractive')`

The hint explicitly named the two logon types — and notably, **Unlock was not on the list**. The lab's interpretation: Unlock is a *session continuation* event, not an authentication event proper. Even though Unlock involves a credential check, the lab considers it post-auth session management. The "session progresses" language in the 0-point hint was misleading — it was hinting at Network's role as the pre-auth phase, not Unlock's role as the post-auth resumption.

### Attempt 2 — Network + RemoteInteractive

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| count
```

646 + 21 + 8 = **675**.

**Flag:** `675`

> **Lesson:** The 0-point hint was technically true but conceptually misleading. "RDP surfaces across more than one logon type" sent thinking toward "list every logon type RDP can produce" — which includes Unlock. The lab actually meant something narrower: RDP authentication itself fires across two logon types (Network for pre-auth, RemoteInteractive for the session). Unlock is a separate concept — re-establishing presence in an already-authenticated session, not a new auth event.
>
> The detection-engineering implication is sharper than the original framing: when writing rules for "external RDP auth attempts," `LogonType in ("Network", "RemoteInteractive")` is the right base predicate. The brute-force signature lives in the Network rows (646 failures here). The successful initial compromise lives in RemoteInteractive (8 here). Unlock events live downstream of those — useful for tracking *what an authenticated session is doing*, but not for measuring auth attempts. Mixing them inflates your numerator with non-auth events and pollutes baselining.
>
> The process lesson is just as important: when a confident-feeling answer is wrong and the next-best guess is around 70%, paying for the explicit hint is cheaper than burning a third attempt. Two attempts at 100% confidence each beats three attempts at 70% — both in points and in not training yourself to guess. The 15-point hint here cost less than a third question would have, and it eliminated all interpretive ambiguity instead of just narrowing it.

