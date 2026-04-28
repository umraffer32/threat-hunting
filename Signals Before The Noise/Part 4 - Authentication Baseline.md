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
