# PRACTICEHunt 03 — Q30 — Why Did It Run?

**Goal:** Identify the change to Defender's operating state that allowed the payload to execute after being quarantined three times earlier in the same hour.

**Approach:** The Q29 result already hinted at the answer — the `ReportSource` field in `AdditionalFields` read `Windows Defender Antivirus passive mode`. To confirm the *transition* (active → passive) and not just the steady state, project `ReportSource` alongside the timeline:

```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| extend ReportSource = tostring(parse_json(AdditionalFields).ReportSource)
| project TimeGenerated, ActionType, ReportSource, AdditionalFields
| order by TimeGenerated asc
```

The chronological view tells the full story:


<img width="1549" height="376" alt="image" src="https://github.com/user-attachments/assets/036344dd-2b1a-4069-8599-97f32cc50431" />
<br>


Before 2:18 PM, Defender was actively neutralizing the payload at every step of its rename chain (`Sarah_Chen_Notes.Txt` → `Sarah_Chen_Notes.exe.Txt` → `Sarah_Chen_Notes.exe`). At 2:18:52 PM, the operating mode flipped from active to **passive**, and the next detection events show Defender continuing to *detect* the file but no longer blocking it. That single operating-state change is what allowed execution to proceed.

### Format consideration

The `ReportSource` value in the raw telemetry rendered as `Windows Defender Antivirus passive mode` (all lowercase, embedded in a longer string). Microsoft's official documentation capitalizes the operating mode as `Passive mode` (sentence case). Going with the Microsoft-canonical form on first submission landed on first try.

**Flag:** `Passive mode`

> **Lesson:** This question reveals the actual exploit — and it's not technical. The attacker didn't bypass Defender; they **disabled** it. Switching Defender from active to passive mode is a privileged operation (admin rights required, accomplished via PowerShell `Set-MpPreference -DisableRealtimeMonitoring $true` or by registering a different AV product as primary). The fact that the operator could flip this state means they had local admin on the box — which they did, because `vmadminusername` was the local administrator account they brute-forced into. Once you have admin on a Windows host, Defender is configurable, not enforceable.
>
> The detection-engineering implication is exactly the inverse of the defensive lesson: **monitor for Defender operating-state transitions as a high-priority alert.** Any event where `ReportSource` changes from `active` to `passive` (or where `Set-MpPreference` is invoked from PowerShell, or where the registry keys under `HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\` get modified) should fire immediately. By the time AV stops detecting things, the attacker is already in.
>
> Two more layered observations: (1) The transition happened *after* three successful quarantines in seven minutes — meaning the operator saw their first three drops fail, then escalated to disabling AV before redropping. That's a tell about operator skill (they understood what was killing the payload and knew where to apply pressure). (2) The detections continued to fire in passive mode — Defender kept *seeing* the threat, it just couldn't act on it. That's actually a gift to defenders: even when AV is disarmed, the telemetry flow doesn't stop. Hunting `AntivirusDetectionActionType` events with `ReportSource` containing "passive mode" surfaces every host where AV is currently disarmed, regardless of whether the attacker ever gets caught any other way. That's a one-line query for a fleet-wide health check on Defender posture.

# PRACTICEHunt 03 — Q31 — First Execution

**Goal:** Identify the filename the payload ran under during its first execution phase.

**Approach:** Pivot from file telemetry to process telemetry, filtering on the SHA256 hash from Q27 to track execution events independently of whatever filename was active at the time. Sort chronologically and look for the phase break that the question hints at.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

<img width="1437" height="250" alt="image" src="https://github.com/user-attachments/assets/4cf3c13b-0b04-4c9e-82d9-878c7eddf825" />
<br>

The result split cleanly into two phases:

| Phase | Time Range | FileName | Path | Parent |
|---|---|---|---|---|
| **Phase 1** | 12/12 2:18 PM – 12/13 10:13 AM | `Sarah_Chen_Notes.exe` | `C:\Users\vmAdminUsername\Documents\PHTG\` | `explorer.exe` |
| Phase 2 | 12/13 10:21 AM onward | `PHTG.exe` | `C:\ProgramData\PHTG\HealthCloud\` | `cmd.exe` |

Phase 1 is operator-driven manual execution — `explorer.exe` as parent means the operator double-clicked the file four separate times across roughly 20 hours. Phase 2 is scripted execution from a different location with `cmd.exe` as parent, consistent with persistence-driven launches. The phase break aligns exactly with the rename and relocation event from Q28 (`Sarah_Chen_Notes.exe` → `PHTG.exe` at 10:16 AM on 12/13).

**Flag:** `Sarah_Chen_Notes.exe`

> **Lesson:** The two-phase execution pattern — manual `explorer.exe`-spawned execution followed by scripted `cmd.exe`-spawned execution from a different path — is the signature of an attacker transitioning from hands-on-keyboard validation to persistence. Phase 1 is the operator confirming the payload runs and behaves correctly under their direct control. Phase 2 is the payload being launched by whatever persistence mechanism the operator installed once they were satisfied (scheduled task, service, registry Run key, Startup folder shortcut — all of which spawn child processes through `cmd.exe`, `svchost.exe`, or the persistence mechanism's own loader). The parent-process change combined with the path change is a stronger signal than either alone: same hash, different parent, different folder = persistence handoff. Detection rules that track execution counts of a given hash across distinct parent processes catch this transition reliably, and the phase break itself is often the cleanest forensic anchor for "when did this stop being a manual intrusion and start being persistent malware?"

# PRACTICEHunt 03 — Q32 — Parent Process

**Goal:** Identify the parent process that launched the payload during the later execution phase.

**Approach:** Already surfaced by the Q31 result. Phase 1 (manual operator execution as `Sarah_Chen_Notes.exe`) was launched by `explorer.exe`. Phase 2 (scripted execution as `PHTG.exe` from `C:\ProgramData\PHTG\HealthCloud\`) was launched by `cmd.exe` — the parent-process shift that signaled the transition from hands-on-keyboard to persistence-driven execution.

**Flag:** `cmd.exe`

# PRACTICEHunt 03 — Q33 — Batch File Wrapper

**Goal:** From the Phase 2 `cmd.exe` command line, extract the full path of the `.bat` file that ran the payload.

**Approach:** The hint pointed at the format `cmd.exe /c <something>` — meaning the batch path is the argument after `/c`. Filter `DeviceProcessEvents` to `cmd.exe` invocations during the Phase 2 window with `.bat` in the command line.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 10:21:00) .. datetime(2025-12-13 11:00:00))
| where DeviceName == "azwks-phtg-02"
| where FileName == "cmd.exe"
| where ProcessCommandLine has ".bat"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

<img width="1098" height="139" alt="image" src="https://github.com/user-attachments/assets/5178c444-2c01-4817-8e8f-bf8cb5b67483" />
<br>

Two matching rows came back — both with command line `cmd.exe /c "C:\ProgramData\PHTG\HealthCloud\Launch.bat"`, both spawned by `explorer.exe` under `vmadminusername`. The batch file lives in the same `HealthCloud` directory as the renamed `PHTG.exe` payload — identical blending strategy, both files dropped into the legitimate service path to inherit whatever trust the directory has.

**Flag:** `C:\ProgramData\PHTG\HealthCloud\Launch.bat`

> **Lesson:** Wrapping a payload in a `.bat` file launched via `cmd.exe /c` is a small but deliberate evasion choice. Direct execution of `PHTG.exe` would log a process tree of `explorer.exe → PHTG.exe` — a clean parent-child relationship pointing straight at the payload. Wrapping in a batch file produces `explorer.exe → cmd.exe → PHTG.exe`, which (a) breaks the visual signal that "the user ran the .exe directly" because the immediate parent is now a benign Windows shell, (b) lets the attacker stage prep commands (env vars, working directory changes, log redirection) before the payload fires without leaving them as separate process events, and (c) defeats simplistic "alert on direct execution from `C:\ProgramData\` by user account" rules because the user is technically launching `cmd.exe`, not the suspicious binary. The detection lift is the same as Q28's lesson: pivot on the *hash*, not the parent. Any `.exe` running from a service directory under a user account context is suspicious regardless of whether `cmd.exe` is in the chain. And the `.bat` itself is now a high-value forensic artifact — its contents will reveal whether the operator built additional staging logic (network calls, env setup, sleep/loop patterns) on top of just running the payload.

# PRACTICEHunt 03 — Q34 — C2 IP

**Goal:** Identify the external IP the compromised device attempted to communicate with after the payload executed.

**Approach:** Pivot back to `DeviceNetworkEvents`, but filter on `InitiatingProcessSHA256` rather than process name — the payload ran under two different filenames across the two phases (`Sarah_Chen_Notes.exe` and `PHTG.exe`), but the SHA256 is constant. Restrict to public destinations only to drop internal noise.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-12 14:18:00) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessSHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where RemoteIPType == "Public"
| project TimeGenerated, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
| order by TimeGenerated asc
```

<img width="1009" height="166" alt="image" src="https://github.com/user-attachments/assets/471c36e1-05ec-4e72-8b30-bb5806977a56" />
<br>

Three rows came back — one for each of the three execution attempts (Phase 1: 12/12 2:19 PM, Phase 1 retry: 12/13 10:13 AM, Phase 2: 12/13 10:22 AM). All three pointed at the same destination: **`173.244.55.130:4444`**, all logged as `ConnectionFailed`.

The signal density on this single result is high. The C2 IP `173.244.55.130` lives in the same `173.244.55.0/24` as the brute-force and successful-auth IPs from Phase 04 (`173.244.55.128` and `173.244.55.131`) — the auth infrastructure and the C2 infrastructure are *neighbors*, almost certainly hosted on the same VPS provider under the same operator account. Port `4444` is the default Metasploit Meterpreter handler port, which corroborates the Q29 detection (`Trojan:Win32/Meterpreter`) — default tooling, default port, no operator effort spent on opsec. The `ConnectionFailed` action type on every attempt means the C2 server wasn't reachable when the payload called home — either the listener wasn't running, the operator had taken it down, or upstream egress controls blocked the connection.

**Flag:** `173.244.55.130`

> **Lesson:** This is the question where the entire kill chain stitches together into one narrative: the same /24 that hosted the brute-force traffic, the successful auth, and now the C2 callback. That kind of cross-phase IP correlation is the gold standard for attribution within a single incident — it ties auth-layer evidence to network-layer evidence to process-layer evidence and lets you say *"this is one operator, this is one piece of infrastructure, this is one attack."* The detection-engineering takeaway is to monitor for any internal host beaconing to a /24 that recently appeared in successful-auth telemetry — if a brand-new external network range authenticates against your environment and that same range later appears as an outbound C2 destination, that's the same actor on both ends, not two unrelated events. Port `4444` is also a free signal: any outbound connection to `4444/tcp` from a workstation should fire, since legitimate enterprise software almost never uses that port and any commodity offensive framework using its default settings does. The combination of "outbound to recent-auth /24 + commodity C2 port + executable in `C:\ProgramData\<service>\`" is a near-zero-false-positive analytic that catches the entire pattern in one rule.

# PRACTICEHunt 03 — Q35 — C2 Geography

**Goal:** Identify the country and continent of the C2 infrastructure.

**Approach:** Geo-enrich the C2 IP from Q34 against the same GeoTable used throughout the hunt. Since the IP was a single value, no need to pivot through `DeviceNetworkEvents` — just feed it directly into `ipv4_lookup`.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
print RemoteIP = "173.244.55.130"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| project RemoteIP, country_name, continent_name
```

<img width="527" height="127" alt="image" src="https://github.com/user-attachments/assets/f9ebe5ed-540f-44eb-84d8-aa8f6868c47b" />
<br>

Result: **Uruguay, South America** — same country as the successful auth IPs (`173.244.55.128` and `173.244.55.131`), same /24, same continent. The full kill chain — credential brute-force, successful auth, payload C2 — all originates from a single contiguous block of Uruguayan infrastructure.

**Flag:** `Uruguay, South America`

> **Lesson:** Geographic confirmation across phases closes the attribution loop. When the brute-force IP, the successful-auth IP, and the C2 IP all geo-resolve to the same country *and* live in the same /24, the case for "single operator, single infrastructure rental, single coordinated attack" is essentially airtight. From a detection standpoint, this kind of cross-phase consistency is the difference between a noisy alert chain and a high-confidence incident: any one phase in isolation could be coincidence (random scanner, random C2 destination, random successful auth), but three phases tied to one /24 cannot be coincidental. Building incident-correlation rules that bucket events by source-IP /24 and look for activity spanning multiple kill-chain phases (auth + network + process telemetry) catches sophisticated actors who rotate individual IPs but reuse the same hosting infrastructure across an operation.

# PRACTICEHunt 03 — Q36 — C2 Remote Port

**Goal:** Identify the remote port the post-execution payload used for C2 callback.

**Approach:** Already surfaced in the Q34 result. All three connection attempts from the payload (across both execution phases) targeted `173.244.55.130` on port **4444** — the default Metasploit Meterpreter handler port, consistent with the `Trojan:Win32/Meterpreter` family classification from Q29.

**Flag:** `4444`

> **Lesson:** Default-port C2 is a free detection win for defenders. Port 4444 is the default Metasploit Meterpreter listener; 5555 is the default for some Cobalt Strike configurations; 8080 is overloaded but commonly seen with commodity frameworks. None of these ports have legitimate enterprise outbound use cases on workstations — alerting on any outbound connection from a non-server host to a public IP on these ports catches commodity offensive tooling at near-zero false-positive cost. The fact that this operator left the Meterpreter handler on the default port (and didn't even bother with HTTPS-style port reuse on 443) is consistent with the rest of their tradecraft: brute-forced default admin account, default Metasploit payload, default port. The operator was efficient, not careful.

