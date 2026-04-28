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
