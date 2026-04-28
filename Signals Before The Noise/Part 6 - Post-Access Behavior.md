# PRACTICEHunt 03 — Q23 — First Notable Process

**Goal:** Identify the first notable process after the first successful Uruguay authentication — the earliest event indicating a person began interacting with the system purposefully.

**Approach:** This question burned two attempts before the right framing emerged. The interpretation problem was severe enough that the path to the answer required completely abandoning the "look for the first user-driven launch from explorer.exe" framework and reaching for a different parent-process pivot entirely.

### Attempt 1 — `powershell.exe` (wrong)

The first instinct was that PowerShell would be the operator's first tradecraft tool — a workstation user opening a PS window from the Start menu is the textbook first move for an attacker on a fresh RDP session.

Initial query — all processes initiated by `vmadminusername` after the first Uruguay logon:

```kql
DeviceProcessEvents
| where TimeGenerated >= datetime(2025-12-12 05:47:45)
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
| take 50
```

<img width="1556" height="597" alt="image" src="https://github.com/user-attachments/assets/6cea3cbb-339c-48e7-8eb9-5622306a1382" />
<br>


The ordered list showed Windows session-init noise (SecurityHealthSystray, OneDrive, Edge auto-launch with `--win-session-start`, OneDrive cleanup `cmd.exe` calls), then a bare `msedge.exe` at 1:33:06 PM, then `powershell.exe` at 1:35:44 PM spawned from `explorer.exe` — the operator opening PowerShell from the Start menu.

**Submitted `powershell.exe` — rejected.**

### Attempt 2 — `msedge.exe` (wrong)

The 25-point hint clarified: *"Scope to after the first Uruguay logon time. Exclude session-init processes. Take the first remaining."* Re-reading that as a chronological filter rather than a tradecraft filter, `msedge.exe` at 1:33:06 PM (parent: `explorer.exe`, no flags) is earlier than the PowerShell launch and looks like the user clicking Edge.

**Submitted `msedge.exe` — rejected.**

### Attempt 3 — `notepad.exe` (correct)

Both `msedge.exe` and `powershell.exe` rejected meant the answer wasn't an `explorer.exe`-spawned process at all. Time to look at the data with both excluded:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12 13:30:00) .. datetime(2025-12-12 14:30:00))
| where DeviceName == "azwks-phtg-02"
| where ProcessCommandLine has_any ("vmAdminUsername", "C:\\Users\\vmAdminUsername") 
    or InitiatingProcessAccountName == "vmadminusername"
| where FileName !in ("msedge.exe", "powershell.exe")
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

That surfaced a sequence of GUI applications launched from PowerShell in rapid succession:

<img width="1560" height="593" alt="image" src="https://github.com/user-attachments/assets/f34515f3-b147-49e0-a352-6cfe4754a859" />
<br>


Notepad, calc, mspaint, and Task Manager launched from `powershell.exe` in six seconds. That is wildly abnormal — a normal user launches these apps from the Start menu (parent: `explorer.exe`), not by typing their names into a PowerShell prompt. This pattern is an operator testing what they can run inside the RDP session — basic capability recon. `notepad.exe` at 1:35:54 PM is chronologically first.

**Flag:** `notepad.exe`

> **Lesson:** The interpretation key for this question was understanding what the lab considers "session-init" vs "operator behavior." The instinct was to treat `powershell.exe` (operator-launched from explorer) as the first operator behavior — but the lab considers that another layer of *infrastructure*, not an operator action. The `powershell.exe` launch is the operator setting up their tooling. The **first thing the operator does with that tooling** is the answer. In this case, `notepad.exe` spawned from PowerShell at 1:35:54 PM.
>
> The detection-engineering takeaway is sharper than the question itself. The pattern *"PowerShell parent + GUI application children in rapid sequence"* is a high-signal anomaly. Normal users don't type `notepad`, `calc`, `mspaint` into a PowerShell window — they click. When PowerShell becomes the parent of GUI apps that have nothing to do with administrative tasks (notepad, calc, mspaint, Task Manager), it's almost always one of two things: a person on the keyboard probing capabilities, or a script using PowerShell as a launcher to obfuscate parent-child relationships from naive detection. Either case is worth alerting on. A simple analytic — `DeviceProcessEvents | where InitiatingProcessFileName == "powershell.exe" and FileName in ("notepad.exe", "calc.exe", "mspaint.exe", "taskmgr.exe", ...)` — produces near-zero false positives in real-world telemetry.
>
> The process lesson also matters. Two confident-feeling attempts both wrong is the signal that the *framework* is wrong, not just the candidate. After Attempt 2, the right move wasn't to pick the next-best item from the list — it was to question whether the right list had even been generated. Adding `where FileName !in ("msedge.exe", "powershell.exe")` made the answer obvious in one query. When stuck, exclude what you've already tried and look at what remains; the answer is often hiding behind the noise floor of your prior assumptions.
