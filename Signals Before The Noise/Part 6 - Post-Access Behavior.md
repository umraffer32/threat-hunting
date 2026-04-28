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

# PRACTICEHunt 03 — Q24 — Sensitive Text File

**Goal:** Identify which text file opened during the operator session contains internal security-relevant content that would meaningfully reduce an attacker's effort if reviewed.

**Approach:** This question burned an attempt and a 25-point hint before landing — and the lesson is in *why* the architectural-document framing felt right but wasn't.

### Data collection — find every notepad invocation with a file argument

The 0-point hint pointed at `notepad.exe` command lines:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12 13:30:00) .. datetime(2025-12-12 23:00:00))
| where DeviceName == "azwks-phtg-02"
| where FileName == "notepad.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

Four notepad launches with file arguments came back — all spawned by `explorer.exe` (the operator double-clicking files in File Explorer), all in a 16-second window:

<img width="1406" height="189" alt="image" src="https://github.com/user-attachments/assets/f42b659d-a587-4d2e-887d-1883621e701c" />



### Attempt 1 — `PHTG_Project_Notes_azwks-phtg-02.txt` (wrong)

The reasoning: looking at what the operator did *after* reading these files would point to the one that gave them actionable intel.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12 13:46:23) .. datetime(2025-12-12 14:30:00))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessAccountName == "vmadminusername"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

The follow-up activity surfaced an obvious cluster:

<img width="882" height="143" alt="image" src="https://github.com/user-attachments/assets/74e2a688-3f16-41a3-8ec1-8b7f6ff93cd1" />
<br>


That sequence — M365 login, internal SharePoint, Azure VM docs, Azure AD roles — read like an operator following architecture/integration references. A *Project Notes* document for a VM commonly contains exactly that: SharePoint site URLs, AAD role references, integration architecture. The match felt very strong.

A `DeviceFileEvents` pivot also showed `PHTG_Project_Notes_*` and `PHTG_ToDo_*` being continuously regenerated (lab simulation scripts), with identical SHA256s across all instances — meaning they're static lab content, not Sarah's actively-edited working files. The two files Sarah *was* actively editing at 4:11 and 4:16 AM (`Notes 12122025.txt` and `notes_sarah.txt`) got dismissed as "scratchpad" content. **That dismissal was the mistake.**

**Submitted `PHTG_Project_Notes_azwks-phtg-02.txt` — rejected.**

### Hint reveal — *"Pick the one whose name suggests an admin's own working file"*

The 25-point hint reframed the entire question. The framing wasn't about *what content reduces attacker effort* (where architectural docs win) — it was about *which file is the admin's own personal working space* (where personal notes win).

The naming reasoning becomes obvious in retrospect:
- `Notes 12122025.txt` — dated daily notes (today's task list, not personal)
- `PHTG_Project_Notes_*` — project documentation (organizational artifact)
- `PHTG_ToDo_*` — VM-specific task list (organizational artifact)
- **`notes_sarah.txt`** — *literally named after the admin* — her own personal long-running notes file

### Attempt 2 — `notes_sarah.txt` (correct)

**Flag:** `notes_sarah.txt`

> **Lesson:** The trap on this question was a wrong threat model. The "Project Notes" reasoning assumed an attacker's value comes from *architectural references* — SharePoint URLs, role definitions, integration docs. That's true, but it's *secondary* value. The *primary* value of a compromised admin's host is the admin's own working files, because that's where unsanitized credentials, hostnames, half-finished commands, "TODO: rotate this," API tokens copy-pasted as scratchpad text, and connection strings live. Engineers write personal notes for themselves with zero security hygiene — they're the dirtiest, highest-value document on any compromised admin workstation, not the polished organizational documentation.
>
> The detection-engineering takeaway: when telemetry shows an attacker accessing files on a compromised admin's box, weight files in this order for "what was potentially leaked": (1) personal notes / scratchpad files in the user's profile, (2) browser saved-passwords / cookies, (3) SSH keys / .azure / .aws config dirs, (4) project documentation. Most defenders prioritize (4) because it sounds important; attackers go for (1) because it's actually useful. The naming pattern matters too — files named after the user (`notes_sarah.txt`, `creds.txt`, `passwords.docx`) or the user's role (`mypasswords.xlsx`) are higher-priority alerts when accessed by anomalous processes than generic project documentation files.
>
> The process lesson layered in: when reasoning about ambiguous content questions, the available follow-up activity (the SharePoint/AAD URLs in this case) is a tempting signal but can be misleading. The operator could browse SharePoint and Azure AD docs because they read about them in *any* of the four files — or for general orientation reasons unrelated to those files at all. Process telemetry showed the actions but not which file *caused* which action. The naming convention of the files themselves was actually a stronger signal than the post-hoc URL pattern, and the hint had to bring me back to that.

# PRACTICEHunt 03 — Q25 — First Executable Form

**Goal:** Identify the first renamed filename where the extension turns the file into a Windows executable.

**Approach:** The question references "the payload file" — context that hadn't been established yet, so the first move was to find every `FileRenamed` event during the operator session and look for a chain where a single file's extension evolves over time. Classic attacker tradecraft: download a payload with an innocuous extension to bypass any "no .exe downloads" gate, then progressively rename it.

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-12 13:30:00) .. datetime(2025-12-12 23:00:00))
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, ActionType, FileName, PreviousFileName, FolderPath, InitiatingProcessFileName
| order by TimeGenerated asc
```

The result surfaced a clean rename chain on a file named `Sarah_Chen_Notes`:

<img width="1363" height="304" alt="image" src="https://github.com/user-attachments/assets/a9480080-c8d2-4f11-90fe-fd841ce57226" />


The progression tells the full story: Edge finalized a download as `.Txt` (the `.crdownload` suffix is the in-progress download marker browsers use), the operator renamed it manually in Explorer to add `.exe.Txt` as a sneaky double-extension form, then renamed it again to drop the `.Txt` entirely — leaving `Sarah_Chen_Notes.exe` as the final executable form.

The question hinged on which rename "turns the file into a Windows executable." Windows reads only the *final* extension when deciding how to handle a file. `Sarah_Chen_Notes.exe.Txt` looks like it has `.exe` in the name, but Windows treats it as a text file because `.Txt` is the actual extension. Only the final rename to `Sarah_Chen_Notes.exe` makes the file double-clickable as a PE executable.

**Flag:** `Sarah_Chen_Notes.exe`

> **Lesson:** Double-extension renaming is a classic payload-staging trick that defeats both lazy security controls and lazy users. The pattern is reliable enough to detect on directly: any `FileRenamed` event where `PreviousFileName` ends in a benign extension and `FileName` ends in a Windows executable extension (`.exe`, `.dll`, `.bat`, `.cmd`, `.ps1`, `.scr`, `.vbs`, `.js`, `.hta`, etc.) is high-signal. Add a parent-process filter for `explorer.exe` to catch hands-on-keyboard renaming specifically — automated processes don't usually rename files this way.
>
> The `.crdownload` suffix is the artifact that lets you pivot from a renamed file back to the originating browser download. Browsers (Chrome, Edge, Brave, Opera) all use `.crdownload` while a download is in progress and rename to the final filename on completion. So a `FileRenamed` event with `PreviousFileName` ending in `.crdownload` and `InitiatingProcessFileName` set to a browser is the **download finalization** — the canonical "this file just arrived from the internet" event. Pair that with the subsequent rename chain and you have the entire payload-arrival sequence captured in three or four telemetry rows.
>
> The double-extension form (`Sarah_Chen_Notes.exe.Txt`) is also a Windows-specific user-interface attack — by default, Windows Explorer hides "known file extensions," meaning a user sees `Sarah_Chen_Notes.exe` displayed for a file actually named `Sarah_Chen_Notes.exe.Txt`. Combined with a custom icon, this is how attackers trick users into thinking a `.exe` is a `.txt`. The defensive response is the same as it's been for 20 years: turn on "show file extensions" in every user's Explorer, every time. Most orgs still don't.

