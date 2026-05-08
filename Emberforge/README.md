<img width="1536" height="1024" alt="emberforge" src="https://github.com/user-attachments/assets/90845804-8160-42da-b9e9-60b6c11be065" />
<br>

# 🎮 Threat Hunt Report — EmberForge

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



<details>
<summary>Q01 — Target Directory</summary>

**Goal:** Identify the source directory the attacker compressed before exfiltration.

**Approach:** The attacker packaged data before stealing it, so compression commands in the logs point straight to the target. Searched for common compression tools across the investigation window, starting broad and narrowing by tool name.

Initial searches for `rar`, `7z`, and `zip` using `has_any` returned nothing — a `has_any` gotcha, since it matches whole tokens and some of those terms were embedded inside longer strings. Switching to `Compress-Archive` (PowerShell's built-in cmdlet) landed the hit.

```kql
EmberForgeX_CL
| where TimeGenerated >= datetime(2026-02-10)
| where TimeGenerated < datetime(2026-02-11)
| where CommandLine_s has_any ("tar", "compress", "archive", "Compress-Archive")
```

Two rows came back on the server (EC2AMAZ-16V3AU4) at 10:38:27 PM, both logging the same command:

```
powershell.exe -c "Compress-Archive -Path C:\GameDev -DestinationPath C:\Users\Public\gamedev.zip"
```

The `-Path` argument is the source — `C:\GameDev`. The `-DestinationPath` staged the archive in `C:\Users\Public\`, a world-writable directory, ready for exfiltration.

**Flag:** `C:\GameDev`

> **Lesson:** `has_any` in KQL matches whole tokens, not substrings. If your search term might appear embedded inside a path or argument (like `7z` inside a filename), use `contains` or `has` on individual values instead. Also worth noting: when the flag format says "full path," they want just the clean directory — no flags, no destination arguments, no quotes.

</details>
