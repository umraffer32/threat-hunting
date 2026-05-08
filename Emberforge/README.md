# Emberforge

## IR-2026-0131-EF: Source Code Breach & Domain Compromise

On January 30, 2026, unreleased source code for EmberForge Studios' upcoming title "Neon Shadows" leaked to underground forums. The breach trace led to Lead Artist Lisa Martin's workstation, compromised after she opened a malicious file delivery disguised as a project review. What started as initial access escalated into full domain compromise within hours: the attacker dumped Active Directory credentials, pivoted to the Domain Controller, extracted the NTDS database, and established persistence through backdoor accounts and C2 infrastructure. This writeup traces the complete attack chain across three hosts — from the first malicious DLL load through lateral movement, privilege escalation, and credential theft — documenting each stage of the intrusion for legal scope and breach notification.

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
