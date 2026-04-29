# Q37 — Repurposed Baseline

**Goal:** Identify the legitimate internal service whose directory the attacker repurposed to host the final payload.

**Approach:** No new query needed — the answer was already established by Q28 (the file path `C:\ProgramData\PHTG\HealthCloud\PHTG.exe`) and the hunt briefing itself, which explicitly described HealthCloud: *"PHTG rolled out HealthCloud on 11 December 2025 as an internal endpoint health service. Scheduled PowerShell tasks, background service executables, diagnostic cache directories under C:\ProgramData\PHTG\HealthCloud\."* Every clue in the question lines up: legitimate internal service ✓, rolled out the same week (11 Dec, attack on 12–13 Dec) ✓, payload inside a directory belonging to it ✓.

**Flag:** `HealthCloud`

> **Lesson:** This is the question that retroactively reframes the entire hunt. The HealthCloud rollout wasn't background context — it was the **operational opportunity** the attacker exploited. A brand-new service directory landing on every PHTG endpoint in the same week as the breach gave the operator perfect cover: the directory exists by design, has a documented purpose, hosts legitimate executables and scheduled tasks, and almost certainly sits in EDR allowlists, AV exclusions, and admin baselines because *that's exactly what the rollout team would have configured to keep their own service from being flagged*. Dropping `PHTG.exe` into that directory inherits all of that trust. The detection-engineering takeaway is sharp: every legitimate service rollout is also a *blending opportunity* for whoever is already inside the environment, and the trust configurations applied to support the rollout (allowlists, exclusions, scheduled task whitelists) need to be paired with **integrity controls** on the directories they cover. File-creation events in `C:\ProgramData\PHTG\HealthCloud\` should fire alerts unl

---

[⬆ Back to Table of Contents](./README.md#table-of-contents)
