# PRACTICEHunt 03 — Q01 — Identifying the Exposed Asset

**Goal:** Anchor the investigation to the specific virtual machine visible in the leaked LinkedIn photo.

**Approach:** Read the Azure portal screenshot. The VM's hostname is shown directly under the breadcrumb at the top of the management blade, and reinforced in the Properties pane under `Computer name`.

**Flag:** `azwks-phtg-02`

# PRACTICEHunt 03 — Q02 — Public Exposure Vector

**Goal:** Identify the public IP address attached to the exposed VM — the actual reachable surface from the internet.

**Approach:** Read the Networking section of the Azure portal screenshot. The `Public IP address` field on the VM's NIC reads `74.249.82.162`, confirmed by the matching `Primary NIC public IP` in the Essentials pane.

**Flag:** `74.249.82.162`

> **Lesson:** A VM hostname leak is embarrassing; a public IP leak is exploitable. Hostnames don't route — they're naming for humans. An IP is the actual ingress point, and once it's public, every scanner on the internet can reach it within minutes. From this single value, an attacker can run port scans, service fingerprinting, CVE matching, and credential spraying without ever needing to resolve DNS or know the company exists. This is the pivot point where an OSINT leak becomes a network-level threat.
