# Q01 — Identifying the Exposed Asset

**Goal:** Anchor the investigation to the specific virtual machine visible in the leaked LinkedIn photo.

**Approach:** Read the Azure portal screenshot. The VM's hostname is shown directly under the breadcrumb at the top of the management blade, and reinforced in the Properties pane under `Computer name`.

**Flag:** `azwks-phtg-02`

# Q02 — Public Exposure Vector

**Goal:** Identify the public IP address attached to the exposed VM — the actual reachable surface from the internet.

**Approach:** Read the Networking section of the Azure portal screenshot. The `Public IP address` field on the VM's NIC reads `74.249.82.162`, confirmed by the matching `Primary NIC public IP` in the Essentials pane.

**Flag:** `74.249.82.162`

> **Lesson:** A VM hostname leak is embarrassing; a public IP leak is exploitable. Hostnames don't route — they're naming for humans. An IP is the actual ingress point, and once it's public, every scanner on the internet can reach it within minutes. From this single value, an attacker can run port scans, service fingerprinting, CVE matching, and credential spraying without ever needing to resolve DNS or know the company exists. This is the pivot point where an OSINT leak becomes a network-level threat.

# Q03 — When Context Becomes Actionable

**Goal:** Identify which piece of leaked information gives an external threat actor the clearest immediate path to action.

**Approach:** Read the multiple-choice options through the lens of *attacker workflow*. OS version, VM size, region, and management tags are all useful context — but none of them are reachable. A public IP is different: it's the routable address an attacker types into `nmap`, `masscan`, or a brute-force tool. Without it, every other detail is academic.

**Flag:** `D`

> **Lesson:** "Information disclosure" findings get triaged by what an attacker can *do* with them, not by how sensitive they sound. Hostname, OS, region — those are passive context. A public IP is active surface. When writing up an OSINT exposure, lead with the routable identifiers (IPs, FQDNs, exposed ports) because those are what convert a leak into a live attack path. Everything else is enrichment for the exploitation phase, not the access phase.

# Q04 — OSINT Correlation

**Goal:** Classify the activity visible on the leaked workstation screen.

**Approach:** Look at what's actually on the monitors. The screen shows the Azure portal open to a VM's management blade — Properties, Networking, Size panes all visible. That's not code, not a SIEM, not a metrics dashboard, not documentation. It's a cloud engineer doing cloud engineering: managing infrastructure resources directly through the cloud provider's console.

**Flag:** `C`

> **Lesson:** OSINT classification matters because it tells you *what an attacker now knows about your operations*. A photo of someone coding leaks development practices. A photo of an incident response screen leaks tooling and detection capability. A photo of cloud infrastructure management leaks asset inventory, naming conventions, subscription structure, and — as in this case — exact routable identifiers. Each activity type maps to a different threat model, and the worst leak is usually the one that exposes live, addressable production assets. That's the category PHTG is now sitting in.

# Q05 — Evidence Source Selection

**Goal:** Pick the right telemetry source to determine whether the exposed public IP was scanned or enumerated.

**Approach:** Reason from the question backwards. Scanning and enumeration are *network-layer* activities — packets arriving at the public IP, connection attempts, port probes. That rules out anything operating at the application layer (event logs, browser history), the identity layer (sign-in logs), or the inventory layer (MDE device list). The only option that captures inbound connections at the network plane is Azure network/platform analytics. In this lab, that's the `DeviceNetworkEvents` table — which logs `ConnectionAttempt`, `InboundConnectionAccepted`, and related actions against the host.

**Flag:** `D`

> **Lesson:** Pick the telemetry source that matches the *layer* of activity you're hunting. Authentication telemetry tells you who got in; process telemetry tells you what they ran; file telemetry tells you what they wrote. But none of those answer "did anyone knock on the door?" That question lives in network telemetry, and specifically in the records of inbound connection attempts. When the hypothesis is "exposure was discovered," the network table is always the first stop — successful auth and post-exploitation activity only matter once you've confirmed someone was looking.

---

[⬆ Back to Table of Contents](./README.md#table-of-contents)
