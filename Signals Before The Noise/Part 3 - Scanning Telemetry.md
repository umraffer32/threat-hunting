# PRACTICEHunt 03 — Q06 — Broad Scanning Indicators

**Goal:** Identify the local port with the strongest signal of broad, automated scanning against the exposed VM.

**Approach:** Scope `DeviceNetworkEvents` to the hunt window and the target host, filter to public-source traffic, and aggregate by `LocalPort`. The right anomaly metric is **distinct source IPs per port** — automated scanning fans out across many sources hitting the same port, while legitimate traffic clusters on a few known callers. Count connections, distinct remote IPs, and roll up the action types per port.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| summarize 
    Connections = count(),
    UniqueSourceIPs = dcount(RemoteIP),
    Actions = make_set(ActionType)
    by LocalPort
| order by UniqueSourceIPs desc
| take 10
```

Port `3389` returned 194 connections from 173 distinct public source IPs, all logged as `InboundConnectionAccepted`. Every other port in the result clustered at 4–5 connections from 4–5 sources. The 3389 row is two orders of magnitude above the rest of the distribution — that's not a user, that's the internet.

<img width="644" height="365" alt="image" src="https://github.com/user-attachments/assets/ab5b5d51-b1fe-4fc6-a086-aee364e84218" />


**Flag:** `3389`

> **Lesson:** Raw connection count is a noisy metric — a single chatty client can inflate it. Distinct-source-IP count is the real scanning signature, because automated scanners are characterized by *breadth* (many sources hitting one target) rather than *volume* (one source hitting many times). When triaging exposure on a public-facing host, always aggregate by destination port and look at the source-IP cardinality. Anything more than a handful of distinct public IPs hitting an admin port (3389, 22, 5985, 445) within a short window is scanning until proven otherwise. And RDP on the open internet remains the single most-scanned port on IPv4 — exposing 3389 publicly guarantees discovery within hours of provisioning.
