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

# PRACTICEHunt 03 — Q07 — Exposure Activity Volume

**Goal:** Count the network events targeting port 3389 on the exposed VM.

**Approach:** This question burned two attempts before the hint clarified what "network events targeted the port" actually meant in the lab's framing. The instinct was to read the question broadly — every event involving 3389 in any direction — but the lab wanted the narrow, scan-specific count that carries forward Q06's exact filter chain.

### Attempt 1 — `LocalPort` only, all sources

First read of the question: count every event where 3389 was the local (listening) port on the host. A diagnostic groupby first, to make sure no event class was being silently dropped:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| summarize 
    EventCount = count(),
    UniqueSourceIPs = dcount(RemoteIP)
    by RemoteIPType, ActionType
| order by EventCount desc
```

Three rows came back:

<img width="712" height="177" alt="image" src="https://github.com/user-attachments/assets/ad4fdc1f-9aa5-4c88-8298-93a43efe804f" />


Sum: **325**. Submitted — rejected.

### Attempt 2 — both port directions

Re-read the hint ("filter the network table to the specific port and count the rows"). Considered that "the specific port" might mean port-as-protocol regardless of which side of the connection it sat on, and expanded the filter to cover `RemotePort` as well:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389 or RemotePort == 3389
| summarize EventCount = count() by ActionType, PortRole = case(LocalPort == 3389, "Local=3389", "Remote=3389")
| order by PortRole, EventCount desc
```
<img width="563" height="313" alt="image" src="https://github.com/user-attachments/assets/e3c3138c-babd-4ae6-9f24-151311331883" />

Result added 39 events on `RemotePort == 3389` — `SslConnectionInspected` (22), `ConnectionSuccess` (5), `ConnectionAcknowledged` (4), `HttpConnectionInspected` (4), `InboundInternetScanInspected` (3), `ConnectionFailed` (1). Total: **364**. Submitted — also rejected.

### Attempt 3 — unlock the 15-point hint

The hint said: *Add `| where LocalPort == 3389 | count` to the Q06 query.*

The key word was **the Q06 query** — meaning the query had to be extended *as written*, including its `RemoteIPType == "Public"` filter, not stripped down. With the public-source filter still in place, the `ConnectionAttempt` events (which have a blank `RemoteIPType` in MDE) get dropped, and so do the 7 private-source events. What's left is just the public + inbound-accepted row from Q06:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| count
```

<img width="228" height="125" alt="image" src="https://github.com/user-attachments/assets/df6ff337-e9c1-4732-a44c-895be917894b" />


**Flag:** `194`

> **Lesson:** When a question says "the port identified in Q06," the lab is testing whether the prior question's *full filter chain* carries forward — not just the headline value. Q06's query established a specific scope (public, inbound, this host, this window). Q07 was a continuation of that scope, narrowed to the single port that came out of it. Stripping the `RemoteIPType == "Public"` filter felt natural ("the new question doesn't restrict to public, so I shouldn't either"), but it actually changed the *population* being counted — moving from "public scanning events on the host" to "all network events involving the port." Two different questions, two different answers.
>
> The deeper lesson: in chained-question hunts, treat each prior query's filter set as a contract that propagates forward unless the new question explicitly relaxes it. The numbers in Q06 are not just data points — they're the population being narrowed. If your next answer is a *subset* of the previous answer's population, the filter chain has to extend, not reset.
>
> One quirk worth remembering: in `DeviceNetworkEvents`, MDE leaves `RemoteIPType` unset (blank) on `ConnectionAttempt` events. Any positive filter on that column (`== "Public"`, `== "Private"`) silently drops those rows. That behavior was the difference between 325 and 194 here — and it's the kind of gotcha that turns a confident query into a wrong answer if you don't run a `summarize by` to see what your filter is actually scoping out.
