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

# PRACTICEHunt 03 — Q08 — Source Diversity

**Goal:** Count the unique public source IP addresses that targeted the exposed RDP service.

**Approach:** Q06's diagnostic already exposed the answer in the `UniqueSourceIPs` column — but after Q07's filter-chain trap, it was worth confirming the question's scope before submitting. Q08 spells out every constraint explicitly: *unique* (distinct count), *public source IP* (the public filter), *targeted the exposed service* (port 3389). No inherited scope, no interpretive wiggle room. The query is Q06's filter chain with `count()` swapped for `dcount(RemoteIP)`:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LocalPort == 3389
| summarize UniqueSourceIPs = dcount(RemoteIP)
```

<img width="188" height="109" alt="image" src="https://github.com/user-attachments/assets/dc92c521-3fbe-49d9-8dd9-468d851eb5d4" />


A sanity check that included `RemotePort == 3389` events returned the same number — the 39 outbound-flavored events on port 3389 didn't introduce any new public IPs, so the answer is stable across both readings.

**Flag:** `173`

> **Lesson:** A diagnostic groupby earlier in an investigation often answers later questions for free. The `UniqueSourceIPs = dcount(RemoteIP)` column was added to the Q06 query for a reason — distinct-source cardinality is the canonical scanning anomaly metric — and once it surfaced 173 on the 3389 row, that number was committed for any later question about scanner diversity. The discipline worth practicing is *projecting more columns than you currently need* during early hunt queries: `count()`, `dcount(RemoteIP)`, `min()`/`max()` of timestamps, distinct action types. None of them cost meaningfully more, and the same dataframe ends up answering 3–4 downstream questions without re-querying. The cost of a too-narrow first query is having to re-scope and re-run when the next question lands; the cost of a wider one is one extra column on screen.

# PRACTICEHunt 03 — Q09 — Connection Outcomes

**Goal:** Count source IPs that show both a connection attempt and an accepted connection against the exposed RDP service — sources that received an actual TCP response, a different threat class than raw probes.

**Approach:** This is a "set membership" question — for each source IP, did its set of action types contain *both* values? The KQL pattern is `make_set(ActionType) by RemoteIP`, then filter for sources whose set length is >1 within the restricted action types. Q07's filter-chain lesson came up here too: the `RemoteIPType == "Public"` filter from prior queries had to be dropped, because `ConnectionAttempt` events have a blank `RemoteIPType` in MDE — keeping the public filter would silently drop every attempt and break the join logic. Scoping on `LocalPort == 3389` is enough to anchor to the right service.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize Outcomes = make_set(ActionType) by RemoteIP
| where array_length(Outcomes) > 1
| count
```

<img width="497" height="107" alt="image" src="https://github.com/user-attachments/assets/04e35af1-f188-4ae8-a3e5-4a5f96f80517" />


That returned **57**. After Q07, every count felt like it could be hiding a trick, so before submitting it was worth running a diagnostic version to see the public/private split and confirm the count was stable across reasonable interpretations:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize 
    Outcomes = make_set(ActionType),
    Attempts = countif(ActionType == "ConnectionAttempt"),
    Accepts = countif(ActionType == "InboundConnectionAccepted"),
    RemoteIPType = take_any(RemoteIPType)
    by RemoteIP
| where Attempts > 0 and Accepts > 0
| summarize 
    TotalSources = count(),
    PublicSources = countif(RemoteIPType == "Public" or isempty(RemoteIPType)),
    PrivateSources = countif(RemoteIPType == "Private")
```

<img width="557" height="122" alt="image" src="https://github.com/user-attachments/assets/4cf7baa5-efbf-46c8-a4d4-f66f8d49e44a" />


Result: 57 total = 53 public + 4 private. Two candidates were now in play — **57** (literal read) or **53** (carry forward Q08's public-only scope). The decisive factor was that Q08 spelled out "public source IP" explicitly and Q09 said only "source IPs." The omission was deliberate.

**Flag:** `57`

> **Lesson:** Two outcomes against the same target on the same port aren't just two events — they're a behavioral pivot. A pure `ConnectionAttempt` is a scanner firing one packet and moving on. An `InboundConnectionAccepted` after an attempt means the source got a TCP handshake, which is what enables credential brute-forcing, banner grabbing, or vulnerability fingerprinting. Sources that show both have *engaged* with the service, not just observed that it exists. In real-world hunting, this set — sources that completed a handshake — is where you focus next: filter the auth telemetry to *just these IPs* and you've collapsed your investigation surface from "every public scanner on the internet" to "the subset that actually tried to talk to the service."
>
> The technical lesson layered underneath: when chaining filters across questions, the right scope to carry forward is the one the *current* question explicitly demands, not the one the *previous* question implied. Q07 burned us for stripping a filter the question expected to inherit. Q09 would have burned us for the opposite mistake — inheriting a filter the question didn't demand. Read each question's text against the schema, not against the last query. Q08 said "public source IP." Q09 said "source IPs." Different questions, different scopes.

# PRACTICEHunt 03 — Q10 — Countries with RDP Activity

**Goal:** Enrich the Q09 source set with geographic data and count the distinct countries associated with the RDP connection activity.

**Approach:** First geo enrichment of the hunt. The pattern is to reuse Q09's query as the input set, prepend the `GeoTable` `externaldata` block from the briefing, and pipe the result through `evaluate ipv4_lookup(GeoTable, RemoteIP, network)` to attach country fields to each IP. Then `dcount(country_name)` gives the answer.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where LocalPort == 3389
| where ActionType in ("ConnectionAttempt", "InboundConnectionAccepted")
| summarize Outcomes = make_set(ActionType) by RemoteIP
| where array_length(Outcomes) > 1
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| summarize DistinctCountries = dcount(country_name)
```

<img width="322" height="142" alt="image" src="https://github.com/user-attachments/assets/b316ab26-3277-4020-86b0-777d2cc31720" />


That returned **11**. A diagnostic version confirmed the join was clean — `ipv4_lookup` silently dropped the 4 private IPs (they don't match any network in the public GeoIP table), leaving 53 public IPs all enriched with no gaps:

```kql
... (same query through the lookup) ...
| summarize 
    TotalIPs = count(),
    IPsWithCountry = countif(isnotempty(country_name)),
    IPsWithoutCountry = countif(isempty(country_name)),
    DistinctCountries = dcount(country_name)
```

<img width="781" height="227" alt="image" src="https://github.com/user-attachments/assets/40a4de93-e7c4-4c37-9606-de5d69395b41" />


53 IPs in, 53 enriched, 0 missing → 11 countries was rock solid.

**Flag:** `11`

> **Lesson:** `ipv4_lookup` is an *inner join* by default — IPs that don't match any network in the lookup table get dropped from the result, not preserved with null country fields. That's a feature when you're enriching public IPs (private/RFC1918 addresses don't belong in geo analysis), but it's a footgun if you assume the join is preserving every row. Always run a `count() vs countif(isnotempty(country_name))` diagnostic on the first geo query of an investigation to confirm the join is doing what you think it is. If `TotalIPs` after the lookup is smaller than `TotalIPs` before the lookup, you have silent drops — usually private IPs (fine), but occasionally public IPs missing from the dataset (a real gap).
>
> The broader lesson: every enrichment is a join, and every join is an opportunity for silent data loss. Geo lookups, threat intel matches, asset inventory pivots — they all behave this way. Verify cardinality before and after.
