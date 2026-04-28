# PRACTICEHunt 03 — Q18 — Unexpected Country

**Goal:** Identify the successful-auth country that falls outside PHTG's expected operating region.

**Approach:** PHTG operates exclusively in the United States. Of the two countries with successful RDP authentication (Q17), one was the US (expected baseline) and the other was Uruguay (outside the operating footprint).

**Flag:** `Uruguay`

> **Lesson:** Geographic baseline checks are one of the highest-signal, lowest-cost detection rules available — but only if the operating footprint is documented. A single-region company turns every out-of-region successful auth into an automatic high-severity alert with near-zero false positives.

# PRACTICEHunt 03 — Q19 — Account Used

**Goal:** Identify the account used in the successful RDP authentication from the unexpected country.

**Approach:** Build on the Q16 query — public source, RDP-related logon types, `LogonSuccess` only — then filter the geo-enriched result to `country_name == "Uruguay"` and project the `AccountName` field.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project TimeGenerated, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
```
<img width="1577" height="394" alt="image" src="https://github.com/user-attachments/assets/00678e10-812b-41dd-a72a-aa2f39d7ad92" />

<br>

23 successful events, all under the same account: **`vmadminusername`**, originating from two Uruguay IPs (`173.244.55.128` and `173.244.55.131`) over December 12.

**Flag:** `vmadminusername`

> **Lesson:** `vmadminusername` is the kind of account name that should never reach production. It reads like a leftover placeholder from a provisioning script or template — the local admin slot was filled but never properly named. From an attacker's perspective, it's a gift: any credential-stuffing list aimed at Windows hosts cycles through the obvious default admin names (`administrator`, `admin`, `vmadmin`, `vm-admin`, `vmadminuser`, etc.) before moving on to per-organization guesses. A non-renamed default account on a public-facing RDP host is functionally a username giveaway.
>
> Two takeaways for detection and hardening: first, audit local admin account names across the fleet — anything matching common defaults or placeholder patterns gets flagged. Second, treat *any* successful auth on a default-named admin account as high-severity, regardless of source — those accounts are supposed to be rotated out of existence post-provisioning, so a successful logon is itself the anomaly.

# PRACTICEHunt 03 — Q20 — Uruguay Success Count

**Goal:** Count the successful RDP authentication events originating from the unexpected country.

**Approach:** Already surfaced by the Q19 query — the result pane showed 23 rows in the Uruguay-filtered set. A `count` instead of `project` returns the number directly.

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| count
```

**Flag:** `23`

# PRACTICEHunt 03 — Q21 — First RemoteIP from Uruguay

**Goal:** Identify the RemoteIP associated with the first successful RDP authentication from the unexpected country.

**Approach:** Already in the Q19 dataset. Sorted ascending by `TimeGenerated`, the first row is `12/12/2025, 5:47:45 AM` from `173.244.55.131` (Network logon).

```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string,
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09) .. datetime(2025-12-23))
| where DeviceName == "azwks-phtg-02"
| where RemoteIPType == "Public"
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| project TimeGenerated, AccountName, RemoteIP, LogonType
| order by TimeGenerated asc
| take 1
```

**Flag:** `173.244.55.131`

> **Lesson:** The two-IP pattern is a behavioral fingerprint worth recognizing. `173.244.55.131` shows up once — the *initial successful credential discovery* — and then `173.244.55.128` takes over for the next ~8 hours of session activity. That's the classic operator pattern: one IP burns through the brute-force list until it finds working credentials, then the operator pivots to a clean IP (often a different VPS in the same hosting provider's range) for actual hands-on-keyboard work. The `.128`/`.131` adjacency suggests both IPs come from the same /24, likely the same VPS provider — common for cheap bulletproof hosting. From a detection standpoint: any successful auth from an IP that is preceded by failed auths from a *neighboring* IP in the same /24 is worth alerting on, because that's the brute-force-then-pivot signature.

# PRACTICEHunt 03 — Q22 — Second RemoteIP from Uruguay

**Goal:** Identify the second RemoteIP associated with successful authentication events from the unexpected country.

**Approach:** Already surfaced by the Q19 result. Two distinct Uruguay IPs appeared: `173.244.55.131` (Q21, first hit) and `173.244.55.128` (the remaining 22 successful auths).

**Flag:** `173.244.55.128`
