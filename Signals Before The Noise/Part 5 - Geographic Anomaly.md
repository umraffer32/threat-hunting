# PRACTICEHunt 03 — Q18 — Unexpected Country

**Goal:** Identify the successful-auth country that falls outside PHTG's expected operating region.

**Approach:** PHTG operates exclusively in the United States. Of the two countries with successful RDP authentication (Q17), one was the US (expected baseline) and the other was Uruguay (outside the operating footprint).

**Flag:** `Uruguay`

> **Lesson:** Geographic baseline checks are one of the highest-signal, lowest-cost detection rules available — but only if the operating footprint is documented. A single-region company turns every out-of-region successful auth into an automatic high-severity alert with near-zero false positives.
