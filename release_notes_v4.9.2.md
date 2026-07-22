# Cloud Honeypot Client v4.9.2

## Highlights

- **OOB-501 aligned to contract 1.4.7** (`api/10-offline-urgent-queue`): local TTL 7d prune, ≤200 KB payload reject, batch ≤500, drop `schema`/`too_large`/`expired` rejects and retry `transient`; drain after successful heartbeat **or** control WS reconnect.
- Flag `security.offline_urgent_queue` remains **default off** — ready for pilot drain, not fleet-on.
- **Threat Center UX:** autoblock threshold is threat score 0–100; Engellenen IP card opens IP Lists → Engellenen; Skor column.

## Production floor

Unchanged: **client ≥ 4.9.0**. Observe / default-off security surfaces only.

## Build

`build.ps1 -Clean -WebRTC`
