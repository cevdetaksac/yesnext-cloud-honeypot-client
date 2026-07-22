# Cloud Honeypot Client v4.9.3

## Highlights

- **OOB-501 acceptance visibility:** durable drop counters (`oldest_dropped`, expired, too-large) persist across restart and appear on `health/report` as `offline_urgent_queue{}`. Pilot harness covers canary spool→reconnect drain and 500-cap drop.
- Flag `security.offline_urgent_queue` remains **default off** (one-host live canary pilot still the open gate).
- **GUI polish:** stat cards keep icon + value on one row; IP Lists uses a single scrollbar sized to the window.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`
