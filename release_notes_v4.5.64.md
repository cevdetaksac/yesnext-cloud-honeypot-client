# v4.5.64 — Interactive-user canaries watched by SYSTEM

## Scenario-tested on this PC
- Threat-intel: fetch / 304 / ack OK (bundle `2026.07.20.011`)
- User Documents sort-bait canaries (H+S) deployed and **watched by Session-0 motor**
- Canary MODIFIED → quarantine armed in ~6s → `RS_UNLOCK` clears
- IFEO process attribution remains best-effort (SYSTEM often cannot see interactive open_files)

## Fixes
- ProfileList + scan `Users\*\Documents\.cloud-honeypot-canary` (4.5.63 deployed files but SYSTEM did not watch them)
- Quarantine arm-first (from 4.5.63)
