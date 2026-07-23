# Cloud Honeypot Client v4.9.17

## Observe default + auto-promote (contract 1.4.19)

- Fresh install defaults to **Observe** — all alerts, no auto process kill / no isolate
- After **3 days** (configurable) auto-promotes to **Balanced** unless locked
- GUI: education for Observe / Balanced / Paranoid + “Switch to Balanced” / “Stay in Observe”
- Never auto-opens Paranoid or `isolate_armed`

## Includes

- 4.9.16 Defense Policy matrix, signed cache, allow_process, snapshots
- 4.9.15 soft network surface inform
