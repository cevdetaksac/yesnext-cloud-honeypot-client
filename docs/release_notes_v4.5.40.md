# v4.5.40

## Engellenen / firewall list fix + Clear all

- Fixed empty Engellenen tab: `netsh` now uses `name=all`, and stdout is decoded from bytes (avoids cp1254 crash on large dumps).
- Failed firewall scans no longer wipe `blocked_ips.json`.
- IP activity header: **Tümünü temizle / Clear all** — removes all honeypot firewall rules, clears local store, notifies API (`sync-rules []` + `clear-data` scopes=`blocks`).
