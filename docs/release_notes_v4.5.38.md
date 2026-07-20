# v4.5.38

## Engellenen = firewall (HP-BLOCK) source of truth
- GUI no longer relies only on empty/stale `blocked_ips.json`.
- On Engellenen refresh: live `netsh` scan → ProgramData store → table.
- Numbered dashboard rules (`HP-BLOCK-1010`…) get RemoteIP via per-rule lookup when bulk list omits it.
- Turkish/locale RemoteIP field parsing hardened.
