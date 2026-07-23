# Cloud Honeypot Client v4.9.13

## STATUS hang fix

Network Guard / System Recovery no longer run PowerShell or full drift scans
inside the single-threaded `:58632` STATUS handler. Live adapters come from the
detect-loop cache; use `list_network_baseline` / `network_diff` /
`system_recovery_diff` for fresh collects.

## Includes 4.9.12

- System Recovery (contract 1.4.13)
- Network Guard panel + `auto_restore_network` (1.4.14)
- Maintenance pause / snapshot / resume (1.4.15)
