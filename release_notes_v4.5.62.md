# v4.5.62 — Ransomware canary harden + quarantine

## Answer (hiding)
Extreme hiding (ADS / obscure paths) often means ransomware **never touches** the canary — so detection fails. This build uses **Hidden+System + `!000_` sort-bait** so Explorer stays clean but ransomware enum still hits early.

## Client
- Sort-bait canaries (`!000_*`), H+S on files and folders; admin README only in ProgramData
- Canary/VSS hit → kill suspect writer + **IFEO quarantine** until unlock
- Unlock: GUI button, IPC `RS_UNLOCK`, remote `unlock_ransomware_quarantine`
- Faster canary check (15s); extra TTPs (USN wipe, wevtutil, VSS PowerShell, net stop vss)
- Frontend ransomware detail via SYSTEM motor IPC (`RS_STATUS`)

## Cloud threat-intel (verified on this host)
- `GET /api/agent/threat-intel` → bundle `2026.07.20.008`
- Conditional fetch → HTTP 304 `not_modified`
- `POST .../ack` → ok
- Applied locally: firewall blocks + ransomware rules + process watch
