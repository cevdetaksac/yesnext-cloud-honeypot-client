# v4.4.30 — Installer PRE-KILL fix

## Fix
- `scripts/kill-honeypot.ps1` UTF-8 em-dash (`—`) Windows PowerShell'de string'i kırıyordu → `Unexpected token ')'`
- Script artık ASCII-only; installer PRE-KILL parse hatası giderildi
