# Cloud Honeypot Client v4.9.5

## Highlights

- **`list_services` empty array fix (4.9.4):** Under Turkish Windows locale, PowerShell JSON stdout failed `cp1254` decode → `success:true` with `services:[]`. Primary path is now **Win32 SCM** via pywin32 (`name`, `display_name`, `status`, `start_type`, `pid` when >0). PowerShell CIM/`Get-Service` kept as UTF-8 fallback.
- **Uninstall PIN gate:** NSIS uninstall / Control Panel removal prompts for GUI PIN (or confirm when no PIN); lifecycle events `uninstall_requested` / `uninstall_pin_failed` / `uninstall_aborted` / `uninstall_authorized`; CLI `--uninstall-gate`.

## Production floor

Unchanged: **client ≥ 4.9.0**. Server Management Services table: **≥ 4.9.5**.

## Build

`build.ps1 -Clean -WebRTC`
