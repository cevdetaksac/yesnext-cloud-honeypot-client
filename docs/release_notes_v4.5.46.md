# v4.5.46

## Centralization & remaining P1

- Threat Center: single coalesced worker (no parallel PowerShell storms); duplicate user-account refresh removed
- Honeypot Start/Stop runs off the Tk thread
- `client_winproc` expanded: `run_ps`, `run_ps_script`, `popen_detached`
- Migrated GUI collectors, auto-response logoff, daemon IPC schtasks spawn, helpers session queries, system_health sessions
