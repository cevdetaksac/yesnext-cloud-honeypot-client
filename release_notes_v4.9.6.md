# Cloud Honeypot Client v4.9.6

## Highlights

- **Update disk bloat cleanup:** After a successful install, remove staged `cloud-client-installer*.exe`, `run-update-*.ps1` launchers, matching Downloads copies, and `TEMP\honeypot_*update_*` dirs. Downloads are no longer used for installer staging; only the active installer is kept under ProgramData until install completes. Daemon auto-enforce also prunes leftovers when no update is in progress.
- **Settings → Security PIN:** Set / change / remove local GUI PIN from the Ayarlar tab (status + dashboard recovery hint). Uses existing `GuiLock` dialogs.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`
