# Cloud Honeypot Client v4.9.24

## Security — scripts folder attack surface

`Program Files\...\scripts` was world-readable; a local user could run `kill-honeypot.ps1`.

Fixes:
- Kill / prepare / update-and-install **not** installed under Program Files (installer `$PLUGINSDIR` only; self-update stages under ProgramData)
- Leftover helpers deleted on upgrade
- `scripts\` ACL: **SYSTEM + Administrators** only
- Scripts refuse non-elevated execution
- Daemon `QUIT` remains gated (operator_stop / update lock)

Release notes for operators: open the folder as a standard user should no longer list/run kill helpers.
