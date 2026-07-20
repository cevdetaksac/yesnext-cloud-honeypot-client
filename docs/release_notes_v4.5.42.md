# v4.5.42

## Clear all blocks (elevated)

GUI “Tümünü temizle” was running as the interactive user without admin rights, so every `netsh delete` failed with “requires elevation” — CMD windows flashed, firewall and dashboard stayed unchanged.

### Fix
- GUI sends `CLEAR_FIREWALL` to the SYSTEM Background daemon over `:58632`
- Daemon deletes all `HP-BLOCK-*` / `HONEYPOT_*` rules (one hidden PowerShell sweep) then `sync-rules []` + `clear-data` scopes=`blocks`
- Non-elevated processes no longer wipe local/API inventory while rules remain
