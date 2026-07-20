# v4.5.41

## Hidden system commands (no CMD flash)

Firewall inventory refresh was calling `netsh` without `CREATE_NO_WINDOW`, so a black console flashed every poll.

- `client_firewall.run_cmd`: `CREATE_NO_WINDOW` + `STARTF_USESHOWWINDOW` / `SW_HIDE`
- Related silent spawns hardened (daemon Popen, shutdown, RDP helpers)
