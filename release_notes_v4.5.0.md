# v4.5.0 — SYSTEM daemon motor + multi GUI frontend

- **SYSTEM Session 0 daemon** kalici motor: threat, firewall, honeypot, Remote Desktop, API
- **GUI** frontend-only: coklu kullanici ayni anda acabilir; daemon'i oldurmez
- IPC: `127.0.0.1:58632` — PING / STATUS / HONEYPOT START|STOP|LIST
- Daemon logon olunca artik `os._exit` yapmaz (tray handoff soft)
- `status.json` → `%ProgramData%\YesNext\CloudHoneypotClient\` (paylasimli)
- Dashboard prompt: `AGENT_SYSTEM_DAEMON_FRONTEND_API_PROMPT.md`
