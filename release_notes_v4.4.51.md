# v4.4.51 — Watchdog 2m + MemoryRestart fix + lifecycle API

- **Watchdog:** 15 dk -> **2 dk** (cokme sonrasi hizli kaldirma)
- **MemoryRestart:** yanlis InstallPath duzeltildi (`Cloud Honeypot Client`); exe yoksa Background task fallback
- Script artik `INSTDIR\scripts\memory_restart.ps1` ( _MEIPASS degil )
- **Lifecycle log:** `%ProgramData%\YesNext\CloudHoneypotClient\lifecycle.log`
- API: `POST /api/alerts/lifecycle` (kuyruk + flush) — prompt: `AGENT_LIFECYCLE_ALERTS_API_PROMPT.md`
