# v4.5.45

## Fix: stuck “Kurulum çalışıyor” banner

Helper heartbeats refreshed `updated_at` every 5s while waiting for NSIS, so the 10‑minute stale timeout never fired.

- Track `phase_started_at` (heartbeats do not reset it)
- Stale timeout uses phase start, not last heartbeat
- If running version is already ≥ target (e.g. 4.5.43 with banner 4.5.40→4.5.42), auto-dismiss as done

### Immediate unblock (any version)

```bat
del /f "%ProgramData%\YesNext\CloudHoneypotClient\update_ui_status.json"
del /f "%ProgramData%\YesNext\CloudHoneypotClient\update_in_progress.lock"
```

Then reopen the GUI (or wait ~1s).
