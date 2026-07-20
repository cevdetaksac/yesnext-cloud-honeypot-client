# v4.5.37

## Daemon always-on after update (root cause)

Silent/interactive update helper previously **disabled** `CloudHoneypot-Background` + `Watchdog`, then often never re-enabled them on success → motor dead, dashboard “poll yok”.

### Fix
- After every install (success **and** fail): `Restore-HoneypotTasks` + `Ensure-DaemonMotor`
- Prefer `schtasks /run CloudHoneypot-Background` (SYSTEM Session 0)
- Wait/re-kick until control port `127.0.0.1:58632` answers
- Then tray (if logon) — GUI is not the motor

Includes 4.5.36 emergency GUI bridge as safety net.
