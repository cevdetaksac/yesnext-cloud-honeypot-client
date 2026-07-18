# v4.5.12 — Remote komut / RD poll geri

**Sorun:** GUI `:58632` portuna bind edip PING cevaplıyordu → herkes “daemon var” sanıyordu → `commands/pending` ve remote WS hiç açılmıyordu.

**Düzeltme:**
- STATUS: `daemon` / `motor_ok` / `remote_commands_running` gerçek motor bilgisi
- Frontend **asla** kontrol portuna bind etmez
- `is_motor_healthy()` — yalnızca PING yetmez
- `ensure_daemon_running` → schtasks Background + motor_ok bekle
- Daemon: RemoteCommands zorunlu construct + poll thread watchdog
- Frontend: 45s motor watchdog
