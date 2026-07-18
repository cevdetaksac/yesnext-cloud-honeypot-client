# v4.4.13 — Login’liyken oturum raporu hiç başlamıyordu

**Kök neden:** `CloudHoneypot-Background` (`--mode=daemon`) kullanıcı oturumu görünce GUI’ye geçiyor ama `start_delayed_api_sync()` çağrılmıyordu. Tray de cmdline’da `--mode=daemon` görüp health’i atlıyordu → **kimse `active_sessions` göndermiyordu**.

## Düzeltme
- Daemon→GUI (logon) path’inde `start_delayed_api_sync()` eklendi
- Tray UI-only health fallback (4.4.12) + daemon health (4.4.11) korunuyor
