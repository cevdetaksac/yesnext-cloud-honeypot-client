# v4.4.6 — Installer process kill fix

Self-protection DACL + `HoneypotClientGuard` görevi installer'ın `taskkill`'ini engelliyordu / yeniden başlatıyordu.

## Düzeltmeler
- **QUIT control socket:** Installer önce `127.0.0.1:58632` üzerinden `QUIT` gönderir — süreç kendini kapatır (DACL bypass)
- **SeDebugPrivilege kill:** `scripts/kill-honeypot.ps1` ile admin TerminateProcess (DACL'yi aşar)
- **HoneypotClientGuard:** Task Scheduler temizliği artık `HoneypotClient*` wildcard'ını da siler
- **Stop flags:** `CloudHoneypotClient\watchdog.token` dahil tüm watchdog yolları
