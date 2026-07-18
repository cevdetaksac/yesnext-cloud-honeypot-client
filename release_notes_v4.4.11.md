# v4.4.11 — Aktif oturumlar daemon’da raporlanmıyordu

**Sorun:** Daemon + Tray (UI-only) mimarisinde `HealthMonitor` hiç başlatılmıyordu. Tray “daemon halleder” diye atlıyor, daemon ise health/sessions kodunu hiç çalıştırmıyordu. Sonuç: giriş yapmış olsanız bile dashboard’da **Aktif Bağlı Kullanıcılar = 0**.

## Düzeltme
- `run_daemon()` artık Threat + RemoteCommands + **HealthMonitor** başlatıyor
- İlk health report hemen gönderiliyor (`force_report`)
- Log: `report ok — sessions=N processes=M`
