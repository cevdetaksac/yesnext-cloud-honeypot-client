# v4.4.43 — Session 0 GUI fix

Kurulum sonrası süreç çalışıyor ama pencere görünmüyordu: client Session 0 (SYSTEM) içinde Tk GUI açıyordu; kullanıcı masaüstünde (Session 1) görünmez.

- Session 0’da GUI açılmaz; interactive `CloudHoneypot-Tray` / `--show-gui` oturumuna devredilir
- Daemon, çalışan GUI’yi çalmaz (Watchdog yarışı engellendi)
- Watchdog: herhangi bir client örneği varsa yeni daemon başlatmaz
- SHOW: Session 0 her zaman `NOGUI` döner (yanlış “pencere açıldı” cevabı yok)
- Tray görevi argümanı: `--show-gui`
