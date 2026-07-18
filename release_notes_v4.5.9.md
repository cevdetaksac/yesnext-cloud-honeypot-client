# v4.5.9 — Logon'da tray otomatik

- Tray görevi `Users` yerine **Authenticated Users** (Administrator / RDP dahil)
- Daemon oturum izleyici: yalnızca console değil, **Active RDP** de tray başlatır
- Sessiz update sonrası etkileşimli oturum varsa Tray de tetiklenir
- Watchdog: daemon varken tray yoksa Logon Tray görevini çalıştırır
