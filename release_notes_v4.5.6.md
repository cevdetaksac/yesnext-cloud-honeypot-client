# v4.5.6 — Hizli acilis (snappy GUI)

Olculen: `Building main GUI` → pencere/tray **15–36 sn** suruyordu.

**Kaldirilan engeller:**
- Task Scheduler XML refresh her acilista (artik sadece VERSION degisince)
- schtasks aktivasyon dongusu GUI'de arka plana alindi
- Lifecycle API + exe SHA hash UI thread'den cikti
- ipify / attack-count senkron cagrilar kaldirildi
- Tray menu `refresh_account_link_status` (API) tray baslatmadan once calismiyordu
- RDP netstat probe acilista yok
- PIN dialog build'i bloklamaz; once pencere, sonra PIN
- Tray `after(50)` ile first paint sonrasina alindi
