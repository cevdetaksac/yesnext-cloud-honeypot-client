# v4.5.10 — GUI performans

- UI thread'de **senkron daemon IPC yok** (protection mode cache + 5s background poller)
- Pulse blink her 800ms IPC çağırmıyor (cache)
- Frontend açılışta threat/Faz motor stack **kurulmuyor** (daemon zaten motor)
- Prewarm 0.9s/1.6s → **8s/12s** (Status paint ile yarışmıyor)
- IP tablo: değişmediyse rebuild yok; max 60 satır
- Session `query` UI thread dışı
- `[PERF]` logları: page_build, nav, dashboard, ip_table, protection_mode, daemon ping
