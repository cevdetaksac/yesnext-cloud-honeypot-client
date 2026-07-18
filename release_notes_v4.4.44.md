# v4.4.44 — Log / runtime fixes

- **Firewall:** `HTTPAdapter` import fixed (`client_firewall.py`) — agent no longer fails on startup
- **Reconcile:** tunnel-status payload’taki `pending_tunnel_commands` listesi artık servis sanılmıyor; crash yok
- **Self-protect:** `PROCESS_TERMINATE` için `win32con` kullanılıyor (DACL katmanı çalışır)
- **Tray:** aktif servis yokken spam WARNING kaldırıldı (iş istasyonunda normal)
