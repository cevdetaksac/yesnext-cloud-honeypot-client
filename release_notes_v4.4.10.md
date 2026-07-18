# v4.4.10 — Güncelleme indirme yarış durumu düzeltmesi

**Sorun:** "Güncellemeleri Denetle" ile indirme ~%20–%25 iken tüm client örnekleri kapanıyor, indirme yarıda kesiliyordu.

**Kök neden:** `CloudHoneypot-SilentUpdater` (veya saatlik watchdog) kendi indirmesini bitirince `prepare_client_for_installer()` çağırıp QUIT + `kill-honeypot.ps1` ile **tüm** `honeypot-client` süreçlerini öldürüyordu — GUI indirmesi de dahil.

## Düzeltmeler
- İndirme sırasında `update_in_progress.lock` kilidi
- Silent updater / watchdog kilit varken atlanır
- İndirme başında yalnızca SilentUpdater/Updater görevleri durdurulur (Background/Tray öldürülmez)
- Süreç kill yalnızca installer kullanıcı tarafından başlatılınca
- Installer önce `Start-Process`, sonra kill (Start-Process kaçmasın)
