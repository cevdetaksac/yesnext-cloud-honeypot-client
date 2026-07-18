# v4.5.2 — Silent auto-update recovery

**Kok neden:** `--silent-update-check` (Task Scheduler SilentUpdater) indirme basinda `schtasks /end CloudHoneypot-SilentUpdater` cagirarak **kendini olduruyordu**. Sonuc:
- `update_in_progress.lock` takili kaliyordu
- Watchdog / SilentUpdater / Background **disable** kalabiliyordu
- Install helper hic baslamiyordu (ProgramData'da `update-install.log` yok)
- Agentler eski surumde mahsur kaliyordu

**Duzeltmeler:**
- SilentUpdater / Updater artik update akisinda `/end` edilmiyor (sadece disable)
- Installer `ProgramData\...\update\` altina stage ediliyor (TEMP yolu kalkti)
- Stale lock: olu PID → otomatik temizlenir
- Basarisiz helper: gorevler tekrar enable + daemon restart
- SilentUpdater tetikleyicisi CalendarTrigger (15 dk) + `network_required=false`
- Her silent-check basinda `heal_update_machinery()` (kilit + gorev recovery)
