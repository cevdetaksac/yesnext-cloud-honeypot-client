# v4.4.24 — Güncelleme indirme “imha” düzeltmesi + daha sık kontrol

## Sorun
GUI “Güncellemeleri Denetle” ile indirirken uygulama kapanıyordu.

**Kök neden:** `update_in_progress.lock` kullanıcı `APPDATA` altındaydı.  
`CloudHoneypot-SilentUpdater` **SYSTEM** olarak çalışıp kilidi görmüyor → indirme ortasında `kill-honeypot` / QUIT.

## Düzeltmeler
- Kilit artık **ProgramData** (makine geneli) — GUI + SYSTEM aynı dosya
- İndirme sırasında kilit heartbeat (15 sn)
- Silent update: kilidi **indirmeden önce** alır; süreç öldürme **yalnızca indirme bitince**
- İndirme sırasında SilentUpdater + MemoryRestart + Watchdog **durdurulur**
- Sürüm kontrolü: **30 dk** (Task Scheduler SilentUpdater PT30M + in-process watchdog)
- Mevcut kurulumlarda startup’ta SilentUpdater aralığı yenilenir

## Config
```json
"updates": {
  "auto_check": true,
  "check_interval_minutes": 30
}
```
