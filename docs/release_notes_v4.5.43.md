# v4.5.43

## Stuck “Kurulum çalışıyor” banner

If the update helper died or never started after the GUI showed “installing”, the banner stayed forever.

### Fix
- Active phases expire (installing ~10 min) → `failed` / “Güncelleme takıldı — tekrar deneyin” + release update lock
- On startup: still on old version with installing status → mark `install_did_not_complete`
- Helper heartbeats `update_ui_status` every 5s while waiting for NSIS
