# v4.5.39

## GUI update status banner

When the dashboard sends `self_update`, the client GUI now shows a top banner:

1. **Güncelleme talimatı alındı** — command accepted
2. **İndiriliyor… %N** — download progress
3. **Kurulum hazırlanıyor / çalışıyor** — staging + installer helper
4. **Tamamlandı** / **Başarısız** — final state

Daemon writes `ProgramData\YesNext\CloudHoneypotClient\update_ui_status.json`; GUI polls every 1s. Toast on key phase changes. Success banner auto-hides after ~12s.
