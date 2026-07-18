# v4.5.11 — Dashboard self_update

- Remote komutlar: `self_update` + `check_update`
- Dashboard **Şimdi güncelle** → pending poll → hemen silent install (takvim beklemez)
- `force=false` + aynı sürüm → `already_current`
- Sadece resmi GitHub release URL; update lock; lifecycle begin/ok/failed
- `expires_at` / 30 dk TTL desteği; result sync sonra process exit
