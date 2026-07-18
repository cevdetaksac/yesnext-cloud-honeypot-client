# v4.4.29 — Hesap bağlılığı API’den

## Değişiklikler
- `GET /api/agent/account-status?token=` (fallback: `client_status` içindeki `account_linked`)
- API yanıtı source of truth: `true`/`false` local cache’i günceller
- Heartbeat yanıtında `account_linked` varsa otomatik sync
- Üst bar: bağlıysa e-posta rozeti; ~60 sn + link sonrası poll
- Manuel işaretleme yalnızca API yokken offline fallback
