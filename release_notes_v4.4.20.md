# v4.4.20 — `clear_firewall` remote command

Dashboard Hesap → Bakım “Firewall bloklarını temizle” artık `clear_firewall` kuyruğa atıyor; agent işlemezse `HP-BLOCK-*` Windows’ta kalıyordu.

## Değişiklikler
- `command_type: clear_firewall` handler (`ALLOWED_COMMANDS` + `_cmd_clear_firewall`)
- Tüm `HP-BLOCK-`, `HONEYPOT_BLOCK*`, `HONEYPOT_BLOCK_REMOTE*`, legacy prefix’leri sil
- Yerel blok cache boşalt + `sync-rules []` + `clear-data` scopes=`blocks`
- `params.ips[]` için isim şablonlarıyla yedek silme
- `priority: critical` / clear_firewall sonrası poll **≤ 2 sn**
- `DataCleanupManager` remote executor’a bağlandı

## Acceptance
- Dashboard firewall temizle → ≤ 60 sn Windows’ta honeypot block kuralı kalmaz
- `POST /api/commands/result` success + `rules_removed`
