# v4.4.7 — Bakım / Temizlik (local + firewall + dashboard)

## Özet

Dashboard’da eski saldırı/KPI verisi kalmasın diye istemci **yerel + firewall + sunucu** temizliğini sırayla destekler. Ayarlar menüsünden çalıştırılır; otomatik limitler arka planda HP-BLOCK kural sayısını ve IP havuzunu sınırlar.

## Client

- `DataCleanupManager` (`client_cleanup.py`)
  - Yerel: IP pool, session stats, alert dedup, `threats.log`
  - Firewall: tüm `HP-BLOCK-*` + `sync-rules([])` + `clear-data` scopes=`blocks`
  - Sunucu: `POST /api/agent/clear-data`
  - Tam bakım: local → firewall → server
- Ayarlar menüsü: 4 temizlik eylemi + onay diyalogları
- Auto limit: max 500 firewall kuralı, max 8000 IP pool (`cleanup.*` config)

## Backend (zorunlu — dashboard temizliği için)

Detay: [`API_CLEAR_DATA_PROMPT.md`](API_CLEAR_DATA_PROMPT.md)

```
POST /api/agent/clear-data
{ "token", "scopes": ["attacks","blocks","alerts","threat_summary","all"], "reason" }
```

`POST /api/agent/sync-rules` boş `blocks: []` ile **replace** (listeyi sıfırla).

Endpoint yoksa client yerel/firewall temizliği yine yapılır; sunucu adımı kullanıcıya uyarı döner.
