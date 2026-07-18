# v4.4.22 — Aylarca uptime: RAM / thread koruması

Saldırı trafiği altında sınırsız büyüyebilecek yapılar ve thread fırtınası giderildi.

## Kritik
- Honeypot rate-limiter: idle key eviction + max 10k key
- Honeypot accept: max **48** concurrent handler / servis (fazlası drop)
- `unique_ips` set: max **5000** (MemoryGuard trim)
- Alert batch: API down iken hard-cap **1000** (eski drop)
- Dedup map: hard-cap **20k** + her flush’ta temizlik
- Urgent/auto-block API raporları: bounded pool (8 worker / 64 pending)
- Auto-response `_blocks`: max **500** in-memory
- Threat IP pool LRU: blocked IP’ler de evict edilebilir
- GDI capture: `finally` ile HDC/HBITMAP sızıntısı yok; log spam azaltıldı
- FP tuner: stale IP’ler gerçekten siliniyor
- MemoryGuard: honeypot limiter + unique_ips + auto blocks kayıtlı

## Beklenen
Aylarca açık sunucuda RAM’in saldırı yoğunluğunda kontrolsüz şişmemesi; process kitlenmesi riskinin düşmesi.
