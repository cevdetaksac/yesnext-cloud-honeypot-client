# POST /api/agent/clear-data — Dashboard veri temizliği

Client v4.4.7+ Ayarlar → Bakım/Temizlik menüsünden çağırır.
Amaç: istemci tarafı temizlik sonrası dashboard’da **geçersiz KPI / saldırı / blok** kalmasın.

---

## Endpoint

```
POST /api/agent/clear-data
Content-Type: application/json
```

### Request

```json
{
  "token": "client-registration-token",
  "scopes": ["attacks", "blocks", "alerts", "threat_summary", "all"],
  "reason": "user_requested_cleanup"
}
```

| Alan | Tip | Zorunlu | Açıklama |
|------|-----|---------|----------|
| `token` | string | evet | Client kayıt token’ı |
| `scopes` | string[] | evet | Temizlenecek veri kümeleri |
| `reason` | string | hayır | Audit log için (örn. `firewall_cleanup`, `user_requested_cleanup`) |

### Scope anlamları

| Scope | Silinecek |
|-------|-----------|
| `attacks` | Bu token’a ait attack / attack batch kayıtları |
| `blocks` | Auto-block + dashboard block kayıtları, pending blocks |
| `alerts` | Urgent / self-protection / ransomware alert kayıtları |
| `threat_summary` | Önbelleklenmiş threat summary / KPI aggregate |
| `all` | Yukarıdakilerin hepsi |

### Response (başarı)

```json
{
  "status": "ok",
  "cleared": {
    "attacks": 8543,
    "blocks": 42,
    "alerts": 17,
    "threat_summary": true
  },
  "token": "…",
  "reason": "user_requested_cleanup"
}
```

HTTP **200** (veya 204). Client `status in (ok, success)` veya body dolu 2xx kabul eder.

### Response (hata)

| HTTP | Anlam |
|------|--------|
| 401 / 403 | Token geçersiz |
| 404 | Endpoint yok (client yerel temizliği yine yapar, kullanıcıya uyarı gösterir) |
| 422 | Geçersiz scope |
| 500 | Sunucu hatası |

---

## İlişkili: POST /api/agent/sync-rules

Firewall temizliği sonrası client boş liste gönderir:

```json
{
  "token": "…",
  "blocks": [],
  "total_rules": 0,
  "synced_at": "2026-07-18T12:00:00+00:00"
}
```

Backend davranışı: bu token için aktif blok listesini **tamamen değiştir** (replace), merge etme.
`blocks: []` → dashboard “engellenen IP” = 0.

---

## Opsiyonel alias

Client fallback: `POST /api/attacks/clear` `{ "token", "reason" }` — yalnızca `attacks` scope için.

---

## Dashboard UI

Temizlik sonrası:

1. Attack count KPI → 0 (veya yeniden hesap)
2. Attack listesi / timeline boş
3. Blocked IPs listesi boş (`sync-rules` + `scopes: blocks`)
4. Alert inbox / urgent feed temiz

Audit: kim (token/server_name), ne zaman, hangi scopes, reason.

---

## Client çağrı noktaları

| Menü | scopes |
|------|--------|
| Dashboard verisini temizle | `attacks`, `blocks`, `alerts`, `threat_summary` |
| Firewall bloklarını temizle | `blocks` (+ `sync-rules` `[]`) |
| Tümünü temizle | `attacks`, `blocks`, `alerts`, `threat_summary`, `all` |
