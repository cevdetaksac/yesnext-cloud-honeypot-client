# Dashboard Prompt: Client Temizlik (Cleanup) API Uyumu

> **Kime:** YesNext Honeypot **Dashboard / Backend** geliştiren yapay zeka  
> **API base:** `https://honeypot.yesnext.com.tr`  
> **Client:** `yesnext-cloud-honeypot-client` **v4.4.7+** (Ayarlar → Bakım / Temizlik)  
> **Tarih:** 2026-07-18  
> **Amaç:** Client’taki temizlik butonlarının çağırdığı API’lerin sunucu + dashboard tarafında doğru çalışması; temizlik sonrası KPI / listelerin anında sıfırlanması.

---

## 1) Senin görevin

1. Aşağıdaki endpoint’leri **implement et veya doğrula** (yoksa ekle, varsa contract’a uyarla).
2. Temizlik sonrası dashboard UI’nin ilgili widget’ları **anında** güncellemesini sağla (poll veya websocket/invalidate).
3. Her temizliği **audit log**’a yaz (token / server_name / scopes / reason / timestamp / counts).
4. Bitince kısa “ne değişti + acceptance checklist” yaz.

**Önemli:** Client zaten bu contract’a göre çağırıyor. Alan adlarını değiştirme; alias eklemek OK.

---

## 2) Client menü → API eşlemesi

Client GUI (`Ayarlar` menüsü):

| Menü (TR) | Client aksiyon | API çağrıları |
|-----------|----------------|---------------|
| Yerel veriyi temizle | Sadece local (IP pool, dedup, threats.log…) | **API yok** |
| Firewall bloklarını temizle | Yerel `HP-BLOCK-*` sil | ① `POST /api/agent/sync-rules` `blocks:[]` ② `POST /api/agent/clear-data` `scopes:["blocks"]` `reason:"firewall_cleanup"` |
| Dashboard verisini temizle | Sunucu kayıtları | `POST /api/agent/clear-data` `scopes:["attacks","blocks","alerts","threat_summary"]` `reason:"user_requested_cleanup"` |
| Tümünü temizle (tam bakım) | local + firewall + server | Yukarıdakilerin hepsi + clear-data’ya ek `scopes` içinde `"all"` |

Auth: tüm isteklerde client **registration token** (`token` alanı + mevcut agent auth header’ları).

---

## 3) Endpoint A — `POST /api/agent/clear-data`

### Request

```http
POST /api/agent/clear-data
Content-Type: application/json
```

```json
{
  "token": "<CLIENT_TOKEN>",
  "scopes": ["attacks", "blocks", "alerts", "threat_summary", "all"],
  "reason": "user_requested_cleanup"
}
```

| Alan | Tip | Zorunlu | Not |
|------|-----|---------|-----|
| `token` | string | evet | Client UUID token |
| `scopes` | string[] | evet | Aşağıdaki tablodaki değerler |
| `reason` | string | hayır | Audit: `user_requested_cleanup` \| `firewall_cleanup` |

### Scope anlamları (silinecek veri)

| Scope | Dashboard / DB etkisi |
|-------|------------------------|
| `attacks` | Bu token’a ait attack + attack-batch kayıtları |
| `blocks` | Auto-block / dashboard block / pending-blocks bu token için |
| `alerts` | Urgent / self-protection / ransomware / health alert kayıtları |
| `threat_summary` | Önbelleklenmiş threat summary + KPI aggregate (attack count cache vb.) |
| `all` | Yukarıdakilerin tamamı (explicit diğer scope’larla birlikte gelebilir) |

### Response (200)

```json
{
  "status": "ok",
  "cleared": {
    "attacks": 8543,
    "blocks": 42,
    "alerts": 17,
    "threat_summary": true
  },
  "token": "<CLIENT_TOKEN>",
  "reason": "user_requested_cleanup"
}
```

Client kabul kriteri: HTTP 2xx ve `status ∈ {ok, success}` **veya** dolu JSON body.

### Hatalar

| HTTP | Anlam |
|------|--------|
| 401 / 403 | Token geçersiz |
| 404 | Endpoint yok → client yerel temizliği yapar, kullanıcıya “sunucu endpoint yok” uyarısı |
| 422 | Geçersiz scope |
| 500 | Sunucu hatası |

### Opsiyonel alias (sadece attacks)

Client fallback: `POST /api/attacks/clear` body `{ "token", "reason" }` — yalnızca attacks scope için.

---

## 4) Endpoint B — `POST /api/agent/sync-rules` (firewall temizliği)

Firewall menüsü sonrası client **boş liste** gönderir:

```json
{
  "token": "<CLIENT_TOKEN>",
  "blocks": [],
  "total_rules": 0,
  "synced_at": "2026-07-18T12:00:00+00:00"
}
```

**Zorunlu semantik:** Bu token için aktif blok listesini **REPLACE** et (merge yok).  
`blocks: []` ⇒ dashboard “Engellenen IP” = **0**.

Başarı: HTTP 2xx + tercihen `{ "status": "ok" }`.

---

## 5) Dashboard UI — temizlik sonrası davranış

Temizlik API’si başarılı olunca (veya client’tan gelen sync sonrası) ilgili agent için:

1. **Attack count KPI** → 0 (veya yeniden hesap; cache invalidate)
2. **Attack list / timeline / map** → boş
3. **Blocked IPs** → boş (`sync-rules []` + `scopes: blocks`)
4. **Alert inbox / urgent feed** → temiz
5. **Threat summary kartları** → sıfır / “veri yok”
6. Üstte kısa toast: “Client verileri temizlendi (`reason`)”

Canlı sayfa açıksa: 5–15 sn poll yetmezse **invalidate query / websocket push** tercih et.

### Audit paneli (öneri)

| Kolon | Kaynak |
|-------|--------|
| Zaman | server now UTC |
| Agent | token → server_name |
| Scopes | request.scopes |
| Reason | request.reason |
| Counts | response.cleared |

---

## 6) Güvenlik

- Sadece **kendi token’ının** verisini silebilsin (cross-tenant yok).
- Rate limit önerisi: aynı token için clear-data ≤ 5/dk.
- `reason` ve scopes’u immutable audit tablosuna yaz.
- Admin dashboard “tüm agent temizle” ayrı endpoint olabilir; bu prompt agent self-cleanup içindir.

---

## 7) Acceptance checklist

- [ ] `POST /api/agent/clear-data` scopes=`attacks,blocks,alerts,threat_summary` → KPI + listeler 0
- [ ] `scopes=["blocks"]` + `reason=firewall_cleanup` → sadece bloklar gider, attack history kalabilir
- [ ] `scopes` içinde `all` → tam temizlik
- [ ] `POST /api/agent/sync-rules` `blocks:[]` → blocked IP listesi 0 (replace)
- [ ] Geçersiz token → 401/403
- [ ] Audit kaydı oluşuyor
- [ ] Açık dashboard sekmesi temizlikten sonra stale veri göstermiyor

---

## 8) Client referans (değiştirme)

| Dosya | Rol |
|-------|-----|
| `cloud-client/client_cleanup.py` | `clear_local` / `clear_firewall` / `clear_server` / `clear_all` |
| `cloud-client/client_api.py` | `clear_client_data()`, `sync_firewall_rules()` |
| `cloud-client/client_gui.py` | Ayarlar menü butonları |
| `cloud-client/API_CLEAR_DATA_PROMPT.md` | İlk sözleşme notu |

Bu prompt, dashboard AI için **tek kaynak** olarak kullanılmalıdır.
