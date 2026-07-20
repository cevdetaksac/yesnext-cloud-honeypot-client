# Firewall, Blocks & Cleanup

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_DEFAULT_BLOCK_RULES_API_PROMPT.md`

# AGENT_DEFAULT_BLOCK_RULES_API_PROMPT.md

## Amac

Dashboard'da **"Varsayilan kurallari olustur"** butonu: tek tikla tum varsayilan
servislere **3 basarisiz giris -> engelle (+ e-posta)** kurallarini seed et.

> Not: Asagidaki metin ASCII-guvenli yazildi (IDE preview kirilmasin diye).
> Anlam ayni; UI metinlerini Turkce duzgun karakterle yazabilirsin.

Client tarafi (v4.4.50+):

- Honeypot bait **kapali** olsa bile EventLog + block rules ile gercek port
  (RDP 3389 vb.) brute-force'u bildirir/engeller.
- API'den kural gelmezse / bos gelirse client **yerel `DEFAULT_BLOCK_RULES`**
  kullanir — yine de dashboard'da kurallarin gorunur olmasi UX icin sart.
- Bu endpoint, Account/Server icin DB'de ayni seti kalici olusturur.

---

## Urun davranisi (UI)

**Konum:** Premium Rules / Blok Kurallari sayfasi

**Buton:** `Varsayilan kurallari olustur`

**Alt metin (onerı):**

```
RDP, SSH, FTP, MSSQL, MySQL ve Network icin 30 dk icinde 3 fail -> e-posta + firewall engeli.
Mevcut ozel kurallar silinmez.
```

**Onay diyalogu (onerı):**

| Secenek | Davranis |
|---------|----------|
| **Ekle / tamamla** (varsayilan) | Eksik `name` degerlerini ekle; mevcut ayni `name`'e dokunma |
| **Sifirla** | Sadece `default_*` kurallarini silip yeniden yaz; kullanici ozel kurallarini koru |

Basari toast: `6 varsayilan kural hazir` (+ olusturulan/atlanan sayilari).

---

## API

### POST /api/premium/rules/seed-defaults

Auth: Account session (dashboard) — agent token **degil**.

Query/body (ikisi de OK):

```json
{
  "mode": "upsert",
  "server_id": null
}
```

| Alan | Tip | Aciklama |
|------|-----|----------|
| `mode` | string | `upsert` (default) veya `reset_defaults` |
| `server_id` | int veya null | `null` = account-wide; doluysa o sunucuya ozel |

**Response 200:**

```json
{
  "status": "ok",
  "created": 6,
  "skipped": 0,
  "updated": 0,
  "rules": []
}
```

`rules` alani: guncel kural listesi — `GET /api/premium/rules` ile ayni sema.

Idempotent: ikinci tikta `created: 0`, `skipped: 6`.

---

## Seed edilecek kurallar (client ile birebir)

Client kaynagi: `cloud-client/client_threat_engine.py` -> `DEFAULT_BLOCK_RULES`

| name | services | threshold_count | window_minutes | actions | enabled |
|------|----------|-----------------|----------------|---------|---------|
| `default_rdp` | `RDP` | 3 | 30 | `email,block` | true |
| `default_ssh` | `SSH` | 3 | 30 | `email,block` | true |
| `default_ftp` | `FTP` | 3 | 30 | `email,block` | true |
| `default_mssql` | `MSSQL` | 3 | 30 | `email,block` | true |
| `default_mysql` | `MYSQL` | 3 | 30 | `email,block` | true |
| `default_network` | `Network` | 10 | 30 | `email,block` | true |

Notlar:

- `MYSQL` servis adi client EventLog/honeypot ile **buyuk harf** `MYSQL` olmali (`MySQL` degil).
- `Network` (LogonType 3 / SMB tarzi) icin esik **10** — false positive azaltma; digerleri **3**.
- `email_cooldown_min` yoksa client/default **10** varsayilabilir.
- `match_usernames` bos birak.

Ornek INSERT payload (tek kural):

```json
{
  "name": "default_rdp",
  "services": "RDP",
  "threshold_count": 3,
  "window_minutes": 30,
  "actions": "email,block",
  "enabled": true,
  "email_cooldown_min": 10,
  "match_usernames": ""
}
```

---

## Mevcut endpoint uyumu

Agent zaten cekiyor:

```
GET /api/premium/rules?token=CLIENT_TOKEN
```

Donus: `list` veya `{ "rules": [ ... ] }`

Seed sonrasi agent bir sonraki `THREAT_CONFIG_SYNC` (yaklasik 5 dk) veya restart ile alir.
Istege bagli: seed sonrasi ilgili sunuculara config bump / websocket `rules_updated`.

CRUD (varsa koru):

- `POST /api/premium/rules` — tek kural ekle
- `PUT` / `PATCH /api/premium/rules/{id}`
- `DELETE /api/premium/rules/{id}`

Seed bunlari bozmamali; sadece `default_*` setini yonetmeli.

---

## Acceptance

- [ ] Kuralsiz hesapta buton -> 6 kural listede gorunur
- [ ] Ikinci tik -> duplicate yok (`skipped: 6`)
- [ ] Agent log: `[THREAT] Block rules updated: ['default_rdp', ...]`
- [ ] Honeypot bait kapali, gercek RDP 3389'a 3 fail -> block + alert
- [ ] Kullanicinin `My custom RDP` kurali `upsert` ile silinmez
- [ ] `reset_defaults` sadece `default_*` satirlarini yeniler

---

## Client notu (dashboard metni icin)

Iki katman:

1. **Port izleme** — EventLog + bu kurallar (orijinal portlar, bait gerekmez)
2. **Honeypot bait** — ayri porta sahte servis (opsiyonel)

Buton aciklamasinda:

```
Honeypot'u acmadan da gercek RDP/SSH fail'lerini engeller.
```

---

## Kaynak: `AGENT_CLEAR_FIREWALL_PROMPT.md`

# Agent Prompt: `clear_firewall` komutu (Dashboard temizlik)

> **Kime:** Windows honeypot-client  
> **Tarih:** 2026-07-18  
> **Bağlam:** Dashboard Hesap → Bakım/Temizlik artık DB’yi silerken agent’a `clear_firewall` kuyruğa atıyor. Agent işlemezse Windows’ta `HP-BLOCK-*` kuralları kalır.

## Komut

`GET /api/commands/pending` içinde:

```json
{
  "command_id": "uuid",
  "command_type": "clear_firewall",
  "priority": "critical",
  "params": {
    "wipe_all_honeypot_rules": true,
    "ips": ["1.2.3.4", "..."],
    "reason": "dashboard_firewall_cleanup",
    "count": 12
  }
}
```

## Uygula

1. `wipe_all_honeypot_rules == true` ise: adı `HP-BLOCK`, `HONEYPOT_BLOCK`, `HONEYPOT_BLOCK_REMOTE` ile başlayan **tüm** advfirewall kurallarını sil.
2. Ek olarak `params.ips[]` için bilinen isim şablonlarıyla tek tek sil (yedek).
3. Yerel blok cache / JSON listesini boşalt.
4. `POST /api/commands/result` → `completed` + silinen kural sayısı.
5. İsteğe bağlı: `POST /api/agent/sync-rules` `{blocks:[], total_rules:0}`.

Örnek:

```bat
netsh advfirewall firewall show rule name=all | findstr /I "HP-BLOCK HONEYPOT_BLOCK"
netsh advfirewall firewall delete rule name="HP-BLOCK-1.2.3.4"
```

PowerShell: `Get-NetFirewallRule` filtre + `Remove-NetFirewallRule`.

## Acceptance

- [ ] Dashboard “Firewall blokları temizle” → ≤ 60 sn Windows’ta honeypot block kuralı kalmaz
- [ ] `commands/result` success
- [ ] Kritik priority; poll ≤ 2 sn

---

## Kaynak: `AGENT_BLOCK_CLEANUP_PROMPT.md`

# Agent Prompt: Stale Block Cleanup (Firewall Unblock Sync)

> **Kime:** Windows tray / honeypot client uygulamasını geliştiren yapay zeka  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Auth:** Tüm isteklerde `token` (UUID)  
> **Tarih:** 2026-07-18  
> **Bağlam:** Cloud API artık eski / geçersiz IP bloklarını periyodik temizler. Client’ın firewall kurallarını buna göre senkron kaldırması **zorunlu**; aksi halde sunucu DB’de blok kalkmış görünür ama Windows firewall şişmeye devam eder.

---

## 1) Senin görevin

1. Cloud’un `remove_pending` kuyruğunu düzenli çek (`pending-unblocks`).
2. Her IP için yerel firewall kuralını **sil**.
3. Başarılı silmelerde sunucuya `block-removed` teyidi gönder.
4. Yerel “kalıcı blok” listeni / cache’ini de temizle (yeniden ekleme).
5. Dashboard `unblock_ip` komutunu da aynı silme yolundan geçir.
6. Bitince kısa “ne değişti + acceptance checklist” yaz.

**Önemli:** Attack / event geçmişini client silmez — o iş **sadece sunucuda**. Client sadece **firewall sync** yapar.

---

## 2) Sunucu tarafı politika (bilgi — değiştirme)

Cloud background job (~15 dk):

| Kural | Davranış |
|--------|----------|
| Applied IP bloğu | Son **30 gündür** o IP’den bu client’a **saldırı yoksa** → `status=remove_pending` |
| `AutoBlock.expires_at` geçmiş | `is_active=false` + eşleşen `BlockRule` → `remove_pending` |
| `country:*` / CIDR (`/`) | Idle sweep’e **dahil değil** |
| Attack geçmişi | Sunucu 180 günden eski satırları batch siler (client işi değil) |

İlk temizlikte yüzlerce `remove_pending` birikebilir — agent bunları **batch** işlemeli, tek tek timeout olmamalı.

---

## 3) Zorunlu poll döngüsü

Mevcut block sync döngüsüne (veya ayrı timer) ekle:

```
Her 30–60 saniye:
  1) GET  /api/agent/pending-blocks?token=...
  2) GET  /api/agent/pending-unblocks?token=...   ← TEMİZLİK İÇİN KRİTİK
  3) (opsiyonel) GET /api/commands/pending … unblock_ip
```

`pending-blocks` ve `pending-unblocks` **aynı sıklıkta** poll edilsin. Unblock poll’u eksikse firewall asla incelmez.

---

## 4) API sözleşmesi

### 4.1 Kaldırılacakları çek

```
GET /api/agent/pending-unblocks?token=CLIENT_TOKEN
```

Örnek yanıt:

```json
[
  { "id": 101, "ip_or_cidr": "185.220.101.1" },
  { "id": 102, "ip_or_cidr": "45.33.32.156" }
]
```

- Boş liste `[]` → yapılacak yok.
- `ip_or_cidr` tek IPv4/IPv6 olabilir (bu kuyrukta genelde tek IP).
- `id` = `block_rules.id` — teyitte **tercihen bunu** kullan.

### 4.2 Yerel firewall’dan sil

Windows (örnek — mevcut naming’inize uyun):

```text
netsh advfirewall firewall delete rule name="HONEYPOT_BLOCK_REMOTE_{ip}"
```

veya sizin kullandığınız rule name şablonu (`HP-BLOCK-{ip}`, `HONEYPOT_BLOCK_REMOTE_{ip}`, vb.).

Kurallar:

1. Bilinen tüm olası rule name varyantlarını dene (eski client sürümleri farklı isim kullanmış olabilir).
2. Kural yoksa (`not found`) → **hata sayma**; teyit yine gönder (idempotent).
3. Aynı IP için birden fazla rule varsa hepsini sil.
4. Batch: örn. 20–50 IP’lik gruplar; aralarında kısa sleep (CPU/firewall kilidi).

### 4.3 Sunucuya teyit (zorunlu)

**Tercih edilen (id listesi):**

```json
POST /api/agent/block-removed
{
  "token": "CLIENT_TOKEN",
  "block_ids": [101, 102]
}
```

**Alternatif (IP ile — id yoksa):**

```json
POST /api/agent/block-removed
{
  "token": "CLIENT_TOKEN",
  "ip": "185.220.101.1"
}
```

Başarı: `{ "updated": N, "status": "ok" }`

Sonuç:

- `block_rules.status` → `removed`
- Eşleşen `auto_blocks.is_active` → `false`

**Teyit göndermezsen:** kuyruk `remove_pending`’de kalır, her poll’da tekrar gelir → sonsuz silme denemesi. Mutlaka ACK at.

Kısmi başarı: silinenlerin `block_ids`’ini gönder; başarısızları bir sonraki poll’a bırak (retry).

---

## 5) Dashboard / komut yolu (`unblock_ip`)

Pending commands içinde:

```json
{
  "command_type": "unblock_ip",
  "params": { "ip": "1.2.3.4" }
}
```

Aynı yerel silme fonksiyonunu çağır → komut sonucunu raporla.  
Mümkünse ardından (veya cloud zaten `remove_pending` yaptıysa) `block-removed` ile de hizala.

---

## 6) Yerel state / cache

Client’ta tutuyorsanız şunları da güncelleyin:

| Yerel kayıt | Unblock sonrası |
|-------------|-----------------|
| Active blocked IP set | IP’yi çıkar |
| Rule name map | Kaydı sil |
| “Permanent block” flag | Temizlik sonrası kalıcı sayma — cloud idle policy geçerli |
| Disk’e yazılan block listesi | Persist’i güncelle (restart’ta yeniden ekleme!) |

**Anti-pattern:** Restart’ta local JSON’daki tüm IP’leri tekrar `block` etmek. Kaynak of truth = cloud (`pending-blocks` / `pending-unblocks` + isteğe bağlı full sync).

Önerilen boot sırası:

1. Local firewall’daki `HONEYPOT_*` / `HP-BLOCK_*` kurallarını say.
2. `pending-unblocks` çek → sil + ACK.
3. `pending-blocks` çek → ekle + `block-applied`.
4. (Opsiyonel) `POST /api/agent/sync-rules` ile özet sayı bildir.

---

## 7) `auto-block` süresi ile ilişki

```json
POST /api/alerts/auto-block
{
  "token": "...",
  "blocked_ip": "1.2.3.4",
  "duration_hours": 24,
  ...
}
```

- `duration_hours > 0` → cloud `expires_at` yazar; süre dolunca `remove_pending`.
- `duration_hours: 0` (kalıcı) → yine de **30 gün saldırı yoksa** cloud stale cleanup ile kaldırır.
- Client tarafında “sonsuz kalıcı” varsayma; her zaman unblock kuyruğunu dinle.

Öneri: yeni auto-block’larda varsayılan `duration_hours: 24` veya `168` (7 gün) kullan; `0`’ı sadece gerçek compromise için sakla.

---

## 8) Hata ve edge case

| Durum | Beklenen davranış |
|--------|-------------------|
| `pending-unblocks` 401/403 | Token yenile / logla; poll’a devam |
| Firewall delete fail (access denied) | Log + retry; ACK **gönderme** |
| Rule zaten yok | ACK gönder (başarılı say) |
| Aynı IP hem pending-block hem pending-unblock | Unblock’u önce uygula (veya cloud tutarlılığına güven; çakışmayı logla) |
| İlk açılışta 300+ unblock | Batch + progress log; UI’da “Firewall senkronize ediliyor…” |
| CIDR / country kuralı gelirse | Destekliyorsan sil; desteklemiyorsan logla, ACK’yi IP-only için gönder |

---

## 9) Log / gözlem

Her sync turunda (debug):

```text
[FW-SYNC] pending_blocks=3 pending_unblocks=42 removed=40 failed=2
```

Cloud’da `reason` alanında şunlar görünebilir (sadece bilgilendirme):

- `[stale-30d]` — 30 gün idle
- `[expired]` — AutoBlock süresi dolmuş

---

## 10) Acceptance checklist

- [ ] Her 30–60 sn `GET /api/agent/pending-unblocks`
- [ ] Dönen her IP için firewall kuralı siliniyor
- [ ] Başarılı / no-op silmelerde `POST /api/agent/block-removed` (`block_ids` tercih)
- [ ] Restart sonrası eski local block listesi körlemesine yeniden eklenmiyor
- [ ] `unblock_ip` komutu aynı silme yolunu kullanıyor
- [ ] İlk sync’te 100+ unblock batch olarak tamamlanıyor (takılmadan)
- [ ] Dashboard “Aktif Blok” sayısı, agent sync sonrası düşüyor
- [ ] Yeni saldıran IP tekrar bloklanabiliyor (`pending-blocks` / auto-block hâlâ çalışıyor)

---

## 11) Minimal referans akış (pseudo)

```text
loop every 30s:
  unblocks = GET /api/agent/pending-unblocks?token=T
  done_ids = []
  for item in unblocks:
    ok = DeleteFirewallRule(item.ip_or_cidr)  // missing rule => ok
    if ok: done_ids.append(item.id)
  if done_ids:
    POST /api/agent/block-removed { token: T, block_ids: done_ids }

  blocks = GET /api/agent/pending-blocks?token=T
  applied_ids = []
  for item in blocks:
    ok = AddFirewallRule(item.ip_or_cidr, item.reason)
    if ok: applied_ids.append(item.id)
  if applied_ids:
    POST /api/agent/block-applied { token: T, block_ids: applied_ids }
```

---

## 12) Özet (tek cümle)

**Cloud “bu IP’yi artık engelleme” der (`remove_pending`) → sen firewall’dan silersin → `block-removed` ile onaylarsın; 30 gün idle / expire politikası sunucuda, sen sadece sync’i eksiksiz uygula.**

---

## Kaynak: `DASHBOARD_CLEANUP_API_PROMPT.md`

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

---

## Kaynak: `AGENT_DISABLE_ALL_USERS_PROMPT.md`

# AGENT_DISABLE_ALL_USERS_PROMPT.md

Tek sözleşme — cloud + agent. Client **≥ 4.5.23**.

## Amaç

Dashboard **Disable All Users** (panik) → cloud `POST /api/commands/send` → agent pending poll → **tüm yerel SAM kullanıcı hesaplarını disable et**.

- **Administrator dahil** disable edilir.
- İsteğe bağlı `exclude` = break-glass (disable edilmez).
- Recovery: dashboard’dan `reset_password` → `enable_account`.

Tek kullanıcı için `disable_account` ayrı kalır; bu komut kitle kilidi içindir.

---

## Cloud

| Alan | Değer |
|------|--------|
| `command_type` | `disable_all_users` |
| `priority` | `critical` (cloud zorlar) |
| TTL | 15 dk |
| Body | `params` |
| Whitelist | `VALID_COMMAND_TYPES` |
| UI | Threats panik butonu + critical alert + onay diyaloğu |

### Send

```json
{
  "token": "…",
  "command_type": "disable_all_users",
  "priority": "critical",
  "params": {
    "logoff": true,
    "exclude": []
  }
}
```

| Param | Zorunlu | Varsayılan | Açıklama |
|-------|---------|------------|----------|
| `logoff` | hayır | `true` | Disable öncesi aktif oturumları kes |
| `exclude` | hayır | `[]` | string veya string[] — break-glass; bu hesaplar disable edilmez |

Break-glass örneği: `"exclude": ["BreakGlassAdmin"]`

### Pending (agent’ın gördüğü)

```json
{
  "command_id": "…",
  "command_type": "disable_all_users",
  "priority": "critical",
  "params": {
    "logoff": true,
    "exclude": [],
    "triggered_by": "dashboard"
  }
}
```

---

## Agent

`commands/pending` içinde `disable_all_users` → **hemen** uygula (takvim / soft kuyruk yok; critical poll).

1. Yerel hesapları listele: `Get-LocalUser` (fallback: `net user` / SAM).
2. Domain-only hesaplara dokunma; yalnızca yerel SAM.
3. **Hard skip** (asla disable etme — bunlar gerçek “kullanıcı paniği” hedefi değil):
   - `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`
   - `WDAGUtilityAccount`, `DefaultAccount`
   - + `params.exclude` (break-glass)
4. **Administrator disable edilir** (`exclude` edilmedikçe).
5. Diğer tüm yerel hesaplar: `net user {name} /active:no` (veya eşdeğeri).
6. `logoff == true` ise disable öncesi/sırasında aktif oturumları logoff et.
7. Concurrent: aynı anda tek `disable_all_users` (lock).
8. Result: `POST /api/commands/result`

### Result (başarı)

```json
{
  "command_id": "…",
  "status": "completed",
  "result": {
    "ok": true,
    "disabled": ["Administrator", "muhasebe", "tarik"],
    "disabled_count": 3,
    "skipped": [
      {"username": "DefaultAccount", "reason": "protected"}
    ],
    "failed": [],
    "logged_off": ["Administrator", "muhasebe"]
  }
}
```

Kısmi başarı: `status: "completed"`, `ok: false`, `failed: [{"username":"…","error":"…"}]`.  
Tam hata: `status: "failed"`.

### Lifecycle (opsiyonel)

`POST /api/alerts/lifecycle`  
`disable_all_users_begin` / `disable_all_users_ok` / `disable_all_users_failed`

---

## Güvenlik

- Dashboard onay diyaloğu zorunlu.
- Yanlışlıkla tüm hesapları kilitleme riski yüksek — break-glass için önceden `exclude` planla.
- Recovery: `reset_password` `{username, new_password}` → `enable_account` `{username}`.
- Domain controller: yalnızca local SAM; AD domain user toplu disable yok.

---

## Acceptance

- [ ] Dashboard **Disable All Users** → pending `disable_all_users` + `logoff` + `priority=critical`
- [ ] Agent poll &lt; ~60s → tüm yerel hesaplar `/active:no` (**Administrator dahil**)
- [ ] Hard-skip + `exclude` dokunulmamış
- [ ] `logoff: true` → oturumlar düşer
- [ ] Result: `disabled` / `skipped` / `failed` / `logged_off`
- [ ] Recovery: `reset_password` + `enable_account` çalışır
- [ ] Tekil `disable_account` bozulmaz

