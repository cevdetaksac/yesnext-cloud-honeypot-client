# Auth & Token

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_BEARER_TOKEN_AUTH_API_PROMPT.md`

# AGENT_BEARER_TOKEN_AUTH_API_PROMPT.md

> **Kime:** Honeypot Cloud / API (`https://honeypot.yesnext.com.tr`)  
> **Konu:** Agent token’ı **query string’den çıkarıp** `Authorization: Bearer` header’a taşımak  
> **Öncelik:** P0 (MITM / access-log / proxy sızıntısı yüzeyi)  
> **Tarih:** 2026-07-20  
> **Client:** zaten Bearer gönderiyor; `api.legacy_token_query` ile query’ye de kopyalıyor (varsayılan `true`). Cloud hazır olunca client `legacy_token_query=false` yapacak.

---

## Amaç

Agent ↔ API trafiğinde kimlik bilgisini URL’den kaldırmak.

| Bugün (riskli) | Hedef |
|----------------|--------|
| `GET /api/commands/pending?token=UUID` | `GET /api/commands/pending` + `Authorization: Bearer UUID` |
| `GET /api/…?token=…` (birçok endpoint) | Aynı path, token **sadece header** (ve gerekirse JSON body) |
| WS `wss://…/ws/remote/agent?token=…` | Tercihen header / `Sec-WebSocket-Protocol` / ilk auth frame — query deprecate |

**Neden P0:** Query token; Cloudflare / origin access log, reverse proxy log, browser history, referrer, destek ticket ekran görüntüsüne düşer. TLS payload’ı korur ama **URL sıkça loglanır**.

Dashboard kullanıcı parolası bunu kapsamaz — agent token ayrı kimliktir.

---

## Auth çözüm sırası (cloud middleware — zorunlu)

Tüm **agent** endpoint’lerinde token’ı şu sırayla bul:

1. **`Authorization: Bearer <token>`** (tercih edilen, kanonik)
2. **JSON body `token`** (POST/PUT — geçiş + mevcut client uyumu)
3. **Query `?token=`** — **sadece geçiş dönemi**; deprecate

```text
resolve_agent_token(request):
  h = Authorization header
  if h matches /^Bearer\s+(\S+)/i → return capture
  if JSON body.token → return body.token
  if query.token → return query.token   # phase 1 only
  → 401 missing_token
```

Kurallar:
- Bearer varsa **query’deki token yok sayılabilir** (çakışmada Bearer kazanır; log’a yazma).
- Token boş / geçersiz → **401** (`{"error":"invalid_token"}` veya mevcut şema).
- Response / error body içinde **token’ı echo etme**.

---

## Faz planı

### Faz 1 — Dual-read (hemen, kırılmadan)

- Middleware Bearer + body + query kabul eder.
- Query ile gelen isteklerde **metric / log flag**: `auth_source=query|bearer|body`.
- Access log / CF log’ta query’den `token=` **redact** (`token=***` veya parametreyi strip et).
- Dokümantasyon: yeni entegrasyonlar sadece Bearer.

### Faz 2 — Client cutover

- Client release: `api.legacy_token_query = false` (sadece Bearer + gerekirse body).
- Fleet çoğunluğu yeni client’a geçince Faz 3.

### Faz 3 — Query reject (hedef)

- Agent API’de `?token=` **401** veya **400** `token_query_deprecated`.
- En az 1 minor client sürümü + duyuru sonrası.
- İstisna yok (aşağıdaki “kapsam dışı” hariç).

---

## Kapsam — agent API (güncellenmeli)

Aşağıdakiler (ve `token` query bekleyen diğer agent route’lar) Bearer kabul etmeli:

| Grup | Örnek path’ler |
|------|----------------|
| Komutlar | `GET /api/commands/pending`, `POST /api/commands/result` |
| Heartbeat / status | `POST/GET /api/heartbeat`, `client_status`, `agent/account-status` |
| Threat / health | `POST /api/health/report`, attack, sessions/processes |
| Firewall | `GET /api/agent/pending-blocks`, `pending-unblocks`, sync-rules |
| Premium / tunnel | `GET /api/premium/tunnel-status`, rules |
| Remote desktop HTTP | `POST /api/remote/frame`, `frame-json`, `GET /api/remote/inputs`, … |
| Lifecycle / alerts | `POST /api/alerts/lifecycle` |
| Logon challenge | ilgili agent endpoint’leri |
| Open ports / IP | `POST /api/agent/open-ports`, update-ip, … |

**Register** (`POST /api/register`): token henüz yok — Bearer gerekmez; değişmez.

**Public** (`GET /api/public/latest-release` vb.): auth yok — değişmez.

### WebSocket (ayrı madde)

Bugün: `wss://…/ws/remote/agent?token=…`

Hedef (sırayla tercih):

1. **Faz 1:** Query hâlâ kabul (mevcut client kırılmasın) + log redact  
2. **Faz 2:** Aynı URL’de **ek** olarak `Authorization: Bearer` (bazı WS client’ları destekler) **veya**  
   `Sec-WebSocket-Protocol: bearer, <token>` (standart kaçış yolu)  
3. **Faz 3:** Query token kapat; client WS URL’sinden `token` kaldırılır

Cloud en azından Faz 1’de WS query redact + Bearer/protocol opsiyonunu dokümante etsin; client WS taşını ayrı PR.

---

## Kapsam dışı (karıştırma)

Bunlar **dashboard kullanıcı oturumu / deep-link**; agent Bearer migration’ının parçası değil (ayrı güvenlik konusu):

- Tarayıcı: `/dashboard?token=…` (GUI “paneli aç” linki)
- İnsan kullanıcı cookie / session login

İleride dashboard deep-link’i de kısa ömürlü ticket’a çevrilebilir; bu prompt’un P0’ı **agent API**.

---

## Response / hata sözleşmesi

| Durum | HTTP | Not |
|-------|------|-----|
| Token yok | 401 | `missing_token` |
| Token geçersiz / revoke | 401 | `invalid_token` |
| Query-only, Faz 3 sonrası | 401/400 | `token_query_deprecated` |
| Auth OK | mevcut 200 davranışı | body şeması değişmez |

CORS: Dashboard origin’den agent token ile çağrı yoksa ek CORS gerekmez. Agent native client — CORS irrelevant.

---

## Cloudflare / logging checklist

- [ ] Transform / custom rule: query `token` değerini log’lardan maskele  
- [ ] Origin (nginx/uvicorn/gunicorn) access log: query redact  
- [ ] Application error tracker: URL’de raw token saklama  
- [ ] Support export / debug dump: token scrub  
- [ ] SSL/TLS mode: **Full (strict)** (ayrı ama aynı güvenlik paketinin parçası)

---

## Client tarafı (referans — cloud hazır olunca)

Mevcut client (`client_api._prepare_request`):

- Her zaman `Authorization: Bearer <token>` gönderir  
- `api.legacy_token_query=true` iken ayrıca `?token=` ekler  
- POST body’ye de `token` koyar (uyumluluk)

Cloud Faz 1 canlı olduktan sonra client config:

```json
"api": {
  "legacy_token_query": false,
  "tls_verify": true
}
```

Varsayılanı `false` yapan client sürümü + release notes.

---

## Acceptance

### Faz 1
- [ ] `curl -H "Authorization: Bearer $TOKEN" https://honeypot.yesnext.com.tr/api/commands/pending` → 200 (query yok)
- [ ] Eski: `…/commands/pending?token=$TOKEN` (Authorization yok) → hâlâ 200
- [ ] Bearer + yanlış query → Bearer kullanılır, 200
- [ ] Token yok → 401
- [ ] Access log’ta raw UUID token görünmez (redact doğrula)

### Faz 2
- [ ] Yeni client (`legacy_token_query=false`) fleet’te komut poll / heartbeat / RD HTTP çalışır

### Faz 3
- [ ] `?token=` only → 401/400 deprecated
- [ ] Bearer-only → 200

---

## Yapılmayacaklar

- Token’ı response JSON’da tekrar etmek
- Query’yi kapatmadan önce client cutover’sız hard-break (Faz 3’ü erken yapma)
- Register / public endpoint’lere Bearer zorunluluğu eklemek
- Dashboard login’i agent Bearer ile birleştirmek

---

## Özet (cloud mühendis)

1. Ortak `resolve_agent_token`: Bearer → body → query  
2. Tüm agent route’lar bu helper’ı kullansın  
3. Log redact  
4. Metric `auth_source`  
5. Duyuru → client `legacy_token_query=false` → sonra query reject  

**Bu prompt cloud implementasyonu içindir.** Client cutover ayrı küçük release.

---

## Kaynak: `AGENT_TOKEN_IMMUTABLE_API_PROMPT.md`

# Agent Prompt: Immutable client token (machine identity)

> **Kime:** Honeypot Cloud / API  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Istek:** Agent token **asla degismemeli / silinmemeli** — sunucunun kimligi (MAC gibi).  
> **Client (v4.4.33+):** Token artik `%ProgramData%\YesNext\CloudHoneypotClient\token.dat` (SYSTEM + user ortak). `/register` isteginde `machine_id` (Windows MachineGuid) gonderir.

---

## Problem

Client daha once token'i `%APPDATA%\...` altinda tutuyordu. Daemon **SYSTEM**, GUI **user** → iki farkli `token.dat` → iki `/register` → API'de eski token "silindi / yok" gibi gorunuyor, yeni orphan Client doguyor.

Client tarafinda:
- Token ProgramData'ya tasindi
- Decrypt/load fail olunca **otomatik yeniden register YOK**
- Mevcut token uzerine farkli token yazmak **yasak**

API tarafinda da ayni sozlesme sart.

---

## Yapilacaklar (P0)

### 1) `POST /api/register` → **upsert by machine_id**

Body (client gonderir):

```json
{
  "server_name": "HOST (1.2.3.4)",
  "ip": "1.2.3.4",
  "machine_id": "{Windows-MachineGuid}",
  "hwid": "{Windows-MachineGuid}"
}
```

Davranis:

1. `machine_id` / `hwid` doluysa: ayni `machine_id` ile Client var mi bak.
2. Varsa: **ayni token'i geri don** (yeni token URETME). IP / server_name guncelle.
3. Yoksa: yeni Client + token olustur, `machine_id` kaydet.
4. `machine_id` yoksa (eski client): eski davranis — ama mumkunse soft-deprecate.

Basarili yanit (200):

```json
{
  "token": "<stable-token>",
  "client_id": 123,
  "machine_id": "...",
  "reused": true
}
```

`reused: true|false` opsiyonel ama faydalı.

### 2) Token / Client silme politikasi

- Idle / offline / re-register → Client satirini **SILME**
- Soft archive / `active=false` kabul; token string ayni kalsin
- Admin "revoke" ayri explicit endpoint olsun; otomatik garbage-collect token'i silmesin
- Dashboard "token deleted" yerine: inactive / replaced_by / archived mesaji

### 3) Opsiyonel reclaim

`existing_token` + `machine_id` gelirse ve token o machine'e aitse ayni token'i dogrula.

---

## Yapilmayacaklar

- Her `/register` cagrisinda yeni token mint etmek
- Heartbeat gelmeyince Client/token hard-delete
- machine_id eslesince token rotate

---

## Test

1. Ayni makineden iki process (SYSTEM + user) `/register` + ayni `machine_id` → **tek token**.
2. Token.dat silinmeden process restart → ayni token.
3. Eski AppData token'li makine migrate → client ProgramData'ya kopyalar; API ayni token'i gormeli.
4. Bilinmeyen machine_id → yeni token (gercek first-run).

---

## Not

Client v4.4.33+ `machine_id` gondermeye baslar. API hazir olana kadar register yine 200+token donmeli; upsert gelince orphan uretimi durur.

