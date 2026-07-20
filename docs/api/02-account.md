# Account Link & Multi-Server

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_ACCOUNT_LINK_INAPP_API_PROMPT.md`

# Agent Prompt: In-app Account Link (email + password + agent token)

> **Kime:** Honeypot Cloud / API  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Istek:** Windows client icinden popup ile e-posta + sifre alip **bu makinenin agent token'ini** hesaba baglamak.  
> **Client (v4.4.37+):** Once bu endpoint'i dener; yoksa web form fallback (`/account/login` + `/account/link-server`).

---

## P0 — Tek JSON endpoint (onerilen)

### `POST /api/agent/link-account`

Auth: **yok** (email/password body'de). Agent token body'de.

```json
{
  "email": "user@example.com",
  "password": "secret",
  "token": "<agent-client-token>"
}
```

Alias kabul edilebilir: `client_token` / `agent_token` ayni anlama.

### Davranis

1. Email+password ile Account authenticate (mevcut login ile ayni kurallar).
2. Token ile `Client` bul; yoksa `404 {"detail":"Client not found"}`.
3. `AccountClient` membership olustur (zaten varsa no-op / idempotent).
4. Sifre/hash **asla** response'ta donme.

### 200 OK

```json
{
  "ok": true,
  "account_linked": true,
  "client_id": 123,
  "server_name": "WIN-XXXX",
  "account": {
    "id": 45,
    "email": "user@example.com",
    "display_name": "User"
  },
  "linked_at": "2026-07-18T18:00:00Z"
}
```

### Hatalar

| Kod | detail |
|-----|--------|
| 401 | Invalid credentials |
| 404 | Client not found |
| 422 | email/password/token missing |
| 429 | rate limit (brute-force korumasi) |

### Guvenlik

- Rate limit (IP + email)
- TLS zorunlu
- Lockout / backoff mevcut login ile ayni
- Log'a password yazma

---

## P1 — Status ile tutarlilk

Link sonrasi ayni token ile:

`GET /api/agent/account-status?token=` → `account_linked: true`

(zaten v4.4.29+ client bunu okuyor)

---

## Not (mevcut web — dokunma)

- `POST /account/login` (form: email, password)  
- `POST /account/link-server` (session + token)  

Client bunlari **fallback** olarak kullanir; JSON endpoint gelince tek cagrıya gecer.

---

## Kaynak: `AGENT_ACCOUNT_LINK_STATUS_API_PROMPT.md`

# Agent Prompt: Account Link Status API (agent token ile)

> **Kime:** Honeypot Cloud / API geliştiren AI  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **İstek sahibi:** Windows `honeypot-client` (v4.4.28+)  
> **Sorun:** Agent UI “Hesaba bağla” CTA’sını gösteriyor/gizliyor; cloud’da `AccountClient` membership var ama **agent token ile sorgulanabilir bir status endpoint yok**. Agent şu an yalnızca local `ProgramData\...\account_link.json` + manuel işaretleme kullanıyor.

---

## 0) Mevcut durum (kontrol listesi)

Cloud’da zaten var (dokunma / bozma):

| Endpoint | Auth | Not |
|----------|------|-----|
| `POST /account/register` | public | Account oluşturur |
| `POST /account/login` | public | Session cookie |
| `POST /account/link-server` | Account session | Token veya server+şifre ile `AccountClient` |
| `POST /account/unlink-server` | Account session | |
| `GET /api/account/me` | Account cookie | Agent token ile **401** |
| `GET /api/account/servers` | Account cookie | Agent token ile **401** |
| `GET /api/client_status?token=` | Agent token | Alive/sync; **account alanları yok** |
| `POST /api/heartbeat` | Agent token | Account bilgisi dönmüyor |

Agent (client) zaten şu alanları okumaya hazır (`refresh_account_link_status`):

- `account_linked` / `linked` / `has_account` / `is_linked` / `linked_to_account`
- veya `account: { email|id|linked }`
- veya `accounts: []` (doluysa linked)

Öncelikli path denemesi: **`GET /api/agent/account-status?token=`**  
Fallback: `GET /api/client_status?token=` içine aynı alanları eklemek.

---

## 1) Yapılması gereken (P0) — yeni endpoint

### `GET /api/agent/account-status`

**Auth:** agent client token (query `token=` **veya** body/header — mevcut agent convention ile aynı; `client_status` gibi `?token=` yeterli).

**Davranış:**

1. Token ile `Client` bul; yoksa `404 {"detail":"Client not found"}`.
2. `AccountClient` (veya eşdeğer membership) tablosunda bu `client_id` için kayıt var mı bak.
3. Varsa bağlı Account’un **güvenli** özetini dön (şifre/hash asla dönme).

### Başarılı yanıt (200) — bağlı

```json
{
  "account_linked": true,
  "client_id": 123,
  "server_name": "WIN-XXXX",
  "account": {
    "id": 45,
    "email": "user@example.com",
    "display_name": "User"
  },
  "linked_at": "2026-07-18T12:00:00Z"
}
```

### Başarılı yanıt (200) — bağlı değil

```json
{
  "account_linked": false,
  "client_id": 123,
  "server_name": "WIN-XXXX",
  "account": null,
  "linked_at": null
}
```

### Hatalar

| Kod | Durum |
|-----|--------|
| 404 | Token geçersiz / client yok |
| 401/403 | İstersen token zorunlu validation (tercihen 404 ile aynı leak profili `client_status` ile hizalı kalsın) |

**Privacy:** `email` agent makinesinde görünecek — kabul edilebilir (kendi sunucusu). İsterseniz `email_masked`: `u***@example.com` de ekleyin; agent maskeli alanı da okuyabilir (opsiyonel).

---

## 2) Yapılması gereken (P1) — mevcut endpoint’lere alan ekle

Agent her health/heartbeat döngüsünde ekstra call istemesin diye **en az birinde** aynı bayrağı yayın:

### A) `GET /api/client_status?token=`

Mevcut JSON’a ekle:

```json
{
  "alive": true,
  "status": "online",
  "account_linked": true,
  "account": { "email": "user@example.com", "id": 45 }
}
```

Bağlı değilse: `"account_linked": false`, `"account": null`.

### B) `POST /api/heartbeat` response (tercihen)

Bugün çoğu yerde sadece başarı/`null` dönülüyor olabilir. Mümkünse 200 body:

```json
{
  "ok": true,
  "account_linked": false
}
```

Agent heartbeat’ten de sync edebilir (ileride).

---

## 3) Yapılmaması gerekenler

- Account cookie / bcrypt / dashboard şifresini agent’a açma
- Agent token olmadan başka client’ın account bilgisini sızdırma
- `GET /api/account/me` veya `/api/account/servers`’ı agent token ile açmak (farklı auth modeli; karıştırma)
- Link işlemini agent’tan zorunlu kılma — web `POST /account/link-server` yeterli; bu ticket **sadece status read**

---

## 4) SQL / model kontrolü (sizin şemanıza göre uyarlayın)

Pseudocode:

```text
client = Client.by_token(token)
if not client: 404

row = AccountClient.where(client_id=client.id).first()
# veya: Account.clients.any(id=client.id)

account_linked = row is not None
account = { id, email, display_name } if row else null
```

Index: `AccountClient(client_id)` unique veya `(account_id, client_id)` — status sorgusu O(1) olmalı.

---

## 5) Acceptance checklist (cloud)

- [ ] `GET /api/agent/account-status?token=<valid>` → 200 + `account_linked` bool
- [ ] Bağlı client → `account_linked: true` + `account.email` (veya masked)
- [ ] Bağlı olmayan client → `account_linked: false`, `account: null`
- [ ] Geçersiz token → 404 (client_status ile aynı stil)
- [ ] `link-server` sonrası aynı token ile status `true` olur (≤ birkaç sn)
- [ ] `unlink-server` sonrası `false` olur
- [ ] OpenAPI’ye path + örnek response ekli
- [ ] (P1) `client_status` içinde de `account_linked` görünür

---

## 6) Agent tarafı (bilgi — cloud implement edince otomatik çalışır)

Windows client `v4.4.28+`:

1. GUI açılışında `refresh_account_link_status(token)` çağırır  
2. Önce `GET .../api/agent/account-status?token=` dener  
3. `account_linked: true` → local flag + UI’da “Hesaba bağlı” rozeti (CTA gizlenir)  
4. Endpoint 404 ise sessizce local/manuel moda düşer  

Cloud endpoint canlı olunca agent’ta ek zorunlu değişiklik gerekmez; isteğe bağlı: heartbeat’ten de sync, local flag’i API’yi source-of-truth sayarak ezme.

---

## 7) Hızlı test (curl)

```bash
# Bağlı olmayan / bilinen token
curl -sS "https://honeypot.yesnext.com.tr/api/agent/account-status?token=YOUR_AGENT_TOKEN"

# Beklenen: {"account_linked":true|false, ...}

# client_status P1
curl -sS "https://honeypot.yesnext.com.tr/api/client_status?token=YOUR_AGENT_TOKEN" | jq .account_linked
```

---

## 8) Tek cümle özet

**Agent token ile `AccountClient` membership’i sorgulayan `GET /api/agent/account-status` ekleyin; `account_linked` (+ opsiyonel `account.email`) dönün; mümkünse aynı alanı `client_status`’a da koyun.**

---

## Kaynak: `AGENT_ACCOUNT_MULTI_SERVER_PROMPT.md`

# Agent Prompt: Çoklu Sunucu / Hesap (Account) Kaydı

> **Kime:** Windows honeypot-client geliştiren AI  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Bağlam:** Cloud tarafında e-posta ile üyelik (`Account`) + birden fazla agent sunucusunu tek hesaba bağlama (`AccountClient`) hazır. Agent tarafında **zorunlu API değişikliği yok**; UX / onboarding iyileştirmeleri isteniyor.

---

## 0) Mimari (cloud — zaten canlı)

| Kavram | Anlam |
|--------|--------|
| `Client` | Tek Windows host / agent token |
| `Account` | E-posta + şifre ile üyelik (çok sunucu) |
| `AccountClient` | Account ↔ Client membership |

Kullanıcı akışı (web):

1. Landing → **Register** (`POST /account/register`) → `/servers`
2. **Link server**: agent token **veya** sunucu adı + dashboard şifresi (`POST /account/link-server`)
3. Login e-posta ile → tek sunucuysa dashboard, birden fazlaysa `/servers` + header switcher

Agent hâlâ klasik `POST /api/register` ile `Client` oluşturur; token local’de saklanır.

---

## 1) Agent’ta yapılması gerekenler (öncelik sırası)

### P0 — Token’ı kullanıcıya kolay göster / kopyala

Link-server için kullanıcıya **agent token** lazım. Tray / first-run UI’da:

- Token’ı maskeli göster + **Copy**
- Kısa metin: *“Bu token’ı honeypot.yesnext.com.tr → My servers → Link server alanına yapıştırın.”*
- Opsiyonel: `https://honeypot.yesnext.com.tr/servers` linkini aç

### P1 — Kurulum sonrası “hesaba bağla” CTA (opsiyonel ama önerilir)

First-run / Settings → Account:

| Alan | Açıklama |
|------|----------|
| E-posta | Kullanıcının YesNext hesabı |
| Şifre | Account şifresi |
| Buton | “Hesaba bağla” / “Open link page” |

**Minimum (tarayıcı):** varsayılan tarayıcıda aç  
`https://honeypot.yesnext.com.tr/?login=1` veya `/servers`  
Token’ı panoya kopyala + toast: “Token kopyalandı — sitede Link server’a yapıştırın.”

**İleri (doğrudan API — ileride eklenebilir):** Cloud şu an agent token ile account link için **agent-auth’lu JSON endpoint zorunlu tutmuyor**. İsterseniz cloud’a `POST /api/account/link-by-token` eklenebilir; şimdilik web form yeterli.

### P2 — Register / notify_email hizası

`POST /api/register` veya premium settings’te `notify_email` set ediliyorsa, aynı e-posta ile Account oluşturulduğunda cloud otomatik membership **yapmaz** (manuel link gerekir). Agent UI’da:

> “Bildirim e-postanız ile web hesabı aynıysa, My servers’dan bu sunucuyu bir kez bağlayın.”

### P3 — Çoklu sunucu bilinci (tray)

Tray menüsü (opsiyonel):

- Bu host’un `server_name` / token kısaltması
- “Dashboard aç” → `https://honeypot.yesnext.com.tr/dashboard?token={TOKEN}`  
  (Account cookie varsa switcher de çalışır)

---

## 2) Agent’ın dokunmaması gerekenler

- Account cookie / bcrypt / `AccountClient` tablosu — **sadece cloud**
- Dashboard şifresi (`dash_pass_hash`) — web’de set edilir; agent bilmek zorunda değil
- Mevcut `token` auth heartbeat / health / commands protokolü **aynı kalır**

---

## 3) Kullanıcıya gösterebileceğin kısa rehber (TR)

1. Agent’ı kur, token’ı kopyala.  
2. https://honeypot.yesnext.com.tr → Register (e-posta + şifre).  
3. My servers → Link server → token’ı yapıştır.  
4. İkinci PC’de aynı hesapla giriş → yine Link server.  
5. Header’daki sunucu listesinden geçiş yap.

---

## 4) Acceptance checklist (agent)

- [ ] Token Settings / About’ta görünür ve tek tıkla kopyalanır  
- [ ] “Hesaba bağla / Dashboard” CTA tarayıcıyı doğru URL ile açar  
- [ ] Token panoya alındığında kullanıcıya net talimat toast’ı  
- [ ] Mevcut register + heartbeat + health bozulmaz  
- [ ] (Opsiyonel) notify_email ile “hesaba bağla” hatırlatması

---

## 5) İleride cloud’a eklenebilecek agent API (isteğe bağlı not)

```
POST /api/account/link-by-agent
{ "token": "<client_token>", "email": "...", "password": "..." }
```

→ Account authenticate + `link_client_to_account`.  
Şu an **yok**; web `POST /account/link-server` yeterli. İsterseniz cloud tarafında ayrıca açılır.

---

## Kaynak: `AGENT_LOGON_CHALLENGE_API_PROMPT.md`

# AGENT_LOGON_CHALLENGE_API_PROMPT.md

## Amaç

Sunucuda başarılı bir Windows logon olduğunda (özellikle RDP/Network),
saldırgan oturumu açık kalmasın. Client anında **logoff** eder ve Account
sahibine e-posta gönderilir. Sahip **"Bu benim"** derse IP whitelist'e alınır;
aksi halde oturum tekrar açılamaz (challenge açık kaldıkça logoff tekrarlanır).

Bu, PIN / self-protect ile birlikte **üçüncü katman**: kimlik onayı.

---

## Client davranışı (v4.4.40+)

1. `Event 4624` / RDP session logon → ThreatEngine urgent alert
2. `LogonChallengeGuard` (config `logon_challenge.enabled=true`):
   - IP zaten whitelist/approved değilse → `logoff_user`
   - `POST /api/alerts/logon-challenge`
   - Urgent alert (`threat_type=logon_challenge`)
3. Periyodik poll: `GET /api/agent/logon-challenges` → `approved_ips` → local whitelist

Config kaynağı: `GET /api/threats/config` içinde:

```json
"logon_challenge": {
  "enabled": true,
  "auto_logoff": true
}
```

---

## Backend endpoint'leri

### 1) `POST /api/alerts/logon-challenge`

Body:

```json
{
  "token": "<agent_token>",
  "challenge_id": "uuid",
  "source_ip": "1.2.3.4",
  "username": "Administrator",
  "service": "RDP",
  "logon_type": 10,
  "event_id": 4624,
  "actions_taken": ["logoff_user"],
  "message": "..."
}
```

Sunucu:

- Challenge kaydı oluştur (TTL örn. 1 saat)
- Linked Account e-postasına mail at:
  - Konu: `Logon onayı — {hostname} / {ip}`
  - Buton: **Bu benim** → signed URL `GET /account/logon-approve?cid=...&sig=...`
  - Buton: **Ben değilim** → block IP + keep denied
- Mevcut urgent/mail pipeline ile de bildirim (opsiyonel duplicate değil)

Response: `200 { "ok": true, "challenge_id": "..." }`

### 2) `GET /api/agent/logon-challenges?token=`

Response:

```json
{
  "pending": [
    { "challenge_id": "...", "source_ip": "...", "username": "...", "created_at": "..." }
  ],
  "approved_ips": ["1.2.3.4"],
  "approved_challenges": [
    { "challenge_id": "...", "source_ip": "1.2.3.4", "approved_at": "..." }
  ]
}
```

### 3) E-posta / dashboard approve

`GET /account/logon-approve?cid=&sig=` (auth cookie veya signed token):

- Challenge'ı `approved` yap
- Agent whitelist'ine IP ekle (`threats/config` whitelist_ips)
- Client bir sonraki poll/sync'te IP'yi güvene alır

**Ben değilim:**

- Challenge `denied`
- IP'yi block listesine ekle / auto-block bildirimi

### 4) Break-glass

Dashboard → Servers → "Approve logon / Whitelist IP" manuel.

Acil erişim: Account sahibi e-postaya ulaşamazsa dashboard'dan whitelist.

---

## Güvenlik notları

- Local Interactive (konsol) IP'siz logon'lar client'ta challenge dışı bırakılabilir
- Whitelist'teki IP'ler challenge almaz
- Update / installer path etkilenmez
- "Asla kilitlenme": Account unlink + PIN ile GUI açılır ama **logon challenge**
  Account mail'ine bağlıdır — mail yoksa özellik kapalı tutulmalı (`enabled: false`)

---

## Acceptance

- [ ] Challenge enable iken RDP success → anında logoff + mail
- [ ] "Bu benim" → IP whitelist + sonraki RDP kalır
- [ ] "Ben değilim" → IP block
- [ ] Disable iken eski davranış (sadece urgent alert)

