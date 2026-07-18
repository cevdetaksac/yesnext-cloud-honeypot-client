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
