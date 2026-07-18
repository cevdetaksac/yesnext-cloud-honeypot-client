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
