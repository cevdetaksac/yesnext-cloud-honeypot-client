# Self-Update & Dashboard Feedback

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_SELF_UPDATE_PROMPT.md`

# AGENT_SELF_UPDATE_PROMPT.md

## Amaç

Dashboard **Şimdi güncelle** butonu → cloud `POST /api/commands/send` → agent pending poll → **hemen self-update**.

Zamanlanmış otomatik güncelleme (saatlik/günlük) **ayrı kalsın**; bu komut takvimden bağımsız tetikler.

---

## Cloud (hazır)

| Alan | Değer |
|------|--------|
| `command_type` | `self_update` |
| Opsiyonel | `check_update` (sadece kontrol, kurma) |
| TTL | 30 dk (`self_update`) |
| Params (cloud doldurur) | `tag`, `download_url`, `installer_name`, `size`, `html_url`, `force`, `channel`, `triggered_by` |

Örnek pending komut:

```json
{
  "command_id": "…",
  "command_type": "self_update",
  "params": {
    "force": true,
    "channel": "stable",
    "tag": "v4.5.10",
    "download_url": "https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases/download/v4.5.10/cloud-client-installer.exe",
    "installer_name": "cloud-client-installer.exe",
    "size": 27400000,
    "triggered_by": "dashboard"
  },
  "priority": "high"
}
```

Result: `POST /api/commands/result` (mevcut).

---

## Agent — yapması gerekenler

### 1) Komut handler

`commands/pending` içinde `self_update` görünce:

1. Zaten aynı `tag` kuruluysa ve `force != true` → skip + result `ok` / `already_current`
2. `download_url` yoksa GitHub latest veya cloud `/api/public/latest-release` çöz
3. Installer’ı güvenli temp’e indir (ProgramData veya `%TEMP%\YesNextUpdate\`)
4. Mümkünse hash / boyut doğrula (`size`)
5. Silent install (mevcut updater ile aynı path — örn. `cloud-client-installer.exe /S` veya bilinen flag’ler)
6. SYSTEM daemon ayakta kalsın; GUI varsa soft restart
7. Result gönder:

```json
{
  "command_id": "…",
  "status": "completed",
  "result": {
    "ok": true,
    "from_version": "4.5.8",
    "to_version": "4.5.10",
    "tag": "v4.5.10"
  }
}
```

Hata:

```json
{
  "command_id": "…",
  "status": "failed",
  "error": "download_failed|install_failed|busy|…",
  "result": { "ok": false, "detail": "…" }
}
```

### 2) `check_update`

Sadece karşılaştır; kurma. Result: `{ "update_available": true/false, "installed": "…", "latest": "…" }`.

### 3) Concurrent / güvenlik

- Aynı anda tek update (lock)
- Sadece resmi GitHub URL / bilinen host
- Token / machine_id koru (ProgramData)
- Update sırasında remote stream kesilebilir — kabul edilebilir

### 4) Lifecycle

İsteğe bağlı: `POST /api/alerts/lifecycle`  
`event_type`: `self_update_begin` / `self_update_ok` / `self_update_failed`

---

## Acceptance

- [ ] Dashboard **Şimdi güncelle** → pending’de `self_update` + `download_url`
- [ ] Agent poll < ~60s → indirme + kurulum başlar (takvim beklemez)
- [ ] Başarıda `agent_version` yeni tag; dashboard badge güncellenir
- [ ] `force=false` + aynı sürüm → no-op
- [ ] Zamanlanmış auto-update bozulmadan çalışmaya devam eder

---

## Not

Cloud tarafı 2026-07-19 hazır. Bu prompt **client** implementasyonu içindir.

---

## Kaynak: `AGENT_SELF_UPDATE_DASHBOARD_FEEDBACK_API_PROMPT.md`

# AGENT_SELF_UPDATE_DASHBOARD_FEEDBACK_API_PROMPT.md

> **Kime:** Honeypot Cloud / Dashboard API  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-20  
> **Konu:** “Şimdi güncelle” tıklanınca kullanıcıya **geri bildirim** — agent komutu aldı / güncelleniyor / bitti  
> **Client (≥ 4.5.19):** Erken ACK + lifecycle + final result **zaten gönderiyor**. Bu prompt cloud/UI’nin bunları **göstermesi** içindir.

---

## Problem

Dashboard’da **Update now** → komut kuyruğa yazılır ama kart uzun süre “Update available” kalır.  
Kullanıcı: “Uygulama güncellemeye geçti mi?” bilemez.

Agent aslında (online ise) saniyeler içinde:
1. Komutu poll eder  
2. **Erken ACK** `status=running` / `message=update_accepted` gönderir  
3. Lifecycle `self_update_begin`  
4. İndirir / silent kurar  
5. Final `commands/result` + lifecycle `self_update_ok` | `self_update_failed`  
6. Yeni sürümle heartbeat

Cloud + UI bu sinyalleri **canlı** yansıtmalı.

---

## Agent → API sinyalleri (mevcut sözleşme — değiştirme)

### A) `POST /api/commands/result` — durum makinesi

Aynı `command_id` için **birden fazla** result gelebilir (idempotent upsert).

| Sıra | `status` | `result.message` / alanlar | UI metni (öneri TR) |
|------|----------|----------------------------|---------------------|
| 1 (erken ACK) | `running` | `message=update_accepted`, `detail=download_starting` | **Güncelleniyor…** / Agent komutu aldı |
| 2a | `completed` | `message=update_started` veya `ok` + `restart_required` | **Kurulum başladı** (helper/installer) |
| 2b | `completed` | `message=already_current` | **Zaten güncel** |
| 3 | `failed` | `error=download_failed\|install_failed\|busy\|…` | **Güncelleme başarısız** + `detail` |
| 4 (reject) | `rejected` | `error=…` | **Reddedildi** |

Erken ACK örneği (client gönderir):

```json
{
  "token": "…",
  "command_id": "…",
  "status": "running",
  "result": {
    "success": true,
    "ok": true,
    "status": "running",
    "message": "update_accepted",
    "detail": "download_starting"
  },
  "executed_at": "2026-07-20T13:00:00Z"
}
```

Final başarı (installer helper launch):

```json
{
  "command_id": "…",
  "status": "completed",
  "result": {
    "ok": true,
    "success": true,
    "message": "update_started",
    "from_version": "4.5.28",
    "to_version": "4.5.30",
    "tag": "v4.5.30",
    "restart_required": true
  }
}
```

### B) `POST /api/alerts/lifecycle` (veya mevcut lifecycle endpoint)

| `event_type` | `reason` | Anlam |
|--------------|----------|--------|
| `self_update_begin` | `dashboard_self_update` | İndirme başladı |
| `self_update_ok` | `helper_launched` | Silent installer / helper çalıştı |
| `self_update_failed` | `download_failed` / `busy` / … | Hata |

`details`: `{ from_version, to_version|tag, force, show_gui? }`

### C) Heartbeat / client version

Kurulum bitince yeni process → `version` alanı yeni tag.  
UI: `installed` badge’i heartbeat’ten güncelle (poll ~15–60s).

---

## Cloud yapacaklar (P0)

### 1) Komut durumu sakla

`commands` tablosu / cache:

| Alan | Not |
|------|-----|
| `command_id` | PK |
| `client_id` / token | |
| `command_type` | `self_update` |
| `status` | `pending` → `running` → `completed` \| `failed` \| `expired` \| `rejected` |
| `result` | JSON (son result merge) |
| `updated_at` | Her result’ta |

**Kritik:** `running` gelince `pending`’de bırakma — status’u **running** yap.

### 2) Dashboard kartı — durum UI

“Download / update client” kartında `self_update` için:

| Durum | Badge | Buton |
|-------|-------|--------|
| Update available, komut yok | turuncu **Update available** | Update now aktif |
| Komut gönderildi, henüz ACK yok | gri **Waiting for agent…** | Update now disabled |
| `status=running` / `update_accepted` | mavi/teal **Updating…** | disabled + spinner |
| `update_started` / helper | **Installing…** | disabled |
| `already_current` | yeşil **Up to date** | Update now (force opsiyonel) |
| `failed` | kırmızı **Update failed** | Retry |
| Heartbeat version = latest | yeşil **Up to date** | — |

Örnek alt yazı:

> Latest v4.5.30 · installed v4.5.28 · **Agent updating…** (command received)

veya TR:

> Agent komutu aldı — güncelleme devam ediyor…

### 3) Canlı yenileme

Update now tıklanınca:

1. `POST /api/commands/send` → `command_id` döndür  
2. UI hemen **Waiting for agent…**  
3. **Poll** (öneri 1–2 sn, max ~2 dk) veya WS/SSE:
   - `GET /api/commands/{command_id}` **veya**
   - client detail içinde `last_self_update: { command_id, status, message, updated_at }`
4. `running` → **Updating…**  
5. `completed` + yeni version heartbeat → **Up to date**  
6. Timeout (örn. 90 sn ACK yok) → **Agent offline or not polling** + Retry

### 4) Önerilen read API (yoksa ekle)

```http
GET /api/commands/{command_id}?token=…   # veya dashboard session auth
```

```json
{
  "command_id": "…",
  "command_type": "self_update",
  "status": "running",
  "result": {
    "message": "update_accepted",
    "detail": "download_starting",
    "from_version": "4.5.28",
    "to_version": "4.5.30"
  },
  "updated_at": "2026-07-20T13:00:01Z"
}
```

Alternatif: client özet endpoint’ine göm:

```json
"update": {
  "available": true,
  "latest": "v4.5.30",
  "installed": "v4.5.28",
  "in_progress": true,
  "phase": "running",
  "message": "update_accepted",
  "command_id": "…"
}
```

`in_progress = (son self_update status ∈ {pending, running})` ve TTL dolmamış.

---

## UI metinleri (kopyala-yapıştır)

| key | TR | EN |
|-----|----|----|
| `update_waiting_agent` | Agent bekleniyor… | Waiting for agent… |
| `update_received` | Komut alındı — güncelleniyor… | Command received — updating… |
| `update_installing` | Kurulum çalışıyor… | Installing… |
| `update_done` | Güncelleme tamam | Up to date |
| `update_already` | Zaten güncel | Already current |
| `update_failed` | Güncelleme başarısız | Update failed |
| `update_offline` | Agent çevrimdışı / poll yok | Agent offline or not polling |

---

## Acceptance

- [ ] Update now → 1 sn içinde kart **Waiting** veya **Updating** (pending’de takılı kalmaz)
- [ ] Agent ACK `running` → badge **Updating…** / “komutu aldı”
- [ ] `already_current` → “Zaten güncel”, false fail değil
- [ ] `failed` → hata + Retry
- [ ] Kurulum sonrası heartbeat version = latest → **Up to date**
- [ ] Agent offline → ~90 sn sonra timeout mesajı (sessizce “available”de kalma)

---

## Yapılmayacaklar

- Agent’tan ekstra zorunlu endpoint istemek (mevcut result + lifecycle yeter)
- Sadece `pending` gösterip `running`’i yok saymak
- Push/WS zorunlu kılmak (poll yeterli; WS opsiyonel iyileştirme)

---

## Not

Client tarafı hazır (≥4.5.19 erken ACK). Bu iş **%100 cloud + dashboard UI**.  
Fleet’te agent poll kapalıysa ACK gelmez → offline mesajı doğru davranıştır.

**Control WS** (`AGENT_CONTROL_WEBSOCKET_PROMPT.md`) açılınca komut anında agent’a gider → Waiting → Updating geçişi poll gecikmesine bağlı kalmaz; yine de UI poll (1–2 sn) yeterli (WS zorunlu değil).

