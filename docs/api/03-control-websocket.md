# Agent Control WebSocket

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_CONTROL_WEBSOCKET_PROMPT.md`

# AGENT_CONTROL_WEBSOCKET_PROMPT.md

> **Kime:** Honeypot Cloud + Windows agent (SYSTEM daemon)  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-20  
> **Amaç:** Dashboard komutlarını **poll yerine (öncelikli) WebSocket push** ile anında iletmek — IR / `self_update` / logoff vb. için sub-saniye tepki.  
> **Kapsam dışı:** Remote Desktop video WS (`/ws/remote/agent`) — ayrı kanal kalır.

---

## Neden

Bugün: agent `GET /api/commands/pending` poll (~0.5–1s). Çalışıyor ama:

- Dashboard “Update now” → kullanıcı ACK’i poll gecikmesiyle görür  
- IR (logoff / kill / disable_all) için her saniye HTTP maliyeti  
- Cloudflare/API üzerinde sürekli GET gürültüsü  

Hedef: **kalıcı kontrol WS** → sunucu komutu **push** eder → agent anında çalıştırır → result WS veya HTTP ile döner.  
HTTP poll **fallback** olarak kalır (WS kopunca).

---

## Endpoint

```
wss://honeypot.yesnext.com.tr/ws/agent/control
```

### Auth (zorunlu — Bearer)

RD WS ile aynı politika (`AGENT_BEARER_TOKEN_AUTH_API_PROMPT`):

1. `Authorization: Bearer <agent_token>` (tercih)
2. Geçiş: `?token=` (Faz 1 dual-read; sonra kapat)
3. Opsiyonel: `Sec-WebSocket-Protocol: bearer,<token>`

Token yok / geçersiz → WS kapat **4401** (veya close code 1008 + reason `unauthorized`).

### Kim bağlanır?

**Yalnızca SYSTEM Session 0 daemon** (`--mode=daemon`).  
GUI/tray bağlanmaz (çift consumer / komut yarışı olmasın).

---

## Bağlantı ömrü

| Davranış | Değer |
|----------|--------|
| Agent connect | Motor start’ta hemen |
| Ping / pong | Uygulama `ping` her 20–30s **veya** WS protocol ping |
| Server idle timeout | ~60–90s pong yoksa drop |
| Agent reconnect | Exponential backoff 1s → 2 → 4 → … max 30s + jitter |
| Fallback | WS down iken HTTP `commands/pending` poll devam (mevcut) |
| WS up | Poll aralığı gevşetilebilir (örn. 15–30s safety net) veya IR hariç durdurulabilir |

---

## Mesaj formatı

Tüm mesajlar **text JSON**. Binary yok (RD kanalına karıştırma).

Ortak zarf:

```json
{
  "v": 1,
  "t": "<type>",
  "id": "optional-msg-id",
  "ts": "2026-07-20T14:00:00Z"
}
```

---

## Server → Agent

### 1) `hello` (bağlanınca sunucu)

```json
{
  "v": 1,
  "t": "hello",
  "server_time": "2026-07-20T14:00:00Z",
  "protocol": 1
}
```

### 2) `command` — dashboard komutu (push)

Pending HTTP ile **aynı şekil**; sadece taşıma WS:

```json
{
  "v": 1,
  "t": "command",
  "command": {
    "command_id": "uuid",
    "command_type": "self_update",
    "priority": "high",
    "expires_at": "2026-07-20T14:30:00Z",
    "issued_at": "2026-07-20T14:00:00Z",
    "params": {
      "force": true,
      "tag": "v4.5.30",
      "download_url": "https://github.com/…/cloud-client-installer.exe"
    },
    "signature": "optional-hmac"
  }
}
```

Kurallar:

- `command_type` mevcut whitelist (`ALLOWED_COMMANDS`)  
- TTL / HMAC / protected target validasyonu **agent’ta aynı**  
- Aynı `command_id` tekrar gelirse: idempotent (ikinci kez çalıştırma; önceki result’ı hatırla veya no-op)  
- Batch: sunucu bir frame’de birden fazla `command` gönderebilir (IR önce)  

### 3) `ping`

```json
{ "v": 1, "t": "ping", "ts": "…" }
```

Agent → `pong`.

### 4) `config_hint` (opsiyonel)

```json
{
  "v": 1,
  "t": "config_hint",
  "poll_fallback_sec": 30,
  "features": ["control_ws_v1"]
}
```

---

## Agent → Server

### 1) `hello` (bağlanınca agent)

```json
{
  "v": 1,
  "t": "hello",
  "role": "agent",
  "version": "4.5.30",
  "hostname": "SRV-01",
  "pid": 1234,
  "mode": "daemon"
}
```

### 2) `pong`

```json
{ "v": 1, "t": "pong", "ts": "…" }
```

### 3) `command_result` — HTTP `POST /api/commands/result` ile **eş payload**

Erken ACK (`self_update`):

```json
{
  "v": 1,
  "t": "command_result",
  "command_id": "uuid",
  "command_type": "self_update",
  "status": "running",
  "result": {
    "ok": true,
    "success": true,
    "status": "running",
    "message": "update_accepted",
    "detail": "download_starting"
  },
  "executed_at": "2026-07-20T14:00:01Z",
  "signature": "…"
}
```

Final:

```json
{
  "v": 1,
  "t": "command_result",
  "command_id": "uuid",
  "command_type": "self_update",
  "status": "completed",
  "result": {
    "ok": true,
    "message": "update_started",
    "from_version": "4.5.28",
    "to_version": "4.5.30",
    "restart_required": true
  },
  "executed_at": "2026-07-20T14:00:25Z"
}
```

Cloud: WS `command_result` gelince **aynı handler** `POST /commands/result` ile — tek kaynak doğruluk.  
Agent: WS drop riskine karşı kritik result’larda **HTTP result’ı da** göndermeye devam edebilir (at-least-once; cloud idempotent).

### 4) `ack` (opsiyonel, komut alındı — execute öncesi)

```json
{
  "v": 1,
  "t": "ack",
  "command_id": "uuid",
  "state": "received"
}
```

Dashboard “Waiting” → “Updating…” için `command_result status=running` yeterli; `ack` ekstra hız.

---

## Dashboard tarafı (cloud)

`POST /api/commands/send` sonrası:

1. Komutu DB’ye yaz (`pending`)  
2. Client’ın **aktif control WS** oturumu varsa → hemen `command` frame push  
3. Yoksa → klasik pending kuyruk (agent HTTP poll veya sonra WS reconnect + drain)  
4. Result (WS veya HTTP) → status `running` / `completed` / `failed`  
5. UI: `AGENT_SELF_UPDATE_DASHBOARD_FEEDBACK_API_PROMPT` ile aynı badge makinesi  

**Drain on connect:** Agent WS açınca sunucu o client için `pending` komutları sırayla push etsin (kaçırılan IR / update).

---

## Agent implementasyon notları

| Madde | Not |
|-------|-----|
| Modül | Örn. `client_control_ws.py` — `RemoteCommandExecutor` ile paylaş execute/validate |
| Thread | Daemon motor içinde tek WS thread + reconnect |
| Execute | Mevcut `_execute` / `_validate` — **tek pipeline** (poll ve WS aynı handler) |
| Dedup | `command_id` set (TTL 1h) |
| self_update | Erken `command_result running` **WS + HTTP**; sonra helper; process exit |
| RD WS | Ayrı bağlantı; control WS binary frame kabul etmez |
| Bearer | `legacy_token_query=false` ile uyumlu header |

### HTTP poll ile birlikte (geçiş)

```
Faz 1: WS + poll (poll 1s) — dual delivery; dedup şart
Faz 2: WS primary; poll 15–30s safety
Faz 3: WS only (poll sadece WS 60s+ down)
```

---

## Güvenlik

- Sadece agent token; dashboard kullanıcı WS’i bu path’e bağlanmaz  
- Rate limit: sunucu aynı client’a flood etmesin; agent mevcut MAX_COMMANDS_PER_MINUTE  
- Signature / expires_at HTTP ile aynı  
- Cloudflare: WebSocket destekli zone; idle timeout’lara dikkat  
- Log: token redact  

---

## Hata / close codes (öneri)

| Code | Anlam |
|------|--------|
| 1000 | Normal |
| 1008 | Policy / unauthorized |
| 1013 | Try again later (overload) |
| 4401 | Unauthorized (app-specific, destekleniyorsa) |

---

## Acceptance

- [ ] Daemon control WS bağlanır; dashboard send → **&lt; 500 ms** agent log’da komut  
- [ ] `self_update` → erken `running` / `update_accepted` WS(+HTTP) → UI Updating…  
- [ ] WS kesilince HTTP poll komutları kaçırmaz  
- [ ] Reconnect sonrası pending drain  
- [ ] Aynı `command_id` çift execute olmaz  
- [ ] RD stream WS’ten bağımsız çalışır  
- [ ] Bearer auth; query token sadece geçiş  

---

## Faz planı

| Faz | Cloud | Agent |
|-----|-------|-------|
| **0** | Bu prompt | — |
| **1** | `/ws/agent/control` + push + result ingest + drain | **Client ≥4.5.31:** Connect + handle `command` + result over WS; keep poll |

| **2** | Dashboard feedback UI poll/WS status | Poll backoff when WS healthy |
| **3** | Query token reject on WS | Poll only as offline fallback |

---

## İlişkili promptlar

- `AGENT_BEARER_TOKEN_AUTH_API_PROMPT.md` — auth  
- `AGENT_SELF_UPDATE_DASHBOARD_FEEDBACK_API_PROMPT.md` — UI durumları  
- `AGENT_SELF_UPDATE_PROMPT.md` — self_update semantiği  
- Remote desktop: `/ws/remote/agent` — **karıştırma**

---

## Özet

Tek cümle: **Komutlar push, result aynı şema, poll emniyet ağı.**  
Cloud önce WS hub + send→push; agent daemon’da control client. Dashboard “Update now” anında “Updating…” için zemin bu kanal.

