# Remote Desktop

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`  
> Client: **≥ 4.5.48** (`list_local_users` / `remote_session_prepare`)

---

## Akış: kullanıcı seç → prepare → yayın

```
list_local_users  →  list_sessions (can_capture)
        ↓
remote_session_prepare { username, password?, session_id?, timeout_sec }
        ↓ ready_for_stream + session_id
remote_stream_start { session_id, username, … }
        ↓
remote_stream_stop  /  remote_session_logoff
```

### `list_local_users`
`params`: `{ "include_disabled": true }`  
`data.users[]`: username, sid, enabled, is_admin, last_logon, has_session, session_id, session_status — **şifre yok**.

### `list_sessions`
Her oturumda `can_capture: true` yalnızca **Active** + interactive (`session_id > 0`).

### `remote_session_prepare`
Dashboard “Bağlan” — one-shot `password` (RAM only, loglanmaz).

| Durum | Davranış |
|--------|----------|
| Active + desktop | `ready_for_stream: true` |
| Disconnected | `WTSConnectSession` / `tscon` → Active + JPEG probe |
| Oturum yok | `UNSUPPORTED` (Session 0’dan fresh logon yok; bir kez RDP/console gerekir) |
| Yanlış şifre | `AUTH_FAILED` / `ACCOUNT_LOCKED` / `ACCOUNT_DISABLED` |

Başarı: `data.ready_for_stream`, `session_id`, `screen.w/h`, `method`.  
Sonra cloud **aynı `session_id`** ile `remote_stream_start` gönderir.

### Güvenlik
- Password disk/config/autologon’a yazılmaz; history’de `***`.
- Session 0’dan sahte siyah JPEG yok — probe fail → `NO_INTERACTIVE_DESKTOP` / `CAPTURE_NO_DESKTOP`.

---

## Kaynak: `AGENT_REMOTE_DESKTOP_PROMPT.md`

# Agent Prompt: Uzak Masaüstü — Akıcı WebSocket + HTTP fallback

> **Kime:** Windows tray / honeypot client  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  

## Öncelikli kanal: WebSocket (akıcı)

Dashboard `/ws/remote/view` kullanıyor. Agent **mutlaka** şunu açmalı:

```
wss://honeypot.yesnext.com.tr/ws/remote/agent?token=CLIENT_TOKEN
```

(HTTP test: `ws://...`)

### Agent → Server
1. (Opsiyonel) text: `{"t":"meta","width":1280,"height":720,"seq":12,"fps":5}`
2. binary: ham JPEG bytes (`FF D8 … FF D9`)

Hedef: **5–10 fps**, max genişlik 1280, JPEG quality ~30–40, kare ≤ 200–350 KB.

### Server → Agent (input)
Text JSON:

```json
{"t":"input","event":"mousedown","x":0.42,"y":0.61,"button":"left"}
```

| event | Uygula |
|--------|--------|
| mousedown / move / mouseup | Sürükle-bırak |
| click / dblclick | Tık |
| wheel | `key` = delta |
| type_text / key | Klavye |

`x,y` = 0..1 → ekran pikseli.

Yayın start/stop hâlâ: `remote_stream_start` / `remote_stream_stop` via `GET /api/commands/pending`.

---

## HTTP fallback (WS yoksa)

- Frame: `POST /api/remote/frame` (multipart JPEG)
- Input: `GET /api/remote/inputs?token=...&limit=80` her **200–500 ms**

WS varsa HTTP input poll şart değil.

---

## Acceptance

- [ ] Agent WS bağlanıyor (`{"t":"hello","role":"agent"}`)
- [ ] Dashboard “WebSocket” rozeti yeşil
- [ ] Sürükle-bırak gecikmesi düşük
- [ ] 5+ fps görünür
- [ ] WS kopunca HTTP fallback çalışıyor

---

## Kaynak: `AGENT_REMOTE_SESSION_SELECT_PROMPT.md`

# Agent Prompt: Remote Desktop — Oturum Seçimi (`session_id`)

> **Kime:** Windows `honeypot-client`  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Dashboard:** Oturum dropdown + “oturum yok → RDP öner” UI hazır

---

## Ürün kuralları

| Durum | Dashboard | Agent |
|--------|-----------|--------|
| **0** interaktif oturum | Uyarı: açık masaüstü yok → RDP ile oturum açın. Start **blocked**. | Stream başlatma; `NO_INTERACTIVE_SESSION` |
| **1** oturum | Otomatik seç + start | O `session_id` desktop’ını capture + input |
| **2+** oturum | Dropdown (Console > Active > diğer). Kullanıcı değiştirebilir. | Seçilen `session_id` |

Varsayılan öncelik (API de aynı): **Console Active → Console → Active RDP → ilk kayıt**.

---

## Komut sözleşmesi

### `remote_stream_start` (GET `/api/commands/pending`)

```json
{
  "command_type": "remote_stream_start",
  "params": {
    "fps": 8.0,
    "quality": 32,
    "max_width": 1280,
    "monitor": 0,
    "session_id": 2,
    "username": "Administrator"
  }
}
```

| Alan | Zorunlu | Açıklama |
|------|---------|----------|
| `session_id` | Evet (mümkünse) | WTS session id — **bu session’ın desktop’ını** yakala |
| `username` | Hayır | Doğrulama / log |
| `monitor` | Hayır | Multi-monitor index (0 = primary) |
| `fps` / `quality` / `max_width` | Evet | Capture ayarı |

### `remote_stream_stop`

Önceki gibi; aktif stream’i kapat.

---

## Agent zorunlu davranışlar

### 1) `active_sessions` düzenli raporla

`POST /api/health/report` (veya mevcut health) içinde:

```json
"active_sessions": [
  {
    "username": "Administrator",
    "session_id": 2,
    "session_name": "RDP-Tcp#3",
    "status": "Active",
    "protocol": "RDP",
    "client_ip": "1.2.3.4"
  },
  {
    "username": "User1",
    "session_id": 1,
    "session_name": "Console",
    "status": "Active",
    "protocol": "Console"
  }
]
```

- Kaynak: `WTSEnumerateSessions` / `query user`
- En az **30–60 sn**’de bir güncelle (health zaten gidiyorsa yeterli)
- `Disconnected` oturumları da listele (`status: "Disconnected"`)

Dashboard `GET /api/remote/status` → `sessions[]` buradan beslenir.

### 2) Start gelince doğru session’ı aç

1. `params.session_id` var → **sadece o WTS session** desktop capture
2. Yoksa agent kendi default’unu seç (Console > Active) ve result’ta `session_id` döndür
3. Session listesi boş / id yok →

```json
{
  "success": false,
  "error": "NO_INTERACTIVE_SESSION",
  "message": "No interactive desktop to mirror"
}
```

`streaming: true` yalan söyleme.

### 3) Capture + input aynı session

- JPEG stream: seçilen session’ın WinSta/Desktop’ı
- Mouse/keyboard (`/ws/remote/agent` input veya `/api/remote/inputs`): **aynı session**’a inject
- Session 0 servisten BitBlt yetmez → active session’a inject / helper process

### 4) WebSocket

```
wss://honeypot.yesnext.com.tr/ws/remote/agent?token=CLIENT_TOKEN
```

Start sonrası ≤ 2 sn bağlan; binary JPEG + opsiyonel meta (`width`, `height`, `seq`, `fps`, `session_id`).

### 5) Result dürüst olsun

```json
{
  "success": true,
  "message": "remote stream started",
  "data": {
    "streaming": true,
    "transport": "websocket",
    "session_id": 2,
    "username": "Administrator",
    "screen": {"w": 1920, "h": 1080},
    "capture": {"w": 1280, "h": 720},
    "stats": {"frames_sent": 0, "bytes_sent": 0}
  }
}
```

`screen/capture` 0 → `success: false`, `error: "CAPTURE_NO_DESKTOP"`.

---

## Dashboard API (referans — zaten canlı)

### `GET /api/remote/status?token=…` (DASH_AUTH)

```json
{
  "sessions": [ ... ],
  "session_count": 2,
  "suggested_session_id": 1,
  "diag": "waiting_start | no_interactive_session | live | ..."
}
```

### `POST /api/remote/session`

```json
{
  "token": "...",
  "action": "start",
  "fps": 8,
  "quality": 32,
  "session_id": 2,
  "username": "Administrator"
}
```

- Oturum yoksa: `{ "status": "blocked", "reason": "no_interactive_session" }` — komut kuyruğa **yazılmaz**
- OK: kuyruğa `remote_stream_start` + `params.session_id`

---

## Kabul kriterleri

1. Health’de `active_sessions` dolu → Remote sayfasında dropdown görünür.
2. 0 session → Start disabled / blocked + RDP mesajı; agent’a boş start yağmuru yok.
3. 2 session → kullanıcı SID değiştirince yeni `remote_stream_start` `session_id` ile gelir; görüntü o kullanıcıya geçer.
4. Input tıklamaları seçili session masaüstüne gider.
5. Disconnected seçilirse ya görüntü gelir ya dürüst `CAPTURE_NO_DESKTOP` / uyarı.

---

## Özet

**Mirror = belirli bir WTS `session_id` masaüstü.** Agent `active_sessions` raporlasın; start’ta `session_id` dinlesin; yoksa `NO_INTERACTIVE_SESSION`. Dashboard tarafı hazır.

---

## Kaynak: `AGENT_REMOTE_KEYBOARD_PROMPT.md`

# Agent Prompt: Uzak Masaüstü — Klavye Self-Check (acil)

> **Kime:** Windows tray / honeypot client (remote input)  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Belirti:** Dashboard’da mouse tıklama çalışıyor, “Metin gönderildi” / tuş toast geliyor ama **ekranda yazı yok**.  
> **Tarih:** 2026-07-18  

Dashboard tarafı input’u agent’a iletiyor. Sorun büyük ihtimalle **agent’ın `key` / `type_text` uygulamaması** veya yanlış session’a inject.

---

## 1) Input nereden gelir? (ikisinden biri)

### A) WebSocket (tercih — akıcı)

```
wss://honeypot.yesnext.com.tr/ws/remote/agent?token=CLIENT_TOKEN
```

Server → agent **text** JSON:

```json
{"t":"input","event":"key","key":"a","ts":"…"}
{"t":"input","event":"key","key":"escape","ts":"…"}
{"t":"input","event":"key","key":"enter","ts":"…"}
{"t":"input","event":"mousedown","x":0.5,"y":0.5,"button":"left","ts":"…"}
```

Eski / nadir:

```json
{"t":"input","event":"type_text","text":"hello","ts":"…"}
```

> **Not (2026-07-18):** Dashboard artık yazılabilir metni çoğunlukla **karakter başına `event=key`** olarak gönderiyor. `type_text` gelirse de işle; yoksa en azından `key` şart.

### B) HTTP fallback (agent WS yoksa)

```
GET /api/remote/inputs?token=CLIENT_TOKEN&limit=80
```

Her **200–500 ms** poll. Cevap:

```json
{"events":[{"event":"key","key":"a","ts":"…"}],"count":1}
```

Her event’i uygula, kuyruk sunucuda silinir (drain).

---

## 2) Zorunlu event tablosu

| `event` | Alanlar | Agent ne yapmalı |
|---------|---------|------------------|
| `mousedown` / `move` / `mouseup` | `x,y` 0..1, `button` | Mouse (zaten çalışıyor deniyor) |
| `wheel` | `x,y`, `key`=delta | Scroll |
| **`key`** | **`key` string** | **Klavye — KRİTİK** |
| `type_text` | `text` string | Unicode string yaz (opsiyonel ama destekle) |

### `key` değerleri (case-insensitive)

| `key` | Anlam |
|-------|--------|
| tek karakter (`a`, `A`, `1`, `@`, `ğ`, `İ` …) | O karakteri yaz (Unicode OK) |
| `escape` / `esc` | Esc |
| `enter` / `return` | Enter |
| `tab` | Tab |
| `backspace` | Backspace |
| `delete` / `del` | Delete |
| `space` / ` ` | Space |
| `up` `down` `left` `right` | Oklar |
| `ctrl+c`, `alt+f4`, `shift+tab` … | Modifiers + `+` birleşik |
| `ctrl+alt+delete` | **CAD değil** — sadece key inject; gerçek CAD için aşağıdaki komut |

**Uygulama:** Seçili WTS `session_id` masaüstüne `SendInput` / eşdeğeri.  
Session 0 / service context’ten UI session’a inject etmiyorsan **mouse da gitmezdi** — mouse gidiyorsa aynı inject path’e klavyeyi ekle.

Önerilen: her `key` = keydown + keyup (veya Unicode `KEYEVENTF_UNICODE` çift).

---

## 2b) Türkçe klavye / AltGr / Unicode (sık kırılır)

Dashboard (güncel) tarayıcının **ürettiği karakteri** gönderir:

| Yerel tuş (TR Q) | Gönderilen `key` |
|------------------|------------------|
| ğ ü ş ı ö ç İ | aynı Unicode char |
| AltGr+Q → `@` | `"@"` — **`ctrl+alt+q` değil** |
| AltGr+E → `€` | `"€"` |
| AltGr+7/8/9/0 → `{[ ]}` | o karakterler |
| Ctrl+C | `"ctrl+c"` (gerçek kısayol) |

Opsiyonel alan: `"code":"KeyQ"` (fiziksel tuş).

**Agent kuralı (zorunlu):**

1. `key` uzunluğu **1** ise → **asla** QWERTY scancode map’leme.  
   `SendInput` ile **`KEYEVENTF_UNICODE`** (keydown+keyup) kullan.
2. `key` ∈ `escape|enter|tab|…` veya `ctrl+…` → sanal VK / shortcut.
3. `ctrl+alt+…` gelirse (eski dashboard) ve tek char üretilemiyorsa `code`’a bak; mümkünse Unicode tercih et.
4. Yerel makine TR, remote US (veya tersi) olsa bile: **Unicode inject layout’tan bağımsız çalışır**.

Yanlış: `key="ğ"` → VK_OEM_ something / ToUnicode yanlış layout.  
Doğru: `key="ğ"` → Unicode 0x011F SendInput.

Self-test: Notepad’te `üğişçö@{}€` yazılabilmeli.

---

## 3) CAD (Ctrl+Alt+Del) — ayrı komut

Düz `key=ctrl+alt+delete` Windows’ta **Secure Attention Sequence üretmez**.

Dashboard `POST /api/remote/cad` → pending command:

```json
{
  "command_type": "remote_send_sas",
  "params": { "session_id": 1 }
}
```

Agent:

1. `GET /api/commands/pending` ile al
2. Elevated service: **`SendSAS(0)`** (sas.dll / eşdeğeri)
3. `POST` result: `ok` / hata mesajı

`remote_send_sas` bilmiyorsan CAD butonu **bilerek** çalışmaz — log’a yaz.

---

## 4) Hemen self-check (log + test)

Kodda şunu ekle / doğrula:

```
[remote-input] t=input event=… key=… text=…
```

Her gelen input’ta bir satır.

### Checklist

- [ ] Agent WS bağlı mı? (`hello` aldın mı?)
- [ ] Dashboard’da mouse tıklayınca log’da `mousedown`/`mouseup` görünüyor mu?
- [ ] Masaüstüne focus + klavye `a` → log’da `event=key key=a` görünüyor mu?
- [ ] Görünüyorsa ama ekranda yok → **inject API eksik / yanlış session**
- [ ] Log’da hiç `key` yok → WS text dinlenmiyor veya sadece binary frame işleniyor
- [ ] Sadece HTTP kullanıyorsan `/api/remote/inputs` poll var mı?
- [ ] `remote_stream_start` ile gelen `session_id` input inject’te de kullanılıyor mu?
- [ ] `type_text` gelirse loop ile her char `key` gibi yazılıyor mu?
- [ ] `remote_send_sas` pending’de işleniyor mu?

### 5 dakikalık repro

1. Stream açık, mouse ile Start menüsüne tıkla (çalışıyor olmalı).
2. Arama kutusuna tıkla.
3. Dashboard’da görüntüye tıkla (“Klavye aktif”) → `test123` yaz.
4. Agent log: 7× `key` (`t`,`e`,`s`,`t`,`1`,`2`,`3`).
5. Windows arama kutusunda `test123` görünmeli.
6. Esc butonu → `key=escape` → arama kapanmalı.
7. CAD → pending `remote_send_sas` (SendSAS yoksa dürüst fail).

---

## 5) Sık hatalar

1. **Sadece mouse handler var**, `key`/`type_text` `default`/`ignore`.
2. WS’te yalnızca **binary JPEG** okunuyor; **text JSON input** parse edilmiyor.
3. Input **Session 0**’a gidiyor; capture başka session’dan — tıklar ofsetli/yanlış hedef.
4. `key` adları birebir (`Escape` vs `escape`) — **normalize et (ToLower)**.
5. Toast “gönderildi” = sunucu kuyruğa aldı; agent uygulamadan ekranda bir şey olmaz.

---

## 6) Acceptance (geçti sayılır)

- [ ] Görüntü focus iken canlı yazı remote’ta görünür
- [ ] Esc / Enter toolbar butonları çalışır
- [ ] Yaz (toplu metin) çalışır
- [ ] Log’da her tuş görünür
- [ ] CAD: ya Secure Desktop açılır ya `remote_send_sas` result’ta net hata

**Özet:** Mouse path’inin yanına **aynı session’a `event=key` inject** ekle; WS text + HTTP `/api/remote/inputs` ikisini de dinle; CAD için `SendSAS`.

---

## Kaynak: `AGENT_REMOTE_BLACK_SCREEN_PROMPT.md`

# Agent Prompt: Uzak Masaüstü SİYAH EKRAN — teşhis & fix

> **Kime:** Windows honeypot-client  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Kanıt (client_id=36, güncel exe):**

```
remote_stream_start → success
transport: websocket | streaming: true
frames_sent: 0 | bytes_sent: 0
screen: {w:0, h:0} | capture: {w:0, h:0}
```

Dashboard WS viewer bağlı (“Canlı · WS”) ama **hiç gerçek JPEG gelmiyor**.  
Eski çalışan oturumda: `screen 1920×1080`, `capture 1280×720`, `frames_sent: 161`.

---

## Kök neden (büyük ihtimal)

**Ekran yakalama başarısız** — agent “streaming” flag’ini açıyor ama desktop bitmap alamıyor.

Windows’ta klasik sebepler:

| Sebep | Belirti |
|--------|---------|
| **Session 0** (servis olarak çalışıyor, interaktif masaüstü yok) | `screen 0×0`, siyah/boş JPEG |
| Yanlış session / `WTSGetActiveConsoleSessionId` yok | RDP açıkken bile siyah |
| DXGI/BitBlt fail sessizce yutuluyor | `frames_sent` artmıyor veya çok küçük JPEG |
| WS “açık” sanılıyor ama sunucuya binary gitmiyor | API log’da `/ws/remote/agent` yok |
| HTTP fallback’te boş base64 | `frame-json` 200 ama minik/siyah görüntü |

---

## Zorunlu düzeltmeler

### 1) Capture gerçek desktop’tan olmalı
- Agent **interaktif kullanıcı session**’ında capture etsin (RDP/console).
- Servis (Session 0) ise: active session’a inject / helper process (`CreateProcessAsUser` + desktop capture) kullan.
- Start sonrası `screen.w/h` ve `capture.w/h` **> 0** olmalı; 0 ise `commands/result` → **failed** + net hata (`CAPTURE_NO_DESKTOP`), `streaming=true` yalan söyleme.

### 2) WebSocket gerçekten API’ye bağlanmalı
```
wss://honeypot.yesnext.com.tr/ws/remote/agent?token=CLIENT_TOKEN
```
- `hello` mesajını bekle: `{"t":"hello","role":"agent"}`
- Her kare: **binary** ham JPEG (`FF D8 … FF D9`), ideally ≥ 5–20 KB (1280 genişlik, q~30–40)
- Meta (opsiyonel text): `{"t":"meta","width":1280,"height":720,"seq":N,"fps":8}`

API log’da şunu görmeliyiz:
`WebSocket /ws/remote/agent?token=... [accepted]` — kaynak IP = agent host.

Bağlanamazsa **HTTP fallback**:
- `POST /api/remote/frame` multipart field adı **`file`** (JPEG) + Form `token`
- veya `POST /api/remote/frame-json` `{token, image_base64, width, height, seq}`
- Not: `POST /api/remote/frame` without `file` → **400** (eski log’da vardı)

### 3) Boş / siyah kare gönderme
- JPEG **< ~1500 byte** API artık reddediyor (`Frame too small`).
- Capture siyahsa gönderme; fail say + log.
- `frames_sent` / `bytes_sent` artmalı; 10 sn `0` ise stream’i failed işaretle.

### 4) `remote_stream_start` sonucu dürüst olsun
```json
{
  "success": true,
  "message": "remote stream started",
  "data": {
    "streaming": true,
    "transport": "websocket",
    "screen": {"w": 1920, "h": 1080},
    "capture": {"w": 1280, "h": 720},
    "stats": {"frames_sent": 0, "bytes_sent": 0}
  }
}
```
`screen/capture` 0 ise `success: false`, `error: "CAPTURE_NO_DESKTOP"`.

---

## Acceptance

- [ ] `remote_stream_start` sonrası 2 sn içinde API’de agent WS `accepted`
- [ ] `screen.w/h > 0` ve `capture.w/h > 0`
- [ ] 5 sn içinde `frames_sent ≥ 10`, her kare ≥ 5 KB
- [ ] Dashboard’da gerçek masaüstü (siyah değil)
- [ ] Capture fail → result `failed` + `CAPTURE_NO_DESKTOP` (streaming=true yalan yok)

---

## Hızlı debug (agent makinesi)

1. RDP ile oturum açık mı? (Session 0’dan capture deneme)
2. Local test: JPEG’i diske yaz — siyah mı?
3. Wireshark/log: `wss://…/ws/remote/agent` kuruluyor mu?
4. Fallback: tek `frame-json` ile ≥10KB JPEG at → dashboard’da görünmeli

---

## Kaynak: `AGENT_REMOTE_CLIENT_FIX_PROMPT.md`

# Agent Prompt: Uzak Masaüstü + Komut Poll — Client Teşhis & Güncelleme

> **Kime:** Windows `honeypot-client` geliştirme  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Öncelik:** 🔴 Kritik — dashboard Remote Desktop sayfası agent poll etmeyince çalışmıyor

---

## Üretim kanıtı (API log + DB)

Dashboard **WIN-CNCMGHODTA4** (`client_id=49`) üzerinde “Yayını Başlat” basıldı.

| Kontrol | Sonuç |
|--------|--------|
| `POST /api/remote/session` → `remote_stream_start` | ✅ Kuyruğa yazıldı |
| Viewer `GET /ws/remote/view?token=705a…` | ✅ Accept edildi |
| Agent `GET /api/commands/pending?token=705a…` | ❌ **Hiç yok** |
| Agent `GET /ws/remote/agent?token=705a…` | ❌ **Hiç yok** |
| Frame `data/remote_frames/49.jpg` | ❌ Yok |
| Komut durumu | `pending` kaldı → `dispatched`/`completed` olmadı |

Karşılaştırma:

| Sunucu | IP | Token (prefix) | Agent | Poll | Remote |
|--------|-----|----------------|-------|------|--------|
| WIN-4VTPQJINJTU | `194.5.236.238` | `0ea8836b-…` | **4.4.38** | ✅ sürekli `commands/pending` | Daha önce frame üretmiş (`36.jpg`); siyah ekran geçmişi var |
| WIN-CNCMGHODTA4 | `194.5.236.239` | `705a7746-…` | **4.4.37** | ❌ poll yok | Stream start stuck |

**Kök neden (49):** Agent bu token ile komut poll etmiyor (servis ölü / yanlış config token / process hang). Dashboard tarafı sağlıklı.

**İkincil risk (36):** Poll var ama geçmişte `screen 0×0` / `frames_sent:0` (Session 0 capture) görüldü — ayrı fix (aşağıda §3).

---

## Client’ta kontrol listesi (sırayla)

### 1) Süreç gerçekten ayakta mı?

Hedef makine: **`194.5.236.239` / WIN-CNCMGHODTA4**

- [ ] `honeypot-client.exe` çalışıyor mu? (Services + Task Manager)
- [ ] Kurulum yolu: `C:\Program Files\YesNext\Cloud Honeypot Client\honeypot-client.exe`
- [ ] Config’teki **token** API’deki ile birebir mi?

```
705a7746-a14e-4bda-911f-6711c6f72785
```

- [ ] Log’da son 5 dk içinde API’ye giden istek var mı?
  - `GET /api/commands/pending`
  - heartbeat / health / attack-count
- [ ] Yoksa: servisi **Restart**, sonra 30 sn izle. Hâlâ yoksa token/config/crash dump.

### 2) Komut poll zorunlu (Remote Desktop’un tetikleyicisi)

```
GET https://honeypot.yesnext.com.tr/api/commands/pending?token=CLIENT_TOKEN
```

**Gereksinimler:**

- [ ] Poll aralığı **≤ 2 sn** (IR / remote için; 10 sn kabul edilmez)
- [ ] `remote_stream_start` / `remote_stream_stop` dispatch edilsin
- [ ] Alındığında hemen `POST /api/commands/result` (`dispatched` → `completed`/`failed`)
- [ ] Aynı anda birden fazla `remote_stream_start` varsa **en sonuncuyu** uygula; eskileri ignore + result `cancelled`/`failed`

Örnek start params:

```json
{
  "command_type": "remote_stream_start",
  "params": { "fps": 8.0, "quality": 32, "max_width": 1280 }
}
```

Start sonrası **2 sn içinde** API log’da şunu görmeliyiz:

```
WebSocket /ws/remote/agent?token=705a7746-… [accepted]
```

kaynak IP = `194.5.236.239`.

### 3) Uzak masaüstü kanalı (WS öncelikli)

```
wss://honeypot.yesnext.com.tr/ws/remote/agent?token=CLIENT_TOKEN
```

- [ ] Bağlan → text `{"t":"hello","role":"agent"}` bekle
- [ ] Her kare: **binary** JPEG (`FF D8…FF D9`), ideally ≥ 5–20 KB
- [ ] Opsiyonel meta text: `{"t":"meta","width":1280,"height":720,"seq":N,"fps":8}`
- [ ] Input text: `{"t":"input","event":"mousedown","x":0.4,"y":0.5,"button":"left"}` → gerçek input uygula

**HTTP fallback** (WS yoksa):

- Frame: `POST /api/remote/frame` multipart field adı **`file`** + Form `token`
- veya `POST /api/remote/frame-json` `{token, image_base64, width, height, seq}`
- Input: `GET /api/remote/inputs?token=…&limit=80` her **200–500 ms**

API reddeder: JPEG **&lt; ~1500 byte** → `400 Frame too small` (siyah stub gönderme).

### 4) Ekran yakalama (siyah ekran / 0×0)

Geçmiş fail (client 36):

```
streaming: true, frames_sent: 0, screen: {w:0,h:0}, capture: {w:0,h:0}
```

- [ ] Capture **interaktif kullanıcı session**’ından (RDP/console) — Session 0 servisten BitBlt/DXGI yetmez
- [ ] Session 0 ise: active session’a helper (`CreateProcessAsUser` + desktop capture)
- [ ] `remote_stream_start` result dürüst olsun:

```json
{
  "success": true,
  "data": {
    "streaming": true,
    "transport": "websocket",
    "screen": {"w": 1920, "h": 1080},
    "capture": {"w": 1280, "h": 720},
    "stats": {"frames_sent": 0, "bytes_sent": 0}
  }
}
```

`screen/capture` 0 ise → `success: false`, `error: "CAPTURE_NO_DESKTOP"` — `streaming=true` yalan söyleme.

- [ ] 10 sn `frames_sent==0` ise stream’i failed işaretle + log

### 5) Sürüm / build

- [ ] **49** makineyi en az **4.4.38+** yap (şu an 4.4.37, poll yok)
- [ ] **36** zaten 4.4.38 — capture fix’i bu build’e veya üstüne koy
- [ ] `settings` / heartbeat ile `agent_version` raporlamaya devam

---

## Kabul kriterleri (QA)

1. **239 (49):** Servis restart sonrası 30 sn içinde API log’da `commands/pending?token=705a…` görünür.
2. Dashboard Remote → Start → komut **≤ 5 sn** içinde `completed` (veya dürüst `failed` + CAPTURE hatası).
3. Aynı pencerede **≤ 5 sn** canlı JPEG (WS veya HTTP).
4. Mouse click dashboard’dan agent masaüstüne yansır.
5. Siyah/0×0 capture’da API’ye mini JPEG gitmez; result `failed`.
6. Agent offline iken dashboard artık “Starting…” diye dönmez — teşhis: `diag=cmds_pending_not_acked` / `agent_offline` (API tarafı hazır).

---

## Hızlı manuel test (client makinede)

```powershell
# Token doğru mu?
$token = "705a7746-a14e-4bda-911f-6711c6f72785"
Invoke-RestMethod "https://honeypot.yesnext.com.tr/api/commands/pending?token=$token"

# Start komutu dashboard'dan basıldıktan sonra burada remote_stream_start görünmeli
# Sonra WS veya:
# curl.exe -F "token=$token" -F "file=@capture.jpg" https://honeypot.yesnext.com.tr/api/remote/frame
```

---

## Referans (mevcut API promptları)

- `AGENT_REMOTE_DESKTOP_PROMPT.md` — WS + HTTP sözleşme  
- `AGENT_REMOTE_BLACK_SCREEN_PROMPT.md` — Session 0 / 0×0 capture  
- Dashboard status teşhisi: `GET /api/remote/status` → `diag`, `pending_stream_cmds`, `agent_ws`, `agent_presence`

---

## Özet (tek cümle)

**49’da agent `commands/pending` poll etmiyor → remote start hiç işlenmiyor; önce token/servis/poll düzelt, sonra WS frame + interaktif session capture’ı doğrula; 36 için siyah ekran (0×0) ayrı capture fix.**

