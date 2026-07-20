# Architecture (Daemon / Frontend)

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_SYSTEM_DAEMON_FRONTEND_API_PROMPT.md`

# AGENT_SYSTEM_DAEMON_FRONTEND_API_PROMPT.md

## Amac

Client v4.5.0+ mimarisi:

- **SYSTEM / Session 0 daemon** = tek motor (threat, firewall, honeypot, Remote Desktop, API)
- **GUI** = sadece frontend (N kullanici ayni anda acabilir)
- Uzak masaustu = secilen WTS `session_id` masaustu (SYSTEM desktop degil)

Dashboard/API tarafinda buna uyum + opsiyonel iyilestirmeler.

---

## Client davranisi (ozet)

| Katman | Gorev |
|--------|--------|
| `CloudHoneypot-Background` (`--mode=daemon`) | Boot'ta SYSTEM; kontrol socket `127.0.0.1:58632` |
| GUI (`--show-gui`) | Daemon'a PING/STATUS/HONEYPOT IPC; motor baslatmaz |
| RD stream | Daemon RemoteCommands; `session_id` ile interactive session |

IPC komutlari (agent-local, dashboard'a gerek yok):

```
PING
STATUS
HONEYPOT START <SVC> <PORT>
HONEYPOT STOP <SVC>
HONEYPOT LIST
```

STATUS ornek:

```json
{
  "ok": true,
  "daemon": true,
  "role": "daemon",
  "version": "4.5.0",
  "running_services": ["SSH"],
  "protection_mode": "monitoring",
  "token_present": true
}
```

---

## Dashboard / API — yapilmasi gerekenler

### 1) Agent runtime / health alanlari (onerilen)

`POST /api/health/report` (veya mevcut health) icine:

```json
"agent_runtime": {
  "architecture": "system_daemon_frontend",
  "daemon": true,
  "daemon_pid": 1234,
  "frontend_sessions": 2,
  "version": "4.5.0",
  "protection_mode": "monitoring|full|inactive"
}
```

UI: sunucu kartinda **"SYSTEM motor: aktif"** / **"Frontend: N oturum"** (opsiyonel).

### 2) Remote Desktop — session secimi (zaten var, vurgula)

- `active_sessions[]` health'ten
- Start: `params.session_id`
- 0 session: Start disabled + `NO_INTERACTIVE_SESSION`
- Logon ekrani = Console/session login/lock — normal
- CAD: `remote_send_sas` (SendSAS)

Metin onerisi (Remote sayfasi):

> Goruntu, SYSTEM degil; sectiginiz Windows oturumunun masaustudur.
> Kimse oturum acmamissa logon ekrani gorunur.

### 3) Lifecycle timeline (onceki prompt ile bagli)

`POST /api/alerts/lifecycle` eventleri:

- `client_startup` (daemon veya frontend)
- `watchdog_restart*`
- `memory_restart*` (sadece Session 0)
- `gui_quit` (frontend kapandi — motor ayakta kalmali)

Dashboard: "GUI kapandi" != "koruma dustu" ayirimi.

### 4) Coklu kullanici / hesap linki

Hesap bagli sunucuda:

- Token makine-bazli (`ProgramData`) — degismez
- Dashboard'dan RD session picker ile farkli kullanicilara bakilir
- "Tum kullanicilara ayni anda tek stream" yok; session degistirilir

### 5) Istemci guncelleme notu

Release notes / in-app:

> v4.5.0: Koruma SYSTEM katmaninda. GUI sadece yonetim arayuzu; birden fazla kullanici acabilir.

---

## Acceptance (dashboard)

- [ ] Health'de daemon/version gorunur (alan eklendiyse)
- [ ] 2 RDP kullanicili sunucuda session dropdown + dogru masaustu
- [ ] GUI'siz (sadece Background task) iken RD + threat calisir
- [ ] Bir kullanici GUI kapatinca lifecycle `gui_quit` gelir ama motor ayakta
- [ ] Remote yardim metni: SYSTEM vs session masaustu net

## Acceptance (client — referans)

- [ ] Session 0 daemon logon olunca `os._exit` yapmaz
- [ ] Iki kullanici `--show-gui` acabilir; birbirini oldurmez
- [ ] Frontend honeypot Start → IPC → daemon dinler
- [ ] `STATUS` PING cevap verir

---

## Not

Bu prompt **API/dashboard** icindir. Agent IPC localhost'tadir; cloud API'ye acilmaz.
Cloud tarafinda asil is: health semasi + RD UX + lifecycle ayirimi.

