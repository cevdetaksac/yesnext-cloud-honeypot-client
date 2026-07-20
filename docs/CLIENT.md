# Windows Client — Sözleşme Özeti

> **API:** `https://honeypot.yesnext.com.tr` / `wss://…`  
> **Durum:** Client **4.5.44**  
> (control WS + self_update ACK; GUI update banner ≥4.5.39; Engellenen live-firewall ≥4.5.40;  
> GUI Clear-all / block → SYSTEM IPC ≥4.5.42–44; perf coalesce ≥4.5.44)  
> Bu dosya yeni client işi için **kısa referans**; detay: [api/](./api/).

Cloud implementasyonu: [CLOUD.md](./CLOUD.md) (varsa)

---

## Auth

- Client varsayılan: sadece `Authorization: Bearer <token>` (`api.legacy_token_query=false`)
- Query `?token=` agent tarafında **gönderilmez** (log sızıntısı); cloud dual-read → reject fazlı olabilir
- Control / RD WS: Bearer header (legacy flag açıksa query fallback)

---

## Control WebSocket

```
wss://honeypot.yesnext.com.tr/ws/agent/control
```

1. Bağlan → agent `hello`  
   `{ v, t:"hello", role:"agent", version, hostname, pid, mode:"daemon" }`  
   (`machine_id` yok; register/heartbeat’te ayrı)
2. `ping` her ~25s → `pong` (+ sunucu alanları)
3. Cloud `command` push → **hemen** mevcut command handler (HTTP poll ile aynı path)
4. Sonuç asıl: `POST /api/commands/result` (WS `command_result` / ack opsiyonel)
5. WS kopunca reconnect (backoff); HTTP `GET /api/commands/pending` **sürekli safety net**  
   (WS sağlıklıyken aralık seyreltilir — tek-shot değil)
6. HTTP heartbeat / attack / health **HTTP** kalır (control WS app-heartbeat göndermez)
7. RD ayrı: `/ws/remote/agent`

---

## Self-update

| Sinyal | Anlam |
|--------|--------|
| `result` `running` / `update_accepted` | Erken ACK |
| `result` `completed` / `update_started` + lifecycle `self_update_ok` | Helper launch (**bitmedi**) |
| Yeni process + heartbeat `version` | Gerçek başarı |

Cloud UI bitişi version eşleşmesiyle yapar; ikinci `install_complete` zorunlu değil.

**GUI (≥4.5.39):** daemon → `%ProgramData%\YesNext\CloudHoneypotClient\update_ui_status.json`  
→ üst banner: accepted → downloading% → installing → done/failed.

---

## IR / hesap komutları

| Type | Not |
|------|-----|
| `logoff_user` | username / session_id |
| `contain_user` | logoff + zorunlu `new_password` (+ opsiyonel disable) |
| `disable_account` / `enable_account` | |
| `reset_password` | Dashboard `new_password` (≥8); agent uydurmasın |
| `disable_all_users` | Administrator **dahil**; `logoff`, `exclude`; priority critical |
| `kill_process` | Agent kendi PID / self-image kill yok |

---

## Firewall / Engellenen

- Envanter SoT: Windows Firewall `HP-BLOCK-*` / `HONEYPOT_*`  
  → canlı `netsh … name=all` → ProgramData `blocked_ips.json` → GUI + `POST /api/agent/sync-rules`
- Komut `clear_firewall` (control WS / poll):
  - Params: `wipe_all_honeypot_rules` (default true), `ips[]` (yedek per-IP), `reason`
  - Önce honeypot kural wipe, sonra `ips[]` name-template silme
  - Ardından `sync-rules` `blocks:[]` + `clear-data` `scopes:["blocks"]`
- **GUI Engellenen → Tümünü temizle** / tek IP engelle:  
  unelevated GUI → IPC (`CLEAR_FIREWALL` / `BLOCK_IP` / `UNBLOCK_IP`) → Session-0 daemon.  
  Periyodik liste: ProgramData + throttled scan (`force` sadece 🔄 / mutate).

---

## Mimari (kısa)

- Motor: SYSTEM `--mode=daemon` (command poll, control WS, firewall, self_update)
- GUI/tray: frontend; motor sağlıklıyken `:58632` çalmaz
- Token immutable (ProgramData); multi-server account link UX

---

## Diğer

- Threat / health / lifecycle / sessions+processes — v4 HTTP
- Remote: session_id seçimi, klavye Unicode, SYSTEM ≠ oturum masaüstü

Detay: [api/01-auth.md](api/01-auth.md) … [api/08-architecture.md](api/08-architecture.md), [CHANGELOG.md](CHANGELOG.md).
