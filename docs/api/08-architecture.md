# Architecture — SYSTEM daemon + GUI frontend

> API: `https://honeypot.yesnext.com.tr`  
> Client: **≥ 4.5.47** (dead-code cleanup + winproc centralization)

---

## Model

| Katman | Process | Rol |
|--------|---------|-----|
| **Motor** | `CloudHoneypot-Background` (`--mode=daemon`, SYSTEM Session 0) | Threat, firewall, honeypot, RemoteCommands, control WS, self_update, RD |
| **Frontend** | Tray / GUI (`--show-gui`, interactive session) | UI only — reads ProgramData + IPC; **does not** own `:58632` when motor healthy |
| **Watchdog** | Scheduled task | Respawn Background if dead |

N kullanıcı aynı anda GUI açabilir; koruma motoru tektir.

```
┌─────────────┐   IPC 127.0.0.1:58632   ┌──────────────────────┐
│ GUI / Tray  │ ◄──────────────────────► │ SYSTEM daemon        │
│ frontend    │   PING/STATUS/HONEYPOT   │ commands/pending     │
│             │   CLEAR_FIREWALL         │ control WS           │
│             │   BLOCK_IP / UNBLOCK_IP  │ firewall / threat    │
└─────────────┘                          └──────────────────────┘
        │                                          │
        ▼                                          ▼
 ProgramData (blocked_ips, update_ui_status)    Cloud API
```

---

## IPC (local, newline UTF-8)

```
PING
STATUS
CLEAR_FIREWALL
BLOCK_IP <ip> [reason]
UNBLOCK_IP <ip>
HONEYPOT START <SVC> <PORT>
HONEYPOT STOP <SVC>
HONEYPOT LIST
SHOW / QUIT   (daemon: SHOW→NOGUI; QUIT for installer)
```

JSON replies start with `{`. Helpers: `client_daemon_ipc.py`.

**Kural:** Unelevated GUI **asla** doğrudan `netsh delete/add` ile envanteri silmez/mutasyon yapmaz — motor IPC kullanır. Okuma: ProgramData + throttled live scan.

---

## Ownership rules (freeze / perf)

| İş | Kim | Not |
|----|-----|-----|
| `commands/pending`, control WS | Daemon | GUI emergency bridge sadece motor yoksa |
| Firewall mutate (block/clear) | Daemon (elevated) | GUI → IPC |
| Engellenen liste | ProgramData SoT; GUI poll store; force live scan only on 🔄 / mutate | Periyodik `force=True name=all` **yasak** (4.5.44) |
| Self-update | Daemon → helper | GUI banner via `update_ui_status.json` |
| Threat / RD capture | Daemon | frontend_only skips local motors |

**Tk thread:** netsh / PowerShell / blocking IPC / honeypot start-stop **yok**.  
Motor health cache (background poll). IP mutate off-thread.  
Threat intel: tek worker + coalesce (paralel PS fırtınası yok). Servis toggle off-thread.

---

## Shared helpers

| Modül | Görev |
|-------|--------|
| `client_winproc` | Canonical hidden subprocess: `run_hidden` / `run_ps` / `run_ps_script` / `popen_detached` |
| `client_update_ui` | Cross-process update banner status |
| `client_block_store` | ProgramData blocked inventory |
| `client_daemon_ipc` | Frontend ↔ motor |

---

## STATUS örneği

```json
{
  "ok": true,
  "daemon": true,
  "role": "daemon",
  "motor_ok": true,
  "remote_commands_running": true,
  "version": "4.5.46",
  "running_services": ["SSH"],
  "protection_mode": "monitoring",
  "token_present": true
}
```

---

## Lifecycle

- `client_startup` — daemon veya frontend
- `gui_quit` — frontend kapandı; **motor ayakta kalmalı**
- `self_update_*` — ACK + helper; bitiş = yeni process version

---

## God-files (bilinçli sınır)

Büyütmeden önce çıkar: `client_gui.py`, `client.py`, `client_utils.py`.  
Yeni GUI özellikleri: `client_gui_*.py` alt modülleri tercih et.

---

## Acceptance

- [ ] Motor sağlıklı → GUI `frontend_only`, `:58632` daemon’da
- [ ] Engelle / Tümünü temizle → IPC; unelevated netsh fail etmez / flaş yok
- [ ] Status açıkken periyodik full `name=all` fırtınası yok
- [ ] GUI kapandı → dashboard poll devam
- [ ] İki RDP kullanıcısı → RD `session_id` doğru masaüstü
