# AGENT_LIFECYCLE_ALERTS_API_PROMPT.md

## Amac

Client (v4.4.51+) cokme / watchdog / memory-restart olaylarini hem lokal loglar
hem de API'ye ozet olarak iletir. Dashboard'da sunucu "neden kapandi?" gorunsun.

Client ham log dump etmez — sadece olay ozetleri (rate-limited, best-effort).

---

## Endpoint

### POST /api/alerts/lifecycle

Auth: agent token (body `token` ve/veya Bearer).

Body ornegi:

```json
{
  "token": "CLIENT_TOKEN",
  "ts": "2026-07-18T21:10:00Z",
  "event_type": "watchdog_restart",
  "reason": "client_not_running",
  "severity": "warning",
  "hostname": "SRV-01",
  "version": "4.4.51",
  "pid": 1234,
  "details": {
    "action": "start_daemon"
  }
}
```

Response 200:

```json
{ "status": "ok" }
```

404/501: client soft-fail eder, olay lokal kuyrukta kalir (sonraki flush).

---

## event_type katalogu (client)

| event_type | severity | Anlam |
|------------|----------|--------|
| `client_startup` | info | Client process acildi |
| `watchdog_restart` | warning | Watchdog process yok buldu, daemon baslatiliyor |
| `watchdog_restart_ok` | info | Restart sonrasi process ayakta |
| `watchdog_restart_failed` | error | Restart denendi ama process ayakta degil |
| `watchdog_error` | error | Watchdog kod hatasi |
| `memory_restart_begin` | info | 8s MemoryRestart basladi |
| `memory_restart_path` | info | Exe yolu cozuldu |
| `memory_restart_kill` | info | Process kill |
| `memory_restart_ok` | info | Restart basarili |
| `memory_restart_fallback` | warning | Direkt start fail, Background task ile denendi |
| `memory_restart_failed` | error | Restart basarisiz (exe yok / stick olmadi) |
| `memory_restart_skipped` | warning | Update lock nedeniyle atlandi |

---

## Dashboard UX (onerı)

- Sunucu detayinda **Client Lifecycle** timeline (son 50 olay)
- `severity=error` -> toast / email (opsiyonel, account prefs)
- Filtre: `watchdog_*`, `memory_restart_*`

---

## Saklama

- Tablo ornegi: `client_lifecycle_events` (server_id, ts, event_type, reason, severity, version, details JSON)
- TTL: 30-90 gun yeter

---

## Acceptance

- [ ] Watchdog client'i oldurunce ~2 dk icinde `watchdog_restart` kaydi olusur
- [ ] MemoryRestart yanlis path'te `memory_restart_failed` + reason `exe_not_found`
- [ ] Endpoint yokken client crash etmez (soft-fail + queue)
- [ ] Dashboard timeline'da olaylar hostname + version ile listelenir

## Client lokal log

`%ProgramData%\YesNext\CloudHoneypotClient\lifecycle.log`
`%ProgramData%\YesNext\CloudHoneypotClient\lifecycle_queue.jsonl`
