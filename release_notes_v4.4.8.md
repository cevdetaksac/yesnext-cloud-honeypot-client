# v4.4.8 — V4 update gaps + sessions/processes + stale blocks

## CLIENT_V4_UPDATE_PROMPT — kapatılan boşluklar

| Madde | Önce | Şimdi |
|--------|------|--------|
| Commands poll | 5s | **10s** |
| events/batch | 60s / max 50 / zayıf summary | **120s / 500** + category + full summary; fail’de buffer korunur |
| Urgent | fire-forget | **3 retry / 30s** + `actions_requested` |
| Urgent cooldown | critical 60s | **5 dk** (threat_type+IP) |
| Config sync | 2 dk | **5 dk** + auto_block limits + channels |
| Health report | const 300 (runtime 60) | **60** |
| Canary check | 10s | **30s** + config paths |
| Remote cmds | eksik start/restart / lockdown alias | **eklendi** |
| Protected accounts | SYSTEM… | + **ADMINISTRATOR** |
| Silent hours TZ | local | **Europe/Istanbul** (zoneinfo) |

## Önceki 4.4.8 işleri (aynı sürüm)

- `active_sessions` + zengin `top_processes`
- `pending-unblocks` batch ACK
- Bakım/temizlik menüsü (clear-data)

## Kalan riskler

- Event channel değişince subscription restart gerekir (uygulandı)
- `signed`/WinVerifyTrust hâlâ yok (opsiyonel)
- Canary Public Desktop yolu görünür olabilir — config’ten kapatılabilir
