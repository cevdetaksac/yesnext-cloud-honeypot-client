# v4.4.5 — API sözleşme hizalaması (dashboard sync)

AGENT_CLIENT_REVIEW_PROMPT.md referans alınarak üretim loglarındaki uyumsuzluklar giderildi.

## Düzeltmeler

| # | Sorun | Düzeltme |
|---|--------|----------|
| 1 | Auto-block path `v4/auto-block` | Kanonik `POST /api/alerts/auto-block` |
| 2 | Urgent `auto_response` / float score | `auto_response_taken: string[]`, `threat_score: int`, ISO timestamp |
| 3 | Attack payload | `ip` alias eklendi; credential → urgent'e password aktarımı |
| 4 | Health field adları | `disk_io_*_bytes_sec`, `network_bytes_*_sec`, `open_connections` |
| 5 | Tunnel status | `listen_port` + `port` birlikte gönderiliyor |
| 6 | events/batch | `batch_id` + kanonik event şeması |
| 7 | API 422 | Schema `detail` loglanıyor; 2xx kabul |
| 8 | Open ports | `process` adı (pid üzerinden) |
| 9 | Installer kill | 5 turlu watchdog-safe process kill |

## Breaking changes
Yok — sunucu toleranslı alias'lar korunuyor; client kanonik forma geçti.
