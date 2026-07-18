# v4.4.21 — Daha hızlı IR (kill / logoff)

Sızma anında dashboard’dan gelen `kill_process` / `logoff_user` 10 sn poll yüzünden geç uygulanıyordu.

## Değişiklikler
- Komut poll: **10s → 1s** (`threat_detection.command_poll_interval`)
- IR komutları rate-limit dışı: kill, logoff, block_ip, disable_account, stop_service, lockdown…
- Aynı poll batch’inde kill/logoff **önce** çalışır
- Health report kill/logoff yolunu **bloklamaz** (async)
- `taskkill` / `logoff` timeout 5s

## Beklenen
Dashboard → Kill/Logoff → agent ≤ ~1 sn içinde uygular.
