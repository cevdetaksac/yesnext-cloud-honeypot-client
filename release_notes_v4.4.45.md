# v4.4.45 — Update: client must be closable

Self-protect artık güncelleme sırasında kapanmayı engellemez:

- `disarm_for_update()` — DACL kaldırılır, `HoneypotClientGuard` kapatılır
- GUI + silent update çıkışında disarm + QUIT
- `prepare_client_for_installer` her zaman disarm eder
- Update lock varken QUIT asla ignore edilmez (startup grace bypass)
- `graceful_exit` önce self-protect’i indirir
