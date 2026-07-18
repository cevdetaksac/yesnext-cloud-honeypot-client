# v4.4.16 — Tam süreç listesi (Notepad++ görünür)

`AGENT_PROCESSES_FULL_LIST_PROMPT.md`:

- `top_processes` / `top_cpu_processes` artık **80–150 unique PID** (eskiden dashboard’da ~10 top-CPU)
- Birleşim: top 80 CPU + top 40 RAM + **interactive session uygulamaları** (0% CPU dahil) + şüpheli
- `top_cpu_processes` alias’ı artık kısaltılmıyor (15 satır bug’ı)
- Acceptance: Notepad++ açıkken ≤60 sn içinde dashboard listesinde

Log: `processes collected: N` / `report ok — … processes=N`
