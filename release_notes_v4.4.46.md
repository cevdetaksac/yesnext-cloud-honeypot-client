# v4.4.46 — Faster silent update checks

- Silent update poll: **30 dk → 15 dk** (Task Scheduler + in-process watchdog)
- Startup: first check ~**90 sn** after launch (previously waited a full interval)
- Config floor lowered to **5 dk** (`updates.check_interval_minutes`)
- No-update poll is a small GitHub `releases/latest` GET only; installer downloads only when a newer version exists
