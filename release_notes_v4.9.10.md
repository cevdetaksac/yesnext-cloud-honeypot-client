# v4.9.10

- Fix Guardian SCM start timeout loop (Event 7009/7000): fast-path boot before heavy imports.
- Soft heal: no delete+recreate; wait on START_PENDING.
- `guardian_restarts_24h` counts successful recovers only (failed heals → heal_attempts).
- Prunes legacy inflated counters; aligns with cloud soft-alert (guardian_false alone ≠ critical).
