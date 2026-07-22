# v4.9.8

- Resource corner badge (App CPU/RAM · Host CPU/RAM · net ↓↑) via STATUS `resources{}`
- Session-0 motor `ABOVE_NORMAL` priority (never REALTIME); optional `security.motor_priority`
- Realtime presence (honeypot-contract **1.4.12** / `api/11-presence-realtime.md`):
  - Sleep: WS `presence` suspend + HTTP `POST /api/presence` ≤2s
  - Stop: `goodbye` then close (`shutdown` / `update` / `uninstall` / `operator_stop`)
  - Wake: reconnect + presence online / hello
  - GUI quit alone does not mark host offline while motor is up
