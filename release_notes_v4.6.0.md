# Release v4.6.0 — Survival + disaster recovery

Contract: `honeypot-contract` **v1.2.0**

## Guardian + tamper
- New Windows service `CloudHoneypotGuardian` (`--mode=guardian`, LocalSystem, SCM failure recovery)
- Motor ensures Guardian every 30s; Guardian resurrects motor every 10s if `motor_ok` false
- Motor QUIT rejected unless `update_in_progress.lock` or signed `operator_stop.json` (PIN exit)
- Unexpected motor exit → `agent_tamper` urgent on next boot; `motor_heartbeat.json` dead-man beacon
- STATUS + health report include `persistence{}` block

## Disaster recovery (dashboard IR)
- `create_user` — break-glass local admin (`if_exists=reset_enable`)
- `remote_logon` — existing session reconnect; zero session → autologon + reboot
- `set_autologon` / `clear_autologon` / `reboot` helpers

## Cloud/API actions required
- Whitelist new command types + destructive confirm for `create_user`, `remote_logon`, `set_autologon`, `reboot`
- Handle `agent_tamper` urgent (`system_context.tamper`) in popup builder
- `pending_tunnel_commands` TTL/dedupe (contract `agent/attacks-and-services.md`)
- Optional: cloud dead-man — alert when `motor_heartbeat.json` stale via health ingest
