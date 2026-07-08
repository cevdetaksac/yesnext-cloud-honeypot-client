# v4.4.0 — Security, Honeypots & Modern UI

**Date:** 2026-07-08

## Security
- TLS certificate verification enabled by default (`api.tls_verify`)
- Bearer token in `Authorization` header; legacy query param optional
- Log redaction for tokens and passwords
- HMAC command signing for remote commands
- `SECURITY.md` added

## Features
- HTTP honeypot (login form decoy, port 80)
- SMB honeypot (minimal negotiate probe, port 445)
- Configurable `services.bind_address`
- Webhook notifications (`notifications.webhook_url`)
- Installer SHA-256 verification option

## UI
- Sidebar navigation (replaces tabs)
- New slate/emerald design system (`client_gui_theme.py`)
- Wider default window (1100×720)

## Quality
- Unit tests (`tests/`)
- GitHub Actions CI
- Pre-commit secret check script
- `OPERATIONS.md` deployment guide

## Migration
1. Update `client_config.json` or reinstall (config merged on upgrade)
2. Revoke old tokens if `client.log` was exposed
3. Backend: enable Bearer auth when ready; set `api.legacy_token_query: false`
