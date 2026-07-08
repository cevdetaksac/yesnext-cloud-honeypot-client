# Operations Guide

## Deployment Phases

| Phase | Version | Contents | Deploy |
|-------|---------|----------|--------|
| 1 | 4.4.0 | TLS, token headers, log redaction, SECURITY.md | Client installer |
| 2 | 4.4.0 | Tests, CI pipeline | GitHub Actions |
| 3 | 4.4.0 | HTTP/SMB honeypots, bind_address, webhooks | Client + config |
| 4 | 4.4.0 | Modern UI | Client installer |

## Build & Release

```powershell
cd cloud-client
.\build.ps1
```

Artifact: `dist\cloud-client-installer.exe`

Publish via GitHub Releases (`cevdetaksac/yesnext-cloud-honeypot-client`).

## Windows Defender / AV

- Submit installer to [Microsoft Defender portal](https://www.microsoft.com/en-us/wdsi/filesubmission)
- Reference `DEFENDER_MARKERS` in `client_constants.py`
- Sign installer with Authenticode certificate for best results

## SIEM Integration

Client sends events to central API. For SIEM export:

1. **API webhooks** — configure `notifications.webhook_url` in `client_config.json`
2. **Local logs** — `%APPDATA%\YesNext\CloudHoneypotClient\threats.log`
3. **Windows Event Log** — v4 EventLog watcher forwards to API `/api/alerts/urgent`

Forward `threats.log` via your log agent (Winlogbeat, NXLog, etc.).

## Linux Notes

`client_firewall.py` supports Linux (ipset/iptables). Honeypot decoys are Windows-focused; Linux agent is firewall-only today.

## Token Rotation

If `client.log` was exposed:

1. Revoke token in dashboard
2. Delete `%APPDATA%\YesNext\CloudHoneypotClient\token.dat`
3. Restart client to re-register

## Backend Coordination (v4.4)

Enable on server when ready:

- `Authorization: Bearer` header support
- Set client `api.legacy_token_query: false`
- Command HMAC signing (see `client_security_utils.sign_command`)
