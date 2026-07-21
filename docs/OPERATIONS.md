# Operations Guide

## Shared contract

API / agent davranış SoT: [`../../honeypot-contract`](../../honeypot-contract) (`VERSION` ≥ **1.1.4**, `FLEET.md`).

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

1. **Central API** — urgent/batch alerts (`POST /api/alerts/urgent` …) — contract `agent/threat-engine.md`
2. **Optional local webhook** — `notifications.webhook_url` in `client_config.json`
3. **Local logs** — `%APPDATA%\YesNext\CloudHoneypotClient\threats.log` (or ProgramData paths)
4. Forward via Winlogbeat / NXLog as needed

## Token Rotation

If `client.log` was exposed:

1. Revoke token in dashboard
2. Delete ProgramData `token.dat` (`%ProgramData%\YesNext\CloudHoneypotClient\`)
3. Restart client to re-register

## Backend / fleet defaults (current)

Contract defaults (not “future work”):

- `Authorization: Bearer` — agent API’de `?token=` yok
- `api.legacy_token_query: false`
- Command HMAC — `security.command_signing` (default true); see contract `api/03-control-websocket.md`
- Destructive IR — dashboard confirmation on cloud

## Linux Notes

`client_firewall.py` supports Linux (ipset/iptables). Honeypot decoys are Windows-focused; Linux agent is firewall-only today.
