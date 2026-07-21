# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| **4.5.68+** | Yes (production floor — see contract `FLEET.md`) |
| 4.5.x | Yes |
| 4.4.x | Upgrade recommended |
| < 4.4 | Upgrade required |

## Reporting a Vulnerability

Email: security@yesnext.com.tr (or open a private GitHub security advisory).

Please include:
- Affected version
- Steps to reproduce
- Impact assessment

We aim to respond within **72 hours**.

## Shared contract (SoT)

Command HMAC, destructive-command dashboard confirmation, Bearer auth:

- [`../../honeypot-contract/api/03-control-websocket.md`](../../honeypot-contract/api/03-control-websocket.md)
- [`../../honeypot-contract/api/01-auth.md`](../../honeypot-contract/api/01-auth.md)

## Threat Model (client-local)

### Assets
- Client API token (`token.dat`, DPAPI-encrypted)
- Captured attacker credentials (reported to central API)
- Remote command execution surface

### Trust Boundaries
- **Internet attackers** → honeypot ports (untrusted)
- **Central API** → trusted when TLS verification is enabled
- **Local machine users** → may decrypt `LOCAL_MACHINE` DPAPI tokens

### Client Protections
- TLS certificate verification enabled by default (`api.tls_verify`)
- Bearer token in `Authorization` header; `?token=` only if `api.legacy_token_query=true` (rollback)
- Sensitive field redaction in application logs
- HMAC command signing (`security.command_signing`) — contract `api/03`
- Command whitelist, expiry, rate limits, protected resources

## Token Handling

- Tokens are stored with Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`)
- Never commit `token.dat`, `client.log`, or `watchdog.token`
- Rotate token via dashboard if logs may have been exposed

## Responsible Disclosure

We appreciate coordinated disclosure. Do not test against production systems without authorization.
