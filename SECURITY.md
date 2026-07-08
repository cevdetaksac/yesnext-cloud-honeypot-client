# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 4.4.x   | Yes       |
| < 4.4   | Upgrade recommended (TLS, token handling fixes) |

## Reporting a Vulnerability

Email: security@yesnext.com.tr (or open a private GitHub security advisory).

Please include:
- Affected version
- Steps to reproduce
- Impact assessment

We aim to respond within **72 hours**.

## Threat Model

### Assets
- Client API token (`token.dat`, DPAPI-encrypted)
- Captured attacker credentials (reported to central API)
- Remote command execution surface

### Trust Boundaries
- **Internet attackers** → honeypot ports (untrusted)
- **Central API** → trusted when TLS verification is enabled
- **Local machine users** → may decrypt `LOCAL_MACHINE` DPAPI tokens

### Client Protections (v4.4+)
- TLS certificate verification enabled by default (`api.tls_verify`)
- Bearer token in `Authorization` header (query string optional via `api.legacy_token_query`)
- Sensitive field redaction in application logs
- HMAC command signing (`security.command_signing`)
- Command whitelist, expiry, rate limits, protected resources

## Token Handling

- Tokens are stored with Windows DPAPI (`CRYPTPROTECT_LOCAL_MACHINE`)
- Never commit `token.dat`, `client.log`, or `watchdog.token`
- Rotate token via dashboard if logs may have been exposed

## Remote Commands

Destructive commands (`reset_password`, `emergency_lockdown`, `disable_account`) require dashboard confirmation on the server side. Client enforces whitelist + protected targets.

## Responsible Disclosure

We appreciate coordinated disclosure. Do not test against production systems without authorization.
