# Cloud Honeypot Client v4.9.7

## Highlights

- **Threat Intel → HP-INTEL-\*:** Firewall IoCs apply as dedicated `HP-INTEL-<id>` inbound+outbound rules (not `HP-BLOCK-*`). Severity/allowlist/`expires_at`/orphan reconcile; ACK includes `firewall_removed`. ETag persisted for 304.
- **successful_logon fix:** Bare RDP/success no longer scores 100 or auto HP-BLOCK. Caps 70 (silent 80). `should_auto_block()` false for bare success. Block only brute→success / honeypot / block_rules / operator. Silent hours alert-only.
- **Whitelist enforce:** Whitelist IPs are never blocked; if already blocked, `block_ip` and `update_whitelist` immediately remove HP-BLOCK/HP-INTEL rules.

## Production floor

Unchanged: **client ≥ 4.9.0**.

## Build

`build.ps1 -Clean -WebRTC`
