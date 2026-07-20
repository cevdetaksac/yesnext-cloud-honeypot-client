# Threat Intel Feed — Client contract

> Full cloud spec: [`../CLOUD_THREAT_INTEL_API.md`](../CLOUD_THREAT_INTEL_API.md)  
> Client: **≥ 4.5.61** · Daemon only (frontend does not poll)

---

## Endpoint

```http
GET /api/agent/threat-intel?token=…&since_version=…&os=windows&client_version=4.5.61
If-None-Match: "<etag>"
```

| Code | Client behavior |
|------|-----------------|
| 200 | Save bundle to ProgramData, apply layers |
| 304 | Keep cache, refresh `last_check_at` |
| 4xx/5xx | Keep cache; retry next interval |

Optional:

```http
POST /api/agent/threat-intel/ack
```

---

## Apply map

| Layer | Module |
|-------|--------|
| `firewall_blocks` | Firewall agent / block store (`HP-INTEL-*`) if policy allows |
| `ransomware.*` | Merge into `RansomwareShield` watch lists (no lockdown from intel alone) |
| `process_watch` | Soft match → alert |
| `kev_cves` / `hardening` / `ui_banners` | Log + GUI/dashboard surfaces |

Cache path: `%ProgramData%\YesNext\CloudHoneypotClient\threat_intel_bundle.json`

---

## Policy defaults (if cloud omits)

```json
{
  "auto_block_firewall": true,
  "intel_block_requires_severity_at_least": "high",
  "max_firewall_rules_from_intel": 500
}
```
