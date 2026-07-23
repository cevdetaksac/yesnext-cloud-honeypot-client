# Cloud Honeypot Client v4.9.18

## Hotfix — defense policy cache token race

- Re-sign valid policy JSON when HMAC fails due to empty-token boot race (avoid false `tamper_observe`)
- Includes 4.9.17 observe default + 3-day auto-promote + GUI education (contract 1.4.19)
