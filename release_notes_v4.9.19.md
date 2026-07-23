# Cloud Honeypot Client v4.9.19

## Hotfix — false defense_policy_tamper

- Do not treat unrelated `config.sig` as defense matrix HMAC
- Invalid `defense_rules_sig` → apply unsigned with hard-safety (no tamper escalate)
- Lab: observe default stays healthy after threats/config sync

Includes 4.9.17–4.9.18 onboarding + cache re-sign.
