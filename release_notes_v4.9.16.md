# Cloud Honeypot Client v4.9.16

## Defense Policy P0 (contract 1.4.18)

- Apply `defense_policy` / `defense_rules` / `defense_policy_version` / `isolate_armed` from threats/config
- Signed local cache + LKG; tamper fails safe to LKG/observe — **never** isolate or escalate
- Matrix-driven canary / VSS / critical process actions (`alert_only`, `suspend`, `kill_quarantine`)
- Hard-reject `auto_isolate_network` on observe/balanced (anti-bait)
- Commands: `allow_process`, `list_allowed_processes`; `isolate_host` gated (P2 not fully enabled)
- Session JPEG snapshot on red events (≤1 / 5 min / family)
- STATUS + health expose `defense_policy` / version for cloud pull

## Includes

- 4.9.15 soft network surface inform
- 4.9.12–4.9.14 System Recovery, NG panel/maintenance, VSS delete intent
