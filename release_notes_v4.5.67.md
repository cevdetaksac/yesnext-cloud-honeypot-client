# v4.5.67 — Enriched ransomware canary alert

Implements honeypot-contract **1.1.3**:

- Canary containment and suspect attribution run before the urgent alert (bounded ≤4s).
- `POST /api/alerts/urgent` includes:
  - `threat_score=100`, `target_service=SYSTEM`
  - `recommended_action=isolate_host`
  - structured `raw_events`
  - `system_context.ransomware` with file/change/suspect PID, cmdline, path and SHA-256
- Health snapshots include persisted `ransomware_quarantine` details.

Cloud compatibility: use structured context first; fall back to parsing `Dosya:` and
`Değişiklik:` from ≤4.5.66 descriptions.
