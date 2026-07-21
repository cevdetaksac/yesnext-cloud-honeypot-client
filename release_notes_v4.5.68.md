# v4.5.68 — Canary urgent wire hotfix

Fixes live smoke gap found after 4.5.67 deploy:

- Canary previously called thin `AlertPipeline.handle_alert` first, then enriched
  `send_urgent`. Live logs showed the thin payload winning the popup.
- Now a **single** enriched urgent is sent after containment (≤4s), including
  `system_context.ransomware`, process-compatible `raw_events`,
  `target_service=SYSTEM`, and `recommended_action=isolate_host`.

Requires cloud popup to prefer `system_context.ransomware` (contract ≥1.1.3).
