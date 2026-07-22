# Cloud Honeypot Client v4.9.11

## Alert signal hygiene (§1–10)

Implements https://honeypot.yesnext.com.tr/static/docs/CLIENT_ALERT_SIGNAL_HYGIENE.md

**Critical fixes in this pass:**
- **Lifecycle double POST (§8):** `report_now` no longer flush-reposts; same `event_type`+UTC-second dedupe; `gui_quit` rate-limit; process-stop → lifecycle only
- **Canary 30m loop (§3):** soft single-file MODIFIED debounce ≥30m all paths; soft never `/api/alerts/urgent`
- **list shadows urgent (§1):** process skip + AlertPipeline `_send_urgent` hard drop

Also: shadow delta tiers, offline flap/dedupe, trusted/local info≤10, intel observe-only.

See `docs/CLIENT_ALERT_SIGNAL_HYGIENE.md`.
