# v4.5.66 — Contract gaps: protection.block_rules + threat_intel_updated

Implements remaining client gaps against honeypot-contract **1.0.0**:

1. **Register / threats/config** — `protection.block_rules` → ThreatEngine (schema normalize + ProgramData persist)
2. **Control WS** — `t: threat_intel_updated` → immediate threat-intel sync

See `agent/register-protection.md` and `api/09-threat-intel.md`.
