# v4.5.63 — Quarantine arm-first + user Documents canaries

## Fixes from local scenario testing (DESKTOP-F5SCL3G)
- Quarantine now **arms immediately** on canary/VSS hit; suspect `open_files` scan is time-boxed (≤4s) so STATUS/GUI no longer wait ~50s
- SYSTEM daemon also deploys canaries under interactive users' `Documents` (previously only systemprofile + Public + ProgramData)

## Still in 4.5.62
- Sort-bait `!000_` canaries, Hidden+System, IFEO quarantine, unlock via GUI/IPC/dashboard
- Cloud threat-intel consumer
