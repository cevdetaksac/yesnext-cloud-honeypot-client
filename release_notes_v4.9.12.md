# Cloud Honeypot Client v4.9.12

## System Recovery (contract 1.4.13)

Attack-surface allowlist — not full Windows/registry backup:

- Policy: DisableTaskMgr / DisableRegistryTools / DisableCMD / NoRun / NoClose
- Services: VSS, swprv, wscsvc, EventLog, Schedule
- Firewall profiles on/off
- Signed snapshots, drift alert `system_recovery_drift`, dashboard commands
  `system_recovery_snapshot` / `list` / `diff` / `restore` (dry_run + confirm)

## Network Guard panel (contract 1.4.14) + maintenance (1.4.15)

- Rich live + golden adapters (IPv4/DNS/dhcp) in STATUS / `list_network_baseline`
- `network_diff`, IPv4 restore, `auto_restore_network` (default on)
- Golden baseline not poisoned by attacker IP changes
- **Maintenance:** GUI chip → Pause → change VPN/IP → Backup → Resume
  (`network_maintenance_start` / `network_maintenance_end`, IPC `NG_MAINT_*`)

See honeypot-contract `agent/system-recovery.md` + `agent/network-guard.md`.
