# Cloud Honeypot Client v4.9.15

## Soft network surface inform (contract 1.4.17)

- Additive changes (Ethernet up, DHCP lease, new NIC) → soft `network_surface_changed` (info, not urgent)
- **No panic while `internet_ok`** — no auto-disable, no auto-restore on enrichment
- `auto_restore_network` remains subtractive-only (adapter down / DNS / firewall)
- STATUS: `surface_inform` + `surface_inform_changes`
- Commands: `network_accept_surface`, `network_disable_adapter` (confirm)
- GUI: chip “Ağ değişti” + soft toast + **Bu bendim — yedeği güncelle** (no PIN)

## Includes

- 4.9.12–4.9.14 System Recovery, NG panel/maintenance, STATUS cache fix, VSS delete intent
