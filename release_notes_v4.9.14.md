# Cloud Honeypot Client v4.9.14

## VSS delete intent (contract 1.4.16)

- `vssadmin delete shadows` / WMI / wbadmin (score ≥95) → immediate `taskkill` + quarantine arm
- Does **not** wait for shadow-count drop (≤120s path)
- No IFEO on `vssadmin` / `wmic` / `powershell` / `cmd` / `wbadmin` (keeps inventory healthy)
- Process poll 5s → 2s
- Urgent alert: `ransomware_vss_delete_intent`

Note: `HP-BLOCK` remains IP firewall identity — it does not deny VSS delete.

## Includes

- 4.9.12 System Recovery + Network Guard panel / auto_restore / maintenance
- 4.9.13 STATUS hang fix (live cache)
