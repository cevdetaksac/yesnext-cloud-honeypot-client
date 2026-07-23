# Cloud Honeypot Client v4.9.22

## Installer — no more FileInUse stalls

Fixes Abort/Retry/Ignore on locked onedir files (e.g. `_internal\win32\servicemanager.pyd`):

1. Stronger kill (any process under install dir)
2. Defender exclusion **before** extract
3. Rename locked `_internal` / exe aside (`.stale_*`), then write a fresh tree
4. Same prep from `update-and-install.ps1` for silent updates

If you still see the dialog on an old installer, cancel and use **v4.9.22+**.
