# Cloud Honeypot Client v4.9.21

## Remote Desktop — console Winlogon / pre-logon (contract 1.4.21)

- Mirror the Windows logon / lock UI when nobody is logged on (`WinSta0` + `Winlogon`)
- `list_sessions` exposes a `pre_logon` console row with `can_capture=true`
- `remote_session_prepare` falls back to Winlogon instead of `UNSUPPORTED` (use `prefer=existing` to keep the old gate)
- Keyboard/mouse inject after Winlogon attach; desktop re-attaches to `Default` after logon

Cloud/viewer: `honeypot-contract` **1.4.21** → `cloud/REMOTE_DESKTOP_WINLOGON.md` (C-WL-*).
