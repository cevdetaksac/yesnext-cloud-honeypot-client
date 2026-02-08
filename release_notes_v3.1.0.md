# 🚀 Cloud Honeypot Client v3.1.0 - UI Polish & Reliability

**Release Date:** February 8, 2026

## 🎨 GUI Improvements

### Dark Mode & Layout
- **Unified top bar**: PC/IP, Token, version, Dashboard, Settings, Help — all in one compact row
- **Custom dark popup menus**: Settings and Help dropdowns now use CTkToplevel dark popups instead of tk.Menu
- **Popup toggle fix**: Menus now properly reopen after first use (replaced FocusOut with global click-away)
- **Service card icon alignment**: Fixed RDP/MSSQL icon extra spacing caused by emoji variation selectors
- **Fixed icon widths**: All service cards now have consistent icon column width (30px, centered)

### Protection Status
- **Accurate header badge**: "Koruma Aktif" (green) shows immediately on startup when services are running — no more 5-second delay
- **Faster pulse blink**: Status dot now blinks every 800ms (was 5 seconds tied to dashboard refresh)

## 🔄 Service Auto-Restore

- **Persistent service state**: Services that were running before app close/update are now automatically restarted on next launch
- **Background restore**: Services restart in a background thread so GUI doesn't freeze
- **Consent-aware**: Auto-restore only activates if user consent is accepted
- **Per-service logging**: Each restored service logs success/failure individually

## 🌐 API Connection Status

- **Real-time tracking**: Dashboard "API Connection" card now reflects actual API call success/failure (`_last_api_ok` flag)
- **Instant disconnect detection**: If API becomes unreachable, status switches to "Disconnected" (red) within one polling cycle
- **No false positives**: Previously showed "Connected" forever after first successful call

## 📦 Installer Improvements

### Finish Page
- **Launch checkbox**: "Launch Cloud Honeypot Client now" checkbox on finish page (checked by default)
- **De-elevated launch**: App launches as current user (not admin) via `explorer.exe` — prevents session/elevation issues
- **No ghost window**: Fixed issue where GUI would flash and disappear into tray after install

### Encoding Fix
- **ASCII-safe finish page**: Replaced Turkish characters with English text in NSIS finish page (NSIS processes .nsi as ACP/ANSI, corrupting Turkish chars like ı, ş, ü, ö, ç, ğ)

## 🐛 Bug Fixes

| Issue | Fix |
|-------|-----|
| Popup menu won't reopen after first use | Replaced `<FocusOut>` with global `<Button-1>` + `_active_popup` tracking |
| Header shows "Koruma Pasif" despite active services | Set header status immediately after service cards build |
| All services reset on every GUI startup | Replaced `write_status([], False)` with `_restore_saved_services()` |
| API status always "Connected" after first success | Track `_last_api_ok` per API call, update dashboard in real-time |
| Installer finish page Turkish chars corrupted | Use English-only text for NSIS finish page defines |
| App launches as admin from installer | Use `explorer.exe` for de-elevated launch via custom NSIS function |
| RDP/MSSQL service card icons misaligned | Remove variation selectors from emojis + fixed 30px icon width |

## 📋 Technical Details

- **Commits**: 7 commits in this release
- **Files changed**: `client_gui.py`, `client.py`, `installer.nsi`, `client_constants.py`
- **Compatibility**: Windows 10/11, Python 3.12.6, CustomTkinter 5.2.2
