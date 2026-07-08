# v4.4.1 — Tray, Performance & Debug

**Date:** 2026-07-08

## Tray
- Thread-safe `show_window()` / `minimize_to_tray()` (Tk main thread)
- Windows `SetForegroundWindow` for reliable foreground focus
- Removed session health auto-hide (prevented reopen from tray)
- `TrayManager.notify()` for alert balloons

## Performance
- Dashboard refresh: 10s default (config: `ui.dashboard_refresh_seconds`)
- Lazy security intel: scans only when Threat Center tab is active
- IP table refresh only on Dashboard tab
- `FalsePositiveTuner.start()` periodic cleanup loop
- Non-blocking CPU sampling in PerformanceOptimizer

## Debug
- `--debug` CLI flag (verbose logs, skip consent, skip admin elevation)
- `debug.*` config section unified with `logging.debug_mode`
- DEBUG badge in title bar when active

## Watchdog
- Restart with `--show-gui` so window is visible after crash recovery
