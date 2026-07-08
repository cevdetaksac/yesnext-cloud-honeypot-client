# v4.4.2 — Auto-update fix

- Silent updater now uses `installer_url` from GitHub API (was broken: looked for `download_url`)
- Weekly updater Task Scheduler task fixed (`--silent-update-check` instead of invalid `--mode=updater`)

**Note:** Clients on v4.4.0/v4.4.1 need one manual update (GUI → Güncellemeleri Denetle) to receive this fix; after that auto-update works every 2 hours.
