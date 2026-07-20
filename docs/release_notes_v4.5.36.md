# v4.5.36

## Dashboard offline while GUI says Connected
- GUI “API Bağlı” only meant auth worked; **commands/pending poll** is owned by SYSTEM daemon.
- After silent update, if Background daemon is down → dashboard “çevrimdışı / poll yok”.
- Fix: frontend motor watchdog starts **emergency command bridge** (poll + heartbeat) when daemon won’t come up.
- Connection card: `API var · motor yok` when auth OK but motor/poll missing.
- Silent helper: prefer `CloudHoneypot-Background` + wait for `:58632` before tray.
