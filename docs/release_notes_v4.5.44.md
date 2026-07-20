# v4.5.44

## Stability & performance pass

- Stop periodic forced full firewall scans (was freezing / CPU storms on Status tab)
- Never wipe block inventory when `netsh` enumeration fails
- GUI IP block/unblock runs off the UI thread via daemon IPC when motor is up
- Cleanup firewall no longer holds a global lock across long netsh/API work
- Shared `client_winproc.run_hidden` for console-free subprocesses
- Updated architecture contract: `docs/api/08-architecture.md`
