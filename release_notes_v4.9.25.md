# Cloud Honeypot Client v4.9.25

## Fix — no more plain `.py` sources under Program Files

`honeypot-client.spec` was copying dozens of `client_*.py` files into `_internal` via `datas=`, so the install tree looked like an open source tree.

- Application modules are packaged **only** into the PYZ archive (bytecode)
- `datas=` keeps icons/JSON/`memory_restart.ps1`/update helper only
- Build gate fails if any `client_*.py` appears under `dist/.../_internal`

Note: bytecode is not strong obfuscation against a determined reverse engineer; it stops casual browsing of readable source in Explorer.
