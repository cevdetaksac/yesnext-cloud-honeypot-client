# Cloud Honeypot Client v4.9.23

## Installer — FileInUse hardened

Follow-up to 4.9.22 when Session-0 still holds the `_internal` directory:

- Per-file relocate (locked `.pyd` / `.dll` renamed aside → NSIS writes fresh originals)
- Stronger process terminate + longer grace after QUIT (DACL disarm)

Use **v4.9.23+**. If an old installer dialog is still open, click **Durdur**, then run this build.
