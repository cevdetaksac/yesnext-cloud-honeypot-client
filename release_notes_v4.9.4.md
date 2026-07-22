# Cloud Honeypot Client v4.9.4

## Highlights

- **Contract 1.4.8 — Server Management:** `list_services` inventory; service mutate accepts `name` **or** `service_name`; Guardian/OS services protected (`PROTECTED_SERVICE`); local users include `groups`; processes/sessions refresh via health after mutates. No account delete in v1 — use disable.
- **Remote Desktop stability:** encode WxH locked for the stream session (min **800×600** when source allows); adaptive controller no longer thrash resolution — only fps/quality.

## Production floor

Unchanged: **client ≥ 4.9.0**. Target for Server Management UI: **≥ 4.9.4**.

## Build

`build.ps1 -Clean -WebRTC`
