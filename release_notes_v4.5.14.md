# v4.5.14 — onedir (kendi klasörü)

**Sorun:** `_MEI*` (TEMP veya ProgramData) → `LoadLibrary: Erişim engellendi`

**Çözüm:** PyInstaller **onedir** — `python312.dll` artık  
`C:\Program Files\YesNext\Cloud Honeypot Client\_internal\` altında sabit.

- Runtime extract yok
- Concurrent launch / AV TEMP kilidi yok
- Installer `dist\honeypot-client\*` + `_internal` kurar
