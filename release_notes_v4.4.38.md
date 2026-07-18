# v4.4.38 — Setup Finish'te Python DLL / _MEI hatasi

## Sorun
- Finish → Launch: once `--create-tasks` sonra hemen `--show-gui`
- PyInstaller onefile iki kez `%TEMP%\_MEI*` aciyordu → `Failed to load Python DLL ... python312.dll`

## Fix
- Interactive finish: tek `ExecShell --show-gui` (task'lar app init'te)
- Silent: tek `--mode=daemon` (create-tasks cift launch yok)
- Kill sonrasi 2s bekle (_MEI temizlik)
