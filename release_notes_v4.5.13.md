# v4.5.13 — PyInstaller TEMP Access denied fix

**Hata:** `Failed to load Python DLL 'C:\WINDOWS\TEMP\_MEI*\python312.dll' — LoadLibrary: Erişim engellendi`

**Neden:** Onefile extract `C:\WINDOWS\TEMP` altında; SYSTEM/Admin + AV / execute-from-TEMP politikası DLL yüklemeyi kesiyor.

**Düzeltme:**
- `runtime_tmpdir` → `%ProgramData%\YesNext\CloudHoneypotClient\runtime`
- Installer bu klasörü + Defender exclusion oluşturur
