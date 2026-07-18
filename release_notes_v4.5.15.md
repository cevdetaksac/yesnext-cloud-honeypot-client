# v4.5.15 — SYSTEM daemon WinError 183 fix

**Hata:**  
`[WinError 183] Halen varolan bir dosya oluşturulamaz: ...\systemprofile\AppData\Roaming\YesNext\CloudHoneypotClient`

**Neden:** Session 0 SYSTEM, Roaming APPDATA altında `makedirs` (dosya/klasör çakışması).

**Düzeltme:**
- SYSTEM / Session 0 → `APP_DIR` = `%ProgramData%\YesNext\CloudHoneypotClient`
- `makedirs` WinError 183’e dayanıklı (`_ensure_directory`)
