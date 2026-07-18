# v4.4.27 — Güvenli güncelleme akışı (DLL / _MEI hatası)

## Sorun
Çalışan onefile EXE kapanmadan üzerine yazılınca PyInstaller `_MEI…\python312.dll` yüklenemiyordu.
Kullanıcı düzeyinde kill, DACL self-protect yüzünden çoğu zaman başarısızdı.

## Yeni akış
1. İndirme biter → `update-and-install.ps1` (elevated, ayrı süreç) başlar  
2. Uygulama kendisi çıkar (QUIT)  
3. Helper SeDebug ile kalan süreçleri öldürür ve **süreç yoksa** kurar  
4. Installer WAIT → `--create-tasks` → `--show-gui`  

Log: `%ProgramData%\YesNext\CloudHoneypotClient\update-install.log`
