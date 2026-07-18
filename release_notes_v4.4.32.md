# v4.4.32 — GUI guncelleme: indirme sonrasi installer acilmiyordu

## Fix
- UAC artik `ShellExecuteW runas` ile GUI prosesinden aciliyor (gizli powershell UAC'yi yutuyordu)
- Indirme bitince hemen "Installer'i calistir?" soruluyor; Evet → helper + hizli exit
- Helper basarisiz/UAC iptal → dogrudan installer fallback
- `update-and-install.ps1` hizlandirildi (kisa grace, hizli kill, 0.8s settle)
- Bloklayan "helper basladi" messagebox kaldirildi (exit gecikiyordu)
