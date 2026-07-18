# v4.4.35 — "Installer'i simdi calistir?" sonrasi installer acilmiyordu

## Sorun
- Evet sonrasi helper once kendi process'ine QUIT gonderiyordu
- Uygulama installer baslamadan kapaninca NSIS hic acilmiyordu
- Gizli powershell yolu da log uretmeden sessiz kaliyordu

## Fix
- Interaktif guncelleme: NSIS installer'i **dogrudan gorunur** ac (UAC/SW_SHOWNORMAL)
- Self-QUIT yarisi kaldirildi; client installer acildiktan sonra cikar
- Silent path helper'i ayri kaldi (arka plan guncelleme)
