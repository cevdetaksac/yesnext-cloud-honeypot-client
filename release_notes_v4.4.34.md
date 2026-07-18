# v4.4.34 — Kurulum sonrasi GUI acilmiyordu

## Sorun
- Eski/gizli `honeypot-client` ornegi singleton mutex'i tutuyordu
- `--show-gui` DACL yuzunden kapatamayip **exit code 2** ile cikiyordu
- Finish page GUI'yi acamiyordu

## Fix
- Calisan ornege once `SHOW` gonder (pencereyi one getir, yeni process gerekmez)
- Steal basarisizsa `kill-honeypot.ps1 -Force` + taskkill
- Control socket log storm (WinError 10038) duzeltildi
- Installer finish: launch oncesi kill + `--create-tasks`
