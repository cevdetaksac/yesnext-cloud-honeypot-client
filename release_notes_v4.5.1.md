# v4.5.1 — GUI acilis hotfix

- Kontrol portu mesgulse GUI artik **sessizce kapanmiyor** (`sys.exit` kaldirildi)
- Kurulum sonrasi GUI hemen acilir; daemon arka planda baslatilir (20sn blok yok)
- `--show-gui` registry LastMode artik `gui` (yanlis `daemon` yazmiyordu)
- Onceki: port mesgul / SHOW path → pencere gelmiyordu
