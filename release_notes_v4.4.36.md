# v4.4.36 — GUI tray'e inmiyordu

## Sorun
- `force_gui_onboarding.flag` token olsa bile tray minimize'i engelliyordu
- `--show-gui` bayragi kalici kilitleyebiliyordu

## Fix
- Token varsa onboarding bitmis sayilir → tray'e izin + bayrak temizlenir
- `--show-gui` artik kalici force flag yazmaz
