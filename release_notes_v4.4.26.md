# v4.4.26 — Sistem dili + güncelleme kill koruması + ilk kurulum GUI

## Dil
- İlk açılışta Windows arayüz diline göre (TR/EN).
- Kullanıcı dil değiştirirse ProgramData’da saklanır; güncellemede kaybolmaz.

## Güncelleme ortasında kapanma
- `kill-honeypot.ps1` artık `update_in_progress.lock` varsa (indirme) öldürmez (`-Force` yalnızca installer).
- MemoryRestart da aynı kilidi kontrol eder.

## İlk kurulum → GUI görünür
- Tray görevi çalışan GUI’yi çalmaz (soft singleton).
- Installer `%ProgramData%` onboarding bayrağı + Tray/Background end.
- `--show-gui` / onboarding’de pencere zorunlu görünür; tray minimize engellenir.
