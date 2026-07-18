# v4.5.5 — PIN popup stack fix

Tray ikonuna tekrar tiklayinca `wait_window` event loop'u islerken yeni PIN
pencereleri aciliyordu.

- Tek aktif PIN dialog; tekrar tiklayinca mevcut pencere one gelir
- `show_window` busy guard
- Pencere zaten acik + unlock ise PIN sormadan focus
