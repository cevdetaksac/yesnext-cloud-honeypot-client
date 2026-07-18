# v4.5.3 — GUI stutter / kasma

- Tray ikonu her health tick'te diskten yeniden aciliyordu → cache + ayni state skip
- GUI, daemon gelmeden motor (firewall 30s, open-ports, update watchdog) baslatiyordu → build_gui'de erken PING + frontend skip
- Frontend modda update watchdog GUI'de tekrar baslamasin
