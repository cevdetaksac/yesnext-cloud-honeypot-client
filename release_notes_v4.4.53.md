# v4.4.53 — Multi-user GUI stabil + masaustu kisayol opt-in

- **Cok kullanicili RDP:** Tray task `StopExisting` -> `IgnoreNew` (ikinci logon birinci GUI'yi oldurmez)
- **MemoryRestart:** sadece Session 0 daemon; interactive GUI'ye dokunmaz
- **Singleton steal:** baska oturumda interactive client varsa kill yok
- **QUIT** olayi lifecycle log'a yazilir
- Installer: **Desktop Shortcut** varsayilan **kapali** (kullanici isaretlerse eklenir)
