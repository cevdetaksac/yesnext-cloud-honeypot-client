# v4.4.23 — Uzak masaüstü siyah ekran (RDP disconnected / input desktop)

Dashboard kanıtı (`/api/remote/status`): `has_frame:false`, `live:false` — viewer WS açık ama agent JPEG göndermiyor.

## Kök neden
RDP oturumu **Disconnected** iken (veya thread input desktop’ta değilken) GDI/ImageGrab **siyah** bitmap döner; client kareyi bilerek göndermez → dashboard “Yayın başlatılıyor…”.

## Düzeltme
- Capture thread: `OpenInputDesktop` + `SetThreadDesktop`
- Session state log (Active / Disconnected)
- Disconnected / siyah karede bir kez `tscon <sid> /dest:console` (masaüstü yeniden çizilsin)
- Probe karesini WS kuyruğuna da koy; WS bağlanınca son iyi kareyi tekrar gönder
- HTTP probe başarısızsa `frames_sent` yalan söylemesin

## Not
`tscon … /dest:console` fiziksel konsolu kısa süre agent oturumuna alabilir — uzak masaüstü için gerekli trade-off.
