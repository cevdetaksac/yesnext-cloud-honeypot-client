# v4.4.17 — Uzak masaüstü siyah ekran düzeltmesi

Dashboard’da siyah görüntü için client tarafı sertleştirildi:

- **GDI BitBlt** birincil yakalama (ImageGrab yedek)
- **Session 0 / yanlış oturum** uyarısı (servis oturumunda capture çoğu zaman siyah)
- **Siyah kare tespiti** + log
- **JPEG magic** doğrulama (`FFD8…FFD9`)
- **Thread-safe WebSocket**: kareler kuyrukla WS thread’inden gönderilir (bozuk binary önlenir)
- **HTTP keyframe** her N karede (WS kopsa / proxy binary düşürse dashboard cache dolu kalsın)

Log örnekleri: `first frame ok`, `Nearly-black frame`, `Session ok`.
