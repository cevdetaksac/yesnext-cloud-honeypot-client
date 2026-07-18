# v4.4.9 — Uzak Masaüstü (ekran aynası MVP)

Dashboard **Koruma → Uzak Masaüstü** için agent tarafı.

## Komutlar
- `remote_stream_start` — JPEG capture loop (fps/quality/max_width)
- `remote_stream_stop` — yayını kes
- `remote_input` — click / dblclick / type_text / key

## Upload
- `POST /api/remote/frame` (multipart `file`)
- Fallback: `POST /api/remote/frame-json` (base64)

## Güvenlik / limit
- Yayın yalnızca komut sonrası
- 5 dk idle (input yok) → otomatik stop
- Input rate limit ~20/sn
- `ctrl+alt+del` OS tarafından engelli (atlanır)

## Acceptance
- [x] start → frame upload
- [x] click / type_text
- [x] stop
- [x] Pillow ImageGrab (user session desktop)
