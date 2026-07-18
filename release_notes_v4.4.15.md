# v4.4.15 — Uzak masaüstü akıcı WebSocket

`AGENT_REMOTE_DESKTOP_PROMPT.md` uyumu:

- **WebSocket birincil:** `wss://…/ws/remote/agent?token=` — hello + meta JSON + binary JPEG
- **HTTP fallback:** `POST /api/remote/frame` + `GET /api/remote/inputs` (~300 ms) WS yokken
- Hedef **~6 fps** (max 10), JPEG q≈35, kare ≤ ~320 KB
- Girdi: `mousedown` / `move` / `mouseup` (sürükle), `wheel`, `click`, `dblclick`, `type_text`, `key`
- UI rozeti: WebSocket (yeşil) / HTTP fallback (turuncu)
