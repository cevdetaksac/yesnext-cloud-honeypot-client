# HOTFIX — Remote Desktop mouse/keyboard (zorunlu)

## Teşhis (cloud log, 2026-07-20)

- Dashboard tıklıyor → `POST /api/remote/input` **200 OK** (çalışıyor).
- Kuyruk doluyor (`data/remote_inputs/{client_id}.jsonl` onlarca event).
- Agent yayın sırasında **frame** atıyor (`POST /api/remote/frame-json`) ama `GET /api/remote/inputs` **seyrek** veya hiç → mouse ölü.
- Görüntü var ≠ input çalışıyor.

## Cloud değişikliği (yayında)

Her frame cevabına input piggyback eklendi:

```http
POST /api/remote/frame-json
→ { "status":"ok", "width":…, "height":…, "inputs":[…], "input_count":N }

POST /api/remote/frame   (multipart)
→ aynı şekilde inputs[]
```

`inputs[]` örneği:

```json
[
  {"event":"mousedown","x":0.52,"y":0.31,"button":"left","ts":"…Z"},
  {"event":"mouseup","x":0.52,"y":0.31,"button":"left","ts":"…Z"},
  {"event":"move","x":0.55,"y":0.33,"button":"left","ts":"…Z"},
  {"event":"wheel","x":0.5,"y":0.5,"key":"1","ts":"…Z"},
  {"event":"key","key":"a","code":"KeyA","ts":"…Z"}
]
```

- `x`,`y`: **0..1** normalize (ekran genişliği/yüksekliği ile çarp).
- Cloud frame cevabında kuyruğu **drain** eder — agent uygulamadan yok sayarsa tıklar kaybolur.

## Agent fix (client ≥ 4.5.55)

Stream loop içinde (her frame upload sonrası):

```text
resp = POST /api/remote/frame-json { jpeg… }
for ev in resp.inputs:
    apply_input_in_target_session(ev)   # aynı session_id / user-helper
```

Uygulandı:

1. `ClientAPI.upload_remote_frame` → `{"ok", "inputs"}`; multipart + frame-json ACK parse.
2. Her capture’da HTTP frame post (WS yanında) — kuyruk frame ACK ile drain edilir.
3. `_apply_input_batch` piggyback event’leri uygular; `mousedown`+`mouseup` ayrı kalır (ekstra `click` üretilmez).
4. `GET /api/remote/inputs` yedek poll (WS açıkken de).
5. `/ws/remote/agent` text `{"t":"input",…}` zaten `apply_input` ile işleniyor.

Not: Input inject hâlâ agent process’inin Win32 oturumunda (`SetCursorPos` / `mouse_event` / `SendInput`). Capture `user-helper` ile başka WTS session’daysa, Session-0 inject hedef masaüstüne gitmeyebilir — ayrı user-session input helper sonraki iş.

## Acceptance

1. Dashboard’da tıkla → 1 sn içinde uzak masaüstünde tık görünür.
2. Sürükle-bırak / sağ tık / tekerlek çalışır.
3. Cloud kuyruk (`pending_inputs`) yayın sırasında **0’a yakın** kalır (birikmez).

Min sürüm: **4.5.55**
