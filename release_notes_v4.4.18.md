# v4.4.18 — Siyah ekran: CAPTURE_NO_DESKTOP + Session 0 helper

`AGENT_REMOTE_BLACK_SCREEN_PROMPT.md` uyumu:

Kanıt (`frames_sent=0`, `screen 0×0`, `streaming=true`) için:

- **Dürüst start:** probe capture; `screen/capture` 0 veya siyah/tiny JPEG → `success:false`, `error: CAPTURE_NO_DESKTOP` (streaming yalanı yok)
- **Siyah / &lt;1500B kare gönderme** (API “Frame too small”)
- **10 sn frames_sent=0** → stream fail + stop
- **Session 0:** `CreateProcessAsUser` + `--rd-capture-once` ile interaktif session’dan JPEG
- Probe sonrası ilk HTTP keyframe hemen basılır

Acceptance: başarılı start’ta `screen.w/h > 0`, birkaç saniyede `frames_sent` artar.
