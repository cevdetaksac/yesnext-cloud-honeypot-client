# v4.4.48 — Remote Desktop session picker

- `remote_stream_start` artık `session_id` / `username` / `monitor` dinliyor
- 0 interaktif oturum → `NO_INTERACTIVE_SESSION` (streaming yalanı yok)
- Varsayılan: Console Active → Console → Active RDP → ilk
- Farklı WTS session → `CreateProcessAsUser` helper ile o masaüstü
- Result + WS meta: `session_id`, `username`
