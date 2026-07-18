# v4.4.25 — Onboarding GUI + hesap bağlantısı + self-process proof

## Non-silent kurulum
- Silent değilse pencere tray’e gizlenmez; kullanıcı token / dashboard kaydı yapabilsin.
- `force_gui_onboarding.flag` (ProgramData) + token yokken pencere zorunlu görünür.
- Token kopyala / Hesaba bağla / Dashboard açıldıktan sonra tray minimize serbest.

## Hesap / çoklu sunucu (Account)
- Üst barda **Hesaba bağla** + token kopyala (Link server talimatı).
- Tray: Dashboard aç, Hesaba bağla, Token’ı kopyala, sunucu adı.

## Self-process (HMAC)
- Her `health/report` → `agent_runtime` / `self_process` (pid, exe_path, proof).
- Kendi satır: `is_agent_self` + `self_proof`; isim taklidi → `name_spoof_candidate`.
- `kill_process` kendi PID → self-refuse (isme göre blanket protect yok).
