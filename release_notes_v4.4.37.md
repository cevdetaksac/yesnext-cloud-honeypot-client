# v4.4.37 — Uygulama ici hesaba bagla

## Yenilik
- "Hesaba bagla" popup: e-posta + sifre
- Once `POST /api/agent/link-account` (API prompt: `AGENT_ACCOUNT_LINK_INAPP_API_PROMPT.md`)
- Yoksa web fallback: `/account/login` + `/account/link-server`
- Tray menusu ayni popup'i acar; "Web'de ac" hala var

## Not
- Sifre saklanmaz; basarida e-posta cache + account-status sync
